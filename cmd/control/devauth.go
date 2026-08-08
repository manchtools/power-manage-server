//go:build devauth

// Development-only authentication bypass. Target design §5.2: a build
// compiled with the `devauth` tag AND run with PM_DEV_AUTH=1
// exposes POST /dev/session, which provisions one fixed local
// administrator and mints an ordinary session for it so the web UI can be
// exercised without an identity provider. Both gates are mandatory: a
// release build omits this file entirely (the !devauth stub replaces it),
// and a devauth build still refuses unless the environment flag is set.
// The minted session is an ordinary signed session subject to the same
// validation, revocation and expiry as an OIDC login.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/auth"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	devAuthEnv     = "PM_DEV_AUTH"
	devSessionPath = "/dev/session"
	// devAdminEmail is the fixed local administrator. Lookup by this
	// address keeps provisioning idempotent across restarts and repeat
	// logins.
	devAdminEmail       = "dev-admin@localhost"
	devAdminDisplayName = "Dev Admin"
	devAdminLinuxName   = "devadmin"
)

// devSessionResponse is the JSON the web dev bypass consumes. It carries a
// real access/refresh pair; the web stores it exactly like an SSO login.
type devSessionResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    string `json:"expiresAt"`
	UserID       string `json:"userId"`
	Email        string `json:"email"`
	DisplayName  string `json:"displayName"`
}

// archiveIsolationRelaxed downgrades the audit archive's separate-filesystem
// requirement to a warning on a development workstation, where the database
// and the archive are two directories on one disk and mounting a second
// filesystem needs root.
//
// It rides the two gates this file already establishes rather than adding a
// third: a release binary compiles the !devauth stub, which returns false and
// has no way to be told otherwise, and a devauth binary still enforces the
// requirement unless PM_DEV_AUTH=1 is set. A build in which this can return
// true is a build that also mints administrator sessions without an identity
// provider, so it can never be mistaken for a deployable one.
func archiveIsolationRelaxed() bool { return os.Getenv(devAuthEnv) == "1" }

// wrapDevAuth mounts POST /dev/session in front of next when this devauth
// build is run with PM_DEV_AUTH=1. Without the flag it returns
// next unchanged, so the route does not exist. Production builds never
// reach here — they compile the !devauth stub instead.
func wrapDevAuth(next http.Handler, st *store.Store, jwtMgr *auth.JWTManager, kek *pmcrypto.Encryptor, logger *slog.Logger) http.Handler {
	if os.Getenv(devAuthEnv) != "1" {
		return next
	}
	logger.Warn("DEVELOPMENT AUTH BYPASS ACTIVE — POST /dev/session mints an administrator session without an identity provider; never run a devauth build in production",
		"endpoint", devSessionPath)

	mux := http.NewServeMux()
	mux.HandleFunc(devSessionPath, func(w http.ResponseWriter, r *http.Request) {
		if !devRequestIsLocal(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			if !devOriginAllowed(origin) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resp, err := devMintAdminSession(r.Context(), st, jwtMgr, kek, time.Now())
		if err != nil {
			logger.Error("dev auth: mint admin session failed", "error", err)
			http.Error(w, "dev session failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error("dev auth: encode response failed", "error", err)
		}
	})
	mux.Handle("/", next)
	return mux
}

func devRequestIsLocal(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	return err == nil && net.ParseIP(host).IsLoopback()
}

func devOriginAllowed(origin string) bool {
	switch origin {
	case "https://localhost:5173", "https://127.0.0.1:5173", "https://[::1]:5173", "https://pm.localhost:5173":
		return true
	default:
		return false
	}
}

// devMintAdminSession idempotently provisions the fixed admin and returns
// an ordinary session for it. The authority is read from the database and
// baked into the access token exactly as the OIDC callback does, so the
// resulting session is indistinguishable downstream from a real login.
func devMintAdminSession(ctx context.Context, st *store.Store, jwtMgr *auth.JWTManager, kek *pmcrypto.Encryptor, now time.Time) (*devSessionResponse, error) {
	userID, err := devEnsureAdmin(ctx, st, kek, now)
	if err != nil {
		return nil, err
	}

	permissions, err := st.ListUserPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}
	grantRows, err := st.ListUserScopedGrants(ctx, userID)
	if err != nil {
		return nil, err
	}
	grants := make([]auth.ScopedGrant, 0, len(grantRows))
	for _, g := range grantRows {
		sg := auth.ScopedGrant{Permission: g.Permission}
		if g.ScopeKind != nil {
			sg.ScopeKind = *g.ScopeKind
		}
		if g.ScopeID != nil {
			sg.ScopeID = *g.ScopeID
		}
		grants = append(grants, sg)
	}
	sessionState, err := st.GetUserSessionState(ctx, userID)
	if err != nil {
		return nil, err
	}

	tokens, err := jwtMgr.GenerateTokens(userID, devAdminEmail, permissions, grants, sessionState.SessionVersion)
	if err != nil {
		return nil, err
	}
	if _, err := st.RecordOperation(ctx, devAuditOperation(), store.AuditEffect{
		ResourceType: "session", ResourceID: userID,
		Action: "DEV_ISSUE", Outcome: store.EffectApplied,
	}); err != nil {
		return nil, err
	}
	return &devSessionResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt.UTC().Format(time.RFC3339),
		UserID:       userID,
		Email:        devAdminEmail,
		DisplayName:  devAdminDisplayName,
	}, nil
}

// devEnsureAdmin returns the fixed admin's id, provisioning it on first
// use. Provision + role grant + the session-issue effect land in one
// audited transaction, mirroring OIDC JIT.
//
// ponytail: check-then-create races on the unique email constraint, which
// a second concurrent InsertUser would reject. That is fine for a
// single-operator dev tool; if it ever matters, catch the violation and
// re-read instead.
func devEnsureAdmin(ctx context.Context, st *store.Store, kek *pmcrypto.Encryptor, now time.Time) (string, error) {
	if existing, err := st.GetUserByEmail(ctx, devAdminEmail); err == nil {
		return existing.ID, nil
	} else if !store.IsNotFound(err) {
		return "", err
	}

	userID := ulid.Make().String()
	op := devAuditOperation()
	_, err := st.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		wrapped, err := pmcrypto.GenerateWrappedDEK(kek, userID)
		if err != nil {
			return err
		}
		if _, err := tx.InsertUserEncryptionKey(ctx, db.InsertUserEncryptionKeyParams{
			UserID:     userID,
			WrappedDek: wrapped,
		}); err != nil {
			return err
		}
		linuxUID, err := tx.GetNextLinuxUID(ctx)
		if err != nil {
			return err
		}
		if linuxUID > 2147483647 {
			return errors.New("assign linux uid: int32 range exhausted")
		}
		createdAt := now.UTC()
		if _, err := tx.InsertUser(ctx, db.InsertUserParams{
			ID:                 userID,
			Email:              devAdminEmail,
			DisplayName:        devAdminDisplayName,
			LinuxUsername:      devAdminLinuxName,
			LinuxUid:           int32(linuxUID),
			ProvisioningSource: store.UserProvisioningSourceOIDCJIT,
			CreatedAt:          &createdAt,
		}); err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{
			ResourceType: "user",
			ResourceID:   userID,
			Action:       "PROVISION",
			Outcome:      store.EffectApplied,
		})

		grantID := ulid.Make().String()
		if _, err := tx.InsertUserRoleGrant(ctx, db.InsertUserRoleGrantParams{
			GrantID:    grantID,
			UserID:     userID,
			RoleID:     auth.AdminRoleID,
			AssignedAt: createdAt,
			AssignedBy: "dev-auth",
		}); err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{
			ResourceType: "user_role",
			ResourceID:   grantID,
			Action:       "GRANT",
			Outcome:      store.EffectApplied,
		})
		return nil
	})
	if err != nil {
		return "", err
	}
	return userID, nil
}

func devAuditOperation() store.AuditOperation {
	return store.AuditOperation{
		Class:                store.ClassBackgroundWriter,
		ActorType:            auth.AnonymousActorType,
		Origin:               auth.ControlRPCOrigin,
		RequestDescriptor:    devSessionPath,
		AuthorizationOutcome: store.AuthorizationNotApplicable,
		Result:               store.ResultSuccess,
	}
}
