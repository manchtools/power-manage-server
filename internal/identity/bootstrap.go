package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// The host-authorized bootstrap-admin path.
//
// Human identity is OIDC only. That leaves one problem: a fresh
// deployment has no identity provider configured and therefore no way
// for anyone to sign in and configure one. The bootstrap token is the
// single exception, and it is deliberately the narrowest one that can
// work:
//
//   - it is minted by a command run ON THE HOST, so possession of the
//     host is the authorization;
//   - it is single-use, enforced by a conditional write rather than by
//     a read-then-write the second caller could interleave with;
//   - it is short-lived;
//   - minting a new one retires every outstanding one, so at most one
//     is ever presentable; and
//   - it authenticates a PERMANENTLY RESERVED principal that is not a
//     user, owns nothing, and can therefore never satisfy `:self`.

const (
	// BootstrapTokenBytes is the entropy of the printed token.
	BootstrapTokenBytes = 32
	// DefaultBootstrapTokenTTL bounds how long an unspent token stays
	// presentable. Long enough for an operator to paste it into a
	// browser, short enough that a token left in a terminal scrollback
	// is not a standing credential.
	DefaultBootstrapTokenTTL = 15 * time.Minute
)

// BootstrapToken is what the host command prints. The plaintext value
// exists only in this struct and in the operator's terminal; the
// database holds its digest.
type BootstrapToken struct {
	Token     string
	URL       string
	ExpiresAt time.Time
}

// BootstrapStore is the database surface the bootstrap path needs.
// Satisfied by *store.Store.
type BootstrapStore interface {
	WithAudit(ctx context.Context, op store.AuditOperation, mutate func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error) (store.AuditRecord, error)
}

// Bootstrapper mints and consumes host-authorized setup tokens.
type Bootstrapper struct {
	store   BootstrapStore
	baseURL string
	ttl     time.Duration
	now     func() time.Time
}

// NewBootstrapper builds the bootstrap-admin mechanism.
func NewBootstrapper(st BootstrapStore, baseURL string, ttl time.Duration, now func() time.Time) *Bootstrapper {
	if ttl <= 0 {
		ttl = DefaultBootstrapTokenTTL
	}
	if now == nil {
		now = time.Now
	}
	return &Bootstrapper{store: st, baseURL: baseURL, ttl: ttl, now: now}
}

// ErrBootstrapTokenRejected is what a token that cannot be spent
// produces. It is one error for every reason — unknown, expired,
// already spent, retired — because the presenter is unauthenticated and
// the distinction is not theirs to learn.
var ErrBootstrapTokenRejected = errors.New("identity: bootstrap token rejected")

// Issue mints a token, retiring any outstanding one in the same
// transaction.
//
// The write is audited as a background writer with no actor id: the
// authorization is possession of the host, and there is no subject to
// attribute it to. The token's digest is the evidence; the token itself
// appears nowhere but the return value.
func (b *Bootstrapper) Issue(ctx context.Context) (BootstrapToken, error) {
	raw := make([]byte, BootstrapTokenBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return BootstrapToken{}, fmt.Errorf("generate bootstrap token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := fingerprint(token)

	tokenID := ulid.Make().String()
	issuedAt := b.now().UTC()
	expiresAt := issuedAt.Add(b.ttl)

	_, err := b.store.WithAudit(ctx, store.AuditOperation{
		Class:                store.ClassBackgroundWriter,
		ActorType:            string(auth.PrincipalBootstrapAdmin),
		Origin:               "host_command",
		RequestDescriptor:    "control.bootstrap-admin/Issue",
		AuthorizationOutcome: store.AuthorizationNotApplicable,
		Result:               store.ResultSuccess,
	}, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		retired, err := tx.RetireBootstrapAdminTokens(ctx, store.BootstrapAdminTokenName)
		if err != nil {
			return err
		}
		if _, err := tx.InsertBootstrapAdminToken(ctx, db.InsertBootstrapAdminTokenParams{
			ID:           tokenID,
			ValueHash:    digest,
			ReservedName: store.BootstrapAdminTokenName,
			ExpiresAt:    &expiresAt,
			CreatedAt:    &issuedAt,
			CreatedBy:    auth.BootstrapPrincipalID,
		}); err != nil {
			return err
		}
		if retired > 0 {
			rec.Effect(store.AuditEffect{
				ResourceType: "bootstrap_token",
				ResourceID:   tokenID,
				Action:       "RETIRE_OUTSTANDING",
				Outcome:      store.EffectApplied,
				BeforeCount:  &retired,
			})
		}
		rec.Effect(store.AuditEffect{
			ResourceType:        "bootstrap_token",
			ResourceID:          tokenID,
			Action:              "ISSUE",
			Outcome:             store.EffectApplied,
			ChangedFields:       []string{"value_hash", "expires_at"},
			EvidenceKind:        "bootstrap_token_sha256",
			EvidenceFingerprint: digest,
		})
		return nil
	})
	if err != nil {
		return BootstrapToken{}, fmt.Errorf("issue bootstrap token: %w", err)
	}

	return BootstrapToken{
		Token:     token,
		URL:       b.setupURL(token),
		ExpiresAt: expiresAt,
	}, nil
}

// AuthenticateBootstrapToken spends a token and returns the reserved
// principal it admits.
//
// The spend is a conditional UPDATE that checks liveness, expiry and
// the use count in one statement, so two concurrent presentations of
// the same value cannot both succeed: the second matches no row.
func (b *Bootstrapper) AuthenticateBootstrapToken(ctx context.Context, token string) (*auth.UserContext, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, ErrBootstrapTokenRejected
	}
	digest := fingerprint(token)

	// The freshness bound is compared against the SAME clock that
	// issued the token, not the database's. Mixing the two would make a
	// token's lifetime depend on the skew between them.
	now := b.now().UTC()

	var spent bool
	_, err := b.store.WithAudit(ctx, store.AuditOperation{
		Class:                store.ClassMutation,
		ActorType:            string(auth.PrincipalBootstrapAdmin),
		Origin:               auth.ControlRPCOrigin,
		RequestDescriptor:    "control.bootstrap-admin/Consume",
		AuthorizationOutcome: store.AuthorizationNotApplicable,
		Result:               store.ResultSuccess,
	}, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.ConsumeBootstrapAdminToken(ctx, db.ConsumeBootstrapAdminTokenParams{
			ValueHash:    digest,
			ReservedName: store.BootstrapAdminTokenName,
			Now:          &now,
		})
		if err != nil {
			if store.IsNotFound(err) {
				return ErrBootstrapTokenRejected
			}
			return err
		}
		spent = true
		rec.Effect(store.AuditEffect{
			ResourceType:        "bootstrap_token",
			ResourceID:          row.ID,
			Action:              "CONSUME",
			Outcome:             store.EffectApplied,
			ChangedFields:       []string{"current_uses"},
			EvidenceKind:        "bootstrap_token_sha256",
			EvidenceFingerprint: digest,
		})
		return nil
	})
	switch {
	case errors.Is(err, ErrBootstrapTokenRejected):
		return nil, ErrBootstrapTokenRejected
	case err != nil:
		// A real failure — the database is unreachable, the audit write
		// was refused — is reported as itself. Folding it into the
		// rejection would hide an outage behind "wrong token" and leave
		// the branch that reports it dead.
		return nil, fmt.Errorf("consume bootstrap token: %w", err)
	case !spent:
		return nil, ErrBootstrapTokenRejected
	}

	return &auth.UserContext{
		ID:   auth.BootstrapPrincipalID,
		Kind: auth.PrincipalBootstrapAdmin,
		// The bootstrap principal holds exactly the authority a fresh
		// deployment needs to become usable: define roles, register an
		// identity provider, and create the first subject. It is NOT
		// given the full administrative set, and it holds no `:self`
		// variant of anything — it is not a subject and owns nothing.
		Permissions: BootstrapPermissions(),
	}, nil
}

// BootstrapPermissions is the fixed authority of the reserved setup
// principal.
//
// Every entry is a base permission with no scope suffix. There is
// deliberately no `:self` key here and no way to add one: the principal
// cannot own resources, so a self-scoped grant would be unsatisfiable
// anyway, and listing one would suggest otherwise.
func BootstrapPermissions() []string {
	return []string{
		PermCreateIdentityProvider,
		PermGetIdentityProvider,
		PermListIdentityProviders,
		PermUpdateIdentityProvider,
		PermCreateRole,
		PermGetRole,
		PermListRoles,
		PermListPermissions,
		PermCreateUser,
		PermGetUser,
		PermListUsers,
		PermAssignRoleToUser,
	}
}

func (b *Bootstrapper) setupURL(token string) string {
	base := strings.TrimSuffix(b.baseURL, "/")
	return base + "/setup?bootstrap_token=" + token
}
