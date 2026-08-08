//go:build devauth

package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
)

// devTestKEK is a 32-byte KEK in hex; the dev admin's DEK is minted under it.
const devTestKEK = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func devTestDeps(t *testing.T) (*store.Store, *auth.JWTManager, *crypto.Encryptor) {
	t.Helper()
	ctx := context.Background()
	st, err := store.New(ctx, filepath.Join(t.TempDir(), "control.db"))
	require.NoError(t, err)
	t.Cleanup(st.Close)
	require.NoError(t, auth.ReconcileSystemRoles(ctx, st, time.Now(), slog.New(slog.NewTextHandler(io.Discard, nil))))

	_, priv, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	jwtMgr, err := auth.NewJWTManager(auth.JWTConfig{PrivateKey: priv})
	require.NoError(t, err)

	kek, err := crypto.NewEncryptor(devTestKEK)
	require.NoError(t, err)
	return st, jwtMgr, kek
}

// base404 stands in for the real control handler: anything the dev wrapper
// does not intercept falls through to it.
func base404() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
}

// AC (b): with the devauth build but PM_DEV_AUTH unset, the route
// does not exist — the wrapper returns the base handler unchanged.
func TestDevAuthDisabledWithoutEnv(t *testing.T) {
	t.Setenv(devAuthEnv, "")
	st, jwtMgr, kek := devTestDeps(t)
	h := wrapDevAuth(base404(), st, jwtMgr, kek, slog.New(slog.NewTextHandler(io.Discard, nil)))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, devSessionPath, nil))
	assert.Equal(t, http.StatusNotFound, rec.Code, "/dev/session must not exist without PM_DEV_AUTH=1")
}

// TestArchiveIsolationRelaxationFollowsTheDevAuthFlag holds the escape hatch's
// only reason to exist: it rides the same two gates as the sign-in bypass and
// adds no third way to turn a verification off. A devauth binary run without
// PM_DEV_AUTH=1 still demands the audit archive's own filesystem, and the
// !devauth stub cannot relax it at all.
func TestArchiveIsolationRelaxationFollowsTheDevAuthFlag(t *testing.T) {
	t.Setenv(devAuthEnv, "")
	assert.False(t, archiveIsolationRelaxed(), "the build tag alone must not relax the requirement")

	t.Setenv(devAuthEnv, "yes")
	assert.False(t, archiveIsolationRelaxed(), "only the exact flag value relaxes it")

	t.Setenv(devAuthEnv, "1")
	assert.True(t, archiveIsolationRelaxed(), "a workstation with one disk must still be able to run control")
}

// TestLoadConfigToleratesOneDiskInADevAuthBuild drives the relaxation through
// the real loader with the real filesystem probe, so the branch is exercised
// where it is actually reached rather than only where it is declared.
func TestLoadConfigToleratesOneDiskInADevAuthBuild(t *testing.T) {
	fixture := newEnvironmentFixture(t)
	useRealFilesystemProbe(t)
	setEnvironment(t, fixture.values)

	t.Setenv(devAuthEnv, "")
	cfg, err := loadConfig()
	require.Error(t, err, "a devauth build without the flag still enforces the separation")
	require.Nil(t, cfg)

	t.Setenv(devAuthEnv, "1")
	cfg, err = loadConfig()
	require.NoError(t, err)
	assert.Equal(t, fixture.values["POWER_MANAGE_BACKUP_PATH"], cfg.BackupPath)
}

// AC (c) + (d): with the flag set, POST /dev/session idempotently provisions
// the fixed admin and returns an access token that authenticates AS an
// administrator (carries the reconciled admin permission set).
func TestDevAuthMintsAdminSession(t *testing.T) {
	t.Setenv(devAuthEnv, "1")
	st, jwtMgr, kek := devTestDeps(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := wrapDevAuth(base404(), st, jwtMgr, kek, logger)

	post := func() devSessionResponse {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, devSessionPath, nil)
		req.RemoteAddr = "127.0.0.1:1234"
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp devSessionResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		return resp
	}

	first := post()
	require.NotEmpty(t, first.AccessToken)
	require.NotEmpty(t, first.RefreshToken)
	assert.Equal(t, devAdminEmail, first.Email)
	require.NotEmpty(t, first.UserID)
	issued, err := st.CountAuditEventRows(context.Background(), store.AuditEventFilter{EventType: "DEV_ISSUE"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), issued)

	// The minted access token validates and carries administrator authority.
	claims, err := jwtMgr.ValidateToken(first.AccessToken, auth.TokenTypeAccess)
	require.NoError(t, err)
	assert.Equal(t, first.UserID, claims.UserID)

	dbPerms, err := st.ListUserPermissions(context.Background(), first.UserID)
	require.NoError(t, err)
	require.NotEmpty(t, dbPerms, "provisioned dev user must hold the admin role's permissions")
	assert.Contains(t, dbPerms, "AssignRoleToUser", "dev user must be an administrator")
	assert.ElementsMatch(t, dbPerms, claims.Permissions, "access token authority must match the DB")

	// Second login is idempotent: the same subject, not a duplicate.
	second := post()
	assert.Equal(t, first.UserID, second.UserID)
	issued, err = st.CountAuditEventRows(context.Background(), store.AuditEventFilter{EventType: "DEV_ISSUE"})
	require.NoError(t, err)
	assert.Equal(t, int64(2), issued, "every minted session needs its own audit evidence")

	users, err := st.ListUsers(context.Background(), "", 100)
	require.NoError(t, err)
	var adminCount int
	emails := make([]string, 0, len(users))
	for _, u := range users {
		emails = append(emails, u.Email)
		if u.Email == devAdminEmail {
			adminCount++
		}
	}
	sort.Strings(emails)
	assert.Equal(t, 1, adminCount, "dev admin must be provisioned exactly once, saw %v", emails)
}

func TestDevAuthOnlyAcceptsLocalRequestsFromKnownDevOrigins(t *testing.T) {
	t.Setenv(devAuthEnv, "1")
	st, jwtMgr, kek := devTestDeps(t)
	h := wrapDevAuth(base404(), st, jwtMgr, kek, slog.New(slog.NewTextHandler(io.Discard, nil)))

	for name, test := range map[string]struct {
		remote string
		origin string
		want   int
	}{
		"remote caller":    {"203.0.113.10:1234", "", http.StatusForbidden},
		"unknown origin":   {"127.0.0.1:1234", "https://evil.example", http.StatusForbidden},
		"localhost origin": {"127.0.0.1:1234", "https://localhost:5173", http.StatusNoContent},
		"local no origin":  {"[::1]:1234", "", http.StatusNoContent},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, devSessionPath, nil)
			req.RemoteAddr = test.remote
			if test.origin != "" {
				req.Header.Set("Origin", test.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, test.want, rec.Code)
			if test.want == http.StatusNoContent && test.origin != "" {
				assert.Equal(t, test.origin, rec.Header().Get("Access-Control-Allow-Origin"))
			} else {
				assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
			}
		})
	}
}
