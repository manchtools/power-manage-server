package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestSSOFlowState_IsReplicaSafe pins spec 31 AC16: the OIDC authorization-code
// flow state (state / nonce / PKCE code_verifier / redirect) lives in the shared
// Postgres store, never replica-local memory, so a flow begun on replica A
// completes on replica B.
//
// GetSSOLoginURL persists via store.Repos().AuthState.Create and SSOCallback
// reads via store.Repos().AuthState.Consume (see sso_handler.go). N control
// replicas all connect to the same Postgres, represented here by one store: what
// replica A writes, replica B reads. A single-use Consume also guards against a
// replayed callback landing on a second replica.
func TestSSOFlowState_IsReplicaSafe(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	enc := testutil.NewEncryptor(t)
	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, actorID, "Test IdP", "test-idp")

	const state = "01JSTATEREPLICASAFE0000000"
	// Replica A (GetSSOLoginURL) persists the flow state to the shared DB.
	require.NoError(t, st.Repos().AuthState.Create(ctx, store.CreateAuthStateParams{
		State:        state,
		ProviderID:   providerID,
		Nonce:        "nonce-value",
		CodeVerifier: "pkce-code-verifier-value",
		RedirectURI:  "https://app.example.com/auth/callback",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}))

	// Replica B (SSOCallback) consumes it from the same shared DB — proving the
	// flow state is not held in replica A's memory.
	got, err := st.Repos().AuthState.Consume(ctx, state)
	require.NoError(t, err)
	assert.Equal(t, "nonce-value", got.Nonce)
	assert.Equal(t, "pkce-code-verifier-value", got.CodeVerifier)
	assert.Equal(t, "https://app.example.com/auth/callback", got.RedirectURI)

	// Consume is single-use: a replayed callback (e.g. retried against another
	// replica) finds nothing.
	_, err = st.Repos().AuthState.Consume(ctx, state)
	require.Error(t, err, "a consumed state must not resolve a second time")
	assert.True(t, store.IsNotFound(err), "a replayed/absent state must surface as not-found")
}
