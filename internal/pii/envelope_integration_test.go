package pii_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Spec 19 stage A integration tests (real Postgres): the envelope
// round-trip — tagged PII is ciphertext in the events table, plaintext
// in projections, rebuilds reproduce 1:1 — and the fail-closed append.

func eventField(t *testing.T, st *store.Store, eventType, field string) string {
	t.Helper()
	var v string
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT data->>$2 FROM events WHERE event_type = $1 ORDER BY sequence_num DESC LIMIT 1`,
		eventType, field).Scan(&v))
	return v
}

// TestEnvelope_UserStreamRoundTrip pins AC 2 + AC 4 on the user
// stream: the appended event holds pii:v1 ciphertext (never the
// plaintext), the projection holds the decrypted plaintext, and a full
// rebuild reproduces it 1:1.
func TestEnvelope_UserStreamRoundTrip(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "env-"+testutil.NewID()[:8]+"@test.com", "pass", "user")

	display := "Envelope Roundtrip"
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  string(eventtypes.UserProfileUpdated),
		Data:       payloads.UserProfileUpdated{DisplayName: &display},
		ActorType:  "user",
		ActorID:    userID,
	}))

	// AC 2 — ciphertext in the event row, plaintext absent.
	raw := eventField(t, st, "UserProfileUpdated", "display_name")
	assert.True(t, strings.HasPrefix(raw, "pii:v1:"), "event must hold sealed PII, got %q", raw)
	assert.NotContains(t, raw, "Envelope", "plaintext must not appear in the event row")

	// AC 4 — plaintext in the projection (decrypt-on-insert).
	u, err := st.Repos().User.Get(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, display, u.DisplayName)

	// AC 4 — a rebuild reproduces the plaintext 1:1.
	_, err = st.RebuildAll(ctx)
	require.NoError(t, err)
	u2, err := st.Repos().User.Get(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, display, u2.DisplayName, "rebuild must decrypt and reproduce the projection")
}

// TestEnvelope_OffStreamRoundTrip pins AC 2 + AC 4 for off-stream PII:
// an identity-link event on the identity_provider stream is sealed
// under the OWNING user's DEK (resolved from the payload's user_id).
func TestEnvelope_OffStreamRoundTrip(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "offs-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	enc := testutil.NewEncryptor(t)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, userID, "Envelope IdP", "env-"+testutil.NewID()[:8])

	linkID := testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   linkID,
		EventType:  string(eventtypes.IdentityLinked),
		Data: payloads.IdentityLinked{
			UserID:        userID,
			ProviderID:    providerID,
			ExternalID:    "ext-" + linkID,
			ExternalEmail: "offstream@idp.example",
			ExternalName:  "Off Stream",
		},
		ActorType: "system",
		ActorID:   "sso",
	}))

	raw := eventField(t, st, "IdentityLinked", "external_email")
	assert.True(t, strings.HasPrefix(raw, "pii:v1:"), "off-stream PII must seal too, got %q", raw)
	// The subject field stays plaintext — it addresses the DEK.
	assert.Equal(t, userID, eventField(t, st, "IdentityLinked", "user_id"))

	link, err := st.Queries().GetIdentityLinkByID(ctx, linkID)
	require.NoError(t, err)
	assert.Equal(t, "offstream@idp.example", link.ExternalEmail, "projection holds plaintext")

	_, err = st.RebuildAll(ctx)
	require.NoError(t, err)
	link2, err := st.Queries().GetIdentityLinkByID(ctx, linkID)
	require.NoError(t, err)
	assert.Equal(t, "offstream@idp.example", link2.ExternalEmail, "rebuild reproduces off-stream PII 1:1")
}

// TestEnvelope_FailClosedAppend pins AC 6: appending a PII-bearing
// event for a user with NO encryption key fails, and NOTHING is
// written — plaintext PII never reaches the log as a fallback.
func TestEnvelope_FailClosedAppend(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	// A user id that never went through a provisioning path: no DEK.
	ghost := testutil.NewID()
	display := "Must Not Land"
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   ghost,
		EventType:  string(eventtypes.UserProfileUpdated),
		Data:       payloads.UserProfileUpdated{DisplayName: &display},
		ActorType:  "user",
		ActorID:    ghost,
	})
	require.Error(t, err, "append must fail closed without a DEK")
	assert.Contains(t, err.Error(), "no encryption key")

	var n int
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM events WHERE stream_id = $1`, ghost).Scan(&n))
	assert.Zero(t, n, "no event row may exist after a refused append")
}

// TestEnvelope_MintIsFirstWriteWins pins the Mint contract backing
// AC 15's groundwork: a second mint for the same user NEVER replaces
// the key that may already have sealed PII.
func TestEnvelope_MintIsFirstWriteWins(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "fw-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	before, err := st.Repos().UserEncryptionKey.Get(ctx, userID)
	require.NoError(t, err)

	require.NoError(t, st.MintUserDEK(ctx, userID), "re-mint is not an error")
	after, err := st.Repos().UserEncryptionKey.Get(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, before.WrappedDEK, after.WrappedDEK,
		"a re-mint must never replace an existing DEK — that would be an accidental shred")
}
