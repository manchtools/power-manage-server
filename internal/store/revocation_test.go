package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Spec 41 criterion 6: certificate renewal and device deletion must write the
// revocation row in the SAME transaction as the event that causes it.
//
// The predecessor did this as an append that committed, followed by a
// best-effort revoke that only logged on failure — which leaves the superseded
// certificate admitted for as long as the revocation keeps failing. These tests
// pin the atomicity itself rather than either handler's happy path, because the
// atomicity is the property the criterion names and both handlers route through
// this one seam.

func revocationRowCount(t *testing.T, st *store.Store, fingerprint string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM revoked_certificates WHERE fingerprint = $1`, fingerprint).Scan(&n))
	return n
}

// devEvent builds an event the real projectors accept. DeviceCertRenewed
// carries a payload because its projector rejects one without a fingerprint —
// an empty Data would still append, but it would exercise a shape no handler
// ever emits.
func devEvent(streamID string, eventType eventtypes.EventType) store.Event {
	var data any = map[string]any{}
	if eventType == eventtypes.DeviceCertRenewed {
		fp := "newfingerprint" + streamID
		notAfter := time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339Nano)
		data = payloads.DeviceCertRenewed{CertFingerprint: &fp, CertNotAfter: &notAfter}
	}
	return store.Event{
		StreamType: "device",
		StreamID:   streamID,
		EventType:  string(eventType),
		Data:       data,
		ActorType:  "device",
		ActorID:    streamID,
	}
}

func TestAppendEventAndRevoke_BothLand(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := t.Context()

	const deviceID = "01J0000000000000000000DEV1"
	const fp = "aa11bb22cc33"
	notAfter := time.Now().Add(24 * time.Hour)

	require.NoError(t, st.AppendEventAndRevoke(ctx,
		devEvent(deviceID, eventtypes.DeviceCertRenewed), fp, notAfter, "superseded by renewal"))

	assert.Equal(t, int64(1), revocationRowCount(t, st, fp),
		"revocation row must be written alongside the event")
	assert.Equal(t, int64(1), countByType(t, st, string(eventtypes.DeviceCertRenewed)),
		"the event itself must still be appended")
}

// The atomicity red-check. RevokeInTx refuses an empty fingerprint, so this
// drives a failure from INSIDE the transaction after appendOne has already
// inserted. On the predecessor's ordering the event was committed before the
// revocation was even attempted, so the event would survive; here the rollback
// must take it with it.
func TestAppendEventAndRevoke_RevocationFailureRollsBackTheEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := t.Context()

	const deviceID = "01J0000000000000000000DEV2"
	before := countByType(t, st, string(eventtypes.DeviceDeleted))

	err := st.AppendEventAndRevoke(ctx,
		devEvent(deviceID, eventtypes.DeviceDeleted), "", time.Now().Add(time.Hour), "device deleted")
	require.Error(t, err, "an unrevokable certificate must fail the whole operation")

	assert.Equal(t, before, countByType(t, st, string(eventtypes.DeviceDeleted)),
		"the event must NOT survive a failed revocation — that is the window criterion 6 closes")
}

// A failure BEFORE the append leaves nothing behind either, and in particular
// does not leave a revocation row for an event that never happened.
func TestAppendEventAndRevoke_RejectsUnattributableEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := t.Context()

	const fp = "dd44ee55ff66"
	evt := devEvent("01J0000000000000000000DEV3", eventtypes.DeviceCertRenewed)
	evt.ActorType = "" // prepareEvent rejects an unattributable event (spec 29 S8)

	require.Error(t, st.AppendEventAndRevoke(ctx, evt, fp, time.Now().Add(time.Hour), "superseded by renewal"))
	assert.Equal(t, int64(0), revocationRowCount(t, st, fp),
		"no revocation row for an event that was never appended")
}

// The read-side half of criterion 6. Writing the revocation in the same
// transaction is worthless if the gate does not see it until some later
// refresh, so this asserts the revocation is visible IMMEDIATELY — no refresh,
// no tick, no warm-up. The predecessor of this test asserted the opposite (that
// a fresh revocation was invisible until Refresh), which encoded the very
// staleness window this change exists to remove.
func TestRevocationChecker_NewRevocationIsVisibleImmediately(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := t.Context()

	c := store.NewRevocationChecker(st)
	const fp = "9988776655"

	revoked, err := c.IsRevoked(ctx, fp)
	require.NoError(t, err)
	require.False(t, revoked, "not revoked before the write")

	require.NoError(t, st.AppendEventAndRevoke(ctx,
		devEvent("01J0000000000000000000DEV4", eventtypes.DeviceDeleted), fp, time.Now().Add(time.Hour), "device deleted"))

	revoked, err = c.IsRevoked(ctx, fp)
	require.NoError(t, err)
	assert.True(t, revoked,
		"a committed revocation must be visible to the very next handshake, with no refresh in between")

	other, err := c.IsRevoked(ctx, "never-revoked")
	require.NoError(t, err)
	assert.False(t, other)
}

// A revoked fingerprint stays revoked no matter what not_after says.
//
// This replaces TestRevocationChecker_ExpiredRevocationIsNotReported, which
// asserted the opposite. That property was real but rested on a false premise:
// it argued an expired certificate is refused by TLS on validity alone, so
// reporting it revoked only muddles the logs. True — if one clock decides both.
// Two do. TLS validity is judged by the CONTROL host and not_after by the
// DATABASE, so a database running ahead calls the row expired while control
// still accepts the certificate, and the handshake succeeds. Clock drift
// between two machines was enough to un-revoke a certificate.
//
// The lookup no longer consults a clock at all, so the case that used to return
// "not revoked" now returns "revoked" — the conservative answer, and the one
// this test pins.
func TestRevocationChecker_RevocationSurvivesItsNotAfter(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := t.Context()

	const fp = "expired0001"
	// not_after already in the past — the shape a skewed database clock
	// produces for a certificate control still considers valid.
	require.NoError(t, st.AppendEventAndRevoke(ctx,
		devEvent("01J0000000000000000000DEV5", eventtypes.DeviceDeleted), fp, time.Now().Add(-time.Hour), "device deleted"))

	revoked, err := store.NewRevocationChecker(st).IsRevoked(ctx, fp)
	require.NoError(t, err)
	assert.True(t, revoked,
		"a listed fingerprint must report revoked regardless of not_after — otherwise a database clock "+
			"running ahead of control silently re-admits a revoked certificate")
}

// The retention sweep must actually remove expired rows: the table is called
// TTL-bounded, and every certificate rotation writes one, so an uncalled or
// non-functioning sweep means unbounded growth.
func TestDeleteExpiredRevocations_RemovesOnlyExpired(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := t.Context()

	const live = "livefp0001"
	const recentlyExpired = "recentfp01"
	const longExpired = "deadfp0001"
	require.NoError(t, st.AppendEventAndRevoke(ctx,
		devEvent("01J0000000000000000000DEV6", eventtypes.DeviceDeleted), live, time.Now().Add(time.Hour), "device deleted"))
	// Inside the skew grace: expired by the database's reckoning, but recently
	// enough that a clock difference could explain it.
	require.NoError(t, st.AppendEventAndRevoke(ctx,
		devEvent("01J0000000000000000000DEV8", eventtypes.DeviceDeleted), recentlyExpired, time.Now().Add(-time.Hour), "device deleted"))
	require.NoError(t, st.AppendEventAndRevoke(ctx,
		devEvent("01J0000000000000000000DEV7", eventtypes.DeviceDeleted), longExpired, time.Now().Add(-30*24*time.Hour), "device deleted"))

	n, err := st.DeleteExpiredRevocations(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "exactly the long-expired row is swept")
	assert.Equal(t, int64(1), revocationRowCount(t, st, live), "the live revocation must survive")
	assert.Equal(t, int64(1), revocationRowCount(t, st, recentlyExpired),
		"a just-expired revocation must survive the skew grace — deleting it is irreversible, and a database "+
			"clock ahead of control would drop a revocation control still needs")
	assert.Equal(t, int64(0), revocationRowCount(t, st, longExpired))
}
