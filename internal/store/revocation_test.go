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

func TestRevocationCache_FailsClosedUntilLoaded(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := t.Context()

	c := store.NewRevocationCache(st, nil)
	require.False(t, c.Loaded(),
		"a fresh cache must report unloaded so the handshake gate rejects rather than admitting blind")

	const fp = "9988776655"
	require.NoError(t, st.AppendEventAndRevoke(ctx,
		devEvent("01J0000000000000000000DEV4", eventtypes.DeviceDeleted), fp, time.Now().Add(time.Hour), "device deleted"))

	require.False(t, c.IsRevoked(fp), "not visible before the first refresh")
	require.NoError(t, c.Refresh(ctx))
	assert.True(t, c.Loaded())
	assert.True(t, c.IsRevoked(fp), "visible after refresh")
	assert.False(t, c.IsRevoked("never-revoked"))
}

// An expired revocation drops out of the snapshot: the certificate it names can
// no longer authenticate anything, so keeping the row would grow the list
// without bound for no security gain.
func TestRevocationCache_ExpiredRevocationLeavesTheSnapshot(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := t.Context()

	const fp = "expired0001"
	require.NoError(t, st.AppendEventAndRevoke(ctx,
		devEvent("01J0000000000000000000DEV5", eventtypes.DeviceDeleted), fp, time.Now().Add(-time.Hour), "device deleted"))

	c := store.NewRevocationCache(st, nil)
	require.NoError(t, c.Refresh(ctx))
	assert.False(t, c.IsRevoked(fp), "a revocation past its not_after must not stay in the snapshot")
}
