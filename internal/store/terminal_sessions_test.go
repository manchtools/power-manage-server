package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Integration tests for the terminal_sessions table + its sqlc
// queries. Cover the critical invariants of the rc7 reshape:
//
//   - Lifecycle Start creates a complete row.
//   - Chunks append to `input` and bump chunk_count.
//   - A chunk arriving before the lifecycle Start creates a
//     placeholder row that the Start-upsert then fills in without
//     clobbering already-accumulated stdin.
//   - Stopped / Terminated updates set the exit fields.
//   - Retention deletes rows by started_at cutoff.

func upsertStartParams(sessionID, deviceID, userID string) db.UpsertTerminalSessionStartParams {
	return db.UpsertTerminalSessionStartParams{
		SessionID: sessionID,
		DeviceID:  deviceID,
		UserID:    userID,
		TtyUser:   "pm-tty-" + userID,
		StartedAt: time.Now().UTC().Round(time.Microsecond),
		Cols:      80,
		Rows:      24,
	}
}

func TestTerminalSessions_StartCreatesRow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()

	sid := testutil.NewID()
	err := q.UpsertTerminalSessionStart(ctx, upsertStartParams(sid, "dev-1", "user-1"))
	require.NoError(t, err)

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, sid, row.SessionID)
	assert.Equal(t, "dev-1", row.DeviceID)
	assert.Equal(t, "user-1", row.UserID)
	assert.Equal(t, "pm-tty-user-1", row.TtyUser)
	assert.Equal(t, int32(80), row.Cols)
	assert.Equal(t, int32(24), row.Rows)
	assert.Nil(t, row.StoppedAt, "stopped_at should be null on a fresh start")
	assert.Equal(t, int32(0), row.ChunkCount)
	assert.Empty(t, row.Input, "no chunks yet")
}

func TestTerminalSessions_ChunkBeforeStartCreatesPlaceholder(t *testing.T) {
	// Covers the inbox-worker race: an AuditChunk task landing
	// before the TerminalSessionStarted event is processed. The
	// chunk handler must create a row on its own (minimally
	// populated) so the stdin isn't dropped. The later Start
	// upsert fills in the missing metadata without losing data.
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	err := q.AppendTerminalSessionChunk(ctx, db.AppendTerminalSessionChunkParams{
		SessionID: sid,
		DeviceID:  "dev-2",
		UserID:    "user-2",
		Input:     []byte("early\n"),
	})
	require.NoError(t, err)

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, "dev-2", row.DeviceID)
	assert.Equal(t, "user-2", row.UserID)
	assert.Empty(t, row.TtyUser, "tty_user stays empty until the Start upsert fills it")
	assert.Equal(t, int32(1), row.ChunkCount)
	assert.Equal(t, []byte("early\n"), row.Input)

	// Now the Start arrives — upsert must merge metadata without
	// overwriting the already-captured stdin.
	startParams := upsertStartParams(sid, "dev-2", "user-2")
	err = q.UpsertTerminalSessionStart(ctx, startParams)
	require.NoError(t, err)

	row, err = q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, "pm-tty-user-2", row.TtyUser, "Start upsert fills in tty_user")
	assert.Equal(t, int32(80), row.Cols)
	assert.Equal(t, int32(24), row.Rows)
	assert.Equal(t, int32(1), row.ChunkCount, "chunk_count preserved across Start upsert")
	assert.Equal(t, []byte("early\n"), row.Input, "stdin preserved across Start upsert")
}

func TestTerminalSessions_ChunksAppendInOrder(t *testing.T) {
	// Multiple chunks arriving in sequence must concatenate to
	// the exact byte stream, in order, and bump chunk_count once
	// per call.
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	err := q.UpsertTerminalSessionStart(ctx, upsertStartParams(sid, "dev-3", "user-3"))
	require.NoError(t, err)

	chunks := [][]byte{
		[]byte("ls -la\n"),
		[]byte("cat /etc/hostname\n"),
		[]byte("exit\n"),
	}
	for _, c := range chunks {
		err := q.AppendTerminalSessionChunk(ctx, db.AppendTerminalSessionChunkParams{
			SessionID: sid,
			DeviceID:  "dev-3",
			UserID:    "user-3",
			Input:     c,
		})
		require.NoError(t, err)
	}

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, int32(3), row.ChunkCount)
	assert.Equal(t, []byte("ls -la\ncat /etc/hostname\nexit\n"), row.Input)
}

func TestTerminalSessions_MarkStopped(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	require.NoError(t, q.UpsertTerminalSessionStart(ctx, upsertStartParams(sid, "dev-4", "user-4")))

	stoppedAt := time.Now().UTC().Round(time.Microsecond)
	exitCode := int32(0)
	err := q.MarkTerminalSessionStopped(ctx, db.MarkTerminalSessionStoppedParams{
		SessionID: sid,
		StoppedAt: &stoppedAt,
		ExitCode:  &exitCode,
	})
	require.NoError(t, err)

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	require.NotNil(t, row.ExitReason)
	assert.Equal(t, "stopped", *row.ExitReason)
	require.NotNil(t, row.ExitCode)
	assert.Equal(t, int32(0), *row.ExitCode)
	require.NotNil(t, row.StoppedAt)
	assert.WithinDuration(t, stoppedAt, *row.StoppedAt, time.Second)
}

func TestTerminalSessions_MarkTerminated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	require.NoError(t, q.UpsertTerminalSessionStart(ctx, upsertStartParams(sid, "dev-5", "user-5")))

	stoppedAt := time.Now().UTC().Round(time.Microsecond)
	terminatedBy := "admin-1"
	err := q.MarkTerminalSessionTerminated(ctx, db.MarkTerminalSessionTerminatedParams{
		SessionID:    sid,
		StoppedAt:    &stoppedAt,
		TerminatedBy: &terminatedBy,
	})
	require.NoError(t, err)

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	require.NotNil(t, row.ExitReason)
	assert.Equal(t, "terminated", *row.ExitReason)
	require.NotNil(t, row.TerminatedBy)
	assert.Equal(t, "admin-1", *row.TerminatedBy)
	assert.Nil(t, row.ExitCode, "terminated sessions do not carry an exit code")
}

func TestTerminalSessions_ListByDeviceOrdering(t *testing.T) {
	// Sessions for a device must come back newest-first, regardless
	// of the order they were INSERTed.
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	device := "dev-6"

	oldStart := time.Now().UTC().Add(-2 * time.Hour).Round(time.Microsecond)
	mid := time.Now().UTC().Add(-1 * time.Hour).Round(time.Microsecond)
	now := time.Now().UTC().Round(time.Microsecond)

	for i, start := range []time.Time{mid, oldStart, now} {
		p := upsertStartParams(testutil.NewID(), device, "user-6")
		p.StartedAt = start
		require.NoError(t, q.UpsertTerminalSessionStart(ctx, p), "seed %d", i)
	}

	rows, err := q.ListTerminalSessionsByDevice(ctx, db.ListTerminalSessionsByDeviceParams{
		DeviceID: device,
		Limit:    10,
		Offset:   0,
	})
	require.NoError(t, err)
	require.Len(t, rows, 3)
	// Newest first.
	assert.True(t, rows[0].StartedAt.After(rows[1].StartedAt), "rows[0] should be newer than rows[1]")
	assert.True(t, rows[1].StartedAt.After(rows[2].StartedAt), "rows[1] should be newer than rows[2]")
}

func TestTerminalSessions_RetentionDelete(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()

	old := upsertStartParams(testutil.NewID(), "dev-7", "user-7")
	old.StartedAt = time.Now().UTC().Add(-48 * time.Hour).Round(time.Microsecond)
	require.NoError(t, q.UpsertTerminalSessionStart(ctx, old))

	fresh := upsertStartParams(testutil.NewID(), "dev-7", "user-7")
	fresh.StartedAt = time.Now().UTC().Round(time.Microsecond)
	require.NoError(t, q.UpsertTerminalSessionStart(ctx, fresh))

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	err := q.DeleteTerminalSessionsBefore(ctx, cutoff)
	require.NoError(t, err)

	_, err = q.GetTerminalSession(ctx, old.SessionID)
	assert.Error(t, err, "old session should be deleted")
	_, err = q.GetTerminalSession(ctx, fresh.SessionID)
	assert.NoError(t, err, "fresh session must survive")
}
