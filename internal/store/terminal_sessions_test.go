package store_test

import (
	"bytes"
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
//   - Chunks append to `input`, bump chunk_count, and track
//     last_sequence for idempotency.
//   - A chunk arriving before the lifecycle Start creates a
//     placeholder row that the Start-upsert then fills in
//     without clobbering already-accumulated stdin.
//   - Duplicate or out-of-order chunk sequences are rejected
//     (last_sequence guard).
//   - Oversized input clamps at the 8 MiB cap and flips
//     input_truncated.
//   - Stopped / Terminated upserts create a row from scratch
//     when neither Start nor any chunk preceded them.
//   - Retention deletes rows by started_at cutoff.

// inputCapBytes mirrors the hard-coded 8 MiB cap in the append
// query. Centralised here so the test is explicit about the bound
// it asserts.
const inputCapBytes = 8 * 1024 * 1024

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

func chunkParams(sessionID, deviceID, userID string, data []byte, seq int64) db.AppendTerminalSessionChunkParams {
	return db.AppendTerminalSessionChunkParams{
		SessionID: sessionID,
		DeviceID:  deviceID,
		UserID:    userID,
		Input:     data,
		Sequence:  seq,
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
	assert.False(t, row.InputTruncated)
	assert.Equal(t, int64(0), row.LastSequence)
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

	err := q.AppendTerminalSessionChunk(ctx, chunkParams(sid, "dev-2", "user-2", []byte("early\n"), 1))
	require.NoError(t, err)

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, "dev-2", row.DeviceID)
	assert.Equal(t, "user-2", row.UserID)
	assert.Empty(t, row.TtyUser, "tty_user stays empty until the Start upsert fills it")
	assert.Equal(t, int32(1), row.ChunkCount)
	assert.Equal(t, int64(1), row.LastSequence)
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
	assert.Equal(t, int64(1), row.LastSequence, "last_sequence preserved across Start upsert")
}

func TestTerminalSessions_ChunksAppendInOrder(t *testing.T) {
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
	for i, c := range chunks {
		err := q.AppendTerminalSessionChunk(ctx, chunkParams(sid, "dev-3", "user-3", c, int64(i+1)))
		require.NoError(t, err)
	}

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, int32(3), row.ChunkCount)
	assert.Equal(t, int64(3), row.LastSequence)
	assert.Equal(t, []byte("ls -la\ncat /etc/hostname\nexit\n"), row.Input)
}

func TestTerminalSessions_DuplicateSequenceIsNoop(t *testing.T) {
	// Covers the Asynq redelivery case. The same chunk (same
	// sequence) showing up twice must be a no-op, not a
	// double-append. Otherwise a retry-after-partial-success
	// corrupts `input` and bumps chunk_count.
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	require.NoError(t, q.UpsertTerminalSessionStart(ctx, upsertStartParams(sid, "dev-dup", "user-dup")))

	err := q.AppendTerminalSessionChunk(ctx, chunkParams(sid, "dev-dup", "user-dup", []byte("hello\n"), 1))
	require.NoError(t, err)
	err = q.AppendTerminalSessionChunk(ctx, chunkParams(sid, "dev-dup", "user-dup", []byte("hello\n"), 1))
	require.NoError(t, err, "duplicate-sequence must be idempotent, not error")

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello\n"), row.Input, "redelivered chunk must not append twice")
	assert.Equal(t, int32(1), row.ChunkCount, "chunk_count must not inflate on redelivery")
	assert.Equal(t, int64(1), row.LastSequence)
}

func TestTerminalSessions_OutOfOrderSequenceRejected(t *testing.T) {
	// If chunk 5 arrives after chunk 6 (rare but possible with
	// worker-level reorder), the 5 must be rejected rather than
	// inserted out of order. We prefer dropping a stray late
	// chunk to corrupting the assembled stream.
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	require.NoError(t, q.UpsertTerminalSessionStart(ctx, upsertStartParams(sid, "dev-ooo", "user-ooo")))

	require.NoError(t, q.AppendTerminalSessionChunk(ctx, chunkParams(sid, "dev-ooo", "user-ooo", []byte("newer"), 6)))
	err := q.AppendTerminalSessionChunk(ctx, chunkParams(sid, "dev-ooo", "user-ooo", []byte("older"), 5))
	require.NoError(t, err, "late-arriving old chunk must not error; the guard no-ops it")

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, []byte("newer"), row.Input, "older chunk must be dropped, not merged")
	assert.Equal(t, int64(6), row.LastSequence)
	assert.Equal(t, int32(1), row.ChunkCount, "chunk_count only bumps on accepted chunks")
}

func TestTerminalSessions_InputCapClampsAndFlagsTruncation(t *testing.T) {
	// Covers the 8 MiB cap. A single chunk that would push
	// `input` past the cap is clamped to the remaining capacity,
	// and input_truncated flips to true. Subsequent chunks after
	// the cap fully clamp to zero bytes but still count.
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	require.NoError(t, q.UpsertTerminalSessionStart(ctx, upsertStartParams(sid, "dev-cap", "user-cap")))

	// First chunk fills the cap exactly minus 100 bytes.
	under := bytes.Repeat([]byte{'A'}, inputCapBytes-100)
	require.NoError(t, q.AppendTerminalSessionChunk(ctx, chunkParams(sid, "dev-cap", "user-cap", under, 1)))

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, inputCapBytes-100, len(row.Input))
	assert.False(t, row.InputTruncated, "still under the cap; no truncation yet")

	// Second chunk would push 150 bytes past the cap — clamp to
	// remaining 100 and flip the flag.
	over := bytes.Repeat([]byte{'B'}, 150)
	require.NoError(t, q.AppendTerminalSessionChunk(ctx, chunkParams(sid, "dev-cap", "user-cap", over, 2)))

	row, err = q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, inputCapBytes, len(row.Input), "input capped at the 8 MiB limit")
	assert.True(t, row.InputTruncated, "truncation flag must be set on the overflow")
	assert.Equal(t, int32(2), row.ChunkCount)

	// Third chunk after the cap clamps to zero bytes, but
	// chunk_count and last_sequence still advance.
	require.NoError(t, q.AppendTerminalSessionChunk(ctx, chunkParams(sid, "dev-cap", "user-cap", []byte("extra"), 3)))
	row, err = q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, inputCapBytes, len(row.Input), "no further growth past the cap")
	assert.True(t, row.InputTruncated)
	assert.Equal(t, int32(3), row.ChunkCount)
	assert.Equal(t, int64(3), row.LastSequence)
}

func TestTerminalSessions_OversizedFirstChunkClampsOnInsert(t *testing.T) {
	// Pathological first chunk: larger than the entire cap,
	// arriving before any Start. The INSERT branch must clamp
	// to the cap and set input_truncated from the get-go.
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	payload := bytes.Repeat([]byte{'X'}, inputCapBytes+1024)
	require.NoError(t, q.AppendTerminalSessionChunk(ctx, chunkParams(sid, "dev-big", "user-big", payload, 1)))

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, inputCapBytes, len(row.Input))
	assert.True(t, row.InputTruncated)
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
		DeviceID:  "dev-4",
		UserID:    "user-4",
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

func TestTerminalSessions_MarkStoppedCreatesRowWhenMissing(t *testing.T) {
	// Covers the worst-case orphan: neither the Start upsert nor
	// any chunk landed, then Stop fires. The upsert-form of
	// MarkTerminalSessionStopped must still materialise a row so
	// the session appears in history rather than disappearing.
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	stoppedAt := time.Now().UTC().Round(time.Microsecond)
	exitCode := int32(0)
	err := q.MarkTerminalSessionStopped(ctx, db.MarkTerminalSessionStoppedParams{
		SessionID: sid,
		StoppedAt: &stoppedAt,
		ExitCode:  &exitCode,
		DeviceID:  "dev-orphan",
		UserID:    "user-orphan",
	})
	require.NoError(t, err)

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err, "stop must create the row when nothing came before")
	assert.Equal(t, "dev-orphan", row.DeviceID)
	assert.Equal(t, "user-orphan", row.UserID)
	require.NotNil(t, row.ExitReason)
	assert.Equal(t, "stopped", *row.ExitReason)
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
		DeviceID:     "dev-5",
		UserID:       "user-5",
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

func TestTerminalSessions_FirstFinalizerWins_StopThenTerminate(t *testing.T) {
	// Race: the bridge already emitted a graceful Stop, then an
	// admin Terminate arrives shortly after. The subsequent
	// Terminate must be a no-op — exit_reason stays 'stopped',
	// the recorded exit_code survives, and terminated_by stays
	// NULL so the audit record reflects the actual session end.
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	require.NoError(t, q.UpsertTerminalSessionStart(ctx, upsertStartParams(sid, "dev-race", "user-race")))

	stoppedAt := time.Now().UTC().Round(time.Microsecond)
	exitCode := int32(0)
	require.NoError(t, q.MarkTerminalSessionStopped(ctx, db.MarkTerminalSessionStoppedParams{
		SessionID: sid,
		StoppedAt: &stoppedAt,
		ExitCode:  &exitCode,
		DeviceID:  "dev-race",
		UserID:    "user-race",
	}))

	// Admin Terminate arrives late — guard makes it a no-op.
	laterAt := stoppedAt.Add(time.Second)
	terminatedBy := "admin-late"
	require.NoError(t, q.MarkTerminalSessionTerminated(ctx, db.MarkTerminalSessionTerminatedParams{
		SessionID:    sid,
		StoppedAt:    &laterAt,
		TerminatedBy: &terminatedBy,
		DeviceID:     "dev-race",
		UserID:       "user-race",
	}))

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	require.NotNil(t, row.ExitReason)
	assert.Equal(t, "stopped", *row.ExitReason, "first finalizer wins; late Terminate must not flip reason")
	require.NotNil(t, row.ExitCode)
	assert.Equal(t, int32(0), *row.ExitCode, "exit_code from the Stop survives")
	assert.Nil(t, row.TerminatedBy, "no stale terminated_by next to a stopped exit_reason")
	require.NotNil(t, row.StoppedAt)
	assert.WithinDuration(t, stoppedAt, *row.StoppedAt, time.Second, "stopped_at not overwritten by the no-op Terminate")
}

func TestTerminalSessions_FirstFinalizerWins_TerminateThenStop(t *testing.T) {
	// Opposite race: admin Terminate lands first, then the
	// bridge's own Stop event catches up. The Stop must be a
	// no-op — exit_reason stays 'terminated', terminated_by
	// survives, and exit_code stays NULL (the test at
	// MarkTerminated already asserts "terminated sessions do
	// not carry an exit code"; this case enforces the same
	// invariant under the race).
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	require.NoError(t, q.UpsertTerminalSessionStart(ctx, upsertStartParams(sid, "dev-race2", "user-race2")))

	terminatedAt := time.Now().UTC().Round(time.Microsecond)
	terminatedBy := "admin-first"
	require.NoError(t, q.MarkTerminalSessionTerminated(ctx, db.MarkTerminalSessionTerminatedParams{
		SessionID:    sid,
		StoppedAt:    &terminatedAt,
		TerminatedBy: &terminatedBy,
		DeviceID:     "dev-race2",
		UserID:       "user-race2",
	}))

	// Late graceful Stop — guard makes it a no-op.
	laterAt := terminatedAt.Add(time.Second)
	exitCode := int32(0)
	require.NoError(t, q.MarkTerminalSessionStopped(ctx, db.MarkTerminalSessionStoppedParams{
		SessionID: sid,
		StoppedAt: &laterAt,
		ExitCode:  &exitCode,
		DeviceID:  "dev-race2",
		UserID:    "user-race2",
	}))

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err)
	require.NotNil(t, row.ExitReason)
	assert.Equal(t, "terminated", *row.ExitReason, "first finalizer wins; late Stop must not flip reason")
	require.NotNil(t, row.TerminatedBy)
	assert.Equal(t, "admin-first", *row.TerminatedBy, "terminated_by from the Terminate survives")
	assert.Nil(t, row.ExitCode, "no stale exit_code next to a terminated exit_reason")
	require.NotNil(t, row.StoppedAt)
	assert.WithinDuration(t, terminatedAt, *row.StoppedAt, time.Second, "stopped_at not overwritten by the no-op Stop")
}

func TestTerminalSessions_MarkTerminatedCreatesRowWhenMissing(t *testing.T) {
	// Same orphan coverage as MarkStopped — admin Terminate must
	// materialise history even when nothing else created the row.
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	q := st.Queries()
	sid := testutil.NewID()

	stoppedAt := time.Now().UTC().Round(time.Microsecond)
	terminatedBy := "admin-orphan"
	err := q.MarkTerminalSessionTerminated(ctx, db.MarkTerminalSessionTerminatedParams{
		SessionID:    sid,
		StoppedAt:    &stoppedAt,
		TerminatedBy: &terminatedBy,
		DeviceID:     "dev-term-orphan",
		UserID:       "user-term-orphan",
	})
	require.NoError(t, err)

	row, err := q.GetTerminalSession(ctx, sid)
	require.NoError(t, err, "terminate must create the row when nothing came before")
	assert.Equal(t, "dev-term-orphan", row.DeviceID)
	assert.Equal(t, "user-term-orphan", row.UserID)
	require.NotNil(t, row.ExitReason)
	assert.Equal(t, "terminated", *row.ExitReason)
	require.NotNil(t, row.TerminatedBy)
	assert.Equal(t, "admin-orphan", *row.TerminatedBy)
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
