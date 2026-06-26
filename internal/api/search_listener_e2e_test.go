package api_test

// End-to-end search-listener tests per manchtools/power-manage-server#115.
//
// The classifier-table tests in search_listener_test.go prove that
// AffectedSearchOps returns the right SearchAffected slice for each
// event type. They do NOT exercise the listener's runtime behaviour:
// loadSearchEntityData, cascadeIDsForRemove, the panic-recovery
// wrapper, the synchronous Asynq enqueue, or the error-handling on
// entity-not-found.
//
// These tests do, against a real Postgres testcontainer + an
// in-memory recording fake of api.SearchIndex. One test per scope
// fires a real event through st.AppendEvent and asserts the
// listener enqueued exactly the expected (op, scope, id, payload)
// triple. The cascade test exercises the GetReverseMembers →
// EnqueueRemove path; the not-found test exercises the silent skip
// when loadSearchEntityData reports not-found; the panic test
// exercises the recover wrapper inside fireListeners.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// discardLogger silences listener log output so test runs stay clean.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// =============================================================================
// Recording fake — implements api.SearchIndex
// =============================================================================

type reindexCall struct {
	Scope string
	ID    string
	Data  *taskqueue.SearchEntityData
}

type removeCall struct {
	Scope      string
	ID         string
	CascadeIDs []string
}

type fakeSearchIndex struct {
	mu sync.Mutex

	reindexed []reindexCall
	removed   []removeCall

	// reverse map keyed by scope+":"+id → cascade IDs returned by
	// GetReverseMembers. Empty key returns nil (the production behaviour
	// for scopes without reverse-member tracking).
	reverse map[string][]string

	// reindexErr / removeErr override the enqueue return value for
	// negative-path tests. Defaults to nil (success).
	reindexErr error
	removeErr  error

	// panicOnReindex flips the next EnqueueReindex call to panic.
	// Used to validate the listener is wrapped by store.fireListeners'
	// panic recovery and doesn't crash AppendEvent.
	panicOnReindex bool
}

func newFakeSearchIndex() *fakeSearchIndex {
	return &fakeSearchIndex{reverse: map[string][]string{}}
}

func (f *fakeSearchIndex) EnqueueReindex(_ context.Context, scope, id string, data *taskqueue.SearchEntityData) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panicOnReindex {
		f.panicOnReindex = false
		panic("fakeSearchIndex.EnqueueReindex: forced panic for recovery test")
	}
	f.reindexed = append(f.reindexed, reindexCall{Scope: scope, ID: id, Data: data})
	return f.reindexErr
}

func (f *fakeSearchIndex) EnqueueRemove(_ context.Context, scope, id string, cascadeIDs []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, removeCall{Scope: scope, ID: id, CascadeIDs: cascadeIDs})
	return f.removeErr
}

func (f *fakeSearchIndex) GetReverseMembers(_ context.Context, scope, id string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reverse[scope+":"+id]
}

func (f *fakeSearchIndex) lastReindex(t *testing.T) reindexCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.reindexed, "expected at least one EnqueueReindex call")
	return f.reindexed[len(f.reindexed)-1]
}

func (f *fakeSearchIndex) lastRemove(t *testing.T) removeCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.removed, "expected at least one EnqueueRemove call")
	return f.removed[len(f.removed)-1]
}

// reindexedScope reports whether (scope, id) was reindexed at least once.
func (f *fakeSearchIndex) reindexedScope(scope, id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.reindexed {
		if c.Scope == scope && c.ID == id {
			return true
		}
	}
	return false
}

func (f *fakeSearchIndex) reindexCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reindexed)
}

// setupListener wires the fake into the test store via a fresh
// PostgreSQL testcontainer. Returns the store + the fake so the
// caller can drive events and assert recorded calls.
func setupListener(t *testing.T) (*store.Store, *fakeSearchIndex) {
	t.Helper()
	st := testutil.SetupPostgres(t)
	t.Cleanup(func() { st.Close() })
	fake := newFakeSearchIndex()
	st.RegisterEventListener(api.SearchListener(st, fake, discardLogger()))
	return st, fake
}

// =============================================================================
// User scope
// =============================================================================

func TestSearchListener_UserCreated_Reindexes(t *testing.T) {
	st, fake := setupListener(t)
	userID := testutil.CreateTestUser(t, st, "alice@example.com", "pass", "viewer")

	last := fake.lastReindex(t)
	assert.Equal(t, search.ScopeUser, last.Scope)
	assert.Equal(t, userID, last.ID)
	require.NotNil(t, last.Data)
	assert.Equal(t, "alice@example.com", last.Data.Email)
}

// =============================================================================
// Device scope
// =============================================================================

func TestSearchListener_DeviceRegistered_Reindexes(t *testing.T) {
	st, fake := setupListener(t)
	deviceID := testutil.CreateTestDevice(t, st, "host-listener-1")

	last := fake.lastReindex(t)
	assert.Equal(t, search.ScopeDevice, last.Scope)
	assert.Equal(t, deviceID, last.ID)
	require.NotNil(t, last.Data)
	assert.Equal(t, "host-listener-1", last.Data.Hostname)
}

// =============================================================================
// DeviceGroup scope (incl. composite-StreamID member event)
// =============================================================================

func TestSearchListener_DeviceGroupCreated_Reindexes(t *testing.T) {
	st, fake := setupListener(t)
	groupID := testutil.CreateTestDeviceGroup(t, st, "u", "ops-east")

	last := fake.lastReindex(t)
	assert.Equal(t, search.ScopeDeviceGroup, last.Scope)
	assert.Equal(t, groupID, last.ID)
	require.NotNil(t, last.Data)
	assert.Equal(t, "ops-east", last.Data.Name)
}

func TestSearchListener_DeviceGroupMemberAdded_ReindexesGroup(t *testing.T) {
	st, fake := setupListener(t)
	groupID := testutil.CreateTestDeviceGroup(t, st, "u", "members-test")
	deviceID := testutil.CreateTestDevice(t, st, "host-member")

	before := fake.reindexCount()
	testutil.AddDeviceToTestGroup(t, st, "u", groupID, deviceID)

	// A DeviceGroupMemberAdded event reindexes the GROUP (member_count) AND the
	// affected DEVICE (its scope_group_ids changed, #7 spec 14).
	require.Greater(t, fake.reindexCount(), before, "membership change must trigger reindexes")
	assert.True(t, fake.reindexedScope(search.ScopeDeviceGroup, groupID), "group must be reindexed (member_count)")
	assert.True(t, fake.reindexedScope(search.ScopeDevice, deviceID), "affected device must be reindexed (scope_group_ids)")
}

// =============================================================================
// UserGroup scope (composite-StreamID prefix-split path)
// =============================================================================

func TestSearchListener_UserGroupMemberAdded_ReindexesGroupViaPrefixSplit(t *testing.T) {
	st, fake := setupListener(t)
	groupID := testutil.CreateTestUserGroup(t, st, "u", "engineers")
	userID := testutil.CreateTestUser(t, st, "bob@example.com", "pass", "viewer")

	before := fake.reindexCount()
	testutil.AddUserToTestGroup(t, st, "u", groupID, userID)

	// AddUserToTestGroup uses a composite stream id "<group>:<user>". The listener
	// splits on ':' to reindex the GROUP (member_count) AND the affected USER (its
	// scope_group_ids changed, #7 spec 14).
	require.Greater(t, fake.reindexCount(), before)
	assert.True(t, fake.reindexedScope(search.ScopeUserGroup, groupID), "group must be reindexed")
	assert.True(t, fake.reindexedScope(search.ScopeUser, userID), "affected user must be reindexed")
}

// =============================================================================
// ActionSet scope
// =============================================================================

func TestSearchListener_ActionSetCreated_Reindexes(t *testing.T) {
	st, fake := setupListener(t)
	setID := testutil.CreateTestActionSet(t, st, "u", "rollout-v1")

	last := fake.lastReindex(t)
	assert.Equal(t, search.ScopeActionSet, last.Scope)
	assert.Equal(t, setID, last.ID)
	require.NotNil(t, last.Data)
	assert.Equal(t, "rollout-v1", last.Data.Name)
}

// =============================================================================
// Definition scope
// =============================================================================

func TestSearchListener_DefinitionCreated_Reindexes(t *testing.T) {
	st, fake := setupListener(t)
	defID := testutil.CreateTestDefinition(t, st, "u", "baseline")

	last := fake.lastReindex(t)
	assert.Equal(t, search.ScopeDefinition, last.Scope)
	assert.Equal(t, defID, last.ID)
	require.NotNil(t, last.Data)
	assert.Equal(t, "baseline", last.Data.Name)
}

// =============================================================================
// Action scope
// =============================================================================

func TestSearchListener_ActionCreated_Reindexes(t *testing.T) {
	st, fake := setupListener(t)
	actionID := testutil.CreateTestAction(t, st, "u", "install-curl", 1) // ACTION_TYPE_PACKAGE

	last := fake.lastReindex(t)
	assert.Equal(t, search.ScopeAction, last.Scope)
	assert.Equal(t, actionID, last.ID)
	require.NotNil(t, last.Data)
	assert.Equal(t, "install-curl", last.Data.Name)
}

// =============================================================================
// Cascade-on-remove (Action / ActionSet / Definition)
// =============================================================================

func TestSearchListener_ActionDeleted_ResolvesCascadeAndEnqueuesRemove(t *testing.T) {
	st, fake := setupListener(t)
	actionID := testutil.CreateTestAction(t, st, "u", "doomed-action", 1)

	// Seed the fake so cascadeIDsForRemove returns a non-empty list
	// for the deleted action — this is the EnqueueRemove path the
	// production GetReverseMembers feeds.
	fake.reverse[search.ScopeAction+":"+actionID] = []string{"set-A", "set-B"}

	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "action", StreamID: actionID, EventType: string(eventtypes.ActionDeleted),
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	last := fake.lastRemove(t)
	assert.Equal(t, search.ScopeAction, last.Scope)
	assert.Equal(t, actionID, last.ID)
	assert.Equal(t, []string{"set-A", "set-B"}, last.CascadeIDs,
		"cascade IDs must be the GetReverseMembers result, passed through to EnqueueRemove")
}

// =============================================================================
// Loader-not-found contract
// =============================================================================

func TestSearchListener_EntityGoneBeforeReindex_SilentlySkips(t *testing.T) {
	st, fake := setupListener(t)

	// AppendEvent for an unknown user_id triggers the listener; the
	// loader reports not-found (store.IsNotFound); the listener logs at Debug and
	// MUST NOT enqueue. The reindex queue stays empty.
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user", StreamID: "01HXNONEXISTENT00000000000",
		EventType: string(eventtypes.UserEmailChanged),
		Data:      map[string]any{"email": "ghost@example.com"},
		ActorType: "system", ActorID: "test",
	}))

	assert.Zero(t, fake.reindexCount(),
		"listener must skip enqueue when the entity row is gone (not-found path)")
}

// =============================================================================
// Panic recovery contract
// =============================================================================

func TestSearchListener_PanicInListenerDoesNotCrashAppendEvent(t *testing.T) {
	st, fake := setupListener(t)
	fake.panicOnReindex = true

	// Even though the next listener call will panic, AppendEvent must
	// return cleanly because store.fireListeners wraps each listener
	// in a defer-recover. CreateTestUser asserts no error from the
	// AppendEvent under the hood.
	require.NotPanics(t, func() {
		_ = testutil.CreateTestUser(t, st, "panic-test@example.com", "pass", "viewer")
	})

	// Sanity: the panic consumed the panicOnReindex flag and the next
	// reindex (e.g., from a follow-up event) would proceed normally.
	assert.False(t, fake.panicOnReindex, "panic flag should reset after firing once")
}

// =============================================================================
// Loader error (non-NotFound) is logged, not enqueued
// =============================================================================

func TestSearchListener_EnqueueErrorIsSwallowed(t *testing.T) {
	st, fake := setupListener(t)
	fake.reindexErr = errors.New("simulated valkey timeout")

	// The listener must swallow enqueue errors (post-commit
	// notification contract — the periodic reconciler is the safety
	// net). AppendEvent returns success regardless.
	require.NotPanics(t, func() {
		_ = testutil.CreateTestUser(t, st, "err-test@example.com", "pass", "viewer")
	})
	// Although the fake returned an error, it was still called once.
	assert.Equal(t, 1, fake.reindexCount())
}
