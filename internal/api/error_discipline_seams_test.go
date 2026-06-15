package api

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// WS16 #8: AssignDevice discarded DB errors from its dedup lookups and
// proceeded blind on infra failure, which would re-emit duplicate
// DeviceAssigned events. The lookups must fail closed with CodeInternal and
// emit no event.

type failingAssignmentLister struct{}

func (failingAssignmentLister) ListDeviceAssignedUserIDs(context.Context, string) ([]string, error) {
	return nil, errors.New("simulated dedup DB failure")
}
func (failingAssignmentLister) ListDeviceAssignedGroupIDs(context.Context, string) ([]string, error) {
	return nil, errors.New("simulated dedup DB failure")
}

func TestAssignDevice_DedupLookupDBError_ReturnsInternal_NotBlind(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := NewDeviceHandler(st, enc, slog.Default(), NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "dedup-fail-host")
	targetUser := testutil.CreateTestUser(t, st, testutil.NewID()+"@target.com", "pass", "user")

	// Force the dedup lookups to error.
	h.assignmentLister = failingAssignmentLister{}

	// Count DeviceAssigned events before.
	before := deviceEventCount(t, st, deviceID)

	_, err := h.AssignDevice(ctx, connect.NewRequest(&pm.AssignDeviceRequest{
		DeviceId: deviceID,
		UserId:   targetUser,
	}))
	require.Error(t, err, "a dedup DB failure must abort the assignment")
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))

	after := deviceEventCount(t, st, deviceID)
	assert.Equal(t, before, after, "no DeviceAssigned event may be emitted when the dedup lookup failed")
}

// deviceEventCount counts events on a device stream (DeviceAssigned etc.).
func deviceEventCount(t *testing.T, st *store.Store, deviceID string) int {
	t.Helper()
	var n int
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		"SELECT count(*) FROM events WHERE stream_type='device' AND stream_id=$1", deviceID).Scan(&n))
	return n
}

// WS16 #9: a panic inside the detached settings fan-out goroutine must be
// recovered and logged, not propagate and crash the control process.

type panicSyncer struct{}

func (panicSyncer) SyncAllUsersSystemActions(context.Context) error {
	panic("simulated panic in settings fan-out")
}

func TestUpdateServerSettings_FanoutGoroutinePanic_DoesNotCrashProcess(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := NewSettingsHandler(st, slog.Default(), nil)

	done := make(chan struct{})
	h.onPropagationDone = func() { close(done) }
	h.systemActions = panicSyncer{} // panics when the fan-out reaches it

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Both flags false so only the (panicking) syncer runs — isolates the panic.
	resp, err := h.UpdateServerSettings(ctx, connect.NewRequest(&pm.UpdateServerSettingsRequest{
		UserProvisioningEnabled: false,
		SshAccessForAll:         false,
	}))
	require.NoError(t, err, "the RPC must still return success despite a fan-out panic")
	require.NotNil(t, resp)

	select {
	case <-done:
		// The goroutine finished — meaning the panic was recovered and the
		// process survived (a propagated panic would have killed the test binary).
	case <-time.After(5 * time.Second):
		t.Fatal("settings fan-out goroutine never completed — panic not recovered?")
	}
}
