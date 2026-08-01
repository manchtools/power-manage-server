package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/dispatch"
	"github.com/manchtools/power-manage/server/internal/store"
)

type committedWaker struct {
	store     *store.Store
	ids       []string
	committed bool
}

func (w *committedWaker) Wake(id string) bool {
	w.ids = append(w.ids, id)
	_, err := w.store.GetDelivery(context.Background(), id)
	w.committed = err == nil
	return false
}

func dispatchManifest() *pmv1.Manifest {
	actionID := newID()
	return &pmv1.Manifest{
		ManifestId: newID(),
		Provenance: &pmv1.ManifestProvenance{ActionId: actionID},
		Schedule:   &pmv1.ActionSchedule{},
		Occurrences: []*pmv1.ManifestOccurrence{{
			OccurrenceId: newID(),
			Action: &pmv1.Action{
				Id: &pmv1.ActionId{Value: actionID}, Type: pmv1.ActionType_ACTION_TYPE_SYNC,
				DesiredState: pmv1.DesiredState_DESIRED_STATE_PRESENT, TimeoutSeconds: 60,
			},
			OnFailure: pmv1.OnFailure_ON_FAILURE_CONTINUE,
		}},
	}
}

func TestDispatchSubmission_CommitsManifestExecutionsAndAuditBeforeWake(t *testing.T) {
	st, raw := setupPostgres(t)
	deviceID := seedDevice(t, raw)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	waker := &committedWaker{store: st}
	service := dispatch.New(dispatch.Config{Store: st, Waker: waker, Now: func() time.Time { return now }})
	manifest := dispatchManifest()
	op := mutationOp()
	op.RequestDescriptor = "/powermanage.v1.ControlService/DispatchInstantAction"
	op.AuthorizationDetail = "DispatchInstantAction"

	result, err := service.Submit(context.Background(), dispatch.SubmitParams{
		Operation: op, DeviceID: deviceID,
		Manifests: []dispatch.ManifestInput{{Manifest: manifest}},
	})
	require.NoError(t, err)
	require.Len(t, result.DeliveryIDs, 1)
	require.Len(t, result.Executions, 1)
	assert.Equal(t, manifest.Occurrences[0].OccurrenceId, result.Executions[0].ID)
	assert.Equal(t, "pending", result.Executions[0].Status)
	assert.Nil(t, result.Executions[0].ActionID, "an inline/instant action is not a catalog reference")
	assert.Equal(t, result.DeliveryIDs, waker.ids)
	assert.True(t, waker.committed, "the lossy wake must happen only after commit")

	deliveryRow, err := st.GetDelivery(context.Background(), result.DeliveryIDs[0])
	require.NoError(t, err)
	assert.Equal(t, "PENDING", deliveryRow.State)
	operation, err := latestOperationFor(t, st, raw, op.RequestDescriptor)
	require.NoError(t, err)
	require.NotNil(t, deliveryRow.OperationID)
	assert.Equal(t, operation.OperationID, *deliveryRow.OperationID)
	effects, err := st.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 2)
	assert.ElementsMatch(t, []string{"delivery", "execution"},
		[]string{effects[0].ResourceType, effects[1].ResourceType})
}

func TestDispatchSubmission_SchedulingAndAuditFailure(t *testing.T) {
	st, raw := setupPostgres(t)
	deviceID := seedDevice(t, raw)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	waker := &committedWaker{store: st}
	service := dispatch.New(dispatch.Config{Store: st, Waker: waker, Now: func() time.Time { return now }})
	scheduledFor := now.Add(2 * time.Hour)
	op := mutationOp()
	op.RequestDescriptor = "/powermanage.v1.ControlService/DispatchAction"

	result, err := service.Submit(context.Background(), dispatch.SubmitParams{
		Operation: op, DeviceID: deviceID, ScheduledFor: &scheduledFor,
		Manifests: []dispatch.ManifestInput{{Manifest: dispatchManifest()}},
	})
	require.NoError(t, err)
	assert.Equal(t, "scheduled", result.Executions[0].Status)
	assert.True(t, result.Executions[0].ScheduledFor.Equal(scheduledFor))
	deliveryRow, err := st.GetDelivery(context.Background(), result.DeliveryIDs[0])
	require.NoError(t, err)
	assert.True(t, deliveryRow.AvailableAt.Equal(scheduledFor))

	_, err = raw.Exec(context.Background(), `
		ALTER TABLE audit_operations ADD CONSTRAINT reject_dispatch_submission_audit
		CHECK (request_descriptor <> 'dispatch.rollback') NOT VALID`)
	require.NoError(t, err)
	beforeWakes := len(waker.ids)
	op = mutationOp()
	op.RequestDescriptor = "dispatch.rollback"
	failedManifest := dispatchManifest()
	_, err = service.Submit(context.Background(), dispatch.SubmitParams{
		Operation: op, DeviceID: deviceID,
		Manifests: []dispatch.ManifestInput{{Manifest: failedManifest}},
	})
	require.Error(t, err)
	assert.Len(t, waker.ids, beforeWakes, "an uncommitted delivery must never wake")
	_, err = st.GetExecution(context.Background(), failedManifest.Occurrences[0].OccurrenceId)
	assert.True(t, store.IsNotFound(err), "audit failure must roll the execution back")
}
