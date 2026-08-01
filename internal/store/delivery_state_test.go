package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/delivery"
	"github.com/manchtools/power-manage/server/internal/store"
)

type deliveryFixture struct {
	t          *testing.T
	store      *store.Store
	raw        *pgxpool.Pool
	now        time.Time
	deviceID   string
	manifest   *pmv1.Manifest
	deliveryID string
	service    *delivery.Service
}

func newDeliveryFixture(t *testing.T) *deliveryFixture {
	t.Helper()
	st, raw := setupPostgres(t)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	deviceID := seedDevice(t, raw)
	actionID, manifestID := newID(), newID()
	manifest := &pmv1.Manifest{
		ManifestId: manifestID,
		Provenance: &pmv1.ManifestProvenance{ActionId: actionID},
		Schedule:   &pmv1.ActionSchedule{RunOnAssign: true},
		Occurrences: []*pmv1.ManifestOccurrence{{
			OccurrenceId: newID(),
			Action: &pmv1.Action{
				Id: &pmv1.ActionId{Value: actionID}, Type: pmv1.ActionType_ACTION_TYPE_REBOOT,
			},
		}},
	}
	op := mutationOp()
	op.OperationID = newID()
	op.RequestDescriptor = "powermanage.v1.ControlService/DispatchAction"
	var deliveryID string
	_, err := st.WithAudit(context.Background(), op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		var err error
		deliveryID, err = delivery.InsertInTx(ctx, tx, rec, delivery.InsertParams{
			OperationID: op.OperationID, DeviceID: deviceID, Manifest: manifest, AvailableAt: now,
		})
		return err
	})
	require.NoError(t, err)
	return &deliveryFixture{
		t: t, store: st, raw: raw, now: now, deviceID: deviceID, manifest: manifest, deliveryID: deliveryID,
		service: delivery.New(delivery.Config{Store: st, Now: func() time.Time { return now }}),
	}
}

func TestDelivery_InsertCommitsCompleteManifestWithAudit(t *testing.T) {
	f := newDeliveryFixture(t)
	row, err := f.store.GetDelivery(context.Background(), f.deliveryID)
	require.NoError(t, err)
	assert.Equal(t, delivery.StatePending, row.State)
	assert.Equal(t, f.deviceID, row.DeviceID)
	assert.Equal(t, f.manifest.ManifestId, row.ManifestID)
	require.NotNil(t, row.OperationID)

	var stored pmv1.Manifest
	require.NoError(t, protojson.Unmarshal(row.Manifest, &stored))
	assert.True(t, proto.Equal(f.manifest, &stored), "the durable row must carry the complete manifest")
	effects, err := f.store.ListAuditEffects(context.Background(), *row.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 1)
	assert.Equal(t, f.deliveryID, effects[0].ResourceID)
	assert.Equal(t, "CREATE", effects[0].Action)
}

func TestDelivery_InsertRejectsAmbiguousOrDuplicateManifestIdentity(t *testing.T) {
	f := newDeliveryFixture(t)
	tests := map[string]func(*pmv1.Manifest){
		"ambiguous provenance": func(manifest *pmv1.Manifest) {
			manifest.Provenance.ActionSetId = newID()
		},
		"duplicate occurrence": func(manifest *pmv1.Manifest) {
			manifest.Occurrences = append(manifest.Occurrences, proto.Clone(manifest.Occurrences[0]).(*pmv1.ManifestOccurrence))
		},
		"missing nested action id": func(manifest *pmv1.Manifest) {
			manifest.Occurrences[0].Action.Id.Value = ""
		},
	}
	for name, breakManifest := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := proto.Clone(f.manifest).(*pmv1.Manifest)
			manifest.ManifestId = newID()
			breakManifest(manifest)
			op := mutationOp()
			op.OperationID = newID()
			_, err := f.store.WithAudit(context.Background(), op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
				_, err := delivery.InsertInTx(ctx, tx, rec, delivery.InsertParams{
					OperationID: op.OperationID, DeviceID: f.deviceID, Manifest: manifest, AvailableAt: f.now,
				})
				return err
			})
			assert.ErrorIs(t, err, delivery.ErrInvalidInput)
		})
	}
	var count int
	require.NoError(t, f.raw.QueryRow(context.Background(), `SELECT count(*) FROM deliveries`).Scan(&count))
	assert.Equal(t, 1, count, "rejected manifests must not create delivery rows")
}

func TestDelivery_PushEpochAndReceiptStateMachine(t *testing.T) {
	f := newDeliveryFixture(t)
	ctx := context.Background()

	changed, err := f.service.MarkPushed(ctx, f.deliveryID, f.deviceID, 7)
	require.NoError(t, err)
	assert.True(t, changed)
	changed, err = f.service.MarkPushed(ctx, f.deliveryID, f.deviceID, 3)
	assert.ErrorIs(t, err, delivery.ErrStaleEpoch)
	assert.False(t, changed)

	changed, err = f.service.AcknowledgeReceipt(ctx, f.deliveryID, f.deviceID)
	require.NoError(t, err)
	assert.True(t, changed)
	changed, err = f.service.AcknowledgeReceipt(ctx, f.deliveryID, f.deviceID)
	require.NoError(t, err)
	assert.False(t, changed, "receipt replay must be absorbed")

	changed, err = f.service.Complete(ctx, f.deliveryID, f.deviceID, f.manifest.ManifestId, delivery.StateSucceeded, "OK")
	require.NoError(t, err)
	assert.True(t, changed)
	changed, err = f.service.Complete(ctx, f.deliveryID, f.deviceID, f.manifest.ManifestId, delivery.StateSucceeded, "OK")
	require.NoError(t, err)
	assert.False(t, changed, "result replay must be absorbed")

	row, err := f.store.GetDelivery(ctx, f.deliveryID)
	require.NoError(t, err)
	assert.Equal(t, delivery.StateSucceeded, row.State)
	assert.Equal(t, int64(7), row.PushEpoch)
	assert.Equal(t, int32(1), row.AttemptCount, "a refused stale push must not count as an attempt")
	var actions []string
	require.NoError(t, f.raw.QueryRow(ctx, `
		SELECT array_agg(action ORDER BY chain_seq)
		FROM audit_effects WHERE resource_type = 'delivery' AND resource_id = $1
	`, f.deliveryID).Scan(&actions))
	assert.Equal(t, []string{"CREATE", "PUSH", "ACK", "RESULT"}, actions)
}

func TestDelivery_RejectsOutOfOrderAndMismatchedFrames(t *testing.T) {
	f := newDeliveryFixture(t)
	ctx := context.Background()

	changed, err := f.service.AcknowledgeReceipt(ctx, f.deliveryID, f.deviceID)
	assert.ErrorIs(t, err, delivery.ErrInvalidTransition)
	assert.False(t, changed)
	changed, err = f.service.MarkPushed(ctx, f.deliveryID, newID(), 1)
	assert.ErrorIs(t, err, delivery.ErrWrongDevice)
	assert.False(t, changed)

	changed, err = f.service.MarkPushed(ctx, f.deliveryID, f.deviceID, 1)
	require.NoError(t, err)
	assert.True(t, changed)
	changed, err = f.service.AcknowledgeReceipt(ctx, f.deliveryID, f.deviceID)
	require.NoError(t, err)
	assert.True(t, changed)
	changed, err = f.service.Complete(ctx, f.deliveryID, f.deviceID, newID(), delivery.StateSucceeded, "OK")
	assert.ErrorIs(t, err, delivery.ErrWrongManifest)
	assert.False(t, changed)
}

func TestDelivery_ReceiptAuditFailureRollsBackState(t *testing.T) {
	f := newDeliveryFixture(t)
	ctx := context.Background()
	_, err := f.service.MarkPushed(ctx, f.deliveryID, f.deviceID, 1)
	require.NoError(t, err)

	_, err = f.raw.Exec(ctx, `ALTER TABLE audit_effects ADD CONSTRAINT reject_delivery_ack CHECK (action <> 'ACK')`)
	require.NoError(t, err)

	changed, err := f.service.AcknowledgeReceipt(ctx, f.deliveryID, f.deviceID)
	require.Error(t, err)
	assert.False(t, changed)
	row, getErr := f.store.GetDelivery(ctx, f.deliveryID)
	require.NoError(t, getErr)
	assert.Equal(t, delivery.StatePushed, row.State, "a failed audit insert must roll the delivery state back")
}
