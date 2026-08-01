package device

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

var errRevocationStateChanged = errors.New("LUKS revocation state changed")

// RevokeLuksDeviceKey commits the operator's intent and then sends the instant
// action over the device's authenticated mTLS stream. No queue or application
// signature is involved: the stream already supplies peer authentication,
// confidentiality, integrity, ordering, and replay protection.
func (h *Handlers) RevokeLuksDeviceKey(ctx context.Context, req *connect.Request[pmv1.RevokeLuksDeviceKeyRequest]) (*connect.Response[pmv1.RevokeLuksDeviceKeyResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.mutationDevice(ctx, "RevokeLuksDeviceKey", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	target, err := h.store.GetLuksRevocationTarget(ctx, req.Msg.DeviceId, req.Msg.ActionId)
	if err != nil {
		return nil, h.internal(ctx, "read LUKS revocation target", err)
	}
	switch {
	case target.KeyCount == 0:
		return nil, notFound(ctx, errLuksKeyNotFound, "LUKS key not found")
	case target.DispatchPending:
		return nil, rpcError(ctx, errRevocationPending, connect.CodeFailedPrecondition, "LUKS key revocation is already pending")
	case target.AlreadyRevoked:
		return nil, rpcError(ctx, errAlreadyRevoked, connect.CodeFailedPrecondition, "LUKS key is already revoked")
	}

	revocationID := ulid.Make().String()
	requestedAt := h.now().UTC()
	record, err := h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRevokeLuksDeviceKeyProcedure, "RevokeLuksDeviceKey"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			rows, err := tx.MarkLuksKeyRevocationDispatched(ctx, db.MarkLuksKeyRevocationDispatchedParams{
				RevocationAt: &requestedAt, DeviceID: req.Msg.DeviceId, ActionID: req.Msg.ActionId,
			})
			if err != nil {
				return fmt.Errorf("mark LUKS revocation dispatched: %w", err)
			}
			if rows != target.KeyCount {
				return errRevocationStateChanged
			}
			rec.Effect(luksRevocationEffect(req.Msg.ActionId, "DISPATCH", store.EffectApplied, rows, "revocation_at", "revocation_status"))
			return nil
		})
	if err != nil {
		if errors.Is(err, errRevocationStateChanged) {
			return nil, rpcError(ctx, errRevocationPending, connect.CodeFailedPrecondition, "LUKS key revocation state changed")
		}
		return nil, h.internal(ctx, "commit LUKS revocation", err)
	}

	err = h.agentSender.Send(req.Msg.DeviceId, &pmv1.ServerMessage{
		Id: revocationID,
		Payload: &pmv1.ServerMessage_RevokeLuksDeviceKey{
			RevokeLuksDeviceKey: &pmv1.RevokeLuksDeviceKey{ActionId: req.Msg.ActionId},
		},
	})
	if err == nil {
		return connect.NewResponse(&pmv1.RevokeLuksDeviceKeyResponse{}), nil
	}

	failedAt := h.now().UTC()
	_, auditErr := h.store.WithAuditEffects(ctx, record.OperationID,
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			rows, updateErr := tx.MarkLuksKeyRevocationDispatchFailed(ctx, db.MarkLuksKeyRevocationDispatchFailedParams{
				RevocationAt: &failedAt, DeviceID: req.Msg.DeviceId, ActionID: req.Msg.ActionId,
			})
			if updateErr != nil {
				return fmt.Errorf("mark LUKS revocation dispatch failed: %w", updateErr)
			}
			rec.Effect(luksRevocationEffect(req.Msg.ActionId, "DISPATCH", store.EffectFailed, rows,
				"revocation_at", "revocation_error", "revocation_status"))
			return nil
		})
	if auditErr != nil {
		return nil, h.internal(ctx, "record LUKS revocation dispatch failure", auditErr)
	}
	h.logger.Warn("LUKS revocation device unavailable", "device_id", req.Msg.DeviceId, "error", err)
	return nil, rpcError(ctx, errDeviceUnavailable, connect.CodeUnavailable, "device is unavailable")
}

// CompleteLuksKeyRevocation applies an agent result directly. A replay or stale
// result updates no row but is still recorded as rejected audit evidence.
func (h *Handlers) CompleteLuksKeyRevocation(ctx context.Context, deviceID string, result *pmv1.RevokeLuksDeviceKeyResult) error {
	if _, err := ulid.ParseStrict(deviceID); err != nil {
		return fmt.Errorf("invalid device id: %w", err)
	}
	if result == nil {
		return errors.New("LUKS revocation result is required")
	}
	if _, err := ulid.ParseStrict(result.ActionId); err != nil {
		return fmt.Errorf("invalid action id: %w", err)
	}
	if len(result.Error) > 1024 {
		return errors.New("LUKS revocation error exceeds 1024 bytes")
	}

	status := "success"
	var resultError *string
	if !result.Success {
		status = "failed"
		resultError = &result.Error
	}
	completedAt := h.now().UTC()
	op := store.AuditOperation{
		Class: store.ClassMutation, ActorType: "agent", ActorID: deviceID, Origin: "agent_stream",
		RequestDescriptor:    "powermanage.v1.AgentService.Stream/RevokeLuksDeviceKeyResult",
		AuthorizationOutcome: store.AuthorizationAllowed, AuthorizationDetail: "device_mtls",
		Result: store.ResultSuccess, ResultCode: "OK",
	}
	_, err := h.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		rows, err := tx.CompleteLuksKeyRevocation(ctx, db.CompleteLuksKeyRevocationParams{
			RevocationStatus: &status, RevocationError: resultError, RevocationAt: &completedAt,
			DeviceID: deviceID, ActionID: result.ActionId,
		})
		if err != nil {
			return fmt.Errorf("complete LUKS revocation: %w", err)
		}
		outcome := store.EffectApplied
		if rows == 0 {
			outcome = store.EffectRejected
		}
		rec.Effect(luksRevocationEffect(result.ActionId, "COMPLETE", outcome, rows,
			"revocation_at", "revocation_error", "revocation_status"))
		return nil
	})
	return err
}

func luksRevocationEffect(actionID, action string, outcome store.EffectOutcome, rows int64, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "luks_key_action", ResourceID: actionID, Action: action, Outcome: outcome,
		ChangedFields: fields, AfterCount: &rows,
	}
}
