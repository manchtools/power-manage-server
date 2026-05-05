package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// LuksKeyListener returns a store.EventListener that applies every
// LUKS-key event the deleted PL/pgSQL project_luks_key_event handled.
// Replaces the four-case dispatcher with one switch in Go:
//
//   - LuksKeyRotated: 3 writes (mark previous not-current, insert
//     new, trim to last 3) wrapped in store.WithTx so the projection
//     never observes the intermediate "no current row" state.
//   - LuksDeviceKeyRevocationDispatched: UPDATE current row's
//     revocation_status='dispatched' + revocation_at, clear error.
//   - LuksDeviceKeyRevoked: UPDATE current row's revocation_status='success'
//     (note column-value vs event-name mismatch — matches PL/pgSQL).
//   - LuksDeviceKeyRevocationFailed: UPDATE revocation_status='failed'
//     + revocation_error captured.
//
// LuksDeviceKeyRevocationRequested is intentionally a no-op (the
// PL/pgSQL projector also lacked a case for it). The Requested event
// is a marker the dispatcher handler appends before enqueueing; the
// projection only changes once Dispatched / Revoked / Failed lands.
//
// Wired in projectors.WireAll. Refs #99, tracker #107.
func LuksKeyListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "luks_key" {
			return
		}

		switch e.EventType {
		case "LuksKeyRotated":
			applyLuksKeyRotated(ctx, st, logger, e)
		case "LuksDeviceKeyRevocationDispatched":
			applyLuksRevocation(ctx, st, logger, e, LuksRevocationDispatchedFromEvent)
		case "LuksDeviceKeyRevoked":
			applyLuksRevocation(ctx, st, logger, e, LuksRevokedFromEvent)
		case "LuksDeviceKeyRevocationFailed":
			applyLuksRevocation(ctx, st, logger, e, LuksRevocationFailedFromEvent)
		}
		// Every other event_type (incl. LuksDeviceKeyRevocationRequested)
		// is silently ignored — same behaviour as the deleted PL/pgSQL
		// projector's CASE ... ELSE NULL.
	}
}

func applyLuksKeyRotated(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := LuksKeyRotatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("luks_key projector: invalid LuksKeyRotated payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.WithTx(ctx, func(q *store.Queries) error {
		if err := q.MarkLuksKeysNotCurrent(ctx, db.MarkLuksKeysNotCurrentParams{
			DeviceID:   payload.DeviceID,
			ActionID:   payload.ActionID,
			DevicePath: payload.DevicePath,
		}); err != nil {
			return err
		}
		if err := q.InsertLuksKey(ctx, db.InsertLuksKeyParams{
			DeviceID:       payload.DeviceID,
			ActionID:       payload.ActionID,
			DevicePath:     payload.DevicePath,
			Passphrase:     payload.Passphrase,
			RotatedAt:      payload.RotatedAt,
			RotationReason: payload.RotationReason,
		}); err != nil {
			return err
		}
		return q.TrimLuksKeysToLast3(ctx, db.TrimLuksKeysToLast3Params{
			DeviceID:   payload.DeviceID,
			ActionID:   payload.ActionID,
			DevicePath: payload.DevicePath,
		})
	}); err != nil {
		logger.Warn("luks_key projector: failed to apply LuksKeyRotated",
			"event_id", e.ID,
			"device_id", payload.DeviceID,
			"action_id", payload.ActionID,
			"device_path", payload.DevicePath,
			"error", err)
	}
}

// applyLuksRevocation is generic across the three revocation event
// types — they all UPDATE the current row's (revocation_status,
// revocation_error, revocation_at). The decoder picks the right
// timestamp key + status value; the writer is identical.
func applyLuksRevocation(
	ctx context.Context,
	st *store.Store,
	logger *slog.Logger,
	e store.PersistedEvent,
	decode func(store.PersistedEvent) (LuksRevocationPayload, error),
) {
	payload, err := decode(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("luks_key projector: invalid revocation payload",
			"event_id", e.ID, "event_type", e.EventType, "error", err)
		return
	}
	at := payload.At
	if err := st.Queries().UpdateLuksKeyRevocationStatus(ctx, db.UpdateLuksKeyRevocationStatusParams{
		DeviceID:         payload.DeviceID,
		ActionID:         payload.ActionID,
		RevocationStatus: stringPtr(payload.Status),
		RevocationError:  payload.Error,
		RevocationAt:     &at,
	}); err != nil {
		logger.Warn("luks_key projector: failed to update revocation_status",
			"event_id", e.ID,
			"event_type", e.EventType,
			"device_id", payload.DeviceID,
			"action_id", payload.ActionID,
			"status", payload.Status,
			"error", err)
	}
}

func stringPtr(s string) *string { return &s }
