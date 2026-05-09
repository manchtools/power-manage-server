package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// TotpListener returns a store.EventListener that applies every
// TOTP* event to the totp_projection AND propagates the cross-stream
// effect on users_projection.totp_enabled. Replaces the deleted
// PL/pgSQL project_totp_event function.
//
// Cross-stream nuance:
//   - TOTPVerified flips users_projection.totp_enabled to TRUE.
//   - TOTPDisabled flips it back to FALSE.
//
// Both writes happen in the listener — the deleted PL/pgSQL
// projector did them inline in one transaction, but for our
// post-commit listener "both eventually land within milliseconds"
// is the right contract: TotpEnabled is read on the auth/login
// path, not on every API call, so there's a logout/login cycle
// between the verify and the next read in practice. If both writes
// would fail atomicity matters less than seeing the right state at
// auth time.
//
// Wired in cmd/control/main.go alongside the other unconditional
// projector listeners.
//
// Refs #97, tracker #107.
func TotpListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "totp" {
			return
		}

		payload, err := decodeTotpPayload(e)
		if err != nil {
			if errors.Is(err, ErrIgnoredEvent) {
				return
			}
			logger.Warn("totp projector: invalid event payload",
				"event_id", e.ID, "event_type", e.EventType, "error", err)
			return
		}

		q := st.Queries()
		updatedAt := e.OccurredAt
		userID := e.StreamID

		switch e.EventType {
		case string(eventtypes.TOTPSetupInitiated):
			if err := q.UpsertTotpProjection(ctx, db.UpsertTotpProjectionParams{
				UserID:            userID,
				SecretEncrypted:   payload.SecretEncrypted,
				BackupCodesHash:   payload.BackupCodesHash,
				CreatedAt:         updatedAt,
				ProjectionVersion: deref(e.SequenceNum),
			}); err != nil {
				logger.Warn("totp projector: failed to upsert TOTPSetupInitiated",
					"event_id", e.ID, "user_id", userID, "error", err)
			}

		case string(eventtypes.TOTPVerified):
			if err := q.VerifyTotpProjection(ctx, db.VerifyTotpProjectionParams{
				UserID:            userID,
				UpdatedAt:         updatedAt,
				ProjectionVersion: deref(e.SequenceNum),
			}); err != nil {
				logger.Warn("totp projector: failed to flip totp_projection to verified",
					"event_id", e.ID, "user_id", userID, "error", err)
			}
			if err := q.SetUserTotpEnabled(ctx, db.SetUserTotpEnabledParams{
				ID:                userID,
				TotpEnabled:       true,
				UpdatedAt:         &updatedAt,
				ProjectionVersion: deref(e.SequenceNum),
			}); err != nil {
				logger.Warn("totp projector: failed to flip users_projection.totp_enabled=TRUE",
					"event_id", e.ID, "user_id", userID, "error", err)
			}

		case string(eventtypes.TOTPDisabled):
			if err := q.DeleteTotpProjection(ctx, userID); err != nil {
				logger.Warn("totp projector: failed to delete totp_projection row",
					"event_id", e.ID, "user_id", userID, "error", err)
			}
			if err := q.SetUserTotpEnabled(ctx, db.SetUserTotpEnabledParams{
				ID:                userID,
				TotpEnabled:       false,
				UpdatedAt:         &updatedAt,
				ProjectionVersion: deref(e.SequenceNum),
			}); err != nil {
				logger.Warn("totp projector: failed to flip users_projection.totp_enabled=FALSE",
					"event_id", e.ID, "user_id", userID, "error", err)
			}

		case string(eventtypes.TOTPBackupCodeUsed):
			if payload.Index == nil {
				logger.Warn("totp projector: TOTPBackupCodeUsed missing index field",
					"event_id", e.ID, "user_id", userID)
				return
			}
			// PL/pgSQL projector: backup_codes_used[(idx)::int + 1]
			// — convert 0-based event index to the 1-based Postgres
			// array index here so the SQL stays clean.
			if err := q.MarkTotpBackupCodeUsed(ctx, db.MarkTotpBackupCodeUsedParams{
				UserID:            userID,
				Column2:           int32(*payload.Index + 1),
				UpdatedAt:         updatedAt,
				ProjectionVersion: deref(e.SequenceNum),
			}); err != nil {
				logger.Warn("totp projector: failed to mark backup code used",
					"event_id", e.ID, "user_id", userID, "index", *payload.Index, "error", err)
			}

		case string(eventtypes.TOTPBackupCodesRegenerated):
			if err := q.RegenerateTotpBackupCodes(ctx, db.RegenerateTotpBackupCodesParams{
				UserID:            userID,
				BackupCodesHash:   payload.BackupCodesHash,
				UpdatedAt:         updatedAt,
				ProjectionVersion: deref(e.SequenceNum),
			}); err != nil {
				logger.Warn("totp projector: failed to regenerate backup codes",
					"event_id", e.ID, "user_id", userID, "error", err)
			}
		}
	}
}
