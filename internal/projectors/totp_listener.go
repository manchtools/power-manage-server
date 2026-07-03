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
		if err := ApplyTotp(ctx, st.Queries(), e); err != nil {
			logger.Warn("totp projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "error", err)
		}
	}
}

// ApplyTotp is the transactional core of the TOTP projector: writes through
// the supplied Queries and returns errors. Live dispatch wraps it
// (log-and-swallow); the rebuild path (#497) registers it via
// RegisterRebuildApply so a users rebuild — which CASCADE-wipes the
// FK-child totp_projection — is followed by a totp target that replays the
// enrollments. The cross-stream users_projection.totp_enabled write is safe
// during rebuild because the totp target runs AFTER users.
func ApplyTotp(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "totp" {
		return nil
	}
	payload, err := decodeTotpPayload(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}

	updatedAt := e.OccurredAt
	userID := e.StreamID

	switch e.EventType {
	case string(eventtypes.TOTPSetupInitiated):
		return q.UpsertTotpProjection(ctx, db.UpsertTotpProjectionParams{
			UserID:            userID,
			SecretEncrypted:   payload.SecretEncrypted,
			BackupCodesHash:   payload.BackupCodesHash,
			CreatedAt:         updatedAt,
			ProjectionVersion: e.SequenceNum,
		})

	case string(eventtypes.TOTPVerified):
		if err := q.VerifyTotpProjection(ctx, db.VerifyTotpProjectionParams{
			UserID:            userID,
			UpdatedAt:         updatedAt,
			ProjectionVersion: e.SequenceNum,
		}); err != nil {
			return err
		}
		if err := q.SetUserTotpEnabled(ctx, db.SetUserTotpEnabledParams{
			ID:                userID,
			TotpEnabled:       true,
			UpdatedAt:         &updatedAt,
			ProjectionVersion: e.SequenceNum,
		}); err != nil {
			return err
		}
		return enqueueDynamicUserGroupsForUser(ctx, q, userID)

	case string(eventtypes.TOTPDisabled):
		if err := q.DeleteTotpProjection(ctx, userID); err != nil {
			return err
		}
		if err := q.SetUserTotpEnabled(ctx, db.SetUserTotpEnabledParams{
			ID:                userID,
			TotpEnabled:       false,
			UpdatedAt:         &updatedAt,
			ProjectionVersion: e.SequenceNum,
		}); err != nil {
			return err
		}
		return enqueueDynamicUserGroupsForUser(ctx, q, userID)

	case string(eventtypes.TOTPBackupCodeUsed):
		if payload.Index == nil {
			// A malformed event that the live projector logged-and-skipped;
			// keep the same non-fatal behaviour during rebuild.
			return nil
		}
		// Convert 0-based event index to the 1-based Postgres array index.
		return q.MarkTotpBackupCodeUsed(ctx, db.MarkTotpBackupCodeUsedParams{
			UserID:            userID,
			Column2:           int32(*payload.Index + 1),
			UpdatedAt:         updatedAt,
			ProjectionVersion: e.SequenceNum,
		})

	case string(eventtypes.TOTPBackupCodesRegenerated):
		return q.RegenerateTotpBackupCodes(ctx, db.RegenerateTotpBackupCodesParams{
			UserID:            userID,
			BackupCodesHash:   payload.BackupCodesHash,
			UpdatedAt:         updatedAt,
			ProjectionVersion: e.SequenceNum,
		})
	}
	return nil
}
