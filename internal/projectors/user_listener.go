package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// UserListener returns a store.EventListener that applies every user
// stream event the deleted PL/pgSQL project_user_event handled.
// Sixteen event types - the largest projector under tracker #136 and
// the LAST Phase 2 port. After this lands, the cleanup migration can
// drop project_event() and the dispatcher trigger entirely.
//
// Event-type families:
//   - User CRUD: CreatedWithRoles (INSERT user + N x INSERT user_role
//     in one tx, issue #135), ProfileUpdated (UPDATE), EmailChanged
//     (UPDATE), PasswordChanged (UPDATE + session_version bump),
//     RoleChanged (UPDATE), Deleted (soft + cascade DELETE on
//     identity_links_projection).
//   - Session controls: SessionInvalidated, Disabled, Enabled,
//     LoggedIn - single guarded UPDATEs.
//   - SSH: SshKeyAdded (JSONB array append), SshKeyRemoved (JSONB
//     filter), SshSettingsUpdated (COALESCE-preserve booleans).
//   - Linux integration: LinuxUsernameChanged (UPDATE),
//     SystemActionLinked (targeted CASE on three columns),
//     ProvisioningSettingsUpdated (COALESCE-preserve boolean).
//
// Multi-write events (UserCreatedWithRoles, UserDeleted) wrap their
// fan-out in store.WithTx so the user INSERT + per-role INSERTs (or
// the soft-delete + identity-links cascade) stay atomic with each
// other; single-statement events run on the autocommit pool.
//
// Asymmetric-guard discipline (per the role + identity_provider +
// action_set + assignment + user_group + device_group +
// compliance_policy + compliance + action+definition + execution +
// device ports): every UPDATE on users_projection carries a
// `WHERE projection_version < $N` guard via :execrows, and the
// listener short-circuits the UserDeleted cascade when n == 0 -
// otherwise a stale UserDeleted re-applied later would silently nuke
// a freshly-restored user's identity links.
//
// Session-version monotonicity: PasswordChanged, SessionInvalidated,
// and Disabled all bump session_version. The bump is paired with the
// other column writes inside ONE guarded UPDATE - a stale Disable
// replayed after a re-Enable fails the projection_version guard
// outright (n == 0), so neither disabled NOR session_version regress
// to the stale value. session_version stays monotonic by construction.
//
// Wired in projectors.WireAll. Refs #136 (last Phase 2 port of
// tracker #107) and #135 (UserCreatedWithRoles compound event).
func UserListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "user" {
			return
		}
		// Multi-write events (UserCreatedWithRoles, UserDeleted)
		// route through ApplyUser via WithTx so their fan-out writes
		// land atomically. UserCreatedWithRoles inserts the user row
		// AND its per-role assignment rows in one tx (#135), so the
		// pre-#135 partial-write window between the user INSERT and
		// its role INSERTs is no longer reachable. Every other event
		// is a single statement and runs on the autocommit pool.
		// ApplyUser handles all event types when called with
		// tx-bound queries (the rebuild path).
		if e.EventType == "UserCreatedWithRoles" || e.EventType == "UserDeleted" {
			if err := st.WithTx(ctx, func(q *store.Queries) error {
				return ApplyUser(ctx, q, e)
			}); err != nil {
				logger.Warn("user projector: failed to apply multi-write event",
					"event_id", e.ID, "event_type", e.EventType,
					"user_id", e.StreamID, "error", err)
			}
			return
		}
		if err := ApplyUser(ctx, st.Queries(), e); err != nil {
			logger.Warn("user projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "user_id", e.StreamID, "error", err)
		}
	}
}

// ApplyUser is the transactional core of the user projector. The
// listener wraps it for live-event dispatch (using WithTx for
// UserDeleted's two-write atomicity); the rebuild path
// (manchtools/power-manage-server#125) registers it via
// RegisterRebuildApply so RebuildAll re-derives the projection from
// the event store instead of dispatching to the no-op PL/pgSQL stub.
func ApplyUser(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "user" {
		return nil
	}
	switch e.EventType {
	case "UserCreatedWithRoles":
		return applyUserCreatedWithRoles(ctx, q, e)
	case "UserProfileUpdated":
		return applyUserProfileUpdated(ctx, q, e)
	case "UserEmailChanged":
		return applyUserEmailChanged(ctx, q, e)
	case "UserPasswordChanged":
		return applyUserPasswordChanged(ctx, q, e)
	case "UserRoleChanged":
		return applyUserRoleChanged(ctx, q, e)
	case "UserSessionInvalidated":
		return applyUserSessionInvalidated(ctx, q, e)
	case "UserDisabled":
		return applyUserDisabled(ctx, q, e)
	case "UserEnabled":
		return applyUserEnabled(ctx, q, e)
	case "UserLoggedIn":
		return applyUserLoggedIn(ctx, q, e)
	case "UserDeleted":
		return applyUserDeleted(ctx, q, e)
	case "UserSshKeyAdded":
		return applyUserSshKeyAdded(ctx, q, e)
	case "UserSshKeyRemoved":
		return applyUserSshKeyRemoved(ctx, q, e)
	case "UserSshSettingsUpdated":
		return applyUserSshSettingsUpdated(ctx, q, e)
	case "UserLinuxUsernameChanged":
		return applyUserLinuxUsernameChanged(ctx, q, e)
	case "UserSystemActionLinked":
		return applyUserSystemActionLinked(ctx, q, e)
	case "UserProvisioningSettingsUpdated":
		return applyUserProvisioningSettingsUpdated(ctx, q, e)
	}
	return nil
}

// applyUserCreatedWithRoles inserts the user row AND every requested
// user_role assignment. The listener wrapper invokes this inside
// store.WithTx so all writes commit atomically (issue #135) - no
// partial-write window between the user INSERT and its role INSERTs.
//
// The per-role INSERT uses ON CONFLICT (user_id, role_id) DO NOTHING
// (the same idempotency the user_role projector relies on), so a
// rebuild that re-applies the event against an existing role row
// is a no-op rather than a constraint violation.
func applyUserCreatedWithRoles(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserCreatedWithRolesFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	occurredAt := e.OccurredAt
	// password_hash column is nullable in the schema; the PL/pgSQL
	// projector wrote `COALESCE(payload, '')` and computed
	// has_password from the non-empty check. Mirror that:
	// passwordHashPtr is nil only if we want SQL NULL - but the
	// PL/pgSQL projector NEVER wrote NULL, it wrote "". Keep that.
	passwordHash := payload.PasswordHash
	hasPassword := payload.PasswordHash != ""
	if err := q.InsertUserProjection(ctx, db.InsertUserProjectionParams{
		ID:                payload.ID,
		Email:             payload.Email,
		PasswordHash:      &passwordHash,
		Role:              payload.Role,
		CreatedAt:         &occurredAt,
		ProjectionVersion: deref(e.SequenceNum),
		HasPassword:       hasPassword,
		DisplayName:       payload.DisplayName,
		GivenName:         payload.GivenName,
		FamilyName:        payload.FamilyName,
		PreferredUsername: payload.PreferredUsername,
		Picture:           payload.Picture,
		Locale:            payload.Locale,
		LinuxUsername:     payload.LinuxUsername,
		LinuxUid:          payload.LinuxUID,
	}); err != nil {
		return err
	}
	for _, roleID := range payload.RoleIDs {
		if roleID == "" {
			continue
		}
		if err := q.InsertUserRoleProjection(ctx, db.InsertUserRoleProjectionParams{
			UserID:            payload.ID,
			RoleID:            roleID,
			AssignedAt:        occurredAt,
			AssignedBy:        e.ActorID,
			ProjectionVersion: deref(e.SequenceNum),
		}); err != nil {
			return err
		}
	}
	return nil
}

func applyUserProfileUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserProfileUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateUserProfileProjection(ctx, db.UpdateUserProfileProjectionParams{
		ID:                payload.ID,
		DisplayName:       payload.DisplayName,
		GivenName:         payload.GivenName,
		FamilyName:        payload.FamilyName,
		PreferredUsername: payload.PreferredUsername,
		Picture:           payload.Picture,
		Locale:            payload.Locale,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserEmailChanged(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserEmailChangedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateUserEmailProjection(ctx, db.UpdateUserEmailProjectionParams{
		ID:                payload.ID,
		Email:             payload.Email,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserPasswordChanged(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserPasswordChangedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	passwordHash := payload.PasswordHash
	updatedAt := e.OccurredAt
	if _, err := q.UpdateUserPasswordProjection(ctx, db.UpdateUserPasswordProjectionParams{
		ID:                payload.ID,
		PasswordHash:      &passwordHash,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserRoleChanged(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserRoleChangedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateUserRoleProjection(ctx, db.UpdateUserRoleProjectionParams{
		ID:                payload.ID,
		Role:              payload.Role,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserSessionInvalidated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	updatedAt := e.OccurredAt
	if _, err := q.InvalidateUserSessionProjection(ctx, db.InvalidateUserSessionProjectionParams{
		ID:                e.StreamID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserDisabled(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	updatedAt := e.OccurredAt
	if _, err := q.DisableUserProjection(ctx, db.DisableUserProjectionParams{
		ID:                e.StreamID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserEnabled(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	updatedAt := e.OccurredAt
	if _, err := q.EnableUserProjection(ctx, db.EnableUserProjectionParams{
		ID:                e.StreamID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserLoggedIn(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	loggedInAt := e.OccurredAt
	if _, err := q.UpdateUserLoginProjection(ctx, db.UpdateUserLoginProjectionParams{
		ID:                e.StreamID,
		LastLoginAt:       &loggedInAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserDeleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	updatedAt := e.OccurredAt
	n, err := q.SoftDeleteUserProjection(ctx, db.SoftDeleteUserProjectionParams{
		ID:                e.StreamID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// Stale UserDeleted replay against a row whose
		// projection_version has moved past this event. Skipping the
		// cascade (identity_links wipe) is mandatory: otherwise an old
		// delete re-applied by the reconciler against a freshly-restored
		// user would silently nuke that user's identity links.
		return nil
	}
	return q.DeleteIdentityLinksByUser(ctx, e.StreamID)
}

func applyUserSshKeyAdded(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserSshKeyAddedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.AppendUserSshKeyProjection(ctx, db.AppendUserSshKeyProjectionParams{
		ID:                payload.ID,
		KeyID:             payload.KeyID,
		PublicKey:         payload.PublicKey,
		Comment:           payload.Comment,
		AddedAt:           payload.AddedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserSshKeyRemoved(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserSshKeyRemovedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.RemoveUserSshKeyProjection(ctx, db.RemoveUserSshKeyProjectionParams{
		ID:                payload.ID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
		KeyID:             payload.KeyID,
	}); err != nil {
		return err
	}
	return nil
}

func applyUserSshSettingsUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserSshSettingsUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateUserSshSettingsProjection(ctx, db.UpdateUserSshSettingsProjectionParams{
		SshAccessEnabled:  payload.SshAccessEnabled,
		SshAllowPubkey:    payload.SshAllowPubkey,
		SshAllowPassword:  payload.SshAllowPassword,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
		ID:                payload.ID,
	}); err != nil {
		return err
	}
	return nil
}

func applyUserLinuxUsernameChanged(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserLinuxUsernameChangedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateUserLinuxUsernameProjection(ctx, db.UpdateUserLinuxUsernameProjectionParams{
		ID:                payload.ID,
		LinuxUsername:     payload.LinuxUsername,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserSystemActionLinked(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserSystemActionLinkedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.LinkUserSystemActionProjection(ctx, db.LinkUserSystemActionProjectionParams{
		Field:             payload.Field,
		ActionID:          payload.ActionID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
		ID:                payload.ID,
	}); err != nil {
		return err
	}
	return nil
}

func applyUserProvisioningSettingsUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserProvisioningSettingsUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateUserProvisioningSettingsProjection(ctx, db.UpdateUserProvisioningSettingsProjectionParams{
		UserProvisioningEnabled: payload.UserProvisioningEnabled,
		UpdatedAt:               &updatedAt,
		ProjectionVersion:       deref(e.SequenceNum),
		ID:                      payload.ID,
	}); err != nil {
		return err
	}
	return nil
}
