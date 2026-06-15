package projectors

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// UserCreatedWithRolesPayload mirrors the user fields the deleted
// PL/pgSQL project_user_event() read out of a UserCreated event,
// extended with a role_ids array carrying the role assignments that
// used to ship as separate UserRoleAssigned events.
//
// Issue #135 collapses the legacy two-step UserCreated +
// N x UserRoleAssigned emission into one atomic compound event.
// The projector arm wraps the user INSERT and the per-role inserts
// in one transaction, so a partial-failure window between them is
// no longer reachable. The downstream "react to user creation"
// cases in system_actions_listener and search_listener key off
// this event instead of the dropped UserCreated literal.
//
// Per-field semantics (PL/pgSQL parity preserved verbatim):
//
//   - email (required, NOT NULL column). Missing key -> decoder
//     error. Explicit empty string -> round-trips as "".
//   - password_hash (defaults to "" - matches PL/pgSQL
//     COALESCE(event.data->>"password_hash", "")). Drives
//     has_password.
//   - role (defaults to "user" only when key is missing - matches
//     PL/pgSQL COALESCE(event.data->>"role", "user")). An explicit
//     empty string round-trips as "".
//   - profile fields (display_name, given_name, family_name,
//     preferred_username, picture, locale): each defaults to ""
//     (matches PL/pgSQL COALESCE(payload, "")).
//   - linux_username (defaults to "").
//   - linux_uid (defaults to 0).
//   - role_ids: array of role IDs to assign at creation time.
//     Missing or empty -> empty slice (the listener simply skips
//     the per-role INSERT loop). Each element becomes one
//     user_roles_projection row inside the same transaction as
//     the users_projection INSERT.
type UserCreatedWithRolesPayload struct {
	ID                string
	Email             string
	PasswordHash      string
	Role              string
	DisplayName       string
	GivenName         string
	FamilyName        string
	PreferredUsername string
	Picture           string
	Locale            string
	LinuxUsername     string
	LinuxUID          int32
	RoleIDs           []string
}

// UserCreatedWithRolesFromEvent decodes UserCreatedWithRoles. Returns
// ErrIgnoredEvent for any other (stream, event_type) so the listener
// wrapper can silently no-op.
func UserCreatedWithRolesFromEvent(e store.PersistedEvent) (UserCreatedWithRolesPayload, error) {
	raw, err := decodePayload[payloads.UserCreatedWithRoles](e, "user", eventtypes.UserCreatedWithRoles)
	if err != nil {
		return UserCreatedWithRolesPayload{}, err
	}
	// PL/pgSQL parity: a missing email key would have produced SQL
	// NULL and crashed the NOT NULL constraint at INSERT time. Surface
	// that earlier as a decoder error. An explicitly-empty email ("")
	// is preserved verbatim — the PL/pgSQL projector would have
	// written it through.
	if raw.Email == nil {
		return UserCreatedWithRolesPayload{}, fmt.Errorf("projector: UserCreatedWithRoles requires email")
	}
	out := UserCreatedWithRolesPayload{
		ID:    e.StreamID,
		Email: *raw.Email,
		// Default role mirrors the PL/pgSQL COALESCE(...,'user'):
		// it kicks in ONLY for a missing key, NOT for an explicit
		// empty string. An emitted role:"" must round-trip as "".
		Role:    "user",
		RoleIDs: raw.RoleIDs,
	}
	if out.RoleIDs == nil {
		out.RoleIDs = []string{}
	}
	if raw.PasswordHash != nil {
		out.PasswordHash = *raw.PasswordHash
	}
	if raw.Role != nil {
		out.Role = *raw.Role
	}
	if raw.DisplayName != nil {
		out.DisplayName = *raw.DisplayName
	}
	if raw.GivenName != nil {
		out.GivenName = *raw.GivenName
	}
	if raw.FamilyName != nil {
		out.FamilyName = *raw.FamilyName
	}
	if raw.PreferredUsername != nil {
		out.PreferredUsername = *raw.PreferredUsername
	}
	if raw.Picture != nil {
		out.Picture = *raw.Picture
	}
	if raw.Locale != nil {
		out.Locale = *raw.Locale
	}
	if raw.LinuxUsername != nil {
		out.LinuxUsername = *raw.LinuxUsername
	}
	if raw.LinuxUID != nil {
		out.LinuxUID = *raw.LinuxUID
	}
	return out, nil
}

// UserProfileUpdatedPayload mirrors the six profile fields the
// PL/pgSQL projector REPLACED on UserProfileUpdated. Each field is
// COALESCE-to-"" — missing key in the event payload writes "".
type UserProfileUpdatedPayload struct {
	ID                string
	DisplayName       string
	GivenName         string
	FamilyName        string
	PreferredUsername string
	Picture           string
	Locale            string
}

// UserProfileUpdatedFromEvent decodes UserProfileUpdated.
func UserProfileUpdatedFromEvent(e store.PersistedEvent) (UserProfileUpdatedPayload, error) {
	if e.StreamType != "user" || e.EventType != string(eventtypes.UserProfileUpdated) {
		return UserProfileUpdatedPayload{}, ErrIgnoredEvent
	}
	out := UserProfileUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw payloads.UserProfileUpdated
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserProfileUpdatedPayload{}, fmt.Errorf("projector: invalid UserProfileUpdated payload: %w", err)
	}
	if raw.DisplayName != nil {
		out.DisplayName = *raw.DisplayName
	}
	if raw.GivenName != nil {
		out.GivenName = *raw.GivenName
	}
	if raw.FamilyName != nil {
		out.FamilyName = *raw.FamilyName
	}
	if raw.PreferredUsername != nil {
		out.PreferredUsername = *raw.PreferredUsername
	}
	if raw.Picture != nil {
		out.Picture = *raw.Picture
	}
	if raw.Locale != nil {
		out.Locale = *raw.Locale
	}
	return out, nil
}

// UserEmailChangedPayload mirrors the single field the PL/pgSQL
// projector wrote on UserEmailChanged.
type UserEmailChangedPayload struct {
	ID    string
	Email string
}

// UserEmailChangedFromEvent decodes UserEmailChanged. The PL/pgSQL
// projector wrote `event.data->>"email"` directly — if the key was
// missing the column would land as SQL NULL, but the column is
// NOT NULL, so the original projector relied on the emitter always
// supplying a non-empty value. Keep that contract here.
func UserEmailChangedFromEvent(e store.PersistedEvent) (UserEmailChangedPayload, error) {
	raw, err := decodePayload[payloads.UserEmailChanged](e, "user", eventtypes.UserEmailChanged)
	if err != nil {
		return UserEmailChangedPayload{}, err
	}
	// PL/pgSQL parity: missing key → SQL NULL → NOT NULL violation
	// at UPDATE time. Surface earlier here. Explicit "" is preserved
	// verbatim — the PL/pgSQL projector would have written it through.
	if raw.Email == nil {
		return UserEmailChangedPayload{}, fmt.Errorf("projector: UserEmailChanged requires email")
	}
	return UserEmailChangedPayload{ID: e.StreamID, Email: *raw.Email}, nil
}

// UserPasswordChangedPayload mirrors UserPasswordChanged. The PL/pgSQL
// projector wrote `event.data->>"password_hash"` directly without a
// COALESCE — emitter always supplies it. We require it explicitly for
// the same reason.
type UserPasswordChangedPayload struct {
	ID           string
	PasswordHash string
}

// UserPasswordChangedFromEvent decodes UserPasswordChanged.
func UserPasswordChangedFromEvent(e store.PersistedEvent) (UserPasswordChangedPayload, error) {
	raw, err := decodePayload[payloads.UserPasswordChanged](e, "user", eventtypes.UserPasswordChanged)
	if err != nil {
		return UserPasswordChangedPayload{}, err
	}
	if raw.PasswordHash == nil {
		return UserPasswordChangedPayload{}, fmt.Errorf("projector: UserPasswordChanged requires password_hash")
	}
	return UserPasswordChangedPayload{ID: e.StreamID, PasswordHash: *raw.PasswordHash}, nil
}

// UserRoleChangedPayload mirrors UserRoleChanged. role is required
// (NOT NULL column).
type UserRoleChangedPayload struct {
	ID   string
	Role string
}

// UserRoleChangedFromEvent decodes UserRoleChanged.
func UserRoleChangedFromEvent(e store.PersistedEvent) (UserRoleChangedPayload, error) {
	raw, err := decodePayload[payloads.UserRoleChanged](e, "user", eventtypes.UserRoleChanged)
	if err != nil {
		return UserRoleChangedPayload{}, err
	}
	// PL/pgSQL parity: missing key → SQL NULL → NOT NULL violation.
	// Explicit "" is preserved verbatim.
	if raw.Role == nil {
		return UserRoleChangedPayload{}, fmt.Errorf("projector: UserRoleChanged requires role")
	}
	return UserRoleChangedPayload{ID: e.StreamID, Role: *raw.Role}, nil
}

// UserSshKeyAddedPayload mirrors the JSONB array-append the PL/pgSQL
// projector did on UserSshKeyAdded. AddedAt is the event's
// occurred_at timestamp (matches PL/pgSQL `event.occurred_at`).
//
// PublicKey + Comment are pointers so the SQL builder can write a
// JSON null for an omitted key rather than an empty string —
// PL/pgSQL fed `event.data->>'public_key'` straight into
// `jsonb_build_object`, so missing keys became JSON null. Replay
// of historical sparse events must produce the same JSONB shape.
type UserSshKeyAddedPayload struct {
	ID        string
	KeyID     string
	PublicKey *string
	Comment   *string
	AddedAt   time.Time
}

// UserSshKeyAddedFromEvent decodes UserSshKeyAdded. key_id is
// required because the JSONB element is the only addressable handle
// for the matching UserSshKeyRemoved event. public_key + comment
// default to "" so callers that omit them still produce a valid
// element shape in the JSONB array.
func UserSshKeyAddedFromEvent(e store.PersistedEvent) (UserSshKeyAddedPayload, error) {
	raw, err := decodePayload[payloads.UserSshKeyAdded](e, "user", eventtypes.UserSshKeyAdded)
	if err != nil {
		return UserSshKeyAddedPayload{}, err
	}
	if raw.KeyID == nil || *raw.KeyID == "" {
		return UserSshKeyAddedPayload{}, fmt.Errorf("projector: UserSshKeyAdded requires key_id")
	}
	out := UserSshKeyAddedPayload{
		ID:      e.StreamID,
		KeyID:   *raw.KeyID,
		AddedAt: e.OccurredAt,
	}
	// Keep the pointer-presence distinction so the SQL builder
	// can emit JSON null vs explicit value (PL/pgSQL parity).
	out.PublicKey = raw.PublicKey
	out.Comment = raw.Comment
	return out, nil
}

// UserSshKeyRemovedPayload mirrors the JSONB filter-by-id the PL/pgSQL
// projector did on UserSshKeyRemoved.
type UserSshKeyRemovedPayload struct {
	ID    string
	KeyID string
}

// UserSshKeyRemovedFromEvent decodes UserSshKeyRemoved.
func UserSshKeyRemovedFromEvent(e store.PersistedEvent) (UserSshKeyRemovedPayload, error) {
	raw, err := decodePayload[payloads.UserSshKeyRemoved](e, "user", eventtypes.UserSshKeyRemoved)
	if err != nil {
		return UserSshKeyRemovedPayload{}, err
	}
	if raw.KeyID == nil || *raw.KeyID == "" {
		return UserSshKeyRemovedPayload{}, fmt.Errorf("projector: UserSshKeyRemoved requires key_id")
	}
	return UserSshKeyRemovedPayload{ID: e.StreamID, KeyID: *raw.KeyID}, nil
}

// UserSshSettingsUpdatedPayload mirrors the three SSH settings the
// PL/pgSQL projector COALESCE-preserved on UserSshSettingsUpdated.
// nil pointer = "field absent in payload, preserve existing column
// value"; non-nil pointer = "field present in payload, set to value"
// (the SQL UPDATE does `COALESCE($N::BOOLEAN, existing)`).
type UserSshSettingsUpdatedPayload struct {
	ID               string
	SshAccessEnabled *bool
	SshAllowPubkey   *bool
	SshAllowPassword *bool
}

// UserSshSettingsUpdatedFromEvent decodes UserSshSettingsUpdated.
// Empty payload is valid (a no-op event that only bumps
// projection_version + updated_at, leaving every column as-is).
func UserSshSettingsUpdatedFromEvent(e store.PersistedEvent) (UserSshSettingsUpdatedPayload, error) {
	if e.StreamType != "user" || e.EventType != string(eventtypes.UserSshSettingsUpdated) {
		return UserSshSettingsUpdatedPayload{}, ErrIgnoredEvent
	}
	out := UserSshSettingsUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw payloads.UserSshSettingsUpdated
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserSshSettingsUpdatedPayload{}, fmt.Errorf("projector: invalid UserSshSettingsUpdated payload: %w", err)
	}
	out.SshAccessEnabled = raw.SshAccessEnabled
	out.SshAllowPubkey = raw.SshAllowPubkey
	out.SshAllowPassword = raw.SshAllowPassword
	return out, nil
}

// UserLinuxUsernameChangedPayload mirrors UserLinuxUsernameChanged.
// linux_username is required (the PL/pgSQL projector wrote
// `event.data->>"linux_username"` directly, so an absent key would
// have produced a NULL violation against the NOT NULL column).
type UserLinuxUsernameChangedPayload struct {
	ID            string
	LinuxUsername string
}

// UserLinuxUsernameChangedFromEvent decodes UserLinuxUsernameChanged.
func UserLinuxUsernameChangedFromEvent(e store.PersistedEvent) (UserLinuxUsernameChangedPayload, error) {
	raw, err := decodePayload[payloads.UserLinuxUsernameChanged](e, "user", eventtypes.UserLinuxUsernameChanged)
	if err != nil {
		return UserLinuxUsernameChangedPayload{}, err
	}
	if raw.LinuxUsername == nil {
		return UserLinuxUsernameChangedPayload{}, fmt.Errorf("projector: UserLinuxUsernameChanged requires linux_username")
	}
	return UserLinuxUsernameChangedPayload{ID: e.StreamID, LinuxUsername: *raw.LinuxUsername}, nil
}

// UserSystemActionLinkedPayload mirrors the targeted CASE the
// PL/pgSQL projector did on UserSystemActionLinked. The `field` value
// selects which of three columns
// (system_user_action_id / system_ssh_action_id / system_tty_action_id)
// gets the supplied action_id; the other two columns are preserved.
type UserSystemActionLinkedPayload struct {
	ID       string
	Field    string
	ActionID string
}

// Allowed field names for UserSystemActionLinked. Mirrors the
// PL/pgSQL CASE arms exactly — anything else falls through to the
// three "preserve existing" branches in the original projector,
// which is equivalent to the Go listener producing a no-op.
const (
	SystemActionFieldUser = "system_user_action_id"
	SystemActionFieldSSH  = "system_ssh_action_id"
	SystemActionFieldTTY  = "system_tty_action_id"
)

// UserSystemActionLinkedFromEvent decodes UserSystemActionLinked.
// field is required so the listener knows which column to write.
// action_id defaults to "" so an explicit "unlink" can still flow
// through (matches PL/pgSQL `COALESCE(event.data->>"action_id", "")`).
func UserSystemActionLinkedFromEvent(e store.PersistedEvent) (UserSystemActionLinkedPayload, error) {
	raw, err := decodePayload[payloads.UserSystemActionLinked](e, "user", eventtypes.UserSystemActionLinked)
	if err != nil {
		return UserSystemActionLinkedPayload{}, err
	}
	if raw.Field == nil || *raw.Field == "" {
		return UserSystemActionLinkedPayload{}, fmt.Errorf("projector: UserSystemActionLinked requires field")
	}
	out := UserSystemActionLinkedPayload{
		ID:    e.StreamID,
		Field: *raw.Field,
	}
	if raw.ActionID != nil {
		out.ActionID = *raw.ActionID
	}
	return out, nil
}

// UserProvisioningSettingsUpdatedPayload mirrors the single
// COALESCE-preserved boolean the PL/pgSQL projector wrote on
// UserProvisioningSettingsUpdated. nil pointer = "field absent,
// preserve existing"; non-nil = "set to value".
type UserProvisioningSettingsUpdatedPayload struct {
	ID                      string
	UserProvisioningEnabled *bool
}

// UserProvisioningSettingsUpdatedFromEvent decodes
// UserProvisioningSettingsUpdated. Empty payload is valid (no-op
// event that only bumps projection_version + updated_at).
func UserProvisioningSettingsUpdatedFromEvent(e store.PersistedEvent) (UserProvisioningSettingsUpdatedPayload, error) {
	if e.StreamType != "user" || e.EventType != string(eventtypes.UserProvisioningSettingsUpdated) {
		return UserProvisioningSettingsUpdatedPayload{}, ErrIgnoredEvent
	}
	out := UserProvisioningSettingsUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw payloads.UserProvisioningSettingsUpdated
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserProvisioningSettingsUpdatedPayload{}, fmt.Errorf("projector: invalid UserProvisioningSettingsUpdated payload: %w", err)
	}
	out.UserProvisioningEnabled = raw.UserProvisioningEnabled
	return out, nil
}
