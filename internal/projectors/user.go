package projectors

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
)

// UserCreatedPayload mirrors the fields the deleted PL/pgSQL
// project_user_event() read out of a UserCreated event:
//
//   - email (required, NOT NULL column).
//   - password_hash (defaults to "" — matches PL/pgSQL
//     `COALESCE(event.data->>"password_hash", "")`). Drives has_password.
//   - role (defaults to "user" — matches PL/pgSQL
//     `COALESCE(event.data->>"role", "user")`).
//   - profile fields (display_name, given_name, family_name,
//     preferred_username, picture, locale): each defaults to ""
//     (matches PL/pgSQL `COALESCE(payload, "")`).
//   - linux_username (defaults to "").
//   - linux_uid (defaults to 0).
type UserCreatedPayload struct {
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
}

type userCreatedRaw struct {
	Email             string  `json:"email"`
	PasswordHash      *string `json:"password_hash,omitempty"`
	Role              *string `json:"role,omitempty"`
	DisplayName       *string `json:"display_name,omitempty"`
	GivenName         *string `json:"given_name,omitempty"`
	FamilyName        *string `json:"family_name,omitempty"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
	Picture           *string `json:"picture,omitempty"`
	Locale            *string `json:"locale,omitempty"`
	LinuxUsername     *string `json:"linux_username,omitempty"`
	LinuxUID          *int32  `json:"linux_uid,omitempty"`
}

// UserCreatedFromEvent decodes UserCreated. Returns ErrIgnoredEvent
// for any other (stream, event_type) so the listener wrapper can
// silently no-op.
func UserCreatedFromEvent(e store.PersistedEvent) (UserCreatedPayload, error) {
	if e.StreamType != "user" || e.EventType != "UserCreated" {
		return UserCreatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return UserCreatedPayload{}, fmt.Errorf("projector: empty UserCreated payload")
	}
	var raw userCreatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserCreatedPayload{}, fmt.Errorf("projector: invalid UserCreated payload: %w", err)
	}
	if raw.Email == "" {
		return UserCreatedPayload{}, fmt.Errorf("projector: UserCreated requires email")
	}
	out := UserCreatedPayload{
		ID:    e.StreamID,
		Email: raw.Email,
		// Default role mirrors the PL/pgSQL COALESCE-to-"user".
		Role: "user",
	}
	if raw.PasswordHash != nil {
		out.PasswordHash = *raw.PasswordHash
	}
	if raw.Role != nil && *raw.Role != "" {
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

type userProfileUpdatedRaw struct {
	DisplayName       *string `json:"display_name,omitempty"`
	GivenName         *string `json:"given_name,omitempty"`
	FamilyName        *string `json:"family_name,omitempty"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
	Picture           *string `json:"picture,omitempty"`
	Locale            *string `json:"locale,omitempty"`
}

// UserProfileUpdatedFromEvent decodes UserProfileUpdated.
func UserProfileUpdatedFromEvent(e store.PersistedEvent) (UserProfileUpdatedPayload, error) {
	if e.StreamType != "user" || e.EventType != "UserProfileUpdated" {
		return UserProfileUpdatedPayload{}, ErrIgnoredEvent
	}
	out := UserProfileUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw userProfileUpdatedRaw
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

type userEmailChangedRaw struct {
	Email *string `json:"email,omitempty"`
}

// UserEmailChangedFromEvent decodes UserEmailChanged. The PL/pgSQL
// projector wrote `event.data->>"email"` directly — if the key was
// missing the column would land as SQL NULL, but the column is
// NOT NULL, so the original projector relied on the emitter always
// supplying a non-empty value. Keep that contract here.
func UserEmailChangedFromEvent(e store.PersistedEvent) (UserEmailChangedPayload, error) {
	if e.StreamType != "user" || e.EventType != "UserEmailChanged" {
		return UserEmailChangedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return UserEmailChangedPayload{}, fmt.Errorf("projector: empty UserEmailChanged payload")
	}
	var raw userEmailChangedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserEmailChangedPayload{}, fmt.Errorf("projector: invalid UserEmailChanged payload: %w", err)
	}
	if raw.Email == nil || *raw.Email == "" {
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

type userPasswordChangedRaw struct {
	PasswordHash *string `json:"password_hash,omitempty"`
}

// UserPasswordChangedFromEvent decodes UserPasswordChanged.
func UserPasswordChangedFromEvent(e store.PersistedEvent) (UserPasswordChangedPayload, error) {
	if e.StreamType != "user" || e.EventType != "UserPasswordChanged" {
		return UserPasswordChangedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return UserPasswordChangedPayload{}, fmt.Errorf("projector: empty UserPasswordChanged payload")
	}
	var raw userPasswordChangedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserPasswordChangedPayload{}, fmt.Errorf("projector: invalid UserPasswordChanged payload: %w", err)
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

type userRoleChangedRaw struct {
	Role *string `json:"role,omitempty"`
}

// UserRoleChangedFromEvent decodes UserRoleChanged.
func UserRoleChangedFromEvent(e store.PersistedEvent) (UserRoleChangedPayload, error) {
	if e.StreamType != "user" || e.EventType != "UserRoleChanged" {
		return UserRoleChangedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return UserRoleChangedPayload{}, fmt.Errorf("projector: empty UserRoleChanged payload")
	}
	var raw userRoleChangedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserRoleChangedPayload{}, fmt.Errorf("projector: invalid UserRoleChanged payload: %w", err)
	}
	if raw.Role == nil || *raw.Role == "" {
		return UserRoleChangedPayload{}, fmt.Errorf("projector: UserRoleChanged requires role")
	}
	return UserRoleChangedPayload{ID: e.StreamID, Role: *raw.Role}, nil
}

// UserSshKeyAddedPayload mirrors the JSONB array-append the PL/pgSQL
// projector did on UserSshKeyAdded. AddedAt is the event's
// occurred_at timestamp (matches PL/pgSQL `event.occurred_at`).
type UserSshKeyAddedPayload struct {
	ID        string
	KeyID     string
	PublicKey string
	Comment   string
	AddedAt   time.Time
}

type userSshKeyAddedRaw struct {
	KeyID     *string `json:"key_id,omitempty"`
	PublicKey *string `json:"public_key,omitempty"`
	Comment   *string `json:"comment,omitempty"`
}

// UserSshKeyAddedFromEvent decodes UserSshKeyAdded. key_id is
// required because the JSONB element is the only addressable handle
// for the matching UserSshKeyRemoved event. public_key + comment
// default to "" so callers that omit them still produce a valid
// element shape in the JSONB array.
func UserSshKeyAddedFromEvent(e store.PersistedEvent) (UserSshKeyAddedPayload, error) {
	if e.StreamType != "user" || e.EventType != "UserSshKeyAdded" {
		return UserSshKeyAddedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return UserSshKeyAddedPayload{}, fmt.Errorf("projector: empty UserSshKeyAdded payload")
	}
	var raw userSshKeyAddedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserSshKeyAddedPayload{}, fmt.Errorf("projector: invalid UserSshKeyAdded payload: %w", err)
	}
	if raw.KeyID == nil || *raw.KeyID == "" {
		return UserSshKeyAddedPayload{}, fmt.Errorf("projector: UserSshKeyAdded requires key_id")
	}
	out := UserSshKeyAddedPayload{
		ID:      e.StreamID,
		KeyID:   *raw.KeyID,
		AddedAt: e.OccurredAt,
	}
	if raw.PublicKey != nil {
		out.PublicKey = *raw.PublicKey
	}
	if raw.Comment != nil {
		out.Comment = *raw.Comment
	}
	return out, nil
}

// UserSshKeyRemovedPayload mirrors the JSONB filter-by-id the PL/pgSQL
// projector did on UserSshKeyRemoved.
type UserSshKeyRemovedPayload struct {
	ID    string
	KeyID string
}

type userSshKeyRemovedRaw struct {
	KeyID *string `json:"key_id,omitempty"`
}

// UserSshKeyRemovedFromEvent decodes UserSshKeyRemoved.
func UserSshKeyRemovedFromEvent(e store.PersistedEvent) (UserSshKeyRemovedPayload, error) {
	if e.StreamType != "user" || e.EventType != "UserSshKeyRemoved" {
		return UserSshKeyRemovedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return UserSshKeyRemovedPayload{}, fmt.Errorf("projector: empty UserSshKeyRemoved payload")
	}
	var raw userSshKeyRemovedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserSshKeyRemovedPayload{}, fmt.Errorf("projector: invalid UserSshKeyRemoved payload: %w", err)
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

type userSshSettingsUpdatedRaw struct {
	SshAccessEnabled *bool `json:"ssh_access_enabled,omitempty"`
	SshAllowPubkey   *bool `json:"ssh_allow_pubkey,omitempty"`
	SshAllowPassword *bool `json:"ssh_allow_password,omitempty"`
}

// UserSshSettingsUpdatedFromEvent decodes UserSshSettingsUpdated.
// Empty payload is valid (a no-op event that only bumps
// projection_version + updated_at, leaving every column as-is).
func UserSshSettingsUpdatedFromEvent(e store.PersistedEvent) (UserSshSettingsUpdatedPayload, error) {
	if e.StreamType != "user" || e.EventType != "UserSshSettingsUpdated" {
		return UserSshSettingsUpdatedPayload{}, ErrIgnoredEvent
	}
	out := UserSshSettingsUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw userSshSettingsUpdatedRaw
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

type userLinuxUsernameChangedRaw struct {
	LinuxUsername *string `json:"linux_username,omitempty"`
}

// UserLinuxUsernameChangedFromEvent decodes UserLinuxUsernameChanged.
func UserLinuxUsernameChangedFromEvent(e store.PersistedEvent) (UserLinuxUsernameChangedPayload, error) {
	if e.StreamType != "user" || e.EventType != "UserLinuxUsernameChanged" {
		return UserLinuxUsernameChangedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return UserLinuxUsernameChangedPayload{}, fmt.Errorf("projector: empty UserLinuxUsernameChanged payload")
	}
	var raw userLinuxUsernameChangedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserLinuxUsernameChangedPayload{}, fmt.Errorf("projector: invalid UserLinuxUsernameChanged payload: %w", err)
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

type userSystemActionLinkedRaw struct {
	Field    *string `json:"field,omitempty"`
	ActionID *string `json:"action_id,omitempty"`
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
	if e.StreamType != "user" || e.EventType != "UserSystemActionLinked" {
		return UserSystemActionLinkedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return UserSystemActionLinkedPayload{}, fmt.Errorf("projector: empty UserSystemActionLinked payload")
	}
	var raw userSystemActionLinkedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserSystemActionLinkedPayload{}, fmt.Errorf("projector: invalid UserSystemActionLinked payload: %w", err)
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

type userProvisioningSettingsUpdatedRaw struct {
	UserProvisioningEnabled *bool `json:"user_provisioning_enabled,omitempty"`
}

// UserProvisioningSettingsUpdatedFromEvent decodes
// UserProvisioningSettingsUpdated. Empty payload is valid (no-op
// event that only bumps projection_version + updated_at).
func UserProvisioningSettingsUpdatedFromEvent(e store.PersistedEvent) (UserProvisioningSettingsUpdatedPayload, error) {
	if e.StreamType != "user" || e.EventType != "UserProvisioningSettingsUpdated" {
		return UserProvisioningSettingsUpdatedPayload{}, ErrIgnoredEvent
	}
	out := UserProvisioningSettingsUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw userProvisioningSettingsUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserProvisioningSettingsUpdatedPayload{}, fmt.Errorf("projector: invalid UserProvisioningSettingsUpdated payload: %w", err)
	}
	out.UserProvisioningEnabled = raw.UserProvisioningEnabled
	return out, nil
}
