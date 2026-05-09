package payloads

// UserCreatedWithRoles is the wire shape for the UserCreatedWithRoles
// compound event (issue #135). Pointer fields preserve the
// absent-vs-explicit distinction the PL/pgSQL projector's COALESCE
// chain relied on — see internal/projectors/user.go for the per-field
// fallback semantics.
type UserCreatedWithRoles struct {
	Email             *string  `json:"email,omitempty"`
	PasswordHash      *string  `json:"password_hash,omitempty"`
	Role              *string  `json:"role,omitempty"`
	DisplayName       *string  `json:"display_name,omitempty"`
	GivenName         *string  `json:"given_name,omitempty"`
	FamilyName        *string  `json:"family_name,omitempty"`
	PreferredUsername *string  `json:"preferred_username,omitempty"`
	Picture           *string  `json:"picture,omitempty"`
	Locale            *string  `json:"locale,omitempty"`
	LinuxUsername     *string  `json:"linux_username,omitempty"`
	LinuxUID          *int32   `json:"linux_uid,omitempty"`
	RoleIDs           []string `json:"role_ids,omitempty"`
}

// UserProfileUpdated is the wire shape for UserProfileUpdated.
type UserProfileUpdated struct {
	DisplayName       *string `json:"display_name,omitempty"`
	GivenName         *string `json:"given_name,omitempty"`
	FamilyName        *string `json:"family_name,omitempty"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
	Picture           *string `json:"picture,omitempty"`
	Locale            *string `json:"locale,omitempty"`
}

// UserEmailChanged is the wire shape for UserEmailChanged.
type UserEmailChanged struct {
	Email *string `json:"email,omitempty"`
}

// UserPasswordChanged is the wire shape for UserPasswordChanged.
type UserPasswordChanged struct {
	PasswordHash *string `json:"password_hash,omitempty"`
}

// UserRoleChanged is the wire shape for UserRoleChanged.
type UserRoleChanged struct {
	Role *string `json:"role,omitempty"`
}

// UserSshKeyAdded is the wire shape for UserSshKeyAdded. PublicKey +
// Comment stay pointers so an omitted key marshals as JSON null
// (matches PL/pgSQL `event.data->>'public_key'` writing NULL into the
// JSONB element). AddedAt is the RFC 3339 string the legacy emit site
// stuffed into the map; the projector reads added-at from
// event.occurred_at instead so the field is not required, but keeping
// it on the wire preserves byte-identical event payloads with the
// pre-typed-payload emission for replay safety.
type UserSshKeyAdded struct {
	KeyID     *string `json:"key_id,omitempty"`
	PublicKey *string `json:"public_key,omitempty"`
	Comment   *string `json:"comment,omitempty"`
	AddedAt   *string `json:"added_at,omitempty"`
}

// UserSshKeyRemoved is the wire shape for UserSshKeyRemoved.
type UserSshKeyRemoved struct {
	KeyID *string `json:"key_id,omitempty"`
}

// UserSshSettingsUpdated is the wire shape for UserSshSettingsUpdated.
// Pointer bools preserve the COALESCE-on-missing semantics the
// projector relies on — a nil pointer means "preserve existing column
// value", a non-nil pointer means "set to value".
type UserSshSettingsUpdated struct {
	SshAccessEnabled *bool `json:"ssh_access_enabled,omitempty"`
	SshAllowPubkey   *bool `json:"ssh_allow_pubkey,omitempty"`
	SshAllowPassword *bool `json:"ssh_allow_password,omitempty"`
}

// UserLinuxUsernameChanged is the wire shape for
// UserLinuxUsernameChanged.
type UserLinuxUsernameChanged struct {
	LinuxUsername *string `json:"linux_username,omitempty"`
}

// UserSystemActionLinked is the wire shape for UserSystemActionLinked.
// Field selects which of the three system_*_action_id columns gets
// the supplied action_id (see SystemActionField* constants in the
// projector package).
type UserSystemActionLinked struct {
	Field    *string `json:"field,omitempty"`
	ActionID *string `json:"action_id,omitempty"`
}

// UserProvisioningSettingsUpdated is the wire shape for
// UserProvisioningSettingsUpdated.
type UserProvisioningSettingsUpdated struct {
	UserProvisioningEnabled *bool `json:"user_provisioning_enabled,omitempty"`
}
