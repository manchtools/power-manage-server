package payloads

// ServerSettingUpdated is the wire shape for ServerSettingUpdated.
// Pointer fields preserve absent-vs-explicit semantics so a partial
// update only affects the named columns of server_settings_projection
// — a nil bool means "preserve existing", a non-nil bool means "set".
type ServerSettingUpdated struct {
	UserProvisioningEnabled *bool `json:"user_provisioning_enabled,omitempty"`
	SshAccessForAll         *bool `json:"ssh_access_for_all,omitempty"`
}
