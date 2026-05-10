package payloads

// IdentityUnlinked is the wire shape for IdentityUnlinked. The
// projector deletes the matching identity_link row keyed by
// (provider_id, user_id).
type IdentityUnlinked struct {
	UserID     string `json:"user_id"`
	ProviderID string `json:"provider_id"`
}

// RegistrationTokenConsumed is the wire shape for the token-consumed
// event the registration handler emits when a device registers
// successfully. The projector marks the registration_token row as
// consumed and links it to the device that registered.
type RegistrationTokenConsumed struct {
	DeviceID string `json:"device_id"`
}

// TokenRenamed is the wire shape for TokenRenamed.
type TokenRenamed struct {
	Name string `json:"name"`
}

// UserSelectionChanged is the wire shape for UserSelectionChanged.
// The projector reads (device_id, source_type, source_id, selected)
// and inserts/updates the matching user_selections_projection row.
type UserSelectionChanged struct {
	DeviceID   string `json:"device_id"`
	SourceType string `json:"source_type"`
	SourceID   string `json:"source_id"`
	Selected   bool   `json:"selected"`
}
