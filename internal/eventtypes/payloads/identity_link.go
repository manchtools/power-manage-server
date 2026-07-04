package payloads

// IdentityLinked is the wire shape for the IdentityLinked event the
// SSO linker emits when an OIDC subject is bound to a local user
// (either an existing one with a matching email, or a freshly created
// one). The projector inserts an identity_link row keyed by
// (provider_id, external_id) → user_id and denormalises the external
// email/name onto the same row for display.
type IdentityLinked struct {
	UserID        string `json:"user_id"`
	ProviderID    string `json:"provider_id"`
	ExternalID    string `json:"external_id"`
	ExternalEmail string `json:"external_email,omitempty" pii:"true"`
	ExternalName  string `json:"external_name,omitempty" pii:"true"`
}

// IdentityLinkLoginUpdated is the wire shape for the SSO/SCIM refresh
// path — the user already has a link, but the IdP's claims drifted
// (display name, email). The projector updates the existing row's
// denormalised external_email / external_name, keyed by the
// (provider_id, external_id) tuple. user_id names the owning user:
// the projector doesn't need it (the tuple keys the row), but spec 19
// does — external_email/external_name are PII, and the crypto-shred
// layer resolves the DEK owner from this field (#507). Events emitted
// before the field existed decode with UserID == "".
type IdentityLinkLoginUpdated struct {
	UserID        string `json:"user_id"`
	ProviderID    string `json:"provider_id"`
	ExternalID    string `json:"external_id"`
	ExternalEmail string `json:"external_email,omitempty" pii:"true"`
	ExternalName  string `json:"external_name,omitempty" pii:"true"`
}
