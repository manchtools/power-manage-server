package payloads

import "encoding/json"

// IdentityProviderSCIMEnabled is the wire shape for the
// IdentityProviderSCIMEnabled event. The hash is bcrypt(token); the
// raw token never enters the event store.
type IdentityProviderSCIMEnabled struct {
	ScimTokenHash string `json:"scim_token_hash"`
}

// IdentityProviderSCIMTokenRotated is the wire shape for the
// IdentityProviderSCIMTokenRotated event. Same shape as SCIMEnabled —
// kept as a distinct struct so a future change to "rotated" payloads
// (e.g. previous-hash for grace-period reuse) doesn't accidentally
// reshape the enable path.
type IdentityProviderSCIMTokenRotated struct {
	ScimTokenHash string `json:"scim_token_hash"`
}

// IdentityProviderCreated is the wire shape for the IdentityProviderCreated
// event. ClientSecretEncrypted is the AES-GCM ciphertext (the raw
// secret never enters the event store; the audit-log redactor also
// includes "client_secret" in its sensitive-key set as defense in
// depth — see internal/api/audit_handler.go).
type IdentityProviderCreated struct {
	Name                     string          `json:"name"`
	Slug                     string          `json:"slug"`
	ProviderType             string          `json:"provider_type"`
	ClientID                 string          `json:"client_id"`
	ClientSecretEncrypted    string          `json:"client_secret_encrypted"`
	IssuerURL                string          `json:"issuer_url"`
	AuthorizationURL         string          `json:"authorization_url"`
	TokenURL                 string          `json:"token_url"`
	UserinfoURL              string          `json:"userinfo_url"`
	Scopes                   []string        `json:"scopes,omitempty"`
	AutoCreateUsers          bool            `json:"auto_create_users"`
	AutoLinkByEmail          bool            `json:"auto_link_by_email"`
	TrustEmailAssertions     bool            `json:"trust_email_assertions"`
	DefaultRoleID            string          `json:"default_role_id,omitempty"`
	DisablePasswordForLinked bool            `json:"disable_password_for_linked"`
	GroupClaim               string          `json:"group_claim,omitempty"`
	GroupMapping             json.RawMessage `json:"group_mapping,omitempty"`
}
