package projectors

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
)

// IdentityProviderCreatedPayload represents the decoded shape of an
// IdentityProviderCreated event. Pointers + zero-value defaults
// mirror the PL/pgSQL projector's COALESCE/`CASE WHEN ... IS NOT NULL`
// behaviour: missing optional fields land at the same defaults the
// PL/pgSQL version produced.
type IdentityProviderCreatedPayload struct {
	ID                       string
	Name                     string
	Slug                     string
	ProviderType             string
	ClientID                 string
	ClientSecretEncrypted    string
	IssuerURL                string
	AuthorizationURL         string
	TokenURL                 string
	UserinfoURL              string
	Scopes                   []string
	AutoCreateUsers          bool
	AutoLinkByEmail          bool
	DefaultRoleID            string
	DisablePasswordForLinked bool
	GroupClaim               string
	GroupMapping             []byte // raw JSONB bytes; preserved as-sent
	CreatedBy                string
}

// LogValue masks the encrypted client secret when the payload is
// dumped to structured logs. Mirrors the LpsPasswordRotatedPayload /
// LuksKeyRotatedPayload pattern.
func (p IdentityProviderCreatedPayload) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", p.ID),
		slog.String("name", p.Name),
		slog.String("slug", p.Slug),
		slog.String("provider_type", p.ProviderType),
		slog.String("client_id", p.ClientID),
		slog.String("client_secret_encrypted", "[REDACTED]"),
		slog.String("issuer_url", p.IssuerURL),
	)
}

// IdentityProviderUpdatedPayload — partial update with pointer fields
// that distinguish "field present" from "field omitted". The
// PL/pgSQL projector mixes COALESCE (preserve on NULL) and
// `COALESCE(NULLIF(payload, ""), existing)` (preserve on missing OR
// empty-string) per field; we collapse empty-string to nil at the
// listener layer for the NULLIF-shaped fields.
type IdentityProviderUpdatedPayload struct {
	ID                       string
	Name                     *string
	Enabled                  *bool
	ClientID                 *string // NULLIF — empty collapsed to nil
	ClientSecretEncrypted    *string // NULLIF
	IssuerURL                *string // NULLIF
	AuthorizationURL         *string
	TokenURL                 *string
	UserinfoURL              *string
	Scopes                   *[]string
	AutoCreateUsers          *bool
	AutoLinkByEmail          *bool
	DefaultRoleID            *string
	DisablePasswordForLinked *bool
	GroupClaim               *string
	GroupMapping             []byte // nil if absent; raw JSONB bytes if present
}

// LogValue mirrors the Created variant's masking on
// ClientSecretEncrypted. The listener doesn't currently log this
// payload directly, but symmetry keeps the safety from regressing
// if a future caller adds `slog.Any("payload", payload)` to a Warn.
// "[REDACTED]" only emitted when the secret was set in the payload
// — nil-pointer "not present" stays nil so log readers can tell the
// update didn't touch the secret.
func (p IdentityProviderUpdatedPayload) LogValue() slog.Value {
	attrs := []slog.Attr{slog.String("id", p.ID)}
	if p.ClientSecretEncrypted != nil {
		attrs = append(attrs, slog.String("client_secret_encrypted", "[REDACTED]"))
	}
	return slog.GroupValue(attrs...)
}

// IdentityLinkPayload covers IdentityLinked + IdentityLinkLoginUpdated.
// Both reference (provider_id, external_id) as the lookup key.
type IdentityLinkPayload struct {
	ID            string // event.stream_id (the link's id)
	UserID        string
	ProviderID    string
	ExternalID    string
	ExternalEmail string
	ExternalName  string
}

// SCIMTokenPayload covers IdentityProviderSCIMEnabled +
// IdentityProviderSCIMTokenRotated. Both carry a scim_token_hash.
type SCIMTokenPayload struct {
	ID            string
	ScimTokenHash string
}

type idpCreatedRaw struct {
	Name                     string          `json:"name"`
	Slug                     string          `json:"slug"`
	ProviderType             *string         `json:"provider_type,omitempty"`
	ClientID                 string          `json:"client_id"`
	ClientSecretEncrypted    *string         `json:"client_secret_encrypted,omitempty"`
	IssuerURL                string          `json:"issuer_url"`
	AuthorizationURL         *string         `json:"authorization_url,omitempty"`
	TokenURL                 *string         `json:"token_url,omitempty"`
	UserinfoURL              *string         `json:"userinfo_url,omitempty"`
	Scopes                   *[]string       `json:"scopes,omitempty"`
	AutoCreateUsers          *bool           `json:"auto_create_users,omitempty"`
	AutoLinkByEmail          *bool           `json:"auto_link_by_email,omitempty"`
	DefaultRoleID            *string         `json:"default_role_id,omitempty"`
	DisablePasswordForLinked *bool           `json:"disable_password_for_linked,omitempty"`
	GroupClaim               *string         `json:"group_claim,omitempty"`
	GroupMapping             json.RawMessage `json:"group_mapping,omitempty"`
}

// IdentityProviderCreatedFromEvent decodes IdentityProviderCreated.
// Returns ErrIgnoredEvent for any other (stream, event_type).
func IdentityProviderCreatedFromEvent(e store.PersistedEvent) (IdentityProviderCreatedPayload, error) {
	if e.StreamType != "identity_provider" || e.EventType != "IdentityProviderCreated" {
		return IdentityProviderCreatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return IdentityProviderCreatedPayload{}, fmt.Errorf("projector: empty IdentityProviderCreated payload")
	}
	var raw idpCreatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return IdentityProviderCreatedPayload{}, fmt.Errorf("projector: invalid IdentityProviderCreated payload: %w", err)
	}
	switch {
	case raw.Name == "":
		return IdentityProviderCreatedPayload{}, fmt.Errorf("projector: IdentityProviderCreated requires name")
	case raw.Slug == "":
		return IdentityProviderCreatedPayload{}, fmt.Errorf("projector: IdentityProviderCreated requires slug")
	case raw.ClientID == "":
		return IdentityProviderCreatedPayload{}, fmt.Errorf("projector: IdentityProviderCreated requires client_id")
	case raw.IssuerURL == "":
		return IdentityProviderCreatedPayload{}, fmt.Errorf("projector: IdentityProviderCreated requires issuer_url")
	}
	out := IdentityProviderCreatedPayload{
		ID:           e.StreamID,
		Name:         raw.Name,
		Slug:         raw.Slug,
		ProviderType: "oidc",
		ClientID:     raw.ClientID,
		IssuerURL:    raw.IssuerURL,
		Scopes:       []string{},
		CreatedBy:    e.ActorID,
		GroupMapping: []byte("{}"),
	}
	if raw.ProviderType != nil && *raw.ProviderType != "" {
		out.ProviderType = *raw.ProviderType
	}
	if raw.ClientSecretEncrypted != nil {
		out.ClientSecretEncrypted = *raw.ClientSecretEncrypted
	}
	if raw.AuthorizationURL != nil {
		out.AuthorizationURL = *raw.AuthorizationURL
	}
	if raw.TokenURL != nil {
		out.TokenURL = *raw.TokenURL
	}
	if raw.UserinfoURL != nil {
		out.UserinfoURL = *raw.UserinfoURL
	}
	if raw.Scopes != nil {
		out.Scopes = *raw.Scopes
	}
	if raw.AutoCreateUsers != nil {
		out.AutoCreateUsers = *raw.AutoCreateUsers
	}
	if raw.AutoLinkByEmail != nil {
		out.AutoLinkByEmail = *raw.AutoLinkByEmail
	}
	if raw.DefaultRoleID != nil {
		out.DefaultRoleID = *raw.DefaultRoleID
	}
	if raw.DisablePasswordForLinked != nil {
		out.DisablePasswordForLinked = *raw.DisablePasswordForLinked
	}
	if raw.GroupClaim != nil {
		out.GroupClaim = *raw.GroupClaim
	}
	if len(raw.GroupMapping) > 0 {
		out.GroupMapping = raw.GroupMapping
	}
	return out, nil
}

type idpUpdatedRaw struct {
	Name                     *string         `json:"name,omitempty"`
	Enabled                  *bool           `json:"enabled,omitempty"`
	ClientID                 *string         `json:"client_id,omitempty"`
	ClientSecretEncrypted    *string         `json:"client_secret_encrypted,omitempty"`
	IssuerURL                *string         `json:"issuer_url,omitempty"`
	AuthorizationURL         *string         `json:"authorization_url,omitempty"`
	TokenURL                 *string         `json:"token_url,omitempty"`
	UserinfoURL              *string         `json:"userinfo_url,omitempty"`
	Scopes                   *[]string       `json:"scopes,omitempty"`
	AutoCreateUsers          *bool           `json:"auto_create_users,omitempty"`
	AutoLinkByEmail          *bool           `json:"auto_link_by_email,omitempty"`
	DefaultRoleID            *string         `json:"default_role_id,omitempty"`
	DisablePasswordForLinked *bool           `json:"disable_password_for_linked,omitempty"`
	GroupClaim               *string         `json:"group_claim,omitempty"`
	GroupMapping             json.RawMessage `json:"group_mapping,omitempty"`
}

// IdentityProviderUpdatedFromEvent decodes IdentityProviderUpdated.
// Empty-string is collapsed to nil for the NULLIF-semantic fields
// (client_id, client_secret_encrypted, issuer_url) to match the
// PL/pgSQL projector's `COALESCE(NULLIF(payload, ""), existing)`.
func IdentityProviderUpdatedFromEvent(e store.PersistedEvent) (IdentityProviderUpdatedPayload, error) {
	if e.StreamType != "identity_provider" || e.EventType != "IdentityProviderUpdated" {
		return IdentityProviderUpdatedPayload{}, ErrIgnoredEvent
	}
	out := IdentityProviderUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw idpUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return IdentityProviderUpdatedPayload{}, fmt.Errorf("projector: invalid IdentityProviderUpdated payload: %w", err)
	}
	out.Name = raw.Name
	out.Enabled = raw.Enabled
	out.ClientID = nullifEmpty(raw.ClientID)
	out.ClientSecretEncrypted = nullifEmpty(raw.ClientSecretEncrypted)
	out.IssuerURL = nullifEmpty(raw.IssuerURL)
	out.AuthorizationURL = raw.AuthorizationURL
	out.TokenURL = raw.TokenURL
	out.UserinfoURL = raw.UserinfoURL
	out.Scopes = raw.Scopes
	out.AutoCreateUsers = raw.AutoCreateUsers
	out.AutoLinkByEmail = raw.AutoLinkByEmail
	out.DefaultRoleID = raw.DefaultRoleID
	out.DisablePasswordForLinked = raw.DisablePasswordForLinked
	out.GroupClaim = raw.GroupClaim
	if len(raw.GroupMapping) > 0 {
		out.GroupMapping = raw.GroupMapping
	}
	return out, nil
}

// IdentityLinkedFromEvent decodes IdentityLinked. user_id, provider_id
// and external_id are required (composite key on the projection).
func IdentityLinkedFromEvent(e store.PersistedEvent) (IdentityLinkPayload, error) {
	if e.StreamType != "identity_provider" || e.EventType != "IdentityLinked" {
		return IdentityLinkPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return IdentityLinkPayload{}, fmt.Errorf("projector: empty IdentityLinked payload")
	}
	var raw struct {
		UserID        string  `json:"user_id"`
		ProviderID    string  `json:"provider_id"`
		ExternalID    string  `json:"external_id"`
		ExternalEmail *string `json:"external_email,omitempty"`
		ExternalName  *string `json:"external_name,omitempty"`
	}
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return IdentityLinkPayload{}, fmt.Errorf("projector: invalid IdentityLinked payload: %w", err)
	}
	switch {
	case raw.UserID == "":
		return IdentityLinkPayload{}, fmt.Errorf("projector: IdentityLinked requires user_id")
	case raw.ProviderID == "":
		return IdentityLinkPayload{}, fmt.Errorf("projector: IdentityLinked requires provider_id")
	case raw.ExternalID == "":
		return IdentityLinkPayload{}, fmt.Errorf("projector: IdentityLinked requires external_id")
	}
	out := IdentityLinkPayload{
		ID: e.StreamID, UserID: raw.UserID, ProviderID: raw.ProviderID, ExternalID: raw.ExternalID,
	}
	if raw.ExternalEmail != nil {
		out.ExternalEmail = *raw.ExternalEmail
	}
	if raw.ExternalName != nil {
		out.ExternalName = *raw.ExternalName
	}
	return out, nil
}

// IdentityLinkLoginUpdatedFromEvent decodes IdentityLinkLoginUpdated.
// provider_id + external_id are the lookup key; external_email and
// external_name are NULLIF-semantic (empty preserves existing).
func IdentityLinkLoginUpdatedFromEvent(e store.PersistedEvent) (IdentityLinkPayload, error) {
	if e.StreamType != "identity_provider" || e.EventType != "IdentityLinkLoginUpdated" {
		return IdentityLinkPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return IdentityLinkPayload{}, fmt.Errorf("projector: empty IdentityLinkLoginUpdated payload")
	}
	var raw struct {
		ProviderID    string `json:"provider_id"`
		ExternalID    string `json:"external_id"`
		ExternalEmail string `json:"external_email"`
		ExternalName  string `json:"external_name"`
	}
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return IdentityLinkPayload{}, fmt.Errorf("projector: invalid IdentityLinkLoginUpdated payload: %w", err)
	}
	switch {
	case raw.ProviderID == "":
		return IdentityLinkPayload{}, fmt.Errorf("projector: IdentityLinkLoginUpdated requires provider_id")
	case raw.ExternalID == "":
		return IdentityLinkPayload{}, fmt.Errorf("projector: IdentityLinkLoginUpdated requires external_id")
	}
	return IdentityLinkPayload{
		ID:            e.StreamID,
		ProviderID:    raw.ProviderID,
		ExternalID:    raw.ExternalID,
		ExternalEmail: raw.ExternalEmail,
		ExternalName:  raw.ExternalName,
	}, nil
}

// SCIMTokenFromEvent decodes IdentityProviderSCIMEnabled or
// IdentityProviderSCIMTokenRotated. Both carry the same shape;
// a single decoder + caller-side dispatch keeps the listener clean.
func SCIMTokenFromEvent(e store.PersistedEvent, eventType string) (SCIMTokenPayload, error) {
	if e.StreamType != "identity_provider" || e.EventType != eventType {
		return SCIMTokenPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return SCIMTokenPayload{}, fmt.Errorf("projector: empty %s payload", eventType)
	}
	var raw struct {
		ScimTokenHash string `json:"scim_token_hash"`
	}
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return SCIMTokenPayload{}, fmt.Errorf("projector: invalid %s payload: %w", eventType, err)
	}
	if raw.ScimTokenHash == "" {
		return SCIMTokenPayload{}, fmt.Errorf("projector: %s requires scim_token_hash", eventType)
	}
	return SCIMTokenPayload{ID: e.StreamID, ScimTokenHash: raw.ScimTokenHash}, nil
}

func nullifEmpty(p *string) *string {
	if p == nil || *p == "" {
		return nil
	}
	return p
}
