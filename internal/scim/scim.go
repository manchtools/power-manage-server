// Package scim implements SCIM v2 REST endpoints for user and group provisioning.
package scim

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

// SCIM schema URIs.
const (
	UserSchema         = "urn:ietf:params:scim:schemas:core:2.0:User"
	GroupSchema        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	ListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	PatchOpSchema      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	ErrorSchema        = "urn:ietf:params:scim:api:messages:2.0:Error"
	SPConfigSchema     = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	ResourceTypeSchema = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema       = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// SCIM content type.
const scimContentType = "application/scim+json"

// maxSCIMBodySize is the maximum allowed SCIM request body size (1 MiB).
const maxSCIMBodySize = 1 << 20

// limitBody wraps r.Body with a size-limited reader and returns a cleanup func.
// If the body exceeds maxSCIMBodySize, json.Decode will fail with an error.
func limitBody(r *http.Request) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxSCIMBodySize)
}

// SCIMError represents a SCIM protocol error response.
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
}

// SCIMListResponse is a SCIM list response envelope.
type SCIMListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

// SCIMUser represents a SCIM user resource.
type SCIMUser struct {
	Schemas    []string    `json:"schemas"`
	ID         string      `json:"id"`
	ExternalID string      `json:"externalId,omitempty"`
	UserName   string      `json:"userName"`
	Name       *SCIMName   `json:"name,omitempty"`
	Emails     []SCIMEmail `json:"emails,omitempty"`
	Active     *bool       `json:"active,omitempty"`
	Meta       *SCIMMeta   `json:"meta,omitempty"`
}

// IsActive returns the active status, defaulting to true per SCIM RFC 7643
// when the field is omitted from the JSON payload.
func (u SCIMUser) IsActive() bool {
	if u.Active == nil {
		return true
	}
	return *u.Active
}

func boolPtr(b bool) *bool { return &b }

// SCIMName represents the name component of a SCIM user.
type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

// SCIMEmail represents an email in a SCIM user.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMMeta represents SCIM resource metadata.
type SCIMMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location,omitempty"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

// SCIMGroup represents a SCIM group resource.
type SCIMGroup struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []SCIMMember `json:"members,omitempty"`
	Meta        *SCIMMeta    `json:"meta,omitempty"`
}

// SCIMMember represents a member reference in a SCIM group.
type SCIMMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// SCIMPatchOpType is the typed `op` value of a SCIM PATCH operation.
// SCIM PATCH (RFC 7644 §3.5.2) defines exactly three verbs — add,
// remove, replace — and identity providers occasionally vary case.
// A typed alias plus the canonical-form constants below keep callers
// off raw string literals while leaving the JSON wire format
// unchanged (lowercase per the RFC).
type SCIMPatchOpType string

const (
	// SCIMPatchOpAdd appends a value to a multi-valued attribute, or
	// sets an attribute that has no current value.
	SCIMPatchOpAdd SCIMPatchOpType = "add"
	// SCIMPatchOpRemove deletes the addressed value(s) from the target
	// attribute. Path is required (RFC 7644 §3.5.2.2).
	SCIMPatchOpRemove SCIMPatchOpType = "remove"
	// SCIMPatchOpReplace overwrites the target with the supplied value;
	// behaves like add when no current value exists.
	SCIMPatchOpReplace SCIMPatchOpType = "replace"
)

// IsValid reports whether the op is one of the three RFC 7644 verbs
// after lowercasing. Used at the request boundary to reject unknown
// ops with HTTP 400 instead of silently no-op-ing them inside the
// per-op switch.
func (o SCIMPatchOpType) IsValid() bool {
	switch SCIMPatchOpType(strings.ToLower(string(o))) {
	case SCIMPatchOpAdd, SCIMPatchOpRemove, SCIMPatchOpReplace:
		return true
	default:
		return false
	}
}

// Normalize returns the lowercase canonical form so callers can switch
// on the constants without sprinkling strings.ToLower at every site.
func (o SCIMPatchOpType) Normalize() SCIMPatchOpType {
	return SCIMPatchOpType(strings.ToLower(string(o)))
}

// SCIMPatchOp represents a single SCIM PATCH operation.
type SCIMPatchOp struct {
	Op    SCIMPatchOpType `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value any             `json:"value,omitempty"`
}

// SCIMPatchRequest represents a SCIM PATCH request body.
type SCIMPatchRequest struct {
	Schemas    []string      `json:"schemas"`
	Operations []SCIMPatchOp `json:"Operations"`
}

// writeJSON writes a JSON response with the given status code and SCIM content type.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("failed to encode SCIM JSON response", "error", err)
	}
}

// writeError writes a SCIM-formatted error response.
func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, SCIMError{
		Schemas: []string{ErrorSchema},
		Detail:  detail,
		Status:  strconv.Itoa(status),
	})
}
