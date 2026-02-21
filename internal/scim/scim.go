// Package scim implements SCIM v2 REST endpoints for user and group provisioning.
package scim

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// SCIM schema URIs.
const (
	UserSchema            = "urn:ietf:params:scim:schemas:core:2.0:User"
	GroupSchema           = "urn:ietf:params:scim:schemas:core:2.0:Group"
	ListResponseSchema    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	PatchOpSchema         = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	ErrorSchema           = "urn:ietf:params:scim:api:messages:2.0:Error"
	SPConfigSchema        = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	ResourceTypeSchema    = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema          = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// SCIM content type.
const scimContentType = "application/scim+json"

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
	Active     bool        `json:"active"`
	Meta       *SCIMMeta   `json:"meta,omitempty"`
}

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

// SCIMPatchOp represents a single SCIM PATCH operation.
type SCIMPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
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
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a SCIM-formatted error response.
func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, SCIMError{
		Schemas: []string{ErrorSchema},
		Detail:  detail,
		Status:  strconv.Itoa(status),
	})
}
