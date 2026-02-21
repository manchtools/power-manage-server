package scim

import (
	"net/http"
)

// serviceProviderConfig handles GET /scim/v2/{slug}/ServiceProviderConfig
func (h *Handler) serviceProviderConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]any{
		"schemas": []string{SPConfigSchema},
		"documentationUri": "https://tools.ietf.org/html/rfc7644",
		"patch": map[string]any{
			"supported": true,
		},
		"bulk": map[string]any{
			"supported":  false,
			"maxOperations": 0,
			"maxPayloadSize": 0,
		},
		"filter": map[string]any{
			"supported":  true,
			"maxResults": 200,
		},
		"changePassword": map[string]any{
			"supported": false,
		},
		"sort": map[string]any{
			"supported": false,
		},
		"etag": map[string]any{
			"supported": false,
		},
		"authenticationSchemes": []map[string]any{
			{
				"type":             "oauthbearertoken",
				"name":             "OAuth Bearer Token",
				"description":      "Authentication scheme using the OAuth Bearer Token Standard",
				"specUri":          "https://tools.ietf.org/html/rfc6750",
				"documentationUri": "https://tools.ietf.org/html/rfc6750",
				"primary":          true,
			},
		},
		"meta": map[string]any{
			"resourceType": "ServiceProviderConfig",
			"location":     baseURLFromRequest(r, r.PathValue("slug")) + "/ServiceProviderConfig",
		},
	}

	writeJSON(w, http.StatusOK, config)
}

// schemas handles GET /scim/v2/{slug}/Schemas
func (h *Handler) schemas(w http.ResponseWriter, r *http.Request) {
	baseURL := baseURLFromRequest(r, r.PathValue("slug"))

	userSchema := map[string]any{
		"schemas":     []string{SchemaSchema},
		"id":          UserSchema,
		"name":        "User",
		"description": "User Account",
		"attributes": []map[string]any{
			{
				"name":        "userName",
				"type":        "string",
				"multiValued": false,
				"description": "Unique identifier for the User, typically used by the user to directly authenticate.",
				"required":    true,
				"caseExact":   false,
				"mutability":  "readWrite",
				"returned":    "default",
				"uniqueness":  "server",
			},
			{
				"name":        "name",
				"type":        "complex",
				"multiValued": false,
				"description": "The components of the user's name.",
				"required":    false,
				"subAttributes": []map[string]any{
					{
						"name":        "formatted",
						"type":        "string",
						"multiValued": false,
						"description": "The full name.",
						"required":    false,
						"mutability":  "readWrite",
						"returned":    "default",
					},
					{
						"name":        "familyName",
						"type":        "string",
						"multiValued": false,
						"description": "The family name of the user.",
						"required":    false,
						"mutability":  "readWrite",
						"returned":    "default",
					},
					{
						"name":        "givenName",
						"type":        "string",
						"multiValued": false,
						"description": "The given name of the user.",
						"required":    false,
						"mutability":  "readWrite",
						"returned":    "default",
					},
				},
				"mutability": "readWrite",
				"returned":   "default",
			},
			{
				"name":        "emails",
				"type":        "complex",
				"multiValued": true,
				"description": "Email addresses for the user.",
				"required":    false,
				"subAttributes": []map[string]any{
					{
						"name":        "value",
						"type":        "string",
						"multiValued": false,
						"description": "Email address.",
						"required":    false,
						"mutability":  "readWrite",
						"returned":    "default",
					},
					{
						"name":        "type",
						"type":        "string",
						"multiValued": false,
						"description": "A label indicating the email type.",
						"required":    false,
						"mutability":  "readWrite",
						"returned":    "default",
					},
					{
						"name":        "primary",
						"type":        "boolean",
						"multiValued": false,
						"description": "Indicates if this is the primary email.",
						"required":    false,
						"mutability":  "readWrite",
						"returned":    "default",
					},
				},
				"mutability": "readWrite",
				"returned":   "default",
			},
			{
				"name":        "active",
				"type":        "boolean",
				"multiValued": false,
				"description": "A Boolean value indicating the user's administrative status.",
				"required":    false,
				"mutability":  "readWrite",
				"returned":    "default",
			},
			{
				"name":        "externalId",
				"type":        "string",
				"multiValued": false,
				"description": "An identifier for the resource as defined by the provisioning client.",
				"required":    false,
				"caseExact":   true,
				"mutability":  "readWrite",
				"returned":    "default",
			},
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     baseURL + "/Schemas/" + UserSchema,
		},
	}

	groupSchema := map[string]any{
		"schemas":     []string{SchemaSchema},
		"id":          GroupSchema,
		"name":        "Group",
		"description": "Group",
		"attributes": []map[string]any{
			{
				"name":        "displayName",
				"type":        "string",
				"multiValued": false,
				"description": "A human-readable name for the Group.",
				"required":    true,
				"caseExact":   false,
				"mutability":  "readWrite",
				"returned":    "default",
				"uniqueness":  "none",
			},
			{
				"name":        "members",
				"type":        "complex",
				"multiValued": true,
				"description": "A list of members of the Group.",
				"required":    false,
				"subAttributes": []map[string]any{
					{
						"name":        "value",
						"type":        "string",
						"multiValued": false,
						"description": "Identifier of the member.",
						"required":    false,
						"mutability":  "immutable",
						"returned":    "default",
					},
					{
						"name":        "$ref",
						"type":        "reference",
						"multiValued": false,
						"description": "The URI of the member resource.",
						"required":    false,
						"mutability":  "immutable",
						"returned":    "default",
					},
					{
						"name":        "display",
						"type":        "string",
						"multiValued": false,
						"description": "A human-readable name for the member.",
						"required":    false,
						"mutability":  "readOnly",
						"returned":    "default",
					},
				},
				"mutability": "readWrite",
				"returned":   "default",
			},
			{
				"name":        "externalId",
				"type":        "string",
				"multiValued": false,
				"description": "An identifier for the resource as defined by the provisioning client.",
				"required":    false,
				"caseExact":   true,
				"mutability":  "readWrite",
				"returned":    "default",
			},
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     baseURL + "/Schemas/" + GroupSchema,
		},
	}

	writeJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: 2,
		StartIndex:   1,
		ItemsPerPage: 2,
		Resources:    []any{userSchema, groupSchema},
	})
}

// resourceTypes handles GET /scim/v2/{slug}/ResourceTypes
func (h *Handler) resourceTypes(w http.ResponseWriter, r *http.Request) {
	baseURL := baseURLFromRequest(r, r.PathValue("slug"))

	userResourceType := map[string]any{
		"schemas":     []string{ResourceTypeSchema},
		"id":          "User",
		"name":        "User",
		"description": "User Account",
		"endpoint":    "/Users",
		"schema":      UserSchema,
		"meta": map[string]any{
			"resourceType": "ResourceType",
			"location":     baseURL + "/ResourceTypes/User",
		},
	}

	groupResourceType := map[string]any{
		"schemas":     []string{ResourceTypeSchema},
		"id":          "Group",
		"name":        "Group",
		"description": "Group",
		"endpoint":    "/Groups",
		"schema":      GroupSchema,
		"meta": map[string]any{
			"resourceType": "ResourceType",
			"location":     baseURL + "/ResourceTypes/Group",
		},
	}

	writeJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: 2,
		StartIndex:   1,
		ItemsPerPage: 2,
		Resources:    []any{userResourceType, groupResourceType},
	})
}
