// User → SCIM resource translation. Extracted from users.go (audit
// F009 / #149, slice 1) and DRY'd: the four near-identical converter
// functions in the original file shared the same SCIM-resource shape
// but differed only by their input row type. They now route through a
// single field-bag helper, dropping ~120 LOC of mechanical duplication
// without changing the wire shape.
//
// safeNameField is also lifted here since it's a pure SCIMName helper.
package scim

import (
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// scimUserFields is the minimal projection of any user row that the
// SCIM resource shaper consumes. All four DB row types
// (UsersProjection / ListSCIMUsersRow / FindSCIMUserByEmail*Row /
// FindSCIMUserByExternalIDRow) collapse to this shape; converters
// below extract the common fields then call scimUserFromFields.
type scimUserFields struct {
	ID, ExternalID, Email              string
	DisplayName, GivenName, FamilyName string
	Disabled                           bool
	CreatedAt, UpdatedAt               *time.Time
}

// scimUserFromFields builds the wire-shape SCIMUser. The Name block
// is only populated if at least one of the three name fields is set
// (matches pre-extract behaviour — empty Name would otherwise
// serialise as `"name": {}` and confuse some SCIM clients).
func scimUserFromFields(f scimUserFields, baseURL string) SCIMUser {
	su := SCIMUser{
		Schemas:    []string{UserSchema},
		ID:         f.ID,
		ExternalID: f.ExternalID,
		UserName:   f.Email,
		Active:     boolPtr(!f.Disabled),
		Emails: []SCIMEmail{
			{
				Value:   f.Email,
				Type:    "work",
				Primary: true,
			},
		},
		Meta: &SCIMMeta{
			ResourceType: "User",
			Location:     baseURL + "/Users/" + f.ID,
		},
	}
	if f.DisplayName != "" || f.GivenName != "" || f.FamilyName != "" {
		su.Name = &SCIMName{
			Formatted:  f.DisplayName,
			GivenName:  f.GivenName,
			FamilyName: f.FamilyName,
		}
	}
	if f.CreatedAt != nil {
		su.Meta.Created = f.CreatedAt.Format(time.RFC3339)
	}
	if f.UpdatedAt != nil {
		su.Meta.LastModified = f.UpdatedAt.Format(time.RFC3339)
	}
	return su
}

// userToSCIM converts a UsersProjection (which doesn't carry the
// ScimExternalID column directly — it lives on the
// scim_user_links table) plus an externally-resolved externalID
// into a SCIM resource.
func userToSCIM(user store.User, externalID, baseURL string) SCIMUser {
	return scimUserFromFields(scimUserFields{
		ID:          user.ID,
		ExternalID:  externalID,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		GivenName:   user.GivenName,
		FamilyName:  user.FamilyName,
		Disabled:    user.Disabled,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}, baseURL)
}

// userRowToSCIM converts a ListSCIMUsersRow to a SCIM user resource.
func userRowToSCIM(row db.ListSCIMUsersRow, baseURL string) SCIMUser {
	return scimUserFromFields(scimUserFields{
		ID:          row.ID,
		ExternalID:  row.ScimExternalID,
		Email:       row.Email,
		DisplayName: row.DisplayName,
		GivenName:   row.GivenName,
		FamilyName:  row.FamilyName,
		Disabled:    row.Disabled,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, baseURL)
}

// findUserRowToSCIM converts a FindSCIMUserByEmailRow to a SCIM user resource.
func findUserRowToSCIM(row db.FindSCIMUserByEmailRow, baseURL string) SCIMUser {
	return scimUserFromFields(scimUserFields{
		ID:          row.ID,
		ExternalID:  row.ScimExternalID,
		Email:       row.Email,
		DisplayName: row.DisplayName,
		GivenName:   row.GivenName,
		FamilyName:  row.FamilyName,
		Disabled:    row.Disabled,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, baseURL)
}

// findExternalIDUserRowToSCIM converts a FindSCIMUserByExternalIDRow to a SCIM user resource.
func findExternalIDUserRowToSCIM(row db.FindSCIMUserByExternalIDRow, baseURL string) SCIMUser {
	return scimUserFromFields(scimUserFields{
		ID:          row.ID,
		ExternalID:  row.ScimExternalID,
		Email:       row.Email,
		DisplayName: row.DisplayName,
		GivenName:   row.GivenName,
		FamilyName:  row.FamilyName,
		Disabled:    row.Disabled,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, baseURL)
}

// safeNameField extracts a specific name field from a SCIMName. nil
// SCIMName collapses to "" so callers don't need their own nil-guard.
func safeNameField(name *SCIMName, field string) string {
	if name == nil {
		return ""
	}
	switch field {
	case "given":
		return name.GivenName
	case "family":
		return name.FamilyName
	default:
		return ""
	}
}
