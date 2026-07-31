package scim

import (
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
)

// userResource shapes a stored subject as a SCIM user resource.
//
// The external identifier is a property of the BINDING, not of the
// subject, so it is passed in: the same subject presents a different
// one to each directory it is bound to.
//
// The name block is omitted entirely when the subject has no name
// fields. An empty `"name": {}` is not the same claim, and directories
// differ in how they read it.
func userResource(row store.UserRow, externalID, baseURL string) SCIMUser {
	out := SCIMUser{
		Schemas:    []string{UserSchema},
		ID:         row.ID,
		ExternalID: externalID,
		UserName:   row.Email,
		Active:     boolPtr(!row.Disabled),
		Emails: []SCIMEmail{{
			Value:   row.Email,
			Type:    "work",
			Primary: true,
		}},
		Meta: &SCIMMeta{
			ResourceType: "User",
			Location:     baseURL + "/Users/" + row.ID,
		},
	}
	if row.DisplayName != "" || row.GivenName != "" || row.FamilyName != "" {
		out.Name = &SCIMName{
			Formatted:  row.DisplayName,
			GivenName:  row.GivenName,
			FamilyName: row.FamilyName,
		}
	}
	if row.CreatedAt != nil {
		out.Meta.Created = row.CreatedAt.Format(time.RFC3339)
	}
	if row.UpdatedAt != nil {
		out.Meta.LastModified = row.UpdatedAt.Format(time.RFC3339)
	}
	return out
}
