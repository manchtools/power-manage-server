package auth

// AuthzInput represents the input to the authorization check.
type AuthzInput struct {
	Permissions []string `json:"permissions,omitempty"` // user's permissions from JWT
	SubjectID   string   `json:"subject_id"`
	Action      string   `json:"action"`
	ResourceID  string   `json:"resource_id,omitempty"`
}

// Authorize checks whether the given input is authorized. Agents authenticate
// to the gateway over mTLS and never reach this control-plane interceptor, so
// authorization here is permission-based user access only.
func Authorize(input AuthzInput) bool {
	return authorizeUser(input)
}

// authorizeUser checks permission-based user access.
func authorizeUser(input AuthzInput) bool {
	for _, p := range input.Permissions {
		// Rule 1: Unrestricted permission match
		if p == input.Action {
			return true
		}

		// Rule 2+3: Self-scoped
		if p == input.Action+":self" {
			// No resource ID → creation action, handler enforces restriction
			if input.ResourceID == "" {
				return true
			}
			// Resource belongs to the requesting user
			if input.ResourceID == input.SubjectID {
				return true
			}
		}

		// Rule 4: Assigned-scope (SQL-level filtering handles actual data check)
		if p == input.Action+":assigned" {
			return true
		}
	}
	return false
}
