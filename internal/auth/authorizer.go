package auth

// AuthzInput represents the input to the authorization check.
type AuthzInput struct {
	Permissions []string `json:"permissions,omitempty"` // user's permissions from JWT
	SubjectID   string   `json:"subject_id"`
	Action      string   `json:"action"`
	ResourceID  string   `json:"resource_id,omitempty"`
	DeviceID    string   `json:"device_id,omitempty"` // device context for execution queries
	IsDevice    bool     `json:"is_device,omitempty"` // true when caller is a device
}

// Authorize checks whether the given input is authorized.
// It implements the same four user rules and four device rules
// that were previously expressed in OPA Rego.
func Authorize(input AuthzInput) bool {
	if input.IsDevice {
		return authorizeDevice(input)
	}
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

// authorizeDevice checks hardcoded device access rules.
func authorizeDevice(input AuthzInput) bool {
	switch input.Action {
	case "GetDevice":
		// Devices can only view themselves
		return input.ResourceID == input.SubjectID

	case "ListDefinitions", "GetDefinition":
		// Devices can view definitions (needed to execute actions)
		return true

	case "ListExecutions", "GetExecution":
		// Devices can view their own executions
		return input.DeviceID == input.SubjectID

	case "Heartbeat", "UpdateStatus":
		// Devices can send heartbeats and status updates
		return true

	default:
		return false
	}
}
