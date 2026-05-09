package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// UserRoleAssignedPayload is the decoded shape of a UserRoleAssigned
// event. Both fields are required — they're the (composite-key)
// columns of the row this projector inserts.
type UserRoleAssignedPayload struct {
	UserID     string `json:"user_id"`
	RoleID     string `json:"role_id"`
	AssignedBy string // populated from event.actor_id, not the JSON payload
}

// UserRoleRevokedPayload mirrors the assigned shape; same composite
// key, same required-field semantics.
type UserRoleRevokedPayload struct {
	UserID string `json:"user_id"`
	RoleID string `json:"role_id"`
}

// UserRoleAssignedFromEvent decodes UserRoleAssigned. Returns
// ErrIgnoredEvent for any other (stream, event_type) so the listener
// wrapper can silently no-op.
func UserRoleAssignedFromEvent(e store.PersistedEvent) (UserRoleAssignedPayload, error) {
	if e.StreamType != "user_role" || e.EventType != string(eventtypes.UserRoleAssigned) {
		return UserRoleAssignedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return UserRoleAssignedPayload{}, fmt.Errorf("projector: empty UserRoleAssigned payload")
	}
	var p UserRoleAssignedPayload
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return UserRoleAssignedPayload{}, fmt.Errorf("projector: invalid UserRoleAssigned payload: %w", err)
	}
	switch {
	case p.UserID == "":
		return UserRoleAssignedPayload{}, fmt.Errorf("projector: UserRoleAssigned requires user_id")
	case p.RoleID == "":
		return UserRoleAssignedPayload{}, fmt.Errorf("projector: UserRoleAssigned requires role_id")
	}
	p.AssignedBy = e.ActorID
	return p, nil
}

// UserRoleRevokedFromEvent decodes UserRoleRevoked. Same validation
// shape as UserRoleAssigned — both composite-key fields required.
func UserRoleRevokedFromEvent(e store.PersistedEvent) (UserRoleRevokedPayload, error) {
	if e.StreamType != "user_role" || e.EventType != string(eventtypes.UserRoleRevoked) {
		return UserRoleRevokedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return UserRoleRevokedPayload{}, fmt.Errorf("projector: empty UserRoleRevoked payload")
	}
	var p UserRoleRevokedPayload
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return UserRoleRevokedPayload{}, fmt.Errorf("projector: invalid UserRoleRevoked payload: %w", err)
	}
	switch {
	case p.UserID == "":
		return UserRoleRevokedPayload{}, fmt.Errorf("projector: UserRoleRevoked requires user_id")
	case p.RoleID == "":
		return UserRoleRevokedPayload{}, fmt.Errorf("projector: UserRoleRevoked requires role_id")
	}
	return p, nil
}
