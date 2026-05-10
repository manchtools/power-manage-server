package testutil

// Action / action-set / definition / assignment / token fixtures.
// All the things that make up an action's lifecycle from creation
// through containment in a set or definition through assignment to
// a target through dispatch.

import (
	"context"
	"testing"
	"time"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// CreateTestAction creates an action via events and returns the action ID.
func CreateTestAction(t *testing.T, st *store.Store, actorID, name string, actionType int) string {
	t.Helper()
	return CreateTestActionWithDesiredState(t, st, actorID, name, actionType, 0)
}

// CreateTestActionWithDesiredState creates an action via events with an explicit desired_state.
func CreateTestActionWithDesiredState(t *testing.T, st *store.Store, actorID, name string, actionType, desiredState int) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   id,
		EventType:  string(eventtypes.ActionCreated),
		Data: map[string]any{
			"name":            name,
			"action_type":     actionType,
			"desired_state":   desiredState,
			"params":          map[string]any{},
			"timeout_seconds": 300,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test action: %v", err)
	}

	return id
}

// CreateTestActionSet creates an action set via events and returns the action set ID.
func CreateTestActionSet(t *testing.T, st *store.Store, actorID, name string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "action_set",
		StreamID:   id,
		EventType:  string(eventtypes.ActionSetCreated),
		Data: map[string]any{
			"name": name,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test action set: %v", err)
	}

	return id
}

// CreateTestDefinition creates a definition via events and returns the definition ID.
func CreateTestDefinition(t *testing.T, st *store.Store, actorID, name string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "definition",
		StreamID:   id,
		EventType:  string(eventtypes.DefinitionCreated),
		Data: map[string]any{
			"name": name,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test definition: %v", err)
	}

	return id
}

// CreateTestToken creates a registration token via events and returns the token ID.
func CreateTestToken(t *testing.T, st *store.Store, actorID, name, valueHash string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "token",
		StreamID:   id,
		EventType:  string(eventtypes.TokenCreated),
		Data: map[string]any{
			"name":       name,
			"value_hash": valueHash,
			"one_time":   false,
			"max_uses":   0,
			"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test token: %v", err)
	}

	return id
}

// CreateTestAssignment creates an assignment via events and returns its ID.
func CreateTestAssignment(t *testing.T, st *store.Store, actorID, sourceType, sourceID, targetType, targetID string, mode int) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "assignment",
		StreamID:   id,
		EventType:  string(eventtypes.AssignmentCreated),
		Data: map[string]any{
			"source_type": sourceType,
			"source_id":   sourceID,
			"target_type": targetType,
			"target_id":   targetID,
			"mode":        int32(mode),
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test assignment: %v", err)
	}

	return id
}

// AddActionToTestSet adds an action to an action set via events.
func AddActionToTestSet(t *testing.T, st *store.Store, actorID, setID, actionID string, sortOrder int) {
	t.Helper()
	ctx := context.Background()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "action_set",
		StreamID:   setID,
		EventType:  string(eventtypes.ActionSetMemberAdded),
		Data: map[string]any{
			"action_id":  actionID,
			"sort_order": sortOrder,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("add action to test set: %v", err)
	}
}

// AddActionSetToTestDefinition adds an action set to a definition via events.
func AddActionSetToTestDefinition(t *testing.T, st *store.Store, actorID, definitionID, actionSetID string, sortOrder int) {
	t.Helper()
	ctx := context.Background()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "definition",
		StreamID:   definitionID,
		EventType:  string(eventtypes.DefinitionMemberAdded),
		Data: map[string]any{
			"action_set_id": actionSetID,
			"sort_order":    sortOrder,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("add action set to test definition: %v", err)
	}
}
