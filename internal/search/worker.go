package search

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"

	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// Worker processes search index update tasks from the Asynq search queue.
type Worker struct {
	rdb    *redis.Client
	logger *slog.Logger
}

// NewWorker creates a new search index worker.
func NewWorker(rdb *redis.Client, logger *slog.Logger) *Worker {
	return &Worker{rdb: rdb, logger: logger}
}

// RegisterHandlers registers the search task handlers on the given mux.
func (w *Worker) RegisterHandlers(mux *asynq.ServeMux) {
	mux.HandleFunc(taskqueue.TypeSearchReindex, w.handleReindex)
	mux.HandleFunc(taskqueue.TypeSearchMemberChange, w.handleMemberChange)
	mux.HandleFunc(taskqueue.TypeSearchRemove, w.handleRemove)
}

func (w *Worker) handleReindex(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.SearchReindexPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal reindex payload: %w", err)
	}
	if payload.Data == nil {
		return fmt.Errorf("reindex payload missing data")
	}

	logger := w.logger.With("scope", payload.Scope, "id", payload.ID)
	logger.Debug("reindexing entity")

	// Update the entity's search hash.
	key := hashKey(payload.Scope, payload.ID)
	fields := entityFields(payload.Scope, payload.Data)
	if err := w.rdb.HSet(ctx, key, fields).Err(); err != nil {
		return fmt.Errorf("hset %s: %w", key, err)
	}

	// Cascade to parents.
	return w.cascadeToParents(ctx, payload.Scope, payload.ID)
}

func (w *Worker) handleMemberChange(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.SearchMemberChangePayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal member change payload: %w", err)
	}

	logger := w.logger.With(
		"parent_scope", payload.ParentScope,
		"parent_id", payload.ParentID,
		"child_id", payload.ChildID,
		"action", payload.Action,
	)
	logger.Debug("processing member change")

	membersKey := forwardMembersKey(payload.ParentScope, payload.ParentID)
	reverseKey := reverseKey(payload.ChildScope, payload.ChildID)

	if payload.Action == "add" {
		pipe := w.rdb.Pipeline()
		pipe.SAdd(ctx, membersKey, payload.ChildID)
		pipe.SAdd(ctx, reverseKey, payload.ParentID)
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("sadd membership: %w", err)
		}
	} else {
		pipe := w.rdb.Pipeline()
		pipe.SRem(ctx, membersKey, payload.ChildID)
		pipe.SRem(ctx, reverseKey, payload.ParentID)
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("srem membership: %w", err)
		}
	}

	// Rebuild the parent's denormalized name fields + member_count.
	if err := w.rebuildParent(ctx, payload.ParentScope, payload.ParentID); err != nil {
		return fmt.Errorf("rebuild parent: %w", err)
	}

	// Cascade to grandparents (e.g., action_set change → cascade to definitions).
	return w.cascadeToParents(ctx, payload.ParentScope, payload.ParentID)
}

func (w *Worker) handleRemove(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.SearchRemovePayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal remove payload: %w", err)
	}

	logger := w.logger.With("scope", payload.Scope, "id", payload.ID)
	logger.Debug("removing entity from search index")

	pipe := w.rdb.Pipeline()
	pipe.Del(ctx, hashKey(payload.Scope, payload.ID))
	pipe.Del(ctx, reverseKeyForScope(payload.Scope, payload.ID))
	pipe.Del(ctx, forwardMembersKey(payload.Scope, payload.ID))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("del entity keys: %w", err)
	}

	// For each cascade parent, remove this entity from their membership and rebuild.
	for _, parentID := range payload.CascadeIDs {
		parentScope := parentScopeOf(payload.Scope)
		if parentScope == "" {
			continue
		}

		membersKey := forwardMembersKey(parentScope, parentID)
		w.rdb.SRem(ctx, membersKey, payload.ID)

		if err := w.rebuildParent(ctx, parentScope, parentID); err != nil {
			logger.Warn("failed to rebuild cascade parent", "parent_scope", parentScope, "parent_id", parentID, "error", err)
		}

		// Cascade further up (action_set parent → definition grandparent).
		if err := w.cascadeToParents(ctx, parentScope, parentID); err != nil {
			logger.Warn("failed to cascade to grandparents", "parent_scope", parentScope, "parent_id", parentID, "error", err)
		}
	}

	return nil
}

// cascadeToParents finds all parents of the given entity via reverse-lookup
// sets and rebuilds their denormalized fields.
func (w *Worker) cascadeToParents(ctx context.Context, scope, id string) error {
	rKey := reverseKeyForScope(scope, id)
	if rKey == "" {
		return nil // definitions have no parents
	}

	parentIDs, err := w.rdb.SMembers(ctx, rKey).Result()
	if err != nil {
		return fmt.Errorf("smembers %s: %w", rKey, err)
	}

	parentScope := parentScopeOf(scope)
	for _, pid := range parentIDs {
		if err := w.rebuildParent(ctx, parentScope, pid); err != nil {
			w.logger.Warn("failed to rebuild parent", "scope", parentScope, "id", pid, "error", err)
		}

		// Continue cascading up the hierarchy.
		if err := w.cascadeToParents(ctx, parentScope, pid); err != nil {
			w.logger.Warn("failed to cascade further", "scope", parentScope, "id", pid, "error", err)
		}
	}
	return nil
}

// rebuildParent rebuilds the denormalized name fields and member_count on a
// parent entity (action_set or definition) from current Valkey state.
func (w *Worker) rebuildParent(ctx context.Context, scope, id string) error {
	membersKey := forwardMembersKey(scope, id)
	memberIDs, err := w.rdb.SMembers(ctx, membersKey).Result()
	if err != nil {
		return fmt.Errorf("smembers %s: %w", membersKey, err)
	}

	parentKey := hashKey(scope, id)

	switch scope {
	case ScopeActionSet:
		// Rebuild action_names from member action hashes.
		var names []string
		for _, aid := range memberIDs {
			name, err := w.rdb.HGet(ctx, prefixAction+aid, "name").Result()
			if err == nil {
				names = append(names, name)
			}
		}
		return w.rdb.HSet(ctx, parentKey, map[string]any{
			"action_names": strings.Join(names, " "),
			"member_count": strconv.Itoa(len(memberIDs)),
		}).Err()

	case ScopeDefinition:
		// Rebuild set_names and action_names from member set hashes.
		var setNames []string
		var actionNames []string
		for _, sid := range memberIDs {
			name, err := w.rdb.HGet(ctx, prefixActionSet+sid, "name").Result()
			if err == nil {
				setNames = append(setNames, name)
			}
			// Also collect all action names from each set.
			actionIDs, err := w.rdb.SMembers(ctx, prefixMembersActionSet+sid).Result()
			if err == nil {
				for _, aid := range actionIDs {
					aName, err := w.rdb.HGet(ctx, prefixAction+aid, "name").Result()
					if err == nil {
						actionNames = append(actionNames, aName)
					}
				}
			}
		}
		return w.rdb.HSet(ctx, parentKey, map[string]any{
			"set_names":    strings.Join(setNames, " "),
			"action_names": strings.Join(actionNames, " "),
			"member_count": strconv.Itoa(len(memberIDs)),
		}).Err()
	}

	return nil
}

// --- helpers ---

func hashKey(scope, id string) string {
	switch scope {
	case ScopeAction:
		return prefixAction + id
	case ScopeActionSet:
		return prefixActionSet + id
	case ScopeDefinition:
		return prefixDefinition + id
	case ScopeCompliancePolicy:
		return prefixCompliancePolicy + id
	case ScopeExecution:
		return prefixExecution + id
	case ScopeAuditEvent:
		return prefixAuditEvent + id
	}
	return ""
}

func reverseKey(childScope, childID string) string {
	switch childScope {
	case ScopeAction:
		return prefixReverseAction + childID
	case ScopeActionSet:
		return prefixReverseActionSet + childID
	}
	return ""
}

func reverseKeyForScope(scope, id string) string {
	switch scope {
	case ScopeAction:
		return prefixReverseAction + id
	case ScopeActionSet:
		return prefixReverseActionSet + id
	}
	return "" // definitions have no parents
}

func forwardMembersKey(parentScope, parentID string) string {
	switch parentScope {
	case ScopeActionSet:
		return prefixMembersActionSet + parentID
	case ScopeDefinition:
		return prefixMembersDefinition + parentID
	}
	return ""
}

func parentScopeOf(childScope string) string {
	switch childScope {
	case ScopeAction:
		return ScopeActionSet
	case ScopeActionSet:
		return ScopeDefinition
	}
	return ""
}

func entityFields(scope string, data *taskqueue.SearchEntityData) map[string]any {
	switch scope {
	case ScopeAction:
		isCompliance := "false"
		if data.IsCompliance {
			isCompliance = "true"
		}
		fields := map[string]any{
			"name":          data.Name,
			"description":   data.Description,
			"type":          strconv.Itoa(int(data.Type)),
			"is_compliance": isCompliance,
		}
		if data.CreatedAt != 0 {
			fields["created_at"] = strconv.FormatInt(data.CreatedAt, 10)
		}
		if data.UpdatedAt != 0 {
			fields["updated_at"] = strconv.FormatInt(data.UpdatedAt, 10)
		}
		return fields
	case ScopeActionSet:
		fields := map[string]any{
			"name":         data.Name,
			"description":  data.Description,
			"member_count": strconv.Itoa(int(data.MemberCount)),
		}
		if data.CreatedAt != 0 {
			fields["created_at"] = strconv.FormatInt(data.CreatedAt, 10)
		}
		if data.UpdatedAt != 0 {
			fields["updated_at"] = strconv.FormatInt(data.UpdatedAt, 10)
		}
		return fields
	case ScopeDefinition:
		fields := map[string]any{
			"name":         data.Name,
			"description":  data.Description,
			"member_count": strconv.Itoa(int(data.MemberCount)),
		}
		if data.CreatedAt != 0 {
			fields["created_at"] = strconv.FormatInt(data.CreatedAt, 10)
		}
		if data.UpdatedAt != 0 {
			fields["updated_at"] = strconv.FormatInt(data.UpdatedAt, 10)
		}
		return fields
	case ScopeCompliancePolicy:
		return map[string]any{
			"name":         data.Name,
			"description":  data.Description,
			"action_names": data.ActionNames,
		}
	case ScopeExecution:
		fields := map[string]any{
			"action_name":     data.ActionName,
			"device_hostname": data.DeviceHostname,
			"status":          data.Status,
			"action_type":     strconv.Itoa(int(data.Type)),
			"device_id":       data.DeviceID,
			"action_id":       data.ActionID,
			"desired_state":   strconv.Itoa(int(data.DesiredState)),
			"changed":         strconv.FormatBool(data.Changed),
		}
		if data.CreatedAt != 0 {
			fields["created_at"] = strconv.FormatInt(data.CreatedAt, 10)
		}
		if data.DurationMs != 0 {
			fields["duration_ms"] = strconv.FormatInt(data.DurationMs, 10)
		}
		return fields
	case ScopeAuditEvent:
		fields := map[string]any{
			"event_type":  data.EventType,
			"stream_type": data.StreamType,
			"actor_type":  data.ActorType,
			"actor_id":    data.ActorID,
			"stream_id":   data.StreamID,
		}
		if data.OccurredAt != 0 {
			fields["occurred_at"] = strconv.FormatInt(data.OccurredAt, 10)
		}
		return fields
	}
	return nil
}
