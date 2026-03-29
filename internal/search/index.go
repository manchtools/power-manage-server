// Package search provides a Valkey RediSearch-backed full-text search index
// for actions, action sets, and definitions. Index updates are dispatched via
// Asynq tasks for reliability; the worker handlers live in worker.go.
package search

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/redis/go-redis/v9"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// Valkey key prefixes and index names.
const (
	// Search hash prefixes — indexed by RediSearch.
	prefixAction           = "search:action:"
	prefixActionSet        = "search:action_set:"
	prefixDefinition       = "search:definition:"
	prefixCompliancePolicy = "search:compliance_policy:"

	// Reverse-lookup sets: child → set of parent IDs.
	prefixReverseAction    = "reverse:action:"
	prefixReverseActionSet = "reverse:action_set:"

	// Forward membership sets: parent → set of child IDs.
	prefixMembersActionSet  = "members:action_set:"
	prefixMembersDefinition = "members:definition:"

	// Search hash prefixes for executions and audit events.
	prefixExecution  = "search:execution:"
	prefixAuditEvent = "search:audit_event:"

	// RediSearch index names.
	idxActions            = "idx:actions"
	idxActionSets         = "idx:action_sets"
	idxDefinitions        = "idx:definitions"
	idxCompliancePolicies = "idx:compliance_policies"
	idxExecutions         = "idx:executions"
	idxAuditEvents        = "idx:audit_events"

	// Warm window for high-volume data.
	executionWarmDays = 90
	auditWarmDays     = 90
)

// Scope constants used in task payloads and RPC requests.
const (
	ScopeAction           = "action"
	ScopeActionSet        = "action_set"
	ScopeDefinition       = "definition"
	ScopeCompliancePolicy = "compliance_policy"
	ScopeExecution        = "execution"
	ScopeAuditEvent       = "audit_event"
)

// Index manages the RediSearch full-text search indexes in Valkey.
type Index struct {
	rdb      *redis.Client
	store    *store.Store
	aqClient *taskqueue.Client
	logger   *slog.Logger

	mu        sync.Mutex
	rebuilding bool
}

// New creates a new search Index.
func New(rdb *redis.Client, st *store.Store, aqClient *taskqueue.Client, logger *slog.Logger) *Index {
	return &Index{
		rdb:      rdb,
		store:    st,
		aqClient: aqClient,
		logger:   logger,
	}
}

// RDB returns the underlying Redis client (used by the search handler for FT.SEARCH).
func (idx *Index) RDB() *redis.Client {
	return idx.rdb
}

// FlushSearchData drops all FT indexes and removes all search hashes,
// reverse-lookup sets, and forward membership keys.
func (idx *Index) FlushSearchData(ctx context.Context) error {
	// Drop FT indexes (valkey-search does not support the DD flag).
	for _, name := range []string{idxActions, idxActionSets, idxDefinitions, idxCompliancePolicies, idxExecutions, idxAuditEvents} {
		err := idx.rdb.Do(ctx, "FT.DROPINDEX", name).Err()
		if err != nil && !strings.Contains(err.Error(), "Unknown index") && !strings.Contains(err.Error(), "Unknown Index") && !strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("drop index %s: %w", name, err)
		}
	}

	// Delete search hashes, reverse-lookup sets, and forward membership keys via SCAN.
	for _, pattern := range []string{"search:*", "reverse:*", "members:*"} {
		var cursor uint64
		for {
			keys, next, err := idx.rdb.Scan(ctx, cursor, pattern, 100).Result()
			if err != nil {
				return fmt.Errorf("scan %s: %w", pattern, err)
			}
			if len(keys) > 0 {
				if err := idx.rdb.Del(ctx, keys...).Err(); err != nil {
					return fmt.Errorf("del %s keys: %w", pattern, err)
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
	}

	return nil
}

// EnsureIndexes creates the RediSearch FT indexes if they don't already exist.
func (idx *Index) EnsureIndexes(ctx context.Context) error {
	indexes := []struct {
		name   string
		prefix string
		schema []any
	}{
		{
			name:   idxActions,
			prefix: prefixAction,
			schema: []any{
				"name", "TEXT",
				"description", "TEXT",
				"type", "TAG",
				"is_compliance", "TAG",
				"created_at", "NUMERIC", "SORTABLE",
				"updated_at", "NUMERIC", "SORTABLE",
			},
		},
		{
			name:   idxActionSets,
			prefix: prefixActionSet,
			schema: []any{
				"name", "TEXT",
				"description", "TEXT",
				"member_count", "NUMERIC",
				"action_names", "TEXT",
				"created_at", "NUMERIC", "SORTABLE",
				"updated_at", "NUMERIC", "SORTABLE",
			},
		},
		{
			name:   idxDefinitions,
			prefix: prefixDefinition,
			schema: []any{
				"name", "TEXT",
				"description", "TEXT",
				"member_count", "NUMERIC",
				"set_names", "TEXT",
				"action_names", "TEXT",
				"created_at", "NUMERIC", "SORTABLE",
				"updated_at", "NUMERIC", "SORTABLE",
			},
		},
		{
			name:   idxCompliancePolicies,
			prefix: prefixCompliancePolicy,
			schema: []any{
				"name", "TEXT",
				"description", "TEXT",
				"action_names", "TEXT",
			},
		},
		{
			name:   idxExecutions,
			prefix: prefixExecution,
			schema: []any{
				"action_name", "TEXT",
				"device_hostname", "TEXT",
				"status", "TAG",
				"action_type", "TAG",
				"device_id", "TAG",
				"created_at", "NUMERIC", "SORTABLE",
			},
		},
		{
			name:   idxAuditEvents,
			prefix: prefixAuditEvent,
			schema: []any{
				"event_type", "TEXT",
				"stream_type", "TAG",
				"actor_type", "TAG",
				"actor_id", "TAG",
				"occurred_at", "NUMERIC", "SORTABLE",
			},
		},
	}

	for _, ix := range indexes {
		args := []any{"FT.CREATE", ix.name, "ON", "HASH", "PREFIX", "1", ix.prefix, "SCHEMA"}
		args = append(args, ix.schema...)
		err := idx.rdb.Do(ctx, args...).Err()
		if err != nil {
			if strings.Contains(err.Error(), "Index already exists") {
				continue
			}
			return fmt.Errorf("create index %s: %w", ix.name, err)
		}
	}

	return nil
}

// Warm performs a full rebuild of all search data from PostgreSQL.
// This is the only operation that reads from PG for search purposes.
func (idx *Index) Warm(ctx context.Context) error {
	idx.logger.Info("warming search index from database")
	start := time.Now()

	// 1. Index all actions.
	actionCount, err := idx.warmActions(ctx)
	if err != nil {
		return fmt.Errorf("warm actions: %w", err)
	}

	// 2. Index all action sets + their memberships.
	setCount, err := idx.warmActionSets(ctx)
	if err != nil {
		return fmt.Errorf("warm action sets: %w", err)
	}

	// 3. Index all definitions + their memberships.
	defCount, err := idx.warmDefinitions(ctx)
	if err != nil {
		return fmt.Errorf("warm definitions: %w", err)
	}

	// 4. Index all compliance policies.
	policyCount, err := idx.warmCompliancePolicies(ctx)
	if err != nil {
		return fmt.Errorf("warm compliance policies: %w", err)
	}

	// 5. Index recent executions (last 90 days).
	execCount, err := idx.warmExecutions(ctx)
	if err != nil {
		return fmt.Errorf("warm executions: %w", err)
	}

	// 6. Index recent audit events (last 90 days).
	auditCount, err := idx.warmAuditEvents(ctx)
	if err != nil {
		return fmt.Errorf("warm audit events: %w", err)
	}

	idx.logger.Info("search index warm complete",
		"actions", actionCount,
		"action_sets", setCount,
		"definitions", defCount,
		"compliance_policies", policyCount,
		"executions", execCount,
		"audit_events", auditCount,
		"duration", time.Since(start),
	)
	return nil
}

func (idx *Index) warmActions(ctx context.Context) (int, error) {
	const pageSize int32 = 500
	var offset int32
	var total int

	for {
		actions, err := idx.store.Queries().ListActions(ctx, db.ListActionsParams{
			Column1: 0, // no type filter
			Limit:   pageSize,
			Offset:  offset,
		})
		if err != nil {
			return total, err
		}
		if len(actions) == 0 {
			break
		}

		pipe := idx.rdb.Pipeline()
		for _, a := range actions {
			desc := ""
			if a.Description != nil {
				desc = *a.Description
			}
			isCompliance := "false"
			var params map[string]any
			if json.Unmarshal(a.Params, &params) == nil {
				if v, ok := params["isCompliance"].(bool); ok && v {
					isCompliance = "true"
				}
			}
			fields := map[string]any{
				"name":          a.Name,
				"description":   desc,
				"type":          strconv.Itoa(int(a.ActionType)),
				"is_compliance": isCompliance,
			}
			if a.CreatedAt != nil {
				fields["created_at"] = strconv.FormatInt(a.CreatedAt.Unix(), 10)
			}
			if a.UpdatedAt != nil {
				fields["updated_at"] = strconv.FormatInt(a.UpdatedAt.Unix(), 10)
			}
			pipe.HSet(ctx, prefixAction+a.ID, fields)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return total, fmt.Errorf("pipeline exec: %w", err)
		}

		total += len(actions)
		if int32(len(actions)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, nil
}

func (idx *Index) warmActionSets(ctx context.Context) (int, error) {
	const pageSize int32 = 500
	var offset int32
	var total int

	for {
		sets, err := idx.store.Queries().ListActionSets(ctx, db.ListActionSetsParams{
			Limit:  pageSize,
			Offset: offset,
		})
		if err != nil {
			return total, err
		}
		if len(sets) == 0 {
			break
		}

		for _, s := range sets {
			// Get members for this set.
			members, err := idx.store.Queries().ListActionSetMembers(ctx, s.ID)
			if err != nil {
				idx.logger.Warn("failed to list action set members", "set_id", s.ID, "error", err)
				continue
			}

			pipe := idx.rdb.Pipeline()

			// Build action names + forward/reverse sets.
			var actionNames []string
			for _, m := range members {
				pipe.SAdd(ctx, prefixMembersActionSet+s.ID, m.ActionID)
				pipe.SAdd(ctx, prefixReverseAction+m.ActionID, s.ID)

				// Read action name from Valkey (already warmed in step 1).
				name, err := idx.rdb.HGet(ctx, prefixAction+m.ActionID, "name").Result()
				if err == nil {
					actionNames = append(actionNames, name)
				}
			}

			setFields := map[string]any{
				"name":         s.Name,
				"description":  s.Description,
				"member_count": strconv.Itoa(int(s.MemberCount)),
				"action_names": strings.Join(actionNames, " "),
			}
			if s.CreatedAt != nil {
				setFields["created_at"] = strconv.FormatInt(s.CreatedAt.Unix(), 10)
			}
			if s.UpdatedAt != nil {
				setFields["updated_at"] = strconv.FormatInt(s.UpdatedAt.Unix(), 10)
			}
			pipe.HSet(ctx, prefixActionSet+s.ID, setFields)

			if _, err := pipe.Exec(ctx); err != nil {
				idx.logger.Warn("failed to warm action set", "set_id", s.ID, "error", err)
			}
		}

		total += len(sets)
		if int32(len(sets)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, nil
}

func (idx *Index) warmDefinitions(ctx context.Context) (int, error) {
	const pageSize int32 = 500
	var offset int32
	var total int

	for {
		defs, err := idx.store.Queries().ListDefinitions(ctx, db.ListDefinitionsParams{
			Limit:  pageSize,
			Offset: offset,
		})
		if err != nil {
			return total, err
		}
		if len(defs) == 0 {
			break
		}

		for _, d := range defs {
			// Get members for this definition.
			members, err := idx.store.Queries().ListDefinitionMembers(ctx, d.ID)
			if err != nil {
				idx.logger.Warn("failed to list definition members", "def_id", d.ID, "error", err)
				continue
			}

			pipe := idx.rdb.Pipeline()

			var setNames []string
			var allActionNames []string
			for _, m := range members {
				pipe.SAdd(ctx, prefixMembersDefinition+d.ID, m.ActionSetID)
				pipe.SAdd(ctx, prefixReverseActionSet+m.ActionSetID, d.ID)

				// Read set name from Valkey.
				name, err := idx.rdb.HGet(ctx, prefixActionSet+m.ActionSetID, "name").Result()
				if err == nil {
					setNames = append(setNames, name)
				}

				// Read action names from the set's membership.
				actionIDs, err := idx.rdb.SMembers(ctx, prefixMembersActionSet+m.ActionSetID).Result()
				if err == nil {
					for _, aid := range actionIDs {
						aName, err := idx.rdb.HGet(ctx, prefixAction+aid, "name").Result()
						if err == nil {
							allActionNames = append(allActionNames, aName)
						}
					}
				}
			}

			defFields := map[string]any{
				"name":         d.Name,
				"description":  d.Description,
				"member_count": strconv.Itoa(int(d.MemberCount)),
				"set_names":    strings.Join(setNames, " "),
				"action_names": strings.Join(allActionNames, " "),
			}
			if d.CreatedAt != nil {
				defFields["created_at"] = strconv.FormatInt(d.CreatedAt.Unix(), 10)
			}
			if d.UpdatedAt != nil {
				defFields["updated_at"] = strconv.FormatInt(d.UpdatedAt.Unix(), 10)
			}
			pipe.HSet(ctx, prefixDefinition+d.ID, defFields)

			if _, err := pipe.Exec(ctx); err != nil {
				idx.logger.Warn("failed to warm definition", "def_id", d.ID, "error", err)
			}
		}

		total += len(defs)
		if int32(len(defs)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, nil
}

func (idx *Index) warmCompliancePolicies(ctx context.Context) (int, error) {
	const pageSize int32 = 500
	var offset int32
	var total int

	for {
		policies, err := idx.store.Queries().ListCompliancePolicies(ctx, db.ListCompliancePoliciesParams{
			Limit:  pageSize,
			Offset: offset,
		})
		if err != nil {
			return total, err
		}
		if len(policies) == 0 {
			break
		}

		pipe := idx.rdb.Pipeline()
		for _, p := range policies {
			// Look up action names from compliance rules
			var actionNames []string
			rules, err := idx.store.Queries().ListCompliancePolicyRules(ctx, p.ID)
			if err == nil {
				for _, r := range rules {
					if r.ActionName != "" {
						actionNames = append(actionNames, r.ActionName)
					}
				}
			}
			pipe.HSet(ctx, prefixCompliancePolicy+p.ID, map[string]any{
				"name":         p.Name,
				"description":  p.Description,
				"action_names": strings.Join(actionNames, " "),
			})
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return total, fmt.Errorf("pipeline exec: %w", err)
		}

		total += len(policies)
		if int32(len(policies)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, nil
}

func (idx *Index) warmExecutions(ctx context.Context) (int, error) {
	const pageSize int32 = 1000
	var offset int32
	var total int

	// Build lookup caches for device hostnames and action names.
	deviceNames := make(map[string]string)
	actionNames := make(map[string]string)

	for {
		execs, err := idx.store.Queries().ListExecutionsForWarm(ctx, db.ListExecutionsForWarmParams{
			Limit:  pageSize,
			Offset: offset,
		})
		if err != nil {
			return total, err
		}
		if len(execs) == 0 {
			break
		}

		pipe := idx.rdb.Pipeline()
		for _, e := range execs {
			// Resolve device hostname (cached).
			hostname, ok := deviceNames[e.DeviceID]
			if !ok {
				d, err := idx.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: e.DeviceID})
				if err == nil {
					hostname = d.Hostname
				}
				deviceNames[e.DeviceID] = hostname
			}

			// Resolve action name (cached).
			actionName := ""
			actionID := ""
			if e.ActionID != nil {
				actionID = *e.ActionID
				name, ok := actionNames[*e.ActionID]
				if !ok {
					a, err := idx.store.Queries().GetActionByID(ctx, *e.ActionID)
					if err == nil {
						name = a.Name
					}
					actionNames[*e.ActionID] = name
				}
				actionName = name
			}

			execFields := map[string]any{
				"action_name":     actionName,
				"device_hostname": hostname,
				"status":          e.Status,
				"action_type":     strconv.Itoa(int(e.ActionType)),
				"device_id":       e.DeviceID,
				"action_id":       actionID,
				"desired_state":   strconv.Itoa(int(e.DesiredState)),
				"changed":        strconv.FormatBool(e.Changed),
			}
			if e.CreatedAt != nil {
				execFields["created_at"] = strconv.FormatInt(e.CreatedAt.Unix(), 10)
			}
			if e.DurationMs != nil {
				execFields["duration_ms"] = strconv.FormatInt(*e.DurationMs, 10)
			}
			pipe.HSet(ctx, prefixExecution+e.ID, execFields)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return total, fmt.Errorf("pipeline exec: %w", err)
		}

		total += len(execs)
		if int32(len(execs)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, nil
}

func (idx *Index) warmAuditEvents(ctx context.Context) (int, error) {
	const pageSize int32 = 1000
	var offset int32
	var total int

	for {
		events, err := idx.store.Queries().ListAuditEventsForWarm(ctx, db.ListAuditEventsForWarmParams{
			Limit:  pageSize,
			Offset: offset,
		})
		if err != nil {
			return total, err
		}
		if len(events) == 0 {
			break
		}

		pipe := idx.rdb.Pipeline()
		for _, e := range events {
			id := ulid.ULID(e.ID).String()
			eventFields := map[string]any{
				"event_type":  e.EventType,
				"stream_type": e.StreamType,
				"actor_type":  e.ActorType,
				"actor_id":    e.ActorID,
				"stream_id":   e.StreamID,
				"occurred_at": strconv.FormatInt(e.OccurredAt.Unix(), 10),
			}
			pipe.HSet(ctx, prefixAuditEvent+id, eventFields)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return total, fmt.Errorf("pipeline exec: %w", err)
		}

		total += len(events)
		if int32(len(events)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, nil
}

// Rebuild performs a complete flush + recreate + warm cycle.
// Used by startup, periodic reconciliation, and the admin RPC.
func (idx *Index) Rebuild(ctx context.Context) error {
	idx.mu.Lock()
	if idx.rebuilding {
		idx.mu.Unlock()
		idx.logger.Info("rebuild already in progress, skipping")
		return nil
	}
	idx.rebuilding = true
	idx.mu.Unlock()
	defer func() {
		idx.mu.Lock()
		idx.rebuilding = false
		idx.mu.Unlock()
	}()

	if err := idx.FlushSearchData(ctx); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	if err := idx.EnsureIndexes(ctx); err != nil {
		return fmt.Errorf("ensure indexes: %w", err)
	}
	if err := idx.Warm(ctx); err != nil {
		return fmt.Errorf("warm: %w", err)
	}
	return nil
}

// StartReconciliation launches a background goroutine that periodically
// runs a full Rebuild to correct any drift.
func (idx *Index) StartReconciliation(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				idx.logger.Info("starting periodic search index reconciliation")
				if err := idx.Rebuild(ctx); err != nil {
					idx.logger.Error("periodic reconciliation failed", "error", err)
				}
			}
		}
	}()
}

// --- Enqueue helpers ---

// EnqueueReindex enqueues a search:reindex task with pre-populated entity data.
func (idx *Index) EnqueueReindex(ctx context.Context, scope, id string, data *taskqueue.SearchEntityData) error {
	return idx.aqClient.EnqueueToSearch(taskqueue.TypeSearchReindex, taskqueue.SearchReindexPayload{
		Scope: scope,
		ID:    id,
		Data:  data,
	})
}

// EnqueueMemberAdded enqueues a search:member_change task for a member addition.
func (idx *Index) EnqueueMemberAdded(ctx context.Context, parentScope, parentID, childScope, childID, childName string) error {
	return idx.aqClient.EnqueueToSearch(taskqueue.TypeSearchMemberChange, taskqueue.SearchMemberChangePayload{
		ParentScope: parentScope,
		ParentID:    parentID,
		ChildScope:  childScope,
		ChildID:     childID,
		ChildName:   childName,
		Action:      "add",
	})
}

// EnqueueMemberRemoved enqueues a search:member_change task for a member removal.
func (idx *Index) EnqueueMemberRemoved(ctx context.Context, parentScope, parentID, childScope, childID, childName string) error {
	return idx.aqClient.EnqueueToSearch(taskqueue.TypeSearchMemberChange, taskqueue.SearchMemberChangePayload{
		ParentScope: parentScope,
		ParentID:    parentID,
		ChildScope:  childScope,
		ChildID:     childID,
		ChildName:   childName,
		Action:      "remove",
	})
}

// EnqueueRemove enqueues a search:remove task. cascadeIDs are parent IDs
// that need their denormalized fields rebuilt after this entity is removed.
func (idx *Index) EnqueueRemove(ctx context.Context, scope, id string, cascadeIDs []string) error {
	return idx.aqClient.EnqueueToSearch(taskqueue.TypeSearchRemove, taskqueue.SearchRemovePayload{
		Scope:      scope,
		ID:         id,
		CascadeIDs: cascadeIDs,
	})
}

// GetReverseMembers returns the IDs of parents that contain the given entity.
// Used by handlers before delete to capture cascade IDs.
func (idx *Index) GetReverseMembers(ctx context.Context, scope, id string) []string {
	var key string
	switch scope {
	case ScopeAction:
		key = prefixReverseAction + id
	case ScopeActionSet:
		key = prefixReverseActionSet + id
	default:
		return nil
	}

	members, err := idx.rdb.SMembers(ctx, key).Result()
	if err != nil {
		idx.logger.Warn("failed to get reverse members", "key", key, "error", err)
		return nil
	}
	return members
}
