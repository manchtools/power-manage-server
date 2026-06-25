// Package search provides a Valkey RediSearch-backed full-text search index
// for actions, action sets, and definitions. Index updates are dispatched via
// Asynq tasks for reliability; the worker handlers live in worker.go.
package search

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
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
	prefixDevice           = "search:device:"
	prefixUser             = "search:user:"
	prefixDeviceGroup      = "search:device_group:"
	prefixUserGroup        = "search:user_group:"

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
	idxDevices            = "idx:devices"
	idxUsers              = "idx:users"
	idxDeviceGroups       = "idx:device_groups"
	idxUserGroups         = "idx:user_groups"
	idxExecutions         = "idx:executions"
	idxAuditEvents        = "idx:audit_events"
)

// Scope constants used in task payloads and RPC requests.
const (
	ScopeAction           = "action"
	ScopeActionSet        = "action_set"
	ScopeDefinition       = "definition"
	ScopeCompliancePolicy = "compliance_policy"
	ScopeDevice           = "device"
	ScopeUser             = "user"
	ScopeDeviceGroup      = "device_group"
	ScopeUserGroup        = "user_group"
	ScopeExecution        = "execution"
	ScopeAuditEvent       = "audit_event"
)

// Index manages the RediSearch full-text search indexes in Valkey.
type Index struct {
	now      func() time.Time // clock seam; defaults to time.Now, overridden in tests
	rdb      *redis.Client
	store    *store.Store
	aqClient *taskqueue.Client
	logger   *slog.Logger

	mu         sync.Mutex
	rebuilding bool
}

// New creates a new search Index.
func New(rdb *redis.Client, st *store.Store, aqClient *taskqueue.Client, logger *slog.Logger) *Index {
	return &Index{
		now:      time.Now,
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
	for _, name := range []string{idxActions, idxActionSets, idxDefinitions, idxCompliancePolicies, idxDevices, idxUsers, idxDeviceGroups, idxUserGroups, idxExecutions, idxAuditEvents} {
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

// IndexSchema is one RediSearch (FT.CREATE) index definition. Exported so a
// test can assert that the api-layer scopeFilterFields mirror the TAG/NUMERIC
// fields actually declared here — the two must stay in lockstep, since a tag
// filter on a field the index never declared makes RediSearch reject the whole
// query (server#158).
type IndexSchema struct {
	Name   string // e.g. "idx:devices"
	Prefix string
	Schema []any // field, type, [modifier...] exactly as passed to FT.CREATE SCHEMA
}

// Scope returns the search scope string this index backs — the index name with
// the "idx:" prefix stripped (e.g. "idx:devices" → "devices"). This is the key
// used in the api-layer scopeFilterFields map.
func (s IndexSchema) Scope() string { return strings.TrimPrefix(s.Name, "idx:") }

// FilterableFields returns the field names declared TAG or NUMERIC — the only
// kinds a structured (@field:{...} / range) filter can target. TEXT fields are
// full-text only and are intentionally excluded. Derived by pairing each type
// token with its preceding field name, so SORTABLE and other modifiers are
// ignored.
func (s IndexSchema) FilterableFields() map[string]bool {
	out := map[string]bool{}
	for i := 1; i < len(s.Schema); i++ {
		t, _ := s.Schema[i].(string)
		if t != "TAG" && t != "NUMERIC" {
			continue
		}
		if field, ok := s.Schema[i-1].(string); ok {
			out[field] = true
		}
	}
	return out
}

// NumericFields returns the field names declared NUMERIC. A structured filter on
// a NUMERIC field must use a range (@field:[min max]); the TAG @field:{value}
// syntax is a RediSearch error on a NUMERIC field. Derived by pairing each type
// token with its preceding field name.
func (s IndexSchema) NumericFields() map[string]bool {
	out := map[string]bool{}
	for i := 1; i < len(s.Schema); i++ {
		if t, _ := s.Schema[i].(string); t != "NUMERIC" {
			continue
		}
		if field, ok := s.Schema[i-1].(string); ok {
			out[field] = true
		}
	}
	return out
}

// SortableFields returns the field names declared SORTABLE — the only fields an
// FT.SEARCH SORTBY can target. In every schema here SORTABLE immediately follows
// the field's type (field, TYPE, SORTABLE), so the field is two tokens back; we
// don't stack other modifiers before SORTABLE.
func (s IndexSchema) SortableFields() map[string]bool {
	out := map[string]bool{}
	for i := 2; i < len(s.Schema); i++ {
		if tok, _ := s.Schema[i].(string); tok != "SORTABLE" {
			continue
		}
		if field, ok := s.Schema[i-2].(string); ok {
			out[field] = true
		}
	}
	return out
}

// IndexSchemas is the canonical set of RediSearch indexes EnsureIndexes creates.
var IndexSchemas = []IndexSchema{
	{
		Name:   idxActions,
		Prefix: prefixAction,
		Schema: []any{
			"name", "TEXT", "SORTABLE",
			"description", "TEXT",
			"type", "TAG", "SORTABLE",
			"is_compliance", "TAG",
			"assigned", "TAG",
			// scope_group_ids: multi-value TAG of the device-/user-group ids this
			// object is DIRECTLY assigned to (#7 spec 14). Scoped admins are
			// confined to objects whose groups intersect their scope. Default ","
			// separator — ULIDs contain no comma.
			"scope_group_ids", "TAG",
			"created_at", "NUMERIC", "SORTABLE",
			"updated_at", "NUMERIC", "SORTABLE",
		},
	},
	{
		Name:   idxActionSets,
		Prefix: prefixActionSet,
		Schema: []any{
			"name", "TEXT", "SORTABLE",
			"description", "TEXT",
			"member_count", "NUMERIC", "SORTABLE",
			"action_names", "TEXT",
			"assigned", "TAG",
			"scope_group_ids", "TAG",
			"created_at", "NUMERIC", "SORTABLE",
			"updated_at", "NUMERIC", "SORTABLE",
		},
	},
	{
		Name:   idxDefinitions,
		Prefix: prefixDefinition,
		Schema: []any{
			"name", "TEXT", "SORTABLE",
			"description", "TEXT",
			"member_count", "NUMERIC", "SORTABLE",
			"set_names", "TEXT",
			"action_names", "TEXT",
			"assigned", "TAG",
			"scope_group_ids", "TAG",
			"created_at", "NUMERIC", "SORTABLE",
			"updated_at", "NUMERIC", "SORTABLE",
		},
	},
	{
		Name:   idxCompliancePolicies,
		Prefix: prefixCompliancePolicy,
		Schema: []any{
			"name", "TEXT", "SORTABLE",
			"description", "TEXT",
			"action_names", "TEXT",
			"rule_count", "NUMERIC", "SORTABLE",
			"scope_group_ids", "TAG",
			"created_at", "NUMERIC", "SORTABLE",
		},
	},
	{
		Name:   idxDevices,
		Prefix: prefixDevice,
		Schema: []any{
			"hostname", "TEXT", "SORTABLE",
			"agent_version", "TAG",
			"labels", "TEXT",
			// os_name is a TAG for exact "OS: Ubuntu" filter chips (#325); free-text
			// device search still covers hostname/labels/os_version.
			"os_name", "TAG",
			"os_version", "TEXT",
			"os_arch", "TAG",
			"kernel", "TEXT",
			"compliance_status", "TAG", "SORTABLE",
			"registered_at", "NUMERIC", "SORTABLE",
			"last_seen_at", "NUMERIC", "SORTABLE",
		},
	},
	{
		Name:   idxUsers,
		Prefix: prefixUser,
		Schema: []any{
			"email", "TEXT", "SORTABLE",
			"display_name", "TEXT", "SORTABLE",
			"linux_username", "TEXT",
			"disabled", "TAG", "SORTABLE",
			"role", "TAG",
			"last_login_at", "NUMERIC", "SORTABLE",
			"created_at", "NUMERIC", "SORTABLE",
		},
	},
	{
		Name:   idxDeviceGroups,
		Prefix: prefixDeviceGroup,
		Schema: []any{
			"name", "TEXT", "SORTABLE",
			"description", "TEXT",
			"is_dynamic", "TAG",
			"member_count", "NUMERIC", "SORTABLE",
			"created_at", "NUMERIC", "SORTABLE",
		},
	},
	{
		Name:   idxUserGroups,
		Prefix: prefixUserGroup,
		Schema: []any{
			"name", "TEXT", "SORTABLE",
			"description", "TEXT",
			"is_dynamic", "TAG",
			"member_count", "NUMERIC", "SORTABLE",
			"created_at", "NUMERIC", "SORTABLE",
		},
	},
	{
		Name:   idxExecutions,
		Prefix: prefixExecution,
		Schema: []any{
			"action_name", "TEXT",
			"device_hostname", "TEXT", "SORTABLE",
			"status", "TAG", "SORTABLE",
			"action_type", "TAG", "SORTABLE",
			"device_id", "TAG",
			"created_at", "NUMERIC", "SORTABLE",
		},
	},
	{
		Name:   idxAuditEvents,
		Prefix: prefixAuditEvent,
		Schema: []any{
			"event_type", "TEXT", "SORTABLE",
			"stream_type", "TAG", "SORTABLE",
			"actor_type", "TAG", "SORTABLE",
			"actor_id", "TAG",
			"occurred_at", "NUMERIC", "SORTABLE",
		},
	},
}

// ScopeGroupField is the multi-value TAG that holds the device-/user-group ids an
// object is directly assigned to, used to confine scoped admins to their own
// objects (#7 spec 14). The server both populates it (indexer) and filters on it
// (search handler); it is NOT a client-facing filter, so ServerScopeFields keeps
// it out of the api scopeFilterFields allow-list and the parity guard skips it.
const ScopeGroupField = "scope_group_ids"

// ServerScopeFields are index TAG fields the server populates and filters on for
// RBAC scope confinement — never client-filterable. Self-discovering consumers
// (scopeFilterFields parity, query builders) skip these.
var ServerScopeFields = map[string]bool{ScopeGroupField: true}

// schemaFingerprintKey stores the hash of IndexSchemas from the last Rebuild.
const schemaFingerprintKey = "pm:indexer:schema:fingerprint"

// SchemaFingerprint is a stable hash of IndexSchemas. The indexer stamps it on
// every successful Rebuild and compares it at boot; a mismatch means the schema
// changed (a field added or promoted to SORTABLE/TAG) and the indexes must be
// dropped+recreated to apply it — FT.CREATE is a no-op on an existing index.
// Self-maintaining: editing IndexSchemas changes the fingerprint, so there is no
// version constant to forget to bump (ponytail: the schema IS the version).
func SchemaFingerprint() string {
	h := sha256.New()
	for _, ix := range IndexSchemas {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00", ix.Name, ix.Prefix)
		for _, f := range ix.Schema {
			_, _ = fmt.Fprintf(h, "%v\x00", f)
		}
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SchemaCurrent reports whether the fingerprint stored at the last Rebuild
// matches the current IndexSchemas. A missing stored value (never rebuilt, or a
// pre-fingerprint deploy) counts as NOT current so the new schema is applied.
// Backend read errors are surfaced (fail closed) rather than guessed.
func (idx *Index) SchemaCurrent(ctx context.Context) (bool, error) {
	stored, err := idx.rdb.Get(ctx, schemaFingerprintKey).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read schema fingerprint: %w", err)
	}
	return stored == SchemaFingerprint(), nil
}

// EnsureIndexes creates the FT search indexes if they do not already exist.
func (idx *Index) EnsureIndexes(ctx context.Context) error {
	for _, ix := range IndexSchemas {
		args := []any{"FT.CREATE", ix.Name, "ON", "HASH", "PREFIX", "1", ix.Prefix, "SCHEMA"}
		args = append(args, ix.Schema...)
		err := idx.rdb.Do(ctx, args...).Err()
		if err != nil {
			// "already exists" substring covers both backends used during
			// the redis-stack → valkey-bundle cutover (#319). RediSearch
			// emits "Index already exists"; valkey-search 1.2+ emits
			// "Index <name> in database 0 already exists." — both
			// contain the same anchor word, so a single substring
			// works without per-backend branching.
			if strings.Contains(err.Error(), "already exists") {
				continue
			}
			return fmt.Errorf("create index %s: %w", ix.Name, err)
		}
	}

	return nil
}

// IndexesPresent reports whether ALL configured search indexes already exist in
// the backend (WS13 #12). It is the gate that lets the indexer warm-without-flush
// on a normal restart instead of destructively dropping + rebuilding on every
// boot. A definitively-missing index returns (false, nil); any other backend
// error is surfaced so the caller fails closed rather than wrongly assuming the
// indexes are gone and flushing.
func (idx *Index) IndexesPresent(ctx context.Context) (bool, error) {
	for _, ix := range IndexSchemas {
		err := idx.rdb.Do(ctx, "FT.INFO", ix.Name).Err()
		if err == nil {
			continue
		}
		// A missing index is "not present", NOT a hard error. The wording differs
		// by backend, so match all known shapes (verified against the real
		// backend by TestIndexesPresent):
		//   valkey-search: "Index with name 'X' not found in database 0"
		//   RediSearch:    "Unknown index name"
		// Any OTHER FT.INFO error (e.g. backend unreachable) is surfaced so the
		// caller fails closed and never flushes on an indeterminate result.
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "not found") ||
			strings.Contains(lower, "unknown index") ||
			strings.Contains(lower, "no such index") {
			return false, nil
		}
		return false, fmt.Errorf("FT.INFO %s: %w", ix.Name, err)
	}
	return true, nil
}

// Warm performs a full rebuild of all search data from PostgreSQL.
// This is the only operation that reads from PG for search purposes.
func (idx *Index) Warm(ctx context.Context) error {
	idx.logger.Info("warming search index from database")
	start := idx.now()

	// 1. Index all actions. Returns the action_id → name map so the
	// downstream warm passes (action sets + definitions) can build
	// their denormalised action_names field via in-memory join
	// instead of one Valkey HGet per member. See manchtools/power-
	// manage-server#153 (audit F025).
	actionCount, actionNames, err := idx.warmActions(ctx)
	if err != nil {
		return fmt.Errorf("warm actions: %w", err)
	}

	// 2. Index all action sets + their memberships.
	setCount, setNames, setMembers, err := idx.warmActionSets(ctx, actionNames)
	if err != nil {
		return fmt.Errorf("warm action sets: %w", err)
	}

	// 3. Index all definitions + their memberships. Uses both the
	// setName + setMembers maps from step 2 (and the actionName map
	// from step 1) for the in-memory join — definitions denormalise
	// both set names and the action names of those sets.
	defCount, err := idx.warmDefinitions(ctx, actionNames, setNames, setMembers)
	if err != nil {
		return fmt.Errorf("warm definitions: %w", err)
	}

	// 4. Index all compliance policies.
	policyCount, err := idx.warmCompliancePolicies(ctx)
	if err != nil {
		return fmt.Errorf("warm compliance policies: %w", err)
	}

	// 5. Index all devices.
	deviceCount, err := idx.warmDevices(ctx)
	if err != nil {
		return fmt.Errorf("warm devices: %w", err)
	}

	// 6. Index all users.
	userCount, err := idx.warmUsers(ctx)
	if err != nil {
		return fmt.Errorf("warm users: %w", err)
	}

	// 7. Index all device groups.
	deviceGroupCount, err := idx.warmDeviceGroups(ctx)
	if err != nil {
		return fmt.Errorf("warm device groups: %w", err)
	}

	// 8. Index all user groups.
	userGroupCount, err := idx.warmUserGroups(ctx)
	if err != nil {
		return fmt.Errorf("warm user groups: %w", err)
	}

	// 9. Index recent executions (last 90 days).
	execCount, err := idx.warmExecutions(ctx)
	if err != nil {
		return fmt.Errorf("warm executions: %w", err)
	}

	// 8. Index recent audit events (last 90 days).
	auditCount, err := idx.warmAuditEvents(ctx)
	if err != nil {
		return fmt.Errorf("warm audit events: %w", err)
	}

	idx.logger.Info("search index warm complete",
		"actions", actionCount,
		"action_sets", setCount,
		"definitions", defCount,
		"compliance_policies", policyCount,
		"devices", deviceCount,
		"users", userCount,
		"device_groups", deviceGroupCount,
		"user_groups", userGroupCount,
		"executions", execCount,
		"audit_events", auditCount,
		"duration", idx.now().Sub(start),
	)
	return nil
}

// warmActions writes the indexed action HSETs and ALSO returns the
// action_id → name map. Downstream warm passes (sets + definitions)
// use the map for in-memory joins instead of issuing one Valkey
// HGet per member. See manchtools/power-manage-server#153.
// assignedSourceSet returns the set of source_ids of sourceType that have a live
// assignment — for stamping the search `assigned` TAG during a warm rebuild
// (one query per type, then O(1) lookups).
func (idx *Index) assignedSourceSet(ctx context.Context, sourceType string) (map[string]bool, error) {
	ids, err := idx.store.Queries().ListAssignedSourceIDs(ctx, sourceType)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, nil
}

// tagBool renders a bool as the "true"/"false" string a RediSearch TAG stores.
func tagBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// scopeGroupSet returns source_id → comma-joined sorted device-/user-group ids
// for stamping the search `scope_group_ids` TAG during a warm rebuild (#7 spec
// 14). One query per type, then O(1) lookups. A source absent from the map has
// no group assignments → "" → invisible to scoped admins. Sorted for a stable
// indexed value.
func (idx *Index) scopeGroupSet(ctx context.Context, sourceType string) (map[string]string, error) {
	rows, err := idx.store.Queries().ListScopeGroupAssignmentsBySourceType(ctx, sourceType)
	if err != nil {
		return nil, err
	}
	tmp := map[string][]string{}
	for _, r := range rows {
		tmp[r.SourceID] = append(tmp[r.SourceID], r.TargetID)
	}
	out := make(map[string]string, len(tmp))
	for id, ids := range tmp {
		sort.Strings(ids)
		out[id] = strings.Join(ids, ",")
	}
	return out, nil
}

func (idx *Index) warmActions(ctx context.Context) (int, map[string]string, error) {
	const pageSize int32 = 500
	var offset int32
	var total int
	actionNames := map[string]string{}

	assignedActions, err := idx.assignedSourceSet(ctx, "action")
	if err != nil {
		return total, actionNames, err
	}
	scopeGroups, err := idx.scopeGroupSet(ctx, "action")
	if err != nil {
		return total, actionNames, err
	}

	for {
		actions, err := idx.store.Repos().Action.List(ctx, store.ListActionsFilter{
			ActionTypeFilter: 0, // no type filter
			Limit:            pageSize,
			Offset:           offset,
		})
		if err != nil {
			return total, actionNames, err
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
			isCompliance := false
			var params map[string]any
			if json.Unmarshal(a.Params, &params) == nil {
				if v, ok := params["isCompliance"].(bool); ok {
					isCompliance = v
				}
			}
			data := &taskqueue.SearchEntityData{
				Name:             a.Name,
				Description:      desc,
				Type:             int32(a.ActionType),
				IsCompliance:     isCompliance,
				Assigned:         tagBool(assignedActions[a.ID]),
				ScopeGroupIDs:    scopeGroups[a.ID],
				HasScopeGroupIDs: true,
			}
			if a.CreatedAt != nil {
				data.CreatedAt = a.CreatedAt.Unix()
			}
			if a.UpdatedAt != nil {
				data.UpdatedAt = a.UpdatedAt.Unix()
			}
			pipe.HSet(ctx, prefixAction+a.ID, entityFields(ScopeAction, data))
			actionNames[a.ID] = a.Name
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return total, actionNames, fmt.Errorf("pipeline exec: %w", err)
		}

		total += len(actions)
		if int32(len(actions)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, actionNames, nil
}

// warmActionSets writes the indexed set HSETs + member sets, using
// the actionNames map produced by warmActions for the in-memory
// join. Returns the set_id → name map AND the set_id → []action_id
// map so warmDefinitions can do the same join trick one level up.
// See manchtools/power-manage-server#153.
func (idx *Index) warmActionSets(ctx context.Context, actionNames map[string]string) (int, map[string]string, map[string][]string, error) {
	const pageSize int32 = 500
	var offset int32
	var total int
	setNames := map[string]string{}
	setMembers := map[string][]string{}

	assignedSets, err := idx.assignedSourceSet(ctx, "action_set")
	if err != nil {
		return total, setNames, setMembers, err
	}
	scopeGroups, err := idx.scopeGroupSet(ctx, "action_set")
	if err != nil {
		return total, setNames, setMembers, err
	}

	for {
		sets, err := idx.store.Repos().ActionSet.List(ctx, store.ListActionSetsFilter{
			Limit:  pageSize,
			Offset: offset,
		})
		if err != nil {
			return total, setNames, setMembers, err
		}
		if len(sets) == 0 {
			break
		}

		for _, s := range sets {
			// Get members for this set.
			members, err := idx.store.Repos().ActionSet.ListMembers(ctx, s.ID)
			if err != nil {
				idx.logger.Warn("failed to list action set members", "set_id", s.ID, "error", err)
				continue
			}

			pipe := idx.rdb.Pipeline()

			// Build action names + forward/reverse sets. Names come
			// from the in-memory map populated by warmActions —
			// no per-member Valkey round-trip.
			var memberActionIDs []string
			var memberActionNames []string
			for _, m := range members {
				pipe.SAdd(ctx, prefixMembersActionSet+s.ID, m.ActionID)
				pipe.SAdd(ctx, prefixReverseAction+m.ActionID, s.ID)
				memberActionIDs = append(memberActionIDs, m.ActionID)
				if name, ok := actionNames[m.ActionID]; ok {
					memberActionNames = append(memberActionNames, name)
				}
			}

			data := &taskqueue.SearchEntityData{
				Name:             s.Name,
				Description:      s.Description,
				MemberCount:      s.MemberCount,
				Assigned:         tagBool(assignedSets[s.ID]),
				ScopeGroupIDs:    scopeGroups[s.ID],
				HasScopeGroupIDs: true,
			}
			if s.CreatedAt != nil {
				data.CreatedAt = s.CreatedAt.Unix()
			}
			if s.UpdatedAt != nil {
				data.UpdatedAt = s.UpdatedAt.Unix()
			}
			// entityFields owns the standard fields; action_names is a warm-only
			// denormalised join (the incremental path maintains it via rebuildParent).
			setFields := entityFields(ScopeActionSet, data)
			setFields["action_names"] = strings.Join(memberActionNames, " ")
			pipe.HSet(ctx, prefixActionSet+s.ID, setFields)

			if _, err := pipe.Exec(ctx); err != nil {
				idx.logger.Warn("failed to warm action set", "set_id", s.ID, "error", err)
			}

			setNames[s.ID] = s.Name
			setMembers[s.ID] = memberActionIDs
		}

		total += len(sets)
		if int32(len(sets)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, setNames, setMembers, nil
}

// warmDefinitions writes the indexed definition HSETs + member sets,
// using the actionNames + setNames + setMembers maps produced by
// the prior warm passes for the in-memory joins. Replaces ~3
// Valkey round-trips per definition member with zero — the lookups
// are now O(1) map reads. See manchtools/power-manage-server#153.
func (idx *Index) warmDefinitions(ctx context.Context, actionNames, setNames map[string]string, setMembers map[string][]string) (int, error) {
	const pageSize int32 = 500
	var offset int32
	var total int

	assignedDefs, err := idx.assignedSourceSet(ctx, "definition")
	if err != nil {
		return total, err
	}
	scopeGroups, err := idx.scopeGroupSet(ctx, "definition")
	if err != nil {
		return total, err
	}

	for {
		defs, err := idx.store.Repos().Definition.List(ctx, store.ListDefinitionsFilter{Limit: pageSize, Offset: offset})
		if err != nil {
			return total, err
		}
		if len(defs) == 0 {
			break
		}

		for _, d := range defs {
			// Get members for this definition.
			members, err := idx.store.Repos().Definition.ListMembers(ctx, d.ID)
			if err != nil {
				idx.logger.Warn("failed to list definition members", "def_id", d.ID, "error", err)
				continue
			}

			pipe := idx.rdb.Pipeline()

			var memberSetNames []string
			var allActionNames []string
			for _, m := range members {
				pipe.SAdd(ctx, prefixMembersDefinition+d.ID, m.ActionSetID)
				pipe.SAdd(ctx, prefixReverseActionSet+m.ActionSetID, d.ID)

				if name, ok := setNames[m.ActionSetID]; ok {
					memberSetNames = append(memberSetNames, name)
				}
				for _, aid := range setMembers[m.ActionSetID] {
					if aName, ok := actionNames[aid]; ok {
						allActionNames = append(allActionNames, aName)
					}
				}
			}

			data := &taskqueue.SearchEntityData{
				Name:             d.Name,
				Description:      d.Description,
				MemberCount:      d.MemberCount,
				Assigned:         tagBool(assignedDefs[d.ID]),
				ScopeGroupIDs:    scopeGroups[d.ID],
				HasScopeGroupIDs: true,
			}
			if d.CreatedAt != nil {
				data.CreatedAt = d.CreatedAt.Unix()
			}
			if d.UpdatedAt != nil {
				data.UpdatedAt = d.UpdatedAt.Unix()
			}
			// entityFields owns the standard fields; set_names/action_names are
			// warm-only denormalised joins.
			defFields := entityFields(ScopeDefinition, data)
			defFields["set_names"] = strings.Join(memberSetNames, " ")
			defFields["action_names"] = strings.Join(allActionNames, " ")
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

	scopeGroups, err := idx.scopeGroupSet(ctx, "compliance_policy")
	if err != nil {
		return total, err
	}

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
			// Look up action names + rule count from compliance rules. Fail the
			// rebuild on error rather than indexing the policy with empty
			// action_names and a missing rule_count — a warm rebuild flushes
			// first, so partial data corrupts compliance search/filter state
			// while reporting success.
			rules, err := idx.store.Queries().ListCompliancePolicyRules(ctx, p.ID)
			if err != nil {
				return total, fmt.Errorf("list compliance policy rules %s: %w", p.ID, err)
			}
			var actionNames []string
			for _, r := range rules {
				if r.ActionName != "" {
					actionNames = append(actionNames, r.ActionName)
				}
			}
			data := &taskqueue.SearchEntityData{
				Name:             p.Name,
				Description:      p.Description,
				ActionNames:      strings.Join(actionNames, " "),
				HasActionNames:   true, // warm has the authoritative rule list
				RuleCount:        int32(len(rules)),
				HasRuleCount:     true,
				ScopeGroupIDs:    scopeGroups[p.ID],
				HasScopeGroupIDs: true,
			}
			if p.CreatedAt != nil {
				data.CreatedAt = p.CreatedAt.Unix()
			}
			pipe.HSet(ctx, prefixCompliancePolicy+p.ID, entityFields(ScopeCompliancePolicy, data))
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

func (idx *Index) warmDevices(ctx context.Context) (int, error) {
	const pageSize int32 = 500
	var offset int32
	var total int

	for {
		devices, err := idx.store.Repos().Device.List(ctx, store.ListDevicesFilter{Limit: pageSize, Offset: offset, OwnerScope: nil})
		if err != nil {
			return total, err
		}
		if len(devices) == 0 {
			break
		}

		pipe := idx.rdb.Pipeline()
		for _, d := range devices {
			// Build the same SearchEntityData the incremental path produces, then
			// format via entityFields — single source of the device HSET shape
			// (bounding/sanitising of agent-reported fields lives there).
			data := &taskqueue.SearchEntityData{
				Hostname:         d.Hostname,
				AgentVersion:     d.AgentVersion,
				Labels:           FlattenLabels(d.Labels),
				ComplianceStatus: d.ComplianceStatus,
			}
			if d.RegisteredAt != nil {
				data.RegisteredAt = d.RegisteredAt.Unix()
			}
			if d.LastSeenAt != nil {
				data.LastSeenAt = d.LastSeenAt.Unix()
			}
			// Enrich with inventory data (os_version, system_info, kernel_info).
			// Fail the rebuild on error: entityFields always writes the os_* fields,
			// so skipping enrichment would index empty OS data (breaking the os_name
			// filter) for a device that has inventory — a flush-first rebuild has no
			// prior value to fall back on.
			inv, err := idx.store.Repos().Inventory.ListTables(ctx, d.ID, []string{"os_version", "system_info", "kernel_info"})
			if err != nil {
				return total, fmt.Errorf("list inventory tables for device %s: %w", d.ID, err)
			}
			for _, t := range inv {
				EnrichDeviceInventory(data, t.TableName, t.Rows)
			}
			pipe.HSet(ctx, prefixDevice+d.ID, entityFields(ScopeDevice, data))
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return total, fmt.Errorf("pipeline exec: %w", err)
		}

		total += len(devices)
		if int32(len(devices)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, nil
}

// EnrichDeviceInventory populates inventory fields on a SearchEntityData from a single inventory table.
func EnrichDeviceInventory(data *taskqueue.SearchEntityData, tableName string, rowsJSON []byte) {
	osName, osVer, osArch, kernel := extractInventoryFields(tableName, rowsJSON)
	if osName != "" {
		data.OSName = osName
	}
	if osVer != "" {
		data.OSVersion = osVer
	}
	if osArch != "" {
		data.OSArch = osArch
	}
	if kernel != "" {
		data.Kernel = kernel
	}
}

// extractInventoryFields extracts searchable fields from an inventory table's JSON rows.
func extractInventoryFields(tableName string, rowsJSON []byte) (osName, osVersion, osArch, kernel string) {
	var rows []map[string]string
	if json.Unmarshal(rowsJSON, &rows) != nil || len(rows) == 0 {
		return
	}
	row := rows[0]
	switch tableName {
	case "os_version":
		osName = row["name"]
		osVersion = row["version"]
		osArch = row["arch"]
	case "kernel_info":
		kernel = row["version"]
	}
	return
}

func (idx *Index) warmUsers(ctx context.Context) (int, error) {
	const pageSize int32 = 500
	var offset int32
	var total int

	for {
		users, err := idx.store.Queries().ListAllUsers(ctx, db.ListAllUsersParams{
			Limit:  pageSize,
			Offset: offset,
		})
		if err != nil {
			return total, err
		}
		if len(users) == 0 {
			break
		}

		pipe := idx.rdb.Pipeline()
		for _, u := range users {
			disabled := "false"
			if u.Disabled {
				disabled = "true"
			}
			data := &taskqueue.SearchEntityData{
				Email:         u.Email,
				DisplayName:   u.DisplayName,
				LinuxUsername: u.LinuxUsername,
				Disabled:      disabled,
				Role:          u.Role,
			}
			if u.CreatedAt != nil {
				data.CreatedAt = u.CreatedAt.Unix()
			}
			if u.LastLoginAt != nil {
				data.LastLoginAt = u.LastLoginAt.Unix()
			}
			pipe.HSet(ctx, prefixUser+u.ID, entityFields(ScopeUser, data))
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return total, fmt.Errorf("pipeline exec: %w", err)
		}

		total += len(users)
		if int32(len(users)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, nil
}

func (idx *Index) warmDeviceGroups(ctx context.Context) (int, error) {
	const pageSize int32 = 500
	var offset int32
	var total int

	for {
		groups, err := idx.store.Repos().DeviceGroup.List(ctx, store.ListDeviceGroupsFilter{Limit: pageSize, Offset: offset})
		if err != nil {
			return total, err
		}
		if len(groups) == 0 {
			break
		}

		pipe := idx.rdb.Pipeline()
		for _, g := range groups {
			isDynamic := "false"
			if g.IsDynamic {
				isDynamic = "true"
			}
			data := &taskqueue.SearchEntityData{
				Name:        g.Name,
				Description: g.Description,
				IsDynamic:   isDynamic,
				MemberCount: g.MemberCount,
			}
			if g.CreatedAt != nil {
				data.CreatedAt = g.CreatedAt.Unix()
			}
			pipe.HSet(ctx, prefixDeviceGroup+g.ID, entityFields(ScopeDeviceGroup, data))
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return total, fmt.Errorf("pipeline exec: %w", err)
		}

		total += len(groups)
		if int32(len(groups)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, nil
}

func (idx *Index) warmUserGroups(ctx context.Context) (int, error) {
	const pageSize int32 = 500
	var offset int32
	var total int

	for {
		groups, err := idx.store.Repos().UserGroup.List(ctx, store.ListUserGroupsFilter{Limit: pageSize, Offset: offset})
		if err != nil {
			return total, err
		}
		if len(groups) == 0 {
			break
		}

		pipe := idx.rdb.Pipeline()
		for _, g := range groups {
			isDynamic := "false"
			if g.IsDynamic {
				isDynamic = "true"
			}
			data := &taskqueue.SearchEntityData{
				Name:        g.Name,
				Description: g.Description,
				IsDynamic:   isDynamic,
				MemberCount: g.MemberCount,
			}
			if !g.CreatedAt.IsZero() {
				data.CreatedAt = g.CreatedAt.Unix()
			}
			pipe.HSet(ctx, prefixUserGroup+g.ID, entityFields(ScopeUserGroup, data))
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return total, fmt.Errorf("pipeline exec: %w", err)
		}

		total += len(groups)
		if int32(len(groups)) < pageSize {
			break
		}
		offset += pageSize
	}
	return total, nil
}

// FlattenLabels converts a labels map to a space-separated "key=value"
// string for TEXT search. Wave E.4 dropped the JSONB intermediate;
// callers pass the typed map directly.
func FlattenLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	var parts []string
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

func (idx *Index) warmExecutions(ctx context.Context) (int, error) {
	const pageSize int32 = 1000
	var offset int32
	var total int

	// Build lookup caches for device hostnames and action names.
	deviceNames := make(map[string]string)
	actionNames := make(map[string]string)

	for {
		execs, err := idx.store.Repos().Execution.ListForWarm(ctx, store.WarmFilter{
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
				d, err := idx.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: e.DeviceID})
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
					a, err := idx.store.Repos().Action.Get(ctx, *e.ActionID)
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
				"changed":         strconv.FormatBool(e.Changed),
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
	// Stamp the schema fingerprint so the next boot warms instead of rebuilding
	// (until the schema changes again). Last step: only a fully-rebuilt index
	// should claim to be current.
	if err := idx.rdb.Set(ctx, schemaFingerprintKey, SchemaFingerprint(), 0).Err(); err != nil {
		return fmt.Errorf("stamp schema fingerprint: %w", err)
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
