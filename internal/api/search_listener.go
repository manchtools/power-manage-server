package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// SearchIndex is the narrow surface SearchListener consumes from
// the *search.Index concrete. Defined as an interface here so tests
// can swap in a recording fake without bringing up Asynq + Valkey
// — the production wiring still passes the concrete (it implicitly
// satisfies this interface).
//
// Three methods, in order of how often they fire from this listener:
//
//   - TouchDeviceLastSeen — every device heartbeat (#499)
//   - EnqueueReindex — every reindex op
//   - EnqueueRemove  — every delete op
//   - GetReverseMembers — only on remove for scopes with cascading
//     parent rebuilds (action / action_set / definition)
type SearchIndex interface {
	TouchDeviceLastSeen(ctx context.Context, id string, lastSeen int64) error
	EnqueueReindex(ctx context.Context, scope, id string, data *taskqueue.SearchEntityData) error
	EnqueueRemove(ctx context.Context, scope, id string, cascadeIDs []string) error
	GetReverseMembers(ctx context.Context, scope, id string) []string
}

// SearchOp is the action a search-index listener should take in
// response to a single event. Mirrors the SyncOp pattern from #77's
// system-action listener but scoped to search-index updates: the
// existing `enqueueXxxReindex` helpers in handlers translate
// directly to one of these ops.
//
// Phase 1 of #81 lands the listener BESIDE the existing handler-
// side enqueues, not as a replacement. Both paths fire and the
// Asynq worker deduplicates on (scope,id), so functional behaviour
// is unchanged. Phase 2 (separate PR) removes the handler-side
// enqueues once the listener has been validated in production.
type SearchOp int

const (
	// SearchOpNone — event does not affect the search index.
	SearchOpNone SearchOp = iota
	// SearchOpReindex — upsert the entity's denormalised search row.
	SearchOpReindex
	// SearchOpRemove — drop the entity from the search index.
	// CascadeIDs (if any) come from search.Index.GetReverseMembers
	// so parent entities with denormalised member lists rebuild
	// after the child disappears.
	SearchOpRemove
	// SearchOpTouchDeviceLastSeen — O(1) refresh of ONLY the device's
	// indexed last_seen_at, carrying the event's occurred_at (#499).
	// Deliberately not a SearchOpReindex: heartbeats are the highest-
	// volume device event, and a full row reload per heartbeat would
	// be fleet-size × heartbeat-rate projection reads for one field.
	SearchOpTouchDeviceLastSeen
)

// SearchAffected is the classifier output: which scope is affected,
// which entity ID, and what op to perform.
type SearchAffected struct {
	Op    SearchOp
	Scope string
	ID    string
}

// AffectedSearchOps classifies a single event into the search-index
// operations it should trigger. A single event can affect multiple
// search rows (e.g. UserGroupMemberAdded reindexes the user AND the
// group's member_count), so the return is a slice.
//
// The classifier is the load-bearing surface for #81: a missed event
// type means stale search results until the periodic indexer
// reconciler catches up (~1 hour bound). Add new event types here
// when introducing them in a handler.
//
// Phase 1 covers users + devices end-to-end. Subsequent PRs add
// device_group, user_group, action_set, definition, action,
// compliance_policy, and execution coverage. Each scope is small
// enough to land in one PR with full test coverage.
func AffectedSearchOps(e store.PersistedEvent) []SearchAffected {
	switch e.EventType {

	// ---------------------------------------------------------
	// User scope
	// ---------------------------------------------------------
	// Email / display name / Linux username / disabled flag are
	// the indexed fields. Other user events (SSH keys, password,
	// session invalidation, system-action linking) don't surface
	// in search results today, so they classify as SearchOpNone.
	case string(eventtypes.UserCreatedWithRoles),
		string(eventtypes.UserEmailChanged),
		string(eventtypes.UserProfileUpdated),
		string(eventtypes.UserLinuxUsernameChanged),
		string(eventtypes.UserDisabled),
		string(eventtypes.UserEnabled),
		// role is an indexed filter (#325); role changes are infrequent.
		string(eventtypes.UserRoleChanged):
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeUser, ID: e.StreamID}}
		// Note: UserLoggedIn is intentionally NOT here. last_login_at is an indexed
		// sort (#325) but reindexing on every login is too costly; the value stays
		// eventually-consistent via other user events + the periodic reconcile,
		// which is fine for "sort by last login / find dormant accounts".
		//
		// Contrast with DeviceHeartbeat below (#499): last_seen_at drives the
		// online/offline status FILTER — a correctness surface, not just a sort —
		// so heartbeats DO refresh it, but as an O(1) field touch rather than a
		// row reload. last_login_at stays excluded because sort order degrading
		// gracefully under staleness is the deliberate trade.

	case string(eventtypes.UserDeleted):
		return []SearchAffected{{Op: SearchOpRemove, Scope: search.ScopeUser, ID: e.StreamID}}

	// ---------------------------------------------------------
	// Device scope
	// ---------------------------------------------------------
	// Hostname, agent version, labels, and sync interval are the
	// denormalised fields. Cert renewal / assignment / unassignment
	// do not change any of those fields → SearchOpNone.
	case string(eventtypes.DeviceRegistered),
		string(eventtypes.DeviceLabelSet),
		string(eventtypes.DeviceLabelRemoved),
		string(eventtypes.DeviceSyncIntervalSet):
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeDevice, ID: e.StreamID}}

	case string(eventtypes.DeviceDeleted):
		return []SearchAffected{{Op: SearchOpRemove, Scope: search.ScopeDevice, ID: e.StreamID}}

	// The devices page computes online/offline against the INDEXED
	// last_seen_at (deviceStatusClause, 5-minute window), so a healthy
	// heartbeating device would show offline for up to an hour (the
	// reconcile bound) without this case (#499). The op is an O(1)
	// touch of the one changed field — see SearchOpTouchDeviceLastSeen.
	case string(eventtypes.DeviceHeartbeat):
		return []SearchAffected{{Op: SearchOpTouchDeviceLastSeen, Scope: search.ScopeDevice, ID: e.StreamID}}

	// ---------------------------------------------------------
	// DeviceGroup scope
	// ---------------------------------------------------------
	// Name, description, dynamic_query, sync interval, member_count,
	// and maintenance window are all denormalised in the search row
	// per DeviceGroupHandler.enqueueDeviceGroupReindex. Member-add /
	// member-remove events update member_count; the row reload picks
	// that up.
	case string(eventtypes.DeviceGroupCreated),
		string(eventtypes.DeviceGroupRenamed),
		string(eventtypes.DeviceGroupDescriptionUpdated),
		string(eventtypes.DeviceGroupQueryUpdated),
		string(eventtypes.DeviceGroupSyncIntervalSet),
		string(eventtypes.DeviceGroupMaintenanceWindowSet):
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeDeviceGroup, ID: e.StreamID}}

	// Membership change (static admin add/remove, or legacy aliases): reindex the
	// GROUP (member_count) AND the affected DEVICE (its scope_group_ids changed,
	// #7 spec 14). device_id rides in the payload; StreamID is the group id.
	case string(eventtypes.DeviceGroupMemberAdded),
		string(eventtypes.DeviceGroupMemberRemoved),
		string(eventtypes.DeviceAddedToGroup),
		string(eventtypes.DeviceRemovedFromGroup):
		ops := []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeDeviceGroup, ID: e.StreamID}}
		var p struct {
			DeviceID string `json:"device_id"`
		}
		if json.Unmarshal(e.Data, &p) == nil && p.DeviceID != "" {
			ops = append(ops, SearchAffected{Op: SearchOpReindex, Scope: search.ScopeDevice, ID: p.DeviceID})
		}
		return ops

	// Dynamic re-evaluation delta (#7 spec 14): reindex the group + every device
	// whose membership changed this evaluation.
	case string(eventtypes.DeviceGroupMembersReevaluated):
		ops := []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeDeviceGroup, ID: e.StreamID}}
		var p struct {
			Added   []string `json:"added_device_ids"`
			Removed []string `json:"removed_device_ids"`
		}
		if json.Unmarshal(e.Data, &p) == nil {
			for _, id := range append(p.Added, p.Removed...) {
				if id != "" {
					ops = append(ops, SearchAffected{Op: SearchOpReindex, Scope: search.ScopeDevice, ID: id})
				}
			}
		}
		return ops

	case string(eventtypes.DeviceGroupDeleted):
		return []SearchAffected{{Op: SearchOpRemove, Scope: search.ScopeDeviceGroup, ID: e.StreamID}}

	// ---------------------------------------------------------
	// UserGroup scope
	// ---------------------------------------------------------
	// Group-stream events (Created, Updated, QueryUpdated,
	// MaintenanceWindowSet) carry the group ID directly in StreamID
	// — these reindex against e.StreamID.
	case string(eventtypes.UserGroupCreated),
		string(eventtypes.UserGroupUpdated),
		string(eventtypes.UserGroupQueryUpdated),
		string(eventtypes.UserGroupMaintenanceWindowSet):
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeUserGroup, ID: e.StreamID}}

	case string(eventtypes.UserGroupDeleted):
		return []SearchAffected{{Op: SearchOpRemove, Scope: search.ScopeUserGroup, ID: e.StreamID}}

	// Member / role events use a COMPOSITE StreamID:
	//   - Members: "<group_id>:<user_id>"
	//   - Roles:   "<group_id>:role:<role_id>"
	// We need the group_id prefix to load the user_groups_projection
	// row. Same defensive prefix-split pattern as the system-action
	// listener (#77) — the user_id / role_id suffixes are irrelevant
	// to the search payload (member_count + role list are already
	// denormalised on the projection row by the projector).
	// Member events: composite StreamID "<group_id>:<user_id>" — reindex the group
	// (member_count) AND the affected user (its scope_group_ids changed, #7 spec 14).
	case string(eventtypes.UserGroupMemberAdded),
		string(eventtypes.UserGroupMemberRemoved):
		groupID, userID, _ := strings.Cut(e.StreamID, ":")
		if groupID == "" {
			return nil
		}
		ops := []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeUserGroup, ID: groupID}}
		if userID != "" {
			ops = append(ops, SearchAffected{Op: SearchOpReindex, Scope: search.ScopeUser, ID: userID})
		}
		return ops

	// Role events: composite StreamID "<group_id>:role:<role_id>" — group only.
	case string(eventtypes.UserGroupRoleAssigned),
		string(eventtypes.UserGroupRoleRevoked):
		groupID, _, _ := strings.Cut(e.StreamID, ":")
		if groupID == "" {
			return nil
		}
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeUserGroup, ID: groupID}}

	// Dynamic re-evaluation delta (#7 spec 14): reindex the group + every user
	// whose membership changed. StreamID is the group id (not composite).
	case string(eventtypes.UserGroupMembersReevaluated):
		ops := []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeUserGroup, ID: e.StreamID}}
		var p struct {
			Added   []string `json:"added_user_ids"`
			Removed []string `json:"removed_user_ids"`
		}
		if json.Unmarshal(e.Data, &p) == nil {
			for _, id := range append(p.Added, p.Removed...) {
				if id != "" {
					ops = append(ops, SearchAffected{Op: SearchOpReindex, Scope: search.ScopeUser, ID: id})
				}
			}
		}
		return ops

	// ---------------------------------------------------------
	// Execution scope
	// ---------------------------------------------------------
	// Status, duration, action linkage, and the changed/compliant
	// flags all live in the search row per the DispatchAction
	// handler's existing inline enqueue. Every execution lifecycle
	// event mutates one of those fields, so each one reindexes.
	case string(eventtypes.ExecutionCreated),
		string(eventtypes.ExecutionScheduled),
		string(eventtypes.ExecutionDispatched),
		string(eventtypes.ExecutionStarted),
		string(eventtypes.ExecutionCompleted),
		string(eventtypes.ExecutionFailed),
		string(eventtypes.ExecutionCancelled),
		string(eventtypes.ExecutionTimedOut):
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeExecution, ID: e.StreamID}}

	// ---------------------------------------------------------
	// ActionSet scope
	// ---------------------------------------------------------
	// Name, description, schedule, and member_count live on the
	// search row. Member-add / member-remove / member-reorder all
	// touch member_count or the displayed member list, so they
	// reindex too.
	//
	// The action↔set membership EDGE (handler's
	// EnqueueMemberAdded/Removed calls) is intentionally NOT covered
	// here yet — those still fire from the handler. Phase 2c.2 (a
	// follow-up PR) extends SearchAffected with member-edge variants
	// and removes those calls. Splitting keeps this PR's diff small
	// and CR-reviewable.
	case string(eventtypes.ActionSetCreated),
		string(eventtypes.ActionSetRenamed),
		string(eventtypes.ActionSetDescriptionUpdated),
		string(eventtypes.ActionSetScheduleUpdated),
		string(eventtypes.ActionSetMemberAdded),
		string(eventtypes.ActionSetMemberRemoved),
		string(eventtypes.ActionSetMemberReordered):
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeActionSet, ID: e.StreamID}}

	case string(eventtypes.ActionSetDeleted):
		return []SearchAffected{{Op: SearchOpRemove, Scope: search.ScopeActionSet, ID: e.StreamID}}

	// ---------------------------------------------------------
	// Definition scope (same shape as ActionSet)
	// ---------------------------------------------------------
	case string(eventtypes.DefinitionCreated),
		string(eventtypes.DefinitionRenamed),
		string(eventtypes.DefinitionDescriptionUpdated),
		string(eventtypes.DefinitionScheduleUpdated),
		string(eventtypes.DefinitionMemberAdded),
		string(eventtypes.DefinitionMemberRemoved),
		string(eventtypes.DefinitionMemberReordered):
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeDefinition, ID: e.StreamID}}

	case string(eventtypes.DefinitionDeleted):
		return []SearchAffected{{Op: SearchOpRemove, Scope: search.ScopeDefinition, ID: e.StreamID}}

	// ---------------------------------------------------------
	// Action scope
	// ---------------------------------------------------------
	// Name, description, type, and the isCompliance flag (parsed
	// from action.params) all live on the search row. ParamsUpdated
	// triggers a reindex because the isCompliance derivation can
	// flip when params change.
	case string(eventtypes.ActionCreated),
		string(eventtypes.ActionRenamed),
		string(eventtypes.ActionDescriptionUpdated),
		string(eventtypes.ActionParamsUpdated):
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeAction, ID: e.StreamID}}

	case string(eventtypes.ActionDeleted):
		return []SearchAffected{{Op: SearchOpRemove, Scope: search.ScopeAction, ID: e.StreamID}}

	// ---------------------------------------------------------
	// CompliancePolicy scope
	// ---------------------------------------------------------
	// Name + description live on the search row; the rule list
	// contributes denormalised action names ("ActionNames" field) so
	// a search hit ranks/highlights by the policy's referenced
	// actions. Rule mutations therefore reindex the policy too.
	case string(eventtypes.CompliancePolicyCreated),
		string(eventtypes.CompliancePolicyRenamed),
		string(eventtypes.CompliancePolicyDescriptionUpdated),
		string(eventtypes.CompliancePolicyRuleAdded),
		string(eventtypes.CompliancePolicyRuleRemoved),
		string(eventtypes.CompliancePolicyRuleUpdated):
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeCompliancePolicy, ID: e.StreamID}}

	case string(eventtypes.CompliancePolicyDeleted):
		return []SearchAffected{{Op: SearchOpRemove, Scope: search.ScopeCompliancePolicy, ID: e.StreamID}}

	// ---------------------------------------------------------
	// Assignment scope — reindex the SOURCE entity's `assigned` TAG (#325).
	// ---------------------------------------------------------
	// StreamID is the assignment id; the source tuple rides in the payload
	// (both Created and Deleted emit it). All four object source types carry
	// `scope_group_ids` (#7 spec 14), so every assignment change reindexes its
	// source. A legacy AssignmentDeleted with an empty payload is a no-op — the
	// periodic reconciler/warm rebuild is the safety net.
	case string(eventtypes.AssignmentCreated),
		string(eventtypes.AssignmentDeleted):
		var p struct {
			SourceType string `json:"source_type"`
			SourceID   string `json:"source_id"`
		}
		if json.Unmarshal(e.Data, &p) != nil || p.SourceID == "" {
			return nil
		}
		scope := assignmentSourceScope(p.SourceType)
		if scope == "" {
			return nil
		}
		return []SearchAffected{{Op: SearchOpReindex, Scope: scope, ID: p.SourceID}}
	}

	return nil
}

// assignmentSourceScope maps an assignment source_type to the search scope whose
// `assigned` / `scope_group_ids` TAG it affects, or "" for an unknown type. All
// four object types carry `scope_group_ids` (#7 spec 14), so compliance_policy —
// which has no `assigned` TAG but IS scope-filtered — must reindex on assignment
// too.
func assignmentSourceScope(sourceType string) string {
	switch sourceType {
	case "action":
		return search.ScopeAction
	case "action_set":
		return search.ScopeActionSet
	case "definition":
		return search.ScopeDefinition
	case "compliance_policy":
		return search.ScopeCompliancePolicy
	}
	return ""
}

// SearchListener returns a store.EventListener that translates the
// classifier output into search-index Asynq enqueues. Wired into the
// store at boot in cmd/control/main.go:
//
//	st.RegisterEventListener(api.SearchListener(st, idx, logger))
//
// Errors are logged and swallowed (post-commit notification
// contract). The periodic indexer reconciler is the safety net for
// any enqueue that drops on the floor — bounded drift, not silent
// data loss.
//
// Listener dispatch is synchronous within fireListeners' RLock loop.
// Search enqueue is a single Valkey LPUSH (~ms); blocking the
// post-commit path on it is acceptable. If future scopes need
// heavier work (e.g. cascade-ID lookups via GetReverseMembers can
// add a second Valkey roundtrip), revisit and consider goroutine
// dispatch like the system-action listener does.
func SearchListener(st *store.Store, idx SearchIndex, logger *slog.Logger) store.EventListener {
	if st == nil || idx == nil {
		// Guard: missing deps shouldn't crash AppendEvent. Return a
		// no-op listener that logs once at registration time elsewhere.
		return func(context.Context, store.PersistedEvent) {}
	}

	return func(ctx context.Context, e store.PersistedEvent) {
		ops := AffectedSearchOps(e)
		if len(ops) == 0 {
			return
		}
		for _, op := range ops {
			switch op.Op {
			case SearchOpReindex:
				data, err := loadSearchEntityData(ctx, st, logger, op.Scope, op.ID)
				if err != nil {
					if errors.Is(err, errSkipSystemAction) {
						// System-managed action: never in the search catalog. Purge
						// any stale entry (no-op if it was never indexed) instead of
						// reindexing, so it can't surface in the actions list.
						if remErr := idx.EnqueueRemove(ctx, op.Scope, op.ID, nil); remErr != nil {
							logger.Warn("search listener: failed to purge system action from index",
								"scope", op.Scope, "id", op.ID, "event_type", e.EventType, "error", remErr)
						}
						continue
					}
					if store.IsNotFound(err) {
						logger.Debug("search listener: entity gone before reindex (likely deleted in same tx batch); skipping",
							"scope", op.Scope, "id", op.ID, "event_type", e.EventType)
						continue
					}
					logger.Warn("search listener: failed to load entity for reindex",
						"scope", op.Scope, "id", op.ID, "event_type", e.EventType, "error", err)
					continue
				}
				if err := idx.EnqueueReindex(ctx, op.Scope, op.ID, data); err != nil {
					logger.Warn("search listener: failed to enqueue reindex",
						"scope", op.Scope, "id", op.ID, "event_type", e.EventType, "error", err)
				}
			case SearchOpRemove:
				// For scopes with reverse-member relationships
				// (action_set, definition), pull cascade IDs from
				// the search index BEFORE enqueueing the remove —
				// those parent rows need to rebuild their
				// denormalised member lists once the child is gone.
				// The reverse-member entries persist in Redis until
				// the indexer worker actually processes the
				// EnqueueRemove task, so the lookup still finds them
				// when the listener fires.
				cascadeIDs := cascadeIDsForRemove(ctx, idx, op.Scope, op.ID)
				if err := idx.EnqueueRemove(ctx, op.Scope, op.ID, cascadeIDs); err != nil {
					logger.Warn("search listener: failed to enqueue remove",
						"scope", op.Scope, "id", op.ID, "event_type", e.EventType, "error", err)
				}
			case SearchOpTouchDeviceLastSeen:
				// #499: single Valkey write, same cost class as the
				// enqueue LPUSH this loop already tolerates. The
				// timestamp is the event's occurred_at — the same
				// value the Postgres projection writes for this
				// heartbeat, so the two stores agree.
				if err := idx.TouchDeviceLastSeen(ctx, op.ID, e.OccurredAt.Unix()); err != nil {
					logger.Warn("search listener: failed to touch device last_seen_at",
						"id", op.ID, "event_type", e.EventType, "error", err)
				}
			}
		}
	}
}

// loadSearchEntityData reads the projection row for an entity and
// converts it into the SearchEntityData payload the indexer worker
// consumes. Mirrors the field selection in each handler's
// enqueueXxxReindex helper — a divergence here would cause the
// listener-driven reindex to populate different fields than the
// handler-driven path, so any change to those helpers must change
// this function in lockstep.
//
// During the Phase 1 migration both paths fire (handler-side and
// listener-side); the Asynq worker deduplicates on the (scope,id)
// key but the LATEST payload wins. So listener payload divergence
// would be silent until Phase 2 removes the handler-side path. The
// Phase 1 tests assert end-to-end equivalence to catch this.
// sourceAssignedTag returns the "assigned" TAG value for a source entity by
// counting its live assignments (#325). source_type is "action"/"action_set"/
// "definition"; empty Column3/Column4 wildcard the target tuple.
func sourceAssignedTag(ctx context.Context, q *db.Queries, sourceType, id string) (string, error) {
	cnt, err := q.CountAssignments(ctx, db.CountAssignmentsParams{Column1: sourceType, Column2: id})
	if err != nil {
		return "", err
	}
	if cnt > 0 {
		return "true", nil
	}
	return "false", nil
}

// loadScopeGroupIDs returns the comma-joined, sorted device-/user-group ids the
// object is DIRECTLY assigned to, for the search index `scope_group_ids` TAG (#7
// spec 14). Sorted so the indexed value is deterministic (stable tests; stable
// HSET). An unassigned object returns "" — written as an empty TAG so it matches
// no scoped query and stays invisible to scoped admins.
func loadScopeGroupIDs(ctx context.Context, q *db.Queries, sourceType, id string) (string, error) {
	ids, err := q.ListScopeGroupIDsForSource(ctx, db.ListScopeGroupIDsForSourceParams{SourceType: sourceType, SourceID: id})
	if err != nil {
		return "", err
	}
	sort.Strings(ids)
	return strings.Join(ids, ","), nil
}

// loadDeviceScopeGroupIDs / loadUserScopeGroupIDs return the comma-joined sorted
// group ids a device/user belongs to, for the device/user search `scope_group_ids`
// TAG (#7 spec 14). Same source as the auth ScopeResolver, so search confinement
// matches handler enforcement.
func loadDeviceScopeGroupIDs(ctx context.Context, q *db.Queries, deviceID string) (string, error) {
	ids, err := q.ListDeviceGroupIDsForDevice(ctx, deviceID)
	if err != nil {
		return "", err
	}
	sort.Strings(ids)
	return strings.Join(ids, ","), nil
}

func loadUserScopeGroupIDs(ctx context.Context, q *db.Queries, userID string) (string, error) {
	ids, err := q.ListUserGroupIDsForUser(ctx, userID)
	if err != nil {
		return "", err
	}
	sort.Strings(ids)
	return strings.Join(ids, ","), nil
}

// errSkipSystemAction signals that an action is system-managed (is_system=true)
// and must NOT be indexed — the SearchListener purges any stale entry instead of
// reindexing. Sentinel rather than (nil, nil) so the unknown-scope guard at the
// end of loadSearchEntityData still catches a genuinely missing loader.
var errSkipSystemAction = errors.New("search: system-managed action excluded from index")

func loadSearchEntityData(ctx context.Context, st *store.Store, logger *slog.Logger, scope, id string) (*taskqueue.SearchEntityData, error) {
	q := st.Queries()
	switch scope {

	case search.ScopeUser:
		u, err := q.GetUserByID(ctx, id)
		if err != nil {
			return nil, err
		}
		disabled := "false"
		if u.Disabled {
			disabled = "true"
		}
		var createdAt, lastLoginAt int64
		if u.CreatedAt != nil {
			createdAt = u.CreatedAt.Unix()
		}
		if u.LastLoginAt != nil {
			lastLoginAt = u.LastLoginAt.Unix()
		}
		scopeGroups, err := loadUserScopeGroupIDs(ctx, q, id)
		if err != nil {
			return nil, err
		}
		return &taskqueue.SearchEntityData{
			Email:            u.Email,
			DisplayName:      u.DisplayName,
			LinuxUsername:    u.LinuxUsername,
			Disabled:         disabled,
			Role:             u.Role,
			LastLoginAt:      lastLoginAt,
			CreatedAt:        createdAt,
			ScopeGroupIDs:    scopeGroups,
			HasScopeGroupIDs: true,
		}, nil

	case search.ScopeDevice:
		d, err := q.GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: id})
		if err != nil {
			return nil, err
		}
		// Wave E.4: labels live in device_labels — load separately.
		labelRows, err := q.ListDeviceLabels(ctx, id)
		if err != nil {
			return nil, err
		}
		labels := make(map[string]string, len(labelRows))
		for _, r := range labelRows {
			labels[r.Key] = r.Value
		}
		var registeredAt, lastSeenAt int64
		if d.RegisteredAt != nil {
			registeredAt = d.RegisteredAt.Unix()
		}
		if d.LastSeenAt != nil {
			lastSeenAt = d.LastSeenAt.Unix()
		}
		scopeGroups, err := loadDeviceScopeGroupIDs(ctx, q, id)
		if err != nil {
			return nil, err
		}
		data := &taskqueue.SearchEntityData{
			Hostname:         d.Hostname,
			AgentVersion:     d.AgentVersion,
			Labels:           search.FlattenLabels(labels),
			ComplianceStatus: d.ComplianceStatus,
			RegisteredAt:     registeredAt,
			LastSeenAt:       lastSeenAt,
			ScopeGroupIDs:    scopeGroups,
			HasScopeGroupIDs: true,
		}
		// Inventory enrichment is best-effort — matches the
		// handler-side helper in device_handler.go. A missing
		// inventory row leaves the index without OS/kernel detail
		// but doesn't fail the reindex.
		if inv, invErr := q.GetDeviceInventoryByTables(ctx, db.GetDeviceInventoryByTablesParams{
			DeviceID: id,
			Column2:  []string{"os_version", "kernel_info"},
		}); invErr == nil {
			for _, t := range inv {
				search.EnrichDeviceInventory(data, t.TableName, t.Rows)
			}
		}
		return data, nil

	case search.ScopeDeviceGroup:
		g, err := q.GetDeviceGroupByID(ctx, id)
		if err != nil {
			return nil, err
		}
		isDynamic := "false"
		if g.IsDynamic {
			isDynamic = "true"
		}
		var createdAt int64
		if g.CreatedAt != nil {
			createdAt = g.CreatedAt.Unix()
		}
		return &taskqueue.SearchEntityData{
			Name:        g.Name,
			Description: g.Description,
			IsDynamic:   isDynamic,
			MemberCount: g.MemberCount,
			CreatedAt:   createdAt,
			// A device group is in-scope for a caller scoped to it: stamp its OWN
			// id so ObjectScopeListFilter (union device-/user-group scope) confines
			// Search to the groups the caller can list (H4).
			ScopeGroupIDs:    id,
			HasScopeGroupIDs: true,
		}, nil

	case search.ScopeActionSet:
		s, err := q.GetActionSetByID(ctx, id)
		if err != nil {
			return nil, err
		}
		var createdAt, updatedAt int64
		if s.CreatedAt != nil {
			createdAt = s.CreatedAt.Unix()
		}
		if s.UpdatedAt != nil {
			updatedAt = s.UpdatedAt.Unix()
		}
		assigned, err := sourceAssignedTag(ctx, q, "action_set", id)
		if err != nil {
			return nil, err
		}
		scopeGroups, err := loadScopeGroupIDs(ctx, q, "action_set", id)
		if err != nil {
			return nil, err
		}
		return &taskqueue.SearchEntityData{
			Name:             s.Name,
			Description:      s.Description,
			MemberCount:      s.MemberCount,
			Assigned:         assigned,
			ScopeGroupIDs:    scopeGroups,
			HasScopeGroupIDs: true,
			CreatedAt:        createdAt,
			UpdatedAt:        updatedAt,
		}, nil

	case search.ScopeCompliancePolicy:
		p, err := q.GetCompliancePolicyByID(ctx, id)
		if err != nil {
			return nil, err
		}
		scopeGroups, err := loadScopeGroupIDs(ctx, q, "compliance_policy", id)
		if err != nil {
			return nil, err
		}
		data := &taskqueue.SearchEntityData{
			Name:             p.Name,
			Description:      p.Description,
			ScopeGroupIDs:    scopeGroups,
			HasScopeGroupIDs: true,
		}
		if p.CreatedAt != nil {
			data.CreatedAt = p.CreatedAt.Unix()
		}
		// Rule list is denormalised into ActionNames so a search
		// hit can match against the action names referenced by the
		// policy's rules. Best-effort: a rule-list query failure
		// is logged but doesn't fail the reindex — we'd rather
		// publish a payload missing ActionNames than skip the
		// reindex entirely. HasActionNames stays false so the
		// indexer worker leaves any prior denormalised value alone
		// (HSET-additive semantics) instead of clobbering it with
		// an empty string we never confirmed was correct.
		rules, rErr := q.ListCompliancePolicyRules(ctx, id)
		if rErr != nil {
			logger.Warn("search listener: failed to load compliance policy rules; reindex without action_names",
				"policy_id", id, "error", rErr)
		} else {
			var actionNames []string
			for _, r := range rules {
				if r.ActionName != "" {
					actionNames = append(actionNames, r.ActionName)
				}
			}
			data.ActionNames = strings.Join(actionNames, " ")
			data.HasActionNames = true
			data.RuleCount = int32(len(rules))
			data.HasRuleCount = true
		}
		return data, nil

	case search.ScopeAction:
		a, err := q.GetActionByID(ctx, id)
		if err != nil {
			return nil, err
		}
		// System-managed actions (SSH/TTY/provisioning grants) are never part of
		// the user-facing search catalog — the SQL ListActions path already
		// excludes them (is_system=FALSE), so the incremental indexer must too,
		// or they'd leak into the actions list page. Signal the listener to purge
		// any stale entry instead of reindexing.
		if a.IsSystem {
			return nil, errSkipSystemAction
		}
		desc := ""
		if a.Description != nil {
			desc = *a.Description
		}
		// isCompliance lives in action.params as a boolean. The
		// search row denormalises it so a search hit can render
		// without parsing JSON. Mirrors the handler's old
		// enqueueActionReindex shape.
		isCompliance := false
		var params map[string]any
		if json.Unmarshal(a.Params, &params) == nil {
			if v, ok := params["isCompliance"].(bool); ok {
				isCompliance = v
			}
		}
		var createdAt, updatedAt int64
		if a.CreatedAt != nil {
			createdAt = a.CreatedAt.Unix()
		}
		if a.UpdatedAt != nil {
			updatedAt = a.UpdatedAt.Unix()
		}
		assigned, err := sourceAssignedTag(ctx, q, "action", id)
		if err != nil {
			return nil, err
		}
		scopeGroups, err := loadScopeGroupIDs(ctx, q, "action", id)
		if err != nil {
			return nil, err
		}
		return &taskqueue.SearchEntityData{
			Name:             a.Name,
			Description:      desc,
			Type:             a.ActionType,
			IsCompliance:     isCompliance,
			Assigned:         assigned,
			ScopeGroupIDs:    scopeGroups,
			HasScopeGroupIDs: true,
			CreatedAt:        createdAt,
			UpdatedAt:        updatedAt,
		}, nil

	case search.ScopeDefinition:
		d, err := q.GetDefinitionByID(ctx, id)
		if err != nil {
			return nil, err
		}
		var createdAt, updatedAt int64
		if d.CreatedAt != nil {
			createdAt = d.CreatedAt.Unix()
		}
		if d.UpdatedAt != nil {
			updatedAt = d.UpdatedAt.Unix()
		}
		assigned, err := sourceAssignedTag(ctx, q, "definition", id)
		if err != nil {
			return nil, err
		}
		scopeGroups, err := loadScopeGroupIDs(ctx, q, "definition", id)
		if err != nil {
			return nil, err
		}
		return &taskqueue.SearchEntityData{
			Name:             d.Name,
			Description:      d.Description,
			MemberCount:      d.MemberCount,
			Assigned:         assigned,
			ScopeGroupIDs:    scopeGroups,
			HasScopeGroupIDs: true,
			CreatedAt:        createdAt,
			UpdatedAt:        updatedAt,
		}, nil

	case search.ScopeUserGroup:
		g, err := q.GetUserGroupByID(ctx, id)
		if err != nil {
			return nil, err
		}
		isDynamic := "false"
		if g.IsDynamic {
			isDynamic = "true"
		}
		var createdAt int64
		if !g.CreatedAt.IsZero() {
			createdAt = g.CreatedAt.Unix()
		}
		return &taskqueue.SearchEntityData{
			Name:        g.Name,
			Description: g.Description,
			IsDynamic:   isDynamic,
			MemberCount: g.MemberCount,
			CreatedAt:   createdAt,
			// Own id — same rationale as ScopeDeviceGroup (H4).
			ScopeGroupIDs:    id,
			HasScopeGroupIDs: true,
		}, nil

	case search.ScopeExecution:
		// Execution rows denormalise action name + device hostname
		// into the search payload so a search hit can render without
		// a join. Mirror the inline assembly the DispatchAction
		// handler does today; missing action / device rows are
		// non-fatal (the search payload renders the empty fields).
		exec, err := q.GetExecutionByID(ctx, id)
		if err != nil {
			return nil, err
		}
		var actionName, deviceHostname string
		execActionID := ""
		if exec.ActionID != nil {
			execActionID = *exec.ActionID
			if action, aErr := q.GetActionByID(ctx, *exec.ActionID); aErr == nil {
				actionName = action.Name
			}
		}
		if device, dErr := q.GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: exec.DeviceID}); dErr == nil {
			deviceHostname = device.Hostname
		}
		var execCreatedAt, execDurationMs int64
		if exec.CreatedAt != nil {
			execCreatedAt = exec.CreatedAt.Unix()
		}
		if exec.DurationMs != nil {
			execDurationMs = *exec.DurationMs
		}
		// An execution inherits the scope of its TARGET DEVICE: stamp the device's
		// device-group ids so a scope-restricted caller sees only executions on
		// devices in their scope, mirroring the dedicated ListExecutions confinement
		// (H4 — was leaking every execution fleet-wide).
		scopeGroups, err := loadDeviceScopeGroupIDs(ctx, q, exec.DeviceID)
		if err != nil {
			return nil, err
		}
		return &taskqueue.SearchEntityData{
			ActionName:       actionName,
			DeviceHostname:   deviceHostname,
			Status:           exec.Status,
			Type:             exec.ActionType,
			DeviceID:         exec.DeviceID,
			CreatedAt:        execCreatedAt,
			DurationMs:       execDurationMs,
			Changed:          exec.Changed,
			DesiredState:     exec.DesiredState,
			ActionID:         execActionID,
			ScopeGroupIDs:    scopeGroups,
			HasScopeGroupIDs: true,
		}, nil
	}

	// Unknown scope. Returning an explicit error rather than (nil, nil)
	// catches classifier/loader drift at the listener boundary — if a
	// future PR adds a scope to AffectedSearchOps without updating
	// loadSearchEntityData, the listener logs a warning instead of
	// silently enqueueing an empty SearchEntityData payload that would
	// blank out the indexed entity.
	return nil, fmt.Errorf("loadSearchEntityData: unknown scope %q", scope)
}

// cascadeIDsForRemove looks up the parent IDs that need their
// denormalised member-list rebuilt after a child entity is removed
// from the search index. Only ActionSet and Definition support
// reverse-member tracking today (other scopes return nil for "no
// cascade needed"). Mirrors the GetReverseMembers + EnqueueRemove
// dance the action_set / definition handlers used to do inline
// before #81 Phase 2c moved the responsibility to the listener.
//
// Race window: if multiple removes for the same parent fire rapidly,
// the indexer worker may have already processed one and cleared the
// reverse-member set in Redis, so subsequent listener invocations
// will see an empty cascade list. The periodic indexer reconciler
// catches the resulting drift within ~1h. Single-remove flows have
// no race.
func cascadeIDsForRemove(ctx context.Context, idx SearchIndex, scope, id string) []string {
	switch scope {
	case search.ScopeAction, search.ScopeActionSet, search.ScopeDefinition:
		return idx.GetReverseMembers(ctx, scope, id)
	}
	return nil
}
