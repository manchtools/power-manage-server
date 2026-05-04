package api

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

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
	// the indexed fields per UserHandler.enqueueUserReindex (in
	// user_handler.go). Other user events (SSH keys, password,
	// session invalidation, system-action linking) don't surface
	// in search results today, so they classify as SearchOpNone.
	case "UserCreated",
		"UserEmailChanged",
		"UserProfileUpdated",
		"UserLinuxUsernameChanged",
		"UserDisabled":
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeUser, ID: e.StreamID}}

	case "UserDeleted":
		return []SearchAffected{{Op: SearchOpRemove, Scope: search.ScopeUser, ID: e.StreamID}}

	// ---------------------------------------------------------
	// Device scope
	// ---------------------------------------------------------
	// Hostname, agent version, labels, and sync interval are the
	// denormalised fields per DeviceHandler.enqueueDeviceReindex.
	// Cert renewal / assignment / unassignment do not change any
	// of those fields → SearchOpNone.
	case "DeviceRegistered",
		"DeviceLabelSet",
		"DeviceLabelRemoved",
		"DeviceSyncIntervalSet":
		return []SearchAffected{{Op: SearchOpReindex, Scope: search.ScopeDevice, ID: e.StreamID}}

	case "DeviceDeleted":
		return []SearchAffected{{Op: SearchOpRemove, Scope: search.ScopeDevice, ID: e.StreamID}}
	}

	return nil
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
func SearchListener(st *store.Store, idx *search.Index, logger *slog.Logger) store.EventListener {
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
				data, err := loadSearchEntityData(ctx, st, op.Scope, op.ID)
				if err != nil {
					if errors.Is(err, pgx.ErrNoRows) {
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
				if err := idx.EnqueueRemove(ctx, op.Scope, op.ID, nil); err != nil {
					logger.Warn("search listener: failed to enqueue remove",
						"scope", op.Scope, "id", op.ID, "event_type", e.EventType, "error", err)
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
func loadSearchEntityData(ctx context.Context, st *store.Store, scope, id string) (*taskqueue.SearchEntityData, error) {
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
		var createdAt int64
		if u.CreatedAt != nil {
			createdAt = u.CreatedAt.Unix()
		}
		return &taskqueue.SearchEntityData{
			Email:         u.Email,
			DisplayName:   u.DisplayName,
			LinuxUsername: u.LinuxUsername,
			Disabled:      disabled,
			CreatedAt:     createdAt,
		}, nil

	case search.ScopeDevice:
		d, err := q.GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: id})
		if err != nil {
			return nil, err
		}
		var registeredAt, lastSeenAt int64
		if d.RegisteredAt != nil {
			registeredAt = d.RegisteredAt.Unix()
		}
		if d.LastSeenAt != nil {
			lastSeenAt = d.LastSeenAt.Unix()
		}
		data := &taskqueue.SearchEntityData{
			Hostname:         d.Hostname,
			AgentVersion:     d.AgentVersion,
			Labels:           search.FlattenLabels(d.Labels),
			ComplianceStatus: d.ComplianceStatus,
			RegisteredAt:     registeredAt,
			LastSeenAt:       lastSeenAt,
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
	}

	return nil, nil
}
