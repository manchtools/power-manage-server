package api

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// Object-visibility scope enforcement (#7 spec 14). The four shared object types
// (action, action_set, definition, compliance_policy) are confined to a scoped
// admin by ASSIGNMENT: a caller scoped to device/user groups sees and manages
// only objects assigned within those groups. Caller scope comes from the JWT
// (auth.ObjectScopeListFilter — no DB round-trip); the object's groups are
// resolved live here.
//
//   - READ  uses EFFECTIVE groups (the object's own assignments PLUS its
//     containers' — an action that runs on your fleet via an assigned set/
//     definition is visible). Out of scope → NotFound (never PermissionDenied —
//     no existence leak), and the real reason is logged at WARN.
//   - WRITE uses DIRECT groups only (a transitively-visible object is not
//     editable). Out of scope → PermissionDenied.

// objectScopeGroups resolves an object's scope groups. Behind an interface so the
// enforcement decision logic (restricted-gate, intersection, error mapping) is
// unit-testable without a database.
type objectScopeGroups interface {
	// effective returns the object's own assignment groups plus its containers'.
	effective(ctx context.Context, objectType, id string) ([]string, error)
	// direct returns only the object's own assignment groups.
	direct(ctx context.Context, objectType, id string) ([]string, error)
}

// storeObjectScopeGroups resolves object scope groups from the projections.
type storeObjectScopeGroups struct {
	q        *db.Queries
	resolver auth.ScopeResolver
}

// objScope builds the store-backed resolver for a handler's store.
func objScope(st *store.Store) objectScopeGroups {
	return storeObjectScopeGroups{q: st.Queries(), resolver: newScopeResolver(st)}
}

// resolveAssignmentGroups returns the device-/user-group ids an object is
// directly assigned to: device_group/user_group targets contribute their id;
// device/user targets are resolved through group membership (spec 14, criterion
// 8). Shared by direct() and the container walk in effective().
func (s storeObjectScopeGroups) resolveAssignmentGroups(ctx context.Context, objectType, id string) ([]string, error) {
	assigns, err := s.q.ListAssignmentsForSource(ctx, db.ListAssignmentsForSourceParams{SourceType: objectType, SourceID: id})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range assigns {
		switch a.TargetType {
		case "device_group", "user_group":
			out = append(out, a.TargetID)
		case "device":
			gs, err := s.resolver.DeviceGroupsForDevice(ctx, a.TargetID)
			if err != nil {
				return nil, err
			}
			out = append(out, gs...)
		case "user":
			gs, err := s.resolver.UserGroupsForUser(ctx, a.TargetID)
			if err != nil {
				return nil, err
			}
			out = append(out, gs...)
		}
	}
	return out, nil
}

func (s storeObjectScopeGroups) direct(ctx context.Context, objectType, id string) ([]string, error) {
	return s.resolveAssignmentGroups(ctx, objectType, id)
}

func (s storeObjectScopeGroups) effective(ctx context.Context, objectType, id string) ([]string, error) {
	groups, err := s.resolveAssignmentGroups(ctx, objectType, id)
	if err != nil {
		return nil, err
	}
	switch objectType {
	case "action":
		// Containers: every set holding the action, and every definition holding
		// one of those sets. (Definitions hold sets, not actions directly.)
		setIDs, err := s.q.ListActionSetIDsContainingAction(ctx, id)
		if err != nil {
			return nil, err
		}
		defIDs := map[string]struct{}{}
		for _, sid := range setIDs {
			g, err := s.resolveAssignmentGroups(ctx, "action_set", sid)
			if err != nil {
				return nil, err
			}
			groups = append(groups, g...)
			dids, err := s.q.ListDefinitionIDsContainingActionSet(ctx, sid)
			if err != nil {
				return nil, err
			}
			for _, did := range dids {
				defIDs[did] = struct{}{}
			}
		}
		for did := range defIDs {
			g, err := s.resolveAssignmentGroups(ctx, "definition", did)
			if err != nil {
				return nil, err
			}
			groups = append(groups, g...)
		}
	case "action_set":
		defIDs, err := s.q.ListDefinitionIDsContainingActionSet(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, did := range defIDs {
			g, err := s.resolveAssignmentGroups(ctx, "definition", did)
			if err != nil {
				return nil, err
			}
			groups = append(groups, g...)
		}
	}
	// definition / compliance_policy are top-level — no containers.
	return groups, nil
}

// enforceObjectReadScope confines a Get to the caller's scope. A scope-restricted
// caller whose scope groups don't intersect the object's EFFECTIVE groups gets
// notFoundErr (CodeNotFound) — never PermissionDenied, so existence isn't leaked
// — while the true reason is logged at WARN so operators can see the denial
// (spec 14, criterion 5). Unrestricted callers (global admins) are unaffected.
func enforceObjectReadScope(ctx context.Context, groups objectScopeGroups, logger *slog.Logger, objectType, id, notFoundErr, notFoundMsg string) error {
	callerGroups, restricted := auth.ObjectScopeListFilter(ctx)
	if !restricted {
		return nil
	}
	objGroups, err := groups.effective(ctx, objectType, id)
	if err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "scope resolution failed")
	}
	if groupsIntersect(callerGroups, objGroups) {
		return nil
	}
	logger.Warn("out-of-scope object access denied (returning NotFound)",
		"object_type", objectType, "object_id", id, "caller_scope_group_ids", callerGroups)
	return apiErrorCtx(ctx, notFoundErr, connect.CodeNotFound, notFoundMsg)
}

// enforceObjectWriteScope confines a mutation to the caller's scope. A
// scope-restricted caller whose scope groups don't intersect the object's DIRECT
// groups gets PermissionDenied — including when the object is only transitively
// visible (visible via a container, but not directly assigned to the caller).
// Unrestricted callers are unaffected.
func enforceObjectWriteScope(ctx context.Context, groups objectScopeGroups, logger *slog.Logger, objectType, id string) error {
	callerGroups, restricted := auth.ObjectScopeListFilter(ctx)
	if !restricted {
		return nil
	}
	objGroups, err := groups.direct(ctx, objectType, id)
	if err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "scope resolution failed")
	}
	if groupsIntersect(callerGroups, objGroups) {
		return nil
	}
	logger.Warn("out-of-scope object mutation denied",
		"object_type", objectType, "object_id", id, "caller_scope_group_ids", callerGroups)
	return apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "permission denied")
}

// groupsIntersect reports whether a and b share any element.
func groupsIntersect(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, x := range a {
		set[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := set[y]; ok {
			return true
		}
	}
	return false
}
