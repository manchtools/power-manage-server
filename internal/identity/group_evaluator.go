package identity

import (
	"context"
	"errors"
	"sort"

	"github.com/manchtools/power-manage/server/internal/dynamicquery"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

var (
	errUserGroupNotDynamic   = errors.New("user group is not dynamic")
	errUserGroupInvalidQuery = errors.New("invalid user group query")
)

type userGroupEvaluationResult struct {
	added   int64
	removed int64
}

func (h *Handlers) countMatchingUsers(ctx context.Context, raw string) (int64, error) {
	expr, err := parseUserGroupQuery(raw)
	if err != nil {
		return 0, err
	}
	rows, err := h.store.ListUsersForDynamicUserGroupEvaluation(ctx)
	if err != nil {
		return 0, err
	}
	return int64(len(matchingUserIDs(expr, rows))), nil
}

// evaluateDynamicUserGroup reconciles the materialized membership, session
// invalidation and audit evidence in one transaction.
func (h *Handlers) evaluateDynamicUserGroup(ctx context.Context, op store.AuditOperation, groupID, actorID string) (userGroupEvaluationResult, error) {
	var result userGroupEvaluationResult
	_, err := h.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		// Take the shared authority-removal lock before the group row lock.
		// Delete/revoke paths take the same order, so an Admin-bearing
		// dynamic group cannot deadlock with a concurrent removal.
		if err := tx.LockLastAdminGuard(ctx); err != nil {
			return err
		}
		group, err := tx.GetDynamicUserGroupQueryForUpdate(ctx, groupID)
		if err != nil {
			return err
		}
		if !group.IsDynamic {
			return errUserGroupNotDynamic
		}
		if group.DynamicQuery == nil {
			return errUserGroupInvalidQuery
		}
		expr, err := parseUserGroupQuery(*group.DynamicQuery)
		if err != nil {
			return err
		}
		users, err := tx.ListUsersForDynamicUserGroupEvaluation(ctx)
		if err != nil {
			return err
		}
		wanted := matchingUserIDs(expr, users)
		current, err := tx.ListUserGroupMemberIDs(ctx, groupID)
		if err != nil {
			return err
		}
		added, removed := userMembershipDelta(current, wanted)

		if len(removed) > 0 {
			confersAdmin, err := tx.UserGroupConfersUnscopedAdmin(ctx, groupID)
			if err != nil {
				return err
			}
			if confersAdmin {
				remains, err := tx.EnabledAdminExistsAfterDynamicUserGroupEvaluation(ctx, db.EnabledAdminExistsAfterDynamicUserGroupEvaluationParams{
					GroupID: groupID, WantedUserIds: wanted,
				})
				if err != nil {
					return err
				}
				if !remains {
					return errLastAdmin
				}
			}
		}

		if len(removed) > 0 {
			removed, err = tx.RemoveDynamicUserGroupMembers(ctx, db.RemoveDynamicUserGroupMembersParams{
				GroupID: groupID, UserIds: removed,
			})
			if err != nil {
				return err
			}
		}
		if len(added) > 0 {
			at := h.now().UTC()
			added, err = tx.AddDynamicUserGroupMembers(ctx, db.AddDynamicUserGroupMembersParams{
				GroupID: groupID, UserIds: added, AddedAt: at, AddedBy: actorID,
			})
			if err != nil {
				return err
			}
		}
		sort.Strings(added)
		sort.Strings(removed)
		changed := append(append(make([]string, 0, len(added)+len(removed)), added...), removed...)
		if len(changed) > 0 {
			at := h.now().UTC()
			affected, err := tx.BumpUserSessionsByIDs(ctx, db.BumpUserSessionsByIDsParams{
				UpdatedAt: &at, UserIds: changed,
			})
			if err != nil {
				return err
			}
			effect := userGroupEffect(groupID, "INVALIDATE_MEMBER_SESSIONS", "session_version")
			effect.AfterCount = &affected
			rec.Effect(effect)
		}
		before, after := int64(len(current)), int64(len(current)-len(removed)+len(added))
		effect := userGroupEffect(groupID, "EVALUATE", "members")
		effect.BeforeCount, effect.AfterCount = &before, &after
		rec.Effect(effect)
		result.added, result.removed = int64(len(added)), int64(len(removed))
		return nil
	})
	return result, err
}

func parseUserGroupQuery(raw string) (dynamicquery.Expr, error) {
	if dynamicquery.ValidateUserQuery(raw) != nil {
		return nil, errUserGroupInvalidQuery
	}
	expr, err := dynamicquery.Parse(raw)
	if err != nil {
		return nil, errUserGroupInvalidQuery
	}
	return expr, nil
}

func matchingUserIDs(expr dynamicquery.Expr, rows []store.UserDynamicEvaluationRow) []string {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		if dynamicquery.EvaluateUser(expr, dynamicquery.UserContext{
			Email: row.Email, Disabled: row.Disabled, DisplayName: row.DisplayName,
			PreferredUsername: row.PreferredUsername, Locale: row.Locale,
		}) {
			ids = append(ids, row.ID)
		}
	}
	return ids
}

func userMembershipDelta(current, wanted []string) (added, removed []string) {
	currentSet := make(map[string]struct{}, len(current))
	wantedSet := make(map[string]struct{}, len(wanted))
	for _, id := range current {
		currentSet[id] = struct{}{}
	}
	for _, id := range wanted {
		wantedSet[id] = struct{}{}
		if _, exists := currentSet[id]; !exists {
			added = append(added, id)
		}
	}
	for _, id := range current {
		if _, exists := wantedSet[id]; !exists {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
