-- Replace project_user_group_event() with a no-op stub. The actual
-- projection logic now lives in projectors.UserGroupListener (Go,
-- post-commit). The shared project_event() dispatcher trigger still
-- PERFORMs project_user_group_event(NEW) for every user_group-stream
-- event; the no-op stub keeps that dispatch quiet (no
-- plpgsql_projection_errors entries) until the Phase 2 cleanup
-- migration drops every still-PL/pgSQL WHEN clause from the
-- dispatcher.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The ten event types (Created, Updated,
--     QueryUpdated, MaintenanceWindowSet, Deleted, MemberAdded,
--     MemberRemoved, RoleAssigned, RoleRevoked, MembersRebuilt) and
--     their cascades were atomic with the event commit.
--   - After: Go listener fires post-commit. Every multi-write event
--     (MemberAdded/Removed, Deleted, MembersRebuilt, QueryUpdated when
--     flipping to dynamic) wraps its writes in store.WithTx so the
--     cascade stays atomic with itself, but not with the event commit.
--     The handler's read-after-write paths (CreateUserGroup /
--     AddUserToGroup / DeleteUserGroup etc. reading back from
--     user_groups_projection) still see the projection because
--     fireListeners is synchronous — the listener has already run by
--     the time AppendEvent returns.
--
-- Tightening: every UPDATE on user_groups_projection (Updated,
-- QueryUpdated, MaintenanceWindowSet, member_count recount, soft-
-- delete) now carries an explicit `WHERE projection_version < $N`
-- guard, rejecting stale reconciler replays. The PL/pgSQL projector
-- stamped projection_version without a guard.
--
-- Asymmetric-guard discipline (per the role + identity_provider +
-- action_set + assignment ports): the guarded SoftDelete uses
-- :execrows, and the listener short-circuits the cascade (member
-- wipe + role-assignment wipe + scim_group_mapping cleanup +
-- dynamic_user_group_evaluation_queue cleanup) when n == 0 —
-- otherwise a stale UserGroupDeleted re-applied later would silently
-- nuke a freshly-restored group's members and role assignments.
--
-- Member/role mutation guards: UserGroupMemberAdded /
-- UserGroupMemberRemoved both early-out when the parent group is
-- dynamic (mirrors the PL/pgSQL `IF NOT EXISTS (... is_dynamic = TRUE)`
-- guard); the dynamic-query evaluator owns the member set for dynamic
-- groups. UserGroupRoleAssigned / UserGroupRoleRevoked have no parent-
-- row update so they only carry composite-PK ON CONFLICT DO NOTHING /
-- DELETE semantics.
--
-- Dynamic-query engine scope: per #136 the dynamic-query evaluator
-- (evaluate_dynamic_user_group, evaluate_queued_dynamic_user_groups,
-- validate_user_group_query) STAYS in PL/pgSQL until a later phase.
-- The Go listener only persists the query string column +
-- (re-)enqueues the group for evaluation when is_dynamic flips ON;
-- the evaluator itself runs inside Postgres unchanged.
--
-- See manchtools/power-manage-server#138. Third port under Phase 2
-- of tracker #107's projector-migration pattern.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_group_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.UserGroupListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the PL/pgSQL projector verbatim from migration 014 (the
-- last definition before this port — the body that added the
-- UserGroupMaintenanceWindowSet handling on top of 003's body).

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_group_event(event events) RETURNS void AS $$
DECLARE
    is_dyn BOOLEAN;
BEGIN
    CASE event.event_type
        WHEN 'UserGroupCreated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            INSERT INTO user_groups_projection (
                id, name, description, member_count,
                created_at, created_by, updated_at, projection_version,
                is_dynamic, dynamic_query
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                0,
                event.occurred_at,
                event.actor_id,
                event.occurred_at,
                event.sequence_num,
                is_dyn,
                event.data->>'dynamic_query'
            );

            IF is_dyn THEN
                INSERT INTO dynamic_user_group_evaluation_queue (group_id, reason)
                VALUES (event.stream_id, 'group_created')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
            END IF;

        WHEN 'UserGroupUpdated' THEN
            UPDATE user_groups_projection
            SET name = event.data->>'name',
                description = COALESCE(event.data->>'description', description),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserGroupQueryUpdated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            UPDATE user_groups_projection
            SET is_dynamic = is_dyn,
                dynamic_query = event.data->>'dynamic_query',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            IF is_dyn THEN
                DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
                UPDATE user_groups_projection SET member_count = 0 WHERE id = event.stream_id;
                INSERT INTO dynamic_user_group_evaluation_queue (group_id, reason)
                VALUES (event.stream_id, 'query_updated')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
            END IF;

        WHEN 'UserGroupMaintenanceWindowSet' THEN
            UPDATE user_groups_projection
            SET maintenance_window = COALESCE(event.data->'maintenance_window', '{}'::JSONB),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserGroupDeleted' THEN
            DELETE FROM scim_group_mapping_projection WHERE user_group_id = event.stream_id;

            UPDATE user_groups_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
            DELETE FROM user_group_roles_projection WHERE group_id = event.stream_id;
            DELETE FROM dynamic_user_group_evaluation_queue WHERE group_id = event.stream_id;

        WHEN 'UserGroupMemberAdded' THEN
            IF NOT EXISTS (
                SELECT 1 FROM user_groups_projection
                WHERE id = event.data->>'group_id' AND is_dynamic = TRUE
            ) THEN
                INSERT INTO user_group_members_projection (
                    group_id, user_id, added_at, added_by, projection_version
                ) VALUES (
                    event.data->>'group_id',
                    event.data->>'user_id',
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                )
                ON CONFLICT (group_id, user_id) DO NOTHING;

                UPDATE user_groups_projection
                SET member_count = member_count + 1,
                    updated_at = event.occurred_at,
                    projection_version = event.sequence_num
                WHERE id = event.data->>'group_id';
            END IF;

        WHEN 'UserGroupMemberRemoved' THEN
            IF NOT EXISTS (
                SELECT 1 FROM user_groups_projection
                WHERE id = event.data->>'group_id' AND is_dynamic = TRUE
            ) THEN
                DELETE FROM user_group_members_projection
                WHERE group_id = event.data->>'group_id'
                  AND user_id = event.data->>'user_id';

                UPDATE user_groups_projection
                SET member_count = GREATEST(member_count - 1, 0),
                    updated_at = event.occurred_at,
                    projection_version = event.sequence_num
                WHERE id = event.data->>'group_id';
            END IF;

        WHEN 'UserGroupRoleAssigned' THEN
            INSERT INTO user_group_roles_projection (
                group_id, role_id, assigned_at, assigned_by, projection_version
            ) VALUES (
                event.data->>'group_id',
                event.data->>'role_id',
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            )
            ON CONFLICT (group_id, role_id) DO NOTHING;

        WHEN 'UserGroupRoleRevoked' THEN
            DELETE FROM user_group_roles_projection
            WHERE group_id = event.data->>'group_id'
              AND role_id = event.data->>'role_id';

        WHEN 'UserGroupMembersRebuilt' THEN
            DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;

            INSERT INTO user_group_members_projection (group_id, user_id, added_at, added_by, projection_version)
            SELECT event.stream_id, uid, event.occurred_at, 'system', event.sequence_num
            FROM jsonb_array_elements_text(event.data->'user_ids') AS uid
            ON CONFLICT (group_id, user_id) DO NOTHING;

            UPDATE user_groups_projection
            SET member_count = COALESCE(jsonb_array_length(event.data->'user_ids'), 0),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
