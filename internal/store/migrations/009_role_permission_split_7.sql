-- manchtools/power-manage-server#7 — permission registry split for
-- group-anchored RBAC scoping. Renames legacy permission keys in
-- existing roles_projection rows so custom roles created against
-- the pre-#7 registry keep working:
--
--   CreateDeviceGroup      → CreateStaticDeviceGroup
--                            (+ CreateDynamicDeviceGroup appended,
--                             preserving the old key's combined
--                             static-OR-dynamic capability)
--   CreateUserGroup        → CreateStaticUserGroup
--                            (+ CreateDynamicUserGroup appended)
--   UpdateDeviceGroupQuery → UpdateDynamicDeviceGroupQuery
--                            (no append — the old key was already
--                             dynamic-only by RPC semantics)
--   UpdateUserGroupQuery   → UpdateDynamicUserGroupQuery
--
-- The bootstrap Admin role is overwritten on next server startup by
-- internal/auth.ReconcileSystemRoles, which always syncs to
-- AdminPermissions() — so the seed-installed Admin gets the
-- AssignRoleScope key without further migration. This migration
-- exists to cover custom roles in the projection that
-- ReconcileSystemRoles does NOT touch.
--
-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    -- Rename the legacy single-key Create permissions; append the
    -- dynamic counterpart so combined capability is preserved.
    UPDATE roles_projection
       SET permissions =
           CASE
               WHEN NOT ('CreateDynamicDeviceGroup' = ANY(permissions))
                   THEN array_append(
                       array_replace(permissions, 'CreateDeviceGroup', 'CreateStaticDeviceGroup'),
                       'CreateDynamicDeviceGroup'
                   )
               ELSE array_replace(permissions, 'CreateDeviceGroup', 'CreateStaticDeviceGroup')
           END
     WHERE 'CreateDeviceGroup' = ANY(permissions);

    UPDATE roles_projection
       SET permissions =
           CASE
               WHEN NOT ('CreateDynamicUserGroup' = ANY(permissions))
                   THEN array_append(
                       array_replace(permissions, 'CreateUserGroup', 'CreateStaticUserGroup'),
                       'CreateDynamicUserGroup'
                   )
               ELSE array_replace(permissions, 'CreateUserGroup', 'CreateStaticUserGroup')
           END
     WHERE 'CreateUserGroup' = ANY(permissions);

    -- Rename the legacy Update*Query permissions in place. The old
    -- keys were dynamic-only by RPC semantics, so no append needed.
    UPDATE roles_projection
       SET permissions = array_replace(permissions, 'UpdateDeviceGroupQuery', 'UpdateDynamicDeviceGroupQuery')
     WHERE 'UpdateDeviceGroupQuery' = ANY(permissions);

    UPDATE roles_projection
       SET permissions = array_replace(permissions, 'UpdateUserGroupQuery', 'UpdateDynamicUserGroupQuery')
     WHERE 'UpdateUserGroupQuery' = ANY(permissions);
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    -- Reverse the rename. The split-vs-combined re-collapse drops
    -- the explicit dynamic permission and replaces the static one
    -- with the legacy key. Loses information (a role granted ONLY
    -- the dynamic capability post-#7 would collapse to the legacy
    -- "both" key on downgrade) — acceptable for an undo of an
    -- additive migration with no deployed callers.

    UPDATE roles_projection
       SET permissions = array_remove(
               array_replace(permissions, 'CreateStaticDeviceGroup', 'CreateDeviceGroup'),
               'CreateDynamicDeviceGroup'
           )
     WHERE 'CreateStaticDeviceGroup' = ANY(permissions)
        OR 'CreateDynamicDeviceGroup' = ANY(permissions);

    UPDATE roles_projection
       SET permissions = array_remove(
               array_replace(permissions, 'CreateStaticUserGroup', 'CreateUserGroup'),
               'CreateDynamicUserGroup'
           )
     WHERE 'CreateStaticUserGroup' = ANY(permissions)
        OR 'CreateDynamicUserGroup' = ANY(permissions);

    UPDATE roles_projection
       SET permissions = array_replace(permissions, 'UpdateDynamicDeviceGroupQuery', 'UpdateDeviceGroupQuery')
     WHERE 'UpdateDynamicDeviceGroupQuery' = ANY(permissions);

    UPDATE roles_projection
       SET permissions = array_replace(permissions, 'UpdateDynamicUserGroupQuery', 'UpdateUserGroupQuery')
     WHERE 'UpdateDynamicUserGroupQuery' = ANY(permissions);
END $$;
-- +goose StatementEnd
