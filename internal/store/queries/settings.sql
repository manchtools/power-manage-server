-- name: GetServerSettings :one
SELECT * FROM server_settings_projection WHERE id = 'global';

-- name: UpdateServerSettings :exec
-- Replaces the deleted PL/pgSQL project_server_settings_event
-- function. COALESCE preserves existing column values when the
-- event payload omits a field — sqlc.narg yields nullable *bool
-- params, and the listener passes nil for any field the event left
-- out, which COALESCE collapses to the existing value. The
-- `projection_version` guard protects against stale reconciler
-- replays clobbering a fresher state.
UPDATE server_settings_projection
SET user_provisioning_enabled = COALESCE(sqlc.narg('user_provisioning_enabled')::BOOLEAN, user_provisioning_enabled),
    ssh_access_for_all        = COALESCE(sqlc.narg('ssh_access_for_all')::BOOLEAN, ssh_access_for_all),
    updated_at                = sqlc.arg('updated_at'),
    projection_version        = sqlc.arg('projection_version')
WHERE id = 'global'
  AND projection_version < sqlc.arg('projection_version');
