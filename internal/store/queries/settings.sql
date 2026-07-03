-- name: GetServerSettings :one
SELECT * FROM server_settings_projection WHERE id = 'global';

-- name: SeedServerSettings :exec
-- Re-seeds the singleton 'global' row at projection_version 0 (#497). A
-- rebuild TRUNCATEs the table, dropping the migration-seeded row; the
-- UPDATE-only projector would then no-op forever. The rebuild applier calls
-- this first so the subsequent ServerSettingUpdated replays (all at
-- projection_version > 0) land on a present row. Idempotent: ON CONFLICT DO
-- NOTHING means a live-path call (row already present) is a no-op, and it
-- never clobbers a rebuilt row's settings.
INSERT INTO server_settings_projection (id, projection_version)
VALUES ('global', 0)
ON CONFLICT (id) DO NOTHING;

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
