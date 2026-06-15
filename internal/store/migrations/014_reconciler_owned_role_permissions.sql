-- 014_reconciler_owned_role_permissions.sql
--
-- WS17b #18: the Admin/User system-role permission arrays were seeded as SQL
-- literals (008_seeds.sql) and patched by later migrations (009, 010). Each
-- frozen snapshot drifts from the Go source of truth (auth.AdminPermissions /
-- auth.DefaultUserPermissions) as permissions are added/renamed — the Admin
-- literal had already drifted 18 added + 6 renamed permissions behind by the
-- time this landed.
--
-- auth.ReconcileSystemRoles runs on every control-server boot (after
-- migrations) and OVERWRITES these arrays from the Go sets, so the literals are
-- runtime-irrelevant — only misleading, and a drift surface that no test could
-- guard while the literal was the seed. Blank them here so the permission set
-- is reconciler-owned (single source of truth = Go) with no SQL literal left to
-- drift. The reconciler refills them on the same boot.

-- +goose Up
UPDATE public.roles_projection
SET permissions = '{}'
WHERE id IN ('00000000000000000000000001', '00000000000000000000000002')
  AND is_system = TRUE;

-- +goose Down
-- No-op: the Go reconciler repopulates these on every boot regardless, so there
-- is nothing meaningful to restore.
SELECT 1;
