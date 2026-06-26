-- 009_v2026_07.sql — consolidated 2026.06 → 2026.07 schema/data delta.
--
-- This single migration replaces the six incremental migrations that landed on
-- main after the v2026.06 baseline (001–008): 009 role-permission split, 010
-- role-grant scope columns, 011 events append-only trigger, 012 IdP
-- trust_email_assertions, 013 LUKS token hashing, 014 reconciler-owned system
-- role permissions. Per the project's per-release migration convention (v2026.06
-- itself consolidated v2026.05's set), the delta ships as one ordered migration.
-- Statements are preserved verbatim and in their original apply order; Down
-- reverses that order. Source PRs: #333, #334, #404, #412, #420, #440.

-- +goose Up

-- ============================================================ [009_role_permission_split_7] UP
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


-- ============================================================ [010_role_grant_scope_7] UP
-- manchtools/power-manage-server#7 S2 — scope columns on the
-- role-grant projections.
--
-- Adds (scope_kind, scope_id) to user_roles_projection and
-- user_group_roles_projection. Paired-or-neither: both NULL means an
-- unscoped/global grant (backward-compatible with every pre-#7
-- row), both set means the grant is constrained to the named
-- group's members. The CHECK constraints enforce the invariant at
-- the DB layer so a misbehaving projector (or a crafted event)
-- can't write a half-scoped row.
--
-- Uniqueness model:
--   * Drop the existing 2-tuple primary key (user_id, role_id) and
--     replace it with two PARTIAL UNIQUE indexes:
--       - one (user_id, role_id) WHERE scope_id IS NULL    — at
--         most ONE unscoped grant per (user, role).
--       - one (user_id, role_id, scope_kind, scope_id) WHERE
--         scope_id IS NOT NULL — at most one scoped grant per
--         (user, role, scope-tuple).
--   * Symmetric shape for user_group_roles_projection.
--
-- Why partial indexes (not a single 4-column UNIQUE): NULLs are
-- treated as distinct in PostgreSQL <15 ordinary unique indexes, so
-- a single 4-column unique would let multiple unscoped grants
-- coexist for the same (user, role). NULLS NOT DISTINCT (pg ≥ 15)
-- would also work but the partial-index shape is portable across
-- versions.
--
-- Index for scope-targeted queries (the reconciler in S6 reads
-- scoped grants by (scope_kind, scope_id) to compute per-scope
-- cohorts): a separate btree index on the scope tuple, filtered to
-- rows with a scope set.
--
-- +goose StatementBegin
DO $$
BEGIN
    -- =========================================================
    -- user_roles_projection
    -- =========================================================
    ALTER TABLE public.user_roles_projection
        ADD COLUMN scope_kind TEXT NULL,
        ADD COLUMN scope_id   TEXT NULL;

    ALTER TABLE public.user_roles_projection
        ADD CONSTRAINT user_roles_scope_pair_or_neither
        CHECK ((scope_kind IS NULL) = (scope_id IS NULL));

    ALTER TABLE public.user_roles_projection
        ADD CONSTRAINT user_roles_scope_kind_valid
        CHECK (
            scope_kind IS NULL
            OR scope_kind IN ('device_group', 'user_group')
        );

    -- Swap the primary key for the two partial unique indexes.
    ALTER TABLE public.user_roles_projection
        DROP CONSTRAINT user_roles_projection_pkey;

    CREATE UNIQUE INDEX user_roles_unscoped_unique
        ON public.user_roles_projection (user_id, role_id)
        WHERE scope_id IS NULL;

    CREATE UNIQUE INDEX user_roles_scoped_unique
        ON public.user_roles_projection (user_id, role_id, scope_kind, scope_id)
        WHERE scope_id IS NOT NULL;

    -- Reconciler/lookup index for scoped grants only.
    CREATE INDEX user_roles_scope_lookup
        ON public.user_roles_projection (scope_kind, scope_id)
        WHERE scope_id IS NOT NULL;

    -- =========================================================
    -- user_group_roles_projection — symmetric shape
    -- =========================================================
    ALTER TABLE public.user_group_roles_projection
        ADD COLUMN scope_kind TEXT NULL,
        ADD COLUMN scope_id   TEXT NULL;

    ALTER TABLE public.user_group_roles_projection
        ADD CONSTRAINT user_group_roles_scope_pair_or_neither
        CHECK ((scope_kind IS NULL) = (scope_id IS NULL));

    ALTER TABLE public.user_group_roles_projection
        ADD CONSTRAINT user_group_roles_scope_kind_valid
        CHECK (
            scope_kind IS NULL
            OR scope_kind IN ('device_group', 'user_group')
        );

    ALTER TABLE public.user_group_roles_projection
        DROP CONSTRAINT user_group_roles_projection_pkey;

    CREATE UNIQUE INDEX user_group_roles_unscoped_unique
        ON public.user_group_roles_projection (group_id, role_id)
        WHERE scope_id IS NULL;

    CREATE UNIQUE INDEX user_group_roles_scoped_unique
        ON public.user_group_roles_projection (group_id, role_id, scope_kind, scope_id)
        WHERE scope_id IS NOT NULL;

    CREATE INDEX user_group_roles_scope_lookup
        ON public.user_group_roles_projection (scope_kind, scope_id)
        WHERE scope_id IS NOT NULL;
END $$;
-- +goose StatementEnd


-- ============================================================ [011_events_append_only] UP
-- 011_events_append_only.sql
--
-- Defense-in-depth: enforce the event store's append-only invariant at the
-- DATABASE level, not only in application code. The events table is the
-- system's audit trail and the single source of truth every projection
-- rebuilds from; a compromised gateway, a buggy query, or an operator with
-- direct DB access must not be able to rewrite or erase history. A BEFORE
-- trigger RAISEs on any UPDATE / DELETE / TRUNCATE, so only INSERT (append)
-- and SELECT (read) succeed.
--
-- RebuildAll only TRUNCATEs *_projection tables, never public.events, so this
-- guard does not interfere with projection rebuilds. The application-layer
-- invariant (no sqlc query mutates events) is pinned separately by
-- TestNoSQLCQueryMutatesEvents; this trigger is the belt to that suspenders.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.events_block_mutation() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'events is append-only: % is not permitted on public.events', TG_OP;
END;
$$;
-- +goose StatementEnd

-- Row-level guard for UPDATE/DELETE.
CREATE TRIGGER events_block_row_mutation
    BEFORE UPDATE OR DELETE ON public.events
    FOR EACH ROW EXECUTE FUNCTION public.events_block_mutation();

-- Statement-level guard for TRUNCATE (TRUNCATE fires no per-row triggers).
CREATE TRIGGER events_block_truncate
    BEFORE TRUNCATE ON public.events
    FOR EACH STATEMENT EXECUTE FUNCTION public.events_block_mutation();


-- ============================================================ [012_idp_trust_email_assertions] UP
-- 012_idp_trust_email_assertions.sql
--
-- WS5 #2: add an explicit operator opt-in for delegating email-identity
-- assertion to an IdP. When false (the secure default), SCIM AutoLinkByEmail
-- must NOT bind an IdP-asserted email to a pre-existing LOCAL PASSWORD account
-- — that path is an account-takeover vector (an IdP/SCIM operator who can
-- assert any email could seize a local admin's account). When true, the
-- operator has knowingly delegated identity to this provider, so auto-link to
-- a local account is permitted.
--
-- identity_providers_projection is written by the Go projector
-- (internal/projectors/identity_provider*.go), so no PL/pgSQL trigger change is
-- needed; the column is read into store.IdentityProvider and consumed by the
-- SCIM createUser handler.

ALTER TABLE public.identity_providers_projection
    ADD COLUMN trust_email_assertions boolean DEFAULT false NOT NULL;


-- ============================================================ [013_luks_token_hash] UP
-- 013_luks_token_hash.sql
--
-- WS10 #3: LUKS one-time tokens are now stored as a SHA-256 hash at rest
-- (consistent with registration/terminal tokens), so the plaintext token
-- no longer persists in luks_tokens.token. The column shape is unchanged
-- (still text) — only the value written by the handler changed
-- (device_handler.CreateLuksToken stores hashLuksToken(token);
-- ProxyValidateLuksToken hashes the presented token before lookup).
--
-- Any rows written before this change hold PLAINTEXT tokens that would
-- (a) never match the now-hashed lookup and (b) leave a usable secret at
-- rest. They are one-time and expire after 15 minutes, so clearing them
-- is safe — an operator simply re-creates the token. No schema or
-- PL/pgSQL change is needed.

DELETE FROM public.luks_tokens;


-- ============================================================ [014_reconciler_owned_role_permissions] UP
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

UPDATE public.roles_projection
SET permissions = '{}'
WHERE id IN ('00000000000000000000000001', '00000000000000000000000002')
  AND is_system = TRUE;


-- +goose Down

-- ============================================================ [014_reconciler_owned_role_permissions] DOWN
-- No-op: the Go reconciler repopulates these on every boot regardless, so there
-- is nothing meaningful to restore.
SELECT 1;

-- ============================================================ [013_luks_token_hash] DOWN
-- No-op: deleted one-time tokens cannot be restored, and the column
-- shape is unchanged.
SELECT 1;

-- ============================================================ [012_idp_trust_email_assertions] DOWN
ALTER TABLE public.identity_providers_projection
    DROP COLUMN trust_email_assertions;

-- ============================================================ [011_events_append_only] DOWN
DROP TRIGGER IF EXISTS events_block_truncate ON public.events;
DROP TRIGGER IF EXISTS events_block_row_mutation ON public.events;
DROP FUNCTION IF EXISTS public.events_block_mutation();

-- ============================================================ [010_role_grant_scope_7] DOWN
-- +goose StatementBegin
DO $$
BEGIN
    -- Drop the new indexes + constraints, then restore the original
    -- 2-tuple primary keys. Any rows holding a scope tuple are
    -- collapsed back to the unscoped shape (scope columns dropped).
    -- A scoped grant + the original PK aren't compatible (two scoped
    -- grants of the same (user, role) at different scopes), so the
    -- down here is necessarily lossy for any actor who held more
    -- than one scoped grant of the same (user, role) at downgrade
    -- time — acceptable because the up shape is the new product
    -- behaviour and downgrade is an emergency operation.

    -- =========================================================
    -- user_group_roles_projection
    -- =========================================================
    DROP INDEX IF EXISTS public.user_group_roles_scope_lookup;
    DROP INDEX IF EXISTS public.user_group_roles_scoped_unique;
    DROP INDEX IF EXISTS public.user_group_roles_unscoped_unique;

    ALTER TABLE public.user_group_roles_projection
        DROP CONSTRAINT IF EXISTS user_group_roles_scope_pair_or_neither,
        DROP CONSTRAINT IF EXISTS user_group_roles_scope_kind_valid;

    -- Collapse duplicates so the 2-tuple PK fits.
    DELETE FROM public.user_group_roles_projection a
    USING public.user_group_roles_projection b
    WHERE  a.group_id = b.group_id
      AND  a.role_id  = b.role_id
      AND  a.ctid     > b.ctid;

    ALTER TABLE public.user_group_roles_projection
        DROP COLUMN IF EXISTS scope_kind,
        DROP COLUMN IF EXISTS scope_id;

    ALTER TABLE public.user_group_roles_projection
        ADD CONSTRAINT user_group_roles_projection_pkey
        PRIMARY KEY (group_id, role_id);

    -- =========================================================
    -- user_roles_projection
    -- =========================================================
    DROP INDEX IF EXISTS public.user_roles_scope_lookup;
    DROP INDEX IF EXISTS public.user_roles_scoped_unique;
    DROP INDEX IF EXISTS public.user_roles_unscoped_unique;

    ALTER TABLE public.user_roles_projection
        DROP CONSTRAINT IF EXISTS user_roles_scope_pair_or_neither,
        DROP CONSTRAINT IF EXISTS user_roles_scope_kind_valid;

    DELETE FROM public.user_roles_projection a
    USING public.user_roles_projection b
    WHERE  a.user_id = b.user_id
      AND  a.role_id = b.role_id
      AND  a.ctid    > b.ctid;

    ALTER TABLE public.user_roles_projection
        DROP COLUMN IF EXISTS scope_kind,
        DROP COLUMN IF EXISTS scope_id;

    ALTER TABLE public.user_roles_projection
        ADD CONSTRAINT user_roles_projection_pkey
        PRIMARY KEY (user_id, role_id);
END $$;
-- +goose StatementEnd

-- ============================================================ [009_role_permission_split_7] DOWN
-- +goose StatementBegin
DO $$
BEGIN
    -- Collapse the static/dynamic split back to the legacy single
    -- key. Three cases per role:
    --   1. Holds both Static AND Dynamic — replace Static with the
    --      legacy key, drop the Dynamic key.
    --   2. Holds only Static — replace Static with the legacy key.
    --   3. Holds only Dynamic — replace Dynamic with the legacy key
    --      (do NOT drop it; otherwise the role loses ALL create
    --      capability, which is information loss).
    --
    -- Flagged in #333 review: the prior "unconditionally remove
    -- Dynamic" shape silently stripped roles whose only create
    -- capability was the dynamic variant.

    UPDATE roles_projection
       SET permissions =
           CASE
               WHEN 'CreateStaticDeviceGroup' = ANY(permissions) AND 'CreateDynamicDeviceGroup' = ANY(permissions) THEN
                   array_remove(
                       array_replace(permissions, 'CreateStaticDeviceGroup', 'CreateDeviceGroup'),
                       'CreateDynamicDeviceGroup'
                   )
               WHEN 'CreateStaticDeviceGroup' = ANY(permissions) THEN
                   array_replace(permissions, 'CreateStaticDeviceGroup', 'CreateDeviceGroup')
               WHEN 'CreateDynamicDeviceGroup' = ANY(permissions) THEN
                   array_replace(permissions, 'CreateDynamicDeviceGroup', 'CreateDeviceGroup')
               ELSE permissions
           END
     WHERE 'CreateStaticDeviceGroup' = ANY(permissions)
        OR 'CreateDynamicDeviceGroup' = ANY(permissions);

    UPDATE roles_projection
       SET permissions =
           CASE
               WHEN 'CreateStaticUserGroup' = ANY(permissions) AND 'CreateDynamicUserGroup' = ANY(permissions) THEN
                   array_remove(
                       array_replace(permissions, 'CreateStaticUserGroup', 'CreateUserGroup'),
                       'CreateDynamicUserGroup'
                   )
               WHEN 'CreateStaticUserGroup' = ANY(permissions) THEN
                   array_replace(permissions, 'CreateStaticUserGroup', 'CreateUserGroup')
               WHEN 'CreateDynamicUserGroup' = ANY(permissions) THEN
                   array_replace(permissions, 'CreateDynamicUserGroup', 'CreateUserGroup')
               ELSE permissions
           END
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
