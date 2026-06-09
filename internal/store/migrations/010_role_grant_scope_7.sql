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
-- +goose Up
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

-- +goose Down
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
