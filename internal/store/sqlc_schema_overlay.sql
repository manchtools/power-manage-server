-- sqlc PARSE-ONLY schema overlay (#336). NOT a goose migration; never
-- applied to a database.
--
-- migration 010_role_grant_scope_7.sql adds scope_kind / scope_id to
-- user_roles_projection and user_group_roles_projection INSIDE a
-- `DO $$ … END $$;` PL/pgSQL block (for atomic multi-statement
-- application). sqlc's schema parser does not read DO-blocks, so it never
-- learns those columns exist and any SELECT that *outputs* them fails
-- `sqlc generate` with "column scope_kind does not exist".
--
-- This file re-declares exactly those columns as plain DDL so sqlc can
-- resolve them as query outputs. It is listed AFTER migrations/ in
-- sqlc.yaml's `schema:`, so the tables already exist when these run.
--
-- KEEP IN SYNC with migration 010: same tables, columns, and TEXT type.
ALTER TABLE user_roles_projection       ADD COLUMN scope_kind TEXT, ADD COLUMN scope_id TEXT;
ALTER TABLE user_group_roles_projection ADD COLUMN scope_kind TEXT, ADD COLUMN scope_id TEXT;
