-- Group-scoped variables (manchtools/power-manage-server#195, design #59).
--
-- Adds a `variables` JSONB column to device_groups_projection and
-- user_groups_projection. The column holds an array of pm.v1.Variable-
-- shaped objects. Per-type validation runs at the API boundary
-- (group_variables_validator.go); the column is intentionally schema-
-- light so the JSONB stays flexible as future VariableType values land.
--
-- Default '[]'::jsonb means existing groups behave exactly as today —
-- no variables defined, no rendering side effect. No backfill needed.
--
-- Step 1 of #195 (foundation). Step 2 wires the real handler logic +
-- GroupVariableSet/Updated/Deleted events + the matching projector
-- writes; until then the API surface returns Unimplemented.

-- +goose Up

ALTER TABLE device_groups_projection
    ADD COLUMN variables JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE user_groups_projection
    ADD COLUMN variables JSONB NOT NULL DEFAULT '[]'::jsonb;

-- +goose Down

ALTER TABLE user_groups_projection DROP COLUMN variables;

ALTER TABLE device_groups_projection DROP COLUMN variables;
