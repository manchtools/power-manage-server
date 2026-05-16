-- Wave C.5 (tracker manchtools/power-manage-server#242): drop every
-- PL/pgSQL function that implemented the dynamic-query interpreter.
-- C.1 - C.4 ported every caller to Go (internal/dynamicquery +
-- internal/dyngroupeval), so these are unreachable from production code
-- as of this migration.
--
-- DROP ordering matches caller-first: the queue drains call the
-- per-group evaluators which call the per-atom evaluators which call
-- the helpers. PostgreSQL would happily resolve the dependency graph
-- itself with CASCADE, but spelling the order out makes the intent
-- explicit and surfaces accidental missed callers as a clearer error.
--
-- Down: not reversible. The Up of this migration is the codified
-- replacement; rolling forward through a fresh DB skips Up→Down→Up
-- cycles anyway. If a regression requires the old PL/pgSQL path,
-- restore from the migration 004 / 006 / 016 / 044 originals — that's
-- a code revert decision, not a goose down.

-- +goose Up

-- Queue drains (top-level callers from Go's old sqlc path).
DROP FUNCTION IF EXISTS evaluate_queued_dynamic_groups();
DROP FUNCTION IF EXISTS evaluate_queued_dynamic_user_groups();

-- Per-group evaluators (callers of the per-atom evaluators).
DROP FUNCTION IF EXISTS evaluate_dynamic_group(TEXT);
DROP FUNCTION IF EXISTS evaluate_dynamic_user_group(TEXT);

-- Per-query evaluators (callers of the per-atom evaluators).
DROP FUNCTION IF EXISTS evaluate_dynamic_query(JSONB, TEXT, INTEGER);
DROP FUNCTION IF EXISTS evaluate_dynamic_query_v2(TEXT, JSONB, TEXT, INTEGER);
DROP FUNCTION IF EXISTS evaluate_dynamic_user_query(TEXT, BOOLEAN, BOOLEAN, BOOLEAN, TEXT, TEXT, TEXT, TEXT);

-- Validators (also depended on the per-query evaluators).
DROP FUNCTION IF EXISTS validate_dynamic_query(TEXT);
DROP FUNCTION IF EXISTS validate_user_group_query(TEXT);

-- Per-atom evaluators.
DROP FUNCTION IF EXISTS evaluate_condition(JSONB, TEXT);
DROP FUNCTION IF EXISTS evaluate_condition_v2(TEXT, JSONB, TEXT);
DROP FUNCTION IF EXISTS evaluate_user_condition(TEXT, BOOLEAN, BOOLEAN, BOOLEAN, TEXT, TEXT, TEXT, TEXT);

-- Helpers (no more callers).
DROP FUNCTION IF EXISTS extract_label_key(TEXT);
DROP FUNCTION IF EXISTS resolve_inventory_field(TEXT, TEXT);

-- +goose Down

-- Intentionally not reversible — see migration header. The PL/pgSQL
-- function bodies live in migration 004 / 006 / 016 / 044 history if
-- needed for forensic reference. A real rollback is a code revert,
-- not a goose down.
SELECT 1;
