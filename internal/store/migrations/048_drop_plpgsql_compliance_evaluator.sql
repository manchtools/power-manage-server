-- Wave D (tracker manchtools/power-manage-server#242): drop the PL/pgSQL
-- compliance evaluator functions. Wave D ported every Go caller off
-- these shims (internal/compliance), so they are unreachable from
-- production code as of this migration.
--
-- DROP ordering matches caller-first: reevaluate_compliance_policy_devices
-- calls evaluate_device_compliance_policies which calls
-- recalculate_device_compliance.
--
-- Down: not reversible. Per the same convention as migration 046
-- (Wave C.5), the bodies live in migration 003 history if needed for
-- forensic reference. A real rollback is a code revert, not a goose
-- down.

-- +goose Up

DROP FUNCTION IF EXISTS reevaluate_compliance_policy_devices(TEXT);
DROP FUNCTION IF EXISTS evaluate_device_compliance_policies(TEXT);
DROP FUNCTION IF EXISTS recalculate_device_compliance(TEXT);

-- +goose Down

-- Intentionally not reversible — see migration header. A regression
-- requires restoring from migration 003's bodies as a code revert.
SELECT 1;
