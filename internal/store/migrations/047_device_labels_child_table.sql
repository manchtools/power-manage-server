-- Wave E.4 (tracker manchtools/power-manage-server#242): normalize the
-- devices_projection.labels JSONB column into a relational child table
-- device_labels. The Go evaluator already consumes labels through a
-- map; this migration is the last step of the JSONB cleanup, closing
-- the Wave E DoD ("no JSONB operator in any sqlc query").
--
-- Idempotency for projector replay: the device-projector listener writes
-- this child table under the parent projection_version guard (replacing
-- the per-row JSONB-merge guard the PL/pgSQL projector did). Replay-safe
-- because an out-of-order event hits the version check before any child
-- write happens.
--
-- The dynamic-group queue trigger that previously fired on labels-JSONB
-- updates is re-pointed at device_labels (INSERT/UPDATE/DELETE) so
-- dynamic-group re-evaluation still queues on every label change.

-- +goose Up

CREATE TABLE device_labels (
    device_id TEXT NOT NULL REFERENCES devices_projection(id) ON DELETE CASCADE,
    key       TEXT NOT NULL,
    value     TEXT NOT NULL,
    PRIMARY KEY (device_id, key)
);

CREATE INDEX idx_device_labels_key_value ON device_labels(key, value);

INSERT INTO device_labels (device_id, key, value)
SELECT d.id, kv.key, kv.value
FROM devices_projection d,
     jsonb_each_text(d.labels) AS kv
WHERE d.labels IS NOT NULL
  AND jsonb_typeof(d.labels) = 'object';

-- Drop the JSONB-column-driven trigger before re-creating it against
-- the child table.
DROP TRIGGER IF EXISTS device_label_change_trigger ON devices_projection;

-- New trigger function pulls the device id from NEW or OLD so it
-- handles INSERT/UPDATE/DELETE uniformly. Behaviour is identical: enqueue
-- the device for dynamic-group re-evaluation.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION trigger_device_labels_child_change() RETURNS trigger AS $$
DECLARE
    target_id TEXT;
BEGIN
    target_id := COALESCE(NEW.device_id, OLD.device_id);
    PERFORM queue_dynamic_groups_for_device(target_id);
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER device_labels_change_trigger
    AFTER INSERT OR UPDATE OR DELETE ON device_labels
    FOR EACH ROW
    EXECUTE FUNCTION trigger_device_labels_child_change();

DROP INDEX IF EXISTS idx_devices_labels;
ALTER TABLE devices_projection DROP COLUMN labels;

-- +goose Down

-- Re-create the JSONB column and backfill from the child table so a
-- downgrade still has the projection state. The dynamic-group trigger
-- re-pointing is reversed (drop child-table trigger, re-create the
-- JSONB-column one).
ALTER TABLE devices_projection
    ADD COLUMN labels JSONB NOT NULL DEFAULT '{}';

UPDATE devices_projection d
SET labels = COALESCE((
        SELECT jsonb_object_agg(l.key, l.value)
        FROM device_labels l
        WHERE l.device_id = d.id
    ), '{}'::JSONB);

CREATE INDEX idx_devices_labels ON devices_projection USING GIN (labels);

DROP TRIGGER IF EXISTS device_labels_change_trigger ON device_labels;
DROP FUNCTION IF EXISTS trigger_device_labels_child_change();

CREATE TRIGGER device_label_change_trigger
    AFTER INSERT OR UPDATE OF labels ON devices_projection
    FOR EACH ROW
    EXECUTE FUNCTION trigger_device_label_change();

DROP INDEX IF EXISTS idx_device_labels_key_value;
DROP TABLE device_labels;
