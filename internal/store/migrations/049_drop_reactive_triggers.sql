-- Wave F (tracker manchtools/power-manage-server#242): drop the
-- reactive triggers that fired dynamic-group re-evaluation on side-
-- table changes. Wave F moves the enqueueing into the Go projector
-- listeners that already process the underlying events, so the PG
-- triggers come out entirely.
--
-- Triggers dropped:
-- 1. device_labels_change_trigger (on device_labels) — was added in
--    047 to replace the JSONB-column trigger; both queueing flows
--    now happen in the Go device-label listener (label set/removed/
--    updated/registered).
-- 2. device_deleted_trigger (on devices_projection) — cascade-delete
--    of device_group_members + recount moved into the device-deleted
--    listener.
-- 3. device_inventory_changed (on device_inventory) — queueing moved
--    into the inbox-worker's inventory-update flow.
-- 4. user_attribute_change_trigger (on users_projection) — queueing
--    moved into every user-event listener whose payload mutates one
--    of the columns the user-group query language reads.
--
-- Plus the supporting PL/pgSQL functions: trigger_device_labels_child_change,
-- trigger_device_label_change (legacy), trigger_device_deleted,
-- trigger_inventory_change, queue_dynamic_groups_for_device,
-- queue_dynamic_user_groups_on_user_change, queue_all_dynamic_groups.
--
-- Down: not reversible. Same pattern as the Wave C.5 + D drops. The
-- bodies live in migration 004 / 047 history if needed for forensic
-- reference.

-- +goose Up

DROP TRIGGER IF EXISTS device_labels_change_trigger ON device_labels;
DROP TRIGGER IF EXISTS device_deleted_trigger ON devices_projection;
DROP TRIGGER IF EXISTS device_inventory_changed ON device_inventory;
DROP TRIGGER IF EXISTS user_attribute_change_trigger ON users_projection;

DROP FUNCTION IF EXISTS trigger_device_labels_child_change();
DROP FUNCTION IF EXISTS trigger_device_label_change();
DROP FUNCTION IF EXISTS trigger_device_deleted();
DROP FUNCTION IF EXISTS trigger_inventory_change();
DROP FUNCTION IF EXISTS queue_dynamic_groups_for_device(TEXT);
DROP FUNCTION IF EXISTS queue_dynamic_user_groups_on_user_change();
DROP FUNCTION IF EXISTS queue_all_dynamic_groups();

-- +goose Down

-- Intentionally not reversible.
SELECT 1;
