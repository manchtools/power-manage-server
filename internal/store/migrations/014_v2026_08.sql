-- 2026.08 — spec 22 (server-side inventory collection interval).
--
-- Adds the per-device / per-group inventory interval policy columns
-- (0 = inherit: device falls back to the group minimum, then the
-- server default of 1440 minutes). Written by the Go projectors for
-- DeviceInventoryIntervalSet / DeviceGroupInventoryIntervalSet.
-- device_inventory itself is untouched — collected_at already carries
-- the freshness timestamp.

-- +goose Up
ALTER TABLE public.devices_projection
    ADD COLUMN inventory_interval_minutes integer DEFAULT 0 NOT NULL;
ALTER TABLE public.device_groups_projection
    ADD COLUMN inventory_interval_minutes integer DEFAULT 0 NOT NULL;

-- +goose Down
ALTER TABLE public.devices_projection
    DROP COLUMN inventory_interval_minutes;
ALTER TABLE public.device_groups_projection
    DROP COLUMN inventory_interval_minutes;
