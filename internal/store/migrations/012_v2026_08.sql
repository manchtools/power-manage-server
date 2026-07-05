-- 2026.08 — spec 19 (audit retention), stage C: a projection must not
-- pin the prunable event log.
--
-- security_alerts_projection.event_id FK-referenced events(id) with no
-- ON DELETE action (NO ACTION / restrict). That made the sanctioned
-- prune path (011) fail with a foreign-key violation the moment it tried
-- to delete a raising event that still had a live alert row — a
-- projection was holding the append-only log hostage against retention.
--
-- event_id is the raising event's ULID kept for audit linking, not an
-- integrity anchor: the alert projection is DERIVED state, reproduced on
-- rebuild from the device stream (or, for pruned history, from the cold
-- snapshot). It must survive its source event aging into the archive.
-- Dropping the FK lets prune delete archived events while the derived
-- alert row remains (with a now-dangling event_id reference, the same
-- contract every other projection has toward the prunable log).

-- +goose Up

ALTER TABLE public.security_alerts_projection
    DROP CONSTRAINT IF EXISTS security_alerts_projection_event_id_fkey;

-- +goose Down

-- Re-adding the FK will fail if any alert row references an event that
-- has already been pruned — expected once retention has run. Restore
-- both events and the projection from a pre-prune backup before a down
-- migration if referential integrity to the live log is required again.
ALTER TABLE public.security_alerts_projection
    ADD CONSTRAINT security_alerts_projection_event_id_fkey
    FOREIGN KEY (event_id) REFERENCES public.events(id);
