-- SecurityAlert projection — enables the UI to list security alerts
-- without scanning the raw events table.
--
-- Rationale: agents emit SecurityAlert events via the inbox worker
-- (internal/control/inbox_worker.go handleSecurityAlert). They are
-- persisted on the device stream, but nothing projected them into a
-- queryable table, so compliance / dashboard consumers had to either
-- scan the append-only events log or ignore alerts entirely. The
-- rc10 audit flagged this as silent data loss for the SIEM path.
--
-- Shape follows the LpsPasswordRotated / LuksKey rotation pattern:
-- a derived projection keyed by a new UUID with an acknowledged
-- flag so "unacknowledged alerts" is a cheap query. alert_type is
-- the free-form tag from the payload (e.g. "file_integrity_violation",
-- "auditd_rule_trip"); details is a small key/value blob from the
-- agent's evidence bundle.
--
-- Wiring: rather than rewriting project_event() (the central
-- dispatcher in migration 004 uses BEGIN/EXCEPTION isolation per
-- case arm), we install a second AFTER INSERT trigger on events
-- that ONLY fires for SecurityAlert-shaped rows. This keeps the
-- change additive and prevents an accidental dropped case arm from
-- breaking an unrelated projection.

-- +goose Up

-- The primary key is the originating event_id rather than a fresh
-- UUID. This is the event-sourcing idempotency pattern: if the
-- projection is ever replayed (backfill, rebuild, trigger re-fire),
-- the same SecurityAlert event produces the same row, so ON CONFLICT
-- DO NOTHING prevents duplicates without needing deduplication
-- logic in the acknowledge path. SecurityAlertAcknowledged carries
-- the alert_id explicitly in its payload and UPDATEs by that key.
CREATE TABLE security_alerts_projection (
    event_id UUID PRIMARY KEY REFERENCES events(id),
    device_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    message TEXT NOT NULL,
    details JSONB,
    raised_at TIMESTAMPTZ NOT NULL,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_alerts_device ON security_alerts_projection(device_id, acknowledged, raised_at DESC);
CREATE INDEX idx_security_alerts_type ON security_alerts_projection(alert_type, raised_at DESC);
CREATE INDEX idx_security_alerts_unack ON security_alerts_projection(acknowledged, raised_at DESC) WHERE acknowledged = FALSE;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_security_alert_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'SecurityAlert' THEN
            INSERT INTO security_alerts_projection (
                event_id, device_id, alert_type, message, details, raised_at
            ) VALUES (
                event.id,
                event.stream_id,
                event.data->>'alert_type',
                event.data->>'message',
                event.data->'details',
                event.occurred_at
            )
            ON CONFLICT (event_id) DO NOTHING;
        WHEN 'SecurityAlertAcknowledged' THEN
            UPDATE security_alerts_projection
            SET acknowledged = TRUE,
                acknowledged_at = event.occurred_at,
                acknowledged_by = event.data->>'acknowledged_by'
            WHERE event_id::TEXT = event.data->>'alert_id';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Sidecar trigger: fires AFTER INSERT alongside the existing
-- event_projector trigger, but only for the SecurityAlert event
-- types so unrelated streams are unaffected. Error isolation
-- follows the same pattern as the central dispatcher: failures
-- route to projection_errors instead of aborting the event append.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_security_alert_trigger() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.stream_type = 'device'
       AND NEW.event_type IN ('SecurityAlert', 'SecurityAlertAcknowledged') THEN
        BEGIN
            PERFORM project_security_alert_event(NEW);
        EXCEPTION WHEN OTHERS THEN
            INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
            VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
        END;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER security_alert_projector
    AFTER INSERT ON events
    FOR EACH ROW
    EXECUTE FUNCTION project_security_alert_trigger();

-- +goose Down

DROP TRIGGER IF EXISTS security_alert_projector ON events;
DROP FUNCTION IF EXISTS project_security_alert_trigger;
DROP FUNCTION IF EXISTS project_security_alert_event;
DROP TABLE IF EXISTS security_alerts_projection;
