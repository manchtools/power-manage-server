-- Drop the PL/pgSQL security_alert projector + its sidecar trigger.
-- Replaced by a Go event listener (projectors.SecurityAlertListener)
-- registered against the post-commit RegisterEventListener pipeline
-- in cmd/control/main.go.
--
-- Behavioural delta:
--   - Before: PL/pgSQL trigger fired inside the AppendEvent
--     transaction. Projection write was atomic with the event
--     commit. Projector errors went into projection_errors via the
--     sidecar trigger's EXCEPTION handler.
--   - After: Go listener fires post-commit. Projection write is
--     async (~ms after the event lands). Errors are logged via
--     slog.Warn ("security_alert projector: ..."). The
--     InsertSecurityAlertProjection sqlc query uses
--     ON CONFLICT (event_id) DO NOTHING so a crash-recovered
--     re-fire is idempotent.
--
-- Why this is safe for security_alert specifically:
--   - The InboxWorker that emits SecurityAlert events is itself an
--     async Asynq task — no synchronous caller waits on the
--     projection write.
--   - No API handler reads back a security_alert immediately after
--     emitting one. The web UI's "ListSecurityAlertsForDevice"
--     query naturally tolerates the small post-commit gap (refresh
--     would catch up).
--
-- See manchtools/power-manage-server#96. First scope ported under
-- the projector-migration pattern; subsequent stream types follow
-- in #97–#106.

-- +goose Up

DROP TRIGGER IF EXISTS security_alert_projector ON events;
DROP FUNCTION IF EXISTS project_security_alert_trigger();
DROP FUNCTION IF EXISTS project_security_alert_event(events);


-- +goose Down

-- Restore both functions verbatim from migration 010 so a
-- Down + Up cycle leaves the database in pre-#96 state.

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
            WHERE event_id = (event.data->>'alert_id')::uuid;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'SecurityAlertAcknowledged references unknown alert_id=%', event.data->>'alert_id';
            END IF;
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

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
