-- +goose Up

-- Master projector: routes events to stream-specific projectors.
CREATE TRIGGER event_projector
    AFTER INSERT ON events
    FOR EACH ROW
    EXECUTE FUNCTION project_event();

-- Notification: sends pg_notify for real-time updates.
CREATE TRIGGER event_notifier
    AFTER INSERT ON events
    FOR EACH ROW
    EXECUTE FUNCTION notify_event();

-- Dynamic group re-evaluation when device labels change.
CREATE TRIGGER device_label_change_trigger
    AFTER INSERT OR UPDATE OF labels ON devices_projection
    FOR EACH ROW
    EXECUTE FUNCTION trigger_device_label_change();

-- Remove devices from groups when soft-deleted.
CREATE TRIGGER device_deleted_trigger
    AFTER UPDATE OF is_deleted ON devices_projection
    FOR EACH ROW
    EXECUTE FUNCTION trigger_device_deleted();

-- +goose Down

DROP TRIGGER IF EXISTS device_deleted_trigger ON devices_projection;
DROP TRIGGER IF EXISTS device_label_change_trigger ON devices_projection;
DROP TRIGGER IF EXISTS event_notifier ON events;
DROP TRIGGER IF EXISTS event_projector ON events;
