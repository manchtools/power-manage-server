-- +goose Up

-- The notify_event trigger fires pg_notify on every event INSERT but nothing
-- listens to these channels anymore. Agent communication and UI updates are
-- handled via Asynq (Valkey) task queues. Remove the trigger and function to
-- eliminate wasted work on every event append.

DROP TRIGGER IF EXISTS event_notifier ON events;
DROP FUNCTION IF EXISTS notify_event;

-- +goose Down

-- Restoring the full notify_event function is not practical here because it
-- was overwritten by migration 007_rbac.sql. A rollback of this migration is
-- a no-op — the trigger is not needed for correct operation.
