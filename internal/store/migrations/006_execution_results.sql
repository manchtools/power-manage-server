-- +goose Up

-- Execution identity is the authored occurrence within one durable delivery.
-- This intentionally refuses to preserve pre-delivery execution rows: the
-- project is pre-alpha and agents are reinstalled instead of migrated through
-- a second result model.
TRUNCATE TABLE executions CASCADE;

ALTER TABLE executions
    ADD COLUMN delivery_id text NOT NULL
        REFERENCES deliveries(delivery_id) ON DELETE CASCADE,
    ADD CONSTRAINT executions_delivery_occurrence_unique UNIQUE (delivery_id, id),
    ADD CONSTRAINT executions_status_valid CHECK (status = ANY (ARRAY[
        'scheduled'::text,
        'pending'::text,
        'running'::text,
        'success'::text,
        'failed'::text,
        'skipped'::text,
        'timeout'::text,
        'cancelled'::text,
        'not_applicable'::text,
        'indeterminate'::text
    ]));

CREATE INDEX idx_executions_delivery ON executions(delivery_id);

CREATE TABLE execution_output_chunks (
    execution_id text NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    stream       text NOT NULL CHECK (stream IN ('stdout', 'stderr')),
    sequence     bigint NOT NULL CHECK (sequence >= 0),
    data         bytea NOT NULL CHECK (octet_length(data) <= 65536),
    received_at  timestamp with time zone NOT NULL,
    PRIMARY KEY (execution_id, stream, sequence)
);

-- +goose Down

DROP TABLE execution_output_chunks;
DROP INDEX idx_executions_delivery;
ALTER TABLE executions
    DROP CONSTRAINT executions_status_valid,
    DROP CONSTRAINT executions_delivery_occurrence_unique,
    DROP COLUMN delivery_id;
