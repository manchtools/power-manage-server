-- +goose Up
CREATE TABLE log_query_results (
    query_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    error TEXT NOT NULL DEFAULT '',
    logs TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_log_query_results_device ON log_query_results(device_id);
CREATE INDEX idx_log_query_results_completed ON log_query_results(completed, created_at);

-- +goose Down
DROP TABLE IF EXISTS log_query_results;
