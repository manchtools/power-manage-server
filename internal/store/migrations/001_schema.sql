-- +goose Up

-- ============================================================================
-- EXTENSIONS
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- EVENT STORE
-- ============================================================================

CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sequence_num BIGSERIAL UNIQUE,
    stream_type TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    stream_version INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    actor_type TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (stream_type, stream_id, stream_version)
);

CREATE INDEX idx_events_stream ON events (stream_type, stream_id);
CREATE INDEX idx_events_type ON events (event_type);
CREATE INDEX idx_events_stream_type ON events (stream_type);
CREATE INDEX idx_events_occurred_at ON events (occurred_at);

-- ============================================================================
-- PROJECTION TABLES
-- ============================================================================

CREATE TABLE users_projection (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0,
    session_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE tokens_projection (
    id TEXT PRIMARY KEY,
    value_hash TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    one_time BOOLEAN NOT NULL DEFAULT FALSE,
    max_uses INTEGER NOT NULL DEFAULT 0,
    current_uses INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0,
    owner_id TEXT
);

CREATE INDEX idx_tokens_owner ON tokens_projection (owner_id);

CREATE TABLE devices_projection (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    cert_fingerprint TEXT UNIQUE,
    cert_not_after TIMESTAMPTZ,
    registered_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    registration_token_id TEXT,
    labels JSONB NOT NULL DEFAULT '{}',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0,
    assigned_user_id TEXT,
    sync_interval_minutes INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_devices_assigned_user ON devices_projection (assigned_user_id);
CREATE INDEX idx_devices_labels ON devices_projection USING GIN (labels);

CREATE TABLE actions_projection (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    action_type INTEGER NOT NULL DEFAULT 0,
    params JSONB NOT NULL DEFAULT '{}',
    timeout_seconds INTEGER NOT NULL DEFAULT 300,
    created_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0,
    signature BYTEA,
    params_canonical BYTEA,
    desired_state INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE executions_projection (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    action_id TEXT,
    action_type INTEGER NOT NULL DEFAULT 0,
    desired_state INTEGER NOT NULL DEFAULT 0,
    params JSONB NOT NULL DEFAULT '{}',
    timeout_seconds INTEGER NOT NULL DEFAULT 300,
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    output JSONB,
    created_at TIMESTAMPTZ,
    dispatched_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms BIGINT,
    created_by_type TEXT NOT NULL DEFAULT '',
    created_by_id TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    changed BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_executions_device ON executions_projection (device_id);
CREATE INDEX idx_executions_status ON executions_projection (status);
CREATE INDEX idx_executions_device_status ON executions_projection (device_id, status);

CREATE TABLE action_sets_projection (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    member_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE action_set_members_projection (
    set_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    added_at TIMESTAMPTZ,
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (set_id, action_id)
);

CREATE TABLE definitions_projection (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    member_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE definition_members_projection (
    definition_id TEXT NOT NULL,
    action_set_id TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    added_at TIMESTAMPTZ,
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (definition_id, action_set_id)
);

CREATE TABLE device_groups_projection (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    member_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0,
    is_dynamic BOOLEAN NOT NULL DEFAULT FALSE,
    dynamic_query TEXT,
    sync_interval_minutes INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE device_group_members_projection (
    group_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    added_at TIMESTAMPTZ,
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, device_id)
);

CREATE TABLE assignments_projection (
    id TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    mode INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0,
    UNIQUE (source_type, source_id, target_type, target_id)
);

CREATE TABLE user_selections_projection (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    selected BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    UNIQUE (device_id, source_type, source_id)
);

CREATE INDEX idx_user_selections_device ON user_selections_projection (device_id);

CREATE TABLE revoked_tokens (
    jti TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_revoked_tokens_expires ON revoked_tokens (expires_at);

CREATE TABLE dynamic_group_evaluation_queue (
    group_id TEXT PRIMARY KEY,
    queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT
);

CREATE TABLE projection_errors (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID,
    event_type TEXT,
    stream_type TEXT,
    error_message TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose Down

DROP TABLE IF EXISTS projection_errors;
DROP TABLE IF EXISTS dynamic_group_evaluation_queue;
DROP TABLE IF EXISTS revoked_tokens;
DROP TABLE IF EXISTS user_selections_projection;
DROP TABLE IF EXISTS assignments_projection;
DROP TABLE IF EXISTS device_group_members_projection;
DROP TABLE IF EXISTS device_groups_projection;
DROP TABLE IF EXISTS definition_members_projection;
DROP TABLE IF EXISTS definitions_projection;
DROP TABLE IF EXISTS action_set_members_projection;
DROP TABLE IF EXISTS action_sets_projection;
DROP TABLE IF EXISTS executions_projection;
DROP TABLE IF EXISTS actions_projection;
DROP TABLE IF EXISTS devices_projection;
DROP TABLE IF EXISTS tokens_projection;
DROP TABLE IF EXISTS users_projection;
DROP TABLE IF EXISTS events;
DROP EXTENSION IF EXISTS pgcrypto;
