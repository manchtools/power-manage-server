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
    email TEXT NOT NULL,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0,
    session_version INTEGER NOT NULL DEFAULT 0,
    has_password BOOLEAN NOT NULL DEFAULT TRUE,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    display_name TEXT NOT NULL DEFAULT '',
    given_name TEXT NOT NULL DEFAULT '',
    family_name TEXT NOT NULL DEFAULT '',
    preferred_username TEXT NOT NULL DEFAULT '',
    picture TEXT NOT NULL DEFAULT '',
    locale TEXT NOT NULL DEFAULT '',
    linux_username TEXT NOT NULL DEFAULT '',
    linux_uid INTEGER NOT NULL DEFAULT 0,
    ssh_public_keys JSONB NOT NULL DEFAULT '[]',
    ssh_access_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ssh_allow_pubkey BOOLEAN NOT NULL DEFAULT TRUE,
    ssh_allow_password BOOLEAN NOT NULL DEFAULT FALSE,
    system_user_action_id TEXT NOT NULL DEFAULT '',
    system_ssh_action_id TEXT NOT NULL DEFAULT '',
    user_provisioning_enabled BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE UNIQUE INDEX idx_users_email_active ON users_projection(email) WHERE is_deleted = FALSE;

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
    sync_interval_minutes INTEGER NOT NULL DEFAULT 0,
    compliance_status INTEGER NOT NULL DEFAULT 0,
    compliance_checked_at TIMESTAMPTZ,
    compliance_total INTEGER NOT NULL DEFAULT 0,
    compliance_passing INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_devices_labels ON devices_projection USING GIN (labels);

CREATE TABLE actions_projection (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
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
    desired_state INTEGER NOT NULL DEFAULT 0,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ
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
    changed BOOLEAN NOT NULL DEFAULT TRUE,
    compliant BOOLEAN NOT NULL DEFAULT FALSE,
    detection_output JSONB
);

CREATE INDEX idx_executions_device ON executions_projection (device_id);
CREATE INDEX idx_executions_status ON executions_projection (status);
CREATE INDEX idx_executions_device_status ON executions_projection (device_id, status);

CREATE TABLE action_sets_projection (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    member_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ
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
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    member_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ
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
    name TEXT NOT NULL,
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

-- ============================================================================
-- LPS PASSWORDS PROJECTION (from 002)
-- ============================================================================

CREATE TABLE lps_passwords_projection (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    rotated_at TIMESTAMPTZ NOT NULL,
    rotation_reason TEXT NOT NULL DEFAULT 'scheduled',
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_lps_passwords_device ON lps_passwords_projection(device_id, is_current);
CREATE INDEX idx_lps_passwords_action_device ON lps_passwords_projection(action_id, device_id);
CREATE INDEX idx_lps_passwords_username ON lps_passwords_projection(device_id, action_id, username, is_current);

-- ============================================================================
-- LUKS KEYS PROJECTION (from 004, with revocation columns from 005)
-- ============================================================================

CREATE TABLE luks_keys_projection (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    device_path TEXT NOT NULL,
    passphrase TEXT NOT NULL,
    rotated_at TIMESTAMPTZ NOT NULL,
    rotation_reason TEXT NOT NULL DEFAULT 'scheduled',
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revocation_status TEXT,
    revocation_error TEXT,
    revocation_at TIMESTAMPTZ
);

CREATE INDEX idx_luks_keys_device ON luks_keys_projection(device_id, is_current);
CREATE INDEX idx_luks_keys_action_device ON luks_keys_projection(action_id, device_id);
CREATE INDEX idx_luks_keys_current ON luks_keys_projection(device_id, action_id, device_path, is_current);

-- ============================================================================
-- LUKS TOKENS (from 004)
-- ============================================================================

CREATE TABLE luks_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    min_length INTEGER NOT NULL DEFAULT 16,
    complexity INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_luks_tokens_token ON luks_tokens(token) WHERE NOT used;

-- ============================================================================
-- DEVICE INVENTORY (from 006)
-- ============================================================================

CREATE TABLE device_inventory (
    device_id TEXT NOT NULL,
    table_name TEXT NOT NULL,
    rows JSONB NOT NULL DEFAULT '[]',
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (device_id, table_name)
);

CREATE INDEX idx_device_inventory_device ON device_inventory(device_id);

-- ============================================================================
-- OSQUERY ON-DEMAND RESULTS
-- ============================================================================

CREATE TABLE osquery_results (
    query_id     TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL,
    table_name   TEXT NOT NULL,
    completed    BOOLEAN NOT NULL DEFAULT FALSE,
    success      BOOLEAN NOT NULL DEFAULT FALSE,
    error        TEXT NOT NULL DEFAULT '',
    rows         JSONB NOT NULL DEFAULT '[]'::JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_osquery_results_device ON osquery_results(device_id);

-- ============================================================================
-- RBAC TABLES (from 007)
-- ============================================================================

CREATE TABLE roles_projection (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT[] NOT NULL DEFAULT '{}',
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE user_roles_projection (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_user_id ON user_roles_projection(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles_projection(role_id);

-- ============================================================================
-- TOTP PROJECTION (from 009)
-- ============================================================================

CREATE TABLE totp_projection (
    user_id TEXT PRIMARY KEY REFERENCES users_projection(id),
    secret_encrypted TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    backup_codes_hash TEXT[] NOT NULL DEFAULT '{}',
    backup_codes_used BOOLEAN[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    projection_version BIGINT NOT NULL DEFAULT 0
);

-- ============================================================================
-- USER GROUPS (from 010, with dynamic columns from 015)
-- ============================================================================

CREATE TABLE user_groups_projection (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    member_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0,
    is_dynamic BOOLEAN NOT NULL DEFAULT FALSE,
    dynamic_query TEXT
);

CREATE UNIQUE INDEX idx_user_groups_name ON user_groups_projection(name) WHERE is_deleted = FALSE;

CREATE TABLE user_group_members_projection (
    group_id TEXT NOT NULL REFERENCES user_groups_projection(id),
    user_id TEXT NOT NULL REFERENCES users_projection(id),
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_user_group_members_user ON user_group_members_projection(user_id);

CREATE TABLE user_group_roles_projection (
    group_id TEXT NOT NULL REFERENCES user_groups_projection(id),
    role_id TEXT NOT NULL REFERENCES roles_projection(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, role_id)
);

CREATE INDEX idx_user_group_roles_role ON user_group_roles_projection(role_id);

-- ============================================================================
-- DYNAMIC USER GROUP EVALUATION QUEUE (from 015)
-- ============================================================================

CREATE TABLE dynamic_user_group_evaluation_queue (
    group_id TEXT PRIMARY KEY REFERENCES user_groups_projection(id),
    queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT
);

-- ============================================================================
-- IDENTITY PROVIDERS (from 011, with SCIM columns from 012)
-- ============================================================================

CREATE TABLE identity_providers_projection (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    provider_type TEXT NOT NULL DEFAULT 'oidc',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    client_id TEXT NOT NULL,
    client_secret_encrypted TEXT NOT NULL DEFAULT '',
    issuer_url TEXT NOT NULL,
    authorization_url TEXT NOT NULL DEFAULT '',
    token_url TEXT NOT NULL DEFAULT '',
    userinfo_url TEXT NOT NULL DEFAULT '',
    scopes TEXT[] NOT NULL DEFAULT '{}',
    auto_create_users BOOLEAN NOT NULL DEFAULT FALSE,
    auto_link_by_email BOOLEAN NOT NULL DEFAULT FALSE,
    default_role_id TEXT NOT NULL DEFAULT '',
    attribute_mapping JSONB NOT NULL DEFAULT '{}',
    disable_password_for_linked BOOLEAN NOT NULL DEFAULT FALSE,
    group_claim TEXT NOT NULL DEFAULT '',
    group_mapping JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0,
    scim_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    scim_token_hash TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX idx_identity_providers_slug ON identity_providers_projection(slug) WHERE is_deleted = FALSE;

-- ============================================================================
-- IDENTITY LINKS (from 011)
-- ============================================================================

CREATE TABLE identity_links_projection (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users_projection(id),
    provider_id TEXT NOT NULL REFERENCES identity_providers_projection(id),
    external_id TEXT NOT NULL,
    external_email TEXT NOT NULL DEFAULT '',
    external_name TEXT NOT NULL DEFAULT '',
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX idx_identity_links_provider_external ON identity_links_projection(provider_id, external_id);
CREATE UNIQUE INDEX idx_identity_links_user_provider ON identity_links_projection(user_id, provider_id);
CREATE INDEX idx_identity_links_user ON identity_links_projection(user_id);

-- ============================================================================
-- AUTH STATES (from 011)
-- ============================================================================

CREATE TABLE auth_states (
    state TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES identity_providers_projection(id),
    nonce TEXT NOT NULL DEFAULT '',
    code_verifier TEXT NOT NULL DEFAULT '',
    redirect_uri TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_auth_states_expires ON auth_states(expires_at);

-- ============================================================================
-- SCIM GROUP MAPPING (from 012)
-- ============================================================================

CREATE TABLE scim_group_mapping_projection (
    id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES identity_providers_projection(id),
    scim_group_id TEXT NOT NULL,
    scim_display_name TEXT NOT NULL DEFAULT '',
    user_group_id TEXT NOT NULL REFERENCES user_groups_projection(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX idx_scim_group_mapping_provider_scim
    ON scim_group_mapping_projection(provider_id, scim_group_id);
CREATE INDEX idx_scim_group_mapping_provider
    ON scim_group_mapping_projection(provider_id);
CREATE INDEX idx_scim_group_mapping_user_group
    ON scim_group_mapping_projection(user_group_id);

-- ============================================================================
-- COMPLIANCE RESULTS (from 017)
-- ============================================================================

CREATE TABLE compliance_results_projection (
    device_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    action_name TEXT NOT NULL DEFAULT '',
    compliant BOOLEAN NOT NULL DEFAULT FALSE,
    detection_output JSONB,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, action_id)
);

CREATE INDEX idx_compliance_device ON compliance_results_projection (device_id);

-- ============================================================================
-- COMPLIANCE POLICIES (from 018)
-- ============================================================================

CREATE TABLE compliance_policies_projection (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    rule_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE compliance_policy_rules_projection (
    policy_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    action_name TEXT NOT NULL DEFAULT '',
    grace_period_hours INTEGER NOT NULL DEFAULT 0,
    added_at TIMESTAMPTZ,
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (policy_id, action_id)
);

CREATE INDEX idx_compliance_policy_rules_action ON compliance_policy_rules_projection (action_id);

CREATE TABLE compliance_policy_evaluation_projection (
    device_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    compliant BOOLEAN NOT NULL DEFAULT FALSE,
    first_failed_at TIMESTAMPTZ,
    status INTEGER NOT NULL DEFAULT 0,
    checked_at TIMESTAMPTZ,
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, policy_id, action_id)
);

CREATE INDEX idx_compliance_eval_device ON compliance_policy_evaluation_projection (device_id);
CREATE INDEX idx_compliance_eval_policy ON compliance_policy_evaluation_projection (policy_id);

-- ============================================================================
-- SERVER SETTINGS (from 020)
-- ============================================================================

CREATE TABLE server_settings_projection (
    id TEXT PRIMARY KEY DEFAULT 'global',
    user_provisioning_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ssh_access_for_all BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    projection_version BIGINT NOT NULL DEFAULT 0
);

INSERT INTO server_settings_projection (id) VALUES ('global');

-- ============================================================================
-- DEVICE ASSIGNED USERS/GROUPS (from 026)
-- ============================================================================

CREATE TABLE device_assigned_users_projection (
    device_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, user_id)
);

CREATE INDEX idx_device_assigned_users_user ON device_assigned_users_projection(user_id);

CREATE TABLE device_assigned_groups_projection (
    device_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, group_id)
);

CREATE INDEX idx_device_assigned_groups_group ON device_assigned_groups_projection(group_id);

-- ============================================================================
-- LOG QUERY RESULTS (from 029)
-- ============================================================================

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

-- ============================================================================
-- SEQUENCES
-- ============================================================================

CREATE SEQUENCE linux_uid_seq START WITH 10000;

-- +goose Down
-- Full teardown is handled by Part 5's down migration.
-- This stub exists for goose compatibility.
