-- docref: anchor sqlite-baseline
-- Power Manage SQLite baseline. The project is pre-alpha: PostgreSQL data is
-- not migrated and a SQLite installation always starts from this schema.

PRAGMA user_version = 1;

CREATE TABLE linux_uid_sequence (
    id         integer PRIMARY KEY CHECK (id = 1),
    next_value integer NOT NULL CHECK (next_value >= 10000)
);
INSERT INTO linux_uid_sequence (id, next_value) VALUES (1, 10000);

CREATE TABLE users (
    id                        text PRIMARY KEY,
    email                     text NOT NULL,
    provisioning_source       text NOT NULL DEFAULT 'scim'
                                      CHECK (provisioning_source IN ('scim', 'oidc_jit')),
    created_at                timestamp,
    updated_at                timestamp,
    last_login_at             timestamp,
    disabled                  boolean NOT NULL DEFAULT false,
    is_deleted                boolean NOT NULL DEFAULT false,
    session_version           integer NOT NULL DEFAULT 0,
    display_name              text NOT NULL DEFAULT '',
    given_name                text NOT NULL DEFAULT '',
    family_name               text NOT NULL DEFAULT '',
    preferred_username        text NOT NULL DEFAULT '',
    picture                   text NOT NULL DEFAULT '',
    locale                    text NOT NULL DEFAULT '',
    linux_username            text NOT NULL DEFAULT '',
    linux_uid                 integer NOT NULL DEFAULT 0,
    ssh_access_enabled        boolean NOT NULL DEFAULT false,
    ssh_allow_pubkey          boolean NOT NULL DEFAULT true,
    ssh_allow_password        boolean NOT NULL DEFAULT false,
    system_user_action_id     text NOT NULL DEFAULT '',
    system_ssh_action_id      text NOT NULL DEFAULT '',
    system_tty_action_id      text NOT NULL DEFAULT '',
    user_provisioning_enabled boolean NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX idx_users_email_active
    ON users(email COLLATE NOCASE) WHERE is_deleted = false;

CREATE TABLE user_ssh_keys (
    user_id    text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id     text NOT NULL,
    public_key text,
    comment    text,
    added_at   timestamp NOT NULL,
    PRIMARY KEY (user_id, key_id)
);
CREATE INDEX idx_user_ssh_keys_user ON user_ssh_keys(user_id);

-- Deliberately not foreign-keyed: removing this row crypto-shreds the user's
-- sealed detail even after the user row is erased.
CREATE TABLE user_encryption_keys (
    user_id     text PRIMARY KEY,
    wrapped_dek text NOT NULL,
    created_at  timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- JSON arrays are used for the three list-valued columns. This keeps the
-- schema native to SQLite and lets json_each provide indexed set membership.
CREATE TABLE roles (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    permissions text NOT NULL DEFAULT '[]' CHECK (
                    json_valid(permissions) AND json_type(permissions) = 'array'),
    is_system   boolean NOT NULL DEFAULT false,
    created_at  timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by  text NOT NULL DEFAULT '',
    updated_at  timestamp,
    is_deleted  boolean NOT NULL DEFAULT false
);

CREATE TABLE user_groups (
    id                 text PRIMARY KEY,
    name               text NOT NULL,
    description        text NOT NULL DEFAULT '',
    member_count       integer NOT NULL DEFAULT 0,
    created_at         timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by         text NOT NULL DEFAULT '',
    updated_at         timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_deleted         boolean NOT NULL DEFAULT false,
    is_dynamic         boolean NOT NULL DEFAULT false,
    dynamic_query      text,
    maintenance_window text NOT NULL DEFAULT '{}' CHECK (
                           json_valid(maintenance_window)
                           AND json_type(maintenance_window) = 'object')
);
CREATE UNIQUE INDEX idx_user_groups_name ON user_groups(name) WHERE is_deleted = false;

CREATE TABLE user_group_members (
    group_id text NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    user_id  text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    added_by text NOT NULL DEFAULT '',
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX idx_user_group_members_user ON user_group_members(user_id);

CREATE TABLE user_roles (
    grant_id    text PRIMARY KEY,
    user_id     text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     text NOT NULL REFERENCES roles(id),
    assigned_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by text NOT NULL DEFAULT '',
    scope_kind  text CHECK (scope_kind IS NULL OR scope_kind IN ('device_group', 'user_group')),
    scope_id    text,
    CHECK ((scope_kind IS NULL) = (scope_id IS NULL))
);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX user_roles_scope_lookup ON user_roles(scope_kind, scope_id) WHERE scope_id IS NOT NULL;
CREATE UNIQUE INDEX user_roles_scoped_unique
    ON user_roles(user_id, role_id, scope_kind, scope_id) WHERE scope_id IS NOT NULL;
CREATE UNIQUE INDEX user_roles_unscoped_unique
    ON user_roles(user_id, role_id) WHERE scope_id IS NULL;

CREATE TABLE user_group_roles (
    grant_id    text PRIMARY KEY,
    group_id    text NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    role_id     text NOT NULL REFERENCES roles(id),
    assigned_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by text NOT NULL DEFAULT '',
    scope_kind  text CHECK (scope_kind IS NULL OR scope_kind IN ('device_group', 'user_group')),
    scope_id    text,
    CHECK ((scope_kind IS NULL) = (scope_id IS NULL))
);
CREATE INDEX idx_user_group_roles_role ON user_group_roles(role_id);
CREATE INDEX user_group_roles_scope_lookup
    ON user_group_roles(scope_kind, scope_id) WHERE scope_id IS NOT NULL;
CREATE UNIQUE INDEX user_group_roles_scoped_unique
    ON user_group_roles(group_id, role_id, scope_kind, scope_id) WHERE scope_id IS NOT NULL;
CREATE UNIQUE INDEX user_group_roles_unscoped_unique
    ON user_group_roles(group_id, role_id) WHERE scope_id IS NULL;

CREATE TABLE identity_providers (
    id                      text PRIMARY KEY,
    name                    text NOT NULL,
    slug                    text NOT NULL,
    provider_type           text NOT NULL DEFAULT 'oidc',
    enabled                 boolean NOT NULL DEFAULT true,
    client_id               text NOT NULL,
    cli_client_id           text NOT NULL DEFAULT '',
    client_secret_encrypted text NOT NULL DEFAULT '',
    issuer_url              text NOT NULL,
    authorization_url       text NOT NULL DEFAULT '',
    token_url               text NOT NULL DEFAULT '',
    userinfo_url            text NOT NULL DEFAULT '',
    scopes                  text NOT NULL DEFAULT '[]' CHECK (
                                json_valid(scopes) AND json_type(scopes) = 'array'),
    auto_create_users       boolean NOT NULL DEFAULT false,
    auto_link_by_email      boolean NOT NULL DEFAULT false,
    trust_email_assertions  boolean NOT NULL DEFAULT false,
    default_role_id         text NOT NULL DEFAULT '',
    attribute_mapping       text NOT NULL DEFAULT '{}' CHECK (
                                json_valid(attribute_mapping)
                                AND json_type(attribute_mapping) = 'object'),
    group_claim             text NOT NULL DEFAULT '',
    group_mapping           text NOT NULL DEFAULT '{}' CHECK (
                                json_valid(group_mapping)
                                AND json_type(group_mapping) = 'object'),
    scim_enabled            boolean NOT NULL DEFAULT false,
    scim_token_hash         text NOT NULL DEFAULT '',
    created_at              timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by              text NOT NULL DEFAULT '',
    updated_at              timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_deleted              boolean NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX idx_identity_providers_slug
    ON identity_providers(slug) WHERE is_deleted = false;

CREATE TABLE identity_links (
    id             text PRIMARY KEY,
    user_id        text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id    text NOT NULL REFERENCES identity_providers(id),
    external_id    text NOT NULL,
    external_email text NOT NULL DEFAULT '',
    external_name  text NOT NULL DEFAULT '',
    linked_at      timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at  timestamp
);
CREATE INDEX idx_identity_links_user ON identity_links(user_id);
CREATE UNIQUE INDEX idx_identity_links_provider_external
    ON identity_links(provider_id, external_id);
CREATE UNIQUE INDEX idx_identity_links_user_provider
    ON identity_links(user_id, provider_id);

CREATE TABLE scim_group_mapping (
    id                text PRIMARY KEY,
    provider_id       text NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    scim_group_id     text NOT NULL,
    scim_display_name text NOT NULL DEFAULT '',
    user_group_id     text NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    created_at        timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_scim_group_mapping_provider ON scim_group_mapping(provider_id);
CREATE INDEX idx_scim_group_mapping_user_group ON scim_group_mapping(user_group_id);
CREATE UNIQUE INDEX idx_scim_group_mapping_provider_scim
    ON scim_group_mapping(provider_id, scim_group_id);

CREATE TABLE auth_states (
    state         text PRIMARY KEY,
    provider_id   text NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    flow_kind     text NOT NULL DEFAULT 'browser' CHECK (flow_kind IN ('browser', 'cli')),
    nonce         text NOT NULL DEFAULT '',
    code_verifier text NOT NULL DEFAULT '',
    redirect_uri  text NOT NULL DEFAULT '',
    created_at    timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    timestamp NOT NULL
);
CREATE INDEX idx_auth_states_expires ON auth_states(expires_at);

CREATE TABLE revoked_tokens (
    jti        text PRIMARY KEY,
    revoked_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp NOT NULL
);
CREATE INDEX idx_revoked_tokens_expires ON revoked_tokens(expires_at);

CREATE TABLE tokens (
    id           text PRIMARY KEY,
    value_hash   text NOT NULL UNIQUE,
    name         text NOT NULL DEFAULT '',
    one_time     boolean NOT NULL DEFAULT false,
    max_uses     integer NOT NULL DEFAULT 0,
    current_uses integer NOT NULL DEFAULT 0,
    expires_at   timestamp,
    created_at   timestamp,
    created_by   text NOT NULL DEFAULT '',
    owner_id     text REFERENCES users(id) ON DELETE CASCADE,
    disabled     boolean NOT NULL DEFAULT false,
    is_deleted   boolean NOT NULL DEFAULT false
);
CREATE INDEX idx_tokens_owner ON tokens(owner_id);

CREATE TABLE devices (
    id                         text PRIMARY KEY,
    hostname                   text NOT NULL DEFAULT '',
    agent_version              text NOT NULL DEFAULT '',
    agent_sealing_public_key   blob NOT NULL CHECK (length(agent_sealing_public_key) = 32),
    cert_fingerprint           text UNIQUE,
    cert_not_after             timestamp,
    registered_at              timestamp,
    last_seen_at               timestamp,
    registration_token_id      text REFERENCES tokens(id) ON DELETE SET NULL,
    is_deleted                 boolean NOT NULL DEFAULT false,
    sync_interval_minutes      integer NOT NULL DEFAULT 0,
    inventory_interval_minutes integer NOT NULL DEFAULT 0,
    compliance_status          integer NOT NULL DEFAULT 0,
    compliance_checked_at      timestamp,
    compliance_total           integer NOT NULL DEFAULT 0,
    compliance_passing         integer NOT NULL DEFAULT 0
);

CREATE TABLE device_labels (
    device_id text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key       text NOT NULL,
    value     text NOT NULL,
    PRIMARY KEY (device_id, key)
);
CREATE INDEX idx_device_labels_key_value ON device_labels(key, value);

CREATE TABLE device_groups (
    id                         text PRIMARY KEY,
    name                       text NOT NULL,
    description                text NOT NULL DEFAULT '',
    member_count               integer NOT NULL DEFAULT 0,
    created_at                 timestamp,
    created_by                 text NOT NULL DEFAULT '',
    is_deleted                 boolean NOT NULL DEFAULT false,
    is_dynamic                 boolean NOT NULL DEFAULT false,
    dynamic_query              text,
    sync_interval_minutes      integer NOT NULL DEFAULT 0,
    inventory_interval_minutes integer NOT NULL DEFAULT 0,
    maintenance_window         text NOT NULL DEFAULT '{}' CHECK (
                                   json_valid(maintenance_window)
                                   AND json_type(maintenance_window) = 'object')
);

CREATE TABLE device_group_members (
    group_id  text NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    device_id text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    added_at  timestamp,
    PRIMARY KEY (group_id, device_id)
);
CREATE INDEX idx_device_group_members_device_id ON device_group_members(device_id);

CREATE TABLE device_assigned_users (
    device_id   text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    user_id     text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by text NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, user_id)
);
CREATE INDEX idx_device_assigned_users_user ON device_assigned_users(user_id);

CREATE TABLE device_assigned_groups (
    device_id   text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    group_id    text NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    assigned_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by text NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, group_id)
);
CREATE INDEX idx_device_assigned_groups_group ON device_assigned_groups(group_id);

CREATE TABLE device_inventory (
    device_id    text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    table_name   text NOT NULL,
    rows         text NOT NULL DEFAULT '[]' CHECK (json_valid(rows)),
    collected_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, table_name)
);
CREATE INDEX idx_device_inventory_device ON device_inventory(device_id);

CREATE TABLE osquery_results (
    query_id     text PRIMARY KEY,
    device_id    text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    table_name   text NOT NULL,
    completed    boolean NOT NULL DEFAULT false,
    success      boolean NOT NULL DEFAULT false,
    error        text NOT NULL DEFAULT '',
    rows         text NOT NULL DEFAULT '[]' CHECK (json_valid(rows)),
    created_at   timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp
);
CREATE INDEX idx_osquery_results_device ON osquery_results(device_id);

CREATE TABLE log_query_results (
    query_id     text PRIMARY KEY,
    device_id    text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    completed    boolean NOT NULL DEFAULT false,
    success      boolean NOT NULL DEFAULT false,
    error        text NOT NULL DEFAULT '',
    logs         text NOT NULL DEFAULT '',
    created_at   timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp
);
CREATE INDEX idx_log_query_results_device ON log_query_results(device_id);
CREATE INDEX idx_log_query_results_completed ON log_query_results(completed, created_at);

CREATE TABLE security_alerts (
    alert_id        text PRIMARY KEY,
    device_id       text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    alert_type      text NOT NULL,
    message         text NOT NULL,
    details         text CHECK (details IS NULL OR json_valid(details)),
    raised_at       timestamp NOT NULL,
    acknowledged    boolean NOT NULL DEFAULT false,
    acknowledged_at timestamp,
    acknowledged_by text,
    created_at      timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_security_alerts_device
    ON security_alerts(device_id, acknowledged, raised_at DESC);
CREATE INDEX idx_security_alerts_type ON security_alerts(alert_type, raised_at DESC);
CREATE INDEX idx_security_alerts_unack
    ON security_alerts(acknowledged, raised_at DESC) WHERE acknowledged = false;

CREATE TABLE terminal_sessions (
    session_id      text PRIMARY KEY,
    device_id       text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    user_id         text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tty_user        text NOT NULL,
    started_at      timestamp NOT NULL,
    stopped_at      timestamp,
    exit_reason     text,
    exit_code       integer,
    terminated_by   text,
    input           blob NOT NULL DEFAULT X'',
    input_truncated boolean NOT NULL DEFAULT false,
    last_sequence   integer NOT NULL DEFAULT 0,
    chunk_count     integer NOT NULL DEFAULT 0,
    cols            integer NOT NULL DEFAULT 0,
    rows            integer NOT NULL DEFAULT 0
);
CREATE INDEX idx_terminal_sessions_started ON terminal_sessions(started_at DESC);
CREATE INDEX idx_terminal_sessions_device_started
    ON terminal_sessions(device_id, started_at DESC);
CREATE INDEX idx_terminal_sessions_user_started
    ON terminal_sessions(user_id, started_at DESC);

CREATE TABLE revoked_certificates (
    fingerprint text PRIMARY KEY,
    revoked_at  timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    not_after   timestamp NOT NULL,
    reason      text NOT NULL DEFAULT ''
);
CREATE INDEX revoked_certificates_not_after_idx ON revoked_certificates(not_after);

CREATE TABLE actions (
    id               text PRIMARY KEY,
    name             text NOT NULL,
    description      text,
    action_type      integer NOT NULL,
    desired_state    integer NOT NULL DEFAULT 0,
    params           text NOT NULL DEFAULT '{}' CHECK (
                         json_valid(params) AND json_type(params) = 'object'),
    params_canonical blob,
    timeout_seconds  integer NOT NULL DEFAULT 0,
    schedule         text CHECK (schedule IS NULL OR json_valid(schedule)),
    is_system        boolean NOT NULL DEFAULT false,
    created_at       timestamp,
    created_by       text NOT NULL DEFAULT '',
    updated_at       timestamp,
    is_deleted       boolean NOT NULL DEFAULT false
);

CREATE TABLE lps_passwords (
    id              text PRIMARY KEY,
    device_id       text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    action_id       text NOT NULL REFERENCES actions(id),
    username        text NOT NULL,
    password        text NOT NULL,
    rotated_at      timestamp NOT NULL,
    rotation_reason text NOT NULL DEFAULT 'scheduled',
    is_current      boolean NOT NULL DEFAULT true,
    created_at      timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_lps_passwords_device ON lps_passwords(device_id, is_current);
CREATE INDEX idx_lps_passwords_action_device ON lps_passwords(action_id, device_id);
CREATE INDEX idx_lps_passwords_username
    ON lps_passwords(device_id, action_id, username, is_current);

CREATE TABLE luks_keys (
    id                text PRIMARY KEY,
    device_id         text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    action_id         text NOT NULL REFERENCES actions(id),
    device_path       text NOT NULL,
    passphrase        text NOT NULL,
    rotated_at        timestamp NOT NULL,
    rotation_reason   text NOT NULL DEFAULT 'scheduled',
    is_current        boolean NOT NULL DEFAULT true,
    created_at        timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revocation_status text,
    revocation_error  text,
    revocation_at     timestamp
);
CREATE INDEX idx_luks_keys_device ON luks_keys(device_id, is_current);
CREATE INDEX idx_luks_keys_action_device ON luks_keys(action_id, device_id);
CREATE INDEX idx_luks_keys_current ON luks_keys(device_id, action_id, device_path, is_current);

CREATE TABLE luks_tokens (
    id         text PRIMARY KEY,
    device_id  text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    action_id  text NOT NULL REFERENCES actions(id),
    token      text NOT NULL UNIQUE,
    min_length integer NOT NULL DEFAULT 16,
    complexity integer NOT NULL DEFAULT 0,
    created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp NOT NULL,
    used       boolean NOT NULL DEFAULT false
);
CREATE INDEX idx_luks_tokens_token ON luks_tokens(token) WHERE NOT used;

CREATE TABLE action_sets (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    schedule    text NOT NULL DEFAULT '{}' CHECK (json_valid(schedule)),
    on_failure  integer NOT NULL DEFAULT 0 CHECK (on_failure IN (0, 1)),
    created_at  timestamp,
    created_by  text NOT NULL DEFAULT '',
    updated_at  timestamp,
    is_deleted  boolean NOT NULL DEFAULT false
);

CREATE TABLE action_set_members (
    set_id     text NOT NULL REFERENCES action_sets(id) ON DELETE CASCADE,
    action_id  text NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    sort_order integer NOT NULL DEFAULT 0,
    added_at   timestamp,
    PRIMARY KEY (set_id, action_id)
);

CREATE TABLE definitions (
    id           text PRIMARY KEY,
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',
    member_count integer NOT NULL DEFAULT 0,
    schedule     text NOT NULL DEFAULT '{}' CHECK (json_valid(schedule)),
    created_at   timestamp,
    created_by   text NOT NULL DEFAULT '',
    updated_at   timestamp,
    is_deleted   boolean NOT NULL DEFAULT false
);

CREATE TABLE definition_members (
    definition_id text NOT NULL REFERENCES definitions(id) ON DELETE CASCADE,
    action_set_id text NOT NULL REFERENCES action_sets(id) ON DELETE CASCADE,
    sort_order    integer NOT NULL DEFAULT 0,
    added_at      timestamp,
    PRIMARY KEY (definition_id, action_set_id)
);

CREATE TABLE assignments (
    id          text PRIMARY KEY,
    source_type text NOT NULL,
    source_id   text NOT NULL,
    target_type text NOT NULL,
    target_id   text NOT NULL,
    sort_order  integer NOT NULL DEFAULT 0,
    mode        integer NOT NULL DEFAULT 0,
    created_at  timestamp,
    created_by  text NOT NULL DEFAULT '',
    is_deleted  boolean NOT NULL DEFAULT false,
    UNIQUE (source_type, source_id, target_type, target_id)
);

CREATE TABLE user_selections (
    id          text PRIMARY KEY,
    device_id   text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    source_type text NOT NULL,
    source_id   text NOT NULL,
    selected    boolean NOT NULL DEFAULT false,
    updated_at  timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by  text NOT NULL DEFAULT '',
    UNIQUE (device_id, source_type, source_id)
);
CREATE INDEX idx_user_selections_device ON user_selections(device_id);

CREATE TABLE deliveries (
    delivery_id      text PRIMARY KEY CHECK (
                         length(delivery_id) = 26
                         AND delivery_id NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'),
    device_id        text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    manifest_id      text NOT NULL CHECK (
                         length(manifest_id) = 26
                         AND manifest_id NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'),
    manifest         text NOT NULL CHECK (json_valid(manifest)),
    state            text NOT NULL CHECK (state IN (
                         'PENDING', 'PUSHED', 'ACKED_RECEIPT', 'SUCCEEDED',
                         'PARTIAL', 'FAILED', 'EXPIRED', 'CANCELLED')),
    operation_id     text CHECK (operation_id IS NULL OR (
                         length(operation_id) = 26
                         AND operation_id NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*')),
    push_epoch       integer NOT NULL DEFAULT 0 CHECK (push_epoch >= 0),
    attempt_count    integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    created_at       timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    available_at     timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at       timestamp,
    pushed_at        timestamp,
    acked_receipt_at timestamp,
    terminal_at      timestamp,
    result_code      text NOT NULL DEFAULT '' CHECK (length(result_code) <= 64),
    CHECK (CASE state
        WHEN 'PENDING' THEN pushed_at IS NULL AND acked_receipt_at IS NULL AND terminal_at IS NULL
        WHEN 'PUSHED' THEN pushed_at IS NOT NULL AND acked_receipt_at IS NULL AND terminal_at IS NULL
        WHEN 'ACKED_RECEIPT' THEN pushed_at IS NOT NULL AND acked_receipt_at IS NOT NULL AND terminal_at IS NULL
        ELSE terminal_at IS NOT NULL END),
    CHECK (state NOT IN ('SUCCEEDED', 'PARTIAL', 'FAILED') OR acked_receipt_at IS NOT NULL)
);
CREATE INDEX deliveries_sweep_idx ON deliveries(available_at)
    WHERE state IN ('PENDING', 'PUSHED');
CREATE INDEX deliveries_device_pending_idx ON deliveries(device_id, created_at)
    WHERE state IN ('PENDING', 'PUSHED');
CREATE INDEX deliveries_device_idx ON deliveries(device_id, created_at DESC);
CREATE INDEX deliveries_manifest_idx ON deliveries(manifest_id);
CREATE INDEX deliveries_operation_idx ON deliveries(operation_id);
CREATE INDEX deliveries_expiry_idx ON deliveries(expires_at)
    WHERE expires_at IS NOT NULL AND terminal_at IS NULL;

CREATE TABLE executions (
    id               text PRIMARY KEY,
    delivery_id      text NOT NULL REFERENCES deliveries(delivery_id) ON DELETE CASCADE,
    device_id        text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    action_id        text REFERENCES actions(id) ON DELETE SET NULL,
    action_type      integer NOT NULL,
    desired_state    integer NOT NULL DEFAULT 0,
    params           text NOT NULL DEFAULT '{}' CHECK (
                         json_valid(params) AND json_type(params) = 'object'),
    timeout_seconds  integer NOT NULL DEFAULT 0,
    status           text NOT NULL CHECK (status IN (
                         'scheduled', 'pending', 'running', 'success', 'failed',
                         'skipped', 'timeout', 'cancelled', 'not_applicable', 'indeterminate')),
    error            text,
    output           text CHECK (output IS NULL OR json_valid(output)),
    detection_output text CHECK (detection_output IS NULL OR json_valid(detection_output)),
    changed          boolean NOT NULL DEFAULT false,
    compliant        boolean NOT NULL DEFAULT false,
    created_at       timestamp,
    scheduled_for    timestamp,
    dispatched_at    timestamp,
    started_at       timestamp,
    completed_at     timestamp,
    duration_ms      integer,
    created_by_type  text NOT NULL DEFAULT '',
    created_by_id    text NOT NULL DEFAULT '',
    UNIQUE (delivery_id, id)
);
CREATE INDEX idx_executions_device ON executions(device_id);
CREATE INDEX idx_executions_status ON executions(status);
CREATE INDEX idx_executions_device_status ON executions(device_id, status);
CREATE INDEX idx_executions_delivery ON executions(delivery_id);

CREATE TABLE execution_output_chunks (
    execution_id text NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    stream       text NOT NULL CHECK (stream IN ('stdout', 'stderr')),
    sequence     integer NOT NULL CHECK (sequence >= 0),
    data         blob NOT NULL CHECK (length(data) <= 65536),
    received_at  timestamp NOT NULL,
    PRIMARY KEY (execution_id, stream, sequence)
);

CREATE TABLE compliance_policies (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    rule_count  integer NOT NULL DEFAULT 0,
    created_at  timestamp,
    created_by  text NOT NULL DEFAULT '',
    is_deleted  boolean NOT NULL DEFAULT false
);

CREATE TABLE compliance_policy_rules (
    policy_id          text NOT NULL REFERENCES compliance_policies(id) ON DELETE CASCADE,
    action_id          text NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    action_name        text NOT NULL DEFAULT '',
    grace_period_hours integer NOT NULL DEFAULT 0,
    added_at           timestamp,
    PRIMARY KEY (policy_id, action_id)
);
CREATE INDEX idx_compliance_policy_rules_action ON compliance_policy_rules(action_id);

CREATE TABLE compliance_policy_evaluation (
    device_id       text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    policy_id       text NOT NULL REFERENCES compliance_policies(id) ON DELETE CASCADE,
    action_id       text NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    compliant       boolean NOT NULL DEFAULT false,
    first_failed_at timestamp,
    status          integer NOT NULL DEFAULT 0,
    checked_at      timestamp,
    PRIMARY KEY (device_id, policy_id, action_id)
);
CREATE INDEX idx_compliance_eval_device ON compliance_policy_evaluation(device_id);
CREATE INDEX idx_compliance_eval_policy ON compliance_policy_evaluation(policy_id);

CREATE TABLE compliance_results (
    device_id        text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    action_id        text NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    action_name      text NOT NULL DEFAULT '',
    compliant        boolean NOT NULL DEFAULT false,
    detection_output text CHECK (detection_output IS NULL OR json_valid(detection_output)),
    checked_at       timestamp NOT NULL,
    PRIMARY KEY (device_id, action_id)
);
CREATE INDEX idx_compliance_device ON compliance_results(device_id);

CREATE TABLE server_settings (
    id                        text PRIMARY KEY,
    user_provisioning_enabled boolean NOT NULL DEFAULT false,
    ssh_access_for_all        boolean NOT NULL DEFAULT false,
    updated_at                timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One hash chain shared by operation and effect rows.
CREATE TABLE audit_chain_head (
    stream     text PRIMARY KEY,
    head_hash  blob NOT NULL CHECK (length(head_hash) = 32),
    height     integer NOT NULL DEFAULT 0 CHECK (height >= 0),
    updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO audit_chain_head (stream, head_hash, height) VALUES ('control', zeroblob(32), 0);

CREATE TABLE audit_operations (
    operation_id          text PRIMARY KEY CHECK (
                              length(operation_id) = 26
                              AND operation_id NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'),
    stream                text NOT NULL DEFAULT 'control' REFERENCES audit_chain_head(stream),
    chain_seq             integer NOT NULL CHECK (chain_seq > 0),
    operation_class       text NOT NULL CHECK (operation_class IN (
                              'MUTATION', 'SENSITIVE_READ',
                              'REJECTED_AUTHENTICATION', 'BACKGROUND_WRITER')),
    actor_type            text NOT NULL CHECK (
                              length(actor_type) BETWEEN 1 AND 32
                              AND actor_type NOT GLOB '*[^a-z0-9_]*'
                              AND substr(actor_type, 1, 1) GLOB '[a-z]'),
    actor_id              text NOT NULL DEFAULT '' CHECK (
                              actor_id = '' OR (length(actor_id) = 26
                              AND actor_id NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*')),
    actor_fingerprint     text NOT NULL DEFAULT '' CHECK (
                              actor_fingerprint = '' OR (length(actor_fingerprint) = 64
                              AND actor_fingerprint NOT GLOB '*[^0-9a-f]*')),
    origin                text NOT NULL CHECK (
                              length(origin) BETWEEN 1 AND 32
                              AND origin NOT GLOB '*[^a-z0-9_]*'
                              AND substr(origin, 1, 1) GLOB '[a-z]'),
    origin_fingerprint    text NOT NULL DEFAULT '' CHECK (
                              origin_fingerprint = '' OR (length(origin_fingerprint) = 64
                              AND origin_fingerprint NOT GLOB '*[^0-9a-f]*')),
    request_descriptor    text NOT NULL CHECK (
                              length(request_descriptor) BETWEEN 1 AND 200
                              AND request_descriptor NOT GLOB '*[^A-Za-z0-9_./:-]*'),
    authorization_outcome text NOT NULL CHECK (
                              authorization_outcome IN ('ALLOWED', 'DENIED', 'NOT_APPLICABLE')),
    authorization_detail  text NOT NULL DEFAULT '' CHECK (
                              length(authorization_detail) <= 128
                              AND authorization_detail NOT GLOB '*[^A-Za-z0-9_.:/-]*'),
    result                text NOT NULL CHECK (result IN ('SUCCESS', 'FAILURE', 'REJECTED')),
    result_code           text NOT NULL DEFAULT '' CHECK (
                              length(result_code) <= 64
                              AND result_code NOT GLOB '*[^A-Za-z0-9_.-]*'),
    occurred_at           timestamp NOT NULL,
    sealed_detail         blob,
    sealed_detail_subject text,
    prev_hash             blob NOT NULL CHECK (length(prev_hash) = 32),
    row_hash              blob NOT NULL CHECK (length(row_hash) = 32),
    CHECK ((sealed_detail IS NULL) = (sealed_detail_subject IS NULL)),
    CHECK (sealed_detail_subject IS NULL OR (
        length(sealed_detail_subject) = 26
        AND sealed_detail_subject NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'))
);
CREATE UNIQUE INDEX audit_operations_stream_seq_key ON audit_operations(stream, chain_seq);
CREATE INDEX audit_operations_occurred_at_idx ON audit_operations(occurred_at DESC);
CREATE INDEX audit_operations_actor_idx ON audit_operations(actor_id, occurred_at DESC);
CREATE INDEX audit_operations_class_idx ON audit_operations(operation_class, occurred_at DESC);
CREATE INDEX audit_operations_descriptor_idx
    ON audit_operations(request_descriptor, occurred_at DESC);
CREATE TRIGGER audit_operations_reject_effect_sequence_collision
BEFORE INSERT ON audit_operations
WHEN EXISTS (
    SELECT 1 FROM audit_effects
    WHERE stream = NEW.stream AND chain_seq = NEW.chain_seq
) BEGIN
    SELECT RAISE(ABORT, 'audit chain sequence already belongs to an effect');
END;

CREATE TABLE audit_effects (
    effect_id             text PRIMARY KEY CHECK (
                              length(effect_id) = 26
                              AND effect_id NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'),
    operation_id          text NOT NULL REFERENCES audit_operations(operation_id),
    stream                text NOT NULL DEFAULT 'control' REFERENCES audit_chain_head(stream),
    chain_seq             integer NOT NULL CHECK (chain_seq > 0),
    effect_seq            integer NOT NULL CHECK (effect_seq >= 0),
    resource_type         text NOT NULL CHECK (
                              length(resource_type) BETWEEN 1 AND 64
                              AND resource_type NOT GLOB '*[^a-z0-9_]*'
                              AND substr(resource_type, 1, 1) GLOB '[a-z]'),
    resource_id           text NOT NULL CHECK (
                              length(resource_id) = 26
                              AND resource_id NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'),
    action                text NOT NULL CHECK (
                              length(action) BETWEEN 1 AND 32
                              AND action NOT GLOB '*[^A-Z0-9_]*'
                              AND substr(action, 1, 1) GLOB '[A-Z]'),
    outcome               text NOT NULL CHECK (outcome IN ('APPLIED', 'REJECTED', 'FAILED')),
    changed_fields        text NOT NULL DEFAULT '[]' CHECK (
                              json_valid(changed_fields)
                              AND json_type(changed_fields) = 'array'),
    before_ref            text CHECK (before_ref IS NULL OR (
                              length(before_ref) = 26
                              AND before_ref NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*')),
    after_ref             text CHECK (after_ref IS NULL OR (
                              length(after_ref) = 26
                              AND after_ref NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*')),
    before_flag           boolean,
    after_flag            boolean,
    before_count          integer,
    after_count           integer,
    evidence_kind         text NOT NULL DEFAULT '' CHECK (length(evidence_kind) <= 32),
    evidence_fingerprint  text NOT NULL DEFAULT '' CHECK (
                              evidence_fingerprint = '' OR (length(evidence_fingerprint) = 64
                              AND evidence_fingerprint NOT GLOB '*[^0-9a-f]*')),
    sealed_detail         blob,
    sealed_detail_subject text,
    occurred_at           timestamp NOT NULL,
    prev_hash             blob NOT NULL CHECK (length(prev_hash) = 32),
    row_hash              blob NOT NULL CHECK (length(row_hash) = 32),
    CHECK ((evidence_kind = '') = (evidence_fingerprint = '')),
    CHECK ((sealed_detail IS NULL) = (sealed_detail_subject IS NULL)),
    CHECK (sealed_detail_subject IS NULL OR (
        length(sealed_detail_subject) = 26
        AND sealed_detail_subject NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'))
);
CREATE UNIQUE INDEX audit_effects_stream_seq_key ON audit_effects(stream, chain_seq);
CREATE UNIQUE INDEX audit_effects_operation_seq_key ON audit_effects(operation_id, effect_seq);
CREATE INDEX audit_effects_resource_idx
    ON audit_effects(resource_type, resource_id, occurred_at DESC);
CREATE INDEX audit_effects_operation_idx ON audit_effects(operation_id);
CREATE TRIGGER audit_effects_reject_operation_sequence_collision
BEFORE INSERT ON audit_effects
WHEN EXISTS (
    SELECT 1 FROM audit_operations
    WHERE stream = NEW.stream AND chain_seq = NEW.chain_seq
) BEGIN
    SELECT RAISE(ABORT, 'audit chain sequence already belongs to an operation');
END;
CREATE TRIGGER audit_effects_validate_changed_fields
BEFORE INSERT ON audit_effects
WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.changed_fields)
    WHERE type <> 'text'
       OR length(value) NOT BETWEEN 1 AND 40
       OR value GLOB '*[^a-z0-9_]*'
       OR substr(value, 1, 1) NOT GLOB '[a-z]'
) BEGIN
    SELECT RAISE(ABORT, 'audit changed_fields contains an invalid field name');
END;

-- The API-facing projection intentionally excludes sealed_detail. Effects are
-- the ordinary rows; an operation without effects still contributes evidence,
-- most importantly for rejected authentication attempts.
CREATE VIEW audit_event_rows AS
SELECT
    e.effect_id AS id,
    e.chain_seq,
    e.resource_type AS stream_type,
    e.resource_id AS stream_id,
    e.action AS event_type,
    o.operation_id,
    o.operation_class,
    o.actor_type,
    o.actor_id,
    o.actor_fingerprint,
    o.origin,
    o.origin_fingerprint,
    o.request_descriptor,
    o.authorization_outcome,
    o.authorization_detail,
    o.result,
    o.result_code,
    e.outcome AS effect_outcome,
    e.changed_fields,
    e.before_ref,
    e.after_ref,
    e.before_flag,
    e.after_flag,
    e.before_count,
    e.after_count,
    e.evidence_kind,
    e.evidence_fingerprint,
    e.occurred_at
FROM audit_effects e
JOIN audit_operations o ON o.operation_id = e.operation_id
WHERE e.stream = 'control'

UNION ALL

SELECT
    o.operation_id AS id,
    o.chain_seq,
    CASE WHEN o.operation_class = 'REJECTED_AUTHENTICATION'
         THEN 'authentication' ELSE 'operation' END AS stream_type,
    o.operation_id AS stream_id,
    CASE WHEN o.operation_class = 'REJECTED_AUTHENTICATION'
         THEN 'AUTHENTICATION_REJECTED' ELSE o.operation_class END AS event_type,
    o.operation_id,
    o.operation_class,
    o.actor_type,
    o.actor_id,
    o.actor_fingerprint,
    o.origin,
    o.origin_fingerprint,
    o.request_descriptor,
    o.authorization_outcome,
    o.authorization_detail,
    o.result,
    o.result_code,
    '' AS effect_outcome,
    '[]' AS changed_fields,
    CAST(NULL AS TEXT) AS before_ref,
    CAST(NULL AS TEXT) AS after_ref,
    CAST(NULL AS INTEGER) AS before_flag,
    CAST(NULL AS INTEGER) AS after_flag,
    CAST(NULL AS INTEGER) AS before_count,
    CAST(NULL AS INTEGER) AS after_count,
    '' AS evidence_kind,
    '' AS evidence_fingerprint,
    o.occurred_at
FROM audit_operations o
WHERE o.stream = 'control'
  AND NOT EXISTS (
      SELECT 1 FROM audit_effects e WHERE e.operation_id = o.operation_id
  );

CREATE TABLE audit_chain_anchors (
    anchor_id    text PRIMARY KEY CHECK (
                     length(anchor_id) = 26
                     AND anchor_id NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'),
    stream       text NOT NULL REFERENCES audit_chain_head(stream),
    chain_seq    integer NOT NULL CHECK (chain_seq > 0),
    row_hash     blob NOT NULL CHECK (length(row_hash) = 32),
    captured_at  timestamp NOT NULL,
    external_ref text NOT NULL DEFAULT '' CHECK (length(external_ref) <= 200)
);
CREATE UNIQUE INDEX audit_chain_anchors_stream_seq_key
    ON audit_chain_anchors(stream, chain_seq);
CREATE INDEX audit_chain_anchors_captured_idx
    ON audit_chain_anchors(stream, captured_at DESC);

CREATE TABLE audit_chain_checkpoints (
    checkpoint_id  text PRIMARY KEY CHECK (
                       length(checkpoint_id) = 26
                       AND checkpoint_id NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'),
    stream         text NOT NULL REFERENCES audit_chain_head(stream),
    boundary_seq   integer NOT NULL CHECK (boundary_seq > 0),
    boundary_hash  blob NOT NULL CHECK (length(boundary_hash) = 32),
    resume_seq     integer NOT NULL CHECK (resume_seq > boundary_seq),
    deleted_rows   integer NOT NULL CHECK (deleted_rows >= 0),
    archive_digest text NOT NULL CHECK (
                       length(archive_digest) = 64
                       AND archive_digest NOT GLOB '*[^0-9a-f]*'),
    archive_ref    text NOT NULL CHECK (length(archive_ref) BETWEEN 1 AND 200),
    archived_at    timestamp NOT NULL,
    created_at     timestamp NOT NULL
);
CREATE UNIQUE INDEX audit_chain_checkpoints_stream_boundary_key
    ON audit_chain_checkpoints(stream, boundary_seq);
CREATE INDEX audit_chain_checkpoints_resume_idx
    ON audit_chain_checkpoints(stream, resume_seq);

-- docref: anchor sqlite-audit-guards
-- Retention inserts one transaction-local intent row, deletes only the
-- archived prefix, then removes the intent before commit. A crash rolls all
-- three operations back. Ordinary DELETE remains structurally impossible.
CREATE TABLE audit_retention_guard (
    stream       text PRIMARY KEY REFERENCES audit_chain_head(stream),
    boundary_seq integer NOT NULL CHECK (boundary_seq > 0)
);
CREATE TRIGGER audit_retention_guard_requires_closed_prefix
BEFORE INSERT ON audit_retention_guard
WHEN EXISTS (
    SELECT 1
    FROM audit_operations AS operation
    JOIN audit_effects AS effect ON effect.operation_id = operation.operation_id
    WHERE operation.stream = NEW.stream
      AND operation.chain_seq <= NEW.boundary_seq
      AND effect.chain_seq > NEW.boundary_seq
) BEGIN
    SELECT RAISE(ABORT, 'audit retention boundary is not a closed prefix');
END;

CREATE TRIGGER audit_operations_block_update
BEFORE UPDATE ON audit_operations BEGIN
    SELECT RAISE(ABORT, 'audit_operations is append-only');
END;
CREATE TRIGGER audit_operations_block_delete
BEFORE DELETE ON audit_operations
WHEN NOT EXISTS (
    SELECT 1 FROM audit_retention_guard
    WHERE stream = OLD.stream AND OLD.chain_seq <= boundary_seq
) BEGIN
    SELECT RAISE(ABORT, 'audit_operations is append-only');
END;
CREATE TRIGGER audit_effects_block_update
BEFORE UPDATE ON audit_effects BEGIN
    SELECT RAISE(ABORT, 'audit_effects is append-only');
END;
CREATE TRIGGER audit_effects_block_delete
BEFORE DELETE ON audit_effects
WHEN NOT EXISTS (
    SELECT 1 FROM audit_retention_guard
    WHERE stream = OLD.stream AND OLD.chain_seq <= boundary_seq
) BEGIN
    SELECT RAISE(ABORT, 'audit_effects is append-only');
END;
CREATE TRIGGER audit_chain_anchors_block_update
BEFORE UPDATE ON audit_chain_anchors BEGIN
    SELECT RAISE(ABORT, 'audit_chain_anchors is append-only');
END;
CREATE TRIGGER audit_chain_anchors_block_delete
BEFORE DELETE ON audit_chain_anchors BEGIN
    SELECT RAISE(ABORT, 'audit_chain_anchors is append-only');
END;
CREATE TRIGGER audit_chain_checkpoints_block_update
BEFORE UPDATE ON audit_chain_checkpoints BEGIN
    SELECT RAISE(ABORT, 'audit_chain_checkpoints is append-only');
END;
CREATE TRIGGER audit_chain_checkpoints_block_delete
BEFORE DELETE ON audit_chain_checkpoints BEGIN
    SELECT RAISE(ABORT, 'audit_chain_checkpoints is append-only');
END;

CREATE TABLE jobs (
    job_id        text PRIMARY KEY CHECK (
                      length(job_id) = 26
                      AND job_id NOT GLOB '*[^0-9A-HJKMNP-TV-Z]*'),
    kind          text NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    payload       text NOT NULL DEFAULT '{}' CHECK (
                      json_valid(payload) AND json_type(payload) = 'object' AND length(payload) <= 65536),
    state         text NOT NULL CHECK (state IN (
                      'PENDING', 'CLAIMED', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    due_at        timestamp NOT NULL,
    claimed_at    timestamp,
    claimed_until timestamp,
    claimed_by    text NOT NULL DEFAULT '',
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts  integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 100),
    result_code   text NOT NULL DEFAULT '' CHECK (length(result_code) <= 64),
    dedupe_key    text CHECK (dedupe_key IS NULL OR length(dedupe_key) <= 128),
    created_at    timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    terminal_at   timestamp,
    CHECK ((claimed_at IS NULL) = (claimed_until IS NULL)),
    CHECK (CASE state
        WHEN 'PENDING' THEN claimed_at IS NULL AND claimed_until IS NULL
                            AND claimed_by = '' AND terminal_at IS NULL
        WHEN 'CLAIMED' THEN claimed_at IS NOT NULL AND claimed_until IS NOT NULL
                            AND claimed_by <> '' AND terminal_at IS NULL
        ELSE claimed_at IS NULL AND claimed_until IS NULL
             AND claimed_by = '' AND terminal_at IS NOT NULL END)
);
CREATE INDEX jobs_due_idx ON jobs(due_at) WHERE state = 'PENDING';
CREATE INDEX jobs_lease_idx ON jobs(claimed_until) WHERE state = 'CLAIMED';
CREATE INDEX jobs_kind_idx ON jobs(kind, due_at);
CREATE UNIQUE INDEX jobs_dedupe_live_key ON jobs(dedupe_key)
    WHERE dedupe_key IS NOT NULL AND state IN ('PENDING', 'CLAIMED');

-- docref: anchor sqlite-search
-- All facets share one explicit document table. Owning-row and cross-row
-- updates will write this table in the same transaction as the CRUD mutation.
CREATE TABLE search_documents (
    rowid        integer PRIMARY KEY,
    scope        text NOT NULL,
    entity_id    text NOT NULL,
    primary_text text NOT NULL DEFAULT '',
    description  text NOT NULL DEFAULT '',
    related_text text NOT NULL DEFAULT '',
    sort_text    text NOT NULL DEFAULT '',
    member_count integer NOT NULL DEFAULT 0,
    fields       text NOT NULL DEFAULT '{}' CHECK (
                     json_valid(fields) AND json_type(fields) = 'object'),
    UNIQUE (scope, entity_id)
);
CREATE INDEX search_documents_entity_idx ON search_documents(scope, entity_id);

CREATE VIRTUAL TABLE search_fts USING fts5(
    primary_text, description, related_text,
    content = 'search_documents', content_rowid = 'rowid',
    tokenize = "unicode61 remove_diacritics 2"
);
CREATE VIRTUAL TABLE search_trigram USING fts5(
    primary_text, description, related_text,
    content = 'search_documents', content_rowid = 'rowid',
    tokenize = "trigram remove_diacritics 1"
);

CREATE TRIGGER search_documents_insert AFTER INSERT ON search_documents BEGIN
    INSERT INTO search_fts(rowid, primary_text, description, related_text)
    VALUES (NEW.rowid, NEW.primary_text, NEW.description, NEW.related_text);
    INSERT INTO search_trigram(rowid, primary_text, description, related_text)
    VALUES (NEW.rowid, NEW.primary_text, NEW.description, NEW.related_text);
END;
CREATE TRIGGER search_documents_delete AFTER DELETE ON search_documents BEGIN
    INSERT INTO search_fts(search_fts, rowid, primary_text, description, related_text)
    VALUES ('delete', OLD.rowid, OLD.primary_text, OLD.description, OLD.related_text);
    INSERT INTO search_trigram(search_trigram, rowid, primary_text, description, related_text)
    VALUES ('delete', OLD.rowid, OLD.primary_text, OLD.description, OLD.related_text);
END;
CREATE TRIGGER search_documents_update AFTER UPDATE ON search_documents BEGIN
    INSERT INTO search_fts(search_fts, rowid, primary_text, description, related_text)
    VALUES ('delete', OLD.rowid, OLD.primary_text, OLD.description, OLD.related_text);
    INSERT INTO search_fts(rowid, primary_text, description, related_text)
    VALUES (NEW.rowid, NEW.primary_text, NEW.description, NEW.related_text);
    INSERT INTO search_trigram(search_trigram, rowid, primary_text, description, related_text)
    VALUES ('delete', OLD.rowid, OLD.primary_text, OLD.description, OLD.related_text);
    INSERT INTO search_trigram(rowid, primary_text, description, related_text)
    VALUES (NEW.rowid, NEW.primary_text, NEW.description, NEW.related_text);
END;

INSERT INTO server_settings (id, updated_at)
VALUES ('00000000000000000000000003', '2026-01-01 00:00:00+00:00');
INSERT INTO roles (id, name, description, permissions, is_system, created_at, updated_at)
VALUES ('00000000000000000000000001', 'Admin', 'Full system access', '[]', true,
        '2026-01-01 00:00:00+00:00', '2026-01-01 00:00:00+00:00');
INSERT INTO roles (id, name, description, permissions, is_system, created_at, updated_at)
VALUES ('00000000000000000000000002', 'User', 'Basic user access', '[]', true,
        '2026-01-01 00:00:00+00:00', '2026-01-01 00:00:00+00:00');

PRAGMA user_version = 1;
