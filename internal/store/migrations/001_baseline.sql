-- Core application state.
--
-- Ordinary mutable tables. Handlers create, read, update and delete
-- rows through explicit domain operations.
--
-- Conventions used throughout the schema:
--   * every identifier column is a text ULID;
--   * every timestamp is timestamp with time zone;
--   * `is_deleted` marks a row retired from the product surface while
--     rows that reference it stay resolvable; partial unique indexes
--     are scoped to live rows so a name can be reused after deletion;
--   * columns that hold sensitive values store AES-256-GCM ciphertext
--     with resource-context AAD, or a non-reversible hash — never a
--     plaintext secret.

-- +goose Up

-- ===========================================================================
-- Identity
-- ===========================================================================

-- Linux UIDs for provisioned users. A sequence rather than a MAX()+1
-- read so two concurrent provisioning transactions cannot collide.
CREATE SEQUENCE public.linux_uid_seq
    START WITH 10000
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- Human identities, sourced from OIDC login and SCIM provisioning.
CREATE TABLE public.users (
    id                        text PRIMARY KEY,
    email                     text NOT NULL,
    created_at                timestamp with time zone,
    updated_at                timestamp with time zone,
    last_login_at             timestamp with time zone,
    disabled                  boolean DEFAULT false NOT NULL,
    is_deleted                boolean DEFAULT false NOT NULL,
    -- Bumped to invalidate every session already issued to this
    -- subject (disable, role change, forced logout). Sessions carry
    -- the value they were minted with and are rejected once it lags.
    session_version           integer DEFAULT 0 NOT NULL,
    display_name              text DEFAULT ''::text NOT NULL,
    given_name                text DEFAULT ''::text NOT NULL,
    family_name               text DEFAULT ''::text NOT NULL,
    preferred_username        text DEFAULT ''::text NOT NULL,
    picture                   text DEFAULT ''::text NOT NULL,
    locale                    text DEFAULT ''::text NOT NULL,
    linux_username            text DEFAULT ''::text NOT NULL,
    linux_uid                 integer DEFAULT 0 NOT NULL,
    ssh_access_enabled        boolean DEFAULT false NOT NULL,
    ssh_allow_pubkey          boolean DEFAULT true NOT NULL,
    ssh_allow_password        boolean DEFAULT false NOT NULL,
    system_user_action_id     text DEFAULT ''::text NOT NULL,
    system_ssh_action_id      text DEFAULT ''::text NOT NULL,
    system_tty_action_id      text DEFAULT ''::text NOT NULL,
    user_provisioning_enabled boolean DEFAULT false NOT NULL
);

CREATE UNIQUE INDEX idx_users_email_active
    ON public.users USING btree (email) WHERE (is_deleted = false);

CREATE TABLE public.user_ssh_keys (
    user_id    text NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    key_id     text NOT NULL,
    public_key text,
    comment    text,
    added_at   timestamp with time zone NOT NULL,
    PRIMARY KEY (user_id, key_id)
);

CREATE INDEX idx_user_ssh_keys_user ON public.user_ssh_keys USING btree (user_id);

-- One KEK-wrapped data-encryption key per subject. Destroying the row
-- is the erasure: every value sealed under that DEK — including
-- class-three audit detail, which is never deleted — becomes
-- permanently unreadable. The key material cannot be regenerated, so
-- this table is jointly authoritative with the audit log and must be
-- in every backup set.
--
-- Deliberately not foreign-keyed to users: erasure removes the user
-- row and the key independently, and either order must be legal.
CREATE TABLE public.user_encryption_keys (
    user_id     text PRIMARY KEY,
    wrapped_dek text NOT NULL,
    created_at  timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.roles (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    permissions text[] DEFAULT '{}'::text[] NOT NULL,
    is_system   boolean DEFAULT false NOT NULL,
    created_at  timestamp with time zone DEFAULT now() NOT NULL,
    created_by  text DEFAULT ''::text NOT NULL,
    updated_at  timestamp with time zone,
    is_deleted  boolean DEFAULT false NOT NULL
);

CREATE TABLE public.user_groups (
    id                 text PRIMARY KEY,
    name               text NOT NULL,
    description        text DEFAULT ''::text NOT NULL,
    member_count       integer DEFAULT 0 NOT NULL,
    created_at         timestamp with time zone DEFAULT now() NOT NULL,
    created_by         text DEFAULT ''::text NOT NULL,
    updated_at         timestamp with time zone DEFAULT now() NOT NULL,
    is_deleted         boolean DEFAULT false NOT NULL,
    is_dynamic         boolean DEFAULT false NOT NULL,
    dynamic_query      text,
    maintenance_window jsonb DEFAULT '{}'::jsonb NOT NULL
);

CREATE UNIQUE INDEX idx_user_groups_name
    ON public.user_groups USING btree (name) WHERE (is_deleted = false);

CREATE TABLE public.user_group_members (
    group_id text NOT NULL REFERENCES public.user_groups(id),
    user_id  text NOT NULL REFERENCES public.users(id),
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    added_by text DEFAULT ''::text NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_user_group_members_user ON public.user_group_members USING btree (user_id);

-- Direct role grants. scope_kind/scope_id confine a grant to one
-- device or user group; both NULL means the grant is global.
--
-- The key is a surrogate id because one subject may hold the same role
-- globally AND at several distinct scopes at once; a natural key of
-- (subject, role) would make that unrepresentable. Uniqueness is
-- instead exactly what it should be: at most one unscoped grant per
-- subject and role, and at most one per subject, role and distinct
-- scope.
--
-- The authorization layer refuses a scope on permissions that could
-- grant or widen privilege; the pairing and the scope vocabulary are
-- enforced here so a half-set scope cannot reach the evaluator.
CREATE TABLE public.user_roles (
    grant_id    text PRIMARY KEY,
    user_id     text NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    role_id     text NOT NULL REFERENCES public.roles(id),
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    assigned_by text DEFAULT ''::text NOT NULL,
    scope_kind  text,
    scope_id    text,
    CONSTRAINT user_roles_scope_kind_valid
        CHECK (scope_kind IS NULL OR scope_kind = ANY (ARRAY['device_group'::text, 'user_group'::text])),
    CONSTRAINT user_roles_scope_pair_or_neither
        CHECK ((scope_kind IS NULL) = (scope_id IS NULL))
);

CREATE INDEX idx_user_roles_user_id ON public.user_roles USING btree (user_id);
CREATE INDEX idx_user_roles_role_id ON public.user_roles USING btree (role_id);
CREATE INDEX user_roles_scope_lookup
    ON public.user_roles USING btree (scope_kind, scope_id) WHERE (scope_id IS NOT NULL);
CREATE UNIQUE INDEX user_roles_scoped_unique
    ON public.user_roles USING btree (user_id, role_id, scope_kind, scope_id) WHERE (scope_id IS NOT NULL);
CREATE UNIQUE INDEX user_roles_unscoped_unique
    ON public.user_roles USING btree (user_id, role_id) WHERE (scope_id IS NULL);

CREATE TABLE public.user_group_roles (
    grant_id    text PRIMARY KEY,
    group_id    text NOT NULL REFERENCES public.user_groups(id) ON DELETE CASCADE,
    role_id     text NOT NULL REFERENCES public.roles(id),
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    assigned_by text DEFAULT ''::text NOT NULL,
    scope_kind  text,
    scope_id    text,
    CONSTRAINT user_group_roles_scope_kind_valid
        CHECK (scope_kind IS NULL OR scope_kind = ANY (ARRAY['device_group'::text, 'user_group'::text])),
    CONSTRAINT user_group_roles_scope_pair_or_neither
        CHECK ((scope_kind IS NULL) = (scope_id IS NULL))
);

CREATE INDEX idx_user_group_roles_role ON public.user_group_roles USING btree (role_id);
CREATE INDEX user_group_roles_scope_lookup
    ON public.user_group_roles USING btree (scope_kind, scope_id) WHERE (scope_id IS NOT NULL);
CREATE UNIQUE INDEX user_group_roles_scoped_unique
    ON public.user_group_roles USING btree (group_id, role_id, scope_kind, scope_id) WHERE (scope_id IS NOT NULL);
CREATE UNIQUE INDEX user_group_roles_unscoped_unique
    ON public.user_group_roles USING btree (group_id, role_id) WHERE (scope_id IS NULL);

CREATE TABLE public.identity_providers (
    id                      text PRIMARY KEY,
    name                    text NOT NULL,
    slug                    text NOT NULL,
    provider_type           text DEFAULT 'oidc'::text NOT NULL,
    enabled                 boolean DEFAULT true NOT NULL,
    client_id               text NOT NULL,
    -- AES-256-GCM ciphertext, AAD-bound to this provider row.
    client_secret_encrypted text DEFAULT ''::text NOT NULL,
    issuer_url              text NOT NULL,
    authorization_url       text DEFAULT ''::text NOT NULL,
    token_url               text DEFAULT ''::text NOT NULL,
    userinfo_url            text DEFAULT ''::text NOT NULL,
    scopes                  text[] DEFAULT '{}'::text[] NOT NULL,
    auto_create_users       boolean DEFAULT false NOT NULL,
    auto_link_by_email      boolean DEFAULT false NOT NULL,
    -- Whether an email claim from this provider may be treated as
    -- verified. Off by default: linking by an unverified email is an
    -- account-takeover path.
    trust_email_assertions  boolean DEFAULT false NOT NULL,
    default_role_id         text DEFAULT ''::text NOT NULL,
    attribute_mapping       jsonb DEFAULT '{}'::jsonb NOT NULL,
    group_claim             text DEFAULT ''::text NOT NULL,
    group_mapping           jsonb DEFAULT '{}'::jsonb NOT NULL,
    scim_enabled            boolean DEFAULT false NOT NULL,
    -- Non-reversible hash of the SCIM bearer token.
    scim_token_hash         text DEFAULT ''::text NOT NULL,
    created_at              timestamp with time zone DEFAULT now() NOT NULL,
    created_by              text DEFAULT ''::text NOT NULL,
    updated_at              timestamp with time zone DEFAULT now() NOT NULL,
    is_deleted              boolean DEFAULT false NOT NULL
);

CREATE UNIQUE INDEX idx_identity_providers_slug
    ON public.identity_providers USING btree (slug) WHERE (is_deleted = false);

CREATE TABLE public.identity_links (
    id             text PRIMARY KEY,
    user_id        text NOT NULL REFERENCES public.users(id),
    provider_id    text NOT NULL REFERENCES public.identity_providers(id),
    external_id    text NOT NULL,
    external_email text DEFAULT ''::text NOT NULL,
    external_name  text DEFAULT ''::text NOT NULL,
    linked_at      timestamp with time zone DEFAULT now() NOT NULL,
    last_login_at  timestamp with time zone
);

CREATE INDEX idx_identity_links_user ON public.identity_links USING btree (user_id);
-- One external subject maps to at most one local user, and a user has
-- at most one identity per provider. Both directions are enforced so a
-- second link cannot be used to hijack an existing account.
CREATE UNIQUE INDEX idx_identity_links_provider_external
    ON public.identity_links USING btree (provider_id, external_id);
CREATE UNIQUE INDEX idx_identity_links_user_provider
    ON public.identity_links USING btree (user_id, provider_id);

CREATE TABLE public.scim_group_mapping (
    id                text PRIMARY KEY,
    provider_id       text NOT NULL REFERENCES public.identity_providers(id),
    scim_group_id     text NOT NULL,
    scim_display_name text DEFAULT ''::text NOT NULL,
    user_group_id     text NOT NULL REFERENCES public.user_groups(id),
    created_at        timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX idx_scim_group_mapping_provider ON public.scim_group_mapping USING btree (provider_id);
CREATE INDEX idx_scim_group_mapping_user_group ON public.scim_group_mapping USING btree (user_group_id);
CREATE UNIQUE INDEX idx_scim_group_mapping_provider_scim
    ON public.scim_group_mapping USING btree (provider_id, scim_group_id);

-- One in-flight OIDC authorization-code exchange, pinning the nonce,
-- PKCE verifier and redirect URI for that attempt. The row is consumed
-- (read and deleted in one statement) on callback, so a captured state
-- token cannot be replayed.
CREATE TABLE public.auth_states (
    state         text PRIMARY KEY,
    provider_id   text NOT NULL REFERENCES public.identity_providers(id),
    nonce         text DEFAULT ''::text NOT NULL,
    code_verifier text DEFAULT ''::text NOT NULL,
    redirect_uri  text DEFAULT ''::text NOT NULL,
    created_at    timestamp with time zone DEFAULT now() NOT NULL,
    expires_at    timestamp with time zone NOT NULL
);

CREATE INDEX idx_auth_states_expires ON public.auth_states USING btree (expires_at);

-- Revoked JWT ids. Rows are bounded by the token's own expiry: once a
-- token can no longer validate, its revocation row is dead weight.
CREATE TABLE public.revoked_tokens (
    jti        text PRIMARY KEY,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE INDEX idx_revoked_tokens_expires ON public.revoked_tokens USING btree (expires_at);

-- Device-enrollment and API tokens. Only the hash of the value is
-- stored; the token is shown once at creation and never recoverable.
-- max_uses/current_uses back the consume-once conditional write.
CREATE TABLE public.tokens (
    id           text PRIMARY KEY,
    value_hash   text NOT NULL UNIQUE,
    name         text DEFAULT ''::text NOT NULL,
    one_time     boolean DEFAULT false NOT NULL,
    max_uses     integer DEFAULT 0 NOT NULL,
    current_uses integer DEFAULT 0 NOT NULL,
    expires_at   timestamp with time zone,
    created_at   timestamp with time zone,
    created_by   text DEFAULT ''::text NOT NULL,
    owner_id     text REFERENCES public.users(id) ON DELETE CASCADE,
    disabled     boolean DEFAULT false NOT NULL,
    is_deleted   boolean DEFAULT false NOT NULL
);

CREATE INDEX idx_tokens_owner ON public.tokens USING btree (owner_id);

-- ===========================================================================
-- Devices and fleet
-- ===========================================================================

CREATE TABLE public.devices (
    id                         text PRIMARY KEY,
    hostname                   text DEFAULT ''::text NOT NULL,
    agent_version              text DEFAULT ''::text NOT NULL,
    -- Dedicated X25519 recipient key generated by the agent. Control uses
    -- it only for control-to-agent secret-field sealing.
    agent_sealing_public_key   bytea NOT NULL,
    -- Fingerprint of the device's current leaf certificate. Unique, so
    -- one certificate can authenticate exactly one device.
    cert_fingerprint           text UNIQUE,
    cert_not_after             timestamp with time zone,
    registered_at              timestamp with time zone,
    last_seen_at               timestamp with time zone,
    registration_token_id      text,
    is_deleted                 boolean DEFAULT false NOT NULL,
    sync_interval_minutes      integer DEFAULT 0 NOT NULL,
    inventory_interval_minutes integer DEFAULT 0 NOT NULL,
    compliance_status          integer DEFAULT 0 NOT NULL,
    compliance_checked_at      timestamp with time zone,
    compliance_total           integer DEFAULT 0 NOT NULL,
    compliance_passing         integer DEFAULT 0 NOT NULL,
    CONSTRAINT devices_agent_sealing_public_key_length
        CHECK (octet_length(agent_sealing_public_key) = 32)
);

CREATE TABLE public.device_labels (
    device_id text NOT NULL REFERENCES public.devices(id) ON DELETE CASCADE,
    key       text NOT NULL,
    value     text NOT NULL,
    PRIMARY KEY (device_id, key)
);

CREATE INDEX idx_device_labels_key_value ON public.device_labels USING btree (key, value);

CREATE TABLE public.device_groups (
    id                         text PRIMARY KEY,
    name                       text NOT NULL,
    description                text DEFAULT ''::text NOT NULL,
    member_count               integer DEFAULT 0 NOT NULL,
    created_at                 timestamp with time zone,
    created_by                 text DEFAULT ''::text NOT NULL,
    is_deleted                 boolean DEFAULT false NOT NULL,
    is_dynamic                 boolean DEFAULT false NOT NULL,
    dynamic_query              text,
    sync_interval_minutes      integer DEFAULT 0 NOT NULL,
    inventory_interval_minutes integer DEFAULT 0 NOT NULL,
    maintenance_window         jsonb DEFAULT '{}'::jsonb NOT NULL
);

CREATE TABLE public.device_group_members (
    group_id  text NOT NULL,
    device_id text NOT NULL,
    added_at  timestamp with time zone,
    PRIMARY KEY (group_id, device_id)
);

CREATE TABLE public.device_assigned_users (
    device_id   text NOT NULL,
    user_id     text NOT NULL,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    assigned_by text DEFAULT ''::text NOT NULL,
    PRIMARY KEY (device_id, user_id)
);

CREATE INDEX idx_device_assigned_users_user ON public.device_assigned_users USING btree (user_id);

CREATE TABLE public.device_assigned_groups (
    device_id   text NOT NULL,
    group_id    text NOT NULL,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    assigned_by text DEFAULT ''::text NOT NULL,
    PRIMARY KEY (device_id, group_id)
);

CREATE INDEX idx_device_assigned_groups_group ON public.device_assigned_groups USING btree (group_id);

CREATE TABLE public.device_inventory (
    device_id    text NOT NULL,
    table_name   text NOT NULL,
    rows         jsonb DEFAULT '[]'::jsonb NOT NULL,
    collected_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (device_id, table_name)
);

CREATE INDEX idx_device_inventory_device ON public.device_inventory USING btree (device_id);

CREATE TABLE public.osquery_results (
    query_id     text PRIMARY KEY,
    device_id    text NOT NULL,
    table_name   text NOT NULL,
    completed    boolean DEFAULT false NOT NULL,
    success      boolean DEFAULT false NOT NULL,
    error        text DEFAULT ''::text NOT NULL,
    rows         jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at   timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone
);

CREATE INDEX idx_osquery_results_device ON public.osquery_results USING btree (device_id);

CREATE TABLE public.log_query_results (
    query_id     text PRIMARY KEY,
    device_id    text NOT NULL,
    completed    boolean DEFAULT false NOT NULL,
    success      boolean DEFAULT false NOT NULL,
    error        text DEFAULT ''::text NOT NULL,
    logs         text DEFAULT ''::text NOT NULL,
    created_at   timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone
);

CREATE INDEX idx_log_query_results_device ON public.log_query_results USING btree (device_id);
CREATE INDEX idx_log_query_results_completed ON public.log_query_results USING btree (completed, created_at);

CREATE TABLE public.security_alerts (
    alert_id        text PRIMARY KEY,
    device_id       text NOT NULL,
    alert_type      text NOT NULL,
    message         text NOT NULL,
    details         jsonb,
    raised_at       timestamp with time zone NOT NULL,
    acknowledged    boolean DEFAULT false NOT NULL,
    acknowledged_at timestamp with time zone,
    acknowledged_by text,
    created_at      timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX idx_security_alerts_device
    ON public.security_alerts USING btree (device_id, acknowledged, raised_at DESC);
CREATE INDEX idx_security_alerts_type
    ON public.security_alerts USING btree (alert_type, raised_at DESC);
CREATE INDEX idx_security_alerts_unack
    ON public.security_alerts USING btree (acknowledged, raised_at DESC) WHERE (acknowledged = false);

CREATE TABLE public.terminal_sessions (
    session_id      text PRIMARY KEY,
    device_id       text NOT NULL,
    user_id         text NOT NULL,
    tty_user        text NOT NULL,
    started_at      timestamp with time zone NOT NULL,
    stopped_at      timestamp with time zone,
    exit_reason     text,
    exit_code       integer,
    terminated_by   text,
    -- Recorded operator keystrokes, capped; input_truncated says the
    -- cap was hit so a short recording is never mistaken for a
    -- complete one.
    input           bytea DEFAULT '\x'::bytea NOT NULL,
    input_truncated boolean DEFAULT false NOT NULL,
    last_sequence   bigint DEFAULT 0 NOT NULL,
    chunk_count     integer DEFAULT 0 NOT NULL,
    cols            integer DEFAULT 0 NOT NULL,
    rows            integer DEFAULT 0 NOT NULL
);

CREATE INDEX idx_terminal_sessions_started ON public.terminal_sessions USING btree (started_at DESC);
CREATE INDEX idx_terminal_sessions_device_started
    ON public.terminal_sessions USING btree (device_id, started_at DESC);
CREATE INDEX idx_terminal_sessions_user_started
    ON public.terminal_sessions USING btree (user_id, started_at DESC);

-- Agent-certificate revocation. Consulted with a primary-key lookup on
-- every mTLS handshake, so it must stay an index probe and never a
-- scan. A row is dead once not_after has passed: the certificate can
-- no longer authenticate anything.
CREATE TABLE public.revoked_certificates (
    fingerprint text PRIMARY KEY,
    revoked_at  timestamp with time zone DEFAULT now() NOT NULL,
    not_after   timestamp with time zone NOT NULL,
    reason      text DEFAULT ''::text NOT NULL
);

CREATE INDEX revoked_certificates_not_after_idx ON public.revoked_certificates USING btree (not_after);

-- Rotated local-administrator passwords. `password` holds AES-256-GCM
-- ciphertext, AAD-bound to the device and action.
CREATE TABLE public.lps_passwords (
    id              text PRIMARY KEY,
    device_id       text NOT NULL,
    action_id       text NOT NULL,
    username        text NOT NULL,
    password        text NOT NULL,
    rotated_at      timestamp with time zone NOT NULL,
    rotation_reason text DEFAULT 'scheduled'::text NOT NULL,
    is_current      boolean DEFAULT true NOT NULL,
    created_at      timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX idx_lps_passwords_device ON public.lps_passwords USING btree (device_id, is_current);
CREATE INDEX idx_lps_passwords_action_device ON public.lps_passwords USING btree (action_id, device_id);
CREATE INDEX idx_lps_passwords_username
    ON public.lps_passwords USING btree (device_id, action_id, username, is_current);

-- Rotated LUKS passphrases. `passphrase` holds AES-256-GCM ciphertext,
-- AAD-bound to the device, action and device path. Superseded rows are
-- kept (is_current = false) because recovery may need the passphrase
-- that was in place at an earlier point.
CREATE TABLE public.luks_keys (
    id                text PRIMARY KEY,
    device_id         text NOT NULL,
    action_id         text NOT NULL,
    device_path       text NOT NULL,
    passphrase        text NOT NULL,
    rotated_at        timestamp with time zone NOT NULL,
    rotation_reason   text DEFAULT 'scheduled'::text NOT NULL,
    is_current        boolean DEFAULT true NOT NULL,
    created_at        timestamp with time zone DEFAULT now() NOT NULL,
    revocation_status text,
    revocation_error  text,
    revocation_at     timestamp with time zone
);

CREATE INDEX idx_luks_keys_device ON public.luks_keys USING btree (device_id, is_current);
CREATE INDEX idx_luks_keys_action_device ON public.luks_keys USING btree (action_id, device_id);
CREATE INDEX idx_luks_keys_current
    ON public.luks_keys USING btree (device_id, action_id, device_path, is_current);

-- One-time LUKS enrollment tokens. `token` is the non-reversible hash;
-- `used` backs the consume-once conditional write.
CREATE TABLE public.luks_tokens (
    id         text PRIMARY KEY,
    device_id  text NOT NULL,
    action_id  text NOT NULL,
    token      text NOT NULL UNIQUE,
    min_length integer DEFAULT 16 NOT NULL,
    complexity integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used       boolean DEFAULT false NOT NULL
);

CREATE INDEX idx_luks_tokens_token ON public.luks_tokens USING btree (token) WHERE (NOT used);

-- ===========================================================================
-- Authoring: Definition -> ActionSet -> Action
-- ===========================================================================

CREATE TABLE public.actions (
    id               text PRIMARY KEY,
    name             text NOT NULL,
    description      text,
    action_type      integer NOT NULL,
    desired_state    integer DEFAULT 0 NOT NULL,
    params           jsonb DEFAULT '{}'::jsonb NOT NULL,
    -- Canonical byte encoding of params, used for output
    -- deduplication (skip_if_unchanged) so equivalent params that
    -- differ only in JSON key order do not look like a change.
    params_canonical bytea,
    timeout_seconds  integer DEFAULT 0 NOT NULL,
    schedule         jsonb,
    is_system        boolean DEFAULT false NOT NULL,
    created_at       timestamp with time zone,
    created_by       text DEFAULT ''::text NOT NULL,
    updated_at       timestamp with time zone,
    is_deleted       boolean DEFAULT false NOT NULL
);

CREATE TABLE public.action_sets (
    id           text PRIMARY KEY,
    name         text NOT NULL,
    description  text DEFAULT ''::text NOT NULL,
    member_count integer DEFAULT 0 NOT NULL,
    -- Sets keep independent schedules and failure policies, which is
    -- why assigning a Definition produces one manifest per set.
    schedule     jsonb DEFAULT '{}'::jsonb NOT NULL,
    on_failure   integer DEFAULT 0 NOT NULL CHECK (on_failure IN (0, 1)),
    created_at   timestamp with time zone,
    created_by   text DEFAULT ''::text NOT NULL,
    updated_at   timestamp with time zone,
    is_deleted   boolean DEFAULT false NOT NULL
);

CREATE TABLE public.action_set_members (
    set_id     text NOT NULL,
    action_id  text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    added_at   timestamp with time zone,
    PRIMARY KEY (set_id, action_id)
);

CREATE TABLE public.definitions (
    id           text PRIMARY KEY,
    name         text NOT NULL,
    description  text DEFAULT ''::text NOT NULL,
    member_count integer DEFAULT 0 NOT NULL,
    schedule     jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at   timestamp with time zone,
    created_by   text DEFAULT ''::text NOT NULL,
    updated_at   timestamp with time zone,
    is_deleted   boolean DEFAULT false NOT NULL
);

CREATE TABLE public.definition_members (
    definition_id text NOT NULL,
    action_set_id text NOT NULL,
    sort_order    integer DEFAULT 0 NOT NULL,
    added_at      timestamp with time zone,
    PRIMARY KEY (definition_id, action_set_id)
);

CREATE TABLE public.assignments (
    id          text PRIMARY KEY,
    source_type text NOT NULL,
    source_id   text NOT NULL,
    target_type text NOT NULL,
    target_id   text NOT NULL,
    sort_order  integer DEFAULT 0 NOT NULL,
    mode        integer DEFAULT 0 NOT NULL,
    created_at  timestamp with time zone,
    created_by  text DEFAULT ''::text NOT NULL,
    is_deleted  boolean DEFAULT false NOT NULL,
    UNIQUE (source_type, source_id, target_type, target_id)
);

CREATE TABLE public.user_selections (
    id          text PRIMARY KEY,
    device_id   text NOT NULL,
    source_type text NOT NULL,
    source_id   text NOT NULL,
    selected    boolean DEFAULT false NOT NULL,
    updated_at  timestamp with time zone DEFAULT now() NOT NULL,
    created_by  text DEFAULT ''::text NOT NULL,
    UNIQUE (device_id, source_type, source_id)
);

CREATE INDEX idx_user_selections_device ON public.user_selections USING btree (device_id);

CREATE TABLE public.executions (
    id               text PRIMARY KEY,
    device_id        text NOT NULL,
    action_id        text,
    action_type      integer NOT NULL,
    desired_state    integer DEFAULT 0 NOT NULL,
    params           jsonb DEFAULT '{}'::jsonb NOT NULL,
    timeout_seconds  integer DEFAULT 0 NOT NULL,
    status           text NOT NULL,
    error            text,
    output           jsonb,
    detection_output jsonb,
    changed          boolean DEFAULT false NOT NULL,
    compliant        boolean DEFAULT false NOT NULL,
    created_at       timestamp with time zone,
    scheduled_for    timestamp with time zone,
    dispatched_at    timestamp with time zone,
    started_at       timestamp with time zone,
    completed_at     timestamp with time zone,
    duration_ms      bigint,
    created_by_type  text DEFAULT ''::text NOT NULL,
    created_by_id    text DEFAULT ''::text NOT NULL
);

CREATE INDEX idx_executions_device ON public.executions USING btree (device_id);
CREATE INDEX idx_executions_status ON public.executions USING btree (status);
CREATE INDEX idx_executions_device_status ON public.executions USING btree (device_id, status);

-- ===========================================================================
-- Compliance
-- ===========================================================================

CREATE TABLE public.compliance_policies (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    rule_count  integer DEFAULT 0 NOT NULL,
    created_at  timestamp with time zone,
    created_by  text DEFAULT ''::text NOT NULL,
    is_deleted  boolean DEFAULT false NOT NULL
);

CREATE TABLE public.compliance_policy_rules (
    policy_id          text NOT NULL,
    action_id          text NOT NULL,
    action_name        text DEFAULT ''::text NOT NULL,
    -- How long a failing rule may stay failing before the device is
    -- reported non-compliant.
    grace_period_hours integer DEFAULT 0 NOT NULL,
    added_at           timestamp with time zone,
    PRIMARY KEY (policy_id, action_id)
);

CREATE INDEX idx_compliance_policy_rules_action ON public.compliance_policy_rules USING btree (action_id);

CREATE TABLE public.compliance_policy_evaluation (
    device_id       text NOT NULL,
    policy_id       text NOT NULL,
    action_id       text NOT NULL,
    compliant       boolean DEFAULT false NOT NULL,
    -- When the rule first started failing; the grace period is
    -- measured from here, so a flapping rule cannot reset it.
    first_failed_at timestamp with time zone,
    status          integer DEFAULT 0 NOT NULL,
    checked_at      timestamp with time zone,
    PRIMARY KEY (device_id, policy_id, action_id)
);

CREATE INDEX idx_compliance_eval_device ON public.compliance_policy_evaluation USING btree (device_id);
CREATE INDEX idx_compliance_eval_policy ON public.compliance_policy_evaluation USING btree (policy_id);

CREATE TABLE public.compliance_results (
    device_id        text NOT NULL,
    action_id        text NOT NULL,
    action_name      text DEFAULT ''::text NOT NULL,
    compliant        boolean DEFAULT false NOT NULL,
    detection_output jsonb,
    checked_at       timestamp with time zone NOT NULL,
    PRIMARY KEY (device_id, action_id)
);

CREATE INDEX idx_compliance_device ON public.compliance_results USING btree (device_id);

-- ===========================================================================
-- Server settings
-- ===========================================================================

-- Singleton row, id = 'global'.
CREATE TABLE public.server_settings (
    id                        text PRIMARY KEY,
    user_provisioning_enabled boolean DEFAULT false NOT NULL,
    ssh_access_for_all        boolean DEFAULT false NOT NULL,
    updated_at                timestamp with time zone DEFAULT now() NOT NULL
);


-- ===========================================================================
-- Cross-domain foreign keys
-- ===========================================================================
--
-- Declared here rather than inline so a link may point at a table
-- defined further down the file.
--
-- Every clear, non-polymorphic link is constrained. Delete behaviour
-- follows ownership: a row that exists only as part of its parent
-- CASCADEs, and a row that merely names a catalogue entry does not, so
-- deleting something still in use is refused rather than silently
-- shredding history.
--
-- Three kinds of reference are deliberately left unconstrained:
--
--   * audit operation references. The audit log is evidence, not
--     state; live state must never hold an evidence row alive, and
--     audit retention must never be blocked by a delivery.
--   * polymorphic ids — assignments.source_id/target_id and
--     user_selections.source_id name a row in one of several tables
--     chosen by a sibling column, which no single foreign key can
--     express.
--   * historical actor ids — created_by, assigned_by, added_by,
--     acknowledged_by, terminated_by, executions.created_by_id. These
--     record who did something. Constraining them would make deleting
--     an actor either impossible or a rewrite of what happened.

-- Group membership and assignment exist only for their endpoints.
ALTER TABLE ONLY public.device_group_members
    ADD CONSTRAINT device_group_members_group_id_fkey
        FOREIGN KEY (group_id) REFERENCES public.device_groups(id) ON DELETE CASCADE,
    ADD CONSTRAINT device_group_members_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;

-- device_assigned_groups.group_id is a USER group, not a device group:
-- assigning a device hands it to people, individually through
-- device_assigned_users and collectively through this table. Device
-- group membership is device_group_members above.
ALTER TABLE ONLY public.device_assigned_groups
    ADD CONSTRAINT device_assigned_groups_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE,
    ADD CONSTRAINT device_assigned_groups_group_id_fkey
        FOREIGN KEY (group_id) REFERENCES public.user_groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.device_assigned_users
    ADD CONSTRAINT device_assigned_users_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE,
    ADD CONSTRAINT device_assigned_users_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

-- Per-device collected data and session records. All of it describes
-- one device and is meaningless once that device is gone.
ALTER TABLE ONLY public.device_inventory
    ADD CONSTRAINT device_inventory_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.osquery_results
    ADD CONSTRAINT osquery_results_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.log_query_results
    ADD CONSTRAINT log_query_results_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.security_alerts
    ADD CONSTRAINT security_alerts_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;

-- A terminal session belongs to both its device and the operator who
-- opened it, and is personal state of that operator: erasing them
-- takes the recording with it. terminated_by stays unconstrained — it
-- names whoever stopped the session, which is history.
ALTER TABLE ONLY public.terminal_sessions
    ADD CONSTRAINT terminal_sessions_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE,
    ADD CONSTRAINT terminal_sessions_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

-- Rotated secrets follow their device. The action they were rotated by
-- is a catalogue entry, so deleting an action still referenced by
-- stored key material is refused: the material would become
-- unattributable, and it is the only copy.
ALTER TABLE ONLY public.lps_passwords
    ADD CONSTRAINT lps_passwords_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE,
    ADD CONSTRAINT lps_passwords_action_id_fkey
        FOREIGN KEY (action_id) REFERENCES public.actions(id);

ALTER TABLE ONLY public.luks_keys
    ADD CONSTRAINT luks_keys_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE,
    ADD CONSTRAINT luks_keys_action_id_fkey
        FOREIGN KEY (action_id) REFERENCES public.actions(id);

ALTER TABLE ONLY public.luks_tokens
    ADD CONSTRAINT luks_tokens_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE,
    ADD CONSTRAINT luks_tokens_action_id_fkey
        FOREIGN KEY (action_id) REFERENCES public.actions(id);

-- Authoring composition. A membership row is part of its container.
ALTER TABLE ONLY public.action_set_members
    ADD CONSTRAINT action_set_members_set_id_fkey
        FOREIGN KEY (set_id) REFERENCES public.action_sets(id) ON DELETE CASCADE,
    ADD CONSTRAINT action_set_members_action_id_fkey
        FOREIGN KEY (action_id) REFERENCES public.actions(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.definition_members
    ADD CONSTRAINT definition_members_definition_id_fkey
        FOREIGN KEY (definition_id) REFERENCES public.definitions(id) ON DELETE CASCADE,
    ADD CONSTRAINT definition_members_action_set_id_fkey
        FOREIGN KEY (action_set_id) REFERENCES public.action_sets(id) ON DELETE CASCADE;

-- Compliance rules and results are derived from their policy, device
-- and action, and none of them outlive those.
ALTER TABLE ONLY public.compliance_policy_rules
    ADD CONSTRAINT compliance_policy_rules_policy_id_fkey
        FOREIGN KEY (policy_id) REFERENCES public.compliance_policies(id) ON DELETE CASCADE,
    ADD CONSTRAINT compliance_policy_rules_action_id_fkey
        FOREIGN KEY (action_id) REFERENCES public.actions(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.compliance_policy_evaluation
    ADD CONSTRAINT compliance_policy_evaluation_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE,
    ADD CONSTRAINT compliance_policy_evaluation_policy_id_fkey
        FOREIGN KEY (policy_id) REFERENCES public.compliance_policies(id) ON DELETE CASCADE,
    ADD CONSTRAINT compliance_policy_evaluation_action_id_fkey
        FOREIGN KEY (action_id) REFERENCES public.actions(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.compliance_results
    ADD CONSTRAINT compliance_results_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE,
    ADD CONSTRAINT compliance_results_action_id_fkey
        FOREIGN KEY (action_id) REFERENCES public.actions(id) ON DELETE CASCADE;

-- An execution is a device's own history. action_id is nullable
-- because an ad-hoc execution has no catalogue entry, and a deleted
-- action leaves the record standing with the link cleared.
ALTER TABLE ONLY public.executions
    ADD CONSTRAINT executions_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE,
    ADD CONSTRAINT executions_action_id_fkey
        FOREIGN KEY (action_id) REFERENCES public.actions(id) ON DELETE SET NULL;

-- A user's per-device opt-in.
ALTER TABLE ONLY public.user_selections
    ADD CONSTRAINT user_selections_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;

-- The certificate a device enrolled with.
ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_registration_token_id_fkey
        FOREIGN KEY (registration_token_id) REFERENCES public.tokens(id) ON DELETE SET NULL;

-- +goose Down

SELECT 1;
