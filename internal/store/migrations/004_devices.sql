-- Devices projection + the device_labels child table + per-device assignments, inventory, osquery results, security alerts, terminal sessions, log query results, and the LUKS / LPS secrets.
--
-- Wave H consolidation (tracker manchtools/power-manage-server#242):
-- replaces the 49 historical migrations with a small thematic set
-- containing the current schema. Existing deployments are broken on
-- purpose — fresh deploys run this set cleanly.
--
-- Generated from a pg_dump --schema-only of a testcontainer that
-- replayed every original migration, then split by domain. Order
-- between files is irrelevant for fresh setup; goose runs them in
-- numeric order.

-- +goose Up

--
-- Name: device_assigned_groups_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_assigned_groups_projection (
    device_id text NOT NULL,
    group_id text NOT NULL,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    assigned_by text DEFAULT ''::text NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: device_inventory; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_inventory (
    device_id text NOT NULL,
    table_name text NOT NULL,
    rows jsonb DEFAULT '[]'::jsonb NOT NULL,
    collected_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: device_labels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_labels (
    device_id text NOT NULL,
    key text NOT NULL,
    value text NOT NULL
);

--
-- Name: devices_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.devices_projection (
    id text NOT NULL,
    hostname text DEFAULT ''::text NOT NULL,
    agent_version text DEFAULT ''::text NOT NULL,
    cert_fingerprint text,
    cert_not_after timestamp with time zone,
    registered_at timestamp with time zone,
    last_seen_at timestamp with time zone,
    registration_token_id text,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL,
    sync_interval_minutes integer DEFAULT 0 NOT NULL,
    compliance_status integer DEFAULT 0 NOT NULL,
    compliance_checked_at timestamp with time zone,
    compliance_total integer DEFAULT 0 NOT NULL,
    compliance_passing integer DEFAULT 0 NOT NULL
);

--
-- Name: log_query_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.log_query_results (
    query_id text NOT NULL,
    device_id text NOT NULL,
    completed boolean DEFAULT false NOT NULL,
    success boolean DEFAULT false NOT NULL,
    error text DEFAULT ''::text NOT NULL,
    logs text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone
);

--
-- Name: lps_passwords_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lps_passwords_projection (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    device_id text NOT NULL,
    action_id text NOT NULL,
    username text NOT NULL,
    password text NOT NULL,
    rotated_at timestamp with time zone NOT NULL,
    rotation_reason text DEFAULT 'scheduled'::text NOT NULL,
    is_current boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: luks_keys_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.luks_keys_projection (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    device_id text NOT NULL,
    action_id text NOT NULL,
    device_path text NOT NULL,
    passphrase text NOT NULL,
    rotated_at timestamp with time zone NOT NULL,
    rotation_reason text DEFAULT 'scheduled'::text NOT NULL,
    is_current boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revocation_status text,
    revocation_error text,
    revocation_at timestamp with time zone,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: luks_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.luks_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    device_id text NOT NULL,
    action_id text NOT NULL,
    token text NOT NULL,
    min_length integer DEFAULT 16 NOT NULL,
    complexity integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used boolean DEFAULT false NOT NULL
);

--
-- Name: osquery_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.osquery_results (
    query_id text NOT NULL,
    device_id text NOT NULL,
    table_name text NOT NULL,
    completed boolean DEFAULT false NOT NULL,
    success boolean DEFAULT false NOT NULL,
    error text DEFAULT ''::text NOT NULL,
    rows jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone
);

--
-- Name: security_alerts_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.security_alerts_projection (
    event_id uuid NOT NULL,
    device_id text NOT NULL,
    alert_type text NOT NULL,
    message text NOT NULL,
    details jsonb,
    raised_at timestamp with time zone NOT NULL,
    acknowledged boolean DEFAULT false NOT NULL,
    acknowledged_at timestamp with time zone,
    acknowledged_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: terminal_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.terminal_sessions (
    session_id text NOT NULL,
    device_id text NOT NULL,
    user_id text NOT NULL,
    tty_user text NOT NULL,
    started_at timestamp with time zone NOT NULL,
    stopped_at timestamp with time zone,
    exit_reason text,
    exit_code integer,
    terminated_by text,
    input bytea DEFAULT '\x'::bytea NOT NULL,
    input_truncated boolean DEFAULT false NOT NULL,
    last_sequence bigint DEFAULT 0 NOT NULL,
    chunk_count integer DEFAULT 0 NOT NULL,
    cols integer DEFAULT 0 NOT NULL,
    rows integer DEFAULT 0 NOT NULL
);

--
-- Name: device_assigned_groups_projection device_assigned_groups_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_assigned_groups_projection
    ADD CONSTRAINT device_assigned_groups_projection_pkey PRIMARY KEY (device_id, group_id);

--
-- Name: device_inventory device_inventory_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_inventory
    ADD CONSTRAINT device_inventory_pkey PRIMARY KEY (device_id, table_name);

--
-- Name: device_labels device_labels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_labels
    ADD CONSTRAINT device_labels_pkey PRIMARY KEY (device_id, key);

--
-- Name: devices_projection devices_projection_cert_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices_projection
    ADD CONSTRAINT devices_projection_cert_fingerprint_key UNIQUE (cert_fingerprint);

--
-- Name: devices_projection devices_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices_projection
    ADD CONSTRAINT devices_projection_pkey PRIMARY KEY (id);

--
-- Name: log_query_results log_query_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_query_results
    ADD CONSTRAINT log_query_results_pkey PRIMARY KEY (query_id);

--
-- Name: lps_passwords_projection lps_passwords_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lps_passwords_projection
    ADD CONSTRAINT lps_passwords_projection_pkey PRIMARY KEY (id);

--
-- Name: luks_keys_projection luks_keys_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.luks_keys_projection
    ADD CONSTRAINT luks_keys_projection_pkey PRIMARY KEY (id);

--
-- Name: luks_tokens luks_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.luks_tokens
    ADD CONSTRAINT luks_tokens_pkey PRIMARY KEY (id);

--
-- Name: luks_tokens luks_tokens_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.luks_tokens
    ADD CONSTRAINT luks_tokens_token_key UNIQUE (token);

--
-- Name: osquery_results osquery_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.osquery_results
    ADD CONSTRAINT osquery_results_pkey PRIMARY KEY (query_id);

--
-- Name: security_alerts_projection security_alerts_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_alerts_projection
    ADD CONSTRAINT security_alerts_projection_pkey PRIMARY KEY (event_id);

--
-- Name: terminal_sessions terminal_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.terminal_sessions
    ADD CONSTRAINT terminal_sessions_pkey PRIMARY KEY (session_id);

--
-- Name: idx_device_assigned_groups_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_assigned_groups_group ON public.device_assigned_groups_projection USING btree (group_id);

--
-- Name: idx_device_assigned_users_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_assigned_users_user ON public.device_assigned_users_projection USING btree (user_id);

--
-- Name: idx_device_inventory_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_inventory_device ON public.device_inventory USING btree (device_id);

--
-- Name: idx_device_labels_key_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_labels_key_value ON public.device_labels USING btree (key, value);

--
-- Name: idx_log_query_results_completed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_query_results_completed ON public.log_query_results USING btree (completed, created_at);

--
-- Name: idx_log_query_results_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_query_results_device ON public.log_query_results USING btree (device_id);

--
-- Name: idx_lps_passwords_action_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_lps_passwords_action_device ON public.lps_passwords_projection USING btree (action_id, device_id);

--
-- Name: idx_lps_passwords_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_lps_passwords_device ON public.lps_passwords_projection USING btree (device_id, is_current);

--
-- Name: idx_lps_passwords_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_lps_passwords_username ON public.lps_passwords_projection USING btree (device_id, action_id, username, is_current);

--
-- Name: idx_luks_keys_action_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_luks_keys_action_device ON public.luks_keys_projection USING btree (action_id, device_id);

--
-- Name: idx_luks_keys_current; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_luks_keys_current ON public.luks_keys_projection USING btree (device_id, action_id, device_path, is_current);

--
-- Name: idx_luks_keys_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_luks_keys_device ON public.luks_keys_projection USING btree (device_id, is_current);

--
-- Name: idx_luks_tokens_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_luks_tokens_token ON public.luks_tokens USING btree (token) WHERE (NOT used);

--
-- Name: idx_osquery_results_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_osquery_results_device ON public.osquery_results USING btree (device_id);

--
-- Name: idx_security_alerts_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_alerts_device ON public.security_alerts_projection USING btree (device_id, acknowledged, raised_at DESC);

--
-- Name: idx_security_alerts_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_alerts_type ON public.security_alerts_projection USING btree (alert_type, raised_at DESC);

--
-- Name: idx_security_alerts_unack; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_alerts_unack ON public.security_alerts_projection USING btree (acknowledged, raised_at DESC) WHERE (acknowledged = false);

--
-- Name: idx_terminal_sessions_device_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_terminal_sessions_device_started ON public.terminal_sessions USING btree (device_id, started_at DESC);

--
-- Name: idx_terminal_sessions_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_terminal_sessions_started ON public.terminal_sessions USING btree (started_at DESC);

--
-- Name: idx_terminal_sessions_user_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_terminal_sessions_user_started ON public.terminal_sessions USING btree (user_id, started_at DESC);


-- +goose Down

-- Intentionally not reversible — see header.
SELECT 1;
