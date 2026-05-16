-- Actions, action sets, definitions, executions, the compliance projection family, and global server settings.
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
-- Name: action_set_members_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.action_set_members_projection (
    set_id text NOT NULL,
    action_id text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    added_at timestamp with time zone,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: action_sets_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.action_sets_projection (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    member_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone,
    created_by text DEFAULT ''::text NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone,
    schedule jsonb DEFAULT '{"interval_hours": 8}'::jsonb NOT NULL
);

--
-- Name: actions_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.actions_projection (
    id text NOT NULL,
    name text NOT NULL,
    description text,
    action_type integer DEFAULT 0 NOT NULL,
    params jsonb DEFAULT '{}'::jsonb NOT NULL,
    timeout_seconds integer DEFAULT 300 NOT NULL,
    created_at timestamp with time zone,
    created_by text DEFAULT ''::text NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL,
    signature bytea,
    params_canonical bytea,
    desired_state integer DEFAULT 0 NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone,
    schedule jsonb
);

--
-- Name: compliance_policies_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_policies_projection (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    rule_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone,
    created_by text DEFAULT ''::text NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: compliance_policy_evaluation_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_policy_evaluation_projection (
    device_id text NOT NULL,
    policy_id text NOT NULL,
    action_id text NOT NULL,
    compliant boolean DEFAULT false NOT NULL,
    first_failed_at timestamp with time zone,
    status integer DEFAULT 0 NOT NULL,
    checked_at timestamp with time zone,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: compliance_policy_rules_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_policy_rules_projection (
    policy_id text NOT NULL,
    action_id text NOT NULL,
    action_name text DEFAULT ''::text NOT NULL,
    grace_period_hours integer DEFAULT 0 NOT NULL,
    added_at timestamp with time zone,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: compliance_results_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_results_projection (
    device_id text NOT NULL,
    action_id text NOT NULL,
    action_name text DEFAULT ''::text NOT NULL,
    compliant boolean DEFAULT false NOT NULL,
    detection_output jsonb,
    checked_at timestamp with time zone DEFAULT now() NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: definition_members_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.definition_members_projection (
    definition_id text NOT NULL,
    action_set_id text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    added_at timestamp with time zone,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: definitions_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.definitions_projection (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    member_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone,
    created_by text DEFAULT ''::text NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone,
    schedule jsonb DEFAULT '{"interval_hours": 8}'::jsonb NOT NULL
);

--
-- Name: executions_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.executions_projection (
    id text NOT NULL,
    device_id text NOT NULL,
    action_id text,
    action_type integer DEFAULT 0 NOT NULL,
    desired_state integer DEFAULT 0 NOT NULL,
    params jsonb DEFAULT '{}'::jsonb NOT NULL,
    timeout_seconds integer DEFAULT 300 NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    error text,
    output jsonb,
    created_at timestamp with time zone,
    dispatched_at timestamp with time zone,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    duration_ms bigint,
    created_by_type text DEFAULT ''::text NOT NULL,
    created_by_id text DEFAULT ''::text NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL,
    changed boolean DEFAULT true NOT NULL,
    compliant boolean DEFAULT false NOT NULL,
    detection_output jsonb,
    scheduled_for timestamp with time zone
);

--
-- Name: server_settings_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.server_settings_projection (
    id text DEFAULT 'global'::text NOT NULL,
    user_provisioning_enabled boolean DEFAULT false NOT NULL,
    ssh_access_for_all boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: action_set_members_projection action_set_members_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_set_members_projection
    ADD CONSTRAINT action_set_members_projection_pkey PRIMARY KEY (set_id, action_id);

--
-- Name: action_sets_projection action_sets_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_sets_projection
    ADD CONSTRAINT action_sets_projection_pkey PRIMARY KEY (id);

--
-- Name: actions_projection actions_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actions_projection
    ADD CONSTRAINT actions_projection_pkey PRIMARY KEY (id);

--
-- Name: compliance_policies_projection compliance_policies_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policies_projection
    ADD CONSTRAINT compliance_policies_projection_pkey PRIMARY KEY (id);

--
-- Name: compliance_policy_evaluation_projection compliance_policy_evaluation_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policy_evaluation_projection
    ADD CONSTRAINT compliance_policy_evaluation_projection_pkey PRIMARY KEY (device_id, policy_id, action_id);

--
-- Name: compliance_policy_rules_projection compliance_policy_rules_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policy_rules_projection
    ADD CONSTRAINT compliance_policy_rules_projection_pkey PRIMARY KEY (policy_id, action_id);

--
-- Name: compliance_results_projection compliance_results_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_results_projection
    ADD CONSTRAINT compliance_results_projection_pkey PRIMARY KEY (device_id, action_id);

--
-- Name: definition_members_projection definition_members_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.definition_members_projection
    ADD CONSTRAINT definition_members_projection_pkey PRIMARY KEY (definition_id, action_set_id);

--
-- Name: definitions_projection definitions_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.definitions_projection
    ADD CONSTRAINT definitions_projection_pkey PRIMARY KEY (id);

--
-- Name: executions_projection executions_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.executions_projection
    ADD CONSTRAINT executions_projection_pkey PRIMARY KEY (id);

--
-- Name: server_settings_projection server_settings_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.server_settings_projection
    ADD CONSTRAINT server_settings_projection_pkey PRIMARY KEY (id);

--
-- Name: idx_compliance_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_compliance_device ON public.compliance_results_projection USING btree (device_id);

--
-- Name: idx_compliance_eval_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_compliance_eval_device ON public.compliance_policy_evaluation_projection USING btree (device_id);

--
-- Name: idx_compliance_eval_policy; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_compliance_eval_policy ON public.compliance_policy_evaluation_projection USING btree (policy_id);

--
-- Name: idx_compliance_policy_rules_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_compliance_policy_rules_action ON public.compliance_policy_rules_projection USING btree (action_id);

--
-- Name: idx_executions_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_device ON public.executions_projection USING btree (device_id);

--
-- Name: idx_executions_device_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_device_status ON public.executions_projection USING btree (device_id, status);

--
-- Name: idx_executions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_status ON public.executions_projection USING btree (status);


-- +goose Down

-- Intentionally not reversible — see header.
SELECT 1;
