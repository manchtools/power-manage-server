-- Device groups, user groups, their member tables, dynamic-evaluation queues, generic assignments, and per-user availability selections.
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
-- Name: assignments_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assignments_projection (
    id text NOT NULL,
    source_type text NOT NULL,
    source_id text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    mode integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone,
    created_by text DEFAULT ''::text NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: device_group_members_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_group_members_projection (
    group_id text NOT NULL,
    device_id text NOT NULL,
    added_at timestamp with time zone,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: device_groups_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_groups_projection (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    member_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone,
    created_by text DEFAULT ''::text NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL,
    is_dynamic boolean DEFAULT false NOT NULL,
    dynamic_query text,
    sync_interval_minutes integer DEFAULT 0 NOT NULL,
    maintenance_window jsonb DEFAULT '{}'::jsonb NOT NULL
);

--
-- Name: dynamic_group_evaluation_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dynamic_group_evaluation_queue (
    group_id text NOT NULL,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    reason text
);

--
-- Name: dynamic_user_group_evaluation_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dynamic_user_group_evaluation_queue (
    group_id text NOT NULL,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    reason text
);

--
-- Name: user_group_members_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_group_members_projection (
    group_id text NOT NULL,
    user_id text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    added_by text DEFAULT ''::text NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: user_groups_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_groups_projection (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    member_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL,
    is_dynamic boolean DEFAULT false NOT NULL,
    dynamic_query text,
    maintenance_window jsonb DEFAULT '{}'::jsonb NOT NULL
);

--
-- Name: user_selections_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_selections_projection (
    id text NOT NULL,
    device_id text NOT NULL,
    source_type text NOT NULL,
    source_id text NOT NULL,
    selected boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: assignments_projection assignments_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assignments_projection
    ADD CONSTRAINT assignments_projection_pkey PRIMARY KEY (id);

--
-- Name: assignments_projection assignments_projection_source_type_source_id_target_type_ta_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assignments_projection
    ADD CONSTRAINT assignments_projection_source_type_source_id_target_type_ta_key UNIQUE (source_type, source_id, target_type, target_id);

--
-- Name: device_group_members_projection device_group_members_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_group_members_projection
    ADD CONSTRAINT device_group_members_projection_pkey PRIMARY KEY (group_id, device_id);

--
-- Name: device_groups_projection device_groups_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_groups_projection
    ADD CONSTRAINT device_groups_projection_pkey PRIMARY KEY (id);

--
-- Name: dynamic_group_evaluation_queue dynamic_group_evaluation_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dynamic_group_evaluation_queue
    ADD CONSTRAINT dynamic_group_evaluation_queue_pkey PRIMARY KEY (group_id);

--
-- Name: dynamic_user_group_evaluation_queue dynamic_user_group_evaluation_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dynamic_user_group_evaluation_queue
    ADD CONSTRAINT dynamic_user_group_evaluation_queue_pkey PRIMARY KEY (group_id);

--
-- Name: user_group_members_projection user_group_members_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_members_projection
    ADD CONSTRAINT user_group_members_projection_pkey PRIMARY KEY (group_id, user_id);

--
-- Name: user_groups_projection user_groups_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups_projection
    ADD CONSTRAINT user_groups_projection_pkey PRIMARY KEY (id);

--
-- Name: user_selections_projection user_selections_projection_device_id_source_type_source_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_selections_projection
    ADD CONSTRAINT user_selections_projection_device_id_source_type_source_id_key UNIQUE (device_id, source_type, source_id);

--
-- Name: user_selections_projection user_selections_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_selections_projection
    ADD CONSTRAINT user_selections_projection_pkey PRIMARY KEY (id);

--
-- Name: idx_user_group_members_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_group_members_user ON public.user_group_members_projection USING btree (user_id);

--
-- Name: idx_user_group_roles_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_group_roles_role ON public.user_group_roles_projection USING btree (role_id);

--
-- Name: idx_user_groups_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_user_groups_name ON public.user_groups_projection USING btree (name) WHERE (is_deleted = false);

--
-- Name: idx_user_selections_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_selections_device ON public.user_selections_projection USING btree (device_id);


-- +goose Down

-- Intentionally not reversible — see header.
SELECT 1;
