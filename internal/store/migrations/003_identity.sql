-- Users, roles, tokens, identity providers, SCIM mappings, TOTP, OAuth auth states, refresh-token revocations, and the user_ssh_keys child table.
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
-- Name: auth_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_states (
    state text NOT NULL,
    provider_id text NOT NULL,
    nonce text DEFAULT ''::text NOT NULL,
    code_verifier text DEFAULT ''::text NOT NULL,
    redirect_uri text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

--
-- Name: device_assigned_users_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_assigned_users_projection (
    device_id text NOT NULL,
    user_id text NOT NULL,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    assigned_by text DEFAULT ''::text NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: identity_links_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_links_projection (
    id text NOT NULL,
    user_id text NOT NULL,
    provider_id text NOT NULL,
    external_id text NOT NULL,
    external_email text DEFAULT ''::text NOT NULL,
    external_name text DEFAULT ''::text NOT NULL,
    linked_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login_at timestamp with time zone,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: identity_providers_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_providers_projection (
    id text NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    provider_type text DEFAULT 'oidc'::text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    client_id text NOT NULL,
    client_secret_encrypted text DEFAULT ''::text NOT NULL,
    issuer_url text NOT NULL,
    authorization_url text DEFAULT ''::text NOT NULL,
    token_url text DEFAULT ''::text NOT NULL,
    userinfo_url text DEFAULT ''::text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    auto_create_users boolean DEFAULT false NOT NULL,
    auto_link_by_email boolean DEFAULT false NOT NULL,
    default_role_id text DEFAULT ''::text NOT NULL,
    attribute_mapping jsonb DEFAULT '{}'::jsonb NOT NULL,
    disable_password_for_linked boolean DEFAULT false NOT NULL,
    group_claim text DEFAULT ''::text NOT NULL,
    group_mapping jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL,
    scim_enabled boolean DEFAULT false NOT NULL,
    scim_token_hash text DEFAULT ''::text NOT NULL
);

--
-- Name: linux_uid_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.linux_uid_seq
    START WITH 10000
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: revoked_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.revoked_tokens (
    jti text NOT NULL,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

--
-- Name: roles_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles_projection (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    permissions text[] DEFAULT '{}'::text[] NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: scim_group_mapping_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scim_group_mapping_projection (
    id text NOT NULL,
    provider_id text NOT NULL,
    scim_group_id text NOT NULL,
    scim_display_name text DEFAULT ''::text NOT NULL,
    user_group_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: tokens_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tokens_projection (
    id text NOT NULL,
    value_hash text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    one_time boolean DEFAULT false NOT NULL,
    max_uses integer DEFAULT 0 NOT NULL,
    current_uses integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone,
    created_by text DEFAULT ''::text NOT NULL,
    disabled boolean DEFAULT false NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL,
    owner_id text
);

--
-- Name: totp_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.totp_projection (
    user_id text NOT NULL,
    secret_encrypted text NOT NULL,
    verified boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    backup_codes_hash text[] DEFAULT '{}'::text[] NOT NULL,
    backup_codes_used boolean[] DEFAULT '{}'::boolean[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: user_group_roles_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_group_roles_projection (
    group_id text NOT NULL,
    role_id text NOT NULL,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    assigned_by text DEFAULT ''::text NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: user_roles_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_roles_projection (
    user_id text NOT NULL,
    role_id text NOT NULL,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    assigned_by text DEFAULT ''::text NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL
);

--
-- Name: user_ssh_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_ssh_keys (
    user_id text NOT NULL,
    key_id text NOT NULL,
    public_key text,
    comment text,
    added_at timestamp with time zone NOT NULL
);

--
-- Name: users_projection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users_projection (
    id text NOT NULL,
    email text NOT NULL,
    password_hash text,
    role text DEFAULT 'user'::text NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    last_login_at timestamp with time zone,
    disabled boolean DEFAULT false NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    projection_version bigint DEFAULT 0 NOT NULL,
    session_version integer DEFAULT 0 NOT NULL,
    has_password boolean DEFAULT true NOT NULL,
    totp_enabled boolean DEFAULT false NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    given_name text DEFAULT ''::text NOT NULL,
    family_name text DEFAULT ''::text NOT NULL,
    preferred_username text DEFAULT ''::text NOT NULL,
    picture text DEFAULT ''::text NOT NULL,
    locale text DEFAULT ''::text NOT NULL,
    linux_username text DEFAULT ''::text NOT NULL,
    linux_uid integer DEFAULT 0 NOT NULL,
    ssh_access_enabled boolean DEFAULT false NOT NULL,
    ssh_allow_pubkey boolean DEFAULT true NOT NULL,
    ssh_allow_password boolean DEFAULT false NOT NULL,
    system_user_action_id text DEFAULT ''::text NOT NULL,
    system_ssh_action_id text DEFAULT ''::text NOT NULL,
    user_provisioning_enabled boolean DEFAULT false NOT NULL,
    system_tty_action_id text DEFAULT ''::text NOT NULL
);

--
-- Name: auth_states auth_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_states
    ADD CONSTRAINT auth_states_pkey PRIMARY KEY (state);

--
-- Name: device_assigned_users_projection device_assigned_users_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_assigned_users_projection
    ADD CONSTRAINT device_assigned_users_projection_pkey PRIMARY KEY (device_id, user_id);

--
-- Name: identity_links_projection identity_links_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_links_projection
    ADD CONSTRAINT identity_links_projection_pkey PRIMARY KEY (id);

--
-- Name: identity_providers_projection identity_providers_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_providers_projection
    ADD CONSTRAINT identity_providers_projection_pkey PRIMARY KEY (id);

--
-- Name: revoked_tokens revoked_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revoked_tokens
    ADD CONSTRAINT revoked_tokens_pkey PRIMARY KEY (jti);

--
-- Name: roles_projection roles_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles_projection
    ADD CONSTRAINT roles_projection_pkey PRIMARY KEY (id);

--
-- Name: scim_group_mapping_projection scim_group_mapping_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scim_group_mapping_projection
    ADD CONSTRAINT scim_group_mapping_projection_pkey PRIMARY KEY (id);

--
-- Name: tokens_projection tokens_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tokens_projection
    ADD CONSTRAINT tokens_projection_pkey PRIMARY KEY (id);

--
-- Name: tokens_projection tokens_projection_value_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tokens_projection
    ADD CONSTRAINT tokens_projection_value_hash_key UNIQUE (value_hash);

--
-- Name: totp_projection totp_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_projection
    ADD CONSTRAINT totp_projection_pkey PRIMARY KEY (user_id);

--
-- Name: user_group_roles_projection user_group_roles_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_roles_projection
    ADD CONSTRAINT user_group_roles_projection_pkey PRIMARY KEY (group_id, role_id);

--
-- Name: user_roles_projection user_roles_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles_projection
    ADD CONSTRAINT user_roles_projection_pkey PRIMARY KEY (user_id, role_id);

--
-- Name: user_ssh_keys user_ssh_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_ssh_keys
    ADD CONSTRAINT user_ssh_keys_pkey PRIMARY KEY (user_id, key_id);

--
-- Name: users_projection users_projection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_projection
    ADD CONSTRAINT users_projection_pkey PRIMARY KEY (id);

--
-- Name: idx_auth_states_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_states_expires ON public.auth_states USING btree (expires_at);

--
-- Name: idx_identity_links_provider_external; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_identity_links_provider_external ON public.identity_links_projection USING btree (provider_id, external_id);

--
-- Name: idx_identity_links_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_identity_links_user ON public.identity_links_projection USING btree (user_id);

--
-- Name: idx_identity_links_user_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_identity_links_user_provider ON public.identity_links_projection USING btree (user_id, provider_id);

--
-- Name: idx_identity_providers_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_identity_providers_slug ON public.identity_providers_projection USING btree (slug) WHERE (is_deleted = false);

--
-- Name: idx_revoked_tokens_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_revoked_tokens_expires ON public.revoked_tokens USING btree (expires_at);

--
-- Name: idx_scim_group_mapping_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scim_group_mapping_provider ON public.scim_group_mapping_projection USING btree (provider_id);

--
-- Name: idx_scim_group_mapping_provider_scim; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_scim_group_mapping_provider_scim ON public.scim_group_mapping_projection USING btree (provider_id, scim_group_id);

--
-- Name: idx_scim_group_mapping_user_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scim_group_mapping_user_group ON public.scim_group_mapping_projection USING btree (user_group_id);

--
-- Name: idx_tokens_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tokens_owner ON public.tokens_projection USING btree (owner_id);

--
-- Name: idx_user_roles_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_roles_role_id ON public.user_roles_projection USING btree (role_id);

--
-- Name: idx_user_roles_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_roles_user_id ON public.user_roles_projection USING btree (user_id);

--
-- Name: idx_user_ssh_keys_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_ssh_keys_user ON public.user_ssh_keys USING btree (user_id);

--
-- Name: idx_users_email_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_users_email_active ON public.users_projection USING btree (email) WHERE (is_deleted = false);


-- +goose Down

-- Intentionally not reversible — see header.
SELECT 1;
