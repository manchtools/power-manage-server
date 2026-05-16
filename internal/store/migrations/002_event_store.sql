-- The append-only events table — heart of the CQRS pipeline. Sequence + unique stream-version constraint enforce OCC at the SQL level.
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
-- Name: events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sequence_num bigint NOT NULL,
    stream_type text NOT NULL,
    stream_id text NOT NULL,
    stream_version integer NOT NULL,
    event_type text NOT NULL,
    data jsonb DEFAULT '{}'::jsonb NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    actor_type text DEFAULT ''::text NOT NULL,
    actor_id text DEFAULT ''::text NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: events_sequence_num_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.events_sequence_num_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: events_sequence_num_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.events_sequence_num_seq OWNED BY public.events.sequence_num;

--
-- Name: events sequence_num; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ALTER COLUMN sequence_num SET DEFAULT nextval('public.events_sequence_num_seq'::regclass);

--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (id);

--
-- Name: events events_sequence_num_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_sequence_num_key UNIQUE (sequence_num);

--
-- Name: events events_stream_type_stream_id_stream_version_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_stream_type_stream_id_stream_version_key UNIQUE (stream_type, stream_id, stream_version);

--
-- Name: idx_events_occurred_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_occurred_at ON public.events USING btree (occurred_at);

--
-- Name: idx_events_stream; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_stream ON public.events USING btree (stream_type, stream_id);

--
-- Name: idx_events_stream_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_stream_type ON public.events USING btree (stream_type);

--
-- Name: idx_events_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_type ON public.events USING btree (event_type);


-- +goose Down

-- Intentionally not reversible — see header.
SELECT 1;
