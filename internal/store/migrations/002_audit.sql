-- The append-only audit log.
--
-- The audit log is evidence, not state: no application behaviour is
-- reconstructed from it.
--
-- Each logical request or background operation receives one
-- `operation_id` and produces exactly one row in audit_operations
-- (actor, origin, request, authorization outcome, overall result) and
-- zero or more rows in audit_effects (affected resource, action,
-- before/after-safe fields, effect outcome). The operation row, its
-- initial effect rows and the state mutation commit in ONE
-- transaction. Work that fans out later — a dispatch that is acked
-- minutes afterwards, a result that arrives after a reconnect —
-- appends further effect rows carrying the SAME operation_id, so a
-- partial outcome stays attributable to the request that caused it
-- without pretending it was atomic with it.
--
-- ONE CHAIN, TWO ROW KINDS. audit_operations and audit_effects share a
-- single gapless per-stream chain. Every row of either kind carries
-- its own chain_seq, the prev_hash of whichever row precedes it in
-- that chain, and
--
--   row_hash = SHA-256(prev_hash || canonical content of THIS row)
--
-- A row's hash therefore covers only itself, and a late effect appends
-- at the current head with its own position. Nothing already
-- committed is ever recomputed or rewritten, which is what makes both
-- append-only enforcement and off-host anchoring possible: an anchor
-- taken before a late effect still authenticates its prefix
-- afterwards.
--
-- audit_chain_head holds the current tip. Appenders take a row lock on
-- it before assigning positions, which gives concurrent writers a
-- single total order and a chain_seq with no gaps.
--
-- Four operation classes exist so the log does not force every request
-- through one mutation template: MUTATION, SENSITIVE_READ,
-- REJECTED_AUTHENTICATION, BACKGROUND_WRITER.
--
-- APPEND-ONLY. UPDATE and TRUNCATE are rejected outright on the audit
-- tables; DELETE is rejected except through the one sanctioned
-- retention path described at the bottom of this file. The guards stop
-- application mistakes, not a host administrator with superuser
-- rights — a superuser can disable a trigger. The hash chain is the
-- second, detection-side guard that a disabled trigger cannot defeat,
-- and audit_chain_anchors is the third: a head published off-host
-- cannot be rewritten by whoever controls this database.
--
-- NO VALUE SLOT ACCEPTS A CREDENTIAL. Audit fields are exhaustively
-- classified, and every column that carries a VALUE is typed to one of
-- three classes rather than to a permissive string pattern:
--
--   class 1  durable references — ULID columns constrained to
--            Crockford base32, plus explicitly typed boolean state
--            flags and bigint counts. There is no generic string slot
--            for a field value, so a password, an API token or a hex
--            secret has nowhere to go: it is neither a 26-character
--            ULID nor a boolean nor an integer.
--   class 2  non-reversible evidence — every fingerprint has its own
--            named column constrained to exactly 64 lowercase hex
--            characters, paired with a kind token that says what was
--            digested. The column can hold a SHA-256 digest and
--            nothing else.
--   class 3  per-subject encrypted detail — sealed_detail bytea,
--            valid only together with the subject ULID whose DEK
--            seals it. Destroying that DEK erases the detail while
--            the non-personal attribution survives.
--
-- The only human-readable text in an effect row is the list of changed
-- FIELD NAMES, bounded to 40 lowercase identifier characters each.
-- Names, never values.
--
-- The operation row's text columns (request_descriptor,
-- authorization_detail, result_code) are code-derived constants — an
-- RPC full method, a permission constant, a status code name — taken
-- from descriptors and enums in Go, never from request input.
--
-- There is deliberately no free-text message, payload or note column:
-- a slot that accepts arbitrary text is a slot that will eventually
-- accept a secret.

-- +goose Up

-- ---------------------------------------------------------------------------
-- Field-name guard
-- ---------------------------------------------------------------------------

-- Every element of a changed-field list must be a bounded lowercase
-- identifier. Checking the elements individually is the point:
-- joining the array and matching the result would treat a separator
-- inside an element as an element boundary, so "two words" would pass
-- as two names. A CHECK cannot contain a subquery, which is why this
-- is a function.
-- +goose StatementBegin
CREATE FUNCTION public.audit_field_names_valid(names text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT NOT EXISTS (
        SELECT 1 FROM unnest(names) AS n
        WHERE n !~ '^[a-z][a-z0-9_]{0,39}$'
    );
$$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- Chain head
-- ---------------------------------------------------------------------------

-- One row per audit stream, holding the tip of that stream's chain.
-- Appenders lock this row first, so the chain order is a total order
-- even under concurrency and chain_seq has no gaps. This is ordinary
-- mutable state: the append-only guards below do not cover it, and it
-- holds no evidence the chain does not already carry.
CREATE TABLE public.audit_chain_head (
    stream     text PRIMARY KEY,
    head_hash  bytea NOT NULL,
    height     bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_chain_head_stream_token CHECK (stream ~ '^[a-z][a-z0-9_]{0,31}$'),
    CONSTRAINT audit_chain_head_hash_len CHECK (octet_length(head_hash) = 32),
    CONSTRAINT audit_chain_head_height_nonneg CHECK (height >= 0)
);

-- Genesis: 32 zero bytes at height 0.
INSERT INTO public.audit_chain_head (stream, head_hash, height)
VALUES ('control', '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea, 0);

-- ---------------------------------------------------------------------------
-- Operations
-- ---------------------------------------------------------------------------

CREATE TABLE public.audit_operations (
    -- Minted once per logical request or background operation and
    -- reused by everything that fans out from it.
    operation_id          text PRIMARY KEY,
    stream                text DEFAULT 'control'::text NOT NULL
                              REFERENCES public.audit_chain_head(stream),
    -- Position in the stream's chain, shared with audit_effects.
    chain_seq             bigint NOT NULL,

    operation_class       text NOT NULL,
    actor_type            text NOT NULL,
    -- class 1: the acting subject's ULID. Empty when the attempt never
    -- authenticated, which is exactly what REJECTED_AUTHENTICATION
    -- records.
    actor_id              text DEFAULT ''::text NOT NULL,
    -- class 2: digest of the presented certificate, key or token.
    actor_fingerprint     text DEFAULT ''::text NOT NULL,

    -- class 1: the surface the operation entered through.
    origin                text NOT NULL,
    -- class 2: digest of the peer address. The address is personal
    -- data and audit rows are never edited, so it is never stored in
    -- the clear; when the address itself is required evidence it goes
    -- into sealed_detail, where erasure can reach it.
    origin_fingerprint    text DEFAULT ''::text NOT NULL,
    -- class 1: fully-qualified RPC method, SCIM route or job kind.
    request_descriptor    text NOT NULL,

    authorization_outcome text NOT NULL,
    -- class 1: the permission constant or scope kind that decided it.
    authorization_detail  text DEFAULT ''::text NOT NULL,

    result                text NOT NULL,
    -- class 1: a status code name. Never an error message, which is
    -- unbounded text and routinely quotes its input.
    result_code           text DEFAULT ''::text NOT NULL,

    occurred_at           timestamp with time zone NOT NULL,

    -- class 3: detail that is only meaningful as its value, sealed
    -- under sealed_detail_subject's DEK.
    sealed_detail         bytea,
    sealed_detail_subject text,

    prev_hash             bytea NOT NULL,
    row_hash              bytea NOT NULL,

    CONSTRAINT audit_operations_id_ulid
        CHECK (operation_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT audit_operations_chain_seq_positive
        CHECK (chain_seq > 0),
    CONSTRAINT audit_operations_class_valid
        CHECK (operation_class = ANY (ARRAY[
            'MUTATION'::text,
            'SENSITIVE_READ'::text,
            'REJECTED_AUTHENTICATION'::text,
            'BACKGROUND_WRITER'::text])),
    CONSTRAINT audit_operations_actor_type_token
        CHECK (actor_type ~ '^[a-z][a-z0-9_]{0,31}$'),
    CONSTRAINT audit_operations_actor_id_ulid_or_empty
        CHECK (actor_id = '' OR actor_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT audit_operations_actor_fingerprint_sha256
        CHECK (actor_fingerprint = '' OR actor_fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_operations_origin_token
        CHECK (origin ~ '^[a-z][a-z0-9_]{0,31}$'),
    CONSTRAINT audit_operations_origin_fingerprint_sha256
        CHECK (origin_fingerprint = '' OR origin_fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_operations_request_descriptor_token
        CHECK (request_descriptor ~ '^[A-Za-z0-9_./:-]{1,200}$'),
    CONSTRAINT audit_operations_authorization_outcome_valid
        CHECK (authorization_outcome = ANY (ARRAY[
            'ALLOWED'::text, 'DENIED'::text, 'NOT_APPLICABLE'::text])),
    CONSTRAINT audit_operations_authorization_detail_token
        CHECK (authorization_detail ~ '^[A-Za-z0-9_.:/-]{0,128}$'),
    CONSTRAINT audit_operations_result_valid
        CHECK (result = ANY (ARRAY['SUCCESS'::text, 'FAILURE'::text, 'REJECTED'::text])),
    CONSTRAINT audit_operations_result_code_token
        CHECK (result_code ~ '^[A-Za-z0-9_.-]{0,64}$'),
    CONSTRAINT audit_operations_sealed_detail_paired
        CHECK ((sealed_detail IS NULL) = (sealed_detail_subject IS NULL)),
    CONSTRAINT audit_operations_sealed_subject_ulid
        CHECK (sealed_detail_subject IS NULL OR sealed_detail_subject ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT audit_operations_prev_hash_len CHECK (octet_length(prev_hash) = 32),
    CONSTRAINT audit_operations_row_hash_len CHECK (octet_length(row_hash) = 32)
);

CREATE UNIQUE INDEX audit_operations_stream_seq_key
    ON public.audit_operations USING btree (stream, chain_seq);
CREATE INDEX audit_operations_occurred_at_idx
    ON public.audit_operations USING btree (occurred_at DESC);
CREATE INDEX audit_operations_actor_idx
    ON public.audit_operations USING btree (actor_id, occurred_at DESC);
CREATE INDEX audit_operations_class_idx
    ON public.audit_operations USING btree (operation_class, occurred_at DESC);
CREATE INDEX audit_operations_descriptor_idx
    ON public.audit_operations USING btree (request_descriptor, occurred_at DESC);

-- ---------------------------------------------------------------------------
-- Effects
-- ---------------------------------------------------------------------------

CREATE TABLE public.audit_effects (
    effect_id             text PRIMARY KEY,
    operation_id          text NOT NULL REFERENCES public.audit_operations(operation_id),
    stream                text DEFAULT 'control'::text NOT NULL
                              REFERENCES public.audit_chain_head(stream),
    -- Position in the same chain the operation rows occupy. An effect
    -- appended long after its operation simply gets a later position;
    -- its operation's row is untouched.
    chain_seq             bigint NOT NULL,
    -- Position within the operation, in the order the effects were
    -- recorded. Distinct from chain_seq, which orders the stream.
    effect_seq            integer NOT NULL,

    -- class 1: what was affected and how.
    resource_type         text NOT NULL,
    resource_id           text NOT NULL,
    action                text NOT NULL,
    outcome               text NOT NULL,

    -- The NAMES of the fields this effect changed. Names only — the
    -- values live in the typed slots below or nowhere.
    changed_fields        text[] DEFAULT '{}'::text[] NOT NULL,

    -- class 1 value slots, one per representable kind. A field value
    -- is either a reference to another row (ULID), a state flag
    -- (boolean) or a count (bigint). Anything else is not a class-1
    -- value and belongs in sealed_detail.
    before_ref            text,
    after_ref             text,
    before_flag           boolean,
    after_flag            boolean,
    before_count          bigint,
    after_count           bigint,

    -- class 2: a digest of something that must be provable but never
    -- readable — a certificate fingerprint, an SSH key fingerprint, a
    -- token hash. evidence_kind names what was digested so the digest
    -- is interpretable without being reversible.
    evidence_kind         text DEFAULT ''::text NOT NULL,
    evidence_fingerprint  text DEFAULT ''::text NOT NULL,

    -- class 3: per-subject encrypted detail.
    sealed_detail         bytea,
    sealed_detail_subject text,

    occurred_at           timestamp with time zone NOT NULL,

    prev_hash             bytea NOT NULL,
    row_hash              bytea NOT NULL,

    CONSTRAINT audit_effects_id_ulid
        CHECK (effect_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT audit_effects_chain_seq_positive CHECK (chain_seq > 0),
    CONSTRAINT audit_effects_seq_nonneg CHECK (effect_seq >= 0),
    CONSTRAINT audit_effects_resource_type_token
        CHECK (resource_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT audit_effects_resource_id_ulid
        CHECK (resource_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT audit_effects_action_token
        CHECK (action ~ '^[A-Z][A-Z0-9_]{0,31}$'),
    CONSTRAINT audit_effects_outcome_valid
        CHECK (outcome = ANY (ARRAY['APPLIED'::text, 'REJECTED'::text, 'FAILED'::text])),
    -- Every element is checked on its own: a field name is a
    -- lowercase identifier of at most 40 characters, so it cannot be a
    -- 48-character token, and cannot contain punctuation, whitespace
    -- or upper case.
    CONSTRAINT audit_effects_changed_fields_identifiers
        CHECK (public.audit_field_names_valid(changed_fields)),
    CONSTRAINT audit_effects_before_ref_ulid
        CHECK (before_ref IS NULL OR before_ref ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT audit_effects_after_ref_ulid
        CHECK (after_ref IS NULL OR after_ref ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT audit_effects_evidence_kind_token
        CHECK (evidence_kind ~ '^[a-z][a-z0-9_]{0,31}$' OR evidence_kind = ''),
    CONSTRAINT audit_effects_evidence_fingerprint_sha256
        CHECK (evidence_fingerprint = '' OR evidence_fingerprint ~ '^[0-9a-f]{64}$'),
    -- A digest without a kind is uninterpretable and a kind without a
    -- digest is an empty claim; neither is admissible evidence.
    CONSTRAINT audit_effects_evidence_paired
        CHECK ((evidence_kind = '') = (evidence_fingerprint = '')),
    CONSTRAINT audit_effects_sealed_detail_paired
        CHECK ((sealed_detail IS NULL) = (sealed_detail_subject IS NULL)),
    CONSTRAINT audit_effects_sealed_subject_ulid
        CHECK (sealed_detail_subject IS NULL OR sealed_detail_subject ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT audit_effects_prev_hash_len CHECK (octet_length(prev_hash) = 32),
    CONSTRAINT audit_effects_row_hash_len CHECK (octet_length(row_hash) = 32)
);

CREATE UNIQUE INDEX audit_effects_stream_seq_key
    ON public.audit_effects USING btree (stream, chain_seq);
CREATE UNIQUE INDEX audit_effects_operation_seq_key
    ON public.audit_effects USING btree (operation_id, effect_seq);
CREATE INDEX audit_effects_resource_idx
    ON public.audit_effects USING btree (resource_type, resource_id, occurred_at DESC);
CREATE INDEX audit_effects_operation_idx
    ON public.audit_effects USING btree (operation_id);

-- ---------------------------------------------------------------------------
-- Off-host anchors
-- ---------------------------------------------------------------------------

-- A chain position published off-host. Verification compares the
-- locally recomputed chain against an anchor: whoever controls this
-- database can rewrite rows and recompute every hash after them, but
-- cannot change a value that is already held somewhere else. An anchor
-- authenticates the PREFIX up to its chain_seq; rows appended
-- afterwards, including late effects of already-anchored operations,
-- do not disturb it.
CREATE TABLE public.audit_chain_anchors (
    anchor_id    text PRIMARY KEY,
    stream       text NOT NULL REFERENCES public.audit_chain_head(stream),
    chain_seq    bigint NOT NULL,
    -- row_hash of the chain row at chain_seq.
    row_hash     bytea NOT NULL,
    captured_at  timestamp with time zone NOT NULL,
    -- class 1: bounded reference to the off-host location. Empty means
    -- captured but not yet published.
    external_ref text DEFAULT ''::text NOT NULL,

    CONSTRAINT audit_chain_anchors_id_ulid
        CHECK (anchor_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT audit_chain_anchors_seq_positive CHECK (chain_seq > 0),
    CONSTRAINT audit_chain_anchors_hash_len CHECK (octet_length(row_hash) = 32),
    CONSTRAINT audit_chain_anchors_external_ref_token
        CHECK (external_ref ~ '^[A-Za-z0-9_.:/-]{0,200}$')
);

CREATE UNIQUE INDEX audit_chain_anchors_stream_seq_key
    ON public.audit_chain_anchors USING btree (stream, chain_seq);
CREATE INDEX audit_chain_anchors_captured_idx
    ON public.audit_chain_anchors USING btree (stream, captured_at DESC);

-- ---------------------------------------------------------------------------
-- Retention checkpoints
-- ---------------------------------------------------------------------------

-- The boundary left behind when a chain prefix is deleted. Written in
-- the SAME transaction as that deletion, so a gap in chain_seq is
-- always explained by a checkpoint and never by a silent removal:
-- verification resumes from boundary_hash at resume_seq instead of
-- from genesis, and a gap with no checkpoint is a detected break.
--
-- archive_digest and archive_ref record that the prefix was archived
-- off-host BEFORE it was deleted; the deletion primitive refuses to
-- run without them.
CREATE TABLE public.audit_chain_checkpoints (
    checkpoint_id  text PRIMARY KEY,
    stream         text NOT NULL REFERENCES public.audit_chain_head(stream),
    -- Highest chain_seq removed by this retention pass.
    boundary_seq   bigint NOT NULL,
    -- row_hash of the chain row at boundary_seq: the prev_hash the
    -- first surviving row must chain from.
    boundary_hash  bytea NOT NULL,
    -- chain_seq of the first surviving chain row.
    resume_seq     bigint NOT NULL,
    deleted_rows   bigint NOT NULL,
    -- class 2: digest of the archived prefix, so the archive can be
    -- proven to be the thing that was deleted.
    archive_digest text NOT NULL,
    -- class 1: bounded reference to where the archive landed.
    archive_ref    text NOT NULL,
    archived_at    timestamp with time zone NOT NULL,
    created_at     timestamp with time zone NOT NULL,

    CONSTRAINT audit_chain_checkpoints_id_ulid
        CHECK (checkpoint_id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    CONSTRAINT audit_chain_checkpoints_boundary_positive CHECK (boundary_seq > 0),
    CONSTRAINT audit_chain_checkpoints_resume_after_boundary CHECK (resume_seq > boundary_seq),
    CONSTRAINT audit_chain_checkpoints_deleted_nonneg CHECK (deleted_rows >= 0),
    CONSTRAINT audit_chain_checkpoints_boundary_hash_len CHECK (octet_length(boundary_hash) = 32),
    CONSTRAINT audit_chain_checkpoints_archive_digest_sha256
        CHECK (archive_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_chain_checkpoints_archive_ref_token
        CHECK (archive_ref ~ '^[A-Za-z0-9_.:/-]{1,200}$')
);

CREATE UNIQUE INDEX audit_chain_checkpoints_stream_boundary_key
    ON public.audit_chain_checkpoints USING btree (stream, boundary_seq);
CREATE INDEX audit_chain_checkpoints_resume_idx
    ON public.audit_chain_checkpoints USING btree (stream, resume_seq);

-- ---------------------------------------------------------------------------
-- Append-only guards
-- ---------------------------------------------------------------------------

-- Unconditional guard: nothing may edit or remove these rows.
-- +goose StatementBegin
CREATE FUNCTION public.audit_block_mutation() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % is not permitted', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;
-- +goose StatementEnd

-- Guard for the two chain tables. UPDATE and TRUNCATE are always
-- refused. DELETE is refused unless BOTH retention conditions hold:
--
--   1. the transaction-scoped guard pm.audit_retention_active is 'on'.
--      The retention primitive sets it with SET LOCAL, so it is
--      cleared at COMMIT or ROLLBACK and can never leak into the next
--      user of a pooled connection;
--   2. the row lies at or below pm.audit_retention_up_to_seq, the
--      boundary that was archived. A retention pass therefore cannot
--      delete beyond the prefix it archived even with the guard set.
--
-- The paired checkpoint write is the third condition and is enforced
-- by the primitive, in the same transaction as the deletion. The
-- fourth is the closed-prefix rule: the primitive refuses a boundary
-- that would leave a surviving effect referencing a deleted
-- operation, and the foreign key from audit_effects to
-- audit_operations backs that refusal even if the check were
-- bypassed. A prefix is archived whole or not at all.
-- +goose StatementBegin
CREATE FUNCTION public.audit_chain_block_mutation() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    retention_active text := current_setting('pm.audit_retention_active', true);
    retention_up_to  text := current_setting('pm.audit_retention_up_to_seq', true);
BEGIN
    IF TG_OP = 'DELETE'
       AND retention_active = 'on'
       AND coalesce(retention_up_to, '') <> ''
       AND OLD.chain_seq <= retention_up_to::bigint
    THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION '% is append-only: % is not permitted', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER audit_operations_block_row_mutation
    BEFORE UPDATE OR DELETE ON public.audit_operations
    FOR EACH ROW EXECUTE FUNCTION public.audit_chain_block_mutation();

-- TRUNCATE fires no row triggers, so it needs its own statement-level
-- guard; it would otherwise bypass the chain_seq bound entirely.
CREATE TRIGGER audit_operations_block_truncate
    BEFORE TRUNCATE ON public.audit_operations
    FOR EACH STATEMENT EXECUTE FUNCTION public.audit_block_mutation();

CREATE TRIGGER audit_effects_block_row_mutation
    BEFORE UPDATE OR DELETE ON public.audit_effects
    FOR EACH ROW EXECUTE FUNCTION public.audit_chain_block_mutation();

CREATE TRIGGER audit_effects_block_truncate
    BEFORE TRUNCATE ON public.audit_effects
    FOR EACH STATEMENT EXECUTE FUNCTION public.audit_block_mutation();

-- An anchor is a published fact and a checkpoint explains a gap in the
-- chain. Editing or removing either would defeat the guard it exists
-- to provide, so both are append-only with no exemption at all.
CREATE TRIGGER audit_chain_anchors_block_row_mutation
    BEFORE UPDATE OR DELETE ON public.audit_chain_anchors
    FOR EACH ROW EXECUTE FUNCTION public.audit_block_mutation();

CREATE TRIGGER audit_chain_anchors_block_truncate
    BEFORE TRUNCATE ON public.audit_chain_anchors
    FOR EACH STATEMENT EXECUTE FUNCTION public.audit_block_mutation();

CREATE TRIGGER audit_chain_checkpoints_block_row_mutation
    BEFORE UPDATE OR DELETE ON public.audit_chain_checkpoints
    FOR EACH ROW EXECUTE FUNCTION public.audit_block_mutation();

CREATE TRIGGER audit_chain_checkpoints_block_truncate
    BEFORE TRUNCATE ON public.audit_chain_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION public.audit_block_mutation();

-- +goose Down

SELECT 1;
