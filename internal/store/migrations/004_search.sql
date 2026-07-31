-- Same-row full-text search vectors.
--
-- A search document is derived data, never authoritative state, and is
-- updated in the same transaction as the row it describes. A
-- GENERATED ... STORED column is that guarantee expressed by the
-- database: the vector is recomputed by the same statement that writes
-- the row, so it cannot drift, and deleting personal data removes its
-- searchable form atomically — there is no separate index row left
-- holding the deleted values.
--
-- Only same-row derivation belongs here. Cross-row documents — a
-- device's group names, a user's role names, an action's parent sets —
-- are assembled in application code; business cascades do not become
-- SQL triggers, and this file installs none.
--
-- The 'simple' configuration applies no stemming and no stop-word
-- list, which suits hostnames, emails, dotted identifiers and
-- mixed-language administrative text. The regconfig is passed
-- explicitly because to_tsvector(regconfig, text) is IMMUTABLE while
-- the one-argument form is only STABLE and cannot back a generated
-- column.

-- +goose Up

ALTER TABLE public.actions
    ADD COLUMN search_tsv tsvector GENERATED ALWAYS AS (
        to_tsvector('simple'::regconfig,
            coalesce(name, '') || ' ' || coalesce(description, ''))
    ) STORED;
CREATE INDEX actions_search_idx ON public.actions USING gin (search_tsv);

ALTER TABLE public.action_sets
    ADD COLUMN search_tsv tsvector GENERATED ALWAYS AS (
        to_tsvector('simple'::regconfig,
            coalesce(name, '') || ' ' || coalesce(description, ''))
    ) STORED;
CREATE INDEX action_sets_search_idx ON public.action_sets USING gin (search_tsv);

ALTER TABLE public.definitions
    ADD COLUMN search_tsv tsvector GENERATED ALWAYS AS (
        to_tsvector('simple'::regconfig,
            coalesce(name, '') || ' ' || coalesce(description, ''))
    ) STORED;
CREATE INDEX definitions_search_idx ON public.definitions USING gin (search_tsv);

ALTER TABLE public.compliance_policies
    ADD COLUMN search_tsv tsvector GENERATED ALWAYS AS (
        to_tsvector('simple'::regconfig,
            coalesce(name, '') || ' ' || coalesce(description, ''))
    ) STORED;
CREATE INDEX compliance_policies_search_idx ON public.compliance_policies USING gin (search_tsv);

ALTER TABLE public.devices
    ADD COLUMN search_tsv tsvector GENERATED ALWAYS AS (
        to_tsvector('simple'::regconfig,
            coalesce(hostname, '') || ' ' || coalesce(agent_version, ''))
    ) STORED;
CREATE INDEX devices_search_idx ON public.devices USING gin (search_tsv);

ALTER TABLE public.device_groups
    ADD COLUMN search_tsv tsvector GENERATED ALWAYS AS (
        to_tsvector('simple'::regconfig,
            coalesce(name, '') || ' ' || coalesce(description, ''))
    ) STORED;
CREATE INDEX device_groups_search_idx ON public.device_groups USING gin (search_tsv);

-- Personal data. Generated from the same row, so erasing the user
-- erases the searchable form in the same statement.
ALTER TABLE public.users
    ADD COLUMN search_tsv tsvector GENERATED ALWAYS AS (
        to_tsvector('simple'::regconfig,
            coalesce(email, '') || ' ' ||
            coalesce(display_name, '') || ' ' ||
            coalesce(given_name, '') || ' ' ||
            coalesce(family_name, '') || ' ' ||
            coalesce(preferred_username, '') || ' ' ||
            coalesce(linux_username, ''))
    ) STORED;
CREATE INDEX users_search_idx ON public.users USING gin (search_tsv);

ALTER TABLE public.user_groups
    ADD COLUMN search_tsv tsvector GENERATED ALWAYS AS (
        to_tsvector('simple'::regconfig,
            coalesce(name, '') || ' ' || coalesce(description, ''))
    ) STORED;
CREATE INDEX user_groups_search_idx ON public.user_groups USING gin (search_tsv);

ALTER TABLE public.executions
    ADD COLUMN search_tsv tsvector GENERATED ALWAYS AS (
        to_tsvector('simple'::regconfig,
            coalesce(id, '') || ' ' ||
            coalesce(device_id, '') || ' ' ||
            coalesce(action_id, '') || ' ' ||
            coalesce(status, ''))
    ) STORED;
CREATE INDEX executions_search_idx ON public.executions USING gin (search_tsv);

-- The audit operation stream. Only class-1 reference fields feed the
-- vector: no fingerprint and no sealed detail, so the search index
-- cannot become a side channel around the audit field classification.
-- Append-only is unaffected — a STORED generated column is computed by
-- the INSERT, never by an UPDATE.
ALTER TABLE public.audit_operations
    ADD COLUMN search_tsv tsvector GENERATED ALWAYS AS (
        to_tsvector('simple'::regconfig,
            coalesce(request_descriptor, '') || ' ' ||
            coalesce(operation_class, '') || ' ' ||
            coalesce(actor_type, '') || ' ' ||
            coalesce(actor_id, '') || ' ' ||
            coalesce(origin, '') || ' ' ||
            coalesce(authorization_outcome, '') || ' ' ||
            coalesce(result, ''))
    ) STORED;
CREATE INDEX audit_operations_search_idx ON public.audit_operations USING gin (search_tsv);

-- +goose Down

SELECT 1;
