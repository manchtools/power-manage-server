-- 012_idp_trust_email_assertions.sql
--
-- WS5 #2: add an explicit operator opt-in for delegating email-identity
-- assertion to an IdP. When false (the secure default), SCIM AutoLinkByEmail
-- must NOT bind an IdP-asserted email to a pre-existing LOCAL PASSWORD account
-- — that path is an account-takeover vector (an IdP/SCIM operator who can
-- assert any email could seize a local admin's account). When true, the
-- operator has knowingly delegated identity to this provider, so auto-link to
-- a local account is permitted.
--
-- identity_providers_projection is written by the Go projector
-- (internal/projectors/identity_provider*.go), so no PL/pgSQL trigger change is
-- needed; the column is read into store.IdentityProvider and consumed by the
-- SCIM createUser handler.

-- +goose Up
ALTER TABLE public.identity_providers_projection
    ADD COLUMN trust_email_assertions boolean DEFAULT false NOT NULL;

-- +goose Down
ALTER TABLE public.identity_providers_projection
    DROP COLUMN trust_email_assertions;
