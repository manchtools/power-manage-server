-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pm_readonly') THEN
        CREATE ROLE pm_readonly NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pm_indexer') THEN
        CREATE ROLE pm_indexer LOGIN PASSWORD 'changeme_see_env' IN ROLE pm_readonly;
    END IF;
END
$$;
-- +goose StatementEnd

GRANT CONNECT ON DATABASE powermanage TO pm_readonly;
GRANT USAGE ON SCHEMA public TO pm_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO pm_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE powermanage IN SCHEMA public GRANT SELECT ON TABLES TO pm_readonly;

-- +goose Down
REASSIGN OWNED BY pm_indexer TO powermanage;
DROP ROLE IF EXISTS pm_indexer;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM pm_readonly;
REVOKE USAGE ON SCHEMA public FROM pm_readonly;
REVOKE CONNECT ON DATABASE powermanage FROM pm_readonly;
DROP ROLE IF EXISTS pm_readonly;
