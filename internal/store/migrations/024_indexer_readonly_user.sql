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

-- +goose StatementBegin
DO $$
DECLARE
    dbname TEXT := current_database();
    dbowner TEXT := (SELECT pg_catalog.pg_get_userbyid(d.datdba) FROM pg_catalog.pg_database d WHERE d.datname = dbname);
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO pm_readonly', dbname);
    EXECUTE 'GRANT USAGE ON SCHEMA public TO pm_readonly';
    EXECUTE 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO pm_readonly';
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON TABLES TO pm_readonly', dbowner);
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    dbname TEXT := current_database();
BEGIN
    REASSIGN OWNED BY pm_indexer TO CURRENT_USER;
    DROP ROLE IF EXISTS pm_indexer;
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM pm_readonly';
    EXECUTE 'REVOKE USAGE ON SCHEMA public FROM pm_readonly';
    EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM pm_readonly', dbname);
    DROP ROLE IF EXISTS pm_readonly;
END
$$;
-- +goose StatementEnd
