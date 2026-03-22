#!/bin/bash
# Creates the read-only pm_indexer database user for the search indexer service.
# This script runs automatically on first PostgreSQL initialization via
# docker-entrypoint-initdb.d. For existing deployments, migration 024 handles
# role creation and the password must be set manually:
#   ALTER ROLE pm_indexer PASSWORD 'your_password';
set -e

if [ -z "$INDEXER_POSTGRES_PASSWORD" ]; then
    echo "WARN: INDEXER_POSTGRES_PASSWORD not set, skipping pm_indexer user creation"
    exit 0
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pm_readonly') THEN
            CREATE ROLE pm_readonly NOLOGIN;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pm_indexer') THEN
            CREATE ROLE pm_indexer LOGIN PASSWORD '${INDEXER_POSTGRES_PASSWORD}' IN ROLE pm_readonly;
        END IF;
    END
    \$\$;
    GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO pm_readonly;
    GRANT USAGE ON SCHEMA public TO pm_readonly;
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO pm_readonly;
    ALTER DEFAULT PRIVILEGES FOR ROLE ${POSTGRES_USER} IN SCHEMA public GRANT SELECT ON TABLES TO pm_readonly;
EOSQL

echo "pm_indexer read-only user created successfully"
