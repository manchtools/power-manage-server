# Contributing to Power Manage Server

## Prerequisites

- Go 1.25+
- PostgreSQL or a container engine for integration tests
- `sqlc` when changing SQL queries

This repository is normally developed beside the SDK, agent, and web
repositories in the Power Manage Go workspace.

```bash
go build ./cmd/control
go test ./...
go vet ./...
```

Database migrations live in `internal/store/migrations`. After changing files
under `internal/store/queries`, regenerate checked-in query code with:

```bash
cd internal/store
sqlc generate
```

The deployable consolidation stack is Traefik, control, and PostgreSQL. Do not
add a broker, auxiliary search process, dynamic container-socket routing,
event-store, or projector path. The architecture tests enforce these deletion
boundaries.

Use focused conventional commits and keep the complete test and vet gates green
before opening a pull request. CodeRabbit reviews every pull request.

By contributing, you agree that your contributions are licensed under the
AGPL-3.0 license.
