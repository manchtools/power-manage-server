# Power Manage control server.
#
# Build/test recipes live in CLAUDE.md / README.md; this Makefile exists
# for the code-generation steps that must be reproducible and version-
# pinned.
.PHONY: sqlc-generate sqlc-check help

# Pinned OFFICIAL sqlc image. This is load-bearing: a locally
# `go install`-ed sqlc resolves type overrides differently from the
# release build — it silently ignored the (unqualified) `timestamptz`
# override and emitted `pgtype.Timestamptz` instead of `time.Time`.
# Generation MUST go through this image for output that matches
# the committed config.
SQLC_IMAGE ?= sqlc/sqlc:1.30.0
DOCKER ?= docker

help:
	@echo "Targets:"
	@echo "  sqlc-generate  regenerate internal/store/generated/ via the pinned sqlc image"
	@echo "  sqlc-check     fail if generated code is stale (run sqlc-generate first)"

# Regenerate the sqlc query layer. Runs from internal/store so the image
# sees sqlc.yaml, queries/, migrations/, and the parse-only
# sqlc_schema_overlay.sql (which re-declares the scope columns that
# migration 010 hides from sqlc's parser inside a DO-block).
#
# Two prerequisites are baked into internal/store/sqlc.yaml:
#   * overrides use `db_type: "pg_catalog.timestamptz"` — the qualified
#     name modern sqlc matches (the bare `timestamptz` is ignored).
#   * timestamptz PARAMETERS must NOT carry a redundant `::TIMESTAMPTZ`
#     cast in queries/: sqlc applies go_type overrides to catalog-resolved
#     columns but not to cast-typed params, so a cast forces
#     pgtype.Timestamptz. Drop the no-op cast and sqlc infers the param
#     type from the bound column.
# A clean regeneration is a no-op. If sqlc-generate produces a diff, commit the
# regenerated output; never hand-edit generated/.
# Generate into a temporary sibling first. sqlc does not remove output for a
# deleted query file, so a successful run replaces the whole directory. A
# failed run leaves the committed output untouched.
sqlc-generate:
	@set -eu; \
	stage=$$(mktemp -d internal/store/.sqlc.XXXXXX); \
	trap 'rm -rf "$$stage"' EXIT INT TERM; \
	cp -R internal/store/sqlc.yaml internal/store/migrations internal/store/queries "$$stage/"; \
	$(DOCKER) run --rm --user "$$(id -u):$$(id -g)" \
		-v "$$(realpath "$$stage")":/src:Z -w /src $(SQLC_IMAGE) generate; \
	mv internal/store/generated "$$stage/previous"; \
	if mv "$$stage/generated" internal/store/generated; then \
		rm -rf "$$stage"; \
		trap - EXIT INT TERM; \
	else \
		mv "$$stage/previous" internal/store/generated; \
		exit 1; \
	fi

# Fail if generated code is out of date. Wired into CI as the "sqlc drift"
# workflow (.github/workflows/sqlc.yml), which runs on any change to
# queries/, migrations/, sqlc.yaml, the overlay, generated/, or this file.
sqlc-check: sqlc-generate
	git diff --exit-code internal/store/generated
