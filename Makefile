# Power Manage — Control / Gateway server.
#
# Build/test recipes live in CLAUDE.md / README.md; this Makefile exists
# for the code-generation steps that must be reproducible and version-
# pinned (#336).
.PHONY: sqlc-generate sqlc-check help

# Pinned OFFICIAL sqlc image. This is load-bearing: a locally
# `go install`-ed sqlc resolves type overrides differently from the
# release build — it silently ignored the (unqualified) `timestamptz`
# override and emitted `pgtype.Timestamptz` instead of `time.Time`
# (#336). Generation MUST go through this image for output that matches
# the committed config.
SQLC_IMAGE ?= sqlc/sqlc:1.30.0

help:
	@echo "Targets:"
	@echo "  sqlc-generate  regenerate internal/store/generated/ via the pinned sqlc image"
	@echo "  sqlc-check     fail if generated code is stale (run sqlc-generate first)"

# Regenerate the sqlc query layer. Runs from internal/store so the image
# sees sqlc.yaml, queries/, migrations/, and the parse-only
# sqlc_schema_overlay.sql (which re-declares the scope columns that
# migration 010 hides from sqlc's parser inside a DO-block, #336).
#
# Two prerequisites are baked into internal/store/sqlc.yaml:
#   * overrides use `db_type: "pg_catalog.timestamptz"` — the qualified
#     name modern sqlc matches (the bare `timestamptz` is ignored).
#   * timestamptz PARAMETERS must NOT carry a redundant `::TIMESTAMPTZ`
#     cast in queries/: sqlc applies go_type overrides to catalog-resolved
#     columns but not to cast-typed params, so a cast forces
#     pgtype.Timestamptz. Drop the no-op cast and sqlc infers the param
#     type from the bound column.
#
# HISTORY (#336): the committed generated/ had years of hand-maintenance
# that diverged from a clean regen — most notably Event.SequenceNum was
# *int64 (the column is `bigint NOT NULL`, so sqlc emits int64) with ~131
# deref() call sites built around it, plus hand-written #7 scope-grant
# queries. That divergence was fully reconciled in #349, so a regen is now
# a no-op against committed main — and the sqlc-drift CI job keeps it that
# way. If sqlc-generate produces a diff, the queries/config changed: commit
# the regenerated output, never hand-edit generated/.
sqlc-generate:
	cd internal/store && docker run --rm \
		-v "$$(pwd)":/src:Z -w /src $(SQLC_IMAGE) generate

# Fail if generated code is out of date. Wired into CI as the "sqlc drift"
# workflow (.github/workflows/sqlc.yml), which runs on any change to
# queries/, migrations/, sqlc.yaml, the overlay, generated/, or this file.
sqlc-check: sqlc-generate
	git diff --exit-code internal/store/generated
