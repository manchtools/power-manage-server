# Power Manage control server.
#
# Build/test recipes live in CLAUDE.md / README.md; this Makefile exists
# for the code-generation steps that must be reproducible and version-
# pinned.
.PHONY: sqlc-generate sqlc-check help

# Pinned OFFICIAL sqlc image. This is load-bearing: sqlc versions differ in the
# Go they emit for the same query, so generation MUST go through this image or
# the drift check fails on a version difference rather than a real change. The
# pin has to match the version that produced the committed output — 1.30.0, for
# example, emits `int64` where 1.31.1 emits `bool` for an EXISTS query. A
# locally `go install`-ed sqlc is not a substitute.
SQLC_IMAGE ?= sqlc/sqlc:1.31.1
DOCKER ?= docker

help:
	@echo "Targets:"
	@echo "  sqlc-generate  regenerate internal/store/generated/ via the pinned sqlc image"
	@echo "  sqlc-check     fail if generated code is stale (run sqlc-generate first)"

# Regenerate the sqlc query layer. Runs from internal/store so the image sees
# sqlc.yaml, queries/, and sqliteschema/schema.sql — the single SQLite baseline
# that sqlc.yaml declares as its schema. There is no migrations directory: the
# datastore is embedded SQLite and the baseline is created fresh, so the schema
# is one file rather than an ordered migration set.
#
# A clean regeneration is a no-op. If sqlc-generate produces a diff, commit the
# regenerated output; never hand-edit generated/.
# Generate into a temporary sibling first. sqlc does not remove output for a
# deleted query file, so a successful run replaces the whole directory. A
# failed run leaves the committed output untouched.
sqlc-generate:
	@set -eu; \
	stage=$$(mktemp -d internal/store/.sqlc.XXXXXX); \
	trap 'rm -rf "$$stage"' EXIT INT TERM; \
	cp -R internal/store/sqlc.yaml internal/store/sqliteschema internal/store/queries "$$stage/"; \
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
