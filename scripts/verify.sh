#!/usr/bin/env bash
# The control server's canonical verification gate.
#
# The one thing this adds over the generic gate verify-stamp.sh would otherwise
# run: GOWORK=off. The workspace go.work replaces the pinned SDK with the local
# sibling checkout, so a branch whose go.mod still points at a pre-change SDK
# builds and tests perfectly here and cannot compile anywhere else. CI checks
# out this repo alone, and that is what it sees.
#
# That is not hypothetical — spec 41 shipped eleven green commits in exactly
# that state. Every gate passed; the branch could not build in CI at all.
set -euo pipefail

cd "$(dirname "$0")/.."
export GOWORK=off

echo "== gofmt"
# No `|| true`: swallowing a gofmt FAILURE reports an empty violation list, so
# the check would pass precisely when it could not run.
unfmt=$(gofmt -l .)
if [ -n "$unfmt" ]; then
  echo "gofmt violations:" >&2
  echo "$unfmt" >&2
  exit 1
fi

echo "== go build (standalone module — no go.work)"
go build ./...

echo "== go vet"
go vet ./...

# Fail closed on a MISSING tool. Skipping it and reporting green is the exact
# shape this gate exists to prevent: a pass that means "not checked".
if ! command -v staticcheck >/dev/null 2>&1; then
  echo "staticcheck is not installed — the gate cannot certify this tree" >&2
  exit 1
fi
echo "== staticcheck"
staticcheck ./...

echo "== go test"
go test ./... -count=1

if ! command -v docref >/dev/null 2>&1; then
  echo "docref is not installed — the gate cannot certify this tree" >&2
  exit 1
fi
echo "== docref check"
docref check

echo "== server gate green"
