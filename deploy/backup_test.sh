#!/usr/bin/env bash

set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"

cleanup() {
    rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$WORK_DIR/bin" "$WORK_DIR/data/backups"
cp "$SOURCE_DIR/backup.sh" "$WORK_DIR/backup.sh"

cat > "$WORK_DIR/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *" pg_dump"* ]]; then
    printf 'verified-fake-postgres-dump-%s\n' "$(date +%s%N)"
elif [[ "$*" == *" pg_restore --list"* ]]; then
    test -n "$(cat)"
else
    printf 'unexpected docker invocation: %s\n' "$*" >&2
    exit 1
fi
EOF
chmod +x "$WORK_DIR/bin/docker"

for _ in {1..12}; do
    PATH="$WORK_DIR/bin:$PATH" BACKUP_KEEP=010 bash "$WORK_DIR/backup.sh" >/dev/null
done

[[ "$(find "$WORK_DIR/data/backups" -maxdepth 1 -type f -name 'postgres-*.dump' | wc -l)" == 10 ]]
[[ "$(stat -c '%a' "$WORK_DIR/data/backups/postgres-backup-status.json")" == 600 ]]
python3 - "$WORK_DIR/data/backups/postgres-backup-status.json" <<'PY'
import json
import pathlib
import sys

status_path = pathlib.Path(sys.argv[1])
status = json.loads(status_path.read_text())
assert status["version"] == 1
assert status["size_bytes"] > 0
assert len(status["sha256"]) == 64
assert (status_path.parent / status["artifact"]).is_file()
PY

printf 'PASS bounded verified PostgreSQL backups\n'
