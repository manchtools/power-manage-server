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
last="${*: -1}"
if [[ "$*" == *" test -f /var/lib/power-manage/state/control.db"* ]]; then
    exit 0
elif [[ "$*" == *" sqlite3 /var/lib/power-manage/state/control.db PRAGMA user_version;"* ]]; then
    printf '1\n'
elif [[ "$last" == ".backup "* ]]; then
    container_path="${last:9:${#last}-10}"
    printf 'verified-fake-sqlite-snapshot-%s\n' "$(date +%s%N)" > "$TEST_BACKUP_DIR/${container_path##*/}"
elif [[ "$last" == "PRAGMA integrity_check;" ]]; then
    printf 'ok\n'
elif [[ "$last" == "PRAGMA foreign_key_check;" ]]; then
    exit 0
elif [[ "$*" == *" chmod 600 /var/lib/power-manage/backups/"* ]]; then
    chmod 600 "$TEST_BACKUP_DIR/${last##*/}"
elif [[ "$*" == *" stat -c %s /var/lib/power-manage/backups/"* ]]; then
    stat -c '%s' "$TEST_BACKUP_DIR/${last##*/}"
elif [[ "$*" == *" sha256sum /var/lib/power-manage/backups/"* ]]; then
    sha256sum "$TEST_BACKUP_DIR/${last##*/}"
else
    printf 'unexpected docker invocation: %s\n' "$*" >&2
    exit 1
fi
EOF
chmod +x "$WORK_DIR/bin/docker"

for _ in {1..12}; do
    PATH="$WORK_DIR/bin:$PATH" TEST_BACKUP_DIR="$WORK_DIR/data/backups" \
        BACKUP_KEEP=010 bash "$WORK_DIR/backup.sh" >/dev/null
done

[[ "$(find "$WORK_DIR/data/backups" -maxdepth 1 -type f -name 'sqlite-*.db' | wc -l)" == 10 ]]
[[ "$(stat -c '%a' "$WORK_DIR/data/backups/backup-status.json")" == 600 ]]
python3 - "$WORK_DIR/data/backups/backup-status.json" <<'PY'
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

printf 'PASS bounded verified SQLite backups\n'
