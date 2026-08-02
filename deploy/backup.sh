#!/usr/bin/env bash

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$DEPLOY_DIR/data/backups"
BACKUP_KEEP="${BACKUP_KEEP:-7}"

case "$BACKUP_KEEP" in
    ''|*[!0-9]*) printf 'BACKUP_KEEP must be an integer from 1 to 365\n' >&2; exit 2 ;;
esac
BACKUP_KEEP=$((10#$BACKUP_KEEP))
(( BACKUP_KEEP >= 1 && BACKUP_KEEP <= 365 )) || {
    printf 'BACKUP_KEEP must be an integer from 1 to 365\n' >&2
    exit 2
}
[[ -d "$BACKUP_DIR" && -w "$BACKUP_DIR" ]] || {
    printf 'backup directory is missing or not writable: %s\n' "$BACKUP_DIR" >&2
    exit 1
}
command -v docker >/dev/null || { printf 'docker is required\n' >&2; exit 1; }

compose() {
    docker compose --project-directory "$DEPLOY_DIR" "$@"
}

umask 077
stamp="$(date -u '+%Y%m%dT%H%M%S%NZ')"
artifact="sqlite-${stamp}.db"
final_path="$BACKUP_DIR/$artifact"
temp_artifact=".sqlite-backup-${stamp}-$$.db"
temp_path="$BACKUP_DIR/$temp_artifact"
status_temp="$(mktemp "$BACKUP_DIR/.backup-status-XXXXXX.json")"
container_database="/var/lib/power-manage/state/control.db"
container_temp="/var/lib/power-manage/backups/$temp_artifact"

cleanup() {
    local status=$?
    trap - EXIT
    [[ -z "$temp_path" ]] || rm -f -- "$temp_path"
    [[ -z "$status_temp" ]] || rm -f -- "$status_temp"
    exit "$status"
}
trap cleanup EXIT

# docref: begin sqlite-backup
compose exec -T control test -f "$container_database" \
    || { printf 'SQLite database does not exist\n' >&2; exit 1; }
schema_version="$(compose exec -T control sqlite3 "$container_database" 'PRAGMA user_version;')"
[[ "$schema_version" == 1 ]] || { printf 'SQLite schema version is %s, want 1\n' "$schema_version" >&2; exit 1; }
[[ ! -e "$temp_path" ]] || { printf 'temporary backup name collision\n' >&2; exit 1; }
compose exec -T control sqlite3 "$container_database" ".backup '$container_temp'"
compose exec -T control chmod 600 "$container_temp"

integrity="$(compose exec -T control sqlite3 "$container_temp" 'PRAGMA integrity_check;')"
[[ "$integrity" == ok ]] || { printf 'SQLite backup integrity check failed: %s\n' "$integrity" >&2; exit 1; }
foreign_key_violations="$(compose exec -T control sqlite3 "$container_temp" 'PRAGMA foreign_key_check;')"
[[ -z "$foreign_key_violations" ]] || { printf 'SQLite backup foreign-key check failed\n%s\n' "$foreign_key_violations" >&2; exit 1; }

completed_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
size_bytes="$(compose exec -T control stat -c '%s' "$container_temp")"
(( size_bytes > 0 )) || { printf 'SQLite backup is empty\n' >&2; exit 1; }
sha256="$(compose exec -T control sha256sum "$container_temp")"
sha256="${sha256%% *}"
[[ ! -e "$final_path" ]] || { printf 'backup name collision\n' >&2; exit 1; }
mv -- "$temp_path" "$final_path"
temp_path=""

printf '{"version":1,"completed_at":"%s","artifact":"%s","size_bytes":%s,"sha256":"%s"}\n' \
    "$completed_at" "$artifact" "$size_bytes" "$sha256" > "$status_temp"
chmod 600 "$status_temp"
mv -- "$status_temp" "$BACKUP_DIR/backup-status.json"
status_temp=""

mapfile -t backups < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'sqlite-*.db' -printf '%f\n' | sort -r)
for ((index = BACKUP_KEEP; index < ${#backups[@]}; index++)); do
    rm -f -- "$BACKUP_DIR/${backups[$index]}"
done
# docref: end sqlite-backup

printf 'Verified SQLite backup: %s\n' "$final_path"
