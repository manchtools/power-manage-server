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
artifact="postgres-${stamp}.dump"
final_path="$BACKUP_DIR/$artifact"
temp_path="$(mktemp "$BACKUP_DIR/.postgres-backup-XXXXXX.dump")"
status_temp="$(mktemp "$BACKUP_DIR/.postgres-backup-status-XXXXXX.json")"

cleanup() {
    local status=$?
    trap - EXIT
    [[ -z "$temp_path" ]] || rm -f -- "$temp_path"
    [[ -z "$status_temp" ]] || rm -f -- "$status_temp"
    exit "$status"
}
trap cleanup EXIT

# docref: begin postgres-backup
compose exec -T postgres pg_dump \
    --username powermanage --dbname powermanage --format=custom \
    --no-owner --no-privileges > "$temp_path"
compose exec -T postgres pg_restore --list < "$temp_path" >/dev/null

completed_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
size_bytes="$(stat -c '%s' "$temp_path")"
(( size_bytes > 0 )) || { printf 'PostgreSQL backup is empty\n' >&2; exit 1; }
sha256="$(sha256sum "$temp_path")"
sha256="${sha256%% *}"
[[ ! -e "$final_path" ]] || { printf 'backup name collision\n' >&2; exit 1; }
chmod 600 "$temp_path"
mv -- "$temp_path" "$final_path"
temp_path=""

printf '{"version":1,"completed_at":"%s","artifact":"%s","size_bytes":%s,"sha256":"%s"}\n' \
    "$completed_at" "$artifact" "$size_bytes" "$sha256" > "$status_temp"
chmod 600 "$status_temp"
mv -- "$status_temp" "$BACKUP_DIR/postgres-backup-status.json"
status_temp=""

mapfile -t backups < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'postgres-*.dump' -printf '%f\n' | sort -r)
for ((index = BACKUP_KEEP; index < ${#backups[@]}; index++)); do
    rm -f -- "$BACKUP_DIR/${backups[$index]}"
done
# docref: end postgres-backup

printf 'Verified PostgreSQL backup: %s\n' "$final_path"
