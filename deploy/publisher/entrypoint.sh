#!/bin/sh
# Runs as root: take ownership of the DB directory and SQLite sidecar files,
# then drop privileges to the runtime user and exec the CMD with env intact.
#
# Ported verbatim from the hub's deploy/entrypoint.sh (cathedral repo). The
# validator-adjacent origin publisher is byte-for-byte the same serving
# surface, so the volume-ownership fixup is identical.
set -e

db_path="${CATHEDRAL_DB_PATH:-/data/publisher.db}"
db_dir="$(dirname "$db_path")"
mkdir -p "$db_dir" /app/data
chown cathedral:cathedral "$db_dir" /app/data 2>/dev/null || true
for path in "$db_path" "$db_path-wal" "$db_path-shm"; do
  if [ -e "$path" ]; then
    chown cathedral:cathedral "$path" 2>/dev/null || true
  fi
done

export HOME=/home/cathedral
exec setpriv --reuid=cathedral --regid=cathedral --init-groups "$@"
