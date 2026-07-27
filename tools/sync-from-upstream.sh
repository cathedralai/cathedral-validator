#!/usr/bin/env bash
# One-way sync: cathedralai/cathedral -> this repo.
# Copies every manifest entry to the IDENTICAL relative path in <dest>.
# Usage: sync.sh <upstream-checkout> <dest> <manifest>
set -euo pipefail

UPSTREAM="$1"
DEST="$2"
MANIFEST="$3"

entries=()
while IFS= read -r line; do
  line="${line%%#*}"
  line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [ -z "$line" ] && continue
  entries+=("$line")
done < "$MANIFEST"

# Drop the previously synced copy of each managed path so removals upstream
# propagate, then copy fresh. Never touches anything outside the manifest,
# so repo-local files (README, BOUNDARY, CI, tools) survive a re-sync.
for rel in "${entries[@]}"; do
  [ -e "$DEST/$rel" ] && rm -rf "${DEST:?}/$rel"
done

for rel in "${entries[@]}"; do
  src="$UPSTREAM/$rel"
  dst="$DEST/$rel"
  if [ -d "$src" ]; then
    mkdir -p "$dst"
    (cd "$src" && tar cf - \
      --exclude '__pycache__' --exclude '*.pyc' --exclude '.pytest_cache' .) \
      | (cd "$dst" && tar xf -)
  elif [ -f "$src" ]; then
    mkdir -p "$(dirname "$dst")"
    cp -p "$src" "$dst"
  else
    echo "MISSING in upstream: $rel" >&2
    exit 1
  fi
done

find "$DEST" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$DEST" -name '*.pyc' -delete 2>/dev/null || true
echo "sync complete: ${#entries[@]} manifest entries"
