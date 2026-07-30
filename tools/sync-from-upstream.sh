#!/usr/bin/env bash
# One-way sync: cathedralai/cathedral -> this repo.
# Copies every manifest entry to the IDENTICAL relative path in <dest>.
# Usage: sync-from-upstream.sh <upstream-checkout> <dest> <manifest>
#        sync-from-upstream.sh selftest <upstream-checkout>
#
# Ten manifest entries are DIRECTORIES (scaffold/publisher/, cathedral_thin/,
# tests/thin/, deploy/sn39/, ...), and this repo keeps local additions inside several
# of them: the whole integration lane is cathedral_thin/integration*.py plus
# tests/thin/test_integration_*.py, none of which exists upstream. An earlier version
# cleared each entry with `rm -rf` before recopying, which deleted 22 tracked local
# files on every sync and restored only the upstream ones. Nothing failed — the files
# were simply gone. BOUNDARY.md's promise that a re-sync "touches nothing outside the
# manifest" was true and beside the point, because those files are INSIDE it.
#
# Removals are therefore driven by MANIFEST.origin.tsv, which records for every
# tracked file whether it came from upstream (`identical` / `modified`) or is local to
# this repo (`local`). Only upstream-derived paths are cleared, which still propagates
# an upstream deletion — the path is removed here and the copy does not recreate it —
# while a local addition survives. Missing that manifest is a refusal, not a guess,
# because guessing means deleting someone's work.
set -euo pipefail

usage() {
  echo "usage: $0 <upstream-checkout> <dest> <manifest>" >&2
  echo "       $0 selftest <upstream-checkout>" >&2
  exit 2
}

read_entries() {
  local manifest="$1"
  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [ -z "$line" ] && continue
    printf '%s\n' "$line"
  done < "$manifest"
}

# Tracked paths that came from upstream, per MANIFEST.origin.tsv's origin column.
# Anything classed `local` is deliberately absent, so it is never deleted.
upstream_derived() {
  awk -F'\t' '/^#/ {next} $1=="path" {next} NF>=3 && $3!="local" {print $1}' "$1"
}

local_additions() {
  awk -F'\t' '/^#/ {next} $1=="path" {next} NF>=3 && $3=="local" {print $1}' "$1"
}

do_sync() {
  local UPSTREAM="$1" DEST="$2" MANIFEST="$3"
  local ORIGIN="$DEST/MANIFEST.origin.tsv"

  if [ ! -f "$ORIGIN" ]; then
    echo "REFUSING: $ORIGIN is missing." >&2
    echo "  It is the only record of which files came from upstream and which are" >&2
    echo "  local to this repo. Without it, clearing the previous copy cannot be" >&2
    echo "  done without risking local additions inside a synced directory." >&2
    exit 1
  fi

  local -a entries derived
  mapfile -t entries < <(read_entries "$MANIFEST")
  mapfile -t derived < <(upstream_derived "$ORIGIN")

  # Clear only upstream-derived paths under a manifest entry.
  local removed=0 kept=0 rel path
  for path in "${derived[@]}"; do
    for rel in "${entries[@]}"; do
      case "$path" in
        "$rel"|"$rel"*)
          if [ -e "$DEST/$path" ]; then
            rm -f "${DEST:?}/$path"
            removed=$((removed + 1))
          fi
          break
          ;;
      esac
    done
  done

  local src dst
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

  # Assert the invariant rather than trusting it: every local addition still exists.
  local survivor
  while IFS= read -r survivor; do
    [ -n "$survivor" ] || continue
    if [ -e "$DEST/$survivor" ]; then
      kept=$((kept + 1))
    else
      echo "LOST local file: $survivor" >&2
      echo "  A sync must never remove a file classed 'local'. Aborting so the tree" >&2
      echo "  can be restored from git rather than committed in this state." >&2
      exit 1
    fi
  done < <(local_additions "$ORIGIN")

  echo "sync complete: ${#entries[@]} manifest entries"
  echo "  cleared $removed upstream-derived files, preserved $kept local additions"
}

# --- selftest -------------------------------------------------------------- #
# Proves the property that broke: a local addition inside a directory manifest entry
# survives. A sync tool with no test is how 22 files went missing unnoticed.
do_selftest() {
  local UPSTREAM="$1"
  local here; here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  local tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  local work="$tmp/repo"
  mkdir -p "$work"
  (cd "$here" && git ls-files -z | tar cf - --null -T -) | (cd "$work" && tar xf -)

  local canary="cathedral_thin/__selftest_local__.py"
  echo "# local addition, absent upstream" > "$work/$canary"
  printf '%s\t%s\tlocal\t-\t-\n' "$canary" \
    "$(sha256sum "$work/$canary" | cut -d' ' -f1)" >> "$work/MANIFEST.origin.tsv"

  local carried="cathedral_thin/core.py"
  [ -f "$work/$carried" ] || { echo "FAIL  fixture: $carried missing"; exit 1; }
  echo "# local drift a sync must overwrite" >> "$work/$carried"

  if ! "$work/tools/sync-from-upstream.sh" "$UPSTREAM" "$work" \
        "$work/tools/upstream-manifest.txt" >/dev/null; then
    echo "FAIL  sync exited nonzero on a clean tree"; exit 1
  fi

  if [ -f "$work/$canary" ]; then
    echo "PASS  local addition inside a directory entry survived"
  else
    echo "FAIL  local addition was deleted: $canary"; exit 1
  fi

  if diff -q "$UPSTREAM/$carried" "$work/$carried" >/dev/null; then
    echo "PASS  upstream-derived file refreshed over local drift"
  else
    echo "FAIL  $carried still differs from upstream after a sync"; exit 1
  fi

  # An upstream deletion must still propagate: a path recorded as upstream-derived
  # but absent upstream has to be removed here.
  local gone="cathedral_thin/__selftest_upstream_gone__.py"
  echo "# recorded as upstream-derived, but not present upstream" > "$work/$gone"
  printf '%s\t%s\tidentical\t%s\t%s\n' "$gone" \
    "$(sha256sum "$work/$gone" | cut -d' ' -f1)" "$gone" \
    "$(sha256sum "$work/$gone" | cut -d' ' -f1)" >> "$work/MANIFEST.origin.tsv"
  "$work/tools/sync-from-upstream.sh" "$UPSTREAM" "$work" \
    "$work/tools/upstream-manifest.txt" >/dev/null
  if [ -e "$work/$gone" ]; then
    echo "FAIL  a file deleted upstream was not removed here"; exit 1
  fi
  echo "PASS  upstream deletion propagated"

  rm -f "$work/MANIFEST.origin.tsv"
  if "$work/tools/sync-from-upstream.sh" "$UPSTREAM" "$work" \
       "$work/tools/upstream-manifest.txt" >/dev/null 2>&1; then
    echo "FAIL  synced with no origin manifest instead of refusing"; exit 1
  fi
  echo "PASS  refused to sync without the origin manifest"
  echo "SELFTEST OK"
}

case "${1:-}" in
  selftest) [ $# -eq 2 ] || usage; do_selftest "$2" ;;
  "")       usage ;;
  *)        [ $# -eq 3 ] || usage; do_sync "$1" "$2" "$3" ;;
esac
