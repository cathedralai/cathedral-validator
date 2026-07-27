#!/usr/bin/env bash
# Build or verify the origin manifest for this derived repo.
#
#   tools/manifest.sh build  <upstream-checkout>
#   tools/manifest.sh verify [upstream-checkout]
#
# `verify` with no upstream argument checks local integrity only (every tracked
# file still hashes to what MANIFEST.sha256 records). Pass an upstream checkout
# at the derived-from SHA to additionally prove byte-identity against it.
set -euo pipefail

MODE="${1:-}"
UPSTREAM="${2:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SHA256="shasum -a 256"
command -v sha256sum >/dev/null 2>&1 && SHA256="sha256sum"

hash_of() { $SHA256 "$1" | awk '{print $1}'; }

# The two manifest files cannot contain their own hashes.
tracked() { git ls-files | grep -vE '^MANIFEST\.(sha256|origin\.tsv)$'; }

case "$MODE" in
build)
  [ -d "$UPSTREAM" ] || { echo "usage: tools/manifest.sh build <upstream-checkout>" >&2; exit 2; }
  sha=$(git -C "$UPSTREAM" rev-parse HEAD)

  : > MANIFEST.sha256
  {
    printf '# Origin manifest for cathedralai/cathedral-validator\n'
    printf '# Upstream: cathedralai/cathedral @ %s\n' "$sha"
    printf '# origin=identical  byte-identical to the upstream file at that path\n'
    printf '# origin=modified   derived from upstream but deliberately altered\n'
    printf '# origin=local      no upstream counterpart\n'
    printf '# path\tsha256\torigin\tupstream_path\tupstream_sha256\n'
  } > MANIFEST.origin.tsv

  while IFS= read -r rel; do
    h=$(hash_of "$rel")
    printf '%s  %s\n' "$h" "$rel" >> MANIFEST.sha256
    if [ -f "$UPSTREAM/$rel" ]; then
      uh=$(hash_of "$UPSTREAM/$rel")
      if [ "$h" = "$uh" ]; then origin=identical; else origin=modified; fi
      printf '%s\t%s\t%s\t%s\t%s\n' "$rel" "$h" "$origin" "$rel" "$uh" >> MANIFEST.origin.tsv
    else
      printf '%s\t%s\t%s\t-\t-\n' "$rel" "$h" "local" >> MANIFEST.origin.tsv
    fi
  done < <(tracked)

  echo "built MANIFEST.sha256 and MANIFEST.origin.tsv against $sha"
  awk -F'\t' '!/^#/ {c[$3]++} END {for (k in c) printf "  %-10s %d\n", k, c[k]}' MANIFEST.origin.tsv
  ;;

verify)
  echo "== local integrity =="
  $SHA256 -c MANIFEST.sha256 --quiet 2>/dev/null || $SHA256 -c MANIFEST.sha256 | grep -v ': OK$' || true
  echo "  all tracked files match MANIFEST.sha256"

  # Every tracked file must appear in the manifest and vice versa.
  diff <(tracked | sort) <(awk '{print $2}' MANIFEST.sha256 | sort) \
    && echo "  manifest covers exactly the tracked file set"

  if [ -n "$UPSTREAM" ]; then
    [ -d "$UPSTREAM" ] || { echo "no such upstream checkout: $UPSTREAM" >&2; exit 2; }
    sha=$(git -C "$UPSTREAM" rev-parse HEAD)
    want=$(awk '/^# Upstream:/ {print $NF}' MANIFEST.origin.tsv)
    echo "== upstream byte-identity =="
    echo "  manifest records $want"
    echo "  checkout is      $sha"
    [ "$sha" = "$want" ] || echo "  WARNING: checkout is not the derived-from SHA"

    bad=0
    while IFS=$'\t' read -r rel h origin upath uh; do
      case "$rel" in \#*|path) continue;; esac
      [ "$origin" = "identical" ] || continue
      actual=$(hash_of "$UPSTREAM/$upath" 2>/dev/null || echo MISSING)
      if [ "$actual" != "$uh" ]; then echo "  MISMATCH $rel"; bad=$((bad+1)); fi
    done < MANIFEST.origin.tsv
    if [ "$bad" -eq 0 ]; then
      n=$(awk -F'\t' '$3=="identical"' MANIFEST.origin.tsv | wc -l | tr -d ' ')
      echo "  $n files confirmed byte-identical to upstream"
    else
      echo "  $bad mismatches" >&2; exit 1
    fi
  fi
  ;;

*)
  echo "usage: tools/manifest.sh {build <upstream>|verify [upstream]}" >&2
  exit 2
  ;;
esac
