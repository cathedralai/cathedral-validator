#!/usr/bin/env bash
# Build, verify, or self-test the origin manifest for this derived repo.
#
#   tools/manifest.sh build    <upstream-checkout>
#   tools/manifest.sh verify   [upstream-checkout]
#   tools/manifest.sh selftest <upstream-checkout>
#
# `verify` with no upstream argument checks local integrity only. Pass an
# upstream checkout at the derived-from SHA to additionally prove byte-identity
# against it. Any failure exits nonzero; success messages are printed only when
# the corresponding check actually passed.
#
# `selftest` proves the gate works by tampering with a throwaway copy and
# asserting verify rejects it, both with and without a manifest rebuild.
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

# The only files permitted to differ from upstream. Anything else classified
# `modified` is a defect, not a decision.
ALLOWED_DIVERGENCE="pyproject.toml README.md"

is_allowed_divergence() {
  local needle="$1" p
  for p in $ALLOWED_DIVERGENCE; do [ "$p" = "$needle" ] && return 0; done
  return 1
}

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

  # A build that silently reclassifies a carried file as `modified` is how a
  # tampered file escapes the identity check. Refuse to write such a manifest.
  unexpected=$(awk -F'\t' -v allow="$ALLOWED_DIVERGENCE" '
    BEGIN { n=split(allow, a, " "); for (i=1;i<=n;i++) ok[a[i]]=1 }
    !/^#/ && $1!="path" && $3=="modified" && !($1 in ok) { print $1 }' MANIFEST.origin.tsv)
  if [ -n "$unexpected" ]; then
    echo "REFUSING to write manifest: files differ from upstream but are not declared divergences:" >&2
    echo "$unexpected" | sed 's/^/  /' >&2
    exit 1
  fi

  echo "built MANIFEST.sha256 and MANIFEST.origin.tsv against $sha"
  awk -F'\t' '!/^#/ && $1!="path" {c[$3]++} END {for (k in c) printf "  %-10s %d\n", k, c[k]}' MANIFEST.origin.tsv
  ;;

verify)
  rc=0

  echo "== local integrity =="
  if out=$($SHA256 -c MANIFEST.sha256 2>&1); then
    n=$(printf '%s\n' "$out" | grep -c ': OK$' || true)
    echo "  $n tracked files match MANIFEST.sha256"
  else
    printf '%s\n' "$out" | grep -v ': OK$' | sed 's/^/  /' >&2
    echo "  LOCAL INTEGRITY FAILED" >&2
    rc=1
  fi

  # Every tracked file must appear in the manifest and vice versa.
  if diff <(tracked | sort) <(awk '{print $2}' MANIFEST.sha256 | sort) >/dev/null; then
    echo "  manifest covers exactly the tracked file set"
  else
    echo "  MANIFEST COVERAGE MISMATCH:" >&2
    diff <(tracked | sort) <(awk '{print $2}' MANIFEST.sha256 | sort) | sed 's/^/    /' >&2
    rc=1
  fi

  if [ -n "$UPSTREAM" ]; then
    [ -d "$UPSTREAM" ] || { echo "no such upstream checkout: $UPSTREAM" >&2; exit 2; }
    sha=$(git -C "$UPSTREAM" rev-parse HEAD)
    want=$(awk '/^# Upstream:/ {print $NF}' MANIFEST.origin.tsv)
    echo "== upstream byte-identity =="
    echo "  manifest records $want"
    echo "  checkout is      $sha"
    if [ "$sha" != "$want" ]; then
      echo "  CHECKOUT IS NOT THE DERIVED-FROM SHA" >&2
      rc=1
    fi

    bad=0; nident=0; nmod=0; nlocal=0
    while IFS=$'\t' read -r rel h origin upath uh; do
      case "$rel" in \#*|path|"") continue;; esac

      # Hash the LOCAL file directly. Comparing only recorded hashes lets a
      # tampered file pass once the manifest is rebuilt around it.
      if [ ! -f "$rel" ]; then echo "  MISSING LOCALLY $rel" >&2; bad=$((bad+1)); continue; fi
      lh=$(hash_of "$rel")

      case "$origin" in
      identical)
        if [ ! -f "$UPSTREAM/$upath" ]; then
          echo "  MISSING UPSTREAM $upath" >&2; bad=$((bad+1)); continue
        fi
        actual_up=$(hash_of "$UPSTREAM/$upath")
        if [ "$lh" != "$actual_up" ]; then
          echo "  NOT IDENTICAL TO UPSTREAM $rel" >&2; bad=$((bad+1))
        elif [ "$actual_up" != "$uh" ] || [ "$lh" != "$h" ]; then
          echo "  MANIFEST HASHES STALE FOR $rel" >&2; bad=$((bad+1))
        else
          nident=$((nident+1))
        fi
        ;;
      modified)
        if ! is_allowed_divergence "$rel"; then
          echo "  UNDECLARED DIVERGENCE $rel" >&2; bad=$((bad+1)); continue
        fi
        if [ ! -f "$UPSTREAM/$upath" ]; then
          echo "  MISSING UPSTREAM $upath" >&2; bad=$((bad+1)); continue
        fi
        if [ "$lh" = "$(hash_of "$UPSTREAM/$upath")" ]; then
          echo "  CLASSIFIED modified BUT IDENTICAL $rel" >&2; bad=$((bad+1))
        else
          nmod=$((nmod+1))
        fi
        ;;
      local)
        if [ -f "$UPSTREAM/$rel" ]; then
          echo "  CLASSIFIED local BUT EXISTS UPSTREAM $rel" >&2; bad=$((bad+1))
        else
          nlocal=$((nlocal+1))
        fi
        ;;
      *)
        echo "  UNKNOWN ORIGIN CLASS '$origin' FOR $rel" >&2; bad=$((bad+1))
        ;;
      esac
    done < MANIFEST.origin.tsv

    # Every declared divergence must actually be present and classified.
    for p in $ALLOWED_DIVERGENCE; do
      if ! awk -F'\t' -v p="$p" '$1==p && $3=="modified" {found=1} END {exit !found}' MANIFEST.origin.tsv; then
        echo "  DECLARED DIVERGENCE NOT FOUND AS modified: $p" >&2; bad=$((bad+1))
      fi
    done

    if [ "$bad" -eq 0 ]; then
      echo "  $nident files confirmed byte-identical to upstream"
      echo "  $nmod declared divergences confirmed different: $ALLOWED_DIVERGENCE"
      echo "  $nlocal additions confirmed absent upstream"
    else
      echo "  $bad problems" >&2
      rc=1
    fi
  fi

  if [ "$rc" -ne 0 ]; then echo "VERIFY FAILED" >&2; else echo "VERIFY OK"; fi
  exit "$rc"
  ;;

selftest)
  [ -d "$UPSTREAM" ] || { echo "usage: tools/manifest.sh selftest <upstream-checkout>" >&2; exit 2; }
  up=$(cd "$UPSTREAM" && pwd)
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  work="$tmp/repo"
  mkdir -p "$work"
  # Copy the WORKING TREE, not HEAD: the point is to test the script as it
  # stands right now, including uncommitted changes to this file.
  git ls-files -z | tar -c --null -T - -f - | tar -x -C "$work" -f -
  ( cd "$work" && git init -q -b main && git add -A \
      && git -c user.name=selftest -c user.email=selftest@local commit -qm selftest )

  fail=0

  # Build inside the copy so the baseline is self-consistent regardless of
  # whether the parent's manifest is currently up to date. Manifest freshness
  # in the parent is `verify`'s job, not this test's.
  ( cd "$work" && ./tools/manifest.sh build "$up" >/dev/null 2>&1 ) || true

  # The unmodified copy must pass, otherwise the negative results below prove
  # nothing.
  if ( cd "$work" && ./tools/manifest.sh verify "$up" >/dev/null 2>&1 ); then
    echo "PASS  baseline copy verifies clean"
  else
    echo "FAIL  baseline copy does not verify; selftest is inconclusive" >&2; fail=1
  fi

  printf '\n# tampered by selftest\n' >> "$work/scaffold/validator_thin.py"

  # Case 1: tampered, manifest untouched. Local integrity must catch it.
  if ( cd "$work" && ./tools/manifest.sh verify "$up" >/dev/null 2>&1 ); then
    echo "FAIL  tampered file passed verify with stale manifest" >&2; fail=1
  else
    echo "PASS  tampered file rejected (stale manifest)"
  fi

  # Case 2: tampered, then manifest rebuilt around the tampering. The build
  # must refuse, and verify must still reject if a forged manifest is supplied.
  if ( cd "$work" && ./tools/manifest.sh build "$up" >/dev/null 2>&1 ); then
    echo "FAIL  build accepted an undeclared divergence" >&2; fail=1
  else
    echo "PASS  build refused to bless an undeclared divergence"
  fi

  # Case 3: forge the manifest by hand the way a rebuild used to, then verify.
  ( cd "$work" \
    && h=$($SHA256 scaffold/validator_thin.py | awk '{print $1}') \
    && awk -F'\t' -v OFS='\t' -v h="$h" '$1=="scaffold/validator_thin.py"{$2=h; $3="identical"}1' \
         MANIFEST.origin.tsv > MANIFEST.origin.tsv.new \
    && mv MANIFEST.origin.tsv.new MANIFEST.origin.tsv \
    && awk -v h="$h" '$2=="scaffold/validator_thin.py"{print h"  "$2; next}1' \
         MANIFEST.sha256 > MANIFEST.sha256.new \
    && mv MANIFEST.sha256.new MANIFEST.sha256 ) 2>/dev/null || true
  if ( cd "$work" && ./tools/manifest.sh verify "$up" >/dev/null 2>&1 ); then
    echo "FAIL  forged manifest passed verify" >&2; fail=1
  else
    echo "PASS  forged manifest rejected (local bytes hashed against upstream)"
  fi

  if [ "$fail" -eq 0 ]; then echo "SELFTEST OK"; else echo "SELFTEST FAILED" >&2; fi
  exit "$fail"
  ;;

*)
  echo "usage: tools/manifest.sh {build <upstream>|verify [upstream]|selftest <upstream>}" >&2
  exit 2
  ;;
esac
