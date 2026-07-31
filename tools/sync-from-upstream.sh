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
# DECLARED DIVERGENCES are the second class of file a blind copy destroys, and the
# reason this script gained a second guard. A file classed `modified` in
# MANIFEST.origin.tsv and listed in manifest.sh's ALLOWED_DIVERGENCE holds content
# this repo means to differ from upstream. Copying upstream over it silently REVERTS
# that decision. It happened: a re-sync reverted config/validator-mainnet-sn39.toml
# and dropped [logs].status_jsonl, so nothing wrote the sanitized status projection
# and cathedral-sn39-public-status.service could never satisfy its
# ConditionPathExists. systemd records an unmet condition as SKIPPED, not failed, so
# the public status stream stopped with no error anywhere.
#
# So a declared divergence is NOT overwritten. Upstream's version is written beside
# it as `<path>.upstream` for a human to reconcile, and the sync refuses to report
# success while any reconciliation is outstanding. Upstream changes to a divergent
# file still have to be READ (that is how #403-#408 went missing), which is exactly
# what the companion file and the refusal force.
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

# The declared divergences, parsed from manifest.sh so there is ONE list rather than
# two that can drift apart.
declared_divergences() {
  local tools_dir="$1"
  awk '
    /^ALLOWED_DIVERGENCE=/ { collecting = 1; sub(/^ALLOWED_DIVERGENCE="?/, ""); }
    collecting {
      line = $0
      done_here = (line !~ /\\$/)
      gsub(/\\$/, "", line)
      gsub(/"/, "", line)
      n = split(line, parts, /[[:space:]]+/)
      for (i = 1; i <= n; i++) if (parts[i] != "") print parts[i]
      if (done_here) exit
    }
  ' "$tools_dir/manifest.sh"
}

local_additions() {
  awk -F'\t' '/^#/ {next} $1=="path" {next} NF>=3 && $3=="local" {print $1}' "$1"
}

# The upstream sha256 MANIFEST.origin.tsv recorded for a path, i.e. the upstream
# bytes as of the PREVIOUS derived-from commit. Comparing the incoming checkout
# against this is what distinguishes "upstream changed this file" from "this
# file is a divergence, so of course it differs from upstream".
recorded_upstream_sha() {
  awk -F'\t' -v want="$2" '
    /^#/ {next} $1=="path" {next}
    NF>=5 && $1==want && $3!="local" { print $5; exit }
  ' "$1"
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

  local -a entries derived diverged
  mapfile -t entries < <(read_entries "$MANIFEST")
  mapfile -t derived < <(upstream_derived "$ORIGIN")
  mapfile -t diverged < <(declared_divergences "$(dirname "${BASH_SOURCE[0]}")")

  # Snapshot every declared divergence before touching anything, so the copy cannot
  # lose one even if the protection below is bypassed by a future edit.
  local snapshot; snapshot="$(mktemp -d)"
  local d
  for d in "${diverged[@]}"; do
    if [ -f "$DEST/$d" ]; then
      mkdir -p "$snapshot/$(dirname "$d")"
      cp -p "$DEST/$d" "$snapshot/$d"
    fi
  done

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
    # A declared divergence named directly as a manifest entry is never overwritten.
    if printf '%s\n' "${diverged[@]}" | grep -qxF "$rel"; then
      continue
    fi
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

  # Restore any declared divergence a DIRECTORY entry copied over, and record which
  # ones upstream has since changed so a human reconciles them deliberately.
  #
  # TWO defects lived here, and they pull in opposite directions.
  #
  # 1. It cried wolf. The trigger was "upstream's bytes differ from ours", which
  #    is true of every divergence by definition, so MUST RECONCILE fired on the
  #    same three deploy/sn39 files on EVERY sync whether or not upstream had
  #    touched them. A warning that always fires is worse than none: it teaches
  #    the operator to delete the .upstream companion unread, and then the one
  #    sync where upstream really did change a divergent file looks identical to
  #    all the others.
  #
  # 2. It was silent where it mattered most. The check only ran on divergences a
  #    DIRECTORY entry had copied over. Seven of the thirteen -- including
  #    pyproject.toml, scripts/build_sn39_release_manifest.py, and
  #    config/validator-mainnet-sn39.toml, the file whose silent revert is why
  #    this guard exists -- are named DIRECTLY in tools/upstream-manifest.txt.
  #    The copy loop skips those with `continue`, so nothing ever clobbered them,
  #    so they were never compared and NEVER raised a reconciliation, no matter
  #    what upstream did. Caught in practice: the sync to aa79135 changed
  #    scripts/build_sn39_release_manifest.py upstream and this tool said nothing.
  #
  # So the reconciliation question is now asked about every declared divergence,
  # independently of how (or whether) the copy loop touched it, and it asks the
  # right question: did UPSTREAM's bytes move since the manifest recorded them.
  # MANIFEST.origin.tsv's fifth column is upstream's sha256 at the PREVIOUS
  # derived-from commit, which is exactly that baseline. A path with no recorded
  # upstream digest (newly declared divergence, manifest not rebuilt yet) is
  # flagged, because "unknown" must not read as "unchanged".
  local restored=0 pending=0
  for d in "${diverged[@]}"; do
    local upstream_moved=0 recorded incoming
    recorded="$(recorded_upstream_sha "$ORIGIN" "$d")"
    if [ -f "$UPSTREAM/$d" ]; then
      incoming="$(sha256sum "$UPSTREAM/$d" | awk '{print $1}')"
      if [ -z "$recorded" ] || [ "$recorded" != "$incoming" ]; then
        upstream_moved=1
      fi
    elif [ -n "$recorded" ]; then
      # Upstream deleted a file this repo diverges from: a reconciliation too.
      upstream_moved=1
    fi

    # `restored` counts what a directory copy actually clobbered and we put back,
    # whether or not upstream moved -- that is the protection doing its job and it
    # should stay visible. Only `pending` gates success.
    if [ -f "$snapshot/$d" ]; then
      if [ -f "$DEST/$d" ] && ! cmp -s "$snapshot/$d" "$DEST/$d"; then
        restored=$((restored + 1))
      fi
      cp -p "$snapshot/$d" "$DEST/$d"
    fi

    # Upstream's version is written beside ours for whatever a human has to read,
    # whether or not the copy loop ever touched the file.
    if [ "$upstream_moved" -eq 1 ] && [ -f "$UPSTREAM/$d" ]; then
      cp -p "$UPSTREAM/$d" "$DEST/$d.upstream"
      pending=$((pending + 1))
    elif [ "$upstream_moved" -eq 1 ]; then
      pending=$((pending + 1))
      echo "  NOTE: upstream DELETED $d, which this repo declares divergent" >&2
    fi
  done
  rm -rf "$snapshot"

  echo "sync complete: ${#entries[@]} manifest entries"
  echo "  cleared $removed upstream-derived files, preserved $kept local additions"
  echo "  protected ${#diverged[@]} declared divergences (restored $restored)"

  if [ "$pending" -gt 0 ]; then
    echo "" >&2
    echo "MUST RECONCILE: upstream changed $pending declared divergence(s)." >&2
    for d in "${diverged[@]}"; do
      [ -f "$DEST/$d.upstream" ] || continue
      echo "  $d   (upstream version saved as $d.upstream)" >&2
    done
    echo "" >&2
    echo "  Your version was kept, so nothing was silently reverted. Read the" >&2
    echo "  .upstream file, decide what to carry across, then delete it. Refusing" >&2
    echo "  to report success while a reconciliation is outstanding, because an" >&2
    echo "  unread upstream change to a divergent file is how hardening goes" >&2
    echo "  missing (see #403-#408)." >&2
    if [ "${ALLOW_UNRECONCILED:-0}" != "1" ]; then
      exit 3
    fi
    echo "  ALLOW_UNRECONCILED=1 set; continuing anyway." >&2
  fi
}

# --- selftest -------------------------------------------------------------- #
# Proves the property that broke: a local addition inside a directory manifest entry
# survives. A sync tool with no test is how 22 files went missing unnoticed.
do_selftest() {
  local UPSTREAM="$1"
  # This selftest exercises the PRESERVATION semantics, and against a real upstream some
  # declared divergence has almost always changed, which the guard deliberately reports
  # as an outstanding reconciliation (exit 3). Export the override for the whole
  # function so every preservation assertion below is unaffected by that gate; the gate
  # itself is asserted separately, with the override explicitly off.
  export ALLOW_UNRECONCILED=1
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

  # A DECLARED divergence must survive a sync. This is the exact regression: the
  # config below is `modified` and listed in manifest.sh ALLOWED_DIVERGENCE, and an
  # earlier sync copied upstream over it, dropping [logs].status_jsonl.
  local diverged="config/validator-mainnet-sn39.toml"
  local marker="__selftest_divergence_marker__"
  if [ -f "$work/$diverged" ]; then
    printf '\n# %s\n' "$marker" >> "$work/$diverged"
  fi

  local carried="cathedral_thin/core.py"
  [ -f "$work/$carried" ] || { echo "FAIL  fixture: $carried missing"; exit 1; }
  echo "# local drift a sync must overwrite" >> "$work/$carried"

  # ALLOW_UNRECONCILED=1: this selftest proves the PRESERVATION semantics, and a real
  # upstream will usually have changed some declared divergence, which the guard
  # deliberately reports as an outstanding reconciliation (exit 3). The refusal itself
  # is asserted separately below, so both halves are covered.
  if ! "$work/tools/sync-from-upstream.sh" "$UPSTREAM" "$work" \
        "$work/tools/upstream-manifest.txt" >/dev/null 2>&1; then
    echo "FAIL  sync exited nonzero on a clean tree even with ALLOW_UNRECONCILED=1"
    exit 1
  fi

  # The reconciliation gate, both directions, constructed rather than hoped for.
  #
  # `deploy/sn39/cathedral-validator-sn39.service` is a declared divergence that
  # lives under a DIRECTORY manifest entry, so a sync always copies upstream over
  # it and always restores ours. Whether that is a RECONCILIATION depends on one
  # thing only: did upstream's bytes move since the manifest recorded them. Both
  # answers are forced below by rewriting the recorded digest, so neither case
  # depends on what upstream happens to contain when the selftest runs.
  # Baseline the whole fixture first: rewrite every declared divergence's
  # recorded upstream digest to the digest the given checkout actually has, so
  # "upstream moved" is false for all of them. Without this the cases below
  # depend on which commit the caller's upstream happens to sit at -- and it
  # matters, because at aa79135 upstream really had changed
  # scripts/build_sn39_release_manifest.py, so the no-reconciliation case failed
  # for a correct reason. Each case then perturbs exactly one path.
  local set_recorded_for  # (path, sha) -> rewrite column 5 in the work manifest
  set_recorded_for() {
    awk -F'\t' -v OFS='\t' -v want="$1" -v sha="$2" '
      $1==want && NF>=5 { $5 = sha } { print }
    ' "$work/MANIFEST.origin.tsv" > "$work/MANIFEST.origin.tsv.tmp"
    mv "$work/MANIFEST.origin.tsv.tmp" "$work/MANIFEST.origin.tsv"
  }
  local dv
  while IFS= read -r dv; do
    [ -n "$dv" ] || continue
    [ -f "$UPSTREAM/$dv" ] || continue
    set_recorded_for "$dv" "$(sha256sum "$UPSTREAM/$dv" | cut -d' ' -f1)"
  done < <(declared_divergences "$work/tools")

  local dir_diverged="deploy/sn39/cathedral-validator-sn39.service"
  if [ -f "$work/$dir_diverged" ] && [ -f "$UPSTREAM/$dir_diverged" ]; then
    local live_sha; live_sha="$(sha256sum "$UPSTREAM/$dir_diverged" | cut -d' ' -f1)"
    local set_recorded
    set_recorded() { set_recorded_for "$dir_diverged" "$1"; }

    # (a) upstream has NOT moved -> no companion, no refusal. This is the case
    # that regressed: the trigger used to be "differs from ours", which is true
    # of every divergence forever, so MUST RECONCILE fired on every sync whether
    # or not anything had changed. An always-on warning is read as noise and
    # deleted unread, and then the one sync that matters looks identical.
    find "$work" -name '*.upstream' -delete
    set_recorded "$live_sha"
    if ! ALLOW_UNRECONCILED=0 "$work/tools/sync-from-upstream.sh" "$UPSTREAM" \
          "$work" "$work/tools/upstream-manifest.txt" >/dev/null 2>&1; then
      echo "FAIL  sync refused although upstream changed no declared divergence"
      echo "      A reconciliation prompt that always fires trains the operator to"
      echo "      ignore it, which is the failure this guard exists to prevent."
      exit 1
    fi
    if find "$work" -name '*.upstream' -print -quit | grep -q .; then
      echo "FAIL  wrote a .upstream companion for a file upstream never changed"
      exit 1
    fi
    echo "PASS  no reconciliation demanded when upstream did not move"

    # (b) upstream HAS moved -> companion written, and the gate REFUSES. A guard
    # that reports success is not a guard.
    set_recorded "0000000000000000000000000000000000000000000000000000000000000000"
    if ALLOW_UNRECONCILED=0 "$work/tools/sync-from-upstream.sh" "$UPSTREAM" "$work" \
          "$work/tools/upstream-manifest.txt" >/dev/null 2>&1; then
      echo "FAIL  sync reported success with an outstanding reconciliation"
      exit 1
    fi
    if [ ! -f "$work/$dir_diverged.upstream" ]; then
      echo "FAIL  refused without leaving upstream's version to reconcile against"
      exit 1
    fi
    echo "PASS  sync refuses while a reconciliation is outstanding"

    find "$work" -name '*.upstream' -delete
    set_recorded "$live_sha"
  fi

  # (c) the same question for a divergence named DIRECTLY in the manifest, which
  # is the class that used to be invisible. The copy loop skips those, so nothing
  # clobbered them, so the old check never compared them and they could never
  # raise a reconciliation however much upstream changed. Seven of the thirteen
  # divergences are in this class, config/validator-mainnet-sn39.toml among them
  # -- the file whose silent revert is the reason this guard exists at all.
  local direct_diverged="scripts/build_sn39_release_manifest.py"
  if grep -qxF "$direct_diverged" "$work/tools/upstream-manifest.txt" \
     && [ -f "$UPSTREAM/$direct_diverged" ]; then
    local direct_live; direct_live="$(sha256sum "$UPSTREAM/$direct_diverged" | cut -d' ' -f1)"
    local set_direct
    set_direct() { set_recorded_for "$direct_diverged" "$1"; }
    local before; before="$(sha256sum "$work/$direct_diverged" | cut -d' ' -f1)"

    set_direct "1111111111111111111111111111111111111111111111111111111111111111"
    if ALLOW_UNRECONCILED=0 "$work/tools/sync-from-upstream.sh" "$UPSTREAM" "$work" \
          "$work/tools/upstream-manifest.txt" >/dev/null 2>&1; then
      echo "FAIL  upstream changed a directly-named divergence and the sync passed"
      echo "      $direct_diverged is skipped by the copy loop, so it is never"
      echo "      clobbered -- which is exactly why it must be checked separately."
      exit 1
    fi
    if [ ! -f "$work/$direct_diverged.upstream" ]; then
      echo "FAIL  no upstream version left to reconcile for $direct_diverged"; exit 1
    fi
    if [ "$(sha256sum "$work/$direct_diverged" | cut -d' ' -f1)" != "$before" ]; then
      echo "FAIL  the local version of $direct_diverged was modified"; exit 1
    fi
    echo "PASS  a directly-named divergence still demands reconciliation"

    find "$work" -name '*.upstream' -delete
    set_direct "$direct_live"
  fi

  if [ -f "$work/$diverged" ] && grep -q "$marker" "$work/$diverged"; then
    echo "PASS  declared divergence survived the sync"
  else
    echo "FAIL  declared divergence was overwritten by upstream: $diverged"
    echo "      A file in manifest.sh ALLOWED_DIVERGENCE holds content this repo"
    echo "      means to differ. Reverting it silently is how the sanitized status"
    echo "      projection was lost."
    exit 1
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
