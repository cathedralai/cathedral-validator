#!/bin/sh
# init-clean-journal.sh — provision a CLEAN validator submission journal for a
# fresh attestation-verified (thin/shadow) deploy.
#
# WHY THIS EXISTS (pitfall learned the hard way): attestation-verified/thin must
# be reachable from a CLEAN validator deploy with a fresh journal, NEVER by
# hand-editing live state. A stale `submission_active_lane="authority"` trips the
# persistent authority->thin fence; a `submission_finalized_id` triggers the
# "finalized common submission recovery record is contradictory" check. Both
# WEDGE startup. This helper creates the runtime root and guarantees the journal
# starts in one of the three permitted clean shapes, and REFUSES to run if a
# journal already exists (which forces the archive-not-edit migration path).
#
# CLEAN JOURNAL is EXACTLY one of:
#   (a) ABSENT   — recommended; the loop creates it on the first thin write.
#   (b) {}       — literal empty object, mode 0600.
#   (c) identity — the optional anti-replay identity-pinned doc containing ONLY
#                  provenance_network, provenance_netuid, submission_genesis_hash,
#                  submission_validator_hotkey (byte-exact pins, no lane/pending/
#                  finalized keys).
#
# Usage:
#   init-clean-journal.sh [--mode absent|empty|identity]
#                         [--state-file PATH]
#                         [--owner USER] [--genesis 0x..] [--hotkey SS58]
#
# Defaults: --mode absent, state-file /var/lib/cathedral-validator/thin-state.json,
# owner cathedral-validator.
set -eu

MODE=absent
STATE_FILE=/var/lib/cathedral-validator/thin-state.json
OWNER=cathedral-validator
GENESIS=""
HOTKEY=""
NETUID=39
NETWORK=finney

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --state-file) STATE_FILE="$2"; shift 2 ;;
    --owner) OWNER="$2"; shift 2 ;;
    --genesis) GENESIS="$2"; shift 2 ;;
    --hotkey) HOTKEY="$2"; shift 2 ;;
    --netuid) NETUID="$2"; shift 2 ;;
    --network) NETWORK="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

RUNTIME_ROOT="$(dirname "$STATE_FILE")"

# HARD REFUSAL: never touch an existing journal. A previously-authority host is
# migrated by archiving, not editing:
#   mv "$STATE_FILE" "$STATE_FILE.authority.$(date +%s).bak"
# and then starting thin against an ABSENT file.
if [ -e "$STATE_FILE" ]; then
  echo "REFUSING: a journal already exists at $STATE_FILE." >&2
  echo "Do NOT hand-edit live state. Archive it first:" >&2
  echo "  mv \"$STATE_FILE\" \"$STATE_FILE.authority.\$(date +%s).bak\"" >&2
  echo "then re-run this helper (or just start thin against the absent file)." >&2
  exit 1
fi

# Runtime root: owner-only, 0700, owned by the service account.
mkdir -p "$RUNTIME_ROOT"
chmod 0700 "$RUNTIME_ROOT"
chown "$OWNER":"$OWNER" "$RUNTIME_ROOT" 2>/dev/null || true

case "$MODE" in
  absent)
    echo "clean journal: ABSENT — $STATE_FILE left uncreated (loop writes it on first thin reservation)."
    ;;
  empty)
    umask 0077
    printf '{}' > "$STATE_FILE"
    chmod 0600 "$STATE_FILE"
    chown "$OWNER":"$OWNER" "$STATE_FILE" 2>/dev/null || true
    echo "clean journal: EMPTY — wrote {} to $STATE_FILE (0600)."
    ;;
  identity)
    if [ -z "$GENESIS" ] || [ -z "$HOTKEY" ]; then
      echo "identity mode requires --genesis 0x<finney-genesis> and --hotkey <ss58>." >&2
      exit 2
    fi
    umask 0077
    # ONLY the four anti-replay identity pins. No submission_active_lane,
    # submission_pending_*, submission_finalized_*, submission_launch_*,
    # submission_continuous_*, policy-version, or attempt-journal keys.
    cat > "$STATE_FILE" <<EOF
{
  "provenance_network": "$NETWORK",
  "provenance_netuid": $NETUID,
  "submission_genesis_hash": "$GENESIS",
  "submission_validator_hotkey": "$HOTKEY"
}
EOF
    chmod 0600 "$STATE_FILE"
    chown "$OWNER":"$OWNER" "$STATE_FILE" 2>/dev/null || true
    echo "clean journal: IDENTITY — wrote 4 anti-replay pins to $STATE_FILE (0600)."
    ;;
  *)
    echo "unknown --mode: $MODE (expected absent|empty|identity)" >&2
    exit 2
    ;;
esac
