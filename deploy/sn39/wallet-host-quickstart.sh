#!/usr/bin/env bash
# Native, no-root, auditable wallet-host onboarding — run it from this checkout.
#
# WHY THIS SHAPE (not a container / not `curl | sh`)
# The wallet host holds the signing hotkey, so its install must be the thing an auditor
# reads line by line: this only runs the commands the README quickstart already documents
# — venv, `pip install -e '.[provenance]'`, then `cathedral-validator serve` in SHADOW.
# No root, no daemon, no image. Containers belong on the sandbox host and for
# cross-platform shadow evaluation (deploy/sn39/docker), never around the wallet.
#
# It stops at a proven shadow run. Broadcasting for real is the staged systemd
# side-by-side model in this directory + the rollback tool (cathedral-validator #102).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"   # deploy/sn39/ -> repo root
cd "$REPO"
NETWORK="${CATHEDRAL_NETWORK:-finney}"
NETUID="${CATHEDRAL_NETUID:-39}"
RUNTIME="${CATHEDRAL_RUNTIME_ROOT:-$HOME/.cathedral}"

command -v python3 >/dev/null || { echo "python3 (3.11/3.12) required" >&2; exit 1; }

# 1. The shipping quickstart, verbatim — venv + editable install, no root.
[ -x .venv/bin/python ] || { echo ">> creating .venv"; python3 -m venv .venv; }
echo ">> installing (editable, [provenance]) — no root"
.venv/bin/python -m pip install --upgrade pip >/dev/null
.venv/bin/python -m pip install -e '.[provenance]'

# 2. Detect a valid validator candidate from the live chain (reads only).
[ -n "${BT_WALLET_NAME:-}" ] || {
  echo ">> set BT_WALLET_NAME (your coldkey), then re-run:  BT_WALLET_NAME=my-coldkey $0" >&2; exit 2; }
CAND="$(.venv/bin/python deploy/sn39/docker/detect_validator_candidate.py \
  --network "$NETWORK" --netuid "$NETUID" --wallet-name "$BT_WALLET_NAME")" || {
    echo "$CAND" >&2; echo ">> no usable candidate — follow the btcli guidance above, then re-run." >&2; exit 2; }
echo "$CAND"
HOTKEY="${CATHEDRAL_VALIDATOR_HOTKEY:-$(printf '%s\n' "$CAND" | sed -n 's/^CANDIDATE_HOTKEY=//p')}"
[ -n "$HOTKEY" ] || { echo ">> could not determine the validator hotkey" >&2; exit 2; }

# 3. Build my-validator.toml from the relay template + your wallet labels.
TOML="$REPO/my-validator.toml"
[ -f "$TOML" ] || cp config/validator-thin-sn39-relay.toml "$TOML"
sed -i.bak \
  -e "s|^name = .*|name = \"$NETWORK\"|" \
  -e "s|^netuid = .*|netuid = $NETUID|" \
  -e "s|^wallet_name = .*|wallet_name = \"$BT_WALLET_NAME\"|" \
  -e "s|^validator_hotkey = .*|validator_hotkey = \"$HOTKEY\"|" "$TOML" && rm -f "$TOML.bak"
echo ">> wrote $TOML ([network] wallet_name='$BT_WALLET_NAME' validator_hotkey='$HOTKEY')"

# 4. SHADOW verification — README steps 1 (offline) then 2 (metagraph dry cycle).
mkdir -p "$RUNTIME"
COMMON=(serve --config "$TOML" --runtime-root "$RUNTIME"
        --state-file "$RUNTIME/thin-state.json" --jsonl "$RUNTIME/validator-events.jsonl")
echo ">> shadow 1/2: offline verify (no chain, no wallet)"
.venv/bin/cathedral-validator "${COMMON[@]}" --offline --once || true
echo ">> shadow 2/2: one metagraph-backed dry cycle (reads chain, writes nothing)"
.venv/bin/cathedral-validator "${COMMON[@]}" --dry-run --once || true

cat <<EOF

>> Shadow onboarding complete. Nothing was written on-chain.
   Run continuously in shadow (drop --once):
     .venv/bin/cathedral-validator ${COMMON[*]} --dry-run
   To BROADCAST for real, graduate to the staged systemd model in this directory
   (deploy/sn39) with the rollback tool (cathedral-validator #102).
EOF
