#!/usr/bin/env bash
# In-container role dispatcher for the SN39 no-write preview. It generates the
# wallet config from env and runs the shipped `cathedral-validator serve` with
# a fixed dry-run posture. The container has no chain-writing selector.
set -euo pipefail

ROLE="${1:-validator}"; shift || true
APP=/opt/cathedral-validator
NETWORK="${CATHEDRAL_NETWORK:-finney}"
NETUID="${CATHEDRAL_NETUID:-39}"
DETECT="$APP/deploy/sn39/docker/detect_validator_candidate.py"

_detect() {
  python "$DETECT" --network "$NETWORK" --netuid "$NETUID" \
    --wallet-path "${BT_WALLET_PATH:-/root/.bittensor/wallets}" \
    --wallet-name "${BT_WALLET_NAME:-default}"
}

# Build my-validator.toml from the shipped relay template + the operator's wallet
# labels. Only the four [network] fields are set; the rest is the pinned trust profile.
_gen_config() {
  local out="$1"
  cp "$APP/config/validator-thin-sn39-relay.toml" "$out"
  sed -i \
    -e "s|^name = .*|name = \"$NETWORK\"|" \
    -e "s|^netuid = .*|netuid = $NETUID|" \
    -e "s|^wallet_name = .*|wallet_name = \"${BT_WALLET_NAME:?set BT_WALLET_NAME in .env}\"|" \
    -e "s|^validator_hotkey = .*|validator_hotkey = \"${CATHEDRAL_VALIDATOR_HOTKEY:?set CATHEDRAL_VALIDATOR_HOTKEY in .env}\"|" \
    "$out"
}

case "$ROLE" in
  candidate)
    exec python "$DETECT" --network "$NETWORK" --netuid "$NETUID" \
      --wallet-path "${BT_WALLET_PATH:-/root/.bittensor/wallets}" \
      --wallet-name "${BT_WALLET_NAME:-default}"
    ;;

  validator)
    if [ "$#" -ne 0 ]; then
      echo ">> Docker preview accepts no validator arguments; use the native immutable systemd release for production." >&2
      exit 64
    fi
    if [ "${CATHEDRAL_BROADCAST+x}" = "x" ]; then
      echo ">> CATHEDRAL_BROADCAST is retired. Remove it from .env; Docker is no-write only." >&2
      exit 64
    fi
    if ! _detect; then
      echo ">> No valid validator candidate for this wallet — see guidance above. Not starting." >&2
      exit 2
    fi
    CFG=/state/my-validator.toml
    _gen_config "$CFG"
    echo ">> NO-WRITE PREVIEW: reads chain, verifies, and writes nothing." >&2
    exec cathedral-validator serve --config "$CFG" \
      --runtime-root /state \
      --state-file /state/thin-state.json \
      --jsonl /state/validator-events.jsonl \
      --dry-run
    ;;

  *) echo "unknown role: $ROLE (validator | candidate)" >&2; exit 64 ;;
esac
