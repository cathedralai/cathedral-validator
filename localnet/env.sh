# shellcheck shell=bash
# Shared settings for the localnet harness. Sourced by the other scripts.
# Every value can be overridden from the environment.

LOCALNET_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VALIDATOR_REPO=$(cd "$LOCALNET_DIR/.." && pwd)

# Runtime state: wallets, snapshot keys, TLS material, logs, journal, pids.
LOCALNET_HOME=${LOCALNET_HOME:-$LOCALNET_DIR/.run}
# A cathedral-sandbox checkout that carries cathedral/attest/localnet_stub.py.
CATHEDRAL_SANDBOX_DIR=${CATHEDRAL_SANDBOX_DIR:-$(cd "$VALIDATOR_REPO/.." && pwd)/cathedral-sandbox}

LOCALNET_NETWORK=${LOCALNET_NETWORK:-ws://127.0.0.1:9944}
LOCALNET_CONTAINER=${LOCALNET_CONTAINER:-cathedral-localchain}
LOCALNET_COLIMA_PROFILE=${LOCALNET_COLIMA_PROFILE:-cathedral-localnet}
LOCALNET_IMAGE=${LOCALNET_IMAGE:-ghcr.io/opentensor/subtensor-localnet:devnet-ready}

# Python environments: the validator's pin is bittensor>=10.4,<11.
VENV_VALIDATOR=${VENV_VALIDATOR:-$LOCALNET_HOME/venv-validator}
VENV_MINER=${VENV_MINER:-$LOCALNET_HOME/venv-miner}
PYTHON_VERSION=${PYTHON_VERSION:-3.12}

WALLET_PATH=${WALLET_PATH:-$LOCALNET_HOME/wallets}
LOCALNET_MINERS=${LOCALNET_MINERS:-2}
MINER_BASE_PORT=${MINER_BASE_PORT:-8091}
# Workers advertise this address on chain. The chain refuses 127.0.0.1, so
# the default is the first private IPv4 of this host.
if [ -z "${LOCALNET_HOST_IP:-}" ]; then
  LOCALNET_HOST_IP=$(ipconfig getifaddr en0 2>/dev/null || true)
  if [ -z "$LOCALNET_HOST_IP" ]; then
    LOCALNET_HOST_IP=$(ifconfig 2>/dev/null | awk '/inet / && $2 != "127.0.0.1" {print $2; exit}')
  fi
fi
# The worker and the snapshot must agree on this floor exactly.
VALIDATOR_MINIMUM_STAKE_RAO=${VALIDATOR_MINIMUM_STAKE_RAO:-1000000000}
SNAPSHOT_KEY_ID=${SNAPSHOT_KEY_ID:-localnet-access}
VALIDATOR_INTERVAL_SECONDS=${VALIDATOR_INTERVAL_SECONDS:-30}

mkdir -p "$LOCALNET_HOME/pids" "$LOCALNET_HOME/logs"
chmod 700 "$LOCALNET_HOME"

validator_hotkey() {
  "$VENV_VALIDATOR/bin/python" - "$WALLET_PATH" <<'PY'
import sys
from bittensor_wallet import Wallet
print(Wallet(name="localnet-validator", hotkey="default", path=sys.argv[1]).hotkey.ss58_address)
PY
}

miner_hotkey() {
  "$VENV_VALIDATOR/bin/python" - "$WALLET_PATH" "$1" <<'PY'
import sys
from bittensor_wallet import Wallet
print(Wallet(name=f"localnet-miner{sys.argv[2]}", hotkey="default", path=sys.argv[1]).hotkey.ss58_address)
PY
}

stop_pidfile() {
  local file=$1
  if [ -f "$file" ]; then
    local pid
    pid=$(cat "$file")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$file"
  fi
}
