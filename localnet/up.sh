#!/usr/bin/env bash
# From zero on a Mac with colima: start the local subtensor chain, build the
# two Python environments, and prepare netuid 94 (wallets, registrations,
# stake, permit). Idempotent; rerun it any time.
#
# Needs: colima, docker CLI, uv (https://docs.astral.sh/uv/), and a
# cathedral-sandbox checkout on branch feature/localnet-e2e (CATHEDRAL_SANDBOX_DIR,
# default: a sibling of this repository).
set -euo pipefail
. "$(dirname "$0")/env.sh"

for tool in colima docker uv curl; do
  command -v "$tool" >/dev/null || { echo "up: $tool is required" >&2; exit 1; }
done
if [ ! -f "$CATHEDRAL_SANDBOX_DIR/cathedral/attest/localnet_stub.py" ]; then
  echo "up: $CATHEDRAL_SANDBOX_DIR must be a cathedral-sandbox checkout of feature/localnet-e2e" >&2
  exit 1
fi

# 1. The colima VM and the chain container. Fast blocks (about 0.3 s): the
#    direct writer's 16-block era and freshness window still hold on this Mac
#    because every chain RPC is local. The image holds both runtimes; the
#    argument True selects the fast one.
# Three fast-block nodes grow by roughly 15 to 20 MB a minute each; 12 GiB and
# chain_watchdog.sh keep them up overnight.
if ! colima status -p "$LOCALNET_COLIMA_PROFILE" >/dev/null 2>&1; then
  colima start -p "$LOCALNET_COLIMA_PROFILE" --cpu 4 --memory 12 --disk 30
fi
export DOCKER_CONTEXT="colima-$LOCALNET_COLIMA_PROFILE"
fresh_chain=0
if ! docker ps --format '{{.Names}}' | grep -qx "$LOCALNET_CONTAINER"; then
  if docker ps -a --format '{{.Names}}' | grep -qx "$LOCALNET_CONTAINER"; then
    docker start "$LOCALNET_CONTAINER" >/dev/null
  else
    # --no-purge: a restart keeps the chain instead of starting from genesis.
    docker run -d --name "$LOCALNET_CONTAINER" -p "${LOCALNET_NETWORK##*:}:9944" \
      "$LOCALNET_IMAGE" True --no-purge >/dev/null
  fi
  fresh_chain=1
fi
echo "up: waiting for $LOCALNET_NETWORK"
for _ in $(seq 1 120); do
  if curl -fsS -H 'Content-Type: application/json' \
       -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader","params":[]}' \
       "http://127.0.0.1:${LOCALNET_NETWORK##*:}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# 2. Python environments. The validator pins bittensor>=10.4,<11.
if [ ! -x "$VENV_VALIDATOR/bin/cathedral-validator" ]; then
  uv venv -q -p "$PYTHON_VERSION" "$VENV_VALIDATOR"
  uv pip install -q -p "$VENV_VALIDATOR/bin/python" -e "${VALIDATOR_REPO}[test]"
fi
if [ ! -x "$VENV_MINER/bin/python" ] || ! "$VENV_MINER/bin/python" -c 'import cathedral.attest.localnet_stub, sr25519' 2>/dev/null; then
  uv venv -q -p "$PYTHON_VERSION" "$VENV_MINER"
  uv pip install -q -p "$VENV_MINER/bin/python" -e "${CATHEDRAL_SANDBOX_DIR}[validator-access-worker]"
fi

# 3. A chain that restarted from genesis forgets every subnet and weight. The
#    validator journal then names blocks this chain never had, so it is moved
#    aside (kept, never deleted) before the new chain is prepared.
if [ "$fresh_chain" = 1 ] && [ -d "$LOCALNET_HOME/validator-home" ]; then
  if ! "$VENV_VALIDATOR/bin/python" - "$LOCALNET_NETWORK" <<'PY'
import sys
import bittensor as bt
st = bt.Subtensor(network=sys.argv[1])
sys.exit(0 if 94 in st.get_all_subnets_netuid() else 1)
PY
  then
    mv "$LOCALNET_HOME/validator-home" "$LOCALNET_HOME/validator-home.stale-$(date -u +%Y%m%dT%H%M%SZ)"
    rm -f "$LOCALNET_HOME/access/validator-access.json"
    rm -f "$LOCALNET_HOME"/miner*/validator-access.sqlite
  fi
fi

# 4. netuid 94, wallets, registrations, stake.
"$VENV_VALIDATOR/bin/python" "$LOCALNET_DIR/setup_chain.py" \
  --network "$LOCALNET_NETWORK" --wallet-path "$WALLET_PATH" \
  --miners "$LOCALNET_MINERS" --out "$LOCALNET_HOME/chain.json"
# 5. Watchdog: restarts the chain container when a node dies or memory runs high.
if ! { [ -f "$LOCALNET_HOME/pids/chain-watchdog.pid" ] && kill -0 "$(cat "$LOCALNET_HOME/pids/chain-watchdog.pid")" 2>/dev/null; }; then
  "$LOCALNET_DIR/chain_watchdog.sh" >>"$LOCALNET_HOME/logs/chain-watchdog.log" 2>&1 </dev/null &
  echo $! >"$LOCALNET_HOME/pids/chain-watchdog.pid"
fi
echo "up: chain ready; next: $LOCALNET_DIR/run_miner.sh && $LOCALNET_DIR/run_validator.sh && $LOCALNET_DIR/check.sh"
