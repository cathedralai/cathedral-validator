#!/usr/bin/env bash
# Start the localnet miner workers: cathedral-sandbox `cathedral worker serve`
# (the authenticated production TDX posture) with signed validator access,
# worker TLS, and stub TDX evidence. Runs them in the background.
#
# Per miner i (1..LOCALNET_MINERS):
#   - fresh in-worker TLS key and certificate (the image's own generator);
#   - axon advertised on netuid 94 at LOCALNET_HOST_IP:MINER_BASE_PORT+i-1;
#   - worker log in $LOCALNET_HOME/logs/miner<i>.log.
# Shared: one Ed25519 snapshot-signing key, a signed validator-access snapshot
# captured from the local chain, and a refresher that re-signs it every 2 min.
set -euo pipefail
. "$(dirname "$0")/env.sh"

if [ ! -f "$CATHEDRAL_SANDBOX_DIR/cathedral/attest/localnet_stub.py" ]; then
  echo "run_miner: $CATHEDRAL_SANDBOX_DIR lacks cathedral/attest/localnet_stub.py;" \
       "check out cathedral-sandbox branch feature/localnet-e2e there or set CATHEDRAL_SANDBOX_DIR" >&2
  exit 1
fi
if [ -z "$LOCALNET_HOST_IP" ]; then
  echo "run_miner: set LOCALNET_HOST_IP to this host's private IPv4" >&2
  exit 1
fi

ACCESS="$LOCALNET_HOME/access"
mkdir -p "$ACCESS"
chmod 700 "$ACCESS"
ACCESS_TOOL="$CATHEDRAL_SANDBOX_DIR/scripts/cathedral_validator_access.py"
SIGNING_KEY="$ACCESS/snapshot-signing.key"
KEYS="$ACCESS/snapshot-keys.json"
SNAPSHOT="$ACCESS/validator-access.json"
VALIDATOR_HOTKEY=$(validator_hotkey)

if [ ! -f "$SIGNING_KEY" ]; then
  "$VENV_VALIDATOR/bin/python" "$ACCESS_TOOL" init-key \
    --signing-key-id "$SNAPSHOT_KEY_ID" --signing-key-out "$SIGNING_KEY" --keys-out "$KEYS"
fi
KEYS_DIGEST="sha256:$(shasum -a 256 "$KEYS" | cut -d' ' -f1)"

capture() {
  # The access tool reads the chain through bittensor's "local" network name;
  # this points that name at LOCALNET_NETWORK.
  BT_SUBTENSOR_CHAIN_ENDPOINT="$LOCALNET_NETWORK" \
  "$VENV_VALIDATOR/bin/python" "$ACCESS_TOOL" capture \
    --network local --netuid 94 \
    --minimum-stake-rao "$VALIDATOR_MINIMUM_STAKE_RAO" \
    --signing-key-id "$SNAPSHOT_KEY_ID" --signing-key-file "$SIGNING_KEY" \
    --out "$SNAPSHOT" --valid-seconds 900 \
    --require-hotkey "$VALIDATOR_HOTKEY"
}

echo "run_miner: waiting for the validator permit before signing the access snapshot"
"$VENV_VALIDATOR/bin/python" "$LOCALNET_DIR/chain_tool.py" --network "$LOCALNET_NETWORK" \
  wait-permit --hotkey "$VALIDATOR_HOTKEY" --timeout 300
capture

# Refresher: a snapshot is valid 15 min; re-sign every 2 min like the
# production refresh timer. The worker re-verifies when the file changes.
stop_pidfile "$LOCALNET_HOME/pids/snapshot-refresher.pid"
(
  while true; do
    sleep 120
    capture || echo "$(date -u +%FT%TZ) capture failed"
  done
) >>"$LOCALNET_HOME/logs/snapshot-refresher.log" 2>&1 </dev/null &
echo $! >"$LOCALNET_HOME/pids/snapshot-refresher.pid"

for i in $(seq 1 "$LOCALNET_MINERS"); do
  PORT=$((MINER_BASE_PORT + i - 1))
  MINER_DIR="$LOCALNET_HOME/miner$i"
  mkdir -p "$MINER_DIR"
  chmod 700 "$MINER_DIR"
  HOTKEY=$(miner_hotkey "$i")
  stop_pidfile "$LOCALNET_HOME/pids/miner$i.pid"

  "$VENV_MINER/bin/python" - "$MINER_DIR/tls" <<'PY'
import sys
from pathlib import Path
from cathedral.audit_miner_entrypoint import generate_tls_material
generate_tls_material(Path(sys.argv[1]))
PY

  "$VENV_VALIDATOR/bin/python" "$LOCALNET_DIR/chain_tool.py" --network "$LOCALNET_NETWORK" \
    serve-axon --wallet-path "$WALLET_PATH" --wallet-name "localnet-miner$i" \
    --ip "$LOCALNET_HOST_IP" --port "$PORT"

  (
    cd "$CATHEDRAL_SANDBOX_DIR"
    exec env CATHEDRAL_LOCALNET_STUB_EVIDENCE=1 "$VENV_MINER/bin/python" -u -m cathedral.cli \
      worker serve \
      --hotkey "$HOTKEY" \
      --host "$LOCALNET_HOST_IP" --port "$PORT" \
      --tls-certificate "$MINER_DIR/tls/worker.crt" \
      --tls-private-key "$MINER_DIR/tls/worker.key" \
      --validator-access-snapshot "$SNAPSHOT" \
      --validator-access-keys "$KEYS" \
      --validator-access-keys-digest "$KEYS_DIGEST" \
      --validator-access-state "$MINER_DIR/validator-access.sqlite" \
      --validator-minimum-stake-rao "$VALIDATOR_MINIMUM_STAKE_RAO" \
      --validator-network local --validator-netuid 94 \
      --public-endpoint "https://$LOCALNET_HOST_IP:$PORT"
  ) >>"$LOCALNET_HOME/logs/miner$i.log" 2>&1 </dev/null &
  echo $! >"$LOCALNET_HOME/pids/miner$i.pid"
  echo "run_miner: miner$i hotkey $HOTKEY serving https://$LOCALNET_HOST_IP:$PORT (log $LOCALNET_HOME/logs/miner$i.log)"
done

sleep 3
for i in $(seq 1 "$LOCALNET_MINERS"); do
  if ! kill -0 "$(cat "$LOCALNET_HOME/pids/miner$i.pid")" 2>/dev/null; then
    echo "run_miner: miner$i exited; last log lines:" >&2
    tail -20 "$LOCALNET_HOME/logs/miner$i.log" >&2
    exit 1
  fi
  grep -h '"schema": "cathedral_effective_startup_v1"' "$LOCALNET_HOME/logs/miner$i.log" | tail -1
done
