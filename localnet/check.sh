#!/usr/bin/env bash
# Prove the loop from chain state: the validator's weight row on netuid 94
# names a miner UID, and after an epoch that miner's incentive and emission are
# above zero. Polls until PASS or --timeout seconds (default 180).
# Writes the last observation to $LOCALNET_HOME/evidence/check-<utc>.json.
set -euo pipefail
. "$(dirname "$0")/env.sh"

TIMEOUT=180
if [ "${1:-}" = "--timeout" ]; then
  TIMEOUT=$2
fi
VALIDATOR_HOTKEY=$(validator_hotkey)
mkdir -p "$LOCALNET_HOME/evidence"
OUT="$LOCALNET_HOME/evidence/check-$(date -u +%Y%m%dT%H%M%SZ).json"
DEADLINE=$(( $(date +%s) + TIMEOUT ))
while true; do
  if "$VENV_VALIDATOR/bin/python" "$LOCALNET_DIR/chain_tool.py" --network "$LOCALNET_NETWORK" \
       check --validator-hotkey "$VALIDATOR_HOTKEY" --require-pass >"$OUT"; then
    echo "check: PASS (evidence $OUT)"
    "$VENV_VALIDATOR/bin/python" - "$OUT" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
print(f"block {doc['block']} validator uid {doc['validator_uid']} weights {doc['validator_weights']}")
for row in doc["rows"]:
    print(f"  uid {row['uid']:>2} permit {str(row['validator_permit']):5} "
          f"incentive {row['incentive']:.4f} emission {row['emission']:.4f} "
          f"dividends {row['dividends']:.4f} axon {row['axon']}")
PY
    exit 0
  fi
  if [ "$(date +%s)" -ge "$DEADLINE" ]; then
    echo "check: NOT_YET after ${TIMEOUT}s (last observation $OUT)" >&2
    exit 1
  fi
  sleep 5
done
