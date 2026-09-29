#!/usr/bin/env bash
# Run the direct validator (`cathedral-validator`) from this checkout against
# the local chain, in development localnet mode. Background by default; pass
# --once to run one cycle in the foreground and exit with its status.
#
# Localnet mode (CATHEDRAL_LOCALNET=1) swaps exactly these pins, see
# cathedral_thin/independent_runtime/localnet.py:
#   Finney genesis      -> this chain's genesis (never Finney's)
#   --network finney    -> ws://127.0.0.1:<port> only
#   release TDX QVL     -> localnet/stub_tdx_verifier.py, pinned by digest
#   public miner IPs    -> private, CGNAT, and loopback IPv4 also dialed
#   request network     -> "local"
#   AMD SNP verifier    -> not constructed (the SNP policy is still loaded)
# The writer journal lives under $LOCALNET_HOME/validator-home, never ~.
set -euo pipefail
. "$(dirname "$0")/env.sh"

MODE=background
if [ "${1:-}" = "--once" ]; then
  MODE=once
fi

VALIDATOR_HOTKEY=$(validator_hotkey)
GENESIS=$("$VENV_VALIDATOR/bin/python" "$LOCALNET_DIR/chain_tool.py" --network "$LOCALNET_NETWORK" genesis)
VALIDATOR_HOME="$LOCALNET_HOME/validator-home"
mkdir -p "$VALIDATOR_HOME"
chmod 700 "$VALIDATOR_HOME"

# The validator requires a reviewed SNP policy file. No localnet miner sends
# SNP evidence; this one admits a single all-zero measurement no real guest has.
SNP_POLICY="$LOCALNET_HOME/snp-policy.localnet.json"
if [ ! -f "$SNP_POLICY" ]; then
  printf '%s\n' '{"generations":{"genoa":{"allowed_measurements":["000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"],"minimum_tcb":"0x0000000000000001"}},"schema":"cathedral_amd_sev_snp_policy_v1"}' >"$SNP_POLICY"
  chmod 644 "$SNP_POLICY"
fi

ARGS=(
  --network "$LOCALNET_NETWORK"
  --wallet-name localnet-validator --wallet-hotkey default --wallet-path "$WALLET_PATH"
  --expected-hotkey "$VALIDATOR_HOTKEY"
  --qvl "$LOCALNET_DIR/stub_tdx_verifier.py"
  --snp-policy "$SNP_POLICY"
  --snpguest localnet-unused
  --interval-seconds "$VALIDATOR_INTERVAL_SECONDS"
  --confirm-direct-write
)

run() {
  # Keep running after the launching terminal closes.
  trap '' HUP
  cd "$VALIDATOR_REPO"
  exec env HOME="$VALIDATOR_HOME" \
    CATHEDRAL_LOCALNET=1 CATHEDRAL_LOCALNET_GENESIS_HASH="$GENESIS" \
    "$VENV_VALIDATOR/bin/cathedral-validator" "$@"
}

if [ "$MODE" = once ]; then
  (run "${ARGS[@]}" --once)
  exit $?
fi

stop_pidfile "$LOCALNET_HOME/pids/validator.pid"
(run "${ARGS[@]}") >>"$LOCALNET_HOME/logs/validator.log" 2>&1 </dev/null &
echo $! >"$LOCALNET_HOME/pids/validator.pid"
echo "run_validator: validator $VALIDATOR_HOTKEY running (log $LOCALNET_HOME/logs/validator.log)"
sleep 5
if ! kill -0 "$(cat "$LOCALNET_HOME/pids/validator.pid")" 2>/dev/null; then
  echo "run_validator: validator exited; last log lines:" >&2
  tail -20 "$LOCALNET_HOME/logs/validator.log" >&2
  exit 1
fi
