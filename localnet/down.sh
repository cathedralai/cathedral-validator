#!/usr/bin/env bash
# Stop the localnet validator, miner workers, and snapshot refresher.
# --chain also stops the chain container (its state survives a docker start).
set -euo pipefail
. "$(dirname "$0")/env.sh"

stop_pidfile "$LOCALNET_HOME/pids/validator.pid"
for file in "$LOCALNET_HOME"/pids/miner*.pid; do
  [ -e "$file" ] && stop_pidfile "$file"
done
stop_pidfile "$LOCALNET_HOME/pids/snapshot-refresher.pid"
if [ "${1:-}" = "--chain" ]; then
  stop_pidfile "$LOCALNET_HOME/pids/chain-watchdog.pid"
  DOCKER_CONTEXT="colima-$LOCALNET_COLIMA_PROFILE" docker stop "$LOCALNET_CONTAINER" >/dev/null || true
fi
echo "down: stopped"
