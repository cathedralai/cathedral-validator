#!/usr/bin/env bash
# Keep the local chain up unattended. Checked every 60 s:
#   - container stopped: start it;
#   - fewer than 3 nodes running (the VM's OOM killer takes nodes, not the
#     container) or node memory above LOCALNET_CHAIN_MEMORY_LIMIT_MB: restart it.
# The fast-block nodes grow by roughly 15 to 20 MB a minute each. up.sh creates
# the container with --no-purge, so a restart keeps the chain; the validator
# reports NOT_PROVEN for a cycle or two and then confirms again. A container
# created without --no-purge would reset the chain on restart, so it is left
# alone and only logged.
#   - host disk below LOCALNET_MIN_FREE_DISK_GB: stop the chain and the VM, then
#     exit. A full disk gives the VM's docker storage I/O errors and the chain
#     cannot restart (seen 2026-09-29: macOS swap filled a 24 GiB Mac). Nothing
#     restarts it; run up.sh again once space is back.
set -uo pipefail
. "$(dirname "$0")/env.sh"
export DOCKER_CONTEXT="colima-$LOCALNET_COLIMA_PROFILE"
# Default sized for the 6 GiB VM up.sh creates: restart well before the VM's
# OOM killer takes nodes. Raise both together for a bigger VM.
LIMIT_MB=${LOCALNET_CHAIN_MEMORY_LIMIT_MB:-3500}
MIN_FREE_GB=${LOCALNET_MIN_FREE_DISK_GB:-8}

log() { echo "$(date -u +%FT%TZ) $*"; }
# Keep running after the launching terminal closes.
trap '' HUP

while true; do
  free_gb=$(df -Pk "$HOME" | awk 'NR==2 {print int($4 / 1048576)}')
  if [ "$free_gb" -lt "$MIN_FREE_GB" ]; then
    log "host disk has ${free_gb} GiB free (floor ${MIN_FREE_GB} GiB); stopping the chain and the VM"
    docker stop -t 30 "$LOCALNET_CONTAINER" >/dev/null 2>&1
    colima stop -p "$LOCALNET_COLIMA_PROFILE" >/dev/null 2>&1
    exit 0
  fi
  running=$(docker inspect -f '{{.State.Running}}' "$LOCALNET_CONTAINER" 2>/dev/null || echo missing)
  keeps_state=0
  if docker inspect -f '{{json .Args}}' "$LOCALNET_CONTAINER" 2>/dev/null | grep -q -- '--no-purge'; then
    keeps_state=1
  fi
  if [ "$running" = "false" ] && [ "$keeps_state" = 1 ]; then
    log "container stopped; starting it"
    docker start "$LOCALNET_CONTAINER" >/dev/null
  elif [ "$running" = "true" ]; then
    nodes=$(docker exec "$LOCALNET_CONTAINER" sh -c 'ps -o rss= -C node-subtensor' 2>/dev/null)
    count=$(printf '%s\n' "$nodes" | grep -c '[0-9]')
    used=$(printf '%s\n' "$nodes" | awk '{s+=$1} END {print int(s/1024)}')
    if [ "$count" -lt 3 ] || [ "$used" -gt "$LIMIT_MB" ]; then
      if [ "$keeps_state" = 1 ]; then
        log "restarting chain: $count nodes, ${used} MB (limit ${LIMIT_MB} MB)"
        docker restart -t 30 "$LOCALNET_CONTAINER" >/dev/null
      else
        log "chain needs a restart ($count nodes, ${used} MB) but was created without --no-purge; a restart would reset it"
      fi
    fi
  fi
  sleep 60
done
