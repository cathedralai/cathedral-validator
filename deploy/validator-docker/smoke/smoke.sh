#!/bin/bash
# Offline container smoke for the SN94 bootstrap image.
# Builds the image (unless --image is set), starts it with the documented
# flags, and never talks to mainnet or the signed release channel.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SMOKE_DIR="$ROOT/deploy/validator-docker/smoke"
IMAGE="${CATHEDRAL_VALIDATOR_SMOKE_IMAGE:-cathedral-validator:smoke}"
SKIP_BUILD=0
KEEP=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --image)
      IMAGE="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --keep)
      KEEP=1
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

WORK="$(mktemp -d /tmp/cathedral-smoke.XXXXXX)"
NAMES=()
cleanup() {
  status=$?
  if [ "$KEEP" -eq 0 ]; then
    for name in "${NAMES[@]+"${NAMES[@]}"}"; do
      docker rm -f "$name" >/dev/null 2>&1 || true
    done
    as_root rm -rf "$WORK"
  else
    echo "keeping $WORK" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

if [ "$SKIP_BUILD" -eq 0 ]; then
  docker build \
    --file "$ROOT/deploy/validator-docker/Dockerfile" \
    --tag "$IMAGE" \
    "$ROOT"
fi

# Throwaway hotkey. Not a wallet. No seed, no mnemonic.
HOTKEY="$WORK/hotkey"
printf '%s\n' '{"ss58Address":"5SmokeTestPublicAddressNotOnChain","smoke":true}' >"$HOTKEY"
chmod 0600 "$HOTKEY"
POLICY="$SMOKE_DIR/snp-policy.json"
EXPECTED="5SmokeTestPublicAddressNotOnChain"

seed_volume() {
  local volume="$1"
  mkdir -p "$volume/releases/current/bin" "$volume/update" "$volume/validator"
  install -m 0755 "$SMOKE_DIR/stub_validator.sh" \
    "$volume/releases/current/bin/cathedral-validator"
  printf '%s\n' '{"schema":"cathedral_validator_updater_state_v3","selected_channel":"stable","channels":{},"pending":null}' \
    >"$volume/update/state.json"
  chmod 0600 "$volume/update/state.json"
  # Named volumes are root-owned. A host bind owned by the runner cannot be
  # chmod'd inside --cap-drop ALL (needs FOWNER).
  as_root chown -R root:root "$volume"
}

run_flags() {
  local name="$1"
  local volume="$2"
  shift 2
  docker run -d --name "$name" \
    --restart no \
    --network none \
    --stop-timeout 150 \
    --read-only --tmpfs /tmp --tmpfs /run --tmpfs /etc/cathedral-validator \
    --security-opt no-new-privileges \
    --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
    --cap-add CHOWN --cap-add DAC_READ_SEARCH \
    -v "$volume:/var/lib/cathedral" \
    -v "$HOTKEY:/run/secrets/hotkey:ro" \
    -v "$SMOKE_DIR/stub_update.py:/usr/local/lib/cathedral-container/container_update.py:ro" \
    -e "CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=$EXPECTED" \
    "$@" \
    "$IMAGE"
}

wait_log() {
  local name="$1"
  local needle="$2"
  local seconds="$3"
  local i=0
  while [ "$i" -lt "$seconds" ]; do
    if docker logs "$name" 2>&1 | grep -F -q -- "$needle"; then
      return 0
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$name")" = "false" ]; then
      docker logs "$name" >&2 || true
      echo "container $name exited before matching: $needle" >&2
      return 1
    fi
    sleep 1
    i=$((i + 1))
  done
  docker logs "$name" >&2 || true
  echo "timed out waiting for: $needle" >&2
  return 1
}

assert_running() {
  local name="$1"
  if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != "true" ]; then
    docker logs "$name" >&2 || true
    echo "container $name is not running" >&2
    return 1
  fi
}

# Missing SNP policy refuses clearly and does not start a writer.
missing="$WORK/missing-snp"
mkdir -p "$missing/releases" "$missing/update" "$missing/validator"
printf '%s\n' '{"schema":"cathedral_validator_updater_state_v3","selected_channel":"stable","channels":{},"pending":null}' \
  >"$missing/update/state.json"
name_missing="cathedral-smoke-missing-snp"
NAMES+=("$name_missing")
docker run --name "$name_missing" \
  --restart no \
  --network none \
  --stop-timeout 150 \
  --read-only --tmpfs /tmp --tmpfs /run --tmpfs /etc/cathedral-validator \
  --security-opt no-new-privileges \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --cap-add CHOWN --cap-add DAC_READ_SEARCH \
  -v "$missing:/var/lib/cathedral" \
  -v "$HOTKEY:/run/secrets/hotkey:ro" \
  -e "CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=$EXPECTED" \
  "$IMAGE" >/dev/null || true
missing_code="$(docker inspect -f '{{.State.ExitCode}}' "$name_missing")"
missing_logs="$(docker logs "$name_missing" 2>&1 || true)"
if [ "$missing_code" != "2" ]; then
  printf '%s\n' "$missing_logs" >&2
  echo "missing SNP policy should exit 2, got $missing_code" >&2
  exit 1
fi
printf '%s\n' "$missing_logs" | grep -F -q "snp-policy.json"
printf '%s\n' "$missing_logs" | grep -F -q "does not ship a default policy"
echo "ok missing SNP policy refused"

# Happy path: reconcile, exec, uid split, SIGTERM.
volume="$WORK/state"
seed_volume "$volume"
name="cathedral-smoke-run"
NAMES+=("$name")
run_flags "$name" "$volume" \
  -v "$POLICY:/etc/cathedral/snp-policy.json:ro"
wait_log "$name" "CATHEDRAL_VALIDATOR_SUPERVISOR_UPDATER first_install=false reconcile=true" 30
wait_log "$name" "CATHEDRAL_VALIDATOR_UPDATE_RECONCILED" 30
wait_log "$name" "CATHEDRAL_VALIDATOR_SUPERVISOR_START" 30
wait_log "$name" "CATHEDRAL_VALIDATOR_SMOKE_EXEC uid=910" 30
assert_running "$name"

mode_uid="$(docker exec "$name" stat -c '%a %u' /run/cathedral-validator-wallet/validator/hotkeys/default)"
if [ "$mode_uid" != "400 910" ]; then
  echo "hotkey dest should be 0400 uid 910, got $mode_uid" >&2
  exit 1
fi
docker exec -u cathedral-validator "$name" \
  cat /run/cathedral-validator-wallet/validator/hotkeys/default >/dev/null
if docker exec "$name" /usr/bin/setpriv \
  --inh-caps=-dac_override,-dac_read_search \
  --ambient-caps=-dac_override,-dac_read_search \
  --bounding-set=-dac_override,-dac_read_search \
  -- /bin/cat /run/cathedral-validator-wallet/validator/hotkeys/default \
  >/dev/null 2>&1; then
  echo "updater-style root without DAC should not read the hotkey" >&2
  exit 1
fi

record="$(docker exec "$name" cat /var/lib/cathedral/update/smoke-updater.json)"
printf '%s\n' "$record" | grep -F -q '"install_root":"/var/lib/cathedral/releases"'
printf '%s\n' "$record" | grep -F -q '"state_root":"/var/lib/cathedral/update"'
printf '%s\n' "$record" | grep -F -q '"reconcile_boot":true'
printf '%s\n' "$record" | grep -F -q '"install_root_is_symlink":false'
echo "ok reconcile used real volume roots and validator exec'd as uid 910"

start="$(date +%s)"
docker stop --time 20 "$name" >/dev/null
elapsed=$(($(date +%s) - start))
if [ "$elapsed" -ge 20 ]; then
  echo "SIGTERM did not stop within the grace ($elapsed seconds)" >&2
  exit 1
fi
echo "ok SIGTERM stopped in ${elapsed}s"

# Exit 2 and 3 stay stopped inside a running container.
for code in 2 3; do
  held_volume="$WORK/held-$code"
  seed_volume "$held_volume"
  held="cathedral-smoke-held-$code"
  NAMES+=("$held")
  run_flags "$held" "$held_volume" \
    -v "$POLICY:/etc/cathedral/snp-policy.json:ro" \
    -e "CATHEDRAL_VALIDATOR_SMOKE_EXIT=$code"
  wait_log "$held" "CATHEDRAL_VALIDATOR_SUPERVISOR_TERMINAL exit=$code" 30
  sleep 3
  assert_running "$held"
  if docker logs "$held" 2>&1 | grep -F -q "CATHEDRAL_VALIDATOR_SUPERVISOR_START"; then
    starts="$(docker logs "$held" 2>&1 | grep -F -c "CATHEDRAL_VALIDATOR_SUPERVISOR_START" || true)"
    if [ "$starts" -gt 1 ]; then
      echo "exit $code restarted the validator" >&2
      exit 1
    fi
  fi
  docker stop --time 10 "$held" >/dev/null
  echo "ok exit $code stayed stopped"
done

echo "CATHEDRAL_VALIDATOR_CONTAINER_SMOKE_OK image=$IMAGE"
