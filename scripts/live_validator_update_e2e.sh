#!/usr/bin/env bash
# Live, no-chain resilience test for the signed Cathedral validator updater.
#
# This controller is intentionally inert unless invoked with --execute.  It
# reads source commits and attestations only from cathedralai/cathedral-validator.
# Every write goes to the separate public TEST_GITHUB_REPOSITORY mirror: unique
# hostile/runtime branches plus one content-addressed immutable test bootstrap
# prerelease. It creates two bounded GCP hosts, exercises the real
# updater/bootstrap/systemd path, records evidence, and deletes only the exact
# GCP resources it created. Public mirror artifacts remain as the test record.

set -Eeuo pipefail
set +x
umask 077

readonly EXPECTED_PROJECT="polaris-tdx-attest"
readonly SOURCE_GITHUB_REPOSITORY="cathedralai/cathedral-validator"
readonly MACHINE_TYPE="e2-standard-2"
readonly VM_COUNT=2
readonly MAX_RUN_SECONDS=14400
readonly BOOT_DISK_GB=20
readonly HARD_COST_CAP_USD="2.00"
readonly TEST_COST_CAP_USD="0.65"
readonly NETWORK_ALLOWANCE_USD="0.20"
readonly VM_HOURLY_CEILING_USD="0.075"
readonly DISK_GB_HOURLY_CEILING_USD="0.00015"
readonly FIXED_CHANNEL_CACHE_MAX_SECONDS=300
readonly UPDATE_TIMER_INTERVAL_SECONDS=60
readonly REACTIVATION_PROOF_DELAY_SECONDS=60
readonly REACTIVATION_PROOF_REARM_SECONDS=86400
readonly REACTIVATION_PROOF_WAIT_SECONDS=1860
# The signed timer services retain the production updater's 20-minute
# operation deadline plus the service manager's two-minute shutdown margin. A
# fixed channel can also serve cached metadata until the next timer tick, so
# the controller must not confuse a still-permitted update with a failed one.
# Keep an extra three minutes beyond every enforced phase.
readonly TIMER_OPERATION_TIMEOUT_SECONDS=1200
readonly TIMER_SYSTEMD_MARGIN_SECONDS=120
readonly FIXED_CHANNEL_WAIT_MARGIN_SECONDS=180
readonly FIXED_CHANNEL_WAIT_SECONDS=1860
readonly CAPTURE_RETRY_ATTEMPTS=6
readonly CAPTURE_RETRY_INTERVAL_SECONDS=5
readonly CRASH_PENDING_WAIT_SECONDS=120
# This reserves planning time for the lightweight final checks. It is not a
# command timeout. The fresh elapsed-time gate below remains authoritative.
readonly CRASH_POST_PENDING_RESERVE_SECONDS=60
readonly TRANSIENT_UPDATE_TIMEOUT_SECONDS=240
readonly TRANSIENT_SYSTEMD_TIMEOUT_SECONDS=360
readonly RESET_MINIMUM_HEADROOM_SECONDS=60
readonly RESET_REQUEST_TIMEOUT_SECONDS=45
readonly PRE_ACTION_READ_ATTEMPTS=3
readonly PRE_ACTION_RETRY_INTERVAL_SECONDS=2
readonly VALIDATOR_SERVICE_CONTROL_TIMEOUT_SECONDS=300
readonly DIRECT_START_TIMEOUT_SECONDS=300
readonly READINESS_DELAY_MAX_SECONDS=300
readonly IMAGE_PROJECT="ubuntu-os-cloud"
readonly IMAGE_FAMILY="ubuntu-2404-lts-amd64"
readonly CLOUD_RESOURCE_MANAGER_API="cloudresourcemanager.googleapis.com"
readonly IAP_API="iap.googleapis.com"
readonly IAP_TCP_SOURCE_RANGE="35.235.240.0/20"
readonly IAP_CONTROLLER_TRANSPORT="gcp_iap_tcp_forwarding"
readonly GOOGLE_API_MAX_ATTEMPTS=3
readonly GOOGLE_API_TOTAL_TIMEOUT_SECONDS=100
readonly GOOGLE_AUTH_TIMEOUT_SECONDS=10
readonly GOOGLE_API_CURL_TIMEOUT_SECONDS=20
readonly IAP_SCP_MAX_ATTEMPTS=3
readonly TEARDOWN_DELETE_ATTEMPTS=5
readonly TEARDOWN_RETRY_INTERVAL_SECONDS=5
readonly CONTROLLER_PROJECT_PERMISSIONS=(
  "compute.disks.create"
  "compute.disks.delete"
  "compute.disks.get"
  "compute.disks.list"
  "compute.firewalls.create"
  "compute.firewalls.delete"
  "compute.firewalls.get"
  "compute.firewalls.list"
  "compute.globalOperations.get"
  "compute.instances.get"
  "compute.instances.list"
  "compute.instances.create"
  "compute.instances.delete"
  "compute.instances.reset"
  "compute.instances.setLabels"
  "compute.instances.setMetadata"
  "compute.instances.setTags"
  "compute.machineTypes.get"
  "compute.networks.create"
  "compute.networks.delete"
  "compute.networks.get"
  "compute.networks.list"
  "compute.networks.updatePolicy"
  "compute.networks.use"
  "compute.networks.useExternalIp"
  "compute.projects.get"
  "compute.regionOperations.get"
  "compute.subnetworks.create"
  "compute.subnetworks.delete"
  "compute.subnetworks.get"
  "compute.subnetworks.list"
  "compute.subnetworks.use"
  "compute.subnetworks.useExternalIp"
  "compute.zoneOperations.get"
  "iap.tunnelInstances.accessViaIAP"
)
readonly CONTROLLER_PROJECT_PERMISSION_REQUEST='{"permissions":["compute.disks.create","compute.disks.delete","compute.disks.get","compute.disks.list","compute.firewalls.create","compute.firewalls.delete","compute.firewalls.get","compute.firewalls.list","compute.globalOperations.get","compute.instances.create","compute.instances.delete","compute.instances.get","compute.instances.list","compute.instances.reset","compute.instances.setLabels","compute.instances.setMetadata","compute.instances.setTags","compute.machineTypes.get","compute.networks.create","compute.networks.delete","compute.networks.get","compute.networks.list","compute.networks.updatePolicy","compute.networks.use","compute.networks.useExternalIp","compute.projects.get","compute.regionOperations.get","compute.subnetworks.create","compute.subnetworks.delete","compute.subnetworks.get","compute.subnetworks.list","compute.subnetworks.use","compute.subnetworks.useExternalIp","compute.zoneOperations.get","iap.tunnelInstances.accessViaIAP"]}'
readonly IAP_INSTANCE_PERMISSION_REQUEST='{"permissions":["iap.tunnelInstances.accessViaIAP"]}'
REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly HARNESS_SOURCE="$REPOSITORY_ROOT/tests/live/cathedral_no_chain_readiness.py"
readonly FAULT_ORIGIN_SOURCE="$REPOSITORY_ROOT/tests/live/tampered_https_origin.py"
readonly STATE_WAITER_SOURCE="$REPOSITORY_ROOT/tests/live/wait_updater_state.py"
readonly SIGNER="$REPOSITORY_ROOT/deploy/validator-update/build_signed_release.py"
readonly PUBLISHER="$REPOSITORY_ROOT/deploy/validator-update/publish_github_channel.py"
readonly BOOTSTRAP_BUILDER="$REPOSITORY_ROOT/deploy/validator-update/build_updater_bundle.py"
readonly BOOTSTRAP_PUBLISHER="$REPOSITORY_ROOT/deploy/validator-update/publish_github_bootstrap.py"

if (( FIXED_CHANNEL_WAIT_SECONDS < FIXED_CHANNEL_CACHE_MAX_SECONDS + UPDATE_TIMER_INTERVAL_SECONDS + TIMER_OPERATION_TIMEOUT_SECONDS + TIMER_SYSTEMD_MARGIN_SECONDS + FIXED_CHANNEL_WAIT_MARGIN_SECONDS )); then
  printf 'REFUSED: fixed-channel wait must cover cache, timer, updater, systemd, and margin bounds\n' >&2
  exit 2
fi
if (( TRANSIENT_UPDATE_TIMEOUT_SECONDS < CRASH_PENDING_WAIT_SECONDS + CRASH_POST_PENDING_RESERVE_SECONDS + RESET_MINIMUM_HEADROOM_SECONDS )); then
  printf 'REFUSED: transient updater must cover pending wait, pre-action reserve, and action headroom\n' >&2
  exit 2
fi
if (( RESET_REQUEST_TIMEOUT_SECONDS >= RESET_MINIMUM_HEADROOM_SECONDS )); then
  printf 'REFUSED: reset request timeout must fit inside reserved action headroom\n' >&2
  exit 2
fi
if (( TRANSIENT_SYSTEMD_TIMEOUT_SECONDS < TRANSIENT_UPDATE_TIMEOUT_SECONDS + TIMER_SYSTEMD_MARGIN_SECONDS )); then
  printf 'REFUSED: transient systemd timeout must outlive the updater deadline and manager margin\n' >&2
  exit 2
fi
if (( DIRECT_START_TIMEOUT_SECONDS < TRANSIENT_UPDATE_TIMEOUT_SECONDS + RESET_MINIMUM_HEADROOM_SECONDS )); then
  printf 'REFUSED: direct-service test bound must cover the transient updater and action headroom\n' >&2
  exit 2
fi
if (( READINESS_DELAY_MAX_SECONDS < TRANSIENT_UPDATE_TIMEOUT_SECONDS + RESET_MINIMUM_HEADROOM_SECONDS )); then
  printf 'REFUSED: readiness test bound must cover the transient updater and action headroom\n' >&2
  exit 2
fi
if (( DIRECT_START_TIMEOUT_SECONDS > VALIDATOR_SERVICE_CONTROL_TIMEOUT_SECONDS )); then
  printf 'REFUSED: direct-service test bound exceeds the fixed updater service-control ceiling\n' >&2
  exit 2
fi
if (( READINESS_DELAY_MAX_SECONDS > VALIDATOR_SERVICE_CONTROL_TIMEOUT_SECONDS )); then
  printf 'REFUSED: readiness test bound exceeds the fixed updater service-control ceiling\n' >&2
  exit 2
fi

MODE="${1:-}"
if [[ "$MODE" != "--preflight" && "$MODE" != "--execute" ]]; then
  printf 'usage: %s --preflight|--execute\n' "$0" >&2
  printf 'required: TEST_GITHUB_REPOSITORY=public-owner/test-mirror plus run, candidate, revision, and evidence variables\n' >&2
  exit 2
fi

required_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    printf 'REFUSED: required environment variable %s is unset\n' "$name" >&2
    exit 2
  fi
}

for variable in \
  RUN_ID CANDIDATE_A_DIR CANDIDATE_B_DIR \
  SOURCE_REVISION_A SOURCE_REVISION_B EVIDENCE_DIR TEST_GITHUB_REPOSITORY; do
  required_env "$variable"
done

readonly GCP_PROJECT="${GCP_PROJECT:-$EXPECTED_PROJECT}"
readonly ZONE="${ZONE:-us-central1-a}"
readonly REGION="${REGION:-${ZONE%-*}}"
readonly BUDGET_USD="${BUDGET_USD:-$HARD_COST_CAP_USD}"

if [[ "$GCP_PROJECT" != "$EXPECTED_PROJECT" ]]; then
  printf 'REFUSED: GCP project must be exactly %s\n' "$EXPECTED_PROJECT" >&2
  exit 2
fi
if [[ -n "${GITHUB_REPOSITORY+x}" ]]; then
  printf 'REFUSED: GITHUB_REPOSITORY is obsolete; set only TEST_GITHUB_REPOSITORY\n' >&2
  exit 2
fi
if [[ -n "${CONTROLLER_CIDR+x}" ]]; then
  printf 'REFUSED: CONTROLLER_CIDR is obsolete; the live controller requires authenticated IAP\n' >&2
  exit 2
fi
python3 - "$TEST_GITHUB_REPOSITORY" "$SOURCE_GITHUB_REPOSITORY" <<'PY'
import re
import sys

test_repository, source_repository = sys.argv[1:]
component = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?")
parts = test_repository.split("/")
if (
    len(parts) != 2
    or any(component.fullmatch(part) is None for part in parts)
    or any(part in {".", ".."} or part.endswith(".git") for part in parts)
):
    raise SystemExit("REFUSED: TEST_GITHUB_REPOSITORY must be one safe owner/repo")
if test_repository.casefold() == source_repository.casefold():
    raise SystemExit(
        "REFUSED: TEST_GITHUB_REPOSITORY must not be cathedralai/cathedral-validator"
    )
PY
readonly TEST_GITHUB_REPOSITORY
if [[ ! "$RUN_ID" =~ ^[a-z0-9][a-z0-9-]{5,20}$ ]]; then
  printf 'REFUSED: RUN_ID must match [a-z0-9][a-z0-9-]{5,20}\n' >&2
  exit 2
fi
if [[ ! "$SOURCE_REVISION_A" =~ ^[0-9a-f]{40}$ || ! "$SOURCE_REVISION_B" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'REFUSED: both source revisions must be 40 lower-case hex characters\n' >&2
  exit 2
fi
if [[ "$SOURCE_REVISION_A" == "$SOURCE_REVISION_B" ]]; then
  printf 'REFUSED: A and B must be distinct reviewed source revisions\n' >&2
  exit 2
fi
if [[ "$EVIDENCE_DIR" != /* || "$CANDIDATE_A_DIR" != /* || "$CANDIDATE_B_DIR" != /* ]]; then
  printf 'REFUSED: evidence and candidate directories must be absolute paths\n' >&2
  exit 2
fi

readonly CANARY_VM="catval-${RUN_ID}-canary"
readonly STABLE_VM="catval-${RUN_ID}-stable"
readonly NETWORK="catval-${RUN_ID}-net"
readonly SUBNET="catval-${RUN_ID}-subnet"
readonly FIREWALL="catval-${RUN_ID}-ssh"
readonly INSTANCE_TAG="catval-${RUN_ID}"
readonly CANARY_BRANCH="validator-release-live-${RUN_ID}-canary"
readonly STABLE_BRANCH="validator-release-live-${RUN_ID}-stable"
readonly FAULT_BRANCH="validator-release-fault-${RUN_ID}"
readonly SSH_USER="cathedrallive"
# TEST_HOTKEY and JOURNAL are bound after the run root exists, from a
# disposable bittensor-wallet keyfile, so the stable host can be configured
# through the installed guided setup exactly as a public operator would.
readonly SNP_POLICY_JSON='{"schema":"cathedral_amd_sev_snp_policy_v1","generations":{"genoa":{"allowed_measurements":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"minimum_tcb":"0x0000000000000001"}}}'
readonly CANARY_URL="https://raw.githubusercontent.com/${TEST_GITHUB_REPOSITORY}/${CANARY_BRANCH}/validator/canary.json"
readonly STABLE_URL="https://raw.githubusercontent.com/${TEST_GITHUB_REPOSITORY}/${STABLE_BRANCH}/validator/stable.json"
readonly ARCHIVE_URL_TEMPLATE="https://github.com/${TEST_GITHUB_REPOSITORY}/releases/download/validator-{archive_sha256}/cathedral-validator-{archive_sha256}.tar.gz"

ESTIMATED_COST_USD="$(python3 - "$VM_COUNT" "$MAX_RUN_SECONDS" "$VM_HOURLY_CEILING_USD" "$BOOT_DISK_GB" "$DISK_GB_HOURLY_CEILING_USD" <<'PY'
from decimal import Decimal
import sys

count = Decimal(sys.argv[1])
hours = Decimal(sys.argv[2]) / Decimal(3600)
vm = Decimal(sys.argv[3])
disk_gb = Decimal(sys.argv[4])
disk = Decimal(sys.argv[5])
print((count * hours * (vm + disk_gb * disk)).quantize(Decimal("0.0001")))
PY
)"
readonly ESTIMATED_COST_USD
PLANNING_TOTAL_USD="$(python3 - "$ESTIMATED_COST_USD" "$NETWORK_ALLOWANCE_USD" <<'PY'
from decimal import Decimal
import sys

print((Decimal(sys.argv[1]) + Decimal(sys.argv[2])).quantize(Decimal("0.0001")))
PY
)"
readonly PLANNING_TOTAL_USD

python3 - \
  "$ESTIMATED_COST_USD" "$TEST_COST_CAP_USD" "$NETWORK_ALLOWANCE_USD" \
  "$PLANNING_TOTAL_USD" "$BUDGET_USD" "$HARD_COST_CAP_USD" <<'PY'
from decimal import Decimal
import sys

compute_disk, test_cap, network_allowance, total, requested, hard_cap = map(
    Decimal, sys.argv[1:]
)
if compute_disk >= test_cap:
    raise SystemExit(
        f"REFUSED: VM and disk estimate ${compute_disk} is not below ${test_cap}"
    )
if total != compute_disk + network_allowance:
    raise SystemExit("REFUSED: total cost ceiling calculation is inconsistent")
if requested > hard_cap:
    raise SystemExit(f"REFUSED: requested budget ${requested} exceeds hard cap ${hard_cap}")
if total > hard_cap:
    raise SystemExit(f"REFUSED: planning total ${total} exceeds hard cap ${hard_cap}")
if total > requested:
    raise SystemExit(f"REFUSED: planning total ${total} exceeds requested budget ${requested}")
PY

for command in awk basename cmp curl cut find gcloud gh git grep jq openssl python3 sed seq shasum ssh-keygen tee; do
  command -v "$command" >/dev/null || {
    printf 'REFUSED: required command is missing: %s\n' "$command" >&2
    exit 2
  }
done
if ! python3 -c 'import cryptography' >/dev/null 2>&1; then
  printf 'REFUSED: controller Python cannot import cryptography\n' >&2
  exit 2
fi
if ! python3 -c 'import bittensor_wallet' >/dev/null 2>&1; then
  printf 'REFUSED: controller Python cannot import bittensor_wallet for the disposable operator hotkey\n' >&2
  exit 2
fi
for file in \
  "$HARNESS_SOURCE" "$FAULT_ORIGIN_SOURCE" "$STATE_WAITER_SOURCE" \
  "$SIGNER" "$PUBLISHER" "$BOOTSTRAP_BUILDER" "$BOOTSTRAP_PUBLISHER"; do
  [[ -f "$file" && ! -L "$file" ]] || {
    printf 'REFUSED: required reviewed file is unavailable: %s\n' "$file" >&2
    exit 2
  }
done

gc() {
  gcloud --quiet --project="$GCP_PROJECT" "$@"
}

fresh_access_token() {
  local timeout_seconds="$1"
  python3 - "$GCP_PROJECT" "$timeout_seconds" <<'PY'
import os
import signal
import subprocess
import sys

project = sys.argv[1]
timeout = int(sys.argv[2])
if timeout < 1:
    raise SystemExit(75)
try:
    process = subprocess.Popen(
        ["gcloud", "--quiet", f"--project={project}", "auth", "print-access-token"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
except OSError:
    raise SystemExit(76)
try:
    stdout, _stderr = process.communicate(timeout=timeout)
except subprocess.TimeoutExpired:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate()
    raise SystemExit(75)
if process.returncode != 0:
    raise SystemExit(75)
lines = stdout.splitlines()
if len(lines) != 1:
    raise SystemExit(76)
token = lines[0]
if (
    not token.isascii()
    or not 20 <= len(token) <= 4096
    or any(character.isspace() for character in token)
):
    raise SystemExit(76)
sys.stdout.write(token)
PY
}

google_api_post() {
  local url="$1"
  local body="$2"
  local label="$3"
  local total_timeout_seconds="${4:-$GOOGLE_API_TOTAL_TIMEOUT_SECONDS}"
  local access_token
  local attempt
  local curl_status
  local deadline=$((SECONDS + total_timeout_seconds))
  local http_status
  local phase_timeout
  local remaining
  local response
  local response_body
  local retryable
  local sleep_seconds
  local token_status
  for attempt in $(seq 1 "$GOOGLE_API_MAX_ATTEMPTS"); do
    remaining=$((deadline - SECONDS))
    if (( remaining < 1 )); then
      printf 'REFUSED: Google API total deadline expired label=%s attempts=%s\n' \
        "$label" "$((attempt - 1))" >&2
      return 1
    fi
    phase_timeout="$GOOGLE_AUTH_TIMEOUT_SECONDS"
    if (( remaining < phase_timeout )); then
      phase_timeout="$remaining"
    fi
    access_token=""
    response=""
    set +e
    access_token="$(fresh_access_token "$phase_timeout")"
    token_status=$?
    set -e
    curl_status=0
    http_status="000"
    response_body=""
    if (( token_status == 0 )); then
      remaining=$((deadline - SECONDS))
      if (( remaining < 1 )); then
        unset access_token
        printf 'REFUSED: Google API total deadline expired label=%s attempts=%s\n' \
          "$label" "$((attempt - 1))" >&2
        return 1
      fi
      phase_timeout="$GOOGLE_API_CURL_TIMEOUT_SECONDS"
      if (( remaining < phase_timeout )); then
        phase_timeout="$remaining"
      fi
      set +e
      response="$(
        printf 'Authorization: Bearer %s\n' "$access_token" | curl --disable \
          --silent \
          --show-error \
          --connect-timeout 10 \
          --max-time "$phase_timeout" \
          --proto '=https' \
          --tlsv1.2 \
          --request POST \
          --header @- \
          --header 'Content-Type: application/json' \
          --data "$body" \
          --write-out $'\n%{http_code}' \
          "$url"
      )"
      curl_status=$?
      set -e
      unset access_token
    fi
    if [[ "$response" == *$'\n'* ]]; then
      http_status="${response##*$'\n'}"
      response_body="${response%$'\n'*}"
    fi
    if (( token_status == 0 && curl_status == 0 )) && [[ "$http_status" =~ ^2[0-9]{2}$ ]]; then
      printf '%s' "$response_body"
      return 0
    fi
    retryable=0
    if (( token_status == 75 )); then
      retryable=1
    elif (( token_status != 0 )); then
      retryable=0
    elif (( curl_status != 0 )); then
      case "$curl_status" in
        5 | 6 | 7 | 18 | 28 | 35 | 52 | 55 | 56 | 92)
          retryable=1
          ;;
      esac
    elif [[ "$http_status" == "408" || "$http_status" == "429" || "$http_status" =~ ^5[0-9]{2}$ ]]; then
      retryable=1
    fi
    if (( retryable == 0 || attempt == GOOGLE_API_MAX_ATTEMPTS )); then
      printf 'REFUSED: Google API request failed label=%s attempt=%s token_status=%s curl_status=%s http_status=%s\n' \
        "$label" "$attempt" "$token_status" "$curl_status" "$http_status" >&2
      return 1
    fi
    printf 'RETRY: transient Google API failure label=%s attempt=%s token_status=%s curl_status=%s http_status=%s\n' \
      "$label" "$attempt" "$token_status" "$curl_status" "$http_status" >&2
    sleep_seconds="$attempt"
    remaining=$((deadline - SECONDS))
    if (( remaining <= sleep_seconds )); then
      printf 'REFUSED: Google API total deadline expired label=%s attempts=%s\n' \
        "$label" "$attempt" >&2
      return 1
    fi
    sleep "$sleep_seconds"
  done
  return 1
}

request_instance_reset() {
  local host="$1"
  local response
  response="$(google_api_post \
    "https://compute.googleapis.com/compute/v1/projects/${GCP_PROJECT}/zones/${ZONE}/instances/${host}/reset" \
    '{}' "reset-${host}" "$RESET_REQUEST_TIMEOUT_SECONDS")"
  printf '%s\n' "$response" | jq -e \
    '{name: (.name | select(type == "string" and length > 0)), status: (.status | select(type == "string" and length > 0))}'
}

require_exact_permissions() {
  local response="$1"
  shift
  python3 - "$response" "$@" <<'PY'
import json
import sys

try:
    document = json.loads(sys.argv[1])
except (json.JSONDecodeError, TypeError) as error:
    raise SystemExit("REFUSED: malformed IAM permission response") from error
if not isinstance(document, dict):
    raise SystemExit("REFUSED: malformed IAM permission response")
permissions = document.get("permissions")
expected = sys.argv[2:]
if (
    not isinstance(permissions, list)
    or any(not isinstance(item, str) for item in permissions)
    or len(set(permissions)) != len(permissions)
    or sorted(permissions) != sorted(expected)
):
    raise SystemExit("REFUSED: required controller permissions are unavailable")
PY
}

verify_candidate() {
  local root="$1"
  local revision="$2"
  python3 - "$root" "$revision" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve(strict=True)
expected_revision = sys.argv[2]
manifest_path = root / "INPUTS.json"
manifest = json.loads(manifest_path.read_text(encoding="ascii"))
if manifest.get("schema") != "cathedral_validator_release_inputs_v1":
    raise SystemExit(f"REFUSED: {root} has the wrong candidate schema")
if manifest.get("source_revision") != expected_revision:
    raise SystemExit(f"REFUSED: {root} source revision differs from the requested revision")
files = manifest.get("files")
if not isinstance(files, dict) or not files:
    raise SystemExit(f"REFUSED: {root} has no candidate file map")
actual = {
    path.relative_to(root).as_posix()
    for path in root.rglob("*")
    if path.is_file() and path != manifest_path
}
if actual != set(files):
    raise SystemExit(f"REFUSED: {root} candidate file set differs from INPUTS.json")
for relative, expected in files.items():
    path = root / relative
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise SystemExit(f"REFUSED: unsafe candidate file {path}")
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != expected:
        raise SystemExit(f"REFUSED: candidate digest mismatch for {path}")
required = {
    "runtime/cathedral-validator.pex",
    "runtime/cathedral-tdx-verifier",
    "runtime/snpguest",
    "runtime/cathedral-validator-cpython312-linux-x86_64.pex.lock",
    "runtime/cathedral-validator.pex-distributions.json",
    "updater-requirements.lock",
}
if not required.issubset(files):
    raise SystemExit(f"REFUSED: {root} is missing required release inputs")
PY
}

verify_candidate "$CANDIDATE_A_DIR" "$SOURCE_REVISION_A"
verify_candidate "$CANDIDATE_B_DIR" "$SOURCE_REVISION_B"

if [[ "$(git -C "$REPOSITORY_ROOT" rev-parse HEAD)" != "$SOURCE_REVISION_B" ]]; then
  printf 'REFUSED: controller checkout HEAD must equal SOURCE_REVISION_B\n' >&2
  exit 2
fi
if [[ -n "$(git -C "$REPOSITORY_ROOT" status --short)" ]]; then
  printf 'REFUSED: controller checkout must be clean\n' >&2
  exit 2
fi

gh auth status >/dev/null
TEST_GITHUB_RESOLVED_REPOSITORY="$(gh api "repos/${TEST_GITHUB_REPOSITORY}" --jq .full_name)"
readonly TEST_GITHUB_RESOLVED_REPOSITORY
if [[ "$TEST_GITHUB_RESOLVED_REPOSITORY" != "$TEST_GITHUB_REPOSITORY" ]]; then
  printf 'REFUSED: TEST_GITHUB_REPOSITORY redirected or differs from its exact GitHub full_name\n' >&2
  exit 2
fi
python3 - "$TEST_GITHUB_RESOLVED_REPOSITORY" "$SOURCE_GITHUB_REPOSITORY" <<'PY'
import sys

if sys.argv[1].casefold() == sys.argv[2].casefold():
    raise SystemExit("REFUSED: resolved test repository is the canonical source")
PY
if [[ "$(gh api "repos/${TEST_GITHUB_REPOSITORY}" --jq .private)" != "false" ]]; then
  printf 'REFUSED: TEST_GITHUB_REPOSITORY must be public\n' >&2
  exit 2
fi
if [[ "$(gh api "repos/${TEST_GITHUB_REPOSITORY}/immutable-releases" --jq .enabled)" != "true" ]]; then
  printf 'REFUSED: TEST_GITHUB_REPOSITORY must enforce immutable releases\n' >&2
  exit 2
fi
gc auth list --filter=status:ACTIVE --format='value(account)' | grep -q .
if ! ENABLED_CONTROLLER_APIS="$(
  gc services list --enabled --format='value(config.name)'
)"; then
  printf 'REFUSED: serviceusage.services.list is required to verify enabled APIs\n' >&2
  exit 2
fi
readonly ENABLED_CONTROLLER_APIS
for required_api in "$CLOUD_RESOURCE_MANAGER_API" "$IAP_API"; do
  if ! grep -Fx "$required_api" <<<"$ENABLED_CONTROLLER_APIS" >/dev/null; then
    printf 'REFUSED: %s must be enabled before the live test\n' \
      "$required_api" >&2
    exit 2
  fi
done
CONTROLLER_PROJECT_PERMISSIONS_JSON="$(
  google_api_post \
    "https://cloudresourcemanager.googleapis.com/v1/projects/${GCP_PROJECT}:testIamPermissions" \
    "$CONTROLLER_PROJECT_PERMISSION_REQUEST" \
    project-permissions
)"
readonly CONTROLLER_PROJECT_PERMISSIONS_JSON
require_exact_permissions \
  "$CONTROLLER_PROJECT_PERMISSIONS_JSON" \
  "${CONTROLLER_PROJECT_PERMISSIONS[@]}"
gc compute machine-types describe "$MACHINE_TYPE" --zone="$ZONE" >/dev/null
gcloud --quiet compute images describe-from-family "$IMAGE_FAMILY" --project="$IMAGE_PROJECT" >/dev/null

for revision in "$SOURCE_REVISION_A" "$SOURCE_REVISION_B"; do
  [[ "$(gh api "repos/${SOURCE_GITHUB_REPOSITORY}/commits/${revision}" --jq .sha)" == "$revision" ]] || {
    printf 'REFUSED: canonical source did not resolve revision %s exactly\n' "$revision" >&2
    exit 2
  }
  comparison="$(gh api "repos/${SOURCE_GITHUB_REPOSITORY}/compare/${revision}...main" --jq .status)"
  if [[ "$comparison" != "ahead" && "$comparison" != "identical" ]]; then
    printf 'REFUSED: canonical source revision %s is not merged into main\n' "$revision" >&2
    exit 2
  fi
  if [[ "$(gh api "repos/${TEST_GITHUB_REPOSITORY}/commits/${revision}" --jq .sha)" != "$revision" ]]; then
    printf 'REFUSED: test mirror does not contain source revision %s exactly\n' "$revision" >&2
    exit 2
  fi
done
TEST_MIRROR_MAIN_SHA="$(gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)"
readonly TEST_MIRROR_MAIN_SHA
if [[ "$TEST_MIRROR_MAIN_SHA" != "$SOURCE_REVISION_B" ]]; then
  printf 'REFUSED: test mirror main must equal SOURCE_REVISION_B exactly\n' >&2
  exit 2
fi

assert_test_repository_boundary() {
  local resolved
  resolved="$(gh api "repos/${TEST_GITHUB_REPOSITORY}" --jq .full_name)"
  if [[ "$resolved" != "$TEST_GITHUB_REPOSITORY" ]]; then
    printf 'REFUSED: test repository identity changed or redirected\n' >&2
    return 1
  fi
  if [[ "$(gh api "repos/${TEST_GITHUB_REPOSITORY}" --jq .private)" != "false" ]]; then
    printf 'REFUSED: test repository is no longer public\n' >&2
    return 1
  fi
}

if gc compute instances describe "$CANARY_VM" --zone="$ZONE" >/dev/null 2>&1; then
  printf 'REFUSED: exact GCP test resource already exists: %s\n' "$CANARY_VM" >&2
  exit 2
fi
if gc compute instances describe "$STABLE_VM" --zone="$ZONE" >/dev/null 2>&1; then
  printf 'REFUSED: exact GCP test resource already exists: %s\n' "$STABLE_VM" >&2
  exit 2
fi
if gc compute disks describe "$CANARY_VM" --zone="$ZONE" >/dev/null 2>&1; then
  printf 'REFUSED: exact GCP test disk already exists: %s\n' "$CANARY_VM" >&2
  exit 2
fi
if gc compute disks describe "$STABLE_VM" --zone="$ZONE" >/dev/null 2>&1; then
  printf 'REFUSED: exact GCP test disk already exists: %s\n' "$STABLE_VM" >&2
  exit 2
fi
if gc compute networks describe "$NETWORK" >/dev/null 2>&1; then
  printf 'REFUSED: exact GCP test resource already exists: %s\n' "$NETWORK" >&2
  exit 2
fi
if gc compute networks subnets describe "$SUBNET" --region="$REGION" >/dev/null 2>&1; then
  printf 'REFUSED: exact GCP test resource already exists: %s\n' "$SUBNET" >&2
  exit 2
fi
if gc compute firewall-rules describe "$FIREWALL" >/dev/null 2>&1; then
  printf 'REFUSED: exact GCP test resource already exists: %s\n' "$FIREWALL" >&2
  exit 2
fi
for branch in "$CANARY_BRANCH" "$STABLE_BRANCH" "$FAULT_BRANCH"; do
  if gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/heads/${branch}" >/dev/null 2>&1; then
    printf 'REFUSED: exact GitHub test branch already exists: %s\n' "$branch" >&2
    exit 2
  fi
done

# Prove that the offline signer accepts this exact isolated mirror before any
# live resources are created.  The production default remains the canonical
# repository, so an unbound mirror here would otherwise fail later, after the
# paid test has started.
python3 "$SIGNER" validate-archive-target \
  --archive-url-template "$ARCHIVE_URL_TEMPLATE" \
  --expected-archive-repository "$TEST_GITHUB_REPOSITORY" \
  >/dev/null

if [[ "$MODE" == "--preflight" ]]; then
  printf 'PREFLIGHT_PASS project=%s zone=%s hosts=%s vm_disk_estimate_usd=%s network_allowance_usd=%s planning_total_usd=%s\n' \
    "$GCP_PROJECT" "$ZONE" "$VM_COUNT" "$ESTIMATED_COST_USD" \
    "$NETWORK_ALLOWANCE_USD" "$PLANNING_TOTAL_USD"
  printf 'IMMUTABLE_TEST_CHANNELS canary=%s stable=%s fault=%s\n' \
    "$CANARY_BRANCH" "$STABLE_BRANCH" "$FAULT_BRANCH"
  printf 'REPOSITORY_SPLIT source=%s test_publication=%s mirror_main=%s\n' \
    "$SOURCE_GITHUB_REPOSITORY" "$TEST_GITHUB_REPOSITORY" "$TEST_MIRROR_MAIN_SHA"
  printf 'CONTROLLER_TRANSPORT type=%s source_range=%s vm_service_account_attached=false\n' \
    "$IAP_CONTROLLER_TRANSPORT" "$IAP_TCP_SOURCE_RANGE"
  exit 0
fi

mkdir -p "$EVIDENCE_DIR"
if [[ -n "$(find "$EVIDENCE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  printf 'REFUSED: EVIDENCE_DIR must be empty for an unambiguous run\n' >&2
  exit 2
fi
chmod 0700 "$EVIDENCE_DIR"
jq -n \
  --arg cloud_resource_manager "$CLOUD_RESOURCE_MANAGER_API" \
  --arg iap "$IAP_API" \
  --arg enabled "$ENABLED_CONTROLLER_APIS" \
  '{
    source: "gcloud services list --enabled",
    required: ([$cloud_resource_manager, $iap] | sort),
    observed: (
      $enabled
      | split("\n")
      | map(select(. == $cloud_resource_manager or . == $iap))
      | sort
    )
  }' \
  >"$EVIDENCE_DIR/controller-api-state.json"
jq -e '.required == .observed' \
  "$EVIDENCE_DIR/controller-api-state.json" >/dev/null
printf '%s\n' "$CONTROLLER_PROJECT_PERMISSIONS_JSON" \
  | jq -S . >"$EVIDENCE_DIR/controller-project-permissions.json"

RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/cathedral-validator-live-${RUN_ID}.XXXXXX")"
readonly RUN_ROOT
readonly SIGNED_DIR="$RUN_ROOT/signed"
readonly KEY_DIR="$RUN_ROOT/keys"
readonly BOOTSTRAP_DIR="$RUN_ROOT/bootstrap"
mkdir -m 0700 "$SIGNED_DIR" "$KEY_DIR" "$BOOTSTRAP_DIR"

readonly SSH_PRIVATE_KEY="$RUN_ROOT/ssh-ed25519"
readonly SSH_PUBLIC_KEY="$RUN_ROOT/ssh-ed25519.pub"
readonly SSH_METADATA_FILE="$RUN_ROOT/instance-ssh-keys"
readonly SSH_KNOWN_HOSTS="$RUN_ROOT/known-hosts"
HARNESS_SHA="$(shasum -a 256 "$HARNESS_SOURCE" | cut -d' ' -f1)"
FAULT_ORIGIN_SHA="$(shasum -a 256 "$FAULT_ORIGIN_SOURCE" | cut -d' ' -f1)"
STATE_WAITER_SHA="$(shasum -a 256 "$STATE_WAITER_SOURCE" | cut -d' ' -f1)"
readonly HARNESS_SHA FAULT_ORIGIN_SHA STATE_WAITER_SHA
ssh-keygen -q -t ed25519 -N '' -C "cathedral-live-${RUN_ID}" -f "$SSH_PRIVATE_KEY"
chmod 0600 "$SSH_PRIVATE_KEY"
chmod 0644 "$SSH_PUBLIC_KEY"
printf '%s:%s\n' "$SSH_USER" "$(cat "$SSH_PUBLIC_KEY")" >"$SSH_METADATA_FILE"
chmod 0600 "$SSH_METADATA_FILE"

# Disposable operator inputs for the stable host. The hotkey is a real
# bittensor-wallet keyfile written by the pinned writer, so the guided setup is
# exercised against the exact shape btcli produces. It is never registered on
# any chain, never recorded in evidence, and dies with the run root and host.
readonly OPERATOR_DIR="$RUN_ROOT/operator"
readonly OPERATOR_HOTKEY="$OPERATOR_DIR/hotkeys/validator"
readonly OPERATOR_POLICY="$OPERATOR_DIR/amd-sev-snp-policy.json"
readonly ASSETS_DIR="$RUN_ROOT/assets"
mkdir -m 0700 "$OPERATOR_DIR" "$OPERATOR_DIR/hotkeys" "$ASSETS_DIR"
TEST_HOTKEY="$(python3 - "$OPERATOR_HOTKEY" <<'PY'
import sys

from bittensor_wallet import Keyfile, Keypair

path = sys.argv[1]
keypair = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
Keyfile(path).set_keypair(keypair, encrypt=False, overwrite=True)
print(keypair.ss58_address)
PY
)"
readonly TEST_HOTKEY
if [[ ! "$TEST_HOTKEY" =~ ^5[1-9A-HJ-NP-Za-km-z]{47}$ ]]; then
  printf 'REFUSED: disposable operator hotkey is not a Bittensor SS58 address\n' >&2
  exit 2
fi
chmod 0600 "$OPERATOR_HOTKEY"
readonly JOURNAL="/var/lib/cathedral-validator/.local/state/cathedral-validator/direct-writer/finney-sn39-mechanism-0/${TEST_HOTKEY}/state.json"
printf '%s\n' "$SNP_POLICY_JSON" >"$OPERATOR_POLICY"
chmod 0600 "$OPERATOR_POLICY"
OPERATOR_HOTKEY_SHA="$(shasum -a 256 "$OPERATOR_HOTKEY" | cut -d' ' -f1)"
OPERATOR_POLICY_SHA="$(shasum -a 256 "$OPERATOR_POLICY" | cut -d' ' -f1)"
readonly OPERATOR_HOTKEY_SHA OPERATOR_POLICY_SHA

# Signed bootstrap assets: the reviewed deploy assets with only the two channel
# URLs in update.env.example pointed at this run's isolated mirror branches.
# The installed guided setup then follows the signed example exactly as a
# public operator's setup follows the production example.
python3 - "$REPOSITORY_ROOT/deploy/validator-update" "$ASSETS_DIR" \
  "$CANARY_URL" "$STABLE_URL" <<'PY'
import importlib.util
import shutil
import sys
from pathlib import Path

source, target = Path(sys.argv[1]), Path(sys.argv[2])
urls = {
    "CATHEDRAL_VALIDATOR_CANARY_METADATA_URL=": sys.argv[3],
    "CATHEDRAL_VALIDATOR_STABLE_METADATA_URL=": sys.argv[4],
}
spec = importlib.util.spec_from_file_location(
    "live_bootstrap_builder", source / "build_updater_bundle.py"
)
module = importlib.util.module_from_spec(spec)
# Dataclass processing resolves the defining module through sys.modules.
sys.modules[spec.name] = module
spec.loader.exec_module(module)
for name in sorted(module.REQUIRED_ASSETS):
    shutil.copyfile(source / name, target / name)
    (target / name).chmod(0o644)
example = target / "update.env.example"
rewritten = []
seen = set()
for line in example.read_text(encoding="ascii").splitlines(keepends=True):
    for key, url in urls.items():
        if line.startswith(key):
            if key in seen:
                raise SystemExit(f"REFUSED: update.env.example repeats {key}")
            seen.add(key)
            line = f"{key}{url}\n"
    rewritten.append(line)
if seen != set(urls):
    raise SystemExit("REFUSED: update.env.example lacks a channel URL line")
example.write_text("".join(rewritten), encoding="ascii")
PY

CREATED_CANARY_VM=0
CREATED_STABLE_VM=0
CREATED_FIREWALL=0
CREATED_SUBNET=0
CREATED_NETWORK=0

cleanup_resource_snapshot() {
  local kind="$1"
  local name="$2"
  case "$kind" in
    instance)
      gc compute instances list --filter="name=${name}" --format=json | \
        jq --arg name "$name" '[.[] | select(.name == $name)]'
      ;;
    disk)
      gc compute disks list --zones="$ZONE" --filter="name=${name}" \
        --format=json | jq --arg name "$name" '[.[] | select(.name == $name)]'
      ;;
    firewall)
      gc compute firewall-rules list --filter="name=${name}" --format=json | \
        jq --arg name "$name" '[.[] | select(.name == $name)]'
      ;;
    subnet)
      gc compute networks subnets list --regions="$REGION" \
        --filter="name=${name}" --format=json | \
        jq --arg name "$name" '[.[] | select(.name == $name)]'
      ;;
    network)
      gc compute networks list --filter="name=${name}" --format=json | \
        jq --arg name "$name" '[.[] | select(.name == $name)]'
      ;;
    *)
      printf 'REFUSED: unsupported cleanup resource kind: %s\n' "$kind" >&2
      return 2
      ;;
  esac
}

cleanup_resource_delete() {
  local kind="$1"
  local name="$2"
  case "$kind" in
    instance)
      gc compute instances delete "$name" --zone="$ZONE"
      ;;
    disk)
      gc compute disks delete "$name" --zone="$ZONE"
      ;;
    firewall)
      gc compute firewall-rules delete "$name"
      ;;
    subnet)
      gc compute networks subnets delete "$name" --region="$REGION"
      ;;
    network)
      gc compute networks delete "$name"
      ;;
    *)
      return 2
      ;;
  esac
}

cleanup_resource_until_absent() {
  local label="$1"
  local kind="$2"
  local name="$3"
  local attempt
  local delete_status
  local snapshot
  for attempt in $(seq 1 "$TEARDOWN_DELETE_ATTEMPTS"); do
    snapshot="$EVIDENCE_DIR/teardown-${label}-check-${attempt}.json"
    if cleanup_resource_snapshot "$kind" "$name" >"$snapshot" \
      2>"$EVIDENCE_DIR/teardown-${label}-check-${attempt}.err" && \
      jq -e 'length == 0' "$snapshot" >/dev/null; then
      printf 'TEARDOWN_RESOURCE_ABSENT kind=%s name=%s attempt=%s\n' \
        "$kind" "$name" "$attempt" \
        >"$EVIDENCE_DIR/teardown-${label}-result.txt"
      return 0
    fi
    if cleanup_resource_delete "$kind" "$name" \
      >"$EVIDENCE_DIR/teardown-${label}-delete-${attempt}.log" 2>&1; then
      delete_status=0
    else
      delete_status=$?
    fi
    printf 'delete_status=%s\n' "$delete_status" \
      >>"$EVIDENCE_DIR/teardown-${label}-delete-${attempt}.log"
    sleep "$TEARDOWN_RETRY_INTERVAL_SECONDS"
  done
  snapshot="$EVIDENCE_DIR/teardown-${label}-final.json"
  if cleanup_resource_snapshot "$kind" "$name" >"$snapshot" \
    2>"$EVIDENCE_DIR/teardown-${label}-final.err" && \
    jq -e 'length == 0' "$snapshot" >/dev/null; then
    printf 'TEARDOWN_RESOURCE_ABSENT kind=%s name=%s attempt=final\n' \
      "$kind" "$name" >"$EVIDENCE_DIR/teardown-${label}-result.txt"
    return 0
  fi
  printf 'TEARDOWN_RESOURCE_REMAINS kind=%s name=%s attempts=%s\n' \
    "$kind" "$name" "$TEARDOWN_DELETE_ATTEMPTS" >&2
  return 1
}

cleanup() {
  local status=$?
  local teardown_ok=1
  local final_status
  trap - EXIT INT TERM
  set +e
  if [[ "$CREATED_CANARY_VM" == 1 ]]; then
    cleanup_resource_until_absent canary-vm instance "$CANARY_VM" || teardown_ok=0
  fi
  if [[ "$CREATED_STABLE_VM" == 1 ]]; then
    cleanup_resource_until_absent stable-vm instance "$STABLE_VM" || teardown_ok=0
  fi
  if [[ "$CREATED_CANARY_VM" == 1 ]]; then
    cleanup_resource_until_absent canary-disk disk "$CANARY_VM" || teardown_ok=0
  fi
  if [[ "$CREATED_STABLE_VM" == 1 ]]; then
    cleanup_resource_until_absent stable-disk disk "$STABLE_VM" || teardown_ok=0
  fi
  if [[ "$CREATED_FIREWALL" == 1 ]]; then
    cleanup_resource_until_absent firewall firewall "$FIREWALL" || teardown_ok=0
  fi
  if [[ "$CREATED_SUBNET" == 1 ]]; then
    cleanup_resource_until_absent subnet subnet "$SUBNET" || teardown_ok=0
  fi
  if [[ "$CREATED_NETWORK" == 1 ]]; then
    cleanup_resource_until_absent network network "$NETWORK" || teardown_ok=0
  fi

  if ! gc compute instances list \
    --filter="(name=${CANARY_VM} OR name=${STABLE_VM})" \
    --format=json >"$EVIDENCE_DIR/post-teardown-exact-instances.json" 2>"$EVIDENCE_DIR/post-teardown-exact-instances.err"; then
    teardown_ok=0
  elif ! jq -e 'length == 0' "$EVIDENCE_DIR/post-teardown-exact-instances.json" >/dev/null; then
    teardown_ok=0
  fi
  if ! gc compute instances list \
    --filter="labels.cathedral-live-run=${RUN_ID}" \
    --format=json >"$EVIDENCE_DIR/post-teardown-labeled-instances.json" 2>"$EVIDENCE_DIR/post-teardown-labeled-instances.err"; then
    teardown_ok=0
  elif ! jq -e 'length == 0' "$EVIDENCE_DIR/post-teardown-labeled-instances.json" >/dev/null; then
    teardown_ok=0
  fi
  if ! gc compute disks list --zones="$ZONE" \
    --filter="(name=${CANARY_VM} OR name=${STABLE_VM})" \
    --format=json >"$EVIDENCE_DIR/post-teardown-exact-disks.json" 2>"$EVIDENCE_DIR/post-teardown-exact-disks.err"; then
    teardown_ok=0
  elif ! jq -e 'length == 0' "$EVIDENCE_DIR/post-teardown-exact-disks.json" >/dev/null; then
    teardown_ok=0
  fi
  if ! gc compute firewall-rules list --filter="name=${FIREWALL}" \
    --format=json >"$EVIDENCE_DIR/post-teardown-firewall.json" 2>"$EVIDENCE_DIR/post-teardown-firewall.err"; then
    teardown_ok=0
  elif ! jq -e 'length == 0' "$EVIDENCE_DIR/post-teardown-firewall.json" >/dev/null; then
    teardown_ok=0
  fi
  if ! gc compute networks subnets list --regions="$REGION" --filter="name=${SUBNET}" \
    --format=json >"$EVIDENCE_DIR/post-teardown-subnet.json" 2>"$EVIDENCE_DIR/post-teardown-subnet.err"; then
    teardown_ok=0
  elif ! jq -e 'length == 0' "$EVIDENCE_DIR/post-teardown-subnet.json" >/dev/null; then
    teardown_ok=0
  fi
  if ! gc compute networks list --filter="name=${NETWORK}" \
    --format=json >"$EVIDENCE_DIR/post-teardown-network.json" 2>"$EVIDENCE_DIR/post-teardown-network.err"; then
    teardown_ok=0
  elif ! jq -e 'length == 0' "$EVIDENCE_DIR/post-teardown-network.json" >/dev/null; then
    teardown_ok=0
  fi

  if [[ -f "$EVIDENCE_DIR/project-metadata-before.json" ]]; then
    if ! project_metadata_snapshot "$EVIDENCE_DIR/project-metadata-after-teardown.json"; then
      teardown_ok=0
    elif ! cmp -s "$EVIDENCE_DIR/project-metadata-before.json" \
      "$EVIDENCE_DIR/project-metadata-after-teardown.json"; then
      teardown_ok=0
    fi
  fi

  if [[ -n "${RUN_ROOT:-}" && "$RUN_ROOT" == "${TMPDIR:-/tmp}/cathedral-validator-live-${RUN_ID}."* && -d "$RUN_ROOT" ]]; then
    rm -f -- "$SSH_PRIVATE_KEY"
    if [[ -e "$SSH_PRIVATE_KEY" ]]; then
      teardown_ok=0
    fi
    rm -rf -- "$RUN_ROOT"
  fi
  if [[ -d "${RUN_ROOT:-/path-that-must-not-exist}" ]]; then
    teardown_ok=0
  fi

  final_status=$status
  if [[ "$teardown_ok" != 1 && "$final_status" == 0 ]]; then
    final_status=1
  fi
  printf 'original_status=%s\nteardown_verified=%s\n' \
    "$status" "$teardown_ok" >"$EVIDENCE_DIR/teardown-status.txt"
  if [[ $status -eq 0 && "$teardown_ok" == 1 ]]; then
    printf 'TEARDOWN_COMPLETE run=%s\n' "$RUN_ID"
    printf 'LIVE_UPDATE_E2E_PASS run=%s evidence=%s test_repository=%s vm_disk_estimate_usd=%s planning_total_usd=%s bootstrap_tag=%s\n' \
      "$RUN_ID" "$EVIDENCE_DIR" "$TEST_GITHUB_REPOSITORY" \
      "$ESTIMATED_COST_USD" "$PLANNING_TOTAL_USD" "$BOOTSTRAP_TAG"
  elif [[ "$teardown_ok" != 1 ]]; then
    printf 'TEARDOWN_NOT_PROVEN run=%s original_status=%s\n' "$RUN_ID" "$status" >&2
  else
    printf 'RUN_FAILED_BUT_TEARDOWN_VERIFIED run=%s status=%s\n' "$RUN_ID" "$status" >&2
  fi
  exit "$final_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

record_step() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$EVIDENCE_DIR/steps.log"
}

project_metadata_snapshot() {
  local output="$1"
  gc compute project-info describe --format=json | \
    jq -S '(.commonInstanceMetadata.items // []) | sort_by(.key)' >"$output"
}

assert_project_metadata_unchanged() {
  local label="$1"
  local observed="$EVIDENCE_DIR/project-metadata-${label}.json"
  project_metadata_snapshot "$observed"
  if ! cmp -s "$EVIDENCE_DIR/project-metadata-before.json" "$observed"; then
    printf 'REFUSED: project metadata changed during %s\n' "$label" >&2
    return 1
  fi
}

gh api "repos/${SOURCE_GITHUB_REPOSITORY}" >"$EVIDENCE_DIR/source-repository.json"
gh api "repos/${TEST_GITHUB_REPOSITORY}" >"$EVIDENCE_DIR/test-publication-repository.json"
gh api "repos/${TEST_GITHUB_REPOSITORY}/immutable-releases" \
  >"$EVIDENCE_DIR/test-publication-immutable-releases.json"
gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/heads/main" \
  >"$EVIDENCE_DIR/test-publication-main-before.json"

runtime_private="$KEY_DIR/runtime-private.pem"
runtime_public="$KEY_DIR/runtime-public.pem"
bootstrap_private="$KEY_DIR/bootstrap-private.pem"
bootstrap_public="$KEY_DIR/bootstrap-public.pem"
openssl genpkey -algorithm ED25519 -out "$runtime_private"
openssl pkey -in "$runtime_private" -pubout -out "$runtime_public"
openssl genpkey -algorithm ED25519 -out "$bootstrap_private"
openssl pkey -in "$bootstrap_private" -pubout -out "$bootstrap_public"
chmod 0600 "$runtime_private" "$bootstrap_private"
chmod 0644 "$runtime_public" "$bootstrap_public"
install -m 0444 "$runtime_public" "$EVIDENCE_DIR/runtime-release-public-key.pem"
install -m 0444 "$bootstrap_public" "$EVIDENCE_DIR/bootstrap-release-public-key.pem"
install -m 0444 "$SSH_PUBLIC_KEY" "$EVIDENCE_DIR/controller-ephemeral-ssh-public-key.pub"
{
  shasum -a 256 "$EVIDENCE_DIR/runtime-release-public-key.pem"
  shasum -a 256 "$EVIDENCE_DIR/bootstrap-release-public-key.pem"
  ssh-keygen -lf "$EVIDENCE_DIR/controller-ephemeral-ssh-public-key.pub"
} >"$EVIDENCE_DIR/public-key-fingerprints.txt"

sign_canary() {
  local candidate="$1"
  local revision="$2"
  local sequence="$3"
  local metadata="$4"
  python3 "$SIGNER" --private-key "$runtime_private" canary \
    --pex "$candidate/runtime/cathedral-validator.pex" \
    --qvl "$candidate/runtime/cathedral-tdx-verifier" \
    --snpguest "$candidate/runtime/snpguest" \
    --runtime-lock "$candidate/runtime/cathedral-validator-cpython312-linux-x86_64.pex.lock" \
    --runtime-distributions "$candidate/runtime/cathedral-validator.pex-distributions.json" \
    --source-revision "$revision" \
    --archive-out-dir "$SIGNED_DIR" \
    --metadata-out "$metadata" \
    --archive-url-template "$ARCHIVE_URL_TEMPLATE" \
    --expected-archive-repository "$TEST_GITHUB_REPOSITORY" \
    --sequence "$sequence" \
    --lifetime-seconds 43200 >/dev/null
}

promote_stable() {
  local canary_metadata="$1"
  local sequence="$2"
  local stable_metadata="$3"
  python3 "$SIGNER" --private-key "$runtime_private" stable \
    --canary-metadata "$canary_metadata" \
    --metadata-out "$stable_metadata" \
    --expected-archive-repository "$TEST_GITHUB_REPOSITORY" \
    --sequence "$sequence" \
    --lifetime-seconds 43200
}

readonly CANARY_A1="$SIGNED_DIR/canary-a-seq1.json"
readonly CANARY_B2="$SIGNED_DIR/canary-b-seq2.json"
readonly CANARY_B3="$SIGNED_DIR/canary-b-renewal-seq3.json"
readonly CANARY_A_EQ3="$SIGNED_DIR/canary-a-equivocation-seq3.json"
readonly CANARY_A4="$SIGNED_DIR/canary-a-seq4.json"
readonly STABLE_A1="$SIGNED_DIR/stable-a-seq1.json"
readonly STABLE_B2="$SIGNED_DIR/stable-b-seq2.json"
readonly STABLE_A3="$SIGNED_DIR/stable-a-seq3.json"
readonly STABLE_B4="$SIGNED_DIR/stable-b-seq4.json"
readonly STABLE_A5="$SIGNED_DIR/stable-a-rescue-seq5.json"
readonly INVALID_B2="$SIGNED_DIR/canary-b-invalid-signature.json"

sign_canary "$CANDIDATE_A_DIR" "$SOURCE_REVISION_A" 1 "$CANARY_A1"
sign_canary "$CANDIDATE_B_DIR" "$SOURCE_REVISION_B" 2 "$CANARY_B2"
sign_canary "$CANDIDATE_B_DIR" "$SOURCE_REVISION_B" 3 "$CANARY_B3"
sign_canary "$CANDIDATE_A_DIR" "$SOURCE_REVISION_A" 3 "$CANARY_A_EQ3"
sign_canary "$CANDIDATE_A_DIR" "$SOURCE_REVISION_A" 4 "$CANARY_A4"
promote_stable "$CANARY_A1" 1 "$STABLE_A1"
CANARY_A1_SHA="$(shasum -a 256 "$CANARY_A1" | cut -d' ' -f1)"
readonly CANARY_A1_SHA
promote_stable "$CANARY_B2" 2 "$STABLE_B2"
promote_stable "$CANARY_A4" 3 "$STABLE_A3"
promote_stable "$CANARY_B3" 4 "$STABLE_B4"
promote_stable "$CANARY_A4" 5 "$STABLE_A5"

python3 - "$CANARY_B2" "$INVALID_B2" <<'PY'
import base64
import json
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
signature = bytearray(base64.b64decode(source["signature"], validate=True))
signature[0] ^= 1
source["signature"] = base64.b64encode(signature).decode("ascii")
Path(sys.argv[2]).write_text(
    json.dumps(source, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="ascii",
)
PY
chmod 0644 "$INVALID_B2"
mkdir -m 0700 "$EVIDENCE_DIR/signed-runtime-metadata"
for metadata in \
  "$CANARY_A1" "$CANARY_B2" "$CANARY_B3" "$CANARY_A_EQ3" "$CANARY_A4" \
  "$STABLE_A1" "$STABLE_B2" "$STABLE_A3" "$STABLE_B4" "$STABLE_A5" \
  "$INVALID_B2"; do
  install -m 0444 "$metadata" "$EVIDENCE_DIR/signed-runtime-metadata/$(basename "$metadata")"
done

metadata_field() {
  local path="$1"
  local expression="$2"
  jq -er "$expression" "$path"
}

expected_channel_record() {
  local metadata="$1"
  local channel="$2"
  python3 - "$REPOSITORY_ROOT" "$runtime_public" "$metadata" "$channel" <<'PY'
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

repository_root = Path(sys.argv[1])
public_key_path = Path(sys.argv[2])
metadata_path = Path(sys.argv[3])
channel = sys.argv[4]
sys.path.insert(0, str(repository_root))

from cathedral_thin.independent_runtime.updater import parse_release_metadata

public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
if not isinstance(public_key, Ed25519PublicKey):
    raise SystemExit("runtime release public key is not Ed25519")
release = parse_release_metadata(
    metadata_path.read_bytes(),
    channel=channel,
    public_key=public_key,
)
print(
    json.dumps(
        {
            "sequence": release.sequence,
            "archive_sha256": release.archive_sha256,
            "signed_sha256": release.signed_sha256,
            "metadata_sha256": release.metadata_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)
PY
}

ARCHIVE_A_SHA="$(metadata_field "$CANARY_A1" '.signed.release.archive_sha256')"
ARCHIVE_B_SHA="$(metadata_field "$CANARY_B2" '.signed.release.archive_sha256')"
readonly ARCHIVE_A_SHA ARCHIVE_B_SHA
readonly ARCHIVE_A="$SIGNED_DIR/cathedral-validator-${ARCHIVE_A_SHA}.tar.gz"
readonly ARCHIVE_B="$SIGNED_DIR/cathedral-validator-${ARCHIVE_B_SHA}.tar.gz"
if [[ "$ARCHIVE_A_SHA" == "$ARCHIVE_B_SHA" ]]; then
  printf 'REFUSED: release A and B unexpectedly produced the same archive\n' >&2
  exit 2
fi

printf 'GitHub artifact attestation verification\n' >"$EVIDENCE_DIR/candidate-attestations.log"
for candidate_root in "$CANDIDATE_A_DIR" "$CANDIDATE_B_DIR"; do
  while IFS= read -r relative; do
    {
      printf '\nVERIFY %s\n' "$candidate_root/$relative"
      gh attestation verify "$candidate_root/$relative" --repo "$SOURCE_GITHUB_REPOSITORY"
    } >>"$EVIDENCE_DIR/candidate-attestations.log" 2>&1
  done < <(jq -r '.files | keys[]' "$candidate_root/INPUTS.json")
  {
    printf '\nVERIFY %s\n' "$candidate_root/INPUTS.json"
    gh attestation verify "$candidate_root/INPUTS.json" --repo "$SOURCE_GITHUB_REPOSITORY"
  } >>"$EVIDENCE_DIR/candidate-attestations.log" 2>&1
done

bootstrap_build_json="$(python3 "$BOOTSTRAP_BUILDER" \
  --wheelhouse "$CANDIDATE_B_DIR/updater-wheelhouse" \
  --requirements "$CANDIDATE_B_DIR/updater-requirements.lock" \
  --bootstrap-signing-private-key "$bootstrap_private" \
  --bootstrap-signing-public-key "$bootstrap_public" \
  --runtime-release-public-key "$runtime_public" \
  --stable-release-metadata "$STABLE_A1" \
  --assets-dir "$ASSETS_DIR" \
  --bundle-out "$BOOTSTRAP_DIR/updater-bootstrap.tar.gz" \
  --manifest-out "$BOOTSTRAP_DIR/updater-bootstrap.manifest.json" \
  --signature-out "$BOOTSTRAP_DIR/updater-bootstrap.manifest.sig" \
  --sequence 1 \
  --lifetime-seconds 43200)"
printf '%s\n' "$bootstrap_build_json" >"$EVIDENCE_DIR/bootstrap-build.json"
install -m 0444 "$BOOTSTRAP_DIR/updater-bootstrap.manifest.json" \
  "$EVIDENCE_DIR/updater-bootstrap.manifest.json"
install -m 0444 "$BOOTSTRAP_DIR/updater-bootstrap.manifest.sig" \
  "$EVIDENCE_DIR/updater-bootstrap.manifest.sig"
BOOTSTRAP_FINGERPRINT="$(printf '%s' "$bootstrap_build_json" | jq -er '.bootstrap_signing_key_fingerprint')"
RUNTIME_FINGERPRINT="$(printf '%s' "$bootstrap_build_json" | jq -er '.runtime_release_key_fingerprint')"
readonly BOOTSTRAP_FINGERPRINT RUNTIME_FINGERPRINT
BOOTSTRAP_SEQUENCE="$(printf '%s' "$bootstrap_build_json" | jq -er '.bootstrap_sequence')"
BOOTSTRAP_MANIFEST_SHA="$(printf '%s' "$bootstrap_build_json" | jq -er '.manifest_sha256')"
BOOTSTRAP_BUNDLE_SHA="$(printf '%s' "$bootstrap_build_json" | jq -er '.bundle_sha256')"
BOOTSTRAP_SIGNATURE_SHA="$(shasum -a 256 "$BOOTSTRAP_DIR/updater-bootstrap.manifest.sig" | cut -d' ' -f1)"
BOOTSTRAP_PUBLIC_KEY_SHA="$(shasum -a 256 "$bootstrap_public" | cut -d' ' -f1)"
readonly \
  BOOTSTRAP_SEQUENCE BOOTSTRAP_MANIFEST_SHA BOOTSTRAP_BUNDLE_SHA \
  BOOTSTRAP_SIGNATURE_SHA BOOTSTRAP_PUBLIC_KEY_SHA
if [[ "$BOOTSTRAP_SEQUENCE" != 1 ]]; then
  printf 'REFUSED: disposable bootstrap sequence must be exactly 1\n' >&2
  exit 2
fi
readonly BOOTSTRAP_TAG="validator-bootstrap-test-s${BOOTSTRAP_SEQUENCE}-${BOOTSTRAP_MANIFEST_SHA}"
readonly BOOTSTRAP_BASE_URL="https://github.com/${TEST_GITHUB_REPOSITORY}/releases/download/${BOOTSTRAP_TAG}"
readonly BOOTSTRAP_BUNDLE_URL="${BOOTSTRAP_BASE_URL}/updater-bootstrap.tar.gz"
readonly BOOTSTRAP_MANIFEST_URL="${BOOTSTRAP_BASE_URL}/updater-bootstrap.manifest.json"
readonly BOOTSTRAP_SIGNATURE_URL="${BOOTSTRAP_BASE_URL}/updater-bootstrap.manifest.sig"
readonly BOOTSTRAP_PUBLIC_KEY_URL="${BOOTSTRAP_BASE_URL}/bootstrap-signing-public-key.pem"

bootstrap_publisher() {
  assert_test_repository_boundary
  python3 "$BOOTSTRAP_PUBLISHER" \
    --bundle "$BOOTSTRAP_DIR/updater-bootstrap.tar.gz" \
    --manifest "$BOOTSTRAP_DIR/updater-bootstrap.manifest.json" \
    --signature "$BOOTSTRAP_DIR/updater-bootstrap.manifest.sig" \
    --bootstrap-public-key "$bootstrap_public" \
    --expected-bootstrap-key-fingerprint "$BOOTSTRAP_FINGERPRINT" \
    --minimum-bootstrap-sequence "$BOOTSTRAP_SEQUENCE" \
    --repository "$TEST_GITHUB_REPOSITORY" \
    --track test \
    --target-revision "$SOURCE_REVISION_B" \
    "$@"
}

assert_test_mirror_main_exact() {
  local observed
  observed="$(gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)"
  if [[ "$observed" != "$SOURCE_REVISION_B" ]]; then
    printf 'REFUSED: test mirror main no longer equals SOURCE_REVISION_B\n' >&2
    return 1
  fi
}

readonly BOOTSTRAP_VALIDATE_LINE="CATHEDRAL_VALIDATOR_BOOTSTRAP_VALIDATED_NO_WRITE track=test sequence=${BOOTSTRAP_SEQUENCE} tag=${BOOTSTRAP_TAG} manifest_sha256=${BOOTSTRAP_MANIFEST_SHA} bundle_sha256=${BOOTSTRAP_BUNDLE_SHA}"
readonly BOOTSTRAP_PUBLISH_LINE="CATHEDRAL_VALIDATOR_BOOTSTRAP_PUBLISHED track=test sequence=${BOOTSTRAP_SEQUENCE} tag=${BOOTSTRAP_TAG} manifest_sha256=${BOOTSTRAP_MANIFEST_SHA} bundle_sha256=${BOOTSTRAP_BUNDLE_SHA}"
bootstrap_publisher | tee "$EVIDENCE_DIR/bootstrap-publication-validate.log"
grep -Fx "$BOOTSTRAP_VALIDATE_LINE" "$EVIDENCE_DIR/bootstrap-publication-validate.log" >/dev/null
assert_test_mirror_main_exact
bootstrap_publisher --publish | tee "$EVIDENCE_DIR/bootstrap-publication-publish.log"
grep -Fx "$BOOTSTRAP_PUBLISH_LINE" "$EVIDENCE_DIR/bootstrap-publication-publish.log" >/dev/null
gh api "repos/${TEST_GITHUB_REPOSITORY}/releases/tags/${BOOTSTRAP_TAG}" \
  >"$EVIDENCE_DIR/bootstrap-release-record.json"
gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/tags/${BOOTSTRAP_TAG}" \
  >"$EVIDENCE_DIR/bootstrap-tag-record.json"

python3 - \
  "$EVIDENCE_DIR/bootstrap-publication.json" "$SOURCE_GITHUB_REPOSITORY" \
  "$TEST_GITHUB_REPOSITORY" "$BOOTSTRAP_TAG" \
  "$SOURCE_REVISION_B" "$BOOTSTRAP_SEQUENCE" "$BOOTSTRAP_FINGERPRINT" \
  "$RUNTIME_FINGERPRINT" "$BOOTSTRAP_BUNDLE_URL" "$BOOTSTRAP_BUNDLE_SHA" \
  "$BOOTSTRAP_MANIFEST_URL" "$BOOTSTRAP_MANIFEST_SHA" \
  "$BOOTSTRAP_SIGNATURE_URL" "$BOOTSTRAP_SIGNATURE_SHA" \
  "$BOOTSTRAP_PUBLIC_KEY_URL" "$BOOTSTRAP_PUBLIC_KEY_SHA" <<'PY'
import json
import pathlib
import sys

(
    output,
    source_repository,
    test_repository,
    tag,
    target_revision,
    sequence,
    bootstrap_fingerprint,
    runtime_fingerprint,
    bundle_url,
    bundle_sha256,
    manifest_url,
    manifest_sha256,
    signature_url,
    signature_sha256,
    public_key_url,
    public_key_sha256,
) = sys.argv[1:]
document = {
    "schema": "cathedral_validator_live_bootstrap_publication_v1",
    "source_repository": source_repository,
    "publication_repository": test_repository,
    "canonical_source_write_allowed": False,
    "track": "test",
    "tag": tag,
    "target_revision": target_revision,
    "sequence": int(sequence),
    "bootstrap_key_fingerprint": bootstrap_fingerprint,
    "runtime_key_fingerprint": runtime_fingerprint,
    "anonymous_download_required": True,
    "assets": {
        "bundle": {"url": bundle_url, "sha256": bundle_sha256},
        "manifest": {"url": manifest_url, "sha256": manifest_sha256},
        "signature": {"url": signature_url, "sha256": signature_sha256},
        "public_key": {"url": public_key_url, "sha256": public_key_sha256},
    },
}
pathlib.Path(output).write_text(
    json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="ascii"
)
PY

python3 - \
  "$EVIDENCE_DIR/control.json" "$RUN_ID" "$GCP_PROJECT" "$ZONE" \
  "$IAP_CONTROLLER_TRANSPORT" "$IAP_TCP_SOURCE_RANGE" \
  "$MACHINE_TYPE" "$VM_COUNT" "$MAX_RUN_SECONDS" "$ESTIMATED_COST_USD" \
  "$NETWORK_ALLOWANCE_USD" "$PLANNING_TOTAL_USD" \
  "$SOURCE_GITHUB_REPOSITORY" "$TEST_GITHUB_REPOSITORY" "$TEST_MIRROR_MAIN_SHA" \
  "$SOURCE_REVISION_A" "$SOURCE_REVISION_B" "$ARCHIVE_A_SHA" "$ARCHIVE_B_SHA" \
  "$BOOTSTRAP_FINGERPRINT" "$RUNTIME_FINGERPRINT" "$CANARY_BRANCH" \
  "$STABLE_BRANCH" "$FAULT_BRANCH" "$BOOTSTRAP_TAG" \
  "$FIXED_CHANNEL_CACHE_MAX_SECONDS" "$UPDATE_TIMER_INTERVAL_SECONDS" \
  "$FIXED_CHANNEL_WAIT_SECONDS" \
  "$HARNESS_SHA" "$FAULT_ORIGIN_SHA" "$STATE_WAITER_SHA" <<'PY'
import json
import pathlib
import sys

(
    output,
    run_id,
    project,
    zone,
    controller_transport,
    iap_source_range,
    machine_type,
    vm_count,
    max_run_seconds,
    estimated_cost,
    network_allowance,
    planning_total,
    source_repository,
    test_repository,
    test_mirror_main_sha,
    revision_a,
    revision_b,
    archive_a,
    archive_b,
    bootstrap_fingerprint,
    runtime_fingerprint,
    canary_branch,
    stable_branch,
    fault_branch,
    bootstrap_tag,
    fixed_channel_cache_max_seconds,
    update_timer_interval_seconds,
    fixed_channel_wait_seconds,
    harness_sha256,
    fault_origin_sha256,
    state_waiter_sha256,
) = sys.argv[1:]
path = pathlib.Path(output)
document = {
    "schema": "cathedral_validator_live_update_control_v1",
    "run_id": run_id,
    "gcp_project": project,
    "zone": zone,
    "controller_transport": controller_transport,
    "iap_source_range": iap_source_range,
    "vm_service_account_attached": False,
    "machine_type": machine_type,
    "vm_count": int(vm_count),
    "max_run_seconds": int(max_run_seconds),
    "vm_and_disk_estimate_usd": estimated_cost,
    "network_ipv4_and_egress_allowance_usd": network_allowance,
    "planning_total_usd": planning_total,
    "cost_scope": (
        "conservative VM and disk estimate plus a 0.20 USD planning allowance "
        "for two external IPv4 addresses and bounded network traffic; this is "
        "not a cloud billing cap"
    ),
    "source_repository": source_repository,
    "test_publication_repository": test_repository,
    "test_mirror_main_sha": test_mirror_main_sha,
    "canonical_source_write_allowed": False,
    "source_revision_a": revision_a,
    "source_revision_b": revision_b,
    "archive_a_sha256": archive_a,
    "archive_b_sha256": archive_b,
    "bootstrap_key_fingerprint": bootstrap_fingerprint,
    "runtime_key_fingerprint": runtime_fingerprint,
    "canary_branch": canary_branch,
    "stable_branch": stable_branch,
    "fault_branch": fault_branch,
    "no_chain_harness_sha256": harness_sha256,
    "fault_origin_sha256": fault_origin_sha256,
    "state_waiter_sha256": state_waiter_sha256,
    "bootstrap_track": "test",
    "bootstrap_tag": bootstrap_tag,
    "bootstrap_transport": "anonymous_immutable_github_release",
    "anonymous_bootstrap_download_required": True,
    "stable_host_configuration": "cathedral-validator-setup from the signed bootstrap",
    "stable_host_status_command": "cathedral-validator-status --json",
    "canary_host_configuration": "internal direct updater first install; not a public operating mode",
    "operator_hotkey_shape": "disposable bittensor-wallet keyfile, unregistered, never recorded",
    "bootstrap_assets": "reviewed deploy assets with both channel URLs rewritten to the isolated mirror branches",
    "fixed_channel_cache_max_seconds": int(fixed_channel_cache_max_seconds),
    "update_timer_interval_seconds": int(update_timer_interval_seconds),
    "fixed_channel_wait_seconds": int(fixed_channel_wait_seconds),
}
path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="ascii")
PY

publish_release() {
  local metadata="$1"
  local archive="$2"
  local branch="$3"
  local label="$4"
  assert_test_repository_boundary
  assert_test_mirror_main_exact
  python3 "$PUBLISHER" \
    --metadata "$metadata" \
    --archive "$archive" \
    --public-key "$runtime_public" \
    --repository "$TEST_GITHUB_REPOSITORY" \
    --channel-branch "$branch" | tee "$EVIDENCE_DIR/${label}-validate.log"
  assert_test_repository_boundary
  assert_test_mirror_main_exact
  python3 "$PUBLISHER" \
    --metadata "$metadata" \
    --archive "$archive" \
    --public-key "$runtime_public" \
    --repository "$TEST_GITHUB_REPOSITORY" \
    --channel-branch "$branch" \
    --publish | tee "$EVIDENCE_DIR/${label}-publish.log"
}

create_branch() {
  local branch="$1"
  local base_sha
  assert_test_repository_boundary
  base_sha="$(gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)"
  if [[ "$base_sha" != "$SOURCE_REVISION_B" ]]; then
    printf 'REFUSED: test mirror main changed before branch creation\n' >&2
    return 1
  fi
  jq -n --arg ref "refs/heads/$branch" --arg sha "$base_sha" \
    '{ref:$ref,sha:$sha}' | \
    gh api "repos/${TEST_GITHUB_REPOSITORY}/git/refs" --method POST --input - >/dev/null
}

base64_file() {
  python3 - "$1" <<'PY'
import base64
import sys
from pathlib import Path
print(base64.b64encode(Path(sys.argv[1]).read_bytes()).decode("ascii"))
PY
}

put_pointer() {
  local branch="$1"
  local channel="$2"
  local source="$3"
  local outcome="$4"
  local path="validator/${channel}.json"
  local existing_sha=""
  assert_test_repository_boundary
  existing_sha="$(gh api "repos/${TEST_GITHUB_REPOSITORY}/contents/${path}?ref=${branch}" --jq .sha 2>/dev/null || true)"
  if [[ -n "$existing_sha" ]]; then
    jq -n \
      --arg message "test(release): ${RUN_ID} ${outcome}" \
      --arg content "$(base64_file "$source")" \
      --arg branch "$branch" \
      --arg sha "$existing_sha" \
      '{message:$message,content:$content,branch:$branch,sha:$sha}'
  else
    jq -n \
      --arg message "test(release): ${RUN_ID} ${outcome}" \
      --arg content "$(base64_file "$source")" \
      --arg branch "$branch" \
      '{message:$message,content:$content,branch:$branch}'
  fi | gh api "repos/${TEST_GITHUB_REPOSITORY}/contents/${path}" \
    --method PUT --input - --jq .commit.sha
}

wait_raw_exact() {
  local url="$1"
  local expected="$2"
  python3 - "$url" "$expected" <<'PY'
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

url = sys.argv[1]
expected = Path(sys.argv[2]).read_bytes()
deadline = time.monotonic() + 60
last = "not fetched"
while time.monotonic() < deadline:
    try:
        request = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
        with urllib.request.urlopen(request, timeout=10) as response:
            observed = response.read(len(expected) + 1)
        if observed == expected:
            raise SystemExit(0)
        last = "bytes differed"
    except (OSError, urllib.error.URLError) as exc:
        last = str(exc)
    time.sleep(2)
raise SystemExit(f"REFUSED: commit-pinned raw metadata did not converge: {last}")
PY
}

wait_raw_missing() {
  local url="$1"
  python3 - "$url" <<'PY'
import sys
import time
import urllib.error
import urllib.request

deadline = time.monotonic() + 60
while time.monotonic() < deadline:
    try:
        urllib.request.urlopen(sys.argv[1], timeout=10)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise SystemExit(0)
    except urllib.error.URLError:
        pass
    time.sleep(2)
raise SystemExit("REFUSED: commit-pinned outage URL did not return HTTP 404")
PY
}

pin_fault_pointer() {
  local channel="$1"
  local source="$2"
  local outcome="$3"
  local commit
  local url
  commit="$(put_pointer "$FAULT_BRANCH" "$channel" "$source" "$outcome")"
  if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'REFUSED: GitHub did not return an exact fault commit\n' >&2
    return 1
  fi
  url="https://raw.githubusercontent.com/${TEST_GITHUB_REPOSITORY}/${commit}/validator/${channel}.json"
  wait_raw_exact "$url" "$source"
  printf '%s\t%s\t%s\t%s\n' \
    "$outcome" "$commit" "$(shasum -a 256 "$source" | cut -d' ' -f1)" "$url" \
    >>"$EVIDENCE_DIR/fault-urls.tsv"
  printf '%s\n' "$url"
}

record_step "publish first exact A release to isolated canary and stable channels"
publish_release "$CANARY_A1" "$ARCHIVE_A" "$CANARY_BRANCH" "canary-a1"
publish_release "$STABLE_A1" "$ARCHIVE_A" "$STABLE_BRANCH" "stable-a1"
create_branch "$FAULT_BRANCH"

record_step "create bounded two-host GCP network"
project_metadata_snapshot "$EVIDENCE_DIR/project-metadata-before.json"
CREATED_NETWORK=1
if ! gc compute networks create "$NETWORK" --subnet-mode=custom; then
  exit 1
fi
CREATED_SUBNET=1
if ! gc compute networks subnets create "$SUBNET" \
  --network="$NETWORK" --region="$REGION" --range=10.183.39.0/28; then
  exit 1
fi
CREATED_FIREWALL=1
if ! gc compute firewall-rules create "$FIREWALL" \
  --network="$NETWORK" --direction=INGRESS --priority=1000 \
  --action=ALLOW --rules=tcp:22 --source-ranges="$IAP_TCP_SOURCE_RANGE" \
  --target-tags="$INSTANCE_TAG" \
  --description="Cathedral updater live test ${RUN_ID}; IAP TCP forwarding only"; then
  exit 1
fi

AUTO_DELETE_AT="$(python3 - <<'PY'
from datetime import datetime, timedelta, timezone
print((datetime.now(timezone.utc) + timedelta(hours=4)).isoformat(timespec="seconds"))
PY
)"
readonly AUTO_DELETE_AT
printf '%s\n' "$AUTO_DELETE_AT" >"$EVIDENCE_DIR/auto-delete-at.txt"

create_vm() {
  local name="$1"
  local role="$2"
  gc compute instances create "$name" \
    --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="${BOOT_DISK_GB}GB" \
    --boot-disk-type=pd-balanced \
    --boot-disk-auto-delete \
    --network="$NETWORK" \
    --subnet="$SUBNET" \
    --tags="$INSTANCE_TAG" \
    --labels="cathedral-live-run=${RUN_ID},role=${role},no-chain=true" \
    --metadata=block-project-ssh-keys=true,enable-oslogin=false \
    --metadata-from-file="ssh-keys=${SSH_METADATA_FILE}" \
    --no-service-account \
    --no-scopes \
    --termination-time="$AUTO_DELETE_AT" \
    --instance-termination-action=DELETE \
    --shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring
}

CREATED_CANARY_VM=1
if ! create_vm "$CANARY_VM" canary; then
  exit 1
fi
CREATED_STABLE_VM=1
if ! create_vm "$STABLE_VM" stable; then
  exit 1
fi

gc compute instances describe "$CANARY_VM" --zone="$ZONE" --format=json >"$EVIDENCE_DIR/canary-instance.json"
gc compute instances describe "$STABLE_VM" --zone="$ZONE" --format=json >"$EVIDENCE_DIR/stable-instance.json"
gc compute firewall-rules describe "$FIREWALL" --format=json >"$EVIDENCE_DIR/ssh-firewall.json"
python3 - \
  "$EVIDENCE_DIR/canary-instance.json" "$EVIDENCE_DIR/stable-instance.json" \
  "$MACHINE_TYPE" "$BOOT_DISK_GB" "$RUN_ID" "$AUTO_DELETE_AT" \
  "$SSH_USER" "$SSH_PUBLIC_KEY" "$CANARY_VM" "$STABLE_VM" <<'PY'
import json
import sys
from pathlib import Path

(
    canary,
    stable,
    machine_type,
    disk_gb,
    run_id,
    termination_time,
    ssh_user,
    ssh_public_path,
    canary_name,
    stable_name,
) = sys.argv[1:]
expected_public_key = Path(ssh_public_path).read_text(encoding="ascii").strip()
for source, expected_name in ((canary, canary_name), (stable, stable_name)):
    instance = json.loads(Path(source).read_text(encoding="utf-8"))
    if instance.get("serviceAccounts"):
        raise SystemExit(f"REFUSED: {source} unexpectedly has a service account")
    if not str(instance.get("machineType", "")).endswith(f"/{machine_type}"):
        raise SystemExit(f"REFUSED: {source} has the wrong machine type")
    if instance.get("labels", {}).get("cathedral-live-run") != run_id:
        raise SystemExit(f"REFUSED: {source} lacks the exact run label")
    interfaces = instance.get("networkInterfaces")
    if not isinstance(interfaces, list) or len(interfaces) != 1:
        raise SystemExit(f"REFUSED: {source} has an unexpected network interface set")
    access = interfaces[0].get("accessConfigs")
    if (
        not isinstance(access, list)
        or len(access) != 1
        or not isinstance(access[0].get("natIP"), str)
    ):
        raise SystemExit(f"REFUSED: {source} lacks one explicit external IPv4")
    disks = instance.get("disks")
    if not isinstance(disks, list) or len(disks) != 1:
        raise SystemExit(f"REFUSED: {source} has an unexpected disk set")
    if disks[0].get("autoDelete") is not True:
        raise SystemExit(f"REFUSED: {source} boot disk does not auto-delete")
    if not str(disks[0].get("source", "")).endswith(f"/disks/{expected_name}"):
        raise SystemExit(f"REFUSED: {source} has an unexpected boot disk name")
    size = int(disks[0].get("diskSizeGb", 0))
    if size != int(disk_gb):
        raise SystemExit(f"REFUSED: {source} has the wrong boot disk size")
    observed_termination = instance.get("scheduling", {}).get("terminationTime")
    if observed_termination is None:
        raise SystemExit(f"REFUSED: {source} has no automatic termination time")
    from datetime import datetime
    expected = datetime.fromisoformat(termination_time.replace("Z", "+00:00"))
    observed = datetime.fromisoformat(observed_termination.replace("Z", "+00:00"))
    if abs((observed - expected).total_seconds()) > 1:
        raise SystemExit(f"REFUSED: {source} has the wrong termination time")
    if instance.get("scheduling", {}).get("instanceTerminationAction") != "DELETE":
        raise SystemExit(f"REFUSED: {source} does not auto-delete")
    metadata_items = {
        item.get("key"): item.get("value")
        for item in instance.get("metadata", {}).get("items", [])
        if isinstance(item, dict)
    }
    if metadata_items.get("block-project-ssh-keys") != "true":
        raise SystemExit(f"REFUSED: {source} accepts project SSH keys")
    if metadata_items.get("enable-oslogin") != "false":
        raise SystemExit(f"REFUSED: {source} does not use the isolated metadata SSH key")
    if metadata_items.get("ssh-keys", "").rstrip("\n") != f"{ssh_user}:{expected_public_key}":
        raise SystemExit(f"REFUSED: {source} has unexpected instance SSH metadata")
PY

jq -e \
  --arg cidr "$IAP_TCP_SOURCE_RANGE" \
  --arg network "$NETWORK" \
  --arg tag "$INSTANCE_TAG" \
  '.direction == "INGRESS"
   and .priority == 1000
   and .sourceRanges == [$cidr]
   and .allowed == [{"IPProtocol":"tcp","ports":["22"]}]
   and .targetTags == [$tag]
   and (.network | endswith("/" + $network))' \
  "$EVIDENCE_DIR/ssh-firewall.json" >/dev/null
gc compute instances list --filter="labels.cathedral-live-run=${RUN_ID}" \
  --format=json >"$EVIDENCE_DIR/created-run-instances.json"
jq -e --arg canary "$CANARY_VM" --arg stable "$STABLE_VM" \
  'length == 2 and ([.[].name] | sort) == ([$canary, $stable] | sort)' \
  "$EVIDENCE_DIR/created-run-instances.json" >/dev/null

jq -S '(.metadata.items // []) | sort_by(.key)' \
  "$EVIDENCE_DIR/canary-instance.json" >"$EVIDENCE_DIR/canary-instance-metadata-before.json"
jq -S '(.metadata.items // []) | sort_by(.key)' \
  "$EVIDENCE_DIR/stable-instance.json" >"$EVIDENCE_DIR/stable-instance-metadata-before.json"

require_instance_iap_permission() {
  local host="$1"
  local role="$2"
  local response
  response="$(
    google_api_post \
      "https://iap.googleapis.com/v1/projects/${GCP_PROJECT}/iap_tunnel/zones/${ZONE}/instances/${host}:testIamPermissions" \
      "$IAP_INSTANCE_PERMISSION_REQUEST" \
      "${role}-instance-permissions"
  )"
  require_exact_permissions \
    "$response" \
    "iap.tunnelInstances.accessViaIAP"
  printf '%s\n' "$response" \
    | jq -S . >"$EVIDENCE_DIR/${role}-iap-instance-permissions.json"
}

require_instance_iap_permission \
  "$CANARY_VM" canary
require_instance_iap_permission \
  "$STABLE_VM" stable

assert_instance_metadata_unchanged() {
  local host="$1"
  local role="$2"
  local label="$3"
  local full="$EVIDENCE_DIR/${role}-instance-${label}.json"
  local observed="$EVIDENCE_DIR/${role}-instance-metadata-${label}.json"
  if ! gc compute instances describe "$host" --zone="$ZONE" --format=json >"$full"; then
    printf 'REFUSED: instance metadata was unreadable for %s during %s\n' \
      "$host" "$label" >&2
    return 1
  fi
  jq -S '(.metadata.items // []) | sort_by(.key)' "$full" >"$observed"
  if ! cmp -s "$EVIDENCE_DIR/${role}-instance-metadata-before.json" "$observed"; then
    printf 'REFUSED: instance metadata changed for %s during %s\n' \
      "$host" "$label" >&2
    return 1
  fi
  python3 - "$full" "$AUTO_DELETE_AT" <<'PY'
import json
import pathlib
import sys
from datetime import datetime

instance = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if instance.get("serviceAccounts"):
    raise SystemExit("REFUSED: disposable instance gained a service account")
scheduling = instance.get("scheduling", {})
if scheduling.get("instanceTerminationAction") != "DELETE":
    raise SystemExit("REFUSED: disposable instance lost its DELETE action")
expected = datetime.fromisoformat(sys.argv[2].replace("Z", "+00:00"))
observed = datetime.fromisoformat(
    str(scheduling.get("terminationTime", "")).replace("Z", "+00:00")
)
if abs((observed - expected).total_seconds()) > 1:
    raise SystemExit("REFUSED: disposable instance termination time changed")
PY
}

remote() {
  local host="$1"
  shift
  gc compute ssh "${SSH_USER}@${host}" --zone="$ZONE" \
    --tunnel-through-iap \
    --plain \
    --ssh-key-file="$SSH_PRIVATE_KEY" \
    --ssh-flag="-i${SSH_PRIVATE_KEY}" \
    --ssh-flag='-o IdentitiesOnly=yes' \
    --ssh-flag='-o ConnectTimeout=10' \
    --ssh-flag='-o ServerAliveInterval=15' \
    --ssh-flag='-o ServerAliveCountMax=2' \
    --ssh-flag='-o StrictHostKeyChecking=accept-new' \
    --ssh-flag="-o UserKnownHostsFile=${SSH_KNOWN_HOSTS}" \
    --command="$*"
}

record_iap_ssh_dry_run() {
  local host="$1"
  local role="$2"
  local evidence="$EVIDENCE_DIR/${role}-iap-ssh-dry-run.txt"
  gc compute ssh "${SSH_USER}@${host}" --zone="$ZONE" \
    --tunnel-through-iap \
    --plain \
    --ssh-key-file="$SSH_PRIVATE_KEY" \
    --ssh-flag="-i${SSH_PRIVATE_KEY}" \
    --ssh-flag='-o IdentitiesOnly=yes' \
    --ssh-flag='-o ConnectTimeout=10' \
    --ssh-flag='-o StrictHostKeyChecking=accept-new' \
    --ssh-flag="-o UserKnownHostsFile=${SSH_KNOWN_HOSTS}" \
    --command=true \
    --dry-run 2>&1 \
    | sed "s#${RUN_ROOT}#<ephemeral-run-root>#g" >"$evidence"
  grep -F -- 'start-iap-tunnel' "$evidence" >/dev/null
}

prove_iap_transport() {
  local host="$1"
  local role="$2"
  local expected="IAP_TRANSPORT_READY host=${host} transport=${IAP_CONTROLLER_TRANSPORT}"
  remote "$host" \
    "test \"\$(hostname)\" = '${host}' && printf '%s\\n' '${expected}'" \
    2>&1 | tee "$EVIDENCE_DIR/${role}-iap-ssh-marker.log"
  grep -Fx "$expected" "$EVIDENCE_DIR/${role}-iap-ssh-marker.log" >/dev/null
}

canonical_boot_id() {
  local value="${1//$'\r'/}"
  local pattern='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
  if [[ ! "$value" =~ $pattern ]]; then
    return 2
  fi
  printf '%s\n' "$value"
}

read_boot_id() {
  local host="$1"
  local raw
  raw="$(remote "$host" 'cat /proc/sys/kernel/random/boot_id')" || return $?
  canonical_boot_id "$raw"
}

wait_ssh() {
  local host="$1"
  local _attempt
  for _attempt in $(seq 1 60); do
    if remote "$host" 'true' >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  printf 'REFUSED: SSH did not become ready for %s\n' "$host" >&2
  return 1
}

wait_boot_id_changed() {
  local label="$1"
  local host="$2"
  local before="$3"
  local deadline=$((SECONDS + 300))
  local observed
  if before="$(canonical_boot_id "$before")"; then
    :
  else
    printf 'REFUSED: invalid pre-reset boot ID for %s\n' "$host" >&2
    return 2
  fi
  while (( SECONDS < deadline )); do
    if observed="$(read_boot_id "$host" \
      2>>"$EVIDENCE_DIR/${label}-boot-id-ssh.stderr")"; then
      printf 'before=%s observed=%s\n' "$before" "$observed" \
        >>"$EVIDENCE_DIR/${label}-boot-id-observations.log"
      if [[ "$observed" != "$before" ]]; then
        return 0
      fi
    fi
    sleep 5
  done
  printf 'REFUSED: reboot was not proven by a changed boot ID host=%s\n' \
    "$host" >&2
  return 1
}

record_iap_ssh_dry_run "$CANARY_VM" canary
record_iap_ssh_dry_run "$STABLE_VM" stable
wait_ssh "$CANARY_VM"
wait_ssh "$STABLE_VM"
prove_iap_transport "$CANARY_VM" canary
prove_iap_transport "$STABLE_VM" stable
assert_project_metadata_unchanged after-first-ssh
assert_instance_metadata_unchanged "$CANARY_VM" canary after-first-ssh
assert_instance_metadata_unchanged "$STABLE_VM" stable after-first-ssh

stage_host_files() {
  local host="$1"
  local role="$2"
  local attempt
  local status=1
  local attempt_evidence
  local -a operator_inputs=()
  if [[ "$role" == stable ]]; then
    # The stable host receives the operator inputs the guided setup consumes.
    operator_inputs=("$OPERATOR_HOTKEY" "$OPERATOR_POLICY")
  fi
  for attempt in $(seq 1 "$IAP_SCP_MAX_ATTEMPTS"); do
    attempt_evidence="$EVIDENCE_DIR/${role}-iap-scp-attempt-${attempt}.log"
    if gc compute scp --zone="$ZONE" \
      --tunnel-through-iap \
      --plain \
      --ssh-key-file="$SSH_PRIVATE_KEY" \
      --scp-flag="-i${SSH_PRIVATE_KEY}" \
      --scp-flag='-o IdentitiesOnly=yes' \
      --scp-flag='-o ConnectTimeout=10' \
      --scp-flag='-o ServerAliveInterval=15' \
      --scp-flag='-o ServerAliveCountMax=2' \
      --scp-flag="-o UserKnownHostsFile=${SSH_KNOWN_HOSTS}" \
      --scp-flag='-o StrictHostKeyChecking=accept-new' \
      "$HARNESS_SOURCE" \
      "$FAULT_ORIGIN_SOURCE" \
      "$STATE_WAITER_SOURCE" \
      ${operator_inputs[@]+"${operator_inputs[@]}"} \
      "${SSH_USER}@${host}:/tmp/" \
      2>&1 | tee "$attempt_evidence"; then
      printf 'IAP_SCP_PASS host=%s attempt=%s\n' "$host" "$attempt" \
        >"$EVIDENCE_DIR/${role}-iap-scp.log"
      return 0
    else
      status=$?
    fi
    if (( attempt < IAP_SCP_MAX_ATTEMPTS )); then
      printf 'RETRY: transient IAP SCP failure host=%s attempt=%s status=%s\n' \
        "$host" "$attempt" "$status" >&2
      sleep "$attempt"
    fi
  done
  printf 'REFUSED: IAP SCP failed host=%s attempts=%s status=%s\n' \
    "$host" "$IAP_SCP_MAX_ATTEMPTS" "$status" >&2
  return "$status"
}

stage_host_files "$CANARY_VM" canary
stage_host_files "$STABLE_VM" stable
assert_project_metadata_unchanged after-scp
assert_instance_metadata_unchanged "$CANARY_VM" canary after-scp
assert_instance_metadata_unchanged "$STABLE_VM" stable after-scp

capture_host() {
  local label="$1"
  local host="$2"
  local transient_unit="${3:-}"
  local generic_status=0
  local transient_status=0
  if [[ -n "$transient_unit" && ! "$transient_unit" =~ ^[A-Za-z0-9_.@-]+$ ]]; then
    printf 'REFUSED: unsafe transient systemd unit for evidence capture: %s\n' \
      "$transient_unit" >&2
    return 2
  fi
  if remote "$host" "printf '%s\n' '--- current ---'; sudo readlink /opt/cathedral-validator/current || true; printf '%s\n' '--- updater state ---'; sudo cat /var/lib/cathedral-validator-update/state.json || true; printf '%s\n' '--- direct unit state ---'; sudo systemctl show cathedral-validator-direct.service -p Result -p ExecMainCode -p ExecMainStatus -p ActiveState -p SubState -p MainPID -p FragmentPath -p DropInPaths -p RestrictAddressFamilies -p IPAddressDeny || true; sudo systemctl status cathedral-validator-direct.service --full --no-pager || true; printf '%s\n' '--- direct unit definition ---'; sudo systemctl cat cathedral-validator-direct.service || true; printf '%s\n' '--- boot reconcile state ---'; sudo systemctl show cathedral-validator-boot-reconcile.service -p Result -p ExecMainCode -p ExecMainStatus -p ActiveState -p SubState -p MainPID -p FragmentPath -p DropInPaths || true; sudo systemctl status cathedral-validator-boot-reconcile.service --full --no-pager || true; printf '%s\n' '--- boot reconcile definition ---'; sudo systemctl cat cathedral-validator-boot-reconcile.service || true; printf '%s\n' '--- updater service state ---'; sudo systemctl show cathedral-validator-canary-update.service cathedral-validator-update.service -p Id -p Result -p ExecMainCode -p ExecMainStatus -p ActiveState -p SubState -p MainPID -p FragmentPath -p DropInPaths || true; sudo systemctl status cathedral-validator-canary-update.service cathedral-validator-update.service --full --no-pager || true; printf '%s\n' '--- updater service definitions ---'; sudo systemctl cat cathedral-validator-canary-update.service cathedral-validator-update.service || true; printf '%s\n' '--- timers ---'; sudo systemctl show cathedral-validator-canary-update.timer cathedral-validator-update.timer -p Id -p UnitFileState -p ActiveState -p SubState -p ConditionResult -p NextElapseUSecMonotonic -p LastTriggerUSec -p LastTriggerUSecMonotonic -p DropInPaths || true; sudo systemctl cat cathedral-validator-canary-update.timer cathedral-validator-update.timer || true; sudo systemctl list-timers --all --no-pager 'cathedral-validator*update.timer' || true; printf '%s\n' '--- updater and runtime logs ---'; sudo journalctl -u cathedral-validator-boot-reconcile.service -u cathedral-validator-direct.service -u cathedral-validator-update.service -u cathedral-validator-canary-update.service -b -n 250 --no-pager || true" >"$EVIDENCE_DIR/${label}.txt" 2>&1; then
    :
  else
    generic_status=$?
  fi
  if [[ -n "$transient_unit" ]]; then
    if remote "$host" "printf '%s\n' '--- transient updater unit ---'; sudo systemctl show '${transient_unit}.service' -p Id -p Result -p ExecMainCode -p ExecMainStatus -p ActiveState -p SubState -p MainPID -p InvocationID || true; sudo systemctl status '${transient_unit}.service' --full --no-pager || true; printf '%s\n' '--- transient updater journal ---'; sudo journalctl -u '${transient_unit}.service' -b -n 250 --no-pager || true" >>"$EVIDENCE_DIR/${label}.txt" 2>&1; then
      :
    else
      transient_status=$?
    fi
  fi
  if (( generic_status != 0 )); then
    return "$generic_status"
  fi
  return "$transient_status"
}

capture_host_with_retries() {
  local label="$1"
  local host="$2"
  local transient_unit="${3:-}"
  local attempt
  local attempt_label
  local capture_status=1
  for attempt in $(seq 1 "$CAPTURE_RETRY_ATTEMPTS"); do
    attempt_label="${label}-capture-attempt-${attempt}"
    if capture_host "$attempt_label" "$host" "$transient_unit"; then
      if cp "$EVIDENCE_DIR/${attempt_label}.txt" "$EVIDENCE_DIR/${label}.txt"; then
        printf 'attempt=%s status=0\n' "$attempt" \
          >>"$EVIDENCE_DIR/${label}-capture-retries.log"
        return 0
      else
        capture_status=$?
        printf 'attempt=%s status=%s promotion=failed\n' \
          "$attempt" "$capture_status" \
          >>"$EVIDENCE_DIR/${label}-capture-retries.log"
      fi
    else
      capture_status=$?
      printf 'attempt=%s status=%s\n' "$attempt" "$capture_status" \
        >>"$EVIDENCE_DIR/${label}-capture-retries.log"
    fi
    if (( attempt < CAPTURE_RETRY_ATTEMPTS )); then
      sleep "$CAPTURE_RETRY_INTERVAL_SECONDS"
    fi
  done
  printf 'REFUSED: host evidence capture failed after retries label=%s host=%s\n' \
    "$label" "$host" >&2
  return "$capture_status"
}

readonly GUIDED_SETUP="/usr/local/sbin/cathedral-validator-setup"
readonly GUIDED_STATUS="/usr/local/sbin/cathedral-validator-status"
readonly OPERATOR_HOTKEY_PATH="/home/${SSH_USER}/.bittensor/wallets/live/hotkeys/validator"
readonly OPERATOR_POLICY_PATH="/home/${SSH_USER}/amd-sev-snp-policy.json"

guided_setup_command() {
  printf 'sudo %s --hotkey-file %s --expected-hotkey %s --snp-policy %s --confirm-direct-write' \
    "$GUIDED_SETUP" "$OPERATOR_HOTKEY_PATH" "$TEST_HOTKEY" "$OPERATOR_POLICY_PATH"
}

assert_no_operator_secret_in() {
  # The guided setup must never print or pass the hotkey. Every secret field of
  # the disposable keyfile is checked against the captured output.
  local output="$1"
  local secrets
  secrets="$(python3 - "$OPERATOR_HOTKEY" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for field in ("privateKey", "secretPhrase", "secretSeed"):
    value = document.get(field)
    if isinstance(value, str) and value:
        print(value)
PY
)"
  if [[ -z "$secrets" ]]; then
    printf 'REFUSED: disposable operator hotkey has no secret fields to guard\n' >&2
    return 2
  fi
  if printf '%s\n' "$output" | grep -F -f <(printf '%s\n' "$secrets") >/dev/null; then
    printf 'REFUSED: guided setup output exposed operator hotkey material\n' >&2
    return 1
  fi
}

guided_status_json() {
  # The status command exits 2 whenever it cannot claim OPERATING_CONFIRMED,
  # which the no-chain harness never reaches. Only stdout carries the report.
  local host="$1"
  remote "$host" "set +e; sudo $GUIDED_STATUS --json; status=\$?; test \"\$status\" -eq 2 || test \"\$status\" -eq 0"
}

assert_guided_status() {
  local label="$1"
  local host="$2"
  local expected_release="$3"
  local expected_sequence="$4"
  local expected_result="$5"
  local expected_service_active="$6"
  local expected_timer="$7"
  local report
  local failure_status
  if report="$(guided_status_json "$host" 2>>"$EVIDENCE_DIR/${label}-ssh.stderr")"; then
    :
  else
    failure_status=$?
    printf 'REFUSED: guided status unavailable host=%s label=%s\n' "$host" "$label" >&2
    capture_host_with_retries "${label}-status-failure" "$host" || true
    return "$failure_status"
  fi
  printf '%s\n' "$report" | grep -F '"schema":' | tail -n 1 >"$EVIDENCE_DIR/${label}.json"
  if ! jq -e \
    --arg release "$expected_release" \
    --argjson sequence "$expected_sequence" \
    --arg result "$expected_result" \
    --argjson active "$expected_service_active" \
    --arg timer "$expected_timer" \
    --arg hotkey "$TEST_HOTKEY" '
      .schema == "cathedral_validator_local_status_v1"
      and .result == $result
      and .service_active == $active
      and ($timer == "any"
        or (.stable_timer_active == ($timer == "true")
          and .stable_timer_enabled == ($timer == "true")))
      and .release == $release
      and .updater.channel == "stable"
      and .updater.sequence == $sequence
      and .updater.archive_digest == $release
      and .updater.pending_recovery == false
      and .direct.pending == false
      and .direct.last_result == null
      and .direct.block_number == null
      and (tostring | contains($hotkey) | not)
      and (tostring | contains("validator-hotkey") | not)
    ' "$EVIDENCE_DIR/${label}.json" >/dev/null; then
    printf 'REFUSED: guided status differs from expectation host=%s label=%s\n' \
      "$host" "$label" >&2
    capture_host_with_retries "${label}-status-mismatch" "$host" || true
    return 1
  fi
  printf 'GUIDED_STATUS_PROOF label=%s result=%s release=%s sequence=%s\n' \
    "$label" "$expected_result" "$expected_release" "$expected_sequence"
}

direct_writer_identity() {
  local host="$1"
  remote "$host" "set -eu; sudo systemctl show cathedral-validator-direct.service -p MainPID -p InvocationID --value | paste -sd: -; sudo sha256sum /var/lib/cathedral-validator-update/state.json /etc/cathedral-validator/setup-complete.json /etc/cathedral-validator/validator-hotkey /etc/cathedral-validator/update.env | cut -d' ' -f1 | paste -sd: -" | tr -d '\r'
}

configure_stable_host_through_operator_cli() {
  # The public operator path: staged hotkey and policy inputs, one guided
  # setup command, a sanitized status report, and an idempotent rerun that
  # touches neither the writer nor any durable state. Every step returns the
  # failing status explicitly because set -e is suppressed inside the caller's
  # if condition.
  local host="$1"
  local setup_output
  local rerun_output
  local identity_before
  local identity_after
  local status
  remote "$host" "set -eu; test \"\$(sha256sum /tmp/validator | cut -d' ' -f1)\" = '$OPERATOR_HOTKEY_SHA'; test \"\$(sha256sum /tmp/amd-sev-snp-policy.json | cut -d' ' -f1)\" = '$OPERATOR_POLICY_SHA'; install -d -m 0700 /home/${SSH_USER}/.bittensor /home/${SSH_USER}/.bittensor/wallets /home/${SSH_USER}/.bittensor/wallets/live /home/${SSH_USER}/.bittensor/wallets/live/hotkeys; install -m 0600 /tmp/validator '$OPERATOR_HOTKEY_PATH'; install -m 0600 /tmp/amd-sev-snp-policy.json '$OPERATOR_POLICY_PATH'; rm -f /tmp/validator /tmp/amd-sev-snp-policy.json; test \"\$(stat -c '%a' '$OPERATOR_HOTKEY_PATH')\" = 600; printf 'OPERATOR_INPUTS_STAGED hotkey_sha256=%s policy_sha256=%s\n' '$OPERATOR_HOTKEY_SHA' '$OPERATOR_POLICY_SHA'" || return $?
  if setup_output="$(remote "$host" "$(guided_setup_command)" 2>&1)"; then
    :
  else
    status=$?
    printf '%s\n' "$setup_output"
    return "$status"
  fi
  printf '%s\n' "$setup_output"
  printf '%s\n' "$setup_output" | grep -Fx 'SETUP_COMPLETE: stable direct validator configured' >/dev/null || return 1
  assert_no_operator_secret_in "$setup_output" || return $?
  remote "$host" "set -eu
sudo test -f /etc/cathedral-validator/setup-complete.json
sudo jq -e --arg hotkey '$TEST_HOTKEY' '.schema == \"cathedral_validator_setup_complete_v1\" and .expected_hotkey == \$hotkey' /etc/cathedral-validator/setup-complete.json >/dev/null
test \"\$(sudo cat /etc/cathedral-validator/identity.env)\" = 'CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=$TEST_HOTKEY'
sudo grep -Fx 'CATHEDRAL_VALIDATOR_STABLE_METADATA_URL=$STABLE_URL' /etc/cathedral-validator/update.env >/dev/null
sudo grep -Fx 'CATHEDRAL_VALIDATOR_STABLE_MINIMUM_SEQUENCE=1' /etc/cathedral-validator/update.env >/dev/null
! sudo grep -F CANARY /etc/cathedral-validator/update.env >/dev/null
test \"\$(sudo sha256sum /etc/cathedral-validator/validator-hotkey | cut -d' ' -f1)\" = '$OPERATOR_HOTKEY_SHA'
test \"\$(sudo stat -c '%U:%G:%a' /etc/cathedral-validator/validator-hotkey)\" = root:root:600
test \"\$(sudo stat -c '%U:%G:%a' /etc/cathedral-validator/snp-policy.json)\" = root:cathedral-validator:440
test \"\$(sudo sha256sum /etc/cathedral-validator/snp-policy.json | cut -d' ' -f1)\" = '$OPERATOR_POLICY_SHA'
sudo systemctl is-enabled --quiet cathedral-validator-direct.service
sudo systemctl is-active --quiet cathedral-validator-direct.service
sudo systemctl is-enabled --quiet cathedral-validator-update.timer
sudo systemctl is-active --quiet cathedral-validator-update.timer
! sudo systemctl is-enabled --quiet cathedral-validator-canary-update.timer
! sudo systemctl is-active --quiet cathedral-validator-canary-update.timer
printf 'GUIDED_SETUP_CONFIG_PROOF host=%s\n' '$host'" || return $?
  assert_guided_status guided-status-after-setup "$host" "$ARCHIVE_A_SHA" 1 NOT_PROVEN true true || return $?
  identity_before="$(direct_writer_identity "$host")" || return $?
  if rerun_output="$(remote "$host" "$(guided_setup_command)" 2>&1)"; then
    :
  else
    status=$?
    printf '%s\n' "$rerun_output"
    return "$status"
  fi
  printf '%s\n' "$rerun_output"
  printf '%s\n' "$rerun_output" | grep -Fx 'SETUP_COMPLETE: stable direct validator configured' >/dev/null || return 1
  assert_no_operator_secret_in "$rerun_output" || return $?
  identity_after="$(direct_writer_identity "$host")" || return $?
  if [[ -z "$identity_before" || "$identity_before" != "$identity_after" ]]; then
    printf 'REFUSED: idempotent guided setup rerun changed the writer or durable state host=%s before=%s after=%s\n' \
      "$host" "$identity_before" "$identity_after" >&2
    return 1
  fi
  printf 'GUIDED_SETUP_IDEMPOTENT_RERUN host=%s identity=%s\n' "$host" "$identity_after"
}

prove_guided_setup_refuses_stopped_writer() {
  # A committed installation whose writer is stopped, for any reason, must
  # refuse a setup rerun before any mutation and must not be restarted by it.
  local host="$1"
  local before
  local after
  local refusal
  local status
  before="$(direct_writer_identity "$host")" || return $?
  remote "$host" "set -eu; sudo systemctl stop cathedral-validator-direct.service; ! sudo systemctl is-active --quiet cathedral-validator-direct.service; printf 'DIRECT_WRITER_STOPPED_FOR_PROOF\n'" || return $?
  if refusal="$(remote "$host" "set +e; output=\$($(guided_setup_command) 2>&1); status=\$?; printf '%s\n' \"\$output\"; printf 'SETUP_EXIT=%s\n' \"\$status\"; test \"\$status\" -eq 2 && ! sudo systemctl is-active --quiet cathedral-validator-direct.service && printf 'DIRECT_WRITER_STILL_STOPPED\n'" 2>&1)"; then
    :
  else
    status=$?
    printf '%s\n' "$refusal"
    return "$status"
  fi
  printf '%s\n' "$refusal"
  printf '%s\n' "$refusal" | grep -Fx 'SETUP_REFUSED: existing direct validator is stopped and needs review' >/dev/null || return 1
  printf '%s\n' "$refusal" | grep -Fx 'DIRECT_WRITER_STILL_STOPPED' >/dev/null || return 1
  assert_no_operator_secret_in "$refusal" || return $?
  after="$(direct_writer_identity "$host")" || return $?
  if [[ "${before#*:*:}" != "${after#*:*:}" ]]; then
    printf 'REFUSED: refused guided setup rerun changed durable state host=%s before=%s after=%s\n' \
      "$host" "$before" "$after" >&2
    return 1
  fi
  assert_guided_status guided-status-stopped-writer "$host" "$ARCHIVE_A_SHA" 5 NEEDS_REVIEW false any || return $?
  printf 'GUIDED_SETUP_STOPPED_WRITER_REFUSED host=%s\n' "$host"
}

configure_host() {
  local host="$1"
  local channel="$2"
  local timer="$3"
  local other_timer="$4"
  local failure_status
  remote "$host" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null && sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl jq openssl python3.12 python3.12-venv python3-cryptography >/dev/null"
  remote "$host" "sudo install -d -o root -g root -m 0700 /var/tmp/cathedral-live-${RUN_ID} && sudo env -i PATH=/usr/bin:/bin HOME=/var/empty /usr/bin/curl --disable --fail --show-error --silent --location --proto '=https' --tlsv1.2 --header 'Authorization:' --output /var/tmp/cathedral-live-${RUN_ID}/bundle.tar.gz '$BOOTSTRAP_BUNDLE_URL' && printf '%s\n' ANONYMOUS_BOOTSTRAP_DOWNLOADED:bundle && sudo env -i PATH=/usr/bin:/bin HOME=/var/empty /usr/bin/curl --disable --fail --show-error --silent --location --proto '=https' --tlsv1.2 --header 'Authorization:' --output /var/tmp/cathedral-live-${RUN_ID}/manifest.json '$BOOTSTRAP_MANIFEST_URL' && printf '%s\n' ANONYMOUS_BOOTSTRAP_DOWNLOADED:manifest && sudo env -i PATH=/usr/bin:/bin HOME=/var/empty /usr/bin/curl --disable --fail --show-error --silent --location --proto '=https' --tlsv1.2 --header 'Authorization:' --output /var/tmp/cathedral-live-${RUN_ID}/manifest.sig '$BOOTSTRAP_SIGNATURE_URL' && printf '%s\n' ANONYMOUS_BOOTSTRAP_DOWNLOADED:signature && sudo env -i PATH=/usr/bin:/bin HOME=/var/empty /usr/bin/curl --disable --fail --show-error --silent --location --proto '=https' --tlsv1.2 --header 'Authorization:' --output /var/tmp/cathedral-live-${RUN_ID}/bootstrap-public.pem '$BOOTSTRAP_PUBLIC_KEY_URL' && printf '%s\n' ANONYMOUS_BOOTSTRAP_DOWNLOADED:public_key && sudo chmod 0400 /var/tmp/cathedral-live-${RUN_ID}/bundle.tar.gz /var/tmp/cathedral-live-${RUN_ID}/manifest.json /var/tmp/cathedral-live-${RUN_ID}/manifest.sig && sudo chmod 0444 /var/tmp/cathedral-live-${RUN_ID}/bootstrap-public.pem && sudo /usr/bin/python3 -c 'import hashlib,pathlib; expected={\"bundle.tar.gz\":\"$BOOTSTRAP_BUNDLE_SHA\",\"manifest.json\":\"$BOOTSTRAP_MANIFEST_SHA\",\"manifest.sig\":\"$BOOTSTRAP_SIGNATURE_SHA\",\"bootstrap-public.pem\":\"$BOOTSTRAP_PUBLIC_KEY_SHA\"}; root=pathlib.Path(\"/var/tmp/cathedral-live-${RUN_ID}\"); assert all(hashlib.sha256((root/name).read_bytes()).hexdigest()==digest for name,digest in expected.items())' && printf '%s\n' ANONYMOUS_BOOTSTRAP_EXACT_BYTES_VERIFIED && sudo openssl pkeyutl -verify -pubin -inkey /var/tmp/cathedral-live-${RUN_ID}/bootstrap-public.pem -rawin -in /var/tmp/cathedral-live-${RUN_ID}/manifest.json -sigfile /var/tmp/cathedral-live-${RUN_ID}/manifest.sig && test \"sha256:\$(sudo openssl pkey -pubin -in /var/tmp/cathedral-live-${RUN_ID}/bootstrap-public.pem -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)\" = '$BOOTSTRAP_FINGERPRINT' && sudo /usr/bin/python3 -c 'import hashlib,json,pathlib; b=pathlib.Path(\"/var/tmp/cathedral-live-${RUN_ID}/bundle.tar.gz\").read_bytes(); m=json.loads(pathlib.Path(\"/var/tmp/cathedral-live-${RUN_ID}/manifest.json\").read_text(encoding=\"ascii\")); assert len(b)==m[\"bundle\"][\"size\"] and hashlib.sha256(b).hexdigest()==m[\"bundle\"][\"sha256\"]; assert m[\"bootstrap_signing_key\"][\"fingerprint\"]==\"$BOOTSTRAP_FINGERPRINT\"; assert m[\"bootstrap_metadata\"][\"sequence\"]>=1' && sudo sh -c 'tar -xOf /var/tmp/cathedral-live-${RUN_ID}/bundle.tar.gz payload/installer/install_updater_bundle.py > /var/tmp/cathedral-live-${RUN_ID}/signed-installer.py' && sudo chmod 0400 /var/tmp/cathedral-live-${RUN_ID}/signed-installer.py && sudo /usr/bin/python3.12 /var/tmp/cathedral-live-${RUN_ID}/signed-installer.py --bundle /var/tmp/cathedral-live-${RUN_ID}/bundle.tar.gz --manifest /var/tmp/cathedral-live-${RUN_ID}/manifest.json --signature /var/tmp/cathedral-live-${RUN_ID}/manifest.sig --bootstrap-public-key /var/tmp/cathedral-live-${RUN_ID}/bootstrap-public.pem --expected-bootstrap-key-fingerprint '$BOOTSTRAP_FINGERPRINT' --minimum-bootstrap-sequence '$BOOTSTRAP_SEQUENCE'" | tee "$EVIDENCE_DIR/bootstrap-install-${host}.log"
  remote "$host" "test \"\$(sha256sum /tmp/cathedral_no_chain_readiness.py | cut -d' ' -f1)\" = '$HARNESS_SHA' && test \"\$(sha256sum /tmp/tampered_https_origin.py | cut -d' ' -f1)\" = '$FAULT_ORIGIN_SHA' && test \"\$(sha256sum /tmp/wait_updater_state.py | cut -d' ' -f1)\" = '$STATE_WAITER_SHA' && sudo install -d -o root -g root -m 0755 /usr/local/libexec /etc/cathedral-validator-live-test /etc/systemd/system/cathedral-validator-direct.service.d /etc/systemd/system/${timer}.d /etc/systemd/system/${other_timer}.d && sudo install -o root -g root -m 0555 /tmp/cathedral_no_chain_readiness.py /usr/local/libexec/cathedral-no-chain-readiness.py && sudo install -o root -g root -m 0555 /tmp/tampered_https_origin.py /usr/local/libexec/cathedral-tampered-https-origin.py && sudo install -o root -g root -m 0555 /tmp/wait_updater_state.py /usr/local/libexec/cathedral-wait-updater-state.py"
  if [[ "$channel" == "canary" ]]; then
    # Cathedral's internal canary host is not a public operating mode, so it
    # keeps the direct configuration path. The stable host is configured only
    # through the installed guided setup.
    remote "$host" "printf '%s\n' 'CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=$TEST_HOTKEY' | sudo tee /etc/cathedral-validator/identity.env >/dev/null && printf '%s\n' 'CATHEDRAL_SNP_POLICY=/etc/cathedral-validator/snp-policy.json' 'CATHEDRAL_VALIDATOR_INTERVAL_SECONDS=86400' | sudo tee /etc/cathedral-validator/direct.env >/dev/null && printf '%s\n' 'CATHEDRAL_VALIDATOR_CANARY_METADATA_URL=$CANARY_URL' 'CATHEDRAL_VALIDATOR_STABLE_METADATA_URL=$STABLE_URL' 'CATHEDRAL_VALIDATOR_CANARY_MINIMUM_SEQUENCE=1' 'CATHEDRAL_VALIDATOR_STABLE_MINIMUM_SEQUENCE=1' | sudo tee /etc/cathedral-validator/update.env >/dev/null && printf '%s\n' '$SNP_POLICY_JSON' | sudo tee /etc/cathedral-validator/snp-policy.json >/dev/null && sudo install -o root -g root -m 0600 /dev/null /etc/cathedral-validator/validator-hotkey && sudo chmod 0600 /etc/cathedral-validator/identity.env /etc/cathedral-validator/direct.env /etc/cathedral-validator/update.env && sudo chown root:cathedral-validator /etc/cathedral-validator/snp-policy.json && sudo chmod 0440 /etc/cathedral-validator/snp-policy.json"
  fi
  remote "$host" "sudo systemctl disable --now '$other_timer' && printf '%s\n' '[Service]' 'Environment=PEX_INTERPRETER=1' 'LoadCredential=' 'ExecStartPre=' 'ExecStart=' 'ExecStart=/opt/cathedral-validator/current/bin/cathedral-validator /usr/local/libexec/cathedral-no-chain-readiness.py' 'Environment=CATHEDRAL_LIVE_TEST_PEX_ROOT=/run/cathedral-validator-pex' 'Restart=no' 'TimeoutStartSec=${DIRECT_START_TIMEOUT_SECONDS}s' 'TimeoutStopSec=10s' 'RestrictAddressFamilies=' 'RestrictAddressFamilies=AF_UNIX' 'IPAddressDeny=any' 'PrivateNetwork=true' | sudo tee /etc/systemd/system/cathedral-validator-direct.service.d/no-chain-live-test.conf >/dev/null && printf '%s\n' '[Timer]' 'OnBootSec=' 'OnActiveSec=20s' 'OnUnitActiveSec=${UPDATE_TIMER_INTERVAL_SECONDS}s' 'RandomizedDelaySec=0' | sudo tee /etc/systemd/system/${timer}.d/live-test.conf >/dev/null && printf '%s\n' '[Unit]' 'ConditionPathExists=/run/cathedral-live-${RUN_ID}-permit-${other_timer}' | sudo tee /etc/systemd/system/${other_timer}.d/deny-live-test.conf >/dev/null && test ! -e '/run/cathedral-live-${RUN_ID}-permit-${other_timer}' && sudo systemctl daemon-reload && timer_schedule=\"\$(sudo systemctl show '$timer' -p TimersMonotonic --value)\" && ! printf '%s\n' \"\$timer_schedule\" | grep -F 'OnBootUSec=' >/dev/null && printf '%s\n' \"\$timer_schedule\" | grep -F 'OnActiveUSec=' >/dev/null && printf '%s\n' \"\$timer_schedule\" | grep -F 'OnUnitActiveUSec=' >/dev/null && test \"\$(sudo systemctl show '$timer' -p UnitFileState --value)\" = disabled && test \"\$(sudo systemctl show '$timer' -p ActiveState --value)\" = inactive && test \"\$(sudo systemctl show '$other_timer' -p UnitFileState --value)\" = disabled && sudo systemctl cat '$other_timer' | grep -Fx 'ConditionPathExists=/run/cathedral-live-${RUN_ID}-permit-${other_timer}' >/dev/null && sudo systemctl start '$other_timer' && other_timer_state=\"\$(sudo systemctl show '$other_timer' -p ActiveState -p SubState -p ConditionResult)\" && printf '%s\n' \"\$other_timer_state\" | grep -Fx 'ActiveState=inactive' >/dev/null && printf '%s\n' \"\$other_timer_state\" | grep -Fx 'SubState=dead' >/dev/null && ! sudo systemctl is-active --quiet '$other_timer' && sudo systemctl enable cathedral-validator-direct.service"
  if [[ "$channel" == "canary" ]]; then
    # The internal canary first install binds the exact signed canary record
    # at the minimum sequence, the same anchor the guided setup passes for
    # stable from the signed example.
    if remote "$host" "sudo /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update --bootstrap-first-install --channel=canary --metadata-url='$CANARY_URL' --public-key=/etc/cathedral-validator/runtime-release-public-key.pem --identity-file=/etc/cathedral-validator/identity.env --minimum-sequence=1 --first-install-metadata-sha256='$CANARY_A1_SHA' --cycle-wait-seconds=10 --operation-timeout-seconds=180" 2>&1 | tee "$EVIDENCE_DIR/first-install-command-${host}.log"; then
      :
    else
      failure_status=$?
      capture_host_with_retries "first-install-failure-${channel}" "$host" || true
      return "$failure_status"
    fi
  else
    if configure_stable_host_through_operator_cli "$host" 2>&1 | tee "$EVIDENCE_DIR/first-install-command-${host}.log"; then
      :
    else
      failure_status=$?
      capture_host_with_retries "first-install-failure-${channel}" "$host" || true
      return "$failure_status"
    fi
  fi
  if remote "$host" "sudo systemctl is-active cathedral-validator-direct.service && sudo journalctl -u cathedral-validator-direct.service -n 80 --no-pager | grep 'TEST_NO_CHAIN_READY target=$ARCHIVE_A_SHA'" 2>&1 | tee "$EVIDENCE_DIR/first-readiness-command-${host}.log"; then
    :
  else
    failure_status=$?
    capture_host_with_retries "first-readiness-failure-${channel}" "$host" || true
    return "$failure_status"
  fi
}

record_step "first install A through signed bootstrap and no-chain systemd readiness"
configure_host "$CANARY_VM" canary cathedral-validator-canary-update.timer cathedral-validator-update.timer
configure_host "$STABLE_VM" stable cathedral-validator-update.timer cathedral-validator-canary-update.timer

current_digest() {
  remote "$1" 'sudo readlink /opt/cathedral-validator/current' | awk -F/ '{print $2}' | tr -d '\r'
}

main_pid() {
  remote "$1" 'sudo systemctl show cathedral-validator-direct.service -p MainPID --value' | tr -d '\r'
}

main_invocation_id() {
  remote "$1" 'sudo systemctl show cathedral-validator-direct.service -p InvocationID --value' | tr -d '\r'
}

direct_service_identity() {
  remote "$1" 'sudo systemctl show cathedral-validator-direct.service -p ActiveState -p SubState -p MainPID -p InvocationID' | tr -d '\r'
}

direct_service_identity_is_active() {
  local identity="$1"
  local invocation
  local pid
  invocation="$(printf '%s\n' "$identity" | sed -n 's/^InvocationID=//p')"
  pid="$(printf '%s\n' "$identity" | sed -n 's/^MainPID=//p')"
  [[ "$(printf '%s\n' "$identity" | sed -n 's/^ActiveState=//p')" == active && \
    "$(printf '%s\n' "$identity" | sed -n 's/^SubState=//p')" == running && \
    "$pid" =~ ^[1-9][0-9]*$ && -n "$invocation" ]]
}

wait_direct_service_active() {
  local label="$1"
  local host="$2"
  local deadline=$((SECONDS + DIRECT_START_TIMEOUT_SECONDS))
  local identity=""
  while (( SECONDS < deadline )); do
    if identity="$(direct_service_identity "$host" \
      2>>"$EVIDENCE_DIR/${label}-direct-service-ssh.stderr")"; then
      printf '%s\n' "$identity"
      if direct_service_identity_is_active "$identity"; then
        return 0
      fi
    fi
    sleep 2
  done
  printf 'REFUSED: direct service did not become healthy without controller start host=%s\n' \
    "$host" >&2
  capture_host_with_retries "${label}-direct-service-timeout" "$host" || true
  return 1
}

wait_sequence() {
  local label="$1"
  local host="$2"
  local channel="$3"
  local metadata="$4"
  local expected_record
  local sequence
  local deadline=$((SECONDS + FIXED_CHANNEL_WAIT_SECONDS))
  local snapshot
  expected_record="$(expected_channel_record "$metadata" "$channel")"
  sequence="$(printf '%s\n' "$expected_record" | jq -er '.sequence')"
  while (( SECONDS < deadline )); do
    if snapshot="$(snapshot_state "$host" "$channel" 2>>"$EVIDENCE_DIR/${label}-sequence-snapshot-ssh.stderr")"; then
      printf '%s\n' "$snapshot"
      if printf '%s\n' "$snapshot" | jq -e --argjson expected "$expected_record" \
        '.record == $expected and .sequence == $expected.sequence and .pending == null' >/dev/null; then
        return 0
      fi
    fi
    sleep 5
  done
  printf 'REFUSED: timed out waiting for exact updater state host=%s channel=%s sequence=%s\n' \
    "$host" "$channel" "$sequence" >&2
  capture_host_with_retries "${label}-sequence-wait-failure" "$host" || true
  return 1
}

start_update_timer() {
  local host="$1"
  local timer="$2"
  local active
  local next
  local service="${timer%.timer}.service"
  local service_active
  local status
  local substate
  local timer_output
  if timer_output="$(remote "$host" "set +e; sudo systemctl enable --now '$timer' && sudo systemctl is-enabled --quiet '$timer' && sudo systemctl is-active --quiet '$timer'; timer_status=\$?; sudo systemctl show '$timer' -p Id -p UnitFileState -p ActiveState -p SubState -p ConditionResult -p NextElapseUSecMonotonic -p LastTriggerUSec -p LastTriggerUSecMonotonic || true; printf 'TriggeredServiceActiveState=%s\n' \"\$(sudo systemctl show '$service' -p ActiveState --value 2>/dev/null)\"; sudo systemctl list-timers --all --no-pager '$timer' || true; exit \$timer_status" 2>&1)"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$timer_output"
  if (( status != 0 )); then
    return "$status"
  fi
  active="$(printf '%s\n' "$timer_output" | sed -n 's/^ActiveState=//p' | head -n 1)"
  substate="$(printf '%s\n' "$timer_output" | sed -n 's/^SubState=//p' | head -n 1)"
  next="$(printf '%s\n' "$timer_output" | sed -n 's/^NextElapseUSecMonotonic=//p' | head -n 1)"
  service_active="$(printf '%s\n' "$timer_output" | sed -n 's/^TriggeredServiceActiveState=//p' | head -n 1)"
  if ! timer_state_is_started "$active" "$substate" "$next" "$service_active"; then
    printf 'REFUSED: enabled timer has no scheduled trigger host=%s timer=%s active=%s substate=%s next=%s\n' \
      "$host" "$timer" "$active" "$substate" "$next" >&2
    return 1
  fi
}

timer_state_is_rearmed() {
  local active="$1"
  local substate="$2"
  local next="$3"
  [[ "$active" == active && "$substate" == waiting && -n "$next" && \
    "$next" != 0 && "$next" != infinity && "$next" != n/a ]]
}

timer_state_is_started() {
  local active="$1"
  local substate="$2"
  local next="$3"
  local service_active="$4"
  if timer_state_is_rearmed "$active" "$substate" "$next"; then
    return 0
  fi
  [[ "$active" == active && "$substate" == running && \
    ("$service_active" == active || "$service_active" == activating) ]]
}

wait_timer_rearmed() {
  local label="$1"
  local host="$2"
  local timer="$3"
  local deadline=$((SECONDS + 120))
  local active
  local substate
  local next
  local timer_state=""
  while (( SECONDS < deadline )); do
    if timer_state="$(remote "$host" "sudo systemctl show '$timer' -p ActiveState -p SubState -p NextElapseUSecMonotonic" 2>>"$EVIDENCE_DIR/${label}-timer-rearm-ssh.stderr")"; then
      active="$(printf '%s\n' "$timer_state" | sed -n 's/^ActiveState=//p')"
      substate="$(printf '%s\n' "$timer_state" | sed -n 's/^SubState=//p')"
      next="$(printf '%s\n' "$timer_state" | sed -n 's/^NextElapseUSecMonotonic=//p')"
      if timer_state_is_rearmed "$active" "$substate" "$next"; then
        printf '%s\n' "$timer_state"
        return 0
      fi
    fi
    printf '%s\n' "$timer_state"
    sleep 2
  done
  printf 'REFUSED: timer did not re-arm after update host=%s timer=%s\n' \
    "$host" "$timer" >&2
  return 1
}

wait_timer_reactivation() {
  local label="$1"
  local host="$2"
  local timer="$3"
  local before_invocation="$4"
  local before_trigger="$5"
  local service="${timer%.timer}.service"
  local deadline=$((SECONDS + REACTIVATION_PROOF_WAIT_SECONDS))
  local active
  local exec_status
  local invocation
  local next
  local result
  local service_active
  local state=""
  local substate
  local trigger
  while (( SECONDS < deadline )); do
    if state="$(remote "$host" "sudo systemctl show '$timer' -p ActiveState -p SubState -p NextElapseUSecMonotonic -p LastTriggerUSec; sudo systemctl show '$service' -p InvocationID -p Result -p ExecMainStatus -p ActiveState | sed 's/^/Service/'" 2>>"$EVIDENCE_DIR/${label}-timer-reactivation-ssh.stderr")"; then
      active="$(printf '%s\n' "$state" | sed -n 's/^ActiveState=//p')"
      substate="$(printf '%s\n' "$state" | sed -n 's/^SubState=//p')"
      next="$(printf '%s\n' "$state" | sed -n 's/^NextElapseUSecMonotonic=//p')"
      trigger="$(printf '%s\n' "$state" | sed -n 's/^LastTriggerUSec=//p')"
      invocation="$(printf '%s\n' "$state" | sed -n 's/^ServiceInvocationID=//p')"
      result="$(printf '%s\n' "$state" | sed -n 's/^ServiceResult=//p')"
      exec_status="$(printf '%s\n' "$state" | sed -n 's/^ServiceExecMainStatus=//p')"
      service_active="$(printf '%s\n' "$state" | sed -n 's/^ServiceActiveState=//p')"
      if [[ -n "$invocation" && "$invocation" != "$before_invocation" && \
        -n "$trigger" && "$trigger" != "$before_trigger" && \
        "$result" == success && "$exec_status" == 0 && \
        "$service_active" == inactive ]] && \
        timer_state_is_rearmed "$active" "$substate" "$next"; then
        printf '%s\n' "$state"
        return 0
      fi
    fi
    printf '%s\n' "$state"
    sleep 2
  done
  printf 'REFUSED: re-enabled timer did not launch and complete a fresh update host=%s timer=%s\n' \
    "$host" "$timer" >&2
  capture_host_with_retries "${label}-timer-reactivation-failure" "$host" || true
  return 1
}

start_reactivation_proof_timer() {
  local host="$1"
  local timer="$2"
  local before_invocation="$3"
  local before_trigger="$4"
  local service="${timer%.timer}.service"
  local active
  local next
  local substate
  local timer_output
  if timer_output="$(remote "$host" "set -eu; sudo systemctl disable --now '$timer'; printf '%s\n' '[Timer]' 'OnBootSec=' 'OnActiveSec=${REACTIVATION_PROOF_DELAY_SECONDS}s' 'OnUnitActiveSec=${REACTIVATION_PROOF_REARM_SECONDS}s' 'RandomizedDelaySec=0' | sudo tee /etc/systemd/system/${timer}.d/reactivation-proof.conf >/dev/null; sudo systemctl daemon-reload; timer_schedule=\"\$(sudo systemctl show '$timer' -p TimersMonotonic --value)\"; printf '%s\n' \"\$timer_schedule\"; printf '%s\n' \"\$timer_schedule\" | grep -F 'OnActiveUSec=' >/dev/null; printf '%s\n' \"\$timer_schedule\" | grep -F 'OnUnitActiveUSec=' >/dev/null; ! printf '%s\n' \"\$timer_schedule\" | grep -F 'OnBootUSec=' >/dev/null; test \"\$(sudo systemctl show '$service' -p InvocationID --value)\" = '$before_invocation'; test \"\$(sudo systemctl show '$timer' -p LastTriggerUSec --value)\" = '$before_trigger'; sudo systemctl enable --now '$timer'; sudo systemctl is-enabled --quiet '$timer'; sudo systemctl is-active --quiet '$timer'; test \"\$(sudo systemctl show '$service' -p InvocationID --value)\" = '$before_invocation'; test \"\$(sudo systemctl show '$timer' -p LastTriggerUSec --value)\" = '$before_trigger'; sudo systemctl show '$timer' -p Id -p UnitFileState -p ActiveState -p SubState -p NextElapseUSecMonotonic -p LastTriggerUSec -p LastTriggerUSecMonotonic; sudo systemctl list-timers --all --no-pager '$timer'")"; then
    :
  else
    return $?
  fi
  printf '%s\n' "$timer_output"
  active="$(printf '%s\n' "$timer_output" | sed -n 's/^ActiveState=//p' | tail -n 1)"
  substate="$(printf '%s\n' "$timer_output" | sed -n 's/^SubState=//p' | tail -n 1)"
  next="$(printf '%s\n' "$timer_output" | sed -n 's/^NextElapseUSecMonotonic=//p' | tail -n 1)"
  if ! timer_state_is_rearmed "$active" "$substate" "$next"; then
    printf 'REFUSED: isolated reactivation timer has no scheduled trigger host=%s timer=%s active=%s substate=%s next=%s\n' \
      "$host" "$timer" "$active" "$substate" "$next" >&2
    return 1
  fi
}

observe_timer_reactivation() {
  local label="$1"
  local host="$2"
  local timer="$3"
  local channel="$4"
  local metadata="$5"
  local expected_digest="$6"
  local service="${timer%.timer}.service"
  local before_invocation
  local before_trigger
  local failure_status
  before_invocation="$(remote "$host" "sudo systemctl show '$service' -p InvocationID --value" | tr -d '\r')"
  before_trigger="$(remote "$host" "sudo systemctl show '$timer' -p LastTriggerUSec --value" | tr -d '\r')"
  if [[ -z "$before_invocation" || -z "$before_trigger" ]]; then
    printf 'REFUSED: timer reactivation requires prior timer and service evidence host=%s timer=%s\n' \
      "$host" "$timer" >&2
    return 1
  fi
  if start_reactivation_proof_timer "$host" "$timer" \
    "$before_invocation" "$before_trigger" 2>&1 | \
    tee "$EVIDENCE_DIR/${label}-timer-reactivation-start.log"; then
    :
  else
    failure_status=$?
    capture_host_with_retries "${label}-timer-reactivation-start-failure" \
      "$host" || true
    return "$failure_status"
  fi
  wait_timer_reactivation "$label" "$host" "$timer" \
    "$before_invocation" "$before_trigger" 2>&1 | \
    tee "$EVIDENCE_DIR/${label}-timer-reactivation-wait.log"
  wait_sequence "${label}-state" "$host" "$channel" "$metadata" 2>&1 | \
    tee "$EVIDENCE_DIR/${label}-timer-reactivation-state.log"
  assert_current "$host" "$expected_digest" "$label"
}

observe_timer_update() {
  local label="$1"
  local host="$2"
  local timer="$3"
  local channel="$4"
  local metadata="$5"
  local expected_digest="$6"
  local failure_status
  if start_update_timer "$host" "$timer" 2>&1 | tee "$EVIDENCE_DIR/${label}-timer-start-command.log"; then
    :
  else
    failure_status=$?
    capture_host_with_retries "${label}-timer-start-failure" "$host" || true
    return "$failure_status"
  fi
  if wait_sequence "${label}-timer" "$host" "$channel" "$metadata" 2>&1 | tee "$EVIDENCE_DIR/${label}-timer-wait-command.log"; then
    :
  else
    failure_status=$?
    capture_host_with_retries "${label}-timer-wait-failure" "$host" || true
    return "$failure_status"
  fi
  if assert_current "$host" "$expected_digest" "$label" 2>&1 | tee "$EVIDENCE_DIR/${label}-timer-current-command.log"; then
    :
  else
    failure_status=$?
    capture_host_with_retries "${label}-timer-current-failure" "$host" || true
    return "$failure_status"
  fi
  if wait_timer_rearmed "$label" "$host" "$timer" 2>&1 | tee "$EVIDENCE_DIR/${label}-timer-rearm-command.log"; then
    :
  else
    failure_status=$?
    capture_host_with_retries "${label}-timer-rearm-failure" "$host" || true
    return "$failure_status"
  fi
}

run_update() {
  local host="$1"
  local channel="$2"
  local url="$3"
  local cycle_wait="${4:-10}"
  remote "$host" "sudo /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update --channel='$channel' --metadata-url='$url' --public-key=/etc/cathedral-validator/runtime-release-public-key.pem --identity-file=/etc/cathedral-validator/identity.env --minimum-sequence=1 --cycle-wait-seconds='$cycle_wait' --operation-timeout-seconds=180"
}

require_host_proof() {
  local label="$1"
  local host="$2"
  local failure_status
  shift 2
  if "$@" 2>&1 | tee "$EVIDENCE_DIR/${label}-command.log"; then
    return 0
  else
    failure_status=$?
    capture_host_with_retries "${label}-failure" "$host" || true
    return "$failure_status"
  fi
}

require_host_value() {
  local label="$1"
  local host="$2"
  local failure_status
  shift 2
  if "$@" 2>"$EVIDENCE_DIR/${label}-value-command.stderr" \
    | tee "$EVIDENCE_DIR/${label}-value.txt"; then
    return 0
  else
    failure_status=$?
    capture_host_with_retries "${label}-failure" "$host" || true
    return "$failure_status"
  fi
}

snapshot_state() {
  local host="$1"
  local channel="$2"
  remote "$host" "sudo /usr/bin/python3 /usr/local/libexec/cathedral-wait-updater-state.py --state /var/lib/cathedral-validator-update/state.json --snapshot '$channel'" | tr -d '\r'
}

expect_update_refused() {
  local label="$1"
  local host="$2"
  local channel="$3"
  local url="$4"
  local expected_refusal="$5"
  local cycle_wait="${6:-10}"
  local trust_mode="${7:-system}"
  local service_policy="${8:-unchanged}"
  local before
  local after
  local before_service
  local after_service
  local before_invocation
  local after_invocation
  if [[ "$service_policy" != unchanged && "$service_policy" != restarted ]]; then
    printf 'REFUSED: invalid negative-scenario service policy: %s\n' \
      "$service_policy" >&2
    return 2
  fi
  before="$(snapshot_state "$host" "$channel")"
  printf '%s\n' "$before" >"$EVIDENCE_DIR/${label}-before.json"
  printf '%s\n' "$before" | jq -e '.pending == null' >/dev/null
  before_service="$(require_host_value "${label}-service-before" "$host" \
    direct_service_identity "$host")"
  printf '%s\n' "$before_service" >"$EVIDENCE_DIR/${label}-service-before.txt"
  if ! direct_service_identity_is_active "$before_service"; then
    printf 'REFUSED: %s began without a healthy direct service\n' "$label" >&2
    capture_host_with_retries "${label}-service-before-unhealthy" "$host" || true
    return 1
  fi
  if [[ "$trust_mode" == "combined-test-ca" ]]; then
    if remote "$host" "sudo env -u HTTPS_PROXY -u https_proxy SSL_CERT_FILE=/etc/cathedral-validator-live-test/combined-ca.pem NO_PROXY=github.com,raw.githubusercontent.com no_proxy=github.com,raw.githubusercontent.com /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update --channel='$channel' --metadata-url='$url' --public-key=/etc/cathedral-validator/runtime-release-public-key.pem --identity-file=/etc/cathedral-validator/identity.env --minimum-sequence=1 --cycle-wait-seconds='$cycle_wait' --operation-timeout-seconds=180" >"$EVIDENCE_DIR/${label}.log" 2>&1; then
      printf 'REFUSED: negative scenario unexpectedly succeeded: %s\n' "$label" >&2
      return 1
    fi
  elif run_update "$host" "$channel" "$url" "$cycle_wait" >"$EVIDENCE_DIR/${label}.log" 2>&1; then
    printf 'REFUSED: negative scenario unexpectedly succeeded: %s\n' "$label" >&2
    return 1
  fi
  grep -Fx "CATHEDRAL_VALIDATOR_UPDATE_REFUSED: ${expected_refusal}" \
    "$EVIDENCE_DIR/${label}.log" >/dev/null
  after="$(snapshot_state "$host" "$channel")"
  printf '%s\n' "$after" >"$EVIDENCE_DIR/${label}-after.json"
  if [[ "$before" != "$after" ]]; then
    printf 'REFUSED: %s changed current, sequence, or pending state\n' "$label" >&2
    return 1
  fi
  after_service="$(require_host_value "${label}-service-after" "$host" \
    direct_service_identity "$host")"
  printf '%s\n' "$after_service" >"$EVIDENCE_DIR/${label}-service-after.txt"
  if ! direct_service_identity_is_active "$after_service"; then
    printf 'REFUSED: %s left the direct service unhealthy\n' "$label" >&2
    capture_host_with_retries "${label}-service-after-unhealthy" "$host" || true
    return 1
  fi
  if [[ "$service_policy" == unchanged ]]; then
    if [[ "$before_service" != "$after_service" ]]; then
      printf 'REFUSED: %s restarted or changed the direct service\n' "$label" >&2
      capture_host_with_retries "${label}-service-changed" "$host" || true
      return 1
    fi
  else
    before_invocation="$(printf '%s\n' "$before_service" | sed -n 's/^InvocationID=//p')"
    after_invocation="$(printf '%s\n' "$after_service" | sed -n 's/^InvocationID=//p')"
    if [[ "$before_invocation" == "$after_invocation" ]]; then
      printf 'REFUSED: %s did not prove a fresh healthy rollback invocation\n' \
        "$label" >&2
      capture_host_with_retries "${label}-service-not-restarted" "$host" || true
      return 1
    fi
  fi
}

assert_current() {
  local host="$1"
  local expected="$2"
  local label="$3"
  local observed
  local failure_status
  if observed="$(current_digest "$host" 2>>"$EVIDENCE_DIR/${label}-current-ssh.stderr")"; then
    :
  else
    failure_status=$?
    printf 'expected=%s observed=unavailable\n' "$expected" \
      >"$EVIDENCE_DIR/${label}-current-proof.txt"
    capture_host_with_retries "${label}-current-read-failure" "$host" || true
    return "$failure_status"
  fi
  printf 'expected=%s observed=%s\n' "$expected" "$observed" \
    >"$EVIDENCE_DIR/${label}-current-proof.txt"
  if [[ "$observed" != "$expected" ]]; then
    printf 'REFUSED: %s current digest %s, expected %s\n' "$label" "$observed" "$expected" >&2
    capture_host_with_retries "${label}-current-mismatch" "$host" || true
    return 1
  fi
}

record_step "prove both first installs committed exact release A"
wait_sequence canary-first-install "$CANARY_VM" canary "$CANARY_A1"
wait_sequence stable-first-install "$STABLE_VM" stable "$STABLE_A1"
assert_current "$CANARY_VM" "$ARCHIVE_A_SHA" canary-first-install-a
assert_current "$STABLE_VM" "$ARCHIVE_A_SHA" stable-first-install-a

record_step "invalid signature refuses without changing A"
invalid_url="$(pin_fault_pointer canary "$INVALID_B2" "invalid signature pointer")"
expect_update_refused invalid-signature "$CANARY_VM" canary "$invalid_url" \
  'release metadata signature is invalid'
assert_current "$CANARY_VM" "$ARCHIVE_A_SHA" invalid-signature

start_fault_origin() {
  local host="$1"
  remote "$host" "sudo openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=github.com' -addext 'subjectAltName=DNS:github.com' -addext 'basicConstraints=critical,CA:TRUE' -keyout /etc/cathedral-validator-live-test/fault-key.pem -out /etc/cathedral-validator-live-test/fault-cert.pem >/dev/null 2>&1 && sudo sh -c 'cat /etc/ssl/certs/ca-certificates.crt /etc/cathedral-validator-live-test/fault-cert.pem > /etc/cathedral-validator-live-test/combined-ca.pem' && sudo chmod 0444 /etc/cathedral-validator-live-test/combined-ca.pem && printf 'deliberately-corrupt-archive-%s\n' '$RUN_ID' | sudo tee /etc/cathedral-validator-live-test/tampered-body >/dev/null && printf '127.0.0.1 github.com # cathedral-live-$RUN_ID\n' | sudo tee -a /etc/hosts >/dev/null && grep -Fx '127.0.0.1 github.com # cathedral-live-$RUN_ID' /etc/hosts >/dev/null && ! grep -E '^[^#]*raw\\.githubusercontent\\.com' /etc/hosts >/dev/null && sudo sh -c 'nohup /usr/bin/python3 /usr/local/libexec/cathedral-tampered-https-origin.py --cert /etc/cathedral-validator-live-test/fault-cert.pem --key /etc/cathedral-validator-live-test/fault-key.pem --body /etc/cathedral-validator-live-test/tampered-body >/var/log/cathedral-tampered-origin.log 2>&1 & echo \$! >/run/cathedral-tampered-origin.pid' && sleep 1"
}

stop_fault_origin() {
  local host="$1"
  remote "$host" "sudo sh -c 'test ! -f /run/cathedral-tampered-origin.pid || kill \"\$(cat /run/cathedral-tampered-origin.pid)\" 2>/dev/null || true'; sudo sed -i '\|# cathedral-live-$RUN_ID$|d' /etc/hosts; sudo rm -f /run/cathedral-tampered-origin.pid /etc/cathedral-validator-live-test/fault-key.pem /etc/cathedral-validator-live-test/fault-cert.pem /etc/cathedral-validator-live-test/combined-ca.pem /etc/cathedral-validator-live-test/tampered-body" >/dev/null
}

record_step "tampered archive bytes refuse before activation"
tamper_url="$(pin_fault_pointer canary "$CANARY_B2" "tampered archive metadata")"
start_fault_origin "$CANARY_VM"
tamper_metadata_sha="$(shasum -a 256 "$CANARY_B2" | cut -d' ' -f1)"
remote "$CANARY_VM" "sudo env -u HTTPS_PROXY -u https_proxy SSL_CERT_FILE=/etc/cathedral-validator-live-test/combined-ca.pem NO_PROXY=github.com,raw.githubusercontent.com no_proxy=github.com,raw.githubusercontent.com /usr/bin/python3 -c 'import hashlib,sys,urllib.request; body=urllib.request.urlopen(sys.argv[1],timeout=20).read(); assert hashlib.sha256(body).hexdigest()==sys.argv[2]' '$tamper_url' '$tamper_metadata_sha'"
expect_update_refused tampered-archive "$CANARY_VM" canary "$tamper_url" \
  'release archive digest does not match signed metadata' 10 combined-test-ca
stop_fault_origin "$CANARY_VM"
assert_current "$CANARY_VM" "$ARCHIVE_A_SHA" tampered-archive

record_step "publish B and observe canary timer activate A to B"
publish_release "$CANARY_B2" "$ARCHIVE_B" "$CANARY_BRANCH" "canary-b2"
observe_timer_update canary-timer-a-to-b "$CANARY_VM" \
  cathedral-validator-canary-update.timer canary "$CANARY_B2" "$ARCHIVE_B_SHA"
capture_host_with_retries canary-after-timer-b "$CANARY_VM"

record_step "promote exact B archive and observe stable timer activate it"
publish_release "$STABLE_B2" "$ARCHIVE_B" "$STABLE_BRANCH" "stable-b2"
observe_timer_update stable-exact-promotion "$STABLE_VM" \
  cathedral-validator-update.timer stable "$STABLE_B2" "$ARCHIVE_B_SHA"
require_host_proof guided-status-after-timer-b "$STABLE_VM" \
  assert_guided_status guided-status-after-timer-b "$STABLE_VM" \
  "$ARCHIVE_B_SHA" 2 NOT_PROVEN true true
remote "$STABLE_VM" 'sudo systemctl disable --now cathedral-validator-update.timer'
capture_host_with_retries stable-after-timer-b "$STABLE_VM"

record_step "same B archive renewal advances signed sequence without restart"
pid_before="$(require_host_value same-archive-pid-before "$CANARY_VM" \
  main_pid "$CANARY_VM")"
invocation_before="$(require_host_value same-archive-invocation-before \
  "$CANARY_VM" main_invocation_id "$CANARY_VM")"
publish_release "$CANARY_B3" "$ARCHIVE_B" "$CANARY_BRANCH" "canary-b3-renewal"
observe_timer_update canary-same-archive-renewal "$CANARY_VM" \
  cathedral-validator-canary-update.timer canary "$CANARY_B3" "$ARCHIVE_B_SHA"
pid_after="$(require_host_value same-archive-pid-after "$CANARY_VM" \
  main_pid "$CANARY_VM")"
invocation_after="$(require_host_value same-archive-invocation-after \
  "$CANARY_VM" main_invocation_id "$CANARY_VM")"
observe_timer_reactivation canary-same-boot-reactivation "$CANARY_VM" \
  cathedral-validator-canary-update.timer canary "$CANARY_B3" "$ARCHIVE_B_SHA"
pid_after_reactivation="$(require_host_value same-boot-reactivation-pid-after \
  "$CANARY_VM" main_pid "$CANARY_VM")"
invocation_after_reactivation="$(require_host_value \
  same-boot-reactivation-invocation-after "$CANARY_VM" \
  main_invocation_id "$CANARY_VM")"
remote "$CANARY_VM" 'sudo systemctl disable --now cathedral-validator-canary-update.timer'
if ! [[ "$pid_before" == "$pid_after" && \
  "$pid_before" == "$pid_after_reactivation" && "$pid_before" != 0 && \
  -n "$invocation_before" && "$invocation_before" == "$invocation_after" && \
  "$invocation_before" == "$invocation_after_reactivation" ]]; then
  printf 'REFUSED: same-archive renewal or timer reactivation restarted the direct service\n' >&2
  capture_host_with_retries same-archive-renewal-pid-failure "$CANARY_VM" || true
  exit 1
fi

record_step "replay, equivocation, and metadata outage fail closed"
replay_url="$(pin_fault_pointer canary "$CANARY_B2" "replay sequence 2")"
expect_update_refused replay "$CANARY_VM" canary "$replay_url" \
  'release metadata rolls back the local channel'
equivocation_url="$(pin_fault_pointer canary "$CANARY_A_EQ3" "same sequence equivocation")"
expect_update_refused equivocation "$CANARY_VM" canary "$equivocation_url" \
  'release metadata equivocates at an existing sequence'
outage_url="${equivocation_url%/validator/canary.json}/validator/missing-${RUN_ID}.json"
wait_raw_missing "$outage_url"
expect_update_refused metadata-outage "$CANARY_VM" canary "$outage_url" \
  'HTTPS download failed'
assert_current "$CANARY_VM" "$ARCHIVE_B_SHA" signed-metadata-faults

record_step "pause blocks a valid newer release without changing B"
pause_url="$(pin_fault_pointer canary "$CANARY_A4" "valid paused sequence 4")"
pause_before="$(require_host_value pause-before "$CANARY_VM" \
  snapshot_state "$CANARY_VM" canary)"
pause_service_before="$(require_host_value pause-service-before "$CANARY_VM" \
  direct_service_identity "$CANARY_VM")"
printf '%s\n' "$pause_before" >"$EVIDENCE_DIR/pause-before.json"
printf '%s\n' "$pause_service_before" >"$EVIDENCE_DIR/pause-service-before.txt"
printf '%s\n' "$pause_before" | jq -e '.pending == null' >/dev/null
direct_service_identity_is_active "$pause_service_before"
remote "$CANARY_VM" 'sudo install -o root -g root -m 0600 /dev/null /etc/cathedral-validator/update.pause'
run_update "$CANARY_VM" canary "$pause_url" | tee "$EVIDENCE_DIR/pause.log"
grep -Fx 'CATHEDRAL_VALIDATOR_UPDATE_PAUSED' "$EVIDENCE_DIR/pause.log" >/dev/null
remote "$CANARY_VM" 'sudo rm /etc/cathedral-validator/update.pause'
pause_after="$(require_host_value pause-after "$CANARY_VM" \
  snapshot_state "$CANARY_VM" canary)"
pause_service_after="$(require_host_value pause-service-after "$CANARY_VM" \
  direct_service_identity "$CANARY_VM")"
printf '%s\n' "$pause_after" >"$EVIDENCE_DIR/pause-after.json"
printf '%s\n' "$pause_service_after" >"$EVIDENCE_DIR/pause-service-after.txt"
if [[ "$pause_before" != "$pause_after" || \
  "$pause_service_before" != "$pause_service_after" ]] || \
  ! direct_service_identity_is_active "$pause_service_after"; then
  printf 'REFUSED: pause changed updater state or the direct service\n' >&2
  capture_host_with_retries pause-state-failure "$CANARY_VM" || true
  exit 1
fi
assert_current "$CANARY_VM" "$ARCHIVE_B_SHA" pause

record_step "held cycle lock times out without activation"
  remote "$CANARY_VM" "sudo -u cathedral-validator sh -c 'nohup python3 -c \"import fcntl,time,pathlib; p=pathlib.Path(\\\"${JOURNAL%/*}/cycle.lock\\\"); f=p.open(\\\"r+\\\"); fcntl.flock(f,fcntl.LOCK_EX); pathlib.Path(\\\"/tmp/cathedral-cycle-held\\\").write_text(\\\"ready\\\"); time.sleep(120)\" >/tmp/cathedral-cycle-holder.log 2>&1 & echo \$! >/tmp/cathedral-cycle-holder.pid' && timeout 10 sh -c 'until test -f /tmp/cathedral-cycle-held; do sleep 0.2; done'"
expect_update_refused held-cycle "$CANARY_VM" canary "$pause_url" \
  'direct validator did not finish its cycle before timeout' 3
remote "$CANARY_VM" "set -eu; holder_pid=\"\$(cat /tmp/cathedral-cycle-holder.pid)\"; case \"\$holder_pid\" in ''|*[!0-9]*) exit 2;; esac; sudo kill \"\$holder_pid\"; holder_stopped=0; for attempt in \$(seq 1 30); do if ! sudo kill -0 \"\$holder_pid\" 2>/dev/null; then holder_stopped=1; break; fi; sleep 1; done; test \"\$holder_stopped\" = 1; sudo -u cathedral-validator python3 -c 'import fcntl,pathlib; p=pathlib.Path(\"${JOURNAL%/*}/cycle.lock\"); f=p.open(\"r+\"); fcntl.flock(f,fcntl.LOCK_EX | fcntl.LOCK_NB)' ; sudo rm -f /tmp/cathedral-cycle-holder.pid /tmp/cathedral-cycle-held"
assert_current "$CANARY_VM" "$ARCHIVE_B_SHA" held-cycle

record_step "unresolved writer journal blocks activation"
remote "$CANARY_VM" "sudo -u cathedral-validator python3 -c 'import json,pathlib; p=pathlib.Path(\"$JOURNAL\"); d=json.loads(p.read_text()); d[\"pending\"]={\"live_test\":\"unresolved\"}; p.write_text(json.dumps(d,separators=(\",\",\":\"))+\"\\n\")'"
expect_update_refused unresolved-journal "$CANARY_VM" canary "$pause_url" \
  'direct writer journal has an unresolved or ambiguous submission'
remote "$CANARY_VM" "sudo -u cathedral-validator python3 -c 'import json,pathlib; p=pathlib.Path(\"$JOURNAL\"); d=json.loads(p.read_text()); d[\"pending\"]=None; p.write_text(json.dumps(d,separators=(\",\",\":\"))+\"\\n\")'"
assert_current "$CANARY_VM" "$ARCHIVE_B_SHA" unresolved-journal

record_step "target-specific readiness failure rolls A back to B"
remote "$CANARY_VM" "printf '%s\n' fail | sudo tee /etc/cathedral-validator-live-test/fail-before-ready.${ARCHIVE_A_SHA} >/dev/null"
expect_update_refused readiness-rollback "$CANARY_VM" canary "$pause_url" \
  'new release failed readiness; prior release was restored' 10 system restarted
remote "$CANARY_VM" "sudo rm -f /etc/cathedral-validator-live-test/fail-before-ready.${ARCHIVE_A_SHA}"
assert_current "$CANARY_VM" "$ARCHIVE_B_SHA" readiness-rollback
remote "$CANARY_VM" "sudo systemctl is-active cathedral-validator-direct.service && sudo journalctl -u cathedral-validator-direct.service --no-pager | grep -F 'TEST_NO_CHAIN_TARGET_FAIL target=${ARCHIVE_A_SHA}' && sudo journalctl -u cathedral-validator-direct.service --no-pager | grep -F 'TEST_NO_CHAIN_READY target=${ARCHIVE_B_SHA}'"

wait_pending() {
  local label="$1"
  local host="$2"
  local target="$3"
  local transient_unit="$4"
  local started_at="$5"
  local deadline=$((SECONDS + CRASH_PENDING_WAIT_SECONDS))
  local absolute_deadline
  local snapshot
  if [[ ! "$started_at" =~ ^[0-9]+$ ]]; then
    printf 'REFUSED: pending wait requires a numeric updater start time host=%s\n' \
      "$host" >&2
    return 2
  fi
  absolute_deadline=$((
    started_at + TRANSIENT_UPDATE_TIMEOUT_SECONDS -
    CRASH_POST_PENDING_RESERVE_SECONDS - RESET_MINIMUM_HEADROOM_SECONDS
  ))
  if (( absolute_deadline < deadline )); then
    deadline=$absolute_deadline
  fi
  printf 'started_at=%s absolute_deadline=%s selected_deadline=%s post_pending_reserve=%s action_headroom=%s\n' \
    "$started_at" "$absolute_deadline" "$deadline" \
    "$CRASH_POST_PENDING_RESERVE_SECONDS" "$RESET_MINIMUM_HEADROOM_SECONDS" \
    >"$EVIDENCE_DIR/${label}-pending-deadline.txt"
  while (( SECONDS < deadline )); do
    if snapshot="$(snapshot_state "$host" stable 2>>"$EVIDENCE_DIR/${label}-pending-snapshot-ssh.stderr")"; then
      printf '%s\n' "$snapshot"
      if printf '%s\n' "$snapshot" | jq -e --arg target "releases/$target" \
        '.pending.stage == "may_have_run" and .pending.target_current == $target' >/dev/null; then
        if (( SECONDS < deadline )); then
          return 0
        fi
        printf 'REFUSED: exact pending state arrived after the reserved action deadline host=%s target=%s\n' \
          "$host" "$target" >&2
        break
      fi
    fi
    sleep 2
  done
  printf 'REFUSED: timed out waiting for exact pending updater state host=%s target=%s\n' \
    "$host" "$target" >&2
  capture_host_with_retries \
    "${label}-pending-wait-failure" "$host" "$transient_unit" || true
  return 1
}

assert_pending_pre_action() {
  local label="$1"
  local host="$2"
  local target="$3"
  local transient_unit="$4"
  local started_at="$5"
  local expected_boot_id="${6:-}"
  local elapsed
  local remaining
  local attempt
  local read_status
  local snapshot
  local unit_state
  local observed_boot_id
  if [[ ! "$transient_unit" =~ ^[A-Za-z0-9_.@-]+$ ]]; then
    printf 'REFUSED: unsafe transient systemd unit at pre-action gate: %s\n' \
      "$transient_unit" >&2
    return 2
  fi
  if [[ -n "$expected_boot_id" ]]; then
    if expected_boot_id="$(canonical_boot_id "$expected_boot_id")"; then
      :
    else
      printf 'REFUSED: invalid expected boot ID at pre-action gate host=%s\n' \
        "$host" >&2
      return 2
    fi
  fi
  for attempt in $(seq 1 "$PRE_ACTION_READ_ATTEMPTS"); do
    if snapshot="$(snapshot_state "$host" stable 2>>"$EVIDENCE_DIR/${label}-state-ssh.stderr")"; then
      printf '%s\n' "$snapshot" >"$EVIDENCE_DIR/${label}-state.json"
      if ! printf '%s\n' "$snapshot" | jq -e --arg target "releases/$target" \
        '.current == $target and .pending.stage == "may_have_run" and .pending.target_current == $target' >/dev/null; then
        printf 'REFUSED: pending crash boundary changed before action host=%s target=%s\n' \
          "$host" "$target" >&2
        capture_host_with_retries "${label}-state-failure" \
          "$host" "$transient_unit" || true
        return 1
      fi
    else
      read_status=$?
      printf 'attempt=%s source=state status=%s\n' "$attempt" "$read_status" \
        >>"$EVIDENCE_DIR/${label}-read-retries.log"
      if (( attempt < PRE_ACTION_READ_ATTEMPTS )); then
        sleep "$PRE_ACTION_RETRY_INTERVAL_SECONDS"
      fi
      continue
    fi
    if unit_state="$(remote "$host" "sudo systemctl show '${transient_unit}.service' -p ActiveState -p SubState -p MainPID; printf 'BootID=%s\n' \"\$(cat /proc/sys/kernel/random/boot_id)\"; printf '%s\n' '--- transient updater journal before action ---'; sudo journalctl -u '${transient_unit}.service' -b -n 80 --no-pager" 2>>"$EVIDENCE_DIR/${label}-unit-ssh.stderr")"; then
      printf '%s\n' "$unit_state" >"$EVIDENCE_DIR/${label}-unit.txt"
      if ! printf '%s\n' "$unit_state" | grep -Fx 'ActiveState=active' >/dev/null || \
        ! printf '%s\n' "$unit_state" | grep -Fx 'SubState=running' >/dev/null || \
        ! printf '%s\n' "$unit_state" | grep -Eq '^MainPID=[1-9][0-9]*$'; then
        printf 'REFUSED: transient updater is no longer active at crash boundary host=%s unit=%s\n' \
          "$host" "$transient_unit" >&2
        capture_host_with_retries "${label}-unit-failure" \
          "$host" "$transient_unit" || true
        return 1
      fi
      observed_boot_id="$(printf '%s\n' "$unit_state" | sed -n 's/^BootID=//p')"
      if observed_boot_id="$(canonical_boot_id "$observed_boot_id")"; then
        :
      else
        printf 'REFUSED: transient updater boot ID is invalid before action host=%s\n' \
          "$host" >&2
        capture_host_with_retries "${label}-boot-id-failure" \
          "$host" "$transient_unit" || true
        return 1
      fi
      if [[ -n "$expected_boot_id" && "$observed_boot_id" != "$expected_boot_id" ]]; then
        printf 'REFUSED: host rebooted during pending crash preparation host=%s\n' \
          "$host" >&2
        capture_host_with_retries "${label}-boot-id-changed" \
          "$host" "$transient_unit" || true
        return 1
      fi
    else
      read_status=$?
      printf 'attempt=%s source=unit status=%s\n' "$attempt" "$read_status" \
        >>"$EVIDENCE_DIR/${label}-read-retries.log"
      if (( attempt < PRE_ACTION_READ_ATTEMPTS )); then
        sleep "$PRE_ACTION_RETRY_INTERVAL_SECONDS"
      fi
      continue
    fi
    if [[ "$started_at" =~ ^[0-9]+$ ]]; then
      elapsed=$((SECONDS - started_at))
      remaining=$((TRANSIENT_UPDATE_TIMEOUT_SECONDS - elapsed))
      printf 'started_at=%s elapsed=%s remaining=%s required_headroom=%s\n' \
        "$started_at" "$elapsed" "$remaining" \
        "$RESET_MINIMUM_HEADROOM_SECONDS" \
        >"$EVIDENCE_DIR/${label}-headroom.txt"
      if (( remaining >= RESET_MINIMUM_HEADROOM_SECONDS )); then
        return 0
      fi
    fi
    printf 'REFUSED: insufficient updater deadline headroom before crash action host=%s\n' \
      "$host" >&2
    capture_host_with_retries "${label}-headroom-failure" \
      "$host" "$transient_unit" || true
    return 1
  done
  printf 'REFUSED: pre-action state could not be read after transport retries host=%s unit=%s\n' \
    "$host" "$transient_unit" >&2
  capture_host_with_retries "${label}-transport-failure" \
    "$host" "$transient_unit" || true
  return 1
}

launch_background_update() {
  local host="$1"
  local unit="$2"
  local channel="$3"
  local url="$4"
  remote "$host" "sudo systemd-run --unit='$unit' --collect --property=RuntimeMaxSec='${TRANSIENT_SYSTEMD_TIMEOUT_SECONDS}s' /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update --channel='$channel' --metadata-url='$url' --public-key=/etc/cathedral-validator/runtime-release-public-key.pem --identity-file=/etc/cathedral-validator/identity.env --minimum-sequence=1 --cycle-wait-seconds=10 --operation-timeout-seconds='$TRANSIENT_UPDATE_TIMEOUT_SECONDS'"
}

crash_pending_transient_for_rescue() {
  local label="$1"
  local host="$2"
  local target="$3"
  local transient_unit="$4"
  local failure_status
  if [[ ! "$transient_unit" =~ ^[A-Za-z0-9_.@-]+$ ]]; then
    printf 'REFUSED: unsafe transient systemd unit at rescue crash gate: %s\n' \
      "$transient_unit" >&2
    return 2
  fi
  if remote "$host" "set -eu
expected='releases/$target'
current=\"\$(sudo readlink /opt/cathedral-validator/current)\"
printf 'current=%s\\n' \"\$current\"
test \"\$current\" = \"\$expected\"
sudo jq -e --arg target \"\$expected\" '.pending.stage == \"may_have_run\" and .pending.target_current == \$target' /var/lib/cathedral-validator-update/state.json
unit_state=\"\$(sudo systemctl show '${transient_unit}.service' -p ActiveState -p SubState -p MainPID)\"
printf '%s\\n' \"\$unit_state\"
printf '%s\\n' \"\$unit_state\" | grep -Fx 'ActiveState=active' >/dev/null
printf '%s\\n' \"\$unit_state\" | grep -Fx 'SubState=running' >/dev/null
printf '%s\\n' \"\$unit_state\" | grep -Eq '^MainPID=[1-9][0-9]*$'
main_pid=\"\$(printf '%s\\n' \"\$unit_state\" | sed -n 's/^MainPID=//p')\"
sudo kill -0 \"\$main_pid\"
sudo systemctl kill --kill-whom=main --signal=KILL '${transient_unit}.service'
printf 'TRANSIENT_UPDATER_KILL_ISSUED unit=%s pid=%s\\n' '${transient_unit}.service' \"\$main_pid\"
killed=0
for attempt in \$(seq 1 30); do
  if ! sudo kill -0 \"\$main_pid\" 2>/dev/null && ! sudo systemctl is-active --quiet '${transient_unit}.service'; then
    killed=1
    break
  fi
  sleep 1
done
test \"\$killed\" = 1
test \"\$(sudo readlink /opt/cathedral-validator/current)\" = \"\$expected\"
sudo jq -e --arg target \"\$expected\" '.pending.stage == \"may_have_run\" and .pending.target_current == \$target' /var/lib/cathedral-validator-update/state.json
printf 'TRANSIENT_UPDATER_KILL_CONFIRMED unit=%s pid=%s\\n' '${transient_unit}.service' \"\$main_pid\"
sudo systemctl stop cathedral-validator-direct.service
sudo rm -f /etc/cathedral-validator-live-test/delay-before-ready.${target}
printf '%s\\n' fail | sudo tee /etc/cathedral-validator-live-test/fail-before-ready.${target} >/dev/null" 2>&1 | tee "$EVIDENCE_DIR/${label}-command.log"; then
    return 0
  else
    failure_status=$?
    capture_host_with_retries "${label}-failure" "$host" "$transient_unit" || true
    return "$failure_status"
  fi
}

record_step "reset at durable may_have_run and reconcile exact A on boot"
reset_url="$(pin_fault_pointer stable "$STABLE_A3" "stable reset target A sequence 3")"
remote "$STABLE_VM" "printf '%s\n' '$READINESS_DELAY_MAX_SECONDS' | sudo tee /etc/cathedral-validator-live-test/delay-before-ready.${ARCHIVE_A_SHA} >/dev/null"
reset_boot_id="$(require_host_value stable-reset-boot-id-before "$STABLE_VM" \
  read_boot_id "$STABLE_VM")"
reset_started_at=$SECONDS
launch_background_update "$STABLE_VM" "cathedral-live-reset-${RUN_ID}" stable "$reset_url"
wait_pending stable-reset "$STABLE_VM" "$ARCHIVE_A_SHA" \
  "cathedral-live-reset-${RUN_ID}" "$reset_started_at"
assert_pending_pre_action stable-reset-pre-action "$STABLE_VM" \
  "$ARCHIVE_A_SHA" "cathedral-live-reset-${RUN_ID}" "$reset_started_at" \
  "$reset_boot_id"
require_host_proof stable-reset-request "$STABLE_VM" \
  request_instance_reset "$STABLE_VM"
require_host_proof stable-reset-reboot-observed "$STABLE_VM" \
  wait_boot_id_changed stable-reset "$STABLE_VM" "$reset_boot_id"
require_host_proof stable-reset-delay-clear "$STABLE_VM" \
  remote "$STABLE_VM" \
  "sudo rm -f /etc/cathedral-validator-live-test/delay-before-ready.${ARCHIVE_A_SHA}"
require_host_proof stable-reset-direct-auto-start "$STABLE_VM" \
  wait_direct_service_active stable-reset "$STABLE_VM"
require_host_proof stable-reset-reconcile-proof "$STABLE_VM" \
  remote "$STABLE_VM" \
  "sudo systemctl is-enabled --quiet cathedral-validator-direct.service && sudo systemctl is-active --quiet cathedral-validator-direct.service && test \"\$(sudo systemctl show cathedral-validator-boot-reconcile.service -p Result --value)\" = success && sudo journalctl -b -u cathedral-validator-boot-reconcile.service -n 80 --no-pager | grep CATHEDRAL_VALIDATOR_UPDATE_RECONCILED"
wait_sequence stable-reset-reconcile "$STABLE_VM" stable "$STABLE_A3"
assert_current "$STABLE_VM" "$ARCHIVE_A_SHA" reset-may-have-run
capture_host_with_retries stable-after-reset "$STABLE_VM"

record_step "leave B crash-uncertain, then rescue with higher signed A sequence"
uncertain_url="$(pin_fault_pointer stable "$STABLE_B4" "stable uncertain target B sequence 4")"
remote "$STABLE_VM" "printf '%s\n' '$READINESS_DELAY_MAX_SECONDS' | sudo tee /etc/cathedral-validator-live-test/delay-before-ready.${ARCHIVE_B_SHA} >/dev/null"
rescue_started_at=$SECONDS
launch_background_update "$STABLE_VM" "cathedral-live-rescue-${RUN_ID}" stable "$uncertain_url"
wait_pending stable-rescue "$STABLE_VM" "$ARCHIVE_B_SHA" \
  "cathedral-live-rescue-${RUN_ID}" "$rescue_started_at"
assert_pending_pre_action stable-rescue-pre-action "$STABLE_VM" \
  "$ARCHIVE_B_SHA" "cathedral-live-rescue-${RUN_ID}" "$rescue_started_at"
crash_pending_transient_for_rescue stable-rescue-crash "$STABLE_VM" \
  "$ARCHIVE_B_SHA" "cathedral-live-rescue-${RUN_ID}"
capture_host_with_retries stable-after-rescue-crash "$STABLE_VM" \
  "cathedral-live-rescue-${RUN_ID}"
rescue_url="$(pin_fault_pointer stable "$STABLE_A5" "stable higher sequence rescue A sequence 5")"
require_host_proof higher-sequence-rescue-update "$STABLE_VM" \
  run_update "$STABLE_VM" stable "$rescue_url"
require_host_proof stable-rescue-marker-clear "$STABLE_VM" \
  remote "$STABLE_VM" \
  "sudo rm -f /etc/cathedral-validator-live-test/fail-before-ready.${ARCHIVE_B_SHA}"
require_host_proof higher-sequence-rescue-activation "$STABLE_VM" \
  grep -q 'CATHEDRAL_VALIDATOR_UPDATE_ACTIVATED' \
  "$EVIDENCE_DIR/higher-sequence-rescue-update-command.log"
wait_sequence stable-higher-sequence-rescue "$STABLE_VM" stable "$STABLE_A5"
assert_current "$STABLE_VM" "$ARCHIVE_A_SHA" higher-sequence-rescue
require_host_proof higher-sequence-rescue-service "$STABLE_VM" \
  remote "$STABLE_VM" \
  'sudo systemctl is-active cathedral-validator-direct.service'

record_step "guided setup rerun refuses the stopped writer and status reports review"
require_host_proof guided-setup-stopped-writer "$STABLE_VM" \
  prove_guided_setup_refuses_stopped_writer "$STABLE_VM"

assert_project_metadata_unchanged final
assert_instance_metadata_unchanged "$CANARY_VM" canary final
assert_instance_metadata_unchanged "$STABLE_VM" stable final
capture_host_with_retries final-canary "$CANARY_VM"
capture_host_with_retries final-stable "$STABLE_VM"
gc compute instances list \
  --filter="labels.cathedral-live-run=${RUN_ID}" \
  --format=json >"$EVIDENCE_DIR/pre-teardown-instances.json"
gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/heads/${CANARY_BRANCH}" >"$EVIDENCE_DIR/canary-branch.json"
gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/heads/${STABLE_BRANCH}" >"$EVIDENCE_DIR/stable-branch.json"
gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/heads/${FAULT_BRANCH}" >"$EVIDENCE_DIR/fault-branch.json"

record_step "SCENARIOS_PASS_PENDING_TEARDOWN all bounded no-chain updater scenarios"
