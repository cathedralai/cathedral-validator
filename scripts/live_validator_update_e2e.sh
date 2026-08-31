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
readonly FIXED_CHANNEL_WAIT_SECONDS=420
readonly IMAGE_PROJECT="ubuntu-os-cloud"
readonly IMAGE_FAMILY="ubuntu-2404-lts-amd64"
REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly HARNESS_SOURCE="$REPOSITORY_ROOT/tests/live/cathedral_no_chain_readiness.py"
readonly FAULT_ORIGIN_SOURCE="$REPOSITORY_ROOT/tests/live/tampered_https_origin.py"
readonly STATE_WAITER_SOURCE="$REPOSITORY_ROOT/tests/live/wait_updater_state.py"
readonly SIGNER="$REPOSITORY_ROOT/deploy/validator-update/build_signed_release.py"
readonly PUBLISHER="$REPOSITORY_ROOT/deploy/validator-update/publish_github_channel.py"
readonly BOOTSTRAP_BUILDER="$REPOSITORY_ROOT/deploy/validator-update/build_updater_bundle.py"
readonly BOOTSTRAP_PUBLISHER="$REPOSITORY_ROOT/deploy/validator-update/publish_github_bootstrap.py"

if (( FIXED_CHANNEL_WAIT_SECONDS <= FIXED_CHANNEL_CACHE_MAX_SECONDS + UPDATE_TIMER_INTERVAL_SECONDS )); then
  printf 'REFUSED: fixed-channel wait must exceed cache maximum plus timer interval\n' >&2
  exit 2
fi

MODE="${1:-}"
if [[ "$MODE" != "--preflight" && "$MODE" != "--execute" ]]; then
  printf 'usage: %s --preflight|--execute\n' "$0" >&2
  printf 'required: TEST_GITHUB_REPOSITORY=public-owner/test-mirror plus run, candidate, revision, CIDR, and evidence variables\n' >&2
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
  RUN_ID CONTROLLER_CIDR CANDIDATE_A_DIR CANDIDATE_B_DIR \
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
TEST_HOTKEY="LiveTestHotkey$(printf '%s' "$RUN_ID" | shasum -a 256 | cut -c1-20)"
readonly TEST_HOTKEY
readonly JOURNAL="/var/lib/cathedral-validator/.local/state/cathedral-validator/direct-writer/finney-sn39-mechanism-0/${TEST_HOTKEY}/state.json"
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

python3 - "$CONTROLLER_CIDR" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=True)
if network.version != 4 or network.prefixlen != 32:
    raise SystemExit("REFUSED: CONTROLLER_CIDR must be one exact public IPv4 /32")
if not network.network_address.is_global:
    raise SystemExit("REFUSED: CONTROLLER_CIDR must be globally routable")
PY

for command in awk basename cmp cut find gcloud gh git grep jq openssl python3 sed seq shasum ssh-keygen tee; do
  command -v "$command" >/dev/null || {
    printf 'REFUSED: required command is missing: %s\n' "$command" >&2
    exit 2
  }
done
if ! python3 -c 'import cryptography' >/dev/null 2>&1; then
  printf 'REFUSED: controller Python cannot import cryptography\n' >&2
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
  exit 0
fi

mkdir -p "$EVIDENCE_DIR"
if [[ -n "$(find "$EVIDENCE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  printf 'REFUSED: EVIDENCE_DIR must be empty for an unambiguous run\n' >&2
  exit 2
fi
chmod 0700 "$EVIDENCE_DIR"

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

CREATED_CANARY_VM=0
CREATED_STABLE_VM=0
CREATED_FIREWALL=0
CREATED_SUBNET=0
CREATED_NETWORK=0

cleanup() {
  local status=$?
  local teardown_ok=1
  local final_status
  trap - EXIT INT TERM
  set +e
  if [[ "$CREATED_CANARY_VM" == 1 ]]; then
    gc compute instances delete "$CANARY_VM" --zone="$ZONE" \
      >"$EVIDENCE_DIR/delete-canary-vm.log" 2>&1 || true
  fi
  if [[ "$CREATED_STABLE_VM" == 1 ]]; then
    gc compute instances delete "$STABLE_VM" --zone="$ZONE" \
      >"$EVIDENCE_DIR/delete-stable-vm.log" 2>&1 || true
  fi
  if [[ "$CREATED_CANARY_VM" == 1 ]]; then
    gc compute disks delete "$CANARY_VM" --zone="$ZONE" \
      >"$EVIDENCE_DIR/delete-canary-disk.log" 2>&1 || true
  fi
  if [[ "$CREATED_STABLE_VM" == 1 ]]; then
    gc compute disks delete "$STABLE_VM" --zone="$ZONE" \
      >"$EVIDENCE_DIR/delete-stable-disk.log" 2>&1 || true
  fi
  if [[ "$CREATED_FIREWALL" == 1 ]]; then
    gc compute firewall-rules delete "$FIREWALL" \
      >"$EVIDENCE_DIR/delete-firewall.log" 2>&1 || true
  fi
  if [[ "$CREATED_SUBNET" == 1 ]]; then
    gc compute networks subnets delete "$SUBNET" --region="$REGION" \
      >"$EVIDENCE_DIR/delete-subnet.log" 2>&1 || true
  fi
  if [[ "$CREATED_NETWORK" == 1 ]]; then
    gc compute networks delete "$NETWORK" \
      >"$EVIDENCE_DIR/delete-network.log" 2>&1 || true
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
  --assets-dir "$REPOSITORY_ROOT/deploy/validator-update" \
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
  --action=ALLOW --rules=tcp:22 --source-ranges="$CONTROLLER_CIDR" \
  --target-tags="$INSTANCE_TAG" \
  --description="Cathedral updater live test ${RUN_ID}; exact controller SSH only"; then
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
  --arg cidr "$CONTROLLER_CIDR" \
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
    --plain \
    --ssh-key-file="$SSH_PRIVATE_KEY" \
    --ssh-flag="-i${SSH_PRIVATE_KEY}" \
    --ssh-flag='-o IdentitiesOnly=yes' \
    --ssh-flag='-o ConnectTimeout=10' \
    --ssh-flag='-o StrictHostKeyChecking=accept-new' \
    --ssh-flag="-o UserKnownHostsFile=${SSH_KNOWN_HOSTS}" \
    --command="$*"
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

wait_ssh "$CANARY_VM"
wait_ssh "$STABLE_VM"
assert_project_metadata_unchanged after-first-ssh
assert_instance_metadata_unchanged "$CANARY_VM" canary after-first-ssh
assert_instance_metadata_unchanged "$STABLE_VM" stable after-first-ssh

stage_host_files() {
  local host="$1"
  gc compute scp --zone="$ZONE" \
    --plain \
    --ssh-key-file="$SSH_PRIVATE_KEY" \
    --scp-flag="-i${SSH_PRIVATE_KEY}" \
    --scp-flag='-o IdentitiesOnly=yes' \
    --scp-flag="-o UserKnownHostsFile=${SSH_KNOWN_HOSTS}" \
    --scp-flag='-o StrictHostKeyChecking=accept-new' \
    "$HARNESS_SOURCE" \
    "$FAULT_ORIGIN_SOURCE" \
    "$STATE_WAITER_SOURCE" \
    "${SSH_USER}@${host}:/tmp/"
}

stage_host_files "$CANARY_VM"
stage_host_files "$STABLE_VM"
assert_project_metadata_unchanged after-scp
assert_instance_metadata_unchanged "$CANARY_VM" canary after-scp
assert_instance_metadata_unchanged "$STABLE_VM" stable after-scp

configure_host() {
  local host="$1"
  local channel="$2"
  local timer="$3"
  local other_timer="$4"
  remote "$host" "sudo env DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null && sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl jq openssl python3.12 python3.12-venv python3-cryptography >/dev/null"
  remote "$host" "sudo install -d -o root -g root -m 0700 /var/tmp/cathedral-live-${RUN_ID} && sudo env -i PATH=/usr/bin:/bin HOME=/var/empty /usr/bin/curl --disable --fail --show-error --silent --location --proto '=https' --tlsv1.2 --header 'Authorization:' --output /var/tmp/cathedral-live-${RUN_ID}/bundle.tar.gz '$BOOTSTRAP_BUNDLE_URL' && printf '%s\n' ANONYMOUS_BOOTSTRAP_DOWNLOADED:bundle && sudo env -i PATH=/usr/bin:/bin HOME=/var/empty /usr/bin/curl --disable --fail --show-error --silent --location --proto '=https' --tlsv1.2 --header 'Authorization:' --output /var/tmp/cathedral-live-${RUN_ID}/manifest.json '$BOOTSTRAP_MANIFEST_URL' && printf '%s\n' ANONYMOUS_BOOTSTRAP_DOWNLOADED:manifest && sudo env -i PATH=/usr/bin:/bin HOME=/var/empty /usr/bin/curl --disable --fail --show-error --silent --location --proto '=https' --tlsv1.2 --header 'Authorization:' --output /var/tmp/cathedral-live-${RUN_ID}/manifest.sig '$BOOTSTRAP_SIGNATURE_URL' && printf '%s\n' ANONYMOUS_BOOTSTRAP_DOWNLOADED:signature && sudo env -i PATH=/usr/bin:/bin HOME=/var/empty /usr/bin/curl --disable --fail --show-error --silent --location --proto '=https' --tlsv1.2 --header 'Authorization:' --output /var/tmp/cathedral-live-${RUN_ID}/bootstrap-public.pem '$BOOTSTRAP_PUBLIC_KEY_URL' && printf '%s\n' ANONYMOUS_BOOTSTRAP_DOWNLOADED:public_key && sudo chmod 0400 /var/tmp/cathedral-live-${RUN_ID}/bundle.tar.gz /var/tmp/cathedral-live-${RUN_ID}/manifest.json /var/tmp/cathedral-live-${RUN_ID}/manifest.sig && sudo chmod 0444 /var/tmp/cathedral-live-${RUN_ID}/bootstrap-public.pem && sudo /usr/bin/python3 -c 'import hashlib,pathlib; expected={\"bundle.tar.gz\":\"$BOOTSTRAP_BUNDLE_SHA\",\"manifest.json\":\"$BOOTSTRAP_MANIFEST_SHA\",\"manifest.sig\":\"$BOOTSTRAP_SIGNATURE_SHA\",\"bootstrap-public.pem\":\"$BOOTSTRAP_PUBLIC_KEY_SHA\"}; root=pathlib.Path(\"/var/tmp/cathedral-live-${RUN_ID}\"); assert all(hashlib.sha256((root/name).read_bytes()).hexdigest()==digest for name,digest in expected.items())' && printf '%s\n' ANONYMOUS_BOOTSTRAP_EXACT_BYTES_VERIFIED && sudo openssl pkeyutl -verify -pubin -inkey /var/tmp/cathedral-live-${RUN_ID}/bootstrap-public.pem -rawin -in /var/tmp/cathedral-live-${RUN_ID}/manifest.json -sigfile /var/tmp/cathedral-live-${RUN_ID}/manifest.sig && test \"sha256:\$(sudo openssl pkey -pubin -in /var/tmp/cathedral-live-${RUN_ID}/bootstrap-public.pem -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)\" = '$BOOTSTRAP_FINGERPRINT' && sudo /usr/bin/python3 -c 'import hashlib,json,pathlib; b=pathlib.Path(\"/var/tmp/cathedral-live-${RUN_ID}/bundle.tar.gz\").read_bytes(); m=json.loads(pathlib.Path(\"/var/tmp/cathedral-live-${RUN_ID}/manifest.json\").read_text(encoding=\"ascii\")); assert len(b)==m[\"bundle\"][\"size\"] and hashlib.sha256(b).hexdigest()==m[\"bundle\"][\"sha256\"]; assert m[\"bootstrap_signing_key\"][\"fingerprint\"]==\"$BOOTSTRAP_FINGERPRINT\"; assert m[\"bootstrap_metadata\"][\"sequence\"]>=1' && sudo sh -c 'tar -xOf /var/tmp/cathedral-live-${RUN_ID}/bundle.tar.gz payload/installer/install_updater_bundle.py > /var/tmp/cathedral-live-${RUN_ID}/signed-installer.py' && sudo chmod 0400 /var/tmp/cathedral-live-${RUN_ID}/signed-installer.py && sudo /usr/bin/python3.12 /var/tmp/cathedral-live-${RUN_ID}/signed-installer.py --bundle /var/tmp/cathedral-live-${RUN_ID}/bundle.tar.gz --manifest /var/tmp/cathedral-live-${RUN_ID}/manifest.json --signature /var/tmp/cathedral-live-${RUN_ID}/manifest.sig --bootstrap-public-key /var/tmp/cathedral-live-${RUN_ID}/bootstrap-public.pem --expected-bootstrap-key-fingerprint '$BOOTSTRAP_FINGERPRINT' --minimum-bootstrap-sequence '$BOOTSTRAP_SEQUENCE'" | tee "$EVIDENCE_DIR/bootstrap-install-${host}.log"
  remote "$host" "test \"\$(sha256sum /tmp/cathedral_no_chain_readiness.py | cut -d' ' -f1)\" = '$HARNESS_SHA' && test \"\$(sha256sum /tmp/tampered_https_origin.py | cut -d' ' -f1)\" = '$FAULT_ORIGIN_SHA' && test \"\$(sha256sum /tmp/wait_updater_state.py | cut -d' ' -f1)\" = '$STATE_WAITER_SHA' && sudo install -d -o root -g root -m 0755 /usr/local/libexec /etc/cathedral-validator-live-test /etc/systemd/system/cathedral-validator-direct.service.d /etc/systemd/system/${timer}.d /etc/systemd/system/${other_timer}.d && sudo install -o root -g root -m 0555 /tmp/cathedral_no_chain_readiness.py /usr/local/libexec/cathedral-no-chain-readiness.py && sudo install -o root -g root -m 0555 /tmp/tampered_https_origin.py /usr/local/libexec/cathedral-tampered-https-origin.py && sudo install -o root -g root -m 0555 /tmp/wait_updater_state.py /usr/local/libexec/cathedral-wait-updater-state.py && printf '%s\n' 'CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY=$TEST_HOTKEY' | sudo tee /etc/cathedral-validator/identity.env >/dev/null && printf '%s\n' 'CATHEDRAL_SNP_POLICY=/etc/cathedral-validator/snp-policy.json' 'CATHEDRAL_VALIDATOR_INTERVAL_SECONDS=86400' | sudo tee /etc/cathedral-validator/direct.env >/dev/null && printf '%s\n' 'CATHEDRAL_VALIDATOR_CANARY_METADATA_URL=$CANARY_URL' 'CATHEDRAL_VALIDATOR_STABLE_METADATA_URL=$STABLE_URL' 'CATHEDRAL_VALIDATOR_CANARY_MINIMUM_SEQUENCE=1' 'CATHEDRAL_VALIDATOR_STABLE_MINIMUM_SEQUENCE=1' | sudo tee /etc/cathedral-validator/update.env >/dev/null && printf '%s\n' '{\"schema\":\"cathedral_amd_sev_snp_policy_v1\",\"generations\":{\"genoa\":{\"allowed_measurements\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"],\"minimum_tcb\":\"0x0000000000000001\"}}}' | sudo tee /etc/cathedral-validator/snp-policy.json >/dev/null && sudo install -o root -g root -m 0600 /dev/null /etc/cathedral-validator/validator-hotkey && sudo chmod 0600 /etc/cathedral-validator/identity.env /etc/cathedral-validator/direct.env /etc/cathedral-validator/update.env && sudo chown root:cathedral-validator /etc/cathedral-validator/snp-policy.json && sudo chmod 0440 /etc/cathedral-validator/snp-policy.json"
  remote "$host" "sudo systemctl disable --now '$other_timer' && printf '%s\n' '[Service]' 'Environment=PEX_INTERPRETER=1' 'LoadCredential=' 'ExecStartPre=' 'ExecStart=' 'ExecStart=/opt/cathedral-validator/current/bin/cathedral-validator /usr/local/libexec/cathedral-no-chain-readiness.py' 'Restart=no' 'TimeoutStartSec=180s' 'TimeoutStopSec=10s' 'RestrictAddressFamilies=' 'RestrictAddressFamilies=AF_UNIX' 'IPAddressDeny=any' 'PrivateNetwork=true' | sudo tee /etc/systemd/system/cathedral-validator-direct.service.d/no-chain-live-test.conf >/dev/null && printf '%s\n' '[Timer]' 'OnBootSec=' 'OnBootSec=20s' 'OnUnitActiveSec=' 'OnUnitActiveSec=${UPDATE_TIMER_INTERVAL_SECONDS}s' 'RandomizedDelaySec=0' 'Persistent=true' | sudo tee /etc/systemd/system/${timer}.d/live-test.conf >/dev/null && printf '%s\n' '[Unit]' 'ConditionPathExists=/run/cathedral-live-${RUN_ID}-permit-${other_timer}' | sudo tee /etc/systemd/system/${other_timer}.d/deny-live-test.conf >/dev/null && test ! -e '/run/cathedral-live-${RUN_ID}-permit-${other_timer}' && sudo systemctl daemon-reload && test \"\$(sudo systemctl show '$timer' -p UnitFileState --value)\" = disabled && test \"\$(sudo systemctl show '$timer' -p ActiveState --value)\" = inactive && test \"\$(sudo systemctl show '$other_timer' -p UnitFileState --value)\" = disabled && sudo systemctl cat '$other_timer' | grep -Fx 'ConditionPathExists=/run/cathedral-live-${RUN_ID}-permit-${other_timer}' >/dev/null && sudo systemctl start '$other_timer' && other_timer_state=\"\$(sudo systemctl show '$other_timer' -p ActiveState -p SubState -p ConditionResult)\" && printf '%s\n' \"\$other_timer_state\" | grep -Fx 'ActiveState=inactive' >/dev/null && printf '%s\n' \"\$other_timer_state\" | grep -Fx 'SubState=dead' >/dev/null && ! sudo systemctl is-active --quiet '$other_timer' && sudo systemctl enable cathedral-validator-direct.service"
  if [[ "$channel" == "canary" ]]; then
    remote "$host" "sudo /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update --bootstrap-first-install --channel=canary --metadata-url='$CANARY_URL' --public-key=/etc/cathedral-validator/runtime-release-public-key.pem --identity-file=/etc/cathedral-validator/identity.env --minimum-sequence=1 --cycle-wait-seconds=10 --operation-timeout-seconds=180"
  else
    remote "$host" "sudo /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update --bootstrap-first-install --channel=stable --metadata-url='$STABLE_URL' --public-key=/etc/cathedral-validator/runtime-release-public-key.pem --identity-file=/etc/cathedral-validator/identity.env --minimum-sequence=1 --cycle-wait-seconds=10 --operation-timeout-seconds=180"
  fi
  remote "$host" "sudo systemctl is-active cathedral-validator-direct.service && sudo journalctl -u cathedral-validator-direct.service -n 80 --no-pager | grep 'TEST_NO_CHAIN_READY target=$ARCHIVE_A_SHA'"
}

record_step "first install A through signed bootstrap and no-chain systemd readiness"
configure_host "$CANARY_VM" canary cathedral-validator-canary-update.timer cathedral-validator-update.timer
configure_host "$STABLE_VM" stable cathedral-validator-update.timer cathedral-validator-canary-update.timer

capture_host() {
  local label="$1"
  local host="$2"
  remote "$host" "printf '%s\n' '--- current ---'; sudo readlink /opt/cathedral-validator/current; printf '%s\n' '--- updater state ---'; sudo cat /var/lib/cathedral-validator-update/state.json; printf '%s\n' '--- direct unit ---'; sudo systemctl show cathedral-validator-direct.service -p ActiveState -p SubState -p MainPID -p FragmentPath -p DropInPaths -p RestrictAddressFamilies -p IPAddressDeny; sudo systemctl cat cathedral-validator-direct.service; printf '%s\n' '--- timers ---'; sudo systemctl show cathedral-validator-canary-update.timer cathedral-validator-update.timer -p Id -p UnitFileState -p ActiveState -p SubState -p ConditionResult -p DropInPaths; sudo systemctl list-timers --all --no-pager 'cathedral-validator*update.timer'; printf '%s\n' '--- updater logs ---'; sudo journalctl -u cathedral-validator-update.service -u cathedral-validator-canary-update.service -n 120 --no-pager; printf '%s\n' '--- direct logs ---'; sudo journalctl -u cathedral-validator-direct.service -n 120 --no-pager" >"$EVIDENCE_DIR/${label}.txt"
}

current_digest() {
  remote "$1" 'sudo readlink /opt/cathedral-validator/current' | awk -F/ '{print $2}' | tr -d '\r'
}

main_pid() {
  remote "$1" 'sudo systemctl show cathedral-validator-direct.service -p MainPID --value' | tr -d '\r'
}

wait_sequence() {
  local host="$1"
  local channel="$2"
  local sequence="$3"
  remote "$host" "sudo /usr/bin/python3 /usr/local/libexec/cathedral-wait-updater-state.py --state /var/lib/cathedral-validator-update/state.json --timeout-seconds '$FIXED_CHANNEL_WAIT_SECONDS' --committed '$channel' '$sequence'"
}

start_update_timer() {
  local host="$1"
  local timer="$2"
  remote "$host" "sudo systemctl enable --now '$timer' && sudo systemctl restart '$timer' && selected_timer_state=\"\$(sudo systemctl show '$timer' -p ActiveState -p SubState -p ConditionResult)\" && printf '%s\n' \"\$selected_timer_state\" | grep -Fx 'ActiveState=active' >/dev/null && printf '%s\n' \"\$selected_timer_state\" | grep -Fx 'ConditionResult=yes' >/dev/null && printf '%s\n' \"\$selected_timer_state\" | grep -Eq '^SubState=(waiting|running)$'"
}

run_update() {
  local host="$1"
  local channel="$2"
  local url="$3"
  local cycle_wait="${4:-10}"
  remote "$host" "sudo /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update --channel='$channel' --metadata-url='$url' --public-key=/etc/cathedral-validator/runtime-release-public-key.pem --identity-file=/etc/cathedral-validator/identity.env --minimum-sequence=1 --cycle-wait-seconds='$cycle_wait' --operation-timeout-seconds=180"
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
  local before
  local after
  before="$(snapshot_state "$host" "$channel")"
  printf '%s\n' "$before" >"$EVIDENCE_DIR/${label}-before.json"
  printf '%s\n' "$before" | jq -e '.pending == null' >/dev/null
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
}

assert_current() {
  local host="$1"
  local expected="$2"
  local label="$3"
  local observed
  observed="$(current_digest "$host")"
  if [[ "$observed" != "$expected" ]]; then
    printf 'REFUSED: %s current digest %s, expected %s\n' "$label" "$observed" "$expected" >&2
    return 1
  fi
}

record_step "prove both first installs committed exact release A"
wait_sequence "$CANARY_VM" canary 1
wait_sequence "$STABLE_VM" stable 1
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
start_update_timer "$CANARY_VM" cathedral-validator-canary-update.timer
wait_sequence "$CANARY_VM" canary 2
assert_current "$CANARY_VM" "$ARCHIVE_B_SHA" canary-timer-a-to-b
remote "$CANARY_VM" 'sudo systemctl disable --now cathedral-validator-canary-update.timer'
capture_host canary-after-timer-b "$CANARY_VM"

record_step "promote exact B archive and observe stable timer activate it"
publish_release "$STABLE_B2" "$ARCHIVE_B" "$STABLE_BRANCH" "stable-b2"
start_update_timer "$STABLE_VM" cathedral-validator-update.timer
wait_sequence "$STABLE_VM" stable 2
assert_current "$STABLE_VM" "$ARCHIVE_B_SHA" stable-exact-promotion
remote "$STABLE_VM" 'sudo systemctl disable --now cathedral-validator-update.timer'
capture_host stable-after-timer-b "$STABLE_VM"

record_step "same B archive renewal advances signed sequence without restart"
pid_before="$(main_pid "$CANARY_VM")"
publish_release "$CANARY_B3" "$ARCHIVE_B" "$CANARY_BRANCH" "canary-b3-renewal"
start_update_timer "$CANARY_VM" cathedral-validator-canary-update.timer
wait_sequence "$CANARY_VM" canary 3
pid_after="$(main_pid "$CANARY_VM")"
remote "$CANARY_VM" 'sudo systemctl disable --now cathedral-validator-canary-update.timer'
if [[ "$pid_before" != "$pid_after" || "$pid_before" == 0 ]]; then
  printf 'REFUSED: same-archive renewal restarted the direct service\n' >&2
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
pause_before="$(snapshot_state "$CANARY_VM" canary)"
printf '%s\n' "$pause_before" >"$EVIDENCE_DIR/pause-before.json"
printf '%s\n' "$pause_before" | jq -e '.pending == null' >/dev/null
remote "$CANARY_VM" 'sudo install -o root -g root -m 0600 /dev/null /etc/cathedral-validator/update.pause'
run_update "$CANARY_VM" canary "$pause_url" | tee "$EVIDENCE_DIR/pause.log"
grep -Fx 'CATHEDRAL_VALIDATOR_UPDATE_PAUSED' "$EVIDENCE_DIR/pause.log" >/dev/null
remote "$CANARY_VM" 'sudo rm /etc/cathedral-validator/update.pause'
pause_after="$(snapshot_state "$CANARY_VM" canary)"
printf '%s\n' "$pause_after" >"$EVIDENCE_DIR/pause-after.json"
if [[ "$pause_before" != "$pause_after" ]]; then
  printf 'REFUSED: pause changed current, sequence, or pending state\n' >&2
  exit 1
fi
assert_current "$CANARY_VM" "$ARCHIVE_B_SHA" pause

record_step "held cycle lock times out without activation"
  remote "$CANARY_VM" "sudo -u cathedral-validator sh -c 'nohup python3 -c \"import fcntl,time,pathlib; p=pathlib.Path(\\\"${JOURNAL%/*}/cycle.lock\\\"); f=p.open(\\\"r+\\\"); fcntl.flock(f,fcntl.LOCK_EX); pathlib.Path(\\\"/tmp/cathedral-cycle-held\\\").write_text(\\\"ready\\\"); time.sleep(120)\" >/tmp/cathedral-cycle-holder.log 2>&1 & echo \$! >/tmp/cathedral-cycle-holder.pid' && timeout 10 sh -c 'until test -f /tmp/cathedral-cycle-held; do sleep 0.2; done'"
expect_update_refused held-cycle "$CANARY_VM" canary "$pause_url" \
  'direct validator did not finish its cycle before timeout' 3
remote "$CANARY_VM" "sudo sh -c 'kill \"\$(cat /tmp/cathedral-cycle-holder.pid)\" 2>/dev/null || true'; sudo rm -f /tmp/cathedral-cycle-holder.pid /tmp/cathedral-cycle-held"
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
  'new release failed readiness; prior release was restored'
remote "$CANARY_VM" "sudo rm -f /etc/cathedral-validator-live-test/fail-before-ready.${ARCHIVE_A_SHA}"
assert_current "$CANARY_VM" "$ARCHIVE_B_SHA" readiness-rollback
remote "$CANARY_VM" "sudo systemctl is-active cathedral-validator-direct.service && sudo journalctl -u cathedral-validator-direct.service --no-pager | grep -F 'TEST_NO_CHAIN_TARGET_FAIL target=${ARCHIVE_A_SHA}' && sudo journalctl -u cathedral-validator-direct.service --no-pager | grep -F 'TEST_NO_CHAIN_READY target=${ARCHIVE_B_SHA}'"

wait_pending() {
  local host="$1"
  local target="$2"
  remote "$host" "sudo /usr/bin/python3 /usr/local/libexec/cathedral-wait-updater-state.py --state /var/lib/cathedral-validator-update/state.json --timeout-seconds 120 --pending-target '$target'"
}

launch_background_update() {
  local host="$1"
  local unit="$2"
  local channel="$3"
  local url="$4"
  remote "$host" "sudo systemd-run --unit='$unit' --collect /usr/local/lib/cathedral-validator-updater/bin/cathedral-validator-update --channel='$channel' --metadata-url='$url' --public-key=/etc/cathedral-validator/runtime-release-public-key.pem --identity-file=/etc/cathedral-validator/identity.env --minimum-sequence=1 --cycle-wait-seconds=10 --operation-timeout-seconds=180"
}

record_step "reset at durable may_have_run and reconcile exact A on boot"
reset_url="$(pin_fault_pointer stable "$STABLE_A3" "stable reset target A sequence 3")"
remote "$STABLE_VM" "printf '%s\n' 300 | sudo tee /etc/cathedral-validator-live-test/delay-before-ready.${ARCHIVE_A_SHA} >/dev/null"
launch_background_update "$STABLE_VM" "cathedral-live-reset-${RUN_ID}" stable "$reset_url"
wait_pending "$STABLE_VM" "$ARCHIVE_A_SHA"
capture_host stable-before-reset "$STABLE_VM"
gc compute instances reset "$STABLE_VM" --zone="$ZONE"
wait_ssh "$STABLE_VM"
remote "$STABLE_VM" "sudo rm -f /etc/cathedral-validator-live-test/delay-before-ready.${ARCHIVE_A_SHA} && sudo systemctl start cathedral-validator-direct.service"
wait_sequence "$STABLE_VM" stable 3
assert_current "$STABLE_VM" "$ARCHIVE_A_SHA" reset-may-have-run
remote "$STABLE_VM" "sudo systemctl is-active cathedral-validator-direct.service && sudo journalctl -u cathedral-validator-boot-reconcile.service -n 80 --no-pager | grep CATHEDRAL_VALIDATOR_UPDATE_RECONCILED"
capture_host stable-after-reset "$STABLE_VM"

record_step "leave B crash-uncertain, then rescue with higher signed A sequence"
uncertain_url="$(pin_fault_pointer stable "$STABLE_B4" "stable uncertain target B sequence 4")"
remote "$STABLE_VM" "printf '%s\n' 300 | sudo tee /etc/cathedral-validator-live-test/delay-before-ready.${ARCHIVE_B_SHA} >/dev/null"
launch_background_update "$STABLE_VM" "cathedral-live-rescue-${RUN_ID}" stable "$uncertain_url"
wait_pending "$STABLE_VM" "$ARCHIVE_B_SHA"
capture_host stable-before-rescue "$STABLE_VM"
remote "$STABLE_VM" "sudo systemctl kill --kill-whom=all --signal=KILL cathedral-live-rescue-${RUN_ID}.service || true; sudo systemctl stop cathedral-validator-direct.service || true; sudo rm -f /etc/cathedral-validator-live-test/delay-before-ready.${ARCHIVE_B_SHA}; printf '%s\n' fail | sudo tee /etc/cathedral-validator-live-test/fail-before-ready.${ARCHIVE_B_SHA} >/dev/null"
rescue_url="$(pin_fault_pointer stable "$STABLE_A5" "stable higher sequence rescue A sequence 5")"
run_update "$STABLE_VM" stable "$rescue_url" | tee "$EVIDENCE_DIR/higher-sequence-rescue.log"
remote "$STABLE_VM" "sudo rm -f /etc/cathedral-validator-live-test/fail-before-ready.${ARCHIVE_B_SHA}"
grep -q 'CATHEDRAL_VALIDATOR_UPDATE_ACTIVATED' "$EVIDENCE_DIR/higher-sequence-rescue.log"
wait_sequence "$STABLE_VM" stable 5
assert_current "$STABLE_VM" "$ARCHIVE_A_SHA" higher-sequence-rescue
remote "$STABLE_VM" 'sudo systemctl is-active cathedral-validator-direct.service'

assert_project_metadata_unchanged final
assert_instance_metadata_unchanged "$CANARY_VM" canary final
assert_instance_metadata_unchanged "$STABLE_VM" stable final
capture_host final-canary "$CANARY_VM"
capture_host final-stable "$STABLE_VM"
gc compute instances list \
  --filter="labels.cathedral-live-run=${RUN_ID}" \
  --format=json >"$EVIDENCE_DIR/pre-teardown-instances.json"
gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/heads/${CANARY_BRANCH}" >"$EVIDENCE_DIR/canary-branch.json"
gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/heads/${STABLE_BRANCH}" >"$EVIDENCE_DIR/stable-branch.json"
gh api "repos/${TEST_GITHUB_REPOSITORY}/git/ref/heads/${FAULT_BRANCH}" >"$EVIDENCE_DIR/fault-branch.json"

record_step "SCENARIOS_PASS_PENDING_TEARDOWN all bounded no-chain updater scenarios"
