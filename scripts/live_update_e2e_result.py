#!/usr/bin/env python3
"""Build and verify fail-closed evidence for the live updater controller.

This tool deliberately has no publication or chain-writing mode.  It decodes
the bounded host-capture transport, verifies promoted captures, and creates a
canonical, detached-signed result only after the controller has proved both
scenario completion and resource teardown.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


CAPTURE_SCHEMA = "cathedral_validator_live_update_host_capture_v1"
CAPTURE_MARKER = "CATHEDRAL_EVIDENCE_SECTION_V1"
RESULT_SCHEMA = "cathedral_validator_live_update_e2e_result_v1"
SCENARIO_MATRIX_SCHEMA = "cathedral_validator_live_update_scenario_matrix_v1"
EVIDENCE_INDEX_SCHEMA = "cathedral_validator_live_update_evidence_index_v1"
EVIDENCE_DIGEST_DOMAIN = b"cathedral-validator-live-update-evidence-v1\x00"
RESULT_NAME = "live_update_e2e_result_v1.json"
SIGNATURE_NAME = f"{RESULT_NAME}.sig"
DIGEST_NAME = f"{RESULT_NAME}.sha256"
RESULT_PUBLIC_KEY_NAME = "live-update-e2e-result-public-key.pem"
RESULT_TOOL_PATH = "scripts/live_update_e2e_result.py"
CONTROLLER_PATH = "scripts/live_validator_update_e2e.sh"
EVIDENCE_TREE_ALGORITHM = "sha256-domain-separated-canonical-json-file-list-v1"
SIGNER_PURPOSE = "live_e2e_test_evidence_only"
SIGNER_ALGORITHM = "ed25519"
AUTHORITY_NOTE = (
    "The detached signature authenticates the configured test-evidence "
    "key only; operator identity and immutable publication remain separate "
    "owner/operator actions."
)
TERMINAL_PASS = {
    "state": "pass",
    "original_exit_status": 0,
    "scenarios_complete": True,
    "required_evidence_complete": True,
    "teardown_verified": True,
}
NO_CHAIN_SCOPE = {
    "kind": "no_chain_updater_live_acceptance",
    "chain_write": False,
    "validator_cycle": False,
    "wallet_loaded": False,
    "production_release_key_loaded": False,
    "disposable_test_release_keys_generated": True,
}
UNATTESTED_AUTHORITY = {
    "operator_identity_attested": False,
    "immutable_publication_present": False,
    "note": AUTHORITY_NOTE,
}
RESULT_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema",
        "run",
        "terminal",
        "scope",
        "controller",
        "signer",
        "scenario_matrix",
        "evidence_tree",
        "authority",
    }
)
RUN_FIELDS = frozenset(
    {
        "id",
        "finished_at",
        "source_revision_a",
        "source_revision_b",
        "archive_a_sha256",
        "archive_b_sha256",
    }
)
SIGNER_FIELDS = frozenset(
    {
        "purpose",
        "key_id",
        "algorithm",
        "public_key_path",
        "public_key_fingerprint",
        "authorizes_chain_or_weight_changes",
    }
)
EVIDENCE_TREE_FIELDS = frozenset({"algorithm", "root_sha256", "file_count", "files"})
RUNTIME_METADATA_SCHEMA = "cathedral_validator_release_v1"
BOOTSTRAP_MANIFEST_SCHEMA = "cathedral_validator_updater_bootstrap_v3"
BOOTSTRAP_PUBLICATION_SCHEMA = "cathedral_validator_live_bootstrap_publication_v1"
RUNTIME_METADATA_LIFETIME_SECONDS = 43_200
BOOTSTRAP_LIFETIME_SECONDS = 43_200
RUNTIME_RELEASE_ENTRYPOINT = "bin/cathedral-validator"
RUNTIME_KEY_BUNDLE_PATH = "payload/runtime-release-public-key.pem"
RUNTIME_METADATA_SPECS: tuple[tuple[str, str, int, str, str | None], ...] = (
    ("canary-a-seq1.json", "canary", 1, "archive_a_sha256", None),
    ("canary-b-seq2.json", "canary", 2, "archive_b_sha256", None),
    ("canary-b-renewal-seq3.json", "canary", 3, "archive_b_sha256", None),
    ("canary-a-equivocation-seq3.json", "canary", 3, "archive_a_sha256", None),
    ("canary-a-seq4.json", "canary", 4, "archive_a_sha256", None),
    (
        "stable-a-seq1.json",
        "stable",
        1,
        "archive_a_sha256",
        "canary-a-seq1.json",
    ),
    (
        "stable-b-seq2.json",
        "stable",
        2,
        "archive_b_sha256",
        "canary-b-seq2.json",
    ),
    (
        "stable-a-seq3.json",
        "stable",
        3,
        "archive_a_sha256",
        "canary-a-seq4.json",
    ),
    (
        "stable-b-seq4.json",
        "stable",
        4,
        "archive_b_sha256",
        "canary-b-renewal-seq3.json",
    ),
    (
        "stable-a-rescue-seq5.json",
        "stable",
        5,
        "archive_a_sha256",
        "canary-a-seq4.json",
    ),
)
INVALID_RUNTIME_METADATA_NAME = "canary-b-invalid-signature.json"
RUNTIME_METADATA_NAMES = frozenset(
    {name for name, _channel, _sequence, _archive, _promotion in RUNTIME_METADATA_SPECS}
    | {INVALID_RUNTIME_METADATA_NAME}
)
BOOTSTRAP_PROOF_FILES = frozenset(
    {
        "bootstrap-build.json",
        "updater-bootstrap.manifest.json",
        "updater-bootstrap.manifest.sig",
    }
)
HEX_64 = re.compile(r"[0-9a-f]{64}")
SAFE_SECTION = re.compile(r"[a-z][a-z0-9_]{0,63}")
SAFE_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}")
SAFE_CAPTURE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}")
REVISION = re.compile(r"[0-9a-f]{40}")
SAFE_RUN_ID = re.compile(r"[a-z0-9][a-z0-9-]{5,20}")
SAFE_REPOSITORY_COMPONENT = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?"
)
SAFE_ZONE = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?-[a-z]\b")
RFC3339_UTC_SECONDS = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z"
)

GENERIC_SECTIONS: tuple[tuple[str, bool], ...] = (
    ("current_release", True),
    ("updater_state", True),
    ("direct_unit_show", True),
    ("direct_unit_status", False),
    ("direct_unit_definition", True),
    ("boot_reconcile_show", True),
    ("boot_reconcile_status", False),
    ("boot_reconcile_definition", True),
    ("updater_services_show", True),
    ("updater_services_status", False),
    ("updater_services_definitions", True),
    ("timers_show", True),
    ("timer_definitions", True),
    ("timer_list", True),
    ("updater_runtime_journal", False),
)
TRANSIENT_SECTIONS: tuple[tuple[str, bool], ...] = (
    ("transient_unit_show", False),
    ("transient_unit_status", False),
    ("transient_unit_journal", False),
)

REQUIRED_SUCCESS_FILES = frozenset(
    {
        "bootstrap-publication.json",
        "bootstrap-build.json",
        "bootstrap-release-record.json",
        "bootstrap-tag-record.json",
        "canary-branch.json",
        "canary-iap-instance-permissions.json",
        "canary-iap-scp.log",
        "canary-iap-ssh-dry-run.txt",
        "canary-iap-ssh-marker.log",
        "canary-instance-metadata-before.json",
        "canary-instance-metadata-final.json",
        "canary-instance.json",
        "canary-first-install-sequence-state.json",
        "canary-same-boot-reactivation-timer-reactivation-start.log",
        "canary-same-boot-reactivation-timer-reactivation-state.log",
        "canary-same-boot-reactivation-timer-reactivation-wait.log",
        "candidate-attestations.log",
        "control.json",
        "controller-api-state.json",
        "controller-project-permissions.json",
        "created-run-instances.json",
        "fault-branch.json",
        "fault-urls.tsv",
        "final-canary-capture-retries.log",
        "final-canary-sections.json",
        "final-canary.txt",
        "final-stable-capture-retries.log",
        "final-stable-sections.json",
        "final-stable.txt",
        "operator-secret-scan.json",
        RESULT_PUBLIC_KEY_NAME,
        "post-teardown-exact-disks.json",
        "post-teardown-exact-instances.json",
        "post-teardown-firewall.json",
        "post-teardown-labeled-instances.json",
        "post-teardown-network.json",
        "post-teardown-subnet.json",
        "pre-teardown-instances.json",
        "project-metadata-after-teardown.json",
        "project-metadata-before.json",
        "project-metadata-final.json",
        "runtime-release-public-key.pem",
        "same-archive-invocation-after-value.txt",
        "same-archive-invocation-before-value.txt",
        "same-archive-pid-after-value.txt",
        "same-archive-pid-before-value.txt",
        "same-boot-reactivation-invocation-after-value.txt",
        "same-boot-reactivation-pid-after-value.txt",
        "ssh-firewall.json",
        "source-repository.json",
        "stable-branch.json",
        "stable-iap-instance-permissions.json",
        "stable-iap-scp.log",
        "stable-iap-ssh-dry-run.txt",
        "stable-iap-ssh-marker.log",
        "stable-instance-metadata-before.json",
        "stable-instance-metadata-final.json",
        "stable-instance.json",
        "stable-first-install-sequence-state.json",
        "steps.log",
        "teardown-canary-disk-result.txt",
        "teardown-canary-vm-result.txt",
        "teardown-firewall-result.txt",
        "teardown-network-result.txt",
        "teardown-stable-disk-result.txt",
        "teardown-stable-vm-result.txt",
        "teardown-status.txt",
        "teardown-subnet-result.txt",
        "test-publication-immutable-releases.json",
        "test-publication-main-before.json",
        "test-publication-repository.json",
        "bootstrap-release-public-key.pem",
        "updater-bootstrap.manifest.json",
        "updater-bootstrap.manifest.sig",
        *{f"signed-runtime-metadata/{name}" for name in RUNTIME_METADATA_NAMES},
    }
)
EMPTY_TEARDOWN_LISTS = (
    "post-teardown-exact-disks.json",
    "post-teardown-exact-instances.json",
    "post-teardown-firewall.json",
    "post-teardown-labeled-instances.json",
    "post-teardown-network.json",
    "post-teardown-subnet.json",
)
DIRECT_SERVICE_PID_PROOFS = (
    "same-archive-pid-before-value.txt",
    "same-archive-pid-after-value.txt",
    "same-boot-reactivation-pid-after-value.txt",
)
DIRECT_SERVICE_INVOCATION_PROOFS = (
    "same-archive-invocation-before-value.txt",
    "same-archive-invocation-after-value.txt",
    "same-boot-reactivation-invocation-after-value.txt",
)
TEARDOWN_RESOURCE_PROOFS = (
    ("teardown-canary-vm-result.txt", "instance", "catval-{run_id}-canary"),
    ("teardown-stable-vm-result.txt", "instance", "catval-{run_id}-stable"),
    ("teardown-canary-disk-result.txt", "disk", "catval-{run_id}-canary"),
    ("teardown-stable-disk-result.txt", "disk", "catval-{run_id}-stable"),
    ("teardown-firewall-result.txt", "firewall", "catval-{run_id}-ssh"),
    ("teardown-subnet-result.txt", "subnet", "catval-{run_id}-subnet"),
    ("teardown-network-result.txt", "network", "catval-{run_id}-net"),
)

CONTROL_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "gcp_project",
        "zone",
        "controller_transport",
        "iap_source_range",
        "vm_service_account_attached",
        "machine_type",
        "vm_count",
        "max_run_seconds",
        "vm_and_disk_estimate_usd",
        "network_ipv4_and_egress_allowance_usd",
        "planning_total_usd",
        "cost_scope",
        "source_repository",
        "test_publication_repository",
        "test_mirror_main_sha",
        "canonical_source_write_allowed",
        "source_revision_a",
        "source_revision_b",
        "archive_a_sha256",
        "archive_b_sha256",
        "bootstrap_key_fingerprint",
        "runtime_key_fingerprint",
        "canary_branch",
        "stable_branch",
        "fault_branch",
        "no_chain_harness_sha256",
        "fault_origin_sha256",
        "state_waiter_sha256",
        "result_signer",
        "bootstrap_track",
        "bootstrap_tag",
        "bootstrap_transport",
        "anonymous_bootstrap_download_required",
        "stable_host_configuration",
        "stable_host_status_command",
        "canary_host_configuration",
        "operator_hotkey_shape",
        "bootstrap_assets",
        "guided_operator",
        "fixed_channel_cache_max_seconds",
        "update_timer_interval_seconds",
        "fixed_channel_wait_seconds",
    }
)
CONTROL_COST_SCOPE = (
    "conservative VM and disk estimate plus a 0.20 USD planning allowance "
    "for two external IPv4 addresses and bounded network traffic; this is "
    "not a cloud billing cap"
)

RECORDED_STEPS = (
    "publish first exact A release to isolated canary and stable channels",
    "create bounded two-host GCP network",
    "first install A through signed bootstrap and no-chain systemd readiness",
    "prove both first installs committed exact release A",
    "invalid signature refuses without changing A",
    "tampered archive bytes refuse before activation",
    "publish B and observe canary timer activate A to B",
    "promote exact B archive and observe stable timer activate it",
    "same B archive renewal advances signed sequence without restart",
    "replay, equivocation, and metadata outage fail closed",
    "pause blocks a valid newer release without changing B",
    "held cycle lock times out without activation",
    "unresolved writer journal blocks activation",
    "target-specific readiness failure rolls A back to B",
    "reset at durable may_have_run and reconcile exact A on boot",
    "leave B crash-uncertain, then rescue with higher signed A sequence",
    "guided setup rerun refuses the stopped writer and status reports review",
    "SCENARIOS_PASS_PENDING_TEARDOWN all bounded no-chain updater scenarios",
)

# Each artifact path is stable protocol evidence. ``{run_id}`` is the only
# substitution, and ``empty_allowed`` is explicit so an empty command log can
# never silently stand in for a proof artifact.
SCENARIO_SPECS: tuple[tuple[str, str, tuple[tuple[str, bool], ...]], ...] = (
    (
        "initial_release_publication",
        RECORDED_STEPS[0],
        (("canary-a1-publish.log", False), ("stable-a1-publish.log", False)),
    ),
    (
        "bounded_two_host_network",
        RECORDED_STEPS[1],
        (("created-run-instances.json", False),),
    ),
    (
        "signed_first_install",
        RECORDED_STEPS[2],
        (
            ("bootstrap-build.json", False),
            ("updater-bootstrap.manifest.json", False),
            ("updater-bootstrap.manifest.sig", False),
            ("bootstrap-release-public-key.pem", False),
            ("runtime-release-public-key.pem", False),
            ("first-install-command-catval-{run_id}-canary.log", False),
            ("first-install-command-catval-{run_id}-stable.log", False),
            ("first-readiness-command-catval-{run_id}-canary.log", False),
            ("first-readiness-command-catval-{run_id}-stable.log", False),
            ("guided-status-after-setup.json", False),
            ("guided-setup-idempotence-proof.json", False),
        ),
    ),
    (
        "exact_first_install_commit",
        RECORDED_STEPS[3],
        (
            ("canary-first-install-a-current-proof.txt", False),
            ("stable-first-install-a-current-proof.txt", False),
            ("canary-first-install-sequence-state.json", False),
            ("stable-first-install-sequence-state.json", False),
            ("signed-runtime-metadata/canary-a-seq1.json", False),
            ("signed-runtime-metadata/stable-a-seq1.json", False),
        ),
    ),
    (
        "invalid_signature_refusal",
        RECORDED_STEPS[4],
        (
            ("signed-runtime-metadata/canary-b-invalid-signature.json", False),
            ("invalid-signature.log", False),
            ("invalid-signature-before.json", False),
            ("invalid-signature-after.json", False),
            ("invalid-signature-service-before.txt", False),
            ("invalid-signature-service-after.txt", False),
            ("invalid-signature-current-proof.txt", False),
        ),
    ),
    (
        "tampered_archive_refusal",
        RECORDED_STEPS[5],
        (
            ("signed-runtime-metadata/canary-b-seq2.json", False),
            ("tampered-archive.log", False),
            ("tampered-archive-before.json", False),
            ("tampered-archive-after.json", False),
            ("tampered-archive-service-before.txt", False),
            ("tampered-archive-service-after.txt", False),
            ("tampered-archive-current-proof.txt", False),
        ),
    ),
    (
        "canary_timer_promotion",
        RECORDED_STEPS[6],
        (
            ("signed-runtime-metadata/canary-b-seq2.json", False),
            ("canary-timer-a-to-b-timer-start-command.log", False),
            ("canary-timer-a-to-b-timer-wait-command.log", False),
            ("canary-timer-a-to-b-timer-rearm-command.log", False),
            ("canary-timer-a-to-b-current-proof.txt", False),
        ),
    ),
    (
        "stable_timer_promotion",
        RECORDED_STEPS[7],
        (
            ("signed-runtime-metadata/stable-b-seq2.json", False),
            ("stable-exact-promotion-timer-start-command.log", False),
            ("stable-exact-promotion-timer-wait-command.log", False),
            ("stable-exact-promotion-timer-rearm-command.log", False),
            ("stable-exact-promotion-current-proof.txt", False),
            ("guided-status-after-timer-b-command.log", False),
            ("guided-status-after-timer-b.json", False),
        ),
    ),
    (
        "same_archive_renewal_and_reactivation",
        RECORDED_STEPS[8],
        (
            ("signed-runtime-metadata/canary-b-renewal-seq3.json", False),
            ("canary-same-archive-renewal-current-proof.txt", False),
            (
                "canary-same-boot-reactivation-timer-reactivation-start.log",
                False,
            ),
            (
                "canary-same-boot-reactivation-timer-reactivation-wait.log",
                False,
            ),
            (
                "canary-same-boot-reactivation-timer-reactivation-state.log",
                False,
            ),
            ("same-archive-pid-before-value-command.stderr", True),
        ),
    ),
    (
        "signed_metadata_faults",
        RECORDED_STEPS[9],
        (
            ("signed-runtime-metadata/canary-a-equivocation-seq3.json", False),
            ("replay.log", False),
            ("replay-before.json", False),
            ("replay-after.json", False),
            ("replay-service-before.txt", False),
            ("replay-service-after.txt", False),
            ("equivocation.log", False),
            ("equivocation-before.json", False),
            ("equivocation-after.json", False),
            ("equivocation-service-before.txt", False),
            ("equivocation-service-after.txt", False),
            ("metadata-outage.log", False),
            ("metadata-outage-before.json", False),
            ("metadata-outage-after.json", False),
            ("metadata-outage-service-before.txt", False),
            ("metadata-outage-service-after.txt", False),
            ("signed-metadata-faults-current-proof.txt", False),
        ),
    ),
    (
        "pause",
        RECORDED_STEPS[10],
        (
            ("signed-runtime-metadata/canary-a-seq4.json", False),
            ("pause.log", False),
            ("pause-before.json", False),
            ("pause-after.json", False),
            ("pause-service-before.txt", False),
            ("pause-service-after.txt", False),
            ("pause-current-proof.txt", False),
        ),
    ),
    (
        "held_cycle",
        RECORDED_STEPS[11],
        (
            ("held-cycle.log", False),
            ("held-cycle-before.json", False),
            ("held-cycle-after.json", False),
            ("held-cycle-service-before.txt", False),
            ("held-cycle-service-after.txt", False),
            ("held-cycle-current-proof.txt", False),
        ),
    ),
    (
        "unresolved_journal",
        RECORDED_STEPS[12],
        (
            ("unresolved-journal.log", False),
            ("unresolved-journal-before.json", False),
            ("unresolved-journal-after.json", False),
            ("unresolved-journal-service-before.txt", False),
            ("unresolved-journal-service-after.txt", False),
            ("unresolved-journal-current-proof.txt", False),
        ),
    ),
    (
        "readiness_rollback",
        RECORDED_STEPS[13],
        (
            ("readiness-rollback.log", False),
            ("readiness-rollback-before.json", False),
            ("readiness-rollback-after.json", False),
            ("readiness-rollback-service-before.txt", False),
            ("readiness-rollback-service-after.txt", False),
            ("readiness-rollback-current-proof.txt", False),
        ),
    ),
    (
        "durable_reset_reconciliation",
        RECORDED_STEPS[14],
        (
            ("signed-runtime-metadata/stable-a-seq3.json", False),
            ("stable-reset-pre-action-state.json", False),
            ("stable-reset-request-command.log", False),
            ("stable-reset-reconcile-proof-command.log", False),
            ("reset-may-have-run-current-proof.txt", False),
        ),
    ),
    (
        "higher_sequence_rescue",
        RECORDED_STEPS[15],
        (
            ("signed-runtime-metadata/stable-b-seq4.json", False),
            ("signed-runtime-metadata/stable-a-rescue-seq5.json", False),
            ("stable-rescue-pre-action-state.json", False),
            ("stable-rescue-crash-command.log", False),
            ("higher-sequence-rescue-update-command.log", False),
            ("higher-sequence-rescue-current-proof.txt", False),
        ),
    ),
    (
        "guided_operator_stopped_writer_review",
        RECORDED_STEPS[16],
        (
            ("guided-setup-stopped-writer-command.log", False),
            ("guided-setup-stopped-writer-proof.json", False),
            ("guided-status-stopped-writer.json", False),
        ),
    ),
    (
        "final_capture",
        RECORDED_STEPS[17],
        (
            ("final-canary-sections.json", False),
            ("final-canary-capture-retries.log", False),
            ("final-canary.d/direct_unit_show.txt", False),
            ("final-canary.d/updater_state.txt", False),
            ("final-stable-sections.json", False),
            ("final-stable-capture-retries.log", False),
            ("final-stable.d/direct_unit_show.txt", False),
            ("final-stable.d/updater_state.txt", False),
            ("operator-secret-scan.json", False),
        ),
    ),
)

# Every negative scenario snapshots the updater and direct service on both sides
# of the refused update.  These policies are kept separate from the shell's
# assertions so the signed result verifier independently checks the claimed
# non-mutation boundary.  ``restarted`` is used only for the intentional
# readiness rollback, where state/current must remain unchanged but systemd
# must expose a fresh service invocation.
NEGATIVE_SCENARIO_INVARIANTS = (
    ("invalid-signature", "archive_a_sha256", 1, "unchanged"),
    ("tampered-archive", "archive_a_sha256", 1, "unchanged"),
    ("replay", "archive_b_sha256", 3, "unchanged"),
    ("equivocation", "archive_b_sha256", 3, "unchanged"),
    ("metadata-outage", "archive_b_sha256", 3, "unchanged"),
    ("pause", "archive_b_sha256", 3, "unchanged"),
    ("held-cycle", "archive_b_sha256", 3, "unchanged"),
    ("unresolved-journal", "archive_b_sha256", 3, "unchanged"),
    ("readiness-rollback", "archive_b_sha256", 3, "restarted"),
)

CURRENT_RELEASE_PROOFS = (
    ("invalid-signature-current-proof.txt", "archive_a_sha256"),
    ("tampered-archive-current-proof.txt", "archive_a_sha256"),
    ("signed-metadata-faults-current-proof.txt", "archive_b_sha256"),
    ("pause-current-proof.txt", "archive_b_sha256"),
    ("held-cycle-current-proof.txt", "archive_b_sha256"),
    ("unresolved-journal-current-proof.txt", "archive_b_sha256"),
    ("readiness-rollback-current-proof.txt", "archive_b_sha256"),
)
RESULT_EXCLUSIONS = frozenset({RESULT_NAME, SIGNATURE_NAME, DIGEST_NAME})


class EvidenceError(ValueError):
    """The evidence cannot support a successful live-test result."""


def _reject_constant(value: str) -> None:
    raise EvidenceError(f"non-finite JSON number is forbidden: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(data: bytes, *, label: str, canonical: bool = False) -> Any:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"{label} must be ASCII JSON") from exc
    try:
        value = json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (json.JSONDecodeError, EvidenceError) as exc:
        raise EvidenceError(f"{label} is not strict JSON: {exc}") from exc
    if canonical and data != canonical_bytes(value):
        raise EvidenceError(f"{label} is not byte-canonical")
    return value


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path, *, label: str, require_nonempty: bool = False) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise EvidenceError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise EvidenceError(f"{label} must be a regular non-symlink file: {path}")
    data = path.read_bytes()
    if require_nonempty and not data:
        raise EvidenceError(f"{label} must not be empty: {path}")
    return data


def _resolve_evidence_root(path: Path) -> Path:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise EvidenceError(f"missing EVIDENCE_DIR: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise EvidenceError("EVIDENCE_DIR must be a regular directory")
    return path.resolve(strict=True)


def _require_exact_object(
    value: Any, expected: dict[str, Any], *, label: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise EvidenceError(f"{label} has unexpected or missing fields")
    for key, expected_value in expected.items():
        observed = value[key]
        if type(observed) is not type(expected_value) or observed != expected_value:
            raise EvidenceError(f"{label} has an invalid {key}")
    return value


def _validate_utc_seconds(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or RFC3339_UTC_SECONDS.fullmatch(value) is None:
        raise EvidenceError(
            f"{label} must be an RFC3339 UTC timestamp at whole seconds"
        )
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise EvidenceError(
            f"{label} must be an RFC3339 UTC timestamp at whole seconds"
        ) from exc
    return value


def _reviewed_source_identity(
    controller_input: Path | None = None,
) -> tuple[Path, bytes, bytes]:
    tool_input = Path(__file__)
    tool_bytes = _read_regular(
        tool_input, label="current result verifier source", require_nonempty=True
    )
    tool_path = tool_input.resolve(strict=True)
    if tool_path.name != PurePosixPath(RESULT_TOOL_PATH).name:
        raise EvidenceError("current result verifier does not use its canonical path")
    controller_path = tool_path.with_name(PurePosixPath(CONTROLLER_PATH).name)
    selected_controller = (
        controller_input if controller_input is not None else controller_path
    )
    controller_bytes = _read_regular(
        selected_controller, label="live controller source", require_nonempty=True
    )
    if selected_controller.resolve(strict=True) != controller_path:
        raise EvidenceError(
            "live controller source does not use its reviewed canonical path"
        )
    return controller_path, controller_bytes, tool_bytes


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    if path.exists() or path.is_symlink():
        raise EvidenceError(f"refusing to replace existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _load_key_pair(
    private_path: Path,
    public_path: Path,
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    if not private_path.is_absolute() or not public_path.is_absolute():
        raise EvidenceError("result signing key paths must be absolute")
    private_info = private_path.lstat()
    public_info = public_path.lstat()
    if stat.S_ISLNK(private_info.st_mode) or not stat.S_ISREG(private_info.st_mode):
        raise EvidenceError(
            "result signing private key must be a regular non-symlink file"
        )
    if stat.S_ISLNK(public_info.st_mode) or not stat.S_ISREG(public_info.st_mode):
        raise EvidenceError(
            "result signing public key must be a regular non-symlink file"
        )
    if private_info.st_uid != os.getuid():
        raise EvidenceError(
            "result signing private key must be owned by the controller user"
        )
    if stat.S_IMODE(private_info.st_mode) & 0o077:
        raise EvidenceError(
            "result signing private key must not grant group/other access"
        )
    try:
        private = serialization.load_pem_private_key(
            private_path.read_bytes(), password=None
        )
        public = serialization.load_pem_public_key(public_path.read_bytes())
    except (TypeError, ValueError) as exc:
        raise EvidenceError(
            "result signing keys are not valid unencrypted PEM"
        ) from exc
    if not isinstance(private, Ed25519PrivateKey) or not isinstance(
        public, Ed25519PublicKey
    ):
        raise EvidenceError("result signing key pair must use Ed25519")
    derived = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    observed = public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if derived != observed:
        raise EvidenceError("result signing private/public keys do not match")
    der = public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public, f"sha256:{_sha256(der)}"


def validate_key_pair(args: argparse.Namespace) -> int:
    _, _, fingerprint = _load_key_pair(args.private_key, args.public_key)
    if not SAFE_KEY_ID.fullmatch(args.key_id):
        raise EvidenceError("result signer key id is unsafe")
    print(fingerprint)
    return 0


def _expected_sections(transient_unit: str | None) -> tuple[tuple[str, bool], ...]:
    return GENERIC_SECTIONS + (TRANSIENT_SECTIONS if transient_unit else ())


def _capture_manifest_complete(
    manifest: dict[str, Any], artifacts_dir: Path
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if set(manifest) != {
        "schema",
        "label",
        "host",
        "transient_unit",
        "complete",
        "transport_errors",
        "sections",
    }:
        errors.append("capture manifest has unexpected or missing fields")
    if not isinstance(manifest.get("complete"), bool):
        errors.append("complete must be boolean")
    if not isinstance(manifest.get("label"), str) or not SAFE_CAPTURE_ID.fullmatch(
        manifest["label"]
    ):
        errors.append("capture label is unsafe")
    if not isinstance(manifest.get("host"), str) or not SAFE_CAPTURE_ID.fullmatch(
        manifest["host"]
    ):
        errors.append("capture host is unsafe")
    transient = manifest.get("transient_unit")
    if transient is not None and not isinstance(transient, str):
        errors.append("transient_unit must be null or a string")
        transient = None
    elif isinstance(transient, str) and not SAFE_CAPTURE_ID.fullmatch(transient):
        errors.append("transient_unit is unsafe")
    expected = _expected_sections(transient)
    expected_map = dict(expected)
    sections = manifest.get("sections")
    if not isinstance(sections, list):
        return False, ["sections must be an array"]
    seen: set[str] = set()
    for row in sections:
        if not isinstance(row, dict):
            errors.append("section row must be an object")
            continue
        section_id = row.get("id")
        if not isinstance(section_id, str) or section_id not in expected_map:
            errors.append(f"unexpected section id: {section_id!r}")
            continue
        if section_id in seen:
            errors.append(f"duplicate section id: {section_id}")
            continue
        seen.add(section_id)
        if set(row) != {"id", "required", "command_exit_status", "artifact"}:
            errors.append(f"unexpected fields for section: {section_id}")
        required = row.get("required")
        if required is not expected_map[section_id]:
            errors.append(f"wrong required flag for section: {section_id}")
        status_value = row.get("command_exit_status")
        if (
            not isinstance(status_value, int)
            or isinstance(status_value, bool)
            or not 0 <= status_value <= 255
        ):
            errors.append(f"invalid exit status for section: {section_id}")
            continue
        artifact = row.get("artifact")
        if not isinstance(artifact, dict):
            errors.append(f"missing artifact for section: {section_id}")
            continue
        if set(artifact) != {"path", "bytes", "sha256"}:
            errors.append(f"unexpected artifact fields for section: {section_id}")
        artifact_name = artifact.get("path")
        size = artifact.get("bytes")
        digest = artifact.get("sha256")
        if (
            not isinstance(artifact_name, str)
            or PurePosixPath(artifact_name).name != artifact_name
            or artifact_name != f"{section_id}.txt"
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(digest, str)
            or HEX_64.fullmatch(digest) is None
        ):
            errors.append(f"invalid artifact metadata for section: {section_id}")
            continue
        try:
            data = _read_regular(
                artifacts_dir / artifact_name,
                label=f"capture artifact {section_id}",
            )
        except EvidenceError as exc:
            errors.append(str(exc))
            continue
        if size != len(data) or digest != _sha256(data):
            errors.append(f"artifact size/digest mismatch for section: {section_id}")
        if required and (status_value != 0 or not data):
            errors.append(f"required section failed or is empty: {section_id}")
        if section_id == "current_release" and status_value == 0:
            if re.fullmatch(rb"releases/[0-9a-f]{64}\n?", data) is None:
                errors.append(
                    "current_release is not one exact content-addressed release"
                )
        if section_id == "updater_state" and status_value == 0:
            try:
                state = strict_json(data, label="captured updater_state")
            except EvidenceError as exc:
                errors.append(str(exc))
            else:
                if not isinstance(state, dict) or "pending" not in state:
                    errors.append("captured updater_state lacks a pending field")
    missing = set(expected_map) - seen
    if missing:
        errors.append(f"missing sections: {','.join(sorted(missing))}")
    transport_errors = manifest.get("transport_errors")
    if not isinstance(transport_errors, list):
        errors.append("transport_errors must be an array")
    elif any(not isinstance(item, str) for item in transport_errors):
        errors.append("transport_errors entries must be strings")
    elif transport_errors:
        errors.extend(f"transport: {item}" for item in transport_errors)
    return not errors, errors


def decode_capture(args: argparse.Namespace) -> int:
    raw = _read_regular(args.input, label="capture transport")
    ssh_stderr = _read_regular(args.ssh_stderr, label="capture SSH stderr")
    expected = _expected_sections(args.transient_unit)
    expected_map = dict(expected)
    rows: dict[str, dict[str, Any]] = {}
    payloads: dict[str, bytes] = {}
    errors: list[str] = []

    for line_number, encoded_line in enumerate(raw.splitlines(), start=1):
        try:
            line = encoded_line.decode("ascii")
        except UnicodeDecodeError:
            errors.append(f"line {line_number} is not ASCII")
            continue
        fields = line.split("\t")
        if len(fields) != 7 or fields[0] != CAPTURE_MARKER:
            errors.append(f"line {line_number} is not a section record")
            continue
        _, section_id, requirement, status_text, size_text, digest, encoded = fields
        if not SAFE_SECTION.fullmatch(section_id) or section_id not in expected_map:
            errors.append(f"line {line_number} has unexpected section id")
            continue
        if section_id in rows:
            errors.append(f"line {line_number} duplicates section {section_id}")
            continue
        required = requirement == "required"
        if (
            requirement not in {"required", "optional"}
            or required is not expected_map[section_id]
        ):
            errors.append(f"line {line_number} misclassifies section {section_id}")
            continue
        try:
            status_value = int(status_text, 10)
            size = int(size_text, 10)
        except ValueError:
            errors.append(f"line {line_number} has a non-integer status or size")
            continue
        if not 0 <= status_value <= 255 or size < 0 or not HEX_64.fullmatch(digest):
            errors.append(f"line {line_number} has invalid section metadata")
            continue
        try:
            payload = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            errors.append(f"line {line_number} has invalid base64")
            continue
        if base64.b64encode(payload).decode("ascii") != encoded:
            errors.append(f"line {line_number} has non-canonical base64")
            continue
        if len(payload) != size or _sha256(payload) != digest:
            errors.append(f"line {line_number} has a payload size/digest mismatch")
            continue
        artifact_name = f"{section_id}.txt"
        rows[section_id] = {
            "id": section_id,
            "required": required,
            "command_exit_status": status_value,
            "artifact": {
                "path": artifact_name,
                "bytes": size,
                "sha256": digest,
            },
        }
        payloads[section_id] = payload

    missing = set(expected_map) - set(rows)
    if missing:
        errors.append(f"missing sections: {','.join(sorted(missing))}")
    if args.artifacts_dir.exists() or args.artifacts_dir.is_symlink():
        raise EvidenceError(
            f"capture artifacts directory already exists: {args.artifacts_dir}"
        )
    args.artifacts_dir.mkdir(mode=0o700, parents=True)
    for section_id, _required in expected:
        if section_id in payloads:
            _atomic_write(
                args.artifacts_dir / f"{section_id}.txt",
                payloads[section_id],
                mode=0o600,
            )

    ordered_rows = [
        rows[section_id] for section_id, _ in expected if section_id in rows
    ]
    provisional: dict[str, Any] = {
        "schema": CAPTURE_SCHEMA,
        "label": args.label,
        "host": args.host,
        "transient_unit": args.transient_unit,
        "complete": False,
        "transport_errors": errors,
        "sections": ordered_rows,
    }
    computed_complete, computed_errors = _capture_manifest_complete(
        provisional, args.artifacts_dir
    )
    if computed_errors:
        combined_errors = list(dict.fromkeys(errors + computed_errors))
        provisional["transport_errors"] = combined_errors
        computed_complete = False
    provisional["complete"] = computed_complete

    aggregate = bytearray()
    for section_id, required in expected:
        row = rows.get(section_id)
        if row is None:
            continue
        aggregate.extend(
            (
                f"--- {section_id} required={str(required).lower()} "
                f"status={row['command_exit_status']} ---\n"
            ).encode("ascii")
        )
        aggregate.extend(payloads[section_id])
        if not payloads[section_id].endswith(b"\n"):
            aggregate.extend(b"\n")
    if ssh_stderr:
        aggregate.extend(b"--- controller_ssh_stderr required=false ---\n")
        aggregate.extend(ssh_stderr)
        if not ssh_stderr.endswith(b"\n"):
            aggregate.extend(b"\n")
    _atomic_write(args.text_output, bytes(aggregate), mode=0o600)
    _atomic_write(args.manifest_output, canonical_bytes(provisional), mode=0o600)
    if not computed_complete:
        print(
            f"REFUSED: host evidence capture is incomplete label={args.label}",
            file=sys.stderr,
        )
        return 1
    return 0


def _load_capture_manifest(path: Path) -> dict[str, Any]:
    value = strict_json(
        _read_regular(path, label="capture manifest", require_nonempty=True),
        label="capture manifest",
        canonical=True,
    )
    if not isinstance(value, dict) or value.get("schema") != CAPTURE_SCHEMA:
        raise EvidenceError("capture manifest has the wrong schema")
    return value


def _systemd_show_blocks(data: bytes, *, label: str) -> list[dict[str, str]]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"{label} is not UTF-8 systemd output") from exc
    blocks: list[dict[str, str]] = []
    for raw_block in re.split(r"\n\s*\n", text.strip()):
        if not raw_block:
            continue
        block: dict[str, str] = {}
        for line in raw_block.splitlines():
            if "=" not in line:
                raise EvidenceError(f"{label} contains a malformed property line")
            key, value = line.split("=", 1)
            if not key or key in block:
                raise EvidenceError(f"{label} contains a missing or duplicate property")
            block[key] = value
        blocks.append(block)
    if not blocks:
        raise EvidenceError(f"{label} contains no property blocks")
    return blocks


def _validate_final_systemd_state(
    artifacts_dir: Path, *, label: str, direct_active: bool = True
) -> dict[str, str | int]:
    direct_blocks = _systemd_show_blocks(
        _read_regular(
            artifacts_dir / "direct_unit_show.txt", label=f"{label} direct unit state"
        ),
        label=f"{label} direct unit state",
    )
    if len(direct_blocks) != 1:
        raise EvidenceError(f"{label} direct unit state has multiple property blocks")
    direct = direct_blocks[0]
    try:
        main_pid = int(direct.get("MainPID", "0"), 10)
    except ValueError as exc:
        raise EvidenceError(f"{label} direct unit has an invalid MainPID") from exc
    invocation_id = direct.get("InvocationID", "")
    if direct_active:
        if (
            direct.get("Result") != "success"
            or direct.get("ExecMainCode") != "0"
            or direct.get("ExecMainStatus") != "0"
            or direct.get("ActiveState") != "active"
            or direct.get("SubState") != "running"
            or main_pid <= 0
        ):
            raise EvidenceError(f"{label} direct validator service is not healthy")
        if re.fullmatch(r"[0-9A-Fa-f]{32}", invocation_id) is None:
            raise EvidenceError(
                f"{label} direct validator service has no valid InvocationID"
            )
    elif (
        direct.get("Result") != "success"
        or direct.get("ExecMainCode") not in {"0", "1"}
        or direct.get("ExecMainStatus") != "0"
        or direct.get("ActiveState") != "inactive"
        or direct.get("SubState") != "dead"
        or main_pid != 0
        or (
            invocation_id != ""
            and re.fullmatch(r"[0-9A-Fa-f]{32}", invocation_id) is None
        )
    ):
        raise EvidenceError(
            f"{label} direct validator service is not proven safely stopped"
        )

    boot_blocks = _systemd_show_blocks(
        _read_regular(
            artifacts_dir / "boot_reconcile_show.txt",
            label=f"{label} boot reconcile state",
        ),
        label=f"{label} boot reconcile state",
    )
    if len(boot_blocks) != 1:
        raise EvidenceError(
            f"{label} boot reconcile state has multiple property blocks"
        )
    boot = boot_blocks[0]
    if (
        boot.get("Result") != "success"
        or boot.get("ExecMainCode") not in {"0", "1"}
        or boot.get("ExecMainStatus") != "0"
        or boot.get("ActiveState") != "inactive"
        or boot.get("SubState") != "dead"
        or boot.get("MainPID") != "0"
    ):
        raise EvidenceError(f"{label} boot reconcile service is not settled")

    updater_blocks = _systemd_show_blocks(
        _read_regular(
            artifacts_dir / "updater_services_show.txt",
            label=f"{label} updater service states",
        ),
        label=f"{label} updater service states",
    )
    updater_by_id = {block.get("Id"): block for block in updater_blocks}
    expected_updaters = {
        "cathedral-validator-canary-update.service",
        "cathedral-validator-update.service",
    }
    if (
        len(updater_blocks) != len(expected_updaters)
        or set(updater_by_id) != expected_updaters
        or any(
            block.get("Result") != "success"
            or block.get("ExecMainCode") not in {"0", "1"}
            or block.get("ExecMainStatus") != "0"
            or block.get("ActiveState") != "inactive"
            or block.get("SubState") != "dead"
            or block.get("MainPID") != "0"
            for block in updater_by_id.values()
        )
    ):
        raise EvidenceError(f"{label} updater services are not successful and settled")

    timer_blocks = _systemd_show_blocks(
        _read_regular(artifacts_dir / "timers_show.txt", label=f"{label} timer states"),
        label=f"{label} timer states",
    )
    timers_by_id = {block.get("Id"): block for block in timer_blocks}
    expected_timers = {
        "cathedral-validator-canary-update.timer",
        "cathedral-validator-update.timer",
    }
    if (
        len(timer_blocks) != len(expected_timers)
        or set(timers_by_id) != expected_timers
        or any(
            block.get("UnitFileState") != "disabled"
            or block.get("ActiveState") != "inactive"
            or block.get("SubState") != "dead"
            for block in timers_by_id.values()
        )
    ):
        raise EvidenceError(f"{label} updater timers are not disabled and settled")
    return {"main_pid": main_pid, "invocation_id": invocation_id}


def _validate_final_updater_state(
    value: Any, *, label: str, channel: str, expected_record: dict[str, Any]
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "selected_channel",
        "channels",
        "pending",
    }:
        raise EvidenceError(f"{label} updater state has unexpected or missing fields")
    channels = value.get("channels")
    if (
        value.get("schema") != "cathedral_validator_updater_state_v3"
        or value.get("selected_channel") != channel
        or value.get("pending") is not None
        or not isinstance(channels, dict)
        or set(channels) != {channel}
    ):
        raise EvidenceError(f"{label} updater state is not settled for {channel}")
    if channels[channel] != expected_record:
        raise EvidenceError(
            f"{label} updater channel record does not match retained signed metadata"
        )


def verify_capture(args: argparse.Namespace) -> int:
    manifest = _load_capture_manifest(args.manifest)
    complete, errors = _capture_manifest_complete(manifest, args.artifacts_dir)
    if not complete or manifest.get("complete") is not True:
        detail = "; ".join(errors) if errors else "manifest is not complete"
        raise EvidenceError(f"capture manifest is incomplete: {detail}")
    return 0


def _single_ascii_line(root: Path, relative: str, *, label: str) -> str:
    data = _read_regular(root / relative, label=label, require_nonempty=True)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"{label} must be ASCII") from exc
    if not text.endswith("\n") or not text[:-1] or "\n" in text[:-1]:
        raise EvidenceError(f"{label} must contain exactly one non-empty line")
    return text[:-1]


def _validate_recorded_steps(root: Path) -> list[dict[str, str | int]]:
    data = _read_regular(
        root / "steps.log", label="scenario steps", require_nonempty=True
    )
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EvidenceError("scenario steps must be ASCII") from exc
    if not text.endswith("\n"):
        raise EvidenceError("scenario steps must end with a newline")
    lines = text.splitlines()
    if len(lines) != len(RECORDED_STEPS):
        raise EvidenceError(
            f"scenario steps must contain exactly {len(RECORDED_STEPS)} records"
        )
    rows: list[dict[str, str | int]] = []
    for index, (line, expected_message) in enumerate(
        zip(lines, RECORDED_STEPS, strict=True), start=1
    ):
        timestamp, separator, message = line.partition(" ")
        if separator != " " or message != expected_message:
            raise EvidenceError(
                f"scenario step {index} is missing, reordered, or unexpected"
            )
        _validate_utc_seconds(timestamp, label=f"scenario step {index} timestamp")
        rows.append({"index": index, "recorded_at": timestamp, "record_step": message})
    return rows


def _scenario_artifact_path(template: str, *, run_id: str) -> str:
    relative = template.format(run_id=run_id)
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise EvidenceError(f"scenario artifact path is unsafe: {relative}")
    return path.as_posix()


def _validate_negative_updater_state(
    value: Any,
    *,
    label: str,
    archive_sha256: str,
    sequence: int,
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "channel",
        "current",
        "record",
        "sequence",
        "pending",
    }:
        raise EvidenceError(f"{label} has an invalid updater-state shape")
    record = value.get("record")
    if not isinstance(record, dict) or set(record) != {
        "sequence",
        "archive_sha256",
        "signed_sha256",
        "metadata_sha256",
    }:
        raise EvidenceError(f"{label} has an invalid channel record")
    if (
        value.get("channel") != "canary"
        or value.get("current") != f"releases/{archive_sha256}"
        or type(value.get("sequence")) is not int
        or value.get("sequence") != sequence
        or value.get("pending") is not None
        or type(record.get("sequence")) is not int
        or record.get("sequence") != sequence
        or record.get("archive_sha256") != archive_sha256
        or any(
            type(record.get(field)) is not str
            or HEX_64.fullmatch(record[field]) is None
            for field in ("signed_sha256", "metadata_sha256")
        )
    ):
        raise EvidenceError(f"{label} does not prove the expected settled release")


def _validate_negative_service_identity(data: bytes, *, label: str) -> dict[str, str]:
    blocks = _systemd_show_blocks(data, label=label)
    if len(blocks) != 1 or set(blocks[0]) != {
        "ActiveState",
        "SubState",
        "MainPID",
        "InvocationID",
    }:
        raise EvidenceError(f"{label} has an invalid direct-service identity")
    identity = blocks[0]
    if (
        identity.get("ActiveState") != "active"
        or identity.get("SubState") != "running"
        or re.fullmatch(r"[1-9][0-9]*", identity.get("MainPID", "")) is None
        or re.fullmatch(r"[0-9A-Fa-f]{32}", identity.get("InvocationID", "")) is None
    ):
        raise EvidenceError(f"{label} does not prove a healthy direct service")
    return identity


def _validate_current_release_proof(
    data: bytes, *, label: str, archive_sha256: str
) -> None:
    expected = f"expected={archive_sha256} observed={archive_sha256}\n".encode("ascii")
    if data != expected:
        raise EvidenceError(f"{label} does not prove the expected current release")


def _validate_negative_scenario_invariants(root: Path, control: dict[str, Any]) -> None:
    for label, archive_field, sequence, service_policy in NEGATIVE_SCENARIO_INVARIANTS:
        archive_sha256 = control[archive_field]
        before_state_data = _read_regular(
            root / f"{label}-before.json",
            label=f"negative scenario {label} before state",
            require_nonempty=True,
        )
        after_state_data = _read_regular(
            root / f"{label}-after.json",
            label=f"negative scenario {label} after state",
            require_nonempty=True,
        )
        before_state = strict_json(
            before_state_data,
            label=f"negative scenario {label} before state",
            canonical=True,
        )
        after_state = strict_json(
            after_state_data,
            label=f"negative scenario {label} after state",
            canonical=True,
        )
        _validate_negative_updater_state(
            before_state,
            label=f"negative scenario {label} before state",
            archive_sha256=archive_sha256,
            sequence=sequence,
        )
        _validate_negative_updater_state(
            after_state,
            label=f"negative scenario {label} after state",
            archive_sha256=archive_sha256,
            sequence=sequence,
        )
        if before_state_data != after_state_data:
            raise EvidenceError(f"negative scenario {label} changed updater state")

        before_service_data = _read_regular(
            root / f"{label}-service-before.txt",
            label=f"negative scenario {label} before service identity",
            require_nonempty=True,
        )
        after_service_data = _read_regular(
            root / f"{label}-service-after.txt",
            label=f"negative scenario {label} after service identity",
            require_nonempty=True,
        )
        before_service = _validate_negative_service_identity(
            before_service_data,
            label=f"negative scenario {label} before service identity",
        )
        after_service = _validate_negative_service_identity(
            after_service_data,
            label=f"negative scenario {label} after service identity",
        )
        if service_policy == "unchanged":
            if before_service_data != after_service_data:
                raise EvidenceError(
                    f"negative scenario {label} changed direct-service identity"
                )
        elif (
            before_service["InvocationID"].lower()
            == after_service["InvocationID"].lower()
        ):
            raise EvidenceError(
                f"negative scenario {label} lacks a fresh rollback service invocation"
            )

    for relative, archive_field in CURRENT_RELEASE_PROOFS:
        _validate_current_release_proof(
            _read_regular(
                root / relative,
                label=f"negative scenario current proof {relative}",
                require_nonempty=True,
            ),
            label=f"negative scenario current proof {relative}",
            archive_sha256=control[archive_field],
        )


def _scenario_matrix(root: Path, control: dict[str, Any]) -> dict[str, Any]:
    run_id = control["run_id"]
    steps = _validate_recorded_steps(root)
    scenarios: list[dict[str, Any]] = []
    if len(SCENARIO_SPECS) != len(steps):
        raise EvidenceError("internal scenario matrix does not match the step contract")
    for step, (scenario_id, expected_step, artifacts) in zip(
        steps, SCENARIO_SPECS, strict=True
    ):
        if step["record_step"] != expected_step:
            raise EvidenceError("internal scenario matrix step mismatch")
        artifact_rows: list[dict[str, Any]] = []
        for template, empty_allowed in artifacts:
            relative = _scenario_artifact_path(template, run_id=run_id)
            data = _read_regular(
                root / relative,
                label=f"scenario artifact {scenario_id}:{relative}",
                require_nonempty=not empty_allowed,
            )
            artifact_rows.append(
                {
                    "path": relative,
                    "empty_allowed": empty_allowed,
                    "bytes": len(data),
                    "sha256": _sha256(data),
                }
            )
        scenarios.append(
            {
                "id": scenario_id,
                "step": step,
                "artifacts": artifact_rows,
            }
        )
    _validate_negative_scenario_invariants(root, control)
    return {"schema": SCENARIO_MATRIX_SCHEMA, "scenarios": scenarios}


def _property_values(data: bytes, *, label: str) -> dict[str, list[str]]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"{label} is not UTF-8") from exc
    values: dict[str, list[str]] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)=(.*)", line)
        if match is not None:
            values.setdefault(match.group(1), []).append(match.group(2))
    return values


def _one_property(values: dict[str, list[str]], key: str, *, label: str) -> str:
    observed = values.get(key, [])
    if len(observed) != 1:
        raise EvidenceError(f"{label} must contain exactly one {key}")
    return observed[0]


def _one_timer_schedule_value(data: bytes, key: str) -> str:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise EvidenceError("reactivation timer schedule is not UTF-8") from exc
    observed = re.findall(
        rf"(?:^|[ {{;]){re.escape(key)}=([^ ;}}\n]+)", text, flags=re.MULTILINE
    )
    if len(observed) != 1:
        raise EvidenceError(f"reactivation start must contain exactly one {key}")
    return observed[0]


def _timer_is_rearmed(*, active: str, substate: str, next_elapse: str) -> bool:
    return (
        active == "active"
        and substate == "waiting"
        and next_elapse not in {"", "0", "infinity", "n/a"}
    )


def _last_reactivation_snapshot(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise EvidenceError(
            "same-boot timer reactivation wait proof is not UTF-8"
        ) from exc
    snapshots: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)=(.*)", line)
        if match is None:
            continue
        key, value = match.groups()
        if key == "ActiveState" and current:
            snapshots.append(current)
            current = {}
        if key in current:
            raise EvidenceError(
                "same-boot timer reactivation wait proof has duplicate properties"
            )
        current[key] = value
    if current:
        snapshots.append(current)
    if not snapshots:
        raise EvidenceError("same-boot timer reactivation wait proof has no snapshots")
    return snapshots[-1]


def _last_json_line(data: bytes, *, label: str) -> dict[str, Any]:
    lines = [line for line in data.splitlines() if line]
    if not lines:
        raise EvidenceError(f"{label} contains no JSON snapshots")
    value = strict_json(lines[-1] + b"\n", label=label)
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} final snapshot is not an object")
    return value


def _validate_repository(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{label} must be one safe owner/repository")
    parts = value.split("/")
    if (
        len(parts) != 2
        or any(SAFE_REPOSITORY_COMPONENT.fullmatch(part) is None for part in parts)
        or any(part in {".", ".."} or part.endswith(".git") for part in parts)
    ):
        raise EvidenceError(f"{label} must be one safe owner/repository")
    return value


def _validate_control(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != CONTROL_FIELDS:
        raise EvidenceError("control document has unexpected or missing fields")
    run_id = value.get("run_id")
    source_revision_b = value.get("source_revision_b")
    source_repository = _validate_repository(
        value.get("source_repository"), label="control source repository"
    )
    test_repository = _validate_repository(
        value.get("test_publication_repository"),
        label="control test publication repository",
    )
    fixed_values = {
        "schema": "cathedral_validator_live_update_control_v1",
        "gcp_project": "polaris-tdx-attest",
        "controller_transport": "gcp_iap_tcp_forwarding",
        "iap_source_range": "35.235.240.0/20",
        "vm_service_account_attached": False,
        "machine_type": "e2-standard-2",
        "vm_count": 2,
        "max_run_seconds": 14400,
        "vm_and_disk_estimate_usd": "0.6240",
        "network_ipv4_and_egress_allowance_usd": "0.20",
        "planning_total_usd": "0.8240",
        "cost_scope": CONTROL_COST_SCOPE,
        "source_repository": "cathedralai/cathedral-validator",
        "canonical_source_write_allowed": False,
        "bootstrap_track": "test",
        "bootstrap_transport": "anonymous_immutable_github_release",
        "anonymous_bootstrap_download_required": True,
        "stable_host_configuration": (
            "cathedral-validator-setup from the signed bootstrap"
        ),
        "stable_host_status_command": "cathedral-validator-status --json",
        "canary_host_configuration": (
            "internal direct updater first install; not a public operating mode"
        ),
        "operator_hotkey_shape": (
            "disposable bittensor-wallet keyfile, unregistered, never recorded"
        ),
        "bootstrap_assets": (
            "reviewed deploy assets with both channel URLs rewritten to the "
            "isolated mirror branches"
        ),
        "fixed_channel_cache_max_seconds": 300,
        "update_timer_interval_seconds": 60,
        "fixed_channel_wait_seconds": 1860,
    }
    for field, expected in fixed_values.items():
        observed = value.get(field)
        if type(observed) is not type(expected) or observed != expected:
            raise EvidenceError(f"control document has an invalid {field}")
    if (
        not isinstance(run_id, str)
        or SAFE_RUN_ID.fullmatch(run_id) is None
        or not isinstance(value.get("zone"), str)
        or SAFE_ZONE.fullmatch(value["zone"]) is None
        or test_repository.casefold() == source_repository.casefold()
        or not isinstance(source_revision_b, str)
        or REVISION.fullmatch(source_revision_b) is None
        or value.get("test_mirror_main_sha") != source_revision_b
    ):
        raise EvidenceError("control document has an invalid run or execution boundary")
    for field, pattern in (
        ("source_revision_a", REVISION),
        ("source_revision_b", REVISION),
        ("archive_a_sha256", HEX_64),
        ("archive_b_sha256", HEX_64),
        ("no_chain_harness_sha256", HEX_64),
        ("fault_origin_sha256", HEX_64),
        ("state_waiter_sha256", HEX_64),
    ):
        observed = value.get(field)
        if not isinstance(observed, str) or pattern.fullmatch(observed) is None:
            raise EvidenceError(f"control document has an invalid {field}")
    if value["source_revision_a"] == source_revision_b:
        raise EvidenceError("control document source revisions must be distinct")
    if value["archive_a_sha256"] == value["archive_b_sha256"]:
        raise EvidenceError("control document release archives must be distinct")
    for field in ("bootstrap_key_fingerprint", "runtime_key_fingerprint"):
        observed = value.get(field)
        if (
            not isinstance(observed, str)
            or not observed.startswith("sha256:")
            or HEX_64.fullmatch(observed.removeprefix("sha256:")) is None
        ):
            raise EvidenceError(f"control document has an invalid {field}")
    if value["bootstrap_key_fingerprint"] == value["runtime_key_fingerprint"]:
        raise EvidenceError("control document release signing keys must be distinct")
    guided = value.get("guided_operator")
    if not isinstance(guided, dict) or set(guided) != {
        "setup",
        "status",
        "operator_inputs",
        "terminal_expectation",
    }:
        raise EvidenceError("control document has an invalid guided_operator")
    reviewed_root = Path(__file__).resolve().parents[1] / "deploy" / "validator-update"
    expected_guided_assets = {
        "setup": {
            "source_sha256": _sha256(
                _read_regular(
                    reviewed_root / "cathedral-validator-setup",
                    label="reviewed guided setup source",
                    require_nonempty=True,
                )
            ),
            "installed_path": "/usr/local/sbin/cathedral-validator-setup",
        },
        "status": {
            "source_sha256": _sha256(
                _read_regular(
                    reviewed_root / "cathedral-validator-status",
                    label="reviewed guided status source",
                    require_nonempty=True,
                )
            ),
            "installed_path": "/usr/local/sbin/cathedral-validator-status",
        },
    }
    for name, expected in expected_guided_assets.items():
        _require_exact_object(
            guided.get(name), expected, label=f"control guided_operator {name}"
        )
    operator_inputs = guided.get("operator_inputs")
    if not isinstance(operator_inputs, dict) or set(operator_inputs) != {
        "hotkey_keyfile_sha256",
        "snp_policy_sha256",
        "raw_key_material_recorded",
    }:
        raise EvidenceError("control guided_operator operator_inputs is invalid")
    input_digests = (
        operator_inputs.get("hotkey_keyfile_sha256"),
        operator_inputs.get("snp_policy_sha256"),
    )
    if (
        any(
            not isinstance(digest, str) or HEX_64.fullmatch(digest) is None
            for digest in input_digests
        )
        or input_digests[0] == input_digests[1]
        or operator_inputs.get("raw_key_material_recorded") is not False
        or guided.get("terminal_expectation") != "stopped_writer_needs_review"
    ):
        raise EvidenceError("control guided_operator boundary is invalid")
    expected_branches = {
        "canary_branch": f"validator-release-live-{run_id}-canary",
        "stable_branch": f"validator-release-live-{run_id}-stable",
        "fault_branch": f"validator-release-fault-{run_id}",
    }
    for field, expected in expected_branches.items():
        if value.get(field) != expected:
            raise EvidenceError(f"control document has an invalid {field}")
    bootstrap_tag = value.get("bootstrap_tag")
    if (
        not isinstance(bootstrap_tag, str)
        or re.fullmatch(
            r"validator-bootstrap-test-s[1-9][0-9]*-[0-9a-f]{64}", bootstrap_tag
        )
        is None
    ):
        raise EvidenceError("control document has an invalid bootstrap_tag")
    signer = value.get("result_signer")
    if not isinstance(signer, dict) or set(signer) != {
        "purpose",
        "key_id",
        "algorithm",
        "public_key_fingerprint",
    }:
        raise EvidenceError("control document has an invalid result_signer")
    key_id = signer.get("key_id")
    fingerprint = signer.get("public_key_fingerprint")
    if (
        signer.get("purpose") != SIGNER_PURPOSE
        or signer.get("algorithm") != SIGNER_ALGORITHM
        or not isinstance(key_id, str)
        or SAFE_KEY_ID.fullmatch(key_id) is None
        or not isinstance(fingerprint, str)
        or not fingerprint.startswith("sha256:")
        or HEX_64.fullmatch(fingerprint.removeprefix("sha256:")) is None
        or fingerprint
        in {value["bootstrap_key_fingerprint"], value["runtime_key_fingerprint"]}
    ):
        raise EvidenceError("control document has an invalid result_signer")
    return value


def _instance_identity(
    value: Any, *, expected_name: str, control: dict[str, Any], label: str
) -> str:
    if not isinstance(value, dict) or value.get("name") != expected_name:
        raise EvidenceError(f"{label} has the wrong instance name")
    instance_id = value.get("id")
    if isinstance(instance_id, int) and not isinstance(instance_id, bool):
        instance_id = str(instance_id)
    if (
        not isinstance(instance_id, str)
        or re.fullmatch(r"[1-9][0-9]*", instance_id) is None
    ):
        raise EvidenceError(f"{label} has no immutable instance id")
    zone = value.get("zone")
    if not isinstance(zone, str) or not (
        zone == control["zone"] or zone.endswith(f"/zones/{control['zone']}")
    ):
        raise EvidenceError(f"{label} has the wrong zone")
    labels = value.get("labels")
    if (
        not isinstance(labels, dict)
        or labels.get("cathedral-live-run") != control["run_id"]
    ):
        raise EvidenceError(f"{label} has the wrong run label")
    service_accounts = value.get("serviceAccounts")
    if service_accounts not in (None, []):
        raise EvidenceError(f"{label} unexpectedly has a service account")
    return instance_id


def _instance_inventory(
    value: Any, *, control: dict[str, Any], label: str
) -> dict[str, str]:
    if not isinstance(value, list) or len(value) != 2:
        raise EvidenceError(f"{label} does not contain exactly two hosts")
    identities: dict[str, str] = {}
    for row in value:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise EvidenceError(f"{label} has a malformed host")
        name = row["name"]
        if name in identities:
            raise EvidenceError(f"{label} contains a duplicate host")
        identities[name] = _instance_identity(
            row,
            expected_name=name,
            control=control,
            label=f"{label}:{name}",
        )
    expected_names = {
        f"catval-{control['run_id']}-canary",
        f"catval-{control['run_id']}-stable",
    }
    if set(identities) != expected_names:
        raise EvidenceError(f"{label} has the wrong host set")
    return identities


def _retained_ed25519_key(root: Path, relative: str, *, label: str) -> dict[str, Any]:
    pem = _read_regular(root / relative, label=label, require_nonempty=True)
    try:
        public = serialization.load_pem_public_key(pem)
    except ValueError as exc:
        raise EvidenceError(f"{label} is invalid") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise EvidenceError(f"{label} must use Ed25519")
    canonical_pem = public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if pem != canonical_pem:
        raise EvidenceError(f"{label} is not one canonical public PEM")
    der = public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw = public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "public": public,
        "pem": pem,
        "raw": raw,
        "fingerprint": f"sha256:{_sha256(der)}",
    }


def _decoded_signature(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise EvidenceError(f"{label} is invalid")
    try:
        signature = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise EvidenceError(f"{label} is invalid") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != value:
        raise EvidenceError(f"{label} is invalid")
    return signature


def _runtime_metadata_record(
    root: Path,
    *,
    name: str,
    channel: str,
    sequence: int,
    archive_field: str,
    control: dict[str, Any],
    public: Ed25519PublicKey,
) -> dict[str, Any]:
    label = f"retained runtime metadata {name}"
    raw = _read_regular(
        root / "signed-runtime-metadata" / name,
        label=label,
        require_nonempty=True,
    )
    envelope = strict_json(raw, label=label, canonical=True)
    if not isinstance(envelope, dict) or set(envelope) != {"signed", "signature"}:
        raise EvidenceError(f"{label} has unexpected or missing fields")
    signed = envelope.get("signed")
    if not isinstance(signed, dict) or set(signed) != {
        "schema",
        "channel",
        "sequence",
        "issued_unix",
        "expires_unix",
        "release",
    }:
        raise EvidenceError(f"{label} has an invalid signed payload")
    signature = _decoded_signature(
        envelope.get("signature"), label=f"{label} signature"
    )
    signed_bytes = canonical_bytes(signed)
    try:
        public.verify(signature, signed_bytes)
    except InvalidSignature as exc:
        raise EvidenceError(f"{label} signature is invalid") from exc
    issued_unix = signed.get("issued_unix")
    expires_unix = signed.get("expires_unix")
    if (
        signed.get("schema") != RUNTIME_METADATA_SCHEMA
        or signed.get("channel") != channel
        or type(signed.get("sequence")) is not int
        or signed["sequence"] != sequence
        or type(issued_unix) is not int
        or issued_unix < 1
        or type(expires_unix) is not int
        or expires_unix - issued_unix != RUNTIME_METADATA_LIFETIME_SECONDS
    ):
        raise EvidenceError(f"{label} identity or validity window is invalid")
    release = signed.get("release")
    expected_release_fields = {
        "version",
        "archive_url",
        "archive_sha256",
        "tree_sha256",
        "entrypoint",
    }
    if channel == "stable":
        expected_release_fields.add("promoted_canary")
    if not isinstance(release, dict) or set(release) != expected_release_fields:
        raise EvidenceError(f"{label} has an invalid release payload")
    archive_sha256 = control[archive_field]
    expected_url = (
        f"https://github.com/{control['test_publication_repository']}/releases/"
        f"download/validator-{archive_sha256}/"
        f"cathedral-validator-{archive_sha256}.tar.gz"
    )
    version = release.get("version")
    tree_sha256 = release.get("tree_sha256")
    if (
        not isinstance(version, str)
        or not version
        or len(version) > 128
        or not version.isascii()
        or release.get("archive_url") != expected_url
        or release.get("archive_sha256") != archive_sha256
        or not isinstance(tree_sha256, str)
        or HEX_64.fullmatch(tree_sha256) is None
        or release.get("entrypoint") != RUNTIME_RELEASE_ENTRYPOINT
    ):
        raise EvidenceError(f"{label} does not identify its exact release")
    if channel == "stable":
        promoted = release.get("promoted_canary")
        if not isinstance(promoted, dict) or set(promoted) != {
            "sequence",
            "signed_sha256",
            "metadata_sha256",
            "archive_sha256",
        }:
            raise EvidenceError(f"{label} has an invalid canary promotion")
    base_release = {
        field: release[field]
        for field in (
            "version",
            "archive_url",
            "archive_sha256",
            "tree_sha256",
            "entrypoint",
        )
    }
    return {
        "raw": raw,
        "signed": signed,
        "signature": signature,
        "release": release,
        "base_release": base_release,
        "record": {
            "sequence": sequence,
            "archive_sha256": archive_sha256,
            "signed_sha256": _sha256(signed_bytes),
            "metadata_sha256": _sha256(raw),
        },
    }


def _validate_runtime_metadata(
    root: Path, control: dict[str, Any], public: Ed25519PublicKey
) -> dict[str, dict[str, Any]]:
    metadata_root = root / "signed-runtime-metadata"
    try:
        info = metadata_root.lstat()
    except FileNotFoundError as exc:
        raise EvidenceError("signed runtime metadata directory is missing") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise EvidenceError(
            "signed runtime metadata must be a regular non-symlink directory"
        )
    observed_names = {path.name for path in metadata_root.iterdir()}
    if observed_names != RUNTIME_METADATA_NAMES:
        raise EvidenceError("signed runtime metadata has an unexpected or missing file")

    records: dict[str, dict[str, Any]] = {}
    for name, channel, sequence, archive_field, _promotion in RUNTIME_METADATA_SPECS:
        records[name] = _runtime_metadata_record(
            root,
            name=name,
            channel=channel,
            sequence=sequence,
            archive_field=archive_field,
            control=control,
            public=public,
        )

    for group in (
        (
            "canary-a-seq1.json",
            "canary-a-equivocation-seq3.json",
            "canary-a-seq4.json",
        ),
        ("canary-b-seq2.json", "canary-b-renewal-seq3.json"),
    ):
        expected_release = records[group[0]]["base_release"]
        if any(records[name]["base_release"] != expected_release for name in group[1:]):
            raise EvidenceError("retained canary renewal changed the exact release")

    for name, _channel, _sequence, _archive_field, promotion in RUNTIME_METADATA_SPECS:
        if promotion is None:
            continue
        source = records[promotion]
        stable = records[name]
        expected_promotion = {
            "sequence": source["record"]["sequence"],
            "signed_sha256": source["record"]["signed_sha256"],
            "metadata_sha256": source["record"]["metadata_sha256"],
            "archive_sha256": source["record"]["archive_sha256"],
        }
        if (
            stable["base_release"] != source["base_release"]
            or stable["release"].get("promoted_canary") != expected_promotion
        ):
            raise EvidenceError(
                f"retained stable metadata {name} is not the exact promoted canary"
            )

    invalid_name = INVALID_RUNTIME_METADATA_NAME
    invalid_label = f"retained runtime metadata {invalid_name}"
    invalid_raw = _read_regular(
        metadata_root / invalid_name, label=invalid_label, require_nonempty=True
    )
    invalid = strict_json(invalid_raw, label=invalid_label, canonical=True)
    if not isinstance(invalid, dict) or set(invalid) != {"signed", "signature"}:
        raise EvidenceError(f"{invalid_label} has unexpected or missing fields")
    source = records["canary-b-seq2.json"]
    invalid_signature = _decoded_signature(
        invalid.get("signature"), label=f"{invalid_label} signature"
    )
    expected_invalid_signature = (
        bytes([source["signature"][0] ^ 1]) + source["signature"][1:]
    )
    if (
        invalid.get("signed") != source["signed"]
        or invalid_signature != expected_invalid_signature
    ):
        raise EvidenceError(
            "invalid-signature metadata is not the exact one-bit B2 mutation"
        )
    try:
        public.verify(invalid_signature, canonical_bytes(invalid["signed"]))
    except InvalidSignature:
        pass
    else:
        raise EvidenceError("invalid-signature metadata unexpectedly verifies")
    return records


def _validate_first_install_state_evidence(
    root: Path, control: dict[str, Any], records: dict[str, dict[str, Any]]
) -> None:
    for channel, name in (
        ("canary", "canary-a-seq1.json"),
        ("stable", "stable-a-seq1.json"),
    ):
        relative = f"{channel}-first-install-sequence-state.json"
        state = strict_json(
            _read_regular(
                root / relative,
                label=f"first-install {channel} updater state",
                require_nonempty=True,
            ),
            label=f"first-install {channel} updater state",
            canonical=True,
        )
        _require_exact_object(
            state,
            {
                "channel": channel,
                "current": f"releases/{control['archive_a_sha256']}",
                "record": records[name]["record"],
                "sequence": 1,
                "pending": None,
            },
            label=f"first-install {channel} updater state",
        )


def _validate_bootstrap_manifest_files(
    value: Any, *, runtime_public_pem: bytes, control: dict[str, Any]
) -> None:
    if not isinstance(value, list) or not value:
        raise EvidenceError("bootstrap manifest files must be a non-empty list")
    paths: list[str] = []
    retained_entries: dict[str, dict[str, Any]] = {}
    retained_paths = {
        RUNTIME_KEY_BUNDLE_PATH,
        "payload/operator/cathedral-validator-setup",
        "payload/operator/cathedral-validator-status",
    }
    for index, entry in enumerate(value):
        label = f"bootstrap manifest file {index}"
        if not isinstance(entry, dict) or set(entry) != {
            "mode",
            "path",
            "sha256",
            "size",
        }:
            raise EvidenceError(f"{label} has unexpected or missing fields")
        path_value = entry.get("path")
        path = PurePosixPath(path_value) if isinstance(path_value, str) else None
        if (
            path is None
            or path.is_absolute()
            or not path.parts
            or path == PurePosixPath(".")
            or ".." in path.parts
            or path.as_posix() != path_value
            or not isinstance(entry.get("mode"), str)
            or re.fullmatch(r"0[0-7]{3}", entry["mode"]) is None
            or not isinstance(entry.get("sha256"), str)
            or HEX_64.fullmatch(entry["sha256"]) is None
            or type(entry.get("size")) is not int
            or entry["size"] < 0
        ):
            raise EvidenceError(f"{label} is invalid")
        paths.append(path_value)
        if path_value in retained_paths:
            retained_entries[path_value] = entry
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise EvidenceError("bootstrap manifest file paths are not unique and sorted")
    if retained_entries.get(RUNTIME_KEY_BUNDLE_PATH) != {
        "mode": "0644",
        "path": RUNTIME_KEY_BUNDLE_PATH,
        "sha256": _sha256(runtime_public_pem),
        "size": len(runtime_public_pem),
    }:
        raise EvidenceError(
            "bootstrap manifest does not embed the retained runtime public key"
        )
    reviewed_root = Path(__file__).resolve().parents[1] / "deploy" / "validator-update"
    for name in ("cathedral-validator-setup", "cathedral-validator-status"):
        reviewed = _read_regular(
            reviewed_root / name,
            label=f"reviewed bootstrap operator asset {name}",
            require_nonempty=True,
        )
        archive_path = f"payload/operator/{name}"
        expected = {
            "mode": "0644",
            "path": archive_path,
            "sha256": control["guided_operator"][
                "setup" if name.endswith("setup") else "status"
            ]["source_sha256"],
            "size": len(reviewed),
        }
        if (
            expected["sha256"] != _sha256(reviewed)
            or retained_entries.get(archive_path) != expected
        ):
            raise EvidenceError(
                f"bootstrap manifest does not embed the reviewed {name}"
            )


def _validate_bootstrap_evidence(
    root: Path,
    control: dict[str, Any],
    *,
    runtime_key: dict[str, Any],
    bootstrap_key: dict[str, Any],
    records: dict[str, dict[str, Any]],
) -> None:
    manifest_raw = _read_regular(
        root / "updater-bootstrap.manifest.json",
        label="bootstrap manifest",
        require_nonempty=True,
    )
    manifest = strict_json(manifest_raw, label="bootstrap manifest", canonical=True)
    if not isinstance(manifest, dict) or set(manifest) != {
        "bundle",
        "files",
        "install",
        "bootstrap_signing_key",
        "bootstrap_metadata",
        "runtime_release_key",
        "stable_release_floor",
        "schema",
    }:
        raise EvidenceError("bootstrap manifest has unexpected or missing fields")
    if manifest.get("schema") != BOOTSTRAP_MANIFEST_SCHEMA:
        raise EvidenceError("bootstrap manifest has the wrong schema")
    bundle = manifest.get("bundle")
    if (
        not isinstance(bundle, dict)
        or set(bundle) != {"sha256", "size"}
        or not isinstance(bundle.get("sha256"), str)
        or HEX_64.fullmatch(bundle["sha256"]) is None
        or type(bundle.get("size")) is not int
        or bundle["size"] < 1
    ):
        raise EvidenceError("bootstrap manifest bundle is invalid")
    _validate_bootstrap_manifest_files(
        manifest.get("files"),
        runtime_public_pem=runtime_key["pem"],
        control=control,
    )
    _require_exact_object(
        manifest.get("install"),
        {
            "enable_units": False,
            "installer": "payload/installer/install_updater_bundle.py",
            "python": "CPython==3.12.*",
            "requirements": "payload/requirements.txt",
            "wheelhouse": "payload/wheelhouse",
        },
        label="bootstrap manifest install policy",
    )
    _require_exact_object(
        manifest.get("bootstrap_signing_key"),
        {
            "algorithm": "Ed25519",
            "fingerprint": bootstrap_key["fingerprint"],
            "source": "operator-pinned-external",
        },
        label="bootstrap manifest signing key",
    )
    metadata = manifest.get("bootstrap_metadata")
    if (
        not isinstance(metadata, dict)
        or set(metadata) != {"expires_unix", "issued_unix", "sequence"}
        or type(metadata.get("issued_unix")) is not int
        or metadata["issued_unix"] < 1
        or type(metadata.get("expires_unix")) is not int
        or metadata["expires_unix"] - metadata["issued_unix"]
        != BOOTSTRAP_LIFETIME_SECONDS
        or type(metadata.get("sequence")) is not int
        or metadata["sequence"] != 1
    ):
        raise EvidenceError("bootstrap manifest metadata is invalid")
    _require_exact_object(
        manifest.get("runtime_release_key"),
        {
            "algorithm": "Ed25519",
            "fingerprint": runtime_key["fingerprint"],
            "path": RUNTIME_KEY_BUNDLE_PATH,
        },
        label="bootstrap manifest runtime release key",
    )
    _require_exact_object(
        manifest.get("stable_release_floor"),
        {
            "metadata_sha256": records["stable-a-seq1.json"]["record"][
                "metadata_sha256"
            ],
            "sequence": 1,
        },
        label="bootstrap manifest stable release floor",
    )
    manifest_signature = _read_regular(
        root / "updater-bootstrap.manifest.sig",
        label="bootstrap manifest signature",
        require_nonempty=True,
    )
    if len(manifest_signature) != 64:
        raise EvidenceError("bootstrap manifest signature is invalid")
    try:
        bootstrap_key["public"].verify(manifest_signature, manifest_raw)
    except InvalidSignature as exc:
        raise EvidenceError("bootstrap manifest signature is invalid") from exc

    build_raw = _read_regular(
        root / "bootstrap-build.json",
        label="bootstrap build record",
        require_nonempty=True,
    )
    build = strict_json(build_raw, label="bootstrap build record", canonical=True)
    if not isinstance(build, dict) or set(build) != {
        "bundle_sha256",
        "manifest_sha256",
        "bootstrap_sequence",
        "bootstrap_signing_key_fingerprint",
        "runtime_release_key_fingerprint",
        "stable_release_minimum_sequence",
        "signature_base64",
    }:
        raise EvidenceError("bootstrap build record has unexpected or missing fields")
    encoded_signature = base64.b64encode(manifest_signature).decode("ascii")
    expected_build = {
        "bundle_sha256": bundle["sha256"],
        "manifest_sha256": _sha256(manifest_raw),
        "bootstrap_sequence": 1,
        "bootstrap_signing_key_fingerprint": bootstrap_key["fingerprint"],
        "runtime_release_key_fingerprint": runtime_key["fingerprint"],
        "stable_release_minimum_sequence": 1,
        "signature_base64": encoded_signature,
    }
    _require_exact_object(build, expected_build, label="bootstrap build record")
    expected_tag = f"validator-bootstrap-test-s1-{expected_build['manifest_sha256']}"
    if control["bootstrap_tag"] != expected_tag:
        raise EvidenceError("control bootstrap tag does not bind the retained manifest")

    publication_raw = _read_regular(
        root / "bootstrap-publication.json",
        label="bootstrap publication record",
        require_nonempty=True,
    )
    publication = strict_json(publication_raw, label="bootstrap publication record")
    if not isinstance(publication, dict) or set(publication) != {
        "schema",
        "source_repository",
        "publication_repository",
        "canonical_source_write_allowed",
        "track",
        "tag",
        "target_revision",
        "sequence",
        "bootstrap_key_fingerprint",
        "runtime_key_fingerprint",
        "anonymous_download_required",
        "assets",
    }:
        raise EvidenceError(
            "bootstrap publication record has unexpected or missing fields"
        )
    base_url = (
        f"https://github.com/{control['test_publication_repository']}/releases/"
        f"download/{expected_tag}"
    )
    expected_publication = {
        "schema": BOOTSTRAP_PUBLICATION_SCHEMA,
        "source_repository": control["source_repository"],
        "publication_repository": control["test_publication_repository"],
        "canonical_source_write_allowed": False,
        "track": "test",
        "tag": expected_tag,
        "target_revision": control["source_revision_b"],
        "sequence": 1,
        "bootstrap_key_fingerprint": bootstrap_key["fingerprint"],
        "runtime_key_fingerprint": runtime_key["fingerprint"],
        "anonymous_download_required": True,
        "assets": {
            "bundle": {
                "url": f"{base_url}/updater-bootstrap.tar.gz",
                "sha256": bundle["sha256"],
            },
            "manifest": {
                "url": f"{base_url}/updater-bootstrap.manifest.json",
                "sha256": _sha256(manifest_raw),
            },
            "signature": {
                "url": f"{base_url}/updater-bootstrap.manifest.sig",
                "sha256": _sha256(manifest_signature),
            },
            "public_key": {
                "url": f"{base_url}/bootstrap-signing-public-key.pem",
                "sha256": _sha256(bootstrap_key["pem"]),
            },
        },
    }
    _require_exact_object(
        publication,
        expected_publication,
        label="bootstrap publication record",
    )


def _validate_release_and_bootstrap_evidence(
    root: Path, control: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    runtime_key = _retained_ed25519_key(
        root, "runtime-release-public-key.pem", label="runtime release public key"
    )
    bootstrap_key = _retained_ed25519_key(
        root, "bootstrap-release-public-key.pem", label="bootstrap release public key"
    )
    result_key = _retained_ed25519_key(
        root, RESULT_PUBLIC_KEY_NAME, label="retained result public key"
    )
    if len({runtime_key["raw"], bootstrap_key["raw"], result_key["raw"]}) != 3:
        raise EvidenceError(
            "runtime, bootstrap, and result public keys must be pairwise distinct"
        )
    expected_fingerprints = (
        ("runtime_key_fingerprint", runtime_key),
        ("bootstrap_key_fingerprint", bootstrap_key),
    )
    for field, key in expected_fingerprints:
        if control[field] != key["fingerprint"]:
            raise EvidenceError(f"retained public key differs from control {field}")
    if control["result_signer"]["public_key_fingerprint"] != result_key["fingerprint"]:
        raise EvidenceError(
            "retained result public key differs from the control fingerprint"
        )
    records = _validate_runtime_metadata(root, control, runtime_key["public"])
    _validate_first_install_state_evidence(root, control, records)
    _validate_bootstrap_evidence(
        root,
        control,
        runtime_key=runtime_key,
        bootstrap_key=bootstrap_key,
        records=records,
    )
    return records


def _guided_status_report(
    root: Path,
    *,
    relative: str,
    expected_result: str,
    expected_record: dict[str, Any],
    service_active: bool,
    timer_active: bool,
) -> None:
    label = f"guided operator status {relative}"
    raw = _read_regular(root / relative, label=label, require_nonempty=True)
    if not raw.endswith(b"\n") or b"\n" in raw[:-1]:
        raise EvidenceError(f"{label} must contain exactly one JSON line")
    report = strict_json(raw, label=label)
    expected_top_level = {
        "schema",
        "service_active",
        "stable_timer_active",
        "stable_timer_enabled",
        "release",
        "evidence",
        "updater",
        "direct",
        "result",
        "action",
    }
    if not isinstance(report, dict) or set(report) != expected_top_level:
        raise EvidenceError(f"{label} has unexpected or missing fields")
    expected_action = (
        "Inspect cathedral-validator-direct.service logs. Do not delete its journal."
        if expected_result == "NEEDS_REVIEW"
        else "Wait for recovery or the next cycle. Do not retry or replace the journal."
    )
    for field, expected in {
        "schema": "cathedral_validator_local_status_v1",
        "service_active": service_active,
        "stable_timer_active": timer_active,
        "stable_timer_enabled": timer_active,
        "release": expected_record["archive_sha256"],
        "evidence": (
            "local process and durable state only. This does not prove current "
            "chain inclusion."
        ),
        "result": expected_result,
        "action": expected_action,
    }.items():
        if type(report.get(field)) is not type(expected) or report[field] != expected:
            raise EvidenceError(f"{label} has an invalid {field}")
    _require_exact_object(
        report.get("updater"),
        {
            "channel": "stable",
            "sequence": expected_record["sequence"],
            "archive_digest": expected_record["archive_sha256"],
            "pending_recovery": False,
        },
        label=f"{label} updater",
    )
    direct = report.get("direct")
    if not isinstance(direct, dict) or set(direct) != {
        "pending",
        "last_result",
        "block_number",
        "recorded_age_seconds",
    }:
        raise EvidenceError(f"{label} direct state has unexpected or missing fields")
    age = direct.get("recorded_age_seconds")
    if (
        direct.get("pending") is not False
        or direct.get("last_result") is not None
        or direct.get("block_number") is not None
        or type(age) is not int
        or age < 0
    ):
        raise EvidenceError(f"{label} direct state is not the no-chain test state")
    if any(
        marker in raw
        for marker in (
            b"privateKey",
            b"secretPhrase",
            b"secretSeed",
            b"validator-hotkey",
        )
    ):
        raise EvidenceError(f"{label} exposes operator hotkey material")


def _guided_ascii_log(root: Path, relative: str) -> str:
    raw = _read_regular(
        root / relative,
        label=f"guided operator log {relative}",
        require_nonempty=True,
    )
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"guided operator log {relative} must be ASCII") from exc
    if not text.endswith("\n"):
        raise EvidenceError(f"guided operator log {relative} must end with a newline")
    if any(
        marker in text
        for marker in ("privateKey", "secretPhrase", "secretSeed", "validator-hotkey")
    ):
        raise EvidenceError(f"guided operator log {relative} exposes hotkey material")
    return text


GUIDED_DURABLE_DIGEST_FIELDS = (
    "updater_state_sha256",
    "setup_complete_sha256",
    "installed_hotkey_sha256",
    "update_env_sha256",
    "installed_snp_policy_sha256",
)


def _guided_transition_identity(
    value: Any, *, label: str, active: bool
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "main_pid",
        "invocation_id",
        "durable_sha256",
    }:
        raise EvidenceError(f"{label} has unexpected or missing fields")
    main_pid = value.get("main_pid")
    invocation_id = value.get("invocation_id")
    durable = value.get("durable_sha256")
    if type(main_pid) is not int or not isinstance(invocation_id, str):
        raise EvidenceError(f"{label} has an invalid service identity")
    if active:
        if main_pid <= 0 or re.fullmatch(r"[0-9A-Fa-f]{32}", invocation_id) is None:
            raise EvidenceError(f"{label} does not prove an active writer identity")
    elif main_pid != 0 or (
        invocation_id != "" and re.fullmatch(r"[0-9A-Fa-f]{32}", invocation_id) is None
    ):
        raise EvidenceError(f"{label} does not prove a stopped writer identity")
    if not isinstance(durable, dict) or tuple(sorted(durable)) != tuple(
        sorted(GUIDED_DURABLE_DIGEST_FIELDS)
    ):
        raise EvidenceError(f"{label} has unexpected durable-state fields")
    for field in GUIDED_DURABLE_DIGEST_FIELDS:
        digest = durable.get(field)
        if not isinstance(digest, str) or HEX_64.fullmatch(digest) is None:
            raise EvidenceError(f"{label} has an invalid {field}")
    return value


def _guided_transition_proof(
    root: Path,
    control: dict[str, Any],
    *,
    relative: str,
    schema: str,
    status_file: str,
    stopped_after: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    label = f"guided transition proof {relative}"
    proof = strict_json(
        _read_regular(root / relative, label=label, require_nonempty=True),
        label=label,
        canonical=True,
    )
    if not isinstance(proof, dict) or set(proof) != {
        "schema",
        "host",
        "guided_assets",
        "operator_inputs",
        "before",
        "after",
        "status",
        "outcomes",
    }:
        raise EvidenceError(f"{label} has unexpected or missing fields")
    expected_host = f"catval-{control['run_id']}-stable"
    if proof.get("schema") != schema or proof.get("host") != expected_host:
        raise EvidenceError(f"{label} has an invalid schema or host")

    guided = control["guided_operator"]
    expected_assets = {
        name: {
            "installed_path": guided[name]["installed_path"],
            "sha256": guided[name]["source_sha256"],
            "uid": 0,
            "gid": 0,
            "mode": "0755",
            "regular_file": True,
            "symlink": False,
        }
        for name in ("setup", "status")
    }
    assets = proof.get("guided_assets")
    if not isinstance(assets, dict) or set(assets) != set(expected_assets):
        raise EvidenceError(f"{label} guided assets has unexpected or missing fields")
    for name, expected in expected_assets.items():
        _require_exact_object(
            assets.get(name), expected, label=f"{label} guided asset {name}"
        )
    _require_exact_object(
        proof.get("operator_inputs"),
        guided["operator_inputs"],
        label=f"{label} operator inputs",
    )

    before = _guided_transition_identity(
        proof.get("before"), label=f"{label} before", active=True
    )
    after = _guided_transition_identity(
        proof.get("after"), label=f"{label} after", active=not stopped_after
    )
    hotkey_digest = guided["operator_inputs"]["hotkey_keyfile_sha256"]
    policy_digest = guided["operator_inputs"]["snp_policy_sha256"]
    if (
        before["durable_sha256"]["installed_hotkey_sha256"] != hotkey_digest
        or after["durable_sha256"]["installed_hotkey_sha256"] != hotkey_digest
    ):
        raise EvidenceError(f"{label} does not bind the installed operator hotkey")
    if (
        before["durable_sha256"]["installed_snp_policy_sha256"] != policy_digest
        or after["durable_sha256"]["installed_snp_policy_sha256"] != policy_digest
    ):
        raise EvidenceError(f"{label} does not bind the installed SNP policy")

    status_bytes = _read_regular(
        root / status_file,
        label=f"{label} status evidence",
        require_nonempty=True,
    )
    _require_exact_object(
        proof.get("status"),
        {"file": status_file, "sha256": _sha256(status_bytes)},
        label=f"{label} status binding",
    )
    if stopped_after:
        _require_exact_object(
            proof.get("outcomes"),
            {
                "stop_writer_exit": 0,
                "refused_setup_exit": 2,
                "refusal_marker": (
                    "SETUP_REFUSED: existing direct validator is stopped and "
                    "needs review"
                ),
                "writer_remained_stopped": True,
            },
            label=f"{label} outcomes",
        )
        if before["durable_sha256"] != after["durable_sha256"]:
            raise EvidenceError(f"{label} refused rerun changed durable state")
    else:
        _require_exact_object(
            proof.get("outcomes"),
            {
                "initial_setup_exit": 0,
                "idempotent_rerun_exit": 0,
                "setup_complete_marker": (
                    "SETUP_COMPLETE: stable direct validator configured"
                ),
            },
            label=f"{label} outcomes",
        )
        if before != after:
            raise EvidenceError(f"{label} idempotent rerun changed writer state")
    return before, after


def _validate_operator_secret_scan(root: Path, control: dict[str, Any]) -> None:
    label = "operator secret scan"
    report = strict_json(
        _read_regular(
            root / "operator-secret-scan.json", label=label, require_nonempty=True
        ),
        label=label,
        canonical=True,
    )
    if not isinstance(report, dict) or set(report) != {
        "schema",
        "operator_input_file_sha256",
        "checked_field_names",
        "evidence_file_count",
        "exact_match_count",
    }:
        raise EvidenceError(f"{label} has unexpected or missing fields")
    expected_input = control["guided_operator"]["operator_inputs"][
        "hotkey_keyfile_sha256"
    ]
    if (
        report.get("schema") != "cathedral_validator_operator_secret_scan_v1"
        or report.get("operator_input_file_sha256") != expected_input
        or report.get("exact_match_count") != 0
        or type(report.get("exact_match_count")) is not int
    ):
        raise EvidenceError(f"{label} has an invalid result or input binding")
    checked = report.get("checked_field_names")
    allowed_public = {"accountId", "ss58Address", "publicKey"}
    allowed_private = {"privateKey", "secretPhrase", "secretSeed"}
    if (
        not isinstance(checked, list)
        or any(not isinstance(name, str) for name in checked)
        or checked != sorted(set(checked))
        or not set(checked).issubset(allowed_public | allowed_private)
        or not set(checked).intersection(allowed_public)
        or not set(checked).intersection(allowed_private)
    ):
        raise EvidenceError(f"{label} has invalid checked field names")
    post_scan_files = {
        "operator-secret-scan.json",
        "teardown-status.txt",
        "controller-source-finalization.stderr",
        *RESULT_EXCLUSIONS,
    }
    expected_file_count = sum(
        1
        for path in root.rglob("*")
        if stat.S_ISREG(path.lstat().st_mode)
        and path.relative_to(root).as_posix() not in post_scan_files
    )
    if (
        type(report.get("evidence_file_count")) is not int
        or report["evidence_file_count"] != expected_file_count
    ):
        raise EvidenceError(f"{label} has an invalid evidence file count")


def _validate_guided_operator_evidence(
    root: Path,
    control: dict[str, Any],
    runtime_records: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    host = f"catval-{control['run_id']}-stable"
    archive_a = control["archive_a_sha256"]
    archive_b = control["archive_b_sha256"]
    a1 = runtime_records["stable-a-seq1.json"]["record"]
    b2 = runtime_records["stable-b-seq2.json"]["record"]
    a5 = runtime_records["stable-a-rescue-seq5.json"]["record"]

    idempotent_before, idempotent_after = _guided_transition_proof(
        root,
        control,
        relative="guided-setup-idempotence-proof.json",
        schema="cathedral_validator_guided_setup_idempotence_proof_v1",
        status_file="guided-status-after-setup.json",
        stopped_after=False,
    )

    setup_log = _guided_ascii_log(root, f"first-install-command-{host}.log")
    staged = re.findall(
        r"^OPERATOR_INPUTS_STAGED hotkey_sha256=([0-9a-f]{64}) "
        r"policy_sha256=([0-9a-f]{64})$",
        setup_log,
        flags=re.MULTILINE,
    )
    idempotent = list(
        re.finditer(
            rf"^GUIDED_SETUP_IDEMPOTENT_RERUN host={re.escape(host)} "
            r"identity=([1-9][0-9]*):([0-9A-Fa-f]{32})\n"
            r"((?:[0-9a-f]{64}:){4}[0-9a-f]{64})$",
            setup_log,
            flags=re.MULTILINE,
        )
    )
    setup_status_line = (
        "GUIDED_STATUS_PROOF label=guided-status-after-setup "
        f"result=NOT_PROVEN release={archive_a} sequence=1"
    )
    config_line = f"GUIDED_SETUP_CONFIG_PROOF host={host}"
    setup_complete = "SETUP_COMPLETE: stable direct validator configured"
    if (
        len(staged) != 1
        or staged[0]
        != (
            control["guided_operator"]["operator_inputs"]["hotkey_keyfile_sha256"],
            control["guided_operator"]["operator_inputs"]["snp_policy_sha256"],
        )
        or len(idempotent) != 1
        or idempotent[0].group(1) != str(idempotent_after["main_pid"])
        or idempotent[0].group(2).lower() != idempotent_after["invocation_id"].lower()
        or idempotent[0].group(3)
        != ":".join(
            idempotent_after["durable_sha256"][field]
            for field in GUIDED_DURABLE_DIGEST_FIELDS
        )
        or idempotent_before != idempotent_after
        or setup_log.splitlines().count(setup_complete) != 2
        or setup_log.splitlines().count(config_line) != 1
        or setup_log.splitlines().count(setup_status_line) != 1
        or not (
            setup_log.index("OPERATOR_INPUTS_STAGED ")
            < setup_log.index(setup_complete)
            < setup_log.index(config_line)
            < setup_log.index(setup_status_line)
            < setup_log.index(setup_complete, setup_log.index(setup_complete) + 1)
            < idempotent[0].start()
        )
    ):
        raise EvidenceError(
            "guided setup evidence does not prove configuration and idempotent rerun"
        )

    _guided_status_report(
        root,
        relative="guided-status-after-setup.json",
        expected_result="NOT_PROVEN",
        expected_record=a1,
        service_active=True,
        timer_active=True,
    )

    _, stopped_after = _guided_transition_proof(
        root,
        control,
        relative="guided-setup-stopped-writer-proof.json",
        schema="cathedral_validator_guided_setup_stopped_writer_proof_v1",
        status_file="guided-status-stopped-writer.json",
        stopped_after=True,
    )
    timer_status_line = (
        "GUIDED_STATUS_PROOF label=guided-status-after-timer-b "
        f"result=NOT_PROVEN release={archive_b} sequence=2"
    )
    timer_log = _guided_ascii_log(root, "guided-status-after-timer-b-command.log")
    if timer_log.splitlines().count(timer_status_line) != 1:
        raise EvidenceError("guided timer-B status proof is incomplete")
    _guided_status_report(
        root,
        relative="guided-status-after-timer-b.json",
        expected_result="NOT_PROVEN",
        expected_record=b2,
        service_active=True,
        timer_active=True,
    )

    before_state = strict_json(
        _read_regular(
            root / "stable-higher-sequence-rescue-sequence-state.json",
            label="guided stopped-writer pre-state",
            require_nonempty=True,
        ),
        label="guided stopped-writer pre-state",
        canonical=True,
    )
    _require_exact_object(
        before_state,
        {
            "channel": "stable",
            "current": f"releases/{archive_a}",
            "record": a5,
            "sequence": 5,
            "pending": None,
        },
        label="guided stopped-writer pre-state",
    )
    _validate_current_release_proof(
        _read_regular(
            root / "higher-sequence-rescue-current-proof.txt",
            label="guided stopped-writer pre-current",
            require_nonempty=True,
        ),
        label="guided stopped-writer pre-current",
        archive_sha256=archive_a,
    )
    if (
        _read_regular(
            root / "higher-sequence-rescue-service-command.log",
            label="guided stopped-writer pre-service",
            require_nonempty=True,
        )
        != b"active\n"
    ):
        raise EvidenceError("guided stopped-writer pre-service was not active")

    stopped_status_line = (
        "GUIDED_STATUS_PROOF label=guided-status-stopped-writer "
        f"result=NEEDS_REVIEW release={archive_a} sequence=5"
    )
    stopped_lines = _guided_ascii_log(
        root, "guided-setup-stopped-writer-command.log"
    ).splitlines()
    expected_stopped_markers = (
        "DIRECT_WRITER_STOPPED_FOR_PROOF",
        "SETUP_REFUSED: existing direct validator is stopped and needs review",
        "SETUP_EXIT=2",
        "DIRECT_WRITER_STILL_STOPPED",
        stopped_status_line,
        f"GUIDED_SETUP_STOPPED_WRITER_REFUSED host={host}",
    )
    positions: list[int] = []
    for marker in expected_stopped_markers:
        if stopped_lines.count(marker) != 1:
            raise EvidenceError(
                "guided stopped-writer refusal log is incomplete or ambiguous"
            )
        positions.append(stopped_lines.index(marker))
    if positions != sorted(positions) or any(
        line == setup_complete for line in stopped_lines
    ):
        raise EvidenceError("guided stopped-writer refusal ordering is invalid")
    _guided_status_report(
        root,
        relative="guided-status-stopped-writer.json",
        expected_result="NEEDS_REVIEW",
        expected_record=a5,
        service_active=False,
        timer_active=False,
    )
    return stopped_after


def _validate_success_evidence(root: Path) -> dict[str, Any]:
    for relative in REQUIRED_SUCCESS_FILES:
        _read_regular(
            root / relative,
            label=f"required success evidence {relative}",
            require_nonempty=True,
        )
    teardown = _read_regular(root / "teardown-status.txt", label="teardown status")
    if teardown != b"original_status=0\nteardown_verified=1\n":
        raise EvidenceError(
            "teardown status does not prove a successful clean teardown"
        )
    for relative in EMPTY_TEARDOWN_LISTS:
        value = strict_json(
            _read_regular(root / relative, label=relative), label=relative
        )
        if value != []:
            raise EvidenceError(f"teardown absence check is not empty: {relative}")
    if (root / "project-metadata-before.json").read_bytes() != (
        root / "project-metadata-after-teardown.json"
    ).read_bytes():
        raise EvidenceError("project metadata changed during the live test")
    control = _validate_control(
        strict_json(
            _read_regular(root / "control.json", label="control document"),
            label="control document",
        )
    )
    runtime_records = _validate_release_and_bootstrap_evidence(root, control)
    guided_stopped_identity = _validate_guided_operator_evidence(
        root, control, runtime_records
    )
    pid_values = [
        _single_ascii_line(root, relative, label=f"direct service PID proof {relative}")
        for relative in DIRECT_SERVICE_PID_PROOFS
    ]
    if any(re.fullmatch(r"[1-9][0-9]*", value) is None for value in pid_values) or (
        len(set(pid_values)) != 1
    ):
        raise EvidenceError(
            "same-archive renewal or same-boot timer reactivation changed the direct "
            "service PID"
        )
    invocation_values = [
        _single_ascii_line(
            root,
            relative,
            label=f"direct service invocation proof {relative}",
        )
        for relative in DIRECT_SERVICE_INVOCATION_PROOFS
    ]
    if (
        any(
            re.fullmatch(r"[0-9A-Fa-f]{32}", value) is None
            for value in invocation_values
        )
        or len(set(invocation_values)) != 1
    ):
        raise EvidenceError(
            "same-archive renewal or same-boot timer reactivation changed the direct "
            "service invocation"
        )
    reactivation_start = _read_regular(
        root / "canary-same-boot-reactivation-timer-reactivation-start.log",
        label="same-boot timer reactivation start proof",
        require_nonempty=True,
    )
    start_lines = reactivation_start.splitlines()
    if not start_lines or start_lines[0] != b"CATHEDRAL_TIMER_REACTIVATION_PROOF_V1":
        raise EvidenceError("same-boot timer reactivation start proof is incomplete")
    start_values = _property_values(
        reactivation_start, label="same-boot timer reactivation start proof"
    )
    expected_timer = "cathedral-validator-canary-update.timer"
    expected_service = "cathedral-validator-canary-update.service"
    expected_host = f"catval-{control['run_id']}-canary"
    if (
        _one_property(start_values, "ProofHost", label="reactivation start")
        != expected_host
        or _one_property(start_values, "ProofTimer", label="reactivation start")
        != expected_timer
        or _one_property(start_values, "ProofService", label="reactivation start")
        != expected_service
        or _one_property(start_values, "ProofChannel", label="reactivation start")
        != "canary"
        or _one_property(start_values, "ExpectedRelease", label="reactivation start")
        != control["archive_b_sha256"]
        or _one_property(start_values, "Id", label="reactivation start")
        != expected_timer
        or _one_property(start_values, "UnitFileState", label="reactivation start")
        != "enabled"
    ):
        raise EvidenceError("same-boot timer reactivation start proof is inconsistent")
    before_invocation = _one_property(
        start_values, "BeforeServiceInvocationID", label="reactivation start"
    )
    before_trigger = _one_property(
        start_values, "BeforeLastTriggerUSec", label="reactivation start"
    )
    if (
        re.fullmatch(r"[0-9A-Fa-f]{32}", before_invocation) is None
        or not before_trigger
        or _one_property(start_values, "LastTriggerUSec", label="reactivation start")
        != before_trigger
        or not _timer_is_rearmed(
            active=_one_property(
                start_values, "ActiveState", label="reactivation start"
            ),
            substate=_one_property(
                start_values, "SubState", label="reactivation start"
            ),
            next_elapse=_one_property(
                start_values, "NextElapseUSecMonotonic", label="reactivation start"
            ),
        )
        or _one_timer_schedule_value(reactivation_start, "OnActiveUSec")
        in {"", "0", "infinity", "n/a"}
        or _one_timer_schedule_value(reactivation_start, "OnUnitActiveUSec")
        in {"", "0", "infinity", "n/a"}
        or re.search(r"(?:^|[ {;])OnBootUSec=", reactivation_start.decode("utf-8"))
        is not None
    ):
        raise EvidenceError("same-boot timer reactivation start proof is incomplete")
    reactivation_wait = _read_regular(
        root / "canary-same-boot-reactivation-timer-reactivation-wait.log",
        label="same-boot timer reactivation completion proof",
        require_nonempty=True,
    )
    wait_snapshot = _last_reactivation_snapshot(reactivation_wait)
    wait_invocation = wait_snapshot.get("ServiceInvocationID", "")
    wait_trigger = wait_snapshot.get("LastTriggerUSec", "")
    if (
        re.fullmatch(r"[0-9A-Fa-f]{32}", wait_invocation) is None
        or wait_invocation == before_invocation
        or not wait_trigger
        or wait_trigger == before_trigger
        or wait_snapshot.get("ServiceResult") != "success"
        or wait_snapshot.get("ServiceExecMainStatus") != "0"
        or wait_snapshot.get("ServiceActiveState") != "inactive"
        or not _timer_is_rearmed(
            active=wait_snapshot.get("ActiveState", ""),
            substate=wait_snapshot.get("SubState", ""),
            next_elapse=wait_snapshot.get("NextElapseUSecMonotonic", ""),
        )
    ):
        raise EvidenceError(
            "same-boot timer reactivation completion proof is incomplete"
        )
    reactivation_state = _last_json_line(
        _read_regular(
            root / "canary-same-boot-reactivation-timer-reactivation-state.log",
            label="same-boot timer reactivation updater state proof",
            require_nonempty=True,
        ),
        label="same-boot timer reactivation updater state proof",
    )
    reactivation_record = reactivation_state.get("record")
    if (
        set(reactivation_state)
        != {"channel", "current", "record", "sequence", "pending"}
        or reactivation_state.get("channel") != "canary"
        or reactivation_state.get("current")
        != f"releases/{control['archive_b_sha256']}"
        or reactivation_state.get("sequence") != 3
        or not isinstance(reactivation_record, dict)
        or reactivation_record.get("sequence") != 3
        or reactivation_record.get("archive_sha256") != control["archive_b_sha256"]
        or reactivation_state.get("pending") is not None
    ):
        raise EvidenceError("same-boot timer reactivation updater state is not settled")
    run_id = control["run_id"]
    for relative, kind, name_template in TEARDOWN_RESOURCE_PROOFS:
        value = _single_ascii_line(
            root, relative, label=f"teardown resource proof {relative}"
        )
        expected_name = name_template.format(run_id=run_id)
        proof_match = re.fullmatch(
            rf"TEARDOWN_RESOURCE_ABSENT kind={re.escape(kind)} "
            rf"name={re.escape(expected_name)} attempt=([1-9][0-9]*|final)",
            value,
        )
        if proof_match is None:
            raise EvidenceError(f"teardown resource proof is invalid: {relative}")
        label = relative.removeprefix("teardown-").removesuffix("-result.txt")
        attempt = proof_match.group(1)
        snapshot_name = (
            f"teardown-{label}-final.json"
            if attempt == "final"
            else f"teardown-{label}-check-{attempt}.json"
        )
        snapshot = strict_json(
            _read_regular(
                root / snapshot_name,
                label=f"teardown snapshot {snapshot_name}",
                require_nonempty=True,
            ),
            label=f"teardown snapshot {snapshot_name}",
            canonical=True,
        )
        if snapshot != []:
            raise EvidenceError(
                f"teardown resource marker is not bound to an empty snapshot: {relative}"
            )
    for label in ("final-canary", "final-stable"):
        manifest_path = root / f"{label}-sections.json"
        artifacts_dir = root / f"{label}.d"
        manifest = _load_capture_manifest(manifest_path)
        role = label.removeprefix("final-")
        expected_host = f"catval-{control['run_id']}-{role}"
        label_match = re.fullmatch(
            rf"{re.escape(label)}-capture-attempt-([1-6])",
            str(manifest.get("label")),
        )
        if manifest.get("host") != expected_host or label_match is None:
            raise EvidenceError(
                f"required final capture {label} has the wrong host or label"
            )
        retry_lines = (
            _read_regular(
                root / f"{label}-capture-retries.log",
                label=f"{label} retry selection",
                require_nonempty=True,
            )
            .decode("ascii")
            .splitlines()
        )
        if not retry_lines or retry_lines[-1] != (
            f"attempt={label_match.group(1)} status=0"
        ):
            raise EvidenceError(
                f"required final capture {label} lacks its selection proof"
            )
        complete, errors = _capture_manifest_complete(manifest, artifacts_dir)
        if not complete or manifest.get("complete") is not True:
            raise EvidenceError(
                f"required final capture {label} is incomplete: {'; '.join(errors)}"
            )
        state_path = artifacts_dir / "updater_state.txt"
        state = strict_json(
            _read_regular(state_path, label=f"{label} updater state"),
            label=f"{label} updater state",
        )
        expected_metadata_name = (
            "canary-b-renewal-seq3.json"
            if role == "canary"
            else "stable-a-rescue-seq5.json"
        )
        expected_record = runtime_records[expected_metadata_name]["record"]
        expected_archive_text = expected_record["archive_sha256"]
        _validate_final_updater_state(
            state,
            label=label,
            channel=role,
            expected_record=expected_record,
        )
        current = _read_regular(
            artifacts_dir / "current_release.txt", label=f"{label} current release"
        ).strip()
        expected_archive = expected_archive_text.encode("ascii")
        if current != b"releases/" + expected_archive:
            raise EvidenceError(f"{label} does not point to its expected final release")
        direct_identity = _validate_final_systemd_state(
            artifacts_dir,
            label=label,
            direct_active=role == "canary",
        )
        if label == "final-canary" and (
            str(direct_identity["main_pid"]) != pid_values[0]
            or str(direct_identity["invocation_id"]).lower()
            != invocation_values[0].lower()
        ):
            raise EvidenceError(
                "final-canary direct service identity differs from continuity proofs"
            )
        if (
            label == "final-stable"
            and str(direct_identity["invocation_id"]).lower()
            != str(guided_stopped_identity["invocation_id"]).lower()
        ):
            raise EvidenceError(
                "final-stable direct service invocation differs from the stopped "
                "writer proof"
            )
    initial_identities: dict[str, str] = {}
    for role in ("canary", "stable"):
        name = f"catval-{control['run_id']}-{role}"
        document = strict_json(
            _read_regular(
                root / f"{role}-instance.json",
                label=f"initial {role} instance",
                require_nonempty=True,
            ),
            label=f"initial {role} instance",
        )
        initial_identities[name] = _instance_identity(
            document,
            expected_name=name,
            control=control,
            label=f"initial {role} instance",
        )
    created_identities = _instance_inventory(
        strict_json(
            _read_regular(
                root / "created-run-instances.json",
                label="created host inventory",
                require_nonempty=True,
            ),
            label="created host inventory",
        ),
        control=control,
        label="created host inventory",
    )
    pre_teardown = strict_json(
        _read_regular(root / "pre-teardown-instances.json", label="pre-teardown hosts"),
        label="pre-teardown hosts",
    )
    pre_teardown_identities = _instance_inventory(
        pre_teardown, control=control, label="pre-teardown host inventory"
    )
    if not (initial_identities == created_identities == pre_teardown_identities):
        raise EvidenceError("host immutable identities changed during the live test")
    _scenario_matrix(root, control)
    _validate_operator_secret_scan(root, control)
    return control


def _inventory(root: Path, exclusions: frozenset[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(
        root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
    ):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise EvidenceError(f"evidence tree contains a symlink: {relative}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceError(
                f"evidence tree contains a non-regular file: {relative}"
            )
        if relative in exclusions:
            continue
        data = path.read_bytes()
        rows.append({"path": relative, "bytes": len(data), "sha256": _sha256(data)})
    return rows


def _evidence_root(rows: list[dict[str, Any]]) -> str:
    index = {"schema": EVIDENCE_INDEX_SCHEMA, "files": rows}
    return _sha256(EVIDENCE_DIGEST_DOMAIN + canonical_bytes(index))


def _result_paths(root: Path) -> tuple[Path, Path, Path]:
    return root / RESULT_NAME, root / SIGNATURE_NAME, root / DIGEST_NAME


def _validate_result_path(root: Path, path: Path, expected_name: str) -> None:
    if path.parent.resolve() != root.resolve() or path.name != expected_name:
        raise EvidenceError(
            f"{expected_name} must use its canonical name in EVIDENCE_DIR"
        )


def finalize_result(args: argparse.Namespace) -> int:
    root = _resolve_evidence_root(args.evidence_dir)
    if not SAFE_KEY_ID.fullmatch(args.key_id):
        raise EvidenceError("result signer key id is unsafe")
    result_path, signature_path, digest_path = _result_paths(root)
    for output, name in (
        (result_path, RESULT_NAME),
        (signature_path, SIGNATURE_NAME),
        (digest_path, DIGEST_NAME),
    ):
        _validate_result_path(root, output, name)
        if output.exists() or output.is_symlink():
            raise EvidenceError(f"result output already exists: {output}")
    private, public, fingerprint = _load_key_pair(args.private_key, args.public_key)
    retained_public = _read_regular(
        root / RESULT_PUBLIC_KEY_NAME,
        label="retained result public key",
        require_nonempty=True,
    )
    if retained_public != args.public_key.read_bytes():
        raise EvidenceError("retained result public key differs from the reviewed key")
    control = _validate_success_evidence(root)
    if control.get("result_signer") != {
        "purpose": SIGNER_PURPOSE,
        "key_id": args.key_id,
        "algorithm": SIGNER_ALGORITHM,
        "public_key_fingerprint": fingerprint,
    }:
        raise EvidenceError(
            "control document result signer differs from the configured key"
        )
    scenario_matrix = _scenario_matrix(root, control)
    rows = _inventory(root, RESULT_EXCLUSIONS)
    _controller_path, controller_bytes, result_tool_bytes = _reviewed_source_identity(
        args.controller_script
    )
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "run": {
            "id": control.get("run_id"),
            "finished_at": datetime.now(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "source_revision_a": control.get("source_revision_a"),
            "source_revision_b": control.get("source_revision_b"),
            "archive_a_sha256": control.get("archive_a_sha256"),
            "archive_b_sha256": control.get("archive_b_sha256"),
        },
        "terminal": TERMINAL_PASS,
        "scope": NO_CHAIN_SCOPE,
        "controller": {
            "repository": control.get("source_repository"),
            "revision": control.get("source_revision_b"),
            "path": CONTROLLER_PATH,
            "sha256": _sha256(controller_bytes),
            "result_tool_path": RESULT_TOOL_PATH,
            "result_tool_sha256": _sha256(result_tool_bytes),
        },
        "signer": {
            "purpose": SIGNER_PURPOSE,
            "key_id": args.key_id,
            "algorithm": SIGNER_ALGORITHM,
            "public_key_path": RESULT_PUBLIC_KEY_NAME,
            "public_key_fingerprint": fingerprint,
            "authorizes_chain_or_weight_changes": False,
        },
        "scenario_matrix": scenario_matrix,
        "evidence_tree": {
            "algorithm": EVIDENCE_TREE_ALGORITHM,
            "root_sha256": _evidence_root(rows),
            "file_count": len(rows),
            "files": rows,
        },
        "authority": UNATTESTED_AUTHORITY,
    }
    result_data = canonical_bytes(result)
    signature = private.sign(result_data)
    public.verify(signature, result_data)
    result_digest = _sha256(result_data)
    _atomic_write(result_path, result_data, mode=0o444)
    _atomic_write(signature_path, signature, mode=0o444)
    _atomic_write(
        digest_path,
        f"{result_digest}  {RESULT_NAME}\n".encode("ascii"),
        mode=0o444,
    )
    _verify_result(root, result_path, signature_path, digest_path, args.public_key)
    print(result_digest)
    return 0


def _verify_result(
    root: Path,
    result_path: Path,
    signature_path: Path,
    digest_path: Path,
    public_key_path: Path,
) -> str:
    result_data = _read_regular(
        result_path, label="live E2E result", require_nonempty=True
    )
    digest = _sha256(result_data)
    digest_data = _read_regular(
        digest_path, label="live E2E result digest", require_nonempty=True
    )
    expected_digest_data = f"{digest}  {RESULT_NAME}\n".encode("ascii")
    if digest_data != expected_digest_data:
        raise EvidenceError("live E2E result digest mismatch")
    result = strict_json(result_data, label="live E2E result", canonical=True)
    if not isinstance(result, dict) or set(result) != RESULT_TOP_LEVEL_FIELDS:
        raise EvidenceError("live E2E result has unexpected or missing fields")
    if type(result.get("schema")) is not str or result["schema"] != RESULT_SCHEMA:
        raise EvidenceError("live E2E result has the wrong schema")
    _require_exact_object(
        result.get("terminal"), TERMINAL_PASS, label="live E2E result terminal"
    )
    _require_exact_object(
        result.get("scope"), NO_CHAIN_SCOPE, label="live E2E result scope"
    )
    _require_exact_object(
        result.get("authority"),
        UNATTESTED_AUTHORITY,
        label="live E2E result authority",
    )
    public_data = _read_regular(
        public_key_path, label="result verification public key", require_nonempty=True
    )
    retained_public = _read_regular(
        root / RESULT_PUBLIC_KEY_NAME,
        label="retained result public key",
        require_nonempty=True,
    )
    if retained_public != public_data:
        raise EvidenceError(
            "retained result public key differs from the pinned verifier key"
        )
    try:
        public = serialization.load_pem_public_key(public_data)
    except ValueError as exc:
        raise EvidenceError("result verification public key is invalid") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise EvidenceError("result verification public key must use Ed25519")
    der = public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = f"sha256:{_sha256(der)}"
    signature = _read_regular(
        signature_path, label="live E2E result signature", require_nonempty=True
    )
    try:
        public.verify(signature, result_data)
    except InvalidSignature as exc:
        raise EvidenceError("live E2E result signature is invalid") from exc
    control = _validate_success_evidence(root)
    run = result.get("run")
    if not isinstance(run, dict) or set(run) != RUN_FIELDS:
        raise EvidenceError("live E2E result run has unexpected or missing fields")
    if any(type(run[field]) is not str for field in RUN_FIELDS):
        raise EvidenceError("live E2E result run fields must be strings")
    if (
        SAFE_CAPTURE_ID.fullmatch(run["id"]) is None
        or REVISION.fullmatch(run["source_revision_a"]) is None
        or REVISION.fullmatch(run["source_revision_b"]) is None
        or HEX_64.fullmatch(run["archive_a_sha256"]) is None
        or HEX_64.fullmatch(run["archive_b_sha256"]) is None
    ):
        raise EvidenceError("live E2E result run identity has invalid syntax")
    _validate_utc_seconds(run["finished_at"], label="live E2E result finished_at")
    if any(
        run.get(field) != control.get(field)
        for field in (
            "source_revision_a",
            "source_revision_b",
            "archive_a_sha256",
            "archive_b_sha256",
        )
    ):
        raise EvidenceError("live E2E result run identity differs from control.json")
    if run.get("id") != control.get("run_id"):
        raise EvidenceError("live E2E result run id differs from control.json")
    _controller_path, controller_bytes, result_tool_bytes = _reviewed_source_identity()
    expected_controller = {
        "repository": control.get("source_repository"),
        "revision": control.get("source_revision_b"),
        "path": CONTROLLER_PATH,
        "sha256": _sha256(controller_bytes),
        "result_tool_path": RESULT_TOOL_PATH,
        "result_tool_sha256": _sha256(result_tool_bytes),
    }
    _require_exact_object(
        result.get("controller"),
        expected_controller,
        label="live E2E result controller",
    )
    signer_value = result.get("signer")
    if not isinstance(signer_value, dict) or set(signer_value) != SIGNER_FIELDS:
        raise EvidenceError("live E2E result signer has unexpected or missing fields")
    key_id = signer_value.get("key_id")
    if not isinstance(key_id, str) or SAFE_KEY_ID.fullmatch(key_id) is None:
        raise EvidenceError("live E2E result signer key id is unsafe")
    signer = _require_exact_object(
        signer_value,
        {
            "purpose": SIGNER_PURPOSE,
            "key_id": key_id,
            "algorithm": SIGNER_ALGORITHM,
            "public_key_path": RESULT_PUBLIC_KEY_NAME,
            "public_key_fingerprint": fingerprint,
            "authorizes_chain_or_weight_changes": False,
        },
        label="live E2E result signer",
    )
    control_signer = control.get("result_signer")
    _require_exact_object(
        control_signer,
        {
            "purpose": SIGNER_PURPOSE,
            "key_id": signer["key_id"],
            "algorithm": SIGNER_ALGORITHM,
            "public_key_fingerprint": fingerprint,
        },
        label="control document result signer",
    )
    expected_scenario_matrix = _scenario_matrix(root, control)
    if result.get("scenario_matrix") != expected_scenario_matrix:
        raise EvidenceError(
            "live E2E result scenario matrix differs from recomputed evidence"
        )
    rows = _inventory(root, RESULT_EXCLUSIONS)
    tree = result.get("evidence_tree")
    if (
        not isinstance(tree, dict)
        or set(tree) != EVIDENCE_TREE_FIELDS
        or type(tree.get("algorithm")) is not str
        or tree.get("algorithm") != EVIDENCE_TREE_ALGORITHM
        or type(tree.get("root_sha256")) is not str
        or HEX_64.fullmatch(tree["root_sha256"]) is None
        or type(tree.get("file_count")) is not int
        or not isinstance(tree.get("files"), list)
        or tree.get("files") != rows
        or tree.get("file_count") != len(rows)
        or tree.get("root_sha256") != _evidence_root(rows)
    ):
        raise EvidenceError("live E2E result evidence-tree digest mismatch")
    return digest


def verify_result(args: argparse.Namespace) -> int:
    root = _resolve_evidence_root(args.evidence_dir)
    result_path, signature_path, digest_path = _result_paths(root)
    digest = _verify_result(
        root, result_path, signature_path, digest_path, args.public_key
    )
    print(digest)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    keys = subparsers.add_parser("validate-key-pair")
    keys.add_argument("--private-key", type=Path, required=True)
    keys.add_argument("--public-key", type=Path, required=True)
    keys.add_argument("--key-id", required=True)
    keys.set_defaults(handler=validate_key_pair)

    capture = subparsers.add_parser("decode-capture")
    capture.add_argument("--input", type=Path, required=True)
    capture.add_argument("--ssh-stderr", type=Path, required=True)
    capture.add_argument("--text-output", type=Path, required=True)
    capture.add_argument("--manifest-output", type=Path, required=True)
    capture.add_argument("--artifacts-dir", type=Path, required=True)
    capture.add_argument("--label", required=True)
    capture.add_argument("--host", required=True)
    capture.add_argument("--transient-unit")
    capture.set_defaults(handler=decode_capture)

    verify_host = subparsers.add_parser("verify-capture")
    verify_host.add_argument("--manifest", type=Path, required=True)
    verify_host.add_argument("--artifacts-dir", type=Path, required=True)
    verify_host.set_defaults(handler=verify_capture)

    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--evidence-dir", type=Path, required=True)
    finalize.add_argument("--private-key", type=Path, required=True)
    finalize.add_argument("--public-key", type=Path, required=True)
    finalize.add_argument("--key-id", required=True)
    finalize.add_argument("--controller-script", type=Path, required=True)
    finalize.set_defaults(handler=finalize_result)

    verify = subparsers.add_parser("verify-result")
    verify.add_argument("--evidence-dir", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.set_defaults(handler=verify_result)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        return args.handler(args)
    except (EvidenceError, FileNotFoundError, OSError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
