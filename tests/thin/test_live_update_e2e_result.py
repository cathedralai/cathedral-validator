import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts" / "live_update_e2e_result.py"
CONTROLLER = ROOT / "scripts" / "live_validator_update_e2e.sh"
SPEC = importlib.util.spec_from_file_location("live_update_e2e_result", TOOL)
assert SPEC is not None and SPEC.loader is not None
RESULT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RESULT
SPEC.loader.exec_module(RESULT)


def _section_line(section_id, required, status, payload):
    return "\t".join(
        (
            RESULT.CAPTURE_MARKER,
            section_id,
            "required" if required else "optional",
            str(status),
            str(len(payload)),
            hashlib.sha256(payload).hexdigest(),
            base64.b64encode(payload).decode("ascii"),
        )
    )


def _decode(tmp_path, *, omit=None, optional_status=0):
    raw = tmp_path / "capture.tsv"
    stderr = tmp_path / "capture.stderr"
    rows = []
    for section_id, required in RESULT.GENERIC_SECTIONS:
        if section_id == omit:
            continue
        if section_id == "updater_state":
            payload = b'{"pending":null}\n'
        elif section_id == "current_release":
            payload = b"releases/" + b"1" * 64 + b"\n"
        else:
            payload = b"ok\n"
        status = 0 if required else optional_status
        rows.append(_section_line(section_id, required, status, payload))
    raw.write_text("\n".join(rows) + "\n", encoding="ascii")
    stderr.write_bytes(b"")
    command = [
        sys.executable,
        str(TOOL),
        "decode-capture",
        "--input",
        str(raw),
        "--ssh-stderr",
        str(stderr),
        "--text-output",
        str(tmp_path / "capture.txt"),
        "--manifest-output",
        str(tmp_path / "capture.json"),
        "--artifacts-dir",
        str(tmp_path / "capture.d"),
        "--label",
        "capture",
        "--host",
        "vm-a",
    ]
    return subprocess.run(command, check=False, capture_output=True, text=True)


def test_capture_tolerates_failed_optional_diagnostics(tmp_path):
    completed = _decode(tmp_path, optional_status=3)
    assert completed.returncode == 0, completed.stderr
    manifest = json.loads((tmp_path / "capture.json").read_text(encoding="ascii"))
    assert manifest["complete"] is True
    optional = [row for row in manifest["sections"] if not row["required"]]
    assert optional
    assert {row["command_exit_status"] for row in optional} == {3}
    assert all(row["artifact"]["bytes"] > 0 for row in optional)
    assert all(len(row["artifact"]["sha256"]) == 64 for row in optional)


def test_capture_refuses_a_missing_required_section(tmp_path):
    completed = _decode(tmp_path, omit="updater_state")
    assert completed.returncode != 0
    assert "host evidence capture is incomplete" in completed.stderr
    manifest = json.loads((tmp_path / "capture.json").read_text(encoding="ascii"))
    assert manifest["complete"] is False
    assert any("updater_state" in error for error in manifest["transport_errors"])


def test_capture_verifier_refuses_a_tampered_required_artifact(tmp_path):
    completed = _decode(tmp_path)
    assert completed.returncode == 0, completed.stderr
    (tmp_path / "capture.d" / "updater_state.txt").write_bytes(b"tampered\n")
    verified = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "verify-capture",
            "--manifest",
            str(tmp_path / "capture.json"),
            "--artifacts-dir",
            str(tmp_path / "capture.d"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verified.returncode != 0
    assert "artifact size/digest mismatch" in verified.stderr


def test_controller_refuses_when_all_privileged_capture_commands_fail(tmp_path):
    script = CONTROLLER.read_text(encoding="utf-8")
    capture_host = (
        "capture_host() {"
        + script.split("capture_host() {", 1)[1].split(
            "capture_host_with_retries() {", 1
        )[0]
    )
    evidence = tmp_path / "all-fail"
    evidence.mkdir()
    completed = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            'EVIDENCE_DIR="$1"\n'
            'RESULT_TOOL="$2"\n'
            "remote() {\n"
            "  command=$2\n"
            "  /bin/bash -c 'sudo() { printf \"sudo-denied\\n\" >&2; return 77; }; "
            "export -f sudo; eval \"$1\"' capture-remote \"$command\"\n"
            "}\n"
            + capture_host
            + "\nif capture_host all-privileged-fail vm-a; then exit 19; "
            "else status=$?; fi\n"
            'test "$status" -ne 0\n'
            'test -f "$EVIDENCE_DIR/all-privileged-fail-sections.json"',
            "all-privileged-fail-test",
            str(evidence),
            str(TOOL),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    manifest = json.loads(
        (evidence / "all-privileged-fail-sections.json").read_text(encoding="ascii")
    )
    assert manifest["complete"] is False
    required = [row for row in manifest["sections"] if row["required"]]
    assert required
    assert {row["command_exit_status"] for row in required} == {77}


def test_controller_accepts_required_capture_when_optional_status_fails(tmp_path):
    script = CONTROLLER.read_text(encoding="utf-8")
    capture_host = (
        "capture_host() {"
        + script.split("capture_host() {", 1)[1].split(
            "capture_host_with_retries() {", 1
        )[0]
    )
    evidence = tmp_path / "required-pass"
    evidence.mkdir()
    completed = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            'EVIDENCE_DIR="$1"\n'
            'RESULT_TOOL="$2"\n'
            "remote() {\n"
            "  command=$2\n"
            "  /bin/bash -c 'sudo() {\n"
            "    case \"$1\" in\n"
            "      readlink) printf \"releases/%064d\\n\" 1 ;;\n"
            "      cat) printf \"{\\\"pending\\\":null}\\n\" ;;\n"
            "      journalctl) printf \"no-journal\\n\"; return 4 ;;\n"
            "      systemctl) if [[ \"$2\" == status ]]; then "
            "printf \"inactive\\n\"; return 3; else printf \"recorded\\n\"; fi ;;\n"
            "      *) return 76 ;;\n"
            "    esac\n"
            "  }; export -f sudo; eval \"$1\"' capture-remote \"$command\"\n"
            "}\n"
            + capture_host
            + "\ncapture_host required-pass vm-a\n",
            "required-capture-pass-test",
            str(evidence),
            str(TOOL),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    manifest = json.loads(
        (evidence / "required-pass-sections.json").read_text(encoding="ascii")
    )
    assert manifest["complete"] is True
    required = [row for row in manifest["sections"] if row["required"]]
    optional = [row for row in manifest["sections"] if not row["required"]]
    assert {row["command_exit_status"] for row in required} == {0}
    assert {row["command_exit_status"] for row in optional} == {3, 4}


def _key_pair(root):
    private = Ed25519PrivateKey.generate()
    private_path = root / "private.pem"
    public_path = root / "public.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    private_path.chmod(0o600)
    public_path.chmod(0o644)
    _, _, fingerprint = RESULT._load_key_pair(private_path, public_path)
    return private_path, public_path, fingerprint


def _capture_manifest(evidence, label, release_digest):
    artifacts = evidence / f"{label}.d"
    artifacts.mkdir(mode=0o700)
    rows = []
    for section_id, required in RESULT.GENERIC_SECTIONS:
        if section_id == "updater_state":
            payload = b'{"pending":null}\n'
        elif section_id == "current_release":
            payload = f"releases/{release_digest}\n".encode("ascii")
        elif section_id == "direct_unit_show":
            payload = (
                b"Result=success\nExecMainCode=0\nExecMainStatus=0\n"
                b"ActiveState=active\nSubState=running\nMainPID=42\n"
            )
        elif section_id == "updater_services_show":
            payload = (
                b"Id=cathedral-validator-canary-update.service\n"
                b"ActiveState=inactive\nSubState=dead\n\n"
                b"Id=cathedral-validator-update.service\n"
                b"ActiveState=inactive\nSubState=dead\n"
            )
        elif section_id == "timers_show":
            payload = (
                b"Id=cathedral-validator-canary-update.timer\n"
                b"UnitFileState=disabled\nActiveState=inactive\nSubState=dead\n\n"
                b"Id=cathedral-validator-update.timer\n"
                b"UnitFileState=disabled\nActiveState=inactive\nSubState=dead\n"
            )
        else:
            payload = b"ok\n"
        artifact_name = f"{section_id}.txt"
        (artifacts / artifact_name).write_bytes(payload)
        rows.append(
            {
                "id": section_id,
                "required": required,
                "command_exit_status": 0,
                "artifact": {
                    "path": artifact_name,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
            }
        )
    manifest = {
        "schema": RESULT.CAPTURE_SCHEMA,
        "label": f"{label}-capture-attempt-1",
        "host": f"catval-valupd-fixture-{label.removeprefix('final-')}",
        "transient_unit": None,
        "complete": True,
        "transport_errors": [],
        "sections": rows,
    }
    (evidence / f"{label}-sections.json").write_bytes(RESULT.canonical_bytes(manifest))
    (evidence / f"{label}-capture-retries.log").write_text(
        "attempt=1 status=0\n", encoding="ascii"
    )


def _success_tree(tmp_path):
    key_root = tmp_path / "keys"
    key_root.mkdir()
    private_path, public_path, fingerprint = _key_pair(key_root)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    for relative in RESULT.REQUIRED_SUCCESS_FILES:
        (evidence / relative).write_bytes(b"recorded\n")
    for relative in RESULT.DIRECT_SERVICE_PID_PROOFS:
        (evidence / relative).write_text("42\n", encoding="ascii")
    for relative in RESULT.DIRECT_SERVICE_INVOCATION_PROOFS:
        (evidence / relative).write_text("a" * 32 + "\n", encoding="ascii")
    (
        evidence / "canary-same-boot-reactivation-timer-reactivation-start.log"
    ).write_text(
        "OnActiveUSec=1s\nOnUnitActiveUSec=2s\n"
        "UnitFileState=enabled\nActiveState=active\n",
        encoding="ascii",
    )
    (
        evidence / "canary-same-boot-reactivation-timer-reactivation-wait.log"
    ).write_text(
        "ServiceResult=success\nServiceExecMainStatus=0\n"
        "ServiceActiveState=inactive\n",
        encoding="ascii",
    )
    teardown_resources = {
        "teardown-canary-vm-result.txt": ("instance", "catval-valupd-fixture-canary"),
        "teardown-stable-vm-result.txt": ("instance", "catval-valupd-fixture-stable"),
        "teardown-canary-disk-result.txt": ("disk", "catval-valupd-fixture-canary"),
        "teardown-stable-disk-result.txt": ("disk", "catval-valupd-fixture-stable"),
        "teardown-firewall-result.txt": ("firewall", "catval-valupd-fixture-ssh"),
        "teardown-subnet-result.txt": ("subnet", "catval-valupd-fixture-subnet"),
        "teardown-network-result.txt": ("network", "catval-valupd-fixture-net"),
    }
    for relative, (kind, name) in teardown_resources.items():
        (evidence / relative).write_text(
            f"TEARDOWN_RESOURCE_ABSENT kind={kind} name={name} attempt=1\n",
            encoding="ascii",
        )
    (evidence / RESULT.RESULT_PUBLIC_KEY_NAME).write_bytes(public_path.read_bytes())
    control = {
        "schema": "cathedral_validator_live_update_control_v1",
        "run_id": "valupd-fixture",
        "vm_count": 2,
        "source_repository": "cathedralai/cathedral-validator",
        "source_revision_a": "a" * 40,
        "source_revision_b": "b" * 40,
        "archive_a_sha256": "1" * 64,
        "archive_b_sha256": "2" * 64,
        "result_signer": {
            "purpose": "live_e2e_test_evidence_only",
            "key_id": "auditor-live-e2e-fixture",
            "algorithm": "ed25519",
            "public_key_fingerprint": fingerprint,
        },
    }
    (evidence / "control.json").write_bytes(RESULT.canonical_bytes(control))
    marker = "SCENARIOS_PASS_PENDING_TEARDOWN all bounded no-chain updater scenarios"
    (evidence / "steps.log").write_text(
        f"2026-09-01T00:00:00Z {marker}\n", encoding="ascii"
    )
    (evidence / "teardown-status.txt").write_text(
        "original_status=0\nteardown_verified=1\n", encoding="ascii"
    )
    for relative in RESULT.EMPTY_TEARDOWN_LISTS:
        (evidence / relative).write_text("[]\n", encoding="ascii")
    (evidence / "pre-teardown-instances.json").write_text(
        '[{"name":"catval-valupd-fixture-canary"},'
        '{"name":"catval-valupd-fixture-stable"}]\n',
        encoding="ascii",
    )
    metadata = b'{"items":[]}\n'
    (evidence / "project-metadata-before.json").write_bytes(metadata)
    (evidence / "project-metadata-after-teardown.json").write_bytes(metadata)
    _capture_manifest(evidence, "final-canary", "2" * 64)
    _capture_manifest(evidence, "final-stable", "1" * 64)
    controller = tmp_path / "controller.sh"
    controller.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    return evidence, private_path, public_path, controller


def _finalize(evidence, private_path, public_path, controller):
    return subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "finalize",
            "--evidence-dir",
            str(evidence),
            "--private-key",
            str(private_path),
            "--public-key",
            str(public_path),
            "--key-id",
            "auditor-live-e2e-fixture",
            "--controller-script",
            str(controller),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def _verify(evidence, public_path):
    return subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "verify-result",
            "--evidence-dir",
            str(evidence),
            "--public-key",
            str(public_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_canonical_result_refuses_bound_evidence_tampering(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    finalized = _finalize(evidence, private_path, public_path, controller)
    assert finalized.returncode == 0, finalized.stderr
    result_path = evidence / RESULT.RESULT_NAME
    result_bytes = result_path.read_bytes()
    assert result_bytes == RESULT.canonical_bytes(json.loads(result_bytes))
    verified = _verify(evidence, public_path)
    assert verified.returncode == 0, verified.stderr
    assert verified.stdout.strip() == finalized.stdout.strip()

    (evidence / "source-repository.json").write_bytes(b"tampered\n")
    rejected = _verify(evidence, public_path)
    assert rejected.returncode != 0
    assert "evidence-tree digest mismatch" in rejected.stderr


def test_canonical_result_refuses_result_digest_mismatch(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    finalized = _finalize(evidence, private_path, public_path, controller)
    assert finalized.returncode == 0, finalized.stderr
    result_path = evidence / RESULT.RESULT_NAME
    result_path.chmod(0o644)
    result_path.write_bytes(result_path.read_bytes() + b" ")
    rejected = _verify(evidence, public_path)
    assert rejected.returncode != 0
    assert "live E2E result digest mismatch" in rejected.stderr


def test_canonical_result_refuses_detached_signature_tampering(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    finalized = _finalize(evidence, private_path, public_path, controller)
    assert finalized.returncode == 0, finalized.stderr
    signature_path = evidence / RESULT.SIGNATURE_NAME
    signature = bytearray(signature_path.read_bytes())
    signature[0] ^= 1
    signature_path.chmod(0o644)
    signature_path.write_bytes(signature)
    rejected = _verify(evidence, public_path)
    assert rejected.returncode != 0
    assert "live E2E result signature is invalid" in rejected.stderr


def test_canonical_result_refuses_an_evidence_symlink(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    os.symlink("control.json", evidence / "unexpected-link")
    rejected = _finalize(evidence, private_path, public_path, controller)
    assert rejected.returncode != 0
    assert "evidence tree contains a symlink" in rejected.stderr


def test_canonical_result_refuses_a_capture_from_the_wrong_host(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    manifest_path = evidence / "final-canary-sections.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    manifest["host"] = "catval-valupd-fixture-stable"
    manifest_path.write_bytes(RESULT.canonical_bytes(manifest))
    rejected = _finalize(evidence, private_path, public_path, controller)
    assert rejected.returncode != 0
    assert "wrong host or label" in rejected.stderr


def test_canonical_result_refuses_an_unhealthy_final_validator(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    artifact = evidence / "final-canary.d" / "direct_unit_show.txt"
    failed = artifact.read_bytes().replace(b"ActiveState=active", b"ActiveState=failed")
    artifact.write_bytes(failed)
    manifest_path = evidence / "final-canary-sections.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    for row in manifest["sections"]:
        if row["id"] == "direct_unit_show":
            row["artifact"]["bytes"] = len(failed)
            row["artifact"]["sha256"] = hashlib.sha256(failed).hexdigest()
    manifest_path.write_bytes(RESULT.canonical_bytes(manifest))
    rejected = _finalize(evidence, private_path, public_path, controller)
    assert rejected.returncode != 0
    assert "direct validator service is not healthy" in rejected.stderr


@pytest.mark.parametrize(
    "relative",
    (
        "canary-same-boot-reactivation-timer-reactivation-start.log",
        "same-archive-pid-before-value.txt",
        "teardown-network-result.txt",
    ),
)
def test_canonical_result_requires_new_upstream_scenario_proofs(tmp_path, relative):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    (evidence / relative).unlink()
    rejected = _finalize(evidence, private_path, public_path, controller)
    assert rejected.returncode != 0
    assert relative in rejected.stderr


def test_canonical_result_refuses_direct_service_continuity_mismatch(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    (evidence / "same-boot-reactivation-pid-after-value.txt").write_text(
        "43\n", encoding="ascii"
    )
    rejected = _finalize(evidence, private_path, public_path, controller)
    assert rejected.returncode != 0
    assert "changed the direct service PID" in rejected.stderr


def test_canonical_result_refuses_wrong_teardown_resource_identity(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    (evidence / "teardown-network-result.txt").write_text(
        "TEARDOWN_RESOURCE_ABSENT kind=network name=wrong attempt=1\n",
        encoding="ascii",
    )
    rejected = _finalize(evidence, private_path, public_path, controller)
    assert rejected.returncode != 0
    assert "teardown resource proof is invalid" in rejected.stderr


def test_cleanup_refuses_residual_resource_without_success_markers(tmp_path):
    script = CONTROLLER.read_text(encoding="utf-8")
    cleanup = "cleanup() {" + script.split("cleanup() {", 1)[1].split(
        "trap cleanup EXIT", 1
    )[0]
    evidence = tmp_path / "teardown"
    evidence.mkdir()
    completed = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            'EVIDENCE_DIR="$1"\n'
            "RUN_ID=residual-test\n"
            "CANARY_VM=canary\nSTABLE_VM=stable\nZONE=zone\nREGION=region\n"
            "FIREWALL=firewall\nSUBNET=subnet\nNETWORK=network\n"
            "CREATED_CANARY_VM=0\nCREATED_STABLE_VM=0\nCREATED_FIREWALL=0\n"
            "CREATED_SUBNET=0\nCREATED_NETWORK=0\n"
            "RUN_ROOT=/tmp/cathedral-live-residual-test.does-not-exist\n"
            "gc_calls=0\n"
            "gc() { gc_calls=$((gc_calls + 1)); if (( gc_calls == 6 )); "
            "then printf '[{}]\\n'; else printf '[]\\n'; fi; }\n"
            + cleanup
            + "\ntrue\ncleanup",
            "cleanup-residual-test",
            str(evidence),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    assert "TEARDOWN_NOT_PROVEN" in completed.stderr
    assert "TEARDOWN_COMPLETE" not in completed.stdout
    assert "LIVE_UPDATE_E2E_PASS" not in completed.stdout
    assert (evidence / "teardown-status.txt").read_text(encoding="ascii") == (
        "original_status=0\nteardown_verified=0\n"
    )


def test_cleanup_refuses_result_finalization_failure_without_pass(tmp_path):
    script = CONTROLLER.read_text(encoding="utf-8")
    cleanup = "cleanup() {" + script.split("cleanup() {", 1)[1].split(
        "trap cleanup EXIT", 1
    )[0]
    evidence = tmp_path / "result-failure"
    evidence.mkdir()
    completed = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            'EVIDENCE_DIR="$1"\n'
            "RUN_ID=result-failure\n"
            "CANARY_VM=canary\nSTABLE_VM=stable\nZONE=zone\nREGION=region\n"
            "FIREWALL=firewall\nSUBNET=subnet\nNETWORK=network\n"
            "CREATED_CANARY_VM=0\nCREATED_STABLE_VM=0\nCREATED_FIREWALL=0\n"
            "CREATED_SUBNET=0\nCREATED_NETWORK=0\n"
            "RUN_ROOT=/tmp/cathedral-live-result-failure.does-not-exist\n"
            "REPOSITORY_ROOT=/reviewed/repository\nSOURCE_REVISION_B="
            + "b" * 40
            + "\n"
            "RESULT_TOOL=/reviewed/result-tool\n"
            "E2E_RESULT_SIGNING_PRIVATE_KEY=/secure/private.pem\n"
            "E2E_RESULT_SIGNING_PUBLIC_KEY=/secure/public.pem\n"
            "E2E_RESULT_SIGNER_KEY_ID=test-result-key\n"
            "TEST_GITHUB_REPOSITORY=owner/test\nESTIMATED_COST_USD=0.1\n"
            "PLANNING_TOTAL_USD=0.3\nBOOTSTRAP_TAG=test-tag\n"
            "gc() { printf '[]\\n'; }\n"
            "git() { if [[ \"$*\" == *\"rev-parse HEAD\"* ]]; then "
            "printf '%s\\n' \"$SOURCE_REVISION_B\"; fi; }\n"
            "python3() { printf 'finalizer-refused\\n' >&2; return 2; }\n"
            + cleanup
            + "\ntrue\ncleanup",
            "cleanup-result-failure-test",
            str(evidence),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    assert "TEARDOWN_COMPLETE" in completed.stdout
    assert "LIVE_UPDATE_E2E_RESULT_NOT_PROVEN" in completed.stderr
    assert "LIVE_UPDATE_E2E_PASS" not in completed.stdout


def test_controller_finalizes_before_terminal_pass_and_docs_match():
    script = CONTROLLER.read_text(encoding="utf-8")
    docs = (ROOT / "docs" / "RELEASE_MAINTAINER.md").read_text(encoding="utf-8")
    cleanup = script.split("cleanup() {", 1)[1].split("trap cleanup EXIT", 1)[0]
    assert "EVIDENCE_DIR must be a directory and not a symlink" in script
    assert cleanup.index('"$RESULT_TOOL" finalize') < cleanup.index(
        '"$RESULT_TOOL" verify-result'
    )
    assert cleanup.index('"$RESULT_TOOL" verify-result') < cleanup.index(
        "TEARDOWN_COMPLETE"
    )
    assert cleanup.index("TEARDOWN_COMPLETE") < cleanup.index(
        "LIVE_UPDATE_E2E_RESULT run="
    )
    assert cleanup.index("LIVE_UPDATE_E2E_RESULT run=") < cleanup.index(
        "LIVE_UPDATE_E2E_PASS"
    )
    assert script.count("LIVE_UPDATE_E2E_PASS") == 1
    assert "followed by\n`LIVE_UPDATE_E2E_PASS` as the final line" in docs
