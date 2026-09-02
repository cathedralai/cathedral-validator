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
            '  /bin/bash -c \'sudo() { printf "sudo-denied\\n" >&2; return 77; }; '
            'export -f sudo; eval "$1"\' capture-remote "$command"\n'
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
            '    case "$1" in\n'
            '      readlink) printf "releases/%064d\\n" 1 ;;\n'
            '      cat) printf "{\\"pending\\":null}\\n" ;;\n'
            '      journalctl) printf "no-journal\\n"; return 4 ;;\n'
            '      systemctl) if [[ "$2" == status ]]; then '
            'printf "inactive\\n"; return 3; else printf "recorded\\n"; fi ;;\n'
            "      *) return 76 ;;\n"
            "    esac\n"
            '  }; export -f sudo; eval "$1"\' capture-remote "$command"\n'
            "}\n" + capture_host + "\ncapture_host required-pass vm-a\n",
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


def _release_key_pair(root, stem):
    private = Ed25519PrivateKey.generate()
    private_path = root / f"{stem}-private.pem"
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    der = private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, private_path, pem, f"sha256:{hashlib.sha256(der).hexdigest()}"


def _signed_runtime_metadata(
    private,
    *,
    repository,
    channel,
    sequence,
    archive_sha256,
    promoted_canary=None,
):
    release_name = "a" if archive_sha256 == "1" * 64 else "b"
    release = {
        "version": f"fixture-{release_name}",
        "archive_url": (
            f"https://github.com/{repository}/releases/download/"
            f"validator-{archive_sha256}/"
            f"cathedral-validator-{archive_sha256}.tar.gz"
        ),
        "archive_sha256": archive_sha256,
        "tree_sha256": hashlib.sha256(
            f"fixture-tree-{release_name}".encode("ascii")
        ).hexdigest(),
        "entrypoint": RESULT.RUNTIME_RELEASE_ENTRYPOINT,
    }
    if promoted_canary is not None:
        release["promoted_canary"] = promoted_canary
    issued_unix = 1_700_000_000 + sequence * 60
    signed = {
        "schema": RESULT.RUNTIME_METADATA_SCHEMA,
        "channel": channel,
        "sequence": sequence,
        "issued_unix": issued_unix,
        "expires_unix": issued_unix + RESULT.RUNTIME_METADATA_LIFETIME_SECONDS,
        "release": release,
    }
    signed_bytes = RESULT.canonical_bytes(signed)
    raw = RESULT.canonical_bytes(
        {
            "signed": signed,
            "signature": base64.b64encode(private.sign(signed_bytes)).decode("ascii"),
        }
    )
    return raw, {
        "sequence": sequence,
        "archive_sha256": archive_sha256,
        "signed_sha256": hashlib.sha256(signed_bytes).hexdigest(),
        "metadata_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _runtime_metadata_fixture(evidence, private, repository):
    records = {}
    raw_documents = {}
    for name, sequence, archive_sha256 in (
        ("canary-a-seq1.json", 1, "1" * 64),
        ("canary-b-seq2.json", 2, "2" * 64),
        ("canary-b-renewal-seq3.json", 3, "2" * 64),
        ("canary-a-equivocation-seq3.json", 3, "1" * 64),
        ("canary-a-seq4.json", 4, "1" * 64),
    ):
        raw, record = _signed_runtime_metadata(
            private,
            repository=repository,
            channel="canary",
            sequence=sequence,
            archive_sha256=archive_sha256,
        )
        raw_documents[name] = raw
        records[name] = record
    for name, sequence, source_name in (
        ("stable-a-seq1.json", 1, "canary-a-seq1.json"),
        ("stable-b-seq2.json", 2, "canary-b-seq2.json"),
        ("stable-a-seq3.json", 3, "canary-a-seq4.json"),
        ("stable-b-seq4.json", 4, "canary-b-renewal-seq3.json"),
        ("stable-a-rescue-seq5.json", 5, "canary-a-seq4.json"),
    ):
        source_record = records[source_name]
        promoted_canary = {
            "sequence": source_record["sequence"],
            "signed_sha256": source_record["signed_sha256"],
            "metadata_sha256": source_record["metadata_sha256"],
            "archive_sha256": source_record["archive_sha256"],
        }
        raw, record = _signed_runtime_metadata(
            private,
            repository=repository,
            channel="stable",
            sequence=sequence,
            archive_sha256=source_record["archive_sha256"],
            promoted_canary=promoted_canary,
        )
        raw_documents[name] = raw
        records[name] = record
    invalid = json.loads(raw_documents["canary-b-seq2.json"])
    invalid_signature = bytearray(base64.b64decode(invalid["signature"], validate=True))
    invalid_signature[0] ^= 1
    invalid["signature"] = base64.b64encode(invalid_signature).decode("ascii")
    raw_documents[RESULT.INVALID_RUNTIME_METADATA_NAME] = RESULT.canonical_bytes(
        invalid
    )
    metadata_root = evidence / "signed-runtime-metadata"
    for name, raw in raw_documents.items():
        (metadata_root / name).write_bytes(raw)
    return records


def _bootstrap_fixture(
    evidence,
    *,
    private,
    bootstrap_public_pem,
    bootstrap_fingerprint,
    runtime_public_pem,
    runtime_fingerprint,
    stable_a1_record,
    source_repository,
    publication_repository,
    target_revision,
):
    bundle_sha256 = hashlib.sha256(b"fixture bootstrap bundle").hexdigest()
    guided_setup = (
        ROOT / "deploy" / "validator-update" / "cathedral-validator-setup"
    ).read_bytes()
    guided_status = (
        ROOT / "deploy" / "validator-update" / "cathedral-validator-status"
    ).read_bytes()
    manifest = {
        "bundle": {"sha256": bundle_sha256, "size": 4096},
        "files": [
            {
                "mode": "0755",
                "path": "payload/installer/install_updater_bundle.py",
                "sha256": hashlib.sha256(b"fixture installer").hexdigest(),
                "size": len(b"fixture installer"),
            },
            {
                "mode": "0644",
                "path": "payload/operator/cathedral-validator-setup",
                "sha256": hashlib.sha256(guided_setup).hexdigest(),
                "size": len(guided_setup),
            },
            {
                "mode": "0644",
                "path": "payload/operator/cathedral-validator-status",
                "sha256": hashlib.sha256(guided_status).hexdigest(),
                "size": len(guided_status),
            },
            {
                "mode": "0644",
                "path": "payload/requirements.txt",
                "sha256": hashlib.sha256(b"fixture requirements").hexdigest(),
                "size": len(b"fixture requirements"),
            },
            {
                "mode": "0644",
                "path": RESULT.RUNTIME_KEY_BUNDLE_PATH,
                "sha256": hashlib.sha256(runtime_public_pem).hexdigest(),
                "size": len(runtime_public_pem),
            },
        ],
        "install": {
            "enable_units": False,
            "installer": "payload/installer/install_updater_bundle.py",
            "python": "CPython==3.12.*",
            "requirements": "payload/requirements.txt",
            "wheelhouse": "payload/wheelhouse",
        },
        "bootstrap_signing_key": {
            "algorithm": "Ed25519",
            "fingerprint": bootstrap_fingerprint,
            "source": "operator-pinned-external",
        },
        "bootstrap_metadata": {
            "issued_unix": 1_700_001_000,
            "expires_unix": 1_700_001_000 + RESULT.BOOTSTRAP_LIFETIME_SECONDS,
            "sequence": 1,
        },
        "runtime_release_key": {
            "algorithm": "Ed25519",
            "fingerprint": runtime_fingerprint,
            "path": RESULT.RUNTIME_KEY_BUNDLE_PATH,
        },
        "stable_release_floor": {
            "metadata_sha256": stable_a1_record["metadata_sha256"],
            "sequence": 1,
        },
        "schema": RESULT.BOOTSTRAP_MANIFEST_SCHEMA,
    }
    manifest_raw = RESULT.canonical_bytes(manifest)
    manifest_signature = private.sign(manifest_raw)
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    tag = f"validator-bootstrap-test-s1-{manifest_sha256}"
    build = {
        "bundle_sha256": bundle_sha256,
        "manifest_sha256": manifest_sha256,
        "bootstrap_sequence": 1,
        "bootstrap_signing_key_fingerprint": bootstrap_fingerprint,
        "runtime_release_key_fingerprint": runtime_fingerprint,
        "stable_release_minimum_sequence": 1,
        "signature_base64": base64.b64encode(manifest_signature).decode("ascii"),
    }
    (evidence / "updater-bootstrap.manifest.json").write_bytes(manifest_raw)
    (evidence / "updater-bootstrap.manifest.sig").write_bytes(manifest_signature)
    (evidence / "bootstrap-build.json").write_bytes(RESULT.canonical_bytes(build))
    base_url = f"https://github.com/{publication_repository}/releases/download/{tag}"
    publication = {
        "schema": RESULT.BOOTSTRAP_PUBLICATION_SCHEMA,
        "source_repository": source_repository,
        "publication_repository": publication_repository,
        "canonical_source_write_allowed": False,
        "track": "test",
        "tag": tag,
        "target_revision": target_revision,
        "sequence": 1,
        "bootstrap_key_fingerprint": bootstrap_fingerprint,
        "runtime_key_fingerprint": runtime_fingerprint,
        "anonymous_download_required": True,
        "assets": {
            "bundle": {
                "url": f"{base_url}/updater-bootstrap.tar.gz",
                "sha256": bundle_sha256,
            },
            "manifest": {
                "url": f"{base_url}/updater-bootstrap.manifest.json",
                "sha256": manifest_sha256,
            },
            "signature": {
                "url": f"{base_url}/updater-bootstrap.manifest.sig",
                "sha256": hashlib.sha256(manifest_signature).hexdigest(),
            },
            "public_key": {
                "url": f"{base_url}/bootstrap-signing-public-key.pem",
                "sha256": hashlib.sha256(bootstrap_public_pem).hexdigest(),
            },
        },
    }
    (evidence / "bootstrap-publication.json").write_bytes(
        RESULT.canonical_bytes(publication)
    )
    return tag


def _capture_manifest(evidence, label, expected_record):
    artifacts = evidence / f"{label}.d"
    artifacts.mkdir(mode=0o700)
    role = label.removeprefix("final-")
    rows = []
    for section_id, required in RESULT.GENERIC_SECTIONS:
        if section_id == "updater_state":
            payload = RESULT.canonical_bytes(
                {
                    "schema": "cathedral_validator_updater_state_v3",
                    "selected_channel": role,
                    "channels": {role: expected_record},
                    "pending": None,
                }
            )
        elif section_id == "current_release":
            payload = f"releases/{expected_record['archive_sha256']}\n".encode("ascii")
        elif section_id == "direct_unit_show":
            if role == "canary":
                payload = (
                    b"Result=success\nExecMainCode=0\nExecMainStatus=0\n"
                    b"ActiveState=active\nSubState=running\nMainPID=42\n"
                    b"InvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                )
            else:
                payload = (
                    b"Result=success\nExecMainCode=1\nExecMainStatus=0\n"
                    b"ActiveState=inactive\nSubState=dead\nMainPID=0\n"
                    b"InvocationID=\n"
                )
        elif section_id == "boot_reconcile_show":
            payload = (
                b"Result=success\nExecMainCode=1\nExecMainStatus=0\n"
                b"ActiveState=inactive\nSubState=dead\nMainPID=0\n"
            )
        elif section_id == "updater_services_show":
            payload = (
                b"Id=cathedral-validator-canary-update.service\n"
                b"Result=success\nExecMainCode=1\nExecMainStatus=0\n"
                b"ActiveState=inactive\nSubState=dead\nMainPID=0\n\n"
                b"Id=cathedral-validator-update.service\n"
                b"Result=success\nExecMainCode=0\nExecMainStatus=0\n"
                b"ActiveState=inactive\nSubState=dead\nMainPID=0\n"
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


def _guided_status_fixture(
    evidence,
    relative,
    record,
    *,
    service_active,
    timer_active,
    result,
):
    action = (
        "Inspect cathedral-validator-direct.service logs. Do not delete its journal."
        if result == "NEEDS_REVIEW"
        else "Wait for recovery or the next cycle. Do not retry or replace the journal."
    )
    document = {
        "schema": "cathedral_validator_local_status_v1",
        "service_active": service_active,
        "stable_timer_active": timer_active,
        "stable_timer_enabled": timer_active,
        "release": record["archive_sha256"],
        "evidence": (
            "local process and durable state only. This does not prove current "
            "chain inclusion."
        ),
        "updater": {
            "channel": "stable",
            "sequence": record["sequence"],
            "archive_digest": record["archive_sha256"],
            "pending_recovery": False,
        },
        "direct": {
            "pending": False,
            "last_result": None,
            "block_number": None,
            "recorded_age_seconds": 0,
        },
        "result": result,
        "action": action,
    }
    raw = RESULT.canonical_bytes(document)
    (evidence / relative).write_bytes(raw)
    return raw


def _guided_transition_fixture(
    evidence,
    control,
    *,
    relative,
    schema,
    status_file,
    before,
    after,
    outcomes,
):
    proof = {
        "schema": schema,
        "host": "catval-valupd-fixture-stable",
        "guided_assets": {
            name: {
                "installed_path": control["guided_operator"][name]["installed_path"],
                "sha256": control["guided_operator"][name]["source_sha256"],
                "uid": 0,
                "gid": 0,
                "mode": "0755",
                "regular_file": True,
                "symlink": False,
            }
            for name in ("setup", "status")
        },
        "operator_inputs": control["guided_operator"]["operator_inputs"],
        "before": before,
        "after": after,
        "status": {
            "file": status_file,
            "sha256": hashlib.sha256((evidence / status_file).read_bytes()).hexdigest(),
        },
        "outcomes": outcomes,
    }
    (evidence / relative).write_bytes(RESULT.canonical_bytes(proof))


def _success_tree(tmp_path):
    key_root = tmp_path / "keys"
    key_root.mkdir()
    private_path, public_path, fingerprint = _key_pair(key_root)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    for relative in RESULT.REQUIRED_SUCCESS_FILES:
        path = evidence / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"recorded\n")
    for relative in RESULT.DIRECT_SERVICE_PID_PROOFS:
        (evidence / relative).write_text("42\n", encoding="ascii")
    for relative in RESULT.DIRECT_SERVICE_INVOCATION_PROOFS:
        (evidence / relative).write_text("a" * 32 + "\n", encoding="ascii")
    source_repository = "cathedralai/cathedral-validator"
    publication_repository = "cathedralai/cathedral-validator-release-e2e"
    target_revision = "b" * 40
    (
        runtime_private,
        _runtime_private_path,
        runtime_public_bytes,
        runtime_fingerprint,
    ) = _release_key_pair(key_root, "runtime")
    (
        bootstrap_private,
        _bootstrap_private_path,
        bootstrap_public_bytes,
        bootstrap_fingerprint,
    ) = _release_key_pair(key_root, "bootstrap")
    (evidence / "runtime-release-public-key.pem").write_bytes(runtime_public_bytes)
    (evidence / "bootstrap-release-public-key.pem").write_bytes(bootstrap_public_bytes)
    runtime_records = _runtime_metadata_fixture(
        evidence, runtime_private, publication_repository
    )
    bootstrap_tag = _bootstrap_fixture(
        evidence,
        private=bootstrap_private,
        bootstrap_public_pem=bootstrap_public_bytes,
        bootstrap_fingerprint=bootstrap_fingerprint,
        runtime_public_pem=runtime_public_bytes,
        runtime_fingerprint=runtime_fingerprint,
        stable_a1_record=runtime_records["stable-a-seq1.json"],
        source_repository=source_repository,
        publication_repository=publication_repository,
        target_revision=target_revision,
    )
    for channel, name in (
        ("canary", "canary-a-seq1.json"),
        ("stable", "stable-a-seq1.json"),
    ):
        record = runtime_records[name]
        (evidence / f"{channel}-first-install-sequence-state.json").write_bytes(
            RESULT.canonical_bytes(
                {
                    "channel": channel,
                    "current": "releases/" + "1" * 64,
                    "record": record,
                    "sequence": 1,
                    "pending": None,
                }
            )
        )
    (
        evidence / "canary-same-boot-reactivation-timer-reactivation-start.log"
    ).write_text(
        "CATHEDRAL_TIMER_REACTIVATION_PROOF_V1\n"
        "ProofHost=catval-valupd-fixture-canary\n"
        "ProofTimer=cathedral-validator-canary-update.timer\n"
        "ProofService=cathedral-validator-canary-update.service\n"
        "ProofChannel=canary\n"
        f"ExpectedRelease={'2' * 64}\n"
        f"BeforeServiceInvocationID={'b' * 32}\n"
        "BeforeLastTriggerUSec=Mon 2026-09-01 00:00:00 UTC\n"
        "OnActiveUSec=1s\nOnUnitActiveUSec=2s\n"
        "Id=cathedral-validator-canary-update.timer\n"
        "UnitFileState=enabled\nActiveState=active\nSubState=waiting\n"
        "NextElapseUSecMonotonic=1min\n"
        "LastTriggerUSec=Mon 2026-09-01 00:00:00 UTC\n",
        encoding="ascii",
    )
    (evidence / "canary-same-boot-reactivation-timer-reactivation-wait.log").write_text(
        "ActiveState=active\nSubState=waiting\n"
        "NextElapseUSecMonotonic=2min\n"
        "LastTriggerUSec=Mon 2026-09-01 00:01:00 UTC\n"
        f"ServiceInvocationID={'c' * 32}\n"
        "ServiceResult=success\nServiceExecMainStatus=0\n"
        "ServiceActiveState=inactive\n",
        encoding="ascii",
    )
    (
        evidence / "canary-same-boot-reactivation-timer-reactivation-state.log"
    ).write_text(
        json.dumps(
            {
                "channel": "canary",
                "current": "releases/" + "2" * 64,
                "record": {"sequence": 3, "archive_sha256": "2" * 64},
                "sequence": 3,
                "pending": None,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
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
        label = relative.removeprefix("teardown-").removesuffix("-result.txt")
        (evidence / f"teardown-{label}-check-1.json").write_text(
            "[]\n", encoding="ascii"
        )
    (evidence / RESULT.RESULT_PUBLIC_KEY_NAME).write_bytes(public_path.read_bytes())
    control = {
        "schema": "cathedral_validator_live_update_control_v1",
        "run_id": "valupd-fixture",
        "gcp_project": "polaris-tdx-attest",
        "zone": "us-central1-a",
        "controller_transport": "gcp_iap_tcp_forwarding",
        "iap_source_range": "35.235.240.0/20",
        "vm_service_account_attached": False,
        "machine_type": "e2-standard-2",
        "vm_count": 2,
        "max_run_seconds": 14400,
        "vm_and_disk_estimate_usd": "0.6240",
        "network_ipv4_and_egress_allowance_usd": "0.20",
        "planning_total_usd": "0.8240",
        "cost_scope": RESULT.CONTROL_COST_SCOPE,
        "source_repository": source_repository,
        "test_publication_repository": publication_repository,
        "test_mirror_main_sha": target_revision,
        "canonical_source_write_allowed": False,
        "source_revision_a": "a" * 40,
        "source_revision_b": target_revision,
        "archive_a_sha256": "1" * 64,
        "archive_b_sha256": "2" * 64,
        "bootstrap_key_fingerprint": bootstrap_fingerprint,
        "runtime_key_fingerprint": runtime_fingerprint,
        "canary_branch": "validator-release-live-valupd-fixture-canary",
        "stable_branch": "validator-release-live-valupd-fixture-stable",
        "fault_branch": "validator-release-fault-valupd-fixture",
        "no_chain_harness_sha256": "5" * 64,
        "fault_origin_sha256": "6" * 64,
        "state_waiter_sha256": "7" * 64,
        "result_signer": {
            "purpose": "live_e2e_test_evidence_only",
            "key_id": "auditor-live-e2e-fixture",
            "algorithm": "ed25519",
            "public_key_fingerprint": fingerprint,
        },
        "bootstrap_track": "test",
        "bootstrap_tag": bootstrap_tag,
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
        "guided_operator": {
            "setup": {
                "source_sha256": hashlib.sha256(
                    (
                        ROOT
                        / "deploy"
                        / "validator-update"
                        / "cathedral-validator-setup"
                    ).read_bytes()
                ).hexdigest(),
                "installed_path": "/usr/local/sbin/cathedral-validator-setup",
            },
            "status": {
                "source_sha256": hashlib.sha256(
                    (
                        ROOT
                        / "deploy"
                        / "validator-update"
                        / "cathedral-validator-status"
                    ).read_bytes()
                ).hexdigest(),
                "installed_path": "/usr/local/sbin/cathedral-validator-status",
            },
            "operator_inputs": {
                "hotkey_keyfile_sha256": "8" * 64,
                "snp_policy_sha256": "9" * 64,
                "raw_key_material_recorded": False,
            },
            "terminal_expectation": "stopped_writer_needs_review",
        },
        "fixed_channel_cache_max_seconds": 300,
        "update_timer_interval_seconds": 60,
        "fixed_channel_wait_seconds": 1860,
    }
    (evidence / "control.json").write_bytes(RESULT.canonical_bytes(control))
    (evidence / "steps.log").write_text(
        "".join(
            f"2026-09-01T00:{index:02d}:00Z {message}\n"
            for index, message in enumerate(RESULT.RECORDED_STEPS)
        ),
        encoding="ascii",
    )
    (evidence / "teardown-status.txt").write_text(
        "original_status=0\nteardown_verified=1\n", encoding="ascii"
    )
    for relative in RESULT.EMPTY_TEARDOWN_LISTS:
        (evidence / relative).write_text("[]\n", encoding="ascii")
    instances = [
        {
            "name": "catval-valupd-fixture-canary",
            "id": "101",
            "zone": "https://compute.googleapis.com/compute/v1/projects/"
            "polaris-tdx-attest/zones/us-central1-a",
            "labels": {"cathedral-live-run": "valupd-fixture"},
            "serviceAccounts": [],
        },
        {
            "name": "catval-valupd-fixture-stable",
            "id": "102",
            "zone": "https://compute.googleapis.com/compute/v1/projects/"
            "polaris-tdx-attest/zones/us-central1-a",
            "labels": {"cathedral-live-run": "valupd-fixture"},
            "serviceAccounts": [],
        },
    ]
    (evidence / "canary-instance.json").write_bytes(
        RESULT.canonical_bytes(instances[0])
    )
    (evidence / "stable-instance.json").write_bytes(
        RESULT.canonical_bytes(instances[1])
    )
    (evidence / "created-run-instances.json").write_bytes(
        RESULT.canonical_bytes(instances)
    )
    (evidence / "pre-teardown-instances.json").write_bytes(
        RESULT.canonical_bytes(instances)
    )
    metadata = b'{"items":[]}\n'
    (evidence / "project-metadata-before.json").write_bytes(metadata)
    (evidence / "project-metadata-after-teardown.json").write_bytes(metadata)

    a1 = runtime_records["stable-a-seq1.json"]
    b2 = runtime_records["stable-b-seq2.json"]
    a5 = runtime_records["stable-a-rescue-seq5.json"]
    _guided_status_fixture(
        evidence,
        "guided-status-after-setup.json",
        a1,
        service_active=True,
        timer_active=True,
        result="NOT_PROVEN",
    )
    _guided_status_fixture(
        evidence,
        "guided-status-after-timer-b.json",
        b2,
        service_active=True,
        timer_active=True,
        result="NOT_PROVEN",
    )
    _guided_status_fixture(
        evidence,
        "guided-status-stopped-writer.json",
        a5,
        service_active=False,
        timer_active=False,
        result="NEEDS_REVIEW",
    )
    durable_initial = {
        "updater_state_sha256": "a" * 64,
        "setup_complete_sha256": "b" * 64,
        "installed_hotkey_sha256": "8" * 64,
        "installed_snp_policy_sha256": "9" * 64,
        "update_env_sha256": "c" * 64,
    }
    idempotent_identity = {
        "main_pid": 42,
        "invocation_id": "a" * 32,
        "durable_sha256": durable_initial,
    }
    _guided_transition_fixture(
        evidence,
        control,
        relative="guided-setup-idempotence-proof.json",
        schema="cathedral_validator_guided_setup_idempotence_proof_v1",
        status_file="guided-status-after-setup.json",
        before=idempotent_identity,
        after=idempotent_identity,
        outcomes={
            "initial_setup_exit": 0,
            "idempotent_rerun_exit": 0,
            "setup_complete_marker": (
                "SETUP_COMPLETE: stable direct validator configured"
            ),
        },
    )
    durable_stopped = {
        "updater_state_sha256": "d" * 64,
        "setup_complete_sha256": "e" * 64,
        "installed_hotkey_sha256": "8" * 64,
        "installed_snp_policy_sha256": "9" * 64,
        "update_env_sha256": "f" * 64,
    }
    _guided_transition_fixture(
        evidence,
        control,
        relative="guided-setup-stopped-writer-proof.json",
        schema="cathedral_validator_guided_setup_stopped_writer_proof_v1",
        status_file="guided-status-stopped-writer.json",
        before={
            "main_pid": 55,
            "invocation_id": "d" * 32,
            "durable_sha256": durable_stopped,
        },
        after={
            "main_pid": 0,
            "invocation_id": "",
            "durable_sha256": durable_stopped,
        },
        outcomes={
            "stop_writer_exit": 0,
            "refused_setup_exit": 2,
            "refusal_marker": (
                "SETUP_REFUSED: existing direct validator is stopped and needs review"
            ),
            "writer_remained_stopped": True,
        },
    )
    idempotent_digests = ":".join(
        durable_initial[field] for field in RESULT.GUIDED_DURABLE_DIGEST_FIELDS
    )
    (evidence / "first-install-command-catval-valupd-fixture-stable.log").write_text(
        "OPERATOR_INPUTS_STAGED "
        f"hotkey_sha256={'8' * 64} policy_sha256={'9' * 64}\n"
        "SETUP_COMPLETE: stable direct validator configured\n"
        "GUIDED_SETUP_CONFIG_PROOF host=catval-valupd-fixture-stable\n"
        "GUIDED_STATUS_PROOF label=guided-status-after-setup "
        f"result=NOT_PROVEN release={'1' * 64} sequence=1\n"
        "SETUP_COMPLETE: stable direct validator configured\n"
        "GUIDED_SETUP_IDEMPOTENT_RERUN host=catval-valupd-fixture-stable "
        f"identity=42:{'a' * 32}\n{idempotent_digests}\n",
        encoding="ascii",
    )
    (evidence / "guided-status-after-timer-b-command.log").write_text(
        "GUIDED_STATUS_PROOF label=guided-status-after-timer-b "
        f"result=NOT_PROVEN release={'2' * 64} sequence=2\n",
        encoding="ascii",
    )
    (evidence / "guided-setup-stopped-writer-command.log").write_text(
        "DIRECT_WRITER_STOPPED_FOR_PROOF\n"
        "SETUP_REFUSED: existing direct validator is stopped and needs review\n"
        "SETUP_EXIT=2\n"
        "DIRECT_WRITER_STILL_STOPPED\n"
        "GUIDED_STATUS_PROOF label=guided-status-stopped-writer "
        f"result=NEEDS_REVIEW release={'1' * 64} sequence=5\n"
        "GUIDED_SETUP_STOPPED_WRITER_REFUSED host="
        "catval-valupd-fixture-stable\n",
        encoding="ascii",
    )
    (evidence / "stable-higher-sequence-rescue-sequence-state.json").write_bytes(
        RESULT.canonical_bytes(
            {
                "channel": "stable",
                "current": "releases/" + "1" * 64,
                "record": a5,
                "sequence": 5,
                "pending": None,
            }
        )
    )
    (evidence / "higher-sequence-rescue-current-proof.txt").write_text(
        f"expected={'1' * 64} observed={'1' * 64}\n", encoding="ascii"
    )
    (evidence / "higher-sequence-rescue-service-command.log").write_text(
        "active\n", encoding="ascii"
    )
    _capture_manifest(
        evidence, "final-canary", runtime_records["canary-b-renewal-seq3.json"]
    )
    _capture_manifest(
        evidence, "final-stable", runtime_records["stable-a-rescue-seq5.json"]
    )
    for _scenario_id, _step, artifacts in RESULT.SCENARIO_SPECS:
        for template, empty_allowed in artifacts:
            relative = template.format(run_id="valupd-fixture")
            path = evidence / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(b"" if empty_allowed else b"recorded\n")
    service_before = (
        b"ActiveState=active\nSubState=running\nMainPID=42\n"
        b"InvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    )
    service_after_restart = (
        b"ActiveState=active\nSubState=running\nMainPID=43\n"
        b"InvocationID=dddddddddddddddddddddddddddddddd\n"
    )
    for (
        label,
        archive_field,
        sequence,
        service_policy,
    ) in RESULT.NEGATIVE_SCENARIO_INVARIANTS:
        archive_sha256 = control[archive_field]
        record = runtime_records[
            "canary-a-seq1.json" if sequence == 1 else "canary-b-renewal-seq3.json"
        ]
        snapshot = RESULT.canonical_bytes(
            {
                "channel": "canary",
                "current": f"releases/{archive_sha256}",
                "record": record,
                "sequence": sequence,
                "pending": None,
            }
        )
        (evidence / f"{label}-before.json").write_bytes(snapshot)
        (evidence / f"{label}-after.json").write_bytes(snapshot)
        (evidence / f"{label}-service-before.txt").write_bytes(service_before)
        (evidence / f"{label}-service-after.txt").write_bytes(
            service_after_restart if service_policy == "restarted" else service_before
        )
    for relative, archive_field in RESULT.CURRENT_RELEASE_PROOFS:
        archive_sha256 = control[archive_field]
        (evidence / relative).write_text(
            f"expected={archive_sha256} observed={archive_sha256}\n",
            encoding="ascii",
        )
    scan_exclusions = {
        "operator-secret-scan.json",
        "teardown-status.txt",
        "controller-source-finalization.stderr",
        *RESULT.RESULT_EXCLUSIONS,
    }
    evidence_file_count = sum(
        1
        for path in evidence.rglob("*")
        if path.is_file()
        and path.relative_to(evidence).as_posix() not in scan_exclusions
    )
    (evidence / "operator-secret-scan.json").write_bytes(
        RESULT.canonical_bytes(
            {
                "schema": "cathedral_validator_operator_secret_scan_v1",
                "operator_input_file_sha256": "8" * 64,
                "checked_field_names": ["privateKey", "publicKey", "ss58Address"],
                "evidence_file_count": evidence_file_count,
                "exact_match_count": 0,
            }
        )
    )
    return evidence, private_path, public_path, CONTROLLER


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


def _rewrite_and_resign_result(evidence, private_path, mutation):
    result_path = evidence / RESULT.RESULT_NAME
    signature_path = evidence / RESULT.SIGNATURE_NAME
    digest_path = evidence / RESULT.DIGEST_NAME
    document = json.loads(result_path.read_text(encoding="ascii"))
    mutation(document)
    result_data = RESULT.canonical_bytes(document)
    private = serialization.load_pem_private_key(
        private_path.read_bytes(), password=None
    )
    signature = private.sign(result_data)
    for path in (result_path, signature_path, digest_path):
        path.chmod(0o644)
    result_path.write_bytes(result_data)
    signature_path.write_bytes(signature)
    digest_path.write_text(
        f"{hashlib.sha256(result_data).hexdigest()}  {RESULT.RESULT_NAME}\n",
        encoding="ascii",
    )


def _resign_for_current_evidence(evidence, private_path):
    def refresh(document):
        for scenario in document["scenario_matrix"]["scenarios"]:
            refreshed = []
            for artifact in scenario["artifacts"]:
                path = evidence / artifact["path"]
                if not path.exists():
                    continue
                data = path.read_bytes()
                artifact["bytes"] = len(data)
                artifact["sha256"] = hashlib.sha256(data).hexdigest()
                refreshed.append(artifact)
            scenario["artifacts"] = refreshed
        rows = RESULT._inventory(evidence, RESULT.RESULT_EXCLUSIONS)
        document["evidence_tree"] = {
            "algorithm": RESULT.EVIDENCE_TREE_ALGORITHM,
            "root_sha256": RESULT._evidence_root(rows),
            "file_count": len(rows),
            "files": rows,
        }

    _rewrite_and_resign_result(evidence, private_path, refresh)


def _rewrite_capture_artifact(evidence, label, section_id, payload):
    artifact = evidence / f"{label}.d" / f"{section_id}.txt"
    artifact.write_bytes(payload)
    manifest_path = evidence / f"{label}-sections.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    for row in manifest["sections"]:
        if row["id"] == section_id:
            row["artifact"]["bytes"] = len(payload)
            row["artifact"]["sha256"] = hashlib.sha256(payload).hexdigest()
            break
    else:  # pragma: no cover - fixture contract
        raise AssertionError(f"missing capture section: {section_id}")
    manifest_path.write_bytes(RESULT.canonical_bytes(manifest))


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


@pytest.mark.parametrize(
    ("mutation", "error"),
    (
        (
            lambda result: result.__setitem__("unexpected", True),
            "unexpected or missing fields",
        ),
        (
            lambda result: result["terminal"].__setitem__(
                "original_exit_status", False
            ),
            "terminal has an invalid original_exit_status",
        ),
        (
            lambda result: result["scope"].__setitem__("chain_write", True),
            "scope has an invalid chain_write",
        ),
        (
            lambda result: result["authority"].__setitem__(
                "operator_identity_attested", True
            ),
            "authority has an invalid operator_identity_attested",
        ),
        (
            lambda result: result["signer"].__setitem__(
                "purpose", "mainnet_activation"
            ),
            "signer has an invalid purpose",
        ),
        (
            lambda result: result["signer"].__setitem__(
                "authorizes_chain_or_weight_changes", True
            ),
            "signer has an invalid authorizes_chain_or_weight_changes",
        ),
        (
            lambda result: result["controller"].__setitem__(
                "path", "scripts/not-the-reviewed-controller.sh"
            ),
            "controller has an invalid path",
        ),
        (
            lambda result: result["controller"].__setitem__(
                "result_tool_sha256", "0" * 64
            ),
            "controller has an invalid result_tool_sha256",
        ),
        (
            lambda result: result["evidence_tree"].__setitem__(
                "algorithm", "plain-file-concatenation"
            ),
            "evidence-tree digest mismatch",
        ),
        (
            lambda result: result["evidence_tree"].__setitem__("file_count", False),
            "evidence-tree digest mismatch",
        ),
    ),
)
def test_canonical_result_refuses_resigned_schema_or_authority_mutation(
    tmp_path, mutation, error
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    finalized = _finalize(evidence, private_path, public_path, controller)
    assert finalized.returncode == 0, finalized.stderr
    _rewrite_and_resign_result(evidence, private_path, mutation)

    rejected = _verify(evidence, public_path)

    assert rejected.returncode != 0
    assert error in rejected.stderr


@pytest.mark.parametrize(
    "finished_at",
    (
        "2026-09-01T12:34:56.000000Z",
        "2026-09-01T12:34:56+00:00",
        "2026-02-30T12:34:56Z",
    ),
)
def test_canonical_result_refuses_noncanonical_or_invalid_finished_at(
    tmp_path, finished_at
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    finalized = _finalize(evidence, private_path, public_path, controller)
    assert finalized.returncode == 0, finalized.stderr
    _rewrite_and_resign_result(
        evidence,
        private_path,
        lambda result: result["run"].__setitem__("finished_at", finished_at),
    )

    rejected = _verify(evidence, public_path)

    assert rejected.returncode != 0
    assert (
        "finished_at must be an RFC3339 UTC timestamp at whole seconds"
        in rejected.stderr
    )


def test_canonical_result_requires_retained_key_to_equal_pinned_key(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    finalized = _finalize(evidence, private_path, public_path, controller)
    assert finalized.returncode == 0, finalized.stderr
    replacement = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    retained = evidence / RESULT.RESULT_PUBLIC_KEY_NAME
    retained.chmod(0o644)
    retained.write_bytes(replacement)

    rejected = _verify(evidence, public_path)

    assert rejected.returncode != 0
    assert (
        "retained result public key differs from the pinned verifier key"
        in rejected.stderr
    )


def test_canonical_result_refuses_an_unreviewed_controller_path(tmp_path):
    evidence, private_path, public_path, _controller = _success_tree(tmp_path)
    unreviewed = tmp_path / "controller.sh"
    unreviewed.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")

    rejected = _finalize(evidence, private_path, public_path, unreviewed)

    assert rejected.returncode != 0
    assert (
        "live controller source does not use its reviewed canonical path"
        in rejected.stderr
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("vm_service_account_attached", True),
        ("canonical_source_write_allowed", True),
        ("bootstrap_track", "production"),
        ("test_publication_repository", "cathedralai/cathedral-validator"),
        ("test_mirror_main_sha", "c" * 40),
    ),
)
def test_canonical_result_refuses_a_relaxed_control_boundary(tmp_path, field, value):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    control_path = evidence / "control.json"
    control = json.loads(control_path.read_text(encoding="ascii"))
    control[field] = value
    control_path.write_bytes(RESULT.canonical_bytes(control))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "control document has an invalid" in rejected.stderr


def test_canonical_result_refuses_changed_cloud_instance_identity(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    inventory_path = evidence / "pre-teardown-instances.json"
    inventory = json.loads(inventory_path.read_text(encoding="ascii"))
    inventory[0]["id"] = "999"
    inventory_path.write_bytes(RESULT.canonical_bytes(inventory))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "host immutable identities changed" in rejected.stderr


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
    ("section_id", "old", "new", "error"),
    (
        (
            "boot_reconcile_show",
            b"Result=success",
            b"Result=exit-code",
            "boot reconcile service is not settled",
        ),
        (
            "updater_services_show",
            b"ExecMainStatus=0",
            b"ExecMainStatus=1",
            "updater services are not successful and settled",
        ),
    ),
)
def test_canonical_result_refuses_failed_final_control_services(
    tmp_path, section_id, old, new, error
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    artifact = evidence / "final-canary.d" / f"{section_id}.txt"
    payload = artifact.read_bytes().replace(old, new, 1)
    _rewrite_capture_artifact(evidence, "final-canary", section_id, payload)

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert error in rejected.stderr


@pytest.mark.parametrize("field", ("schema", "selected_channel", "channels"))
def test_canonical_result_requires_exact_final_updater_state(tmp_path, field):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    artifact = evidence / "final-canary.d" / "updater_state.txt"
    state = json.loads(artifact.read_text(encoding="ascii"))
    if field == "schema":
        state[field] = "cathedral_validator_updater_state_v2"
    elif field == "selected_channel":
        state[field] = "stable"
    else:
        state[field]["canary"]["sequence"] = 2
    _rewrite_capture_artifact(
        evidence,
        "final-canary",
        "updater_state",
        RESULT.canonical_bytes(state),
    )

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert (
        "updater state" in rejected.stderr
        or "updater channel record" in rejected.stderr
    )


@pytest.mark.parametrize(
    ("section_id", "error"),
    (
        ("updater_services_show", "updater services are not successful and settled"),
        ("timers_show", "updater timers are not disabled and settled"),
    ),
)
def test_canonical_result_refuses_duplicate_final_systemd_unit_ids(
    tmp_path, section_id, error
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    artifact = evidence / "final-canary.d" / f"{section_id}.txt"
    payload = artifact.read_bytes()
    duplicate = payload.split(b"\n\n", 1)[0]
    _rewrite_capture_artifact(
        evidence,
        "final-canary",
        section_id,
        payload.rstrip(b"\n") + b"\n\n" + duplicate + b"\n",
    )

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert error in rejected.stderr


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


def test_canonical_result_requires_every_scenario_artifact(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    (evidence / "invalid-signature.log").unlink()

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "scenario artifact invalid_signature_refusal" in rejected.stderr


def test_negative_scenario_matrix_binds_all_state_and_service_proofs():
    matrix_paths = {
        template
        for _scenario_id, _step, artifacts in RESULT.SCENARIO_SPECS
        for template, _empty_allowed in artifacts
    }
    for (
        label,
        _archive_field,
        _sequence,
        _service_policy,
    ) in RESULT.NEGATIVE_SCENARIO_INVARIANTS:
        assert {
            f"{label}-before.json",
            f"{label}-after.json",
            f"{label}-service-before.txt",
            f"{label}-service-after.txt",
        } <= matrix_paths


def test_scenario_contract_has_exact_guided_operator_evidence_grouping():
    assert len(RESULT.RECORDED_STEPS) == 18
    assert len(RESULT.SCENARIO_SPECS) == 18
    scenarios = {
        scenario_id: {path for path, _empty in artifacts}
        for scenario_id, _step, artifacts in RESULT.SCENARIO_SPECS
    }
    assert {
        "guided-status-after-setup.json",
        "guided-setup-idempotence-proof.json",
    } <= scenarios["signed_first_install"]
    assert {
        "guided-status-after-timer-b-command.log",
        "guided-status-after-timer-b.json",
    } <= scenarios["stable_timer_promotion"]
    assert scenarios["guided_operator_stopped_writer_review"] == {
        "guided-setup-stopped-writer-command.log",
        "guided-setup-stopped-writer-proof.json",
        "guided-status-stopped-writer.json",
    }
    assert "operator-secret-scan.json" in scenarios["final_capture"]


@pytest.mark.parametrize(
    ("relative", "mutation", "error"),
    (
        (
            "guided-setup-idempotence-proof.json",
            "changed_identity",
            "idempotent rerun changed writer state",
        ),
        (
            "guided-setup-stopped-writer-proof.json",
            "changed_durable_state",
            "refused rerun changed durable state",
        ),
        (
            "guided-setup-stopped-writer-proof.json",
            "writer_restarted",
            "does not prove a stopped writer identity",
        ),
        (
            "guided-setup-idempotence-proof.json",
            "detached_asset",
            "guided asset setup has an invalid sha256",
        ),
        (
            "guided-setup-idempotence-proof.json",
            "detached_policy",
            "does not bind the installed SNP policy",
        ),
        (
            "guided-setup-idempotence-proof.json",
            "detached_status",
            "status binding has an invalid sha256",
        ),
    ),
)
def test_canonical_result_refuses_guided_transition_proof_mutation(
    tmp_path, relative, mutation, error
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    proof_path = evidence / relative
    proof = json.loads(proof_path.read_text(encoding="ascii"))
    if mutation == "changed_identity":
        proof["after"]["main_pid"] += 1
    elif mutation == "changed_durable_state":
        proof["after"]["durable_sha256"]["updater_state_sha256"] = "0" * 64
    elif mutation == "writer_restarted":
        proof["after"]["main_pid"] = 56
        proof["after"]["invocation_id"] = "e" * 32
    elif mutation == "detached_asset":
        proof["guided_assets"]["setup"]["sha256"] = "0" * 64
    elif mutation == "detached_policy":
        proof["before"]["durable_sha256"]["installed_snp_policy_sha256"] = "0" * 64
        proof["after"]["durable_sha256"]["installed_snp_policy_sha256"] = "0" * 64
    else:
        proof["status"]["sha256"] = "0" * 64
    proof_path.write_bytes(RESULT.canonical_bytes(proof))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert error in rejected.stderr


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("installed_path", "/tmp/cathedral-validator-setup"),
        ("uid", 1),
        ("uid", False),
        ("gid", 1),
        ("mode", "0777"),
        ("regular_file", False),
        ("symlink", True),
    ),
)
def test_canonical_result_refuses_guided_asset_metadata_mutation(
    tmp_path, field, value
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    proof_path = evidence / "guided-setup-idempotence-proof.json"
    proof = json.loads(proof_path.read_text(encoding="ascii"))
    proof["guided_assets"]["setup"][field] = value
    proof_path.write_bytes(RESULT.canonical_bytes(proof))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "guided asset setup has an invalid" in rejected.stderr


def test_canonical_result_refuses_stopped_status_with_live_timers(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    status_path = evidence / "guided-status-stopped-writer.json"
    status = json.loads(status_path.read_text(encoding="ascii"))
    status["stable_timer_active"] = True
    status["stable_timer_enabled"] = True
    status_path.write_bytes(RESULT.canonical_bytes(status))
    proof_path = evidence / "guided-setup-stopped-writer-proof.json"
    proof = json.loads(proof_path.read_text(encoding="ascii"))
    proof["status"]["sha256"] = hashlib.sha256(status_path.read_bytes()).hexdigest()
    proof_path.write_bytes(RESULT.canonical_bytes(proof))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "invalid stable_timer_active" in rejected.stderr


def test_canonical_result_requires_final_stable_writer_to_remain_stopped(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    active = (
        b"Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        b"ActiveState=active\nSubState=running\nMainPID=42\n"
        b"InvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    )
    _rewrite_capture_artifact(evidence, "final-stable", "direct_unit_show", active)

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "final-stable direct validator service is not proven safely stopped" in (
        rejected.stderr
    )


def test_canonical_result_binds_final_stable_to_stopped_writer_invocation(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    stopped_again = (
        b"Result=success\nExecMainCode=1\nExecMainStatus=0\n"
        b"ActiveState=inactive\nSubState=dead\nMainPID=0\n"
        b"InvocationID=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n"
    )
    _rewrite_capture_artifact(
        evidence, "final-stable", "direct_unit_show", stopped_again
    )

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "invocation differs from the stopped writer proof" in rejected.stderr


@pytest.mark.parametrize(
    ("mutation", "error"),
    (
        ("input_digest", "invalid result or input binding"),
        ("match", "invalid result or input binding"),
        ("file_count", "invalid evidence file count"),
        ("field_names", "invalid checked field names"),
    ),
)
def test_canonical_result_refuses_operator_secret_scan_mutation(
    tmp_path, mutation, error
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    path = evidence / "operator-secret-scan.json"
    scan = json.loads(path.read_text(encoding="ascii"))
    if mutation == "input_digest":
        scan["operator_input_file_sha256"] = "0" * 64
    elif mutation == "match":
        scan["exact_match_count"] = 1
    elif mutation == "file_count":
        scan["evidence_file_count"] += 1
    else:
        scan["checked_field_names"] = ["publicKey"]
    path.write_bytes(RESULT.canonical_bytes(scan))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert error in rejected.stderr


def test_canonical_result_binds_control_to_reviewed_guided_source(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    path = evidence / "control.json"
    control = json.loads(path.read_text(encoding="ascii"))
    control["guided_operator"]["setup"]["source_sha256"] = "0" * 64
    path.write_bytes(RESULT.canonical_bytes(control))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "control guided_operator setup has an invalid source_sha256" in (
        rejected.stderr
    )


@pytest.mark.parametrize(
    "asset", ("cathedral-validator-setup", "cathedral-validator-status")
)
def test_canonical_result_requires_reviewed_guided_assets_in_bootstrap_manifest(
    tmp_path, asset
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    path = evidence / "updater-bootstrap.manifest.json"
    manifest = json.loads(path.read_text(encoding="ascii"))
    entry = next(
        item
        for item in manifest["files"]
        if item["path"] == f"payload/operator/{asset}"
    )
    entry["sha256"] = "0" * 64
    path.write_bytes(RESULT.canonical_bytes(manifest))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert f"bootstrap manifest does not embed the reviewed {asset}" in rejected.stderr


def test_canonical_result_refuses_resigned_negative_proof_deletion(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    finalized = _finalize(evidence, private_path, public_path, controller)
    assert finalized.returncode == 0, finalized.stderr
    (evidence / "invalid-signature-before.json").unlink()
    _resign_for_current_evidence(evidence, private_path)

    rejected = _verify(evidence, public_path)

    assert rejected.returncode != 0
    assert "invalid-signature-before.json" in rejected.stderr


@pytest.mark.parametrize(
    ("relative", "replacement", "error"),
    (
        (
            "invalid-signature-after.json",
            RESULT.canonical_bytes(
                {
                    "channel": "canary",
                    "current": "releases/" + "2" * 64,
                    "record": {
                        "sequence": 1,
                        "archive_sha256": "2" * 64,
                        "signed_sha256": "b" * 64,
                        "metadata_sha256": "c" * 64,
                    },
                    "sequence": 1,
                    "pending": None,
                }
            ),
            "negative scenario invalid-signature after state",
        ),
        (
            "metadata-outage-service-after.txt",
            b"ActiveState=active\nSubState=running\nMainPID=43\n"
            b"InvocationID=dddddddddddddddddddddddddddddddd\n",
            "negative scenario metadata-outage changed direct-service identity",
        ),
        (
            "readiness-rollback-service-after.txt",
            b"ActiveState=active\nSubState=running\nMainPID=42\n"
            b"InvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            "negative scenario readiness-rollback lacks a fresh rollback service "
            "invocation",
        ),
        (
            "pause-current-proof.txt",
            f"expected={'2' * 64} observed={'1' * 64}\n".encode("ascii"),
            "negative scenario current proof pause-current-proof.txt",
        ),
    ),
)
def test_canonical_result_refuses_resigned_negative_invariant_mutation(
    tmp_path, relative, replacement, error
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    finalized = _finalize(evidence, private_path, public_path, controller)
    assert finalized.returncode == 0, finalized.stderr
    (evidence / relative).write_bytes(replacement)
    _resign_for_current_evidence(evidence, private_path)

    rejected = _verify(evidence, public_path)

    assert rejected.returncode != 0
    assert error in rejected.stderr


@pytest.mark.parametrize(
    ("channel", "mutation"),
    (
        ("canary", "wrong_current"),
        ("stable", "wrong_channel"),
        ("canary", "wrong_record"),
        ("stable", "wrong_sequence"),
        ("canary", "pending"),
        ("stable", "unexpected_field"),
    ),
)
def test_canonical_result_requires_exact_first_install_state(
    tmp_path, channel, mutation
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    state_path = evidence / f"{channel}-first-install-sequence-state.json"
    state = json.loads(state_path.read_text(encoding="ascii"))
    if mutation == "wrong_current":
        state["current"] = "releases/" + "2" * 64
    elif mutation == "wrong_channel":
        state["channel"] = "canary" if channel == "stable" else "stable"
    elif mutation == "wrong_record":
        state["record"]["metadata_sha256"] = "0" * 64
    elif mutation == "wrong_sequence":
        state["sequence"] = 2
    elif mutation == "pending":
        state["pending"] = {"stage": "prepared"}
    else:
        state["unexpected"] = True
    state_path.write_bytes(RESULT.canonical_bytes(state))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert f"first-install {channel} updater state" in rejected.stderr


def test_canonical_result_binds_first_install_state_to_signed_a_metadata(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    metadata_path = evidence / "signed-runtime-metadata/canary-a-seq1.json"
    metadata = json.loads(metadata_path.read_text(encoding="ascii"))
    metadata["signed"]["release"]["archive_sha256"] = "2" * 64
    metadata_path.write_bytes(RESULT.canonical_bytes(metadata))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "retained runtime metadata canary-a-seq1.json signature is invalid" in (
        rejected.stderr
    )


@pytest.mark.parametrize(
    "relative",
    sorted(
        {
            *(
                f"signed-runtime-metadata/{name}"
                for name in RESULT.RUNTIME_METADATA_NAMES
            ),
            *RESULT.BOOTSTRAP_PROOF_FILES,
            "runtime-release-public-key.pem",
            "bootstrap-release-public-key.pem",
        }
    ),
)
def test_canonical_result_requires_every_retained_crypto_proof(tmp_path, relative):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    (evidence / relative).unlink()

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert relative in rejected.stderr


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("channel", "stable"),
        ("sequence", 4),
        ("archive_sha256", "1" * 64),
    ),
)
def test_canonical_result_refuses_resigned_runtime_metadata_detachment(
    tmp_path, field, value
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    path = evidence / "signed-runtime-metadata/canary-b-renewal-seq3.json"
    envelope = json.loads(path.read_text(encoding="ascii"))
    if field == "archive_sha256":
        envelope["signed"]["release"][field] = value
    else:
        envelope["signed"][field] = value
    runtime_private = serialization.load_pem_private_key(
        (private_path.parent / "runtime-private.pem").read_bytes(), password=None
    )
    envelope["signature"] = base64.b64encode(
        runtime_private.sign(RESULT.canonical_bytes(envelope["signed"]))
    ).decode("ascii")
    path.write_bytes(RESULT.canonical_bytes(envelope))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "retained runtime metadata canary-b-renewal-seq3.json" in rejected.stderr


def test_canonical_result_requires_exact_invalid_signature_proof(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    (
        evidence / f"signed-runtime-metadata/{RESULT.INVALID_RUNTIME_METADATA_NAME}"
    ).write_bytes(
        (evidence / "signed-runtime-metadata/canary-b-seq2.json").read_bytes()
    )

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "exact one-bit B2 mutation" in rejected.stderr


def test_canonical_result_refuses_a_tampered_bootstrap_signature(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    signature_path = evidence / "updater-bootstrap.manifest.sig"
    signature = bytearray(signature_path.read_bytes())
    signature[0] ^= 1
    signature_path.write_bytes(signature)

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "bootstrap manifest signature is invalid" in rejected.stderr


def test_canonical_result_refuses_a_detached_bootstrap_build_record(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    build_path = evidence / "bootstrap-build.json"
    build = json.loads(build_path.read_text(encoding="ascii"))
    build["bundle_sha256"] = "0" * 64
    build_path.write_bytes(RESULT.canonical_bytes(build))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "bootstrap build record has an invalid bundle_sha256" in rejected.stderr


def test_canonical_result_refuses_a_resigned_bootstrap_floor_detachment(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    manifest_path = evidence / "updater-bootstrap.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    manifest["stable_release_floor"]["metadata_sha256"] = "0" * 64
    manifest_raw = RESULT.canonical_bytes(manifest)
    bootstrap_private = serialization.load_pem_private_key(
        (private_path.parent / "bootstrap-private.pem").read_bytes(), password=None
    )
    manifest_path.write_bytes(manifest_raw)
    (evidence / "updater-bootstrap.manifest.sig").write_bytes(
        bootstrap_private.sign(manifest_raw)
    )

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "bootstrap manifest stable release floor" in rejected.stderr


@pytest.mark.parametrize(
    "field",
    ("runtime_key_fingerprint", "bootstrap_key_fingerprint", "result_signer"),
)
def test_canonical_result_binds_control_to_retained_public_keys(tmp_path, field):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    control_path = evidence / "control.json"
    control = json.loads(control_path.read_text(encoding="ascii"))
    if field == "result_signer":
        control[field]["public_key_fingerprint"] = "sha256:" + "0" * 64
    else:
        control[field] = "sha256:" + "0" * 64
    control_path.write_bytes(RESULT.canonical_bytes(control))

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "fingerprint" in rejected.stderr


@pytest.mark.parametrize(
    ("target", "source"),
    (
        ("runtime-release-public-key.pem", "bootstrap-release-public-key.pem"),
        ("runtime-release-public-key.pem", RESULT.RESULT_PUBLIC_KEY_NAME),
        ("bootstrap-release-public-key.pem", RESULT.RESULT_PUBLIC_KEY_NAME),
    ),
)
def test_canonical_result_requires_three_distinct_public_keys(tmp_path, target, source):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    (evidence / target).write_bytes((evidence / source).read_bytes())

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "public keys must be pairwise distinct" in rejected.stderr


@pytest.mark.parametrize(
    ("label", "field"),
    (("final-canary", "signed_sha256"), ("final-stable", "metadata_sha256")),
)
def test_canonical_result_binds_final_state_to_retained_runtime_record(
    tmp_path, label, field
):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    artifact = evidence / f"{label}.d/updater_state.txt"
    state = json.loads(artifact.read_text(encoding="ascii"))
    role = label.removeprefix("final-")
    state["channels"][role][field] = "0" * 64
    _rewrite_capture_artifact(
        evidence, label, "updater_state", RESULT.canonical_bytes(state)
    )

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "does not match retained signed metadata" in rejected.stderr


@pytest.mark.parametrize("mutation", ("missing", "reordered"))
def test_canonical_result_requires_exact_ordered_record_steps(tmp_path, mutation):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    steps_path = evidence / "steps.log"
    lines = steps_path.read_text(encoding="ascii").splitlines()
    if mutation == "missing":
        del lines[4]
    else:
        lines[4], lines[5] = lines[5], lines[4]
    steps_path.write_text("\n".join(lines) + "\n", encoding="ascii")

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "scenario step" in rejected.stderr or "scenario steps" in rejected.stderr


def test_canonical_result_requires_teardown_marker_snapshot(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    (evidence / "teardown-network-check-1.json").unlink()

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "teardown snapshot teardown-network-check-1.json" in rejected.stderr


@pytest.mark.parametrize(
    ("old", "new"),
    (
        (b"MainPID=42", b"MainPID=43"),
        (
            b"InvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"InvocationID=dddddddddddddddddddddddddddddddd",
        ),
    ),
)
def test_canonical_result_binds_final_canary_to_continuity_proofs(tmp_path, old, new):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    artifact = evidence / "final-canary.d" / "direct_unit_show.txt"
    payload = artifact.read_bytes().replace(old, new)
    _rewrite_capture_artifact(evidence, "final-canary", "direct_unit_show", payload)

    rejected = _finalize(evidence, private_path, public_path, controller)

    assert rejected.returncode != 0
    assert "differs from continuity proofs" in rejected.stderr


def test_canonical_result_refuses_resigned_scenario_matrix_mutation(tmp_path):
    evidence, private_path, public_path, controller = _success_tree(tmp_path)
    finalized = _finalize(evidence, private_path, public_path, controller)
    assert finalized.returncode == 0, finalized.stderr
    _rewrite_and_resign_result(
        evidence,
        private_path,
        lambda result: result["scenario_matrix"]["scenarios"][0].__setitem__(
            "id", "mutated"
        ),
    )

    rejected = _verify(evidence, public_path)

    assert rejected.returncode != 0
    assert "scenario matrix differs from recomputed evidence" in rejected.stderr


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
    cleanup = (
        "cleanup() {"
        + script.split("cleanup() {", 1)[1].split("trap cleanup EXIT", 1)[0]
    )
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
    cleanup = (
        "cleanup() {"
        + script.split("cleanup() {", 1)[1].split("trap cleanup EXIT", 1)[0]
    )
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
            "REPOSITORY_ROOT=/reviewed/repository\nSOURCE_REVISION_B=" + "b" * 40 + "\n"
            "RESULT_TOOL=/reviewed/result-tool\n"
            "E2E_RESULT_SIGNING_PRIVATE_KEY=/secure/private.pem\n"
            "E2E_RESULT_SIGNING_PUBLIC_KEY=/secure/public.pem\n"
            "E2E_RESULT_SIGNER_KEY_ID=test-result-key\n"
            "TEST_GITHUB_REPOSITORY=owner/test\nESTIMATED_COST_USD=0.1\n"
            "PLANNING_TOTAL_USD=0.3\nBOOTSTRAP_TAG=test-tag\n"
            "gc() { printf '[]\\n'; }\n"
            'git() { if [[ "$*" == *"rev-parse HEAD"* ]]; then '
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
