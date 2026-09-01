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
EVIDENCE_INDEX_SCHEMA = "cathedral_validator_live_update_evidence_index_v1"
EVIDENCE_DIGEST_DOMAIN = b"cathedral-validator-live-update-evidence-v1\x00"
RESULT_NAME = "live_update_e2e_result_v1.json"
SIGNATURE_NAME = f"{RESULT_NAME}.sig"
DIGEST_NAME = f"{RESULT_NAME}.sha256"
RESULT_PUBLIC_KEY_NAME = "live-update-e2e-result-public-key.pem"
HEX_64 = re.compile(r"[0-9a-f]{64}")
SAFE_SECTION = re.compile(r"[a-z][a-z0-9_]{0,63}")
SAFE_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}")
SAFE_CAPTURE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}")
REVISION = re.compile(r"[0-9a-f]{40}")

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
        "steps.log",
        "teardown-status.txt",
        "test-publication-immutable-releases.json",
        "test-publication-main-before.json",
        "test-publication-repository.json",
        "bootstrap-release-public-key.pem",
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
        raise EvidenceError("result signing private key must be a regular non-symlink file")
    if stat.S_ISLNK(public_info.st_mode) or not stat.S_ISREG(public_info.st_mode):
        raise EvidenceError("result signing public key must be a regular non-symlink file")
    if private_info.st_uid != os.getuid():
        raise EvidenceError("result signing private key must be owned by the controller user")
    if stat.S_IMODE(private_info.st_mode) & 0o077:
        raise EvidenceError("result signing private key must not grant group/other access")
    try:
        private = serialization.load_pem_private_key(
            private_path.read_bytes(), password=None
        )
        public = serialization.load_pem_public_key(public_path.read_bytes())
    except (TypeError, ValueError) as exc:
        raise EvidenceError("result signing keys are not valid unencrypted PEM") from exc
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
                errors.append("current_release is not one exact content-addressed release")
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
        if requirement not in {"required", "optional"} or required is not expected_map[
            section_id
        ]:
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
        raise EvidenceError(f"capture artifacts directory already exists: {args.artifacts_dir}")
    args.artifacts_dir.mkdir(mode=0o700, parents=True)
    for section_id, _required in expected:
        if section_id in payloads:
            _atomic_write(
                args.artifacts_dir / f"{section_id}.txt",
                payloads[section_id],
                mode=0o600,
            )

    ordered_rows = [rows[section_id] for section_id, _ in expected if section_id in rows]
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


def _validate_final_systemd_state(artifacts_dir: Path, *, label: str) -> None:
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
    if (
        direct.get("Result") != "success"
        or direct.get("ExecMainCode") != "0"
        or direct.get("ExecMainStatus") != "0"
        or direct.get("ActiveState") != "active"
        or direct.get("SubState") != "running"
        or main_pid <= 0
    ):
        raise EvidenceError(f"{label} direct validator service is not healthy")

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
    if set(updater_by_id) != expected_updaters or any(
        block.get("ActiveState") != "inactive" or block.get("SubState") != "dead"
        for block in updater_by_id.values()
    ):
        raise EvidenceError(f"{label} updater services are not settled")

    timer_blocks = _systemd_show_blocks(
        _read_regular(
            artifacts_dir / "timers_show.txt", label=f"{label} timer states"
        ),
        label=f"{label} timer states",
    )
    timers_by_id = {block.get("Id"): block for block in timer_blocks}
    expected_timers = {
        "cathedral-validator-canary-update.timer",
        "cathedral-validator-update.timer",
    }
    if set(timers_by_id) != expected_timers or any(
        block.get("UnitFileState") != "disabled"
        or block.get("ActiveState") != "inactive"
        or block.get("SubState") != "dead"
        for block in timers_by_id.values()
    ):
        raise EvidenceError(f"{label} updater timers are not disabled and settled")


def verify_capture(args: argparse.Namespace) -> int:
    manifest = _load_capture_manifest(args.manifest)
    complete, errors = _capture_manifest_complete(manifest, args.artifacts_dir)
    if not complete or manifest.get("complete") is not True:
        detail = "; ".join(errors) if errors else "manifest is not complete"
        raise EvidenceError(f"capture manifest is incomplete: {detail}")
    return 0


def _validate_success_evidence(root: Path) -> dict[str, Any]:
    for relative in REQUIRED_SUCCESS_FILES:
        _read_regular(
            root / relative,
            label=f"required success evidence {relative}",
            require_nonempty=True,
        )
    teardown = _read_regular(root / "teardown-status.txt", label="teardown status")
    if teardown != b"original_status=0\nteardown_verified=1\n":
        raise EvidenceError("teardown status does not prove a successful clean teardown")
    steps = _read_regular(root / "steps.log", label="scenario steps").decode(
        "utf-8", errors="strict"
    )
    marker = "SCENARIOS_PASS_PENDING_TEARDOWN all bounded no-chain updater scenarios"
    lines = steps.splitlines()
    if not lines or not lines[-1].endswith(f" {marker}") or steps.count(marker) != 1:
        raise EvidenceError("scenario completion marker is missing, duplicated, or non-terminal")
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
    control = strict_json(
        _read_regular(root / "control.json", label="control document"),
        label="control document",
    )
    if not isinstance(control, dict) or control.get("schema") != (
        "cathedral_validator_live_update_control_v1"
    ):
        raise EvidenceError("control document has the wrong schema")
    if (
        control.get("source_repository") != "cathedralai/cathedral-validator"
        or not isinstance(control.get("run_id"), str)
        or SAFE_CAPTURE_ID.fullmatch(control["run_id"]) is None
        or any(
            not isinstance(control.get(field), str)
            or pattern.fullmatch(control[field]) is None
            for field, pattern in (
                ("source_revision_a", REVISION),
                ("source_revision_b", REVISION),
                ("archive_a_sha256", HEX_64),
                ("archive_b_sha256", HEX_64),
            )
        )
    ):
        raise EvidenceError("control document has an invalid run or source identity")
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
            raise EvidenceError(f"required final capture {label} has the wrong host or label")
        retry_lines = _read_regular(
            root / f"{label}-capture-retries.log",
            label=f"{label} retry selection",
            require_nonempty=True,
        ).decode("ascii").splitlines()
        if not retry_lines or retry_lines[-1] != (
            f"attempt={label_match.group(1)} status=0"
        ):
            raise EvidenceError(f"required final capture {label} lacks its selection proof")
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
        if not isinstance(state, dict) or state.get("pending") is not None:
            raise EvidenceError(f"{label} updater state is not settled")
        current = _read_regular(
            artifacts_dir / "current_release.txt", label=f"{label} current release"
        ).strip()
        expected_archive = control[
            "archive_b_sha256" if label == "final-canary" else "archive_a_sha256"
        ].encode("ascii")
        if current != b"releases/" + expected_archive:
            raise EvidenceError(f"{label} does not point to its expected final release")
        _validate_final_systemd_state(artifacts_dir, label=label)
    pre_teardown = strict_json(
        _read_regular(root / "pre-teardown-instances.json", label="pre-teardown hosts"),
        label="pre-teardown hosts",
    )
    if (
        not isinstance(pre_teardown, list)
        or len(pre_teardown) != control.get("vm_count")
        or control.get("vm_count") != 2
        or {item.get("name") for item in pre_teardown if isinstance(item, dict)}
        != {
            f"catval-{control['run_id']}-canary",
            f"catval-{control['run_id']}-stable",
        }
    ):
        raise EvidenceError("pre-teardown inventory does not contain exactly two hosts")
    return control


def _inventory(root: Path, exclusions: frozenset[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise EvidenceError(f"evidence tree contains a symlink: {relative}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceError(f"evidence tree contains a non-regular file: {relative}")
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
        raise EvidenceError(f"{expected_name} must use its canonical name in EVIDENCE_DIR")


def finalize_result(args: argparse.Namespace) -> int:
    evidence_info = args.evidence_dir.lstat()
    if stat.S_ISLNK(evidence_info.st_mode) or not stat.S_ISDIR(evidence_info.st_mode):
        raise EvidenceError("EVIDENCE_DIR must be a regular directory")
    root = args.evidence_dir.resolve(strict=True)
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
        "purpose": "live_e2e_test_evidence_only",
        "key_id": args.key_id,
        "algorithm": "ed25519",
        "public_key_fingerprint": fingerprint,
    }:
        raise EvidenceError("control document result signer differs from the configured key")
    rows = _inventory(root, RESULT_EXCLUSIONS)
    controller_bytes = _read_regular(
        args.controller_script, label="live controller source", require_nonempty=True
    )
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "run": {
            "id": control.get("run_id"),
            "finished_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace(
                "+00:00", "Z"
            ),
            "source_revision_a": control.get("source_revision_a"),
            "source_revision_b": control.get("source_revision_b"),
            "archive_a_sha256": control.get("archive_a_sha256"),
            "archive_b_sha256": control.get("archive_b_sha256"),
        },
        "terminal": {
            "state": "pass",
            "original_exit_status": 0,
            "scenarios_complete": True,
            "required_evidence_complete": True,
            "teardown_verified": True,
        },
        "scope": {
            "kind": "no_chain_updater_live_acceptance",
            "chain_write": False,
            "validator_cycle": False,
            "wallet_loaded": False,
            "production_release_key_loaded": False,
            "disposable_test_release_keys_generated": True,
        },
        "controller": {
            "repository": control.get("source_repository"),
            "revision": control.get("source_revision_b"),
            "path": "scripts/live_validator_update_e2e.sh",
            "sha256": _sha256(controller_bytes),
            "result_tool_path": "scripts/live_update_e2e_result.py",
            "result_tool_sha256": _sha256(Path(__file__).read_bytes()),
        },
        "signer": {
            "purpose": "live_e2e_test_evidence_only",
            "key_id": args.key_id,
            "algorithm": "ed25519",
            "public_key_path": RESULT_PUBLIC_KEY_NAME,
            "public_key_fingerprint": fingerprint,
            "authorizes_chain_or_weight_changes": False,
        },
        "evidence_tree": {
            "algorithm": "sha256-domain-separated-canonical-json-file-list-v1",
            "root_sha256": _evidence_root(rows),
            "file_count": len(rows),
            "files": rows,
        },
        "authority": {
            "operator_identity_attested": False,
            "immutable_publication_present": False,
            "note": (
                "The detached signature authenticates the configured test-evidence "
                "key only; operator identity and immutable publication remain separate "
                "owner/operator actions."
            ),
        },
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
    if not isinstance(result, dict) or result.get("schema") != RESULT_SCHEMA:
        raise EvidenceError("live E2E result has the wrong schema")
    terminal = result.get("terminal")
    if not isinstance(terminal, dict) or terminal != {
        "state": "pass",
        "original_exit_status": 0,
        "scenarios_complete": True,
        "required_evidence_complete": True,
        "teardown_verified": True,
    }:
        raise EvidenceError("live E2E result does not encode an exact passing terminal state")
    public_data = _read_regular(
        public_key_path, label="result verification public key", require_nonempty=True
    )
    try:
        public = serialization.load_pem_public_key(public_data)
    except ValueError as exc:
        raise EvidenceError("result verification public key is invalid") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise EvidenceError("result verification public key must use Ed25519")
    signer = result.get("signer")
    der = public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = f"sha256:{_sha256(der)}"
    if not isinstance(signer, dict) or signer.get("public_key_fingerprint") != fingerprint:
        raise EvidenceError("live E2E result signer fingerprint mismatch")
    signature = _read_regular(
        signature_path, label="live E2E result signature", require_nonempty=True
    )
    try:
        public.verify(signature, result_data)
    except InvalidSignature as exc:
        raise EvidenceError("live E2E result signature is invalid") from exc
    control = _validate_success_evidence(root)
    run = result.get("run")
    if not isinstance(run, dict) or any(
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
    control_signer = control.get("result_signer")
    if not isinstance(control_signer, dict) or any(
        signer.get(field) != control_signer.get(field)
        for field in ("purpose", "key_id", "algorithm", "public_key_fingerprint")
    ):
        raise EvidenceError("live E2E result signer differs from control.json")
    rows = _inventory(root, RESULT_EXCLUSIONS)
    tree = result.get("evidence_tree")
    if (
        not isinstance(tree, dict)
        or tree.get("files") != rows
        or tree.get("file_count") != len(rows)
        or tree.get("root_sha256") != _evidence_root(rows)
    ):
        raise EvidenceError("live E2E result evidence-tree digest mismatch")
    return digest


def verify_result(args: argparse.Namespace) -> int:
    evidence_info = args.evidence_dir.lstat()
    if stat.S_ISLNK(evidence_info.st_mode) or not stat.S_ISDIR(evidence_info.st_mode):
        raise EvidenceError("EVIDENCE_DIR must be a regular directory")
    root = args.evidence_dir.resolve(strict=True)
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
