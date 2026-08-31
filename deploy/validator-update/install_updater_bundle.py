#!/usr/bin/env python3
"""Verify and install the offline Cathedral validator-updater bootstrap bundle.

The production CLI runs only as root on Linux under CPython 3.12 with systemd.
It authenticates the canonical manifest with an independently supplied pinned
bootstrap Ed25519 public key before it creates or changes any path.  The signed
manifest binds a distinct bundled runtime release public key.  Callers cannot
substitute that runtime key.  The installer never enables or starts a validator
or updater unit.

Do not execute an unauthenticated copy of this file.  First verify the detached
manifest signature and signed archive digest with OpenSSL, then extract and run
the signed ``payload/installer/install_updater_bundle.py`` member.  The CLI also
checks its running bytes against that signed member before persistent mutation.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator, Mapping, Sequence

BUNDLE_SCHEMA = "cathedral_validator_updater_bootstrap_v2"
RUNTIME_RELEASE_PUBLIC_KEY_ARCHIVE_PATH = "payload/runtime-release-public-key.pem"
REQUIREMENTS_ARCHIVE_PATH = "payload/requirements.txt"
INSTALLER_ARCHIVE_PATH = "payload/installer/install_updater_bundle.py"
PUBLIC_KEY_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_BUNDLE_BYTES = 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PAYLOAD_FILES = 2_000
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 900
MAX_BOOTSTRAP_LIFETIME_SECONDS = 90 * 24 * 60 * 60
BOOTSTRAP_STATE_SCHEMA = "cathedral_validator_bootstrap_state_v1"
BOOTSTRAP_PENDING_SCHEMA = "cathedral_validator_bootstrap_pending_v1"
VENV_INTERPRETER_NAME = "python3.12"

SYSTEMD_ASSETS = frozenset(
    {
        "cathedral-validator-boot-reconcile.service",
        "cathedral-validator-canary-update.service",
        "cathedral-validator-canary-update.timer",
        "cathedral-validator-direct.service",
        "cathedral-validator-update.service",
        "cathedral-validator-update.timer",
    }
)
EXAMPLE_ASSETS = frozenset(
    {
        "direct-telemetry.env.example",
        "direct.env.example",
        "identity.env.example",
        "update.env.example",
    }
)
EXPECTED_NON_WHEEL_PATHS = (
    {f"payload/systemd/{name}" for name in SYSTEMD_ASSETS}
    | {f"payload/examples/{name}" for name in EXAMPLE_ASSETS}
    | {
        RUNTIME_RELEASE_PUBLIC_KEY_ARCHIVE_PATH,
        REQUIREMENTS_ARCHIVE_PATH,
        INSTALLER_ARCHIVE_PATH,
        "payload/sysusers/cathedral-validator.conf",
    }
)

Runner = Callable[..., subprocess.CompletedProcess[str]]
SignatureVerifier = Callable[[bytes, bytes, bytes], None]


class InstallRefused(ValueError):
    """The bootstrap bundle or destination is not safe to install."""


@dataclass(frozen=True)
class ManifestFile:
    path: str
    body: bytes
    mode: int
    sha256: str


@dataclass(frozen=True)
class VerifiedBundle:
    manifest: bytes
    signature: bytes
    manifest_sha256: str
    bootstrap_signing_key_fingerprint: str
    runtime_release_key_fingerprint: str
    bootstrap_sequence: int
    issued_unix: int
    expires_unix: int
    files: Mapping[str, ManifestFile]


@dataclass(frozen=True)
class BootstrapState:
    sequence: int
    manifest_sha256: str
    bootstrap_signing_key_fingerprint: str
    runtime_release_key_fingerprint: str


def canonical_json(document: Any) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise InstallRefused("manifest contains a duplicate JSON key")
        document[key] = value
    return document


def _object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise InstallRefused(f"{label} has unsupported fields")
    return value


def _safe_archive_path(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise InstallRefused(f"{label} path is not a string")
    path = PurePosixPath(value)
    if (
        not value
        or len(value.encode("utf-8")) > 255
        or path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or "" in path.parts
    ):
        raise InstallRefused(f"{label} has an unsafe archive path")
    return value


def _read_controlled_file(
    path: Path,
    label: str,
    *,
    expected_owner: int,
    maximum: int,
) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise InstallRefused(f"{label} must be an absolute non-symlink path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InstallRefused(f"{label} is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not 1 <= metadata.st_size <= maximum
        ):
            raise InstallRefused(f"{label} is not an owner-controlled regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            body = handle.read(maximum + 1)
        if len(body) != metadata.st_size or len(body) > maximum:
            raise InstallRefused(f"{label} changed while it was read")
        return body
    finally:
        os.close(descriptor)


def _ed25519_der(pem: bytes, label: str) -> bytes:
    try:
        text = pem.decode("ascii")
    except UnicodeDecodeError as exc:
        raise InstallRefused(f"{label} is not ASCII PEM") from exc
    lines = [line.strip() for line in text.strip().splitlines()]
    if (
        len(lines) < 3
        or lines[0] != "-----BEGIN PUBLIC KEY-----"
        or lines[-1] != "-----END PUBLIC KEY-----"
        or any(not line for line in lines[1:-1])
    ):
        raise InstallRefused(f"{label} is not canonical public-key PEM")
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InstallRefused(f"{label} has invalid base64") from exc
    if len(der) != len(PUBLIC_KEY_DER_PREFIX) + 32 or not der.startswith(
        PUBLIC_KEY_DER_PREFIX
    ):
        raise InstallRefused(f"{label} is not Ed25519")
    return der


def ed25519_public_key_fingerprint(pem: bytes, label: str) -> str:
    return "sha256:" + hashlib.sha256(_ed25519_der(pem, label)).hexdigest()


def _openssl_verify(
    manifest: bytes,
    signature: bytes,
    public_key: bytes,
    *,
    openssl: str = "/usr/bin/openssl",
) -> None:
    descriptors: list[int] = []
    try:
        for name, body in (
            ("cathedral-manifest", manifest),
            ("cathedral-signature", signature),
            ("cathedral-public-key", public_key),
        ):
            descriptor = os.memfd_create(name, flags=0)
            descriptors.append(descriptor)
            remaining = memoryview(body)
            while remaining:
                written = os.write(descriptor, remaining)
                if written < 1:
                    raise InstallRefused(
                        "cannot prepare in-memory signature verification"
                    )
                remaining = remaining[written:]
            os.lseek(descriptor, 0, os.SEEK_SET)
        manifest_fd, signature_fd, key_fd = descriptors
        result = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                f"/proc/self/fd/{key_fd}",
                "-rawin",
                "-in",
                f"/proc/self/fd/{manifest_fd}",
                "-sigfile",
                f"/proc/self/fd/{signature_fd}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            pass_fds=tuple(descriptors),
        )
        if result.returncode != 0:
            raise InstallRefused("manifest Ed25519 signature is invalid")
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _parse_manifest(raw: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        document = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallRefused("manifest is not canonical ASCII JSON") from exc
    if canonical_json(document) != raw:
        raise InstallRefused("manifest is not canonical JSON")
    document = _object(
        document,
        {
            "bootstrap_signing_key",
            "bootstrap_metadata",
            "bundle",
            "files",
            "install",
            "runtime_release_key",
            "schema",
        },
        "manifest",
    )
    if document["schema"] != BUNDLE_SCHEMA:
        raise InstallRefused("manifest schema is unsupported")
    bootstrap_metadata = _object(
        document["bootstrap_metadata"],
        {"expires_unix", "issued_unix", "sequence"},
        "bootstrap metadata",
    )
    sequence = bootstrap_metadata["sequence"]
    issued_unix = bootstrap_metadata["issued_unix"]
    expires_unix = bootstrap_metadata["expires_unix"]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 1 <= sequence <= 2**63 - 1
        or isinstance(issued_unix, bool)
        or not isinstance(issued_unix, int)
        or issued_unix < 1
        or isinstance(expires_unix, bool)
        or not isinstance(expires_unix, int)
        or expires_unix <= issued_unix
        or expires_unix - issued_unix > MAX_BOOTSTRAP_LIFETIME_SECONDS
    ):
        raise InstallRefused("bootstrap metadata validity is invalid")
    bundle = _object(document["bundle"], {"sha256", "size"}, "bundle record")
    if (
        not isinstance(bundle["sha256"], str)
        or DIGEST.fullmatch(bundle["sha256"]) is None
        or isinstance(bundle["size"], bool)
        or not isinstance(bundle["size"], int)
        or not 1 <= bundle["size"] <= MAX_BUNDLE_BYTES
    ):
        raise InstallRefused("bundle record is invalid")
    bootstrap_signing_key = _object(
        document["bootstrap_signing_key"],
        {"algorithm", "fingerprint", "source"},
        "bootstrap-signing-key record",
    )
    if (
        bootstrap_signing_key["algorithm"] != "Ed25519"
        or bootstrap_signing_key["source"] != "operator-pinned-external"
        or not isinstance(bootstrap_signing_key["fingerprint"], str)
        or FINGERPRINT.fullmatch(bootstrap_signing_key["fingerprint"]) is None
    ):
        raise InstallRefused("bootstrap-signing-key record is invalid")
    runtime_release_key = _object(
        document["runtime_release_key"],
        {"algorithm", "fingerprint", "path"},
        "runtime-release-key record",
    )
    if (
        runtime_release_key["algorithm"] != "Ed25519"
        or runtime_release_key["path"] != RUNTIME_RELEASE_PUBLIC_KEY_ARCHIVE_PATH
        or not isinstance(runtime_release_key["fingerprint"], str)
        or FINGERPRINT.fullmatch(runtime_release_key["fingerprint"]) is None
    ):
        raise InstallRefused("runtime-release-key record is invalid")
    if runtime_release_key["fingerprint"] == bootstrap_signing_key["fingerprint"]:
        raise InstallRefused(
            "bootstrap signing key and runtime release key must be distinct"
        )
    install = _object(
        document["install"],
        {"enable_units", "installer", "python", "requirements", "wheelhouse"},
        "install record",
    )
    if install != {
        "enable_units": False,
        "installer": INSTALLER_ARCHIVE_PATH,
        "python": "CPython==3.12.*",
        "requirements": REQUIREMENTS_ARCHIVE_PATH,
        "wheelhouse": "payload/wheelhouse",
    }:
        raise InstallRefused("install policy is unsupported")
    records = document["files"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_PAYLOAD_FILES:
        raise InstallRefused("manifest file list is invalid")
    return document, records


def _manifest_records(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    parsed: dict[str, dict[str, Any]] = {}
    previous = ""
    total = 0
    for value in records:
        record = _object(value, {"mode", "path", "sha256", "size"}, "file record")
        path = _safe_archive_path(record["path"], "file record")
        if path <= previous or path in parsed:
            raise InstallRefused("manifest file paths are not unique and sorted")
        previous = path
        if record["mode"] != "0644":
            raise InstallRefused("manifest file mode is unsupported")
        if (
            not isinstance(record["sha256"], str)
            or DIGEST.fullmatch(record["sha256"]) is None
        ):
            raise InstallRefused("manifest file digest is invalid")
        if (
            isinstance(record["size"], bool)
            or not isinstance(record["size"], int)
            or not 1 <= record["size"] <= MAX_BUNDLE_BYTES
        ):
            raise InstallRefused("manifest file size is invalid")
        total += record["size"]
        if total > MAX_PAYLOAD_BYTES:
            raise InstallRefused("manifest payload exceeds its expanded limit")
        parsed[path] = record
    non_wheels = {path for path in parsed if not path.startswith("payload/wheelhouse/")}
    wheels = {path for path in parsed if path.startswith("payload/wheelhouse/")}
    if non_wheels != EXPECTED_NON_WHEEL_PATHS or not wheels:
        raise InstallRefused("manifest does not contain the fixed bootstrap asset set")
    if any(
        PurePosixPath(path).parent != PurePosixPath("payload/wheelhouse")
        or not path.endswith(".whl")
        for path in wheels
    ):
        raise InstallRefused("manifest wheelhouse path is invalid")
    return parsed


def _archive_files(
    archive: bytes,
    records: Mapping[str, dict[str, Any]],
) -> dict[str, ManifestFile]:
    extracted: dict[str, ManifestFile] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            members = bundle.getmembers()
            if len(members) != len(records):
                raise InstallRefused("bundle member count differs from manifest")
            for member in members:
                path = _safe_archive_path(member.name, "bundle member")
                if path in extracted or path not in records:
                    raise InstallRefused(
                        "bundle contains an unexpected or duplicate member"
                    )
                record = records[path]
                if (
                    not member.isreg()
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                    or member.mtime != 0
                    or stat.S_IMODE(member.mode) != int(record["mode"], 8)
                    or member.size != record["size"]
                    or member.linkname
                ):
                    raise InstallRefused("bundle member metadata differs from manifest")
                handle = bundle.extractfile(member)
                if handle is None:
                    raise InstallRefused("bundle member cannot be read")
                body = handle.read(record["size"] + 1)
                if (
                    len(body) != record["size"]
                    or hashlib.sha256(body).hexdigest() != record["sha256"]
                ):
                    raise InstallRefused("bundle member content differs from manifest")
                extracted[path] = ManifestFile(
                    path=path,
                    body=body,
                    mode=int(record["mode"], 8),
                    sha256=record["sha256"],
                )
    except (OSError, tarfile.TarError) as exc:
        raise InstallRefused("bundle is not a readable gzip tar archive") from exc
    if set(extracted) != set(records):
        raise InstallRefused("bundle omits a manifest member")
    return extracted


def verify_bundle(
    *,
    bundle_path: Path,
    manifest_path: Path,
    signature_path: Path,
    bootstrap_public_key_path: Path,
    expected_bootstrap_fingerprint: str,
    minimum_bootstrap_sequence: int,
    expected_owner: int,
    now_unix: int | None = None,
    signature_verifier: SignatureVerifier = _openssl_verify,
) -> VerifiedBundle:
    if FINGERPRINT.fullmatch(expected_bootstrap_fingerprint) is None:
        raise InstallRefused("expected bootstrap signing key fingerprint is invalid")
    manifest = _read_controlled_file(
        manifest_path,
        "bootstrap manifest",
        expected_owner=expected_owner,
        maximum=MAX_MANIFEST_BYTES,
    )
    signature = _read_controlled_file(
        signature_path,
        "bootstrap signature",
        expected_owner=expected_owner,
        maximum=64,
    )
    if len(signature) != 64:
        raise InstallRefused("bootstrap signature is not 64 bytes")
    bootstrap_public_key = _read_controlled_file(
        bootstrap_public_key_path,
        "bootstrap public key trust anchor",
        expected_owner=expected_owner,
        maximum=16_384,
    )
    bootstrap_fingerprint = ed25519_public_key_fingerprint(
        bootstrap_public_key,
        "bootstrap public key trust anchor",
    )
    if bootstrap_fingerprint != expected_bootstrap_fingerprint:
        raise InstallRefused(
            "bootstrap public-key fingerprint differs from the operator pin"
        )
    if (
        isinstance(minimum_bootstrap_sequence, bool)
        or not isinstance(minimum_bootstrap_sequence, int)
        or not 1 <= minimum_bootstrap_sequence <= 2**63 - 1
    ):
        raise InstallRefused("minimum bootstrap sequence is invalid")
    document, record_list = _parse_manifest(manifest)
    bootstrap_metadata = document["bootstrap_metadata"]
    if bootstrap_metadata["sequence"] < minimum_bootstrap_sequence:
        raise InstallRefused("bootstrap sequence is below the operator checkpoint")
    observed_now = int(time.time()) if now_unix is None else now_unix
    if observed_now < bootstrap_metadata["issued_unix"] - 300:
        raise InstallRefused("bootstrap manifest is not valid yet")
    if observed_now >= bootstrap_metadata["expires_unix"]:
        raise InstallRefused("bootstrap manifest has expired")
    if document["bootstrap_signing_key"]["fingerprint"] != bootstrap_fingerprint:
        raise InstallRefused(
            "manifest bootstrap signing key fingerprint differs from the operator pin"
        )
    try:
        signature_verifier(manifest, signature, bootstrap_public_key)
    except InstallRefused:
        raise
    except Exception as exc:
        raise InstallRefused("manifest Ed25519 signature is invalid") from exc

    archive = _read_controlled_file(
        bundle_path,
        "bootstrap bundle",
        expected_owner=expected_owner,
        maximum=MAX_BUNDLE_BYTES,
    )
    bundle_record = document["bundle"]
    if (
        len(archive) != bundle_record["size"]
        or hashlib.sha256(archive).hexdigest() != (bundle_record["sha256"])
    ):
        raise InstallRefused("bundle bytes differ from the signed manifest")
    records = _manifest_records(record_list)
    files = _archive_files(archive, records)
    bundled_runtime_key = files[RUNTIME_RELEASE_PUBLIC_KEY_ARCHIVE_PATH].body
    runtime_fingerprint = ed25519_public_key_fingerprint(
        bundled_runtime_key,
        "bundled runtime release public key",
    )
    if runtime_fingerprint != document["runtime_release_key"]["fingerprint"]:
        raise InstallRefused(
            "bundled runtime release key fingerprint differs from the signed manifest"
        )
    return VerifiedBundle(
        manifest=manifest,
        signature=signature,
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        bootstrap_signing_key_fingerprint=bootstrap_fingerprint,
        runtime_release_key_fingerprint=runtime_fingerprint,
        bootstrap_sequence=bootstrap_metadata["sequence"],
        issued_unix=bootstrap_metadata["issued_unix"],
        expires_unix=bootstrap_metadata["expires_unix"],
        files=files,
    )


def verify_running_installer(
    bundle: VerifiedBundle,
    *,
    script_path: Path,
    expected_owner: int,
) -> None:
    running = _read_controlled_file(
        script_path,
        "running bootstrap installer",
        expected_owner=expected_owner,
        maximum=MAX_MANIFEST_BYTES,
    )
    if running != bundle.files[INSTALLER_ARCHIVE_PATH].body:
        raise InstallRefused("running installer differs from the signed bundle member")


def _relative(root: Path, relative: str) -> Path:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise InstallRefused("internal destination path is unsafe")
    return root.joinpath(*path.parts)


def _check_root(root: Path, expected_owner: int) -> None:
    if not root.is_absolute() or root.is_symlink():
        raise InstallRefused("installation root must be an absolute directory")
    try:
        metadata = root.stat()
    except OSError as exc:
        raise InstallRefused("installation root is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise InstallRefused("installation root is not owner-controlled")


def _existing_ancestors(root: Path, path: Path, expected_owner: int) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise InstallRefused("destination escapes installation root") from exc
    current = root
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise InstallRefused(f"unsafe destination ancestor: {current}")


def _ensure_directory(root: Path, path: Path, expected_owner: int, mode: int) -> None:
    _existing_ancestors(root, path, expected_owner)
    relative = path.relative_to(root)
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        requested_mode = mode if index == len(relative.parts) - 1 else 0o755
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=requested_mode)
            os.chmod(current, requested_mode, follow_symlinks=False)
            metadata = current.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise InstallRefused(f"unsafe destination directory: {current}")
        if index == len(relative.parts) - 1 and stat.S_IMODE(metadata.st_mode) != mode:
            os.chmod(current, mode, follow_symlinks=False)


def _existing_file(
    path: Path,
    expected: bytes,
    *,
    expected_owner: int,
    mode: int,
) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise InstallRefused(f"existing destination is unsafe: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            body = handle.read(len(expected) + 1)
    finally:
        os.close(descriptor)
    if body != expected:
        raise InstallRefused(f"existing destination differs from signed bundle: {path}")
    return True


def _write_new(path: Path, body: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _managed_file_matches(
    path: Path,
    expected: bytes,
    *,
    expected_owner: int,
    mode: int,
) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise InstallRefused(f"existing managed destination is unsafe: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            body = handle.read(max(len(expected), metadata.st_size) + 1)
    finally:
        os.close(descriptor)
    return body == expected


def _atomic_replace_file(path: Path, body: bytes, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".cathedral-bootstrap-",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _install_managed_file(
    root: Path,
    path: Path,
    body: bytes,
    *,
    expected_owner: int,
    mode: int,
    parent_mode: int = 0o755,
) -> None:
    _ensure_directory(root, path.parent, expected_owner, parent_mode)
    if _managed_file_matches(
        path,
        body,
        expected_owner=expected_owner,
        mode=mode,
    ):
        return
    _atomic_replace_file(path, body, mode)


def _bootstrap_record(bundle: VerifiedBundle, schema: str) -> bytes:
    document = {
        "bootstrap_signing_key_fingerprint": (bundle.bootstrap_signing_key_fingerprint),
        "manifest_sha256": bundle.manifest_sha256,
        "runtime_release_key_fingerprint": bundle.runtime_release_key_fingerprint,
        "schema": schema,
        "sequence": bundle.bootstrap_sequence,
    }
    return canonical_json(document)


def _read_bootstrap_record(
    path: Path,
    *,
    schema: str,
    expected_owner: int,
) -> BootstrapState | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise InstallRefused(f"bootstrap state mode is unsafe: {path}")
    raw = _read_controlled_file(
        path,
        "bootstrap state",
        expected_owner=expected_owner,
        maximum=16_384,
    )
    try:
        document = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallRefused("bootstrap state is not canonical JSON") from exc
    if canonical_json(document) != raw:
        raise InstallRefused("bootstrap state is not canonical JSON")
    document = _object(
        document,
        {
            "bootstrap_signing_key_fingerprint",
            "manifest_sha256",
            "runtime_release_key_fingerprint",
            "schema",
            "sequence",
        },
        "bootstrap state",
    )
    if document["schema"] != schema:
        raise InstallRefused("bootstrap state schema is unsupported")
    sequence = document["sequence"]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 1 <= sequence <= 2**63 - 1
        or not isinstance(document["manifest_sha256"], str)
        or DIGEST.fullmatch(document["manifest_sha256"]) is None
        or not isinstance(document["bootstrap_signing_key_fingerprint"], str)
        or FINGERPRINT.fullmatch(document["bootstrap_signing_key_fingerprint"]) is None
        or not isinstance(document["runtime_release_key_fingerprint"], str)
        or FINGERPRINT.fullmatch(document["runtime_release_key_fingerprint"]) is None
    ):
        raise InstallRefused("bootstrap state fields are invalid")
    return BootstrapState(
        sequence=sequence,
        manifest_sha256=document["manifest_sha256"],
        bootstrap_signing_key_fingerprint=document["bootstrap_signing_key_fingerprint"],
        runtime_release_key_fingerprint=document["runtime_release_key_fingerprint"],
    )


def _check_bootstrap_transition(
    bundle: VerifiedBundle,
    *,
    committed: BootstrapState | None,
    pending: BootstrapState | None,
) -> None:
    for label, state in (("committed", committed), ("pending", pending)):
        if state is None:
            continue
        if bundle.bootstrap_sequence < state.sequence:
            raise InstallRefused(f"bootstrap replay is below the {label} sequence")
        if (
            bundle.bootstrap_sequence == state.sequence
            and bundle.manifest_sha256 != state.manifest_sha256
        ):
            raise InstallRefused(f"bootstrap {label} sequence is equivocal")


@contextmanager
def _bootstrap_operation_lock(
    root: Path,
    *,
    expected_owner: int,
) -> Iterator[Path]:
    state_root = _relative(root, "var/lib/cathedral-validator-update")
    _ensure_directory(root, state_root, expected_owner, 0o700)
    lock_path = state_root / "updater.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise InstallRefused("shared updater lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstallRefused("validator updater is already running") from exc
        yield state_root
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _remove_durable(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _active_updater_digest(
    fixed_link: Path,
    *,
    expected_owner: int,
) -> str | None:
    try:
        metadata = fixed_link.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != expected_owner:
        raise InstallRefused("existing updater activation path is not a safe symlink")
    current = fixed_link.readlink()
    current_parts = PurePosixPath(current.as_posix()).parts
    if (
        len(current_parts) != 2
        or current_parts[0] != "cathedral-validator-updater-releases"
        or DIGEST.fullmatch(current_parts[1]) is None
    ):
        raise InstallRefused("existing updater activation target is unsafe")
    current_target = fixed_link.parent.joinpath(*current_parts)
    try:
        target_metadata = current_target.lstat()
    except OSError as exc:
        raise InstallRefused(
            "existing updater activation target is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(target_metadata.st_mode)
        or not stat.S_ISDIR(target_metadata.st_mode)
        or target_metadata.st_uid != expected_owner
        or stat.S_IMODE(target_metadata.st_mode) & 0o022
    ):
        raise InstallRefused("existing updater activation target is unsafe")
    return current_parts[1]


def _bootstrap_markers_complete(
    version_dir: Path,
    bundle: VerifiedBundle,
    *,
    expected_owner: int,
) -> bool:
    manifest_matches = _managed_file_matches(
        version_dir / ".bootstrap-manifest.json",
        bundle.manifest,
        expected_owner=expected_owner,
        mode=0o444,
    )
    signature_matches = _managed_file_matches(
        version_dir / ".bootstrap-manifest.sig",
        bundle.signature,
        expected_owner=expected_owner,
        mode=0o444,
    )
    return manifest_matches and signature_matches


def _validate_owned_tree(
    path: Path,
    *,
    expected_owner: int,
    expected_device: int | None = None,
) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise InstallRefused(f"updater release tree is unavailable: {path}") from exc
    if metadata.st_uid != expected_owner:
        raise InstallRefused(f"updater release tree has an unsafe owner: {path}")
    if expected_device is None:
        expected_device = metadata.st_dev
    if metadata.st_dev != expected_device:
        raise InstallRefused(f"updater release tree crosses a filesystem: {path}")
    if stat.S_ISLNK(metadata.st_mode):
        try:
            target = os.readlink(path)
        except OSError as exc:
            raise InstallRefused(
                f"updater release tree has an unreadable symlink: {path}"
            ) from exc
        if not target or len(os.fsencode(target)) > 4096:
            raise InstallRefused(f"updater release tree has an unsafe symlink: {path}")
        return
    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
        raise InstallRefused(f"updater release tree has an unsafe node: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise InstallRefused(
            f"updater release tree is writable by another user: {path}"
        )
    if stat.S_ISREG(metadata.st_mode):
        return
    try:
        children = sorted(path.iterdir(), key=lambda child: os.fsencode(child.name))
    except OSError as exc:
        raise InstallRefused(f"updater release tree is unreadable: {path}") from exc
    for child in children:
        _validate_owned_tree(
            child,
            expected_owner=expected_owner,
            expected_device=expected_device,
        )


def _fsync_directory(path: Path, *, expected_owner: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise InstallRefused(f"updater directory is unavailable: {path}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise InstallRefused(f"updater directory is unsafe: {path}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InstallRefused(f"updater directory cannot be opened: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_uid != expected_owner
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            raise InstallRefused(f"updater directory changed while opening: {path}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_owned_tree(
    path: Path,
    *,
    expected_owner: int,
    expected_device: int | None = None,
) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise InstallRefused(f"updater release tree is unavailable: {path}") from exc
    if metadata.st_uid != expected_owner:
        raise InstallRefused(f"updater release tree has an unsafe owner: {path}")
    if expected_device is None:
        expected_device = metadata.st_dev
    if metadata.st_dev != expected_device:
        raise InstallRefused(f"updater release tree crosses a filesystem: {path}")
    if stat.S_ISLNK(metadata.st_mode):
        try:
            target = os.readlink(path)
        except OSError as exc:
            raise InstallRefused(
                f"updater release tree has an unreadable symlink: {path}"
            ) from exc
        if not target or len(os.fsencode(target)) > 4096:
            raise InstallRefused(f"updater release tree has an unsafe symlink: {path}")
        return
    is_directory = stat.S_ISDIR(metadata.st_mode)
    if not (is_directory or stat.S_ISREG(metadata.st_mode)):
        raise InstallRefused(f"updater release tree has an unsafe node: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise InstallRefused(
            f"updater release tree is writable by another user: {path}"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    if is_directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InstallRefused(f"updater release tree cannot be opened: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_uid != expected_owner
            or stat.S_IMODE(opened.st_mode) & 0o022
            or stat.S_ISDIR(opened.st_mode) != is_directory
            or not (stat.S_ISDIR(opened.st_mode) or stat.S_ISREG(opened.st_mode))
        ):
            raise InstallRefused(f"updater release tree changed while opening: {path}")
        if is_directory:
            try:
                children = sorted(
                    path.iterdir(), key=lambda child: os.fsencode(child.name)
                )
            except OSError as exc:
                raise InstallRefused(
                    f"updater release tree is unreadable: {path}"
                ) from exc
            for child in children:
                _fsync_owned_tree(
                    child,
                    expected_owner=expected_owner,
                    expected_device=expected_device,
                )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_venv_interpreter(
    version_dir: Path,
    *,
    expected_owner: int,
) -> None:
    interpreter = version_dir / "bin" / VENV_INTERPRETER_NAME
    try:
        metadata = interpreter.lstat()
    except OSError as exc:
        raise InstallRefused("installed updater interpreter is missing") from exc
    if metadata.st_uid != expected_owner or not (
        stat.S_ISLNK(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
    ):
        raise InstallRefused("installed updater interpreter is unsafe")
    if stat.S_ISLNK(metadata.st_mode):
        try:
            target = os.readlink(interpreter)
            resolved = interpreter.resolve(strict=True)
            resolved_metadata = resolved.lstat()
        except (OSError, RuntimeError) as exc:
            raise InstallRefused(
                "installed updater interpreter link is unsafe"
            ) from exc
        if not target or len(os.fsencode(target)) > 4096:
            raise InstallRefused("installed updater interpreter link is unsafe")
    else:
        resolved_metadata = metadata
    if (
        not stat.S_ISREG(resolved_metadata.st_mode)
        or resolved_metadata.st_uid != expected_owner
        or stat.S_IMODE(resolved_metadata.st_mode) & 0o022
        or not stat.S_IMODE(resolved_metadata.st_mode) & 0o111
    ):
        raise InstallRefused("installed updater interpreter target is unsafe")


def _release_references(
    *,
    fixed_link: Path,
    committed_path: Path,
    pending_path: Path,
    expected_owner: int,
) -> dict[str, str]:
    references: dict[str, str] = {}
    active = _active_updater_digest(fixed_link, expected_owner=expected_owner)
    if active is not None:
        references["active link"] = active
    committed = _read_bootstrap_record(
        committed_path,
        schema=BOOTSTRAP_STATE_SCHEMA,
        expected_owner=expected_owner,
    )
    if committed is not None:
        references["committed state"] = committed.manifest_sha256
    pending = _read_bootstrap_record(
        pending_path,
        schema=BOOTSTRAP_PENDING_SCHEMA,
        expected_owner=expected_owner,
    )
    if pending is not None:
        references["pending state"] = pending.manifest_sha256
    return references


def _remove_unreferenced_release(
    version_dir: Path,
    bundle: VerifiedBundle,
    *,
    fixed_link: Path,
    committed_path: Path,
    pending_path: Path,
    expected_owner: int,
) -> bool:
    references = _release_references(
        fixed_link=fixed_link,
        committed_path=committed_path,
        pending_path=pending_path,
        expected_owner=expected_owner,
    )
    labels = sorted(
        label for label, digest in references.items() if digest == version_dir.name
    )
    if labels:
        if not _bootstrap_markers_complete(
            version_dir,
            bundle,
            expected_owner=expected_owner,
        ):
            raise InstallRefused(
                "incomplete updater release is referenced by " + ", ".join(labels)
            )
        return False
    parent_metadata = version_dir.parent.lstat()
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != expected_owner
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise InstallRefused("updater releases directory is unsafe")
    _validate_owned_tree(
        version_dir,
        expected_owner=expected_owner,
        expected_device=parent_metadata.st_dev,
    )
    shutil.rmtree(version_dir)
    _fsync_directory(version_dir.parent, expected_owner=expected_owner)
    return True


def _activate_updater_link(
    fixed_link: Path,
    relative_link: Path,
    *,
    expected_owner: int,
) -> None:
    current_digest = _active_updater_digest(
        fixed_link,
        expected_owner=expected_owner,
    )
    if current_digest == relative_link.name:
        return
    staging = Path(
        tempfile.mkdtemp(prefix=".cathedral-updater-link-", dir=fixed_link.parent)
    )
    candidate = staging / "current"
    try:
        candidate.symlink_to(relative_link)
        os.replace(candidate, fixed_link)
        directory = os.open(fixed_link.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass
        staging.rmdir()


def _destinations(root: Path, bundle: VerifiedBundle) -> dict[Path, tuple[bytes, int]]:
    result: dict[Path, tuple[bytes, int]] = {
        _relative(
            root,
            "etc/cathedral-validator/runtime-release-public-key.pem",
        ): (
            bundle.files[RUNTIME_RELEASE_PUBLIC_KEY_ARCHIVE_PATH].body,
            0o644,
        ),
        _relative(root, "etc/sysusers.d/cathedral-validator.conf"): (
            bundle.files["payload/sysusers/cathedral-validator.conf"].body,
            0o644,
        ),
        _relative(
            root,
            "usr/local/share/cathedral-validator-updater/bootstrap/"
            "install_updater_bundle.py",
        ): (bundle.files[INSTALLER_ARCHIVE_PATH].body, 0o644),
    }
    for name in SYSTEMD_ASSETS:
        result[_relative(root, f"etc/systemd/system/{name}")] = (
            bundle.files[f"payload/systemd/{name}"].body,
            0o644,
        )
    for name in EXAMPLE_ASSETS:
        result[
            _relative(
                root, f"usr/local/share/cathedral-validator-updater/examples/{name}"
            )
        ] = (bundle.files[f"payload/examples/{name}"].body, 0o644)
    return result


def _preflight_destinations(
    root: Path,
    bundle: VerifiedBundle,
    *,
    expected_owner: int,
) -> None:
    for path, (body, mode) in _destinations(root, bundle).items():
        _existing_ancestors(root, path.parent, expected_owner)
        _managed_file_matches(
            path,
            body,
            expected_owner=expected_owner,
            mode=mode,
        )


def _extract_payload(root: Path, bundle: VerifiedBundle, expected_owner: int) -> None:
    for path, item in sorted(bundle.files.items()):
        destination = _relative(root, path)
        _ensure_directory(root, destination.parent, expected_owner, 0o700)
        _write_new(destination, item.body, item.mode)


def _validate_installed_venv(
    version_dir: Path,
    bundle: VerifiedBundle,
    *,
    expected_owner: int,
) -> None:
    marker = version_dir / ".bootstrap-manifest.json"
    signature = version_dir / ".bootstrap-manifest.sig"
    if not _existing_file(
        marker,
        bundle.manifest,
        expected_owner=expected_owner,
        mode=0o444,
    ):
        raise InstallRefused("installed updater manifest marker is missing")
    if not _existing_file(
        signature,
        bundle.signature,
        expected_owner=expected_owner,
        mode=0o444,
    ):
        raise InstallRefused("installed updater signature marker is missing")
    executable = version_dir / "bin" / "cathedral-validator-update"
    try:
        metadata = executable.lstat()
    except OSError as exc:
        raise InstallRefused("installed updater entry point is missing") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or not stat.S_IMODE(metadata.st_mode) & 0o111
    ):
        raise InstallRefused("installed updater entry point is unsafe")
    expected_shebang = f"#!{version_dir}/bin/{VENV_INTERPRETER_NAME}".encode("utf-8")
    with executable.open("rb") as handle:
        first_line = handle.readline(4096).rstrip(b"\r\n")
    if first_line != expected_shebang:
        raise InstallRefused("installed updater entry point has the wrong interpreter")


def _default_runner(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(*args, **kwargs)


def _preflight_python(python_executable: Path, runner: Runner) -> None:
    try:
        runner(
            [
                str(python_executable),
                "-I",
                "-c",
                "import ensurepip, venv; assert callable(venv.create)",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallRefused(
            "CPython 3.12 venv support is unavailable; install python3.12-venv"
        ) from exc


def _install_verified_bundle_locked(
    bundle: VerifiedBundle,
    *,
    root: Path,
    state_root: Path,
    expected_owner: int,
    python_executable: Path,
    runner: Runner = _default_runner,
) -> str:
    """Install one authenticated bundle while holding the shared updater lock."""

    committed_path = state_root / "bootstrap-state.json"
    pending_path = state_root / "bootstrap-pending.json"
    committed = _read_bootstrap_record(
        committed_path,
        schema=BOOTSTRAP_STATE_SCHEMA,
        expected_owner=expected_owner,
    )
    pending = _read_bootstrap_record(
        pending_path,
        schema=BOOTSTRAP_PENDING_SCHEMA,
        expected_owner=expected_owner,
    )
    _check_bootstrap_transition(bundle, committed=committed, pending=pending)
    destinations = _destinations(root, bundle)

    releases = _relative(root, "usr/local/lib/cathedral-validator-updater-releases")
    version_dir = releases / bundle.manifest_sha256
    fixed_link = _relative(root, "usr/local/lib/cathedral-validator-updater")
    _existing_ancestors(root, releases, expected_owner)
    _existing_ancestors(root, fixed_link.parent, expected_owner)
    relative_link = (
        Path("cathedral-validator-updater-releases") / bundle.manifest_sha256
    )

    version_exists = version_dir.exists() or version_dir.is_symlink()
    if version_exists:
        metadata = version_dir.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise InstallRefused("existing updater release directory is unsafe")
        removed = _remove_unreferenced_release(
            version_dir,
            bundle,
            fixed_link=fixed_link,
            committed_path=committed_path,
            pending_path=pending_path,
            expected_owner=expected_owner,
        )
        version_exists = not removed
        if version_exists:
            _validate_installed_venv(version_dir, bundle, expected_owner=expected_owner)
    if not version_exists:
        _ensure_directory(root, releases, expected_owner, 0o755)
        work_root = _relative(root, "usr/local/lib/cathedral-validator-updater-staging")
        _ensure_directory(root, work_root, expected_owner, 0o700)
        work = Path(
            tempfile.mkdtemp(prefix="cathedral-updater-bootstrap-", dir=work_root)
        )
        created_version = False
        try:
            _extract_payload(work, bundle, expected_owner)
            version_dir.mkdir(mode=0o755)
            created_version = True
            os.chmod(version_dir, 0o755, follow_symlinks=False)
            environment = {
                "HOME": "/root",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "PIP_CONFIG_FILE": "/dev/null",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PIP_NO_INDEX": "1",
                "PYTHONNOUSERSITE": "1",
            }
            runner(
                [str(python_executable), "-m", "venv", str(version_dir)],
                check=True,
                env=environment,
                text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
            runner(
                [
                    str(version_dir / "bin" / VENV_INTERPRETER_NAME),
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--no-deps",
                    "--find-links",
                    str(work / "payload" / "wheelhouse"),
                    "--require-hashes",
                    "--only-binary=:all:",
                    "-r",
                    str(work / REQUIREMENTS_ARCHIVE_PATH),
                ],
                check=True,
                env=environment,
                text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
            runner(
                [
                    str(version_dir / "bin" / VENV_INTERPRETER_NAME),
                    "-I",
                    "-c",
                    "from cathedral_thin.independent_runtime import updater; "
                    "import cryptography; assert callable(updater.main)",
                ],
                check=True,
                env=environment,
                text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
            runner(
                [
                    str(version_dir / "bin" / "cathedral-validator-update"),
                    "--help",
                ],
                check=True,
                env=environment,
                text=True,
                timeout=60,
            )
            _write_new(
                version_dir / ".bootstrap-manifest.json",
                bundle.manifest,
                0o444,
            )
            _write_new(
                version_dir / ".bootstrap-manifest.sig",
                bundle.signature,
                0o444,
            )
            _validate_installed_venv(version_dir, bundle, expected_owner=expected_owner)
        except BaseException:
            if created_version:
                _remove_unreferenced_release(
                    version_dir,
                    bundle,
                    fixed_link=fixed_link,
                    committed_path=committed_path,
                    pending_path=pending_path,
                    expected_owner=expected_owner,
                )
            raise
        finally:
            shutil.rmtree(work)

    _validate_venv_interpreter(version_dir, expected_owner=expected_owner)
    releases_metadata = releases.lstat()
    _fsync_owned_tree(
        version_dir,
        expected_owner=expected_owner,
        expected_device=releases_metadata.st_dev,
    )
    _fsync_directory(releases, expected_owner=expected_owner)

    _install_managed_file(
        root,
        pending_path,
        _bootstrap_record(bundle, BOOTSTRAP_PENDING_SCHEMA),
        expected_owner=expected_owner,
        mode=0o600,
        parent_mode=0o700,
    )
    for path, (body, mode) in destinations.items():
        _install_managed_file(
            root,
            path,
            body,
            expected_owner=expected_owner,
            mode=mode,
        )

    _activate_updater_link(
        fixed_link,
        relative_link,
        expected_owner=expected_owner,
    )

    sysusers = _relative(root, "etc/sysusers.d/cathedral-validator.conf")
    runner(
        ["/usr/bin/systemd-sysusers", str(sysusers)],
        check=True,
        text=True,
        timeout=60,
    )
    runner(
        ["/usr/bin/systemctl", "daemon-reload"],
        check=True,
        text=True,
        timeout=60,
    )
    _install_managed_file(
        root,
        committed_path,
        _bootstrap_record(bundle, BOOTSTRAP_STATE_SCHEMA),
        expected_owner=expected_owner,
        mode=0o600,
        parent_mode=0o700,
    )
    _remove_durable(pending_path)
    return bundle.manifest_sha256


def install_verified_bundle(
    bundle: VerifiedBundle,
    *,
    root: Path,
    expected_owner: int,
    python_executable: Path,
    runner: Runner = _default_runner,
) -> str:
    """Install or recover one authenticated monotonic bootstrap release."""

    _check_root(root, expected_owner)
    _preflight_python(python_executable, runner)
    _preflight_destinations(root, bundle, expected_owner=expected_owner)
    with _bootstrap_operation_lock(root, expected_owner=expected_owner) as state_root:
        return _install_verified_bundle_locked(
            bundle,
            root=root,
            state_root=state_root,
            expected_owner=expected_owner,
            python_executable=python_executable,
            runner=runner,
        )


def _runtime_guard() -> None:
    if os.geteuid() != 0:
        raise InstallRefused("installer must run as root")
    if sys.platform != "linux":
        raise InstallRefused("installer runs only on Linux")
    if sys.version_info[:2] != (3, 12):
        raise InstallRefused("installer requires CPython 3.12")
    if not Path("/run/systemd/system").is_dir():
        raise InstallRefused("installer requires a running systemd host")
    if not hasattr(os, "memfd_create"):
        raise InstallRefused("installer requires Linux memfd support")
    for executable in (
        Path("/usr/bin/openssl"),
        Path("/usr/bin/systemctl"),
        Path("/usr/bin/systemd-sysusers"),
    ):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise InstallRefused(
                f"required host executable is unavailable: {executable}"
            )
    try:
        openssl_version = subprocess.run(
            ["/usr/bin/openssl", "version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallRefused("cannot verify the host OpenSSL version") from exc
    if not openssl_version.startswith("OpenSSL 3."):
        raise InstallRefused("installer requires OpenSSL 3 for Ed25519 verification")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify and install a signed Cathedral updater bootstrap bundle"
    )
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument(
        "--bootstrap-public-key",
        required=True,
        type=Path,
        help="independently authenticated bootstrap trust anchor",
    )
    parser.add_argument(
        "--expected-bootstrap-key-fingerprint",
        required=True,
        help="independently authenticated bootstrap trust-anchor fingerprint",
    )
    parser.add_argument(
        "--minimum-bootstrap-sequence",
        required=True,
        type=int,
        help="independently authenticated bootstrap replay checkpoint",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        _runtime_guard()
        bundle = verify_bundle(
            bundle_path=options.bundle,
            manifest_path=options.manifest,
            signature_path=options.signature,
            bootstrap_public_key_path=options.bootstrap_public_key,
            expected_bootstrap_fingerprint=(options.expected_bootstrap_key_fingerprint),
            minimum_bootstrap_sequence=options.minimum_bootstrap_sequence,
            expected_owner=0,
        )
        verify_running_installer(
            bundle,
            script_path=Path(__file__).absolute(),
            expected_owner=0,
        )
        original_umask = os.umask(0o077)
        try:
            digest = install_verified_bundle(
                bundle,
                root=Path("/"),
                expected_owner=0,
                python_executable=Path(sys.executable),
            )
        finally:
            os.umask(original_umask)
    except (InstallRefused, OSError, subprocess.SubprocessError, ValueError) as exc:
        raise SystemExit(f"bootstrap install refused: {exc}") from exc
    print(
        canonical_json(
            {
                "enabled_units": [],
                "manifest_sha256": digest,
                "bootstrap_sequence": bundle.bootstrap_sequence,
                "bootstrap_signing_key_fingerprint": (
                    bundle.bootstrap_signing_key_fingerprint
                ),
                "runtime_release_key_fingerprint": (
                    bundle.runtime_release_key_fingerprint
                ),
                "status": "installed",
            }
        ).decode("ascii"),
        end="",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
