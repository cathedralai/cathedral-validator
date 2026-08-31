#!/usr/bin/env python3
"""Verify and install the offline Cathedral validator-updater bootstrap bundle.

The production CLI runs only as root on Linux under CPython 3.12 with systemd.
It authenticates the canonical manifest with an independently supplied pinned
Ed25519 public key before it creates or changes any path.  It never enables or
starts a validator or updater unit.

Do not execute an unauthenticated copy of this file.  First verify the detached
manifest signature and signed archive digest with OpenSSL, then extract and run
the signed ``payload/installer/install_updater_bundle.py`` member.  The CLI also
checks its running bytes against that signed member before persistent mutation.
"""

from __future__ import annotations

import argparse
import base64
import binascii
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
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

BUNDLE_SCHEMA = "cathedral_validator_updater_bootstrap_v1"
PUBLIC_KEY_ARCHIVE_PATH = "payload/update-public-key.pem"
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
        PUBLIC_KEY_ARCHIVE_PATH,
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
    public_key_fingerprint: str
    files: Mapping[str, ManifestFile]


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


def _ed25519_der(pem: bytes) -> bytes:
    try:
        text = pem.decode("ascii")
    except UnicodeDecodeError as exc:
        raise InstallRefused("trusted public key is not ASCII PEM") from exc
    lines = [line.strip() for line in text.strip().splitlines()]
    if (
        len(lines) < 3
        or lines[0] != "-----BEGIN PUBLIC KEY-----"
        or lines[-1] != "-----END PUBLIC KEY-----"
        or any(not line for line in lines[1:-1])
    ):
        raise InstallRefused("trusted public key is not canonical public-key PEM")
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InstallRefused("trusted public key has invalid base64") from exc
    if len(der) != len(PUBLIC_KEY_DER_PREFIX) + 32 or not der.startswith(
        PUBLIC_KEY_DER_PREFIX
    ):
        raise InstallRefused("trusted public key is not Ed25519")
    return der


def public_key_fingerprint(pem: bytes) -> str:
    return "sha256:" + hashlib.sha256(_ed25519_der(pem)).hexdigest()


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
        {"bundle", "files", "install", "public_key", "schema"},
        "manifest",
    )
    if document["schema"] != BUNDLE_SCHEMA:
        raise InstallRefused("manifest schema is unsupported")
    bundle = _object(document["bundle"], {"sha256", "size"}, "bundle record")
    if (
        not isinstance(bundle["sha256"], str)
        or DIGEST.fullmatch(bundle["sha256"]) is None
        or isinstance(bundle["size"], bool)
        or not isinstance(bundle["size"], int)
        or not 1 <= bundle["size"] <= MAX_BUNDLE_BYTES
    ):
        raise InstallRefused("bundle record is invalid")
    public = _object(
        document["public_key"],
        {"algorithm", "fingerprint", "path"},
        "public-key record",
    )
    if (
        public["algorithm"] != "Ed25519"
        or public["path"] != PUBLIC_KEY_ARCHIVE_PATH
        or not isinstance(public["fingerprint"], str)
        or FINGERPRINT.fullmatch(public["fingerprint"]) is None
    ):
        raise InstallRefused("public-key record is invalid")
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
    trusted_public_key_path: Path,
    expected_fingerprint: str,
    expected_owner: int,
    signature_verifier: SignatureVerifier = _openssl_verify,
) -> VerifiedBundle:
    if FINGERPRINT.fullmatch(expected_fingerprint) is None:
        raise InstallRefused("expected public-key fingerprint is invalid")
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
    public_key = _read_controlled_file(
        trusted_public_key_path,
        "trusted public key",
        expected_owner=expected_owner,
        maximum=16_384,
    )
    fingerprint = public_key_fingerprint(public_key)
    if fingerprint != expected_fingerprint:
        raise InstallRefused("trusted public-key fingerprint differs from the pin")
    document, record_list = _parse_manifest(manifest)
    if document["public_key"]["fingerprint"] != fingerprint:
        raise InstallRefused("manifest public-key fingerprint differs from the pin")
    try:
        signature_verifier(manifest, signature, public_key)
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
    bundled_key = files[PUBLIC_KEY_ARCHIVE_PATH].body
    if _ed25519_der(bundled_key) != _ed25519_der(public_key):
        raise InstallRefused(
            "bundled public key differs from the external trust anchor"
        )
    return VerifiedBundle(
        manifest=manifest,
        signature=signature,
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        public_key_fingerprint=fingerprint,
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
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=mode)
            metadata = current.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise InstallRefused(f"unsafe destination directory: {current}")


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


def _destinations(root: Path, bundle: VerifiedBundle) -> dict[Path, tuple[bytes, int]]:
    result: dict[Path, tuple[bytes, int]] = {
        _relative(root, "etc/cathedral-validator/update-public-key.pem"): (
            bundle.files[PUBLIC_KEY_ARCHIVE_PATH].body,
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
    _existing_file(
        marker,
        bundle.manifest,
        expected_owner=expected_owner,
        mode=0o444,
    )
    _existing_file(
        signature,
        bundle.signature,
        expected_owner=expected_owner,
        mode=0o444,
    )
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
    expected_shebang = f"#!{version_dir}/bin/python".encode("utf-8")
    with executable.open("rb") as handle:
        first_line = handle.readline(4096).rstrip(b"\r\n")
    if first_line != expected_shebang:
        raise InstallRefused("installed updater entry point has the wrong interpreter")


def _default_runner(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(*args, **kwargs)


def install_verified_bundle(
    bundle: VerifiedBundle,
    *,
    root: Path,
    expected_owner: int,
    python_executable: Path,
    runner: Runner = _default_runner,
) -> str:
    """Install one already-authenticated bundle without enabling any unit."""

    _check_root(root, expected_owner)
    destinations = _destinations(root, bundle)
    for path, (body, mode) in destinations.items():
        _existing_ancestors(root, path.parent, expected_owner)
        _existing_file(
            path,
            body,
            expected_owner=expected_owner,
            mode=mode,
        )

    releases = _relative(root, "usr/local/lib/cathedral-validator-updater-releases")
    version_dir = releases / bundle.manifest_sha256
    fixed_link = _relative(root, "usr/local/lib/cathedral-validator-updater")
    _existing_ancestors(root, releases, expected_owner)
    _existing_ancestors(root, fixed_link.parent, expected_owner)
    relative_link = (
        Path("cathedral-validator-updater-releases") / bundle.manifest_sha256
    )

    link_exists = False
    try:
        link_metadata = fixed_link.lstat()
    except FileNotFoundError:
        pass
    else:
        if (
            not stat.S_ISLNK(link_metadata.st_mode)
            or fixed_link.readlink() != relative_link
        ):
            raise InstallRefused(
                "existing updater activation path differs from this bundle"
            )
        link_exists = True

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
        _validate_installed_venv(version_dir, bundle, expected_owner=expected_owner)
    else:
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
                    str(version_dir / "bin" / "python"),
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
                    str(version_dir / "bin" / "python"),
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
        except Exception:
            if created_version:
                shutil.rmtree(version_dir)
            raise
        finally:
            shutil.rmtree(work)

    for path, (body, mode) in destinations.items():
        _ensure_directory(root, path.parent, expected_owner, 0o755)
        if not _existing_file(
            path,
            body,
            expected_owner=expected_owner,
            mode=mode,
        ):
            _write_new(path, body, mode)

    if not link_exists:
        fixed_link.symlink_to(relative_link)
        parent = os.open(fixed_link.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)

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
    return bundle.manifest_sha256


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
    parser.add_argument("--trusted-public-key", required=True, type=Path)
    parser.add_argument("--expected-public-key-fingerprint", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        _runtime_guard()
        bundle = verify_bundle(
            bundle_path=options.bundle,
            manifest_path=options.manifest,
            signature_path=options.signature,
            trusted_public_key_path=options.trusted_public_key,
            expected_fingerprint=options.expected_public_key_fingerprint,
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
                "public_key_fingerprint": bundle.public_key_fingerprint,
                "status": "installed",
            }
        ).decode("ascii"),
        end="",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
