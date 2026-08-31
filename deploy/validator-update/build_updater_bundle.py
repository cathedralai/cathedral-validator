#!/usr/bin/env python3
"""Build the signed, offline bootstrap bundle for the validator updater.

This program runs on an owner-controlled release workstation.  It accepts only
an already-built Linux wheelhouse, a complete hash lock, the pinned release
public key, and the fixed reviewed systemd/config-template asset set.  The
private signing key is read only to create the detached manifest signature and
is never copied into an output.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import gzip
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

BUNDLE_SCHEMA = "cathedral_validator_updater_bootstrap_v1"
PUBLIC_KEY_ARCHIVE_PATH = "payload/update-public-key.pem"
REQUIREMENTS_ARCHIVE_PATH = "payload/requirements.txt"
INSTALLER_ARCHIVE_PATH = "payload/installer/install_updater_bundle.py"
MAX_CONTROL_FILE_BYTES = 2 * 1024 * 1024
MAX_WHEELS = 1_000
MAX_WHEEL_BYTES = 512 * 1024 * 1024
MAX_WHEEL_MEMBER_BYTES = 128 * 1024 * 1024
MAX_WHEEL_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024

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
SYSUSERS_SOURCE = "cathedral-validator.sysusers"
REQUIRED_ASSETS = SYSTEMD_ASSETS | EXAMPLE_ASSETS | {SYSUSERS_SOURCE}

_LOCKED_REQUIREMENT = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.-]*"
    r"(?:\[[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*\])?"
    r"==[^\s;@/]+"
    r"(?:\s+--hash=sha256:[0-9a-f]{64})+"
)
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})(?=\s|$)")
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)


class BundleRefused(ValueError):
    """The requested bootstrap artifact is not safe to build."""


@dataclass(frozen=True)
class PayloadFile:
    path: str
    body: bytes
    mode: int = 0o644

    def manifest_entry(self) -> dict[str, Any]:
        return {
            "mode": f"{self.mode:04o}",
            "path": self.path,
            "sha256": hashlib.sha256(self.body).hexdigest(),
            "size": len(self.body),
        }


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


def _safe_absolute(path: Path, label: str) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise BundleRefused(f"{label} must be an absolute non-symlink path")


def _controlled_directory(path: Path, label: str) -> None:
    _safe_absolute(path, label)
    try:
        metadata = path.stat()
    except OSError as exc:
        raise BundleRefused(f"{label} is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise BundleRefused(f"{label} must be owner-controlled")


def _read_controlled_file(
    path: Path,
    label: str,
    *,
    maximum: int,
    owner_only: bool = False,
) -> bytes:
    _safe_absolute(path, label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BundleRefused(f"{label} is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        forbidden = 0o077 if owner_only else 0o022
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & forbidden
            or not 1 <= metadata.st_size <= maximum
        ):
            raise BundleRefused(f"{label} is not an owner-controlled regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            body = handle.read(maximum + 1)
        if len(body) != metadata.st_size or len(body) > maximum:
            raise BundleRefused(f"{label} changed while it was read")
        return body
    finally:
        os.close(descriptor)


def _refuse_private_key(body: bytes, label: str) -> None:
    if any(marker in body for marker in _PRIVATE_KEY_MARKERS):
        raise BundleRefused(f"{label} contains private-key material")


def _private_key(path: Path) -> Ed25519PrivateKey:
    raw = _read_controlled_file(
        path,
        "private signing key",
        maximum=16_384,
        owner_only=True,
    )
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except TypeError:
        password = getpass.getpass("Bootstrap signing key password: ").encode("utf-8")
        key = serialization.load_pem_private_key(raw, password=password)
    except ValueError as exc:
        raise BundleRefused("private signing key is not valid PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise BundleRefused("private signing key is not Ed25519")
    return key


def _public_key(path: Path) -> tuple[Ed25519PublicKey, bytes, str]:
    raw = _read_controlled_file(
        path,
        "pinned public key",
        maximum=16_384,
    )
    try:
        key = serialization.load_pem_public_key(raw)
    except ValueError as exc:
        raise BundleRefused("pinned public key is not valid PEM") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise BundleRefused("pinned public key is not Ed25519")
    canonical = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = "sha256:" + hashlib.sha256(der).hexdigest()
    return key, canonical, fingerprint


def _safe_archive_name(name: str, label: str) -> None:
    path = PurePosixPath(name)
    if (
        not name
        or len(name.encode("utf-8")) > 255
        or path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or "" in path.parts
    ):
        raise BundleRefused(f"{label} has an unsafe archive path")


def _scan_wheel(path: Path, body: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(body), mode="r") as wheel:
            members = wheel.infolist()
            if not members or len(members) > 100_000:
                raise BundleRefused(f"wheel {path.name} has an invalid member count")
            names: set[str] = set()
            total = 0
            for member in members:
                _safe_archive_name(member.filename, f"wheel {path.name}")
                if member.filename in names or member.is_dir():
                    if member.filename in names:
                        raise BundleRefused(f"wheel {path.name} has duplicate members")
                    continue
                names.add(member.filename)
                total += member.file_size
                if (
                    member.file_size < 0
                    or member.file_size > MAX_WHEEL_MEMBER_BYTES
                    or total > MAX_WHEEL_EXPANDED_BYTES
                ):
                    raise BundleRefused(f"wheel {path.name} exceeds expanded limits")
                carry = b""
                with wheel.open(member, "r") as handle:
                    while True:
                        chunk = handle.read(64 * 1024)
                        if not chunk:
                            break
                        sample = carry + chunk
                        _refuse_private_key(sample, f"wheel {path.name}")
                        carry = sample[-64:]
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise BundleRefused(f"wheel {path.name} is not a readable wheel") from exc


def _wheelhouse(path: Path) -> tuple[list[PayloadFile], set[str]]:
    _controlled_directory(path, "wheelhouse")
    wheels: list[PayloadFile] = []
    digests: set[str] = set()
    entries = sorted(path.iterdir(), key=lambda item: item.name)
    if not entries or len(entries) > MAX_WHEELS:
        raise BundleRefused("wheelhouse must contain 1..1000 wheels")
    for wheel_path in entries:
        if wheel_path.suffix != ".whl" or "/" in wheel_path.name:
            raise BundleRefused("wheelhouse must contain only flat .whl files")
        body = _read_controlled_file(
            wheel_path,
            f"wheel {wheel_path.name}",
            maximum=MAX_WHEEL_BYTES,
        )
        _scan_wheel(wheel_path, body)
        digest = hashlib.sha256(body).hexdigest()
        if digest in digests:
            raise BundleRefused("wheelhouse contains duplicate wheel bytes")
        digests.add(digest)
        wheels.append(PayloadFile(f"payload/wheelhouse/{wheel_path.name}", body))
    return wheels, digests


def _logical_requirements(raw: bytes) -> list[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BundleRefused("requirements lock is not UTF-8") from exc
    logical: list[str] = []
    pending = ""
    for physical in text.splitlines():
        stripped = physical.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pending += (" " if pending else "") + stripped.removesuffix("\\").strip()
        if stripped.endswith("\\"):
            continue
        logical.append(" ".join(pending.split()))
        pending = ""
    if pending:
        raise BundleRefused("requirements lock has an unfinished continuation")
    return logical


def _requirements(path: Path, wheel_digests: set[str]) -> bytes:
    raw = _read_controlled_file(
        path,
        "requirements lock",
        maximum=MAX_CONTROL_FILE_BYTES,
    )
    _refuse_private_key(raw, "requirements lock")
    lines = _logical_requirements(raw)
    if not lines:
        raise BundleRefused("requirements lock is empty")
    locked_hashes: set[str] = set()
    for line in lines:
        if _LOCKED_REQUIREMENT.fullmatch(line) is None:
            raise BundleRefused(
                "requirements must use exact == pins and sha256 hashes only"
            )
        locked_hashes.update(_HASH.findall(line))
    if locked_hashes != wheel_digests:
        raise BundleRefused(
            "requirements hashes must match every wheel and only the wheelhouse"
        )
    normalized = "\n".join(lines).encode("utf-8") + b"\n"
    return normalized


def _assets(path: Path) -> list[PayloadFile]:
    _controlled_directory(path, "reviewed asset directory")
    actual = {item.name for item in path.iterdir() if item.name in REQUIRED_ASSETS}
    if actual != REQUIRED_ASSETS:
        missing = ", ".join(sorted(REQUIRED_ASSETS - actual))
        raise BundleRefused(f"reviewed asset set is incomplete: {missing}")
    payload: list[PayloadFile] = []
    for name in sorted(REQUIRED_ASSETS):
        body = _read_controlled_file(
            path / name,
            f"reviewed asset {name}",
            maximum=MAX_CONTROL_FILE_BYTES,
        )
        _refuse_private_key(body, f"reviewed asset {name}")
        if name in SYSTEMD_ASSETS:
            archive_path = f"payload/systemd/{name}"
        elif name == SYSUSERS_SOURCE:
            archive_path = "payload/sysusers/cathedral-validator.conf"
        else:
            archive_path = f"payload/examples/{name}"
        payload.append(PayloadFile(archive_path, body))
    return payload


def _installer_payload() -> PayloadFile:
    path = Path(__file__).absolute().with_name("install_updater_bundle.py")
    body = _read_controlled_file(
        path,
        "bootstrap installer",
        maximum=MAX_CONTROL_FILE_BYTES,
    )
    _refuse_private_key(body, "bootstrap installer")
    return PayloadFile(INSTALLER_ARCHIVE_PATH, body)


def deterministic_archive(files: Iterable[PayloadFile]) -> bytes:
    ordered = sorted(files, key=lambda item: item.path)
    if not ordered or len({item.path for item in ordered}) != len(ordered):
        raise BundleRefused("bootstrap payload paths are empty or duplicated")
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(
            fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT
        ) as bundle:
            for item in ordered:
                _safe_archive_name(item.path, "bootstrap payload")
                info = tarfile.TarInfo(item.path)
                info.size = len(item.body)
                info.mode = item.mode
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mtime = 0
                bundle.addfile(info, io.BytesIO(item.body))
    return output.getvalue()


def build_bundle(
    *,
    wheelhouse: Path,
    requirements: Path,
    public_key_path: Path,
    private_key_path: Path,
    assets_dir: Path,
) -> tuple[bytes, bytes, bytes, str]:
    private_key = _private_key(private_key_path)
    public_key, public_pem, fingerprint = _public_key(public_key_path)
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    pinned_public = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if private_public != pinned_public:
        raise BundleRefused("private signing key does not match pinned public key")

    wheels, wheel_digests = _wheelhouse(wheelhouse)
    requirements_body = _requirements(requirements, wheel_digests)
    files = [
        _installer_payload(),
        PayloadFile(PUBLIC_KEY_ARCHIVE_PATH, public_pem),
        PayloadFile(REQUIREMENTS_ARCHIVE_PATH, requirements_body),
        *_assets(assets_dir),
        *wheels,
    ]
    archive = deterministic_archive(files)
    manifest = canonical_json(
        {
            "bundle": {
                "sha256": hashlib.sha256(archive).hexdigest(),
                "size": len(archive),
            },
            "files": [
                item.manifest_entry()
                for item in sorted(files, key=lambda item: item.path)
            ],
            "install": {
                "enable_units": False,
                "installer": INSTALLER_ARCHIVE_PATH,
                "python": "CPython==3.12.*",
                "requirements": REQUIREMENTS_ARCHIVE_PATH,
                "wheelhouse": "payload/wheelhouse",
            },
            "public_key": {
                "algorithm": "Ed25519",
                "fingerprint": fingerprint,
                "path": PUBLIC_KEY_ARCHIVE_PATH,
            },
            "schema": BUNDLE_SCHEMA,
        }
    )
    signature = private_key.sign(manifest)
    return archive, manifest, signature, fingerprint


def _validate_output(path: Path, label: str) -> None:
    _safe_absolute(path, label)
    _controlled_directory(path.parent, f"{label} parent")
    if path.exists() or path.is_symlink():
        raise BundleRefused(f"{label} already exists")


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


def write_outputs(
    *,
    bundle_out: Path,
    manifest_out: Path,
    signature_out: Path,
    archive: bytes,
    manifest: bytes,
    signature: bytes,
) -> None:
    outputs = (
        (bundle_out, archive, 0o644, "bundle output"),
        (manifest_out, manifest, 0o644, "manifest output"),
        (signature_out, signature, 0o644, "signature output"),
    )
    if len({path for path, _, _, _ in outputs}) != len(outputs):
        raise BundleRefused("output paths must be distinct")
    for path, _, _, label in outputs:
        _validate_output(path, label)
    created: list[Path] = []
    try:
        for path, body, mode, _ in outputs:
            _write_new(path, body, mode)
            created.append(path)
    except OSError:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a deterministic signed Cathedral updater bootstrap bundle"
    )
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--requirements", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--assets-dir", required=True, type=Path)
    parser.add_argument("--bundle-out", required=True, type=Path)
    parser.add_argument("--manifest-out", required=True, type=Path)
    parser.add_argument("--signature-out", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        archive, manifest, signature, fingerprint = build_bundle(
            wheelhouse=options.wheelhouse,
            requirements=options.requirements,
            public_key_path=options.public_key,
            private_key_path=options.private_key,
            assets_dir=options.assets_dir,
        )
        write_outputs(
            bundle_out=options.bundle_out,
            manifest_out=options.manifest_out,
            signature_out=options.signature_out,
            archive=archive,
            manifest=manifest,
            signature=signature,
        )
    except (BundleRefused, OSError, ValueError) as exc:
        raise SystemExit(f"bootstrap bundle build refused: {exc}") from exc
    print(
        canonical_json(
            {
                "bundle_sha256": hashlib.sha256(archive).hexdigest(),
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "public_key_fingerprint": fingerprint,
                "signature_base64": base64.b64encode(signature).decode("ascii"),
            }
        ).decode("ascii"),
        end="",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
