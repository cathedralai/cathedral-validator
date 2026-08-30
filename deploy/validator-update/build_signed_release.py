#!/usr/bin/env python3
"""Offline deterministic release builder and Ed25519 metadata signer.

Run this only on a release workstation.  The private signing key is an input to
this tool and is never copied into a validator release or validator host.
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
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cathedral_thin.independent_runtime.preview_io import canonical_document_bytes
from cathedral_thin.independent_runtime.updater import (
    MAX_METADATA_LIFETIME_SECONDS,
    METADATA_SCHEMA,
    UpdateRefused,
    parse_release_metadata,
    release_tree_sha256,
)

VALIDATOR_PEX_ENTRY_POINT = "cathedral_thin.independent_runtime.direct_validator:main"
VALIDATOR_BUNDLE_SCHEMA = "cathedral_validator_bundle_v1"
MAX_PEX_BYTES = 512 * 1024 * 1024
MAX_PEX_FILES = 100_000
MAX_PEX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
_REQUIRED_DISTRIBUTIONS = (
    "bittensor-",
    "cathedral-",
    "cathedral_scaffold-",
    "cryptography-",
    "numpy-",
)
_WHEEL_VERSION = re.compile(r"[0-9][0-9a-z.]*")
_COMPUTE_COMMIT = "8dde6eaca27116eed53386a1fa33ec70b74a01fb"
_RELEASE_INTERPRETER_CONSTRAINT = "CPython==3.12.*"
_RELEASE_INTERPRETER_SHEBANG = b"#!/usr/bin/python3.12\n"
_COMPUTE_REQUIREMENT = (
    "cathedral@git+https://github.com/cathedralai/"
    f"cathedral-sandbox.git@{_COMPUTE_COMMIT}"
)
_PROJECT_RELEASE_REQUIREMENT = "cathedral-scaffold[snp-production]@file://"


@dataclass(frozen=True)
class ValidatedPex:
    raw: bytes
    info_sha256: str
    project_distribution: str
    version: str
    interpreter_constraints: tuple[str, ...]


def _private_key(path: Path) -> Ed25519PrivateKey:
    if not path.is_absolute() or path.is_symlink():
        raise UpdateRefused("private signing key path must be an absolute regular file")
    metadata = path.stat()
    raw = path.read_bytes()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or len(raw) > 16_384
    ):
        raise UpdateRefused("private signing key is not owner-only")
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except TypeError:
        password = getpass.getpass("Release signing key password: ").encode("utf-8")
        key = serialization.load_pem_private_key(raw, password=password)
    except ValueError as exc:
        raise UpdateRefused("private signing key is not valid PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise UpdateRefused("private signing key is not Ed25519")
    return key


def _atomic_write(path: Path, body: bytes, *, mode: int) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise UpdateRefused("output path must be absolute and not a symlink")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _validator_pex(path: Path) -> ValidatedPex:
    """Validate the exact relocatable validator bundle before signing it."""

    if not path.is_absolute() or path.is_symlink():
        raise UpdateRefused("validator PEX must be an absolute regular file")
    try:
        metadata = path.stat()
        raw = path.read_bytes()
    except OSError as exc:
        raise UpdateRefused("validator PEX is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not metadata.st_mode & 0o111
        or not 1 <= len(raw) <= MAX_PEX_BYTES
    ):
        raise UpdateRefused(
            "validator PEX must be owner-controlled, executable, and bounded"
        )
    if not raw.startswith(_RELEASE_INTERPRETER_SHEBANG):
        raise UpdateRefused("validator PEX has an unsupported interpreter shebang")
    try:
        with zipfile.ZipFile(io.BytesIO(raw), mode="r") as bundle:
            members = bundle.infolist()
            names = [member.filename for member in members]
            if len(members) > MAX_PEX_FILES or len(names) != len(set(names)):
                raise UpdateRefused("validator PEX member set is invalid")
            total = 0
            for member in members:
                path_name = PurePosixPath(member.filename)
                if (
                    path_name.is_absolute()
                    or ".." in path_name.parts
                    or member.file_size < 0
                ):
                    raise UpdateRefused("validator PEX has an unsafe member")
                total += member.file_size
                if total > MAX_PEX_UNCOMPRESSED_BYTES:
                    raise UpdateRefused("validator PEX exceeds its expanded limit")
            if names.count("PEX-INFO") != 1:
                raise UpdateRefused("validator PEX has no unique PEX-INFO")
            info_raw = bundle.read("PEX-INFO")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise UpdateRefused("validator PEX is not a readable zipapp") from exc
    if len(info_raw) > 1_048_576:
        raise UpdateRefused("validator PEX metadata is too large")
    try:
        info = json.loads(info_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateRefused("validator PEX metadata is invalid") from exc
    if not isinstance(info, dict):
        raise UpdateRefused("validator PEX metadata is not an object")
    if info.get("entry_point") != VALIDATOR_PEX_ENTRY_POINT:
        raise UpdateRefused("validator PEX has the wrong entry point")
    if (
        info.get("inherit_path") != "false"
        or info.get("pex_path") not in {None, ""}
        or info.get("pex_paths") not in (None, [], ())
        or info.get("inject_env") not in (None, {}, ())
        or info.get("strip_pex_env") is not True
    ):
        raise UpdateRefused("validator PEX inherits an unreviewed runtime environment")
    constraints = info.get("interpreter_constraints")
    if not isinstance(constraints, list) or constraints != [
        _RELEASE_INTERPRETER_CONSTRAINT
    ]:
        raise UpdateRefused("validator PEX has the wrong interpreter constraint")
    distributions = info.get("distributions")
    if not isinstance(distributions, dict) or not distributions:
        raise UpdateRefused("validator PEX has no locked distributions")
    for name, digest in distributions.items():
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(value not in "0123456789abcdef" for value in digest)
        ):
            raise UpdateRefused("validator PEX distribution lock is invalid")
    lowered = tuple(name.lower() for name in distributions)
    if any(
        not any(name.startswith(prefix) for name in lowered)
        for prefix in _REQUIRED_DISTRIBUTIONS
    ):
        raise UpdateRefused("validator PEX omits a required runtime distribution")
    projects = [
        name for name in distributions if name.lower().startswith("cathedral_scaffold-")
    ]
    if len(projects) != 1:
        raise UpdateRefused("validator PEX has no unique Cathedral distribution")
    project = projects[0]
    project_version = project[len("cathedral_scaffold-") :].split("-", 1)[0]
    if _WHEEL_VERSION.fullmatch(project_version) is None:
        raise UpdateRefused("validator PEX Cathedral version is invalid")
    requirements = info.get("requirements")
    normalized_requirements = (
        ["".join(requirement.lower().split()) for requirement in requirements]
        if isinstance(requirements, list)
        and all(isinstance(requirement, str) for requirement in requirements)
        else []
    )
    if _COMPUTE_REQUIREMENT not in normalized_requirements or not any(
        requirement.startswith(_PROJECT_RELEASE_REQUIREMENT)
        for requirement in normalized_requirements
    ):
        raise UpdateRefused(
            "validator PEX omits the production extra or pinned Compute contract"
        )
    module_suffix = "cathedral_thin/independent_runtime/direct_validator.py"
    if not any(name.endswith(module_suffix) for name in names):
        raise UpdateRefused("validator PEX omits the direct validator module")
    snp_suffix = "cathedral_thin/independent_runtime/snp_production.py"
    if not any(name.endswith(snp_suffix) for name in names):
        raise UpdateRefused("validator PEX omits the production SNP verifier")
    return ValidatedPex(
        raw=raw,
        info_sha256=hashlib.sha256(info_raw).hexdigest(),
        project_distribution=project,
        version=project_version,
        interpreter_constraints=tuple(constraints),
    )


def validator_release_tree(pex: Path, destination: Path) -> ValidatedPex:
    """Create the only supported release-tree shape from one validated PEX."""

    if destination.exists() or destination.is_symlink():
        raise UpdateRefused("validator bundle destination already exists")
    validated = _validator_pex(pex)
    executable = destination / "bin" / "cathedral-validator"
    executable.parent.mkdir(mode=0o755, parents=True)
    executable.write_bytes(validated.raw)
    executable.chmod(0o755)
    manifest = {
        "schema": VALIDATOR_BUNDLE_SCHEMA,
        "entry_point": VALIDATOR_PEX_ENTRY_POINT,
        "pex_sha256": hashlib.sha256(validated.raw).hexdigest(),
        "pex_info_sha256": validated.info_sha256,
        "project_distribution": validated.project_distribution,
        "interpreter_constraints": list(validated.interpreter_constraints),
    }
    (destination / "RELEASE.json").write_bytes(canonical_document_bytes(manifest))
    (destination / "RELEASE.json").chmod(0o644)
    return validated


def deterministic_archive(source: Path) -> bytes:
    """Build one path-sorted archive with normalized ownership and timestamps."""

    if not source.is_absolute() or source.is_symlink() or not source.is_dir():
        raise UpdateRefused("release source must be an absolute regular directory")
    files: list[Path] = []
    for path in source.rglob("*"):
        if path.is_symlink():
            raise UpdateRefused("release source contains a symlink")
        if path.is_file():
            files.append(path)
        elif not path.is_dir():
            raise UpdateRefused("release source contains a special file")
    if not files:
        raise UpdateRefused("release source contains no files")
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(
            fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT
        ) as bundle:
            for path in sorted(
                files, key=lambda item: item.relative_to(source).as_posix()
            ):
                relative = path.relative_to(source).as_posix()
                info = tarfile.TarInfo(relative)
                metadata = path.stat()
                info.size = metadata.st_size
                info.mode = 0o755 if stat.S_IMODE(metadata.st_mode) & 0o111 else 0o644
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mtime = 0
                with path.open("rb") as handle:
                    bundle.addfile(info, handle)
    return compressed.getvalue()


def _validity(*, issued_unix: int | None, lifetime_seconds: int) -> tuple[int, int]:
    issued = int(time.time()) if issued_unix is None else issued_unix
    if (
        isinstance(lifetime_seconds, bool)
        or not isinstance(lifetime_seconds, int)
        or not 60 <= lifetime_seconds <= MAX_METADATA_LIFETIME_SECONDS
    ):
        raise UpdateRefused("metadata lifetime is outside 60 seconds to 14 days")
    if isinstance(issued, bool) or not isinstance(issued, int) or issued < 1:
        raise UpdateRefused("metadata issue time is invalid")
    return issued, issued + lifetime_seconds


def _signed_envelope(
    signed: Mapping[str, Any], private_key: Ed25519PrivateKey
) -> bytes:
    payload = canonical_document_bytes(signed)
    signature = base64.b64encode(private_key.sign(payload)).decode("ascii")
    return canonical_document_bytes({"signed": dict(signed), "signature": signature})


def build_canary(
    *,
    pex: Path,
    archive_out: Path,
    metadata_out: Path,
    archive_url: str,
    sequence: int,
    private_key: Ed25519PrivateKey,
    issued_unix: int | None,
    lifetime_seconds: int,
) -> bytes:
    with tempfile.TemporaryDirectory(prefix="cathedral-validator-release-") as work:
        source = Path(work) / "release"
        validated = validator_release_tree(pex, source)
        archive = deterministic_archive(source)
        tree_sha256 = release_tree_sha256(source)

    issued, expires = _validity(
        issued_unix=issued_unix, lifetime_seconds=lifetime_seconds
    )
    release = {
        "version": validated.version,
        "archive_url": archive_url,
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "tree_sha256": tree_sha256,
        "entrypoint": "bin/cathedral-validator",
    }
    signed = {
        "schema": METADATA_SCHEMA,
        "channel": "canary",
        "sequence": sequence,
        "issued_unix": issued,
        "expires_unix": expires,
        "release": release,
    }
    metadata = _signed_envelope(signed, private_key)
    parse_release_metadata(
        metadata,
        channel="canary",
        public_key=private_key.public_key(),
        now_unix=issued,
    )
    _atomic_write(archive_out, archive, mode=0o644)
    _atomic_write(metadata_out, metadata, mode=0o644)
    return metadata


def promote_stable(
    *,
    canary_metadata: Path,
    metadata_out: Path,
    sequence: int,
    private_key: Ed25519PrivateKey,
    issued_unix: int | None,
    lifetime_seconds: int,
) -> bytes:
    raw = canary_metadata.read_bytes()
    issued, expires = _validity(
        issued_unix=issued_unix, lifetime_seconds=lifetime_seconds
    )
    canary = parse_release_metadata(
        raw,
        channel="canary",
        public_key=private_key.public_key(),
        now_unix=issued,
    )
    envelope = json.loads(raw.decode("ascii"))
    release = dict(envelope["signed"]["release"])
    release["promoted_canary"] = {
        "sequence": canary.sequence,
        "signed_sha256": canary.signed_sha256,
        "metadata_sha256": canary.metadata_sha256,
        "archive_sha256": canary.archive_sha256,
    }
    signed = {
        "schema": METADATA_SCHEMA,
        "channel": "stable",
        "sequence": sequence,
        "issued_unix": issued,
        "expires_unix": expires,
        "release": release,
    }
    metadata = _signed_envelope(signed, private_key)
    parse_release_metadata(
        metadata,
        channel="stable",
        public_key=private_key.public_key(),
        now_unix=issued,
    )
    _atomic_write(metadata_out, metadata, mode=0o644)
    return metadata


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and sign immutable Cathedral validator releases offline"
    )
    parser.add_argument("--private-key", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)
    canary = subparsers.add_parser("canary")
    canary.add_argument("--pex", required=True, type=Path)
    canary.add_argument("--archive-out", required=True, type=Path)
    canary.add_argument("--metadata-out", required=True, type=Path)
    canary.add_argument("--archive-url", required=True)
    canary.add_argument("--sequence", required=True, type=int)
    canary.add_argument("--issued-unix", type=int)
    canary.add_argument("--lifetime-seconds", type=int, default=7 * 24 * 60 * 60)
    stable = subparsers.add_parser("stable")
    stable.add_argument("--canary-metadata", required=True, type=Path)
    stable.add_argument("--metadata-out", required=True, type=Path)
    stable.add_argument("--sequence", required=True, type=int)
    stable.add_argument("--issued-unix", type=int)
    stable.add_argument("--lifetime-seconds", type=int, default=7 * 24 * 60 * 60)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        key = _private_key(options.private_key)
        if options.command == "canary":
            build_canary(
                pex=options.pex,
                archive_out=options.archive_out,
                metadata_out=options.metadata_out,
                archive_url=options.archive_url,
                sequence=options.sequence,
                private_key=key,
                issued_unix=options.issued_unix,
                lifetime_seconds=options.lifetime_seconds,
            )
        else:
            promote_stable(
                canary_metadata=options.canary_metadata,
                metadata_out=options.metadata_out,
                sequence=options.sequence,
                private_key=key,
                issued_unix=options.issued_unix,
                lifetime_seconds=options.lifetime_seconds,
            )
    except (OSError, UpdateRefused, ValueError) as exc:
        raise SystemExit(f"release build refused: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
