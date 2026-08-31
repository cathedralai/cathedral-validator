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
import urllib.parse
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cathedral_thin.independent_runtime.preview_io import canonical_document_bytes
from cathedral_thin.independent_runtime.updater import (
    MAX_ARCHIVE_BYTES,
    MAX_METADATA_LIFETIME_SECONDS,
    MAX_METADATA_BYTES,
    MAX_TREE_BYTES,
    METADATA_SCHEMA,
    UpdateRefused,
    extract_release_archive,
    parse_release_metadata,
    release_tree_sha256,
)

VALIDATOR_PEX_ENTRY_POINT = "cathedral_thin.independent_runtime.direct_validator:main"
TELEMETRY_PEX_MODULE = "cathedral_thin.independent_runtime.telemetry_exporter"
VALIDATOR_BUNDLE_SCHEMA = "cathedral_validator_bundle_v2"
VALIDATOR_RELEASE_ENTRYPOINT = "bin/cathedral-validator"
QVL_RELEASE_PATH = "bin/cathedral-tdx-verifier"
SNPGUEST_RELEASE_PATH = "bin/snpguest"
MAX_PEX_BYTES = 512 * 1024 * 1024
MAX_PEX_FILES = 100_000
MAX_PEX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_VERIFIER_BYTES = 512 * 1024 * 1024
_REQUIRED_DISTRIBUTIONS = (
    "bittensor-",
    "cathedral-",
    "cathedral_scaffold-",
    "cryptography-",
    "numpy-",
)
_WHEEL_VERSION = re.compile(r"[0-9][0-9a-z.]*")
_SOURCE_REVISION = re.compile(r"[0-9a-f]{40}")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
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


@dataclass(frozen=True)
class ValidatedExecutable:
    raw: bytes
    sha256: str


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


def _source_revision(value: object) -> str:
    if not isinstance(value, str) or _SOURCE_REVISION.fullmatch(value) is None:
        raise UpdateRefused(
            "source revision must be 40 lower-case hexadecimal characters"
        )
    return value


def _lower_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _LOWER_SHA256.fullmatch(value) is None:
        raise UpdateRefused(f"{label} is not a lower-case SHA-256 digest")
    return value


def _owner_controlled_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    executable: bool,
) -> bytes:
    """Read one exact regular file through a no-follow descriptor."""

    if not path.is_absolute():
        raise UpdateRefused(f"{label} path must be absolute")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise UpdateRefused(f"{label} is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or mode & 0o022
            or (executable and not mode & stat.S_IXUSR)
            or not 1 <= metadata.st_size <= maximum_bytes
        ):
            requirement = (
                "owner-controlled executable" if executable else "owner-controlled file"
            )
            raise UpdateRefused(f"{label} must be a bounded {requirement}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(maximum_bytes + 1)
        if len(raw) != metadata.st_size or len(raw) > maximum_bytes:
            raise UpdateRefused(f"{label} changed while it was read")
        return raw
    finally:
        os.close(descriptor)


def _validated_executable(path: Path, *, label: str) -> ValidatedExecutable:
    raw = _owner_controlled_file(
        path,
        label=label,
        maximum_bytes=MAX_VERIFIER_BYTES,
        executable=True,
    )
    return ValidatedExecutable(raw=raw, sha256=hashlib.sha256(raw).hexdigest())


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise UpdateRefused(f"{label} repeats key {key!r}")
            output[key] = value
        return output

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateRefused(f"{label} is not strict JSON") from exc
    if not isinstance(document, dict):
        raise UpdateRefused(f"{label} is not an object")
    return document


def _canonical_archive_url(url: object, archive_sha256: str) -> str:
    """Require Cathedral's digest-tagged, digest-named GitHub release asset."""

    digest = _lower_sha256(archive_sha256, label="archive digest")
    if not isinstance(url, str) or len(url) > 4096:
        raise UpdateRefused("archive URL is invalid")
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise UpdateRefused("archive URL is not the canonical GitHub HTTPS URL")
    segments = parsed.path.split("/")
    expected_prefix = [
        "",
        "cathedralai",
        "cathedral-validator",
        "releases",
        "download",
        f"validator-{digest}",
    ]
    if len(segments) != 7 or segments[:6] != expected_prefix:
        raise UpdateRefused("archive URL tag is not content-addressed")
    asset = segments[6]
    if (
        not asset
        or "/" in urllib.parse.unquote(asset)
        or re.search(rf"(?<![0-9a-f]){digest}(?![0-9a-f])", asset) is None
    ):
        raise UpdateRefused("archive URL asset is not content-addressed")
    return url


def _archive_url_from_template(template: object, archive_sha256: str) -> str:
    if not isinstance(template, str) or template.count("{archive_sha256}") != 2:
        raise UpdateRefused(
            "archive URL template must put {archive_sha256} in its tag and asset"
        )
    if "{" in template.replace("{archive_sha256}", "") or "}" in template.replace(
        "{archive_sha256}", ""
    ):
        raise UpdateRefused("archive URL template contains an unknown placeholder")
    return _canonical_archive_url(
        template.replace("{archive_sha256}", archive_sha256), archive_sha256
    )


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

    def project_module_present(module_path: str) -> bool:
        return module_path in names or f".deps/{project}/{module_path}" in names

    validator_module = "cathedral_thin/independent_runtime/direct_validator.py"
    if not project_module_present(validator_module):
        raise UpdateRefused("validator PEX omits the direct validator module")
    snp_module = "cathedral_thin/independent_runtime/snp_production.py"
    if not project_module_present(snp_module):
        raise UpdateRefused("validator PEX omits the production SNP verifier")
    for module in ("telemetry.py", "telemetry_exporter.py"):
        module_path = f"cathedral_thin/independent_runtime/{module}"
        if not project_module_present(module_path):
            raise UpdateRefused("validator PEX omits the private telemetry runtime")
    return ValidatedPex(
        raw=raw,
        info_sha256=hashlib.sha256(info_raw).hexdigest(),
        project_distribution=project,
        version=project_version,
        interpreter_constraints=tuple(constraints),
    )


def validator_release_tree(
    pex: Path,
    destination: Path,
    *,
    qvl: Path,
    snpguest: Path,
    source_revision: str,
) -> ValidatedPex:
    """Create the only supported release-tree shape from one validated PEX."""

    if destination.exists() or destination.is_symlink():
        raise UpdateRefused("validator bundle destination already exists")
    validated = _validator_pex(pex)
    reviewed_qvl = _validated_executable(qvl, label="QVL")
    reviewed_snpguest = _validated_executable(snpguest, label="snpguest")
    reviewed_revision = _source_revision(source_revision)

    executable = destination / "bin" / "cathedral-validator"
    executable.parent.mkdir(mode=0o755, parents=True)
    executable.write_bytes(validated.raw)
    executable.chmod(0o755)
    manifest = {
        "schema": VALIDATOR_BUNDLE_SCHEMA,
        "entry_point": VALIDATOR_PEX_ENTRY_POINT,
        "telemetry_module": TELEMETRY_PEX_MODULE,
        "pex_sha256": hashlib.sha256(validated.raw).hexdigest(),
        "pex_info_sha256": validated.info_sha256,
        "project_distribution": validated.project_distribution,
        "interpreter_constraints": list(validated.interpreter_constraints),
    }
    qvl_executable = destination / QVL_RELEASE_PATH
    qvl_executable.write_bytes(reviewed_qvl.raw)
    qvl_executable.chmod(0o755)
    snpguest_executable = destination / SNPGUEST_RELEASE_PATH
    snpguest_executable.write_bytes(reviewed_snpguest.raw)
    snpguest_executable.chmod(0o755)
    manifest.update(
        {
            "source_revision": reviewed_revision,
            "qvl_path": QVL_RELEASE_PATH,
            "qvl_sha256": reviewed_qvl.sha256,
            "snpguest_path": SNPGUEST_RELEASE_PATH,
            "snpguest_sha256": reviewed_snpguest.sha256,
        }
    )
    (destination / "RELEASE.json").write_bytes(canonical_document_bytes(manifest))
    (destination / "RELEASE.json").chmod(0o644)
    tree_bytes = sum(
        path.stat().st_size for path in destination.rglob("*") if path.is_file()
    )
    if tree_bytes > MAX_TREE_BYTES:
        raise UpdateRefused("validator release exceeds the updater tree limit")
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


def _validate_signed_bundle_tree(
    root: Path, *, expected_version: str
) -> dict[str, Any]:
    """Re-verify every signed runtime file before a retained archive is re-signed."""

    expected_files = {
        "RELEASE.json",
        VALIDATOR_RELEASE_ENTRYPOINT,
        QVL_RELEASE_PATH,
        SNPGUEST_RELEASE_PATH,
    }
    actual_files = {
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
    }
    if actual_files != expected_files:
        raise UpdateRefused("retained release has an unexpected runtime file set")
    manifest_path = root / "RELEASE.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise UpdateRefused("retained release has no regular RELEASE.json")
    manifest = _strict_json_object(
        manifest_path.read_bytes(), label="retained RELEASE.json"
    )
    expected_fields = {
        "schema",
        "entry_point",
        "telemetry_module",
        "pex_sha256",
        "pex_info_sha256",
        "project_distribution",
        "interpreter_constraints",
        "source_revision",
        "qvl_path",
        "qvl_sha256",
        "snpguest_path",
        "snpguest_sha256",
    }
    if (
        set(manifest) != expected_fields
        or manifest.get("schema") != VALIDATOR_BUNDLE_SCHEMA
    ):
        raise UpdateRefused("retained release does not use the supported bundle schema")
    if manifest.get("entry_point") != VALIDATOR_PEX_ENTRY_POINT:
        raise UpdateRefused("retained release has the wrong validator entry point")
    if manifest.get("telemetry_module") != TELEMETRY_PEX_MODULE:
        raise UpdateRefused("retained release has the wrong telemetry module")
    _source_revision(manifest.get("source_revision"))
    if manifest.get("qvl_path") != QVL_RELEASE_PATH:
        raise UpdateRefused("retained release has the wrong QVL path")
    if manifest.get("snpguest_path") != SNPGUEST_RELEASE_PATH:
        raise UpdateRefused("retained release has the wrong snpguest path")
    if (
        not isinstance(manifest.get("project_distribution"), str)
        or not manifest["project_distribution"]
        or manifest.get("interpreter_constraints") != [_RELEASE_INTERPRETER_CONSTRAINT]
    ):
        raise UpdateRefused("retained release has invalid PEX identity")

    validator = _validator_pex(root / VALIDATOR_RELEASE_ENTRYPOINT)
    if (
        validator.version != expected_version
        or manifest.get("pex_sha256") != hashlib.sha256(validator.raw).hexdigest()
        or manifest.get("pex_info_sha256") != validator.info_sha256
        or manifest.get("project_distribution") != validator.project_distribution
        or manifest.get("interpreter_constraints")
        != list(validator.interpreter_constraints)
    ):
        raise UpdateRefused("retained validator identity does not match RELEASE.json")
    for relative, digest_field, label in (
        (QVL_RELEASE_PATH, "qvl_sha256", "retained QVL"),
        (SNPGUEST_RELEASE_PATH, "snpguest_sha256", "retained snpguest"),
    ):
        executable = _validated_executable(root / relative, label=label)
        expected_digest = _lower_sha256(
            manifest.get(digest_field), label=f"{label} digest"
        )
        if executable.sha256 != expected_digest:
            raise UpdateRefused(f"{label} does not match RELEASE.json")
    return manifest


def _validated_retained_archive(
    archive_path: Path,
    *,
    archive_sha256: str,
    tree_sha256: str,
    entrypoint: str,
    version: str,
) -> bytes:
    if entrypoint != VALIDATOR_RELEASE_ENTRYPOINT:
        raise UpdateRefused("retained release entrypoint is not supported")
    expected_archive = _lower_sha256(archive_sha256, label="archive digest")
    expected_tree = _lower_sha256(tree_sha256, label="release tree digest")
    archive = _owner_controlled_file(
        archive_path,
        label="retained release archive",
        maximum_bytes=MAX_ARCHIVE_BYTES,
        executable=False,
    )
    if hashlib.sha256(archive).hexdigest() != expected_archive:
        raise UpdateRefused("retained archive does not match signed metadata")
    with tempfile.TemporaryDirectory(prefix="cathedral-retained-release-") as work:
        tree = Path(work) / "release"
        extract_release_archive(archive, tree)
        if release_tree_sha256(tree) != expected_tree:
            raise UpdateRefused("retained tree does not match signed metadata")
        _validate_signed_bundle_tree(tree, expected_version=version)
    return archive


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


def _release_sequence(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 2**63 - 1
    ):
        raise UpdateRefused("release sequence is invalid")
    return value


def _load_retained_metadata(
    path: Path,
    *,
    private_key: Ed25519PrivateKey,
    required_channel: str | None = None,
) -> tuple[Any, dict[str, Any]]:
    raw = _owner_controlled_file(
        path,
        label="retained release metadata",
        maximum_bytes=MAX_METADATA_BYTES,
        executable=False,
    )
    envelope = _strict_json_object(raw, label="retained release metadata")
    signed = envelope.get("signed")
    if not isinstance(signed, dict):
        raise UpdateRefused("retained release metadata has no signed object")
    channel = signed.get("channel")
    if channel not in {"canary", "stable"}:
        raise UpdateRefused("retained release metadata has an unsupported channel")
    if required_channel is not None and channel != required_channel:
        raise UpdateRefused(
            f"retained release metadata must use the {required_channel} channel"
        )
    issued = signed.get("issued_unix")
    if isinstance(issued, bool) or not isinstance(issued, int):
        raise UpdateRefused("retained release metadata issue time is invalid")
    release = parse_release_metadata(
        raw,
        channel=channel,
        public_key=private_key.public_key(),
        now_unix=issued,
    )
    release_object = signed.get("release")
    if not isinstance(release_object, dict):
        raise UpdateRefused("retained release metadata has no release object")
    exact_release = {
        field: release_object[field]
        for field in (
            "version",
            "archive_url",
            "archive_sha256",
            "tree_sha256",
            "entrypoint",
        )
    }
    return release, exact_release


def build_canary(
    *,
    pex: Path,
    qvl: Path,
    snpguest: Path,
    source_revision: str,
    archive_out: Path,
    metadata_out: Path,
    archive_url_template: str,
    sequence: int,
    private_key: Ed25519PrivateKey,
    issued_unix: int | None,
    lifetime_seconds: int,
) -> bytes:
    _release_sequence(sequence)
    with tempfile.TemporaryDirectory(prefix="cathedral-validator-release-") as work:
        source = Path(work) / "release"
        validated = validator_release_tree(
            pex,
            source,
            qvl=qvl,
            snpguest=snpguest,
            source_revision=source_revision,
        )
        archive = deterministic_archive(source)
        if len(archive) > MAX_ARCHIVE_BYTES:
            raise UpdateRefused("validator release exceeds the updater archive limit")
        tree_sha256 = release_tree_sha256(source)

    issued, expires = _validity(
        issued_unix=issued_unix, lifetime_seconds=lifetime_seconds
    )
    archive_sha256 = hashlib.sha256(archive).hexdigest()
    resolved_archive_url = _archive_url_from_template(
        archive_url_template, archive_sha256
    )
    release = {
        "version": validated.version,
        "archive_url": resolved_archive_url,
        "archive_sha256": archive_sha256,
        "tree_sha256": tree_sha256,
        "entrypoint": VALIDATOR_RELEASE_ENTRYPOINT,
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


def resign_canary(
    *,
    current_canary_metadata: Path,
    retained_metadata: Path,
    retained_archive: Path,
    metadata_out: Path,
    sequence: int,
    private_key: Ed25519PrivateKey,
    issued_unix: int | None,
    lifetime_seconds: int,
) -> bytes:
    """Issue a higher canary sequence for one exact retained signed release."""

    next_sequence = _release_sequence(sequence)
    current, _current_release = _load_retained_metadata(
        current_canary_metadata,
        private_key=private_key,
        required_channel="canary",
    )
    if next_sequence <= current.sequence:
        raise UpdateRefused(
            "re-signed canary sequence must exceed the current canary sequence"
        )
    retained, exact_release = _load_retained_metadata(
        retained_metadata,
        private_key=private_key,
    )
    if retained.channel == "canary" and next_sequence <= retained.sequence:
        raise UpdateRefused(
            "re-signed canary sequence must exceed the retained canary sequence"
        )
    _canonical_archive_url(retained.archive_url, retained.archive_sha256)
    _validated_retained_archive(
        retained_archive,
        archive_sha256=retained.archive_sha256,
        tree_sha256=retained.tree_sha256,
        entrypoint=retained.entrypoint,
        version=retained.version,
    )
    issued, expires = _validity(
        issued_unix=issued_unix, lifetime_seconds=lifetime_seconds
    )
    signed = {
        "schema": METADATA_SCHEMA,
        "channel": "canary",
        "sequence": next_sequence,
        "issued_unix": issued,
        "expires_unix": expires,
        "release": exact_release,
    }
    metadata = _signed_envelope(signed, private_key)
    parsed = parse_release_metadata(
        metadata,
        channel="canary",
        public_key=private_key.public_key(),
        now_unix=issued,
    )
    if (
        parsed.archive_url != retained.archive_url
        or parsed.archive_sha256 != retained.archive_sha256
        or parsed.tree_sha256 != retained.tree_sha256
        or parsed.entrypoint != retained.entrypoint
    ):
        raise UpdateRefused("re-signed canary changed the retained release")
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
    enforce_content_addressed: bool = False,
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
    if enforce_content_addressed:
        _canonical_archive_url(canary.archive_url, canary.archive_sha256)
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
    canary.add_argument("--qvl", required=True, type=Path)
    canary.add_argument("--snpguest", required=True, type=Path)
    canary.add_argument("--source-revision", required=True)
    canary.add_argument("--archive-out", required=True, type=Path)
    canary.add_argument("--metadata-out", required=True, type=Path)
    canary.add_argument("--archive-url-template", required=True)
    canary.add_argument("--sequence", required=True, type=int)
    canary.add_argument("--issued-unix", type=int)
    canary.add_argument("--lifetime-seconds", type=int, default=7 * 24 * 60 * 60)
    resign = subparsers.add_parser("resign-canary")
    resign.add_argument("--current-canary-metadata", required=True, type=Path)
    resign.add_argument("--retained-metadata", required=True, type=Path)
    resign.add_argument("--retained-archive", required=True, type=Path)
    resign.add_argument("--metadata-out", required=True, type=Path)
    resign.add_argument("--sequence", required=True, type=int)
    resign.add_argument("--issued-unix", type=int)
    resign.add_argument("--lifetime-seconds", type=int, default=7 * 24 * 60 * 60)
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
                qvl=options.qvl,
                snpguest=options.snpguest,
                source_revision=options.source_revision,
                archive_out=options.archive_out,
                metadata_out=options.metadata_out,
                archive_url_template=options.archive_url_template,
                sequence=options.sequence,
                private_key=key,
                issued_unix=options.issued_unix,
                lifetime_seconds=options.lifetime_seconds,
            )
        elif options.command == "resign-canary":
            resign_canary(
                current_canary_metadata=options.current_canary_metadata,
                retained_metadata=options.retained_metadata,
                retained_archive=options.retained_archive,
                metadata_out=options.metadata_out,
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
                enforce_content_addressed=True,
            )
    except (OSError, UpdateRefused, ValueError) as exc:
        raise SystemExit(f"release build refused: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
