"""Local, signed, fail-closed release updater for Cathedral validators.

The updater runs on the validator's own machine as root.  It has no wallet
arguments, never reads a wallet, and never makes a chain request.  A release is
accepted only when a locally pinned Ed25519 key signs bounded HTTPS metadata,
the exact archive and extracted tree match that metadata, and the direct-writer
journal is known to be idle while the validator's full-cycle lock is held.  It
installs beside the current release and flips one local symlink atomically.

Downloaded code is never executed by this root process.  The fixed systemd
service starts it as the local unprivileged validator account after activation.
The service must report readiness before the updater releases the cycle lock.
If that first readiness attempt fails synchronously, the updater restores the
prior release before any chain cycle can begin.  Crash recovery never guesses
that a target which might already have run is safe to roll back.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .preview_io import canonical_document_bytes


METADATA_SCHEMA = "cathedral_validator_release_v1"
UPDATER_STATE_SCHEMA = "cathedral_validator_updater_state_v2"
VALIDATOR_SERVICE = "cathedral-validator-direct.service"
SYSTEMCTL = "/usr/bin/systemctl"
DEFAULT_CYCLE_WAIT_SECONDS = 300.0
MAX_METADATA_LIFETIME_SECONDS = 14 * 24 * 60 * 60
MAX_METADATA_BYTES = 131_072
MAX_ARCHIVE_BYTES = 536_870_912
MAX_TREE_FILES = 20_000
MAX_TREE_BYTES = 1_073_741_824
_HEX = frozenset("0123456789abcdef")


class UpdateRefused(RuntimeError):
    """The local updater intentionally refused to make a release current."""


@dataclass(frozen=True)
class Release:
    channel: str
    sequence: int
    issued_unix: int
    expires_unix: int
    version: str
    archive_url: str
    archive_sha256: str
    tree_sha256: str
    entrypoint: str
    signed_sha256: str
    metadata_sha256: str
    promoted_canary_sequence: int | None = None
    promoted_canary_signed_sha256: str | None = None
    promoted_canary_metadata_sha256: str | None = None


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise UpdateRefused(f"{label} repeats key {key!r}")
            output[key] = value
        return output

    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateRefused(f"{label} is not strict JSON") from exc
    if not isinstance(decoded, dict):
        raise UpdateRefused(f"{label} is not an object")
    return decoded


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hex_digest(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(item not in _HEX for item in value)
    ):
        raise UpdateRefused(f"{label} is not a lower-case SHA-256 digest")
    return value


def _https_url(value: object, *, label: str) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise UpdateRefused(f"{label} is invalid")
    parsed = urllib.parse.urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
    ):
        raise UpdateRefused(f"{label} must be an HTTPS URL without credentials")
    return value


def _entrypoint(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise UpdateRefused("release entrypoint is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path == PurePosixPath("."):
        raise UpdateRefused("release entrypoint escapes its release")
    return str(path)


def load_pinned_public_key(path: Path, *, expected_uid: int = 0) -> Ed25519PublicKey:
    """Load one root-owned PEM public key, never a network-provided key."""

    if not path.is_absolute() or path.is_symlink():
        raise UpdateRefused("update public key path must be an absolute regular file")
    try:
        metadata = path.stat()
        raw = path.read_bytes()
    except OSError as exc:
        raise UpdateRefused("update public key is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or len(raw) > 16_384
    ):
        raise UpdateRefused("update public key is not root-controlled")
    try:
        key = serialization.load_pem_public_key(raw)
    except ValueError as exc:
        raise UpdateRefused("update public key is not PEM") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise UpdateRefused("update public key is not Ed25519")
    return key


def parse_release_metadata(
    raw: bytes,
    *,
    channel: str,
    public_key: Ed25519PublicKey,
    now_unix: int | None = None,
) -> Release:
    """Verify one exact signed channel document and return its immutable release."""

    if len(raw) > MAX_METADATA_BYTES:
        raise UpdateRefused("release metadata exceeds its size limit")
    envelope = _strict_json(raw, label="release metadata")
    if set(envelope) != {"signed", "signature"}:
        raise UpdateRefused("release metadata fields are invalid")
    signed = envelope["signed"]
    signature = envelope["signature"]
    if not isinstance(signed, dict) or not isinstance(signature, str):
        raise UpdateRefused("release metadata shape is invalid")
    try:
        signature_bytes = base64.b64decode(signature.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise UpdateRefused("release metadata signature is not base64") from exc
    payload = canonical_document_bytes(signed)
    try:
        public_key.verify(signature_bytes, payload)
    except InvalidSignature as exc:
        raise UpdateRefused("release metadata signature is invalid") from exc
    if set(signed) != {
        "schema",
        "channel",
        "sequence",
        "issued_unix",
        "expires_unix",
        "release",
    }:
        raise UpdateRefused("signed release metadata fields are invalid")
    if signed["schema"] != METADATA_SCHEMA or signed["channel"] != channel:
        raise UpdateRefused("release metadata is for a different channel")
    sequence = signed["sequence"]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 1 <= sequence <= 2**63 - 1
    ):
        raise UpdateRefused("release sequence is invalid")
    issued_unix = signed["issued_unix"]
    expires_unix = signed["expires_unix"]
    if (
        isinstance(issued_unix, bool)
        or not isinstance(issued_unix, int)
        or issued_unix < 1
        or isinstance(expires_unix, bool)
        or not isinstance(expires_unix, int)
        or expires_unix <= issued_unix
        or expires_unix - issued_unix > MAX_METADATA_LIFETIME_SECONDS
    ):
        raise UpdateRefused("release metadata validity window is invalid")
    observed_now = int(time.time()) if now_unix is None else now_unix
    if observed_now < issued_unix - 300:
        raise UpdateRefused("release metadata is not valid yet")
    if observed_now >= expires_unix:
        raise UpdateRefused("release metadata has expired")
    release = signed["release"]
    if not isinstance(release, dict):
        raise UpdateRefused("release metadata has no release object")
    expected = {
        "version",
        "archive_url",
        "archive_sha256",
        "tree_sha256",
        "entrypoint",
    }
    if channel == "stable":
        expected.add("promoted_canary")
    if set(release) != expected:
        raise UpdateRefused("release fields are invalid")
    version = release["version"]
    if (
        not isinstance(version, str)
        or not version
        or len(version) > 128
        or not version.isascii()
    ):
        raise UpdateRefused("release version is invalid")
    archive_sha256 = _hex_digest(release["archive_sha256"], label="archive digest")
    promoted_sequence: int | None = None
    promoted_signed: str | None = None
    promoted_metadata: str | None = None
    if channel == "stable":
        promoted = release["promoted_canary"]
        if not isinstance(promoted, dict) or set(promoted) != {
            "sequence",
            "signed_sha256",
            "metadata_sha256",
            "archive_sha256",
        }:
            raise UpdateRefused("stable release has no exact signed canary record")
        promoted_sequence = promoted["sequence"]
        if (
            isinstance(promoted_sequence, bool)
            or not isinstance(promoted_sequence, int)
            or not 1 <= promoted_sequence <= 2**63 - 1
        ):
            raise UpdateRefused("promoted canary sequence is invalid")
        promoted_signed = _hex_digest(
            promoted["signed_sha256"], label="promoted canary signed digest"
        )
        promoted_metadata = _hex_digest(
            promoted["metadata_sha256"], label="promoted canary metadata digest"
        )
        if promoted.get("archive_sha256") != archive_sha256:
            raise UpdateRefused(
                "stable release is not the exact promoted canary archive"
            )
    return Release(
        channel=channel,
        sequence=sequence,
        issued_unix=issued_unix,
        expires_unix=expires_unix,
        version=version,
        archive_url=_https_url(release["archive_url"], label="archive URL"),
        archive_sha256=archive_sha256,
        tree_sha256=_hex_digest(release["tree_sha256"], label="tree digest"),
        entrypoint=_entrypoint(release["entrypoint"]),
        signed_sha256=_sha256(payload),
        metadata_sha256=_sha256(raw),
        promoted_canary_sequence=promoted_sequence,
        promoted_canary_signed_sha256=promoted_signed,
        promoted_canary_metadata_sha256=promoted_metadata,
    )


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        _https_url(newurl, label="redirect URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_bounded_https(
    url: str, *, maximum_bytes: int, timeout_seconds: float = 20.0
) -> bytes:
    """Fetch bounded bytes without credentials or a downgrade redirect."""

    _https_url(url, label="download URL")
    opener = urllib.request.build_opener(_HttpsOnlyRedirects())
    request = urllib.request.Request(
        url, headers={"Accept": "application/json,application/octet-stream"}
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            final_url = str(response.geturl())
            _https_url(final_url, label="download response URL")
            stated = response.headers.get("Content-Length")
            if stated is not None and (
                not stated.isdecimal() or int(stated) > maximum_bytes
            ):
                raise UpdateRefused("download exceeds its size limit")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(min(65_536, maximum_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum_bytes:
                    raise UpdateRefused("download exceeds its size limit")
                chunks.append(chunk)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateRefused("HTTPS download failed") from exc
    return b"".join(chunks)


def _safe_member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or ".." in path.parts
        or path == PurePosixPath(".")
    ):
        raise UpdateRefused("release archive has an unsafe member path")
    return path


def extract_release_archive(archive: bytes, destination: Path) -> None:
    """Extract a bounded regular-file-only release archive into an empty directory."""

    if destination.exists() or destination.is_symlink():
        raise UpdateRefused("release extraction destination already exists")
    destination.mkdir(mode=0o755, parents=True)
    total = 0
    count = 0
    try:
        import io

        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as bundle:
            for member in bundle:
                path = _safe_member_path(member.name)
                if member.isdir():
                    (destination / path).mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue
                if not member.isfile() or member.size < 0:
                    raise UpdateRefused("release archive contains a non-regular member")
                count += 1
                total += member.size
                if count > MAX_TREE_FILES or total > MAX_TREE_BYTES:
                    raise UpdateRefused("release archive exceeds extraction limits")
                target = destination / path
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise UpdateRefused("release archive member is unreadable")
                with target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=65_536)
                os.chmod(target, 0o555 if member.mode & 0o111 else 0o444)
    except (tarfile.TarError, OSError) as exc:
        raise UpdateRefused("release archive extraction failed") from exc


def release_tree_sha256(root: Path) -> str:
    """Hash release paths and bytes, with no metadata, links, or special files."""

    if root.is_symlink() or not root.is_dir():
        raise UpdateRefused("release tree is invalid")
    entries: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise UpdateRefused("release tree contains a symlink")
        if path.is_file():
            entries.append(path)
        elif not path.is_dir():
            raise UpdateRefused("release tree contains an unsupported file")
    digest = hashlib.sha256()
    for path in sorted(entries, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(path.stat().st_size.to_bytes(8, "big"))
        with path.open("rb") as handle:
            while chunk := handle.read(65_536):
                digest.update(chunk)
    return digest.hexdigest()


def _require_owned_release_tree(root: Path, *, expected_uid: int) -> None:
    for path in (root, *root.rglob("*")):
        metadata = path.stat()
        if (
            metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or path.is_symlink()
        ):
            raise UpdateRefused("release tree is not root-controlled")


def require_idle_direct_writer_journal(path: Path) -> None:
    """Refuse any update unless the exact direct writer journal is proved idle."""

    if not path.is_absolute() or path.is_symlink():
        raise UpdateRefused("direct writer journal path is invalid")
    try:
        metadata = path.stat()
        raw = path.read_bytes()
    except OSError as exc:
        raise UpdateRefused("direct writer journal is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 1_048_576
    ):
        raise UpdateRefused("direct writer journal is invalid")
    state = _strict_json(raw, label="direct writer journal")
    if (
        set(state) != {"schema", "pending", "last_attempt"}
        or state.get("schema") != "cathedral_direct_validator_state_v1"
    ):
        raise UpdateRefused("direct writer journal contradicts the supported schema")
    if state["pending"] is not None:
        raise UpdateRefused(
            "direct writer journal has an unresolved or ambiguous submission"
        )
    if state["last_attempt"] is not None and not isinstance(
        state["last_attempt"], dict
    ):
        raise UpdateRefused("direct writer journal contradicts the supported schema")


def _state_path(root: Path) -> Path:
    return root / "state.json"


def _initial_update_state() -> dict[str, Any]:
    return {"schema": UPDATER_STATE_SCHEMA, "channels": {}, "pending": None}


def _validate_channel_record(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "sequence",
        "archive_sha256",
        "signed_sha256",
        "metadata_sha256",
    }:
        raise UpdateRefused(f"{label} is invalid")
    sequence = value["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise UpdateRefused(f"{label} sequence is invalid")
    return {
        "sequence": sequence,
        "archive_sha256": _hex_digest(
            value["archive_sha256"], label=f"{label} archive digest"
        ),
        "signed_sha256": _hex_digest(
            value["signed_sha256"], label=f"{label} signed digest"
        ),
        "metadata_sha256": _hex_digest(
            value["metadata_sha256"], label=f"{label} metadata digest"
        ),
    }


def _validate_pending(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "channel",
        "record",
        "previous_current",
        "target_current",
    }:
        raise UpdateRefused("pending activation record is invalid")
    if value["channel"] not in {"canary", "stable"}:
        raise UpdateRefused("pending activation channel is invalid")
    previous = value["previous_current"]
    if previous is not None and not isinstance(previous, str):
        raise UpdateRefused("pending previous release is invalid")
    target = value["target_current"]
    if not isinstance(target, str):
        raise UpdateRefused("pending target release is invalid")
    for label, stored in (("previous", previous), ("target", target)):
        if stored is None:
            continue
        parts = PurePosixPath(stored).parts
        if (
            len(parts) != 2
            or parts[0] != "releases"
            or parts[1]
            != _hex_digest(parts[1], label=f"pending {label} release digest")
        ):
            raise UpdateRefused(f"pending {label} release is not canonical")
    return {
        "channel": value["channel"],
        "record": _validate_channel_record(
            value["record"], label="pending activation record"
        ),
        "previous_current": previous,
        "target_current": target,
    }


def _read_update_state(root: Path) -> dict[str, Any]:
    path = _state_path(root)
    if not path.exists():
        return _initial_update_state()
    if path.is_symlink():
        raise UpdateRefused("updater state is a symlink")
    raw = path.read_bytes()
    document = _strict_json(raw, label="updater state")
    if (
        set(document) != {"schema", "channels", "pending"}
        or document["schema"] != UPDATER_STATE_SCHEMA
        or not isinstance(document["channels"], dict)
    ):
        raise UpdateRefused("updater state is invalid")
    channels: dict[str, Any] = {}
    for channel, record in document["channels"].items():
        if channel not in {"canary", "stable"}:
            raise UpdateRefused("updater state contains an unknown channel")
        channels[channel] = _validate_channel_record(
            record, label=f"updater {channel} record"
        )
    return {
        "schema": UPDATER_STATE_SCHEMA,
        "channels": channels,
        "pending": _validate_pending(document["pending"]),
    }


def _write_update_state(root: Path, state: Mapping[str, Any]) -> None:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if set(state) != {"schema", "channels", "pending"}:
        raise UpdateRefused("updater state fields are invalid")
    body = canonical_document_bytes(state)
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            dir=root, prefix=".state.", suffix=".tmp"
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, _state_path(root))
        temporary = None
        directory = os.open(root, os.O_RDONLY)
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


def enforce_monotonic_release(state: Mapping[str, Any], release: Release) -> None:
    existing = state["channels"].get(release.channel)
    if existing is None:
        return
    existing = _validate_channel_record(
        existing, label=f"updater {release.channel} record"
    )
    sequence = existing["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise UpdateRefused("updater state contains an invalid release sequence")
    if release.sequence < sequence:
        raise UpdateRefused("release metadata rolls back the local channel")
    if release.sequence == sequence and (
        existing["archive_sha256"] != release.archive_sha256
        or existing["signed_sha256"] != release.signed_sha256
        or existing["metadata_sha256"] != release.metadata_sha256
    ):
        raise UpdateRefused("release metadata equivocates at an existing sequence")


def _root_owned_directory(path: Path, *, expected_uid: int) -> None:
    path.mkdir(mode=0o755, parents=True, exist_ok=True)
    metadata = path.stat()
    if (
        path.is_symlink()
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise UpdateRefused("update installation directory is not root-controlled")


def _release_target(archive_sha256: str) -> str:
    return str(Path("releases") / _hex_digest(archive_sha256, label="release digest"))


def _current_target(install_root: Path) -> str | None:
    current = install_root / "current"
    if not current.exists() and not current.is_symlink():
        return None
    if not current.is_symlink():
        raise UpdateRefused("current release path is not a symlink")
    try:
        target = os.readlink(current)
    except OSError as exc:
        raise UpdateRefused("current release target is unreadable") from exc
    parts = PurePosixPath(target).parts
    if (
        len(parts) != 2
        or parts[0] != "releases"
        or parts[1] != _hex_digest(parts[1], label="current release digest")
    ):
        raise UpdateRefused("current release target is not canonical")
    return target


def _atomic_current_symlink(install_root: Path, target: str) -> None:
    current = install_root / "current"
    _current_target(install_root)
    temporary = install_root / f".current.{os.getpid()}"
    if temporary.exists() or temporary.is_symlink():
        raise UpdateRefused("temporary current release path already exists")
    try:
        os.symlink(target, temporary)
        os.replace(temporary, current)
        directory = os.open(install_root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def _remove_current_symlink(install_root: Path, *, expected_target: str) -> None:
    if _current_target(install_root) != expected_target:
        raise UpdateRefused("current release changed before bootstrap cleanup")
    try:
        (install_root / "current").unlink()
        directory = os.open(install_root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise UpdateRefused(
            "failed bootstrap release could not be deactivated"
        ) from exc


class SignedReleaseUpdater:
    """Performs one lock-held update attempt on the local machine."""

    def __init__(
        self,
        *,
        install_root: Path,
        state_root: Path,
        journal: Path,
        expected_uid: int = 0,
        fetcher: Callable[[str, int], bytes] | None = None,
        service_restarter: Callable[[Sequence[str]], None] | None = None,
    ) -> None:
        self.install_root = install_root
        self.state_root = state_root
        self.journal = journal
        self.expected_uid = expected_uid
        self.fetcher = fetcher or (
            lambda url, maximum: fetch_bounded_https(url, maximum_bytes=maximum)
        )
        self.service_restarter = service_restarter or self._control_validator_service

    @staticmethod
    def _control_validator_service(command: Sequence[str]) -> None:
        if tuple(command) not in {
            (SYSTEMCTL, "restart", VALIDATOR_SERVICE),
            (SYSTEMCTL, "stop", VALIDATOR_SERVICE),
        }:
            raise UpdateRefused("validator service command is not fixed")
        subprocess.run(
            list(command),
            check=True,
            stdin=subprocess.DEVNULL,
            timeout=180,
        )

    def _restart_service(self) -> None:
        try:
            self.service_restarter((SYSTEMCTL, "restart", VALIDATOR_SERVICE))
        except UpdateRefused:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            raise UpdateRefused("fixed validator service restart failed") from exc

    def _stop_service(self) -> None:
        try:
            self.service_restarter((SYSTEMCTL, "stop", VALIDATOR_SERVICE))
        except UpdateRefused:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            raise UpdateRefused("fixed validator service stop failed") from exc

    def _prepare_bootstrap_journal(
        self, *, validator_uid: int, validator_gid: int
    ) -> None:
        """Create the first idle journal and shared lock for the service owner."""

        if (
            isinstance(validator_uid, bool)
            or not isinstance(validator_uid, int)
            or validator_uid < 0
            or isinstance(validator_gid, bool)
            or not isinstance(validator_gid, int)
            or validator_gid < 0
            or not self.journal.is_absolute()
            or self.journal.name != "state.json"
        ):
            raise UpdateRefused("bootstrap validator identity or journal is invalid")
        parent = self.journal.parent
        if parent.is_symlink():
            raise UpdateRefused("bootstrap journal parent is a symlink")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = parent.stat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise UpdateRefused("bootstrap journal parent is not a directory")
        if metadata.st_uid != validator_uid or metadata.st_gid != validator_gid:
            try:
                os.chown(parent, validator_uid, validator_gid)
            except OSError as exc:
                raise UpdateRefused("bootstrap journal owner could not be set") from exc
        os.chmod(parent, 0o700)
        allowed = {"state.json", "cycle.lock", "process.lock", "state.lock"}
        if any(path.name not in allowed for path in parent.iterdir()):
            raise UpdateRefused("bootstrap journal directory is not clean")

        initial = canonical_document_bytes(
            {
                "schema": "cathedral_direct_validator_state_v1",
                "pending": None,
                "last_attempt": None,
            }
        )
        if self.journal.exists() or self.journal.is_symlink():
            if self.journal.is_symlink():
                raise UpdateRefused("bootstrap journal is a symlink")
            require_idle_direct_writer_journal(self.journal)
        else:
            descriptor = os.open(
                self.journal,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            try:
                remaining = memoryview(initial)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise UpdateRefused("bootstrap journal write made no progress")
                    remaining = remaining[written:]
                os.fsync(descriptor)
                os.fchown(descriptor, validator_uid, validator_gid)
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)

        cycle_lock = self.journal.with_name("cycle.lock")
        if cycle_lock.exists() or cycle_lock.is_symlink():
            if cycle_lock.is_symlink():
                raise UpdateRefused("bootstrap cycle lock is a symlink")
        else:
            descriptor = os.open(
                cycle_lock,
                os.O_CREAT | os.O_EXCL | os.O_RDWR,
                0o600,
            )
            try:
                os.fsync(descriptor)
                os.fchown(descriptor, validator_uid, validator_gid)
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        for path in (self.journal, cycle_lock):
            metadata = path.stat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != validator_uid
                or metadata.st_gid != validator_gid
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise UpdateRefused("bootstrap journal or cycle lock is not owner-only")
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @contextmanager
    def _cycle_locked(self, *, wait_seconds: float) -> Iterator[None]:
        if (
            isinstance(wait_seconds, bool)
            or not isinstance(wait_seconds, (int, float))
            or not 0 <= float(wait_seconds) <= 3600
        ):
            raise UpdateRefused("cycle lock wait is invalid")
        if not self.journal.is_absolute() or self.journal.name != "state.json":
            raise UpdateRefused("direct writer journal path is invalid")
        cycle_lock = self.journal.with_name("cycle.lock")
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(cycle_lock, flags)
            lock_metadata = os.fstat(descriptor)
            journal_metadata = self.journal.stat()
        except OSError as exc:
            raise UpdateRefused(
                "direct validator cycle lock is unavailable; start the direct service once"
            ) from exc
        try:
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or stat.S_IMODE(lock_metadata.st_mode) != 0o600
                or lock_metadata.st_uid != journal_metadata.st_uid
            ):
                raise UpdateRefused("direct validator cycle lock is invalid")
            deadline = time.monotonic() + float(wait_seconds)
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise UpdateRefused(
                            "direct validator did not finish its cycle before timeout"
                        ) from exc
                    time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    @staticmethod
    def _record(release: Release) -> dict[str, Any]:
        return {
            "sequence": release.sequence,
            "archive_sha256": release.archive_sha256,
            "signed_sha256": release.signed_sha256,
            "metadata_sha256": release.metadata_sha256,
        }

    def _commit_pending(self, state: Mapping[str, Any]) -> dict[str, Any]:
        pending = _validate_pending(state.get("pending"))
        if pending is None:
            raise UpdateRefused("updater has no pending activation to commit")
        channels = dict(state["channels"])
        channels[pending["channel"]] = pending["record"]
        committed = {
            "schema": UPDATER_STATE_SCHEMA,
            "channels": channels,
            "pending": None,
        }
        _write_update_state(self.state_root, committed)
        return committed

    def _clear_pending(self, state: Mapping[str, Any]) -> dict[str, Any]:
        cleared = {
            "schema": UPDATER_STATE_SCHEMA,
            "channels": dict(state["channels"]),
            "pending": None,
        }
        _write_update_state(self.state_root, cleared)
        return cleared

    def _restart_pending_or_rollback(
        self,
        state: Mapping[str, Any],
        *,
        allow_first_install: bool,
        rollback_on_failure: bool,
    ) -> dict[str, Any]:
        """Require readiness or restore the prior release before writes resume."""

        pending = _validate_pending(state.get("pending"))
        if pending is None:
            raise UpdateRefused("updater has no pending activation to start")
        previous = pending["previous_current"]
        if previous is None:
            if not allow_first_install:
                raise UpdateRefused(
                    "unfinished first installation requires the bootstrap command"
                )
            try:
                self._restart_service()
            except UpdateRefused as startup_error:
                if not rollback_on_failure:
                    raise UpdateRefused(
                        "first release readiness is unconfirmed after recovery; "
                        "pending activation remains"
                    ) from startup_error
                stop_error: UpdateRefused | None = None
                try:
                    self._stop_service()
                except UpdateRefused as exc:
                    stop_error = exc
                _remove_current_symlink(
                    self.install_root, expected_target=pending["target_current"]
                )
                self._clear_pending(state)
                if stop_error is not None:
                    raise UpdateRefused(
                        "first release failed readiness and the failed service "
                        "could not be stopped"
                    ) from stop_error
                raise UpdateRefused(
                    "first release failed readiness and was deactivated"
                ) from startup_error
            return self._commit_pending(state)
        try:
            self._restart_service()
        except UpdateRefused as startup_error:
            if not rollback_on_failure:
                raise UpdateRefused(
                    "release readiness is unconfirmed after recovery; "
                    "pending activation remains"
                ) from startup_error
            try:
                _atomic_current_symlink(self.install_root, previous)
                self._restart_service()
            except UpdateRefused as rollback_error:
                raise UpdateRefused(
                    "new release failed readiness and prior release restart failed; "
                    "pending activation remains"
                ) from rollback_error
            self._clear_pending(state)
            raise UpdateRefused(
                "new release failed readiness; prior release was restored"
            ) from startup_error
        return self._commit_pending(state)

    def _reconcile_pending(
        self,
        state: dict[str, Any],
        *,
        cycle_wait_seconds: float,
        allow_first_install: bool,
    ) -> dict[str, Any]:
        pending = _validate_pending(state.get("pending"))
        if pending is None:
            return state
        current = _current_target(self.install_root)
        if current == pending["previous_current"]:
            if current is None:
                if not allow_first_install:
                    raise UpdateRefused(
                        "unfinished first installation requires the bootstrap command"
                    )
                return self._clear_pending(state)
            with self._cycle_locked(wait_seconds=cycle_wait_seconds):
                require_idle_direct_writer_journal(self.journal)
                self._restart_service()
                return self._clear_pending(state)
        if current != pending["target_current"]:
            raise UpdateRefused("pending activation contradicts the current release")
        with self._cycle_locked(wait_seconds=cycle_wait_seconds):
            require_idle_direct_writer_journal(self.journal)
            return self._restart_pending_or_rollback(
                state,
                allow_first_install=allow_first_install,
                rollback_on_failure=False,
            )

    def _install_release(self, release: Release, archive: bytes) -> Path:
        releases = self.install_root / "releases"
        _root_owned_directory(releases, expected_uid=self.expected_uid)
        release_dir = releases / release.archive_sha256
        if len(archive) > MAX_ARCHIVE_BYTES:
            raise UpdateRefused("release archive exceeds its size limit")
        if _sha256(archive) != release.archive_sha256:
            raise UpdateRefused("release archive digest does not match signed metadata")
        if release_dir.exists():
            _require_owned_release_tree(release_dir, expected_uid=self.expected_uid)
            if release_tree_sha256(release_dir) != release.tree_sha256:
                raise UpdateRefused(
                    "existing release directory does not match signed tree"
                )
        else:
            temporary = releases / f".{release.archive_sha256}.staging-{os.getpid()}"
            try:
                extract_release_archive(archive, temporary)
                _require_owned_release_tree(temporary, expected_uid=self.expected_uid)
                if release_tree_sha256(temporary) != release.tree_sha256:
                    raise UpdateRefused(
                        "release tree digest does not match signed metadata"
                    )
                os.replace(temporary, release_dir)
                directory = os.open(releases, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        executable = release_dir / release.entrypoint
        if (
            not executable.is_file()
            or executable.is_symlink()
            or not os.access(executable, os.X_OK)
        ):
            raise UpdateRefused("signed release has no safe executable entrypoint")
        return release_dir

    def bootstrap(
        self,
        *,
        metadata_url: str,
        channel: str,
        public_key: Ed25519PublicKey,
        pause_file: Path,
        minimum_sequence: int,
        validator_uid: int,
        validator_gid: int,
        cycle_wait_seconds: float = DEFAULT_CYCLE_WAIT_SECONDS,
    ) -> str:
        """Install the first release on an otherwise clean validator host."""

        return self._update_release(
            metadata_url=metadata_url,
            channel=channel,
            public_key=public_key,
            pause_file=pause_file,
            minimum_sequence=minimum_sequence,
            cycle_wait_seconds=cycle_wait_seconds,
            bootstrap_owner=(validator_uid, validator_gid),
        )

    def update(
        self,
        *,
        metadata_url: str,
        channel: str,
        public_key: Ed25519PublicKey,
        pause_file: Path,
        minimum_sequence: int,
        cycle_wait_seconds: float = DEFAULT_CYCLE_WAIT_SECONDS,
    ) -> str:
        """Update an already bootstrapped validator release."""

        return self._update_release(
            metadata_url=metadata_url,
            channel=channel,
            public_key=public_key,
            pause_file=pause_file,
            minimum_sequence=minimum_sequence,
            cycle_wait_seconds=cycle_wait_seconds,
            bootstrap_owner=None,
        )

    def _update_release(
        self,
        *,
        metadata_url: str,
        channel: str,
        public_key: Ed25519PublicKey,
        pause_file: Path,
        minimum_sequence: int,
        cycle_wait_seconds: float,
        bootstrap_owner: tuple[int, int] | None,
    ) -> str:
        if channel not in {"canary", "stable"}:
            raise UpdateRefused("release channel is invalid")
        if (
            isinstance(minimum_sequence, bool)
            or not isinstance(minimum_sequence, int)
            or minimum_sequence < 1
        ):
            raise UpdateRefused("trusted minimum release sequence is invalid")
        _root_owned_directory(self.install_root, expected_uid=self.expected_uid)
        _root_owned_directory(self.state_root, expected_uid=self.expected_uid)
        lock_path = self.state_root / "updater.lock"
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lock_path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            lock_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or lock_metadata.st_uid != self.expected_uid
                or stat.S_IMODE(lock_metadata.st_mode) != 0o600
            ):
                raise UpdateRefused("local updater lock is not root-controlled")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise UpdateRefused("another local updater is running") from exc
            state = _read_update_state(self.state_root)
            allow_first_install = bootstrap_owner is not None
            if bootstrap_owner is not None:
                pending = _validate_pending(state.get("pending"))
                if state["channels"]:
                    raise UpdateRefused(
                        "first-install bootstrap requires empty channel state"
                    )
                if pending is not None and pending["previous_current"] is not None:
                    raise UpdateRefused(
                        "first-install bootstrap found a non-bootstrap activation"
                    )
                if pending is None and _current_target(self.install_root) is not None:
                    raise UpdateRefused(
                        "first-install bootstrap requires no current release"
                    )
                self._prepare_bootstrap_journal(
                    validator_uid=bootstrap_owner[0],
                    validator_gid=bootstrap_owner[1],
                )
            state = self._reconcile_pending(
                state,
                cycle_wait_seconds=cycle_wait_seconds,
                allow_first_install=allow_first_install,
            )
            if pause_file.exists():
                return "PAUSED"
            if not allow_first_install and _current_target(self.install_root) is None:
                raise UpdateRefused(
                    "automatic update requires an existing current release; "
                    "run the first-install bootstrap command"
                )
            metadata = self.fetcher(
                _https_url(metadata_url, label="metadata URL"), MAX_METADATA_BYTES
            )
            release = parse_release_metadata(
                metadata, channel=channel, public_key=public_key
            )
            if release.sequence < minimum_sequence:
                raise UpdateRefused("release is below the trusted bootstrap sequence")
            enforce_monotonic_release(state, release)
            target = _release_target(release.archive_sha256)
            existing = state["channels"].get(channel)
            if (
                existing == self._record(release)
                and _current_target(self.install_root) == target
            ):
                release_dir = self.install_root / target
                _require_owned_release_tree(release_dir, expected_uid=self.expected_uid)
                if release_tree_sha256(release_dir) != release.tree_sha256:
                    raise UpdateRefused("current release tree is not the signed tree")
                executable = release_dir / release.entrypoint
                if (
                    not executable.is_file()
                    or executable.is_symlink()
                    or not os.access(executable, os.X_OK)
                ):
                    raise UpdateRefused("current release entrypoint is not executable")
                return "CURRENT"
            archive = self.fetcher(release.archive_url, MAX_ARCHIVE_BYTES)
            self._install_release(release, archive)
            with self._cycle_locked(wait_seconds=cycle_wait_seconds):
                state = _read_update_state(self.state_root)
                if state.get("pending") is not None:
                    raise UpdateRefused("another activation became pending")
                enforce_monotonic_release(state, release)
                require_idle_direct_writer_journal(self.journal)
                previous = _current_target(self.install_root)
                if previous is None and not allow_first_install:
                    raise UpdateRefused(
                        "automatic update requires an existing current release"
                    )
                pending = {
                    "channel": release.channel,
                    "record": self._record(release),
                    "previous_current": previous,
                    "target_current": target,
                }
                pending_state = dict(state)
                pending_state["pending"] = pending
                _write_update_state(self.state_root, pending_state)
                if previous != target:
                    _atomic_current_symlink(self.install_root, target)
                self._restart_pending_or_rollback(
                    pending_state,
                    allow_first_install=allow_first_install,
                    rollback_on_failure=True,
                )
            return "ACTIVATED"
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install one locally verified Cathedral validator release"
    )
    parser.add_argument("--channel", required=True, choices=("canary", "stable"))
    parser.add_argument("--metadata-url", required=True)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--journal", required=True, type=Path)
    parser.add_argument("--minimum-sequence", required=True, type=int)
    parser.add_argument(
        "--bootstrap-first-install",
        action="store_true",
        help="create the first idle journal and activate only on a clean host",
    )
    parser.add_argument(
        "--cycle-wait-seconds",
        type=float,
        default=DEFAULT_CYCLE_WAIT_SECONDS,
    )
    parser.add_argument(
        "--install-root", type=Path, default=Path("/opt/cathedral-validator")
    )
    parser.add_argument(
        "--state-root", type=Path, default=Path("/var/lib/cathedral-validator-update")
    )
    parser.add_argument(
        "--pause-file", type=Path, default=Path("/etc/cathedral-validator/update.pause")
    )
    options = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("the updater must run as root")
    try:
        key = load_pinned_public_key(options.public_key)
        updater = SignedReleaseUpdater(
            install_root=options.install_root,
            state_root=options.state_root,
            journal=options.journal,
        )
        arguments = {
            "metadata_url": options.metadata_url,
            "channel": options.channel,
            "public_key": key,
            "pause_file": options.pause_file,
            "minimum_sequence": options.minimum_sequence,
            "cycle_wait_seconds": options.cycle_wait_seconds,
        }
        if options.bootstrap_first_install:
            try:
                validator = pwd.getpwnam("cathedral-validator")
            except KeyError as exc:
                raise UpdateRefused(
                    "cathedral-validator service account does not exist"
                ) from exc
            status = updater.bootstrap(
                **arguments,
                validator_uid=validator.pw_uid,
                validator_gid=validator.pw_gid,
            )
        else:
            status = updater.update(**arguments)
    except UpdateRefused as exc:
        print(f"CATHEDRAL_VALIDATOR_UPDATE_REFUSED: {exc}", file=sys.stderr)
        return 2
    print(f"CATHEDRAL_VALIDATOR_UPDATE_{status}")
    return 0


__all__ = [
    "MAX_ARCHIVE_BYTES",
    "METADATA_SCHEMA",
    "VALIDATOR_SERVICE",
    "Release",
    "SignedReleaseUpdater",
    "UpdateRefused",
    "enforce_monotonic_release",
    "extract_release_archive",
    "parse_release_metadata",
    "release_tree_sha256",
    "require_idle_direct_writer_journal",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
