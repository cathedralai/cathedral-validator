"""Pinned-digest subprocess QVL for live Compute quotes.

The independent composer will not pay from an unpinned mock. This verifier
hashes the on-disk binary and that digest is the ``qvl_digest`` pin. The child
must print JSON with ``intel_verified`` and ``report_data_match`` both the
boolean ``true``, matching the production TDX verifier contract.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from cathedral_thin.independent.compute import QuoteIdentityVerdict, QuoteVerdict

from .errors import QuoteVerifyError

# SHA-256 of the on-disk verifier *binary blob* published for SN39
# (``EXPECTED_VERIFIER_BINARY`` in ``scripts/build_sn39_release_manifest.py``).
# ``8292b085…`` is the verifier *implementation* pin used by thin relay
# configs; hashing a real QVL file never yields that digest. Pinning the
# implementation hash here would make every real binary unloadable.
LAUNCH_QVL_DIGEST = "35bb55f89f411d5dcf5f72be90488e999ee68c41dfc0429a0dcb8cc2b448b6bb"
# SHA-256 of the Go 1.25.13 linux/amd64 static verifier required by the
# relay-free direct validator.  The older launch digest above remains frozen
# for historical UID30 artifacts whose signed identities already bind it.
DIRECT_VALIDATOR_QVL_DIGEST = (
    "4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148"
)
MAX_OUTPUT = 1_048_576
MAX_BINARY_BYTES = 64 * 1024 * 1024
TIMEOUT_SECONDS = 30


def digest_file(path: Path) -> str:
    """SHA-256 of the verifier binary, lowercase hex."""
    data = path.read_bytes()
    if not data:
        raise QuoteVerifyError(f"QVL binary {path} is empty")
    return hashlib.sha256(data).hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    """Fields which prove the open inode and visible path are still identical."""

    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


class SubprocessQuoteVerifier:
    """Runs ``command quote_path expected_report_data_hex`` and reads JSON."""

    def __init__(self, command: Path) -> None:
        resolved = Path(command).absolute()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            source_fd = os.open(resolved, flags)
        except OSError as exc:
            raise QuoteVerifyError(
                f"QVL binary {resolved} could not be opened"
            ) from exc
        try:
            source_stat = os.fstat(source_fd)
            if not stat.S_ISREG(source_stat.st_mode):
                raise QuoteVerifyError(f"QVL binary {resolved} is not a regular file")
            if source_stat.st_uid not in {0, os.geteuid()}:
                raise QuoteVerifyError(
                    f"QVL binary {resolved} is not owned by root or this user"
                )
            if source_stat.st_mode & 0o022:
                raise QuoteVerifyError(
                    f"QVL binary {resolved} is writable by group or other users"
                )
            if not source_stat.st_mode & 0o111:
                raise QuoteVerifyError(f"QVL binary {resolved} is not executable")
            if source_stat.st_size <= 0 or source_stat.st_size > MAX_BINARY_BYTES:
                raise QuoteVerifyError(
                    f"QVL binary {resolved} is empty or exceeds {MAX_BINARY_BYTES} bytes"
                )

            private_dir = tempfile.TemporaryDirectory(prefix="cathedral-qvl-exec-")
            private_path = Path(private_dir.name) / "verified-qvl"
            destination_fd = os.open(
                private_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o500,
            )
            digest = hashlib.sha256()
            copied = 0
            try:
                while True:
                    chunk = os.read(source_fd, 1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > MAX_BINARY_BYTES:
                        raise QuoteVerifyError(
                            f"QVL binary {resolved} exceeds {MAX_BINARY_BYTES} bytes"
                        )
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(destination_fd, view)
                        if written <= 0:
                            raise OSError("short QVL copy")
                        view = view[written:]
                os.fsync(destination_fd)
                os.fchmod(destination_fd, 0o500)
            finally:
                os.close(destination_fd)
            if copied != source_stat.st_size or _stat_identity(
                os.fstat(source_fd)
            ) != _stat_identity(source_stat):
                raise QuoteVerifyError(f"QVL binary {resolved} changed while loading")
        except Exception:
            os.close(source_fd)
            raise

        self._source_path = resolved
        self._source_fd = source_fd
        self._source_stat = source_stat
        self._private_dir = private_dir
        self.command = private_path
        self.digest = digest.hexdigest()

    def _source_unchanged(self) -> bool:
        """Refuse if the operator-visible QVL path changed after pinning."""

        try:
            current_path = os.stat(self._source_path, follow_symlinks=False)
            current_fd = os.fstat(self._source_fd)
        except OSError:
            return False
        expected = _stat_identity(self._source_stat)
        return (
            _stat_identity(current_path) == expected
            and _stat_identity(current_fd) == expected
        )

    def _claims(
        self,
        quote: bytes,
        *,
        expected_report_data: bytes,
        deadline_monotonic: float | None = None,
    ) -> tuple[QuoteVerdict, dict[str, object] | None]:
        if not quote or not expected_report_data:
            return QuoteVerdict.FAIL, None
        if not self._source_unchanged():
            return QuoteVerdict.INFRA, None
        handle = None
        quote_path = None
        try:
            handle, quote_path = tempfile.mkstemp(
                prefix="cathedral-qvl-", suffix=".quote"
            )
            os.write(handle, quote)
            os.fsync(handle)
            os.close(handle)
            handle = None
            timeout = float(TIMEOUT_SECONDS)
            if deadline_monotonic is not None:
                timeout = min(timeout, deadline_monotonic - time.monotonic())
                if timeout <= 0:
                    return QuoteVerdict.INFRA, None
            completed = subprocess.run(
                [str(self.command), quote_path, expected_report_data.hex()],
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return QuoteVerdict.INFRA, None
        finally:
            if handle is not None:
                os.close(handle)
            if quote_path is not None and os.path.exists(quote_path):
                os.unlink(quote_path)
        if not self._source_unchanged():
            return QuoteVerdict.INFRA, None
        if len(completed.stdout) + len(completed.stderr) > MAX_OUTPUT:
            return QuoteVerdict.INFRA, None
        if completed.returncode != 0:
            return QuoteVerdict.FAIL, None
        try:
            claims = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return QuoteVerdict.INFRA, None
        if not isinstance(claims, dict):
            return QuoteVerdict.INFRA, None
        if claims.get("intel_verified") is not True:
            return QuoteVerdict.FAIL, claims
        if claims.get("report_data_match") is not True:
            return QuoteVerdict.FAIL, claims
        return QuoteVerdict.PASS, claims

    def verify(
        self,
        quote: bytes,
        *,
        expected_report_data: bytes,
        deadline_monotonic: float | None = None,
    ) -> QuoteVerdict:
        """Retain the reviewed single-machine PASS/FAIL/INFRA contract."""

        verdict, _claims = self._claims(
            quote,
            expected_report_data=expected_report_data,
            deadline_monotonic=deadline_monotonic,
        )
        return verdict

    def verify_with_identity(
        self,
        quote: bytes,
        *,
        expected_report_data: bytes,
        deadline_monotonic: float | None = None,
    ) -> QuoteIdentityVerdict:
        """Return PASS plus a strict PCK/PPID-derived stable platform id.

        Missing or malformed stable identity does not rewrite the legacy quote
        verdict.  It leaves ``platform_identity_verified`` false, which keeps
        the multi-machine feature disabled while the single-machine path can
        continue under its existing contract.
        """

        verdict, claims = self._claims(
            quote,
            expected_report_data=expected_report_data,
            deadline_monotonic=deadline_monotonic,
        )
        if verdict is not QuoteVerdict.PASS or claims is None:
            return QuoteIdentityVerdict(verdict, None, False)
        stable = claims.get("stable_platform_id")
        platform = claims.get("platform_id")
        verified = (
            claims.get("platform_identity_kind") == "stable"
            and claims.get("platform_identity_verified") is True
            and claims.get("claims_bound_to_quote") is True
        )
        if not isinstance(stable, str) or platform != stable or not verified:
            return QuoteIdentityVerdict(QuoteVerdict.PASS, None, False)
        prefix = "tdx-platform-sha256:"
        if (
            not stable.startswith(prefix)
            or len(stable) != len(prefix) + 64
            or any(
                character not in "0123456789abcdef"
                for character in stable[len(prefix) :]
            )
        ):
            return QuoteIdentityVerdict(QuoteVerdict.PASS, None, False)
        return QuoteIdentityVerdict(QuoteVerdict.PASS, stable, True)


def _load_pinned_verifier(
    path: str | None, *, expected_digest: str, pin_name: str
) -> SubprocessQuoteVerifier:
    raw = path or os.environ.get("CATHEDRAL_TDX_VERIFY_CMD")
    if not raw:
        raise QuoteVerifyError(
            "no QVL binary: set CATHEDRAL_TDX_VERIFY_CMD to an executable"
        )
    command = Path(raw.split()[0] if " " in raw else raw)
    verifier = SubprocessQuoteVerifier(command)
    if verifier.digest != expected_digest:
        raise QuoteVerifyError(
            f"QVL digest {verifier.digest} is not the {pin_name} pin {expected_digest}"
        )
    return verifier


def load_verifier(path: str | None) -> SubprocessQuoteVerifier:
    """Load the verifier frozen into historical UID30 launch artifacts."""

    return _load_pinned_verifier(
        path, expected_digest=LAUNCH_QVL_DIGEST, pin_name="launch"
    )


def load_direct_validator_verifier(path: str | None) -> SubprocessQuoteVerifier:
    """Load only the verifier binary reviewed for the direct validator."""

    return _load_pinned_verifier(
        path,
        expected_digest=DIRECT_VALIDATOR_QVL_DIGEST,
        pin_name="direct-validator",
    )
