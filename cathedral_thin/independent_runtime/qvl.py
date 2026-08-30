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
import subprocess
import tempfile
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
TIMEOUT_SECONDS = 30


def digest_file(path: Path) -> str:
    """SHA-256 of the verifier binary, lowercase hex."""
    data = path.read_bytes()
    if not data:
        raise QuoteVerifyError(f"QVL binary {path} is empty")
    return hashlib.sha256(data).hexdigest()


class SubprocessQuoteVerifier:
    """Runs ``command quote_path expected_report_data_hex`` and reads JSON."""

    def __init__(self, command: Path) -> None:
        resolved = Path(command)
        if not resolved.is_file():
            raise QuoteVerifyError(f"QVL binary {resolved} is not a file")
        if not os.access(resolved, os.X_OK):
            raise QuoteVerifyError(f"QVL binary {resolved} is not executable")
        self.command = resolved
        self.digest = digest_file(resolved)

    def _claims(
        self, quote: bytes, *, expected_report_data: bytes
    ) -> tuple[QuoteVerdict, dict[str, object] | None]:
        if not quote or not expected_report_data:
            return QuoteVerdict.FAIL, None
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
            completed = subprocess.run(
                [str(self.command), quote_path, expected_report_data.hex()],
                capture_output=True,
                timeout=TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return QuoteVerdict.INFRA, None
        finally:
            if handle is not None:
                os.close(handle)
            if quote_path is not None and os.path.exists(quote_path):
                os.unlink(quote_path)
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

    def verify(self, quote: bytes, *, expected_report_data: bytes) -> QuoteVerdict:
        """Retain the reviewed single-machine PASS/FAIL/INFRA contract."""

        verdict, _claims = self._claims(
            quote, expected_report_data=expected_report_data
        )
        return verdict

    def verify_with_identity(
        self, quote: bytes, *, expected_report_data: bytes
    ) -> QuoteIdentityVerdict:
        """Return PASS plus a strict PCK/PPID-derived stable platform id.

        Missing or malformed stable identity does not rewrite the legacy quote
        verdict.  It leaves ``platform_identity_verified`` false, which keeps
        the multi-machine feature disabled while the single-machine path can
        continue under its existing contract.
        """

        verdict, claims = self._claims(quote, expected_report_data=expected_report_data)
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
