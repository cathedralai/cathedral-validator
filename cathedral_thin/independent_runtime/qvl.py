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

from cathedral_thin.independent.compute import QuoteVerdict

from .errors import QuoteVerifyError

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

    def verify(self, quote: bytes, *, expected_report_data: bytes) -> QuoteVerdict:
        if not quote or not expected_report_data:
            return QuoteVerdict.FAIL
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
            return QuoteVerdict.INFRA
        finally:
            if handle is not None:
                os.close(handle)
            if quote_path is not None and os.path.exists(quote_path):
                os.unlink(quote_path)
        if len(completed.stdout) + len(completed.stderr) > MAX_OUTPUT:
            return QuoteVerdict.INFRA
        if completed.returncode != 0:
            return QuoteVerdict.FAIL
        try:
            claims = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return QuoteVerdict.INFRA
        if not isinstance(claims, dict):
            return QuoteVerdict.INFRA
        if claims.get("intel_verified") is not True:
            return QuoteVerdict.FAIL
        if claims.get("report_data_match") is not True:
            return QuoteVerdict.FAIL
        return QuoteVerdict.PASS


def load_verifier(path: str | None) -> SubprocessQuoteVerifier:
    """Load a QVL from ``path`` or ``CATHEDRAL_TDX_VERIFY_CMD``."""
    raw = path or os.environ.get("CATHEDRAL_TDX_VERIFY_CMD")
    if not raw:
        raise QuoteVerifyError(
            "no QVL binary: set CATHEDRAL_TDX_VERIFY_CMD to an executable"
        )
    command = Path(raw.split()[0] if " " in raw else raw)
    return SubprocessQuoteVerifier(command)
