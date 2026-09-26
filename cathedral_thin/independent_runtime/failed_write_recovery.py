"""Operator command that clears one proven included-and-failed weight write.

``cathedral-validator record-failed-write --expected-hotkey=<public SS58>``

The direct validator stops with exit code 3 (``FINALIZED_FAILED_STOPPED``)
when its exact weight call was included in a finalized block and its dispatch
failed. The pending intent then blocks every later cycle, setup rerun and
update. This command proves that failure from finalized chain state and only
then records the intent as terminal (``FINALIZED_FAILED``). It loads no key,
never signs or broadcasts, and changes nothing unless it records. It must run
as the validator's service user with the service's ``HOME``, while the
validator is stopped. See ``docs/AUTO_UPDATE.md``.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any, Sequence
from urllib.parse import urlsplit

import bittensor as bt

from cathedral_thin.bt_compat import make_subtensor

from .direct_validator import (
    RECORD_FAILED_WRITE_COMMAND,
    _add_netuid_argument,
    _add_network_argument,
    _configured_netuid,
    _expected_hotkey,
    _pinned_network,
)
from .direct_writer import (
    DirectWeightWriter,
    FailedWriteHistoryUnreadable,
    FailedWriteRecordRefused,
    bound_rpc_waits,
)

STATUS_RECORDED = "FINALIZED_FAILED_RECORDED"
STATUS_REFUSED = "RECORD_REFUSED"
STATUS_RETRY_WITH_ARCHIVE = "RECORD_RETRY_WITH_ARCHIVE"
STATUS_NOT_PROVEN = "RECORD_NOT_PROVEN"
EXIT_RECORDED = 0
EXIT_REFUSED = 1
# sysexits EX_TEMPFAIL: nothing changed and the same command may be retried.
EXIT_RETRY = os.EX_TEMPFAIL
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class PublicHotkey:
    """The signer's public address. It has no key and cannot sign."""

    def __init__(self, ss58_address: str) -> None:
        self.ss58_address = ss58_address


def _archive_endpoint(value: str) -> str:
    """Accept a wss:// endpoint, or ws:// on this host only."""

    parts = urlsplit(value) if value.isascii() and value.isprintable() else None
    if (
        parts is None
        or " " in value
        or not parts.hostname
        or parts.username is not None
        or parts.fragment
        or not (
            parts.scheme == "wss"
            or (parts.scheme == "ws" and parts.hostname in _LOOPBACK_HOSTS)
        )
    ):
        raise SystemExit(
            "--archive-endpoint must be a wss:// URL, or a ws:// URL on this host"
        )
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=f"cathedral-validator {RECORD_FAILED_WRITE_COMMAND}",
        description=(
            "Prove from finalized chain state that the stopped weight write "
            "failed on chain, then record it as terminal. Never signs."
        ),
    )
    _add_network_argument(parser)
    _add_netuid_argument(parser)
    parser.add_argument(
        "--expected-hotkey",
        required=True,
        help="public SS58 address of the validator hotkey whose journal stopped",
    )
    parser.add_argument(
        "--archive-endpoint",
        help=(
            "read the proof's history from this archive node instead of the "
            "network's entrypoint; the pinned genesis still applies"
        ),
    )
    return parser


def _print(document: dict[str, Any]) -> None:
    print(json.dumps(document, sort_keys=True), flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Return 0 once recorded, 1 when refused, and 75 when history is unreadable."""

    options = _parser().parse_args(argv)
    network = _pinned_network(options.network)
    # The journal is scoped by netuid, so the command resolves it exactly as
    # the validator does and hands it to the writer it proves and records with.
    netuid = _configured_netuid(options.netuid)
    hotkey = _expected_hotkey(options.expected_hotkey)
    archive = (
        _archive_endpoint(options.archive_endpoint)
        if options.archive_endpoint is not None
        else None
    )
    try:
        subtensor = make_subtensor(bt, network=archive or network)
        bound_rpc_waits(subtensor)
    except Exception as exc:
        _print(
            {
                "status": STATUS_REFUSED,
                "error": f"chain client refused: {type(exc).__name__}: {exc}",
            }
        )
        return EXIT_REFUSED
    writer = DirectWeightWriter(
        subtensor=subtensor, keypair=PublicHotkey(hotkey), netuid=netuid
    )
    try:
        record = writer.record_finalized_failure()
    except FailedWriteRecordRefused as exc:
        _print({"status": STATUS_REFUSED, "error": str(exc)})
        return EXIT_REFUSED
    except FailedWriteHistoryUnreadable as exc:
        _print(
            {
                "status": STATUS_RETRY_WITH_ARCHIVE,
                "error": str(exc),
                "action": (
                    "the archive endpoint could not serve this history; retry "
                    "later or with another archive endpoint"
                    if archive is not None
                    else "run the same command again with --archive-endpoint"
                ),
            }
        )
        return EXIT_RETRY
    except Exception as exc:
        # Refusals and unreadable history are handled above. What remains is
        # a failure while writing the journal or releasing a lock after the
        # proof, so the record may or may not be on disk. Re-run the command,
        # or the status tool, to read what the journal holds now.
        _print({"status": STATUS_NOT_PROVEN, "error": f"{type(exc).__name__}: {exc}"})
        return EXIT_REFUSED
    _print({"status": STATUS_RECORDED, **record})
    return EXIT_RECORDED


__all__ = [
    "EXIT_RECORDED",
    "EXIT_REFUSED",
    "EXIT_RETRY",
    "PublicHotkey",
    "STATUS_NOT_PROVEN",
    "STATUS_RECORDED",
    "STATUS_REFUSED",
    "STATUS_RETRY_WITH_ARCHIVE",
    "main",
]
