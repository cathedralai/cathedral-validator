"""Operator command that clears one proven included-and-failed weight write.

``cathedral-validator record-failed-write --expected-hotkey=<public SS58>``

The direct validator stops with exit code 3 (``FINALIZED_FAILED_STOPPED``)
when its exact weight call was included in a finalized block and its dispatch
failed. The pending intent then blocks every later cycle, setup rerun and
update. This command proves that failure from finalized chain state and only
then records the intent as terminal (``FINALIZED_FAILED``). It loads no key,
never signs or broadcasts, and changes nothing when it refuses. It must run as
the validator's service user with the service's ``HOME``, while the validator
is stopped. See ``docs/AUTO_UPDATE.md``.
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Sequence

import bittensor as bt

from cathedral_thin.bt_compat import make_subtensor

from .direct_validator import RECORD_FAILED_WRITE_COMMAND, _expected_hotkey
from .direct_writer import (
    DirectWeightWriter,
    FailedWriteRecordRefused,
    bound_rpc_waits,
)

STATUS_RECORDED = "FINALIZED_FAILED_RECORDED"
STATUS_REFUSED = "RECORD_REFUSED"
STATUS_NOT_PROVEN = "RECORD_NOT_PROVEN"


class PublicHotkey:
    """The signer's public address. It has no key and cannot sign."""

    def __init__(self, ss58_address: str) -> None:
        self.ss58_address = ss58_address


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=f"cathedral-validator {RECORD_FAILED_WRITE_COMMAND}",
        description=(
            "Prove from finalized chain state that the stopped weight write "
            "failed on chain, then record it as terminal. Never signs."
        ),
    )
    parser.add_argument(
        "--expected-hotkey",
        required=True,
        help="public SS58 address of the validator hotkey whose journal stopped",
    )
    return parser


def _print(document: dict[str, Any]) -> None:
    print(json.dumps(document, sort_keys=True), flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Return 0 once the failure is proven and recorded, and 1 otherwise."""

    options = _parser().parse_args(argv)
    hotkey = _expected_hotkey(options.expected_hotkey)
    try:
        subtensor = make_subtensor(bt, network="finney")
        bound_rpc_waits(subtensor)
    except Exception as exc:
        _print(
            {
                "status": STATUS_REFUSED,
                "error": f"chain client refused: {type(exc).__name__}: {exc}",
            }
        )
        return 1
    writer = DirectWeightWriter(subtensor=subtensor, keypair=PublicHotkey(hotkey))
    try:
        record = writer.record_finalized_failure()
    except FailedWriteRecordRefused as exc:
        _print({"status": STATUS_REFUSED, "error": str(exc)})
        return 1
    except Exception as exc:
        # Every refusal is converted above, so only the final journal write
        # gets here. Re-run the command, or the status tool, to read what the
        # journal holds now.
        _print({"status": STATUS_NOT_PROVEN, "error": f"{type(exc).__name__}: {exc}"})
        return 1
    _print({"status": STATUS_RECORDED, **record})
    return 0


__all__ = [
    "PublicHotkey",
    "STATUS_NOT_PROVEN",
    "STATUS_RECORDED",
    "STATUS_REFUSED",
    "main",
]
