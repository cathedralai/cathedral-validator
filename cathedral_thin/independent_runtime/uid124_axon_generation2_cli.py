"""Recovery-only shim for the retired UID124 generation-2 axon journal."""

from __future__ import annotations

from typing import Sequence

from .miner_axon import UID124_GENERATION2_AXON_CONTRACT
from .miner_axon_cli import run_contract_cli

WALLET_HOTKEY = "serge_sat_test"


def main(argv: Sequence[str] | None = None) -> int:
    return run_contract_cli(
        argv,
        prog="cathedral-uid124-axon-generation2",
        wallet_hotkey=WALLET_HOTKEY,
        contract=UID124_GENERATION2_AXON_CONTRACT,
        recovery_only=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
