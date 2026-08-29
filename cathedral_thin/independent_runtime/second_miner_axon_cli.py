"""Dedicated one-attempt axon writer for the second Cathedral SN39 miner."""

from __future__ import annotations

from typing import Sequence

from .miner_axon import SECOND_MINER_AXON_CONTRACT
from .miner_axon_cli import run_contract_cli

WALLET_HOTKEY = "serge_sat_test_2"


def main(argv: Sequence[str] | None = None) -> int:
    return run_contract_cli(
        argv,
        prog="cathedral-second-miner-announce",
        wallet_hotkey=WALLET_HOTKEY,
        contract=SECOND_MINER_AXON_CONTRACT,
    )


if __name__ == "__main__":
    raise SystemExit(main())
