"""Guarded public-testnet rehearsal without development verifier shortcuts.

Adapted from the preserved #277 testnet work. Only the selected chain changes:
release verifiers, public miner dialing, signing gates and recovery stay intact.
No localnet, fake quote verifier or private-address exception is introduced.
"""

from __future__ import annotations

import os

from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH, MAX_NETUID, NETUID

TESTNET_ENV = "CATHEDRAL_TESTNET"
TESTNET_ENDPOINT = "wss://test.finney.opentensor.ai:443"
TESTNET_GENESIS_HASH = (
    "0x8f9cf856bf558a14440e75569c9e58594757048d7b3a84b5d25f6bd978263105"
)
TESTNET_NETUID = 584


def testnet_active() -> bool:
    value = os.environ.get(TESTNET_ENV)
    if os.environ.get("CATHEDRAL_LOCALNET"):
        raise SystemExit("this release has no localnet verifier bypass")
    if value is None or value == "":
        return False
    if value != "1":
        raise SystemExit(f"{TESTNET_ENV} must be exactly 1 or unset")
    return True


def require_testnet_network(value: object) -> str:
    if not isinstance(value, str) or value not in {"test", TESTNET_ENDPOINT}:
        raise SystemExit("testnet mode accepts only the pinned public testnet")
    return value


def expected_genesis_hash() -> str:
    return TESTNET_GENESIS_HASH if testnet_active() else FINNEY_GENESIS_HASH


def request_network() -> str:
    return "test" if testnet_active() else "finney"


def state_scope_network() -> str:
    return "testnet" if testnet_active() else "finney"


def configured_netuid(values: list[str] | tuple[str, ...] | None) -> int:
    rehearsal = testnet_active()
    if values is None:
        if rehearsal:
            raise SystemExit("testnet mode needs an explicit --netuid 584")
        return NETUID
    if len(values) != 1:
        raise SystemExit("--netuid may be given only once")
    value = values[0]
    if (
        not value.isascii()
        or not value.isdigit()
        or str(int(value)) != value
        or int(value) > MAX_NETUID
    ):
        raise SystemExit("--netuid must be a canonical decimal u16 integer")
    netuid = int(value)
    if rehearsal:
        if netuid != TESTNET_NETUID:
            raise SystemExit("this rehearsal accepts only public-testnet netuid 584")
    elif netuid != NETUID:
        raise SystemExit(
            f"--netuid {netuid} is not the netuid this release was built for "
            f"({NETUID}); other production netuids are not supported"
        )
    return netuid
