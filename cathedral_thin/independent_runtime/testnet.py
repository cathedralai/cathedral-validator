"""Guarded public-testnet rehearsal without development verifier shortcuts.

Adapted from the preserved #277 testnet work. Only the selected chain changes:
release verifiers, public miner dialing, signing gates and recovery stay intact.
No localnet, fake quote verifier or private-address exception is introduced.
"""

from __future__ import annotations

import os
from typing import Mapping

from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH, MAX_NETUID

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


NETUID_ENVIRONMENT = "CATHEDRAL_VALIDATOR_NETUID"


def _canonical_netuid(value: str, source: str) -> int:
    if (
        not value.isascii()
        or not value.isdigit()
        or str(int(value)) != value
        or int(value) > MAX_NETUID
    ):
        raise SystemExit(f"{source} must be a canonical decimal u16 integer")
    return int(value)


def configured_netuid(
    values: list[str] | tuple[str, ...] | None,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Resolve the one subnet to validate from deploy-time configuration.

    The netuid comes from ``--netuid`` or from ``CATHEDRAL_VALIDATOR_NETUID``,
    which the units read from ``direct.env``; nothing is compiled in. Both may
    be given only if they agree, and at least one must be. Every refusal is a
    ``SystemExit`` message, status 1, which the unit restarts; an argparse
    error would exit with status 2, which ``RestartPreventExitStatus=2`` never
    restarts, so the value is parsed here rather than by argparse.

    The updater, the status tool and the boot gate read the same setting from
    ``direct.env`` to locate this netuid's journal and the cycle lock beside
    it, so an update never activates in the middle of the writer's cycle.

    A testnet rehearsal ignores ``direct.env`` and accepts only an explicit
    ``--netuid 584``, so a production setting can never select it.
    """

    if values is not None and len(values) != 1:
        # argparse would silently keep the last one, and the unit still expands
        # a free-form argument variable after the managed flags.
        raise SystemExit("--netuid may be given only once")
    flag = None if values is None else _canonical_netuid(values[0], "--netuid")
    if testnet_active():
        if flag is None:
            raise SystemExit("testnet mode needs an explicit --netuid 584")
        if flag != TESTNET_NETUID:
            raise SystemExit("this rehearsal accepts only public-testnet netuid 584")
        return flag
    environment = os.environ if environ is None else environ
    raw = environment.get(NETUID_ENVIRONMENT)
    configured = None if raw is None else _canonical_netuid(raw, NETUID_ENVIRONMENT)
    if flag is None and configured is None:
        raise SystemExit(
            f"no netuid is configured: set {NETUID_ENVIRONMENT} in "
            "/etc/cathedral-validator/direct.env or pass --netuid"
        )
    if flag is not None and configured is not None and flag != configured:
        raise SystemExit(
            f"--netuid {flag} disagrees with {NETUID_ENVIRONMENT}={configured}"
        )
    return flag if flag is not None else configured
