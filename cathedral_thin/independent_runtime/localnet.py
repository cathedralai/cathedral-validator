"""Development-only local-chain mode for the direct validator.

Everything here is inert unless ``CATHEDRAL_LOCALNET=1``. It exists so the whole
SN94 loop (discovery, signed requests, evidence, SAT work, the zero-burn vector,
the writer's gates and journal, a finalized weight write, miner incentive) runs
against a local subtensor chain on a laptop without TDX hardware.

When it is on, and only then, the validator:

* accepts only ``--network ws://127.0.0.1:<port>`` or ``ws://localhost:<port>``
  and refuses ``finney`` or any other endpoint before touching a chain;
* pins the genesis in ``CATHEDRAL_LOCALNET_GENESIS_HASH`` instead of Finney's.
  The value must be canonical and must not be the Finney genesis, so a local
  run can never talk to Finney, even through a tunnel on 127.0.0.1;
* loads only the committed stub verifier ``localnet/stub_tdx_verifier.py``,
  pinned by ``LOCALNET_STUB_QVL_DIGEST``, instead of the release QVL. That stub
  accepts only the sandbox's localnet stub quote and still checks REPORT_DATA;
* dials miner axons and fleet endpoints on private, CGNAT, or loopback IPv4;
* signs validator requests for the ``local`` network, never ``finney``;
* journals under a ``localnet-sn<netuid>`` scope, never a ``finney-`` one;
* skips the AMD SEV-SNP verifier, whose pinned ``snpguest`` is a Linux x86-64
  binary. The SNP policy file is still loaded and validated. No localnet miner
  sends SNP evidence; one that did would count as SNP infrastructure failure.

Nothing else changes. Collection, SAT, scoring, the writer's chain gates
(permit, stake threshold, cooldown, commit-reveal off, version key, era), the
journal, and finalized confirmation run exactly as on Finney.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlsplit

from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH

LOCALNET_ENV = "CATHEDRAL_LOCALNET"
LOCALNET_GENESIS_ENV = "CATHEDRAL_LOCALNET_GENESIS_HASH"
LOCALNET_REQUEST_NETWORK = "local"
LOCALNET_STATE_SCOPE = "localnet"
# SHA-256 of localnet/stub_tdx_verifier.py. A test keeps the two in lockstep.
LOCALNET_STUB_QVL_DIGEST = (
    "981fac396886b2570bad132998e346e86675f2ee373eda17c29e934f8894ccbe"
)
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost"})
_HASH_HEX = frozenset("0123456789abcdef")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class LocalnetRefused(SystemExit):
    """Localnet mode was requested outside its development boundary."""


def localnet_active() -> bool:
    """Whether ``CATHEDRAL_LOCALNET=1`` is set. Any other value refuses."""

    value = os.environ.get(LOCALNET_ENV)
    if value is None or value == "":
        return False
    if value != "1":
        raise LocalnetRefused(f"{LOCALNET_ENV} must be exactly 1 or unset")
    return True


def localnet_genesis_hash() -> str:
    """The operator-pinned local genesis. Never the Finney genesis."""

    value = os.environ.get(LOCALNET_GENESIS_ENV, "")
    body = value[2:] if value.startswith("0x") else ""
    if len(body) != 64 or any(character not in _HASH_HEX for character in body):
        raise LocalnetRefused(
            f"{LOCALNET_GENESIS_ENV} must be 0x plus 64 lowercase hex characters"
        )
    if value == FINNEY_GENESIS_HASH:
        raise LocalnetRefused("localnet mode refuses the Finney genesis")
    return value


def expected_genesis_hash() -> str:
    """The genesis every chain read must observe."""

    return localnet_genesis_hash() if localnet_active() else FINNEY_GENESIS_HASH


def require_localnet_network(value: object) -> str:
    """Accept only a plain ws:// endpoint on this host."""

    if not isinstance(value, str) or value == "finney":
        raise LocalnetRefused("localnet mode refuses the Finney network")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise LocalnetRefused("localnet endpoint port is invalid") from exc
    if (
        parsed.scheme != "ws"
        or parsed.hostname not in _LOCAL_HOSTS
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise LocalnetRefused(
            "localnet mode accepts only --network ws://127.0.0.1:<port> or "
            "ws://localhost:<port>"
        )
    return value


def request_network() -> str:
    """The network name signed into every validator request."""

    return LOCALNET_REQUEST_NETWORK if localnet_active() else "finney"


def state_scope_network() -> str:
    """The network label that scopes the writer journal directory."""

    return LOCALNET_STATE_SCOPE if localnet_active() else "finney"


def allows_private_miner_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Whether a non-public miner address may be dialed in localnet mode."""

    return (
        isinstance(address, ipaddress.IPv4Address)
        and (address.is_private or address.is_loopback or address in _CGNAT)
        and not address.is_unspecified
        and not address.is_multicast
        and localnet_active()
    )


__all__ = [
    "LOCALNET_ENV",
    "LOCALNET_GENESIS_ENV",
    "LOCALNET_REQUEST_NETWORK",
    "LOCALNET_STATE_SCOPE",
    "LOCALNET_STUB_QVL_DIGEST",
    "LocalnetRefused",
    "allows_private_miner_address",
    "expected_genesis_hash",
    "localnet_active",
    "localnet_genesis_hash",
    "request_network",
    "require_localnet_network",
    "state_scope_network",
]
