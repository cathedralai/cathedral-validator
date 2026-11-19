"""Where a validator connects to the chain, resolved one way for every path.

The network is a label: it names the chain the validator accepts (the released
validator accepts only ``finney``, checked again by genesis hash). The chain
endpoint only changes where the RPC connection goes, for example an operator's
own subtensor node. It never changes which chain is accepted.

Flags (standard bittensor names):

- ``--subtensor.network`` (alias of the older ``--network``)
- ``--subtensor.chain_endpoint``

Environment, for systemd ``EnvironmentFile=`` and ``docker run -e``:

- ``SUBTENSOR_NETWORK``
- ``SUBTENSOR_CHAIN_ENDPOINT``
- ``CATHEDRAL_CHAIN_ENDPOINT`` (older name, still honoured)

Precedence, endpoint: ``--subtensor.chain_endpoint``, then a ws/wss URL given
as ``--subtensor.network``, then ``SUBTENSOR_CHAIN_ENDPOINT``, then
``CATHEDRAL_CHAIN_ENDPOINT``, then a ws/wss URL in ``SUBTENSOR_NETWORK``, then
none (bittensor's public entrypoint for the network). A ``SUBTENSOR_NETWORK``
label that differs from the flag is refused rather than ignored. Network label: flag,
then ``SUBTENSOR_NETWORK``, then the caller's default. Empty values are unset.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

NETWORK_ENV = "SUBTENSOR_NETWORK"
ENDPOINT_ENV = "SUBTENSOR_CHAIN_ENDPOINT"
LEGACY_ENDPOINT_ENV = "CATHEDRAL_CHAIN_ENDPOINT"
NETWORK_FLAG = "--subtensor.network"
ENDPOINT_FLAG = "--subtensor.chain_endpoint"
DEFAULT_ENDPOINT_LABEL = "default"

# host.docker.internal is how a container reaches a node on its own host.
_LOCAL_NAMES = frozenset({"localhost", "host.docker.internal"})
# Carrier-grade NAT space, also used by Tailscale; Python does not call it private.
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")


class ChainTargetError(ValueError):
    """The configured network or endpoint is refused."""


@dataclass(frozen=True)
class ChainTarget:
    network: str
    endpoint: str | None = None
    endpoint_source: str | None = None

    @property
    def connect_to(self) -> str:
        """What bittensor's ``Subtensor(network=...)`` receives."""

        return self.endpoint or self.network

    def event(self) -> dict[str, object]:
        """Log fields. The endpoint is reduced to scheme://host:port."""

        if self.endpoint is None:
            return {"network": self.network, "endpoint": DEFAULT_ENDPOINT_LABEL}
        return {
            "network": self.network,
            "endpoint": redact_endpoint(self.endpoint),
            "endpoint_source": self.endpoint_source,
        }


def add_chain_arguments(
    parser: argparse.ArgumentParser,
    *,
    network_help: str | None = None,
    network_default: str | None = None,
) -> None:
    """Add ``--network``/``--subtensor.network`` and ``--subtensor.chain_endpoint``.

    Both default to None so the resolver can tell an explicit flag from an
    environment value. Values are validated by ``resolve_chain_target``, not by
    argparse, so a bad value is a status 1 refusal and never argparse's
    status 2 (which the direct unit treats as a journal contradiction).
    """

    parser.add_argument(
        "--network",
        NETWORK_FLAG,
        dest="network",
        default=network_default,
        help=network_help or f"chain network label; also {NETWORK_ENV}",
    )
    parser.add_argument(
        ENDPOINT_FLAG,
        dest="chain_endpoint",
        default=None,
        help=(
            "ws:// or wss:// URL of the subtensor node to connect to, for example "
            f"your own node; the chain must still match the network. Also "
            f"{ENDPOINT_ENV} (or the older {LEGACY_ENDPOINT_ENV})"
        ),
    )


def _clean(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ChainTargetError("chain setting must be text")
    value = value.strip()
    return value or None


def _is_url(value: str) -> bool:
    return value.lower().startswith(("ws://", "wss://"))


def _plaintext_host_allowed(host: str) -> bool:
    if host in _LOCAL_NAMES:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # A single-label name (a Docker or compose service name) cannot be a
        # public DNS name; anything with a dot might be, so it needs wss://.
        return "." not in host
    return (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address in _SHARED_ADDRESS_SPACE
    )


def validate_endpoint(value: str, *, source: str) -> str:
    """Accept wss:// anywhere, ws:// only to a local or private-network host."""

    parts = urlsplit(value) if value.isascii() and value.isprintable() else None
    try:
        port_ok = parts is not None and (parts.port is None or parts.port > 0)
    except ValueError:
        port_ok = False
    if (
        parts is None
        or not port_ok
        or " " in value
        or parts.fragment
        or not parts.hostname
        or parts.scheme not in {"ws", "wss"}
    ):
        raise ChainTargetError(f"{source} must be a ws:// or wss:// URL with a host")
    if parts.scheme == "ws" and not _plaintext_host_allowed(parts.hostname):
        raise ChainTargetError(
            f"{source}: plain ws:// is accepted only for this host or a private "
            "network address; use wss:// for a public host"
        )
    return value


def redact_endpoint(value: str) -> str:
    """scheme://host[:port] only: userinfo, path and query may hold API keys."""

    try:
        parts = urlsplit(value)
        host = parts.hostname or "?"
        port = parts.port
    except ValueError:
        return "<unparseable>"
    if ":" in host:
        host = f"[{host}]"
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


def legacy_network_default(
    fallback: str, environ: Mapping[str, str] | None = None
) -> str:
    """argparse default for the legacy CLIs: SUBTENSOR_NETWORK, BT_NETWORK, fallback.

    The legacy commands expose the resolved label at parse time. Because the
    default already carries SUBTENSOR_NETWORK, the resolver sees the same value
    as flag and environment, so no false conflict arises.
    """

    env = os.environ if environ is None else environ
    return _clean(env.get(NETWORK_ENV)) or _clean(env.get("BT_NETWORK")) or fallback


def resolve_args(args: argparse.Namespace, *, default_network: str) -> ChainTarget:
    """Resolve a legacy CLI's flags in place (thin validator, preflight).

    Rewrites ``args.network`` to the resolved label, so the rest of the
    command sees one value, and returns the target for ``connect_legacy``.
    """

    try:
        target = resolve_chain_target(
            getattr(args, "network", None),
            getattr(args, "chain_endpoint", None),
            default_network=default_network,
        )
    except ChainTargetError as exc:
        raise SystemExit(f"chain endpoint refused: {exc}") from exc
    args.network = target.network
    return target


def connect_legacy(
    bt: object, target: ChainTarget, *, make_subtensor: Any = None
) -> object:
    """Log and connect. An own node for finney or test must serve its genesis."""

    import json
    import sys

    if make_subtensor is None:
        from cathedral_thin.bt_compat import make_subtensor

    print(json.dumps({"chain": target.event()}, sort_keys=True), file=sys.stderr)
    if target.endpoint is None:
        return make_subtensor(bt, network=target.connect_to)
    shown = redact_endpoint(target.endpoint)
    try:
        subtensor = make_subtensor(bt, network=target.connect_to)
    except Exception as exc:
        raise SystemExit(
            f"chain endpoint {shown} refused: could not connect: {type(exc).__name__}"
        ) from exc
    from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH
    from cathedral_thin.independent_runtime.testnet import TESTNET_GENESIS_HASH

    # A node for a known chain must serve that chain's genesis. Other labels
    # (local dev chains) have no pinned genesis to compare.
    pinned = {"finney": FINNEY_GENESIS_HASH, "test": TESTNET_GENESIS_HASH}.get(
        target.network
    )
    if pinned is not None:
        try:
            raw = str(subtensor.substrate.get_block_hash(0)).lower()
        except Exception as exc:
            raise SystemExit(
                f"chain endpoint {shown} refused: "
                f"could not read genesis hash: {type(exc).__name__}"
            ) from exc
        observed = raw if raw.startswith("0x") else "0x" + raw
        if observed != pinned:
            raise SystemExit(
                f"chain endpoint {shown} refused: observed genesis {observed} "
                f"is not the pinned {target.network} genesis"
            )
    return subtensor


def resolve_chain_target(
    network_flag: object,
    endpoint_flag: object,
    *,
    default_network: str,
    environ: Mapping[str, str] | None = None,
) -> ChainTarget:
    """Resolve the one chain setting. Raises ``ChainTargetError`` when refused."""

    env = os.environ if environ is None else environ
    flag_network = _clean(network_flag)
    env_network = _clean(env.get(NETWORK_ENV))
    flag_url = flag_network if flag_network and _is_url(flag_network) else None
    env_url = env_network if env_network and _is_url(env_network) else None
    flag_label = None if flag_url else flag_network
    env_label = None if env_url else env_network
    if flag_label and env_label and flag_label != env_label:
        # The systemd unit and the Docker image always pass --network=finney.
        # An operator who sets SUBTENSOR_NETWORK=local expecting their own
        # node would otherwise be ignored silently.
        raise ChainTargetError(
            f"{NETWORK_ENV}={env_label} conflicts with --network={flag_label}; "
            f"the network names the chain. To use your own node set {ENDPOINT_ENV}"
        )
    network = flag_label or env_label or default_network
    # Flags beat the environment. A ws/wss URL given as the network (the
    # bittensor habit) is an endpoint; the label stays the chain above.
    candidates = (
        (_clean(endpoint_flag), ENDPOINT_FLAG),
        (flag_url, NETWORK_FLAG),
        (_clean(env.get(ENDPOINT_ENV)), ENDPOINT_ENV),
        (_clean(env.get(LEGACY_ENDPOINT_ENV)), LEGACY_ENDPOINT_ENV),
        (env_url, NETWORK_ENV),
    )
    for value, source in candidates:
        if value is not None:
            return ChainTarget(
                network=network,
                endpoint=validate_endpoint(value, source=source),
                endpoint_source=source,
            )
    return ChainTarget(network=network)


def scrub(text: str, endpoint: str | None) -> str:
    """Replace a full endpoint inside an error message with its redacted form."""

    if not endpoint:
        return text
    return text.replace(endpoint, redact_endpoint(endpoint))


__all__ = [
    "ChainTarget",
    "ChainTargetError",
    "DEFAULT_ENDPOINT_LABEL",
    "ENDPOINT_ENV",
    "ENDPOINT_FLAG",
    "LEGACY_ENDPOINT_ENV",
    "NETWORK_ENV",
    "NETWORK_FLAG",
    "add_chain_arguments",
    "connect_legacy",
    "legacy_network_default",
    "resolve_args",
    "redact_endpoint",
    "resolve_chain_target",
    "scrub",
    "validate_endpoint",
]
