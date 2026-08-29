"""Read-only SN39 axon types and metagraph parsing.

This module deliberately contains no wallet loader, nonce lookup, extrinsic
builder, journal, or submission transport.  Fleet previews import their chain
endpoint model from here so importing a preview never imports a chain writer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cathedral_thin.independent.constants import (
    CANARY_HOTKEY,
    FINNEY_GENESIS_HASH,
    REFUSE_HOTKEYS,
)
from cathedral_thin.independent.inclusion import MetagraphView

from .errors import ChainClientError
from .https import axon_evidence_url, axon_sat_work_url

# Probe and scoring paths both need to say why an axon row was excluded.
# Counts only: never list a refused hotkey as dialable.
AXON_SKIP_REASONS = (
    "refuse_or_canary",
    "port_zero",
    "not_serving",
    "unroutable",
    "unusable_ip",
)
_UNROUTABLE_IPS = frozenset({"0.0.0.0", "::", "127.0.0.1", "::1"})


@dataclass(frozen=True)
class ServingAxon:
    uid: int
    hotkey: str
    ip: str
    port: int

    def evidence_url(self) -> str:
        return axon_evidence_url(self.ip, self.port)

    def sat_work_url(self) -> str:
        return axon_sat_work_url(self.ip, self.port)


@dataclass(frozen=True)
class AxonScan:
    """Serving axons plus the skip-reason census of every other row."""

    serving: tuple[ServingAxon, ...]
    skipped: dict[str, int]


def _empty_skips() -> dict[str, int]:
    return {reason: 0 for reason in AXON_SKIP_REASONS}


def _ip_to_str(raw: Any) -> str:
    if isinstance(raw, str) and raw:
        return raw
    if isinstance(raw, int) and not isinstance(raw, bool):
        return f"{(raw >> 24) & 255}.{(raw >> 16) & 255}.{(raw >> 8) & 255}.{raw & 255}"
    raise ChainClientError(f"axon ip {raw!r} is not usable")


def metagraph_view(metagraph: Any) -> MetagraphView:
    """UID/hotkey snapshot from a Bittensor metagraph object."""

    uids = [int(uid) for uid in list(metagraph.uids)]
    hotkeys = [str(hotkey) for hotkey in list(metagraph.hotkeys)]
    if len(uids) != len(hotkeys):
        raise ChainClientError("metagraph uids and hotkeys differ in length")
    return MetagraphView.from_uid_map(dict(zip(uids, hotkeys)))


def scan_axons(metagraph: Any) -> AxonScan:
    """Classify every metagraph axon row. Serving is the only dialable set."""

    uids = [int(uid) for uid in list(metagraph.uids)]
    hotkeys = [str(hotkey) for hotkey in list(metagraph.hotkeys)]
    axons = list(metagraph.axons)
    if not (len(uids) == len(hotkeys) == len(axons)):
        raise ChainClientError("metagraph axon rows are ragged")
    found: list[ServingAxon] = []
    skipped = _empty_skips()
    for uid, hotkey, axon in zip(uids, hotkeys, axons):
        if hotkey in REFUSE_HOTKEYS or hotkey == CANARY_HOTKEY:
            skipped["refuse_or_canary"] += 1
            continue
        port = int(getattr(axon, "port", 0) or 0)
        if port <= 0:
            skipped["port_zero"] += 1
            continue
        serving = bool(getattr(axon, "is_serving", True))
        if not serving:
            skipped["not_serving"] += 1
            continue
        try:
            ip = _ip_to_str(getattr(axon, "ip", ""))
        except ChainClientError:
            skipped["unusable_ip"] += 1
            continue
        if ip in _UNROUTABLE_IPS:
            skipped["unroutable"] += 1
            continue
        found.append(ServingAxon(uid=uid, hotkey=hotkey, ip=ip, port=port))
    return AxonScan(serving=tuple(found), skipped=skipped)


def serving_axons(metagraph: Any) -> tuple[ServingAxon, ...]:
    """Miners that advertise a serving axon. The burn destination is omitted."""

    return scan_axons(metagraph).serving


def observed_genesis_hash(subtensor: Any) -> str:
    """Block-0 hash as ``0x`` plus 64 lowercase hex, or raise."""

    try:
        raw = subtensor.substrate.get_block_hash(0)
    except Exception as exc:
        raise ChainClientError(f"could not read genesis hash: {exc}") from exc
    text = str(raw)
    if not text.startswith("0x"):
        text = "0x" + text
    text = text.lower()
    if text != FINNEY_GENESIS_HASH:
        raise ChainClientError(
            f"observed genesis {text} is not the pinned Finney genesis"
        )
    return text


__all__ = [
    "AXON_SKIP_REASONS",
    "AxonScan",
    "ServingAxon",
    "metagraph_view",
    "observed_genesis_hash",
    "scan_axons",
    "serving_axons",
]
