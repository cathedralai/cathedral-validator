"""Finney / SN39 client living outside `cathedral_thin.independent`.

Reads the metagraph, observes genesis, and submits ``set_mechanism_weights``
as the dedicated canary hotkey. The live relay and burn destination refuse
lists are enforced here as well as in the composer package.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from bittensor.core.extrinsics.pallets import SubtensorModule
from bittensor_wallet import Keypair

from cathedral_thin.independent.constants import (
    CANARY_HOTKEY,
    FINNEY_GENESIS_HASH,
    MECID,
    NETUID,
    REFUSE_HOTKEYS,
    SN39_MORTAL_PERIOD_BLOCKS,
    VERSION_KEY,
)
from cathedral_thin.independent.inclusion import MetagraphView
from cathedral_thin.independent.refuse import require_permitted_hotkey

from .errors import ChainClientError
from .https import axon_evidence_url


@dataclass(frozen=True)
class ServingAxon:
    uid: int
    hotkey: str
    ip: str
    port: int

    def evidence_url(self) -> str:
        return axon_evidence_url(self.ip, self.port)


def _ip_to_str(raw: Any) -> str:
    if isinstance(raw, str) and raw:
        return raw
    if isinstance(raw, int) and not isinstance(raw, bool):
        return f"{(raw >> 24) & 255}.{(raw >> 16) & 255}.{(raw >> 8) & 255}.{raw & 255}"
    raise ChainClientError(f"axon ip {raw!r} is not usable")


def metagraph_view(metagraph: Any) -> MetagraphView:
    """UID/hotkey snapshot from a bittensor metagraph object."""
    uids = [int(uid) for uid in list(metagraph.uids)]
    hotkeys = [str(hotkey) for hotkey in list(metagraph.hotkeys)]
    if len(uids) != len(hotkeys):
        raise ChainClientError("metagraph uids and hotkeys differ in length")
    return MetagraphView.from_uid_map(dict(zip(uids, hotkeys)))


def serving_axons(metagraph: Any) -> tuple[ServingAxon, ...]:
    """Miners that advertise a serving axon. The burn dest is omitted."""
    uids = [int(uid) for uid in list(metagraph.uids)]
    hotkeys = [str(hotkey) for hotkey in list(metagraph.hotkeys)]
    axons = list(metagraph.axons)
    if not (len(uids) == len(hotkeys) == len(axons)):
        raise ChainClientError("metagraph axon rows are ragged")
    found: list[ServingAxon] = []
    for uid, hotkey, axon in zip(uids, hotkeys, axons):
        if hotkey in REFUSE_HOTKEYS or hotkey == CANARY_HOTKEY:
            continue
        port = int(getattr(axon, "port", 0) or 0)
        serving = bool(getattr(axon, "is_serving", port > 0)) and port > 0
        if not serving:
            continue
        try:
            ip = _ip_to_str(getattr(axon, "ip", ""))
        except ChainClientError:
            continue
        if ip in {"0.0.0.0", "::", "127.0.0.1", "::1"}:
            continue
        found.append(ServingAxon(uid=uid, hotkey=hotkey, ip=ip, port=port))
    return tuple(found)


def observed_genesis_hash(subtensor: Any) -> str:
    """Block-0 hash as ``0x`` + 64 lowercase hex, or raise."""
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


def load_keypair(document: Mapping[str, Any] | str) -> Any:
    """Load an sr25519 keypair from a bittensor wallet JSON object or string."""
    if isinstance(document, str):
        try:
            parsed = json.loads(document)
        except json.JSONDecodeError as exc:
            raise ChainClientError("canary hotkey JSON is not valid JSON") from exc
    else:
        parsed = dict(document)
    if not isinstance(parsed, Mapping):
        raise ChainClientError("canary hotkey JSON must be an object")
    seed = parsed.get("secretSeed") or parsed.get("secret_seed")
    if not isinstance(seed, str) or not seed:
        raise ChainClientError("canary hotkey JSON has no secretSeed")
    if seed.startswith("0x"):
        seed = seed[2:]
    try:
        keypair = Keypair.create_from_seed("0x" + seed)
    except Exception as exc:
        raise ChainClientError(f"canary hotkey seed is unusable: {exc}") from exc
    ss58 = str(keypair.ss58_address)
    require_permitted_hotkey(ss58, label="canary hotkey")
    if ss58 != CANARY_HOTKEY:
        raise ChainClientError(
            f"loaded hotkey {ss58} is not the dedicated canary {CANARY_HOTKEY}"
        )
    return keypair


class SubstrateCanaryTransport:
    """CanaryTransport that submits ``SubtensorModule.set_mechanism_weights``."""

    def __init__(self, subtensor: Any, keypair: Any) -> None:
        ss58 = str(getattr(keypair, "ss58_address", ""))
        require_permitted_hotkey(ss58, label="canary hotkey")
        if ss58 != CANARY_HOTKEY:
            raise ChainClientError(
                f"canary transport identity {ss58} is not {CANARY_HOTKEY}"
            )
        self.subtensor = subtensor
        self.keypair = keypair

    def submit_mechanism_weights(self, kwargs: Mapping[str, Any]) -> str:
        if not isinstance(kwargs, Mapping):
            raise ChainClientError("mechanism weight kwargs must be a mapping")
        if int(kwargs.get("netuid", -1)) != NETUID:
            raise ChainClientError("canary transport is pinned to netuid 39")
        if int(kwargs.get("mecid", -1)) != MECID:
            raise ChainClientError("canary transport is pinned to mecid 0")
        if int(kwargs.get("version_key", -1)) != VERSION_KEY:
            raise ChainClientError(
                f"canary transport is pinned to version_key {VERSION_KEY}"
            )
        observed_genesis_hash(self.subtensor)
        substrate = self.subtensor.substrate
        try:
            header = substrate.get_block_header()
            block_number = int(header["header"]["number"])
        except Exception as exc:
            raise ChainClientError(f"could not read sign-time head: {exc}") from exc
        try:
            nonce = substrate.get_account_next_index(self.keypair.ss58_address)
            call = SubtensorModule(self.subtensor).set_mechanism_weights(
                netuid=int(kwargs["netuid"]),
                mecid=int(kwargs["mecid"]),
                dests=list(kwargs["dests"]),
                weights=list(kwargs["weights"]),
                version_key=int(kwargs["version_key"]),
            )
            era = {"period": SN39_MORTAL_PERIOD_BLOCKS, "current": block_number}
            signed = substrate.create_signed_extrinsic(
                call=call,
                keypair=self.keypair,
                nonce=nonce,
                era=era,
            )
            receipt = substrate.submit_extrinsic(
                signed, wait_for_inclusion=True, wait_for_finalization=False
            )
        except Exception as exc:
            raise ChainClientError(f"set_mechanism_weights failed: {exc}") from exc
        extrinsic_hash = getattr(receipt, "extrinsic_hash", None) or getattr(
            signed, "extrinsic_hash", None
        )
        if extrinsic_hash is None:
            raise ChainClientError("submission returned no extrinsic hash")
        text = (
            extrinsic_hash
            if isinstance(extrinsic_hash, str)
            else f"0x{bytes(extrinsic_hash).hex()}"
        )
        if not text.startswith("0x"):
            text = "0x" + text
        return text.lower()
