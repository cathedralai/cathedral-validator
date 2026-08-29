"""Read-only finalized UID30 state shared by preview and bounded recovery code.

This module contains no journal, nonce, extrinsic, submission, or recovery
function. It centralizes the exact chain eligibility and miner-root read so a
no-write fleet proof does not import the UID30 launch writer module.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import numpy as np
import bittensor as bt
from bittensor_wallet import Keypair

from cathedral_thin.bt_compat import make_subtensor, make_wallet
from cathedral_thin.independent.constants import (
    COMMIT_REVEAL_ENABLED,
    FINNEY_GENESIS_HASH,
    MAX_WEIGHT_LIMIT,
    MECID,
    MIN_ALLOWED_WEIGHTS,
    NETUID,
    UID30_MINER_HOTKEY,
    UID30_VALIDATOR_HOTKEY,
    UID30_VALIDATOR_UID,
    VERSION_KEY,
    W,
)
from cathedral_thin.independent_runtime.axon import ServingAxon

NETWORK = "finney"
WALLET_NAME = "cathedral"
WALLET_HOTKEY = "default"
UID30 = UID30_VALIDATOR_UID
UID30_HOTKEY = UID30_VALIDATOR_HOTKEY
MINER_HOTKEY = UID30_MINER_HOTKEY

_CHAIN_HASH_RE = re.compile(r"0x[0-9a-f]{64}")


class UID30LaunchError(Exception):
    """The fixed UID30 contract refused before an ambiguous chain boundary."""


@dataclass(frozen=True)
class UID30ChainState:
    """Finalized chain facts used by previews and sign-time revalidation."""

    preflight: Any
    block_number: int
    block_hash: str
    genesis_hash: str
    subnet_owner_hotkey: str
    validator_hotkey: str
    validator_uid: int
    validator_permit: bool
    validator_stake_rao: int
    stake_threshold_rao: int
    last_update: int
    blocks_since_last_update: int
    weights_rate_limit: int
    mechanism_count: int
    weights_version_key: int
    min_allowed_weights: int
    max_weight_limit: float
    commit_reveal_enabled: bool
    miner_hotkey: str
    miner_uid: int
    serving_axon: ServingAxon
    next_epoch_start_block: int
    blocks_until_next_epoch: int
    uid_safety: Mapping[str, Any]

    def artifact(self) -> dict[str, Any]:
        return {
            "wallet_name": WALLET_NAME,
            "wallet_hotkey": WALLET_HOTKEY,
            "hotkey": self.validator_hotkey,
            "uid": self.validator_uid,
            "validator_permit": self.validator_permit,
            "stake_rao": self.validator_stake_rao,
            "stake_threshold_rao": self.stake_threshold_rao,
            "last_update": self.last_update,
            "blocks_since_last_update": self.blocks_since_last_update,
            "weights_rate_limit": self.weights_rate_limit,
            "mechanism_count": self.mechanism_count,
            "weights_version_key": self.weights_version_key,
            "min_allowed_weights": self.min_allowed_weights,
            "max_weight_limit": self.max_weight_limit,
            "commit_reveal_enabled": self.commit_reveal_enabled,
        }


@dataclass(frozen=True)
class UID30ReadPreflight:
    """Only the finalized read facts consumed by the no-write fleet proof."""

    wallet: Any
    subtensor: Any
    hotkey_to_uid: dict[str, int]
    uid_to_hotkey: dict[int, str]
    validator_hotkey: str
    validator_uid: int
    block: int
    finalized_hash: str
    min_allowed_weights: int
    max_weight_limit: float
    commit_reveal_enabled: bool
    genesis_hash: str
    subnet_owner_hotkey: str
    blocks_until_next_epoch: int
    next_epoch_start_block: int
    weights_rate_limit: int
    validator_blocks_since_last_update: int


def _raw_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _strict_nonnegative_int(value: Any, *, label: str) -> int:
    raw = _raw_value(value)
    if isinstance(raw, np.ndarray):
        if raw.ndim != 0 or not np.issubdtype(raw.dtype, np.integer):
            raise UID30LaunchError(f"{label} is not a non-negative integer")
        raw = raw.item()
    elif isinstance(raw, np.integer):
        raw = raw.item()
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise UID30LaunchError(f"{label} is not a non-negative integer")
    return raw


def _strict_bool(value: Any, *, label: str) -> bool:
    raw = _raw_value(value)
    item = getattr(raw, "item", None)
    if callable(item):
        raw = item()
    if type(raw) is not bool:
        raise UID30LaunchError(f"{label} is not an explicit boolean")
    return raw


def _balance_rao(value: Any, *, label: str) -> int:
    return _strict_nonnegative_int(getattr(value, "rao", value), label=label)


def _canonical_hash(value: Any, *, label: str) -> str:
    text = str(value).lower()
    if _CHAIN_HASH_RE.fullmatch(text) is None:
        raise UID30LaunchError(f"{label} is not a canonical chain hash")
    return text


def _require_ss58(value: object, *, label: str) -> str:
    address = str(value or "")
    try:
        parsed = str(Keypair(ss58_address=address).ss58_address)
    except Exception as exc:
        raise UID30LaunchError(f"{label} is not a valid SS58 address") from exc
    if parsed != address:
        raise UID30LaunchError(f"{label} is not a canonical SS58 address")
    return address


def _serving_axon_from_info_row(raw: Any, *, uid: int, hotkey: str) -> ServingAxon:
    """Decode the axon row already bound to finalized metagraph info."""

    if not isinstance(raw, Mapping):
        raise UID30LaunchError("serving-axon metagraph row is not a mapping")
    ip_type = _strict_nonnegative_int(raw.get("ip_type"), label="serving-axon IP type")
    ip_value = _strict_nonnegative_int(raw.get("ip"), label="serving-axon IP")
    port = _strict_nonnegative_int(raw.get("port"), label="serving-axon port")
    if ip_type != 4 or ip_value > 0xFFFFFFFF:
        raise UID30LaunchError("serving-axon metagraph row is not canonical IPv4")
    try:
        ip = str(ipaddress.IPv4Address(ip_value))
    except ipaddress.AddressValueError as exc:
        raise UID30LaunchError(
            "serving-axon metagraph row is not canonical IPv4"
        ) from exc
    return ServingAxon(uid=uid, hotkey=hotkey, ip=ip, port=port)


def validate_chain_state(state: UID30ChainState) -> UID30ChainState:
    """Apply the fixed UID30 read-only identity and eligibility contract."""

    _require_ss58(UID30_HOTKEY, label="pinned UID30 hotkey")
    _require_ss58(MINER_HOTKEY, label="pinned miner hotkey")
    _require_ss58(state.validator_hotkey, label="resolved validator hotkey")
    _require_ss58(state.miner_hotkey, label="resolved miner hotkey")
    _require_ss58(state.subnet_owner_hotkey, label="resolved subnet owner hotkey")
    if state.genesis_hash != FINNEY_GENESIS_HASH:
        raise UID30LaunchError("chain state is not the pinned Finney genesis")
    if state.validator_hotkey != UID30_HOTKEY:
        raise UID30LaunchError("cathedral/default is not the pinned UID30 hotkey")
    if state.validator_uid != UID30:
        raise UID30LaunchError(
            f"pinned validator resolved to UID {state.validator_uid}, not 30"
        )
    if state.validator_permit is not True:
        raise UID30LaunchError("UID30 lacks the current validator permit")
    if state.validator_stake_rao < state.stake_threshold_rao:
        raise UID30LaunchError("UID30 is below the current weight stake threshold")
    if state.blocks_since_last_update != state.block_number - state.last_update:
        raise UID30LaunchError("UID30 last_update and cooldown distance disagree")
    if state.mechanism_count <= MECID:
        raise UID30LaunchError("SN39 mechanism 0 does not exist")
    if state.min_allowed_weights != MIN_ALLOWED_WEIGHTS:
        raise UID30LaunchError("SN39 min_allowed_weights differs from the launch pin")
    if not math.isclose(
        state.max_weight_limit, MAX_WEIGHT_LIMIT, rel_tol=0.0, abs_tol=0.0
    ):
        raise UID30LaunchError("SN39 max_weight_limit differs from the launch pin")
    if state.commit_reveal_enabled is not COMMIT_REVEAL_ENABLED:
        raise UID30LaunchError("SN39 commit-reveal state differs from the launch pin")
    if state.weights_version_key != 0 and VERSION_KEY < state.weights_version_key:
        raise UID30LaunchError("the pinned weight version is not accepted by SN39")
    if state.miner_hotkey != MINER_HOTKEY:
        raise UID30LaunchError("the launch target is not the pinned Cathedral miner")
    if state.subnet_owner_hotkey in {UID30_HOTKEY, MINER_HOTKEY}:
        raise UID30LaunchError(
            "the subnet owner must remain distinct from UID30 and the verified miner"
        )
    if state.miner_uid == UID30:
        raise UID30LaunchError("UID30 cannot pay itself as the verified miner")
    if state.miner_uid < 0 or state.miner_uid > W:
        raise UID30LaunchError("the verified miner UID is not a u16")
    if (
        state.next_epoch_start_block
        != state.block_number + state.blocks_until_next_epoch
    ):
        raise UID30LaunchError("SN39 next-epoch facts disagree")
    if (
        not isinstance(state.uid_safety, Mapping)
        or state.uid_safety.get("status") != "read_only_current_mapping_only"
        or state.uid_safety.get("authorized_for_chain_write") is not False
    ):
        raise UID30LaunchError("the preview lacks its read-only current-mapping proof")
    return state


def _finalized_head(subtensor: Any) -> tuple[int, str]:
    substrate = getattr(subtensor, "substrate", None)
    if substrate is None:
        raise UID30LaunchError("subtensor has no finalized-head reader")
    try:
        block_hash = _canonical_hash(
            substrate.get_chain_finalised_head(), label="finalized block hash"
        )
        block = _strict_nonnegative_int(
            substrate.get_block_number(block_hash), label="finalized block"
        )
        reverse = _canonical_hash(
            substrate.get_block_hash(block), label="canonical finalized block hash"
        )
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchError("finalized chain head is unavailable") from exc
    if reverse != block_hash:
        raise UID30LaunchError("finalized block number and hash are not canonical")
    return block, block_hash


def _read_preflight() -> UID30ReadPreflight:
    """Read one finalized UID30 identity/policy snapshot without writer imports."""

    try:
        wallet = make_wallet(bt, name=WALLET_NAME, hotkey=WALLET_HOTKEY)
        subtensor = make_subtensor(bt, network=NETWORK)
        block, block_hash = _finalized_head(subtensor)
        genesis_hash = _canonical_hash(
            subtensor.substrate.get_block_hash(0), label="genesis hash"
        )
        metagraph = subtensor.metagraph(NETUID, block=block)
        metagraph_block = _strict_nonnegative_int(
            getattr(metagraph, "block", None), label="metagraph block"
        )
        if metagraph_block != block:
            raise UID30LaunchError("SN39 metagraph is not at the finalized head")
        raw_uids = (
            metagraph.uids.tolist()
            if hasattr(metagraph.uids, "tolist")
            else list(metagraph.uids)
        )
        uids = [
            _strict_nonnegative_int(value, label="metagraph UID") for value in raw_uids
        ]
        hotkeys = [str(value) for value in list(metagraph.hotkeys)]
        permits = list(metagraph.validator_permit)
        if not (len(uids) == len(hotkeys) == len(permits)):
            raise UID30LaunchError("SN39 metagraph identity arrays are inconsistent")
        if len(set(uids)) != len(uids) or len(set(hotkeys)) != len(hotkeys):
            raise UID30LaunchError("SN39 metagraph repeats a UID or hotkey")
        hotkey_to_uid = dict(zip(hotkeys, uids))
        uid_to_hotkey = dict(zip(uids, hotkeys))
        validator_hotkey = str(wallet.hotkey.ss58_address)
        validator_uid = hotkey_to_uid.get(validator_hotkey)
        if isinstance(validator_uid, bool) or not isinstance(validator_uid, int):
            raise UID30LaunchError("validator hotkey is not registered on SN39")
        validator_index = uids.index(validator_uid)
        if (
            _strict_bool(
                permits[validator_index], label="finalized UID30 validator permit"
            )
            is not True
        ):
            raise UID30LaunchError("validator hotkey lacks a strict permit")
        blocks_until_next_epoch = _strict_nonnegative_int(
            subtensor.blocks_until_next_epoch(NETUID, block=block),
            label="blocks until next epoch",
        )
        next_epoch_start_block = _strict_nonnegative_int(
            subtensor.get_next_epoch_start_block(NETUID, block=block),
            label="next epoch start",
        )
        weights_rate_limit = _strict_nonnegative_int(
            subtensor.weights_rate_limit(NETUID, block=block),
            label="SN39 weight cooldown",
        )
        blocks_since_update = _strict_nonnegative_int(
            subtensor.blocks_since_last_update(NETUID, validator_uid, block=block),
            label="blocks since UID30 update",
        )
        commit_reveal = _strict_bool(
            subtensor.commit_reveal_enabled(netuid=NETUID, block=block),
            label="SN39 commit-reveal state",
        )
        preflight = UID30ReadPreflight(
            wallet=wallet,
            subtensor=subtensor,
            hotkey_to_uid=hotkey_to_uid,
            uid_to_hotkey=uid_to_hotkey,
            validator_hotkey=validator_hotkey,
            validator_uid=validator_uid,
            block=block,
            finalized_hash=block_hash,
            min_allowed_weights=_strict_nonnegative_int(
                subtensor.min_allowed_weights(netuid=NETUID, block=block),
                label="minimum allowed weights",
            ),
            max_weight_limit=float(
                subtensor.max_weight_limit(netuid=NETUID, block=block)
            ),
            commit_reveal_enabled=commit_reveal,
            genesis_hash=genesis_hash,
            subnet_owner_hotkey=str(
                subtensor.get_subnet_owner_hotkey(NETUID, block=block) or ""
            ),
            blocks_until_next_epoch=blocks_until_next_epoch,
            next_epoch_start_block=next_epoch_start_block,
            weights_rate_limit=weights_rate_limit,
            validator_blocks_since_last_update=blocks_since_update,
        )
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchError(f"UID30 read-only preflight failed: {exc}") from exc
    return preflight


def read_uid30_chain_state() -> UID30ChainState:
    """Read every mutable UID30 fact at one canonical finalized head."""

    try:
        preflight = _read_preflight()
        block = preflight.block
        block_hash = preflight.finalized_hash
        if preflight.genesis_hash != FINNEY_GENESIS_HASH:
            raise UID30LaunchError("chain preflight resolved the wrong genesis")
        info = preflight.subtensor.get_metagraph_info(NETUID, MECID, block=block)
        if info is None:
            raise UID30LaunchError("SN39 metagraph info is unavailable")
        info_block = _strict_nonnegative_int(
            getattr(info, "block", None), label="metagraph block"
        )
        if info_block != block:
            raise UID30LaunchError("SN39 metagraph info is not at the finalized head")
        hotkeys = [str(value) for value in list(info.hotkeys)]
        axons = list(info.axons)
        permits = list(info.validator_permit)
        total_stakes = list(info.total_stake)
        last_updates = [
            _strict_nonnegative_int(value, label="last update")
            for value in list(info.last_update)
        ]
        if not (
            len(hotkeys)
            == len(axons)
            == len(permits)
            == len(total_stakes)
            == len(last_updates)
        ):
            raise UID30LaunchError("SN39 metagraph eligibility arrays are inconsistent")
        if preflight.validator_uid < 0 or preflight.validator_uid >= len(hotkeys):
            raise UID30LaunchError("UID30 index is outside the metagraph")
        if hotkeys[preflight.validator_uid] != preflight.validator_hotkey:
            raise UID30LaunchError("UID30 hotkey mapping changed during preflight")
        threshold = _strict_nonnegative_int(
            preflight.subtensor.substrate.query(
                module="SubtensorModule",
                storage_function="StakeThreshold",
                params=[],
                block_hash=block_hash,
            ),
            label="weight stake threshold",
        )
        stake = _balance_rao(
            total_stakes[preflight.validator_uid], label="validator effective stake"
        )
        mechanism_count = _strict_nonnegative_int(
            preflight.subtensor.get_mechanism_count(NETUID, block=block),
            label="SN39 mechanism count",
        )
        weights_version_key = _strict_nonnegative_int(
            preflight.subtensor.substrate.query(
                module="SubtensorModule",
                storage_function="WeightsVersionKey",
                params=[NETUID],
                block_hash=block_hash,
            ),
            label="SN39 weight version",
        )
        miner_uid = preflight.hotkey_to_uid.get(MINER_HOTKEY)
        if isinstance(miner_uid, bool) or not isinstance(miner_uid, int):
            raise UID30LaunchError(
                "the pinned Cathedral miner is not registered on SN39"
            )
        # This proof is intentionally not chain-write authority.  It binds the
        # current finalized bidirectional mapping only and makes no mortal-era
        # replacement-safety claim.
        if preflight.uid_to_hotkey.get(miner_uid) != MINER_HOTKEY:
            raise UID30LaunchError("the pinned miner mapping is not bidirectional")
        uid_safety = {
            "status": "read_only_current_mapping_only",
            "mapping_block": block,
            "uid_hotkeys": [[miner_uid, MINER_HOTKEY]],
            "authorized_for_chain_write": False,
        }
        serving_axon = _serving_axon_from_info_row(
            axons[miner_uid], uid=miner_uid, hotkey=MINER_HOTKEY
        )
        last_update = last_updates[preflight.validator_uid]
        state = UID30ChainState(
            preflight=preflight,
            block_number=block,
            block_hash=block_hash,
            genesis_hash=preflight.genesis_hash,
            subnet_owner_hotkey=str(preflight.subnet_owner_hotkey),
            validator_hotkey=preflight.validator_hotkey,
            validator_uid=preflight.validator_uid,
            validator_permit=_strict_bool(
                permits[preflight.validator_uid], label="UID30 validator permit"
            ),
            validator_stake_rao=stake,
            stake_threshold_rao=threshold,
            last_update=last_update,
            blocks_since_last_update=_strict_nonnegative_int(
                preflight.validator_blocks_since_last_update,
                label="blocks since UID30 update",
            ),
            weights_rate_limit=_strict_nonnegative_int(
                preflight.weights_rate_limit, label="SN39 weight cooldown"
            ),
            mechanism_count=mechanism_count,
            weights_version_key=weights_version_key,
            min_allowed_weights=preflight.min_allowed_weights,
            max_weight_limit=preflight.max_weight_limit,
            commit_reveal_enabled=preflight.commit_reveal_enabled,
            miner_hotkey=MINER_HOTKEY,
            miner_uid=miner_uid,
            serving_axon=serving_axon,
            next_epoch_start_block=_strict_nonnegative_int(
                preflight.next_epoch_start_block, label="next epoch start"
            ),
            blocks_until_next_epoch=_strict_nonnegative_int(
                preflight.blocks_until_next_epoch, label="blocks until next epoch"
            ),
            uid_safety=uid_safety,
        )
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchError(f"UID30 chain preflight failed: {exc}") from exc
    return validate_chain_state(state)


__all__ = [
    "MINER_HOTKEY",
    "NETWORK",
    "UID30",
    "UID30_HOTKEY",
    "WALLET_HOTKEY",
    "WALLET_NAME",
    "UID30ChainState",
    "UID30ReadPreflight",
    "UID30LaunchError",
    "read_uid30_chain_state",
    "validate_chain_state",
]
