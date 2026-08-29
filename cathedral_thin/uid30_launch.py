"""One reviewed UID30 launch preview and one digest-authorized submission.

This module deliberately does not extend the recurring validator.  It joins
three already-reviewed seams for one launch event:

* ``independent_runtime.run`` supplies live TLS, TDX QVL, and canonical SAT
  verification from PR 148;
* ``scaffold.validator_thin.chain_preflight`` supplies the finalized Finney
  identity, permit, cooldown, UID-replacement, and chain-policy checks; and
* the canonical validator's identity-derived submission lock and common
  ambiguity journal fence every sign, broadcast, and finalized readback.

The uncommitted independent-E2E extension's
``cathedral_thin/independent_runtime/chain.py`` at the PR 148 base was the
source for the additional StakeThreshold, raw ``last_update``, mechanism-count,
and weight-version checks. Those checks are reimplemented here against the
canonical ``ChainPreflight`` rather than importing or modifying that dirty
worktree.

Preview is the default posture.  A chain call requires all three of an
owner-only canonical preview, its matching detached SHA256, and the explicit
``--confirm-uid30-launch`` flag.  The preview fixes one registered, freshly
verified miner at u16 weight 65535 and carries no burn destination.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from bittensor.utils import get_mechid_storage_index

from cathedral_thin.independent.compute import ComputeAdapter, QuoteVerdict
from cathedral_thin.independent.constants import (
    COMMIT_REVEAL_ENABLED,
    FINNEY_GENESIS_HASH,
    INTEL_COLLATERAL,
    MAX_WEIGHT_LIMIT,
    MECID,
    MIN_ALLOWED_WEIGHTS,
    NETUID,
    SN39_MORTAL_PERIOD_BLOCKS,
    VERSION_KEY,
    W,
)
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from cathedral_thin.independent_runtime.chain import ServingAxon
from cathedral_thin.independent_runtime.qvl import LAUNCH_QVL_DIGEST, load_verifier
from cathedral_thin.independent_runtime.run import _try_collect, _units_after_quote
from cathedral_thin import second_miner_plan
from cathedral_thin.uid30_state import (
    MINER_HOTKEY,
    NETWORK,
    UID30,
    UID30_HOTKEY,
    WALLET_HOTKEY,
    WALLET_NAME,
    UID30ChainState,
    UID30LaunchError,
    _balance_rao,
    _canonical_hash,
    _raw_value,
    _require_ss58,
    _strict_nonnegative_int,
)
from scaffold import validator_thin as canonical_validator

PREVIEW_SCHEMA = canonical_validator.SN39_UID30_LAUNCH_SCHEMA
PREVIEW_STATUS = "READY_FOR_OPERATOR_REVIEW"
POLICY_ID = canonical_validator.SN39_UID30_LAUNCH_POLICY
DEFAULT_RUNTIME_ROOT = Path("/var/lib/cathedral-validator")
DEFAULT_PREVIEW = DEFAULT_RUNTIME_ROOT / "uid30-launch-preview.json"
DEFAULT_SUCCESSOR_PREVIEW = (
    DEFAULT_RUNTIME_ROOT / "uid30-two-miner-successor-preview.json"
)
MAX_PREVIEW_BYTES = 1_048_576
PREVIEW_VALIDITY_SECONDS = 15 * 60
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_CHAIN_HASH_RE = re.compile(r"0x[0-9a-f]{64}")


class UID30LaunchAmbiguous(UID30LaunchError):
    """A signed intent or receipt exists and no replacement is authorized."""


class UID30LaunchContradiction(UID30LaunchAmbiguous):
    """The exact signed attempt has a positive historical mismatch."""


@dataclass(frozen=True)
class UID30SuccessorState:
    """UID30 gates plus both pinned miners at the identical finalized head."""

    base: UID30ChainState
    targets: tuple[second_miner_plan.Neuron, ...]
    uid_safety: Mapping[str, Any]
    current_weights: tuple[tuple[int, int], ...]

    @property
    def preflight(self) -> Any:
        return self.base.preflight

    @property
    def block_number(self) -> int:
        return self.base.block_number

    @property
    def block_hash(self) -> str:
        return self.base.block_hash

    @property
    def genesis_hash(self) -> str:
        return self.base.genesis_hash

    @property
    def subnet_owner_hotkey(self) -> str:
        return self.base.subnet_owner_hotkey

    @property
    def next_epoch_start_block(self) -> int:
        return self.base.next_epoch_start_block


@dataclass(frozen=True)
class UID30SuccessorVerificationState:
    """Post-write read-only state for inclusion and later finalized proofs."""

    preflight: Any
    genesis_hash: str
    targets: tuple[second_miner_plan.Neuron, ...]


@dataclass(frozen=True)
class VerifiedMinerProof:
    """Fresh endpoint evidence for the only destination the launch pays."""

    hotkey: str
    uid: int
    ip: str
    port: int
    qvl_digest: str
    quote_sha256: str
    report_data_sha256: str
    tls_spki_sha256: str
    sat_units: int
    sat_rule: str
    anchor_number: int
    anchor_hash: str

    def artifact(self) -> dict[str, Any]:
        return {
            "hotkey": self.hotkey,
            "uid": self.uid,
            "ip": self.ip,
            "port": self.port,
            "qvl_digest": self.qvl_digest,
            "quote_sha256": self.quote_sha256,
            "report_data_sha256": self.report_data_sha256,
            "tls_spki_sha256": self.tls_spki_sha256,
            "sat_units": self.sat_units,
            "sat_rule": self.sat_rule,
            "anchor_number": self.anchor_number,
            "anchor_hash": self.anchor_hash,
        }


@dataclass(frozen=True)
class UID30SubmissionResult:
    preview_sha256: str
    attempt_id: str
    extrinsic_hash: str
    block_hash: str
    block_number: int
    miner_uid: int
    stored_weight: int


@dataclass(frozen=True)
class UID30RecoveryResult:
    status: str
    preview_sha256: str
    attempt_id: str
    extrinsic_hash: str | None
    block_hash: str | None
    block_number: int | None
    miner_uid: int
    stored_weight: int | None


@dataclass(frozen=True)
class UID30SuccessorSubmissionResult:
    preview_sha256: str
    attempt_id: str
    extrinsic_hash: str
    block_hash: str
    block_number: int
    wire_uids: tuple[int, int]
    wire_weights: tuple[int, int]
    later_finalized_heads: tuple[tuple[int, str], tuple[int, str]]


@dataclass(frozen=True)
class UID30SuccessorRecoveryResult:
    status: str
    preview_sha256: str
    attempt_id: str
    extrinsic_hash: str | None
    block_hash: str | None
    block_number: int | None
    wire_uids: tuple[int, int]
    wire_weights: tuple[int, int] | None
    later_finalized_heads: tuple[tuple[int, str], tuple[int, str]] | None


def _parse_utc(value: object, *, label: str) -> datetime:
    text = str(value or "")
    if not text.endswith("Z"):
        raise UID30LaunchError(f"{label} is not canonical UTC")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise UID30LaunchError(f"{label} is not canonical UTC") from exc
    if moment.tzinfo is None or moment.utcoffset() != timedelta(0):
        raise UID30LaunchError(f"{label} is not canonical UTC")
    return moment.astimezone(UTC)


def _canonical_utc(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise UID30LaunchError("launch time must be timezone-aware")
    value = moment.astimezone(UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _canonical_json_bytes(document: Mapping[str, Any]) -> bytes:
    try:
        encoded = (
            json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise UID30LaunchError(f"preview is not canonical JSON: {exc}") from exc
    if len(encoded) > MAX_PREVIEW_BYTES:
        raise UID30LaunchError("preview exceeds its size bound")
    return encoded


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest_text(value: object, *, label: str) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("sha256:"):
        text = text.removeprefix("sha256:")
    if _DIGEST_RE.fullmatch(text) is None:
        raise UID30LaunchError(f"{label} is not one lowercase SHA256")
    return text


def _require_public_ip(value: object) -> str:
    text = str(value or "")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise UID30LaunchError("verified miner address is not an IP address") from exc
    if not address.is_global or str(address) != text:
        raise UID30LaunchError(
            "verified miner address is not canonical public IP space"
        )
    return text


def _submission_contract(
    *,
    runtime_root: Path,
    genesis_hash: str,
    preview_sha256: str,
    authorized: bool = False,
) -> SimpleNamespace:
    """Build the exact identity used by the canonical writer lock and journal."""

    root = Path(runtime_root)
    if not root.is_absolute():
        raise UID30LaunchError("runtime root must be absolute")
    digest = _digest_text(preview_sha256, label="reviewed preview digest")
    return SimpleNamespace(
        network=NETWORK,
        netuid=NETUID,
        runtime_root=str(root),
        offline=False,
        broadcast=True,
        wallet_name=WALLET_NAME,
        wallet_hotkey=WALLET_HOTKEY,
        max_submissions=1,
        # The digest-authorized command is one launch attempt, not recurring
        # authority. This selects the canonical one-attempt launch budget and
        # bypasses no launch ceremony through the beta waiver.
        require_full_provenance_for_broadcast=authorized,
        require_policy=None,
        beta_skip_launch_ceremony=False,
        provenance="authority",
        _submission_validator_hotkey=UID30_HOTKEY,
        _submission_genesis_hash=genesis_hash,
        _uid30_reviewed_preview_sha256=digest,
    )


def _successor_submission_contract(
    *, runtime_root: Path, genesis_hash: str, preview_sha256: str
) -> SimpleNamespace:
    """Select only the fixed non-launch authority_bounded successor."""

    args = _submission_contract(
        runtime_root=runtime_root,
        genesis_hash=genesis_hash,
        preview_sha256=preview_sha256,
        authorized=False,
    )
    delattr(args, "_uid30_reviewed_preview_sha256")
    args._uid30_two_miner_successor_preview_sha256 = _digest_text(
        preview_sha256,
        label="reviewed successor preview digest",
    )
    return args


def _writer_paths(
    *, runtime_root: Path, genesis_hash: str, preview_sha256: str = "0" * 64
) -> tuple[Path, Path]:
    args = _submission_contract(
        runtime_root=runtime_root,
        genesis_hash=genesis_hash,
        preview_sha256=preview_sha256,
    )
    return (
        canonical_validator._submission_lock_path(args),
        canonical_validator._submission_state_path(args),
    )


def validate_chain_state(state: UID30ChainState) -> UID30ChainState:
    """Apply the fixed UID30, current-eligibility, and one-miner chain contract."""

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
    if state.weights_rate_limit < SN39_MORTAL_PERIOD_BLOCKS:
        raise UID30LaunchError("SN39 weight cooldown is shorter than the mortal era")
    if state.blocks_since_last_update != state.block_number - state.last_update:
        raise UID30LaunchError("UID30 last_update and cooldown distance disagree")
    if state.blocks_since_last_update < state.weights_rate_limit:
        raise UID30LaunchError("UID30 is still inside the current weight cooldown")
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
    if state.blocks_until_next_epoch < SN39_MORTAL_PERIOD_BLOCKS * 2:
        raise UID30LaunchError(
            "too few blocks remain for preview review and mortal inclusion"
        )
    if not isinstance(state.uid_safety, Mapping) or not state.uid_safety:
        raise UID30LaunchError("the verified miner has no UID replacement-safety proof")
    return state


def read_uid30_chain_state() -> UID30ChainState:
    """Read every mutable UID30 launch fact at one canonical finalized head."""

    try:
        preflight = canonical_validator.chain_preflight(
            network=NETWORK,
            netuid=NETUID,
            wallet_name=WALLET_NAME,
            wallet_hotkey=WALLET_HOTKEY,
        )
        block = _strict_nonnegative_int(preflight.block, label="finalized block")
        block_hash = _canonical_hash(
            preflight.finalized_hash, label="finalized block hash"
        )
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
        uid_safety = canonical_validator._require_uid_mapping_stability(
            preflight,
            {miner_uid: MINER_HOTKEY},
            mortal_period_blocks=SN39_MORTAL_PERIOD_BLOCKS,
        )
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
            validator_permit=permits[preflight.validator_uid] is True,
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


def validate_uid30_successor_state(
    state: UID30SuccessorState,
) -> UID30SuccessorState:
    """Require two pinned HTTPS axons and the exact predecessor storage row."""

    validate_chain_state(state.base)
    if len(state.targets) != 2:
        raise UID30LaunchError("successor requires exactly two finalized miners")
    targets = {target.hotkey: target for target in state.targets}
    if len(targets) != 2 or set(targets) != {
        MINER_HOTKEY,
        canonical_validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
    }:
        raise UID30LaunchError("successor targets are not the two pinned hotkeys")
    if len({target.uid for target in targets.values()}) != 2 or UID30 in {
        target.uid for target in targets.values()
    }:
        raise UID30LaunchError("successor UIDs are not two distinct miner UIDs")
    endpoints: set[tuple[str, int]] = set()
    for target in targets.values():
        if target.protocol != second_miner_plan.HTTPS_PROTOCOL:
            raise UID30LaunchError("successor miner axon is not HTTPS protocol 4")
        ip = _require_public_ip(target.ip)
        if target.port != second_miner_plan.HTTPS_PORT or not target.serving:
            raise UID30LaunchError("successor miner is not serving HTTPS port 8081")
        endpoints.add((ip, target.port))
    if len(endpoints) != 2:
        raise UID30LaunchError("successor miners do not have distinct HTTPS axons")
    if state.current_weights != (
        (canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, W),
    ):
        raise UID30LaunchError(
            "current UID30 row is not the exact finalized one-miner predecessor"
        )
    if not isinstance(state.uid_safety, Mapping) or not state.uid_safety:
        raise UID30LaunchError("successor has no combined UID safety proof")
    return state


def read_uid30_successor_state() -> UID30SuccessorState:
    """Read both miners at the exact finalized head used by UID30 preflight."""

    base = read_uid30_chain_state()
    try:
        snapshot = second_miner_plan.read_snapshot_at(
            subtensor=base.preflight.subtensor,
            block_number=base.block_number,
            block_hash=base.block_hash,
            genesis_hash=base.genesis_hash,
        )
        plan = second_miner_plan.build_plan(snapshot)
    except second_miner_plan.SecondMinerPlanError as exc:
        raise UID30LaunchError(f"two-miner finalized snapshot refused: {exc}") from exc
    if plan.get("status") != second_miner_plan.STATUS_PROOF:
        raise UID30LaunchError(
            "two-miner snapshot is not ready for fresh QVL and SAT proofs"
        )
    target_hotkeys = {
        MINER_HOTKEY,
        canonical_validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
    }
    rows = tuple(
        sorted(
            (row for row in snapshot.neurons if row.hotkey in target_hotkeys),
            key=lambda row: row.uid,
        )
    )
    if len(rows) != 2 or {row.hotkey for row in rows} != target_hotkeys:
        raise UID30LaunchError("two-miner finalized mapping is incomplete")
    primary = next(row for row in rows if row.hotkey == MINER_HOTKEY)
    if (
        primary.uid != base.miner_uid
        or primary.ip != base.serving_axon.ip
        or primary.port != base.serving_axon.port
    ):
        raise UID30LaunchError("primary miner differs across same-head readers")
    try:
        uid_safety = canonical_validator._require_uid_mapping_stability(
            base.preflight,
            {row.uid: row.hotkey for row in rows},
            mortal_period_blocks=SN39_MORTAL_PERIOD_BLOCKS,
        )
    except Exception as exc:
        raise UID30LaunchError(f"two-miner UID safety failed: {exc}") from exc
    return validate_uid30_successor_state(
        UID30SuccessorState(
            base=base,
            targets=rows,
            uid_safety=uid_safety,
            current_weights=snapshot.uid30_weights,
        )
    )


def _serving_axon_from_info_row(raw: Any, *, uid: int, hotkey: str) -> ServingAxon:
    """Decode the axon row already bound to the finalized metagraph info.

    Bittensor's ``MetagraphInfo.axons`` rows are dictionaries whose IPv4
    address is stored as a u32.  Capturing this row alongside the hotkey and
    policy arrays avoids a second metagraph RPC after the final preflight.
    """

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


def _finalized_serving_axon(state: UID30ChainState) -> ServingAxon:
    """Resolve the one launch endpoint at the exact validated finalized head."""

    axon = state.serving_axon
    if axon.uid != state.miner_uid or axon.hotkey != state.miner_hotkey:
        raise UID30LaunchError(
            "serving miner identity differs from the finalized mapping"
        )
    _require_public_ip(axon.ip)
    if axon.port != 8081:
        raise UID30LaunchError("verified miner is not serving the pinned TLS port 8081")
    return axon


def collect_verified_endpoint(
    *,
    state: Any,
    axon: ServingAxon,
    miner_hotkey: str,
    qvl_path: str,
) -> VerifiedMinerProof:
    """Collect QVL PASS and SAT from one finalized HTTPS endpoint."""

    try:
        _require_public_ip(axon.ip)
        if axon.hotkey != miner_hotkey or axon.port != 8081:
            raise UID30LaunchError("verified endpoint differs from its miner pin")
        row = _try_collect(
            axon.evidence_url(),
            miner_hotkey,
            UID30_HOTKEY,
            axon.sat_work_url(),
        )
        collected = row.get("collected")
        if collected is None:
            raise UID30LaunchError(
                f"miner evidence collection failed: {row.get('error')}"
            )
        qvl = load_verifier(qvl_path)
        verdict = ComputeAdapter(
            qvl,
            collateral_base_url=INTEL_COLLATERAL,
            qvl_digest=qvl.digest,
        ).verify_quote(collected.quote, expected_report_data=collected.report_data)
        if verdict is not QuoteVerdict.PASS:
            raise UID30LaunchError(f"miner quote verdict is {verdict.value}, not PASS")
        units = _units_after_quote(
            anchor_hash=state.block_hash,
            collected=collected,
            sat_url=axon.sat_work_url(),
        )
        if isinstance(units, bool) or not isinstance(units, int) or units <= 0:
            raise UID30LaunchError(
                "the pinned miner returned no positive canonical SAT units"
            )
        return VerifiedMinerProof(
            hotkey=miner_hotkey,
            uid=axon.uid,
            ip=axon.ip,
            port=axon.port,
            qvl_digest=qvl.digest,
            quote_sha256=_sha256(collected.quote),
            report_data_sha256=_sha256(collected.report_data),
            tls_spki_sha256=collected.channel_binding.digest.hex(),
            sat_units=units,
            sat_rule=SAT_WORK_UNIT_RULE,
            anchor_number=state.block_number,
            anchor_hash=state.block_hash,
        )
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchError(f"verified-miner collection failed: {exc}") from exc


def collect_verified_miner(
    state: UID30ChainState, *, qvl_path: str
) -> VerifiedMinerProof:
    """Collect fresh QVL and SAT from the exact finalized serving endpoint."""

    validate_chain_state(state)
    return collect_verified_endpoint(
        state=state,
        axon=_finalized_serving_axon(state),
        miner_hotkey=MINER_HOTKEY,
        qvl_path=qvl_path,
    )


def validate_verified_endpoint(
    proof: VerifiedMinerProof,
    *,
    state: Any,
    axon: ServingAxon,
    miner_hotkey: str,
) -> VerifiedMinerProof:
    """Bind one proof to its exact finalized endpoint and canonical anchor."""

    if proof.hotkey != miner_hotkey or axon.hotkey != miner_hotkey:
        raise UID30LaunchError("verified proof belongs to the wrong miner hotkey")
    if proof.uid != axon.uid or proof.uid == UID30:
        raise UID30LaunchError("verified proof belongs to the wrong miner UID")
    if proof.ip != axon.ip or proof.port != axon.port:
        raise UID30LaunchError("verified proof belongs to a different HTTPS axon")
    if proof.qvl_digest != LAUNCH_QVL_DIGEST:
        raise UID30LaunchError("verified proof used the wrong QVL binary")
    for value, label in (
        (proof.quote_sha256, "quote digest"),
        (proof.report_data_sha256, "report-data digest"),
        (proof.tls_spki_sha256, "TLS SPKI digest"),
    ):
        _digest_text(value, label=label)
    if proof.sat_rule != SAT_WORK_UNIT_RULE:
        raise UID30LaunchError("verified proof used the wrong SAT work rule")
    if (
        isinstance(proof.sat_units, bool)
        or not isinstance(proof.sat_units, int)
        or proof.sat_units <= 0
    ):
        raise UID30LaunchError("verified proof has no positive SAT units")
    if proof.port != 8081:
        raise UID30LaunchError("verified miner is not serving the pinned TLS port 8081")
    _require_public_ip(proof.ip)
    anchor_hash = _canonical_hash(proof.anchor_hash, label="miner evidence anchor hash")
    if proof.anchor_number > state.block_number:
        raise UID30LaunchError("miner evidence anchor is ahead of finality")
    try:
        canonical = _canonical_hash(
            state.preflight.subtensor.substrate.get_block_hash(proof.anchor_number),
            label="canonical miner evidence anchor",
        )
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchError("miner evidence anchor cannot be re-resolved") from exc
    if canonical != anchor_hash:
        raise UID30LaunchError("miner evidence anchor is not canonical")
    return proof


def validate_miner_proof(
    proof: VerifiedMinerProof, *, state: UID30ChainState
) -> VerifiedMinerProof:
    # Preserve the legacy one-miner validator. Its separate fresh-head check
    # below owns endpoint equality and canonical anchor re-resolution.
    if proof.hotkey != MINER_HOTKEY or proof.hotkey != state.miner_hotkey:
        raise UID30LaunchError("verified proof belongs to the wrong miner hotkey")
    if proof.uid != state.miner_uid or proof.uid == UID30:
        raise UID30LaunchError("verified proof belongs to the wrong miner UID")
    if proof.qvl_digest != LAUNCH_QVL_DIGEST:
        raise UID30LaunchError("verified proof used the wrong QVL binary")
    for value, label in (
        (proof.quote_sha256, "quote digest"),
        (proof.report_data_sha256, "report-data digest"),
        (proof.tls_spki_sha256, "TLS SPKI digest"),
    ):
        _digest_text(value, label=label)
    if proof.sat_rule != SAT_WORK_UNIT_RULE:
        raise UID30LaunchError("verified proof used the wrong SAT work rule")
    if (
        isinstance(proof.sat_units, bool)
        or not isinstance(proof.sat_units, int)
        or proof.sat_units <= 0
    ):
        raise UID30LaunchError("verified proof has no positive SAT units")
    if proof.port != 8081:
        raise UID30LaunchError("verified miner is not serving the pinned TLS port 8081")
    _require_public_ip(proof.ip)
    _canonical_hash(proof.anchor_hash, label="miner evidence anchor hash")
    return proof


def _successor_axon(target: second_miner_plan.Neuron) -> ServingAxon:
    assert target.ip is not None
    return ServingAxon(
        uid=target.uid,
        hotkey=target.hotkey,
        ip=target.ip,
        port=target.port,
    )


def collect_verified_successor_miners(
    state: UID30SuccessorState, *, qvl_path: str
) -> tuple[VerifiedMinerProof, VerifiedMinerProof]:
    """Collect fresh proof from both fixed finalized axons."""

    validate_uid30_successor_state(state)
    proofs = tuple(
        collect_verified_endpoint(
            state=state,
            axon=_successor_axon(target),
            miner_hotkey=target.hotkey,
            qvl_path=qvl_path,
        )
        for target in state.targets
    )
    assert len(proofs) == 2
    return proofs


def validate_successor_proofs(
    proofs: Sequence[VerifiedMinerProof], *, state: UID30SuccessorState
) -> tuple[VerifiedMinerProof, VerifiedMinerProof]:
    """Bind two proofs to distinct machines on the finalized head."""

    validate_uid30_successor_state(state)
    if len(proofs) != 2:
        raise UID30LaunchError("successor requires exactly two fresh miner proofs")
    proof_by_hotkey = {proof.hotkey: proof for proof in proofs}
    target_by_hotkey = {target.hotkey: target for target in state.targets}
    if len(proof_by_hotkey) != 2 or set(proof_by_hotkey) != set(target_by_hotkey):
        raise UID30LaunchError("successor proofs are not the two pinned hotkeys")
    validated = tuple(
        validate_verified_endpoint(
            proof_by_hotkey[target.hotkey],
            state=state,
            axon=_successor_axon(target),
            miner_hotkey=target.hotkey,
        )
        for target in state.targets
    )
    if (
        len({proof.tls_spki_sha256 for proof in validated}) != 2
        or len({(proof.ip, proof.port) for proof in validated}) != 2
    ):
        raise UID30LaunchError("successor proofs do not bind distinct machines")
    assert len(validated) == 2
    return validated


def _assert_writer_available(args: SimpleNamespace) -> None:
    try:
        with canonical_validator._submission_tick_lock(args, lane="authority"):
            state = canonical_validator._read_state(
                canonical_validator._submission_state_path(args)
            )
            if state.get("submission_pending_id") is not None:
                raise UID30LaunchError(
                    "the canonical ambiguity journal has a pending submission"
                )
            active_lane = state.get("submission_active_lane")
            if active_lane not in (None, "authority"):
                raise UID30LaunchError(
                    "the canonical writer is assigned to a different authority lane"
                )
            launch_attempts = state.get("submission_launch_attempt_ids", [])
            if not isinstance(launch_attempts, list) or launch_attempts:
                raise UID30LaunchError(
                    "the canonical one-shot launch attempt budget is not pristine"
                )
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchError(f"canonical writer is not exclusive: {exc}") from exc


def build_preview(
    *,
    state: UID30ChainState,
    miner: VerifiedMinerProof,
    runtime_root: Path = DEFAULT_RUNTIME_ROOT,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build one reviewable 100/0 artifact without signing or chain mutation."""

    validate_chain_state(state)
    validate_miner_proof(miner, state=state)
    writer_lock, ambiguity_journal = _writer_paths(
        runtime_root=Path(runtime_root), genesis_hash=state.genesis_hash
    )
    provisional = _submission_contract(
        runtime_root=Path(runtime_root),
        genesis_hash=state.genesis_hash,
        preview_sha256="0" * 64,
    )
    _assert_writer_available(provisional)
    valid_until_block = state.next_epoch_start_block - SN39_MORTAL_PERIOD_BLOCKS
    created = (
        _parse_utc(created_at, label="preview creation time")
        if created_at is not None
        else datetime.now(UTC)
    )
    timestamp = _canonical_utc(created)
    valid_until_time = _canonical_utc(
        created + timedelta(seconds=PREVIEW_VALIDITY_SECONDS)
    )
    document: dict[str, Any] = {
        "schema": PREVIEW_SCHEMA,
        "status": PREVIEW_STATUS,
        "created_at": timestamp,
        "valid_from_block": state.block_number,
        "valid_until_block": valid_until_block,
        "network": {
            "name": NETWORK,
            "netuid": NETUID,
            "mecid": MECID,
            "genesis_hash": state.genesis_hash,
            "subnet_owner_hotkey": state.subnet_owner_hotkey,
            "finalized_block": state.block_number,
            "finalized_hash": state.block_hash,
            "next_epoch_start_block": state.next_epoch_start_block,
            "blocks_until_next_epoch": state.blocks_until_next_epoch,
        },
        "inclusion_policy": {
            "valid_from_block": state.block_number,
            "valid_until_block": valid_until_block,
            "valid_from_time": timestamp,
            "valid_until_time": valid_until_time,
            "require_commit_reveal_disabled": True,
            "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
            "expected_next_epoch_start_block": state.next_epoch_start_block,
        },
        "validator": state.artifact(),
        "miner": miner.artifact(),
        "uid_safety": dict(state.uid_safety),
        "policy": {
            "id": POLICY_ID,
            "verified_miner_allocation": "1.0",
            "burn_allocation": "0.0",
        },
        "proposed_vector": {
            "dests": [state.miner_uid],
            "weights_u16": [W],
            "normalized": [[state.miner_uid, "1.0"]],
            "burn_destination": None,
            "burn_weight_u16": 0,
            "sum_u16": W,
        },
        "trust_boundary": {
            "qvl_binary_sha256": LAUNCH_QVL_DIGEST,
            "quote_binds": ["nonce", "miner_hotkey", "tls_spki"],
            "oci_image_digest": "NOT_PROVEN_BY_THIS_VALIDATOR_ARTIFACT",
        },
        "exclusivity": {
            "runtime_root": str(Path(runtime_root)),
            "canonical_writer_lock": str(writer_lock),
            "canonical_ambiguity_journal": str(ambiguity_journal),
            "local_writer_lock_available": True,
            "remote_writer_exclusivity": "operator_assertion_required",
        },
        "weight_submission": {
            "call": "SubtensorModule.set_mechanism_weights",
            "version_key": VERSION_KEY,
            "vector_built": True,
            "extrinsic_built": False,
            "signed": False,
            "submitted": False,
            "readback": None,
        },
    }
    validate_preview(document)
    return document


def validate_preview(document: Mapping[str, Any]) -> dict[str, Any]:
    """Reject any reviewed artifact not equal to the one UID30 launch contract."""

    preview = dict(document)
    if (
        preview.get("schema") != PREVIEW_SCHEMA
        or preview.get("status") != PREVIEW_STATUS
    ):
        raise UID30LaunchError(
            "preview schema or status is not the UID30 launch contract"
        )
    network = preview.get("network")
    inclusion = preview.get("inclusion_policy")
    validator = preview.get("validator")
    miner = preview.get("miner")
    policy = preview.get("policy")
    vector = preview.get("proposed_vector")
    submission = preview.get("weight_submission")
    exclusivity = preview.get("exclusivity")
    trust = preview.get("trust_boundary")
    uid_safety = preview.get("uid_safety")
    if not all(
        isinstance(value, Mapping)
        for value in (
            network,
            inclusion,
            validator,
            miner,
            policy,
            vector,
            submission,
            exclusivity,
            trust,
            uid_safety,
        )
    ):
        raise UID30LaunchError("preview is missing a required object")
    assert isinstance(network, Mapping)
    assert isinstance(inclusion, Mapping)
    assert isinstance(validator, Mapping)
    assert isinstance(miner, Mapping)
    assert isinstance(policy, Mapping)
    assert isinstance(vector, Mapping)
    assert isinstance(submission, Mapping)
    assert isinstance(exclusivity, Mapping)
    assert isinstance(trust, Mapping)
    assert isinstance(uid_safety, Mapping)
    if (
        network.get("name") != NETWORK
        or network.get("netuid") != NETUID
        or network.get("mecid") != MECID
        or network.get("genesis_hash") != FINNEY_GENESIS_HASH
        or _require_ss58(
            network.get("subnet_owner_hotkey"), label="preview subnet owner hotkey"
        )
        in {UID30_HOTKEY, MINER_HOTKEY}
        or _CHAIN_HASH_RE.fullmatch(str(network.get("finalized_hash", ""))) is None
    ):
        raise UID30LaunchError("preview network identity is not pinned Finney SN39")
    finalized_block = _strict_nonnegative_int(
        network.get("finalized_block"), label="preview finalized block"
    )
    valid_from = _strict_nonnegative_int(
        preview.get("valid_from_block"), label="preview valid-from block"
    )
    valid_until = _strict_nonnegative_int(
        preview.get("valid_until_block"), label="preview valid-until block"
    )
    next_epoch = _strict_nonnegative_int(
        network.get("next_epoch_start_block"), label="preview next epoch"
    )
    blocks_until_next_epoch = _strict_nonnegative_int(
        network.get("blocks_until_next_epoch"),
        label="preview blocks until next epoch",
    )
    if (
        valid_from != finalized_block
        or next_epoch != finalized_block + blocks_until_next_epoch
        or blocks_until_next_epoch < SN39_MORTAL_PERIOD_BLOCKS * 2
        or valid_until != next_epoch - SN39_MORTAL_PERIOD_BLOCKS
    ):
        raise UID30LaunchError("preview block validity is inconsistent")
    created = _parse_utc(preview.get("created_at"), label="preview creation time")
    policy_from_time = _parse_utc(
        inclusion.get("valid_from_time"), label="preview valid-from time"
    )
    policy_until_time = _parse_utc(
        inclusion.get("valid_until_time"), label="preview valid-until time"
    )
    if (
        inclusion.get("valid_from_block") != finalized_block
        or inclusion.get("valid_until_block") != valid_until
        or policy_from_time != created
        or policy_until_time - policy_from_time
        != timedelta(seconds=PREVIEW_VALIDITY_SECONDS)
        or inclusion.get("require_commit_reveal_disabled") is not True
        or inclusion.get("mortal_period_blocks") != SN39_MORTAL_PERIOD_BLOCKS
        or inclusion.get("expected_next_epoch_start_block") != next_epoch
    ):
        raise UID30LaunchError(
            "preview inclusion policy is not the bounded launch window"
        )
    if (
        validator.get("wallet_name") != WALLET_NAME
        or validator.get("wallet_hotkey") != WALLET_HOTKEY
        or validator.get("hotkey") != UID30_HOTKEY
        or validator.get("uid") != UID30
        or validator.get("validator_permit") is not True
    ):
        raise UID30LaunchError("preview validator is not cathedral/default at UID30")
    _require_ss58(validator.get("hotkey"), label="preview validator hotkey")
    stake = _strict_nonnegative_int(validator.get("stake_rao"), label="preview stake")
    threshold = _strict_nonnegative_int(
        validator.get("stake_threshold_rao"), label="preview stake threshold"
    )
    if stake < threshold:
        raise UID30LaunchError("preview validator is below the stake threshold")
    last_update = _strict_nonnegative_int(
        validator.get("last_update"), label="preview last update"
    )
    blocks_since = _strict_nonnegative_int(
        validator.get("blocks_since_last_update"),
        label="preview blocks since update",
    )
    rate_limit = _strict_nonnegative_int(
        validator.get("weights_rate_limit"), label="preview weight cooldown"
    )
    mechanism_count = _strict_nonnegative_int(
        validator.get("mechanism_count"), label="preview mechanism count"
    )
    chain_version = _strict_nonnegative_int(
        validator.get("weights_version_key"), label="preview weight version"
    )
    max_limit = validator.get("max_weight_limit")
    if (
        blocks_since != finalized_block - last_update
        or rate_limit < SN39_MORTAL_PERIOD_BLOCKS
        or blocks_since < rate_limit
        or mechanism_count <= MECID
        or (chain_version != 0 and VERSION_KEY < chain_version)
        or validator.get("min_allowed_weights") != MIN_ALLOWED_WEIGHTS
        or isinstance(max_limit, bool)
        or not isinstance(max_limit, (int, float))
        or not math.isclose(
            float(max_limit), MAX_WEIGHT_LIMIT, rel_tol=0.0, abs_tol=0.0
        )
        or validator.get("commit_reveal_enabled") is not COMMIT_REVEAL_ENABLED
    ):
        raise UID30LaunchError("preview validator eligibility or chain policy is stale")
    if (
        miner.get("hotkey") != MINER_HOTKEY
        or isinstance(miner.get("uid"), bool)
        or not isinstance(miner.get("uid"), int)
        or miner.get("uid") == UID30
        or miner.get("qvl_digest") != LAUNCH_QVL_DIGEST
        or miner.get("sat_rule") != SAT_WORK_UNIT_RULE
        or isinstance(miner.get("sat_units"), bool)
        or not isinstance(miner.get("sat_units"), int)
        or miner.get("sat_units") <= 0
        or miner.get("port") != 8081
    ):
        raise UID30LaunchError("preview miner is not the one verified launch target")
    _require_ss58(miner.get("hotkey"), label="preview miner hotkey")
    _require_public_ip(miner.get("ip"))
    miner_uid = int(miner["uid"])
    for key, label in (
        ("quote_sha256", "preview quote digest"),
        ("report_data_sha256", "preview report-data digest"),
        ("tls_spki_sha256", "preview TLS SPKI digest"),
    ):
        _digest_text(miner.get(key), label=label)
    _strict_nonnegative_int(
        miner.get("anchor_number"), label="preview evidence anchor number"
    )
    _canonical_hash(miner.get("anchor_hash"), label="preview evidence anchor hash")
    rotation = uid_safety.get("rotation")
    registration = uid_safety.get("registration")
    if not isinstance(rotation, Mapping) or not isinstance(registration, Mapping):
        raise UID30LaunchError("preview UID replacement-safety proof is malformed")
    targets = rotation.get("targets")
    replacement_safe_hotkeys = registration.get("replacement_safe_hotkeys")
    matching_targets = (
        [
            target
            for target in targets
            if isinstance(target, Mapping)
            and target.get("uid") == miner_uid
            and target.get("hotkey") == MINER_HOTKEY
            and target.get("registration_replacement_safe") is True
            and target.get("pending_coldkey_swap") is None
        ]
        if isinstance(targets, list)
        else []
    )
    rotation_mapping_hash = _canonical_hash(
        rotation.get("mapping_block_hash"),
        label="preview UID-safety mapping block hash",
    )
    if (
        uid_safety.get("schema") != "cathedral_sn39_uid_safety_v2"
        or uid_safety.get("stability_basis") != "operator_controlled_coldkeys"
        or uid_safety.get("excluded_hotkeys") != []
        or rotation.get("status") != canonical_validator.PASS
        or rotation.get("mapping_block") != finalized_block
        or rotation_mapping_hash != network.get("finalized_hash")
        or rotation.get("mortal_period_blocks") != SN39_MORTAL_PERIOD_BLOCKS
        or rotation.get("era_last_block")
        != finalized_block + SN39_MORTAL_PERIOD_BLOCKS - 1
        or not isinstance(targets, list)
        or len(targets) != 1
        or len(matching_targets) != 1
        or not isinstance(replacement_safe_hotkeys, list)
        or MINER_HOTKEY not in replacement_safe_hotkeys
    ):
        raise UID30LaunchError(
            "preview does not prove the miner UID stable for its era"
        )
    _require_ss58(
        matching_targets[0].get("coldkey"),
        label="preview UID-safety target coldkey",
    )
    if policy != {
        "id": POLICY_ID,
        "verified_miner_allocation": "1.0",
        "burn_allocation": "0.0",
    }:
        raise UID30LaunchError(
            "preview policy is not fixed 100 percent miner and zero burn"
        )
    if (
        vector.get("dests") != [miner_uid]
        or vector.get("weights_u16") != [W]
        or vector.get("normalized") != [[miner_uid, "1.0"]]
        or vector.get("burn_destination") is not None
        or vector.get("burn_weight_u16") != 0
        or vector.get("sum_u16") != W
    ):
        raise UID30LaunchError("preview vector is not exactly one miner at u16 65535")
    if submission != {
        "call": "SubtensorModule.set_mechanism_weights",
        "version_key": VERSION_KEY,
        "vector_built": True,
        "extrinsic_built": False,
        "signed": False,
        "submitted": False,
        "readback": None,
    }:
        raise UID30LaunchError("preview does not prove a no-write submission posture")
    if trust != {
        "qvl_binary_sha256": LAUNCH_QVL_DIGEST,
        "quote_binds": ["nonce", "miner_hotkey", "tls_spki"],
        "oci_image_digest": "NOT_PROVEN_BY_THIS_VALIDATOR_ARTIFACT",
    }:
        raise UID30LaunchError("preview trust boundary differs from the launch proof")
    runtime_root = Path(str(exclusivity.get("runtime_root", "")))
    if not runtime_root.is_absolute():
        raise UID30LaunchError("preview runtime root is not absolute")
    expected_lock, expected_journal = _writer_paths(
        runtime_root=runtime_root, genesis_hash=FINNEY_GENESIS_HASH
    )
    if (
        exclusivity.get("canonical_writer_lock") != str(expected_lock)
        or exclusivity.get("canonical_ambiguity_journal") != str(expected_journal)
        or exclusivity.get("local_writer_lock_available") is not True
        or exclusivity.get("remote_writer_exclusivity") != "operator_assertion_required"
    ):
        raise UID30LaunchError(
            "preview does not carry the canonical exclusivity contract"
        )
    return preview


def _successor_predecessor_artifact() -> dict[str, Any]:
    body: dict[str, Any] = {
        "attempt_id": canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_ID,
        "identity_sha256": (
            canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_IDENTITY_SHA256
        ),
        "intent_sha256": (
            canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_INTENT_SHA256
        ),
        "receipt_sha256": (
            canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_RECEIPT_SHA256
        ),
        "uid_safety_sha256": (
            canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID_SAFETY_SHA256
        ),
        "canonical_journal_filename": (
            canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
        ),
        "journal_identity_sha256": (
            canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_IDENTITY
        ),
        "original_journal_sha256": (
            canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256
        ),
        "extrinsic_hash": (
            canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH
        ),
        "block_hash": canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH,
        "block_number": canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK,
        "version_key": VERSION_KEY,
        "wire": [[canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_UID, W]],
    }
    return {**body, "sha256": canonical_validator._sha256_document(body)}


def _successor_proof_artifact(proof: VerifiedMinerProof) -> dict[str, Any]:
    return {**proof.artifact(), "qvl_status": canonical_validator.PASS}


def _assert_successor_writer_available(args: SimpleNamespace) -> None:
    """Require exact untouched predecessor bytes while holding the writer lock."""

    try:
        with canonical_validator._submission_tick_lock(args, lane="authority"):
            path = canonical_validator._submission_state_path(args)
            if (
                path.parent != DEFAULT_RUNTIME_ROOT
                or path.name
                != canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
                or canonical_validator._private_state_sha256(path)
                != canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256
            ):
                raise UID30LaunchError(
                    "canonical journal differs from the consumed UID30 predecessor"
                )
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchError(f"canonical successor writer refused: {exc}") from exc


def build_successor_preview(
    *,
    state: UID30SuccessorState,
    miners: Sequence[VerifiedMinerProof],
    runtime_root: Path = DEFAULT_RUNTIME_ROOT,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build the immutable two-miner successor without a chain mutation."""

    validate_uid30_successor_state(state)
    proofs = validate_successor_proofs(miners, state=state)
    args = _successor_submission_contract(
        runtime_root=Path(runtime_root),
        genesis_hash=state.genesis_hash,
        preview_sha256="0" * 64,
    )
    _assert_successor_writer_available(args)
    created = (
        _parse_utc(created_at, label="successor preview creation time")
        if created_at is not None
        else datetime.now(UTC)
    )
    timestamp = _canonical_utc(created)
    valid_until_block = state.next_epoch_start_block - SN39_MORTAL_PERIOD_BLOCKS
    uids, weights = second_miner_plan.equal_wire(
        state.targets[0].uid,
        state.targets[1].uid,
    )
    document: dict[str, Any] = {
        "schema": canonical_validator.SN39_UID30_SUCCESSOR_SCHEMA,
        "status": PREVIEW_STATUS,
        "created_at": timestamp,
        "valid_from_block": state.block_number,
        "valid_until_block": valid_until_block,
        "network": {
            "name": NETWORK,
            "netuid": NETUID,
            "mecid": MECID,
            "genesis_hash": state.genesis_hash,
            "subnet_owner_hotkey": state.subnet_owner_hotkey,
            "finalized_block": state.block_number,
            "finalized_hash": state.block_hash,
            "next_epoch_start_block": state.next_epoch_start_block,
            "blocks_until_next_epoch": state.base.blocks_until_next_epoch,
        },
        "inclusion_policy": {
            "valid_from_block": state.block_number,
            "valid_until_block": valid_until_block,
            "valid_from_time": timestamp,
            "valid_until_time": _canonical_utc(
                created + timedelta(seconds=PREVIEW_VALIDITY_SECONDS)
            ),
            "require_commit_reveal_disabled": True,
            "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
            "expected_next_epoch_start_block": state.next_epoch_start_block,
        },
        "validator": state.base.artifact(),
        "miners": [_successor_proof_artifact(proof) for proof in proofs],
        "uid_safety": dict(state.uid_safety),
        "policy": {
            "id": canonical_validator.SN39_UID30_SUCCESSOR_POLICY,
            "each_verified_miner_semantic_weight": "1.0",
            "burn_allocation": "0.0",
        },
        "proposed_vector": {
            "dests": uids,
            "weights_u16": weights,
            "normalized": [[uid, "1.0"] for uid in uids],
            "expected_storage": [[uid, weight] for uid, weight in zip(uids, weights)],
            "burn_destination": None,
            "burn_weight_u16": 0,
        },
        "predecessor": _successor_predecessor_artifact(),
        "exclusivity": {
            "runtime_root": str(Path(runtime_root)),
            "canonical_writer_lock": str(
                canonical_validator._submission_lock_path(args)
            ),
            "canonical_ambiguity_journal": str(
                canonical_validator._submission_state_path(args)
            ),
            "remote_writer_exclusivity": "operator_assertion_required",
        },
        "weight_submission": {
            "call": "SubtensorModule.set_mechanism_weights",
            "version_key": VERSION_KEY,
            "attempt_budget": {"scope": "authority_bounded", "limit": 1},
            "signed": False,
            "submitted": False,
            "later_finalized_heads_required": 2,
        },
    }
    return validate_successor_preview(document)


def validate_successor_preview(document: Mapping[str, Any]) -> dict[str, Any]:
    """Reject any artifact outside the fixed two-miner successor contract."""

    preview = dict(document)
    required = {
        "schema",
        "status",
        "created_at",
        "valid_from_block",
        "valid_until_block",
        "network",
        "inclusion_policy",
        "validator",
        "miners",
        "uid_safety",
        "policy",
        "proposed_vector",
        "predecessor",
        "exclusivity",
        "weight_submission",
    }
    if (
        set(preview) != required
        or preview.get("schema") != (canonical_validator.SN39_UID30_SUCCESSOR_SCHEMA)
        or preview.get("status") != PREVIEW_STATUS
    ):
        raise UID30LaunchError("successor preview schema or fields are not exact")
    network = preview.get("network")
    inclusion = preview.get("inclusion_policy")
    validator = preview.get("validator")
    miners = preview.get("miners")
    safety = preview.get("uid_safety")
    vector = preview.get("proposed_vector")
    exclusivity = preview.get("exclusivity")
    if (
        not all(
            isinstance(value, Mapping)
            for value in (network, inclusion, validator, safety, vector, exclusivity)
        )
        or not isinstance(miners, list)
        or len(miners) != 2
    ):
        raise UID30LaunchError("successor preview is missing a required object")
    assert isinstance(network, Mapping)
    assert isinstance(inclusion, Mapping)
    assert isinstance(validator, Mapping)
    assert isinstance(safety, Mapping)
    assert isinstance(vector, Mapping)
    assert isinstance(exclusivity, Mapping)
    block = _strict_nonnegative_int(
        network.get("finalized_block"),
        label="successor finalized block",
    )
    next_epoch = _strict_nonnegative_int(
        network.get("next_epoch_start_block"),
        label="successor next epoch",
    )
    created = _parse_utc(preview.get("created_at"), label="successor creation time")
    if (
        network.get("name") != NETWORK
        or network.get("netuid") != NETUID
        or network.get("mecid") != MECID
        or network.get("genesis_hash") != FINNEY_GENESIS_HASH
        or _canonical_hash(network.get("finalized_hash"), label="successor hash")
        != network.get("finalized_hash")
        or preview.get("valid_from_block") != block
        or preview.get("valid_until_block") != next_epoch - SN39_MORTAL_PERIOD_BLOCKS
        or inclusion.get("valid_from_block") != block
        or inclusion.get("valid_until_block") != preview.get("valid_until_block")
        or _parse_utc(inclusion.get("valid_from_time"), label="successor valid-from")
        != created
        or _parse_utc(inclusion.get("valid_until_time"), label="successor valid-until")
        - created
        != timedelta(seconds=PREVIEW_VALIDITY_SECONDS)
        or inclusion.get("require_commit_reveal_disabled") is not True
        or inclusion.get("mortal_period_blocks") != SN39_MORTAL_PERIOD_BLOCKS
        or inclusion.get("expected_next_epoch_start_block") != next_epoch
        or validator.get("hotkey") != UID30_HOTKEY
        or validator.get("uid") != UID30
        or validator.get("validator_permit") is not True
    ):
        raise UID30LaunchError("successor preview chain or signer gate differs")
    try:
        uid_hotkeys = sorted(
            [[row["uid"], row["hotkey"]] for row in miners],
            key=lambda row: row[0],
        )
    except (KeyError, TypeError) as exc:
        raise UID30LaunchError("successor miner rows are malformed") from exc
    if any(type(row[0]) is not int for row in uid_hotkeys):
        raise UID30LaunchError("successor miner UID is malformed")
    uids, weights = second_miner_plan.equal_wire(*(row[0] for row in uid_hotkeys))
    expected_vector = {
        "dests": uids,
        "weights_u16": weights,
        "normalized": [[uid, "1.0"] for uid in uids],
        "expected_storage": [[uid, weight] for uid, weight in zip(uids, weights)],
        "burn_destination": None,
        "burn_weight_u16": 0,
    }
    if (
        vector != expected_vector
        or preview.get("predecessor") != _successor_predecessor_artifact()
        or preview.get("policy")
        != {
            "id": canonical_validator.SN39_UID30_SUCCESSOR_POLICY,
            "each_verified_miner_semantic_weight": "1.0",
            "burn_allocation": "0.0",
        }
        or preview.get("weight_submission")
        != {
            "call": "SubtensorModule.set_mechanism_weights",
            "version_key": VERSION_KEY,
            "attempt_budget": {"scope": "authority_bounded", "limit": 1},
            "signed": False,
            "submitted": False,
            "later_finalized_heads_required": 2,
        }
    ):
        raise UID30LaunchError("successor vector, policy, or lineage differs")
    runtime_root = Path(str(exclusivity.get("runtime_root", "")))
    expected_args = _successor_submission_contract(
        runtime_root=runtime_root,
        genesis_hash=FINNEY_GENESIS_HASH,
        preview_sha256="0" * 64,
    )
    if (
        runtime_root != DEFAULT_RUNTIME_ROOT
        or exclusivity.get("canonical_writer_lock")
        != str(canonical_validator._submission_lock_path(expected_args))
        or exclusivity.get("canonical_ambiguity_journal")
        != str(canonical_validator._submission_state_path(expected_args))
        or exclusivity.get("remote_writer_exclusivity") != "operator_assertion_required"
    ):
        raise UID30LaunchError("successor preview exclusivity differs")
    evidence = [dict(row) for row in miners]
    identity = {
        "network": NETWORK,
        "netuid": NETUID,
        "mapping_block": block,
        "validator_hotkey": UID30_HOTKEY,
        "validator_uid": UID30,
        "source_epoch": block,
        "uid_weights": [[uid, 1.0] for uid in uids],
        "uid_hotkeys": uid_hotkeys,
        "allocation_contract": canonical_validator.SN39_UID30_SUCCESSOR_POLICY,
        "burn_destination": None,
        "burn_share": 0.0,
        "subnet_owner_hotkey": network.get("subnet_owner_hotkey"),
        "uid_safety": dict(safety),
        "uid_safety_sha256": canonical_validator._sha256_document(
            dict(safety)
        ).removeprefix("sha256:"),
        "next_epoch_start_block": next_epoch,
        "successor_schema": canonical_validator.SN39_UID30_SUCCESSOR_SCHEMA,
        "successor_contract": canonical_validator.SN39_UID30_SUCCESSOR_POLICY,
        "successor_preview_sha256": "sha256:" + "0" * 64,
        "report_id": "sha256:" + "0" * 64,
        "operator_declared_authority": True,
        "exclusive_writer_assertion": {
            "asserted": True,
            "scope": "all_other_uid30_processes_and_hosts_stopped",
        },
        "reviewed_preview": {
            "valid_from_block": preview["valid_from_block"],
            "valid_until_block": preview["valid_until_block"],
            "miners": evidence,
            "vector": dict(vector),
            "predecessor": dict(preview["predecessor"]),
        },
        "fresh_miner_evidence": evidence,
        "fresh_evidence_sha256": canonical_validator._sha256_document(
            {"proofs": evidence}
        ).removeprefix("sha256:"),
        "predecessor": dict(preview["predecessor"]),
    }
    try:
        canonical_validator._strict_zero_burn_uid30_successor_contract(
            identity,
            lane="authority",
        )
    except Exception as exc:
        raise UID30LaunchError(f"successor preview contract is invalid: {exc}") from exc
    return preview


def _require_owner_only_file(path: Path, *, max_bytes: int) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise UID30LaunchError(f"owner-only file is unavailable: {path}") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > max_bytes
    ):
        raise UID30LaunchError(f"file must be owner-controlled mode 0600: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise UID30LaunchError(f"owner-only file could not be opened: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise UID30LaunchError("owner-only file changed while opening")
        data = os.read(descriptor, max_bytes + 1)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino)
            or after.st_size != info.st_size
            or len(data) != after.st_size
        ):
            raise UID30LaunchError("owner-only file changed while reading")
    finally:
        os.close(descriptor)
    if len(data) > max_bytes:
        raise UID30LaunchError("owner-only file exceeds its size bound")
    return data


def _write_exclusive_owner_only(path: Path, data: bytes) -> None:
    parent = path.parent
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_info = parent.lstat()
    except OSError as exc:
        raise UID30LaunchError(f"preview directory is unavailable: {parent}") from exc
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or stat.S_IMODE(parent_info.st_mode) & 0o077
    ):
        raise UID30LaunchError("preview directory must be owner-controlled mode 0700")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise UID30LaunchError(f"refusing to overwrite launch artifact {path}") from exc
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise UID30LaunchError("launch artifact write was short")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_preview(
    document: Mapping[str, Any], path: Path | str
) -> tuple[Path, Path, str]:
    """Create one immutable owner-only preview and detached SHA256."""

    validated = validate_preview(document)
    target = Path(path)
    if not target.is_absolute():
        raise UID30LaunchError("preview output path must be absolute")
    digest_path = target.with_suffix(target.suffix + ".sha256")
    data = _canonical_json_bytes(validated)
    digest = _sha256(data)
    _write_exclusive_owner_only(target, data)
    try:
        _write_exclusive_owner_only(digest_path, (digest + "\n").encode("ascii"))
    except Exception:
        # Keep the preview.  Its bytes remain reviewable, but submission requires
        # the detached digest and therefore stays impossible until an operator
        # deliberately resolves the partial local write.
        raise
    return target, digest_path, digest


def load_reviewed_preview(
    path: Path | str, *, reviewed_sha256: str
) -> tuple[dict[str, Any], str]:
    """Load exact canonical bytes and require both detached and supplied digests."""

    target = Path(path)
    supplied = _digest_text(reviewed_sha256, label="reviewed preview digest")
    raw = _require_owner_only_file(target, max_bytes=MAX_PREVIEW_BYTES)
    observed = _sha256(raw)
    if observed != supplied:
        raise UID30LaunchError(
            "reviewed preview digest does not match the preview bytes"
        )
    detached_path = target.with_suffix(target.suffix + ".sha256")
    detached = _require_owner_only_file(detached_path, max_bytes=128)
    try:
        detached_digest = _digest_text(
            detached.decode("ascii"), label="detached preview digest"
        )
    except UnicodeDecodeError as exc:
        raise UID30LaunchError("detached preview digest is not ASCII") from exc
    if detached_digest != supplied:
        raise UID30LaunchError("detached preview digest differs from reviewed digest")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise UID30LaunchError(f"preview contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UID30LaunchError(f"preview is not strict JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise UID30LaunchError("preview is not a JSON object")
    validated = validate_preview(document)
    if _canonical_json_bytes(validated) != raw:
        raise UID30LaunchError("preview bytes are not in the canonical JSON encoding")
    return validated, supplied


def write_successor_preview(
    document: Mapping[str, Any], path: Path | str
) -> tuple[Path, Path, str]:
    """Create one immutable owner-only successor preview and digest."""

    validated = validate_successor_preview(document)
    target = Path(path)
    if not target.is_absolute():
        raise UID30LaunchError("successor preview output path must be absolute")
    digest_path = target.with_suffix(target.suffix + ".sha256")
    data = _canonical_json_bytes(validated)
    digest = _sha256(data)
    _write_exclusive_owner_only(target, data)
    _write_exclusive_owner_only(digest_path, (digest + "\n").encode("ascii"))
    return target, digest_path, digest


def load_reviewed_successor_preview(
    path: Path | str, *, reviewed_sha256: str
) -> tuple[dict[str, Any], str]:
    """Load one byte-canonical, digest-authorized successor preview."""

    target = Path(path)
    supplied = _digest_text(reviewed_sha256, label="reviewed successor digest")
    raw = _require_owner_only_file(target, max_bytes=MAX_PREVIEW_BYTES)
    if _sha256(raw) != supplied:
        raise UID30LaunchError("reviewed successor digest differs from its bytes")
    detached = _require_owner_only_file(
        target.with_suffix(target.suffix + ".sha256"),
        max_bytes=128,
    )
    try:
        detached_digest = _digest_text(
            detached.decode("ascii"),
            label="detached successor digest",
        )
    except UnicodeDecodeError as exc:
        raise UID30LaunchError("detached successor digest is not ASCII") from exc
    if detached_digest != supplied:
        raise UID30LaunchError("detached successor digest differs from review")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise UID30LaunchError(f"successor preview duplicate key {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UID30LaunchError(f"successor preview is not strict JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise UID30LaunchError("successor preview is not a JSON object")
    validated = validate_successor_preview(document)
    if _canonical_json_bytes(validated) != raw:
        raise UID30LaunchError("successor preview bytes are not canonical JSON")
    return validated, supplied


def _preview_inclusion_policy(
    preview: Mapping[str, Any],
) -> canonical_validator.InclusionPolicy:
    raw = preview.get("inclusion_policy")
    if not isinstance(raw, Mapping):
        raise UID30LaunchError("reviewed preview has no inclusion policy")
    try:
        return canonical_validator.InclusionPolicy(
            valid_from_block=int(raw["valid_from_block"]),
            valid_until_block=int(raw["valid_until_block"]),
            valid_from_time=_parse_utc(
                raw["valid_from_time"], label="reviewed valid-from time"
            ),
            valid_until_time=_parse_utc(
                raw["valid_until_time"], label="reviewed valid-until time"
            ),
            require_commit_reveal_disabled=raw["require_commit_reveal_disabled"],
            mortal_period_blocks=int(raw["mortal_period_blocks"]),
            expected_next_epoch_start_block=int(raw["expected_next_epoch_start_block"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise UID30LaunchError("reviewed inclusion policy is malformed") from exc


def _fresh_state_matches_preview(
    fresh: UID30ChainState,
    preview: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> None:
    validate_chain_state(fresh)
    validator = preview["validator"]
    miner = preview["miner"]
    network = preview["network"]
    if (
        not isinstance(validator, Mapping)
        or not isinstance(miner, Mapping)
        or not isinstance(network, Mapping)
    ):
        raise UID30LaunchError("reviewed preview identity is malformed")
    if fresh.block_number > int(preview["valid_until_block"]):
        raise UID30LaunchError("reviewed preview expired before submission")
    reviewed_block = int(network["finalized_block"])
    reviewed_hash = _canonical_hash(
        network["finalized_hash"], label="reviewed finalized hash"
    )
    if fresh.block_number < reviewed_block:
        raise UID30LaunchError("finalized head regressed behind the reviewed preview")
    if (
        fresh.validator_hotkey != validator.get("hotkey")
        or fresh.validator_uid != validator.get("uid")
        or fresh.last_update != validator.get("last_update")
        or fresh.miner_hotkey != miner.get("hotkey")
        or fresh.miner_uid != miner.get("uid")
        or fresh.genesis_hash != network.get("genesis_hash")
        or fresh.subnet_owner_hotkey != network.get("subnet_owner_hotkey")
    ):
        raise UID30LaunchError(
            "UID30 last_update, signer, or miner mapping changed after review"
        )
    if fresh.block_number == reviewed_block:
        canonical_reviewed_hash = fresh.block_hash
    else:
        substrate = getattr(fresh.preflight.subtensor, "substrate", None)
        if substrate is None:
            raise UID30LaunchError(
                "fresh chain state cannot re-resolve the reviewed finalized hash"
            )
        try:
            canonical_reviewed_hash = _canonical_hash(
                substrate.get_block_hash(reviewed_block),
                label="canonical reviewed block hash",
            )
        except UID30LaunchError:
            raise
        except Exception as exc:
            raise UID30LaunchError(
                "fresh chain state cannot re-resolve the reviewed finalized hash"
            ) from exc
    if canonical_reviewed_hash != reviewed_hash:
        raise UID30LaunchError(
            "reviewed finalized hash is not canonical on the fresh chain head"
        )
    policy = _preview_inclusion_policy(preview)
    try:
        canonical_validator._require_inclusion_policy_ready(
            policy, fresh.preflight, now=now
        )
    except Exception as exc:
        raise UID30LaunchError(
            f"reviewed inclusion policy is no longer ready: {exc}"
        ) from exc


def _fresh_miner_matches_preview(
    fresh: VerifiedMinerProof,
    *,
    state: UID30ChainState,
    preview: Mapping[str, Any],
) -> None:
    validate_miner_proof(fresh, state=state)
    reviewed = preview.get("miner")
    if not isinstance(reviewed, Mapping):
        raise UID30LaunchError("reviewed miner proof is malformed")
    for key in (
        "hotkey",
        "uid",
        "ip",
        "port",
        "qvl_digest",
        "tls_spki_sha256",
    ):
        if fresh.artifact()[key] != reviewed.get(key):
            raise UID30LaunchError(
                f"fresh miner {key} differs from the reviewed endpoint"
            )
    _require_miner_on_finalized_head(fresh, state=state)


def _require_miner_on_finalized_head(
    fresh: VerifiedMinerProof, *, state: UID30ChainState
) -> None:
    """Re-resolve the proof anchor and endpoint at the latest finalized head."""

    current = _finalized_serving_axon(state)
    if (
        current.uid != fresh.uid
        or current.hotkey != fresh.hotkey
        or current.ip != fresh.ip
        or current.port != fresh.port
    ):
        raise UID30LaunchError(
            "the miner is no longer the same serving endpoint at the fresh finalized head"
        )
    if fresh.anchor_number > state.block_number:
        raise UID30LaunchError("fresh miner evidence anchor is ahead of finality")
    try:
        canonical_anchor = _canonical_hash(
            state.preflight.subtensor.substrate.get_block_hash(fresh.anchor_number),
            label="fresh miner evidence anchor hash",
        )
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchError(
            "fresh chain state cannot re-resolve the miner evidence anchor"
        ) from exc
    if canonical_anchor != fresh.anchor_hash:
        raise UID30LaunchError("fresh miner evidence anchor is not canonical")


def _fresh_successor_state_matches_preview(
    fresh: UID30SuccessorState,
    preview: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> None:
    validate_uid30_successor_state(fresh)
    network = preview.get("network")
    validator = preview.get("validator")
    miners = preview.get("miners")
    if (
        not isinstance(network, Mapping)
        or not isinstance(validator, Mapping)
        or not isinstance(miners, list)
    ):
        raise UID30LaunchError("reviewed successor identity is malformed")
    if fresh.block_number > int(preview["valid_until_block"]):
        raise UID30LaunchError("reviewed successor preview expired")
    reviewed_block = int(network["finalized_block"])
    reviewed_hash = _canonical_hash(
        network["finalized_hash"],
        label="reviewed successor hash",
    )
    try:
        canonical_reviewed_hash = _canonical_hash(
            fresh.preflight.subtensor.substrate.get_block_hash(reviewed_block),
            label="canonical successor review hash",
        )
    except Exception as exc:
        raise UID30LaunchError("successor review block cannot be re-resolved") from exc
    reviewed_miners = {
        str(row.get("hotkey")): row for row in miners if isinstance(row, Mapping)
    }
    fresh_targets = {target.hotkey: target for target in fresh.targets}
    if (
        fresh.block_number < reviewed_block
        or canonical_reviewed_hash != reviewed_hash
        or fresh.base.validator_hotkey != validator.get("hotkey")
        or fresh.base.validator_uid != validator.get("uid")
        or fresh.base.last_update != validator.get("last_update")
        or fresh.genesis_hash != network.get("genesis_hash")
        or fresh.subnet_owner_hotkey != network.get("subnet_owner_hotkey")
        or set(reviewed_miners) != set(fresh_targets)
        or any(
            reviewed_miners[hotkey].get("uid") != target.uid
            or reviewed_miners[hotkey].get("ip") != target.ip
            or reviewed_miners[hotkey].get("port") != target.port
            for hotkey, target in fresh_targets.items()
        )
    ):
        raise UID30LaunchError("successor signer, mapping, or axon changed")
    try:
        canonical_validator._require_inclusion_policy_ready(
            _preview_inclusion_policy(preview),
            fresh.preflight,
            now=now,
        )
    except Exception as exc:
        raise UID30LaunchError(f"successor inclusion window refused: {exc}") from exc


def _fresh_successor_proofs_match_preview(
    proofs: Sequence[VerifiedMinerProof],
    *,
    state: UID30SuccessorState,
    preview: Mapping[str, Any],
) -> tuple[VerifiedMinerProof, VerifiedMinerProof]:
    fresh = validate_successor_proofs(proofs, state=state)
    reviewed = preview.get("miners")
    if not isinstance(reviewed, list):
        raise UID30LaunchError("reviewed successor proofs are malformed")
    reviewed_by_hotkey = {
        str(row.get("hotkey")): row for row in reviewed if isinstance(row, Mapping)
    }
    for proof in fresh:
        row = reviewed_by_hotkey.get(proof.hotkey)
        if row is None or any(
            proof.artifact()[key] != row.get(key)
            for key in ("hotkey", "uid", "ip", "port", "qvl_digest", "tls_spki_sha256")
        ):
            raise UID30LaunchError("fresh successor proof changed machine identity")
    return fresh


def _successor_attempt_identity(
    *,
    preview: Mapping[str, Any],
    preview_sha256: str,
    state: UID30SuccessorState,
    fresh_miners: Sequence[VerifiedMinerProof],
) -> dict[str, Any]:
    proofs = validate_successor_proofs(fresh_miners, state=state)
    ordered = sorted(state.targets, key=lambda target: target.uid)
    uid_hotkeys = [[target.uid, target.hotkey] for target in ordered]
    evidence = [_successor_proof_artifact(proof) for proof in proofs]
    safety = dict(state.uid_safety)
    return {
        "network": NETWORK,
        "netuid": NETUID,
        "mapping_block": state.block_number,
        "validator_hotkey": UID30_HOTKEY,
        "validator_uid": UID30,
        "source_epoch": state.block_number,
        "uid_weights": [[uid, 1.0] for uid, _hotkey in uid_hotkeys],
        "uid_hotkeys": uid_hotkeys,
        "allocation_contract": canonical_validator.SN39_UID30_SUCCESSOR_POLICY,
        "burn_destination": None,
        "burn_share": 0.0,
        "subnet_owner_hotkey": state.subnet_owner_hotkey,
        "uid_safety": safety,
        "uid_safety_sha256": canonical_validator._sha256_document(safety).removeprefix(
            "sha256:"
        ),
        "next_epoch_start_block": state.next_epoch_start_block,
        "inclusion_policy": dict(preview["inclusion_policy"]),
        "successor_schema": canonical_validator.SN39_UID30_SUCCESSOR_SCHEMA,
        "successor_contract": canonical_validator.SN39_UID30_SUCCESSOR_POLICY,
        "successor_preview_sha256": "sha256:" + preview_sha256,
        "report_id": "sha256:" + preview_sha256,
        "operator_declared_authority": True,
        "exclusive_writer_assertion": {
            "asserted": True,
            "scope": "all_other_uid30_processes_and_hosts_stopped",
        },
        "reviewed_preview": {
            "valid_from_block": preview["valid_from_block"],
            "valid_until_block": preview["valid_until_block"],
            "miners": [dict(row) for row in preview["miners"]],
            "vector": dict(preview["proposed_vector"]),
            "predecessor": dict(preview["predecessor"]),
        },
        "fresh_miner_evidence": evidence,
        "fresh_evidence_sha256": canonical_validator._sha256_document(
            {"proofs": evidence}
        ).removeprefix("sha256:"),
        "predecessor": _successor_predecessor_artifact(),
    }


def _validate_successor_attempt_identity(
    identity: Mapping[str, Any],
    *,
    preview: Mapping[str, Any],
    preview_sha256: str,
) -> tuple[tuple[int, int], tuple[int, int], dict[int, str]]:
    """Bind a durable successor identity back to the reviewed preview bytes."""

    try:
        contract = canonical_validator._strict_zero_burn_uid30_successor_contract(
            dict(identity),
            lane="authority",
        )
    except Exception as exc:
        raise UID30LaunchError(
            f"journaled two-miner successor identity is invalid: {exc}"
        ) from exc
    network = preview.get("network")
    miners = preview.get("miners")
    vector = preview.get("proposed_vector")
    if (
        not isinstance(network, Mapping)
        or not isinstance(miners, list)
        or not isinstance(vector, Mapping)
    ):
        raise UID30LaunchError("reviewed successor preview is malformed")
    try:
        wire_uids = tuple(vector["dests"])
        wire_weights = tuple(vector["weights_u16"])
        uid_hotkeys = {row[0]: row[1] for row in identity["uid_hotkeys"]}
    except (KeyError, TypeError, ValueError) as exc:
        raise UID30LaunchError(
            "journaled successor vector identity is malformed"
        ) from exc
    expected_reviewed = {
        "valid_from_block": preview["valid_from_block"],
        "valid_until_block": preview["valid_until_block"],
        "miners": [dict(row) for row in miners],
        "vector": dict(vector),
        "predecessor": dict(preview["predecessor"]),
    }
    if (
        contract.get("kind") != "two_miner_successor"
        or tuple(uid for uid, _weight in contract["uid_weights"]) != wire_uids
        or tuple(weight for _uid, weight in contract["uid_weights"]) != (1.0, 1.0)
        or tuple(uid_hotkeys) != wire_uids
        or wire_weights != (W, W)
        or identity.get("network") != NETWORK
        or identity.get("netuid") != NETUID
        or identity.get("validator_hotkey") != UID30_HOTKEY
        or identity.get("validator_uid") != UID30
        or identity.get("allocation_contract")
        != canonical_validator.SN39_UID30_SUCCESSOR_POLICY
        or identity.get("burn_destination") is not None
        or identity.get("burn_share") != 0.0
        or identity.get("subnet_owner_hotkey") != network.get("subnet_owner_hotkey")
        or identity.get("next_epoch_start_block")
        != network.get("next_epoch_start_block")
        or identity.get("inclusion_policy") != preview.get("inclusion_policy")
        or identity.get("successor_preview_sha256") != "sha256:" + preview_sha256
        or identity.get("report_id") != "sha256:" + preview_sha256
        or identity.get("reviewed_preview") != expected_reviewed
        or identity.get("predecessor") != _successor_predecessor_artifact()
        or identity.get("exclusive_writer_assertion")
        != {
            "asserted": True,
            "scope": "all_other_uid30_processes_and_hosts_stopped",
        }
    ):
        raise UID30LaunchError(
            "journaled successor identity differs from the reviewed preview"
        )
    mapping_block = _strict_nonnegative_int(
        identity.get("mapping_block"),
        label="journaled successor mapping block",
    )
    policy = _preview_inclusion_policy(preview)
    if not policy.valid_from_block <= mapping_block < policy.valid_until_block:
        raise UID30LaunchError(
            "journaled successor mapping block is outside the reviewed window"
        )
    return (
        (wire_uids[0], wire_uids[1]),
        (wire_weights[0], wire_weights[1]),
        uid_hotkeys,
    )


def _attempt_identity(
    *,
    preview: Mapping[str, Any],
    preview_sha256: str,
    state: UID30ChainState,
    fresh_miner: VerifiedMinerProof,
) -> dict[str, Any]:
    return {
        "network": NETWORK,
        "netuid": NETUID,
        "mapping_block": state.block_number,
        "validator_hotkey": UID30_HOTKEY,
        "validator_uid": UID30,
        "source_epoch": state.block_number,
        "uid_weights": [[state.miner_uid, 1.0]],
        "uid_hotkeys": [[state.miner_uid, MINER_HOTKEY]],
        "allocation_contract": POLICY_ID,
        "burn_destination": None,
        "burn_share": 0.0,
        "subnet_owner_hotkey": state.subnet_owner_hotkey,
        "uid_safety": dict(state.uid_safety),
        "next_epoch_start_block": state.next_epoch_start_block,
        "inclusion_policy": dict(preview["inclusion_policy"]),
        "uid30_launch_schema": PREVIEW_SCHEMA,
        "uid30_launch_preview_sha256": "sha256:" + preview_sha256,
        "uid30_launch_policy": POLICY_ID,
        "report_id": "sha256:" + preview_sha256,
        "exclusive_writer_assertion": {
            "asserted": True,
            "scope": "all_other_uid30_processes_and_hosts_stopped",
        },
        "reviewed_preview": {
            "valid_from_block": preview["valid_from_block"],
            "valid_until_block": preview["valid_until_block"],
            "miner": dict(preview["miner"]),
            "vector": dict(preview["proposed_vector"]),
        },
        "fresh_miner_evidence": fresh_miner.artifact(),
    }


def _attempt_id(identity: Mapping[str, Any]) -> str:
    return canonical_validator._reviewed_uid30_attempt_id(dict(identity))


def _receipt_submission(receipt: Any, *, state: UID30ChainState) -> Any:
    extrinsic_hash = _canonical_hash(
        getattr(receipt, "extrinsic_hash", None), label="submission extrinsic hash"
    )
    block_hash = _canonical_hash(
        getattr(receipt, "block_hash", None), label="submission block hash"
    )
    block_number_raw = getattr(receipt, "block_number", None)
    if block_number_raw is None:
        block_number_raw = state.preflight.subtensor.substrate.get_block_number(
            block_hash
        )
    block_number = _strict_nonnegative_int(
        block_number_raw, label="submission block number"
    )
    success = getattr(receipt, "is_success", None)
    if success is not True:
        raise UID30LaunchAmbiguous("submission returned no explicit successful receipt")
    return canonical_validator.ChainSubmission(
        success=True,
        extrinsic_hash=extrinsic_hash,
        block_hash=block_hash,
        block_number=block_number,
        # Finality is established only by _finalized_readback against the
        # canonical finalized head. Do not trust an SDK receipt flag here.
        finalized=False,
    )


def _finalized_readback(
    *,
    state: UID30ChainState,
    submission: Any,
    receipt: Any,
    identity: Mapping[str, Any],
    require_receipt: bool = True,
    wire_uids: Sequence[int] | None = None,
    wire_weights: Sequence[int] | None = None,
    uid_hotkeys: Mapping[int, str] | None = None,
) -> Mapping[str, Any]:
    """Prove the exact signed call, its execution, finality, and stored vector."""

    substrate = state.preflight.subtensor.substrate
    block_hash = _canonical_hash(submission.block_hash, label="readback block hash")
    canonical = _canonical_hash(
        substrate.get_block_hash(submission.block_number),
        label="canonical readback hash",
    )
    finalized_head = _canonical_hash(
        substrate.get_chain_finalised_head(), label="current finalized head"
    )
    finalized_number = _strict_nonnegative_int(
        substrate.get_block_number(finalized_head), label="current finalized number"
    )
    if canonical != block_hash or submission.block_number > finalized_number:
        raise UID30LaunchAmbiguous("submission block is not on the finalized chain")
    policy = _preview_inclusion_policy(
        {"inclusion_policy": identity.get("inclusion_policy")}
    )
    owner = _require_ss58(
        identity.get("subnet_owner_hotkey"),
        label="submission subnet owner hotkey",
    )
    proof_reason: list[str] = []
    classifier = (
        canonical_validator._classify_finalized_receipt_awaiting_finality
        if require_receipt
        else canonical_validator._classify_finalized_receipt
    )
    exact_uids = list(wire_uids) if wire_uids is not None else [state.miner_uid]
    exact_weights = list(wire_weights) if wire_weights is not None else [W]
    exact_hotkeys = (
        dict(uid_hotkeys)
        if uid_hotkeys is not None
        else {state.miner_uid: MINER_HOTKEY}
    )
    proof = classifier(
        state.preflight.subtensor,
        receipt=receipt,
        extrinsic_hash=_canonical_hash(
            submission.extrinsic_hash, label="readback extrinsic hash"
        ),
        block_hash=block_hash,
        block_number=submission.block_number,
        validator_hotkey=UID30_HOTKEY,
        netuid=NETUID,
        version_key=VERSION_KEY,
        wire_uids=exact_uids,
        wire_weights=exact_weights,
        # Prove both ends of the reviewed contract at inclusion. The validator
        # hotkey being registered and permitted somewhere is insufficient: it
        # must still be the signer bound to UID30 at the receipt block.
        uid_hotkeys={
            **exact_hotkeys,
            UID30: UID30_HOTKEY,
        },
        expected_subnet_owner_hotkey=owner,
        inclusion_policy=policy,
        require_receipt=require_receipt,
        reason_out=proof_reason,
    )
    if proof != canonical_validator.PASS:
        reason = f": {proof_reason[-1]}" if proof_reason else ""
        error = (
            UID30LaunchContradiction
            if proof == canonical_validator.FAIL
            else UID30LaunchAmbiguous
        )
        raise error(f"exact finalized signed-call proof is {proof}{reason}")
    stored = substrate.query(
        module="SubtensorModule",
        storage_function="Weights",
        params=[get_mechid_storage_index(NETUID, MECID), UID30],
        block_hash=block_hash,
    )
    rows = _raw_value(stored)
    expected_list = [[uid, weight] for uid, weight in zip(exact_uids, exact_weights)]
    expected_tuple = list(zip(exact_uids, exact_weights))
    if rows != expected_list and rows != expected_tuple:
        raise UID30LaunchContradiction(
            "finalized UID30 mechanism weights differ from the exact reviewed vector"
        )
    return {
        "block_number": submission.block_number,
        "block_hash": block_hash,
        "validator_uid": UID30,
        "dests": exact_uids,
        "weights_u16": exact_weights,
        "exact_signed_call_proof": canonical_validator.PASS,
    }


def _verify_successor_later_finalized_heads(
    *,
    state: UID30SuccessorState | UID30SuccessorVerificationState,
    submission: Any,
    wire_uids: Sequence[int],
    wire_weights: Sequence[int],
) -> tuple[tuple[int, str], tuple[int, str]]:
    """Prove the complete successor row and fixed identities at two later heads."""

    exact_uids = tuple(wire_uids)
    exact_weights = tuple(wire_weights)
    if (
        len(exact_uids) != 2
        or len(exact_weights) != 2
        or any(type(uid) is not int for uid in exact_uids)
        or any(type(weight) is not int for weight in exact_weights)
        or tuple(sorted(exact_uids)) != exact_uids
        or exact_weights != (W, W)
    ):
        raise UID30LaunchContradiction(
            "later-head verification received a noncanonical successor vector"
        )
    reviewed_targets = {target.uid: target for target in state.targets}
    reviewed_hotkeys = {uid: target.hotkey for uid, target in reviewed_targets.items()}
    if set(reviewed_hotkeys) != set(exact_uids) or set(reviewed_hotkeys.values()) != {
        MINER_HOTKEY,
        canonical_validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
    }:
        raise UID30LaunchContradiction(
            "later-head verification received different reviewed miner UIDs"
        )

    substrate = state.preflight.subtensor.substrate
    try:
        finalized_hash = _canonical_hash(
            substrate.get_chain_finalised_head(),
            label="later finalized head hash",
        )
        finalized_number = _strict_nonnegative_int(
            substrate.get_block_number(finalized_hash),
            label="later finalized head number",
        )
        if (
            _canonical_hash(
                substrate.get_block_hash(finalized_number),
                label="reverse-bound later finalized head hash",
            )
            != finalized_hash
        ):
            raise UID30LaunchAmbiguous(
                "later finalized head number and hash do not match"
            )
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchAmbiguous(
            f"later finalized head could not be read: {exc}"
        ) from exc

    inclusion_number = _strict_nonnegative_int(
        submission.block_number,
        label="successor inclusion block number",
    )
    if finalized_number < inclusion_number + 2:
        raise UID30LaunchAmbiguous(
            "two strictly later finalized heads are not available yet"
        )

    proven: list[tuple[int, str]] = []
    for block_number in (finalized_number - 1, finalized_number):
        if block_number <= inclusion_number:
            raise UID30LaunchAmbiguous(
                "later-head verification did not select two post-inclusion heads"
            )
        try:
            block_hash = _canonical_hash(
                substrate.get_block_hash(block_number),
                label=f"later finalized block {block_number} hash",
            )
            snapshot = second_miner_plan.read_snapshot_at(
                subtensor=state.preflight.subtensor,
                block_number=block_number,
                block_hash=block_hash,
                genesis_hash=state.genesis_hash,
            )
        except (UID30LaunchError, second_miner_plan.SecondMinerPlanError) as exc:
            raise UID30LaunchAmbiguous(
                f"later finalized block {block_number} could not be proven: {exc}"
            ) from exc

        if snapshot.uid30_weights != tuple(zip(exact_uids, exact_weights)):
            raise UID30LaunchContradiction(
                f"UID30 successor row changed at finalized block {block_number}"
            )
        by_hotkey: dict[str, list[second_miner_plan.Neuron]] = {}
        by_uid: dict[int, list[second_miner_plan.Neuron]] = {}
        for neuron in snapshot.neurons:
            by_hotkey.setdefault(neuron.hotkey, []).append(neuron)
            by_uid.setdefault(neuron.uid, []).append(neuron)
        validator_rows = by_hotkey.get(UID30_HOTKEY, [])
        if (
            len(validator_rows) != 1
            or validator_rows[0].uid != UID30
            or validator_rows[0].validator_permit is not True
            or len(by_uid.get(UID30, [])) != 1
            or by_uid[UID30][0].hotkey != UID30_HOTKEY
        ):
            raise UID30LaunchContradiction(
                f"UID30 signer mapping or permit changed at finalized block {block_number}"
            )
        for uid, hotkey in reviewed_hotkeys.items():
            reviewed_target = reviewed_targets[uid]
            observed_target = by_uid.get(uid, [])
            if (
                len(by_hotkey.get(hotkey, [])) != 1
                or by_hotkey[hotkey][0].uid != uid
                or len(observed_target) != 1
                or observed_target[0].hotkey != hotkey
            ):
                raise UID30LaunchContradiction(
                    "successor miner hotkey-to-UID mapping changed at finalized "
                    f"block {block_number}"
                )
            observed = observed_target[0]
            if (
                observed.ip != reviewed_target.ip
                or observed.port != reviewed_target.port
                or observed.protocol != reviewed_target.protocol
                or observed.serving is not True
                or observed.port != second_miner_plan.HTTPS_PORT
                or observed.protocol != second_miner_plan.HTTPS_PROTOCOL
            ):
                raise UID30LaunchContradiction(
                    "successor miner serving axon changed at finalized "
                    f"block {block_number}"
                )
        proven.append((block_number, block_hash))
    return proven[0], proven[1]


def submit_reviewed_successor(
    *,
    preview_path: Path | str,
    reviewed_sha256: str,
    qvl_path: str,
    confirm: bool,
    exclusive_writer_asserted: bool = False,
) -> UID30SuccessorSubmissionResult:
    """Submit the fixed two-miner successor once through the canonical writer."""

    if confirm is not True:
        raise UID30LaunchError(
            "--confirm-uid30-successor is required; no chain call made"
        )
    if exclusive_writer_asserted is not True:
        raise UID30LaunchError(
            "--assert-exclusive-writer is required; stop every other UID30 writer"
        )
    preview, digest = load_reviewed_successor_preview(
        preview_path,
        reviewed_sha256=reviewed_sha256,
    )
    exclusivity = preview["exclusivity"]
    network = preview["network"]
    assert isinstance(exclusivity, Mapping)
    assert isinstance(network, Mapping)
    runtime_root = Path(str(exclusivity["runtime_root"]))
    if runtime_root != DEFAULT_RUNTIME_ROOT:
        raise UID30LaunchError(
            f"live UID30 submission requires canonical runtime root {DEFAULT_RUNTIME_ROOT}"
        )
    args = _successor_submission_contract(
        runtime_root=runtime_root,
        genesis_hash=str(network["genesis_hash"]),
        preview_sha256=digest,
    )
    try:
        with canonical_validator._submission_tick_lock(args, lane="authority"):
            evidence_state = read_uid30_successor_state()
            _fresh_successor_state_matches_preview(
                evidence_state,
                preview,
            )
            collected = collect_verified_successor_miners(
                evidence_state,
                qvl_path=qvl_path,
            )
            # Evidence collection can cross a finalized block. Re-read all
            # mutable chain facts immediately before reserving the one attempt.
            fresh_state = read_uid30_successor_state()
            _fresh_successor_state_matches_preview(fresh_state, preview)
            fresh_miners = _fresh_successor_proofs_match_preview(
                collected,
                state=fresh_state,
                preview=preview,
            )
            identity = _successor_attempt_identity(
                preview=preview,
                preview_sha256=digest,
                state=fresh_state,
                fresh_miners=fresh_miners,
            )
            wire_uids, wire_weights, uid_hotkeys = _validate_successor_attempt_identity(
                identity,
                preview=preview,
                preview_sha256=digest,
            )
            attempt_id = _attempt_id(identity)
            try:
                canonical_validator._reserve_common_submission(
                    args,
                    lane="authority",
                    attempt_id=attempt_id,
                    identity=identity,
                )
            except Exception as exc:
                raise UID30LaunchError(
                    f"canonical ambiguity journal refused before signing: {exc}"
                ) from exc

            try:
                receipt = canonical_validator._submit_exact_sn39_extrinsic(
                    fresh_state.preflight,
                    runtime_contract=args,
                    attempt_id=attempt_id,
                    netuid=NETUID,
                    version_key=VERSION_KEY,
                    wire_uids=list(wire_uids),
                    wire_weights=list(wire_weights),
                    mortal_period_blocks=SN39_MORTAL_PERIOD_BLOCKS,
                    allow_reviewed_uid30_finalized_descendant=True,
                )
                submission = _receipt_submission(receipt, state=fresh_state)
                canonical_validator._record_pending_submission_receipt(
                    args,
                    attempt_id=attempt_id,
                    submission=submission,
                    version_key=VERSION_KEY,
                    wire_uids=list(wire_uids),
                    wire_weights=list(wire_weights),
                )
                readback = _finalized_readback(
                    state=fresh_state,
                    submission=submission,
                    receipt=receipt,
                    identity=identity,
                    wire_uids=wire_uids,
                    wire_weights=wire_weights,
                    uid_hotkeys=uid_hotkeys,
                )
                if (
                    tuple(readback.get("dests", ())) != wire_uids
                    or tuple(readback.get("weights_u16", ())) != wire_weights
                ):
                    raise UID30LaunchContradiction(
                        "finalized readback differs from the reviewed successor vector"
                    )
                later_heads = _verify_successor_later_finalized_heads(
                    state=fresh_state,
                    submission=submission,
                    wire_uids=wire_uids,
                    wire_weights=wire_weights,
                )
                canonical_validator._record_pending_proof_status(
                    args,
                    attempt_id=attempt_id,
                    status=canonical_validator.PASS,
                )
                canonical_validator._finalize_common_submission(
                    args,
                    attempt_id=attempt_id,
                    submission=canonical_validator.ChainSubmission(
                        success=True,
                        extrinsic_hash=submission.extrinsic_hash,
                        block_hash=submission.block_hash,
                        block_number=submission.block_number,
                        finalized=True,
                    ),
                    version_key=VERSION_KEY,
                )
            except UID30LaunchContradiction as exc:
                try:
                    canonical_validator._record_pending_proof_status(
                        args,
                        attempt_id=attempt_id,
                        status=canonical_validator.FAIL,
                    )
                except Exception as persist_exc:
                    raise UID30LaunchContradiction(
                        f"{exc}; the mismatch could not be recorded, so every "
                        "writer must remain stopped"
                    ) from persist_exc
                raise
            except UID30LaunchAmbiguous:
                raise
            except Exception as exc:
                try:
                    safely_aborted = (
                        canonical_validator._abort_unsigned_common_submission(
                            args,
                            attempt_id=attempt_id,
                        )
                    )
                except Exception:
                    safely_aborted = False
                if safely_aborted:
                    raise UID30LaunchError(
                        f"successor submission refused before signed intent: {exc}"
                    ) from exc
                raise UID30LaunchAmbiguous(
                    "successor signed intent or receipt remains in the canonical "
                    "journal; do not retry or submit a replacement"
                ) from exc
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchError(
            f"canonical successor writer lock refused: {exc}"
        ) from exc
    return UID30SuccessorSubmissionResult(
        preview_sha256=digest,
        attempt_id=attempt_id,
        extrinsic_hash=str(submission.extrinsic_hash),
        block_hash=str(submission.block_hash),
        block_number=int(submission.block_number),
        wire_uids=wire_uids,
        wire_weights=wire_weights,
        later_finalized_heads=later_heads,
    )


def submit_reviewed_preview(
    *,
    preview_path: Path | str,
    reviewed_sha256: str,
    qvl_path: str,
    confirm: bool,
    exclusive_writer_asserted: bool = False,
    chain_loader: Callable[[], UID30ChainState] = read_uid30_chain_state,
    miner_loader: Callable[..., VerifiedMinerProof] = collect_verified_miner,
    submit_call: Callable[..., Any] | None = None,
    readback_call: Callable[..., Mapping[str, Any]] | None = None,
    now: datetime | None = None,
) -> UID30SubmissionResult:
    """Submit once after digest review, or leave a durable ambiguity fence."""

    if confirm is not True:
        raise UID30LaunchError("--confirm-uid30-launch is required; no chain call made")
    if exclusive_writer_asserted is not True:
        raise UID30LaunchError(
            "--assert-exclusive-writer is required; stop every other UID30 writer"
        )
    preview, digest = load_reviewed_preview(
        preview_path, reviewed_sha256=reviewed_sha256
    )
    exclusivity = preview["exclusivity"]
    network = preview["network"]
    assert isinstance(exclusivity, Mapping)
    assert isinstance(network, Mapping)
    runtime_root = Path(str(exclusivity["runtime_root"]))
    if runtime_root != DEFAULT_RUNTIME_ROOT:
        raise UID30LaunchError(
            f"live UID30 submission requires canonical runtime root {DEFAULT_RUNTIME_ROOT}"
        )
    args = _submission_contract(
        runtime_root=runtime_root,
        genesis_hash=str(network["genesis_hash"]),
        preview_sha256=digest,
        authorized=True,
    )
    try:
        lock = canonical_validator._submission_tick_lock(args, lane="authority")
        with lock:
            evidence_state = chain_loader()
            _fresh_state_matches_preview(evidence_state, preview, now=now)
            fresh_miner = miner_loader(evidence_state, qvl_path=qvl_path)
            # QVL collateral and SAT replay can span a block. Re-read every
            # mutable chain gate after evidence collection so the canonical
            # exact signer receives the latest finalized head immediately.
            fresh_state = chain_loader()
            _fresh_state_matches_preview(fresh_state, preview, now=now)
            _fresh_miner_matches_preview(
                fresh_miner, state=fresh_state, preview=preview
            )
            identity = _attempt_identity(
                preview=preview,
                preview_sha256=digest,
                state=fresh_state,
                fresh_miner=fresh_miner,
            )
            attempt_id = _attempt_id(identity)
            try:
                canonical_validator._reserve_common_submission(
                    args,
                    lane="authority",
                    attempt_id=attempt_id,
                    identity=identity,
                )
            except Exception as exc:
                raise UID30LaunchError(
                    f"canonical ambiguity journal refused before signing: {exc}"
                ) from exc
            wire_uids = [fresh_state.miner_uid]
            wire_weights = [W]
            call = submit_call or canonical_validator._submit_exact_sn39_extrinsic
            submit_kwargs = {
                "runtime_contract": args,
                "attempt_id": attempt_id,
                "netuid": NETUID,
                "version_key": VERSION_KEY,
                "wire_uids": wire_uids,
                "wire_weights": wire_weights,
                "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
            }
            if submit_call is None:
                # Only this digest-reviewed, zero-burn launch receives the
                # bounded canonical-descendant allowance.  Test doubles and
                # every generic/recurring canonical caller retain the original
                # exact-head contract unless they invoke this production seam.
                submit_kwargs["allow_reviewed_uid30_finalized_descendant"] = True
            try:
                receipt = call(
                    fresh_state.preflight,
                    **submit_kwargs,
                )
                submission = _receipt_submission(receipt, state=fresh_state)
                canonical_validator._record_pending_submission_receipt(
                    args,
                    attempt_id=attempt_id,
                    submission=submission,
                    version_key=VERSION_KEY,
                    wire_uids=wire_uids,
                    wire_weights=wire_weights,
                )
                if readback_call is None:
                    readback = _finalized_readback(
                        state=fresh_state,
                        submission=submission,
                        receipt=receipt,
                        identity=identity,
                    )
                else:
                    readback = readback_call(state=fresh_state, submission=submission)
                if (
                    readback.get("dests") != wire_uids
                    or readback.get("weights_u16") != wire_weights
                ):
                    raise UID30LaunchAmbiguous(
                        "finalized readback differs from the exact reviewed vector"
                    )
                canonical_validator._record_pending_proof_status(
                    args, attempt_id=attempt_id, status=canonical_validator.PASS
                )
                finalized_submission = canonical_validator.ChainSubmission(
                    success=True,
                    extrinsic_hash=submission.extrinsic_hash,
                    block_hash=submission.block_hash,
                    block_number=submission.block_number,
                    finalized=True,
                )
                canonical_validator._finalize_common_submission(
                    args,
                    attempt_id=attempt_id,
                    submission=finalized_submission,
                    version_key=VERSION_KEY,
                )
            except UID30LaunchContradiction as exc:
                try:
                    canonical_validator._record_pending_proof_status(
                        args, attempt_id=attempt_id, status=canonical_validator.FAIL
                    )
                except Exception as persist_exc:
                    raise UID30LaunchContradiction(
                        f"{exc}; the positive mismatch could not be recorded, "
                        "so every writer must remain stopped"
                    ) from persist_exc
                raise
            except UID30LaunchAmbiguous:
                raise
            except Exception as exc:
                safely_aborted = False
                try:
                    safely_aborted = (
                        canonical_validator._abort_unsigned_common_submission(
                            args, attempt_id=attempt_id
                        )
                    )
                except Exception:
                    safely_aborted = False
                if safely_aborted:
                    raise UID30LaunchError(
                        f"submission refused before signed intent: {exc}"
                    ) from exc
                raise UID30LaunchAmbiguous(
                    "signed intent or receipt remains in the canonical journal; "
                    "do not retry or submit a replacement"
                ) from exc
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchError(f"canonical writer lock refused: {exc}") from exc
    return UID30SubmissionResult(
        preview_sha256=digest,
        attempt_id=attempt_id,
        extrinsic_hash=str(submission.extrinsic_hash),
        block_hash=str(submission.block_hash),
        block_number=int(submission.block_number),
        miner_uid=fresh_state.miner_uid,
        stored_weight=W,
    )


def _validate_attempt_identity(
    identity: Mapping[str, Any],
    *,
    preview: Mapping[str, Any],
    preview_sha256: str,
) -> int:
    miner = preview["miner"]
    network = preview["network"]
    assert isinstance(miner, Mapping)
    assert isinstance(network, Mapping)
    miner_uid = int(miner["uid"])
    try:
        strict_owner = canonical_validator._strict_zero_burn_uid30_owner(
            dict(identity), lane="authority"
        )
    except canonical_validator.wire.VectorError as exc:
        raise UID30LaunchError(
            f"journaled zero-burn launch identity is invalid: {exc}"
        ) from exc
    if (
        strict_owner != network.get("subnet_owner_hotkey")
        or identity.get("network") != NETWORK
        or identity.get("netuid") != NETUID
        or identity.get("validator_hotkey") != UID30_HOTKEY
        or identity.get("validator_uid") != UID30
        or identity.get("uid_weights") != [[miner_uid, 1.0]]
        or identity.get("uid_hotkeys") != [[miner_uid, MINER_HOTKEY]]
        or identity.get("allocation_contract") != POLICY_ID
        or identity.get("burn_destination") is not None
        or identity.get("burn_share") != 0.0
        or identity.get("subnet_owner_hotkey") != network.get("subnet_owner_hotkey")
        or identity.get("next_epoch_start_block")
        != network.get("next_epoch_start_block")
        or identity.get("inclusion_policy") != preview.get("inclusion_policy")
        or identity.get("uid30_launch_schema") != PREVIEW_SCHEMA
        or identity.get("uid30_launch_preview_sha256") != "sha256:" + preview_sha256
        or identity.get("uid30_launch_policy") != POLICY_ID
        or identity.get("report_id") != "sha256:" + preview_sha256
        or identity.get("exclusive_writer_assertion")
        != {
            "asserted": True,
            "scope": "all_other_uid30_processes_and_hosts_stopped",
        }
    ):
        raise UID30LaunchError(
            "journaled submission identity differs from the reviewed zero-burn launch"
        )
    mapping_block = _strict_nonnegative_int(
        identity.get("mapping_block"), label="journaled mapping block"
    )
    policy = _preview_inclusion_policy(preview)
    if not policy.valid_from_block <= mapping_block < policy.valid_until_block:
        raise UID30LaunchError(
            "journaled mapping block is outside the reviewed inclusion policy"
        )
    return miner_uid


def _recovery_preflight() -> Any:
    try:
        preflight = canonical_validator.chain_preflight(
            network=NETWORK,
            netuid=NETUID,
            wallet_name=WALLET_NAME,
            wallet_hotkey=WALLET_HOTKEY,
        )
    except Exception as exc:
        raise UID30LaunchAmbiguous(
            f"read-only recovery chain preflight failed: {exc}"
        ) from exc
    if (
        preflight.genesis_hash != FINNEY_GENESIS_HASH
        or preflight.validator_hotkey != UID30_HOTKEY
        or preflight.validator_uid != UID30
    ):
        raise UID30LaunchAmbiguous(
            "read-only recovery resolved the wrong chain or validator identity"
        )
    return preflight


def recover_reviewed_preview(
    *,
    preview_path: Path | str,
    reviewed_sha256: str,
    exclusive_writer_asserted: bool = False,
    preflight_loader: Callable[[], Any] = _recovery_preflight,
    locate_call: Callable[
        ..., Any
    ] = canonical_validator._locate_pending_broadcast_receipt,
) -> UID30RecoveryResult:
    """Recover one exact signed UID30 attempt by finalized reads only."""

    if exclusive_writer_asserted is not True:
        raise UID30LaunchError(
            "--assert-exclusive-writer is required; stop every other UID30 writer"
        )
    preview, digest = load_reviewed_preview(
        preview_path, reviewed_sha256=reviewed_sha256
    )
    exclusivity = preview["exclusivity"]
    network = preview["network"]
    assert isinstance(exclusivity, Mapping)
    assert isinstance(network, Mapping)
    runtime_root = Path(str(exclusivity["runtime_root"]))
    if runtime_root != DEFAULT_RUNTIME_ROOT:
        raise UID30LaunchError(
            f"live UID30 recovery requires canonical runtime root {DEFAULT_RUNTIME_ROOT}"
        )
    args = _submission_contract(
        runtime_root=runtime_root,
        genesis_hash=str(network["genesis_hash"]),
        preview_sha256=digest,
        authorized=True,
    )
    try:
        with canonical_validator._submission_tick_lock(args, lane="authority"):
            journal = canonical_validator._read_state(
                canonical_validator._submission_state_path(args)
            )
            if journal.get("submission_pending_id") is None:
                identity = journal.get("submission_finalized_identity")
                intent = journal.get("submission_finalized_broadcast_intent")
                receipt = journal.get("submission_finalized_receipt")
                attempt_id = str(journal.get("submission_finalized_id") or "")
                if (
                    journal.get("submission_finalized_lane") != "authority"
                    or not isinstance(identity, Mapping)
                    or not isinstance(intent, Mapping)
                    or not isinstance(receipt, Mapping)
                    or _DIGEST_RE.fullmatch(attempt_id.removeprefix("sha256:")) is None
                ):
                    raise UID30LaunchError(
                        "canonical journal has no exact finalized UID30 attempt"
                    )
                miner_uid = _validate_attempt_identity(
                    identity, preview=preview, preview_sha256=digest
                )
                if _attempt_id(identity) != attempt_id:
                    raise UID30LaunchContradiction(
                        "finalized UID30 attempt id differs from its exact identity"
                    )
                try:
                    extrinsic_hash = _canonical_hash(
                        receipt["extrinsic_hash"],
                        label="finalized receipt extrinsic hash",
                    )
                    block_hash = _canonical_hash(
                        receipt["block_hash"], label="finalized receipt block hash"
                    )
                    block_number = int(receipt["block_number"])
                    version_key = int(receipt["version_key"])
                    wire_uids = [int(value) for value in receipt["wire_uids"]]
                    wire_weights = [int(value) for value in receipt["wire_weights"]]
                    intent_hash = _canonical_hash(
                        intent["extrinsic_hash"], label="finalized intent hash"
                    )
                    intent_reference = int(intent["era_reference_block"])
                    intent_mortal = int(intent["mortal_period_blocks"])
                    intent_version = int(intent["version_key"])
                    intent_uids = [int(value) for value in intent["wire_uids"]]
                    intent_weights = [int(value) for value in intent["wire_weights"]]
                except (KeyError, TypeError, ValueError) as exc:
                    raise UID30LaunchContradiction(
                        "finalized UID30 intent or receipt is malformed"
                    ) from exc
                if (
                    block_number <= 0
                    or extrinsic_hash != intent_hash
                    or version_key != VERSION_KEY
                    or intent_version != VERSION_KEY
                    or intent_reference != identity.get("mapping_block")
                    or intent_mortal != SN39_MORTAL_PERIOD_BLOCKS
                    or wire_uids != [miner_uid]
                    or wire_weights != [W]
                    or intent_uids != wire_uids
                    or intent_weights != wire_weights
                    or journal.get("submission_pending_proof_status")
                    != canonical_validator.PASS
                ):
                    raise UID30LaunchContradiction(
                        "finalized UID30 journal differs from the reviewed signed vector"
                    )
                preflight = preflight_loader()
                if (
                    preflight.genesis_hash != FINNEY_GENESIS_HASH
                    or preflight.validator_hotkey != UID30_HOTKEY
                    or preflight.validator_uid != UID30
                ):
                    raise UID30LaunchAmbiguous(
                        "recovery preflight resolved the wrong chain or validator"
                    )
                submission = canonical_validator.ChainSubmission(
                    success=True,
                    extrinsic_hash=extrinsic_hash,
                    block_hash=block_hash,
                    block_number=block_number,
                    finalized=True,
                )
                readback = _finalized_readback(
                    state=SimpleNamespace(preflight=preflight, miner_uid=miner_uid),
                    submission=submission,
                    receipt=None,
                    identity=identity,
                    require_receipt=False,
                )
                if readback.get("dests") != [miner_uid] or readback.get(
                    "weights_u16"
                ) != [W]:
                    raise UID30LaunchContradiction(
                        "finalized UID30 chain readback differs from the reviewed vector"
                    )
                return UID30RecoveryResult(
                    status="ALREADY_FINALIZED",
                    preview_sha256=digest,
                    attempt_id=attempt_id,
                    extrinsic_hash=extrinsic_hash,
                    block_hash=block_hash,
                    block_number=block_number,
                    miner_uid=miner_uid,
                    stored_weight=W,
                )
            attempt_id = str(journal.get("submission_pending_id") or "")
            identity = journal.get("submission_pending_identity")
            intent = journal.get("submission_pending_broadcast_intent")
            if (
                journal.get("submission_pending_lane") != "authority"
                or journal.get("submission_pending_phase") != "signed_intent"
                or not isinstance(identity, Mapping)
                or not isinstance(intent, Mapping)
                or _DIGEST_RE.fullmatch(attempt_id.removeprefix("sha256:")) is None
            ):
                raise UID30LaunchAmbiguous(
                    "canonical journal does not contain one recoverable signed UID30 intent"
                )
            if (
                journal.get("submission_pending_proof_status")
                == canonical_validator.FAIL
            ):
                raise UID30LaunchContradiction(
                    "canonical journal contains a positive historical proof mismatch; "
                    "read-only recovery is forbidden"
                )
            miner_uid = _validate_attempt_identity(
                identity, preview=preview, preview_sha256=digest
            )
            if _attempt_id(identity) != attempt_id:
                raise UID30LaunchAmbiguous(
                    "journaled UID30 attempt id differs from its exact identity"
                )
            try:
                extrinsic_hash = _canonical_hash(
                    intent["extrinsic_hash"], label="journaled extrinsic hash"
                )
                era_reference_block = int(intent["era_reference_block"])
                mortal_period = int(intent["mortal_period_blocks"])
                version_key = int(intent["version_key"])
                wire_uids = [int(value) for value in intent["wire_uids"]]
                wire_weights = [int(value) for value in intent["wire_weights"]]
            except (KeyError, TypeError, ValueError) as exc:
                raise UID30LaunchAmbiguous(
                    "journaled UID30 broadcast intent is malformed"
                ) from exc
            if (
                era_reference_block != identity.get("mapping_block")
                or mortal_period != SN39_MORTAL_PERIOD_BLOCKS
                or version_key != VERSION_KEY
                or wire_uids != [miner_uid]
                or wire_weights != [W]
            ):
                raise UID30LaunchAmbiguous(
                    "journaled broadcast intent differs from the reviewed vector"
                )
            preflight = preflight_loader()
            if (
                preflight.genesis_hash != FINNEY_GENESIS_HASH
                or preflight.validator_hotkey != UID30_HOTKEY
                or preflight.validator_uid != UID30
            ):
                raise UID30LaunchAmbiguous(
                    "recovery preflight resolved the wrong chain or validator"
                )
            policy = _preview_inclusion_policy(preview)
            candidate = journal.get("submission_pending_receipt_candidate")
            if isinstance(candidate, Mapping):
                try:
                    submission = canonical_validator.ChainSubmission(
                        success=True,
                        extrinsic_hash=_canonical_hash(
                            candidate["extrinsic_hash"],
                            label="candidate extrinsic hash",
                        ),
                        block_hash=_canonical_hash(
                            candidate["block_hash"], label="candidate block hash"
                        ),
                        block_number=int(candidate["block_number"]),
                        finalized=True,
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise UID30LaunchAmbiguous(
                        "journaled receipt candidate is malformed"
                    ) from exc
                if (
                    submission.extrinsic_hash != extrinsic_hash
                    or candidate.get("wire_uids") != [miner_uid]
                    or candidate.get("wire_weights") != [W]
                ):
                    raise UID30LaunchAmbiguous(
                        "journaled receipt candidate differs from the signed intent"
                    )
            else:
                locate_status, submission = locate_call(
                    preflight.subtensor,
                    extrinsic_hash=extrinsic_hash,
                    era_reference_block=era_reference_block,
                    mortal_period_blocks=mortal_period,
                    validator_hotkey=UID30_HOTKEY,
                    netuid=NETUID,
                    version_key=VERSION_KEY,
                    wire_uids=[miner_uid],
                    wire_weights=[W],
                    inclusion_policy=policy,
                )
                if (
                    locate_status == canonical_validator.EXPIRED_WITHOUT_INCLUSION
                    and submission is None
                ):
                    canonical_validator._expire_pending_common_submission(
                        args, attempt_id=attempt_id
                    )
                    return UID30RecoveryResult(
                        status=canonical_validator.EXPIRED_WITHOUT_INCLUSION,
                        preview_sha256=digest,
                        attempt_id=attempt_id,
                        extrinsic_hash=extrinsic_hash,
                        block_hash=None,
                        block_number=None,
                        miner_uid=miner_uid,
                        stored_weight=None,
                    )
                if locate_status in {
                    canonical_validator.PASS,
                    canonical_validator.FAIL,
                    canonical_validator.NOT_PROVEN,
                }:
                    canonical_validator._record_pending_proof_status(
                        args, attempt_id=attempt_id, status=locate_status
                    )
                if locate_status != canonical_validator.PASS or submission is None:
                    error = (
                        UID30LaunchContradiction
                        if locate_status == canonical_validator.FAIL
                        else UID30LaunchAmbiguous
                    )
                    raise error(
                        "exact signed UID30 transaction is not uniquely proven on "
                        "the finalized chain"
                    )
                canonical_validator._record_pending_submission_receipt(
                    args,
                    attempt_id=attempt_id,
                    submission=submission,
                    version_key=VERSION_KEY,
                    wire_uids=[miner_uid],
                    wire_weights=[W],
                )
            recovery_state = SimpleNamespace(
                preflight=preflight,
                miner_uid=miner_uid,
            )
            try:
                readback = _finalized_readback(
                    state=recovery_state,
                    submission=submission,
                    receipt=None,
                    identity=identity,
                    require_receipt=False,
                )
            except UID30LaunchContradiction:
                canonical_validator._record_pending_proof_status(
                    args, attempt_id=attempt_id, status=canonical_validator.FAIL
                )
                raise
            if readback.get("dests") != [miner_uid] or readback.get("weights_u16") != [
                W
            ]:
                raise UID30LaunchAmbiguous(
                    "recovered finalized readback differs from the reviewed vector"
                )
            canonical_validator._record_pending_proof_status(
                args, attempt_id=attempt_id, status=canonical_validator.PASS
            )
            canonical_validator._finalize_common_submission(
                args,
                attempt_id=attempt_id,
                submission=canonical_validator.ChainSubmission(
                    success=True,
                    extrinsic_hash=submission.extrinsic_hash,
                    block_hash=submission.block_hash,
                    block_number=submission.block_number,
                    finalized=True,
                ),
                version_key=VERSION_KEY,
            )
            return UID30RecoveryResult(
                status="RECOVERED_FINALIZED",
                preview_sha256=digest,
                attempt_id=attempt_id,
                extrinsic_hash=str(submission.extrinsic_hash),
                block_hash=str(submission.block_hash),
                block_number=int(submission.block_number),
                miner_uid=miner_uid,
                stored_weight=W,
            )
    except (UID30LaunchError, UID30LaunchAmbiguous):
        raise
    except Exception as exc:
        raise UID30LaunchAmbiguous(
            f"read-only UID30 recovery remains fenced: {exc}"
        ) from exc


def _successor_recovery_state(
    *,
    preflight: Any,
    preview: Mapping[str, Any],
    uid_hotkeys: Mapping[int, str],
) -> UID30SuccessorVerificationState:
    """Build the read-only structural view used by inclusion and later reads."""

    if (
        preflight.genesis_hash != FINNEY_GENESIS_HASH
        or preflight.validator_hotkey != UID30_HOTKEY
        or preflight.validator_uid != UID30
        or getattr(preflight, "validator_permit", True) is not True
        or set(uid_hotkeys.values())
        != {
            MINER_HOTKEY,
            canonical_validator.SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
        }
        or any(
            preflight.hotkey_to_uid.get(hotkey) != uid
            or sorted(
                observed_hotkey
                for observed_hotkey, observed_uid in preflight.hotkey_to_uid.items()
                if observed_uid == uid
            )
            != [hotkey]
            for uid, hotkey in uid_hotkeys.items()
        )
        or preflight.hotkey_to_uid.get(UID30_HOTKEY) != UID30
        or sorted(
            observed_hotkey
            for observed_hotkey, observed_uid in preflight.hotkey_to_uid.items()
            if observed_uid == UID30
        )
        != [UID30_HOTKEY]
    ):
        raise UID30LaunchAmbiguous(
            "recovery preflight no longer has the reviewed bidirectional UID mappings"
        )
    network = preview.get("network")
    if not isinstance(network, Mapping):
        raise UID30LaunchError("reviewed successor network is malformed")
    miners = preview.get("miners")
    if not isinstance(miners, list):
        raise UID30LaunchError("reviewed successor miners are malformed")
    reviewed_by_hotkey = {
        str(row.get("hotkey")): row for row in miners if isinstance(row, Mapping)
    }
    targets = tuple(
        second_miner_plan.Neuron(
            uid=uid,
            hotkey=hotkey,
            coldkey=second_miner_plan.CATHEDRAL_COLDKEY,
            validator_permit=False,
            last_update=0,
            ip=str(reviewed_by_hotkey[hotkey]["ip"]),
            port=int(reviewed_by_hotkey[hotkey]["port"]),
            protocol=second_miner_plan.HTTPS_PROTOCOL,
            serving=True,
        )
        for uid, hotkey in sorted(uid_hotkeys.items())
    )
    return UID30SuccessorVerificationState(
        preflight=preflight,
        genesis_hash=str(network["genesis_hash"]),
        targets=targets,
    )


def _successor_signed_record(
    journal: Mapping[str, Any],
    *,
    prefix: str,
    preview: Mapping[str, Any],
    preview_sha256: str,
) -> tuple[
    str,
    Mapping[str, Any],
    Mapping[str, Any],
    tuple[int, int],
    tuple[int, int],
    dict[int, str],
]:
    """Decode one exact pending or finalized successor journal record."""

    attempt_id = journal.get(f"submission_{prefix}_id")
    lane = journal.get(f"submission_{prefix}_lane")
    identity = journal.get(f"submission_{prefix}_identity")
    intent = journal.get(f"submission_{prefix}_broadcast_intent")
    durable_kind = journal.get(f"submission_{prefix}_reviewed_uid30_contract")
    if (
        not isinstance(attempt_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", attempt_id) is None
        or lane != "authority"
        or not isinstance(identity, Mapping)
        or not isinstance(intent, Mapping)
        or durable_kind != "two_miner_successor"
    ):
        raise UID30LaunchAmbiguous(
            f"canonical journal has no exact {prefix} two-miner successor"
        )
    wire_uids, wire_weights, uid_hotkeys = _validate_successor_attempt_identity(
        identity,
        preview=preview,
        preview_sha256=preview_sha256,
    )
    if _attempt_id(identity) != attempt_id:
        raise UID30LaunchContradiction(
            "journaled successor attempt id differs from its immutable identity"
        )
    try:
        intent_hash = _canonical_hash(
            intent["extrinsic_hash"],
            label="successor signed intent hash",
        )
        nonce = intent["nonce"]
        era_reference = intent["era_reference_block"]
        mortal_period = intent["mortal_period_blocks"]
        version_key = intent["version_key"]
        intent_uids = tuple(intent["wire_uids"])
        intent_weights = tuple(intent["wire_weights"])
    except (KeyError, TypeError, ValueError) as exc:
        raise UID30LaunchContradiction(
            "journaled successor signed intent is malformed"
        ) from exc
    if (
        isinstance(nonce, bool)
        or not isinstance(nonce, int)
        or nonce < 0
        or type(era_reference) is not int
        or era_reference != identity.get("mapping_block")
        or mortal_period != SN39_MORTAL_PERIOD_BLOCKS
        or version_key != VERSION_KEY
        or intent_uids != wire_uids
        or intent_weights != wire_weights
    ):
        raise UID30LaunchContradiction(
            "journaled successor signed intent differs from the reviewed vector"
        )
    return (
        attempt_id,
        identity,
        {**dict(intent), "extrinsic_hash": intent_hash},
        wire_uids,
        wire_weights,
        uid_hotkeys,
    )


def recover_reviewed_successor(
    *,
    preview_path: Path | str,
    reviewed_sha256: str,
    exclusive_writer_asserted: bool = False,
) -> UID30SuccessorRecoveryResult:
    """Recover the fixed signed successor without signing or retrying it."""

    if exclusive_writer_asserted is not True:
        raise UID30LaunchError(
            "--assert-exclusive-writer is required; stop every other UID30 writer"
        )
    preview, digest = load_reviewed_successor_preview(
        preview_path,
        reviewed_sha256=reviewed_sha256,
    )
    exclusivity = preview["exclusivity"]
    network = preview["network"]
    assert isinstance(exclusivity, Mapping)
    assert isinstance(network, Mapping)
    runtime_root = Path(str(exclusivity["runtime_root"]))
    if runtime_root != DEFAULT_RUNTIME_ROOT:
        raise UID30LaunchError(
            f"live UID30 recovery requires canonical runtime root {DEFAULT_RUNTIME_ROOT}"
        )
    args = _successor_submission_contract(
        runtime_root=runtime_root,
        genesis_hash=str(network["genesis_hash"]),
        preview_sha256=digest,
    )
    try:
        with canonical_validator._submission_tick_lock(args, lane="authority"):
            journal_path = canonical_validator._submission_state_path(args)
            journal = canonical_validator._read_state(journal_path)
            pristine_predecessor = False
            if (
                journal.get("submission_pending_id") is None
                and journal_path.name
                == canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
            ):
                try:
                    pristine_predecessor = (
                        canonical_validator._private_state_sha256(journal_path)
                        == canonical_validator.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256
                    )
                except OSError:
                    pristine_predecessor = False
            if pristine_predecessor:
                raise UID30LaunchError(
                    "exact predecessor is pristine; no successor attempt exists; "
                    "no state changed"
                )
            finalized = journal.get("submission_pending_id") is None
            prefix = "finalized" if finalized else "pending"
            if not finalized and journal.get("submission_pending_phase") == (
                "unsigned_reserved"
            ):
                attempt_id = str(journal.get("submission_pending_id") or "")
                identity = journal.get("submission_pending_identity")
                if not isinstance(identity, Mapping):
                    raise UID30LaunchAmbiguous(
                        "unsigned successor reservation lost its identity"
                    )
                _validate_successor_attempt_identity(
                    identity,
                    preview=preview,
                    preview_sha256=digest,
                )
                if not canonical_validator._abort_unsigned_common_submission(
                    args,
                    attempt_id=attempt_id,
                ):
                    raise UID30LaunchAmbiguous(
                        "unsigned successor reservation changed while recovery held the lock"
                    )
                vector = preview["proposed_vector"]
                assert isinstance(vector, Mapping)
                return UID30SuccessorRecoveryResult(
                    status="UNSIGNED_RESERVATION_RELEASED",
                    preview_sha256=digest,
                    attempt_id=attempt_id,
                    extrinsic_hash=None,
                    block_hash=None,
                    block_number=None,
                    wire_uids=tuple(vector["dests"]),
                    wire_weights=None,
                    later_finalized_heads=None,
                )
            if not finalized and journal.get("submission_pending_phase") != (
                "signed_intent"
            ):
                raise UID30LaunchAmbiguous(
                    "successor journal has no recognized signed recovery phase"
                )
            if (
                not finalized
                and journal.get("submission_pending_proof_status")
                == canonical_validator.FAIL
            ):
                raise UID30LaunchContradiction(
                    "successor journal contains a positive historical mismatch"
                )
            (
                attempt_id,
                identity,
                intent,
                wire_uids,
                wire_weights,
                uid_hotkeys,
            ) = _successor_signed_record(
                journal,
                prefix=prefix,
                preview=preview,
                preview_sha256=digest,
            )
            preflight = _recovery_preflight()
            verification_state = _successor_recovery_state(
                preflight=preflight,
                preview=preview,
                uid_hotkeys=uid_hotkeys,
            )
            receipt_row = (
                journal.get("submission_finalized_receipt")
                if finalized
                else journal.get("submission_pending_receipt_candidate")
            )
            if not isinstance(receipt_row, Mapping):
                if finalized:
                    raise UID30LaunchContradiction(
                        "finalized successor journal has no exact receipt"
                    )
                policy = _preview_inclusion_policy(preview)
                locate_status, submission = (
                    canonical_validator._locate_pending_broadcast_receipt(
                        preflight.subtensor,
                        extrinsic_hash=str(intent["extrinsic_hash"]),
                        era_reference_block=int(intent["era_reference_block"]),
                        mortal_period_blocks=int(intent["mortal_period_blocks"]),
                        validator_hotkey=UID30_HOTKEY,
                        netuid=NETUID,
                        version_key=VERSION_KEY,
                        wire_uids=list(wire_uids),
                        wire_weights=list(wire_weights),
                        inclusion_policy=policy,
                    )
                )
                if (
                    locate_status == canonical_validator.EXPIRED_WITHOUT_INCLUSION
                    and submission is None
                ):
                    canonical_validator._expire_pending_common_submission(
                        args,
                        attempt_id=attempt_id,
                    )
                    return UID30SuccessorRecoveryResult(
                        status=canonical_validator.EXPIRED_WITHOUT_INCLUSION,
                        preview_sha256=digest,
                        attempt_id=attempt_id,
                        extrinsic_hash=str(intent["extrinsic_hash"]),
                        block_hash=None,
                        block_number=None,
                        wire_uids=wire_uids,
                        wire_weights=None,
                        later_finalized_heads=None,
                    )
                if locate_status in {
                    canonical_validator.PASS,
                    canonical_validator.FAIL,
                    canonical_validator.NOT_PROVEN,
                }:
                    canonical_validator._record_pending_proof_status(
                        args,
                        attempt_id=attempt_id,
                        status=locate_status,
                    )
                if locate_status != canonical_validator.PASS or submission is None:
                    error = (
                        UID30LaunchContradiction
                        if locate_status == canonical_validator.FAIL
                        else UID30LaunchAmbiguous
                    )
                    raise error(
                        "exact successor transaction is not uniquely proven on the "
                        "finalized chain"
                    )
                canonical_validator._record_pending_submission_receipt(
                    args,
                    attempt_id=attempt_id,
                    submission=submission,
                    version_key=VERSION_KEY,
                    wire_uids=list(wire_uids),
                    wire_weights=list(wire_weights),
                )
            else:
                try:
                    submission = canonical_validator.ChainSubmission(
                        success=True,
                        extrinsic_hash=_canonical_hash(
                            receipt_row["extrinsic_hash"],
                            label="successor receipt extrinsic hash",
                        ),
                        block_hash=_canonical_hash(
                            receipt_row["block_hash"],
                            label="successor receipt block hash",
                        ),
                        block_number=_strict_nonnegative_int(
                            receipt_row["block_number"],
                            label="successor receipt block number",
                        ),
                        finalized=True,
                    )
                    receipt_version = receipt_row["version_key"]
                    receipt_uids = tuple(receipt_row["wire_uids"])
                    receipt_weights = tuple(receipt_row["wire_weights"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise UID30LaunchContradiction(
                        "journaled successor receipt is malformed"
                    ) from exc
                if (
                    submission.extrinsic_hash != intent["extrinsic_hash"]
                    or receipt_version != VERSION_KEY
                    or receipt_uids != wire_uids
                    or receipt_weights != wire_weights
                ):
                    raise UID30LaunchContradiction(
                        "journaled successor receipt differs from its signed intent"
                    )
            readback = _finalized_readback(
                state=verification_state,
                submission=submission,
                receipt=None,
                identity=identity,
                require_receipt=False,
                wire_uids=wire_uids,
                wire_weights=wire_weights,
                uid_hotkeys=uid_hotkeys,
            )
            if (
                tuple(readback.get("dests", ())) != wire_uids
                or tuple(readback.get("weights_u16", ())) != wire_weights
            ):
                raise UID30LaunchContradiction(
                    "recovered inclusion readback differs from the reviewed vector"
                )
            later_heads = _verify_successor_later_finalized_heads(
                state=verification_state,
                submission=submission,
                wire_uids=wire_uids,
                wire_weights=wire_weights,
            )
            if not finalized:
                canonical_validator._record_pending_proof_status(
                    args,
                    attempt_id=attempt_id,
                    status=canonical_validator.PASS,
                )
                canonical_validator._finalize_common_submission(
                    args,
                    attempt_id=attempt_id,
                    submission=canonical_validator.ChainSubmission(
                        success=True,
                        extrinsic_hash=submission.extrinsic_hash,
                        block_hash=submission.block_hash,
                        block_number=submission.block_number,
                        finalized=True,
                    ),
                    version_key=VERSION_KEY,
                )
            return UID30SuccessorRecoveryResult(
                status=("ALREADY_FINALIZED" if finalized else "RECOVERED_FINALIZED"),
                preview_sha256=digest,
                attempt_id=attempt_id,
                extrinsic_hash=str(submission.extrinsic_hash),
                block_hash=str(submission.block_hash),
                block_number=int(submission.block_number),
                wire_uids=wire_uids,
                wire_weights=wire_weights,
                later_finalized_heads=later_heads,
            )
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchAmbiguous(
            f"read-only successor recovery remains fenced: {exc}"
        ) from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m cathedral_thin.uid30_launch")
    sub = parser.add_subparsers(dest="command", required=True)
    recover = sub.add_parser(
        "recover",
        help="read-only recovery of the historical one-miner signed attempt",
    )
    recover.add_argument("--preview", required=True)
    recover.add_argument("--reviewed-sha256", required=True)
    recover.add_argument(
        "--assert-exclusive-writer",
        action="store_true",
        help="assert every other process or host able to write UID30 is stopped",
    )
    successor_recover = sub.add_parser(
        "successor-recover",
        help="read-only recovery for a previously journaled retired successor",
    )
    successor_recover.add_argument("--preview", required=True)
    successor_recover.add_argument("--reviewed-sha256", required=True)
    successor_recover.add_argument(
        "--assert-exclusive-writer",
        action="store_true",
        help="assert every other process or host able to write UID30 is stopped",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if options.command == "recover":
            result = recover_reviewed_preview(
                preview_path=Path(options.preview),
                reviewed_sha256=options.reviewed_sha256,
                exclusive_writer_asserted=options.assert_exclusive_writer,
            )
            print(json.dumps(result.__dict__, indent=2, sort_keys=True))
            return 0
        if options.command == "successor-recover":
            result = recover_reviewed_successor(
                preview_path=Path(options.preview),
                reviewed_sha256=options.reviewed_sha256,
                exclusive_writer_asserted=options.assert_exclusive_writer,
            )
            print(json.dumps(result.__dict__, indent=2, sort_keys=True))
            return 0
    except UID30LaunchAmbiguous as exc:
        print(
            json.dumps(
                {"status": "AMBIGUOUS_DO_NOT_RETRY", "error": str(exc)},
                indent=2,
                sort_keys=True,
            )
        )
        return 3
    except UID30LaunchError as exc:
        print(
            json.dumps(
                {"status": "REFUSED_NO_CHAIN_WRITE", "error": str(exc)},
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    raise UID30LaunchError(f"unhandled command {options.command}")


if __name__ == "__main__":
    raise SystemExit(main())
