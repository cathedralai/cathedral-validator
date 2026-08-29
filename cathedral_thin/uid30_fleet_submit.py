"""One digest-bound UID30 fleet consolidation, with no retry path.

This command accepts only a successful owner-only
``cathedral_uid30_same_uid_fleet_preview_v1`` artifact.  It re-runs the two
machine proof, re-proves the exact finalized two-UID predecessor, and submits
the singleton ``[[124, 65535]]`` vector through the canonical ambiguity
journal.  There is no configurable destination, burn row, weight, signer, or
retry flag.

The preview command remains a separate writer-free module.  Importing or
running ``cathedral-uid30-fleet-preview`` does not import this file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from cathedral_thin import second_miner_plan
from cathedral_thin import uid30_fleet_preview as fleet_preview
from cathedral_thin import uid30_launch as launch
from cathedral_thin.independent.constants import (
    FINNEY_GENESIS_HASH,
    MECID,
    NETUID,
    SN39_MORTAL_PERIOD_BLOCKS,
    VERSION_KEY,
    W,
)
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.qvl import LAUNCH_QVL_DIGEST
from cathedral_thin.uid30_state import (
    MINER_HOTKEY,
    NETWORK,
    UID30,
    UID30_HOTKEY,
    WALLET_HOTKEY,
    WALLET_NAME,
    UID30ChainState,
    UID30ReadPreflight,
    UID30LaunchError,
    _canonical_hash,
    _strict_nonnegative_int,
    read_uid30_chain_state,
)
from scaffold import validator_thin as canonical

TARGET_UID = canonical.SN39_UID30_FLEET_TARGET_UID
PREDECESSOR_UID = canonical.SN39_UID30_FLEET_PREDECESSOR_SECOND_UID
PREDECESSOR_HOTKEY = canonical.SN39_UID30_SUCCESSOR_SECOND_HOTKEY
ARCHIVE_CHAIN_ENDPOINT = "wss://archive.chain.opentensor.ai:443"
DEFAULT_RUNTIME_ROOT = launch.DEFAULT_RUNTIME_ROOT
MAX_PREVIEW_BYTES = launch.MAX_PREVIEW_BYTES
PREVIEW_VALIDITY_SECONDS = launch.PREVIEW_VALIDITY_SECONDS
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class UID30FleetState:
    """Fresh chain gates plus the exact two-UID predecessor row."""

    base: UID30ChainState
    current_weights: tuple[tuple[int, int], ...]
    current_axons: tuple[ServingAxon, ...]
    uid_safety: Mapping[str, Any]


@dataclass(frozen=True)
class UID30FleetSubmissionResult:
    preview_sha256: str
    attempt_id: str
    extrinsic_hash: str
    block_hash: str
    block_number: int
    wire_uids: tuple[int]
    wire_weights: tuple[int]
    later_finalized_heads: tuple[tuple[int, str], tuple[int, str]]


@dataclass(frozen=True)
class UID30FleetRecoveryResult:
    status: str
    preview_sha256: str
    attempt_id: str
    extrinsic_hash: str | None
    block_hash: str | None
    block_number: int | None
    wire_uids: tuple[int]
    wire_weights: tuple[int] | None
    later_finalized_heads: tuple[tuple[int, str], tuple[int, str]] | None


def _strict_json(raw: bytes) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise UID30LaunchError(f"fleet preview contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UID30LaunchError(f"fleet preview is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise UID30LaunchError("fleet preview is not a JSON object")
    return value


def _canonical_endpoint(value: object) -> str:
    # Reuse the canonical contract parser for the complete endpoint check.
    row = {
        "uid": TARGET_UID,
        "hotkey": MINER_HOTKEY,
        "endpoint": value,
        "channel_id": "1" * 64,
        "stable_platform_id": "tdx-platform-sha256:" + "2" * 64,
        "machine_id": hashlib.sha256(
            ("tdx-platform-sha256:" + "2" * 64).encode("ascii")
        ).hexdigest(),
        "quote_sha256": "3" * 64,
        "report_data_sha256": "4" * 64,
        "qvl_status": canonical.PASS,
        "qvl_digest": LAUNCH_QVL_DIGEST,
        "sat_rule": canonical.SN39_UID30_SUCCESSOR_SAT_RULE,
        "verified_work_units": 20,
        "anchor_number": 1,
        "anchor_hash": "0x" + "5" * 64,
    }
    other = dict(row)
    other.update(
        {
            "endpoint": "https://1.1.1.1:8081"
            if value != "https://1.1.1.1:8081"
            else "https://8.8.8.8:8081",
            "channel_id": "6" * 64,
            "stable_platform_id": "tdx-platform-sha256:" + "7" * 64,
            "quote_sha256": "8" * 64,
            "report_data_sha256": "9" * 64,
        }
    )
    other["machine_id"] = hashlib.sha256(
        str(other["stable_platform_id"]).encode("ascii")
    ).hexdigest()
    try:
        canonical._strict_uid30_fleet_machine_proofs(
            [row, other], mapping_block=1, label="preview endpoint"
        )
    except Exception as exc:
        raise UID30LaunchError(f"fleet preview endpoint is invalid: {exc}") from exc
    return str(value)


def _proof_rows(document: Mapping[str, Any], *, label: str) -> list[dict[str, Any]]:
    target = document.get("consolidation_target")
    anchor = document.get("evidence_anchor")
    if not isinstance(target, Mapping) or not isinstance(anchor, Mapping):
        raise UID30LaunchError(f"{label} has no fleet target or evidence anchor")
    machines = target.get("machines")
    if not isinstance(machines, list) or len(machines) != 2:
        raise UID30LaunchError(f"{label} does not contain exactly two machines")
    block = _strict_nonnegative_int(
        anchor.get("block_number"), label=f"{label} evidence block"
    )
    block_hash = _canonical_hash(
        anchor.get("block_hash"), label=f"{label} evidence hash"
    )
    machine_keys = {
        "endpoint",
        "channel_id",
        "stable_platform_id",
        "machine_id",
        "quote_sha256",
        "report_data_sha256",
        "sat_rule",
        "verified_work_units",
    }
    if any(
        not isinstance(row, Mapping) or set(row) != machine_keys for row in machines
    ):
        raise UID30LaunchError(f"{label} machine fields are not exact")
    rows = [
        {
            "uid": TARGET_UID,
            "hotkey": MINER_HOTKEY,
            "endpoint": row.get("endpoint"),
            "channel_id": row.get("channel_id"),
            "stable_platform_id": row.get("stable_platform_id"),
            "machine_id": row.get("machine_id"),
            "quote_sha256": row.get("quote_sha256"),
            "report_data_sha256": row.get("report_data_sha256"),
            "qvl_status": canonical.PASS,
            "qvl_digest": LAUNCH_QVL_DIGEST,
            "sat_rule": row.get("sat_rule"),
            "verified_work_units": row.get("verified_work_units"),
            "anchor_number": block,
            "anchor_hash": block_hash,
        }
        for row in machines
    ]
    try:
        canonical._strict_uid30_fleet_machine_proofs(
            rows, mapping_block=block, label=label
        )
    except Exception as exc:
        raise UID30LaunchError(f"{label} machine proof is invalid: {exc}") from exc
    return rows


def validate_reviewed_preview(document: Mapping[str, Any]) -> dict[str, Any]:
    """Require the exact successful writer-free preview contract."""

    preview = dict(document)
    expected_top = {
        "schema",
        "status",
        "network",
        "netuid",
        "mechanism_id",
        "evidence_anchor",
        "finalized_recheck",
        "validator",
        "score_contract",
        "current",
        "consolidation_target",
        "qvl_digest",
        "burn_destination",
        "burn_weight",
        "changes_current_chain_row",
        "authorized_for_chain_write",
        "chain_write_submitted",
        "weight_signed",
        "weight_submitted",
        "proof_boundary",
    }
    current = preview.get("current")
    target = preview.get("consolidation_target")
    validator = preview.get("validator")
    evidence = preview.get("evidence_anchor")
    recheck = preview.get("finalized_recheck")
    if (
        set(preview) != expected_top
        or preview.get("schema") != fleet_preview.SCHEMA
        or preview.get("status") != fleet_preview.STATUS
        or preview.get("network") != NETWORK
        or preview.get("netuid") != NETUID
        or preview.get("mechanism_id") != MECID
        or preview.get("qvl_digest") != LAUNCH_QVL_DIGEST
        or preview.get("burn_destination") is not None
        or preview.get("burn_weight") != 0
        or preview.get("changes_current_chain_row") is not True
        or preview.get("authorized_for_chain_write") is not False
        or preview.get("chain_write_submitted") is not False
        or preview.get("weight_signed") is not False
        or preview.get("weight_submitted") is not False
        or validator != {"uid": UID30, "hotkey": UID30_HOTKEY}
        or not isinstance(current, Mapping)
        or not isinstance(target, Mapping)
        or not isinstance(evidence, Mapping)
        or not isinstance(recheck, Mapping)
    ):
        raise UID30LaunchError("fleet preview schema or no-write gates are not exact")
    evidence_block = _strict_nonnegative_int(
        evidence.get("block_number"), label="reviewed evidence block"
    )
    recheck_block = _strict_nonnegative_int(
        recheck.get("block_number"), label="reviewed recheck block"
    )
    if set(evidence) != {"block_number", "block_hash"} or set(recheck) != {
        "block_number",
        "block_hash",
    }:
        raise UID30LaunchError("fleet preview finalized anchors are not exact")
    _canonical_hash(evidence.get("block_hash"), label="reviewed evidence hash")
    _canonical_hash(recheck.get("block_hash"), label="reviewed recheck hash")
    expected_current_keys = {
        "uid30_storage",
        "burn_destination_uid",
        "burn_weight",
        "weighted_serving_uids",
        "verified_units_by_hotkey",
        "fleet_discovery",
        "machine_observations",
        "exclusions",
        "blockers",
    }
    expected_target_keys = {
        "hotkey",
        "uid",
        "root_axon",
        "fleet_endpoints",
        "machines",
        "raw_uid_units",
        "required_raw_uid_units",
        "proof_complete",
        "not_proven_reasons",
        "non_authorizing_target_wire_row",
    }
    endpoints = target.get("fleet_endpoints")
    weighted = current.get("weighted_serving_uids")
    expected_weighted_keys = {
        "uid",
        "hotkey",
        "endpoint",
        "stored_weight",
        "verified_work_units",
    }
    score_contract = {
        "formula": "sum independently re-derived verified work_units across unique physical identities",
        "declared_machine_count_bonus_units": 0,
        "attestation_only_bonus_units": 0,
        "per_machine_unit_cap": 20,
        "fleet_cap_per_uid": 32,
    }
    proof_boundary = (
        "PROVEN means the pinned UID owns two independently verified TDX "
        "platforms with 20 SAT units each and its signed fleet survived a "
        "finalized recheck. The singleton row remains a no-write target. "
        "This artifact does not authorize weights, prove subnet emission, "
        "or prove TAO earnings. AMD SEV-SNP fleet identity remains "
        "NOT_PROVEN and disabled."
    )
    if (
        recheck_block < evidence_block
        or recheck_block - evidence_block > SN39_MORTAL_PERIOD_BLOCKS
        or set(current) != expected_current_keys
        or current.get("uid30_storage") != [[PREDECESSOR_UID, W], [TARGET_UID, W]]
        or current.get("burn_weight") != 0
        or not isinstance(current.get("burn_destination_uid"), int)
        or isinstance(current.get("burn_destination_uid"), bool)
        or current.get("burn_destination_uid") in {PREDECESSOR_UID, TARGET_UID}
        or not isinstance(weighted, list)
        or len(weighted) != 2
        or any(
            not isinstance(row, Mapping) or set(row) != expected_weighted_keys
            for row in weighted
        )
        or [row.get("uid") for row in weighted] != [PREDECESSOR_UID, TARGET_UID]
        or [row.get("hotkey") for row in weighted] != [PREDECESSOR_HOTKEY, MINER_HOTKEY]
        or [row.get("stored_weight") for row in weighted] != [W, W]
        or [row.get("verified_work_units") for row in weighted] != [0, 40]
        or not isinstance(current.get("verified_units_by_hotkey"), Mapping)
        or current["verified_units_by_hotkey"].get(MINER_HOTKEY) != 40
        or current.get("blockers") != []
        or set(target) != expected_target_keys
        or target.get("hotkey") != MINER_HOTKEY
        or target.get("uid") != TARGET_UID
        or target.get("raw_uid_units") != 40
        or target.get("required_raw_uid_units") != 40
        or target.get("proof_complete") is not True
        or target.get("not_proven_reasons") != []
        or target.get("non_authorizing_target_wire_row") != [[TARGET_UID, W]]
        or not isinstance(endpoints, list)
        or len(endpoints) != 2
        or len(set(endpoints)) != 2
        or target.get("root_axon") != endpoints[0]
        or preview.get("score_contract") != score_contract
        or preview.get("proof_boundary") != proof_boundary
    ):
        raise UID30LaunchError("fleet preview target or predecessor row is not exact")
    for endpoint in endpoints:
        _canonical_endpoint(endpoint)
    rows = _proof_rows(preview, label="reviewed preview")
    if {row["endpoint"] for row in rows} != set(endpoints):
        raise UID30LaunchError("reviewed machines do not match the exact fleet")
    return preview


def load_reviewed_preview(
    path: Path | str, *, reviewed_sha256: str
) -> tuple[dict[str, Any], str]:
    """Load owner-only canonical preview bytes and both digest approvals."""

    target = Path(path)
    supplied = launch._digest_text(
        reviewed_sha256, label="reviewed fleet preview digest"
    )
    raw = launch._require_owner_only_file(target, max_bytes=MAX_PREVIEW_BYTES)
    if hashlib.sha256(raw).hexdigest() != supplied:
        raise UID30LaunchError("reviewed fleet digest differs from its bytes")
    detached = launch._require_owner_only_file(
        Path(str(target) + ".sha256"), max_bytes=256
    )
    try:
        detached_text = detached.decode("ascii")
    except UnicodeDecodeError as exc:
        raise UID30LaunchError("detached fleet digest is not ASCII") from exc
    expected_detached = f"{supplied}  {target.name}\n"
    if detached_text != expected_detached:
        raise UID30LaunchError("detached fleet digest or filename differs from review")
    preview = validate_reviewed_preview(_strict_json(raw))
    if fleet_preview._canonical_bytes(preview) != raw:
        raise UID30LaunchError("fleet preview bytes are not canonical JSON")
    return preview, supplied


def _submission_contract(*, preview_sha256: str) -> SimpleNamespace:
    args = launch._submission_contract(
        runtime_root=DEFAULT_RUNTIME_ROOT,
        genesis_hash=FINNEY_GENESIS_HASH,
        preview_sha256=preview_sha256,
        authorized=False,
    )
    delattr(args, "_uid30_reviewed_preview_sha256")
    args._uid30_fleet_consolidation_preview_sha256 = launch._digest_text(
        preview_sha256, label="reviewed fleet preview digest"
    )
    return args


def _archive_write_preflight() -> canonical.ChainPreflight:
    """Open the full write preflight on the one pinned archive route."""

    try:
        write = canonical.chain_preflight(
            network=NETWORK,
            netuid=NETUID,
            wallet_name=WALLET_NAME,
            wallet_hotkey=WALLET_HOTKEY,
            connection_endpoint=ARCHIVE_CHAIN_ENDPOINT,
        )
    except Exception as exc:
        raise UID30LaunchError(
            f"canonical fleet write preflight failed: {exc}"
        ) from exc
    if not isinstance(write, canonical.ChainPreflight):
        raise UID30LaunchError("canonical fleet write preflight has the wrong type")
    return write


def _read_preflight_from_write(
    write: canonical.ChainPreflight,
) -> UID30ReadPreflight:
    """Reuse one connection and head for the narrower UID30 state reader."""

    reverse: dict[int, str] = {}
    for hotkey, uid in write.hotkey_to_uid.items():
        if uid in reverse:
            raise UID30LaunchError(
                "canonical fleet write preflight repeats a UID mapping"
            )
        reverse[uid] = hotkey
    return UID30ReadPreflight(
        wallet=write.wallet,
        subtensor=write.subtensor,
        hotkey_to_uid=dict(write.hotkey_to_uid),
        uid_to_hotkey=reverse,
        validator_hotkey=write.validator_hotkey,
        validator_uid=write.validator_uid,
        block=_strict_nonnegative_int(write.block, label="canonical write block"),
        finalized_hash=_canonical_hash(
            write.finalized_hash, label="canonical write finalized hash"
        ),
        min_allowed_weights=write.min_allowed_weights,
        max_weight_limit=write.max_weight_limit,
        commit_reveal_enabled=write.commit_reveal_enabled,
        genesis_hash=write.genesis_hash,
        subnet_owner_hotkey=write.subnet_owner_hotkey,
        blocks_until_next_epoch=_strict_nonnegative_int(
            write.blocks_until_next_epoch, label="canonical blocks until next epoch"
        ),
        next_epoch_start_block=_strict_nonnegative_int(
            write.next_epoch_start_block, label="canonical next epoch start"
        ),
        weights_rate_limit=_strict_nonnegative_int(
            write.weights_rate_limit, label="canonical weight cooldown"
        ),
        validator_blocks_since_last_update=_strict_nonnegative_int(
            write.validator_blocks_since_last_update,
            label="canonical validator blocks since last update",
        ),
        connection_target=write.connection_target,
    )


def _full_write_preflight(
    base: UID30ChainState, write: canonical.ChainPreflight
) -> canonical.ChainPreflight:
    """Bind the read-only fleet snapshot to canonical write safety at one head."""

    read = base.preflight
    reverse: dict[int, str] = {}
    for hotkey, uid in write.hotkey_to_uid.items():
        if uid in reverse:
            raise UID30LaunchError(
                "canonical fleet write preflight repeats a UID mapping"
            )
        reverse[uid] = hotkey
    try:
        write_hash = _canonical_hash(
            write.finalized_hash,
            label="canonical fleet write finalized hash",
        )
        read_hash = _canonical_hash(
            base.block_hash,
            label="fleet read finalized hash",
        )
    except Exception as exc:
        raise UID30LaunchError(f"fleet write head binding failed: {exc}") from exc
    if (
        write.block != base.block_number
        or write_hash != read_hash
        or write.subtensor is not read.subtensor
        or write.wallet is not read.wallet
        or write.connection_target != ARCHIVE_CHAIN_ENDPOINT
        or read.connection_target != ARCHIVE_CHAIN_ENDPOINT
        or write.genesis_hash != base.genesis_hash
        or write.validator_uid != UID30
        or write.validator_hotkey != UID30_HOTKEY
        or getattr(write.wallet.hotkey, "ss58_address", None) != UID30_HOTKEY
        or write.subnet_owner_hotkey != base.subnet_owner_hotkey
        or write.min_allowed_weights != base.min_allowed_weights
        or write.max_weight_limit != base.max_weight_limit
        or write.commit_reveal_enabled is not base.commit_reveal_enabled
        or write.blocks_until_next_epoch != base.blocks_until_next_epoch
        or write.next_epoch_start_block != base.next_epoch_start_block
        or write.weights_rate_limit != base.weights_rate_limit
        or write.validator_blocks_since_last_update != base.blocks_since_last_update
        or write.hotkey_to_uid != read.hotkey_to_uid
        or reverse != read.uid_to_hotkey
        or write.hotkey_to_uid.get(PREDECESSOR_HOTKEY) != PREDECESSOR_UID
        or write.hotkey_to_uid.get(MINER_HOTKEY) != TARGET_UID
    ):
        raise UID30LaunchError(
            "canonical write preflight differs from the exact finalized fleet read"
        )
    return write


def read_fleet_state() -> UID30FleetState:
    """Re-prove signer, cooldown, two predecessor UIDs, and both axons."""

    write = _archive_write_preflight()
    read = _read_preflight_from_write(write)
    read_base = read_uid30_chain_state(preflight=read)
    base = replace(read_base, preflight=_full_write_preflight(read_base, write))
    weights = fleet_preview.read_current_uid30_weights(base)
    axons = fleet_preview.read_weighted_serving_axons(base, weights)
    expected_mapping = {
        PREDECESSOR_UID: PREDECESSOR_HOTKEY,
        TARGET_UID: MINER_HOTKEY,
    }
    if (
        base.miner_uid != TARGET_UID
        or base.miner_hotkey != MINER_HOTKEY
        or base.last_update != canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK
        or weights != ((PREDECESSOR_UID, W), (TARGET_UID, W))
        or {axon.uid: axon.hotkey for axon in axons} != expected_mapping
        or next(axon for axon in axons if axon.uid == TARGET_UID) != base.serving_axon
    ):
        raise UID30LaunchError(
            "current UID30 signer, last_update, row, mapping, or root axon "
            "differs from the exact fleet predecessor"
        )
    try:
        safety = canonical._require_uid_mapping_stability(
            base.preflight,
            expected_mapping,
            mortal_period_blocks=SN39_MORTAL_PERIOD_BLOCKS,
        )
        safety = canonical._require_exact_uid30_fleet_safety(safety)
    except Exception as exc:
        raise UID30LaunchError(f"fleet predecessor UID safety failed: {exc}") from exc
    return UID30FleetState(
        base=base,
        current_weights=weights,
        current_axons=axons,
        uid_safety=safety,
    )


def _canonical_review_heads(
    document: Mapping[str, Any], *, state: UID30FleetState, label: str
) -> None:
    evidence = document["evidence_anchor"]
    recheck = document["finalized_recheck"]
    assert isinstance(evidence, Mapping) and isinstance(recheck, Mapping)
    substrate = state.base.preflight.subtensor.substrate
    for row_label, row in (("evidence", evidence), ("recheck", recheck)):
        block = int(row["block_number"])
        if block > state.base.block_number:
            raise UID30LaunchError(f"{label} {row_label} is ahead of finality")
        try:
            observed = _canonical_hash(
                substrate.get_block_hash(block),
                label=f"canonical {label} {row_label} hash",
            )
        except Exception as exc:
            raise UID30LaunchError(
                f"{label} {row_label} cannot be re-resolved"
            ) from exc
        if observed != row["block_hash"]:
            raise UID30LaunchError(f"{label} {row_label} is not canonical")


def _state_matches_document(
    state: UID30FleetState, document: Mapping[str, Any], *, label: str
) -> None:
    validate_reviewed_preview(document)
    _canonical_review_heads(document, state=state, label=label)
    current = document["current"]
    target = document["consolidation_target"]
    assert isinstance(current, Mapping) and isinstance(target, Mapping)
    current_rows = current.get("weighted_serving_uids")
    expected_axons = {
        axon.uid: f"https://{axon.ip}:{axon.port}" for axon in state.current_axons
    }
    if (
        state.current_weights != ((PREDECESSOR_UID, W), (TARGET_UID, W))
        or not isinstance(current_rows, list)
        or {
            int(row["uid"]): str(row["endpoint"])
            for row in current_rows
            if isinstance(row, Mapping)
        }
        != expected_axons
        or target.get("root_axon") != expected_axons[TARGET_UID]
    ):
        raise UID30LaunchError(f"{label} no longer matches the exact chain axons")


def _same_fleet_identity(reviewed: Mapping[str, Any], fresh: Mapping[str, Any]) -> None:
    reviewed_target = reviewed["consolidation_target"]
    fresh_target = fresh["consolidation_target"]
    assert isinstance(reviewed_target, Mapping) and isinstance(fresh_target, Mapping)
    stable_fields = (
        "endpoint",
        "channel_id",
        "stable_platform_id",
        "machine_id",
    )
    reviewed_rows = sorted(
        reviewed_target["machines"], key=lambda row: str(row["endpoint"])
    )
    fresh_rows = sorted(fresh_target["machines"], key=lambda row: str(row["endpoint"]))
    if (
        reviewed_target.get("root_axon") != fresh_target.get("root_axon")
        or reviewed_target.get("fleet_endpoints") != fresh_target.get("fleet_endpoints")
        or any(
            any(old.get(field) != new.get(field) for field in stable_fields)
            for old, new in zip(reviewed_rows, fresh_rows)
        )
    ):
        raise UID30LaunchError(
            "fresh QVL proof changed a reviewed fleet endpoint or physical identity"
        )


def _predecessor_artifact() -> dict[str, Any]:
    body: dict[str, Any] = {
        "attempt_id": canonical.SN39_UID30_FLEET_PREDECESSOR_ID,
        "identity_sha256": canonical.SN39_UID30_FLEET_PREDECESSOR_IDENTITY_SHA256,
        "intent_sha256": canonical.SN39_UID30_FLEET_PREDECESSOR_INTENT_SHA256,
        "receipt_sha256": canonical.SN39_UID30_FLEET_PREDECESSOR_RECEIPT_SHA256,
        "canonical_journal_filename": (
            canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
        ),
        "journal_identity_sha256": (
            canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_IDENTITY
        ),
        "original_journal_sha256": (
            canonical.SN39_UID30_FLEET_PREDECESSOR_JOURNAL_SHA256
        ),
        "extrinsic_hash": canonical.SN39_UID30_FLEET_PREDECESSOR_EXTRINSIC_HASH,
        "block_hash": canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK_HASH,
        "block_number": canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK,
        "version_key": VERSION_KEY,
        "wire": [[PREDECESSOR_UID, W], [TARGET_UID, W]],
    }
    return {**body, "sha256": canonical._sha256_document(body)}


def _reviewed_subset(document: Mapping[str, Any]) -> dict[str, Any]:
    target = document["consolidation_target"]
    current = document["current"]
    assert isinstance(target, Mapping) and isinstance(current, Mapping)
    return {
        "schema": document["schema"],
        "status": document["status"],
        "evidence_anchor": dict(document["evidence_anchor"]),
        "finalized_recheck": dict(document["finalized_recheck"]),
        "current_uid30_storage": [list(row) for row in current["uid30_storage"]],
        "target_hotkey": target["hotkey"],
        "target_uid": target["uid"],
        "root_axon": target["root_axon"],
        "fleet_endpoints": list(target["fleet_endpoints"]),
        "machines": _proof_rows(document, label="reviewed preview"),
        "raw_uid_units": target["raw_uid_units"],
        "target_wire_row": [
            list(row) for row in target["non_authorizing_target_wire_row"]
        ],
        "qvl_digest": document["qvl_digest"],
        "burn_destination": document["burn_destination"],
        "burn_weight": document["burn_weight"],
    }


def _inclusion_policy(
    state: UID30FleetState, fresh: Mapping[str, Any]
) -> dict[str, Any]:
    now = datetime.now(UTC)
    evidence = fresh["evidence_anchor"]
    assert isinstance(evidence, Mapping)
    return {
        "valid_from_block": int(evidence["block_number"]),
        "valid_until_block": (
            state.base.next_epoch_start_block - SN39_MORTAL_PERIOD_BLOCKS
        ),
        "valid_from_time": launch._canonical_utc(now),
        "valid_until_time": launch._canonical_utc(
            now + timedelta(seconds=PREVIEW_VALIDITY_SECONDS)
        ),
        "require_commit_reveal_disabled": True,
        "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
        "expected_next_epoch_start_block": state.base.next_epoch_start_block,
    }


def _attempt_identity(
    *,
    reviewed: Mapping[str, Any],
    preview_sha256: str,
    fresh: Mapping[str, Any],
    state: UID30FleetState,
) -> dict[str, Any]:
    fresh_rows = _proof_rows(fresh, label="fresh fleet evidence")
    try:
        safety = dict(canonical._require_exact_uid30_fleet_safety(state.uid_safety))
    except Exception as exc:
        raise UID30LaunchError(f"fleet write UID safety is invalid: {exc}") from exc
    base = state.base
    return {
        "network": NETWORK,
        "netuid": NETUID,
        "mapping_block": base.block_number,
        "source_epoch": base.block_number,
        "next_epoch_start_block": base.next_epoch_start_block,
        "subnet_owner_hotkey": base.subnet_owner_hotkey,
        "validator_uid": UID30,
        "validator_hotkey": UID30_HOTKEY,
        "uid_weights": [[TARGET_UID, 1.0]],
        "uid_hotkeys": [[TARGET_UID, MINER_HOTKEY]],
        "predecessor_uid_hotkeys": [
            [PREDECESSOR_UID, PREDECESSOR_HOTKEY],
            [TARGET_UID, MINER_HOTKEY],
        ],
        "allocation_contract": canonical.SN39_UID30_FLEET_POLICY,
        "fleet_consolidation_schema": canonical.SN39_UID30_FLEET_SCHEMA,
        "fleet_consolidation_contract": canonical.SN39_UID30_FLEET_POLICY,
        "fleet_preview_sha256": "sha256:" + preview_sha256,
        "report_id": "sha256:" + preview_sha256,
        "burn_destination": None,
        "burn_share": 0.0,
        "operator_declared_authority": True,
        "exclusive_writer_assertion": {
            "asserted": True,
            "scope": "all_other_uid30_processes_and_hosts_stopped",
        },
        "inclusion_policy": _inclusion_policy(state, fresh),
        "uid_safety": safety,
        "uid_safety_sha256": canonical._sha256_document(safety).removeprefix("sha256:"),
        "validator_eligibility": {
            "uid": UID30,
            "hotkey": UID30_HOTKEY,
            "validator_permit": base.validator_permit,
            "stake_rao": base.validator_stake_rao,
            "stake_threshold_rao": base.stake_threshold_rao,
            "last_update": base.last_update,
            "blocks_since_last_update": base.blocks_since_last_update,
            "weights_rate_limit": base.weights_rate_limit,
            "commit_reveal_enabled": base.commit_reveal_enabled,
            "mechanism_count": base.mechanism_count,
            "weights_version_key": base.weights_version_key,
            "min_allowed_weights": base.min_allowed_weights,
            "max_weight_limit": base.max_weight_limit,
        },
        "reviewed_preview": _reviewed_subset(reviewed),
        "fresh_miner_evidence": fresh_rows,
        "fresh_evidence_sha256": canonical._sha256_document(
            {"proofs": fresh_rows}
        ).removeprefix("sha256:"),
        "predecessor": _predecessor_artifact(),
    }


def _validate_attempt_identity(
    identity: Mapping[str, Any],
    *,
    reviewed: Mapping[str, Any],
    preview_sha256: str,
) -> None:
    try:
        contract = canonical._strict_zero_burn_uid30_fleet_contract(
            dict(identity), lane="authority"
        )
    except Exception as exc:
        raise UID30LaunchError(f"fleet write identity is invalid: {exc}") from exc
    if (
        contract.get("kind") != "same_uid_fleet_consolidation"
        or identity.get("fleet_preview_sha256") != "sha256:" + preview_sha256
        or identity.get("reviewed_preview") != _reviewed_subset(reviewed)
        or identity.get("predecessor") != _predecessor_artifact()
        or identity.get("uid_weights") != [[TARGET_UID, 1.0]]
        or identity.get("uid_hotkeys") != [[TARGET_UID, MINER_HOTKEY]]
        or identity.get("burn_destination") is not None
        or identity.get("burn_share") != 0.0
    ):
        raise UID30LaunchError(
            "fleet write identity differs from the digest-reviewed singleton target"
        )


def _assert_pristine_predecessor(args: Any) -> None:
    path = canonical._submission_state_path(args)
    if (
        path.parent != DEFAULT_RUNTIME_ROOT
        or path.name != canonical.SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
        or canonical._private_state_sha256(path)
        != canonical.SN39_UID30_FLEET_PREDECESSOR_JOURNAL_SHA256
    ):
        raise UID30LaunchError(
            "canonical journal is not the exact finalized two-UID predecessor"
        )


def _require_archive_predecessor(args: Any, preflight: Any) -> None:
    """Prove the pinned predecessor on the fixed archive before machine work."""

    _assert_pristine_predecessor(args)
    if (
        not isinstance(preflight, canonical.ChainPreflight)
        or preflight.connection_target != ARCHIVE_CHAIN_ENDPOINT
        or preflight.genesis_hash != FINNEY_GENESIS_HASH
        or preflight.validator_uid != UID30
        or preflight.validator_hotkey != UID30_HOTKEY
    ):
        raise UID30LaunchError(
            "fleet predecessor proof is not bound to the pinned archive and signer"
        )
    journal = canonical._read_state(canonical._submission_state_path(args))
    predecessor_identity = journal.get("submission_finalized_identity")
    if (
        journal.get("submission_pending_id") is not None
        or journal.get("submission_finalized_id")
        != canonical.SN39_UID30_FLEET_PREDECESSOR_ID
        or not isinstance(predecessor_identity, Mapping)
    ):
        raise UID30LaunchError(
            "canonical journal has no exact finalized fleet predecessor identity"
        )
    try:
        inclusion_policy = canonical._policy_from_submission_identity(
            dict(predecessor_identity)
        )
        substrate = preflight.subtensor.substrate
        genesis_hash = _canonical_hash(
            substrate.get_block_hash(0), label="archive genesis hash"
        )
        historical_hash = _canonical_hash(
            substrate.get_block_hash(canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK),
            label="archive fleet predecessor hash",
        )
        historical_number = _strict_nonnegative_int(
            substrate.get_block_number(historical_hash),
            label="archive fleet predecessor block number",
        )
        historical = substrate.query(
            module="SubtensorModule",
            storage_function="Weights",
            params=[canonical.get_mechid_storage_index(NETUID, MECID), UID30],
            block_hash=historical_hash,
        )
    except UID30LaunchError:
        raise
    except Exception as exc:
        raise UID30LaunchError(
            "pinned archive cannot read the exact finalized fleet predecessor"
        ) from exc
    historical_rows = getattr(historical, "value", historical)
    expected_rows = [[PREDECESSOR_UID, W], [TARGET_UID, W]]
    reason: list[str] = []
    historical_proof = canonical._classify_finalized_receipt(
        preflight.subtensor,
        receipt=None,
        extrinsic_hash=canonical.SN39_UID30_FLEET_PREDECESSOR_EXTRINSIC_HASH,
        block_hash=canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK_HASH,
        block_number=canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK,
        validator_hotkey=UID30_HOTKEY,
        netuid=NETUID,
        version_key=VERSION_KEY,
        wire_uids=[PREDECESSOR_UID, TARGET_UID],
        wire_weights=[W, W],
        uid_hotkeys={
            UID30: UID30_HOTKEY,
            PREDECESSOR_UID: PREDECESSOR_HOTKEY,
            TARGET_UID: MINER_HOTKEY,
        },
        expected_subnet_owner_hotkey=str(
            predecessor_identity.get("subnet_owner_hotkey", "")
        ),
        inclusion_policy=inclusion_policy,
        require_receipt=False,
        reason_out=reason,
    )
    if (
        genesis_hash != FINNEY_GENESIS_HASH
        or historical_hash != canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK_HASH
        or historical_number != canonical.SN39_UID30_FLEET_PREDECESSOR_BLOCK
        or historical_rows
        not in (
            expected_rows,
            [tuple(row) for row in expected_rows],
        )
        or historical_proof != canonical.PASS
    ):
        suffix = f" (cause: {reason[-1]})" if reason else ""
        raise UID30LaunchError(
            "pinned archive did not prove the exact finalized fleet predecessor"
            + suffix
        )


def _verification_state(preflight: Any, reviewed: Mapping[str, Any]) -> Any:
    target = reviewed["consolidation_target"]
    assert isinstance(target, Mapping)
    endpoint = str(target["root_axon"])
    host_port = endpoint.removeprefix("https://").split(":", 1)
    if len(host_port) != 2:
        raise UID30LaunchError("reviewed root axon is malformed")
    return SimpleNamespace(
        preflight=preflight,
        genesis_hash=FINNEY_GENESIS_HASH,
        target=second_miner_plan.Neuron(
            uid=TARGET_UID,
            hotkey=MINER_HOTKEY,
            coldkey=second_miner_plan.CATHEDRAL_COLDKEY,
            validator_permit=False,
            last_update=0,
            ip=host_port[0],
            port=int(host_port[1]),
            protocol=second_miner_plan.HTTPS_PROTOCOL,
            serving=True,
        ),
    )


def _verify_later_finalized_heads(
    *,
    state: Any,
    submission: Any,
    wait_seconds: float = 90.0,
) -> tuple[tuple[int, str], tuple[int, str]]:
    """Prove the singleton row and UID30/UID124 identity at two later heads."""

    substrate = state.preflight.subtensor.substrate
    inclusion_number = _strict_nonnegative_int(
        submission.block_number,
        label="fleet inclusion block number",
    )
    deadline = time.monotonic() + max(0.0, wait_seconds)
    while True:
        try:
            finalized_hash = _canonical_hash(
                substrate.get_chain_finalised_head(), label="later finalized head"
            )
            finalized_number = _strict_nonnegative_int(
                substrate.get_block_number(finalized_hash),
                label="later finalized number",
            )
            if (
                _canonical_hash(
                    substrate.get_block_hash(finalized_number),
                    label="reverse-bound later finalized head",
                )
                != finalized_hash
            ):
                raise launch.UID30LaunchAmbiguous(
                    "later finalized head number and hash do not match"
                )
        except UID30LaunchError:
            raise
        except Exception as exc:
            raise launch.UID30LaunchAmbiguous(
                f"later finalized head is unavailable: {exc}"
            ) from exc
        if finalized_number >= inclusion_number + 2:
            break
        if time.monotonic() >= deadline:
            raise launch.UID30LaunchAmbiguous(
                "two later finalized heads are not available; recover, do not retry"
            )
        time.sleep(2.0)

    proven: list[tuple[int, str]] = []
    for block_number in (finalized_number - 1, finalized_number):
        if block_number <= inclusion_number:
            raise launch.UID30LaunchAmbiguous(
                "later-head verification did not select two post-inclusion heads"
            )
        block_hash = _canonical_hash(
            substrate.get_block_hash(block_number),
            label=f"later finalized block {block_number}",
        )
        try:
            snapshot = second_miner_plan.read_snapshot_at(
                subtensor=state.preflight.subtensor,
                block_number=block_number,
                block_hash=block_hash,
                genesis_hash=state.genesis_hash,
            )
        except Exception as exc:
            raise launch.UID30LaunchAmbiguous(
                f"later finalized block {block_number} is unavailable: {exc}"
            ) from exc
        if snapshot.uid30_weights != ((TARGET_UID, W),):
            raise launch.UID30LaunchContradiction(
                f"UID30 singleton row changed at finalized block {block_number}"
            )
        by_uid = {row.uid: row for row in snapshot.neurons}
        validator = by_uid.get(UID30)
        target = by_uid.get(TARGET_UID)
        if (
            validator is None
            or validator.hotkey != UID30_HOTKEY
            or validator.validator_permit is not True
            or target is None
            or target.hotkey != MINER_HOTKEY
            or target.ip != state.target.ip
            or target.port != state.target.port
            or target.protocol != second_miner_plan.HTTPS_PROTOCOL
            or target.serving is not True
        ):
            raise launch.UID30LaunchContradiction(
                f"UID30 signer or UID124 axon changed at block {block_number}"
            )
        proven.append((block_number, block_hash))
    return proven[0], proven[1]


def submit_reviewed_fleet(
    *,
    preview_path: Path | str,
    reviewed_sha256: str,
    qvl_path: str,
    confirm: bool,
    exclusive_writer_asserted: bool,
) -> UID30FleetSubmissionResult:
    """Submit exactly one UID124 weight after fresh two-machine proof."""

    if confirm is not True:
        raise UID30LaunchError(
            "--confirm-uid30-fleet-consolidation is required; no chain call made"
        )
    if exclusive_writer_asserted is not True:
        raise UID30LaunchError(
            "--assert-exclusive-writer is required; stop every other UID30 writer"
        )
    reviewed, digest = load_reviewed_preview(
        preview_path, reviewed_sha256=reviewed_sha256
    )
    args = _submission_contract(preview_sha256=digest)
    try:
        with canonical._submission_tick_lock(args, lane="authority"):
            evidence_state = read_fleet_state()
            _require_archive_predecessor(args, evidence_state.base.preflight)
            _state_matches_document(evidence_state, reviewed, label="reviewed preview")
            fresh_document = validate_reviewed_preview(
                fleet_preview.collect_preview(
                    qvl_path, chain_endpoint=ARCHIVE_CHAIN_ENDPOINT
                )
            )
            fresh_state = read_fleet_state()
            _state_matches_document(fresh_state, reviewed, label="reviewed preview")
            _state_matches_document(fresh_state, fresh_document, label="fresh proof")
            _same_fleet_identity(reviewed, fresh_document)
            identity = _attempt_identity(
                reviewed=reviewed,
                preview_sha256=digest,
                fresh=fresh_document,
                state=fresh_state,
            )
            _validate_attempt_identity(
                identity, reviewed=reviewed, preview_sha256=digest
            )
            attempt_id = launch._attempt_id(identity)
            try:
                canonical._reserve_common_submission(
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
                receipt = canonical._submit_exact_sn39_extrinsic(
                    fresh_state.base.preflight,
                    runtime_contract=args,
                    attempt_id=attempt_id,
                    netuid=NETUID,
                    version_key=VERSION_KEY,
                    wire_uids=[TARGET_UID],
                    wire_weights=[W],
                    mortal_period_blocks=SN39_MORTAL_PERIOD_BLOCKS,
                    allow_reviewed_uid30_finalized_descendant=False,
                )
                submission = launch._receipt_submission(receipt, state=fresh_state.base)
                canonical._record_pending_submission_receipt(
                    args,
                    attempt_id=attempt_id,
                    submission=submission,
                    version_key=VERSION_KEY,
                    wire_uids=[TARGET_UID],
                    wire_weights=[W],
                )
                readback = launch._finalized_readback(
                    state=fresh_state.base,
                    submission=submission,
                    receipt=receipt,
                    identity=identity,
                    wire_uids=(TARGET_UID,),
                    wire_weights=(W,),
                    uid_hotkeys={TARGET_UID: MINER_HOTKEY},
                )
                if readback.get("dests") != [TARGET_UID] or readback.get(
                    "weights_u16"
                ) != [W]:
                    raise launch.UID30LaunchContradiction(
                        "finalized readback differs from exact UID124 weight 65535"
                    )
                later_heads = _verify_later_finalized_heads(
                    state=_verification_state(fresh_state.base.preflight, reviewed),
                    submission=submission,
                )
                canonical._record_pending_proof_status(
                    args, attempt_id=attempt_id, status=canonical.PASS
                )
                canonical._finalize_common_submission(
                    args,
                    attempt_id=attempt_id,
                    submission=canonical.ChainSubmission(
                        success=True,
                        extrinsic_hash=submission.extrinsic_hash,
                        block_hash=submission.block_hash,
                        block_number=submission.block_number,
                        finalized=True,
                    ),
                    version_key=VERSION_KEY,
                )
            except launch.UID30LaunchContradiction as exc:
                try:
                    canonical._record_pending_proof_status(
                        args, attempt_id=attempt_id, status=canonical.FAIL
                    )
                except Exception as persist_exc:
                    raise launch.UID30LaunchContradiction(
                        f"{exc}; mismatch persistence failed, keep every writer stopped"
                    ) from persist_exc
                raise
            except launch.UID30LaunchAmbiguous:
                raise
            except Exception as exc:
                try:
                    unsigned_aborted = canonical._abort_unsigned_common_submission(
                        args, attempt_id=attempt_id
                    )
                except Exception:
                    unsigned_aborted = False
                if unsigned_aborted:
                    raise UID30LaunchError(
                        f"fleet consolidation refused before signed intent: {exc}"
                    ) from exc
                raise launch.UID30LaunchAmbiguous(
                    "signed intent or receipt remains journaled; recover, do not retry"
                ) from exc
    except (UID30LaunchError, launch.UID30LaunchAmbiguous):
        raise
    except Exception as exc:
        raise UID30LaunchError(f"canonical fleet writer lock refused: {exc}") from exc
    return UID30FleetSubmissionResult(
        preview_sha256=digest,
        attempt_id=attempt_id,
        extrinsic_hash=str(submission.extrinsic_hash),
        block_hash=str(submission.block_hash),
        block_number=int(submission.block_number),
        wire_uids=(TARGET_UID,),
        wire_weights=(W,),
        later_finalized_heads=later_heads,
    )


def _signed_record(
    journal: Mapping[str, Any],
    *,
    prefix: str,
    reviewed: Mapping[str, Any],
    preview_sha256: str,
) -> tuple[str, Mapping[str, Any], Mapping[str, Any]]:
    attempt_id = journal.get(f"submission_{prefix}_id")
    identity = journal.get(f"submission_{prefix}_identity")
    intent = journal.get(f"submission_{prefix}_broadcast_intent")
    if (
        not isinstance(attempt_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", attempt_id) is None
        or journal.get(f"submission_{prefix}_lane") != "authority"
        or journal.get(f"submission_{prefix}_reviewed_uid30_contract")
        != "same_uid_fleet_consolidation"
        or not isinstance(identity, Mapping)
        or not isinstance(intent, Mapping)
    ):
        raise launch.UID30LaunchAmbiguous(
            f"journal has no exact {prefix} fleet consolidation"
        )
    try:
        _validate_attempt_identity(
            identity, reviewed=reviewed, preview_sha256=preview_sha256
        )
    except UID30LaunchError as exc:
        raise launch.UID30LaunchContradiction(
            f"journaled {prefix} fleet identity differs from its reviewed proof"
        ) from exc
    if launch._attempt_id(identity) != attempt_id:
        raise launch.UID30LaunchContradiction(
            "journaled fleet attempt id differs from its identity"
        )
    try:
        intent_hash = _canonical_hash(
            intent["extrinsic_hash"], label="fleet signed intent hash"
        )
        nonce = intent["nonce"]
        era_reference = intent["era_reference_block"]
        mortal = intent["mortal_period_blocks"]
        version = intent["version_key"]
        uids = intent["wire_uids"]
        weights = intent["wire_weights"]
    except (KeyError, TypeError, ValueError) as exc:
        raise launch.UID30LaunchContradiction(
            "journaled fleet signed intent is malformed"
        ) from exc
    if (
        type(nonce) is not int
        or nonce < 0
        or era_reference != identity.get("mapping_block")
        or mortal != SN39_MORTAL_PERIOD_BLOCKS
        or version != VERSION_KEY
        or uids != [TARGET_UID]
        or weights != [W]
    ):
        raise launch.UID30LaunchContradiction(
            "journaled fleet signed intent differs from UID124 weight 65535"
        )
    return attempt_id, identity, {**dict(intent), "extrinsic_hash": intent_hash}


def _archive_recovery_preflight() -> canonical.ChainPreflight:
    """Open recovery on the same fixed archive used by the one-shot writer."""

    try:
        preflight = canonical.chain_preflight(
            network=NETWORK,
            netuid=NETUID,
            wallet_name=WALLET_NAME,
            wallet_hotkey=WALLET_HOTKEY,
            connection_endpoint=ARCHIVE_CHAIN_ENDPOINT,
        )
    except Exception as exc:
        raise launch.UID30LaunchAmbiguous(
            f"read-only archive recovery preflight failed: {exc}"
        ) from exc
    if (
        not isinstance(preflight, canonical.ChainPreflight)
        or preflight.connection_target != ARCHIVE_CHAIN_ENDPOINT
        or preflight.genesis_hash != FINNEY_GENESIS_HASH
        or preflight.validator_hotkey != UID30_HOTKEY
        or preflight.validator_uid != UID30
    ):
        raise launch.UID30LaunchAmbiguous(
            "read-only recovery resolved the wrong endpoint, chain, or validator"
        )
    return preflight


def recover_reviewed_fleet(
    *,
    preview_path: Path | str,
    reviewed_sha256: str,
    exclusive_writer_asserted: bool,
) -> UID30FleetRecoveryResult:
    """Recover the one journaled fleet attempt without signing or submitting."""

    if exclusive_writer_asserted is not True:
        raise UID30LaunchError(
            "--assert-exclusive-writer is required; stop every other UID30 writer"
        )
    reviewed, digest = load_reviewed_preview(
        preview_path, reviewed_sha256=reviewed_sha256
    )
    args = _submission_contract(preview_sha256=digest)
    try:
        with canonical._submission_tick_lock(args, lane="authority"):
            journal_path = canonical._submission_state_path(args)
            journal = canonical._read_state(journal_path)
            if (
                journal.get("submission_pending_id") is None
                and canonical._private_state_sha256(journal_path)
                == canonical.SN39_UID30_FLEET_PREDECESSOR_JOURNAL_SHA256
            ):
                raise UID30LaunchError(
                    "exact predecessor is pristine; no fleet write attempt exists"
                )
            if journal.get("submission_expired_id") is not None:
                expired_id = journal.get("submission_expired_id")
                expired_identity = journal.get("submission_expired_identity")
                expired_intent = journal.get("submission_expired_broadcast_intent")
                budget = journal.get("submission_attempt_budgets", {}).get(
                    canonical.SN39_UID30_FLEET_BUDGET_SCOPE
                )
                if (
                    journal.get("submission_pending_id") is not None
                    or journal.get("submission_expired_status")
                    != canonical.EXPIRED_WITHOUT_INCLUSION
                    or journal.get("submission_expired_lane") != "authority"
                    or not isinstance(expired_id, str)
                    or not isinstance(expired_identity, Mapping)
                    or not isinstance(expired_intent, Mapping)
                    or budget != {"limit": 1, "ids": [expired_id]}
                    or expired_id not in journal.get("submission_attempt_ids", [])
                ):
                    raise launch.UID30LaunchContradiction(
                        "expired fleet attempt or its consumed budget is malformed"
                    )
                synthetic = dict(journal)
                synthetic["submission_expired_reviewed_uid30_contract"] = (
                    "same_uid_fleet_consolidation"
                )
                attempt_id, _identity, intent = _signed_record(
                    synthetic,
                    prefix="expired",
                    reviewed=reviewed,
                    preview_sha256=digest,
                )
                if attempt_id != expired_id:
                    raise launch.UID30LaunchContradiction(
                        "expired fleet attempt differs from its signed identity"
                    )
                return UID30FleetRecoveryResult(
                    status=canonical.EXPIRED_WITHOUT_INCLUSION,
                    preview_sha256=digest,
                    attempt_id=attempt_id,
                    extrinsic_hash=str(intent["extrinsic_hash"]),
                    block_hash=None,
                    block_number=None,
                    wire_uids=(TARGET_UID,),
                    wire_weights=None,
                    later_finalized_heads=None,
                )
            finalized = journal.get("submission_pending_id") is None
            if not finalized and journal.get("submission_pending_phase") == (
                "unsigned_reserved"
            ):
                attempt_id = str(journal.get("submission_pending_id") or "")
                identity = journal.get("submission_pending_identity")
                if not isinstance(identity, Mapping):
                    raise launch.UID30LaunchAmbiguous(
                        "unsigned fleet reservation lost its identity"
                    )
                _validate_attempt_identity(
                    identity, reviewed=reviewed, preview_sha256=digest
                )
                if not canonical._abort_unsigned_common_submission(
                    args, attempt_id=attempt_id
                ):
                    raise launch.UID30LaunchAmbiguous(
                        "unsigned fleet reservation changed under the writer lock"
                    )
                return UID30FleetRecoveryResult(
                    status="UNSIGNED_RESERVATION_RELEASED",
                    preview_sha256=digest,
                    attempt_id=attempt_id,
                    extrinsic_hash=None,
                    block_hash=None,
                    block_number=None,
                    wire_uids=(TARGET_UID,),
                    wire_weights=None,
                    later_finalized_heads=None,
                )
            if not finalized and journal.get("submission_pending_phase") != (
                "signed_intent"
            ):
                raise launch.UID30LaunchAmbiguous(
                    "fleet journal has no recognized recovery phase"
                )
            if journal.get("submission_pending_proof_status") == canonical.FAIL:
                raise launch.UID30LaunchContradiction(
                    "fleet journal contains a positive historical mismatch"
                )

            prefix = "finalized" if finalized else "pending"
            attempt_id, identity, intent = _signed_record(
                journal,
                prefix=prefix,
                reviewed=reviewed,
                preview_sha256=digest,
            )
            preflight = _archive_recovery_preflight()
            verification_state = _verification_state(preflight, reviewed)
            receipt_row = journal.get(f"submission_{prefix}_receipt")
            if finalized:
                receipt_row = journal.get("submission_finalized_receipt")
            elif receipt_row is None:
                receipt_row = journal.get("submission_pending_receipt_candidate")
            if receipt_row is None:
                status, located = canonical._locate_pending_broadcast_receipt(
                    preflight.subtensor,
                    extrinsic_hash=str(intent["extrinsic_hash"]),
                    era_reference_block=int(intent["era_reference_block"]),
                    mortal_period_blocks=int(intent["mortal_period_blocks"]),
                    validator_hotkey=UID30_HOTKEY,
                    netuid=NETUID,
                    version_key=VERSION_KEY,
                    wire_uids=[TARGET_UID],
                    wire_weights=[W],
                    inclusion_policy=canonical._policy_from_submission_identity(
                        dict(identity)
                    ),
                )
                if status == canonical.EXPIRED_WITHOUT_INCLUSION:
                    canonical._expire_pending_common_submission(
                        args, attempt_id=attempt_id
                    )
                    return UID30FleetRecoveryResult(
                        status=canonical.EXPIRED_WITHOUT_INCLUSION,
                        preview_sha256=digest,
                        attempt_id=attempt_id,
                        extrinsic_hash=str(intent["extrinsic_hash"]),
                        block_hash=None,
                        block_number=None,
                        wire_uids=(TARGET_UID,),
                        wire_weights=None,
                        later_finalized_heads=None,
                    )
                if status == canonical.FAIL:
                    try:
                        canonical._record_pending_proof_status(
                            args, attempt_id=attempt_id, status=canonical.FAIL
                        )
                    except Exception as persist_exc:
                        raise launch.UID30LaunchContradiction(
                            "fleet historical call contradicts its signed intent, "
                            "and the mismatch could not be persisted"
                        ) from persist_exc
                    raise launch.UID30LaunchContradiction(
                        "fleet historical call contradicts its signed intent"
                    )
                if status != canonical.PASS or located is None:
                    raise launch.UID30LaunchAmbiguous(
                        "signed fleet attempt remains unresolved; do not retry"
                    )
                submission = located
                canonical._record_pending_submission_receipt(
                    args,
                    attempt_id=attempt_id,
                    submission=submission,
                    version_key=VERSION_KEY,
                    wire_uids=[TARGET_UID],
                    wire_weights=[W],
                )
            else:
                if not isinstance(receipt_row, Mapping):
                    raise launch.UID30LaunchContradiction(
                        "journaled fleet receipt is malformed"
                    )
                try:
                    submission = canonical.ChainSubmission(
                        success=True,
                        extrinsic_hash=_canonical_hash(
                            receipt_row["extrinsic_hash"],
                            label="fleet receipt extrinsic hash",
                        ),
                        block_hash=_canonical_hash(
                            receipt_row["block_hash"], label="fleet receipt block hash"
                        ),
                        block_number=_strict_nonnegative_int(
                            receipt_row["block_number"],
                            label="fleet receipt block number",
                        ),
                        finalized=True,
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise launch.UID30LaunchContradiction(
                        "journaled fleet receipt is malformed"
                    ) from exc
                if (
                    submission.extrinsic_hash != intent["extrinsic_hash"]
                    or receipt_row.get("version_key") != VERSION_KEY
                    or receipt_row.get("wire_uids") != [TARGET_UID]
                    or receipt_row.get("wire_weights") != [W]
                ):
                    raise launch.UID30LaunchContradiction(
                        "journaled fleet receipt differs from its signed intent"
                    )

            try:
                launch._finalized_readback(
                    state=SimpleNamespace(preflight=preflight, miner_uid=TARGET_UID),
                    submission=submission,
                    receipt=None,
                    identity=identity,
                    require_receipt=False,
                    wire_uids=(TARGET_UID,),
                    wire_weights=(W,),
                    uid_hotkeys={TARGET_UID: MINER_HOTKEY},
                )
                later_heads = _verify_later_finalized_heads(
                    state=verification_state, submission=submission
                )
            except launch.UID30LaunchContradiction:
                if not finalized:
                    canonical._record_pending_proof_status(
                        args, attempt_id=attempt_id, status=canonical.FAIL
                    )
                raise
            if not finalized:
                canonical._record_pending_proof_status(
                    args, attempt_id=attempt_id, status=canonical.PASS
                )
                canonical._finalize_common_submission(
                    args,
                    attempt_id=attempt_id,
                    submission=canonical.ChainSubmission(
                        success=True,
                        extrinsic_hash=submission.extrinsic_hash,
                        block_hash=submission.block_hash,
                        block_number=submission.block_number,
                        finalized=True,
                    ),
                    version_key=VERSION_KEY,
                )
            return UID30FleetRecoveryResult(
                status="ALREADY_FINALIZED" if finalized else "RECOVERED_FINALIZED",
                preview_sha256=digest,
                attempt_id=attempt_id,
                extrinsic_hash=str(submission.extrinsic_hash),
                block_hash=str(submission.block_hash),
                block_number=int(submission.block_number),
                wire_uids=(TARGET_UID,),
                wire_weights=(W,),
                later_finalized_heads=later_heads,
            )
    except (UID30LaunchError, launch.UID30LaunchAmbiguous):
        raise
    except Exception as exc:
        raise launch.UID30LaunchAmbiguous(
            f"read-only fleet recovery remains fenced: {exc}"
        ) from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cathedral-uid30-fleet-submit")
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit", help="one digest-bound UID124 singleton write")
    submit.add_argument("--preview", required=True)
    submit.add_argument("--reviewed-sha256", required=True)
    submit.add_argument("--qvl", required=True)
    submit.add_argument("--confirm-uid30-fleet-consolidation", action="store_true")
    submit.add_argument("--assert-exclusive-writer", action="store_true")
    recover = sub.add_parser(
        "recover", help="recover the same attempt without signing or submitting"
    )
    recover.add_argument("--preview", required=True)
    recover.add_argument("--reviewed-sha256", required=True)
    recover.add_argument("--assert-exclusive-writer", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if options.command == "submit":
            result = submit_reviewed_fleet(
                preview_path=Path(options.preview),
                reviewed_sha256=options.reviewed_sha256,
                qvl_path=options.qvl,
                confirm=options.confirm_uid30_fleet_consolidation,
                exclusive_writer_asserted=options.assert_exclusive_writer,
            )
        else:
            result = recover_reviewed_fleet(
                preview_path=Path(options.preview),
                reviewed_sha256=options.reviewed_sha256,
                exclusive_writer_asserted=options.assert_exclusive_writer,
            )
        print(json.dumps(result.__dict__, indent=2, sort_keys=True))
        return 0
    except launch.UID30LaunchAmbiguous as exc:
        print(
            json.dumps(
                {"status": "AMBIGUOUS_DO_NOT_RETRY", "error": str(exc)},
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 3
    except UID30LaunchError as exc:
        print(
            json.dumps(
                {"status": "REFUSED_NO_CHAIN_WRITE", "error": str(exc)},
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
