"""Dedicated no-write SN39 multi-machine scoring preview.

This console reads one finalized SN39 metagraph, authenticates worker HTTPS
requests with the pinned UID30 hotkey, verifies bounded fleets, and renders a
non-authorizing normalized row.  It imports no Cloud client, canary writer,
journal, account-nonce helper, extrinsic builder, or submission transport.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import bittensor as bt
from bittensor.utils.weight_utils import convert_and_normalize_weights_and_uids

from cathedral_thin.bt_compat import make_subtensor, make_wallet
from cathedral_thin.independent.compute import ComputeAdapter
from cathedral_thin.independent.constants import (
    FINNEY_GENESIS_HASH,
    INTEL_COLLATERAL,
    MAX_DESTS,
    MULTICOMPUTE_FLEET_CAP,
    MULTICOMPUTE_MACHINE_WORK_UNIT_CAP,
    NETUID,
    UID30_VALIDATOR_HOTKEY,
    UID30_VALIDATOR_UID,
)
from cathedral_thin.independent.errors import IndependentValidatorError

from .axon import ServingAxon, observed_genesis_hash, scan_axons
from .errors import IndependentLiveError, QuoteVerifyError
from .fleet_score import MultiComputeRound, score_multicompute_round
from .preview_io import PreviewWriteError, write_owner_only_preview
from .qvl import load_verifier

SCHEMA = "cathedral_multicompute_preview_v1"
STATUS = "PROVEN_NO_WRITE_PREVIEW"
NOT_PROVEN_STATUS = "NOT_PROVEN_NO_WRITE"
_CHAIN_HASH_RE = re.compile(r"0x[0-9a-f]{64}")


class FleetPreviewError(Exception):
    """The generic preview refused without reaching a chain-write boundary."""


@dataclass(frozen=True)
class FinalizedFleetSnapshot:
    keypair: Any
    block_number: int
    block_hash: str
    genesis_hash: str
    validator_uid: int
    validator_hotkey: str
    uid_to_hotkey: dict[int, str]
    hotkey_to_uid: dict[str, int]
    axons: tuple[ServingAxon, ...]
    skipped: dict[str, int]


def _strict_int(value: Any, *, label: str) -> int:
    raw = getattr(value, "value", value)
    item = getattr(raw, "item", None)
    if callable(item):
        raw = item()
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise FleetPreviewError(f"{label} is not a non-negative integer")
    return raw


def _strict_bool(value: Any, *, label: str) -> bool:
    raw = getattr(value, "value", value)
    item = getattr(raw, "item", None)
    if callable(item):
        raw = item()
    if type(raw) is not bool:
        raise FleetPreviewError(f"{label} is not an explicit boolean")
    return raw


def _canonical_hash(value: Any, *, label: str) -> str:
    text = str(value).lower()
    if _CHAIN_HASH_RE.fullmatch(text) is None:
        raise FleetPreviewError(f"{label} is not a canonical chain hash")
    return text


def read_finalized_snapshot(
    *, wallet_name: str, wallet_hotkey: str, wallet_path: str | None
) -> FinalizedFleetSnapshot:
    """Read one finalized metagraph and the pinned request-signing identity."""

    try:
        wallet = make_wallet(
            bt,
            name=wallet_name,
            hotkey=wallet_hotkey,
            path=wallet_path or None,
        )
        keypair = wallet.hotkey
        if str(
            getattr(keypair, "ss58_address", "")
        ) != UID30_VALIDATOR_HOTKEY or not callable(getattr(keypair, "sign", None)):
            raise FleetPreviewError(
                "request wallet is not the pinned UID30 signing hotkey"
            )
        subtensor = make_subtensor(bt, network="finney")
        substrate = getattr(subtensor, "substrate", None)
        if substrate is None:
            raise FleetPreviewError("subtensor has no finalized-head reader")
        block_hash = _canonical_hash(
            substrate.get_chain_finalised_head(), label="finalized block hash"
        )
        block_number = _strict_int(
            substrate.get_block_number(block_hash), label="finalized block"
        )
        reverse = _canonical_hash(
            substrate.get_block_hash(block_number),
            label="canonical finalized block hash",
        )
        if reverse != block_hash:
            raise FleetPreviewError("finalized block number and hash are not canonical")
        genesis_hash = observed_genesis_hash(subtensor)
        if genesis_hash != FINNEY_GENESIS_HASH:
            raise FleetPreviewError("subtensor is not the pinned Finney chain")
        metagraph = subtensor.metagraph(NETUID, block=block_number)
        if (
            _strict_int(getattr(metagraph, "block", None), label="metagraph block")
            != block_number
        ):
            raise FleetPreviewError("SN39 metagraph is not at the finalized head")
        raw_uids = (
            metagraph.uids.tolist()
            if hasattr(metagraph.uids, "tolist")
            else list(metagraph.uids)
        )
        uids = [_strict_int(value, label="metagraph UID") for value in raw_uids]
        hotkeys = [str(value) for value in list(metagraph.hotkeys)]
        permits = list(metagraph.validator_permit)
        if not (len(uids) == len(hotkeys) == len(permits)):
            raise FleetPreviewError("SN39 metagraph identity arrays are inconsistent")
        if not uids or len(uids) > MAX_DESTS:
            raise FleetPreviewError(
                f"SN39 registered-set size is outside 1..{MAX_DESTS}"
            )
        if len(set(uids)) != len(uids) or len(set(hotkeys)) != len(hotkeys):
            raise FleetPreviewError("SN39 metagraph repeats a UID or hotkey")
        hotkey_to_uid = dict(zip(hotkeys, uids))
        uid_to_hotkey = dict(zip(uids, hotkeys))
        validator_uid = hotkey_to_uid.get(UID30_VALIDATOR_HOTKEY)
        if validator_uid != UID30_VALIDATOR_UID:
            raise FleetPreviewError("pinned UID30 hotkey mapping changed")
        validator_index = uids.index(UID30_VALIDATOR_UID)
        if (
            _strict_bool(permits[validator_index], label="UID30 validator permit")
            is not True
        ):
            raise FleetPreviewError("UID30 lacks its finalized validator permit")
        scan = scan_axons(metagraph)
    except FleetPreviewError:
        raise
    except Exception as exc:
        raise FleetPreviewError(f"finalized SN39 preview failed: {exc}") from exc
    return FinalizedFleetSnapshot(
        keypair=keypair,
        block_number=block_number,
        block_hash=block_hash,
        genesis_hash=genesis_hash,
        validator_uid=UID30_VALIDATOR_UID,
        validator_hotkey=UID30_VALIDATOR_HOTKEY,
        uid_to_hotkey=uid_to_hotkey,
        hotkey_to_uid=hotkey_to_uid,
        axons=scan.serving,
        skipped=dict(scan.skipped),
    )


def _normalized_row(
    snapshot: FinalizedFleetSnapshot, units: Mapping[str, int]
) -> tuple[tuple[int, int], ...]:
    rows: list[tuple[int, int]] = []
    for hotkey, raw_units in units.items():
        uid = snapshot.hotkey_to_uid.get(hotkey)
        if isinstance(uid, bool) or not isinstance(uid, int):
            raise FleetPreviewError(
                "verified work belongs to a hotkey absent from the finalized head"
            )
        if (
            isinstance(raw_units, bool)
            or not isinstance(raw_units, int)
            or raw_units <= 0
        ):
            raise FleetPreviewError("verified work units are not positive integers")
        rows.append((uid, raw_units))
    rows.sort()
    if not rows:
        return ()
    wire_uids, wire_weights = convert_and_normalize_weights_and_uids(
        [uid for uid, _units in rows], [units for _uid, units in rows]
    )
    encoded = tuple(
        (int(uid), int(weight)) for uid, weight in zip(wire_uids, wire_weights)
    )
    if [uid for uid, _weight in encoded] != [uid for uid, _units in rows]:
        raise FleetPreviewError("installed Bittensor reordered the reviewed UIDs")
    if any(weight <= 0 or weight > 65535 for _uid, weight in encoded):
        raise FleetPreviewError("installed Bittensor produced an invalid u16 row")
    return encoded


def build_preview_document(
    *,
    snapshot: FinalizedFleetSnapshot,
    round_result: MultiComputeRound,
    qvl_digest: str,
) -> dict[str, Any]:
    blockers = list(round_result.blockers)
    if round_result.feature_blocked:
        blockers.append("stable platform identity capability is unavailable")
    if round_result.qvl_infra_count:
        blockers.append(
            f"QVL infrastructure failed for {round_result.qvl_infra_count} quote(s)"
        )
    row = _normalized_row(snapshot, round_result.verified_units)
    if not row:
        blockers.append("no independently re-derived work units")
    status = STATUS if not blockers else NOT_PROVEN_STATUS
    raw_rows = [
        {
            "uid": snapshot.hotkey_to_uid[hotkey],
            "hotkey": hotkey,
            "raw_uid_units": units,
        }
        for hotkey, units in sorted(
            round_result.verified_units.items(),
            key=lambda item: snapshot.hotkey_to_uid.get(item[0], MAX_DESTS + 1),
        )
        if hotkey in snapshot.hotkey_to_uid
    ]
    return {
        "schema": SCHEMA,
        "status": status,
        "network": "finney",
        "netuid": NETUID,
        "finalized_anchor": {
            "block_number": snapshot.block_number,
            "block_hash": snapshot.block_hash,
            "genesis_hash": snapshot.genesis_hash,
        },
        "validator": {
            "uid": snapshot.validator_uid,
            "hotkey": snapshot.validator_hotkey,
        },
        "score_contract": {
            "formula": "sum independently re-derived verified work_units across unique physical identities",
            "fleet_cap_per_uid": MULTICOMPUTE_FLEET_CAP,
            "per_machine_work_unit_cap": MULTICOMPUTE_MACHINE_WORK_UNIT_CAP,
            "declared_machine_count_bonus_units": 0,
            "attestation_only_bonus_units": 0,
            "hardware_identity": "QVL-verified stable_platform_id",
        },
        "serving_axon_count": len(snapshot.axons),
        "axon_skip": dict(snapshot.skipped),
        "fleet_discovery": list(round_result.fleet),
        "machine_observations": list(round_result.rows),
        "raw_uid_units": raw_rows,
        "non_authorizing_normalized_row": [list(item) for item in row],
        "qvl_digest": qvl_digest,
        "exclusions": list(round_result.exclusions),
        "blockers": blockers,
        "burn_destination": None,
        "burn_weight": 0,
        "authorized_for_chain_write": False,
        "chain_write_submitted": False,
        "weight_signed": False,
        "weight_submitted": False,
        "proof_boundary": (
            "This artifact proves only the finalized read, signed HTTPS/QVL/SAT "
            "observations, global duplicate handling, raw aggregation, and local "
            "normalization. It is not accepted by a chain writer and does not "
            "prove subnet emission or TAO earnings."
        ),
    }


def collect_preview(options: argparse.Namespace) -> dict[str, Any]:
    snapshot = read_finalized_snapshot(
        wallet_name=options.wallet_name,
        wallet_hotkey=options.wallet_hotkey,
        wallet_path=options.wallet_path,
    )
    verifier = load_verifier(options.qvl)
    adapter = ComputeAdapter(
        verifier,
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=verifier.digest,
    )
    result = score_multicompute_round(
        axons=snapshot.axons,
        keypair=snapshot.keypair,
        anchor_hash=snapshot.block_hash,
        verifier_adapter=adapter,
    )
    return build_preview_document(
        snapshot=snapshot, round_result=result, qvl_digest=verifier.digest
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m cathedral_thin.independent_runtime.fleet_preview",
        allow_abbrev=False,
    )
    parser.add_argument("--qvl", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--wallet-name", default="cathedral")
    parser.add_argument("--wallet-hotkey", default="default")
    parser.add_argument("--wallet-path", default=None)
    return parser


def _refusal(exc: Exception) -> dict[str, Any]:
    return {
        "status": "REFUSED_NO_CHAIN_WRITE",
        "error": str(exc),
        "authorized_for_chain_write": False,
        "chain_write_submitted": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        document = collect_preview(options)
        path, digest_path, digest = write_owner_only_preview(
            document, Path(options.output)
        )
    except (
        FleetPreviewError,
        IndependentLiveError,
        IndependentValidatorError,
        PreviewWriteError,
        QuoteVerifyError,
        OSError,
    ) as exc:
        print(json.dumps(_refusal(exc), sort_keys=True), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": document["status"],
                "preview": str(path),
                "detached_sha256": str(digest_path),
                "sha256": digest,
                "authorized_for_chain_write": False,
                "chain_write_submitted": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if document["status"] == STATUS else 2


if __name__ == "__main__":
    raise SystemExit(main())
