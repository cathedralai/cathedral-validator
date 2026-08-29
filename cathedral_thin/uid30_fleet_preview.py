"""No-write proof for consolidating verified machines behind one SN39 UID.

The command records the current UID30 row and independently scores every
weighted serving UID. It renders a singleton target only for the canonical
launch miner, and calls it proven only after the miner's signed fleet proves
two distinct TDX platforms with SAT20 each and survives finalized rechecks.

There is no journal, nonce, extrinsic, confirmation, submit, or recovery path.
The artifact schema is not accepted by a UID30 writer.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from bittensor.utils import get_mechid_storage_index
from bittensor.utils.weight_utils import convert_and_normalize_weights_and_uids

from cathedral_thin.independent.compute import (
    ComputeAdapter,
    machine_id_from_stable_platform_id,
    require_machine_id,
    require_stable_platform_id,
)
from cathedral_thin.independent.constants import (
    INTEL_COLLATERAL,
    MECID,
    NETUID,
    SN39_MORTAL_PERIOD_BLOCKS,
    W,
)
from cathedral_thin.independent.errors import IndependentValidatorError
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.errors import IndependentLiveError
from cathedral_thin.independent_runtime.fleet_score import (
    MultiComputeRound,
    score_multicompute_round,
)
from cathedral_thin.independent_runtime.https import HttpsEvidenceTransport, axon_origin
from cathedral_thin.independent_runtime.preview_io import (
    PreviewWriteError,
    canonical_document_bytes,
    write_owner_only_preview,
)
from cathedral_thin.independent_runtime.qvl import LAUNCH_QVL_DIGEST, load_verifier
from cathedral_thin.independent_runtime.validator_request import (
    SignedValidatorTransport,
    fetch_worker_fleet,
)
from cathedral_thin.uid30_state import (
    MINER_HOTKEY,
    UID30,
    UID30_HOTKEY,
    UID30ChainState,
    UID30LaunchError,
    _serving_axon_from_info_row,
    _strict_nonnegative_int,
    read_uid30_chain_state,
)

SCHEMA = "cathedral_uid30_same_uid_fleet_preview_v1"
STATUS = "PROVEN_TWO_MACHINE_NO_WRITE_PREVIEW"
NOT_PROVEN_STATUS = "NOT_PROVEN_NO_WRITE"
EXPECTED_MACHINES = 2
EXPECTED_MACHINE_UNITS = 20
EXPECTED_RAW_UID_UNITS = EXPECTED_MACHINES * EXPECTED_MACHINE_UNITS


class UID30FleetPreviewError(Exception):
    """The preview refused without creating chain authority."""


def _keypair(state: UID30ChainState) -> Any:
    keypair = getattr(state.preflight.wallet, "hotkey", None)
    if (
        keypair is None
        or str(getattr(keypair, "ss58_address", "")) != UID30_HOTKEY
        or not callable(getattr(keypair, "sign", None))
    ):
        raise UID30FleetPreviewError(
            "finalized UID30 preflight did not load the pinned signing hotkey"
        )
    return keypair


def _weights_rows(value: Any) -> tuple[tuple[int, int], ...]:
    raw = value.value if hasattr(value, "value") else value
    if not isinstance(raw, (list, tuple)) or not raw:
        raise UID30FleetPreviewError(
            "current UID30 weight storage is not a non-empty sequence"
        )
    rows: list[tuple[int, int]] = []
    for index, row in enumerate(raw):
        if not isinstance(row, (list, tuple)) or len(row) != 2:
            raise UID30FleetPreviewError(
                f"current UID30 weight row {index} is malformed"
            )
        uid, weight = row
        if (
            isinstance(uid, bool)
            or not isinstance(uid, int)
            or isinstance(weight, bool)
            or not isinstance(weight, int)
            or not 0 <= uid <= W
            or not 0 < weight <= W
        ):
            raise UID30FleetPreviewError(
                f"current UID30 weight row {index} is not positive exact u16 data"
            )
        rows.append((uid, weight))
    if len({uid for uid, _weight in rows}) != len(rows):
        raise UID30FleetPreviewError("current UID30 storage repeats a destination")
    return tuple(rows)


def read_current_uid30_weights(state: UID30ChainState) -> tuple[tuple[int, int], ...]:
    value = state.preflight.subtensor.substrate.query(
        module="SubtensorModule",
        storage_function="Weights",
        params=[get_mechid_storage_index(NETUID, MECID), UID30],
        block_hash=state.block_hash,
    )
    return _weights_rows(value)


def read_weighted_serving_axons(
    state: UID30ChainState,
    current_weights: Sequence[tuple[int, int]],
) -> tuple[ServingAxon, ...]:
    """Resolve each positive UID30 destination at the same finalized head."""

    info = state.preflight.subtensor.get_metagraph_info(
        NETUID, MECID, block=state.block_number
    )
    if info is None:
        raise UID30FleetPreviewError("weighted UID metagraph info is unavailable")
    try:
        info_block = _strict_nonnegative_int(
            getattr(info, "block", None), label="weighted UID metagraph block"
        )
    except UID30LaunchError as exc:
        raise UID30FleetPreviewError(str(exc)) from exc
    if info_block != state.block_number:
        raise UID30FleetPreviewError(
            "weighted UID metagraph is not at the finalized proof head"
        )
    hotkeys = [str(value) for value in list(info.hotkeys)]
    axon_rows = list(info.axons)
    if len(hotkeys) != len(axon_rows):
        raise UID30FleetPreviewError("weighted UID metagraph arrays are inconsistent")
    resolved: list[ServingAxon] = []
    for uid, _weight in current_weights:
        if uid >= len(hotkeys):
            raise UID30FleetPreviewError(
                f"current UID30 destination {uid} is outside the metagraph"
            )
        hotkey = hotkeys[uid]
        if state.preflight.hotkey_to_uid.get(hotkey) != uid:
            raise UID30FleetPreviewError(
                f"current UID30 destination {uid} has no bidirectional hotkey mapping"
            )
        raw = axon_rows[uid]
        try:
            axon = _serving_axon_from_info_row(raw, uid=uid, hotkey=hotkey)
            if not isinstance(raw, Mapping):
                raise UID30LaunchError("serving-axon row is not a mapping")
            protocol = _strict_nonnegative_int(
                raw.get("protocol"), label="serving-axon protocol"
            )
        except UID30LaunchError as exc:
            raise UID30FleetPreviewError(str(exc)) from exc
        if axon.ip == "0.0.0.0" or axon.port != 8081 or protocol != 4:
            raise UID30FleetPreviewError(
                f"current UID30 destination {uid} is not serving HTTPS protocol 4"
            )
        resolved.append(axon)
    return tuple(resolved)


def _require_chain_continuity(
    evidence: UID30ChainState, fresh: UID30ChainState
) -> None:
    if fresh.block_number < evidence.block_number:
        raise UID30FleetPreviewError("finalized chain moved backward during proof")
    if fresh.block_number - evidence.block_number > SN39_MORTAL_PERIOD_BLOCKS:
        raise UID30FleetPreviewError("fleet proof exceeded its finalized-head window")
    if (
        fresh.genesis_hash != evidence.genesis_hash
        or fresh.validator_uid != UID30
        or fresh.validator_hotkey != UID30_HOTKEY
        or fresh.miner_uid != evidence.miner_uid
        or fresh.miner_hotkey != MINER_HOTKEY
        or fresh.subnet_owner_hotkey != evidence.subnet_owner_hotkey
        or fresh.serving_axon != evidence.serving_axon
    ):
        raise UID30FleetPreviewError(
            "UID30, consolidation owner, subnet owner, or root axon changed"
        )
    canonical = str(
        fresh.preflight.subtensor.substrate.get_block_hash(evidence.block_number)
    ).lower()
    if canonical != evidence.block_hash:
        raise UID30FleetPreviewError("fleet evidence anchor is no longer canonical")
    fresh_canonical = str(
        fresh.preflight.subtensor.substrate.get_block_hash(fresh.block_number)
    ).lower()
    if fresh_canonical != fresh.block_hash:
        raise UID30FleetPreviewError("fleet finalized recheck is not canonical")


def _target_fleet_endpoints(
    round_result: MultiComputeRound, *, state: UID30ChainState
) -> tuple[str, ...]:
    matches = [
        fleet
        for fleet in round_result.fleet
        if isinstance(fleet, Mapping)
        and fleet.get("uid") == state.miner_uid
        and fleet.get("hotkey") == MINER_HOTKEY
    ]
    if len(matches) != 1:
        raise UID30FleetPreviewError(
            "scoring round has no unique consolidation-owner fleet"
        )
    fleet = matches[0]
    endpoints = fleet.get("endpoints")
    if (
        fleet.get("ok") is not True
        or fleet.get("singleton_compatibility") is not False
        or not isinstance(endpoints, list)
        or len(endpoints) != EXPECTED_MACHINES
        or any(not isinstance(endpoint, str) for endpoint in endpoints)
    ):
        reason = fleet.get("error")
        suffix = f": {reason}" if isinstance(reason, str) and reason else ""
        raise UID30FleetPreviewError(
            "consolidation owner has not exposed exactly two fleet endpoints" + suffix
        )
    resolved = tuple(endpoints)
    expected_root = axon_origin(state.serving_axon.ip, state.serving_axon.port)
    if fleet.get("primary") != expected_root or resolved[0] != expected_root:
        raise UID30FleetPreviewError(
            "consolidation fleet is not rooted at its finalized chain axon"
        )
    return resolved


def _target_machine_rows(
    round_result: MultiComputeRound,
    *,
    state: UID30ChainState,
    endpoints: Sequence[str],
) -> tuple[dict[str, Any], ...]:
    if (
        round_result.qvl_infra_count
        or round_result.feature_blocked
        or round_result.blockers
        or round_result.verified_units.get(MINER_HOTKEY) != EXPECTED_RAW_UID_UNITS
    ):
        raise UID30FleetPreviewError(
            "consolidation owner lacks 40 independently verified work units"
        )
    target_rows = [
        row
        for row in round_result.rows
        if row.get("uid") == state.miner_uid and row.get("hotkey") == MINER_HOTKEY
    ]
    if len(target_rows) != EXPECTED_MACHINES:
        raise UID30FleetPreviewError(
            "consolidation proof does not contain exactly two target machines"
        )
    machines: list[dict[str, Any]] = []
    for row in target_rows:
        if (
            row.get("endpoint") not in endpoints
            or row.get("verdict") != "PASS"
            or row.get("platform_identity_verified") is not True
            or row.get("sat_units") != EXPECTED_MACHINE_UNITS
            or row.get("counted_units") != EXPECTED_MACHINE_UNITS
            or row.get("sat_rule") != SAT_WORK_UNIT_RULE
            or row.get("score_reasons")
        ):
            raise UID30FleetPreviewError(
                "one consolidation candidate lacks exact QVL and SAT proof"
            )
        machines.append(
            {
                "endpoint": row.get("endpoint"),
                "channel_id": row.get("channel_id"),
                "stable_platform_id": row.get("stable_platform_id"),
                "machine_id": row.get("machine_id"),
                "quote_sha256": row.get("quote_sha256"),
                "report_data_sha256": row.get("report_data_sha256"),
                "sat_rule": row.get("sat_rule"),
                "verified_work_units": row.get("counted_units"),
            }
        )
    if {row["endpoint"] for row in machines} != set(endpoints):
        raise UID30FleetPreviewError(
            "machine proof does not cover the exact consolidation fleet"
        )
    for field in (
        "endpoint",
        "channel_id",
        "stable_platform_id",
        "machine_id",
        "quote_sha256",
        "report_data_sha256",
    ):
        values = [row[field] for row in machines]
        if any(not isinstance(value, str) or not value for value in values):
            raise UID30FleetPreviewError(f"machine proof is missing {field}")
        if len(set(values)) != EXPECTED_MACHINES:
            raise UID30FleetPreviewError(
                f"consolidation machines do not have distinct {field}"
            )
    for row in machines:
        try:
            stable = require_stable_platform_id(row["stable_platform_id"])
            row["channel_id"] = require_machine_id(row["channel_id"], "channel_id")
            row["machine_id"] = require_machine_id(row["machine_id"])
            row["quote_sha256"] = require_machine_id(
                row["quote_sha256"], "quote_sha256"
            )
            row["report_data_sha256"] = require_machine_id(
                row["report_data_sha256"], "report_data_sha256"
            )
        except IndependentValidatorError as exc:
            raise UID30FleetPreviewError(
                "machine proof carries a malformed evidence identity or digest"
            ) from exc
        if row["machine_id"] != machine_id_from_stable_platform_id(stable):
            raise UID30FleetPreviewError(
                "machine proof ID is not derived from its stable platform identity"
            )
    machines.sort(key=lambda row: row["endpoint"])
    return tuple(machines)


def _target_proof(
    round_result: MultiComputeRound,
    *,
    state: UID30ChainState,
    refreshed_endpoints: Sequence[str] | None,
    fleet_recheck_error: str | None,
) -> tuple[tuple[str, ...], tuple[dict[str, Any], ...], tuple[str, ...]]:
    try:
        endpoints = _target_fleet_endpoints(round_result, state=state)
        machines = _target_machine_rows(round_result, state=state, endpoints=endpoints)
    except UID30FleetPreviewError as exc:
        return (), (), (str(exc),)
    reasons: list[str] = []
    if fleet_recheck_error:
        reasons.append(f"signed fleet recheck failed: {fleet_recheck_error}")
    elif refreshed_endpoints is None or tuple(refreshed_endpoints) != endpoints:
        reasons.append("signed fleet endpoint list changed after machine scoring")
    return endpoints, machines, tuple(reasons)


def build_preview_document(
    *,
    evidence_state: UID30ChainState,
    fresh_state: UID30ChainState,
    evidence_axons: Sequence[ServingAxon],
    fresh_axons: Sequence[ServingAxon],
    round_result: MultiComputeRound,
    refreshed_endpoints: Sequence[str] | None,
    fleet_recheck_error: str | None,
    current_weights: tuple[tuple[int, int], ...],
    qvl_digest: str,
) -> dict[str, Any]:
    """Build one immutable proof artifact with no chain authority."""

    _require_chain_continuity(evidence_state, fresh_state)
    if tuple(fresh_axons) != tuple(evidence_axons):
        raise UID30FleetPreviewError(
            "weighted UID mapping or serving axon changed during scoring"
        )
    if len(current_weights) != len(fresh_axons):
        raise UID30FleetPreviewError(
            "current UID30 row and weighted serving axons differ in length"
        )
    if [uid for uid, _weight in current_weights] != [axon.uid for axon in fresh_axons]:
        raise UID30FleetPreviewError(
            "weighted serving axons do not match the current UID30 row"
        )
    if qvl_digest != LAUNCH_QVL_DIGEST:
        raise UID30FleetPreviewError("fleet proof does not use the pinned launch QVL")
    if fresh_state.miner_uid not in {uid for uid, _weight in current_weights}:
        raise UID30FleetPreviewError(
            "consolidation owner is absent from the current UID30 row"
        )

    endpoints, machines, target_reasons = _target_proof(
        round_result,
        state=fresh_state,
        refreshed_endpoints=refreshed_endpoints,
        fleet_recheck_error=fleet_recheck_error,
    )
    target_proven = not target_reasons
    wire_uids, wire_weights = convert_and_normalize_weights_and_uids(
        [fresh_state.miner_uid], [EXPECTED_RAW_UID_UNITS]
    )
    exact_uids = [int(value) for value in wire_uids]
    exact_weights = [int(value) for value in wire_weights]
    if exact_uids != [fresh_state.miner_uid] or exact_weights != [W]:
        raise UID30FleetPreviewError(
            "installed Bittensor did not encode the singleton target as 65535"
        )
    target_row = ((fresh_state.miner_uid, W),)
    owner_uid = fresh_state.preflight.hotkey_to_uid.get(fresh_state.subnet_owner_hotkey)
    current_burn_weight = sum(
        weight for uid, weight in current_weights if uid == owner_uid
    )
    current_units = dict(round_result.verified_units)
    current_rows = [
        {
            "uid": axon.uid,
            "hotkey": axon.hotkey,
            "endpoint": axon_origin(axon.ip, axon.port),
            "stored_weight": dict(current_weights)[axon.uid],
            "verified_work_units": current_units.get(axon.hotkey, 0),
        }
        for axon in fresh_axons
    ]
    return {
        "schema": SCHEMA,
        "status": STATUS if target_proven else NOT_PROVEN_STATUS,
        "network": "finney",
        "netuid": NETUID,
        "mechanism_id": MECID,
        "evidence_anchor": {
            "block_number": evidence_state.block_number,
            "block_hash": evidence_state.block_hash,
        },
        "finalized_recheck": {
            "block_number": fresh_state.block_number,
            "block_hash": fresh_state.block_hash,
        },
        "validator": {"uid": UID30, "hotkey": UID30_HOTKEY},
        "score_contract": {
            "formula": "sum independently re-derived verified work_units across unique physical identities",
            "declared_machine_count_bonus_units": 0,
            "attestation_only_bonus_units": 0,
            "per_machine_unit_cap": EXPECTED_MACHINE_UNITS,
            "fleet_cap_per_uid": 32,
        },
        "current": {
            "uid30_storage": [list(row) for row in current_weights],
            "burn_destination_uid": owner_uid,
            "burn_weight": current_burn_weight,
            "weighted_serving_uids": current_rows,
            "verified_units_by_hotkey": current_units,
            "fleet_discovery": list(round_result.fleet),
            "machine_observations": list(round_result.rows),
            "exclusions": list(round_result.exclusions),
            "blockers": list(round_result.blockers),
        },
        "consolidation_target": {
            "hotkey": MINER_HOTKEY,
            "uid": fresh_state.miner_uid,
            "root_axon": axon_origin(
                fresh_state.serving_axon.ip, fresh_state.serving_axon.port
            ),
            "fleet_endpoints": list(endpoints),
            "machines": list(machines),
            "raw_uid_units": current_units.get(MINER_HOTKEY, 0),
            "required_raw_uid_units": EXPECTED_RAW_UID_UNITS,
            "proof_complete": target_proven,
            "not_proven_reasons": list(target_reasons),
            "non_authorizing_target_wire_row": [
                [uid, weight] for uid, weight in zip(exact_uids, exact_weights)
            ],
        },
        "qvl_digest": qvl_digest,
        "burn_destination": None,
        "burn_weight": 0,
        "changes_current_chain_row": current_weights != target_row,
        "authorized_for_chain_write": False,
        "chain_write_submitted": False,
        "weight_signed": False,
        "weight_submitted": False,
        "proof_boundary": (
            "PROVEN means the pinned UID owns two independently verified TDX "
            "platforms with 20 SAT units each and its signed fleet survived a "
            "finalized recheck. The singleton row remains a no-write target. "
            "This artifact does not authorize weights, prove subnet emission, "
            "or prove TAO earnings. AMD SEV-SNP fleet identity remains "
            "NOT_PROVEN and disabled."
        ),
    }


def collect_preview(
    qvl_path: str, *, chain_endpoint: str | None = None
) -> dict[str, Any]:
    evidence_state = read_uid30_chain_state(chain_endpoint=chain_endpoint)
    keypair = _keypair(evidence_state)
    evidence_weights = read_current_uid30_weights(evidence_state)
    evidence_axons = read_weighted_serving_axons(evidence_state, evidence_weights)
    verifier = load_verifier(qvl_path)
    adapter = ComputeAdapter(
        verifier,
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=verifier.digest,
    )
    round_result = score_multicompute_round(
        axons=evidence_axons,
        keypair=keypair,
        anchor_hash=evidence_state.block_hash,
        verifier_adapter=adapter,
    )

    fresh_state = read_uid30_chain_state(chain_endpoint=chain_endpoint)
    _require_chain_continuity(evidence_state, fresh_state)
    fresh_keypair = _keypair(fresh_state)
    current_weights = read_current_uid30_weights(fresh_state)
    if current_weights != evidence_weights:
        raise UID30FleetPreviewError("current UID30 storage changed during scoring")
    fresh_axons = read_weighted_serving_axons(fresh_state, current_weights)
    if fresh_axons != evidence_axons:
        raise UID30FleetPreviewError(
            "weighted UID mapping or serving axon changed during scoring"
        )

    refreshed_endpoints: Sequence[str] | None = None
    fleet_recheck_error: str | None = None
    try:
        endpoints = _target_fleet_endpoints(round_result, state=fresh_state)
        _target_machine_rows(round_result, state=fresh_state, endpoints=endpoints)
    except UID30FleetPreviewError as exc:
        fleet_recheck_error = str(exc)
    else:
        root = axon_origin(fresh_state.serving_axon.ip, fresh_state.serving_axon.port)
        root_row = next(
            (
                row
                for row in round_result.rows
                if row.get("uid") == fresh_state.miner_uid
                and row.get("hotkey") == MINER_HOTKEY
                and row.get("endpoint") == root
            ),
            None,
        )
        if not isinstance(root_row, Mapping):
            fleet_recheck_error = "fleet proof is missing its root axon row"
        else:
            try:
                root_spki = bytes.fromhex(str(root_row.get("channel_id")))
                if len(root_spki) != 32:
                    raise ValueError("wrong digest length")
                refreshed = fetch_worker_fleet(
                    primary_origin=root,
                    worker_hotkey=MINER_HOTKEY,
                    transport=SignedValidatorTransport(
                        HttpsEvidenceTransport(),
                        keypair=fresh_keypair,
                        worker_hotkey=MINER_HOTKEY,
                        expected_spki=root_spki,
                    ),
                )
                if refreshed.worker_hotkey != MINER_HOTKEY:
                    raise IndependentLiveError(
                        "fleet recheck returned a different worker hotkey"
                    )
                if refreshed.singleton_compatibility:
                    raise IndependentLiveError(
                        "fleet recheck fell back to one chain axon"
                    )
                refreshed_endpoints = refreshed.endpoints
            except (ValueError, IndependentLiveError) as exc:
                fleet_recheck_error = f"{type(exc).__name__}: {exc}"

    return build_preview_document(
        evidence_state=evidence_state,
        fresh_state=fresh_state,
        evidence_axons=evidence_axons,
        fresh_axons=fresh_axons,
        round_result=round_result,
        refreshed_endpoints=refreshed_endpoints,
        fleet_recheck_error=fleet_recheck_error,
        current_weights=current_weights,
        qvl_digest=verifier.digest,
    )


def _canonical_bytes(document: Mapping[str, Any]) -> bytes:
    return canonical_document_bytes(document)


def write_preview(document: Mapping[str, Any], output: Path) -> tuple[Path, Path, str]:
    try:
        return write_owner_only_preview(document, output)
    except PreviewWriteError as exc:
        raise UID30FleetPreviewError(str(exc)) from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cathedral-uid30-fleet-preview")
    parser.add_argument("--qvl", required=True)
    parser.add_argument("--output", required=True)
    return parser


def _error_report(exc: Exception) -> dict[str, Any]:
    return {
        "status": "REFUSED_NO_CHAIN_WRITE",
        "error": str(exc),
        "authorized_for_chain_write": False,
        "chain_write_submitted": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        document = collect_preview(options.qvl)
        path, digest_path, digest = write_preview(document, Path(options.output))
    except (
        UID30FleetPreviewError,
        UID30LaunchError,
        IndependentLiveError,
        IndependentValidatorError,
        OSError,
    ) as exc:
        print(json.dumps(_error_report(exc), sort_keys=True), file=sys.stderr)
        return 2
    result = {
        "status": document["status"],
        "preview": str(path),
        "detached_sha256": str(digest_path),
        "sha256": digest,
        "authorized_for_chain_write": False,
        "chain_write_submitted": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if document["status"] == STATUS else 2


if __name__ == "__main__":
    raise SystemExit(main())
