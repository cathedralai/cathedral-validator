"""Write-free signed fleet collection and deterministic work aggregation.

This module has no wallet loader, journal, nonce query, extrinsic builder, or
chain-submission function.  A caller supplies an already-loaded public signing
hotkey solely to authenticate validator-to-worker HTTPS requests.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Sequence

from cathedral_thin.independent.collect import (
    CollectedEvidence,
    collect_evidence,
    mint_nonce,
)
from cathedral_thin.independent.compute import (
    ComputeAdapter,
    QuoteVerdict,
    machine_id_from_stable_platform_id,
)
from cathedral_thin.independent.constants import (
    MAX_DESTS,
    MULTICOMPUTE_MACHINE_WORK_UNIT_CAP,
)
from cathedral_thin.independent.errors import SatWorkError
from cathedral_thin.independent.sat import (
    SAT_WORK_UNIT_RULE,
    canonical_work_item,
    collect_sat_work,
)

from .axon import ServingAxon
from .errors import IndependentLiveError
from .https import (
    HttpsEvidenceTransport,
    axon_origin,
    require_cert_chain_matches_peer,
)
from .multicompute import (
    MachineWorkObservation,
    aggregate_multicompute_units,
    duplicate_channel_indexes,
    duplicate_endpoint_indexes,
    duplicate_hardware_indexes,
)
from .validator_request import (
    SignedValidatorTransport,
    fetch_worker_fleet,
    validate_public_worker_endpoint,
)


@dataclass(frozen=True)
class FleetCandidate:
    uid: int
    hotkey: str
    endpoint: str


@dataclass(frozen=True)
class MultiComputeRound:
    rows: tuple[dict[str, Any], ...]
    fleet: tuple[dict[str, Any], ...]
    verified_units: dict[str, int]
    pass_count: int
    qvl_infra_count: int
    feature_blocked: bool
    exclusions: tuple[str, ...]
    blockers: tuple[str, ...]


def _candidate_urls(endpoint: str) -> tuple[str, str]:
    return endpoint + "/v1/evidence", endpoint + "/v1/sat-work"


def _try_collect(
    *,
    evidence_url: str,
    sat_url: str,
    hotkey: str,
    validator_ss58: str,
    keypair: Any,
) -> dict[str, Any]:
    transport = SignedValidatorTransport(
        HttpsEvidenceTransport(), keypair=keypair, worker_hotkey=hotkey
    )
    try:
        binding = transport.observe_binding(evidence_url)
        nonce = mint_nonce(validator_ss58, entropy=os.urandom(16))
        collected = collect_evidence(
            url=evidence_url,
            assigned_hotkey=hotkey,
            nonce=nonce,
            channel_binding=binding,
            transport=transport,
        )
        if transport.last_spki != binding.digest:
            raise IndependentLiveError(
                "TLS SPKI changed between binding and signed evidence POST"
            )
        require_cert_chain_matches_peer(
            collected.cert_chain, collected.channel_binding.digest
        )
    except Exception as exc:
        return {
            "url": evidence_url,
            "sat_url": sat_url,
            "hotkey": hotkey,
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "url": evidence_url,
        "sat_url": sat_url,
        "hotkey": collected.assigned_hotkey,
        "ok": True,
        "quote_bytes": len(collected.quote),
        "kind": collected.kind,
        "collected": collected,
    }


def _units_after_quote(
    *,
    anchor_hash: str,
    collected: CollectedEvidence,
    sat_url: str,
    keypair: Any,
) -> int:
    item = canonical_work_item(
        anchor_hash=anchor_hash,
        miner_ss58=collected.assigned_hotkey,
        machine_id=collected.channel_binding.digest.hex(),
    )
    transport = SignedValidatorTransport(
        HttpsEvidenceTransport(),
        keypair=keypair,
        worker_hotkey=collected.assigned_hotkey,
        expected_spki=collected.channel_binding.digest,
    )
    units = collect_sat_work(
        url=sat_url,
        assigned_hotkey=collected.assigned_hotkey,
        item=item,
        transport=transport,
    )
    if transport.last_spki != collected.channel_binding.digest:
        raise SatWorkError(
            "the TLS SPKI on the work POST is not the attested channel binding"
        )
    return units


def _collect_candidate(
    *,
    candidate: FleetCandidate,
    keypair: Any,
    validator_ss58: str,
    anchor_hash: str,
    verifier_adapter: ComputeAdapter,
) -> tuple[dict[str, Any], MachineWorkObservation, CollectedEvidence | None, bool]:
    evidence_url, sat_url = _candidate_urls(candidate.endpoint)
    row = _try_collect(
        evidence_url=evidence_url,
        sat_url=sat_url,
        hotkey=candidate.hotkey,
        validator_ss58=validator_ss58,
        keypair=keypair,
    )
    row.update(
        {
            "uid": candidate.uid,
            "endpoint": candidate.endpoint,
            "scoring_window": anchor_hash,
        }
    )
    collected = row.get("collected")
    machine_id: str | None = None
    hardware_verified = False
    verdict_pass = False
    if isinstance(collected, CollectedEvidence):
        row["quote_sha256"] = hashlib.sha256(collected.quote).hexdigest()
        row["report_data_sha256"] = hashlib.sha256(collected.report_data).hexdigest()
        identity = verifier_adapter.verify_quote_with_identity(
            collected.quote, expected_report_data=collected.report_data
        )
        row["verdict"] = identity.verdict.value
        verdict_pass = identity.verdict is QuoteVerdict.PASS
        if verdict_pass:
            if (
                not identity.platform_identity_verified
                or identity.stable_platform_id is None
            ):
                row["identity_error"] = (
                    "QVL PASS did not carry a quote-bound verified "
                    "stable_platform_id; this machine earns zero"
                )
            else:
                machine_id = machine_id_from_stable_platform_id(
                    identity.stable_platform_id
                )
                hardware_verified = True
                row["stable_platform_id"] = identity.stable_platform_id
                row["machine_id"] = machine_id
                row["channel_id"] = collected.channel_binding.digest.hex()
                row["platform_identity_verified"] = True
    observation = MachineWorkObservation(
        scoring_window=anchor_hash,
        uid=candidate.uid,
        miner_hotkey=candidate.hotkey,
        endpoint=candidate.endpoint,
        channel_id=(
            None
            if not isinstance(collected, CollectedEvidence)
            else collected.channel_binding.digest.hex()
        ),
        machine_id=machine_id,
        evidence_fresh=isinstance(collected, CollectedEvidence),
        hardware_verified=hardware_verified,
        channel_bound=isinstance(collected, CollectedEvidence),
        work_units=None,
    )
    return row, observation, collected, verdict_pass


def score_multicompute_round(
    *,
    axons: Sequence[ServingAxon],
    keypair: Any,
    anchor_hash: str,
    verifier_adapter: ComputeAdapter,
) -> MultiComputeRound:
    """Attest roots, discover fleets, deduplicate, challenge, and aggregate."""

    if not verifier_adapter.supports_stable_platform_identity:
        return MultiComputeRound(
            rows=(),
            fleet=(),
            verified_units={},
            pass_count=0,
            qvl_infra_count=0,
            feature_blocked=True,
            exclusions=(),
            blockers=(
                "QVL does not expose verified stable platform identity; "
                "multi-machine scoring remains disabled",
            ),
        )

    if isinstance(axons, (str, bytes)) or not isinstance(axons, Sequence):
        raise IndependentLiveError("serving axons must be a bounded sequence")
    if not axons or len(axons) > MAX_DESTS:
        raise IndependentLiveError(
            f"serving axon count is outside the bounded range 1..{MAX_DESTS}"
        )
    uid_hotkeys: dict[int, str] = {}
    hotkey_uids: dict[str, int] = {}
    for axon in axons:
        if not isinstance(axon, ServingAxon):
            raise IndependentLiveError("serving axon row has the wrong type")
        if (
            isinstance(axon.uid, bool)
            or not isinstance(axon.uid, int)
            or not 0 <= axon.uid < MAX_DESTS
            or not isinstance(axon.hotkey, str)
            or not axon.hotkey
        ):
            raise IndependentLiveError("serving axon identity is malformed")
        if axon.uid in uid_hotkeys or axon.hotkey in hotkey_uids:
            raise IndependentLiveError("serving axons repeat a UID or hotkey")
        validate_public_worker_endpoint(axon_origin(axon.ip, axon.port))
        uid_hotkeys[axon.uid] = axon.hotkey
        hotkey_uids[axon.hotkey] = axon.uid

    fleet_report: list[dict[str, Any]] = []
    exclusions: list[str] = []
    blockers: list[str] = []
    validator_ss58 = str(keypair.ss58_address)
    rows: list[dict[str, Any]] = []
    observations: list[MachineWorkObservation] = []
    collected_by_key: dict[tuple[int, str], CollectedEvidence] = {}
    row_by_key: dict[tuple[int, str], dict[str, Any]] = {}
    non_scoreable_keys: set[tuple[int, str]] = set()
    pass_count = 0
    qvl_infra_count = 0

    def collect_admitted(candidate: FleetCandidate) -> None:
        nonlocal pass_count, qvl_infra_count
        row, observation, collected, verdict_pass = _collect_candidate(
            candidate=candidate,
            keypair=keypair,
            validator_ss58=validator_ss58,
            anchor_hash=anchor_hash,
            verifier_adapter=verifier_adapter,
        )
        if row.get("verdict") == QuoteVerdict.INFRA.value:
            qvl_infra_count += 1
        if verdict_pass:
            pass_count += 1
        key = (candidate.uid, candidate.endpoint)
        rows.append(row)
        observations.append(observation)
        row_by_key[key] = row
        if observation.hardware_verified and collected is not None:
            collected_by_key[key] = collected

    for axon in axons:
        primary = axon_origin(axon.ip, axon.port)
        root = FleetCandidate(axon.uid, axon.hotkey, primary)
        root_row, root_observation, root_collected, root_pass = _collect_candidate(
            candidate=root,
            keypair=keypair,
            validator_ss58=validator_ss58,
            anchor_hash=anchor_hash,
            verifier_adapter=verifier_adapter,
        )
        if root_row.get("verdict") == QuoteVerdict.INFRA.value:
            qvl_infra_count += 1
        if root_pass:
            pass_count += 1
        if not root_observation.hardware_verified or root_collected is None:
            root_row["counted_units"] = 0
            root_row.pop("collected", None)
            rows.append(root_row)
            reason = (
                root_row.get("identity_error")
                or root_row.get("error")
                or ("chain axon did not produce verified stable hardware identity")
            )
            fleet_report.append(
                {
                    "uid": axon.uid,
                    "hotkey": axon.hotkey,
                    "primary": primary,
                    "ok": False,
                    "error": reason,
                }
            )
            exclusions.append(f"fleet uid {axon.uid}: {reason}")
            continue
        signed_fleet = SignedValidatorTransport(
            HttpsEvidenceTransport(),
            keypair=keypair,
            worker_hotkey=axon.hotkey,
            expected_spki=root_collected.channel_binding.digest,
        )
        root_key = (root.uid, root.endpoint)
        try:
            fleet = fetch_worker_fleet(
                primary_origin=primary,
                worker_hotkey=axon.hotkey,
                transport=signed_fleet,
            )
        except Exception as exc:
            reason = f"{type(exc).__name__}: {exc}"
            root_row["fleet_error"] = reason
            root_row["counted_units"] = 0
            root_row.pop("collected", None)
            rows.append(root_row)
            # This root already passed fresh assigned-hotkey evidence, QVL
            # stable-identity verification, and channel binding. A malformed
            # or unauthorized later fleet response cannot erase that verified
            # endpoint/SPKI/platform claim and thereby hide a duplicate from
            # the global batch. Keep it in conflict detection, but fence it
            # from SAT and score because its fleet contract failed.
            observations.append(root_observation)
            row_by_key[root_key] = root_row
            non_scoreable_keys.add(root_key)
            fleet_report.append(
                {
                    "uid": axon.uid,
                    "hotkey": axon.hotkey,
                    "primary": primary,
                    "ok": False,
                    "error": reason,
                }
            )
            exclusions.append(f"fleet uid {axon.uid}: {reason}")
            continue
        fleet_report.append(
            {
                "uid": axon.uid,
                "hotkey": axon.hotkey,
                "primary": primary,
                "ok": True,
                "singleton_compatibility": fleet.singleton_compatibility,
                "candidate_count": len(fleet.endpoints),
                "endpoints": list(fleet.endpoints),
            }
        )
        rows.append(root_row)
        observations.append(root_observation)
        row_by_key[root_key] = root_row
        collected_by_key[root_key] = root_collected
        for endpoint in fleet.endpoints[1:]:
            collect_admitted(FleetCandidate(axon.uid, axon.hotkey, endpoint))

    duplicate_endpoints = duplicate_endpoint_indexes(observations)
    duplicate_channels = duplicate_channel_indexes(observations)
    duplicate_hardware = duplicate_hardware_indexes(observations)
    for index, observation in enumerate(tuple(observations)):
        key = (observation.uid, observation.endpoint)
        row = row_by_key[key]
        if not observation.hardware_verified:
            continue
        if key in non_scoreable_keys:
            row["sat_error"] = (
                "fleet_discovery_failed: verified identity retained only for "
                "global duplicate rejection"
            )
            continue
        if index in duplicate_endpoints:
            row["sat_error"] = "duplicate_endpoint: every verified claimant is zero"
            continue
        if index in duplicate_channels:
            row["sat_error"] = (
                "duplicate_channel_identity: every verified claimant is zero"
            )
            continue
        if index in duplicate_hardware:
            row["sat_error"] = (
                "duplicate_hardware_identity: every verified claimant is zero"
            )
            continue
        collected = collected_by_key[key]
        try:
            units = _units_after_quote(
                anchor_hash=anchor_hash,
                collected=collected,
                sat_url=row["sat_url"],
                keypair=keypair,
            )
            if units > MULTICOMPUTE_MACHINE_WORK_UNIT_CAP:
                raise SatWorkError(
                    "verified units exceed per-machine cap "
                    f"{MULTICOMPUTE_MACHINE_WORK_UNIT_CAP}"
                )
        except Exception as exc:
            row["sat_error"] = f"{type(exc).__name__}: {exc}"
            continue
        row["sat_units"] = units
        row["sat_rule"] = SAT_WORK_UNIT_RULE
        observations[index] = MachineWorkObservation(
            **{**observation.__dict__, "work_units": units}
        )

    score = aggregate_multicompute_units(
        tuple(observations), scoring_window=anchor_hash
    )
    machine_scores = {(row.uid, row.endpoint): row for row in score.machines}
    for row in rows:
        result = machine_scores.get((row["uid"], row["endpoint"]))
        if result is None:
            row.setdefault("counted_units", 0)
            row.pop("collected", None)
            continue
        if result.reasons:
            row["score_reasons"] = list(result.reasons)
        row["counted_units"] = result.units
        row.pop("collected", None)

    if duplicate_endpoints:
        exclusions.append(
            f"duplicate endpoints: {len(duplicate_endpoints)} verified claimants zeroed"
        )
    if duplicate_channels:
        exclusions.append(
            f"duplicate channels: {len(duplicate_channels)} verified claimants zeroed"
        )
    if duplicate_hardware:
        exclusions.append(
            f"duplicate hardware: {len(duplicate_hardware)} verified claimants zeroed"
        )
    return MultiComputeRound(
        rows=tuple(rows),
        fleet=tuple(fleet_report),
        verified_units=score.hotkey_units,
        pass_count=pass_count,
        qvl_infra_count=qvl_infra_count,
        feature_blocked=False,
        exclusions=tuple(exclusions),
        blockers=tuple(blockers),
    )


__all__ = ["MultiComputeRound", "score_multicompute_round"]
