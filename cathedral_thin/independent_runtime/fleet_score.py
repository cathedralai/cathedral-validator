"""Write-free signed fleet collection and deterministic work aggregation.

This module has no wallet loader, journal, nonce query, extrinsic builder, or
chain-submission function.  A caller supplies an already-loaded public signing
hotkey solely to authenticate validator-to-worker HTTPS requests.
"""

from __future__ import annotations

import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor, wait
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
from .qvl import TIMEOUT_SECONDS as QVL_TIMEOUT_SECONDS
from .validator_request import (
    SignedValidatorTransport,
    fetch_worker_fleet,
    validate_public_worker_endpoint,
)

DISCOVERY_RESPONSE_DEADLINE_SECONDS = 60.0
MINER_RESPONSE_DEADLINE_SECONDS = 90.0
FULL_CYCLE_RESPONSE_DEADLINE_SECONDS = 120.0
MAX_CONCURRENT_MINERS = 32
PHASE_TIMING_FIELDS = ("binding", "evidence", "fleet", "qvl", "sat")
QVL_DEADLINE_MARGIN_SECONDS = 0.5


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


@dataclass
class _MinerEvidence:
    axon: ServingAxon
    rows: list[dict[str, Any]]
    observations: list[MachineWorkObservation]
    collected_by_key: dict[tuple[int, str], CollectedEvidence]
    row_by_key: dict[tuple[int, str], dict[str, Any]]
    non_scoreable_keys: set[tuple[int, str]]
    fleet_row: dict[str, Any]
    exclusions: list[str]
    pass_count: int
    qvl_infra_count: int
    finished_monotonic: float


def _empty_phase_timings() -> dict[str, int | None]:
    return {phase: None for phase in PHASE_TIMING_FIELDS}


def _phase_started() -> int:
    return time.monotonic_ns()


def _phase_finished(started: int) -> int:
    return max(0, (time.monotonic_ns() - started) // 1_000_000)


def _transport(deadline_monotonic: float | None) -> HttpsEvidenceTransport:
    if deadline_monotonic is None:
        return HttpsEvidenceTransport()
    return HttpsEvidenceTransport(deadline_monotonic=deadline_monotonic)


def _deadline_expired(deadline_monotonic: float | None) -> bool:
    return deadline_monotonic is not None and time.monotonic() >= deadline_monotonic


def _anchor_rotated_axons(
    axons: Sequence[ServingAxon], anchor_hash: str
) -> tuple[ServingAxon, ...]:
    """Deterministic scheduling order which rotates with the finalized anchor."""

    ordered = tuple(sorted(axons, key=lambda item: (item.uid, item.hotkey)))
    try:
        rotation = int(anchor_hash.removeprefix("0x"), 16) % len(ordered)
    except (TypeError, ValueError, ZeroDivisionError) as exc:
        raise IndependentLiveError(
            "anchor hash cannot schedule serving miners"
        ) from exc
    return ordered[rotation:] + ordered[:rotation]


def _candidate_urls(endpoint: str) -> tuple[str, str]:
    return endpoint + "/v1/evidence", endpoint + "/v1/sat-work"


def _try_collect(
    *,
    evidence_url: str,
    sat_url: str,
    hotkey: str,
    validator_ss58: str,
    keypair: Any,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    transport = SignedValidatorTransport(
        _transport(deadline_monotonic), keypair=keypair, worker_hotkey=hotkey
    )
    timings = _empty_phase_timings()
    try:
        started = _phase_started()
        binding = transport.observe_binding(evidence_url)
        timings["binding"] = _phase_finished(started)
        started = _phase_started()
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
        timings["evidence"] = _phase_finished(started)
    except Exception as exc:
        if timings["binding"] is None:
            timings["binding"] = _phase_finished(started)
        elif timings["evidence"] is None:
            timings["evidence"] = _phase_finished(started)
        return {
            "url": evidence_url,
            "sat_url": sat_url,
            "hotkey": hotkey,
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "phase_timings_ms": timings,
        }
    return {
        "url": evidence_url,
        "sat_url": sat_url,
        "hotkey": collected.assigned_hotkey,
        "ok": True,
        "quote_bytes": len(collected.quote),
        "kind": collected.kind,
        "collected": collected,
        "phase_timings_ms": timings,
    }


def _units_after_quote(
    *,
    anchor_hash: str,
    collected: CollectedEvidence,
    sat_url: str,
    keypair: Any,
    deadline_monotonic: float | None = None,
) -> int:
    item = canonical_work_item(
        anchor_hash=anchor_hash,
        miner_ss58=collected.assigned_hotkey,
        machine_id=collected.channel_binding.digest.hex(),
    )
    transport = SignedValidatorTransport(
        _transport(deadline_monotonic),
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
    deadline_monotonic: float | None = None,
) -> tuple[dict[str, Any], MachineWorkObservation, CollectedEvidence | None, bool]:
    evidence_url, sat_url = _candidate_urls(candidate.endpoint)
    collect_kwargs: dict[str, Any] = {
        "evidence_url": evidence_url,
        "sat_url": sat_url,
        "hotkey": candidate.hotkey,
        "validator_ss58": validator_ss58,
        "keypair": keypair,
    }
    if deadline_monotonic is not None:
        collect_kwargs["deadline_monotonic"] = deadline_monotonic
    row = _try_collect(**collect_kwargs)
    timings = row.setdefault("phase_timings_ms", _empty_phase_timings())
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
        qvl_deadline = deadline_monotonic
        if deadline_monotonic is not None and (
            deadline_monotonic - time.monotonic()
            <= QVL_TIMEOUT_SECONDS + QVL_DEADLINE_MARGIN_SECONDS
        ):
            row["deadline_error"] = "insufficient discovery budget for bounded QVL"
        else:
            started = _phase_started()
            verify_kwargs: dict[str, Any] = {
                "expected_report_data": collected.report_data
            }
            if qvl_deadline is not None:
                verify_kwargs["deadline_monotonic"] = (
                    qvl_deadline - QVL_DEADLINE_MARGIN_SECONDS
                )
            try:
                identity = verifier_adapter.verify_quote_with_identity(
                    collected.quote, **verify_kwargs
                )
            finally:
                timings["qvl"] = _phase_finished(started)
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


def _collect_miner_evidence(
    *,
    axon: ServingAxon,
    keypair: Any,
    validator_ss58: str,
    anchor_hash: str,
    verifier_adapter: ComputeAdapter,
    deadline_monotonic: float | None,
) -> _MinerEvidence:
    """Collect one miner into local state which late workers cannot publish."""

    rows: list[dict[str, Any]] = []
    observations: list[MachineWorkObservation] = []
    collected_by_key: dict[tuple[int, str], CollectedEvidence] = {}
    row_by_key: dict[tuple[int, str], dict[str, Any]] = {}
    non_scoreable_keys: set[tuple[int, str]] = set()
    exclusions: list[str] = []
    pass_count = 0
    qvl_infra_count = 0
    primary = axon_origin(axon.ip, axon.port)
    root = FleetCandidate(axon.uid, axon.hotkey, primary)

    def collect(candidate: FleetCandidate) -> None:
        nonlocal pass_count, qvl_infra_count
        row, observation, collected, verdict_pass = _collect_candidate(
            candidate=candidate,
            keypair=keypair,
            validator_ss58=validator_ss58,
            anchor_hash=anchor_hash,
            verifier_adapter=verifier_adapter,
            deadline_monotonic=deadline_monotonic,
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

    root_row, root_observation, root_collected, root_pass = _collect_candidate(
        candidate=root,
        keypair=keypair,
        validator_ss58=validator_ss58,
        anchor_hash=anchor_hash,
        verifier_adapter=verifier_adapter,
        deadline_monotonic=deadline_monotonic,
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
            or "chain axon did not produce verified stable hardware identity"
        )
        fleet_row = {
            "uid": axon.uid,
            "hotkey": axon.hotkey,
            "primary": primary,
            "ok": False,
            "error": reason,
            "phase_timings_ms": {"fleet": None},
        }
        exclusions.append(f"fleet uid {axon.uid}: {reason}")
        return _MinerEvidence(
            axon,
            rows,
            observations,
            collected_by_key,
            row_by_key,
            non_scoreable_keys,
            fleet_row,
            exclusions,
            pass_count,
            qvl_infra_count,
            time.monotonic(),
        )

    transport = SignedValidatorTransport(
        _transport(deadline_monotonic),
        keypair=keypair,
        worker_hotkey=axon.hotkey,
        expected_spki=root_collected.channel_binding.digest,
    )
    root_key = (root.uid, root.endpoint)
    fleet_started = _phase_started()
    try:
        fleet = fetch_worker_fleet(
            primary_origin=primary,
            worker_hotkey=axon.hotkey,
            transport=transport,
        )
    except Exception as exc:
        fleet_ms = _phase_finished(fleet_started)
        root_row["phase_timings_ms"]["fleet"] = fleet_ms
        reason = f"{type(exc).__name__}: {exc}"
        root_row["fleet_error"] = reason
        root_row["counted_units"] = 0
        root_row.pop("collected", None)
        rows.append(root_row)
        observations.append(root_observation)
        row_by_key[root_key] = root_row
        non_scoreable_keys.add(root_key)
        fleet_row = {
            "uid": axon.uid,
            "hotkey": axon.hotkey,
            "primary": primary,
            "ok": False,
            "error": reason,
            "phase_timings_ms": {"fleet": fleet_ms},
        }
        exclusions.append(f"fleet uid {axon.uid}: {reason}")
        return _MinerEvidence(
            axon,
            rows,
            observations,
            collected_by_key,
            row_by_key,
            non_scoreable_keys,
            fleet_row,
            exclusions,
            pass_count,
            qvl_infra_count,
            time.monotonic(),
        )

    fleet_ms = _phase_finished(fleet_started)
    root_row["phase_timings_ms"]["fleet"] = fleet_ms
    fleet_row = {
        "uid": axon.uid,
        "hotkey": axon.hotkey,
        "primary": primary,
        "ok": True,
        "singleton_compatibility": fleet.singleton_compatibility,
        "candidate_count": len(fleet.endpoints),
        "endpoints": list(fleet.endpoints),
        "phase_timings_ms": {"fleet": fleet_ms},
    }
    rows.append(root_row)
    observations.append(root_observation)
    row_by_key[root_key] = root_row
    collected_by_key[root_key] = root_collected
    for endpoint in fleet.endpoints[1:]:
        if _deadline_expired(deadline_monotonic):
            reason = "discovery_response_deadline_exceeded"
            exclusions.append(f"fleet uid {axon.uid}: {reason}")
            break
        collect(FleetCandidate(axon.uid, axon.hotkey, endpoint))
        rows[-1]["phase_timings_ms"]["fleet"] = fleet_ms
    return _MinerEvidence(
        axon,
        rows,
        observations,
        collected_by_key,
        row_by_key,
        non_scoreable_keys,
        fleet_row,
        exclusions,
        pass_count,
        qvl_infra_count,
        time.monotonic(),
    )


def _deadline_miner_evidence(axon: ServingAxon, reason: str) -> _MinerEvidence:
    primary = axon_origin(axon.ip, axon.port)
    return _MinerEvidence(
        axon=axon,
        rows=[],
        observations=[],
        collected_by_key={},
        row_by_key={},
        non_scoreable_keys=set(),
        fleet_row={
            "uid": axon.uid,
            "hotkey": axon.hotkey,
            "primary": primary,
            "ok": False,
            "error": reason,
            "phase_timings_ms": {"fleet": None},
        },
        exclusions=[f"fleet uid {axon.uid}: {reason}"],
        pass_count=0,
        qvl_infra_count=0,
        finished_monotonic=time.monotonic(),
    )


def score_multicompute_round(
    *,
    axons: Sequence[ServingAxon],
    keypair: Any,
    anchor_hash: str,
    verifier_adapter: ComputeAdapter,
    cycle_deadline_monotonic: float | None = None,
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

    if cycle_deadline_monotonic is not None and (
        isinstance(cycle_deadline_monotonic, bool)
        or not isinstance(cycle_deadline_monotonic, (int, float))
    ):
        raise IndependentLiveError("cycle response deadline must be numeric")
    if _deadline_expired(cycle_deadline_monotonic):
        raise IndependentLiveError("cycle response deadline expired before discovery")

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
    ordered_axons = tuple(sorted(axons, key=lambda item: (item.uid, item.hotkey)))
    scheduled_axons = _anchor_rotated_axons(ordered_axons, anchor_hash)
    miner_results: dict[int, _MinerEvidence] = {}
    round_started = time.monotonic()
    discovery_deadline: float | None = None
    miner_deadline: float | None = None
    bounded_executor: ThreadPoolExecutor | None = None
    if cycle_deadline_monotonic is not None:
        discovery_deadline = min(
            float(cycle_deadline_monotonic),
            round_started + DISCOVERY_RESPONSE_DEADLINE_SECONDS,
        )
        miner_deadline = min(
            float(cycle_deadline_monotonic),
            round_started + MINER_RESPONSE_DEADLINE_SECONDS,
        )
        bounded_executor = ThreadPoolExecutor(
            max_workers=min(len(scheduled_axons), MAX_CONCURRENT_MINERS),
            thread_name_prefix="cathedral-miner",
        )
        future_axons = {
            bounded_executor.submit(
                _collect_miner_evidence,
                axon=axon,
                keypair=keypair,
                validator_ss58=validator_ss58,
                anchor_hash=anchor_hash,
                verifier_adapter=verifier_adapter,
                deadline_monotonic=discovery_deadline,
            ): axon
            for axon in scheduled_axons
        }
        done, pending = wait(
            future_axons,
            timeout=max(0.0, discovery_deadline - time.monotonic()),
        )
        unexpected: Exception | None = None
        for future in done:
            axon = future_axons[future]
            try:
                result = future.result()
            except IndependentLiveError as exc:
                result = _deadline_miner_evidence(axon, f"{type(exc).__name__}: {exc}")
            except Exception as exc:
                unexpected = exc
                continue
            if result.finished_monotonic > discovery_deadline:
                result = _deadline_miner_evidence(
                    axon, "discovery_response_deadline_exceeded"
                )
            miner_results[axon.uid] = result
        for future in pending:
            axon = future_axons[future]
            future.cancel()
            miner_results[axon.uid] = _deadline_miner_evidence(
                axon, "discovery_response_deadline_exceeded"
            )
        if unexpected is not None:
            bounded_executor.shutdown(wait=False, cancel_futures=True)
            raise unexpected
    else:
        for axon in ordered_axons:
            miner_results[axon.uid] = _collect_miner_evidence(
                axon=axon,
                keypair=keypair,
                validator_ss58=validator_ss58,
                anchor_hash=anchor_hash,
                verifier_adapter=verifier_adapter,
                deadline_monotonic=None,
            )

    for axon in ordered_axons:
        result = miner_results[axon.uid]
        rows.extend(result.rows)
        observations.extend(result.observations)
        collected_by_key.update(result.collected_by_key)
        row_by_key.update(result.row_by_key)
        non_scoreable_keys.update(result.non_scoreable_keys)
        fleet_report.append(result.fleet_row)
        exclusions.extend(result.exclusions)
        pass_count += result.pass_count
        qvl_infra_count += result.qvl_infra_count

    rows.sort(key=lambda row: (int(row["uid"]), str(row["endpoint"])))
    observations.sort(key=lambda row: (row.uid, row.endpoint))

    duplicate_endpoints = duplicate_endpoint_indexes(observations)
    duplicate_channels = duplicate_channel_indexes(observations)
    duplicate_hardware = duplicate_hardware_indexes(observations)
    sat_indexes_by_uid: dict[int, list[int]] = {}
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
        sat_indexes_by_uid.setdefault(observation.uid, []).append(index)

    def run_sat(
        indexes: Sequence[int],
    ) -> list[tuple[int, int | None, str | None, int]]:
        outcomes: list[tuple[int, int | None, str | None, int]] = []
        for index in indexes:
            observation = observations[index]
            key = (observation.uid, observation.endpoint)
            row = row_by_key[key]
            started = _phase_started()
            try:
                if _deadline_expired(miner_deadline):
                    raise SatWorkError("miner_total_response_deadline_exceeded")
                kwargs: dict[str, Any] = {
                    "anchor_hash": anchor_hash,
                    "collected": collected_by_key[key],
                    "sat_url": row["sat_url"],
                    "keypair": keypair,
                }
                if miner_deadline is not None:
                    kwargs["deadline_monotonic"] = miner_deadline
                units = _units_after_quote(**kwargs)
                if _deadline_expired(miner_deadline):
                    raise SatWorkError("miner_total_response_deadline_exceeded")
                if units > MULTICOMPUTE_MACHINE_WORK_UNIT_CAP:
                    raise SatWorkError(
                        "verified units exceed per-machine cap "
                        f"{MULTICOMPUTE_MACHINE_WORK_UNIT_CAP}"
                    )
            except Exception as exc:
                outcomes.append(
                    (
                        index,
                        None,
                        f"{type(exc).__name__}: {exc}",
                        _phase_finished(started),
                    )
                )
                continue
            outcomes.append((index, units, None, _phase_finished(started)))
        return outcomes

    sat_outcomes: list[tuple[int, int | None, str | None, int | None]] = []
    if miner_deadline is None:
        for uid in sorted(sat_indexes_by_uid):
            sat_outcomes.extend(run_sat(sat_indexes_by_uid[uid]))
    elif sat_indexes_by_uid:
        if bounded_executor is None:
            raise IndependentLiveError("bounded miner executor is unavailable")
        future_uids = {
            bounded_executor.submit(run_sat, tuple(indexes)): uid
            for uid, indexes in sorted(sat_indexes_by_uid.items())
        }
        done, pending = wait(
            future_uids,
            timeout=max(0.0, miner_deadline - time.monotonic()),
        )
        for future in done:
            sat_outcomes.extend(future.result())
        for future in pending:
            future.cancel()
            for index in sat_indexes_by_uid[future_uids[future]]:
                sat_outcomes.append(
                    (
                        index,
                        None,
                        "SatWorkError: miner_total_response_deadline_exceeded",
                        None,
                    )
                )
    if bounded_executor is not None:
        bounded_executor.shutdown(wait=False, cancel_futures=True)

    for index, units, error, elapsed_ms in sorted(sat_outcomes):
        observation = observations[index]
        row = row_by_key[(observation.uid, observation.endpoint)]
        row["phase_timings_ms"]["sat"] = elapsed_ms
        if error is not None or units is None:
            row["sat_error"] = error or "SatWorkError: SAT result is missing"
            continue
        row["sat_units"] = units
        row["sat_rule"] = SAT_WORK_UNIT_RULE
        observations[index] = MachineWorkObservation(
            **{**observation.__dict__, "work_units": units}
        )

    if _deadline_expired(cycle_deadline_monotonic):
        raise IndependentLiveError("full evidence cycle response deadline exceeded")

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
        fleet=tuple(sorted(fleet_report, key=lambda row: (row["uid"], row["hotkey"]))),
        verified_units=score.hotkey_units,
        pass_count=pass_count,
        qvl_infra_count=qvl_infra_count,
        feature_blocked=False,
        exclusions=tuple(exclusions),
        blockers=tuple(blockers),
    )


__all__ = [
    "DISCOVERY_RESPONSE_DEADLINE_SECONDS",
    "FULL_CYCLE_RESPONSE_DEADLINE_SECONDS",
    "MAX_CONCURRENT_MINERS",
    "MINER_RESPONSE_DEADLINE_SECONDS",
    "MultiComputeRound",
    "score_multicompute_round",
]
