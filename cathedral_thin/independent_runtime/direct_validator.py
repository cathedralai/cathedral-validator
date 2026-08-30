"""Small direct SN39 validator built from the independent fleet primitives.

One cycle reads one finalized metagraph, sends a signed validator request to
every serving miner for its fleet, verifies every machine, runs the existing
SAT challenge, applies the existing order-independent duplicate rules, and
builds one zero-burn mechanism-weight vector. The vector is derived locally
from raw machine counts.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import math
import os
import socket
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Sequence

import bittensor as bt

from cathedral_thin.bt_compat import make_subtensor, make_wallet
from cathedral_thin.independent.compute import ComputeAdapter
from cathedral_thin.independent.constants import INTEL_COLLATERAL, NETUID
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE
from .axon import (
    AXON_SKIP_REASONS,
    ServingAxon,
    finalized_head,
    metagraph_view,
    observed_genesis_hash,
    scan_axons,
)
from .direct_contract import (
    DIRECT_PLAN_SCHEMA,
    DirectValidatorError,
    DirectWeightPlan,
    FinalizedMetagraphSnapshot,
    zero_burn_vector,
)
from .errors import IndependentLiveError
from .fleet_score import (
    DISCOVERY_RESPONSE_DEADLINE_SECONDS,
    FULL_CYCLE_RESPONSE_DEADLINE_SECONDS,
    MAX_CONCURRENT_MINERS,
    MINER_RESPONSE_DEADLINE_SECONDS,
    MultiComputeRound,
    PHASE_TIMING_FIELDS,
    score_multicompute_round,
)
from .preview_io import canonical_document_bytes
from .qvl import DIRECT_VALIDATOR_QVL_DIGEST, load_direct_validator_verifier
from .snp_production import SnpProductionError, SnpProductionVerifier, load_snp_policy
from .telemetry import (
    PendingTelemetryStore,
    TelemetryError,
    TelemetrySpool,
    build_telemetry_candidate,
    journal_pending_plan_matches,
    journal_receipt_for_plan,
)

DEFAULT_INTERVAL_SECONDS = 1500.0
_REPORTED_EXCLUSION_CATEGORIES = (
    "fleet",
    "duplicate_endpoint",
    "duplicate_channel",
    "duplicate_hardware",
    "other",
)


def _expected_hotkey(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 64
        or not value.isascii()
        or not value.isalnum()
    ):
        raise SystemExit("--expected-hotkey must be a path-safe public SS58 address")
    return value


def _notify_ready() -> None:
    """Tell systemd initialization finished before any cycle or chain write."""

    notify_socket = os.environ.get("NOTIFY_SOCKET")
    if not notify_socket:
        return
    address = (
        "\0" + notify_socket[1:] if notify_socket.startswith("@") else notify_socket
    )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
            client.connect(address)
            client.sendall(
                b"READY=1\nSTATUS=initialized; waiting for the next direct cycle"
            )
    except OSError as exc:
        raise SystemExit("systemd readiness notification failed") from exc


def _strict_bool(value: Any, *, label: str) -> bool:
    value = getattr(value, "value", value)
    item = getattr(value, "item", None)
    if callable(item):
        value = item()
    if type(value) is not bool:
        raise DirectValidatorError(f"{label} is not an explicit boolean")
    return value


def _metagraph_block(metagraph: Any) -> int:
    raw = getattr(metagraph, "block", None)
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise DirectValidatorError("finalized metagraph has no exact block") from exc
    if isinstance(raw, bool) or value < 0:
        raise DirectValidatorError("finalized metagraph block is invalid")
    return value


def finalized_serving_miners_snapshot(
    subtensor: Any,
    keypair: Any,
) -> FinalizedMetagraphSnapshot:
    """Read every serving non-validator miner at one finalized head."""

    observed_genesis_hash(subtensor)
    block_number, block_hash = finalized_head(subtensor)
    try:
        metagraph = subtensor.metagraph(NETUID, block=block_number)
    except Exception as exc:
        raise DirectValidatorError("finalized SN39 metagraph is unavailable") from exc
    if _metagraph_block(metagraph) != block_number:
        raise DirectValidatorError("SN39 metagraph is not at the finalized head")

    view = metagraph_view(metagraph)
    validator_hotkey = str(getattr(keypair, "ss58_address", ""))
    validator_uid = view.hotkey_to_uid.get(validator_hotkey)
    if isinstance(validator_uid, bool) or not isinstance(validator_uid, int):
        raise DirectValidatorError("validator hotkey is not registered on SN39")
    try:
        uids = [int(value) for value in list(metagraph.uids)]
        permits = list(metagraph.validator_permit)
    except Exception as exc:
        raise DirectValidatorError(
            "finalized validator permits are unavailable"
        ) from exc
    if len(uids) != len(permits) or validator_uid not in uids:
        raise DirectValidatorError("finalized validator permit rows are inconsistent")
    strict_permits = tuple(
        _strict_bool(value, label="finalized validator permit") for value in permits
    )
    if strict_permits[uids.index(validator_uid)] is not True:
        raise DirectValidatorError("validator hotkey lacks a finalized permit")
    validator_uids = {
        uid for uid, permit in zip(uids, strict_permits) if permit is True
    }

    scan = scan_axons(metagraph)
    miners = tuple(
        sorted(
            (axon for axon in scan.serving if axon.uid not in validator_uids),
            key=lambda axon: (axon.uid, axon.hotkey),
        )
    )
    if not miners:
        raise DirectValidatorError("direct validator found no serving miner")
    for miner in miners:
        if view.uid_to_hotkey.get(miner.uid) != miner.hotkey:
            raise DirectValidatorError(
                "serving miner UID and hotkey are not bidirectional"
            )
    return FinalizedMetagraphSnapshot(
        block_number=block_number,
        block_hash=block_hash,
        validator_uid=validator_uid,
        validator_hotkey=validator_hotkey,
        miners=miners,
        skipped_axons=dict(scan.skipped),
    )


def _positive_machine_rows(
    result: MultiComputeRound,
    miners: Sequence[ServingAxon],
) -> tuple[dict[str, Any], ...]:
    if (
        result.feature_blocked
        or result.blockers
        or result.qvl_infra_count
        or result.snp_infra_count
    ):
        raise DirectValidatorError("machine verification round is not fully proven")
    identities = {miner.uid: miner.hotkey for miner in miners}
    fleet_ok: set[int] = set()
    for uid, hotkey in identities.items():
        matching = [
            row
            for row in result.fleet
            if row.get("uid") == uid and row.get("hotkey") == hotkey
        ]
        if len(matching) != 1:
            raise DirectValidatorError("scoring round has no unique miner fleet row")
        if (
            matching[0].get("ok") is True
            and matching[0].get("singleton_compatibility") is False
        ):
            fleet_ok.add(uid)

    rows: list[dict[str, Any]] = []
    observed_sat_units: dict[str, int] = {}
    for source in result.rows:
        uid = source.get("uid")
        hotkey = source.get("hotkey")
        if not isinstance(uid, int) or identities.get(uid) != hotkey:
            raise DirectValidatorError(
                "machine result belongs to another UID or hotkey"
            )
        counted = source.get("counted_units")
        sat_units = source.get("sat_units")
        paid = (
            source.get("verdict") == "PASS"
            and source.get("platform_identity_verified") is True
            and source.get("sat_rule") == SAT_WORK_UNIT_RULE
            and isinstance(sat_units, int)
            and not isinstance(sat_units, bool)
            and sat_units > 0
            and counted == sat_units
            and not source.get("score_reasons")
            and not source.get("sat_error")
            and uid in fleet_ok
        )
        if not paid:
            continue
        for field in ("endpoint", "channel_id", "machine_id"):
            if not isinstance(source.get(field), str) or not source[field]:
                raise DirectValidatorError(f"verified machine is missing {field}")
        rows.append(dict(source))
        observed_sat_units[str(hotkey)] = observed_sat_units.get(str(hotkey), 0) + (
            sat_units
        )

    for field in ("endpoint", "channel_id", "machine_id"):
        values = [row[field] for row in rows]
        if len(values) != len(set(values)):
            raise DirectValidatorError(
                f"positive machine rows survived duplicate {field} rejection"
            )
    known_hotkeys = set(identities.values())
    if set(result.verified_units) - known_hotkeys or any(
        result.verified_units.get(identities[uid], 0)
        != observed_sat_units.get(identities[uid], 0)
        for uid in fleet_ok
    ):
        raise DirectValidatorError("SAT unit aggregation differs from positive rows")
    rows.sort(key=lambda row: (row["uid"], row["machine_id"], row["endpoint"]))
    return tuple(rows)


def build_direct_plan(
    snapshot: FinalizedMetagraphSnapshot,
    result: MultiComputeRound,
    *,
    scored_miners: Sequence[ServingAxon] | None = None,
) -> DirectWeightPlan:
    """Count unique verified machines per UID and normalize with zero burn."""

    miners = tuple(snapshot.miners if scored_miners is None else scored_miners)
    if not miners:
        raise DirectValidatorError("direct plan has no scored miner")
    miner_by_uid = {miner.uid: miner for miner in miners}
    if len(miner_by_uid) != len(miners) or any(
        snapshot.miner_by_uid().get(uid) != miner for uid, miner in miner_by_uid.items()
    ):
        raise DirectValidatorError("scored miners do not belong to the anchor")
    rows = _positive_machine_rows(result, miners)
    grouped: dict[int, list[str]] = {miner.uid: [] for miner in miners}
    for row in rows:
        grouped[int(row["uid"])].append(str(row["machine_id"]))
    raw_scores = tuple((uid, len(grouped[uid])) for uid in sorted(grouped))
    uid_hotkeys = {uid: miner_by_uid[uid].hotkey for uid in sorted(miner_by_uid)}
    wire_uids, wire_weights = zero_burn_vector(raw_scores, uid_hotkeys)
    evidence = {
        "schema": "cathedral_direct_validator_evidence_v1",
        "anchor": snapshot.identity(),
        "qvl_digest": DIRECT_VALIDATOR_QVL_DIGEST,
        "fleet": list(result.fleet),
        "machines": rows,
        "exclusions": list(result.exclusions),
        "sat_rule": SAT_WORK_UNIT_RULE,
        "response_deadlines_seconds": {
            "discovery": DISCOVERY_RESPONSE_DEADLINE_SECONDS,
            "miner_total": MINER_RESPONSE_DEADLINE_SECONDS,
            "full_cycle": FULL_CYCLE_RESPONSE_DEADLINE_SECONDS,
        },
        "max_concurrent_miners": MAX_CONCURRENT_MINERS,
        "scheduling_order": "finalized_anchor_hash_rotation",
    }
    evidence_digest = (
        "sha256:" + hashlib.sha256(canonical_document_bytes(evidence)).hexdigest()
    )
    plan = DirectWeightPlan(
        snapshot=snapshot,
        qvl_digest=DIRECT_VALIDATOR_QVL_DIGEST,
        evidence_digest=evidence_digest,
        machine_ids_by_uid=tuple(
            (uid, tuple(sorted(grouped[uid]))) for uid in sorted(grouped)
        ),
        raw_scores=raw_scores,
        uid_hotkeys=tuple(sorted(uid_hotkeys.items())),
        wire_uids=wire_uids,
        wire_weights=wire_weights,
    )
    plan.kwargs()
    return plan


def _reported_exclusion_category(value: object) -> str:
    if not isinstance(value, str):
        return "other"
    if value.startswith("fleet uid "):
        return "fleet"
    if value.startswith("duplicate endpoints:"):
        return "duplicate_endpoint"
    if value.startswith("duplicate channels:"):
        return "duplicate_channel"
    if value.startswith("duplicate hardware:"):
        return "duplicate_hardware"
    return "other"


def _evidence_cycle_summary(
    snapshot: FinalizedMetagraphSnapshot,
    result: MultiComputeRound,
    plan: DirectWeightPlan,
) -> dict[str, object]:
    """Return fixed-shape telemetry which never enters scoring.

    ``sample_sum`` is cumulative task time across concurrent miners. The event's
    ``evidence_cycle_elapsed_ms`` remains the sole end-to-end wall duration.
    """

    phase_summary: dict[str, dict[str, int | None]] = {}
    for phase in PHASE_TIMING_FIELDS:
        values: list[int] = []
        sources = result.fleet if phase == "fleet" else result.rows
        for row in sources:
            timings = row.get("phase_timings_ms")
            if not isinstance(timings, dict):
                continue
            value = timings.get(phase)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                values.append(value)
        phase_summary[phase] = {
            "samples": len(values),
            "minimum": min(values) if values else None,
            "maximum": max(values) if values else None,
            "sample_sum": sum(values),
        }

    reported_categories = {name: 0 for name in _REPORTED_EXCLUSION_CATEGORIES}
    for exclusion in result.exclusions:
        reported_categories[_reported_exclusion_category(exclusion)] += 1
    skipped_axons = {}
    for reason in AXON_SKIP_REASONS:
        value = snapshot.skipped_axons.get(reason, 0)
        skipped_axons[reason] = (
            value
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else 0
        )
    admitted_machine_rows = sum(count for _uid, count in plan.raw_scores)
    return {
        "phase_timings_ms": phase_summary,
        "exclusions": {
            "skipped_axons": skipped_axons,
            "failed_fleets": sum(row.get("ok") is not True for row in result.fleet),
            "excluded_machine_rows": max(0, len(result.rows) - admitted_machine_rows),
            "reported": len(result.exclusions),
            "reported_categories": reported_categories,
        },
    }


def _run_direct_cycle_unlocked(
    *,
    subtensor: Any,
    keypair: Any,
    verifier_adapter: ComputeAdapter,
    writer: Any,
    snp_verifier: SnpProductionVerifier | None = None,
    telemetry_sink: TelemetrySpool | None = None,
) -> dict[str, Any]:
    """Recover first, otherwise derive and submit at most one fresh vector."""

    pending_telemetry = (
        PendingTelemetryStore(telemetry_sink) if telemetry_sink is not None else None
    )
    recovered = writer.recover()
    if recovered is not None:
        return _recovered_cycle_event(
            recovered=recovered,
            writer=writer,
            keypair=keypair,
            telemetry_sink=telemetry_sink,
        )
    if getattr(verifier_adapter, "qvl_digest", None) != DIRECT_VALIDATOR_QVL_DIGEST:
        raise DirectValidatorError(
            "direct validator adapter does not use the pinned QVL digest"
        )
    cycle_started = time.monotonic()
    cycle_deadline = cycle_started + FULL_CYCLE_RESPONSE_DEADLINE_SECONDS
    snapshot = finalized_serving_miners_snapshot(subtensor, keypair)
    if time.monotonic() >= cycle_deadline:
        raise DirectValidatorError("full evidence cycle expired during discovery")
    result = score_multicompute_round(
        axons=snapshot.miners,
        keypair=keypair,
        anchor_hash=snapshot.block_hash,
        verifier_adapter=verifier_adapter,
        snp_verifier=snp_verifier,
        cycle_deadline_monotonic=cycle_deadline,
    )
    plan = build_direct_plan(snapshot, result)
    evidence_summary = _evidence_cycle_summary(snapshot, result, plan)
    evidence_completed = time.monotonic()
    if evidence_completed >= cycle_deadline:
        raise DirectValidatorError("full evidence cycle expired before submission")
    evidence_cycle_elapsed_ms = max(0, int((evidence_completed - cycle_started) * 1000))
    try:
        receipt = writer.submit(plan, cycle_deadline_monotonic=cycle_deadline)
    except Exception as exc:
        # The writer owns the chain ambiguity boundary. Only after it returns
        # control may telemetry persist the in-memory candidate for recovery.
        from .direct_writer import (
            DirectSubmissionAmbiguous,
            DirectSubmissionContradiction,
        )

        if (
            pending_telemetry is not None
            and isinstance(exc, DirectSubmissionAmbiguous)
            and not isinstance(exc, DirectSubmissionContradiction)
        ):
            try:
                plan_identity_sha256 = (
                    "sha256:"
                    + hashlib.sha256(
                        canonical_document_bytes(plan.identity())
                    ).hexdigest()
                )
                if journal_pending_plan_matches(
                    writer.state_path,
                    plan_identity_sha256,
                ):
                    pending_telemetry.prepare(
                        build_telemetry_candidate(
                            result_rows=result.rows,
                            plan=plan,
                        ),
                        plan,
                        None,
                    )
            except Exception:
                pass
        raise
    event = {
        "status": receipt.status,
        "anchor": snapshot.identity(),
        "raw_scores": [list(row) for row in plan.raw_scores],
        "wire_uids": list(plan.wire_uids),
        "wire_weights": list(plan.wire_weights),
        "evidence_digest": plan.evidence_digest,
        "evidence_cycle_elapsed_ms": evidence_cycle_elapsed_ms,
        "evidence_summary": evidence_summary,
        "receipt": receipt.as_document(),
    }
    reconciled_event_id: str | None = None
    if pending_telemetry is not None:
        try:
            # A prior candidate contains its own finalized receipt. Reconcile
            # only after this cycle's authoritative chain write has finished.
            prior_event = pending_telemetry.finalize(keypair=keypair)
            if prior_event is not None:
                reconciled_event_id = str(prior_event["event_id"])
        except Exception:
            pass
    if telemetry_sink is not None:
        try:
            if pending_telemetry is None:
                raise TelemetryError("telemetry pending store is absent")
            # Every telemetry filesystem operation happens only after the
            # authoritative writer has returned a finalized receipt.
            telemetry_candidate = build_telemetry_candidate(
                result_rows=result.rows,
                plan=plan,
            )
            pending_telemetry.prepare(telemetry_candidate, plan, receipt)
            telemetry = pending_telemetry.finalize(
                keypair=keypair,
                expected_receipt=receipt,
            )
            if telemetry is None:
                raise TelemetryError("finalized telemetry event is absent")
            event["telemetry"] = {
                "status": "SPOOLED",
                "event_id": telemetry["event_id"],
            }
        except Exception:
            # The scoring result and finalized chain receipt are authoritative.
            # A local projection failure is reported but never changes them.
            event["telemetry"] = {"status": "FAILED"}
    if reconciled_event_id is not None:
        event["reconciled_telemetry_event_id"] = reconciled_event_id
    return event


def _recovered_cycle_event(
    *,
    recovered: Any,
    writer: Any,
    keypair: Any,
    telemetry_sink: TelemetrySpool | None,
) -> dict[str, Any]:
    """Project one already-finalized writer recovery without chain access."""

    event = {"status": recovered.status, "recovery": recovered.as_document()}
    if telemetry_sink is None:
        return event
    pending_telemetry = PendingTelemetryStore(telemetry_sink)
    try:
        pending_plan = pending_telemetry.plan_identity_sha256()
        journal_receipt = (
            journal_receipt_for_plan(writer.state_path, pending_plan)
            if pending_plan is not None
            else None
        )
        telemetry = (
            pending_telemetry.finalize(
                keypair=keypair,
                expected_receipt=recovered,
            )
            if journal_receipt == recovered
            else None
        )
        event["telemetry"] = (
            {"status": "SPOOLED", "event_id": telemetry["event_id"]}
            if telemetry is not None
            else {"status": "NO_FINALIZED_EVENT"}
        )
    except Exception:
        event["telemetry"] = {"status": "FAILED"}
    return event


def run_direct_cycle(
    *,
    subtensor: Any,
    keypair: Any,
    verifier_adapter: ComputeAdapter,
    writer: Any,
    snp_verifier: SnpProductionVerifier | None = None,
    telemetry_sink: TelemetrySpool | None = None,
) -> dict[str, Any]:
    """Run one complete cycle while excluding a release activation.

    Test doubles without a cycle lock remain usable, while the installed
    ``DirectWeightWriter`` always supplies the per-signer flock.
    """

    lock = getattr(writer, "cycle_locked", None)
    context = lock() if callable(lock) else nullcontext()
    with context:
        return _run_direct_cycle_unlocked(
            subtensor=subtensor,
            keypair=keypair,
            verifier_adapter=verifier_adapter,
            writer=writer,
            snp_verifier=snp_verifier,
            telemetry_sink=telemetry_sink,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cathedral-validator")
    parser.add_argument("--network", default="finney")
    parser.add_argument("--wallet-name", default="validator")
    parser.add_argument("--wallet-hotkey", default="default")
    parser.add_argument("--wallet-path", type=Path)
    parser.add_argument(
        "--expected-hotkey",
        required=True,
        help="public SS58 address which the loaded hotkey credential must match",
    )
    parser.add_argument("--qvl", required=True)
    parser.add_argument(
        "--snp-policy",
        required=True,
        help="owner-controlled AMD SEV-SNP production policy JSON",
    )
    parser.add_argument(
        "--snpguest",
        required=True,
        help="pinned AMD snpguest verifier",
    )
    parser.add_argument(
        "--telemetry-spool",
        type=Path,
        help="sanitized telemetry path shared with the isolated exporter",
    )
    parser.add_argument(
        "--telemetry-reader-group",
        help="group allowed to read only the sanitized telemetry spool",
    )
    parser.add_argument(
        "--interval-seconds", type=float, default=DEFAULT_INTERVAL_SECONDS
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--confirm-direct-write",
        action="store_true",
        help="required acknowledgement that this process signs SN39 weights",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    if options.confirm_direct_write is not True:
        raise SystemExit("--confirm-direct-write is required before any chain access")
    if options.network != "finney":
        raise SystemExit("direct validator is pinned to the Finney network")
    expected_hotkey = _expected_hotkey(options.expected_hotkey)
    if (
        not isinstance(options.interval_seconds, float)
        or not math.isfinite(options.interval_seconds)
        or options.interval_seconds <= 0
    ):
        raise SystemExit("interval must be positive")

    verifier = load_direct_validator_verifier(options.qvl)
    adapter = ComputeAdapter(
        verifier,
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=verifier.digest,
    )
    try:
        snp_verifier = SnpProductionVerifier(
            policy=load_snp_policy(options.snp_policy),
            snpguest_path=options.snpguest,
        )
    except SnpProductionError as exc:
        raise SystemExit(f"AMD SEV-SNP production verifier refused: {exc}") from exc
    wallet = make_wallet(
        bt,
        name=options.wallet_name,
        hotkey=options.wallet_hotkey,
        path=str(options.wallet_path) if options.wallet_path is not None else None,
    )
    keypair = wallet.hotkey
    if str(getattr(keypair, "ss58_address", "")) != expected_hotkey:
        raise SystemExit("loaded validator hotkey does not match --expected-hotkey")
    if not callable(getattr(keypair, "sign", None)):
        raise SystemExit("validator hotkey cannot sign")
    subtensor = make_subtensor(bt, network=options.network)
    from .direct_writer import (
        DirectSubmissionAmbiguous,
        DirectSubmissionContradiction,
        DirectWeightWriter,
        STATUS_CONFIRMED,
        STATUS_RECOVERED,
    )

    writer = DirectWeightWriter(
        subtensor=subtensor,
        keypair=keypair,
    )
    if bool(options.telemetry_spool) != bool(options.telemetry_reader_group):
        raise SystemExit(
            "--telemetry-spool and --telemetry-reader-group must be supplied together"
        )
    if options.telemetry_spool is None:
        telemetry_sink = None
    else:
        if not options.telemetry_spool.is_absolute():
            raise SystemExit("--telemetry-spool must be absolute")
        try:
            reader_gid = grp.getgrnam(options.telemetry_reader_group).gr_gid
        except KeyError as exc:
            raise SystemExit("telemetry reader group does not exist") from exc
        telemetry_sink = TelemetrySpool(
            options.telemetry_spool,
            reader_gid=reader_gid,
        )
    process_lock = getattr(writer, "process_locked", None)
    process_context = process_lock() if callable(process_lock) else nullcontext()
    with process_context:
        # This read-only recovery preflight validates the durable journal and
        # any unresolved chain identity before systemd treats the release as
        # ready.  During an update, the root updater still owns cycle.lock, so
        # no fresh scoring or signing cycle can begin before activation commits.
        startup_recovery = writer.recover()
        _notify_ready()
        if startup_recovery is not None:
            startup_event = _recovered_cycle_event(
                recovered=startup_recovery,
                writer=writer,
                keypair=keypair,
                telemetry_sink=telemetry_sink,
            )
            print(
                json.dumps(
                    startup_event,
                    sort_keys=True,
                    default=str,
                ),
                flush=True,
            )
            if options.once:
                return (
                    0
                    if startup_recovery.status in {STATUS_CONFIRMED, STATUS_RECOVERED}
                    else 2
                )
            time.sleep(options.interval_seconds)
        while True:
            try:
                event = run_direct_cycle(
                    subtensor=subtensor,
                    keypair=keypair,
                    verifier_adapter=adapter,
                    writer=writer,
                    snp_verifier=snp_verifier,
                    telemetry_sink=telemetry_sink,
                )
                print(json.dumps(event, sort_keys=True, default=str), flush=True)
            except DirectSubmissionContradiction as exc:
                print(
                    json.dumps(
                        {"status": "CONTRADICTION_STOPPED", "error": str(exc)},
                        sort_keys=True,
                    ),
                    flush=True,
                )
                return 2
            except (DirectSubmissionAmbiguous, IndependentLiveError) as exc:
                print(
                    json.dumps(
                        {"status": "NOT_PROVEN", "error": str(exc)},
                        sort_keys=True,
                    ),
                    flush=True,
                )
                if options.once:
                    return 2
            except Exception as exc:
                print(
                    json.dumps(
                        {
                            "status": "NOT_PROVEN",
                            "error": f"{type(exc).__name__}: {exc}",
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
                if options.once:
                    return 2
            if options.once:
                return (
                    0
                    if event.get("status") in {STATUS_CONFIRMED, STATUS_RECOVERED}
                    else 2
                )
            time.sleep(options.interval_seconds)


__all__ = [
    "DIRECT_PLAN_SCHEMA",
    "DirectValidatorError",
    "DirectWeightPlan",
    "FinalizedMetagraphSnapshot",
    "build_direct_plan",
    "finalized_serving_miners_snapshot",
    "main",
    "run_direct_cycle",
]
