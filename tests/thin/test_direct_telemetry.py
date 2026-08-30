from __future__ import annotations

import base64
import hashlib
import json
import os
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from bittensor_wallet import Keypair

from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.direct_contract import (
    DirectSubmissionReceipt,
    DirectWeightPlan,
    FinalizedMetagraphSnapshot,
)
from cathedral_thin.independent_runtime.telemetry import (
    TELEMETRY_SIGNING_DOMAIN,
    PendingTelemetryStore,
    TELEMETRY_SCHEMA,
    TelemetryError,
    TelemetrySpool,
    build_telemetry_snapshot,
    build_telemetry_candidate,
    canonical_telemetry_path,
    latest_telemetry_event,
    validate_public_telemetry_event,
)
from cathedral_thin.independent_runtime.preview_io import canonical_document_bytes

VALIDATOR_KEYPAIR = Keypair.create_from_uri("//Alice")
TDX_MINER_KEYPAIR = Keypair.create_from_uri("//Bob")
SNP_MINER_KEYPAIR = Keypair.create_from_uri("//Charlie")


def _plan() -> DirectWeightPlan:
    snapshot = FinalizedMetagraphSnapshot(
        block_number=123,
        block_hash="0x" + "a" * 64,
        validator_uid=30,
        validator_hotkey=VALIDATOR_KEYPAIR.ss58_address,
        miners=(
            ServingAxon(41, TDX_MINER_KEYPAIR.ss58_address, "1.1.1.1", 8081),
            ServingAxon(42, SNP_MINER_KEYPAIR.ss58_address, "8.8.8.8", 8081),
        ),
        skipped_axons={},
    )
    return DirectWeightPlan(
        snapshot=snapshot,
        qvl_digest="4b6f" + "0" * 60,
        evidence_digest="sha256:" + "b" * 64,
        machine_ids_by_uid=(
            (41, ("private-machine-41",)),
            (42, ("private-machine-42",)),
        ),
        raw_scores=((41, 1), (42, 1)),
        uid_hotkeys=(
            (41, TDX_MINER_KEYPAIR.ss58_address),
            (42, SNP_MINER_KEYPAIR.ss58_address),
        ),
        wire_uids=(41, 42),
        wire_weights=(32768, 32767),
    )


def _receipt() -> DirectSubmissionReceipt:
    return DirectSubmissionReceipt(
        status="CONFIRMED",
        attempt_id="sha256:" + "c" * 64,
        extrinsic_hash="0x" + "d" * 64,
        block_hash="0x" + "e" * 64,
        block_number=124,
        recovered=False,
    )


def _row(uid: int, hotkey: str, tee: str, elapsed: int) -> dict[str, object]:
    return {
        "uid": uid,
        "hotkey": hotkey,
        "endpoint": "https://private.example:8081",
        "machine_id": f"private-machine-{uid}",
        "channel_id": "private-spki",
        "quote_sha256": "private-quote",
        "verdict": "PASS",
        "platform_identity_verified": True,
        "sat_units": 20,
        "counted_units": 20,
        "tee_kind": tee,
        "phase_timings_ms": {
            "binding": elapsed,
            "evidence": elapsed,
            "qvl": elapsed,
            "sat": elapsed,
        },
    }


def test_snapshot_exposes_only_sanitized_direct_round_facts() -> None:
    snapshot = build_telemetry_snapshot(
        result_rows=(
            _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
            _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
        ),
        plan=_plan(),
        receipt=_receipt(),
        keypair=VALIDATOR_KEYPAIR,
        observed_at=datetime(2026, 8, 30, 12, 0, tzinfo=UTC),
    )

    assert snapshot["schema"] == TELEMETRY_SCHEMA
    assert snapshot["validator"] == {
        "uid": 30,
        "hotkey": VALIDATOR_KEYPAIR.ss58_address,
        "permit": True,
    }
    assert snapshot["burn_weight"] == 0
    assert snapshot["signature"]["algorithm"] == "sr25519"
    assert VALIDATOR_KEYPAIR.verify(
        b"cathedral-validator-telemetry-v2\x00" + snapshot["event_id"].encode("ascii"),
        base64.b64decode(snapshot["signature"]["value_base64"], validate=True),
    )
    assert snapshot["miners"] == [
        {
            "uid": 41,
            "hotkey": TDX_MINER_KEYPAIR.ss58_address,
            "distinct_verified_compute": 1,
            "tee_counts": {"tdx": 1, "sev_snp": 0},
            "sat_units": 20,
            "verification_ms": {"samples": 1, "average": 40, "maximum": 40},
            "weight_u16": 32768,
            "verified_at": "2026-08-30T12:00:00Z",
            "status": "weighted",
        },
        {
            "uid": 42,
            "hotkey": SNP_MINER_KEYPAIR.ss58_address,
            "distinct_verified_compute": 1,
            "tee_counts": {"tdx": 0, "sev_snp": 1},
            "sat_units": 20,
            "verification_ms": {"samples": 1, "average": 80, "maximum": 80},
            "weight_u16": 32767,
            "verified_at": "2026-08-30T12:00:00Z",
            "status": "weighted",
        },
    ]
    encoded = json.dumps(snapshot, sort_keys=True)
    for secret in (
        "private.example",
        "private-machine",
        "private-spki",
        "private-quote",
        "1.1.1.1",
        "8.8.8.8",
    ):
        assert secret not in encoded


def test_snapshot_uses_plan_admission_for_mixed_legacy_and_fleet_rows() -> None:
    base = _plan()
    plan = DirectWeightPlan(
        snapshot=base.snapshot,
        qvl_digest=base.qvl_digest,
        evidence_digest=base.evidence_digest,
        machine_ids_by_uid=((41, ()), (42, ("private-machine-42",))),
        raw_scores=((41, 0), (42, 1)),
        uid_hotkeys=base.uid_hotkeys,
        wire_uids=(41, 42),
        wire_weights=(0, 65535),
    )

    snapshot = build_telemetry_snapshot(
        result_rows=(
            _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
            _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
        ),
        plan=plan,
        receipt=_receipt(),
        keypair=VALIDATOR_KEYPAIR,
        observed_at=datetime(2026, 8, 30, 12, 1, tzinfo=UTC),
    )

    legacy, current = snapshot["miners"]
    assert legacy == {
        "uid": 41,
        "hotkey": TDX_MINER_KEYPAIR.ss58_address,
        "distinct_verified_compute": 0,
        "tee_counts": {"tdx": 0, "sev_snp": 0},
        "sat_units": 0,
        "verification_ms": {"samples": 0, "average": None, "maximum": None},
        "weight_u16": 0,
        "verified_at": None,
        "status": "not_verified",
    }
    assert current["uid"] == 42
    assert current["distinct_verified_compute"] == 1
    assert current["weight_u16"] == 65535
    assert current["status"] == "weighted"


def test_python_generated_wire_fixture_stays_collector_compatible() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "cathedral_validator_telemetry_v2_python.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="ascii"))
    validator = Keypair.create_from_seed("0x" + bytes(range(32)).hex())
    miner = "5CShbTqxKUgKZBRDu1VGVpivm3m415stz86A5GBdoV7wrU1d"
    plan = DirectWeightPlan(
        snapshot=FinalizedMetagraphSnapshot(
            block_number=123,
            block_hash="0x" + "a" * 64,
            validator_uid=30,
            validator_hotkey=validator.ss58_address,
            miners=(ServingAxon(41, miner, "1.1.1.1", 8081),),
            skipped_axons={},
        ),
        qvl_digest="fixture",
        evidence_digest="sha256:" + "b" * 64,
        machine_ids_by_uid=((41, ("fixture-machine",)),),
        raw_scores=((41, 1),),
        uid_hotkeys=((41, miner),),
        wire_uids=(41,),
        wire_weights=(65535,),
    )
    receipt = DirectSubmissionReceipt(
        status="CONFIRMED",
        attempt_id="sha256:" + "c" * 64,
        extrinsic_hash="0x" + "d" * 64,
        block_hash="0x" + "e" * 64,
        block_number=124,
        recovered=False,
    )
    row = {
        "uid": 41,
        "hotkey": miner,
        "machine_id": "fixture-machine",
        "verdict": "PASS",
        "platform_identity_verified": True,
        "sat_units": 20,
        "counted_units": 20,
        "tee_kind": "tdx",
        "phase_timings_ms": {
            "binding": 10,
            "evidence": 10,
            "qvl": 10,
            "sat": 10,
        },
    }
    generated = build_telemetry_snapshot(
        result_rows=(row,),
        plan=plan,
        receipt=receipt,
        keypair=validator,
        observed_at=datetime(2026, 8, 30, 12, 3, tzinfo=UTC),
    )

    assert fixture_path.read_bytes() == canonical_document_bytes(fixture)
    assert validate_public_telemetry_event(fixture) == fixture
    assert {key: value for key, value in generated.items() if key != "signature"} == {
        key: value for key, value in fixture.items() if key != "signature"
    }


def test_signed_snapshot_refuses_content_and_signature_tampering(tmp_path) -> None:
    event = build_telemetry_snapshot(
        result_rows=(
            _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
            _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
        ),
        plan=_plan(),
        receipt=_receipt(),
        keypair=VALIDATOR_KEYPAIR,
    )
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")

    changed_content = deepcopy(event)
    changed_content["miners"][0]["weight_u16"] = 1
    with pytest.raises(TelemetryError, match="identity"):
        spool.append(changed_content)

    changed_signature = deepcopy(event)
    original_signature = changed_signature["signature"]["value_base64"]
    changed_signature["signature"]["value_base64"] = (
        "B" if original_signature.startswith("A") else "A"
    ) + original_signature[1:]
    with pytest.raises(TelemetryError, match="signature"):
        spool.append(changed_signature)


def test_spool_refuses_a_signed_event_whose_weights_are_not_finalized(tmp_path) -> None:
    event = build_telemetry_snapshot(
        result_rows=(
            _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
            _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
        ),
        plan=_plan(),
        receipt=_receipt(),
        keypair=VALIDATOR_KEYPAIR,
    )
    event["miners"][0]["weight_u16"] = 1
    unsigned = deepcopy(event)
    unsigned.pop("event_id")
    unsigned.pop("signature")
    event_id = (
        "sha256:"
        + hashlib.sha256(
            canonical_document_bytes(unsigned).removesuffix(b"\n")
        ).hexdigest()
    )
    event["event_id"] = event_id
    event["signature"] = {
        "algorithm": "sr25519",
        "value_base64": base64.b64encode(
            VALIDATOR_KEYPAIR.sign(TELEMETRY_SIGNING_DOMAIN + event_id.encode("ascii"))
        ).decode("ascii"),
    }

    with pytest.raises(TelemetryError, match="weights do not match"):
        TelemetrySpool(tmp_path / "telemetry" / "events.jsonl").append(event)


def test_snapshot_refuses_a_nonfinalized_submission_receipt() -> None:
    pending_receipt = DirectSubmissionReceipt(
        status="PENDING",
        attempt_id="pending",
        extrinsic_hash="pending",
        block_hash=None,
        block_number=None,
        recovered=False,
    )

    with pytest.raises(TelemetryError, match="finalized successful receipt"):
        build_telemetry_snapshot(
            result_rows=(
                _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
                _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
            ),
            plan=_plan(),
            receipt=pending_receipt,
            keypair=VALIDATOR_KEYPAIR,
        )


def test_snapshot_refuses_a_different_or_non_sr25519_signer() -> None:
    rows = (
        _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
        _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
    )
    with pytest.raises(TelemetryError, match="does not match"):
        build_telemetry_snapshot(
            result_rows=rows,
            plan=_plan(),
            receipt=_receipt(),
            keypair=TDX_MINER_KEYPAIR,
        )

    class _Ed25519Lookalike:
        ss58_address = VALIDATOR_KEYPAIR.ss58_address
        crypto_type = 0

        def sign(self, _message):
            return b"x" * 64

    with pytest.raises(TelemetryError, match="does not match"):
        build_telemetry_snapshot(
            result_rows=rows,
            plan=_plan(),
            receipt=_receipt(),
            keypair=_Ed25519Lookalike(),
        )


def test_snapshot_refuses_if_positive_rows_do_not_match_weight_plan() -> None:
    with pytest.raises(TelemetryError, match="differ from the plan"):
        build_telemetry_snapshot(
            result_rows=(_row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),),
            plan=_plan(),
            receipt=_receipt(),
            keypair=VALIDATOR_KEYPAIR,
        )


def test_owner_only_spool_round_trips_canonical_latest_event(tmp_path) -> None:
    event = build_telemetry_snapshot(
        result_rows=(
            _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
            _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
        ),
        plan=_plan(),
        receipt=_receipt(),
        keypair=VALIDATOR_KEYPAIR,
    )
    state_path = tmp_path / "direct-writer" / "state.json"
    path = canonical_telemetry_path(state_path)
    spool = TelemetrySpool(path)

    spool.append(event)

    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert latest_telemetry_event(path) == event


def test_spool_refuses_a_symlink(tmp_path) -> None:
    event = build_telemetry_snapshot(
        result_rows=(
            _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
            _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
        ),
        plan=_plan(),
        receipt=_receipt(),
        keypair=VALIDATOR_KEYPAIR,
    )
    outside = tmp_path / "outside"
    outside.write_text("do not replace", encoding="ascii")
    path = tmp_path / "telemetry" / "events.jsonl"
    path.parent.mkdir(mode=0o700)
    path.symlink_to(outside)

    with pytest.raises(TelemetryError, match="symlink"):
        TelemetrySpool(path).append(event)
    assert outside.read_text(encoding="ascii") == "do not replace"


def test_pending_candidate_survives_until_the_finalized_receipt(tmp_path) -> None:
    candidate = build_telemetry_candidate(
        result_rows=(
            _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
            _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
        ),
        plan=_plan(),
    )
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    pending = PendingTelemetryStore(spool)
    receipt = _receipt()

    pending.prepare(candidate, _plan(), receipt)
    event = pending.finalize(
        keypair=VALIDATOR_KEYPAIR,
        expected_receipt=receipt,
    )

    assert event is not None
    assert event["submission"]["status"] == "CONFIRMED"
    assert latest_telemetry_event(spool.path) == event
    assert not pending.path.exists()


def test_pending_candidate_durably_binds_a_recovered_receipt(tmp_path) -> None:
    plan = _plan()
    candidate = build_telemetry_candidate(
        result_rows=(
            _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
            _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
        ),
        plan=plan,
    )
    spool = TelemetrySpool(tmp_path / "telemetry" / "events.jsonl")
    pending = PendingTelemetryStore(spool)
    receipt = _receipt()
    plan_identity_sha256 = (
        "sha256:"
        + hashlib.sha256(canonical_document_bytes(plan.identity())).hexdigest()
    )

    pending.prepare(candidate, plan, None)
    assert pending.bind_receipt(plan_identity_sha256, receipt) is True
    assert json.loads(pending.path.read_text())["receipt"] == receipt.as_document()

    event = pending.finalize(keypair=VALIDATOR_KEYPAIR)
    assert event is not None
    assert event["submission"]["block_number"] == receipt.block_number
    assert latest_telemetry_event(spool.path) == event
    assert not pending.path.exists()


def test_shared_spool_exposes_only_sanitized_events_to_the_reader_group(
    tmp_path,
) -> None:
    event = build_telemetry_snapshot(
        result_rows=(
            _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
            _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
        ),
        plan=_plan(),
        receipt=_receipt(),
        keypair=VALIDATOR_KEYPAIR,
    )
    path = tmp_path / "shared" / "events.jsonl"
    gid = os.getegid()

    TelemetrySpool(path, reader_gid=gid).append(event)

    assert path.stat().st_mode & 0o777 == 0o640
    assert path.parent.stat().st_mode & 0o777 == 0o750
    assert latest_telemetry_event(path, expected_reader_gid=gid) == event
