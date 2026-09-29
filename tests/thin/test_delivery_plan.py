"""Local accounting tests; admitted objects are explicit synthetic fixtures."""

from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cathedral.delivery import (
    AdmittedDelivery,
    sign_receipt,
    verify_receipt,
    MIN_RETENTION_SECONDS,
)
from cathedral_thin.independent_runtime.delivery_plan import (
    DeliveryLedger,
    DeliveryPlanError,
    build_plan,
    consume_bundle,
    digest,
)

START = 1_790_640_000
NOW = START + 3601
MEASUREMENT = "tdx-measurement-sha256:" + "33" * 32
EX = Ed25519PrivateKey.generate()
CP = Ed25519PrivateKey.generate()


def policy():
    return dict(
        schema="cathedral_sn94_delivery_policy_v1",
        netuid=94,
        mode="plan_only",
        window_seconds=3600,
        burn_bps=1000,
        burn_uid=0,
        burn_hotkey="burn",
        allowed_measurements=[MEASUREMENT],
        verifier_path="/nonexistent/pinned-verifier",
        verifier_sha256="aa" * 32,
        control_plane_keys={
            "central-1": CP.public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
            .hex()
        },
    )


def entry(**changes):
    body = dict(
        schema="cathedral_delivery_receipt_v1",
        netuid=94,
        receipt_id="r-1",
        attempt_id="a-1",
        sandbox_id="s-1",
        miner_hotkey="miner-1",
        hardware_id="11" * 32,
        executor_key_id="ex-1",
        control_plane_key_id="central-1",
        evidence_sha256="22" * 32,
        measurement=MEASUREMENT,
        admission_nonce="44" * 32,
        admitted_at=START,
        admission_expires_at=START + 7200,
        window_start=START,
        window_end=START + 3600,
        started_at=START + 1,
        ended_at=START + 61,
        vcpu=1,
        memory_gib=4,
        vcpu_seconds=60,
        gib_seconds=240,
        issued_at=START + 62,
        retention_until=START + 62 + MIN_RETENTION_SECONDS,
        execution_class="attested",
        outcome="completed",
    )
    body.update(changes)
    receipt = sign_receipt(body, executor_key=EX, control_plane_key=CP)
    verified = verify_receipt(
        receipt,
        executor_key=EX.public_key(),
        control_plane_key=CP.public_key(),
        now=max(NOW, body["issued_at"]),
    )
    return AdmittedDelivery(verified, "aa" * 32, "bb" * 32), receipt


def plan(entries=None, p=None):
    return build_plan(
        policy=p or policy(),
        window_start=START,
        uid_hotkeys={0: "burn", 1: "miner-1", 2: "miner-2"},
        admitted=entries or [entry()[0]],
    )


def test_actual_receipt_units_and_burn_rounding():
    one = entry()[0]
    two = entry(
        receipt_id="r-2",
        attempt_id="a-2",
        sandbox_id="s-2",
        miner_hotkey="miner-2",
        vcpu=2,
        vcpu_seconds=120,
    )[0]
    result = plan([one, two])
    assert result["raw_scores"] == [[1, 300], [2, 360]]
    assert sum(result["wire_weights"]) == 65535
    assert result["burn_weight"] == 65535 - (65535 * 9000 // 10000)
    assert result["chain_write"] is False


def test_no_eligible_work_means_burn_not_machine_count_fallback():
    result = build_plan(
        policy=policy(),
        window_start=START,
        uid_hotkeys={0: "burn", 1: "miner-1"},
        admitted=[],
    )
    assert result["wire_uids"] == [0] and result["wire_weights"] == [65535]


def test_unattested_is_zero_without_quote_verifier():
    _, receipt = entry(execution_class="unattested")
    bundle = {
        "window_start": START,
        "uid_hotkeys": [[0, "burn"], [1, "miner-1"]],
        "entries": [
            {
                "receipt": receipt,
                "executor_public_key": EX.public_key()
                .public_bytes(Encoding.Raw, PublicFormat.Raw)
                .hex(),
                "quote_hex": "",
            }
        ],
    }
    result = consume_bundle(bundle, policy(), now=NOW)
    assert result["wire_uids"] == [0]
    assert result["rejected"][0]["score"] == 0
    bundle["entries"][0]["receipt"]["body"]["miner_hotkey"] = "spoofed"
    with pytest.raises(DeliveryPlanError):
        consume_bundle(bundle, policy(), now=NOW)


def test_claimed_attestation_without_vendor_verifier_fails_closed():
    _, receipt = entry()
    bundle = {
        "window_start": START,
        "uid_hotkeys": [[0, "burn"], [1, "miner-1"]],
        "entries": [
            {
                "receipt": receipt,
                "executor_public_key": EX.public_key()
                .public_bytes(Encoding.Raw, PublicFormat.Raw)
                .hex(),
                "quote_hex": "00",
            }
        ],
    }
    with pytest.raises(DeliveryPlanError):
        consume_bundle(bundle, policy(), now=NOW)


@pytest.mark.parametrize(
    "changes", [{"receipt_id": "r-2"}, {"receipt_id": "r-2", "attempt_id": "a-2"}]
)
def test_duplicate_attempt_or_overlapping_sandbox_rejected(changes):
    with pytest.raises(DeliveryPlanError):
        plan([entry()[0], entry(**changes)[0]])


def test_restart_recovers_exact_reserved_plan_and_policy(tmp_path):
    path = tmp_path / "ledger.sqlite"
    expected = plan()
    ledger = DeliveryLedger(path)
    value, recovered = ledger.prepare(expected)
    ledger.close()
    assert not recovered
    ledger = DeliveryLedger(path)
    assert ledger.recover(START, digest(policy())) == expected
    assert ledger.prepare(expected)[1] is True
    changed = policy()
    changed["burn_bps"] = 2000
    with pytest.raises(DeliveryPlanError):
        ledger.prepare(plan(p=changed))
    with pytest.raises(DeliveryPlanError):
        ledger.recover(START, digest(changed))
    ledger.close()


def test_concurrent_ingestion_reserves_once(tmp_path):
    path = tmp_path / "ledger.sqlite"
    expected = plan()
    # Initialize schema before concurrent connections exercise the transaction.
    DeliveryLedger(path).close()

    def ingest(_):
        ledger = DeliveryLedger(path)
        try:
            return ledger.prepare(expected)[1]
        finally:
            ledger.close()

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(ingest, range(4)))
    assert results.count(False) == 1 and results.count(True) == 3


def test_existing_receipt_id_cannot_move_to_next_window(tmp_path):
    ledger = DeliveryLedger(tmp_path / "ledger.sqlite")
    ledger.prepare(plan())
    next_entry = entry(
        window_start=START + 3600,
        window_end=START + 7200,
        started_at=START + 3600,
        ended_at=START + 3660,
        issued_at=START + 3661,
        retention_until=START + 3661 + MIN_RETENTION_SECONDS,
    )[0]
    next_plan = build_plan(
        policy=policy(),
        window_start=START + 3600,
        uid_hotkeys={0: "burn", 1: "miner-1"},
        admitted=[next_entry],
    )
    with pytest.raises(DeliveryPlanError):
        ledger.prepare(next_plan)
    ledger.close()
