"""SN94 receipt weighting with the actual writer and an in-memory chain double."""

import json
from copy import deepcopy
from dataclasses import replace

import pytest

from cathedral_thin.independent_runtime.delivery_plan import (
    DeliveryLedger,
    DeliveryPlanError,
    build_plan,
    digest,
)
from cathedral_thin.independent_runtime.delivery_runtime import (
    DeliveryContext,
    weight_plan,
)
from cathedral_thin.independent_runtime.direct_contract import DirectValidatorError
from cathedral_thin.independent_runtime.direct_writer import (
    STATUS_CONFIRMED,
    STATUS_RECOVERED,
    DirectSubmissionAmbiguous,
    DirectSubmissionContradiction,
)
from cathedral_thin.independent_runtime.qvl import DIRECT_VALIDATOR_QVL_DIGEST
from tests.thin.test_delivery_plan import START, entry, policy
from tests.thin.test_direct_validator import (
    MINER_ONE,
    MINER_ONE_AXON,
    MINER_TWO,
    MINER_TWO_AXON,
    snapshot,
    submit_before_deadline,
    writer,
)
from tests.thin.test_direct_validator import (
    plan as sat_plan,
)


def delivery_plan():
    p = policy()
    p.update(
        mode="write",
        burn_uid=20,
        burn_hotkey=MINER_TWO,
        verifier_sha256=DIRECT_VALIDATOR_QVL_DIGEST,
    )
    admitted = replace(
        entry(miner_hotkey=MINER_ONE)[0], verifier_digest=DIRECT_VALIDATOR_QVL_DIGEST
    )
    document = build_plan(
        policy=p,
        window_start=START,
        uid_hotkeys={19: MINER_ONE, 20: MINER_TWO},
        admitted=[admitted],
    )
    return weight_plan(snapshot(miners=(MINER_ONE_AXON, MINER_TWO_AXON)), document)


def setup(tmp_path, monkeypatch):
    planned = delivery_plan()
    instance, chain, _ = writer(tmp_path, monkeypatch, planned=planned)
    instance.delivery_policy_digest = planned.delivery["policy_digest"]
    return instance, chain, planned


def test_delivery_writer_requires_explicit_mode(tmp_path, monkeypatch):
    planned = delivery_plan()
    instance, chain, _ = writer(tmp_path, monkeypatch, planned=planned)
    with pytest.raises(DirectValidatorError):
        submit_before_deadline(instance, planned)
    assert chain.substrate.sign_calls == 0


def test_delivery_writer_never_falls_back_to_sat(tmp_path, monkeypatch):
    instance, chain, _ = setup(tmp_path, monkeypatch)
    with pytest.raises(DirectValidatorError):
        submit_before_deadline(instance, sat_plan())
    assert chain.substrate.sign_calls == 0


def test_real_writer_submits_delivery_weight_vector(tmp_path, monkeypatch):
    instance, chain, planned = setup(tmp_path, monkeypatch)
    receipt = submit_before_deadline(instance, planned)
    assert receipt.status == STATUS_CONFIRMED
    assert planned.raw_scores == ((19, 300),)
    assert planned.wire_weights == (58981, 6554)
    assert chain.substrate.sign_calls == chain.substrate.submit_calls == 1
    assert (
        instance.delivery_record(planned.delivery["plan_id"])["status"]
        == STATUS_CONFIRMED
    )


def test_delivery_recovers_exact_hash_without_resign(tmp_path, monkeypatch):
    instance, chain, planned = setup(tmp_path, monkeypatch)
    chain.substrate.raise_after_include = True
    with pytest.raises(DirectSubmissionAmbiguous):
        submit_before_deadline(instance, planned)
    receipt = instance.recover()
    assert receipt.status == STATUS_RECOVERED
    assert chain.substrate.sign_calls == chain.substrate.submit_calls == 1
    assert (
        instance.delivery_record(planned.delivery["plan_id"])["status"]
        == STATUS_RECOVERED
    )


def test_recovery_cannot_change_receipt_policy(tmp_path, monkeypatch):
    instance, chain, planned = setup(tmp_path, monkeypatch)
    chain.substrate.raise_after_include = True
    with pytest.raises(DirectSubmissionAmbiguous):
        submit_before_deadline(instance, planned)
    instance.delivery_policy_digest = "ff" * 32
    with pytest.raises(DirectSubmissionContradiction):
        instance.recover()
    assert chain.substrate.sign_calls == chain.substrate.submit_calls == 1


@pytest.mark.parametrize(
    "field,value", [("raw_scores", [[19, 301]]), ("wire_weights", [65534, 1])]
)
def test_rehashed_tampering_does_not_bypass_recomputation(
    tmp_path, monkeypatch, field, value
):
    planned = delivery_plan()
    document = deepcopy(planned.delivery)
    document[field] = value
    document["plan_id"] = digest({k: v for k, v in document.items() if k != "plan_id"})
    with pytest.raises(DeliveryPlanError):
        weight_plan(planned.snapshot, document)


def test_sn39_cannot_use_delivery_weights():
    planned = delivery_plan()
    with pytest.raises(DeliveryPlanError):
        weight_plan(replace(planned.snapshot, netuid=39), planned.delivery)


def context(tmp_path, planned):
    policy_path, bundle_path = tmp_path / "policy.json", tmp_path / "bundle.json"
    policy_path.write_text(json.dumps(planned.delivery["policy"]))
    bundle_path.write_text(json.dumps({"window_start": START, "entries": []}))
    return DeliveryContext(
        policy_path=policy_path,
        bundle_path=bundle_path,
        ledger_path=tmp_path / "delivery.sqlite",
    )


def test_started_without_writer_journal_never_retries(tmp_path, monkeypatch):
    instance, chain, planned = setup(tmp_path, monkeypatch)
    ctx = context(tmp_path, planned)
    ledger = DeliveryLedger(ctx.ledger_path)
    ledger.prepare(planned.delivery)
    ledger.db.execute(
        "CREATE TABLE submissions(plan_id TEXT PRIMARY KEY,state TEXT,receipt TEXT)"
    )
    ledger.db.execute(
        "INSERT INTO submissions VALUES(?,'STARTED',NULL)",
        (planned.delivery["plan_id"],),
    )
    ledger.close()
    result = ctx.run(
        subtensor=chain,
        keypair=instance.keypair,
        writer=instance,
        snapshot_reader=lambda *_: planned.snapshot,
    )
    assert result["status"] == "NOT_PROVEN"
    assert chain.substrate.sign_calls == chain.substrate.submit_calls == 0


def test_reserved_delivery_window_recovers_then_cannot_submit_twice(
    tmp_path, monkeypatch
):
    instance, chain, planned = setup(tmp_path, monkeypatch)
    ctx = context(tmp_path, planned)
    ledger = DeliveryLedger(ctx.ledger_path)
    ledger.prepare(planned.delivery)
    ledger.close()
    chain.substrate.raise_after_include = True
    with pytest.raises(DirectSubmissionAmbiguous):
        ctx.run(
            subtensor=chain,
            keypair=instance.keypair,
            writer=instance,
            snapshot_reader=lambda *_: planned.snapshot,
        )
    # New process/context, same on-disk ledgers.
    ctx = context(tmp_path, planned)
    result = ctx.run(
        subtensor=chain,
        keypair=instance.keypair,
        writer=instance,
        snapshot_reader=lambda *_: planned.snapshot,
    )
    assert result["status"] == STATUS_RECOVERED
    result = ctx.run(
        subtensor=chain,
        keypair=instance.keypair,
        writer=instance,
        snapshot_reader=lambda *_: planned.snapshot,
    )
    assert result["status"] == "WINDOW_ALREADY_CONSUMED"
    assert chain.substrate.sign_calls == chain.substrate.submit_calls == 1


def test_bundle_consumer_to_real_writer_unattested_burn_only(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from tests.thin.test_delivery_plan import EX
    from cathedral_thin.independent_runtime import delivery_runtime

    planned = delivery_plan()
    zero = build_plan(
        policy=planned.delivery["policy"],
        window_start=START,
        uid_hotkeys={19: MINER_ONE, 20: MINER_TWO},
        admitted=[],
    )
    burn_plan = weight_plan(planned.snapshot, zero)
    instance, chain, _ = writer(tmp_path, monkeypatch, planned=burn_plan)
    instance.delivery_policy_digest = burn_plan.delivery["policy_digest"]
    ctx = context(tmp_path, burn_plan)
    _, receipt = entry(miner_hotkey=MINER_ONE, execution_class="unattested")
    ctx.bundle_path.write_text(
        json.dumps(
            {
                "window_start": START,
                "uid_hotkeys": [[999, "feed-cannot-choose-chain-owner"]],
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
        )
    )
    monkeypatch.setattr(delivery_runtime.time, "time", lambda: START + 3601)
    result = ctx.run(
        subtensor=chain,
        keypair=instance.keypair,
        writer=instance,
        snapshot_reader=lambda *_: planned.snapshot,
    )
    assert result["status"] == STATUS_CONFIRMED
    assert result["raw_scores"] == []
    assert result["wire_uids"] == [20] and result["wire_weights"] == [65535]
    assert chain.substrate.sign_calls == chain.substrate.submit_calls == 1


def test_cooldown_before_signing_does_not_poison_delivery_window(tmp_path, monkeypatch):
    instance, chain, planned = setup(tmp_path, monkeypatch)
    ctx = context(tmp_path, planned)
    ledger = DeliveryLedger(ctx.ledger_path)
    ledger.prepare(planned.delivery)
    ledger.close()
    old = chain.blocks_since
    chain.blocks_since = 5
    with pytest.raises(DirectValidatorError):
        ctx.run(
            subtensor=chain,
            keypair=instance.keypair,
            writer=instance,
            snapshot_reader=lambda *_: planned.snapshot,
        )
    ledger = DeliveryLedger(ctx.ledger_path)
    assert ledger.db.execute("SELECT count(*) FROM submissions").fetchone() == (0,)
    ledger.close()
    assert chain.substrate.sign_calls == 0
    chain.blocks_since = old
    result = ctx.run(
        subtensor=chain,
        keypair=instance.keypair,
        writer=instance,
        snapshot_reader=lambda *_: planned.snapshot,
    )
    assert result["status"] == STATUS_CONFIRMED
    assert chain.substrate.sign_calls == chain.substrate.submit_calls == 1
