"""Replay refusal and epoch-level single-flight across restarts and races.

The consumption ledger is the only gate that stops a still-valid receipt from
being credited twice, so its behaviour is exercised here at the validator seam
rather than trusted from the shared contract:

* restart: the ledger is a file, so a validator restart must not forget what it
  already credited;
* repeatability: a preview READS the ledger, so running it any number of times
  returns the same vector, and only the explicit authoritative pass records;
* replay: a receipt recorded by the authoritative pass is refused afterwards;
* fail-open ledger: a ledger that reports a consume it did not record, or that
  cannot be read back at all, is refused as a preview-level failure rather than
  trusted, because within-preview deduplication cannot see across previews;
* concurrency: two authoritative passes racing one epoch, exactly one wins the
  epoch claim before receipt consumption; the shared ledger's lower-level
  one-token race is also exercised directly.
"""

from __future__ import annotations

import threading
from collections import Counter
from datetime import UTC, datetime

import pytest

_NEEDS_CONTRACT = (
    "needs the shared cathedral-distill contract: pip install -e '.[integration]'. "
    "Without it this module is skipped whole, and the nine modules that do so "
    "together drop ~168 thin tests without failing anything."
)

pytest.importorskip("cathedral_distill.integrated_feed", reason=_NEEDS_CONTRACT)
pytest.importorskip("cathedral_distill.testing", reason=_NEEDS_CONTRACT)

from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill.consumption_ledger import (  # noqa: E402
    ConsumptionLedger,
    ReplayError,
)
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402
from _durable_ledger import durable_ledger  # noqa: E402

from cathedral_thin import integration as ig  # noqa: E402

NOW_DT = datetime(2026, 7, 25, 12, 30, tzinfo=UTC)
NOW_ISO = "2026-07-25T12:30:00.000000Z"
LANE_CPU = ig.LANE_COMPUTE_CPU
LANE_DISTILL = ig.LANE_DISTILL

_ALLOCATIONS = [
    {"lane": LANE_CPU, "allocation": "0.45", "enabled": True},
    {"lane": LANE_DISTILL, "allocation": "0.45", "enabled": True},
]

RACE_CONSUMERS = 24


def _preview(fx, receipts, ledger, **kw):
    kw.setdefault("allowed_measurements", frozenset({fx.tdx_measurement}))
    kw.setdefault("allowed_tcb_statuses", frozenset({"UpToDate"}))
    kw.setdefault("allowed_advisories", frozenset())
    kw.setdefault("current_block", 6_000_100)
    return ig.preview_integrated_vector(
        burn_config=fx.burn_config(),
        allocation_config=fx.allocation_config(_ALLOCATIONS),
        key_registry=fx.registry,
        receipts=receipts,
        network="finney",
        netuid=39,
        source_epoch=fx.source_epoch,
        now=NOW_DT,
        now_iso=NOW_ISO,
        consumption_ledger=ledger,
        **kw,
    )


def _authoritative(fx, receipts, ledger, **kw):
    """The one pass per epoch that is allowed to record consumption."""
    return _preview(fx, receipts, ledger, consume_receipts=True, **kw)


def _one(fx, receipt):
    return [ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, receipt)]


def _verdict(out):
    (audited,) = out["audit"]["receipts"]
    return audited


# --------------------------------------------------------------------------- #
# B7(a) restart, B7(b) replay
# --------------------------------------------------------------------------- #


def test_a_replayed_receipt_is_refused_after_the_authoritative_pass():
    fx = IntegrationFixtures()
    receipt = fx.cpu_receipt()
    ledger = durable_ledger()

    first = _authoritative(fx, _one(fx, receipt), ledger)
    assert _verdict(first)["verdict"] == itf.PASS

    second = _preview(fx, _one(fx, receipt), ledger)  # inspection sees the record
    refused = _verdict(second)
    assert refused["verdict"] == itf.FAIL
    assert "already consumed" in refused["detail"]
    assert second["feed"]["weights"] == []


def test_ledger_state_survives_a_restart_and_still_refuses_the_replay(tmp_path):
    """The second preview runs on a ledger reopened from disk, as a restart does."""
    fx = IntegrationFixtures()
    receipt = fx.cpu_receipt()
    path = str(tmp_path / "consumption.sqlite")

    before = ConsumptionLedger(path)
    assert (
        _verdict(_authoritative(fx, _one(fx, receipt), before))["verdict"] == itf.PASS
    )
    assert before.size() == 2  # epoch claim + receipt
    before.close()  # the validator process exits here

    after = ConsumptionLedger(path)
    assert after.is_consumed(receipt["receipt_id"])  # state came back from disk
    refused = _verdict(_preview(fx, _one(fx, receipt), after))
    assert refused["verdict"] == itf.FAIL
    assert "already consumed" in refused["detail"]
    assert after.size() == 2  # and nothing new was consumed


def test_the_next_epoch_still_passes_after_a_restart(tmp_path):
    """The durable claim fences one epoch, not the restarted validator forever."""
    before_fx = IntegrationFixtures(source_epoch=11)
    path = str(tmp_path / "consumption.sqlite")
    before = ConsumptionLedger(path)
    assert (
        _verdict(
            _authoritative(
                before_fx,
                _one(before_fx, before_fx.cpu_receipt(work_units="30")),
                before,
            )
        )["verdict"]
        == itf.PASS
    )
    before.close()

    after_fx = IntegrationFixtures(source_epoch=12)
    after = ConsumptionLedger(path)
    out = _authoritative(
        after_fx,
        _one(after_fx, after_fx.cpu_receipt(work_units="31")),
        after,
    )
    assert _verdict(out)["verdict"] == itf.PASS
    assert after.size() == 4  # two epoch claims + two receipt tokens


def test_a_refused_receipt_is_not_consumed_and_can_be_resubmitted(tmp_path):
    """A receipt the policy refuses must not burn its own replay token."""
    fx = IntegrationFixtures()
    receipt = fx.cpu_receipt()
    ledger = ConsumptionLedger(str(tmp_path / "consumption.sqlite"))

    refused = _verdict(
        _preview(
            fx,
            _one(fx, receipt),
            ledger,
            allowed_measurements=frozenset({"tdx-measurement-sha256:" + "ff" * 32}),
        )
    )
    assert refused["verdict"] == itf.FAIL
    assert not ledger.is_consumed(receipt["receipt_id"])

    # policy corrected: the same receipt is still creditable
    assert (
        _verdict(_authoritative(fx, _one(fx, receipt), ledger))["verdict"] == itf.PASS
    )
    assert ledger.size() == 2  # epoch claim + receipt


# --------------------------------------------------------------------------- #
# A preview is repeatable: inspecting the evidence must not destroy it
# --------------------------------------------------------------------------- #


def test_repeated_previews_return_an_identical_vector():
    """The activation evidence must survive being looked at.

    A preview that consumed its own tokens composed a 100% burn vector on the
    second run, so the operator who checked their work twice saw a different, and
    wrong, answer. The default gate is a read.
    """
    fx = IntegrationFixtures()
    ledger = durable_ledger()
    receipts = _one(fx, fx.cpu_receipt())

    runs = [_preview(fx, receipts, ledger) for _ in range(4)]
    first = runs[0]
    for out in runs[1:]:
        assert out["feed"] == first["feed"]
        assert out["audit"] == first["audit"]
    assert _verdict(first)["verdict"] == itf.PASS
    assert ledger.size() == 0  # nothing was recorded by any of them


def test_inspection_mode_reports_itself_and_authoritative_mode_says_so():
    fx = IntegrationFixtures()
    ledger = durable_ledger()
    receipts = _one(fx, fx.cpu_receipt())
    assert _preview(fx, receipts, ledger)["gates"]["replay_mode"] == "inspection"
    assert (
        _authoritative(fx, receipts, ledger)["gates"]["replay_mode"] == "authoritative"
    )


def test_the_authoritative_pass_records_and_a_later_inspection_sees_it():
    fx = IntegrationFixtures()
    ledger = durable_ledger()
    receipt = fx.cpu_receipt()

    inspected = _preview(fx, _one(fx, receipt), ledger)
    assert _verdict(inspected)["verdict"] == itf.PASS
    assert ledger.size() == 0

    authoritative = _authoritative(fx, _one(fx, receipt), ledger)
    assert _verdict(authoritative)["verdict"] == itf.PASS
    assert ledger.size() == 2  # epoch claim + receipt
    assert authoritative["gates"]["authoritative_epoch_claim"].startswith(
        "cathedral-integration-authoritative-epoch-v1:sha256:"
    )
    # and the vector the authoritative pass wrote matches what inspection showed
    assert authoritative["feed"] == inspected["feed"]

    after = _preview(fx, _one(fx, receipt), ledger)
    assert _verdict(after)["verdict"] == itf.FAIL
    assert "already consumed" in _verdict(after)["detail"]


def test_a_second_authoritative_pass_for_the_same_epoch_fails_closed():
    fx = IntegrationFixtures()
    ledger = durable_ledger()
    first = fx.cpu_receipt(work_units="30")
    second = fx.cpu_receipt(work_units="31")

    assert _verdict(_authoritative(fx, _one(fx, first), ledger))["verdict"] == itf.PASS
    with pytest.raises(ig.IntegrationLedgerError, match="epoch already claimed"):
        _authoritative(fx, _one(fx, second), ledger)

    assert ledger.is_consumed(first["receipt_id"])
    assert not ledger.is_consumed(second["receipt_id"])
    assert ledger.size() == 2


def test_authoritative_mode_refuses_without_a_real_epoch_ledger():
    no_replay = pytest.importorskip(
        "cathedral_distill.consumption_ledger"
    ).NO_REPLAY_LEDGER
    fx = IntegrationFixtures()
    with pytest.raises(ig.IntegrationPolicyError, match="authoritative pass requires"):
        _preview(
            fx,
            _one(fx, fx.cpu_receipt()),
            no_replay,
            consume_receipts=True,
            allow_unpoliced_preview=True,
        )


@pytest.mark.parametrize("value", ["false", "0", 1, {"consume": True}])
def test_the_authoritative_mode_needs_a_real_boolean(value):
    fx = IntegrationFixtures()
    with pytest.raises(ig.IntegrationPolicyError, match="must be the boolean"):
        _preview(
            fx, _one(fx, fx.cpu_receipt()), durable_ledger(), consume_receipts=value
        )


# --------------------------------------------------------------------------- #
# A ledger that does not actually record is refused, not trusted
# --------------------------------------------------------------------------- #


def test_a_no_op_ledger_is_refused_instead_of_credited(monkeypatch):
    """Presence is not a gate: the consumption is read back before crediting.

    Deduplication inside one preview hid this. Across two CONSECUTIVE previews the
    seam had nothing left to dedupe against, so a ledger whose `consume` silently
    did nothing let the same receipt earn twice.
    """
    fx = IntegrationFixtures()
    receipt = fx.cpu_receipt()
    ledger = durable_ledger()
    monkeypatch.setattr(ledger, "consume", lambda *_a, **_kw: None)  # fails open

    with pytest.raises(ig.IntegrationLedgerError, match="not recorded"):
        _authoritative(fx, _one(fx, receipt), ledger)


def test_a_no_op_ledger_cannot_credit_the_same_receipt_in_two_previews(monkeypatch):
    fx = IntegrationFixtures()
    receipt = fx.cpu_receipt()
    ledger = durable_ledger()
    monkeypatch.setattr(ledger, "consume", lambda *_a, **_kw: None)

    for _attempt in (1, 2):
        with pytest.raises(ig.IntegrationLedgerError):
            _authoritative(fx, _one(fx, receipt), ledger)
    assert ledger.size() == 0  # nothing was credited on that basis


def test_a_failure_after_the_epoch_claim_stays_locked_for_operator_review(
    monkeypatch,
):
    fx = IntegrationFixtures()
    ledger = durable_ledger()
    receipt = fx.cpu_receipt()
    real_consume = ledger.consume

    def fail_after_claim(token, *, kind="receipt_id", **kw):
        if kind == "integration_authoritative_epoch":
            return real_consume(token, kind=kind, **kw)
        raise RuntimeError("simulated crash before receipt token commit")

    monkeypatch.setattr(ledger, "consume", fail_after_claim)
    with pytest.raises(ig.IntegrationLedgerError, match="simulated crash"):
        _authoritative(fx, _one(fx, receipt), ledger)

    assert ledger.size() == 1  # the durable epoch claim survived
    assert not ledger.is_consumed(receipt["receipt_id"])

    monkeypatch.setattr(ledger, "consume", real_consume)
    with pytest.raises(ig.IntegrationLedgerError, match="epoch already claimed"):
        _authoritative(fx, _one(fx, receipt), ledger)
    assert ledger.size() == 1


def test_a_ledger_that_cannot_be_queried_is_refused_at_the_gate():
    """An object that cannot record and read back is not replay protection."""

    class WriteOnly:
        def consume(self, *_a, **_kw):
            return None

    fx = IntegrationFixtures()
    with pytest.raises(ig.IntegrationLedgerError, match="is_consumed"):
        _preview(fx, _one(fx, fx.cpu_receipt()), WriteOnly())


def test_the_contract_no_replay_marker_counts_as_no_ledger():
    """NO_REPLAY_LEDGER is the contract's "no protection" marker, not a gate.

    Accepting it as an applied ledger would let a funded lane preview with replay
    protection switched off while reporting the ledger gate as satisfied.
    """
    no_replay = pytest.importorskip(
        "cathedral_distill.consumption_ledger"
    ).NO_REPLAY_LEDGER
    fx = IntegrationFixtures()
    with pytest.raises(ig.IntegrationPolicyError, match="consumption_ledger"):
        _preview(fx, _one(fx, fx.cpu_receipt()), no_replay)

    out = _preview(
        fx, _one(fx, fx.cpu_receipt()), no_replay, allow_unpoliced_preview=True
    )
    assert out["gates"]["applied"]["consumption_ledger"] is False
    assert "consumption_ledger" in out["gates"]["omitted_gates"]


def test_the_seam_credits_one_receipt_once_within_a_preview():
    """Deduplication is independent of the ledger, which is the second line."""
    fx = IntegrationFixtures()
    receipt = fx.cpu_receipt()
    out = _preview(
        fx,
        [
            ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, receipt),
            ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, receipt),
        ],
        durable_ledger(),
    )
    # Both submissions verify (it is the same signed receipt), and the once-only
    # rule credits exactly one of them.
    verdicts = out["audit"]["verdicts"]
    assert verdicts["pass"] == 2 and verdicts["fail"] == 0
    assert [r["credited"] for r in out["audit"]["receipts"]].count(True) == 1
    assert (
        len([w for w in out["feed"]["weights"] if w["miner_hotkey"] == "5CpuMiner"])
        == 1
    )


# --------------------------------------------------------------------------- #
# B7(f) concurrent consumption: epoch single-flight and token atomicity
# --------------------------------------------------------------------------- #


def test_exactly_one_racing_authoritative_pass_claims_the_epoch(tmp_path):
    path = str(tmp_path / "authoritative.sqlite")
    ledgers = [ConsumptionLedger(path) for _ in range(8)]
    barrier = threading.Barrier(len(ledgers))
    lock = threading.Lock()
    outcomes: list[str] = []

    def authoritative(index: int) -> None:
        fx = IntegrationFixtures(source_epoch=11)
        barrier.wait()
        try:
            out = _authoritative(fx, _one(fx, fx.cpu_receipt()), ledgers[index])
            outcome = "won" if _verdict(out)["verdict"] == itf.PASS else "wrong-verdict"
        except ig.IntegrationLedgerError as exc:
            outcome = (
                "refused" if "epoch already claimed" in str(exc) else "ledger-error"
            )
        except Exception as exc:
            outcome = f"error:{type(exc).__name__}"
        with lock:
            outcomes.append(outcome)

    threads = [
        threading.Thread(target=authoritative, args=(index,))
        for index in range(len(ledgers))
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    tally = Counter(outcomes)
    assert tally["won"] == 1, tally
    assert tally["refused"] == len(ledgers) - 1, tally
    assert ledgers[0].size() == 2  # one epoch claim + one receipt token
    for ledger in ledgers:
        ledger.close()


def test_exactly_one_racing_consumer_wins_the_same_token(tmp_path):
    path = str(tmp_path / "consumption.sqlite")
    ledgers = [ConsumptionLedger(path), ConsumptionLedger(path)]
    token = "receipt-sha256:" + "ab" * 32
    barrier = threading.Barrier(RACE_CONSUMERS)
    lock = threading.Lock()
    outcomes: list[str] = []

    def consumer(index: int) -> None:
        ledger = ledgers[index % len(ledgers)]
        barrier.wait()
        try:
            ledger.consume(token, kind="receipt_id", source_epoch=11)
            outcome = "won"
        except ReplayError:
            outcome = "refused"
        except Exception as exc:  # sqlite operational errors count as failures
            outcome = f"error:{type(exc).__name__}"
        with lock:
            outcomes.append(outcome)

    threads = [
        threading.Thread(target=consumer, args=(i,)) for i in range(RACE_CONSUMERS)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    tally = Counter(outcomes)
    assert tally["won"] == 1, tally
    assert tally["refused"] == RACE_CONSUMERS - 1, tally
    assert ledgers[0].size() == 1
    for ledger in ledgers:
        ledger.close()
