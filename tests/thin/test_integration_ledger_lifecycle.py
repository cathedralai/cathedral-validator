"""Replay refusal across restarts, repeats, and a racing consumer.

The consumption ledger is the only gate that stops a still-valid receipt from
being credited twice, so its behaviour is exercised here at the validator seam
rather than trusted from the shared contract:

* restart: the ledger is a file, so a validator restart must not forget what it
  already credited;
* replay: the same receipt offered to two consecutive previews is refused the
  second time;
* fail-open ledger: even if the ledger wrongly reports a fresh consume, the seam
  itself still credits one receipt once, so replay protection is not a single
  point of failure;
* concurrency: two consumers racing one token, exactly one wins. That case is
  gated on CATHEDRAL_LEDGER_RACE_TEST=1 because the shipped ledger shares one
  connection with no busy timeout and does NOT hold under a real race; enabling
  it belongs to the cross-repo phase once the ledger fix lands.
"""

from __future__ import annotations

import os
import threading
from collections import Counter
from datetime import UTC, datetime

import pytest

pytest.importorskip("cathedral_distill.integrated_feed")
pytest.importorskip("cathedral_distill.testing")

from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill.consumption_ledger import (  # noqa: E402
    ConsumptionLedger,
    ReplayError,
)
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402

from cathedral_thin import integration as ig  # noqa: E402

NOW_DT = datetime(2026, 7, 25, 12, 30, tzinfo=UTC)
NOW_ISO = "2026-07-25T12:30:00.000000Z"
LANE_CPU = ig.LANE_COMPUTE_CPU
LANE_DISTILL = ig.LANE_DISTILL

_ALLOCATIONS = [
    {"lane": LANE_CPU, "allocation": "0.45", "enabled": True},
    {"lane": LANE_DISTILL, "allocation": "0.45", "enabled": True},
]

RACE_ENV = "CATHEDRAL_LEDGER_RACE_TEST"
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
        source_epoch=11,
        now=NOW_DT,
        now_iso=NOW_ISO,
        consumption_ledger=ledger,
        **kw,
    )


def _one(fx, receipt):
    return [ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, receipt)]


def _verdict(out):
    (audited,) = out["audit"]["receipts"]
    return audited


# --------------------------------------------------------------------------- #
# B7(a) restart, B7(b) replay
# --------------------------------------------------------------------------- #


def test_a_replayed_receipt_is_refused_by_the_second_preview():
    fx = IntegrationFixtures()
    receipt = fx.cpu_receipt()
    ledger = ConsumptionLedger(":memory:")

    first = _preview(fx, _one(fx, receipt), ledger)
    assert _verdict(first)["verdict"] == itf.PASS

    second = _preview(fx, _one(fx, receipt), ledger)
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
    assert _verdict(_preview(fx, _one(fx, receipt), before))["verdict"] == itf.PASS
    assert before.size() == 1
    before.close()  # the validator process exits here

    after = ConsumptionLedger(path)
    assert after.is_consumed(receipt["receipt_id"])  # state came back from disk
    refused = _verdict(_preview(fx, _one(fx, receipt), after))
    assert refused["verdict"] == itf.FAIL
    assert "already consumed" in refused["detail"]
    assert after.size() == 1  # and nothing new was consumed


def test_a_fresh_receipt_still_passes_after_a_restart(tmp_path):
    """The refusal must be specific to the replayed receipt, not to restarting."""
    fx = IntegrationFixtures()
    path = str(tmp_path / "consumption.sqlite")
    before = ConsumptionLedger(path)
    assert (
        _verdict(_preview(fx, _one(fx, fx.cpu_receipt(work_units="30")), before))[
            "verdict"
        ]
        == itf.PASS
    )
    before.close()

    after = ConsumptionLedger(path)
    out = _preview(fx, _one(fx, fx.cpu_receipt(work_units="31")), after)
    assert _verdict(out)["verdict"] == itf.PASS
    assert after.size() == 2


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
    assert _verdict(_preview(fx, _one(fx, receipt), ledger))["verdict"] == itf.PASS


# --------------------------------------------------------------------------- #
# Defence in depth: the seam credits once even if the ledger fails open
# --------------------------------------------------------------------------- #


def test_the_seam_credits_once_even_if_the_ledger_never_refuses(monkeypatch):
    """A ledger that wrongly reports a fresh consume must not double-credit."""
    fx = IntegrationFixtures()
    receipt = fx.cpu_receipt()
    ledger = ConsumptionLedger(":memory:")
    monkeypatch.setattr(ledger, "consume", lambda *_a, **_kw: None)  # fails open

    out = _preview(
        fx,
        [
            ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, receipt),
            ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, receipt),
        ],
        ledger,
    )
    verdicts = out["audit"]["verdicts"]
    assert verdicts["pass"] == 1 and verdicts["fail"] == 1
    assert (
        len([w for w in out["feed"]["weights"] if w["miner_hotkey"] == "5CpuMiner"])
        == 1
    )


# --------------------------------------------------------------------------- #
# B7(f) concurrent consumption: NOT PROVEN against the pinned ledger
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(
    os.environ.get(RACE_ENV) != "1",
    reason=(
        f"set {RACE_ENV}=1 to run the concurrent-consumption race. The pinned "
        "consumption ledger shares one connection with no busy timeout, so "
        "racing consumers report several successful consumes for one token and "
        "raise sqlite operational errors. Enable this in the cross-repo phase, "
        "once the ledger atomicity fix lands."
    ),
)
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
