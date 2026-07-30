"""One bad contribution must never abort the whole preview.

The shared contract returns FAIL for its three typed receipt errors, but several
real failures are raised, not returned: an unknown receipt kind, a lane the signed
allocation does not fund, a miner holding two credited receipts in one lane (which
is legitimate, not adversarial), an exception from an injected verifier or from the
ledger. Every one of those escaped this seam unwrapped and destroyed the complete
vector, including every honest lane in it.

Also proven here: the burn destination is not a reward subject, and one receipt
earns at most once even with no ledger configured.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest

pytest.importorskip("cathedral_distill.integrated_feed")
pytest.importorskip("cathedral_distill.testing")

from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402
from _durable_ledger import durable_ledger  # noqa: E402

from cathedral_thin import integration as ig  # noqa: E402
from scaffold.events import EventLogger  # noqa: E402

NOW_DT = datetime(2026, 7, 25, 12, 30, tzinfo=UTC)
NOW_ISO = "2026-07-25T12:30:00.000000Z"

LANE_CPU = "cathedral_confidential_tdx"
LANE_DISTILL = "cathedral_distill"
BURN_HOTKEY = "5Burn"  # the fixtures' burn destination

_ALLOCATIONS = [
    {"lane": LANE_CPU, "allocation": "0.45", "enabled": True},
    {"lane": LANE_DISTILL, "allocation": "0.45", "enabled": True},
]


def _logger():
    buf = io.StringIO()
    return EventLogger(mode="shadow", jsonl=buf, tty=io.StringIO()), buf


def _events(buf):
    return [json.loads(line) for line in buf.getvalue().splitlines()]


def _preview(fx, receipts, **kw):
    kw.setdefault("allow_unpoliced_preview", True)
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
        **kw,
    )


def _by_receipt(out):
    return {(r["kind"], r["receipt_id"]): r for r in out["audit"]["receipts"]}


def _good_cpu(fx):
    return ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, fx.cpu_receipt())


# --------------------------------------------------------------------------- #
# Containment: the complete vector survives a bad contribution
# --------------------------------------------------------------------------- #


def test_an_unknown_kind_fails_only_itself():
    fx = IntegrationFixtures()
    out = _preview(
        fx,
        [
            _good_cpu(fx),
            ig.LaneReceipt("sat_solve", LANE_DISTILL, fx.distill_receipt()),
        ],
    )
    assert {w["miner_hotkey"] for w in out["feed"]["weights"]} == {"5CpuMiner"}
    assert out["audit"]["verdicts"]["fail"] == 1
    bad = next(r for r in out["audit"]["receipts"] if r["kind"] == "sat_solve")
    assert bad["verdict"] == itf.FAIL and "lane boundary" in bad["detail"]


def test_a_receipt_naming_an_unfunded_lane_fails_only_itself():
    fx = IntegrationFixtures()
    out = _preview(
        fx,
        [
            _good_cpu(fx),
            ig.LaneReceipt(
                itf.KIND_DISTILL, "lane_nobody_funded", fx.distill_receipt()
            ),
        ],
    )
    assert {w["miner_hotkey"] for w in out["feed"]["weights"]} == {"5CpuMiner"}
    bad = next(r for r in out["audit"]["receipts"] if r["lane"] == "lane_nobody_funded")
    assert bad["verdict"] == itf.FAIL and "not a funded lane" in bad["detail"]


def test_a_malformed_receipt_burns_only_its_own_lane_share():
    fx = IntegrationFixtures()
    out = _preview(
        fx,
        [_good_cpu(fx), ig.LaneReceipt(itf.KIND_DISTILL, LANE_DISTILL, {"junk": True})],
    )
    assert {w["miner_hotkey"] for w in out["feed"]["weights"]} == {"5CpuMiner"}
    # 0.10 base burn + the distill lane's forfeited 0.45
    assert out["feed"]["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(55.0)
    lanes = {ln["lane"]: ln for ln in out["audit"]["lanes"]}
    assert lanes[LANE_CPU]["contributing"] is True
    assert lanes[LANE_DISTILL]["contributing"] is False


def test_a_verifier_that_raises_fails_only_that_receipt():
    """An injected verifier is operator code; it must not be able to abort the run."""

    def explode(_evidence):
        raise RuntimeError("verifier blew up")

    fx = IntegrationFixtures()
    out = _preview(
        fx,
        [
            _good_cpu(fx),
            ig.LaneReceipt(itf.KIND_DISTILL, LANE_DISTILL, fx.distill_receipt()),
        ],
        cpu_quote_verifier=explode,
    )
    assert {w["miner_hotkey"] for w in out["feed"]["weights"]} == {"5DistillMiner"}
    cpu = next(r for r in out["audit"]["receipts"] if r["kind"] == "compute_cpu")
    assert cpu["verdict"] == itf.FAIL


def test_a_ledger_that_raises_an_unexpected_error_fails_only_that_receipt(monkeypatch):
    fx = IntegrationFixtures()
    ledger = durable_ledger()

    def explode(*_args, **_kw):
        raise RuntimeError("ledger storage is unavailable")

    monkeypatch.setattr(ledger, "consume", explode)
    out = _preview(
        fx,
        [
            _good_cpu(fx),
            ig.LaneReceipt(itf.KIND_DISTILL, LANE_DISTILL, fx.distill_receipt()),
        ],
        consumption_ledger=ledger,
    )
    # no receipt is credited, no lane steals another lane's share, nothing aborts
    assert out["feed"]["weights"] == []
    assert out["audit"]["verdicts"]["fail"] == 2
    assert out["feed"]["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(
        100.0
    )


# --------------------------------------------------------------------------- #
# One miner, two valid receipts in one lane: legitimate, and it used to abort
# --------------------------------------------------------------------------- #


def test_two_valid_receipts_from_one_miner_credit_exactly_one():
    fx = IntegrationFixtures()
    first = fx.cpu_receipt(work_units="30")
    second = fx.cpu_receipt(work_units="31")
    assert first["receipt_id"] != second["receipt_id"]
    events, buf = _logger()
    out = _preview(
        fx,
        [
            ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, first),
            ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, second),
            ig.LaneReceipt(itf.KIND_DISTILL, LANE_DISTILL, fx.distill_receipt()),
        ],
        events=events,
    )
    verdicts = out["audit"]["verdicts"]
    assert verdicts["pass"] == 2 and verdicts["fail"] == 1  # cpu once + distill
    assert {w["miner_hotkey"] for w in out["feed"]["weights"]} == {
        "5CpuMiner",
        "5DistillMiner",
    }
    refused = next(r for r in out["audit"]["receipts"] if r["verdict"] == itf.FAIL)
    assert "already has a credited receipt" in refused["detail"]
    receipt_events = [e for e in _events(buf) if e["event"] == "INTEGRATION_RECEIPT"]
    assert len(receipt_events) == 3  # every submission is still audited


def test_which_duplicate_wins_is_independent_of_submission_order():
    fx = IntegrationFixtures()
    first = fx.cpu_receipt(work_units="30")
    second = fx.cpu_receipt(work_units="31")

    def credited(order):
        out = _preview(
            fx, [ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, r) for r in order]
        )
        return {
            r["receipt_id"]
            for r in out["audit"]["receipts"]
            if r["verdict"] == itf.PASS
        }

    assert credited([first, second]) == credited([second, first])


def test_one_receipt_replayed_into_two_lanes_earns_once_without_a_ledger():
    fx = IntegrationFixtures()
    receipt = fx.distill_receipt()
    out = _preview(
        fx,
        [
            ig.LaneReceipt(itf.KIND_DISTILL, LANE_DISTILL, receipt),
            ig.LaneReceipt(itf.KIND_DISTILL, LANE_CPU, receipt),
        ],
    )
    assert out["audit"]["verdicts"] == {"pass": 1, "fail": 1, "not_proven": 0}
    weights = [
        w for w in out["feed"]["weights"] if w["miner_hotkey"] == "5DistillMiner"
    ]
    assert len(weights) == 1
    refused = next(r for r in out["audit"]["receipts"] if r["verdict"] == itf.FAIL)
    assert "credited once only" in refused["detail"]


# --------------------------------------------------------------------------- #
# The burn destination is never a reward subject
# --------------------------------------------------------------------------- #


def test_the_burn_hotkey_cannot_earn_weight():
    fx = IntegrationFixtures()
    events, buf = _logger()
    out = _preview(
        fx,
        [
            _good_cpu(fx),
            ig.LaneReceipt(
                itf.KIND_COMPUTE_CPU, LANE_DISTILL, fx.cpu_receipt(subject=BURN_HOTKEY)
            ),
        ],
        events=events,
    )
    subjects = {w["miner_hotkey"] for w in out["feed"]["weights"]}
    assert subjects == {"5CpuMiner"}
    assert BURN_HOTKEY not in subjects
    burn = next(r for r in out["audit"]["receipts"] if r["lane"] == LANE_DISTILL)
    assert burn["verdict"] == itf.FAIL
    assert "burn hotkey" in burn["detail"]
    event = next(
        e
        for e in _events(buf)
        if e["event"] == "INTEGRATION_RECEIPT" and e["lane"] == LANE_DISTILL
    )
    assert event["status"] == itf.FAIL


def test_a_burn_subject_receipt_never_reaches_the_ledger():
    """It is refused before consumption, so it cannot burn its own token."""
    fx = IntegrationFixtures()
    ledger = durable_ledger()
    receipt = fx.cpu_receipt(subject=BURN_HOTKEY)
    out = _preview(
        fx,
        [ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, receipt)],
        consumption_ledger=ledger,
    )
    assert out["feed"]["weights"] == []
    assert ledger.size() == 0
    assert not ledger.is_consumed(receipt["receipt_id"])
