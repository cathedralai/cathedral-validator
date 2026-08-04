"""A receipt that is not credited keeps its one-time token, for EVERY reason.

The seam used to apply the replay gate itself, before composition, and it
pre-refused four of `compose_integrated`'s five drop rules. The fifth was a lane
the signed config *enables* but funds with zero, which is a valid config: an
allocation is any decimal in 0..1 and `resolve_allocation` keeps every enabled
lane whatever its share. A receipt aimed at such a lane was credited by the seam,
had its token burned, and was then dropped by composition as "allocated zero and
cannot pay". It earned nothing and could never be credited again in any later
epoch: denial of reward with no forgery, which is the exact failure the shared
contract moved consumption into composition to prevent.

Consumption is now deferred to composition (`defer_consumption=True` plus the
ledger handed to `compose_integrated`), so it happens after all five rules and
only for a contribution that is genuinely credited. These tests pin that, the
audit field that reports it, and the per-lane slot accounting that the seam's
own re-implementation got wrong.
"""

from __future__ import annotations

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
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402
from _durable_ledger import durable_ledger  # noqa: E402

from cathedral_thin import integration as ig  # noqa: E402

NOW_DT = datetime(2026, 7, 25, 12, 30, tzinfo=UTC)
NOW_ISO = "2026-07-25T12:30:00.000000Z"

# An enabled lane funded with zero, alongside a funded one. 0.90 + 0.10 burn == 1.
ZERO_FUNDED_CPU = [
    {"lane": ig.LANE_COMPUTE_CPU, "allocation": "0.00", "enabled": True},
    {"lane": ig.LANE_DISTILL, "allocation": "0.90", "enabled": True},
]
BOTH_FUNDED = [
    {"lane": ig.LANE_COMPUTE_CPU, "allocation": "0.45", "enabled": True},
    {"lane": ig.LANE_DISTILL, "allocation": "0.45", "enabled": True},
]


def _preview(fx, receipts, ledger, allocations=BOTH_FUNDED, version=1, **kw):
    return ig.preview_integrated_vector(
        burn_config=fx.burn_config(),
        allocation_config=fx.allocation_config(allocations, version=version),
        key_registry=fx.registry,
        receipts=receipts,
        network="finney",
        netuid=39,
        source_epoch=fx.source_epoch,
        now=NOW_DT,
        now_iso=NOW_ISO,
        consumption_ledger=ledger,
        allowed_measurements=frozenset({fx.tdx_measurement}),
        allowed_tcb_statuses=frozenset({"UpToDate"}),
        allowed_advisories=frozenset(),
        current_block=6_000_100,
        **kw,
    )


# --------------------------------------------------------------------------- #
# The zero-allocation lane: the fifth drop rule
# --------------------------------------------------------------------------- #


def test_a_zero_allocation_lane_cannot_pay_and_does_not_burn_the_token():
    fx = IntegrationFixtures()
    receipt = fx.cpu_receipt(subject="5CpuMiner", work_units="30")
    ledger = durable_ledger()

    out = _preview(
        fx,
        [ig.LaneReceipt(itf.KIND_COMPUTE_CPU, ig.LANE_COMPUTE_CPU, receipt)],
        ledger,
        allocations=ZERO_FUNDED_CPU,
        consume_receipts=True,
    )
    (row,) = out["audit"]["receipts"]

    assert row["verdict"] == itf.PASS  # it verified; the lane simply cannot pay
    assert row["credited"] is False
    assert "allocated zero" in row["drop_reason"]
    # The one-time token survives, so the receipt is still worth something.
    assert ledger.is_consumed(row["receipt_id"]) is False
    assert row["replay_token_consumed"] is False
    # Only the epoch claim was written.
    assert ledger.size() == 1


def test_a_receipt_kept_by_a_zero_lane_still_earns_once_the_lane_is_funded():
    """The whole point of not burning the token: the receipt is still spendable."""
    fx = IntegrationFixtures()
    receipt = fx.cpu_receipt(subject="5CpuMiner", work_units="30")
    ledger = durable_ledger()

    _preview(
        fx,
        [ig.LaneReceipt(itf.KIND_COMPUTE_CPU, ig.LANE_COMPUTE_CPU, receipt)],
        ledger,
        allocations=ZERO_FUNDED_CPU,
        consume_receipts=True,
    )

    # A later epoch, the lane properly funded. Same receipt, and it earns.
    out = _preview(
        fx,
        [ig.LaneReceipt(itf.KIND_COMPUTE_CPU, ig.LANE_COMPUTE_CPU, receipt)],
        ledger,
        allocations=BOTH_FUNDED,
        version=2,
    )
    (row,) = out["audit"]["receipts"]
    assert row["verdict"] == itf.PASS
    assert row["credited"] is True
    assert row["final_weight"] > 0


# --------------------------------------------------------------------------- #
# The audit's record of what the pass actually spent
# --------------------------------------------------------------------------- #


def test_the_audit_reports_the_consumption_that_happened():
    """`replay_token_consumed` is the operator's record that a token was burned.

    While the seam consumed the tokens itself, every decision reached composition
    marked REPLAY_NONE, so composition derived this field as False for every row
    of an authoritative pass that had in fact consumed all of them. The audit is
    the activation evidence; it denied every consumption it made.
    """
    fx = IntegrationFixtures()
    ledger = durable_ledger()
    out = _preview(
        fx,
        [ig.LaneReceipt(itf.KIND_COMPUTE_CPU, ig.LANE_COMPUTE_CPU, fx.cpu_receipt())],
        ledger,
        consume_receipts=True,
    )
    (row,) = out["audit"]["receipts"]
    assert row["credited"] is True
    assert row["replay_token_consumed"] is True
    assert ledger.is_consumed(row["receipt_id"]) is True


def test_an_inspection_pass_reports_no_consumption_and_makes_none():
    fx = IntegrationFixtures()
    ledger = durable_ledger()
    out = _preview(
        fx,
        [ig.LaneReceipt(itf.KIND_COMPUTE_CPU, ig.LANE_COMPUTE_CPU, fx.cpu_receipt())],
        ledger,
    )
    (row,) = out["audit"]["receipts"]
    assert row["credited"] is True
    assert row["replay_token_consumed"] is False
    assert ledger.is_consumed(row["receipt_id"]) is False
    assert ledger.size() == 0


# --------------------------------------------------------------------------- #
# Per-lane slot accounting: a cross-lane replay must not cost the miner a
# different, entirely valid receipt
# --------------------------------------------------------------------------- #


def test_a_cross_lane_replay_does_not_suppress_the_miners_other_receipt():
    """Composition claims a lane's per-miner slot only when it credits.

    Re-deriving the rule here from a precomputed winner map got this wrong: one
    receipt tagged into two lanes took the second lane's per-miner slot, was then
    refused there as already credited elsewhere, and the miner's own second valid
    receipt in that lane was refused naming a receipt that lane never credited.
    Whether it bit depended on how two sha256 receipt ids happened to sort.
    """
    fx = IntegrationFixtures()
    miner = "5CpuMiner"
    # `a` sorts below `b`, which is the ordering the defect needed.
    a, b = sorted(
        (
            fx.cpu_receipt(subject=miner, work_units="20"),
            fx.cpu_receipt(subject=miner, work_units="22"),
        ),
        key=lambda receipt: receipt["receipt_id"],
    )

    out = _preview(
        fx,
        [
            ig.LaneReceipt(itf.KIND_COMPUTE_CPU, ig.LANE_COMPUTE_CPU, a),
            ig.LaneReceipt(itf.KIND_COMPUTE_CPU, ig.LANE_DISTILL, a),
            ig.LaneReceipt(itf.KIND_COMPUTE_CPU, ig.LANE_DISTILL, b),
        ],
        durable_ledger(),
    )
    rows = out["audit"]["receipts"]
    assert [r["lane"] for r in rows] == [  # still submission order
        ig.LANE_COMPUTE_CPU,
        ig.LANE_DISTILL,
        ig.LANE_DISTILL,
    ]
    # `a` earns in the lower lane id; its second copy is dropped WITHOUT taking the
    # distill lane's slot, so `b` takes it.
    assert [r["credited"] for r in rows] == [True, False, True]
    assert "receipt_id already credited" in rows[1]["drop_reason"]
    # Both lanes contribute, so only the base burn applies.
    assert out["feed"]["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(10.0)


def test_the_outcome_does_not_depend_on_submission_order():
    fx = IntegrationFixtures()
    miner = "5CpuMiner"
    a = fx.cpu_receipt(subject=miner, work_units="20")
    b = fx.cpu_receipt(subject=miner, work_units="22")
    submissions = [
        ig.LaneReceipt(itf.KIND_COMPUTE_CPU, ig.LANE_COMPUTE_CPU, a),
        ig.LaneReceipt(itf.KIND_COMPUTE_CPU, ig.LANE_DISTILL, a),
        ig.LaneReceipt(itf.KIND_COMPUTE_CPU, ig.LANE_DISTILL, b),
    ]

    def credited(order):
        out = _preview(fx, order, durable_ledger())
        return (
            out["feed"]["burn_snapshot"]["forced_burn_percentage"],
            sorted(
                (r["lane"], r["receipt_id"])
                for r in out["audit"]["receipts"]
                if r["credited"]
            ),
        )

    forward = credited(submissions)
    assert forward == credited(list(reversed(submissions)))
    assert forward == credited([submissions[1], submissions[2], submissions[0]])


# --------------------------------------------------------------------------- #
# The ledger's effects are checked back against the audit
# --------------------------------------------------------------------------- #


def test_a_composer_consume_failure_is_a_preview_level_failure(monkeypatch):
    """Composition reports a failed consume as one dropped contribution.

    Right for one receipt, catastrophic for an outage: every contribution drops
    the same way and the pass still returns a burn vector. The seam re-composes
    with no ledger to learn what the five admission rules alone would credit, so a
    receipt that falls out of the real pass is known to have lost its credit to the
    ledger rather than to a rule.
    """
    fx = IntegrationFixtures()
    ledger = durable_ledger()
    real_consume = ledger.consume

    def only_the_epoch_claim(token, *, kind="receipt_id", **kw):
        if kind == "integration_authoritative_epoch":
            return real_consume(token, kind=kind, **kw)
        raise RuntimeError("receipt token storage is unavailable")

    monkeypatch.setattr(ledger, "consume", only_the_epoch_claim)
    with pytest.raises(ig.IntegrationLedgerError, match="would have credited"):
        _preview(
            fx,
            [
                ig.LaneReceipt(
                    itf.KIND_COMPUTE_CPU, ig.LANE_COMPUTE_CPU, fx.cpu_receipt()
                )
            ],
            ledger,
            consume_receipts=True,
        )


def test_a_ledger_that_forgets_a_consume_it_reported_is_refused(monkeypatch):
    """Fail-open: a consume that is not kept leaves the receipt creditable again."""
    fx = IntegrationFixtures()
    ledger = durable_ledger()
    real_consume = ledger.consume

    def swallow_receipt_tokens(token, *, kind="receipt_id", **kw):
        if kind == "integration_authoritative_epoch":
            return real_consume(token, kind=kind, **kw)
        return None  # claims success, records nothing

    monkeypatch.setattr(ledger, "consume", swallow_receipt_tokens)
    with pytest.raises(ig.IntegrationLedgerError, match="not on record"):
        _preview(
            fx,
            [
                ig.LaneReceipt(
                    itf.KIND_COMPUTE_CPU, ig.LANE_COMPUTE_CPU, fx.cpu_receipt()
                )
            ],
            ledger,
            consume_receipts=True,
        )


def test_the_contract_pin_must_offer_the_deferred_path(monkeypatch):
    """The fix depends on the composer accepting the ledger; assert the pin does.

    A pin whose `compose_integrated` cannot take `consumption_ledger` cannot defer
    consumption at all, so the seam would silently fall back to being unable to
    record anything. Refuse before any receipt is classified.
    """

    def composer_without_the_ledger(resolved, decisions):  # pragma: no cover
        raise AssertionError("must not be reached")

    monkeypatch.setattr(itf, "compose_integrated", composer_without_the_ledger)
    fx = IntegrationFixtures()
    with pytest.raises(
        ig.IntegrationUnavailable, match="compose_integrated is missing"
    ):
        _preview(
            fx,
            [
                ig.LaneReceipt(
                    itf.KIND_COMPUTE_CPU, ig.LANE_COMPUTE_CPU, fx.cpu_receipt()
                )
            ],
            durable_ledger(),
        )
