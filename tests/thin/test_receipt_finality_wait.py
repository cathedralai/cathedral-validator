"""Finality lag is a wait, not a fault.

A proof attempted immediately after a successful submission routinely loses the
finality race: the receipt's block exists and is canonical, but the finalized
head has not reached it yet. The response used to be to exit non-zero so
systemd could restart the process, which then proved the identical receipt
seconds later — a restart and a lost tick on every write.

These tests hold the narrow contract: ONLY that one reason is waited on, every
other verdict returns immediately, and an unfinalized receipt at the end of the
bound is still NOT_PROVEN and still fenced.
"""

from __future__ import annotations

from scaffold import validator_thin as vt


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, secs: float) -> None:
        self.slept.append(secs)
        self.now += secs


def _classify(statuses, reasons, clock, **over):
    """Drive the waiter over a scripted sequence of underlying verdicts."""
    calls = {"n": 0}

    def fake(_subtensor, **kwargs):
        i = min(calls["n"], len(statuses) - 1)
        calls["n"] += 1
        out = kwargs.get("reason_out")
        if isinstance(out, list) and reasons[i] is not None:
            out.append(reasons[i])
        return statuses[i]

    original = vt._classify_finalized_receipt
    vt._classify_finalized_receipt = fake
    try:
        kwargs = dict(
            wait_secs=48.0,
            poll_secs=4.0,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            reason_out=[],
        )
        kwargs.update(over)
        status = vt._classify_finalized_receipt_awaiting_finality(object(), **kwargs)
    finally:
        vt._classify_finalized_receipt = original
    return status, calls["n"]


def test_it_waits_for_finality_and_then_passes():
    clock = _Clock()
    status, calls = _classify(
        [vt.NOT_PROVEN, vt.NOT_PROVEN, vt.PASS],
        [vt.RECEIPT_FINALITY_LAG_REASON, vt.RECEIPT_FINALITY_LAG_REASON, None],
        clock,
    )
    assert status == vt.PASS
    assert calls == 3
    assert clock.slept == [4.0, 4.0]


def test_a_fail_verdict_is_never_waited_on():
    """A positive mismatch is a fault; waiting on it would delay a real alarm."""
    clock = _Clock()
    status, calls = _classify(
        [vt.FAIL], ["the receipt block hash is not canonical"], clock
    )
    assert status == vt.FAIL
    assert calls == 1
    assert clock.slept == []


def test_any_other_not_proven_reason_returns_immediately():
    clock = _Clock()
    status, calls = _classify(
        [vt.NOT_PROVEN], ["the extrinsic is absent from its block"], clock
    )
    assert status == vt.NOT_PROVEN
    assert calls == 1
    assert clock.slept == [], "only the finality-lag reason may be waited on"


def test_finality_that_never_arrives_is_still_not_proven():
    """The bound expires and the verdict is unchanged — still fenced."""
    clock = _Clock()
    status, _ = _classify(
        [vt.NOT_PROVEN] * 50, [vt.RECEIPT_FINALITY_LAG_REASON] * 50, clock
    )
    assert status == vt.NOT_PROVEN
    assert sum(clock.slept) <= 48.0, "the wait must respect its bound"


def test_the_wait_is_bounded_well_under_the_tick_interval():
    """A wait longer than the tick would trade one problem for another."""
    assert vt.RECEIPT_FINALITY_WAIT_SECS <= 60.0
    assert vt.RECEIPT_FINALITY_POLL_SECS > 0
