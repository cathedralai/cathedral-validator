"""Each way the epoch-room gate can refuse names itself.

Six distinct conditions shared one sentence, and they call for opposite
operator responses: "the tick landed near an epoch boundary" clears itself on
the next tick and needs nobody, while "the signed vector expects a different
epoch than the chain reports" is a producer disagreement that never resolves on
its own. These tests hold each message to naming its own cause.
"""

from __future__ import annotations

import re

from scaffold import validator_thin as vt

SOURCE = vt.__file__


def _gate_source() -> str:
    import inspect

    src = inspect.getsource(vt)
    start = src.index("required_epoch_room = (")
    return src[start : start + 3000]


def test_the_boundary_wait_names_the_block_it_clears_at():
    body = _gate_source()
    assert "block(s) remain in this epoch" in body
    assert "clears itself" in body
    assert "mortal +" in body


def test_a_policy_epoch_disagreement_is_its_own_message():
    body = _gate_source()
    assert "signed inclusion policy expects next epoch start" in body
    assert "composed against a different epoch" in body


def test_inconsistent_chain_arithmetic_is_its_own_message():
    body = _gate_source()
    assert "chain epoch arithmetic is inconsistent" in body


def test_the_six_conditions_are_no_longer_one_raise():
    """The collapsed form raised once for every cause; the split form does not."""
    body = _gate_source()
    # One of the five is now raised as `_EpochRoomUnavailable` — the only
    # cause that clears itself — so the count spans both raise forms.
    raises = body.count("raise wire.VectorError") + body.count(
        "raise _EpochRoomUnavailable"
    )
    assert raises >= 5
    assert "cannot prove the exact next epoch with enough room" not in body, (
        "the collapsed catch-all message is gone"
    )


def test_the_required_room_is_still_mortal_plus_finality_margin():
    """The gate's arithmetic is unchanged — only its reporting."""
    assert vt.SN39_EPOCH_FINALITY_MARGIN_BLOCKS == 32
    assert vt.SN39_MORTAL_PERIOD_BLOCKS == 16
    body = _gate_source()
    assert "policy.mortal_period_blocks + SN39_EPOCH_FINALITY_MARGIN_BLOCKS" in re.sub(
        r"\s+", " ", body
    )


def test_the_boundary_wait_is_its_own_exception_type():
    """Only the self-clearing cause is downgradable.

    The other five refusals this gate raises need a human and must keep
    arriving as the plain refusal the loop reports at `TICK_FAILED`/`FAIL`.
    """
    body = _gate_source()
    assert "raise _EpochRoomUnavailable(" in body
    assert body.count("raise _EpochRoomUnavailable(") == 1
    assert issubclass(vt._EpochRoomUnavailable, vt.wire.VectorError)


def test_a_reserved_attempt_keeps_the_boundary_refusal_a_failure():
    """After the fence is held, the same sentence is not a routine skip.

    The chain-call boundary re-checks this gate with a durable attempt already
    reserved for that exact call. Downgrading there would report journal state
    an operator has to resolve as a wait that clears itself.
    """
    import inspect

    src = inspect.getsource(vt)
    start = src.index("_require_inclusion_policy_ready(inclusion_policy, preflight)")
    body = src[start - 200 : start + 800]
    assert "except _EpochRoomUnavailable as exc:" in body
    assert "raise wire.VectorError(str(exc)) from exc" in body


def test_the_plain_english_reading_survived_the_rewording():
    """`render._PLAIN` matched the collapsed sentence, which no longer exists."""
    from scaffold import render

    live = (
        "tick failed: VectorError: only 32 block(s) remain in this epoch; a "
        "submission needs 48 (16 mortal + 32 finality margin) to prove mortal "
        "inclusion and finalized verification. This clears itself at block 8680428"
    )
    plain, original = render.humanize(live)
    assert plain == "too close to the epoch boundary to land safely"
    assert original == live

    # The siblings are not boundary timing and must not borrow a reading that
    # promises they clear themselves.
    for other in (
        "VectorError: submission cannot prove the blocks remaining in this epoch",
        "VectorError: the signed inclusion policy expects next epoch start 5, but "
        "the chain reports 9; the vector was composed against a different epoch",
        "VectorError: chain epoch arithmetic is inconsistent: next epoch start 5",
    ):
        assert render.humanize(other) == (other, "")


def test_the_blocking_refusals_read_in_plain_english_too():
    from scaffold import render

    plain, _ = render.humanize(
        "VectorError: continuous broadcast is locked until `cathedral-validator "
        "reconcile-launch` independently verifies the finalized launch"
    )
    assert "reconcile-launch" in plain
    plain, _ = render.humanize(
        "VectorError: thin submission attempt fence refused before chain write: X"
    )
    assert "nothing was sent" in plain
