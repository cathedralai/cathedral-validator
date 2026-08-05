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
    assert body.count("raise wire.VectorError") >= 5
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
