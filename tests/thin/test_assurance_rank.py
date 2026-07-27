"""Full mode submits on the claim it can actually establish.

The old gate demanded the whole epoch be proven. On SN39 that is not strict,
it is unsatisfiable: the 255 registered hotkeys that never submitted work have
no replayable evidence to produce, and independently the manifest caps verified
candidates at 28 while permitting thousands of candidate rows, so the quantifier
and the byte budget range over different sets and cannot both be met.

The rank asks the answerable question instead. Everything that receives weight
must have been independently replayed from raw evidence, and everything not
replayed must carry exactly zero. That is what a weight vector rests on, and it
holds whether one miner participated or none did.
"""

from __future__ import annotations

import pytest

from scaffold import provenance_audit as pa

MINER = "5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK"
OTHER = "5C57oZABvkaLQYMiGMSyX6a4YRfdKjmg9gLtgFt3i7929cd5"


def _rank(**over):
    kwargs = {
        "library_level": "receipts_only",
        "receipt_hotkeys": [MINER],
        "raw_replayed": [MINER],
        "recomputed": {MINER: 1.0},
        "candidate_count": 256,
        "anchored_block": 8_716_000,
        "not_proven_reasons": ["255 anchored candidates are asserted, not replayed"],
    }
    kwargs.update(over)
    return pa._rank_assurance(**kwargs)


# -- the shape of the ladder ------------------------------------------------


def test_ranks_are_ordered_and_unknown_levels_rank_below_everything():
    assert pa.assurance_rank("receipts_only") == 0
    assert pa.assurance_rank("rewarded_set_proven") == 1
    assert pa.assurance_rank("full_over_epoch") == 2
    # The library's legacy spelling of the whole-epoch claim.
    assert pa.assurance_rank("full") == 2
    # An unrecognized claim must never clear a gate by accident.
    assert pa.assurance_rank("totally_proven") == -1
    assert pa.assurance_rank(None) == -1


def test_rank_one_does_not_say_full():
    # Someone will read this in a log. It must not imply the epoch was proven.
    assert "full" not in "rewarded_set_proven"


# -- the live case ----------------------------------------------------------


def test_tonights_epoch_reaches_rewarded_set_proven():
    # One participant, 255 strangers: exactly the state that refused all night.
    level, scope = _rank()
    assert level == "rewarded_set_proven"
    assert scope["unproven_count"] == 255
    assert scope["proven"] == [MINER]
    assert scope["failures"] == []


def test_the_silent_candidates_are_stated_not_hidden():
    _, scope = _rank()
    # The claim has to say out loud what it is silent about, or "proven" reads
    # as a stronger statement than it is.
    assert scope["candidates"] == 256
    assert scope["unproven_count"] == 255
    assert scope["library_reasons"]


# -- what still refuses -----------------------------------------------------


def test_paying_a_hotkey_that_was_never_replayed_is_refused():
    # The property the whole rank exists to protect.
    level, scope = _rank(recomputed={MINER: 0.9, OTHER: 0.1})
    assert level == "receipts_only"
    assert any("not raw-replayed" in f for f in scope["failures"])


def test_a_verified_label_with_no_replay_behind_it_is_refused():
    level, scope = _rank(receipt_hotkeys=[MINER, OTHER])
    assert level == "receipts_only"
    assert any("differ" in f for f in scope["failures"])


def test_a_replay_the_report_never_claimed_is_refused():
    level, scope = _rank(raw_replayed=[MINER, OTHER])
    assert level == "receipts_only"
    assert any("differ" in f for f in scope["failures"])


def test_an_epoch_with_nothing_replayed_stays_at_receipts_only():
    # No miners running is fine and must not crash, but it is also not a
    # proof of anything, so it cannot back a submission.
    level, scope = _rank(receipt_hotkeys=[], raw_replayed=[], recomputed={})
    assert level == "receipts_only"
    assert any("no positive raw replay" in f for f in scope["failures"])


def test_zero_weight_entries_do_not_count_as_rewarded():
    # The producer writes explicit zero rows for non-participants; those must
    # not be read as payments needing a replay.
    level, _ = _rank(recomputed={MINER: 1.0, OTHER: 0.0})
    assert level == "rewarded_set_proven"


def test_a_negative_weight_is_not_treated_as_rewarded_but_is_still_not_paid():
    level, _ = _rank(recomputed={MINER: 1.0, OTHER: -1.0})
    assert level == "rewarded_set_proven"


# -- the whole-epoch level still exists -------------------------------------


def test_the_library_whole_epoch_claim_still_outranks():
    level, _ = _rank(library_level="full", candidate_count=1)
    assert level == "full_over_epoch"
    assert pa.assurance_rank(level) == 2


def test_whole_epoch_is_not_granted_on_our_own_authority():
    # Rank 1 is this validator's claim to make. Rank 2 is the library's.
    level, _ = _rank(candidate_count=1, not_proven_reasons=[])
    assert level == "rewarded_set_proven"


# -- the rollback lever -----------------------------------------------------


def test_minimum_rank_defaults_to_rewarded_set_proven():
    from types import SimpleNamespace

    from scaffold import validator_thin as vt

    assert vt._minimum_assurance_rank(SimpleNamespace()) == 1


def test_pinning_the_minimum_to_whole_epoch_restores_the_old_behaviour():
    from types import SimpleNamespace

    from scaffold import validator_thin as vt

    args = SimpleNamespace(min_assurance="full_over_epoch")
    assert vt._minimum_assurance_rank(args) == 2
    # Which is exactly the level tonight's epoch cannot reach.
    level, _ = _rank()
    assert pa.assurance_rank(level) < 2


def test_an_unknown_minimum_fails_closed():
    from types import SimpleNamespace

    from scaffold import validator_thin as vt

    with pytest.raises(vt.wire.VectorError, match="min_assurance"):
        vt._minimum_assurance_rank(SimpleNamespace(min_assurance="whatever"))
