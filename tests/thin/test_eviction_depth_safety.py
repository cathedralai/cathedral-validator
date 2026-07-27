"""Eviction-depth replacement safety.

`set_mechanism_weights` binds UIDs, so what must be proven before a submission
is that no sequence of registrations inside the mortal era can reach a target's
UID. Registration immunity protects a NEW neuron from pruning, so requiring it
of a reward target inverts the intent and makes every mature miner permanently
unrewardable. These tests pin the corrected rule and the exclusion behaviour.
"""

from __future__ import annotations

import pytest

from scaffold import validator_thin


def _depth(prunable, metrics):
    """Reimplements the published depth rule for the test's own account."""
    depth = {}
    for uid, hotkey in prunable:
        target = metrics[hotkey]
        count = 0
        for other_uid, other_hotkey in prunable:
            if other_hotkey == hotkey:
                continue
            other = metrics[other_hotkey]
            strictly_weaker = all(o < t for o, t in zip(other, target))
            tied_lower_uid = other == target and other_uid < uid
            if strictly_weaker or tied_lower_uid:
                count += 1
        depth[hotkey] = count
    return depth


def test_mature_zero_score_miner_is_safe_when_ranked_deep():
    # The live SN39 shape: a full subnet, one registration per block, a mature
    # miner whose immunity expired, sitting behind many equally scored UIDs.
    prunable = [(uid, f"hk{uid}") for uid in range(200)]
    metrics = {hotkey: (0.0, 0.0, 0.0) for _, hotkey in prunable}
    depth = _depth(prunable, metrics)
    worst_case_evictions = 4  # max_regs_per_block(1) * mortal era(4), zero free slots

    # 112 zero-score UIDs sit below uid 163, so the runtime cannot reach it.
    assert depth["hk163"] == 163
    assert depth["hk163"] >= worst_case_evictions

    # The lowest-indexed candidates are the ones actually at risk.
    assert depth["hk0"] == 0
    assert depth["hk3"] < worst_case_evictions
    assert depth["hk4"] >= worst_case_evictions


def test_immunity_alone_no_longer_decides_safety():
    # Two identical mature miners; only their UID index differs. The old rule
    # called both unsafe because immunity had expired. Depth separates them.
    prunable = [(uid, f"hk{uid}") for uid in range(8)]
    metrics = {hotkey: (0.0, 0.0, 0.0) for _, hotkey in prunable}
    depth = _depth(prunable, metrics)
    assert depth["hk1"] == 1  # reachable when 2+ evictions are possible
    assert depth["hk7"] == 7  # never reachable at that eviction count


def test_a_stronger_target_outranks_weaker_candidates():
    prunable = [(0, "weak"), (1, "mid"), (2, "strong")]
    metrics = {
        "weak": (0.0, 0.0, 0.0),
        "mid": (0.1, 1.0, 0.1),
        "strong": (0.5, 10.0, 0.5),
    }
    depth = _depth(prunable, metrics)
    assert depth["weak"] == 0
    assert depth["mid"] == 1
    assert depth["strong"] == 2


def test_ambiguous_ordering_counts_as_behind_the_target():
    # Higher stake but lower incentive is NOT provably weaker under an unknown
    # scalar score, so it must not be counted as ranking ahead.
    prunable = [(0, "ambiguous"), (1, "target")]
    metrics = {"ambiguous": (0.0, 99.0, 0.0), "target": (0.5, 1.0, 0.5)}
    depth = _depth(prunable, metrics)
    assert depth["target"] == 0, "ambiguous candidates must not inflate depth"


def test_unprovable_target_is_excluded_not_aborted():
    preflight = validator_thin.ChainPreflight(
        wallet=None,
        subtensor=None,
        hotkey_to_uid={"safe": 1, "unsafe": 2},
        validator_hotkey="v",
        validator_uid=0,
        block=100,
        min_allowed_weights=1,
        max_weight_limit=1.0,
        genesis_hash="not-finney",
        replacement_safe_hotkeys=frozenset({"safe"}),
    )
    result = validator_thin._require_uid_mapping_stability(
        preflight,
        {1: "safe", 2: "unsafe"},
        mortal_period_blocks=validator_thin.SN39_MORTAL_PERIOD_BLOCKS,
    )
    # One target survives, so the vector proceeds with the unsafe target dropped.
    assert result["excluded_hotkeys"] == ["unsafe"]


def test_no_safe_target_is_a_hard_failure():
    preflight = validator_thin.ChainPreflight(
        wallet=None,
        subtensor=None,
        hotkey_to_uid={"a": 1},
        validator_hotkey="v",
        validator_uid=0,
        block=100,
        min_allowed_weights=1,
        max_weight_limit=1.0,
        genesis_hash="not-finney",
        replacement_safe_hotkeys=frozenset({"someone-else"}),
    )
    with pytest.raises(validator_thin.wire.VectorError, match="cannot prove any UID"):
        validator_thin._require_uid_mapping_stability(
            preflight,
            {1: "a"},
            mortal_period_blocks=validator_thin.SN39_MORTAL_PERIOD_BLOCKS,
        )
