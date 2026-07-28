"""Eviction-depth replacement safety, against the real runtime prune order.

`set_mechanism_weights` binds UIDs, so what must be proven before a submission
is that no sequence of registrations inside the mortal era can reach a target's
UID. The deployed runtime selects its prune victim as the minimum of
(emission, block_at_registration, uid) lexicographically, so on an exact metric
tie the OLDEST registration is pruned first, then the lower UID. An earlier
version of this rule (and of this test, which reimplemented it privately
instead of calling the code) tie-broke on UID alone, overcounting depth for
exactly the mature targets the proof exists to protect.

These tests call the production functions.
"""

from __future__ import annotations

import pytest

from scaffold import validator_thin
from scaffold.validator_thin import (
    SN39_MORTAL_PERIOD_BLOCKS,
    _drop_unprovable_targets,
    _eviction_depths,
)

ZERO = (0.0, 0.0, 0.0)


def _rows(entries):
    """(uid, registered_at) pairs -> prunable_rows plus all-zero metrics."""
    rows = [(uid, f"hk{uid}", registered_at) for uid, registered_at in entries]
    return rows, {hotkey: ZERO for _, hotkey, _ in rows}


# -- the tie rule is the runtime's, not a UID sort ---------------------------


def test_on_a_tie_the_oldest_registration_is_pruned_first():
    # Lower UID but LATER registration: the runtime reaches the older target
    # first, so the younger low-UID neuron is NOT a body in front of it.
    rows, metrics = _rows([(10, 5_000), (163, 1_000)])
    depths = _eviction_depths(rows, metrics)
    assert depths["hk163"] == 0, "an older registration has nobody ahead of it"
    assert depths["hk10"] == 1


def test_equal_registration_falls_back_to_lower_uid():
    # Same registration block: the runtime's final key is the UID, so the
    # LOWER uid is pruned first and stands in front of the higher one.
    rows, metrics = _rows([(10, 1_000), (163, 1_000)])
    depths = _eviction_depths(rows, metrics)
    assert depths["hk10"] == 0
    assert depths["hk163"] == 1


def test_strict_metric_dominance_still_outranks_age():
    # Strictly weaker on all metrics implies strictly lower emission, the
    # runtime's primary key, so age never rescues a dominated neuron.
    rows = [(1, "weak", 100), (2, "strong", 9_000)]
    metrics = {"weak": ZERO, "strong": (0.5, 10.0, 0.5)}
    depths = _eviction_depths(rows, metrics)
    assert depths["strong"] == 1
    assert depths["weak"] == 0


def test_ambiguous_ordering_counts_as_behind_the_target():
    # Higher stake but lower incentive is not provably weaker; it must not
    # inflate the target's depth.
    rows = [(0, "ambiguous", 100), (1, "target", 200)]
    metrics = {"ambiguous": (0.0, 99.0, 0.0), "target": (0.5, 1.0, 0.5)}
    depths = _eviction_depths(rows, metrics)
    assert depths["target"] == 0


def test_a_mature_miner_behind_older_zero_score_peers_is_deep():
    # The live SN39 shape: a full subnet of zero-score neurons. The miner is
    # deep only by virtue of peers REGISTERED BEFORE it, not by UID index.
    rows, metrics = _rows([(uid, 1_000 + uid) for uid in range(200)])
    depths = _eviction_depths(rows, metrics)
    assert depths["hk163"] == 163  # 163 older registrations ahead of it
    assert depths["hk0"] == 0
    worst_case = SN39_MORTAL_PERIOD_BLOCKS  # 1 reg/block, zero free slots
    assert depths["hk163"] >= worst_case
    assert depths["hk3"] < worst_case


# -- exclusion is applied, not just reported --------------------------------


def _preflight(safe):
    return validator_thin.ChainPreflight(
        wallet=None,
        subtensor=None,
        hotkey_to_uid={"safe": 1, "unsafe": 2},
        validator_hotkey="v",
        validator_uid=0,
        block=100,
        min_allowed_weights=1,
        max_weight_limit=1.0,
        genesis_hash="not-finney",
        replacement_safe_hotkeys=frozenset(safe),
    )


def test_unprovable_target_is_excluded_not_aborted():
    result = validator_thin._require_uid_mapping_stability(
        _preflight({"safe"}),
        {1: "safe", 2: "unsafe"},
        mortal_period_blocks=SN39_MORTAL_PERIOD_BLOCKS,
    )
    assert result["excluded_hotkeys"] == ["unsafe"]


def test_no_safe_target_is_a_hard_failure():
    with pytest.raises(validator_thin.wire.VectorError, match="cannot prove any UID"):
        validator_thin._require_uid_mapping_stability(
            _preflight({"someone-else"}),
            {1: "safe", 2: "unsafe"},
            mortal_period_blocks=SN39_MORTAL_PERIOD_BLOCKS,
        )


class _Events:
    def __init__(self):
        self.emitted = []

    def event(self, name, **fields):
        self.emitted.append((name, fields))


def test_excluded_targets_are_actually_dropped_from_the_vector(monkeypatch):
    # The stability proof's contract line says "targets the caller must drop".
    # This is the drop: the unsafe UID leaves the vector, loudly.
    from types import SimpleNamespace

    events = _Events()
    args = SimpleNamespace(_events=None)
    monkeypatch.setattr(validator_thin, "_get_events", lambda _a: events)
    kept = _drop_unprovable_targets(
        args,
        {1: 0.9, 2: 0.1},
        {"excluded_hotkeys": ["unsafe"]},
        {"safe": 1, "unsafe": 2},
    )
    assert kept == {1: 0.9}
    assert events.emitted and events.emitted[0][0] == "UNSAFE_TARGETS_EXCLUDED"


def test_no_exclusions_means_the_vector_is_untouched(monkeypatch):
    from types import SimpleNamespace

    weights = {1: 0.9, 2: 0.1}
    kept = _drop_unprovable_targets(
        SimpleNamespace(), weights, {"excluded_hotkeys": []}, {"a": 1, "b": 2}
    )
    assert kept is weights


def test_dropping_everything_refuses(monkeypatch):
    from types import SimpleNamespace

    events = _Events()
    monkeypatch.setattr(validator_thin, "_get_events", lambda _a: events)
    with pytest.raises(validator_thin.wire.VectorError, match="nothing safe"):
        _drop_unprovable_targets(
            SimpleNamespace(),
            {2: 1.0},
            {"excluded_hotkeys": ["unsafe"]},
            {"unsafe": 2},
        )
