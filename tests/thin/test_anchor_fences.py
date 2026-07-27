"""The anchored candidate block is producer-chosen, so it needs a fence.

Every "independent" chain cross-check in the FULL path is evaluated AT
candidate_set.block: the block hash lookup, and the bidirectional equality
between the manifest's candidate set and the historical metagraph. Those checks
are honest, but they answer questions about a moment the producer selected.

That makes an unbounded anchor an omission channel that set equality cannot
see. Pin the anchor to a block before a victim registered and the victim is not
omitted from the audited universe, they are outside it, so nothing quantifies
over them and every check passes. Two fences close it: a ceiling on how stale
an anchor may be against the live head, and a durable high-water mark so the
anchor cannot be walked backwards across epochs.
"""

from __future__ import annotations

import pytest

from scaffold import provenance_audit as pa
from scaffold import validator_thin as vt


def _settings(**over):
    base = {
        "mode": "authority",
        "evidence_url": "https://api.example.test/v1/evidence",
        "registry_keys": "/tmp/rk.json",
        "report_keys": "/tmp/pk.json",
        "index_keys": "/tmp/ik.json",
        "verifier_digest": "sha256:" + "0" * 64,
        "registry_keys_digest": "sha256:" + "1" * 64,
        "report_keys_digest": "sha256:" + "2" * 64,
        "index_keys_digest": "sha256:" + "3" * 64,
        "source_revision": "a" * 40,
        "verifier_binary": "/tmp/verifier",
        "controlled_dir": "/tmp/controlled",
        "max_anchor_lag_blocks": 600,
    }
    base.update(over)
    return pa.ProvenanceSettings(**base)


# -- the ceiling is mandatory where it matters ------------------------------


def test_full_mode_refuses_to_run_without_an_anchor_ceiling():
    with pytest.raises(pa.ProvenanceAuditError, match="max-anchor-lag-blocks"):
        _settings(max_anchor_lag_blocks=None).validate_for_audit()


@pytest.mark.parametrize("bad", [0, -1, True, "600"])
def test_a_nonsensical_ceiling_is_refused(bad):
    with pytest.raises(pa.ProvenanceAuditError, match="max-anchor-lag-blocks"):
        _settings(max_anchor_lag_blocks=bad).validate_for_audit()


def test_a_sane_ceiling_validates():
    _settings().validate_for_audit()  # must not raise


def test_shadow_mode_does_not_require_the_ceiling():
    # Shadow never submits, so an unfenced anchor there costs nothing and
    # forcing the pin would break every observing validator on upgrade.
    _settings(mode="shadow", max_anchor_lag_blocks=None).validate_for_audit()


# -- the durable high-water mark --------------------------------------------


def _fence(new: int | None, stored: int | None):
    """Run the reservation fence with only the anchor fields populated."""
    current = {} if stored is None else {"provenance_candidate_block": stored}
    updates = {} if new is None else {"provenance_candidate_block": new}
    return current, updates


def test_walking_the_anchor_backwards_is_refused():
    current, updates = _fence(new=8_700_000, stored=8_716_000)
    with pytest.raises(ValueError, match="anchor rollback"):
        vt._assert_anchor_not_rewound(current, updates)


def test_reusing_the_same_anchor_is_allowed(tmp_path):
    # Two epochs exported inside one block is legitimate.
    current, updates = _fence(new=8_716_000, stored=8_716_000)
    vt._assert_anchor_not_rewound(*_fence(8_716_000, 8_716_000))


def test_advancing_the_anchor_is_allowed():
    vt._assert_anchor_not_rewound(*_fence(8_716_100, 8_716_000))


def test_a_first_run_has_nothing_to_compare_against():
    vt._assert_anchor_not_rewound(*_fence(8_716_000, None))


def test_a_missing_new_anchor_does_not_bypass_the_fence_silently():
    # Absent means "this write carries no anchor", not "any anchor is fine".
    # It must not raise, but it must also not clear the stored high-water mark.
    current, updates = _fence(new=None, stored=8_716_000)
    vt._assert_anchor_not_rewound(current, updates)
    assert current["provenance_candidate_block"] == 8_716_000


def test_a_boolean_is_not_accepted_as_a_block_height():
    # True == 1 in Python, so a bool would silently rank below every real
    # block and either bypass or trip the fence for the wrong reason.
    vt._assert_anchor_not_rewound(*_fence(True, 8_716_000))
