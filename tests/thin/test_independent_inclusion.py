"""Inclusion-time UID safety: a swapped hotkey forfeits its mass to burn.

``set_mechanism_weights`` binds UIDs. If a hotkey swap lands between the anchor
the mass map was composed from and the block the extrinsic is included in, the
UID is still a valid destination -- it just belongs to somebody else now. These
tests pin the two outcomes that matter: a miner's mass goes to burn and the new
occupant is not in the vector, and a swap on the burn UID halts the epoch.
"""

from __future__ import annotations

import pytest

from _independent_fixtures import ALICE, BOB, BURN_UID, CHARLIE, DAVE
from cathedral_thin.independent.constants import BURN_HOTKEY, H
from cathedral_thin.independent.errors import InclusionHalt
from cathedral_thin.independent.hamilton import Dest, apportion
from cathedral_thin.independent.inclusion import (
    MetagraphView,
    apply_inclusion_forfeit,
    resolve_burn_uid,
)

ANCHOR_MAP = {BURN_UID: BURN_HOTKEY, 7: BOB, 9: DAVE}


def h_map() -> list[Dest]:
    return [
        Dest(BURN_UID, BURN_HOTKEY, 200_000_000_000),
        Dest(7, BOB, 500_000_000_000),
        Dest(9, DAVE, 300_000_000_000),
    ]


def test_the_burn_uid_is_resolved_from_the_pinned_hotkey():
    view = MetagraphView.from_uid_map(ANCHOR_MAP)
    assert resolve_burn_uid(view) == BURN_UID
    assert view.hotkey_to_uid[BURN_HOTKEY] == BURN_UID


def test_an_unregistered_burn_hotkey_halts():
    with pytest.raises(InclusionHalt, match="not registered"):
        resolve_burn_uid(MetagraphView.from_uid_map({7: BOB}))


def test_unchanged_maps_preserve_every_destination():
    anchor = MetagraphView.from_uid_map(ANCHOR_MAP)
    outcome = apply_inclusion_forfeit(
        h_map(), anchor=anchor, inclusion=anchor, burn_uid=BURN_UID
    )
    assert outcome.forfeits == ()
    assert outcome.degraded is False
    assert {dest.uid: dest.m for dest in outcome.dests} == {
        BURN_UID: 200_000_000_000,
        7: 500_000_000_000,
        9: 300_000_000_000,
    }
    result = apportion(outcome.dests, burn_uid=outcome.burn_uid)
    assert result.dests == (7, 9, BURN_UID)
    assert sum(result.weights) == 65535


def test_a_remapped_miner_forfeits_its_mass_to_burn():
    """The new occupant is not paid, and the survivors are not paid more."""
    anchor = MetagraphView.from_uid_map(ANCHOR_MAP)
    inclusion = MetagraphView.from_uid_map({**ANCHOR_MAP, 7: CHARLIE})
    outcome = apply_inclusion_forfeit(
        h_map(), anchor=anchor, inclusion=inclusion, burn_uid=BURN_UID
    )
    assert [forfeit.uid for forfeit in outcome.forfeits] == [7]
    assert outcome.forfeits[0].anchor_hotkey == BOB
    assert outcome.forfeits[0].inclusion_hotkey == CHARLIE
    assert outcome.forfeits[0].m == 500_000_000_000
    assert {dest.uid: dest.m for dest in outcome.dests} == {
        BURN_UID: 700_000_000_000,
        9: 300_000_000_000,
    }
    # uid 9 kept exactly its own mass: nothing was renormalised onto it.
    assert outcome.burn_mass == 700_000_000_000
    result = apportion(outcome.dests, burn_uid=outcome.burn_uid)
    assert 7 not in result.dests
    assert sum(result.weights) == 65535


def test_a_deregistered_miner_forfeits_too():
    anchor = MetagraphView.from_uid_map(ANCHOR_MAP)
    inclusion = MetagraphView.from_uid_map({BURN_UID: BURN_HOTKEY, 9: DAVE})
    outcome = apply_inclusion_forfeit(
        h_map(), anchor=anchor, inclusion=inclusion, burn_uid=BURN_UID
    )
    assert outcome.forfeits[0].inclusion_hotkey is None
    assert outcome.burn_mass == 700_000_000_000


def test_a_remapped_burn_uid_halts():
    """Burn mass has no fallback destination. The epoch stops."""
    anchor = MetagraphView.from_uid_map(ANCHOR_MAP)
    inclusion = MetagraphView.from_uid_map({**ANCHOR_MAP, BURN_UID: ALICE})
    with pytest.raises(InclusionHalt, match="no longer holds the pinned burn hotkey"):
        apply_inclusion_forfeit(
            h_map(), anchor=anchor, inclusion=inclusion, burn_uid=BURN_UID
        )


def test_a_burn_uid_absent_at_inclusion_halts():
    anchor = MetagraphView.from_uid_map(ANCHOR_MAP)
    inclusion = MetagraphView.from_uid_map({7: BOB, 9: DAVE})
    with pytest.raises(InclusionHalt, match="no longer holds the pinned burn hotkey"):
        apply_inclusion_forfeit(
            h_map(), anchor=anchor, inclusion=inclusion, burn_uid=BURN_UID
        )


def test_every_miner_forfeiting_is_degraded_not_a_halt():
    anchor = MetagraphView.from_uid_map(ANCHOR_MAP)
    inclusion = MetagraphView.from_uid_map(
        {BURN_UID: BURN_HOTKEY, 7: CHARLIE, 9: ALICE}
    )
    outcome = apply_inclusion_forfeit(
        h_map(), anchor=anchor, inclusion=inclusion, burn_uid=BURN_UID
    )
    assert outcome.degraded is True
    assert outcome.burn_mass == H
    assert len(outcome.dests) == 1
    result = apportion(outcome.dests, burn_uid=BURN_UID)
    assert (result.dests, result.weights) == ((BURN_UID,), (65535,))


def test_a_burn_only_map_is_not_marked_degraded_by_inclusion():
    """It was already burn-only; inclusion did not degrade anything."""
    view = MetagraphView.from_uid_map({BURN_UID: BURN_HOTKEY})
    outcome = apply_inclusion_forfeit(
        [Dest(BURN_UID, BURN_HOTKEY, H)],
        anchor=view,
        inclusion=view,
        burn_uid=BURN_UID,
    )
    assert outcome.degraded is False
    assert outcome.forfeits == ()


def test_a_mass_map_that_does_not_match_the_anchor_view_halts():
    anchor = MetagraphView.from_uid_map({BURN_UID: BURN_HOTKEY, 7: CHARLIE, 9: DAVE})
    with pytest.raises(InclusionHalt, match="was not held by"):
        apply_inclusion_forfeit(
            h_map(), anchor=anchor, inclusion=anchor, burn_uid=BURN_UID
        )


def test_a_mass_map_that_does_not_sum_to_h_halts():
    anchor = MetagraphView.from_uid_map(ANCHOR_MAP)
    with pytest.raises(InclusionHalt, match="not H="):
        apply_inclusion_forfeit(
            [Dest(BURN_UID, BURN_HOTKEY, 1)],
            anchor=anchor,
            inclusion=anchor,
            burn_uid=BURN_UID,
        )


def test_a_view_with_one_hotkey_on_two_uids_is_refused():
    with pytest.raises(InclusionHalt, match="maps hotkey"):
        MetagraphView.from_uid_map({7: BOB, 9: BOB})
