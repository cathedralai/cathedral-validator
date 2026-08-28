"""Hamilton apportionment: the u16 vector two composers must agree on byte for byte.

Yuma compares the submitted u16 vector, so a rounding difference between two
independent validators is a consensus difference. These are golden tests: they
pin the exact integers, not a property.
"""

from __future__ import annotations

import pytest

from _independent_fixtures import ALICE, BOB, BURN_UID, DAVE
from cathedral_thin.independent.constants import BURN_HOTKEY, H, W
from cathedral_thin.independent.errors import HamiltonError
from cathedral_thin.independent.hamilton import Dest, apportion


def burn(mass: int, uid: int = BURN_UID) -> Dest:
    return Dest(uid=uid, ss58=BURN_HOTKEY, m=mass)


def test_burn_only_is_the_whole_budget():
    """The genesis shape: one destination, the entire u16 budget."""
    result = apportion([burn(H)], burn_uid=BURN_UID)
    assert result.dests == (136,)
    assert result.weights == (65535,)
    assert sum(result.weights) == W


def test_remainder_ties_break_on_ss58_not_on_mass():
    """Two unequal masses with an identical remainder: the lower ss58 wins.

    3e11 and 5e11 differ by 2e11, which is exactly the period that makes
    ``m * 65535 mod 10**12`` repeat, so both carry remainder 5e11. Mass cannot
    decide the bonus, and dict order must not either.
    """
    dests = [burn(2 * 10**11), Dest(7, DAVE, 5 * 10**11), Dest(9, BOB, 3 * 10**11)]
    result = apportion(dests, burn_uid=BURN_UID)
    assert result.rem[7] == result.rem[9] == 500_000_000_000
    assert result.remainder_bonuses == 1
    # DAVE < BOB by ss58, so uid 7 takes the single bonus.
    assert dict(zip(result.dests, result.weights)) == {7: 32768, 9: 19660, 136: 13107}
    assert sum(result.weights) == W

    swapped = apportion(
        [burn(2 * 10**11), Dest(7, DAVE, 3 * 10**11), Dest(9, BOB, 5 * 10**11)],
        burn_uid=BURN_UID,
    )
    # Masses swapped, the tie is the same, and the lower ss58 still wins: the
    # bonus followed the hotkey, not the larger mass.
    assert dict(zip(swapped.dests, swapped.weights)) == {7: 19661, 9: 32767, 136: 13107}


def test_uid_is_the_final_tie_break_and_hotkeys_must_be_distinct():
    """The uid tie-break only matters below ss58, which is unique by construction."""
    with pytest.raises(HamiltonError, match="duplicate destination hotkey"):
        apportion(
            [burn(H // 2), Dest(7, DAVE, H // 4), Dest(9, DAVE, H // 4)],
            burn_uid=BURN_UID,
        )


def test_three_destinations_come_back_strictly_increasing():
    result = apportion(
        [
            Dest(900, ALICE, 250_000_000_000),
            burn(500_000_000_000),
            Dest(12, BOB, 250_000_000_000),
        ],
        burn_uid=BURN_UID,
    )
    assert result.dests == (12, 136, 900)
    assert list(result.dests) == sorted(result.dests)
    assert sum(result.weights) == W
    assert all(0 < weight <= W for weight in result.weights)


def test_a_dust_destination_is_omitted_and_burn_survives():
    """A mass below one u16 step is dropped, not sent as a zero weight."""
    result = apportion([burn(H - 1), Dest(7, BOB, 1)], burn_uid=BURN_UID)
    assert result.base[7] == 0
    assert result.dests == (136,)
    assert result.weights == (65535,)
    assert sum(result.weights) == W


def test_duplicate_uid_halts_rather_than_merging():
    with pytest.raises(HamiltonError, match="duplicate destination uid"):
        apportion(
            [burn(H // 2), Dest(7, BOB, H // 4), Dest(7, ALICE, H // 4)],
            burn_uid=BURN_UID,
        )


def test_a_missing_burn_destination_halts():
    with pytest.raises(HamiltonError, match="burn destination uid 136 is not"):
        apportion([Dest(7, BOB, H)], burn_uid=BURN_UID)


def test_a_burn_row_that_would_apportion_to_zero_halts():
    """The burn row is never dropped, even when its mass is dust."""
    with pytest.raises(HamiltonError, match="apportions to weight 0"):
        apportion([burn(1), Dest(7, BOB, H - 1)], burn_uid=BURN_UID)


def test_a_bool_mass_halts_before_apportionment():
    """``True`` is an ``int`` in Python. It is not one unit of mass."""
    with pytest.raises(HamiltonError, match="must be an integer, not a bool"):
        apportion([burn(H - 1), Dest(7, BOB, True)], burn_uid=BURN_UID)


def test_masses_that_do_not_partition_h_halt():
    with pytest.raises(HamiltonError, match="not H="):
        apportion([burn(H - 5), Dest(7, BOB, 4)], burn_uid=BURN_UID)


def test_no_float_appears_anywhere_in_the_result():
    result = apportion(
        [burn(333_333_333_333), Dest(7, BOB, 666_666_666_667)], burn_uid=BURN_UID
    )
    values = [
        *result.weights,
        *result.base.values(),
        *result.rem.values(),
        *result.masses.values(),
    ]
    assert all(
        isinstance(value, int) and not isinstance(value, bool) for value in values
    )
    assert sum(result.weights) == W
