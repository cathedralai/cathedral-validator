"""Hamilton (largest-remainder) apportionment from integer mass to u16 weights.

Yuma compares the u16 vector, so the u16 vector is what has to be deterministic
across independent validators. Two composers with the same mass map must emit
byte-identical destinations and weights, which rules out any float division and
any tie-break that depends on dict ordering or on numpy's rounding.

The rule, in full:

    q_i    = m_i * W                     (Python int, exact)
    base_i = q_i // H
    rem_i  = q_i % H
    R      = W - sum(base_i)              0 <= R < number of destinations
    sort by (rem desc, ss58 asc, uid asc); the first R destinations get +1

The burn destination is never dropped. A legal economics set always carries a
positive burn amount, so a burn row that apportioned to zero means the mass map
disagrees with the policy, and that halts instead of quietly emitting a vector
that pays only miners.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from .constants import H, MAX_DESTS, W
from .errors import HamiltonError


@dataclass(frozen=True)
class Dest:
    """One destination: a UID, the hotkey that occupied it, and integer mass."""

    uid: int
    ss58: str
    m: int


@dataclass(frozen=True)
class HamiltonResult:
    """The apportioned vector plus the intermediate terms, for the journal."""

    dests: tuple[int, ...]
    weights: tuple[int, ...]
    masses: Mapping[int, int]
    base: Mapping[int, int]
    rem: Mapping[int, int]
    remainder_bonuses: int

    def as_journal(self) -> dict[str, object]:
        return {
            "masses": {str(uid): value for uid, value in sorted(self.masses.items())},
            "base": {str(uid): value for uid, value in sorted(self.base.items())},
            "rem": {str(uid): value for uid, value in sorted(self.rem.items())},
            "remainder_bonuses": self.remainder_bonuses,
            "dests": list(self.dests),
            "weights": list(self.weights),
        }


def _validate_dest(dest: Dest, index: int) -> None:
    if isinstance(dest.uid, bool) or not isinstance(dest.uid, int):
        raise HamiltonError(f"dests[{index}].uid must be an integer")
    if not (0 <= dest.uid <= 0xFFFF):
        raise HamiltonError(f"dests[{index}].uid {dest.uid} does not fit in u16")
    if not isinstance(dest.ss58, str) or not dest.ss58:
        raise HamiltonError(f"dests[{index}].ss58 must be a non-empty string")
    if isinstance(dest.m, bool) or not isinstance(dest.m, int):
        raise HamiltonError(f"dests[{index}].m must be an integer, not a bool")
    if not (0 <= dest.m <= H):
        raise HamiltonError(f"dests[{index}].m {dest.m} is outside [0, {H}]")


def apportion(dests: Sequence[Dest], *, burn_uid: int) -> HamiltonResult:
    """Apportion integer masses summing to ``H`` onto u16 weights summing to ``W``."""
    if isinstance(burn_uid, bool) or not isinstance(burn_uid, int):
        raise HamiltonError("burn_uid must be an integer")
    rows = list(dests)
    if not rows:
        raise HamiltonError("no destinations to apportion")
    if len(rows) > MAX_DESTS:
        raise HamiltonError(
            f"{len(rows)} destinations exceeds the {MAX_DESTS} destination cap"
        )
    seen_uids: set[int] = set()
    seen_hotkeys: set[str] = set()
    for index, dest in enumerate(rows):
        _validate_dest(dest, index)
        if dest.uid in seen_uids:
            # Never merged silently: two rows for one UID means the mass map was
            # built from two disagreeing views, and summing them invents mass.
            raise HamiltonError(f"duplicate destination uid {dest.uid}")
        if dest.ss58 in seen_hotkeys:
            raise HamiltonError(f"duplicate destination hotkey {dest.ss58}")
        seen_uids.add(dest.uid)
        seen_hotkeys.add(dest.ss58)
    if burn_uid not in seen_uids:
        raise HamiltonError(f"burn destination uid {burn_uid} is not in the mass map")
    total = sum(dest.m for dest in rows)
    if total != H:
        raise HamiltonError(f"destination masses sum to {total}, not H={H}")

    masses = {dest.uid: dest.m for dest in rows}
    base: dict[int, int] = {}
    rem: dict[int, int] = {}
    for dest in rows:
        quotient = dest.m * W
        base[dest.uid] = quotient // H
        rem[dest.uid] = quotient % H

    bonuses = W - sum(base.values())
    if not (0 <= bonuses < len(rows)):
        raise HamiltonError(
            f"remainder budget {bonuses} is outside [0, {len(rows)}); "
            "the mass map is not a partition of H"
        )
    ordered = sorted(rows, key=lambda dest: (-rem[dest.uid], dest.ss58, dest.uid))
    weights = dict(base)
    for dest in ordered[:bonuses]:
        weights[dest.uid] += 1

    if weights.get(burn_uid, 0) <= 0:
        raise HamiltonError(
            f"burn destination uid {burn_uid} apportions to weight 0; "
            "the burn row is never dropped"
        )
    # A miner whose mass rounds below one u16 step is omitted rather than sent
    # as a zero: the chain treats a zero weight as a destination that was named
    # and paid nothing, and omitting it keeps the vector minimal.
    surviving = sorted(uid for uid, weight in weights.items() if weight > 0)
    if not surviving:
        raise HamiltonError("every destination apportioned to weight 0")
    if len(surviving) > MAX_DESTS:
        raise HamiltonError(
            f"{len(surviving)} destinations exceeds the {MAX_DESTS} destination cap"
        )
    final_weights = tuple(weights[uid] for uid in surviving)
    if any(not (0 < weight <= W) for weight in final_weights):
        raise HamiltonError("apportioned weight outside (0, 65535]")
    if sum(final_weights) != W:
        raise HamiltonError(f"apportioned weights sum to {sum(final_weights)}, not {W}")
    final_dests = tuple(surviving)
    if any(
        final_dests[index] >= final_dests[index + 1]
        for index in range(len(final_dests) - 1)
    ):
        raise HamiltonError("destinations are not strictly increasing")
    return HamiltonResult(
        dests=final_dests,
        weights=final_weights,
        masses=masses,
        base=base,
        rem=rem,
        remainder_bonuses=bonuses,
    )


__all__ = ["Dest", "HamiltonResult", "apportion"]
