"""Inclusion-time UID safety: a remapped destination forfeits its mass to burn.

``set_mechanism_weights`` binds UIDs, not hotkeys. A hotkey swap between the
anchor the mass map was composed from and the block the extrinsic is included
in puts a DIFFERENT hotkey on the same UID, and the vector then pays the new
occupant for the previous occupant's work.

So the mass map is composed at the anchor and re-checked against the inclusion
view immediately before signing. For every non-burn destination:

* the inclusion hotkey still matches the anchor hotkey -> keep the mass;
* it does not -> the mass moves to burn and the destination is dropped.

The mass is never renormalised onto the surviving miners. Renormalising would
pay everyone else more because someone swapped a key, which is a reward for an
event no miner did any work for. Forfeited mass goes to burn, in integer ``H``,
and only then is the vector apportioned.

A destination this lineage may never pay forfeits the same way. The canary
hotkey signs the vector, so paying it is a self-payment under another name, and
the live relay identity is not a miner. Those destinations are dropped and their
mass folds to burn, exactly like a remap: refusing the whole epoch would let any
hotkey that lands on the refuse-list stop the subnet from paying anybody.

If the burn destination itself is remapped, or cannot be proven, the whole
epoch halts. There is no fallback destination for burn mass.

``InclusionOutcome`` carries the surviving ``uid -> hotkey`` bindings so a later
gate can ask what a UID it is about to pay actually is, without reading a chain.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from .constants import BURN_HOTKEY, H
from .errors import InclusionHalt
from .hamilton import Dest
from .refuse import is_refused_destination

FORFEIT_REMAPPED = "the inclusion hotkey is not the anchor hotkey"
FORFEIT_REFUSED = "this lineage never pays this hotkey"


@dataclass(frozen=True)
class MetagraphView:
    """A UID/hotkey snapshot at one block. Bijective by construction."""

    uid_to_hotkey: Mapping[int, str]
    hotkey_to_uid: Mapping[str, int]

    @classmethod
    def from_uid_map(cls, uid_to_hotkey: Mapping[int, str]) -> MetagraphView:
        forward: dict[int, str] = {}
        reverse: dict[str, int] = {}
        for uid, hotkey in uid_to_hotkey.items():
            if isinstance(uid, bool) or not isinstance(uid, int):
                raise InclusionHalt("metagraph uid must be an integer")
            if not (0 <= uid <= 0xFFFF):
                raise InclusionHalt(f"metagraph uid {uid} does not fit in u16")
            if not isinstance(hotkey, str) or not hotkey:
                raise InclusionHalt(f"metagraph uid {uid} has no hotkey")
            if hotkey in reverse:
                # One hotkey on two UIDs is not a view this composer can reason
                # about: "did this hotkey keep its slot" has two answers.
                raise InclusionHalt(
                    f"metagraph maps hotkey {hotkey} to uids "
                    f"{reverse[hotkey]} and {uid}"
                )
            forward[uid] = hotkey
            reverse[hotkey] = uid
        return cls(
            uid_to_hotkey=MappingProxyType(forward),
            hotkey_to_uid=MappingProxyType(reverse),
        )


@dataclass(frozen=True)
class Forfeit:
    """One destination that lost its mass to burn, and why."""

    uid: int
    anchor_hotkey: str
    inclusion_hotkey: str | None
    m: int
    reason: str

    def as_journal(self) -> dict[str, object]:
        return {
            "uid": self.uid,
            "anchor_hotkey": self.anchor_hotkey,
            "inclusion_hotkey": self.inclusion_hotkey,
            "m": self.m,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class InclusionOutcome:
    dests: tuple[Dest, ...]
    forfeits: tuple[Forfeit, ...]
    burn_uid: int
    burn_mass: int
    degraded: bool
    reason: str
    uid_hotkeys: Mapping[int, str]

    def as_journal(self) -> dict[str, object]:
        return {
            "burn_uid": self.burn_uid,
            "burn_mass": self.burn_mass,
            "forfeits": [forfeit.as_journal() for forfeit in self.forfeits],
            "uid_hotkeys": {
                str(uid): self.uid_hotkeys[uid] for uid in sorted(self.uid_hotkeys)
            },
            "degraded": self.degraded,
            "reason": self.reason,
        }


def resolve_burn_uid(view: MetagraphView) -> int:
    """The UID the pinned burn hotkey occupies in ``view``, or halt.

    Resolved from the hotkey every time. The owner hotkey has moved UIDs before,
    and a pinned UID would keep paying whoever inherited the old slot.
    """
    uid = view.hotkey_to_uid.get(BURN_HOTKEY)
    if uid is None:
        raise InclusionHalt(
            "the pinned burn hotkey is not registered in this metagraph view"
        )
    return uid


def apply_inclusion_forfeit(
    h_map: Sequence[Dest],
    *,
    anchor: MetagraphView,
    inclusion: MetagraphView,
    burn_uid: int,
) -> InclusionOutcome:
    """Re-check an anchor mass map against the inclusion view.

    Returns the destinations to apportion, with every remapped destination's
    mass folded into burn.
    """
    rows = list(h_map)
    if not rows:
        raise InclusionHalt("the mass map is empty")
    total = sum(dest.m for dest in rows)
    if total != H:
        raise InclusionHalt(f"anchor mass map sums to {total}, not H={H}")

    burn_rows = [dest for dest in rows if dest.uid == burn_uid]
    if len(burn_rows) != 1:
        raise InclusionHalt(
            f"the mass map carries {len(burn_rows)} rows for burn uid {burn_uid}"
        )
    burn_row = burn_rows[0]
    if burn_row.ss58 != BURN_HOTKEY:
        raise InclusionHalt("the burn row does not carry the pinned burn hotkey")
    if anchor.uid_to_hotkey.get(burn_uid) != BURN_HOTKEY:
        raise InclusionHalt(
            f"uid {burn_uid} did not hold the pinned burn hotkey at the anchor"
        )
    if inclusion.uid_to_hotkey.get(burn_uid) != BURN_HOTKEY:
        # Never pay burn mass to whoever now holds that UID.
        raise InclusionHalt(
            f"uid {burn_uid} no longer holds the pinned burn hotkey at inclusion; "
            "the epoch halts rather than paying the new occupant"
        )

    kept: list[Dest] = []
    forfeits: list[Forfeit] = []
    burn_mass = burn_row.m
    for dest in rows:
        if dest.uid == burn_uid:
            continue
        if anchor.uid_to_hotkey.get(dest.uid) != dest.ss58:
            raise InclusionHalt(
                f"uid {dest.uid} was not held by {dest.ss58} at the anchor; "
                "the mass map does not match the view it was composed from"
            )
        inclusion_hotkey = inclusion.uid_to_hotkey.get(dest.uid)
        if is_refused_destination(dest.ss58):
            reason = FORFEIT_REFUSED
        elif inclusion_hotkey != dest.ss58:
            reason = FORFEIT_REMAPPED
        else:
            kept.append(dest)
            continue
        burn_mass += dest.m
        forfeits.append(
            Forfeit(
                uid=dest.uid,
                anchor_hotkey=dest.ss58,
                inclusion_hotkey=inclusion_hotkey,
                m=dest.m,
                reason=reason,
            )
        )

    dests = tuple([Dest(uid=burn_uid, ss58=BURN_HOTKEY, m=burn_mass), *kept])
    if sum(dest.m for dest in dests) != H:
        raise InclusionHalt("forfeit accounting did not preserve the total mass")

    was_burn_only = len(rows) == 1
    burn_only_now = len(dests) == 1
    degraded = burn_only_now and not was_burn_only
    reason = ""
    if degraded:
        reason = (
            "every miner destination forfeited to burn at inclusion; the vector "
            "is legal but is not an acceptance signal"
        )
    elif forfeits:
        reason = f"{len(forfeits)} destination(s) forfeited to burn at inclusion"
    return InclusionOutcome(
        dests=dests,
        forfeits=tuple(forfeits),
        burn_uid=burn_uid,
        burn_mass=burn_mass,
        degraded=degraded,
        reason=reason,
        uid_hotkeys=MappingProxyType({dest.uid: dest.ss58 for dest in dests}),
    )


__all__ = [
    "FORFEIT_REFUSED",
    "FORFEIT_REMAPPED",
    "Forfeit",
    "InclusionOutcome",
    "MetagraphView",
    "apply_inclusion_forfeit",
    "resolve_burn_uid",
]
