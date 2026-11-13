"""Open-season share: a bounded, fail-open weight share for delivered demand.

Outside miners who deliver attested sealed room-hours can earn a share of a
weight budget, at most ``MAX_OPEN_SEASON_FRACTION`` of it, split by delivered
hours times each hotkey's uptime factor. The default fraction is zero, so the
rule changes nothing until the owner sets it.

The rule fails open. Any error reading or scoring the injected feeds leaves the
existing fleet with the whole budget. One malformed row fails the whole share
open rather than being skipped, because a partial feed would move weight
between open-season miners on data the validator could not check.

Neither input is built here. ``DeliveredHoursFeed`` is the signed per-hotkey
room-hour feed (AB#319) and ``UptimeFeed`` the rolling uptime score (AB#326);
both are passed in as callables. Nothing in the live direct path calls this
module yet. Whoever wires it chooses the budget (the whole vector or the
compute lane) and must refuse a malformed configured fraction at startup, as
the escape config does; the fail-open here is not a substitute for that check.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Union

from cathedral_thin.independent.constants import CANARY_HOTKEY, REFUSE_HOTKEYS, W

from .direct_contract import _lane_weights

DEFAULT_OPEN_SEASON_FRACTION = Fraction(0)
MAX_OPEN_SEASON_FRACTION = Fraction(1, 10)

STATUS_DISABLED = "DISABLED"
STATUS_NO_DELIVERY = "NO_DELIVERY"
STATUS_PAID = "PAID"
STATUS_FAILED_OPEN = "FAILED_OPEN"

# Attested sealed room-hours for one window. Exact numbers only, so every
# validator computes the same split.
Hours = Union[int, Fraction]
DeliveredHoursFeed = Callable[[], Mapping[str, Hours]]
# Uptime factor in [0, 1] per hotkey.
UptimeFeed = Callable[[], Mapping[str, Fraction]]


class OpenSeasonError(ValueError):
    """An input to the open-season share is malformed."""


@dataclass(frozen=True)
class OpenSeasonRow:
    hotkey: str
    uid: int
    hours: Fraction
    uptime: Fraction
    units: Fraction
    weight: int

    def evidence(self) -> dict[str, Any]:
        return {
            "hotkey": self.hotkey,
            "uid": self.uid,
            "hours": str(self.hours),
            "uptime": str(self.uptime),
            "units": str(self.units),
            "weight": self.weight,
        }


@dataclass(frozen=True)
class OpenSeasonShare:
    """How one budget splits between the fleet and open-season miners.

    ``fleet_units`` is what stays in the fleet's lane. It is the whole budget
    on every status except ``PAID``. Whether the fleet lane then pays a miner
    or is burned is decided by the caller's vector, not here.
    """

    status: str
    fraction: Fraction
    budget: int
    fleet_units: int
    rows: tuple[OpenSeasonRow, ...]
    reason: str

    @property
    def weights_by_uid(self) -> tuple[tuple[int, int], ...]:
        return tuple((row.uid, row.weight) for row in self.rows if row.weight > 0)

    @property
    def open_season_units(self) -> int:
        return sum(row.weight for row in self.rows)

    def evidence(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "fraction": str(self.fraction),
            "budget": self.budget,
            "fleet_units": self.fleet_units,
            "rows": [row.evidence() for row in self.rows],
            "reason": self.reason,
        }


def require_fraction(value: object) -> Fraction:
    """Return ``value`` as an exact fraction in [0, MAX], or refuse."""

    if isinstance(value, bool) or not isinstance(value, (int, Fraction)):
        raise OpenSeasonError("open-season fraction must be an int or Fraction")
    fraction = Fraction(value)
    if not 0 <= fraction <= MAX_OPEN_SEASON_FRACTION:
        raise OpenSeasonError("open-season fraction is outside [0, 1/10]")
    return fraction


def _budget(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= W:
        raise OpenSeasonError("open-season budget is not an integer in [0, W]")
    return value


def _hotkey(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise OpenSeasonError("feed hotkey is not a non-empty string")
    return value


def _hours(value: object) -> Fraction:
    if isinstance(value, bool) or not isinstance(value, (int, Fraction)):
        raise OpenSeasonError("delivered hours must be an int or Fraction")
    hours = Fraction(value)
    if hours < 0:
        raise OpenSeasonError("delivered hours are negative")
    return hours


def _uptime(value: object) -> Fraction:
    if isinstance(value, bool) or not isinstance(value, (int, Fraction)):
        raise OpenSeasonError("uptime factor must be an int or Fraction")
    uptime = Fraction(value)
    if not 0 <= uptime <= 1:
        raise OpenSeasonError("uptime factor is outside [0, 1]")
    return uptime


def _fleet_keeps_all(
    status: str, fraction: Fraction, budget: int, reason: str
) -> OpenSeasonShare:
    return OpenSeasonShare(
        status=status,
        fraction=fraction,
        budget=budget,
        fleet_units=budget,
        rows=(),
        reason=reason,
    )


def score_open_season(
    *,
    budget: int,
    registered: Mapping[str, int],
    validator_uid: int,
    delivered_hours: DeliveredHoursFeed,
    uptime: UptimeFeed,
    fraction: object = DEFAULT_OPEN_SEASON_FRACTION,
    excluded_hotkeys: frozenset[str] = frozenset(),
) -> OpenSeasonShare:
    """Split ``budget`` between the fleet and open-season miners.

    ``registered`` maps every hotkey registered on the subnet to its UID, the
    map escape scoring uses. Delivery from any other hotkey is ignored. The
    validator's own UID, ``REFUSE_HOTKEYS``, the canary and
    ``excluded_hotkeys`` are never paid; the caller passes the burn hotkey and
    the approved fleet hotkeys there, so a fleet miner is not paid twice.

    Never raises. Every failure returns ``FAILED_OPEN`` with the fleet keeping
    the whole budget.
    """

    try:
        budget = _budget(budget)
    except OpenSeasonError as exc:
        # No valid budget to hand back; the caller's vector is unchanged.
        return _fleet_keeps_all(STATUS_FAILED_OPEN, Fraction(0), 0, str(exc))
    try:
        fraction = require_fraction(fraction)
    except OpenSeasonError as exc:
        return _fleet_keeps_all(STATUS_FAILED_OPEN, Fraction(0), budget, str(exc))
    if fraction == 0:
        # Default: the feeds are not even read.
        return _fleet_keeps_all(
            STATUS_DISABLED, fraction, budget, "open-season fraction is zero"
        )
    try:
        return _score(
            budget=budget,
            fraction=fraction,
            registered=registered,
            validator_uid=validator_uid,
            delivered_hours=delivered_hours,
            uptime=uptime,
            excluded_hotkeys=excluded_hotkeys,
        )
    except Exception as exc:  # noqa: BLE001 - the share always fails open
        error = str(exc) if isinstance(exc, OpenSeasonError) else type(exc).__name__
        return _fleet_keeps_all(STATUS_FAILED_OPEN, fraction, budget, error[:200])


def _score(
    *,
    budget: int,
    fraction: Fraction,
    registered: Mapping[str, int],
    validator_uid: int,
    delivered_hours: DeliveredHoursFeed,
    uptime: UptimeFeed,
    excluded_hotkeys: frozenset[str],
) -> OpenSeasonShare:
    # Validate the whole hours feed before reading uptime, so one bad row
    # fails the share open even when the rest would have paid.
    hours_by_hotkey = {
        _hotkey(hotkey): _hours(value) for hotkey, value in delivered_hours().items()
    }
    if not any(hours > 0 for hours in hours_by_hotkey.values()):
        return _fleet_keeps_all(
            STATUS_NO_DELIVERY, fraction, budget, "no delivered hours"
        )
    uptime_by_hotkey = {
        _hotkey(hotkey): _uptime(value) for hotkey, value in uptime().items()
    }
    refused = REFUSE_HOTKEYS | {CANARY_HOTKEY} | frozenset(excluded_hotkeys)
    eligible: list[tuple[str, int, Fraction, Fraction, Fraction]] = []
    seen_uids: set[int] = set()
    for hotkey in sorted(hours_by_hotkey):
        if hotkey in refused or hotkey not in registered:
            continue
        uid = registered[hotkey]
        if isinstance(uid, bool) or not isinstance(uid, int) or not 0 <= uid <= W:
            raise OpenSeasonError("registered UID is invalid")
        if uid in seen_uids:
            raise OpenSeasonError("two registered hotkeys share one UID")
        seen_uids.add(uid)
        if uid == validator_uid:
            continue
        hours = hours_by_hotkey[hotkey]
        # A hotkey with hours but no uptime score has no proven availability.
        factor = uptime_by_hotkey.get(hotkey, Fraction(0))
        units = hours * factor
        if units > 0:
            eligible.append((hotkey, uid, hours, factor, units))
    if not eligible:
        return _fleet_keeps_all(
            STATUS_NO_DELIVERY,
            fraction,
            budget,
            "no eligible registered hotkey with delivered hours and uptime",
        )
    share_budget = math.floor(fraction * budget)
    # Scale the exact units to integers so the existing lane apportioner,
    # largest remainder then hotkey then UID, does the split.
    scale = math.lcm(*(units.denominator for *_rest, units in eligible))
    uid_hotkeys = {uid: hotkey for hotkey, uid, *_rest in eligible}
    weights = _lane_weights(
        [(uid, int(units * scale)) for _hotkey, uid, _h, _f, units in eligible],
        share_budget,
        uid_hotkeys,
    )
    rows = tuple(
        OpenSeasonRow(
            hotkey=hotkey,
            uid=uid,
            hours=hours,
            uptime=factor,
            units=units,
            weight=weights.get(uid, 0),
        )
        for hotkey, uid, hours, factor, units in sorted(eligible, key=lambda r: r[1])
    )
    paid = sum(row.weight for row in rows)
    if paid != share_budget or paid > budget:
        raise OpenSeasonError("open-season share did not apportion exactly")
    return OpenSeasonShare(
        status=STATUS_PAID,
        fraction=fraction,
        budget=budget,
        fleet_units=budget - paid,
        rows=rows,
        reason="",
    )
