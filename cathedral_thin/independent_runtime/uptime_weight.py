"""Uptime rule for compute weight (AB#327).

Pure window math with no I/O. The rounds are the validator's own finalized,
spooled telemetry rounds, read the same way as the rolling availability
(AB#326): a hotkey is up in a round when it had at least one verified machine.

The rule:

- A window is one UTC day. A hotkey's uptime in a window is the share of the
  window's counted rounds in which it was up, in basis points.
- A judged window at or above ``UPTIME_THRESHOLD_BPS`` multiplies the hotkey's
  compute weight by its uptime. Below it the factor is zero.
- The factor applied now is the one from the latest settled window: the
  previous UTC day, once ``SETTLE`` has passed since it ended (a commit-reveal
  round is spooled only after its reveal). The current day is not complete, so
  it cannot be judged yet; a miner down right now is already paid zero this
  round because it has no verified machine.
- ``PROBATION_STRIKES`` failing windows among the last ``PROBATION_LOOKBACK``
  settled windows put the hotkey on probation: factor zero until enough of
  them age out of the lookback. Nothing is stored; it is derived every cycle.

What does not count against a miner:

- Validator downtime: only rounds the validator finalized are counted.
- Rounds with no verified machine at all. The validator burns the whole
  compute lane when its own verifier is out (``compute_lane_unproven``) and
  then spools every miner with zero machines, so such a round cannot tell a
  miner outage from a verifier outage.
- Rounds before the hotkey was first up anywhere in the history, so a new
  miner's onboarding day is not a failing window.
- A window with fewer than ``MIN_ROUNDS_PER_WINDOW`` counted rounds.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Iterable

from .availability import AVAILABILITY_BPS, AvailabilityRound

UPTIME_RULE = "cathedral_uptime_rule_v1"
UPTIME_WINDOW = timedelta(days=1)
UPTIME_THRESHOLD_BPS = 9_500
MIN_ROUNDS_PER_WINDOW = 12
PROBATION_STRIKES = 3
PROBATION_LOOKBACK = 7
SETTLE = timedelta(hours=1)


@dataclass(frozen=True)
class WindowUptime:
    start: datetime
    up_rounds: int
    rounds: int

    @property
    def bps(self) -> int:
        return self.up_rounds * AVAILABILITY_BPS // self.rounds

    @property
    def failing(self) -> bool:
        return self.bps < UPTIME_THRESHOLD_BPS


@dataclass(frozen=True)
class HotkeyUptime:
    factor_bps: int
    last_window: WindowUptime | None
    failing_windows: int
    probation: bool

    def as_document(self) -> dict[str, object]:
        last = self.last_window
        return {
            "factor_bps": self.factor_bps,
            "last_window": None
            if last is None
            else {
                "start": last.start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "up_rounds": last.up_rounds,
                "rounds": last.rounds,
                "bps": last.bps,
            },
            "failing_windows": self.failing_windows,
            "probation": self.probation,
        }


def _window_start(moment: datetime) -> datetime:
    return datetime(moment.year, moment.month, moment.day, tzinfo=UTC)


def settled_windows(now: datetime) -> tuple[datetime, ...]:
    """Starts of the last ``PROBATION_LOOKBACK`` settled windows, newest first."""

    if now.tzinfo is None:
        raise ValueError("uptime needs an aware clock")
    newest = _window_start(now.astimezone(UTC) - SETTLE) - UPTIME_WINDOW
    return tuple(newest - index * UPTIME_WINDOW for index in range(PROBATION_LOOKBACK))


def uptime_factors(
    rounds: Iterable[AvailabilityRound],
    *,
    hotkeys: Iterable[str],
    now: datetime,
) -> dict[str, HotkeyUptime]:
    """Each hotkey's compute weight factor for a cycle at ``now``."""

    windows = settled_windows(now)
    oldest = windows[-1]
    end = windows[0] + UPTIME_WINDOW
    # Rounds sharing an observed_at are one round spooled twice.
    up_by_time: dict[datetime, set[str]] = {}
    first_up: dict[str, datetime] = {}
    for item in rounds:
        when = item.observed_at
        if when.tzinfo is None:
            raise ValueError("uptime rounds need aware timestamps")
        for hotkey in item.verified_hotkeys:
            if hotkey not in first_up or when < first_up[hotkey]:
                first_up[hotkey] = when
        if oldest <= when < end:
            up_by_time.setdefault(when, set()).update(item.verified_hotkeys)
    counted = {when: up for when, up in up_by_time.items() if up}

    results: dict[str, HotkeyUptime] = {}
    for hotkey in hotkeys:
        judged: list[WindowUptime] = []
        start_seen = first_up.get(hotkey)
        for start in windows:
            stop = start + UPTIME_WINDOW
            eligible = [
                up
                for when, up in counted.items()
                if start <= when < stop
                and start_seen is not None
                and when >= start_seen
            ]
            if len(eligible) < MIN_ROUNDS_PER_WINDOW:
                continue
            judged.append(
                WindowUptime(
                    start=start,
                    up_rounds=sum(1 for up in eligible if hotkey in up),
                    rounds=len(eligible),
                )
            )
        failing = sum(1 for window in judged if window.failing)
        probation = failing >= PROBATION_STRIKES
        # The latest settled window decides, only if it was judged.
        last = judged[0] if judged and judged[0].start == windows[0] else None
        if probation:
            factor = 0
        elif last is None:
            factor = AVAILABILITY_BPS
        elif last.failing:
            factor = 0
        else:
            factor = last.bps
        results[hotkey] = HotkeyUptime(
            factor_bps=factor,
            last_window=last,
            failing_windows=failing,
            probation=probation,
        )
    return results


__all__ = [
    "HotkeyUptime",
    "MIN_ROUNDS_PER_WINDOW",
    "PROBATION_LOOKBACK",
    "PROBATION_STRIKES",
    "SETTLE",
    "UPTIME_RULE",
    "UPTIME_THRESHOLD_BPS",
    "UPTIME_WINDOW",
    "WindowUptime",
    "settled_windows",
    "uptime_factors",
]
