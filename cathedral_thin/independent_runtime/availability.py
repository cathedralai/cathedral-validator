"""Rolling seven-day availability per hotkey (AB#326).

Pure window math with no I/O, so the telemetry path and the separate exporter
can import it without loading the evidence collector in ``fleet_score``. The
observations are finalized, signed telemetry rounds from the validator's own
spool; see ``telemetry.PendingTelemetryStore.finalize``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

AVAILABILITY_WINDOW = timedelta(days=7)
AVAILABILITY_BPS = 10_000


@dataclass(frozen=True)
class AvailabilityRound:
    """One finalized, published round: when it was observed and who verified."""

    observed_at: datetime
    verified_hotkeys: frozenset[str]


@dataclass(frozen=True)
class HotkeyAvailability:
    verified_rounds: int
    rounds: int

    @property
    def bps(self) -> int:
        return self.verified_rounds * AVAILABILITY_BPS // self.rounds

    def as_document(self) -> dict[str, int]:
        return {
            "verified_rounds": self.verified_rounds,
            "rounds": self.rounds,
            "bps": self.bps,
        }


def rolling_availability(
    rounds: Iterable[AvailabilityRound],
    *,
    hotkeys: Iterable[str],
    now: datetime,
    window: timedelta = AVAILABILITY_WINDOW,
) -> dict[str, HotkeyAvailability]:
    """Per-hotkey share of finalized rounds in ``(now - window, now]`` where
    the hotkey had at least one verified machine.

    The denominator is every round the validator finalized in the window, so
    validator downtime is not held against a miner, while a hotkey missing
    from a round (not serving, or not yet registered) counts as not verified.
    Rounds with the same ``observed_at`` count once: a crash between spooling
    and clearing can spool one round twice. Keyed by hotkey, so a UID that is
    re-registered starts a fresh history.
    """

    if now.tzinfo is None or window <= timedelta(0):
        raise ValueError("availability needs an aware clock and a positive window")
    start = now - window
    verified_by_time: dict[datetime, set[str]] = {}
    for item in rounds:
        if start < item.observed_at <= now:
            verified_by_time.setdefault(item.observed_at, set()).update(
                item.verified_hotkeys
            )
    total = len(verified_by_time)
    if total == 0:
        return {}
    return {
        hotkey: HotkeyAvailability(
            verified_rounds=sum(
                1 for seen in verified_by_time.values() if hotkey in seen
            ),
            rounds=total,
        )
        for hotkey in hotkeys
    }


__all__ = [
    "AVAILABILITY_BPS",
    "AVAILABILITY_WINDOW",
    "AvailabilityRound",
    "HotkeyAvailability",
    "rolling_availability",
]
