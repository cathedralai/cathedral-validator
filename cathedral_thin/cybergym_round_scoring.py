"""Per-round CyberGym scoring — the KING payout, owned by the validator for weight composition.

NOT a rolling tournament: each round is scored on its own (jared, 2026-09-04). A miner's round
score is its benchmarked completion (base-100); miners are ranked, and the CyberGym lane is split
by the KING curve — ranks 2..5 take fixed 0.07/0.03/0.03/0.03 and the king (rank 1) takes the
residual, so the field only decides how much the king keeps and the vector always sums to 1 for a
non-empty field:

    1 miner  -> [1.00]                          (a lone miner takes the whole lane)
    2        -> [0.93, 0.07]
    3        -> [0.90, 0.07, 0.03]
    4        -> [0.87, 0.07, 0.03, 0.03]
    5        -> [0.84, 0.07, 0.03, 0.03, 0.03]
    6+       -> only the top five paid; king still 0.84, ranks 6+ earn 0
    0        -> the whole lane forfeits to burn (no miner -> weight goes to the sandbox lane)

The validator owns this (rather than importing distill's copy) because a validator must be able
to compose weights deterministically without an optional runtime dependency, and every validator
must produce the IDENTICAL split — so it is a pure, fixed-precision function with an ungrindable
nonce-keyed tie-break, mirroring the distill scoreboard the backend announces.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal

RUNNER_UP_SHARES: tuple[Decimal, ...] = (
    Decimal("0.07"),
    Decimal("0.03"),
    Decimal("0.03"),
    Decimal("0.03"),
)
WINNER_SLOTS = len(RUNNER_UP_SHARES) + 1  # 5 (king + four runners-up)
BASE = Decimal("100")
QUANT = Decimal("0.000001")


class RoundScoringError(ValueError):
    """Incoherent scoring input. Fails closed — never silently rounds a payout boundary."""


def _q(v: Decimal) -> Decimal:
    return v.quantize(QUANT, rounding=ROUND_HALF_EVEN)


def round_score_base100(solved_units, total_units) -> Decimal:
    """Base-100 completion for one round: ``100 × solved / total`` (0 when nothing dispatched)."""
    solved, total = Decimal(solved_units), Decimal(total_units)
    if solved < 0 or total < 0:
        raise RoundScoringError("units must be non-negative")
    if solved > total:
        raise RoundScoringError(f"solved ({solved}) exceeds total ({total})")
    return Decimal(0) if total == 0 else _q(BASE * solved / total)


def award_shares(n_winners: int) -> list[Decimal]:
    """KING lane shares for ``n_winners`` (0..5+), rank order. See module docstring for the table."""
    if n_winners <= 0:
        return []
    n = min(n_winners, WINNER_SLOTS)
    if n == 1:
        return [Decimal(1)]
    runners = list(RUNNER_UP_SHARES[: n - 1])
    return [_q(Decimal(1) - sum(runners, Decimal(0))), *runners]


def _tiebreak(nonce: bytes, source_epoch: int, hotkey: str) -> str:
    material = (
        nonce + b"\x00" + str(int(source_epoch)).encode() + b"\x00" + hotkey.encode()
    )
    return hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class RoundStanding:
    miner_hotkey: str
    score: Decimal  # base-100 round score
    rank: int  # 1-based over all miners
    lane_share: Decimal  # share of the CyberGym lane; 0 unless a top-5 winner


@dataclass(frozen=True)
class RoundBoard:
    source_epoch: int
    standings: tuple[RoundStanding, ...]
    winners: tuple[str, ...]
    lane_burn: Decimal


def compose_round_board(
    source_epoch: int,
    round_scores: Mapping[str, Decimal | int | str],
    *,
    nonce: bytes | str,
) -> RoundBoard:
    """Rank miners by their single-round score and award the KING shares.

    Ranking: score desc, then an ungrindable ``sha256(nonce ‖ source_epoch ‖ hotkey)`` (ties are
    common — a fully-solved round ties at 100 — and the top-5 cutoff is payout-decisive), then
    hotkey. A winner is a top-5 miner with score > 0; a field with no positive score burns the
    whole lane (the "no miner -> sandbox lane" rule).
    """
    if not isinstance(nonce, (bytes, bytearray, str)):
        raise RoundScoringError(
            "nonce must be bytes/bytearray/str (the chain-anchored nonce)"
        )
    nb = (
        bytes(nonce) if isinstance(nonce, (bytes, bytearray)) else nonce.encode("utf-8")
    )
    if not nb:
        raise RoundScoringError(
            "a non-empty nonce is required (payout-decisive tie-break)"
        )
    totals = {hk: _q(Decimal(s)) for hk, s in round_scores.items()}
    ordered = sorted(
        totals, key=lambda hk: (-totals[hk], _tiebreak(nb, source_epoch, hk), hk)
    )
    winners = [h for h in ordered if totals[h] > 0][:WINNER_SLOTS]
    shares = award_shares(len(winners))
    by_hk = dict(zip(winners, shares))
    standings = tuple(
        RoundStanding(
            miner_hotkey=h,
            score=totals[h],
            rank=i + 1,
            lane_share=by_hk.get(h, Decimal(0)),
        )
        for i, h in enumerate(ordered)
    )
    return RoundBoard(
        source_epoch=int(source_epoch),
        standings=standings,
        winners=tuple(winners),
        lane_burn=_q(Decimal(1) - sum(shares, Decimal(0))),
    )


__all__ = [
    "RUNNER_UP_SHARES",
    "WINNER_SLOTS",
    "BASE",
    "RoundScoringError",
    "round_score_base100",
    "award_shares",
    "RoundStanding",
    "RoundBoard",
    "compose_round_board",
]
