"""Closed-tempo anchor from a produced block, not a future one.

``epoch_open`` is the start of the current tempo (the identifier of the
tempo that just closed). The anchor is the last produced block of that
closed tempo. Using ``(block // tempo + 1) * tempo - 1`` names a block
that does not exist yet for 359 of every 360 blocks.
"""

from __future__ import annotations

from cathedral_thin.independent.compose import EpochAnchor
from cathedral_thin.independent.constants import TEMPO_BLOCKS

from .errors import ChainClientError

_HEX = frozenset("0123456789abcdef")


def closed_epoch_open(block: int) -> int:
    """Return the open block of the current tempo.

    That value is the frozen ``epoch_open`` for the tempo that closed at
    ``open - 1``. Mid-tempo and on-boundary heads both name a produced block.
    """
    if isinstance(block, bool) or not isinstance(block, int) or block < TEMPO_BLOCKS:
        raise ChainClientError(
            f"block {block} is before the first closed tempo of {TEMPO_BLOCKS}"
        )
    return (block // TEMPO_BLOCKS) * TEMPO_BLOCKS


def require_block_hash(raw: object) -> str:
    """Return ``0x`` + 64 lowercase hex, or raise. ``None`` is not a hash."""
    if raw is None:
        raise ChainClientError("anchor block hash is missing")
    text = str(raw).lower()
    if not text.startswith("0x"):
        text = "0x" + text
    body = text[2:]
    if len(body) != 64 or any(character not in _HEX for character in body):
        raise ChainClientError(f"anchor block hash {text!r} is not 0x + 64 hex")
    return text


def closed_epoch_anchor(block: int, anchor_hash: object) -> EpochAnchor:
    epoch_open = closed_epoch_open(block)
    return EpochAnchor(
        epoch_open=epoch_open,
        anchor_number=epoch_open - 1,
        anchor_hash=require_block_hash(anchor_hash),
    )
