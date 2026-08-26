"""Integer Compute mass from independently re-derived work units.

Attestation is admission, not payment. A PASS quote does not bind mass.
A miner that completed verified work gets a positive integer share of the
funded Compute allocation; leftover folds to burn in the composer.
"""

from __future__ import annotations

from typing import Mapping

from cathedral_thin.independent.constants import H
from cathedral_thin.independent.errors import ComputeEvidenceError


def mass_from_units(allocation: int, units: Mapping[str, int]) -> dict[str, int]:
    """Apportion ``allocation`` over miners by integer work units.

    ``units`` values must be positive. Miners with zero units are omitted.
    Leftover remainder after integer division is not assigned here; the
    composer folds unassigned allocation to burn.
    """
    if isinstance(allocation, bool) or not isinstance(allocation, int):
        raise ComputeEvidenceError("Compute allocation must be an integer")
    if not (0 < allocation <= H):
        raise ComputeEvidenceError("Compute allocation is outside (0, H]")
    if not isinstance(units, Mapping) or not units:
        return {}
    cleaned: dict[str, int] = {}
    total = 0
    for ss58, value in units.items():
        if not isinstance(ss58, str) or not ss58:
            raise ComputeEvidenceError("work-unit keys must be miner ss58 strings")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ComputeEvidenceError(
                f"work units for {ss58} must be a non-negative integer"
            )
        if value == 0:
            continue
        cleaned[ss58] = value
        total += value
    if total <= 0:
        return {}
    assigned: dict[str, int] = {}
    used = 0
    items = sorted(cleaned.items(), key=lambda item: (-item[1], item[0]))
    for index, (ss58, value) in enumerate(items):
        share = allocation * value // total
        if index == len(items) - 1:
            share = allocation - used
        if share <= 0:
            continue
        assigned[ss58] = share
        used += share
    return assigned
