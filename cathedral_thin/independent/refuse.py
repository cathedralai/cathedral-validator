"""The start-up refuse-list.

Two hotkeys must never be the identity an independent composer boots as:

* the live relay validator hotkey, because a second runtime signing as it is
  indistinguishable from the relay itself, and both would be racing to reserve
  the same epoch;
* the subnet owner hotkey, which is this composer's BURN DESTINATION. A runtime
  that holds the destination it pays to can pay itself, and every burn-only
  epoch would be a self-payment.

This is a start-up gate, not a runtime warning. A process that finds itself on
the list does not start.
"""

from __future__ import annotations

from .constants import BURN_HOTKEY, REFUSE_HOTKEYS
from .errors import RefuseListError


def is_refused(ss58: object) -> bool:
    """Whether ``ss58`` is on the refuse-list."""
    return isinstance(ss58, str) and ss58 in REFUSE_HOTKEYS


def require_permitted_hotkey(ss58: object, *, label: str = "validator hotkey") -> str:
    """Return ``ss58`` if it may run this lineage, else raise ``RefuseListError``."""
    if not isinstance(ss58, str) or not ss58:
        raise RefuseListError(f"{label} must be a non-empty ss58 address")
    if ss58 in REFUSE_HOTKEYS:
        detail = (
            "it is the burn destination this composer pays to"
            if ss58 == BURN_HOTKEY
            else "it is an operationally reserved identity"
        )
        raise RefuseListError(
            f"{label} {ss58} is on the refuse-list ({detail}); "
            "this runtime will not start as it"
        )
    return ss58


__all__ = ["is_refused", "require_permitted_hotkey"]
