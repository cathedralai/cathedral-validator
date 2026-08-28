"""The start-up refuse-list, and the destinations this lineage never pays.

Two hotkeys must never be the identity an independent composer boots as:

* the live relay validator hotkey, because a second runtime signing as it is
  indistinguishable from the relay itself, and both would be racing to reserve
  the same epoch;
* the subnet owner hotkey, which is this composer's BURN DESTINATION. A runtime
  that holds the destination it pays to can pay itself, and every burn-only
  epoch would be a self-payment.

This is a start-up gate, not a runtime warning. A process that finds itself on
the list does not start.

The same reasoning runs in the other direction for destinations. The canary is
the identity that signs the vector, so paying it is the composer paying itself
under a different name than the burn dest -- the case the burn rule above
already forbids. ``is_refused_destination`` is that rule generalised: every
refuse-listed hotkey and the canary hotkey are unpayable, with the burn dest as
the single deliberate exception. It is on ``REFUSE_HOTKEYS`` because nothing may
RUN as it, which is not the same claim as it being unpayable: it is the one
address this lineage exists to pay.
"""

from __future__ import annotations

from .constants import BURN_HOTKEY, CANARY_HOTKEY, REFUSE_HOTKEYS
from .errors import RefuseListError


def is_refused(ss58: object) -> bool:
    """Whether ``ss58`` is on the refuse-list."""
    return isinstance(ss58, str) and ss58 in REFUSE_HOTKEYS


def is_refused_destination(ss58: object) -> bool:
    """Whether ``ss58`` may never hold mass in a composed vector.

    Fail-closed on anything that is not a usable ss58 string: an unidentified
    destination is refused rather than paid.
    """
    if not isinstance(ss58, str) or not ss58:
        return True
    if ss58 == BURN_HOTKEY:
        return False
    return ss58 in REFUSE_HOTKEYS or ss58 == CANARY_HOTKEY


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


__all__ = ["is_refused", "is_refused_destination", "require_permitted_hotkey"]
