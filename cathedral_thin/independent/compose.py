"""Dry-run composition: policy bundle plus two metagraph views to a u16 vector.

This is the whole composer for `independent_v1` as it stands: it verifies that
the anchor's on-chain commitment names exactly the policy document in hand,
turns that document into an integer mass map, re-checks every destination
against the inclusion view, apportions to u16, and journals the result. It
never touches a chain client and it has no writer to call.

Two outcomes are deliberately NOT acceptance:

* ``DEGRADED`` -- a legal burn-only vector. Every lane sits at allocation 0
  until its blockers close, so burn-only is the expected shape right now. It
  proves the composer runs; it proves nothing about a lane.
* ``BROADCAST_BLOCKED`` -- a funded, enabled lane that this runtime cannot
  substantiate. Recorded even in dry-run, because the interesting failure is a
  future runtime that would have broadcast it.

The mass of an unpayable funded lane folds into burn rather than being spread
over the destinations that did survive. Redistributing it would pay miners more
because a lane was broken, which is mass nobody earned.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from .constants import BURN_HOTKEY, H, INDEPENDENT_STATE_FILE, LINEAGE, NETUID
from .errors import BroadcastDisabled, CommitmentError, ConfigError
from .hamilton import Dest, HamiltonResult, apportion
from .inclusion import (
    InclusionOutcome,
    MetagraphView,
    apply_inclusion_forfeit,
    resolve_burn_uid,
)
from .journal import write_journal
from .policy import (
    LaneContractId,
    PolicyBundle,
    bundle_digest,
    decode_commitment,
    require_commitment,
)

STATUS_COMPOSED = "COMPOSED"
STATUS_BROADCAST_BLOCKED = "BROADCAST_BLOCKED"
STATUS_DEGRADED = "DEGRADED"

_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class EpochAnchor:
    """The frozen epoch boundary one vector is composed against.

    Frozen on disk when the process first observes the crossing, and never
    re-derived: the RPC that reports the next epoch open is relative to the
    CURRENT head, so asking again after the crossing answers about the epoch
    after this one and composes against the wrong tempo.
    """

    epoch_open: int
    anchor_number: int
    anchor_hash: str

    def __post_init__(self) -> None:
        for name in ("epoch_open", "anchor_number"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ConfigError(f"anchor {name} must be a non-negative integer")
        if self.anchor_number != self.epoch_open - 1:
            raise ConfigError(
                f"anchor_number {self.anchor_number} must be epoch_open - 1 "
                f"({self.epoch_open - 1})"
            )
        if not isinstance(self.anchor_hash, str) or not self.anchor_hash.startswith(
            "0x"
        ):
            raise ConfigError("anchor_hash must be a 0x-prefixed block hash")
        body = self.anchor_hash[2:]
        if len(body) != 64 or any(character not in _HEX for character in body):
            raise ConfigError("anchor_hash must be 0x plus 64 lowercase hex characters")


class LaneAdapter(Protocol):
    """A registered lane adapter.

    An adapter never names its own lane: the composer stamps the
    ``LaneContractId`` from the signed policy document, so a compromised
    adapter cannot claim another lane's allocation.

    ``probe`` is not called in this step. Every lane sits at allocation 0, and a
    funded lane is refused before any adapter runs (see ``compose_dry_run``).
    """

    def probe(
        self, *, anchor: EpochAnchor, view: MetagraphView
    ) -> Mapping[str, int]: ...


@dataclass(frozen=True)
class LaneBlock:
    """One funded lane that cannot be paid, and why."""

    lane_contract_id: LaneContractId
    amount: int
    reason: str

    def as_journal(self) -> dict[str, Any]:
        return {
            "lane_contract_id": self.lane_contract_id.as_dict(),
            "amount": self.amount,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ComposeResult:
    status: str
    dests: tuple[int, ...]
    weights: tuple[int, ...]
    reason: str
    broadcast_eligible: bool
    blocks: tuple[LaneBlock, ...]
    inclusion: InclusionOutcome
    hamilton: HamiltonResult
    record: Mapping[str, Any]
    journal_path: Path | None


def mass_map(
    bundle: PolicyBundle,
    *,
    burn_uid: int,
    adapters: Mapping[LaneContractId, Any] | None = None,
) -> tuple[tuple[Dest, ...], tuple[LaneBlock, ...]]:
    """Turn the signed economics into an integer mass map at the anchor.

    Returns the destinations and every funded lane that could not be paid.
    Disabled rows are not folded anywhere: they are not part of the signed
    partition of ``H`` at all, and inventing mass for them would be paying from
    numbers no signer summed.
    """
    economics = bundle.economics
    registry = dict(adapters or {})
    blocks: list[LaneBlock] = []
    burn_mass = economics.burn.amount
    for allocation in economics.allocations:
        if not allocation.funded:
            continue
        if allocation.lane_contract_id not in registry:
            reason = "no adapter is registered for this funded, enabled lane"
        else:
            # An adapter existing is not the same as a lane being fundable. Every
            # lane's evidence blockers are open, so a funded row is refused here
            # rather than being paid from a mock adapter's numbers.
            reason = (
                "lane funding is deferred at allocation 0 in this lineage; a "
                "registered adapter does not make the lane contributing"
            )
        blocks.append(
            LaneBlock(
                lane_contract_id=allocation.lane_contract_id,
                amount=allocation.amount,
                reason=reason,
            )
        )
        burn_mass += allocation.amount
    if burn_mass != H:
        raise CommitmentError(
            f"the composed mass map sums to {burn_mass}, not H={H}; the signed "
            "economics and this composer disagree"
        )
    return (Dest(uid=burn_uid, ss58=BURN_HOTKEY, m=burn_mass),), tuple(blocks)


def last_good_is_usable(
    *, last_good_digest: bytes, commitment: bytes, netuid: int, epoch: int
) -> bool:
    """Whether a cached policy bundle may still be used at this anchor.

    The anchor's commitment must still name the cached document's digest. This
    is what stops last-good from outrunning the chain: a superseded bundle is
    exactly the document the commitment no longer names, and reusing it would
    pay last epoch's economics forever if the publisher went dark.
    """
    if (
        not isinstance(last_good_digest, (bytes, bytearray))
        or len(last_good_digest) != 32
    ):
        raise CommitmentError("last-good digest must be 32 bytes")
    observed_netuid, observed_epoch, digest = decode_commitment(commitment)
    return (
        observed_netuid == netuid
        and observed_epoch == epoch
        and digest == bytes(last_good_digest)
    )


def require_last_good(
    *, last_good_digest: bytes, commitment: bytes, netuid: int, epoch: int
) -> None:
    """Raise unless the anchor commitment still names the cached digest."""
    if not last_good_is_usable(
        last_good_digest=last_good_digest,
        commitment=commitment,
        netuid=netuid,
        epoch=epoch,
    ):
        raise CommitmentError(
            "the anchor commitment does not name the cached policy bundle; "
            "a superseded bundle is never reused"
        )


def compose_dry_run(
    *,
    bundle: PolicyBundle,
    commitment: bytes,
    anchor: EpochAnchor,
    anchor_view: MetagraphView,
    inclusion_view: MetagraphView,
    adapters: Mapping[LaneContractId, Any] | None = None,
    journal_path: Path | str | None = INDEPENDENT_STATE_FILE,
    broadcast: bool = False,
) -> ComposeResult:
    """Compose and journal one epoch's vector without touching a chain.

    ``broadcast=True`` is refused outright. There is no writer behind this
    function, and stubbing one so the flag "works" is how a dry-run path becomes
    a live one by accident.
    """
    if broadcast is not False:
        raise BroadcastDisabled(
            "this lineage has no chain writer; broadcast is not implemented"
        )
    if bundle.economics.netuid != NETUID:
        raise ConfigError(
            f"the policy bundle is for netuid {bundle.economics.netuid}, "
            f"this composer is pinned to {NETUID}"
        )
    digest = require_commitment(
        commitment,
        netuid=bundle.economics.netuid,
        # Commitment epoch is the frozen epoch_open block, not tempo index.
        epoch=anchor.epoch_open,
        document=bundle.document,
    )
    burn_uid = resolve_burn_uid(anchor_view)
    h_map, blocks = mass_map(bundle, burn_uid=burn_uid, adapters=adapters)
    outcome = apply_inclusion_forfeit(
        h_map, anchor=anchor_view, inclusion=inclusion_view, burn_uid=burn_uid
    )
    hamilton = apportion(outcome.dests, burn_uid=outcome.burn_uid)

    burn_only = hamilton.dests == (burn_uid,)
    if blocks:
        status = STATUS_BROADCAST_BLOCKED
        reason = "; ".join(
            f"{block.lane_contract_id}: {block.reason}" for block in blocks
        )
    elif burn_only or outcome.degraded or bundle.economics.explicit_burn_only:
        status = STATUS_DEGRADED
        reason = outcome.reason or (
            "burn-only vector under explicit_burn_only; composed and journalled, "
            "but not an acceptance signal for any lane"
        )
    else:
        status = STATUS_COMPOSED
        reason = outcome.reason
    record = {
        "lineage": LINEAGE,
        "netuid": bundle.economics.netuid,
        "epoch_open": anchor.epoch_open,
        "anchor_number": anchor.anchor_number,
        "anchor_hash": anchor.anchor_hash,
        "bundle_digest": digest.hex(),
        "commitment": bytes(commitment).hex(),
        "economics_version": bundle.economics.version,
        "previous_digest": bundle.economics.previous_digest,
        "h_map": {
            str(dest.uid): {"ss58": dest.ss58, "m": dest.m} for dest in outcome.dests
        },
        "hamilton": hamilton.as_journal(),
        "inclusion": outcome.as_journal(),
        "blocks": [block.as_journal() for block in blocks],
        "status": status,
        "broadcast": False,
        "reason": reason,
    }
    written: Path | None = None
    if journal_path is not None:
        written = write_journal(record, journal_path)
    return ComposeResult(
        status=status,
        dests=hamilton.dests,
        weights=hamilton.weights,
        reason=reason,
        broadcast_eligible=False,
        blocks=blocks,
        inclusion=outcome,
        hamilton=hamilton,
        record=record,
        journal_path=written,
    )


def anchor_bundle_digest(bundle: PolicyBundle) -> bytes:
    """The digest an anchor commitment must carry for ``bundle``."""
    return bundle_digest(bundle.document)


def adapter_registry(
    pairs: Sequence[tuple[LaneContractId, Any]],
) -> dict[LaneContractId, Any]:
    """Build an adapter registry, refusing two adapters for one lane."""
    registry: dict[LaneContractId, Any] = {}
    for lane, adapter in pairs:
        if lane in registry:
            raise ConfigError(f"two adapters are registered for {lane}")
        registry[lane] = adapter
    return registry


__all__ = [
    "STATUS_BROADCAST_BLOCKED",
    "STATUS_COMPOSED",
    "STATUS_DEGRADED",
    "ComposeResult",
    "EpochAnchor",
    "LaneAdapter",
    "LaneBlock",
    "adapter_registry",
    "anchor_bundle_digest",
    "compose_dry_run",
    "last_good_is_usable",
    "mass_map",
    "require_last_good",
]
