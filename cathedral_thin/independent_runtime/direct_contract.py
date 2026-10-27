"""Shared data contract for the relay-free validator and its chain writer."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Mapping, Sequence

from cathedral_thin.independent.constants import MAX_NETUID, W
from cathedral_thin.independent.submit import build_mechanism_weights_kwargs

from .axon import ServingAxon
from .errors import IndependentLiveError

DIRECT_PLAN_SCHEMA = "cathedral_direct_validator_plan_v1"


class DirectValidatorError(IndependentLiveError):
    """The direct path refused before a chain result became ambiguous."""


def require_netuid(value: object) -> int:
    """Return ``value`` if it can name a subnet, or refuse.

    Every layer of the direct path that receives a netuid checks it here, so a
    bool, a string, or an out-of-range integer never reaches a chain read, a
    journal path, or a signed call.
    """

    if isinstance(value, bool) or not isinstance(value, int):
        raise DirectValidatorError("netuid is not an integer")
    if not 0 <= value <= MAX_NETUID:
        raise DirectValidatorError("netuid is outside the u16 range")
    return value


def zero_burn_vector(
    raw_scores: Sequence[tuple[int, int]],
    uid_hotkeys: Mapping[int, str],
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Normalize positive integer machine counts with deterministic remainders."""

    if isinstance(raw_scores, (str, bytes)) or not isinstance(raw_scores, Sequence):
        raise DirectValidatorError("raw machine scores are not a sequence")
    seen: set[int] = set()
    positive: list[tuple[int, int]] = []
    for row in raw_scores:
        if not isinstance(row, tuple) or len(row) != 2:
            raise DirectValidatorError("raw machine score row is malformed")
        uid, count = row
        if (
            isinstance(uid, bool)
            or not isinstance(uid, int)
            or not 0 <= uid <= W
            or uid in seen
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            or not isinstance(uid_hotkeys.get(uid), str)
            or not uid_hotkeys[uid]
        ):
            raise DirectValidatorError("raw machine score identity is invalid")
        seen.add(uid)
        if count > 0:
            positive.append((uid, count))
    total = sum(count for _uid, count in positive)
    if total <= 0:
        raise DirectValidatorError("no miner has a verified machine")
    base = {uid: count * W // total for uid, count in positive}
    remainder = {uid: count * W % total for uid, count in positive}
    bonuses = W - sum(base.values())
    ordered = sorted(
        positive,
        key=lambda row: (-remainder[row[0]], uid_hotkeys[row[0]], row[0]),
    )
    weights = dict(base)
    for uid, _count in ordered[:bonuses]:
        weights[uid] += 1
    uids = tuple(sorted(uid for uid, weight in weights.items() if weight > 0))
    values = tuple(weights[uid] for uid in uids)
    if not uids or sum(values) != W:
        raise DirectValidatorError("zero-burn machine counts did not normalize to u16")
    return uids, values


def escape_blended_vector(
    base_uids: Sequence[int],
    base_weights: Sequence[int],
    escape_units: Sequence[tuple[int, int]],
    fraction: Fraction,
    uid_hotkeys: Mapping[int, str],
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Blend the zero-burn machine vector with escape breaks by ``fraction``.

    Each UID's exact target is ``(1 - f) * base / W + f * units / total`` of
    W. Floors are taken, and the remainder is handed out by largest fractional
    part, then hotkey, then UID, the same order ``zero_burn_vector`` uses, so
    the result is deterministic and sums to W.
    """

    if not isinstance(fraction, Fraction) or not 0 < fraction < 1:
        raise DirectValidatorError("escape fraction must be in (0, 1)")
    if len(base_uids) != len(base_weights) or sum(base_weights) != W:
        raise DirectValidatorError("escape blend needs a normalized base vector")
    total = 0
    seen: set[int] = set()
    for uid, units in escape_units:
        if (
            isinstance(uid, bool)
            or not isinstance(uid, int)
            or not 0 <= uid <= W
            or uid in seen
            or isinstance(units, bool)
            or not isinstance(units, int)
            or units <= 0
            or not isinstance(uid_hotkeys.get(uid), str)
            or not uid_hotkeys[uid]
        ):
            raise DirectValidatorError("escape unit row is invalid")
        seen.add(uid)
        total += units
    if total <= 0:
        raise DirectValidatorError("escape blend has no verified break")
    targets: dict[int, Fraction] = {}
    for uid, weight in zip(base_uids, base_weights, strict=True):
        targets[uid] = targets.get(uid, Fraction(0)) + (1 - fraction) * weight
    for uid, units in escape_units:
        targets[uid] = targets.get(uid, Fraction(0)) + fraction * W * units / total
    base = {uid: int(value) for uid, value in targets.items()}
    remainder = {uid: value - base[uid] for uid, value in targets.items()}
    bonuses = W - sum(base.values())
    ordered = sorted(targets, key=lambda uid: (-remainder[uid], uid_hotkeys[uid], uid))
    for uid in ordered[:bonuses]:
        base[uid] += 1
    uids = tuple(sorted(uid for uid, weight in base.items() if weight > 0))
    values = tuple(base[uid] for uid in uids)
    if not uids or sum(values) != W:
        raise DirectValidatorError("escape blend did not normalize to u16")
    return uids, values


@dataclass(frozen=True)
class FinalizedMetagraphSnapshot:
    """Validator and serving-miner identities read at one finalized head.

    ``netuid`` records the subnet whose metagraph was read, so every later
    step takes it from the snapshot rather than from a module constant.
    """

    block_number: int
    block_hash: str
    validator_uid: int
    validator_hotkey: str
    miners: tuple[ServingAxon, ...]
    skipped_axons: Mapping[str, int]
    netuid: int
    # Every registered hotkey at the anchor, serving or not. Only the escape
    # receipt source reads it (a breaker need not run an axon); it is left out
    # of identity() so journalled anchors stay byte-identical.
    registered_hotkeys: Mapping[str, int] | None = None

    def identity(self) -> dict[str, object]:
        # The netuid is deliberately absent. A plan's identity already binds it
        # through the call kwargs, and leaving the anchor document unchanged
        # keeps every journalled identity and evidence digest for the compiled
        # netuid byte-identical to what earlier releases wrote.
        return {
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "validator": {
                "uid": self.validator_uid,
                "hotkey": self.validator_hotkey,
            },
            "miners": [
                {
                    "uid": miner.uid,
                    "hotkey": miner.hotkey,
                    "ip": miner.ip,
                    "port": miner.port,
                }
                for miner in self.miners
            ],
        }

    def miner_by_uid(self) -> dict[int, ServingAxon]:
        return {miner.uid: miner for miner in self.miners}


@dataclass(frozen=True)
class DirectWeightPlan:
    """Locally derived multi-UID vector and the evidence identity behind it."""

    snapshot: FinalizedMetagraphSnapshot
    qvl_digest: str
    evidence_digest: str
    machine_ids_by_uid: tuple[tuple[int, tuple[str, ...]], ...]
    raw_scores: tuple[tuple[int, int], ...]
    uid_hotkeys: tuple[tuple[int, str], ...]
    wire_uids: tuple[int, ...]
    wire_weights: tuple[int, ...]
    # Escape receipt share. Empty when the source is off or found no break,
    # and then identity() and the vector are exactly the machine-only plan.
    escape_units: tuple[tuple[int, int], ...] = ()
    escape_uid_hotkeys: tuple[tuple[int, str], ...] = ()
    escape_fraction: str = "0"

    @property
    def escape_active(self) -> bool:
        return bool(self.escape_units)

    def expected_vector(self) -> tuple[tuple[int, ...], tuple[int, ...]]:
        """The only vector this plan may sign, recomputed from its inputs."""

        base = zero_burn_vector(self.raw_scores, dict(self.uid_hotkeys))
        if not self.escape_active:
            return base
        hotkeys = dict(self.uid_hotkeys)
        for uid, hotkey in self.escape_uid_hotkeys:
            if hotkeys.setdefault(uid, hotkey) != hotkey:
                raise DirectValidatorError("escape UID hotkey disagrees with the miner row")
        return escape_blended_vector(
            base[0], base[1], self.escape_units, Fraction(self.escape_fraction), hotkeys
        )

    @property
    def netuid(self) -> int:
        """The subnet this vector is for: the one its anchor was read on."""

        return self.snapshot.netuid

    def kwargs(self) -> dict[str, Any]:
        return build_mechanism_weights_kwargs(
            dests=self.wire_uids,
            weights=self.wire_weights,
            netuid=self.netuid,
            expected_netuid=self.netuid,
        )

    def identity(self) -> dict[str, object]:
        document = self._base_identity()
        if self.escape_active:
            document["escape"] = {
                "fraction": self.escape_fraction,
                "units_by_uid": [list(row) for row in self.escape_units],
                "uid_hotkeys": [list(row) for row in self.escape_uid_hotkeys],
            }
        return document

    def _base_identity(self) -> dict[str, object]:
        return {
            "schema": DIRECT_PLAN_SCHEMA,
            "anchor": self.snapshot.identity(),
            "qvl_digest": self.qvl_digest,
            "evidence_digest": self.evidence_digest,
            "machine_ids_by_uid": [
                [uid, list(machine_ids)] for uid, machine_ids in self.machine_ids_by_uid
            ],
            "raw_scores": [list(row) for row in self.raw_scores],
            "uid_hotkeys": [list(row) for row in self.uid_hotkeys],
            "burn_uid": None,
            "burn_weight": 0,
            "call": "SubtensorModule.set_mechanism_weights",
            "kwargs": self.kwargs(),
        }


@dataclass(frozen=True)
class DirectSubmissionReceipt:
    status: str
    attempt_id: str
    extrinsic_hash: str
    block_hash: str | None
    block_number: int | None
    recovered: bool
    confirmation_heads: tuple[tuple[int, str], ...] = ()

    def as_document(self) -> dict[str, object]:
        return {
            "status": self.status,
            "attempt_id": self.attempt_id,
            "extrinsic_hash": self.extrinsic_hash,
            "block_hash": self.block_hash,
            "block_number": self.block_number,
            "recovered": self.recovered,
            "confirmation_heads": [list(row) for row in self.confirmation_heads],
        }


__all__ = [
    "DIRECT_PLAN_SCHEMA",
    "DirectSubmissionReceipt",
    "DirectValidatorError",
    "DirectWeightPlan",
    "FinalizedMetagraphSnapshot",
    "escape_blended_vector",
    "require_netuid",
    "zero_burn_vector",
]
