"""Deterministic raw Compute units for bounded multi-machine UIDs.

The score is exercised work, not capacity:

``raw_uid_units = sum(verified_work_units for each unique admitted machine)``

Every summand is independently re-derived from one canonical SAT witness in
the same scoring window.  Machine count, vCPU, memory, declared slots, uptime,
and attestation alone are absent from the input contract and therefore cannot
create score.  Normalization into the funded Compute allocation happens later
in ``mass_from_units`` exactly as it did for a single machine.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Sequence

from cathedral_thin.independent.compute import (
    require_machine_id,
    require_miner_ss58,
)
from cathedral_thin.independent.constants import (
    MULTICOMPUTE_FLEET_CAP,
    MULTICOMPUTE_MACHINE_WORK_UNIT_CAP,
)
from cathedral_thin.independent.errors import ComputeEvidenceError

from .validator_request import validate_public_worker_endpoint

MAX_MULTICOMPUTE_OBSERVATIONS = 256 * MULTICOMPUTE_FLEET_CAP

REASON_DUPLICATE_ENDPOINT = "duplicate_endpoint"
REASON_DUPLICATE_CHANNEL = "duplicate_channel_identity"
REASON_DUPLICATE_HARDWARE = "duplicate_hardware_identity"
REASON_FLEET_OVER_CAP = "fleet_over_cap"
REASON_STALE_WINDOW = "stale_scoring_window"
REASON_HARDWARE_NOT_VERIFIED = "hardware_not_verified"
REASON_CHANNEL_NOT_BOUND = "channel_not_bound"
REASON_WORK_NOT_VERIFIED = "work_not_verified"
REASON_WORK_OVER_CAP = "work_units_over_machine_cap"


@dataclass(frozen=True)
class MachineWorkObservation:
    """One direct endpoint after evidence and, when admitted, work replay."""

    scoring_window: str
    uid: int
    miner_hotkey: str
    endpoint: str
    channel_id: str | None
    machine_id: str | None
    evidence_fresh: bool
    hardware_verified: bool
    channel_bound: bool
    work_units: int | None


@dataclass(frozen=True)
class MachineScore:
    scoring_window: str
    uid: int
    miner_hotkey: str
    endpoint: str
    channel_id: str | None
    machine_id: str | None
    units: int
    reasons: tuple[str, ...]

    @property
    def paid(self) -> bool:
        return self.units > 0 and not self.reasons


@dataclass(frozen=True)
class MultiComputeScore:
    scoring_window: str
    uid_units: dict[int, int]
    hotkey_units: dict[str, int]
    machines: tuple[MachineScore, ...]


def _require_window(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("0x")
        or len(value) != 66
        or any(character not in "0123456789abcdef" for character in value[2:])
    ):
        raise ComputeEvidenceError(
            "scoring_window must be a 0x-prefixed lowercase block hash"
        )
    return value


def _validate_observation(row: MachineWorkObservation) -> None:
    if not isinstance(row, MachineWorkObservation):
        raise ComputeEvidenceError(
            "multi-machine scoring requires MachineWorkObservation rows"
        )
    _require_window(row.scoring_window)
    if isinstance(row.uid, bool) or not isinstance(row.uid, int) or row.uid < 0:
        raise ComputeEvidenceError("machine observation uid must be non-negative")
    require_miner_ss58(row.miner_hotkey)
    validate_public_worker_endpoint(row.endpoint)
    if row.channel_id is not None:
        require_machine_id(row.channel_id, "channel_id")
    if row.machine_id is not None:
        require_machine_id(row.machine_id)
    if (
        row.evidence_fresh
        and row.hardware_verified
        and row.channel_bound
        and row.machine_id is None
    ):
        raise ComputeEvidenceError(
            "verified hardware observation is missing stable platform identity"
        )
    if row.channel_bound and row.channel_id is None:
        raise ComputeEvidenceError(
            "channel-bound observation is missing its TLS SPKI identity"
        )
    for value, label in (
        (row.evidence_fresh, "evidence_fresh"),
        (row.hardware_verified, "hardware_verified"),
        (row.channel_bound, "channel_bound"),
    ):
        if not isinstance(value, bool):
            raise ComputeEvidenceError(f"{label} must be a boolean")
    if row.work_units is not None and (
        isinstance(row.work_units, bool)
        or not isinstance(row.work_units, int)
        or row.work_units < 0
    ):
        raise ComputeEvidenceError("machine work_units must be non-negative integer")


def duplicate_endpoint_indexes(
    rows: Sequence[MachineWorkObservation],
) -> frozenset[int]:
    """Fresh admitted rows whose endpoint appears more than once.

    A manifest entry alone is not authority to poison an honest endpoint.  The
    duplicate becomes a conflict only after both claimants independently pass
    fresh evidence, assigned-hotkey, and channel-binding verification.
    """

    endpoints = Counter(
        row.endpoint
        for row in rows
        if row.evidence_fresh and row.hardware_verified and row.channel_bound
    )
    return frozenset(
        index
        for index, row in enumerate(rows)
        if row.evidence_fresh
        and row.hardware_verified
        and row.channel_bound
        and endpoints[row.endpoint] > 1
    )


def duplicate_hardware_indexes(
    rows: Sequence[MachineWorkObservation],
) -> frozenset[int]:
    """Admitted rows whose quote-bound identity appears more than once."""

    admitted = Counter(
        row.machine_id
        for row in rows
        if row.evidence_fresh
        and row.hardware_verified
        and row.channel_bound
        and row.machine_id is not None
    )
    return frozenset(
        index
        for index, row in enumerate(rows)
        if row.evidence_fresh
        and row.hardware_verified
        and row.channel_bound
        and row.machine_id is not None
        and admitted[row.machine_id] > 1
    )


def duplicate_channel_indexes(
    rows: Sequence[MachineWorkObservation],
) -> frozenset[int]:
    """Admitted rows presenting one copied TLS channel key."""

    admitted = Counter(
        row.channel_id
        for row in rows
        if row.evidence_fresh
        and row.hardware_verified
        and row.channel_bound
        and row.channel_id is not None
    )
    return frozenset(
        index
        for index, row in enumerate(rows)
        if row.evidence_fresh
        and row.hardware_verified
        and row.channel_bound
        and row.channel_id is not None
        and admitted[row.channel_id] > 1
    )


def aggregate_multicompute_units(
    rows: Sequence[MachineWorkObservation],
    *,
    scoring_window: str,
) -> MultiComputeScore:
    """Aggregate verified units after global endpoint and identity deduplication."""

    window = _require_window(scoring_window)
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise ComputeEvidenceError("machine observations must be a sequence")
    if len(rows) > MAX_MULTICOMPUTE_OBSERVATIONS:
        raise ComputeEvidenceError("machine observation batch exceeds its hard cap")
    observations = tuple(rows)
    for row in observations:
        _validate_observation(row)

    uid_to_hotkey: dict[int, str] = {}
    hotkey_to_uid: dict[str, int] = {}
    fleet_counts: Counter[str] = Counter()
    for row in observations:
        prior_hotkey = uid_to_hotkey.setdefault(row.uid, row.miner_hotkey)
        prior_uid = hotkey_to_uid.setdefault(row.miner_hotkey, row.uid)
        if prior_hotkey != row.miner_hotkey or prior_uid != row.uid:
            raise ComputeEvidenceError(
                "machine observations do not have a one-to-one UID/hotkey mapping"
            )
        fleet_counts[row.miner_hotkey] += 1

    duplicate_endpoints = duplicate_endpoint_indexes(observations)
    duplicate_channels = duplicate_channel_indexes(observations)
    duplicate_hardware = duplicate_hardware_indexes(observations)
    uid_units: defaultdict[int, int] = defaultdict(int)
    hotkey_units: defaultdict[str, int] = defaultdict(int)
    scored: list[MachineScore] = []

    for index, row in enumerate(observations):
        reasons: list[str] = []
        if fleet_counts[row.miner_hotkey] > MULTICOMPUTE_FLEET_CAP:
            reasons.append(REASON_FLEET_OVER_CAP)
        if row.scoring_window != window or not row.evidence_fresh:
            reasons.append(REASON_STALE_WINDOW)
        if index in duplicate_endpoints:
            reasons.append(REASON_DUPLICATE_ENDPOINT)
        if index in duplicate_channels:
            reasons.append(REASON_DUPLICATE_CHANNEL)
        if not row.hardware_verified:
            reasons.append(REASON_HARDWARE_NOT_VERIFIED)
        if not row.channel_bound:
            reasons.append(REASON_CHANNEL_NOT_BOUND)
        if index in duplicate_hardware:
            reasons.append(REASON_DUPLICATE_HARDWARE)
        if row.work_units is None or row.work_units <= 0:
            reasons.append(REASON_WORK_NOT_VERIFIED)
        elif row.work_units > MULTICOMPUTE_MACHINE_WORK_UNIT_CAP:
            reasons.append(REASON_WORK_OVER_CAP)

        unique_reasons = tuple(dict.fromkeys(reasons))
        units = 0 if unique_reasons else int(row.work_units or 0)
        if units:
            uid_units[row.uid] += units
            hotkey_units[row.miner_hotkey] += units
        scored.append(
            MachineScore(
                scoring_window=window,
                uid=row.uid,
                miner_hotkey=row.miner_hotkey,
                endpoint=row.endpoint,
                channel_id=row.channel_id,
                machine_id=row.machine_id,
                units=units,
                reasons=unique_reasons,
            )
        )

    scored.sort(
        key=lambda row: (
            row.uid,
            row.miner_hotkey,
            row.endpoint,
            row.channel_id or "",
            row.machine_id or "",
        )
    )
    return MultiComputeScore(
        scoring_window=window,
        uid_units=dict(sorted(uid_units.items())),
        hotkey_units=dict(sorted(hotkey_units.items())),
        machines=tuple(scored),
    )


__all__ = [
    "MAX_MULTICOMPUTE_OBSERVATIONS",
    "REASON_CHANNEL_NOT_BOUND",
    "REASON_DUPLICATE_CHANNEL",
    "REASON_DUPLICATE_ENDPOINT",
    "REASON_DUPLICATE_HARDWARE",
    "REASON_FLEET_OVER_CAP",
    "REASON_HARDWARE_NOT_VERIFIED",
    "REASON_STALE_WINDOW",
    "REASON_WORK_NOT_VERIFIED",
    "REASON_WORK_OVER_CAP",
    "MachineScore",
    "MachineWorkObservation",
    "MultiComputeScore",
    "aggregate_multicompute_units",
    "duplicate_endpoint_indexes",
    "duplicate_channel_indexes",
    "duplicate_hardware_indexes",
]
