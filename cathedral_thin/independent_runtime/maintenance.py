"""Planned maintenance versus unannounced exit for miner hotels (AB#328).

A miner announces maintenance with a drain notice signed by its SN94 hotkey.
The broker drains the hotel when it receives the notice and stamps
``received_at`` with its own clock (cathedral-sandbox broker/drain_notice.go).

This module decides what that notice is worth. It has no I/O.

* A notice counts only when its signature verifies, it names this network and
  netuid, and it arrived at least ``MIN_DRAIN_NOTICE_SECONDS`` before
  ``drain_at``. Lead time is measured from a trusted ``received_at`` (the
  broker record, or the validator's own first sighting), never from the
  miner's ``issued_at``, which the miner could backdate.
* An accepted notice opens a window ``[drain_at, until)`` for that one hotel.
  Down rounds inside it are excused: they drop out of the availability
  numerator and denominator, so planned maintenance costs nothing.
* Every other down round is an unannounced exit and counts as downtime.

Times are unix seconds.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

SCHEMA = "cathedral_drain_notice_v1"
SIGN_DOMAIN = b"cathedral-drain-notice-v1\x00"
MIN_DRAIN_NOTICE_SECONDS = 24 * 3600
# A notice parked far ahead would hold an excuse open for an outage that may
# never be planned; a window this long would excuse a day of downtime.
MAX_DRAIN_NOTICE_LEAD_SECONDS = 7 * 24 * 3600
MAX_MAINTENANCE_WINDOW_SECONDS = 24 * 3600

PLANNED_MAINTENANCE = "planned_maintenance"
UNANNOUNCED_EXIT = "unannounced_exit"

_BODY_KEYS = frozenset(
    {
        "schema",
        "network",
        "netuid",
        "hotkey",
        "hotel_id",
        "drain_at",
        "until",
        "issued_at",
    }
)
_NOTICE_KEYS = _BODY_KEYS | {"notice_id", "signature"}


class MaintenanceNoticeError(ValueError):
    """A drain notice is malformed, forged, or for another network."""


@dataclass(frozen=True)
class DrainNotice:
    network: str
    netuid: int
    hotkey: str
    hotel_id: str
    drain_at: int
    until: int
    issued_at: int
    notice_id: str


@dataclass(frozen=True)
class MaintenanceWindow:
    hotkey: str
    hotel_id: str
    start: int  # inclusive
    end: int  # exclusive

    def covers(self, hotkey: str, hotel_id: str, at: int) -> bool:
        return (
            self.hotkey == hotkey
            and self.hotel_id == hotel_id
            and self.start <= at < self.end
        )


@dataclass(frozen=True)
class MaintenanceAvailability:
    rounds: int  # rounds that count: every round minus the excused ones
    verified_rounds: int
    excused_rounds: int  # down inside an accepted maintenance window
    unannounced_down_rounds: int  # down with no accepted window: penalized
    bps: int


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def notice_id_for(body: Mapping[str, Any]) -> str:
    unsigned = {k: v for k, v in body.items() if k in _BODY_KEYS}
    return "sha256:" + hashlib.sha256(canonical_json(unsigned)).hexdigest()


def _int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MaintenanceNoticeError(f"{label} must be a non-negative integer")
    return value


def _text(value: Any, label: str, limit: int = 64) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise MaintenanceNoticeError(f"{label} must be a short string")
    return value


def sign_drain_notice(
    keypair: Any,
    *,
    network: str,
    netuid: int,
    hotel_id: str,
    drain_at: int,
    until: int,
    issued_at: int,
) -> dict[str, Any]:
    """Build and sign a notice with the miner's hotkey keypair."""
    body: dict[str, Any] = {
        "schema": SCHEMA,
        "network": network,
        "netuid": netuid,
        "hotkey": keypair.ss58_address,
        "hotel_id": hotel_id,
        "drain_at": drain_at,
        "until": until,
        "issued_at": issued_at,
    }
    notice_id = notice_id_for(body)
    signature = bytes(keypair.sign(SIGN_DOMAIN + notice_id.encode("ascii")))
    return {
        **body,
        "notice_id": notice_id,
        "signature": {
            "algorithm": "sr25519",
            "value_base64": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_drain_notice(
    doc: Mapping[str, Any], *, network: str, netuid: int
) -> DrainNotice:
    if not isinstance(doc, Mapping) or set(doc) != _NOTICE_KEYS:
        raise MaintenanceNoticeError("drain notice fields do not match the schema")
    if doc["schema"] != SCHEMA:
        raise MaintenanceNoticeError("drain notice schema is not supported")
    if doc["network"] != network or doc["netuid"] != netuid:
        raise MaintenanceNoticeError("drain notice is for another network or netuid")
    hotkey = _text(doc["hotkey"], "hotkey")
    hotel_id = _text(doc["hotel_id"], "hotel_id")
    drain_at = _int(doc["drain_at"], "drain_at")
    until = _int(doc["until"], "until")
    issued_at = _int(doc["issued_at"], "issued_at")
    if until <= drain_at:
        raise MaintenanceNoticeError("drain notice until must be after drain_at")
    notice_id = doc["notice_id"]
    if notice_id != notice_id_for(doc):
        raise MaintenanceNoticeError("drain notice id does not match its body")
    sig = doc["signature"]
    if not isinstance(sig, Mapping) or set(sig) != {"algorithm", "value_base64"}:
        raise MaintenanceNoticeError("drain notice signature must be an object")
    if sig["algorithm"] != "sr25519" or not isinstance(sig["value_base64"], str):
        raise MaintenanceNoticeError("drain notice signature must be sr25519")
    try:
        raw = base64.b64decode(sig["value_base64"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MaintenanceNoticeError("drain notice signature is not base64") from exc
    if len(raw) != 64:
        raise MaintenanceNoticeError("drain notice signature must be 64 bytes")
    try:
        from bittensor_wallet import Keypair

        valid = Keypair(ss58_address=hotkey).verify(
            SIGN_DOMAIN + notice_id.encode("ascii"), raw
        )
    except Exception as exc:
        raise MaintenanceNoticeError("drain notice hotkey is invalid") from exc
    if not valid:
        raise MaintenanceNoticeError("drain notice signature does not verify")
    return DrainNotice(
        network=network,
        netuid=netuid,
        hotkey=hotkey,
        hotel_id=hotel_id,
        drain_at=drain_at,
        until=until,
        issued_at=issued_at,
        notice_id=notice_id,
    )


def accepted_window(notice: DrainNotice, received_at: int) -> MaintenanceWindow | None:
    """The excused window, or None when the notice came too late or too early."""
    received_at = _int(received_at, "received_at")
    lead = notice.drain_at - received_at
    if lead < MIN_DRAIN_NOTICE_SECONDS or lead > MAX_DRAIN_NOTICE_LEAD_SECONDS:
        return None
    if notice.until - notice.drain_at > MAX_MAINTENANCE_WINDOW_SECONDS:
        return None
    return MaintenanceWindow(
        notice.hotkey, notice.hotel_id, notice.drain_at, notice.until
    )


def maintenance_windows(
    records: Iterable[Mapping[str, Any]], *, network: str, netuid: int
) -> tuple[MaintenanceWindow, ...]:
    """Accepted windows from broker records ``{"notice": ..., "received_at": ...}``.

    A record that does not verify or came too late gives no window, so the
    outage it meant to cover counts as unannounced.
    """
    windows: list[MaintenanceWindow] = []
    for record in records:
        try:
            notice = verify_drain_notice(
                record["notice"], network=network, netuid=netuid
            )
            window = accepted_window(notice, record["received_at"])
        except (MaintenanceNoticeError, KeyError, TypeError):
            continue
        if window is not None:
            windows.append(window)
    return tuple(windows)


def classify_outage(
    hotkey: str, hotel_id: str, down_at: int, windows: Iterable[MaintenanceWindow]
) -> str:
    if any(w.covers(hotkey, hotel_id, down_at) for w in windows):
        return PLANNED_MAINTENANCE
    return UNANNOUNCED_EXIT


def availability_with_maintenance(
    hotkey: str,
    hotel_id: str,
    rounds: Iterable[tuple[int, bool]],
    windows: Iterable[MaintenanceWindow],
) -> MaintenanceAvailability:
    """Availability of one hotel over ``(observed_at, verified)`` rounds."""
    windows = tuple(windows)
    counted = verified = excused = unannounced = 0
    for observed_at, ok in rounds:
        if ok:
            counted += 1
            verified += 1
        elif (
            classify_outage(hotkey, hotel_id, observed_at, windows)
            == PLANNED_MAINTENANCE
        ):
            excused += 1
        else:
            counted += 1
            unannounced += 1
    bps = 10000 if counted == 0 else verified * 10000 // counted
    return MaintenanceAvailability(counted, verified, excused, unannounced, bps)
