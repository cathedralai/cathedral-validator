"""Signed delivered sealed room-hours per miner hotkey, for the open-season share (#331, AB#319).

The control plane (bigailabs/polariscomputer,
polaris/services/cathedral_delivery_receipts.py, served at
GET /v1/miners/delivery/published) signs one receipt per (miner hotkey, UTC
hour): the sealed customer rooms booked on that miner's verified hotel, each
with the seconds it ran in the hour and the sha256 of the hotel-signed create
receipt that attested it. The receipt shape is the escape feed's: a signed body
plus ``sig``, ``key_id`` and ``signer``, signed by the same pinned contest key
set. ``schema`` keeps the two apart: this module accepts only the delivery
schema and the escape verifier only its own.

This module verifies each receipt, refuses unattested or malformed rooms,
counts each room once per hour, and returns delivered hours per hotkey as
exact fractions: the ``DeliveredHoursFeed`` input of the open-season rule.
Feed errors raise, so a caller that fails open (the open-season rule) leaves
the fleet whole. The direct validator reads it for the compute anchor
(AB#822, ``read_anchor_delivery``): in shadow it only reports, in enforce it
splits the compute lane by delivered room-seconds.

Key rotation: a ``key_id`` must cover the hour's end (the earliest moment the
hour can be signed). The control plane signs on read, so a key added with a
later ``not_before`` refuses older hours; set ``not_before`` at or before the
oldest hour still in the lookback when rotating.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import re
import time
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from cryptography.exceptions import InvalidSignature

from .direct_contract import DELIVERY_FEED_DEFAULT_SOURCE
from .escape_receipts import (
    FEED_TIMEOUT_SECONDS,
    MAX_FEED_BYTES,
    MAX_FEED_RECEIPTS,
    PINNED_CONTEST_SIGNERS,
    PINNED_CONTEST_SIGNERS_SHA256,
    ContestSignerSet,
    EscapeReceiptError,
    _candidate_signers,
    _feed_remaining,
    _fetch_https,
    _require_source,
    canonical_bytes,
    load_receipt_feed,
)

RECEIPT_SCHEMA = "cathedral_delivery_receipt_v0"
WINDOW_SECONDS = 3600
DEFAULT_LOOKBACK_SECONDS = 24 * 3600
MAX_LOOKBACK_SECONDS = 7 * 24 * 3600
# An hour that ends further in the future than this is refused: the control
# plane publishes closed hours only.
MAX_FUTURE_SKEW_SECONDS = 300
MAX_ROOMS_PER_RECEIPT = 4096
MAX_HOTKEY_CHARS = 64
MAX_ROOM_ID_CHARS = 256

_BODY_FIELDS = frozenset(
    {
        "schema",
        "window_id",
        "window_start",
        "window_end",
        "miner_hotkey",
        "room_seconds",
        "rooms",
    }
)
_OUTER_FIELDS = frozenset({"sig", "key_id", "signer"})
_ROOM_FIELDS = frozenset({"room_id", "seconds", "attestation_sha256"})
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class DeliveryReceiptError(EscapeReceiptError):
    """One delivery receipt, or the delivery feed, is refused."""


@dataclass(frozen=True)
class VerifiedDelivery:
    digest: str
    window_id: str
    window_start: int
    window_end: int
    hotkey: str
    rooms: tuple[tuple[str, int], ...]  # (room_id, seconds), sorted by room_id
    key_id: str


def _int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DeliveryReceiptError(f"{label} must be an integer")
    return value


def signed_body(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {name: receipt.get(name) for name in sorted(_BODY_FIELDS)}


def _check_rooms(rows: object) -> tuple[tuple[str, int], ...]:
    if not isinstance(rows, list) or not rows:
        raise DeliveryReceiptError("rooms required")
    if len(rows) > MAX_ROOMS_PER_RECEIPT:
        raise DeliveryReceiptError("too many rooms")
    rooms: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != _ROOM_FIELDS:
            raise DeliveryReceiptError(
                "room must have room_id, seconds, attestation_sha256"
            )
        room_id = row["room_id"]
        if (
            not isinstance(room_id, str)
            or not room_id
            or len(room_id) > MAX_ROOM_ID_CHARS
        ):
            raise DeliveryReceiptError("room_id required")
        attestation = row["attestation_sha256"]
        if not isinstance(attestation, str) or not _SHA256_HEX.fullmatch(attestation):
            raise DeliveryReceiptError("room is not attested")
        seconds = _int(row["seconds"], "room seconds")
        if not 0 < seconds <= WINDOW_SECONDS:
            raise DeliveryReceiptError("room seconds must be in (0, 3600]")
        if room_id in rooms:
            raise DeliveryReceiptError("room listed twice")
        rooms[room_id] = seconds
    return tuple(sorted(rooms.items()))


def verify_delivery_receipt(
    receipt: object,
    *,
    signers: ContestSignerSet | None = None,
) -> VerifiedDelivery:
    """Verify one receipt's shape and its signature against the contest signer set."""

    if not isinstance(receipt, dict):
        raise DeliveryReceiptError("receipt must be an object")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise DeliveryReceiptError("bad delivery receipt schema")
    if set(receipt) - _OUTER_FIELDS != _BODY_FIELDS:
        raise DeliveryReceiptError("delivery receipt fields do not match the schema")
    if receipt.get("signer") != "control_plane":
        raise DeliveryReceiptError("signer must be control_plane")
    start = _int(receipt["window_start"], "window_start")
    end = _int(receipt["window_end"], "window_end")
    if start < 0 or start % WINDOW_SECONDS or end != start + WINDOW_SECONDS:
        raise DeliveryReceiptError("window must be one aligned UTC hour")
    window_id = receipt["window_id"]
    if window_id != f"delivery-{start}":
        raise DeliveryReceiptError("window_id does not name window_start")
    hotkey = receipt["miner_hotkey"]
    if not isinstance(hotkey, str) or not hotkey or len(hotkey) > MAX_HOTKEY_CHARS:
        raise DeliveryReceiptError("miner_hotkey required")
    rooms = _check_rooms(receipt["rooms"])
    if _int(receipt["room_seconds"], "room_seconds") != sum(s for _, s in rooms):
        raise DeliveryReceiptError("room_seconds is not the sum of its rooms")
    sig_b64 = receipt.get("sig")
    if not isinstance(sig_b64, str) or not sig_b64:
        raise DeliveryReceiptError("sig required")
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DeliveryReceiptError("sig is not valid base64") from exc
    body = canonical_bytes(signed_body(receipt))
    matched = None
    for key in _candidate_signers(
        receipt,
        signers=PINNED_CONTEST_SIGNERS if signers is None else signers,
        planted_at=float(end),
    ):
        try:
            key.public_key.verify(sig, body)
        except InvalidSignature:
            continue
        matched = key
        break
    if matched is None:
        raise DeliveryReceiptError("delivery signature rejected (non-pinned key)")
    return VerifiedDelivery(
        digest="sha256:" + hashlib.sha256(body).hexdigest(),
        window_id=window_id,
        window_start=start,
        window_end=end,
        hotkey=hotkey,
        rooms=rooms,
        key_id=matched.key_id,
    )


@dataclass(frozen=True)
class DeliveryRound:
    """Verified, deduplicated, in-lookback delivered hours for one cycle."""

    hours_by_hotkey: Mapping[str, Fraction]
    accepted_digests: tuple[str, ...]
    refused: Mapping[str, int] = field(default_factory=dict)
    signer_set_sha256: str = ""

    def evidence(self) -> dict[str, object]:
        return {
            "schema": "cathedral_delivery_receipts_v1",
            "signer_set_sha256": self.signer_set_sha256
            or PINNED_CONTEST_SIGNERS_SHA256,
            "accepted_digests": list(self.accepted_digests),
            "hours_by_hotkey": {
                hotkey: str(hours)
                for hotkey, hours in sorted(self.hours_by_hotkey.items())
            },
        }


def score_delivered_hours(
    receipts: Iterable[object],
    *,
    now: float,
    lookback_seconds: int = DEFAULT_LOOKBACK_SECONDS,
    signers: ContestSignerSet | None = None,
) -> DeliveryRound:
    """Delivered hours per hotkey from hours that ended within the lookback.

    A malformed or unverified receipt is skipped and counted, never fatal. The
    same signed body twice counts once (``replay``); a second receipt for one
    (hour, hotkey) is refused (``duplicate_window``); a room already counted in
    an hour under another receipt is dropped from the later one
    (``duplicate_room``). Order: hour, then digest.
    """

    if not math.isfinite(now):
        raise DeliveryReceiptError("now must be finite")
    if not 0 < lookback_seconds <= MAX_LOOKBACK_SECONDS:
        raise DeliveryReceiptError("lookback must be in (0, 7 days]")
    refused: dict[str, int] = {}

    def refuse(reason: str, count: int = 1) -> None:
        refused[reason] = refused.get(reason, 0) + count

    verified: list[VerifiedDelivery] = []
    for receipt in receipts:
        try:
            verified.append(verify_delivery_receipt(receipt, signers=signers))
        except DeliveryReceiptError as exc:
            refuse("unattested_room" if "not attested" in str(exc) else "invalid")
        except EscapeReceiptError:
            refuse("invalid")  # key id rules from the shared signer set
        except (OverflowError, ValueError, TypeError, UnicodeError):
            refuse("invalid")
    verified.sort(key=lambda item: (item.window_start, item.digest))

    seen_digests: set[str] = set()
    seen_windows: set[tuple[int, str]] = set()
    seen_rooms: set[tuple[int, str]] = set()
    seconds_by_hotkey: dict[str, int] = {}
    accepted: list[str] = []
    for item in verified:
        if item.digest in seen_digests:
            refuse("replay")
            continue
        seen_digests.add(item.digest)
        if item.window_end > now + MAX_FUTURE_SKEW_SECONDS:
            refuse("future")
            continue
        if now - item.window_end > lookback_seconds:
            refuse("expired")
            continue
        if (item.window_start, item.hotkey) in seen_windows:
            refuse("duplicate_window")
            continue
        seen_windows.add((item.window_start, item.hotkey))
        counted = 0
        for room_id, seconds in item.rooms:
            if (item.window_start, room_id) in seen_rooms:
                refuse("duplicate_room")
                continue
            seen_rooms.add((item.window_start, room_id))
            counted += seconds
        if counted:
            seconds_by_hotkey[item.hotkey] = (
                seconds_by_hotkey.get(item.hotkey, 0) + counted
            )
        accepted.append(item.digest)
    return DeliveryRound(
        hours_by_hotkey={
            hotkey: Fraction(seconds, WINDOW_SECONDS)
            for hotkey, seconds in sorted(seconds_by_hotkey.items())
        },
        accepted_digests=tuple(accepted),
        refused=refused,
        signer_set_sha256=(
            PINNED_CONTEST_SIGNERS_SHA256 if signers is None else signers.source_sha256
        ),
    )


def delivered_hours_feed(
    source: str,
    *,
    lookback_seconds: int = DEFAULT_LOOKBACK_SECONDS,
    signers: ContestSignerSet | None = None,
    fetch: Callable[[str], bytes] | None = None,
    clock: Callable[[], float] = time.time,
    timeout: float = FEED_TIMEOUT_SECONDS,
) -> Callable[[], Mapping[str, Fraction]]:
    """A zero-argument feed of delivered hours per hotkey (the open-season ``DeliveredHoursFeed``).

    ``source`` is an https URL or an absolute path, read as the escape feed is
    (``{"receipts": [...]}``, same size, count and time limits). A feed that
    cannot be read raises; single bad receipts are skipped.
    """

    def feed() -> Mapping[str, Fraction]:
        receipts = load_receipt_feed(source, fetch=fetch, timeout=timeout)
        return score_delivered_hours(
            receipts,
            now=clock(),
            lookback_seconds=lookback_seconds,
            signers=signers,
        ).hours_by_hotkey

    return feed


# The compute anchor (AB#822) ---------------------------------------------

DELIVERY_RECEIPTS_SOURCE_ENV = "CATHEDRAL_DELIVERY_RECEIPTS_SOURCE"
# The anchor reads only hours that closed at least this long before the cycle
# clock. The control plane settles an hour 10 minutes after it closes.
ANCHOR_SETTLE_SECONDS = 15 * 60
ANCHOR_LOOKBACK_SECONDS = DEFAULT_LOOKBACK_SECONDS


def delivery_source_from_environment(
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """The delivery feed the compute anchor reads, or None when disabled.

    Unset means the release default, so validators without an operator file
    still read the feed. An explicit ``off`` or an empty value disables the
    read. Any other value must be an https URL or an absolute path, or this
    raises, so a mistyped source refuses at start instead of reading nothing.
    """

    env = os.environ if environ is None else environ
    if DELIVERY_RECEIPTS_SOURCE_ENV not in env:
        return DELIVERY_FEED_DEFAULT_SOURCE
    source = env[DELIVERY_RECEIPTS_SOURCE_ENV].strip()
    if not source or source.lower() == "off":
        return None
    _require_source(source)
    return source


def anchor_lookback(clock: float) -> tuple[int, int]:
    """``(since, until)``: the 24 whole UTC hours the anchor pays for.

    ``until`` is the end of the last hour that closed at least
    ``ANCHOR_SETTLE_SECONDS`` before ``clock``.
    """

    if not math.isfinite(clock) or clock < 0:
        raise DeliveryReceiptError("anchor clock must be finite")
    until = (
        (math.floor(clock) - ANCHOR_SETTLE_SECONDS) // WINDOW_SECONDS * WINDOW_SECONDS
    )
    since = until - ANCHOR_LOOKBACK_SECONDS
    if since < 0:
        raise DeliveryReceiptError("anchor clock is before the first lookback")
    return since, until


def room_seconds(hours: Fraction) -> int:
    """Exact integer room-seconds from delivered hours (receipts are whole seconds)."""

    seconds = Fraction(hours) * WINDOW_SECONDS
    if seconds.denominator != 1 or seconds < 0:
        raise DeliveryReceiptError("delivered hours are not whole room-seconds")
    return int(seconds)


@dataclass(frozen=True)
class AnchorDelivery:
    """Delivered room-seconds per hotkey over one anchor lookback."""

    since: int
    until: int
    seconds_by_hotkey: Mapping[str, int]
    delivery_round: DeliveryRound
    body_bytes: int


def read_anchor_delivery(
    source: str,
    *,
    clock: float,
    timeout: float,
    fetch: Callable[[str], bytes] | None = None,
    signers: ContestSignerSet | None = None,
) -> AnchorDelivery:
    """Read, verify and score the delivery feed for one cycle's lookback.

    ``since`` and ``until`` are sent explicitly and scoring runs with
    ``now = until``, so the oldest hour of the range is never refused as
    expired. Any read failure raises: the caller treats it as a feed error.
    A read that hit the receipt ceiling raises too, since it may be partial.
    """

    since, until = anchor_lookback(clock)
    if not math.isfinite(timeout) or timeout <= 0:
        raise DeliveryReceiptError("delivery feed timeout is invalid")
    deadline = time.monotonic() + timeout
    body_bytes = 0

    def counted(url: str) -> bytes:
        nonlocal body_bytes
        raw = (
            fetch(url)
            if fetch is not None
            else _fetch_https(
                url, timeout=min(FEED_TIMEOUT_SECONDS, _feed_remaining(deadline))
            )
        )
        body_bytes += len(raw)
        return raw

    receipts = load_receipt_feed(
        source,
        fetch=counted,
        timeout=timeout,
        since=since,
        until=until,
    )
    if not source.startswith("https://"):
        body_bytes = min(Path(source).stat().st_size, MAX_FEED_BYTES)
    if len(receipts) >= MAX_FEED_RECEIPTS:
        raise DeliveryReceiptError("delivery feed reached the receipt ceiling")
    # With now = until, the oldest hour of [since, until) ended
    # ANCHOR_LOOKBACK_SECONDS - WINDOW_SECONDS before now, so it is kept, and
    # an hour before since (ended a full lookback ago) is expired: exactly 24
    # hours count even if the feed answers a wider range.
    delivery_round = score_delivered_hours(
        receipts,
        now=float(until),
        lookback_seconds=ANCHOR_LOOKBACK_SECONDS - WINDOW_SECONDS,
        signers=signers,
    )
    return AnchorDelivery(
        since=since,
        until=until,
        seconds_by_hotkey={
            hotkey: room_seconds(hours)
            for hotkey, hours in sorted(delivery_round.hours_by_hotkey.items())
        },
        delivery_round=delivery_round,
        body_bytes=body_bytes,
    )


__all__ = [
    "ANCHOR_LOOKBACK_SECONDS",
    "ANCHOR_SETTLE_SECONDS",
    "DELIVERY_RECEIPTS_SOURCE_ENV",
    "AnchorDelivery",
    "anchor_lookback",
    "delivery_source_from_environment",
    "read_anchor_delivery",
    "room_seconds",
    "DEFAULT_LOOKBACK_SECONDS",
    "MAX_LOOKBACK_SECONDS",
    "RECEIPT_SCHEMA",
    "WINDOW_SECONDS",
    "DeliveryReceiptError",
    "DeliveryRound",
    "VerifiedDelivery",
    "delivered_hours_feed",
    "score_delivered_hours",
    "signed_body",
    "verify_delivery_receipt",
]
