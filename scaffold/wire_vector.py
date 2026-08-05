"""Signed weight-vector wire helpers shared by the orchestrator and the
validator — canonical bytes, signature verify, structural invariants.

Dependency-light by design: stdlib + cryptography only, no FastAPI, no store,
no bittensor. A validator install imports this; it must not drag in the
publisher's server dependencies. The orchestrator's
``scaffold.publisher.weights`` re-exports these so its callers and the gates
keep one import surface.
"""

from __future__ import annotations

import base64
import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

MAX_VECTOR_ENTRIES = 8192
MAX_VECTOR_LIFETIME_SECONDS = 3600.0
MAX_VECTOR_FUTURE_SKEW_SECONDS = 120.0
_UTC_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3}|\.\d{6})Z$"
)

# Smallest host-versus-publisher offset worth naming as a clock fault. The HTTP
# ``Date`` header has one-second granularity and the reading also absorbs the
# request round trip, so a smaller number is measurement noise. Printing it
# would be inventing a figure the operator cannot act on.
MIN_REPORTABLE_CLOCK_SKEW_SECONDS = 5.0

# Longest ``Date:`` header this will even attempt to parse. It is unvalidated
# bytes off the wire, so a broken or hostile publisher does not get to grow a
# refusal message.
_MAX_DATE_HEADER_CHARS = 128

# The exact key set of the v3 allocation contract's CyberGym lane, carried on
# the wire as ``policy_metadata["cybergym_lane"]``.
#
# This lives here, in the module both sides already import, because the lane's
# SHAPE is a wire contract rather than a judgment: the orchestrator
# (``scaffold.publisher.weights._compose_cybergym_lane_v3``) emits it and the
# validator (``scaffold.validator_thin``) admits it by exact-set equality, so a
# field added on one side and not the other rejects every vector for the whole
# epoch. Stating the set once means that class of drift cannot be introduced by
# editing a single file.
#
# Note what is deliberately NOT shared: the validator still re-derives every
# VALUE independently — lane mass, the burn UID against this tick's metagraph,
# and the UID-to-hotkey bindings that stop a recycled UID from being paid. The
# publisher is trusted for the shape of the envelope and for nothing inside it.
V3_CYBERGYM_LANE_FIELDS = frozenset(
    {
        "fraction",
        "weights",
        "contributing_fraction",
        "forfeited_fraction",
        "burn_uid",
        "uid_hotkeys",
        "cybergym",
    }
)


class VectorError(Exception):
    """Signature, key-id, or structural-invariant check failed."""


@dataclass(frozen=True)
class PublisherClock:
    """One reading of the publisher's HTTP ``Date:`` response header, paired
    with what the host clock said at the instant that header arrived.

    DIAGNOSTIC ONLY, AND DELIBERATELY SO. NEVER PROMOTE THIS INTO A CHECK.

    This value is unauthenticated: it is not signed, it is not covered by the
    vector's Ed25519 signature, and anyone who can answer the HTTP request can
    put any instant in it. It exists for exactly one purpose — writing the text
    of a refusal that has ALREADY been decided by the host clock alone — and
    nothing downstream of it may read it for any other reason.

    Concretely, it must never be used to derive ``now_iso``, to widen or relax
    ``MAX_VECTOR_FUTURE_SKEW_SECONDS``, to decide whether ``expires_at`` has
    passed, to correct the host clock, or to let a vector through that the host
    clock rejected. Doing any of those would hand the freshness gate — the
    thing that stops a replayed or stale weight vector from reaching the chain
    — to whoever serves the response. A refusal explained badly is an operator
    inconvenience; a refusal decided by the publisher is a security hole.
    """

    #: Raw header text as received. Unvalidated; parsed defensively below.
    date_header: str
    #: The host clock at the moment the header was read. This is the thing
    #: being diagnosed, not a correction applied to it.
    observed_at: datetime


def clock_skew_hint(publisher_clock: PublisherClock | None) -> str:
    """Return a trailing clause explaining a freshness refusal in terms of the
    HOST clock, or ``""`` when there is nothing trustworthy to say.

    Empty is always the safe answer, and it is what comes back whenever the
    fetch never happened (offline runs, a cached vector, a stubbed fetch), the
    publisher sent no ``Date:`` header, the header did not parse, or the
    measured offset is inside the noise floor. In every one of those cases the
    caller's existing message stands exactly as it does today.

    This function never raises and never influences whether a vector is
    refused. It only decides what the operator gets to read afterwards.
    """
    if publisher_clock is None:
        return ""
    header = publisher_clock.date_header
    if not isinstance(header, str) or not 0 < len(header) <= _MAX_DATE_HEADER_CHARS:
        return ""
    observed = publisher_clock.observed_at
    if not isinstance(observed, datetime) or observed.tzinfo is None:
        return ""
    # Everything that touches the header stays inside one guard, including the
    # rendering. A well-formed date at the edge of the representable range
    # (``31 Dec 9999 ... -1400``) overflows on conversion to UTC, and an
    # explanation that raised would replace a clean refusal with a crash — a
    # different exception, a different exit path. Diagnosis never gets to do
    # that: anything unexpected here means no hint, and today's message stands.
    try:
        published = parsedate_to_datetime(header)
        if published is None:
            return ""
        if published.tzinfo is None:
            # RFC 5322 "-0000" means "no timezone stated"; HTTP dates are GMT.
            published = published.replace(tzinfo=UTC)
        offset = (observed - published).total_seconds()
        if not math.isfinite(offset):
            return ""
        # The parsed value is re-rendered rather than echoed, so no unvalidated
        # header bytes are ever interpolated into an operator-facing message.
        stamp = published.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:  # noqa: BLE001 - unvalidated wire input; silence is fine
        return ""
    if abs(offset) < MIN_REPORTABLE_CLOCK_SKEW_SECONDS:
        return (
            f"; your host clock matches the publisher's (its Date: header "
            f"says {stamp}), so this is not host clock skew"
        )
    direction = "BEHIND" if offset < 0 else "AHEAD OF"
    return (
        f"; your host clock is {abs(offset):.0f}s {direction} the publisher's "
        f"(its Date: header says {stamp}); check NTP/chrony"
    )


def _parse_canonical_utc(value: Any, *, field: str) -> datetime:
    """Parse the feed's bounded canonical UTC timestamp representation."""
    if not isinstance(value, str) or _UTC_TIMESTAMP_RE.fullmatch(value) is None:
        raise VectorError(f"{field} must be canonical UTC (YYYY-MM-DDTHH:MM:SS.sssZ)")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise VectorError(f"{field} is not a valid timestamp") from exc
    if parsed.tzinfo != UTC:
        raise VectorError(f"{field} must be UTC")
    return parsed


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Drop ``signature``, sort keys, no whitespace, UTF-8 — must stay
    byte-identical to ``cathedral.policy.signing.canonical_bytes`` so the
    deployed validator and this one verify the same emission."""
    body = {k: v for k, v in payload.items() if k != "signature"}
    try:
        return json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise VectorError("vector cannot be encoded as finite canonical JSON") from exc


def verify_signature(
    payload: dict[str, Any], *, public_key_hex: str, expected_key_id: str
) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    sig_b64 = payload.get("signature") or ""
    if not str(sig_b64).strip():
        raise VectorError("vector is missing signature")
    if payload.get("key_id") != expected_key_id:
        raise VectorError(
            f"key_id mismatch: vector={payload.get('key_id')!r}, pinned={expected_key_id!r}"
        )
    try:
        sig = base64.b64decode(str(sig_b64).encode("ascii"), validate=True)
    except Exception as e:
        raise VectorError(f"signature is not valid base64: {e}") from e
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex.strip()))
    try:
        pk.verify(sig, canonical_bytes(payload))
    except InvalidSignature as e:
        raise VectorError("ed25519 signature verify failed") from e


def invariant_check(
    payload: dict[str, Any],
    *,
    network: str,
    netuid: int,
    now_iso: str,
    publisher_clock: PublisherClock | None = None,
) -> None:
    """Structural sanity — mirrors the deployed validator's checks.

    ``publisher_clock`` is optional and purely explanatory. Every decision
    below is made against ``now_iso`` — the host clock — exactly as before;
    the observation is read only after a freshness check has already failed,
    to name the host clock as the likely cause instead of leaving the operator
    to conclude the feed is broken. Passing it, omitting it, or passing a
    garbage header cannot change which vectors are accepted.
    """
    weights = payload.get("weights") or []
    snap = payload.get("burn_snapshot") or {}
    b_uid = snap.get("burn_uid")
    b_hotkey = snap.get("burn_hotkey")
    b_pct = float(snap.get("forced_burn_percentage", -1))
    if len(weights) > MAX_VECTOR_ENTRIES:
        raise VectorError(f"weights vector exceeds {MAX_VECTOR_ENTRIES}")
    if not 0.0 <= b_pct <= 100.0:
        raise VectorError(f"forced_burn_percentage out of range: {b_pct!r}")
    if b_hotkey is not None and (
        not isinstance(b_hotkey, str) or not 1 <= len(b_hotkey) <= 128
    ):
        raise VectorError("burn_hotkey must be a non-empty bounded string")
    if b_pct > 0.0 and b_uid is None and b_hotkey is None:
        raise VectorError("forced_burn_percentage requires a burn destination")
    total = 0.0
    for w in weights:
        v = float(w["weight"])
        if not math.isfinite(v) or v < 0:
            raise VectorError(f"bad weight for {w.get('miner_hotkey')!r}: {v!r}")
        total += v
    if total <= 0 and b_uid is None and b_hotkey is None:
        raise VectorError("empty/zero-sum weights without burn fallback")
    if payload.get("network") != network:
        raise VectorError(
            f"network mismatch: {payload.get('network')!r} != {network!r}"
        )
    if int(payload.get("netuid", -1)) != netuid:
        raise VectorError(f"netuid mismatch: {payload.get('netuid')!r} != {netuid!r}")
    generated_at = _parse_canonical_utc(
        payload.get("generated_at"), field="generated_at"
    )
    expires_at = _parse_canonical_utc(payload.get("expires_at"), field="expires_at")
    now = _parse_canonical_utc(now_iso, field="validator now")
    if expires_at <= generated_at:
        raise VectorError("expires_at must be after generated_at")
    lifetime = (expires_at - generated_at).total_seconds()
    if lifetime > MAX_VECTOR_LIFETIME_SECONDS:
        raise VectorError(
            f"vector lifetime {lifetime:.0f}s exceeds "
            f"{MAX_VECTOR_LIFETIME_SECONDS:.0f}s"
        )
    # Both freshness bounds below are decided against `now` (the host clock)
    # and nothing else. `clock_skew_hint` runs only on the raise path, after
    # the refusal is settled, and can only append explanatory text.
    future_skew = (generated_at - now).total_seconds()
    if future_skew > MAX_VECTOR_FUTURE_SKEW_SECONDS:
        raise VectorError(
            f"generated_at is {future_skew:.0f}s in the future; "
            f"maximum skew is {MAX_VECTOR_FUTURE_SKEW_SECONDS:.0f}s"
            + clock_skew_hint(publisher_clock)
        )
    if expires_at <= now:
        raise VectorError(
            f"vector expired at {payload.get('expires_at')!r}"
            + clock_skew_hint(publisher_clock)
        )
