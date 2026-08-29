"""The thin v4 validator — the WHOLE validator, ~200 lines.

    fetch signed scores from the orchestrator
    -> verify Ed25519 signature against the pinned key
    -> sanity-check (finite, nonnegative, fresh, right subnet, no rollback)
    -> apply burn FROM THE SAME SIGNED PAYLOAD
    -> map hotkeys to uids against the live metagraph
    -> set weights

No local row database. No backfill. No rolling window. No score buckets.
Every scoring decision (recency, multi-lane composition, burn) lives
orchestrator-side and changes WITHOUT a validator release; this binary only
enforces that what it applies is exactly what the pinned key signed.

Run:  python -m scaffold.validator_thin --publisher-url https://api.cathedral.computer \
          --public-key-hex <pinned hex> [--once] [--broadcast]

Dry-run by default (computes + prints the uid vector, does not submit).
Rollback fence state persists in a small JSON file (--state-file), so a
publisher cannot re-serve an older policy_version after a restart.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import sys
import threading
import time
import zlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from bittensor.utils import get_mechid_storage_index

from . import render
from . import wire_vector as wire
from .chain import CHAIN_ENDPOINT_ENV, connection_target
from .events import (
    FAIL,
    INFO,
    NOT_PROVEN,
    PASS,
    EventLogger,
    EventLogPathError,
    stable_error,
)
from .provenance_audit import (
    ASSURANCE_RANKS,
    MECHANISM_DEFAULT,
    ProvenanceSettings,
    assurance_rank,
    run_audit,
)

# Cathedral's published weight-policy signing key (kid: cathedral-weight-policy).
# This is a PUBLIC verification key — shipping it as the default means operators
# don't have to pin it by hand; the validator still applies only what this key
# signed. Verify it any time against
# https://api.cathedral.computer/.well-known/cathedral-jwks.json
# Override with --public-key-hex or CATHEDRAL_WEIGHT_POLICY_PUBLIC_KEY.
DEFAULT_PUBLIC_KEY_HEX = (
    "10890a66aa752479cb3b634f366d7bd27c374324d83f88d2d6b69ab066f25e26"
)

FINNEY_GENESIS_HASH = (
    "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"
)

# Every trust-bearing field in the supported SN39 profile is immutable in the
# release, not merely a convenient config default.
SN39_PUBLISHER_URL = "https://api.cathedral.computer"
SN39_EVIDENCE_URL = "https://api.cathedral.computer/v1/evidence"
SN39_WEIGHT_POLICY_KEY_ID = "cathedral-weight-policy"
SN39_REGISTRY_KEYS_DIGEST = (
    "sha256:5fb8f00cd2541606927373f596c2ba77d4ce485df0539f4afd5091858af48512"
)
SN39_REPORT_KEYS_DIGEST = (
    "sha256:30e438fff5b0508402b233eb5eec590a834882801a552edbbf7e62e45cf98c70"
)
SN39_INDEX_KEYS_DIGEST = (
    "sha256:1e35b9ce36b3da3362a88feb93dfa90f1fe03ab7c42e902b13ac3789324f7611"
)
SN39_VERIFIER_DIGEST = (
    "sha256:8292b085e4dbe228f8ffd2ec7046a1c0f1324ff5e7a29d1574ce16963f9b098f"
)
SN39_PRODUCER_REVISION = "26ebdbb885746f1835ea67ff314e384b4838560f"
# The burn destination must be the LIVE SN39 subnet owner. The broadcast path
# refuses to sign when this hotkey is not the owner on the finalized head
# ("requires the pinned burn hotkey to remain the live subnet owner"), which is
# deliberate: a stale pin would keep paying an address the subnet has moved off.
#
# The cost of that safety is that an on-chain owner change stops the writer until
# this pin, the relay config's `burn_hotkey`, and the publisher's
# CATHEDRAL_WEIGHT_POLICY_BURN_HOTKEY are moved together. Moving only this one
# swaps the failure for "signed vector burn destination is not the pinned burn
# hotkey"; all three are one change, not three.
#
# 2026-08-14: owner moved 5G3qVaXz... (uid 204) -> 5GP7c3fF... (uid 136).
SN39_BURN_HOTKEY = "5GP7c3fFazW9GXK8Up3qgu2DJBk8inu4aK9TZy3RuoSWVCMi"
SN39_STATE_FILE = Path("/var/lib/cathedral-validator/thin-state.json")
SN39_LAUNCH_CONTROLLED_DIR = Path(
    "/var/lib/cathedral-validator-controlled-sn39/current"
)
SN39_LAUNCH_VERIFIER_BINARY = Path("/opt/cathedral-sn39/bin/cathedral-tdx-verifier")
SN39_LAUNCH_APPROVAL_FILE = Path("/etc/cathedral-validator/sn39-launch-approval.json")
SN39_LAUNCH_APPROVAL_SCHEMA = "cathedral_sn39_launch_approval_v1"
SN39_LAUNCH_APPROVAL_LIFETIME_BLOCKS = 64
SN39_LAUNCH_APPROVAL_MAX_BYTES = 256 * 1024
SN39_LAUNCH_APPROVAL_OWNER_UID = 0
SN39_RELEASE_SHA_ENV = "CATHEDRAL_SN39_RELEASE_SHA"
SN39_LAUNCH_CONFIG_DIGEST_ENV = "CATHEDRAL_SN39_LAUNCH_CONFIG_SHA256"
SN39_UID30_LAUNCH_SCHEMA = "cathedral_sn39_uid30_launch_preview_v1"
SN39_UID30_LAUNCH_POLICY = "uid30_single_verified_miner_100_v1"
SN39_UID30_LAUNCH_VALIDATOR_UID = 30
SN39_UID30_LAUNCH_VALIDATOR_HOTKEY = (
    "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"  # pragma: allowlist secret
)
SN39_UID30_LAUNCH_MINER_HOTKEY = (
    "5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G"  # pragma: allowlist secret
)
SN39_UID30_LAUNCH_VERSION_KEY = 10005000
SN39_UID30_SUCCESSOR_SCHEMA = "cathedral_sn39_uid30_two_miner_successor_preview_v1"
SN39_UID30_SUCCESSOR_POLICY = "uid30_two_verified_miners_equal_v1"
SN39_UID30_SUCCESSOR_SECOND_HOTKEY = (
    "5Ct2DBJPULeQxGmFiKrpGvvWuYVxgYEX8tRfNjWYRga8VRbq"  # pragma: allowlist secret
)
SN39_UID30_SUCCESSOR_PREDECESSOR_ID = (
    "sha256:5aefc31742136b72c9bee64ae30909bdc4d3c2cee5be17b2ba3e54a67d90b213"
)
SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256 = (
    "700812f931a8c5c26bf35644e93a90c4ba4b15c5125ab22a231211777e647285"
)
SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_IDENTITY = (
    "193d0fdd303bb233a1e48265a8f6db8eca6fcd573354dd4d083166ea7dcd6f63"
)
SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME = (
    "journal-193d0fdd303bb233a1e48265a8f6db8eca6fcd573354dd4d083166ea7dcd6f63.json"
)
SN39_UID30_SUCCESSOR_PREDECESSOR_IDENTITY_SHA256 = (
    "7468d075545c3e42b23ece3233a7f338e5b764a6e599dfbbf0aa965998ed7132"
)
SN39_UID30_SUCCESSOR_PREDECESSOR_INTENT_SHA256 = (
    "967087a13d3442af89b9a833e8a79f1fdb002c2b8971ce1d9b0324222f913810"
)
SN39_UID30_SUCCESSOR_PREDECESSOR_RECEIPT_SHA256 = (
    "704812ccd9660b73b7e473f12cfa5e1335cf83b22abe992dc893e82b72a0309e"
)
SN39_UID30_SUCCESSOR_PREDECESSOR_UID_SAFETY_SHA256 = (
    "952546f8ba03112e559d728559f7fdd41bf5c6d4e8487ffe71b07d5b6f326bbd"
)
SN39_UID30_SUCCESSOR_QVL_SHA256 = (
    "35bb55f89f411d5dcf5f72be90488e999ee68c41dfc0429a0dcb8cc2b448b6bb"
)
SN39_UID30_SUCCESSOR_SAT_RULE = "sat_work_units_v1"
SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH = (
    "0x7dad84c0323a0e2c79ca5d6f55f9b6689c26a64c99ff10ab67bb7024697ef94b"
)
SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH = (
    "0x65d5d3cd210f98f4509afd619f906fee516e4f28ab4d6e08df6f04c953ce7849"
)
SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK = 8_945_370
SN39_UID30_SUCCESSOR_PREDECESSOR_SOURCE_EPOCH = 8_945_366
SN39_UID30_SUCCESSOR_PREDECESSOR_UID = 124
SN39_UID30_SUCCESSOR_ROLLBACK_MAX_BYTES = 1_048_576
SN39_UID30_SUCCESSOR_ROLLBACK_B64_MAX_BYTES = 262_144
# The one reviewed UID30 launch performs a complete finalized-state and TDX
# revalidation immediately before signing.  That read is slightly longer than
# one Finney block, so requiring the finalized head to remain byte-for-byte
# unchanged makes the safe signer lose a deterministic race.  The launch-only
# path may advance by at most two finalized blocks, leaving fourteen blocks of
# its pinned 16-block mortal era.  Every recurring and generic writer retains
# the exact-head rule.
SN39_UID30_LAUNCH_MAX_FINALIZED_DRIFT_BLOCKS = 2


class _RetryablePreSignHeadDrift(wire.VectorError):
    """The proven head changed before any signed intent or broadcast existed."""


class _PendingReceiptNotProven(wire.VectorError):
    """A signed attempt may have finalized, but archive proof is unavailable.

    ``fenced_attempt`` records whether the durable journal actually named a
    signed attempt before this was raised. Every raise that happens after the
    journal named one leaves it true, which is the default and the historical
    behaviour. The failures that happen BEFORE the journal is opened at all —
    chain preflight, most of which are ordinary configuration faults — set it
    false.

    The distinction is reporting-only: both cases still exit nonzero, still
    refuse a replacement write, and still leave restart recovery as the only
    way forward. It exists because the surfaced remediation "the exact signed
    attempt remains fenced" is a claim about durable state, and repeating it
    when no attempt was ever recorded sends an operator hunting for a
    transaction that does not exist.
    """

    def __init__(self, message: str, *, fenced_attempt: bool = True) -> None:
        super().__init__(message)
        self.fenced_attempt = bool(fenced_attempt)


class _PostSignedSubmissionMismatch(wire.VectorError):
    """A signed attempt has a positive receipt or execution contradiction."""


class _ChainWeightCooldownActive(wire.VectorError):
    """The chain itself forbids this validator's next weight write for now.

    `weights_rate_limit` is a subnet parameter and the tick interval is a
    local one, so the two are not synchronized: any tick that lands sooner
    than the subnet's cooldown — typically the one right after a recovered
    write — is refused by the runtime before anything is signed. That is the
    chain working as designed, not a fault, so it is reported as a skip with
    the exact block at which the next write becomes possible. The strict gate
    in `_require_inclusion_policy_ready` is unchanged and still owns every
    case this pre-check cannot positively prove."""


class _EpochRoomUnavailable(wire.VectorError):
    """This tick landed too near the epoch boundary to prove mortal inclusion.

    A submission needs the mortal era plus the finality margin to still be
    inside the epoch it was composed against. A tick that starts with fewer
    blocks than that left is refused before anything is reserved or signed,
    and the very next tick — after the boundary passes — has a whole epoch of
    room. The refusal names the block at which it clears, so it is a schedule
    fact with a known expiry, not a verdict on this validator.

    It is deliberately NOT a sibling of the other five epoch refusals
    `_require_inclusion_policy_ready` raises. "The chain's epoch arithmetic is
    inconsistent" and "the signed vector was composed against a different
    epoch" never clear on their own and need a human; only this one does
    nothing but wait. Reporting them under one code and one status is what
    made an operator's alert filter choose between paging on routine waits and
    muting genuine blockers.

    The class is only about REPORTING. Every caller still refuses exactly the
    same ticks, and the one call site that runs after a durable attempt has
    been reserved re-raises it as a plain refusal, because there the same
    sentence describes a tick that must be resolved through the journal."""


class _SubmissionFenceRefused(wire.VectorError):
    """The local durable attempt fence would not reserve, before any chain call.

    Nothing was signed, submitted, or finalized: the reservation is taken
    immediately before `set_weights_on_chain` precisely so that a refusal here
    leaves no ambiguous write. But the cause is always local and durable — an
    unwritable runtime root, a journal left pending by an earlier attempt, a
    second writer — and none of those clear on their own, so this needs a
    human. It carries its own code purely so that a human can be paged for it
    without also being paged for the chain's routine cooldown."""


class _ContinuousLaunchLocked(wire.VectorError):
    """Recurring writes are locked until `reconcile-launch` proves the launch.

    This is the loudest thing the loop can say: the validator is up, ticking,
    and writing nothing at all, and it will keep doing exactly that until an
    operator runs one named command. Sharing `TICK_FAILED` with a refusal that
    clears itself in 32 blocks is what let this hide in a muted filter."""


EXPIRED_WITHOUT_INCLUSION = "expired_without_inclusion"
# A full attempt (preflight, feed, gates, provenance audit) spends most of a
# 12s Finney block between sampling the finalized head and reaching the
# pre-sign equality check, so any single attempt loses that race more often
# than it wins. Two attempts per tick therefore stalled recurring operation
# behind the 25 minute tick interval. Every retry rebuilds the entire tick from
# a fresh finalized head and re-proves signature, freshness, rollback fence,
# contract, burn invariants and UID mapping safety, so this is a retry budget
# only: the pre-sign check itself stays exact.
SN39_PRE_SIGN_HEAD_DRIFT_RETRIES = 8

# Retrying IMMEDIATELY made those 8 attempts one attempt tried 8 times.
#
# The note above assumed "the very next attempt from a fresh finalized head is
# as likely to win the race as any other". Measured on the live writer, it is
# not: a tick takes about as long as a block, so an immediate retry re-enters
# the block cycle at the phase it just failed at. The attempts are correlated,
# not independent draws.
#
# 120 consecutive ticks, retries needed before the tick ended:
#
#     0 retries  29 ticks     <- won immediately
#     1           9
#     2          19
#     3           4
#     4          10
#     5           9
#     6          10
#     7           4
#     8          26 ticks     <- hit the cap, 20 of them wrote nothing
#
# An independent per-attempt race decays monotonically. This is bimodal: win at
# once, or burn the whole budget. Median gap between consecutive retries was
# 12.57s against a 12s block. That is the phase lock, and it abandoned ~17% of
# ticks (10 of 33 writes on 2026-08-15).
#
# Sleeping a uniform random fraction of one block before retrying decorrelates
# the attempts, which is the property the retry budget always assumed it had.
# Uniform over a full block period rather than a smaller nudge: a partial
# offset still correlates, and only full-period coverage makes the next sample
# independent of the phase that just lost. Not a cryptographic draw; this only
# has to be unpredictable with respect to block arrival.
SN39_PRE_SIGN_HEAD_DRIFT_JITTER_SECS = 12.0

# Exhausting that budget is a TIMING outcome, not a fault: nothing was
# reserved, nothing was signed, and the very next attempt from a fresh
# finalized head is as likely to win the race as any other. Sleeping the whole
# write interval after it therefore threw away a ~25 minute cycle to recover
# from a ~12 second phenomenon. Re-arm on a short bounded delay instead.
#
# The delay is several block times, so the attempt that follows starts at an
# independently drawn offset into a block rather than immediately re-running
# the sequence that just lost. It is capped to a few CONSECUTIVE re-arms so a
# genuinely wedged chain falls back to the daemon's own cadence instead of
# retrying forever at the short interval.
SN39_PRE_SIGN_HEAD_DRIFT_REARM_SECS = 60
SN39_PRE_SIGN_HEAD_DRIFT_REARM_MAX_CONSECUTIVE = 3


def _head_drift_phase_offset(width_secs: float) -> float:
    """A delay drawn uniformly from one block period, to break the phase lock.

    Both head-drift delays claim to start the next attempt at "an independently
    drawn offset into a block". Neither did. The inner retry slept not at all,
    and the re-arm slept exactly 60s, which is 5 block times: a whole number of
    periods lands on the same phase just as reliably as sleeping nothing does.

    Offsetting by a uniform draw over one full period is what actually makes the
    next attempt's phase independent of the one that just lost.
    """
    if not (width_secs > 0.0):
        return 0.0
    return random.uniform(0.0, width_secs)  # noqa: S311 - timing, not secrecy


def _ms_iso_now() -> str:
    dt = datetime.now(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _lifecycle(event: str, detail: str = "") -> None:
    """One human-facing lifecycle line per state transition. No secrets.

    Call sites pass ``<EVENT>`` plus a flat ``key=value`` detail string; the
    renderer in `render.py` owns how that becomes something a person can read.
    Keeping the call-site contract flat means presentation can change without
    touching the tick logic, and the durable JSONL journal (the publisher's
    actual contract) stays independent of anything decided here.
    """
    render.lifecycle(event, detail, _ms_iso_now())


def _feed_label(publisher_url: str) -> str:
    """Return a log-safe feed identity without credentials, query, or fragment."""
    parsed = urlsplit(publisher_url)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or "<invalid-host>"
    try:
        port = parsed.port
    except ValueError:
        port = None
    suffix = f":{port}" if port is not None else ""
    return f"{scheme}://{host}{suffix}"


def _safe_endpoint_label(value: Any) -> str | None:
    """Return only a validated endpoint identity for structured telemetry.

    Configuration is logged before the first fetch. Never put the raw value in
    an event: a malformed URL can contain whitespace that defeats ordinary URL
    tokenization while still carrying credentials or a signed query.
    """
    if value is None:
        return None
    if not isinstance(value, str) or any(
        character.isspace() or character == "\\" for character in value
    ):
        return "<invalid-endpoint>"
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or "@" in parsed.netloc
            or parsed.query
            or parsed.fragment
        ):
            return "<invalid-endpoint>"
        return _feed_label(value)
    except (TypeError, ValueError):
        return "<invalid-endpoint>"


MAX_VECTOR_FETCH_BYTES = 4 * 1024 * 1024

# How long a `Date:` reading stays usable as an explanation. Clock skew does
# not change minute to minute, but an operator who fixes NTP must not keep
# being told about the drift that was measured before the fix, and a cached
# vector re-verified hours later must not borrow a stale reading. Past this
# age the observation is dropped and refusals read exactly as they do today.
PUBLISHER_CLOCK_OBSERVATION_TTL_SECONDS = 900.0

# Last observed publisher `Date:` header, as (observation, monotonic stamp).
#
# DIAGNOSTIC ONLY. Nothing here is a time source: see the warning on
# `wire.PublisherClock`. It is module state rather than a return value because
# `fetch_vector`'s contract is "returns the vector document" and is stubbed
# under that contract in tests and in the offline paths — a stubbed or skipped
# fetch simply leaves this empty, which degrades to today's message.
_PUBLISHER_CLOCK: tuple[wire.PublisherClock, float] | None = None


def _record_publisher_clock(date_header: str | None) -> None:
    """Remember the publisher's `Date:` header for refusal diagnostics only."""
    global _PUBLISHER_CLOCK
    if not date_header:
        # No header: forget the previous reading rather than let an older,
        # unrelated observation explain this fetch's vector.
        _PUBLISHER_CLOCK = None
        return
    _PUBLISHER_CLOCK = (
        wire.PublisherClock(date_header=date_header, observed_at=datetime.now(UTC)),
        time.monotonic(),
    )


def _observed_publisher_clock() -> wire.PublisherClock | None:
    """Return the recent `Date:` observation, or None when there is none."""
    if _PUBLISHER_CLOCK is None:
        return None
    observation, stamp = _PUBLISHER_CLOCK
    if time.monotonic() - stamp > PUBLISHER_CLOCK_OBSERVATION_TTL_SECONDS:
        return None
    return observation


def fetch_vector(publisher_url: str, timeout: float = 30.0) -> dict[str, Any]:
    """Hardened bounded fetch of the thin feed (public HTTPS only).

    Beyond the scheme check: userinfo, query, fragment, and ambiguous URL
    shapes are rejected outright; EVERY resolved peer must be a public
    routable address (pooled bounded DNS); the TCP connection is pinned to
    the validated peer while TLS still verifies the certificate for the
    ORIGINAL hostname via SNI; ONE total deadline spans DNS, connect, TLS,
    request/headers, and every body read; redirects are never followed
    (any non-200 fails); the body is size-bounded; and the strict JSON
    parse rejects duplicate keys and non-finite numbers. Fail closed."""
    import http.client
    import ipaddress
    import socket
    import ssl

    from .provenance_audit import ProvenanceAuditError, _getaddrinfo_bounded

    if not isinstance(publisher_url, str) or any(
        character.isspace() or character == "\\" for character in publisher_url
    ):
        raise wire.VectorError("publisher URL is malformed")
    parsed = urlsplit(publisher_url.rstrip("/"))
    if parsed.scheme != "https":
        raise wire.VectorError("publisher URL must be https")
    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
    ):
        raise wire.VectorError("publisher URL must be credential-free")
    if parsed.query or parsed.fragment:
        raise wire.VectorError("publisher URL must carry no query or fragment")
    host = parsed.hostname
    if not host:
        raise wire.VectorError("publisher URL has no host")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise wire.VectorError("publisher URL port is malformed") from exc
    target_path = (parsed.path or "") + "/v1/validator/weights/next"

    deadline = time.monotonic() + timeout

    def _phase_timeout() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise wire.VectorError("vector fetch exceeded its total deadline")
        return remaining

    try:
        infos = _getaddrinfo_bounded(host, port, _phase_timeout())
    except ProvenanceAuditError as exc:
        raise wire.VectorError(f"publisher DNS failed: {exc}") from exc
    if not infos:
        raise wire.VectorError("publisher host does not resolve")
    # EVERY resolved address is validated up front; only this validated,
    # order-preserving public list may ever be dialed (no private retry).
    peer_ips: list[str] = []
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global:
            raise wire.VectorError(
                "publisher resolves to a non-public address; the production "
                "endpoint is public HTTPS"
            )
        if info[4][0] not in peer_ips:
            peer_ips.append(info[4][0])

    # ONE aggregate body budget spans every address attempt: a peer that
    # streams most of the cap and then dies cannot reset it by failing over.
    body_budget = {"bytes": MAX_VECTOR_FETCH_BYTES}

    class _PinnedConnection(http.client.HTTPSConnection):
        peer_ip = ""

        def connect(self) -> None:
            raw = socket.create_connection((self.peer_ip, port), _phase_timeout())
            # TLS must not inherit the connect phase's stale allowance; SNI
            # and certificate verification use the ORIGINAL hostname.
            raw.settimeout(_phase_timeout())
            self.sock = self._context.wrap_socket(raw, server_hostname=host)

    def _fetch_via(peer_ip: str) -> bytes:
        connection = _PinnedConnection(
            host, port, timeout=_phase_timeout(), context=ssl.create_default_context()
        )
        connection.peer_ip = peer_ip
        try:
            connection.connect()  # TCP + TLS under freshly computed bounds
            connection.sock.settimeout(_phase_timeout())
            connection.request(
                "GET",
                target_path,
                headers={"Host": host, "User-Agent": "cathedral-thin-validator/1.0"},
            )
            connection.sock.settimeout(_phase_timeout())
            response = connection.getresponse()
            # Read before the status gate: a 503 still carries a usable clock
            # reading, and this is only ever used to EXPLAIN a later refusal.
            # It is never consulted by any check — see `wire.PublisherClock`.
            _record_publisher_clock(response.getheader("Date"))
            if response.status != 200:
                raise wire.VectorError(
                    f"vector fetch failed with status {response.status} "
                    "(redirects are never followed)"
                )
            chunks: list[bytes] = []
            while True:
                connection.sock.settimeout(_phase_timeout())
                chunk = response.read(min(65536, body_budget["bytes"] + 1))
                if not chunk:
                    break
                body_budget["bytes"] -= len(chunk)
                if body_budget["bytes"] < 0:
                    raise wire.VectorError(
                        "vector response exceeds the bounded size limit"
                    )
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            connection.close()

    data: bytes | None = None
    transport_failures: list[str] = []
    # Try every already validated public address under the one total
    # deadline. Only transport failures move on; a served response (any
    # status) is final, and redirects are never followed.
    for candidate_ip in peer_ips:
        _phase_timeout()
        try:
            data = _fetch_via(candidate_ip)
            break
        except OSError as exc:
            transport_failures.append(f"{candidate_ip}: {type(exc).__name__}")
    if data is None:
        raise wire.VectorError(
            "publisher unreachable on every validated address: "
            + "; ".join(transport_failures)
        )

    def _no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise wire.VectorError("vector JSON has duplicate keys")
            result[key] = value
        return result

    def _finite_float(raw: str) -> float:
        value = float(raw)
        if not math.isfinite(value):
            raise wire.VectorError("vector JSON has non-finite numbers")
        return value

    document = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_no_duplicates,
        parse_float=_finite_float,
        parse_constant=lambda _v: (_ for _ in ()).throw(
            wire.VectorError("vector JSON has non-finite numbers")
        ),
    )
    if not isinstance(document, dict):
        raise wire.VectorError("vector payload is not a JSON object")
    return document


# -- rollback fence ------------------------------------------------------------


def _strict_state_document(payload: str) -> dict[str, Any]:
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("validator state has duplicate keys")
            result[key] = value
        return result

    def finite_float(raw: str) -> float:
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError("validator state has non-finite numbers")
        return value

    document = json.loads(
        payload,
        object_pairs_hook=no_duplicates,
        parse_float=finite_float,
        parse_constant=lambda _value: (_ for _ in ()).throw(
            ValueError("validator state has non-finite numbers")
        ),
    )
    if not isinstance(document, dict):
        raise TypeError("validator state file is corrupt")
    return document


def _canonical_json_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_document(document: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(document)).hexdigest()


def _strict_launch_approval_bytes(payload: bytes) -> dict[str, Any]:
    """Parse one byte-canonical launch approval with no ambiguous JSON."""

    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise wire.VectorError("launch approval has duplicate keys")
            result[key] = value
        return result

    try:
        text = payload.decode("utf-8")
        document = json.loads(
            text,
            object_pairs_hook=no_duplicates,
            parse_float=lambda raw: (
                float(raw)
                if math.isfinite(float(raw))
                else (_ for _ in ()).throw(
                    wire.VectorError("launch approval has non-finite numbers")
                )
            ),
            parse_constant=lambda _raw: (_ for _ in ()).throw(
                wire.VectorError("launch approval has non-finite numbers")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise wire.VectorError("launch approval is not strict UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise wire.VectorError("launch approval must be a JSON object")
    if payload != _canonical_json_bytes(document) + b"\n":
        raise wire.VectorError("launch approval is not byte-canonical JSON")
    return document


def _read_root_launch_approval(path: Path) -> dict[str, Any]:
    """Read one immutable operator approval without following links."""
    import stat as stat_module

    if not path.is_absolute():
        raise wire.VectorError("launch approval path must be absolute")
    try:
        parent = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise wire.VectorError("launch approval directory is unavailable") from exc
    try:
        parent_info = os.fstat(parent)
        if (
            not stat_module.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != SN39_LAUNCH_APPROVAL_OWNER_UID
            or stat_module.S_IMODE(parent_info.st_mode) & 0o022
        ):
            raise wire.VectorError("launch approval directory is not root-controlled")
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent,
            )
        except OSError as exc:
            raise wire.VectorError("required launch approval is unavailable") from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat_module.S_ISREG(info.st_mode)
                or info.st_uid != SN39_LAUNCH_APPROVAL_OWNER_UID
                or stat_module.S_IMODE(info.st_mode) & 0o022
            ):
                raise wire.VectorError(
                    "launch approval is not an immutable root-controlled file"
                )
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                payload = handle.read(SN39_LAUNCH_APPROVAL_MAX_BYTES + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    finally:
        os.close(parent)
    if len(payload) > SN39_LAUNCH_APPROVAL_MAX_BYTES:
        raise wire.VectorError("launch approval exceeds its bounded size")
    return _strict_launch_approval_bytes(payload)


def _write_root_launch_approval(path: Path, document: dict[str, Any]) -> None:
    """Atomically emit the sole intended preflight mutation: the approval."""
    import stat as stat_module

    if not path.is_absolute():
        raise wire.VectorError("launch approval output path must be absolute")
    payload = _canonical_json_bytes(document) + b"\n"
    if len(payload) > SN39_LAUNCH_APPROVAL_MAX_BYTES:
        raise wire.VectorError("launch approval exceeds its bounded size")
    try:
        parent = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise wire.VectorError(
            "launch approval output directory is unavailable"
        ) from exc
    tmp_name = path.name + ".tmp"
    try:
        info = os.fstat(parent)
        if (
            not stat_module.S_ISDIR(info.st_mode)
            or info.st_uid != SN39_LAUNCH_APPROVAL_OWNER_UID
            or stat_module.S_IMODE(info.st_mode) & 0o022
        ):
            raise wire.VectorError(
                "launch approval output directory is not root-controlled"
            )
        try:
            os.unlink(tmp_name, dir_fd=parent)
        except FileNotFoundError:
            pass
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(tmp_name, flags, 0o644, dir_fd=parent)
        try:
            os.fchmod(descriptor, 0o644)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        os.replace(tmp_name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(tmp_name, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def _open_private_lock(path: Path) -> int:
    import stat as stat_module

    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        info = os.fstat(descriptor)
        mode = stat_module.S_IMODE(info.st_mode)
        if not stat_module.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError("validator lock must be owner-controlled mode 0600")
        if mode != 0o600:
            if mode & 0o022:
                raise ValueError("validator lock must be owner-controlled mode 0600")
            os.fchmod(descriptor, 0o600)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_private_state_dir(path: Path) -> int:
    """Open one owner-only state directory without following its final link.

    Older validators commonly created ``0755`` state directories. A directory
    owned by this process and not writable by group/other can be tightened
    safely through the already-open descriptor. Writable or foreign-owned
    paths still fail closed.
    """
    import stat as stat_module

    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        info = os.fstat(descriptor)
        mode = stat_module.S_IMODE(info.st_mode)
        if not stat_module.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError(
                "validator state directory must be owner-controlled mode 0700"
            )
        if mode != 0o700:
            if mode & 0o022:
                raise ValueError(
                    "validator state directory must be owner-controlled mode 0700"
                )
            os.fchmod(descriptor, 0o700)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _read_state(state_file: Path) -> dict[str, Any]:
    """Read the whole durable state document (fence + provenance chain).

    The file is opened once with ``O_NOFOLLOW`` and validated through that
    same descriptor. This avoids a check/use replacement window and refuses
    state another account can edit.
    """
    import stat as stat_module

    parent = _open_private_state_dir(state_file.parent)
    try:
        try:
            descriptor = os.open(
                state_file.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent,
            )
        except FileNotFoundError:
            return {}
        try:
            info = os.fstat(descriptor)
            mode = stat_module.S_IMODE(info.st_mode)
            if not stat_module.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError(
                    "validator state must be an owner-controlled regular file mode 0600"
                )
            if mode != 0o600:
                if mode & 0o022:
                    raise ValueError(
                        "validator state must be an owner-controlled regular file "
                        "mode 0600"
                    )
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                return _strict_state_document(handle.read())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    finally:
        os.close(parent)


def _private_state_bytes(state_file: Path) -> bytes:
    """Read exact bounded owner-only state bytes without following the path."""

    import stat as stat_module

    parent = _open_private_state_dir(state_file.parent)
    try:
        descriptor = os.open(
            state_file.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent,
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat_module.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat_module.S_IMODE(info.st_mode) != 0o600
                or info.st_size <= 0
                or info.st_size > SN39_UID30_SUCCESSOR_ROLLBACK_MAX_BYTES
            ):
                raise ValueError(
                    "validator predecessor state must be owner-only mode 0600 "
                    "and at most 1 MiB"
                )
            payload = bytearray()
            while True:
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > SN39_UID30_SUCCESSOR_ROLLBACK_MAX_BYTES:
                    raise ValueError(
                        "validator predecessor state grew beyond the 1 MiB cap"
                    )
            return bytes(payload)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _private_state_sha256(state_file: Path) -> str:
    """Hash exact owner-only state bytes without following the final path."""

    return hashlib.sha256(_private_state_bytes(state_file)).hexdigest()


def _encode_uid30_successor_predecessor_bytes(
    payload: bytes,
    *,
    expected_sha256: str,
) -> str:
    """Bound and compress the exact unsigned-rollback preimage."""

    if (
        not payload
        or len(payload) > SN39_UID30_SUCCESSOR_ROLLBACK_MAX_BYTES
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise ValueError("UID30 successor predecessor bytes differ from their pin")
    encoded = base64.b64encode(zlib.compress(payload, level=9)).decode("ascii")
    if len(encoded) > SN39_UID30_SUCCESSOR_ROLLBACK_B64_MAX_BYTES:
        raise ValueError("UID30 successor predecessor rollback bytes exceed their cap")
    return encoded


def _decode_uid30_successor_predecessor_bytes(
    encoded: Any,
    *,
    expected_sha256: str,
) -> bytes:
    """Recover only the bounded exact predecessor preimage."""

    if (
        not isinstance(encoded, str)
        or not encoded
        or len(encoded) > SN39_UID30_SUCCESSOR_ROLLBACK_B64_MAX_BYTES
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise ValueError("UID30 successor predecessor rollback bytes are malformed")
    try:
        compressed = base64.b64decode(encoded, validate=True)
        inflater = zlib.decompressobj()
        payload = inflater.decompress(
            compressed,
            SN39_UID30_SUCCESSOR_ROLLBACK_MAX_BYTES + 1,
        )
        if inflater.unconsumed_tail or not inflater.eof or inflater.unused_data:
            raise ValueError("UID30 successor predecessor rollback bytes exceed 1 MiB")
        remaining = SN39_UID30_SUCCESSOR_ROLLBACK_MAX_BYTES + 1 - len(payload)
        if remaining <= 0:
            raise ValueError("UID30 successor predecessor rollback bytes exceed 1 MiB")
        payload += inflater.flush(remaining)
    except (binascii.Error, ValueError, zlib.error) as exc:
        raise ValueError(
            "UID30 successor predecessor rollback bytes are malformed"
        ) from exc
    if (
        not payload
        or len(payload) > SN39_UID30_SUCCESSOR_ROLLBACK_MAX_BYTES
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise ValueError("UID30 successor predecessor rollback bytes differ from pin")
    try:
        _strict_state_document(payload.decode("utf-8"))
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        raise ValueError(
            "UID30 successor predecessor rollback bytes are not strict state JSON"
        ) from exc
    return payload


def _read_state_without_mutation(state_file: Path) -> dict[str, Any]:
    """Read validator state for root preflight without chmod/mkdir side effects."""
    import stat as stat_module

    if not state_file.is_absolute():
        raise wire.VectorError("validator state path must be absolute")
    try:
        parent = os.open(
            state_file.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise wire.VectorError("validator state directory is unavailable") from exc
    try:
        parent_info = os.fstat(parent)
        if (
            not stat_module.S_ISDIR(parent_info.st_mode)
            or stat_module.S_IMODE(parent_info.st_mode) & 0o022
        ):
            raise wire.VectorError("validator state directory is not owner-controlled")
        try:
            descriptor = os.open(
                state_file.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent,
            )
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise wire.VectorError("validator state is unavailable") from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat_module.S_ISREG(info.st_mode)
                or stat_module.S_IMODE(info.st_mode) != 0o600
            ):
                raise wire.VectorError(
                    "validator state is not an owner-controlled regular file mode 0600"
                )
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                return _strict_state_document(handle.read())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    finally:
        os.close(parent)


def _replace_private_bytes(state_file: Path, payload: bytes) -> None:
    """Atomically replace one owner-only file with exact bytes."""

    if not payload:
        raise ValueError("validator state bytes are empty")
    parent = _open_private_state_dir(state_file.parent)
    tmp_name = state_file.name + ".tmp"
    try:
        try:
            os.unlink(tmp_name, dir_fd=parent)
        except FileNotFoundError:
            pass
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(tmp_name, flags, 0o600, dir_fd=parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        os.replace(
            tmp_name,
            state_file.name,
            src_dir_fd=parent,
            dst_dir_fd=parent,
        )
        os.fsync(parent)
    finally:
        try:
            os.unlink(tmp_name, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def _replace_private_state(state_file: Path, document: dict[str, Any]) -> None:
    """Atomically replace state relative to one verified directory descriptor.

    A failed write here stays FATAL, deliberately, and that is the opposite of
    what `scaffold.events` does with the same ENOSPC. The asymmetry is the
    point:

    * The event journal is telemetry. Nothing reads it back to decide whether
      a write may happen, so a lost line costs visibility and nothing else —
      and killing the loop over one costs the operator the `TICK_FAILED` that
      would have explained the outage. It degrades to stderr.
    * This file carries the monotonic fences and the anti-rollback watermark.
      Every caller writes it to record that something irreversible happened or
      is about to. Swallowing a failure here would leave the fence pointing at
      an older attempt while the process carried on believing it advanced,
      which is how a validator replays or double-submits. A crash is strictly
      the better outcome: the fence stays where it was, the next start reads
      it, and nothing is written on top of an unrecorded attempt.

    So the OSError raised out of the write, `os.fsync` or `os.replace` below
    is left to propagate. In the tick loop it reaches the generic handler,
    which fails the tick closed — no reservation, no signature, no submission.
    """
    _replace_private_bytes(
        state_file,
        json.dumps(document, indent=2, allow_nan=False).encode("utf-8"),
    )


def _state_policy_fence(document: dict[str, Any]) -> int:
    """Return the highest policy version that may already be on-chain.

    An irreversible call is ambiguous from the instant its intent is fsynced:
    the process may die after the chain accepts it but before final state
    persistence. Consequently the rollback fence includes both finalized
    versions and every thin version ever attempted, not just confirmed
    successes.
    """
    candidates = [-1]
    for key in (
        "last_accepted_policy_version",
        "highest_attempted_policy_version",
    ):
        if key not in document:
            continue
        value = document[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"validator state {key} is malformed")
        candidates.append(value)
    identity = document.get("thin_submission_identity")
    if identity is not None:
        if not isinstance(identity, dict):
            raise ValueError("validator state thin submission identity is malformed")
        value = identity.get("policy_version")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(
                "validator state thin submission policy version is malformed"
            )
        candidates.append(value)
    accepted = document.get("last_accepted_policy_version")
    attempted = document.get("highest_attempted_policy_version")
    if (
        isinstance(accepted, int)
        and isinstance(attempted, int)
        and attempted < accepted
    ):
        raise ValueError(
            "validator state attempted-policy fence regresses below accepted policy"
        )
    return max(candidates)


def _authority_lane_transition_authorized(
    state: dict[str, Any],
    identity: dict[str, Any],
) -> bool:
    """Allow only the reviewed transition into a historical full-replay lane.

    The bounded launch process has already reproduced the root-signed launch seal
    and completed a current strict replay before it constructs this identity.
    This check binds that authorization back to the durable launch journal.
    The serialized lane remains named ``authority`` for journal compatibility.
    """
    # Historical beta launch journals carry an explicit marker for this lane.
    # The launch journal proves a completed ceremony, which a beta runtime
    # deliberately does not have, so that half is waived exactly as the rest of
    # the ceremony is. Chain identity is NOT waived: the transition still has to
    # be for this hotkey, on this genesis and netuid, so a reservation cannot be
    # replayed onto another chain or wallet.
    if identity.get("operator_declared_authority") is True:
        return bool(
            identity.get("network") == "finney"
            and identity.get("netuid") == 39
            and identity.get("validator_hotkey")
            == state.get("submission_validator_hotkey")
            and state.get("submission_genesis_hash") == FINNEY_GENESIS_HASH
            and state.get("provenance_netuid") == 39
        )
    authorization = identity.get("continuous_authorization")
    if not isinstance(authorization, dict):
        return False
    launch_attempt_id = state.get("submission_launch_attempt_id")
    launch_attempt_ids = state.get("submission_launch_attempt_ids")
    return bool(
        identity.get("network") == "finney"
        and identity.get("netuid") == 39
        and identity.get("validator_hotkey") == state.get("submission_validator_hotkey")
        and state.get("submission_genesis_hash") == FINNEY_GENESIS_HASH
        and state.get("provenance_netuid") == 39
        and state.get("submission_launch_status") == "finalized"
        and state.get("submission_continuous_enabled") is True
        and isinstance(launch_attempt_id, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", launch_attempt_id) is not None
        and isinstance(launch_attempt_ids, list)
        and launch_attempt_id in launch_attempt_ids
        and state.get("submission_continuous_launch_attempt_id") == launch_attempt_id
        and authorization.get("launch_attempt_id") == launch_attempt_id
        and authorization.get("release_sha256")
        == state.get("submission_continuous_release_sha256")
        and authorization.get("reproducer_revision")
        == state.get("submission_continuous_reproducer_revision")
        and authorization.get("validator_hotkey")
        == state.get("submission_validator_hotkey")
        and authorization.get("genesis_hash") == state.get("submission_genesis_hash")
        and isinstance(authorization.get("authorization_sha256"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", authorization["authorization_sha256"])
        is not None
        and isinstance(authorization.get("lanes"), list)
        and "authority" in authorization["lanes"]
        and isinstance(authorization.get("max_attempts"), int)
        and not isinstance(authorization["max_attempts"], bool)
        and 0 < authorization["max_attempts"] <= 96
        and isinstance(authorization.get("valid_from_nonce"), int)
        and not isinstance(authorization["valid_from_nonce"], bool)
        and authorization["valid_from_nonce"] >= 0
        and isinstance(authorization.get("valid_until_nonce_exclusive"), int)
        and not isinstance(authorization["valid_until_nonce_exclusive"], bool)
        and authorization["valid_until_nonce_exclusive"]
        == authorization["valid_from_nonce"] + authorization["max_attempts"]
    )


def _assert_anchor_not_rewound(
    current: dict[str, Any], updates: dict[str, Any]
) -> None:
    """Refuse a reservation whose anchored candidate block moved backwards.

    The per-audit ceiling bounds how STALE an anchor may be against the live
    head. This bounds it against history. Without both, a producer can walk the
    anchor backwards epoch over epoch while every in-audit chain check still
    passes, because each one is evaluated at whatever block it was handed.

    Reusing the same anchor is legitimate (two exports inside one block). Only
    a strict decrease is a rollback. A non-int, or a bool masquerading as one,
    carries no ordering and is ignored here rather than silently compared.
    """
    new_anchor = updates.get("provenance_candidate_block")
    stored_anchor = current.get("provenance_candidate_block")
    if (
        isinstance(new_anchor, int)
        and not isinstance(new_anchor, bool)
        and isinstance(stored_anchor, int)
        and not isinstance(stored_anchor, bool)
        and new_anchor < stored_anchor
    ):
        raise ValueError(
            f"anchor rollback: candidate block {new_anchor} < reserved {stored_anchor}"
        )


def _write_state_fenced(state_file: Path, updates: dict[str, Any]) -> None:
    """Atomic CHECK-AND-RESERVE under the shared submission-state lock.

    The high-water comparison and the write happen inside ONE flock hold:
    a concurrent writer that reserved a newer epoch, an equivocating
    manifest, or a diverging policy/report line makes THIS reservation
    RAISE — a stale read can never overwrite or silently coexist.
    """
    import fcntl

    state_directory = _open_private_state_dir(state_file.parent)
    os.close(state_directory)
    lock_path = state_file.with_suffix(".lock")
    lock_descriptor = _open_private_lock(lock_path)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        current = _read_state(state_file)
        updates = dict(updates)
        expected_state_sha256 = updates.pop("_expected_state_sha256", None)
        if expected_state_sha256 is not None:
            if (
                not isinstance(expected_state_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", expected_state_sha256) is None
                or _private_state_sha256(state_file) != expected_state_sha256
            ):
                raise ValueError(
                    "canonical predecessor journal bytes changed before reservation"
                )
        receipt_submission_id = updates.pop("_record_receipt_for_submission_id", None)
        if receipt_submission_id is not None:
            if (
                not isinstance(receipt_submission_id, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", receipt_submission_id) is None
                or current.get("submission_pending_id") != receipt_submission_id
            ):
                raise ValueError(
                    "receipt candidate does not match the common pending fence"
                )
        finalize_submission_id = updates.pop("_finalize_submission_id", None)
        if finalize_submission_id is not None:
            if (
                not isinstance(finalize_submission_id, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", finalize_submission_id) is None
                or current.get("submission_pending_id") != finalize_submission_id
            ):
                raise ValueError(
                    "submission finalization does not match the common pending fence"
                )
            updates["submission_pending_id"] = None
        new_common_attempt = updates.get("submission_pending_id")
        if new_common_attempt is not None:
            provisional = updates.pop("_provisional_submission", False)
            allow_authority_transition = updates.pop(
                "_allow_authority_lane_transition",
                False,
            )
            if provisional is not True:
                raise ValueError(
                    "new common submissions must begin as unsigned reservations"
                )
            if not isinstance(allow_authority_transition, bool):
                raise ValueError("submission lane transition marker is malformed")
            if (
                not isinstance(new_common_attempt, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", new_common_attempt) is None
            ):
                raise ValueError("common submission attempt id is malformed")
            pending = current.get("submission_pending_id")
            if pending is not None:
                raise ValueError(
                    "a prior thin/full submission is pending reconciliation"
                )
            raw_common_history = current.get("submission_attempt_ids", [])
            if not isinstance(raw_common_history, list) or any(
                not isinstance(item, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                for item in raw_common_history
            ):
                raise ValueError("common submission attempt journal is corrupt")
            if new_common_attempt in raw_common_history:
                raise ValueError(
                    "this exact thin/full submission was already attempted"
                )
            lane = updates.get("submission_pending_lane")
            if lane not in ("thin", "authority"):
                raise ValueError("common submission lane is malformed")
            identity = updates.get("submission_pending_identity")
            if not isinstance(identity, dict):
                raise ValueError("common submission identity is malformed")
            active_lane = current.get("submission_active_lane")
            lane_transition_from: str | None = None
            if active_lane is not None and active_lane != lane:
                if (
                    allow_authority_transition
                    and active_lane == "thin"
                    and lane == "authority"
                    and _authority_lane_transition_authorized(current, identity)
                ):
                    lane_transition_from = "thin"
                else:
                    raise ValueError(
                        "submission authority lane changed without explicit operator "
                        f"reconciliation ({active_lane!r} -> {lane!r})"
                    )
            elif allow_authority_transition and lane != "authority":
                raise ValueError(
                    "only FULL authority may request a submission lane transition"
                )
            launch_attempt = updates.pop("_launch_attempt", False)
            if not isinstance(launch_attempt, bool):
                raise ValueError("launch attempt marker is malformed")
            budget_scope = updates.pop("_submission_budget_scope", None)
            budget_limit = updates.pop("_submission_budget_limit", None)
            if budget_scope is not None:
                if (
                    not isinstance(budget_scope, str)
                    or re.fullmatch(r"[a-z0-9_]{1,64}", budget_scope) is None
                    or isinstance(budget_limit, bool)
                    or not isinstance(budget_limit, int)
                    or budget_limit <= 0
                ):
                    raise ValueError("submission attempt budget scope is malformed")
                budgets = current.get("submission_attempt_budgets", {})
                if not isinstance(budgets, dict):
                    raise ValueError("submission attempt budgets are corrupt")
                budget = budgets.get(budget_scope, {"limit": budget_limit, "ids": []})
                if (
                    not isinstance(budget, dict)
                    or set(budget) != {"limit", "ids"}
                    or budget.get("limit") != budget_limit
                    or not isinstance(budget.get("ids"), list)
                    or any(
                        not isinstance(item, str)
                        or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                        for item in budget.get("ids", [])
                    )
                ):
                    raise ValueError("submission attempt budget changed or is corrupt")
                if len(budget["ids"]) >= budget_limit:
                    raise ValueError(
                        f"submission attempt budget {budget_limit} is exhausted"
                    )
            configured_limit = updates.pop("_launch_budget_limit", None)
            if launch_attempt:
                if (
                    isinstance(configured_limit, bool)
                    or not isinstance(configured_limit, int)
                    or configured_limit != 1
                ):
                    raise ValueError("launch submission budget must be exactly one")
                launch_history = current.get("submission_launch_attempt_ids", [])
                if not isinstance(launch_history, list) or any(
                    not isinstance(item, str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                    for item in launch_history
                ):
                    raise ValueError("launch submission attempt journal is corrupt")
                if launch_history:
                    raise ValueError("launch submission attempt budget 1 is exhausted")
            elif configured_limit is not None:
                raise ValueError("non-launch reservation carries a launch budget")
            policy_version = updates.pop("submission_highest_policy_version", None)
            source_epoch = updates.pop("submission_highest_source_epoch", None)
            if lane == "thin":
                if (
                    isinstance(policy_version, bool)
                    or not isinstance(policy_version, int)
                    or policy_version < 0
                ):
                    raise ValueError("common thin policy fence is malformed")
                prior_policy = current.get("submission_highest_policy_version")
                if isinstance(prior_policy, int) and policy_version <= prior_policy:
                    raise ValueError(
                        f"common thin policy rollback {policy_version} <= "
                        f"{prior_policy}"
                    )
            else:
                if (
                    isinstance(source_epoch, bool)
                    or not isinstance(source_epoch, int)
                    or source_epoch < 0
                ):
                    raise ValueError("common authority source-epoch fence is malformed")
                prior_source = current.get("submission_highest_source_epoch")
                if isinstance(prior_source, int) and source_epoch <= prior_source:
                    raise ValueError(
                        f"common authority epoch rollback {source_epoch} <= "
                        f"{prior_source}"
                    )
            # A pre-sign reservation linearizes the in-process decision under the
            # shared submission lock, but it is not yet an irreversible attempt.
            # Histories, rollback fences, and budgets are committed atomically
            # with the exact signed hash immediately before broadcast.
            for stale_key in (
                "submission_pending_broadcast_intent",
                "submission_pending_broadcast_started_at",
                "submission_pending_receipt_candidate",
                "submission_pending_receipt_recorded_at",
                "submission_pending_proof_status",
                "submission_pending_proof_checked_at",
                "submission_pending_lane_transition_from",
            ):
                current.pop(stale_key, None)
            updates.update(
                {
                    "submission_pending_phase": "unsigned_reserved",
                    "submission_pending_launch_attempt": launch_attempt,
                    "submission_pending_launch_budget_limit": configured_limit,
                    "submission_pending_budget_scope": budget_scope,
                    "submission_pending_budget_limit": budget_limit,
                    "submission_pending_policy_version": policy_version,
                    "submission_pending_source_epoch": source_epoch,
                    "submission_pending_lane_transition_from": lane_transition_from,
                }
            )
        if finalize_submission_id is not None:
            finalized_count = current.get("submission_finalized_count", 0)
            if (
                isinstance(finalized_count, bool)
                or not isinstance(finalized_count, int)
                or finalized_count < 0
            ):
                raise ValueError("common finalized-submission count is malformed")
            updates["submission_finalized_count"] = finalized_count + 1
        new_policy_fence = updates.get("highest_attempted_policy_version")
        if new_policy_fence is not None:
            if (
                isinstance(new_policy_fence, bool)
                or not isinstance(new_policy_fence, int)
                or new_policy_fence < 0
            ):
                raise ValueError("attempted policy version is malformed")
            stored_policy_fence = _state_policy_fence(current)
            if new_policy_fence <= stored_policy_fence:
                raise ValueError(
                    f"stale attempted policy version {new_policy_fence} <= "
                    f"durable fence {stored_policy_fence}"
                )
        new_epoch = updates.get("provenance_index_epoch")
        stored_epoch = current.get("provenance_index_epoch")
        if isinstance(new_epoch, int) and isinstance(stored_epoch, int):
            if new_epoch < stored_epoch:
                raise ValueError(
                    f"stale reservation: index epoch {new_epoch} < reserved "
                    f"{stored_epoch}"
                )
            if new_epoch == stored_epoch and current.get(
                "provenance_index_manifest"
            ) != updates.get("provenance_index_manifest"):
                raise ValueError(
                    "reservation equivocation: same epoch, different manifest"
                )
        new_release = updates.get("provenance_policy_release")
        stored_release = current.get("provenance_policy_release")
        if isinstance(new_release, int) and isinstance(stored_release, int):
            if new_release < stored_release:
                raise ValueError(
                    f"stale reservation: policy release {new_release} < "
                    f"reserved {stored_release}"
                )
            if new_release == stored_release and current.get(
                "provenance_policy_digest"
            ) != updates.get("provenance_policy_digest"):
                raise ValueError(
                    "reservation equivocation: same release, different digest"
                )
        new_source = updates.get("provenance_last_source_epoch")
        stored_source = current.get("provenance_last_source_epoch")
        if isinstance(new_source, int) and isinstance(stored_source, int):
            if new_source < stored_source:
                raise ValueError(
                    f"stale reservation: source epoch {new_source} < reserved "
                    f"{stored_source}"
                )
            if new_source == stored_source and current.get(
                "provenance_last_report_id"
            ) != updates.get("provenance_last_report_id"):
                raise ValueError(
                    "reservation equivocation: same source epoch, different report"
                )
        _assert_anchor_not_rewound(current, updates)
        # Append-only attempted-ID journals prevent A -> B -> A replay, not
        # merely immediate duplicate A -> A. They are intentionally unbounded:
        # deleting an old irreversible attempt would reopen its retry window.
        # Existing single-ID state is folded into the journal on first write.
        for lane in ("authority", "thin"):
            attempt_key = f"{lane}_submission_attempt_id"
            history_key = f"{lane}_submission_attempt_ids"
            new_attempt = updates.get(attempt_key)
            if new_attempt is None:
                continue
            if (
                not isinstance(new_attempt, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", new_attempt) is None
            ):
                raise ValueError(f"{lane} submission attempt id is malformed")
            raw_history = current.get(history_key, [])
            if not isinstance(raw_history, list) or any(
                not isinstance(item, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                for item in raw_history
            ):
                raise ValueError(f"{lane} submission attempt journal is corrupt")
            history = list(raw_history)
            previous = current.get(attempt_key)
            if previous is not None:
                if (
                    not isinstance(previous, str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", previous) is None
                ):
                    raise ValueError(f"{lane} prior submission attempt id is malformed")
                if previous not in history:
                    history.append(previous)
            if new_attempt in history:
                raise ValueError(
                    f"{lane} submission was already attempted for this exact "
                    "evidence/vector identity"
                )
            history.append(new_attempt)
            updates[history_key] = history
        for key in (
            "provenance_network",
            "provenance_netuid",
            "submission_genesis_hash",
            "submission_validator_hotkey",
        ):
            if key in updates and key in current and updates[key] != current[key]:
                raise ValueError(
                    f"reservation chain-identity mismatch: {key} "
                    f"{updates[key]!r} != reserved {current[key]!r}"
                )
        document = dict(current)
        document.update(updates)
        _replace_private_state(state_file, document)
    finally:
        os.close(lock_descriptor)


def _write_state(state_file: Path, updates: dict[str, Any]) -> None:
    """Locked atomic read-merge-write (0600, fsync, parent fsync) so the
    fence writer and the background shadow auditor never clobber each other
    and a crash mid-write can't corrupt the fail-closed load."""
    import fcntl

    state_directory = _open_private_state_dir(state_file.parent)
    os.close(state_directory)
    lock_path = state_file.with_suffix(".lock")
    lock_descriptor = _open_private_lock(lock_path)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        document = _read_state(state_file)
        document.update(updates)
        _replace_private_state(state_file, document)
    finally:
        os.close(lock_descriptor)


def load_fence(state_file: Path) -> int:
    """FAIL CLOSED: only a genuinely absent state file means 'no fence yet'.
    A corrupt/unreadable file raises (the tick fails) instead of silently
    resetting the fence to -1 and reopening the rollback window."""
    return _state_policy_fence(_read_state(state_file))


def save_fence(state_file: Path, version: int, vector_id: str) -> None:
    _write_state(
        state_file,
        {
            "last_accepted_policy_version": version,
            "last_vector_id": vector_id,
            "accepted_at": _ms_iso_now(),
        },
    )


# -- provenance audit -----------------------------------------------------------


def _provenance_settings(args) -> ProvenanceSettings:
    mode = getattr(args, "provenance", "shadow") or "shadow"
    evidence_url = getattr(args, "evidence_url", None)
    evidence_dir = getattr(args, "evidence_dir", None)
    if not evidence_url and not evidence_dir:
        evidence_url = args.publisher_url.rstrip("/") + "/v1/evidence"
    return ProvenanceSettings(
        mode=mode,
        evidence_url=evidence_url,
        evidence_dir=evidence_dir,
        registry_keys=getattr(args, "provenance_registry_keys", None),
        registry_keys_digest=getattr(args, "provenance_registry_keys_digest", None),
        report_keys=getattr(args, "provenance_report_keys", None),
        report_keys_digest=getattr(args, "provenance_report_keys_digest", None),
        index_keys=getattr(args, "provenance_index_keys", None),
        index_keys_digest=getattr(args, "provenance_index_keys_digest", None),
        verifier_digest=getattr(args, "provenance_verifier_digest", None),
        mechanism=getattr(args, "provenance_mechanism", MECHANISM_DEFAULT)
        or MECHANISM_DEFAULT,
        controlled_dir=getattr(args, "provenance_controlled_dir", None),
        verifier_binary=getattr(args, "provenance_verifier_binary", None),
        source_revision=getattr(args, "provenance_source_revision", None),
        allow_private_hosts=bool(
            getattr(args, "provenance_allow_private_hosts", False)
        ),
        index_max_age_secs=float(
            getattr(args, "provenance_index_max_age_secs", 3600.0)
        ),
        max_anchor_lag_blocks=(
            None
            if getattr(args, "provenance_max_anchor_lag_blocks", None) is None
            else int(args.provenance_max_anchor_lag_blocks)
        ),
    )


def _operator_declared_authority(args: Any) -> bool:
    """Read the legacy marker used by bounded full-replay launch journals.

    Recurring operator entrypoints never call this as a mode selector. It stays
    for bounded launch and historical-journal recovery and is gated on the beta
    waiver so the reviewed production path still demands the signed
    ContinuousAuthorization instead of this.
    """
    if not bool(getattr(args, "beta_skip_launch_ceremony", False)):
        return False
    return (getattr(args, "provenance", "shadow") or "shadow") == "authority"


def _minimum_assurance_rank(args: Any) -> int:
    """The lowest assurance the shadow verifier treats as PROVEN.

    Defaults to rewarded_set_proven: every hotkey receiving weight was
    independently replayed from raw evidence, and everything not replayed
    carries exactly zero. This is NOT the thin/attestation-verified write path's
    gate — recurring thin ticks submit the signed vector after verifying its
    attestation + report signatures and never call this. Setting this to
    receipts_only is a deliberate operator choice (a receipts-only shadow audit
    then reads as PASS and persists observational chain state); full_over_epoch
    reproduces the old behaviour exactly, which on any subnet with more
    registered hotkeys than the manifest's receipt cap means never submitting at
    all. That is the rollback lever, and it needs no producer redeploy.
    """
    configured = getattr(args, "min_assurance", None) or "rewarded_set_proven"
    rank = ASSURANCE_RANKS.get(str(configured))
    if rank is None:
        raise wire.VectorError(
            f"min_assurance must be one of {', '.join(sorted(ASSURANCE_RANKS))}; "
            f"got {configured!r}"
        )
    return rank


def _runtime_modes(args: Any) -> tuple[str, str]:
    """Return the serialized event-writer label and provenance audit mode."""
    provenance_mode = getattr(args, "provenance", "shadow") or "shadow"
    if provenance_mode not in {"shadow", "authority"}:
        raise wire.VectorError(f"unsupported provenance mode {provenance_mode!r}")
    submission_authority = (
        "full_provenance" if provenance_mode == "authority" else "thin"
    )
    return submission_authority, provenance_mode


def _get_events(args) -> EventLogger:
    """One logger per process; the compatibility writer label is recorded."""
    existing = getattr(args, "_events", None)
    if existing is not None:
        return existing
    authority, _provenance_mode = _runtime_modes(args)
    logger = EventLogger(
        mode=authority,
        jsonl_path=getattr(args, "jsonl", None) or None,
        jsonl_group=os.environ.get("CATHEDRAL_VALIDATOR_JSONL_GROUP") or None,
        # The raw journal above stays private. A publisher reads this
        # projection instead, so the reader group lands on the sanitized
        # surface rather than on the record that carries hotkeys, receipts
        # and caller-supplied fields.
        status_path=getattr(args, "status_jsonl", None) or None,
        status_group=os.environ.get("CATHEDRAL_VALIDATOR_STATUS_GROUP") or None,
        tty=sys.stdout,
    )
    try:
        args._events = logger
    except AttributeError:  # frozen namespaces in tests
        pass
    return logger


# The versioned mechanism fixes the burn fraction; the burn DESTINATION is
# the operator's configured pin resolved against the live metagraph. The
# signed Cathedral vector's burn row is comparison input only for the bounded
# full-replay launch calculation.
# Every supported mechanism pins its own burn contract. The fraction is always
# looked up by the operator's own pinned mechanism, never by the id the manifest
# claims, so MECHANISM_ACCEPTED widening which evidence is admitted can never let
# a producer move the burn.
MECHANISM_BURN_FRACTION = {
    "validated_supply_v1": 0.10,
    "validated_supply_v2": 0.10,
}


def _provenance_uid_weights(
    recomputed: dict[str, float],
    *,
    mechanism: str,
    burn_hotkey: str,
    hotkey_to_uid: dict[str, int],
) -> dict[int, float]:
    """Bounded launch: the COMPLETE UID vector from a strict recomputation.

    Inputs are the pinned versioned mechanism's shares, the operator's
    configured burn hotkey, and the live chain metagraph — nothing from
    Cathedral's signed vector. All-or-nothing mapping; nonfinite, negative,
    duplicate, or unmappable weights reject the whole vector.
    """
    if mechanism == "validated_supply_v3":
        # The bounded full-replay gate derives a SINGLE-lane vector (TDX + fixed burn)
        # from cathedral.provenance.verify_and_recompute. The v3 contract adds a
        # second (CyberGym) lane whose independent recompute needs the
        # cathedral-distill producer contract, which is not wired into this
        # single-lane recomposition. Fail closed rather than pay the whole
        # recomputed TDX lane as if it were 100% of emission.
        raise wire.VectorError(
            "bounded full-replay derivation of validated_supply_v3 is not "
            "supported: the CyberGym lane requires the cathedral-distill "
            "recompute contract. Run v3 in shadow/thin mode (signed-vector "
            "re-derivation via vector_to_uid_weights) until that is wired."
        )
    burn_fraction = MECHANISM_BURN_FRACTION.get(mechanism)
    if burn_fraction is None:
        raise wire.VectorError(f"mechanism {mechanism!r} has no pinned burn contract")
    if not isinstance(burn_hotkey, str) or not burn_hotkey:
        raise wire.VectorError(
            "bounded full replay requires a configured provenance burn hotkey (the "
            "burn destination; never taken from Cathedral's vector)"
        )
    if burn_hotkey not in hotkey_to_uid:
        raise wire.VectorError(
            f"configured burn hotkey {burn_hotkey!r} has no current metagraph UID"
        )
    burn_uid = hotkey_to_uid[burn_hotkey]

    scores: dict[int, float] = {}
    seen: set[int] = set()
    total = 0.0
    for hotkey, weight in sorted(recomputed.items()):
        value = float(weight)
        if not math.isfinite(value) or value < 0.0:
            raise wire.VectorError(
                f"recomputed weight for {hotkey!r} is non-finite or negative"
            )
        if value == 0.0:
            continue
        if hotkey not in hotkey_to_uid:
            raise wire.VectorError(
                f"provenance hotkey {hotkey!r} has no current metagraph UID"
            )
        uid = hotkey_to_uid[hotkey]
        if uid == burn_uid:
            raise wire.VectorError(
                f"provenance hotkey {hotkey!r} resolves to the burn UID"
            )
        if uid in seen:
            raise wire.VectorError(f"provenance duplicate UID {uid}")
        seen.add(uid)
        scores[uid] = value
        total += value
    if scores and not math.isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise wire.VectorError(f"recomputed shares sum to {total!r}, expected 1.0")
    out = {uid: value * (1.0 - burn_fraction) for uid, value in scores.items()}
    out[burn_uid] = out.get(burn_uid, 0.0) + (burn_fraction if scores else 1.0)
    norm = math.fsum(out.values())
    return {uid: value / norm for uid, value in out.items()}


class _ShadowAuditor:
    """Single-flight background worker for the shadow provenance audit.

    tick() submits non-blocking; while an audit is in flight further
    submissions are skipped (single-flight). Results are drained and logged
    by the MAIN thread on a later tick, so a slow or broken audit can never
    delay, reorder, or fail the thin submission path.

    Completed results are LOSSLESS and exactly-once: they accumulate in a
    queue under the same lock drain() holds, so an audit that finishes
    between drain() and the next submit() can never be overwritten by a
    later completion — every completed audit is handed to exactly one
    drain() caller, in completion order.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._results: list = []  # completed, unreported (audit, state_file)

    def busy(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def wait(self, timeout: float) -> bool:
        """Bounded join of the in-flight audit thread (once-mode drain).
        True when no audit remains in flight afterwards."""
        with self._lock:
            thread = self._thread
        if thread is None:
            return True
        thread.join(timeout=max(0.0, timeout))
        return not thread.is_alive()

    def submit(
        self,
        settings,
        *,
        network,
        netuid,
        payload,
        state,
        state_file,
        current_block=None,
        historical_hotkeys_lookup=None,
        block_hash_lookup=None,
    ) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False

            def _run() -> None:
                audit = run_audit(
                    settings,
                    network=network,
                    netuid=netuid,
                    vector_payload=payload,
                    state=state,
                    current_block=current_block,
                    historical_hotkeys_lookup=historical_hotkeys_lookup,
                    block_hash_lookup=block_hash_lookup,
                )
                # Append (never assign) under the drain lock: a completed
                # result is either queued or already handed out — a later
                # completion cannot overwrite an unreported one.
                with self._lock:
                    self._results.append((audit, state_file))

            self._thread = threading.Thread(
                target=_run, name="cathedral-shadow-audit", daemon=True
            )
            self._thread.start()
            return True

    def drain(self) -> list:
        """Every completed, not-yet-reported result — exactly once, in
        completion order."""
        with self._lock:
            results, self._results = self._results, []
            return results


def _get_shadow_auditor(args) -> _ShadowAuditor:
    existing = getattr(args, "_shadow_auditor", None)
    if existing is not None:
        return existing
    auditor = _ShadowAuditor()
    try:
        args._shadow_auditor = auditor
    except AttributeError:
        pass
    return auditor


def _log_audit_events(args, audit, state_file: Path, *, persist: bool = True) -> bool:
    """Log one completed audit and (for shadow) persist chain state
    observationally — the fence still refuses stale/equivocating writes, but
    a refusal is logged and skipped, never fatal. A bounded strict-replay caller
    passes persist=False because it already reserved under the fence before any
    PASS event is emitted on the main thread."""
    events = _get_events(args)
    status_map = {"PASS": PASS, "FAIL": FAIL, "NOT_PROVEN": NOT_PROVEN}
    if audit.status == "PASS" and audit.agrees_with_vector is False:
        # Vector agreement is independent of assurance level. In particular,
        # a receipts-only audit can still prove that Cathedral's signed vector
        # disagrees with the independently recomputed receipts. Emit that
        # structured failure before the partial-assurance early return so
        # shadow-mode reproduction can never mislabel disagreement as PASS.
        stale_epoch = getattr(audit, "vector_stale_epoch", None)
        if stale_epoch is not None:
            # A vector the audit re-verified IN FULL against the older epoch it
            # names — that epoch's signed manifest, report body digest, and
            # recomputed shares (see provenance_audit._classify_stale_vector).
            # It is the publisher's ~60s signing/serving race against the 311s
            # epoch, and calling it tampering is what made the one event that
            # means "a bad vector landed" fire on a benign, self-resolving
            # condition. It is still a disagreement: NOT_PROVEN, no PASS, no
            # state persisted, and vector_agrees stays False.
            events.event(
                "PROVENANCE_VECTOR_STALE_EPOCH",
                stage="provenance",
                status=NOT_PROVEN,
                detail=(
                    f"signed vector re-verified in full against its own signed "
                    f"epoch {stale_epoch} (manifest, report body digest, and "
                    f"recomputed shares); the verified evidence has since "
                    f"advanced to epoch {audit.source_epoch}"
                )[:512],
                remediation=audit.remediation,
                vector_agrees=False,
            )
            _lifecycle(
                "PROVENANCE vector stale",
                f"vector_epoch={stale_epoch} evidence_epoch={audit.source_epoch}",
            )
            # Terminal for exactly the reason the mismatch branch is: never
            # append a later PASS a tail-based consumer could read as the
            # verdict for this audit.
            return False
        events.event(
            "PROVENANCE_VECTOR_MISMATCH",
            stage="provenance",
            status=FAIL,
            detail="; ".join(audit.discrepancies)[:512],
            remediation=audit.remediation,
            vector_agrees=False,
        )
        _lifecycle(
            "PROVENANCE mismatch",
            f"discrepancies={len(audit.discrepancies)}",
        )
        # Disagreement is the terminal aggregate outcome regardless of the
        # assurance level. Never append a later PASS/NOT_PROVEN event that a
        # tail-based consumer could mistake for the final verdict.
        return False
    if audit.status == "PASS" and assurance_rank(
        getattr(audit, "assurance", None)
    ) < _minimum_assurance_rank(args):
        # Below the configured bar this is PARTIAL provenance. Positive raw
        # evidence may already have replayed successfully while the paid set
        # and the replayed set still disagree. Never erase that distinction in
        # the operator log: it must not be announced as a provenance PASS or
        # persist the durable reservation state as if it were proven.
        scope = dict(getattr(audit, "assurance_scope", {}) or {})
        reasons = list(scope.get("failures") or []) + list(
            getattr(audit, "not_proven_reasons", ()) or ()
        )
        raw_replayed = list(getattr(audit, "raw_replayed_hotkeys", ()) or ())
        replay_summary = (
            f"positive raw evidence replayed for {len(raw_replayed)} miner(s)"
            if raw_replayed
            else "no positive raw evidence replayed"
        )
        detail = (
            f"{replay_summary}; assurance "
            f"{getattr(audit, 'assurance', 'unknown')!s} is below the required "
            f"level"
        ) + (": " + "; ".join(str(r) for r in reasons) if reasons else "")
        events.event(
            "PROVENANCE_AUDIT_NOT_PROVEN",
            stage="provenance",
            status=NOT_PROVEN,
            duration_ms=audit.duration_ms,
            artifact=audit.manifest_digest,
            detail=detail[:512],
            vector_agrees=audit.agrees_with_vector,
            remediation=(
                "the recurring writer remains on the signed vector; strict replay "
                "requires independently replayable "
                "evidence for every anchored candidate outcome"
                if reasons
                else "provide the controlled package and verifier pins for strict replay"
            ),
        )
        return False
    if audit.status == "PASS":
        try:
            if persist:
                _write_state_fenced(
                    state_file,
                    {
                        "provenance_last_source_epoch": audit.source_epoch,
                        "provenance_last_report_id": audit.report_id,
                        "provenance_index_epoch": audit.index_source_epoch,
                        "provenance_index_manifest": audit.index_manifest,
                        "provenance_policy_release": audit.policy_release,
                        "provenance_policy_digest": audit.policy_digest,
                        "provenance_candidate_block": audit.candidate_block,
                    },
                )
        except ValueError as exc:
            events.event(
                "PROVENANCE_STATE_STALE_SKIPPED",
                stage="provenance",
                status=NOT_PROVEN,
                detail=stable_error(exc),
                remediation="a newer reservation exists; shadow stays observational",
            )
            return False
        except Exception as exc:  # noqa: BLE001 - shadow is observational only
            events.event(
                "PROVENANCE_STATE_WRITE_FAILED",
                stage="provenance",
                status=NOT_PROVEN,
                detail=stable_error(exc),
                remediation="fix the state file path/permissions; thin is unaffected",
            )
            return False
        events.event(
            "PROVENANCE_AUDIT_PASS",
            stage="provenance",
            status=PASS,
            duration_ms=audit.duration_ms,
            artifact=audit.manifest_digest,
            detail=(
                f"assurance={audit.assurance} "
                f"source_epoch={audit.source_epoch} release={audit.policy_release} "
                f"mechanism={audit.mechanism} verified_miners={len(audit.recomputed)} "
                f"unproven_candidates="
                f"{(getattr(audit, 'assurance_scope', {}) or {}).get('unproven_count', 'n/a')} "
                f"vector_agrees={audit.agrees_with_vector}"
            ),
            vector_agrees=audit.agrees_with_vector,
            assurance=audit.assurance,
        )
        return True
    else:
        events.event(
            "PROVENANCE_AUDIT_" + audit.status,
            stage="provenance",
            status=status_map.get(audit.status, FAIL),
            duration_ms=audit.duration_ms,
            artifact=audit.manifest_digest,
            detail=(audit.error or "; ".join(audit.discrepancies))[:512] or None,
            remediation=audit.remediation,
        )
        _lifecycle(
            "PROVENANCE " + audit.status.lower(),
            f"error={audit.error!r}" if audit.error else "",
        )
        return False


def _run_provenance_stage(
    args,
    payload: dict[str, Any],
    state_file: Path,
    current_block: int | None = None,
    historical_hotkeys_lookup=None,
    block_hash_lookup=None,
) -> tuple[str, dict[str, float] | None]:
    """Provenance stage for this tick.

    A bounded SINGLE-FLIGHT background worker drains and logs the previous
    audit, then starts a new audit without blocking. The signed-vector thin
    submission proceeds untouched regardless of audit speed or health.
    """
    settings = _provenance_settings(args)
    auditor = _get_shadow_auditor(args)
    for finished_audit, finished_state_file in auditor.drain():
        _log_audit_events(args, finished_audit, finished_state_file)
    submitted = auditor.submit(
        settings,
        network=args.network,
        netuid=args.netuid,
        payload=dict(payload),
        state=_read_state(state_file),
        state_file=state_file,
        current_block=current_block,
        historical_hotkeys_lookup=historical_hotkeys_lookup,
        block_hash_lookup=block_hash_lookup,
    )
    if not submitted:
        _get_events(args).event(
            "PROVENANCE_AUDIT_SKIPPED",
            stage="provenance",
            status=INFO,
            detail="previous shadow audit still in flight (single-flight)",
        )
    return "PENDING", None


def _run_launch_rewarded_set_gate(
    args: Any,
    *,
    payload: dict[str, Any],
    uid_weights: dict[int, float],
    hotkey_to_uid: dict[str, int],
    current_block: int,
    state_file: Path,
    state: dict[str, Any] | None = None,
    persist: bool = True,
) -> Any:
    """Synchronously replay every rewarded miner and prove vector agreement.

    This is a launch-only gate. Normal shadow operation remains non-blocking;
    the one bounded mainnet canary opts into this function and cannot reserve
    or submit its thin vector unless controlled raw evidence for every rewarded
    miner independently derives the identical UID allocation.
    """
    settings = replace(_provenance_settings(args), mode="authority")
    audit = run_audit(
        settings,
        network=args.network,
        netuid=args.netuid,
        vector_payload=payload,
        state=dict(state) if state is not None else _read_state(state_file),
        current_block=current_block,
        historical_hotkeys_lookup=_historical_metagraph_lookup(
            args.network, args.netuid
        ),
        block_hash_lookup=_block_hash_lookup(args.network),
    )
    rewarded = set(getattr(audit, "recomputed", {}) or {})
    receipt_hotkeys = set(getattr(audit, "receipt_hotkeys", ()) or ())
    raw_replayed = set(getattr(audit, "raw_replayed_hotkeys", ()) or ())
    if (
        audit.status != "PASS"
        or audit.agrees_with_vector is not True
        or not rewarded
        or rewarded != receipt_hotkeys
        or rewarded != raw_replayed
    ):
        _log_audit_events(args, audit, state_file, persist=False)
        raise wire.VectorError(
            "launch canary requires controlled raw replay of every rewarded "
            "miner and exact agreement with Cathedral's signed vector"
        )
    recomputed_uid_weights = _provenance_uid_weights(
        dict(audit.recomputed),
        mechanism=getattr(args, "provenance_mechanism", MECHANISM_DEFAULT)
        or MECHANISM_DEFAULT,
        burn_hotkey=getattr(args, "provenance_burn_hotkey", None),
        hotkey_to_uid=hotkey_to_uid,
    )
    if set(recomputed_uid_weights) != set(uid_weights) or any(
        not math.isclose(
            recomputed_uid_weights[uid],
            uid_weights[uid],
            rel_tol=0.0,
            abs_tol=1e-12,
        )
        for uid in uid_weights
    ):
        raise wire.VectorError(
            "launch rewarded-set recomputation does not match the thin UID vector"
        )
    if persist:
        try:
            _write_state_fenced(
                state_file,
                {
                    "provenance_network": args.network,
                    "provenance_netuid": args.netuid,
                    "provenance_last_source_epoch": audit.source_epoch,
                    "provenance_last_report_id": audit.report_id,
                    "provenance_index_epoch": audit.index_source_epoch,
                    "provenance_index_manifest": audit.index_manifest,
                    "provenance_policy_release": audit.policy_release,
                    "provenance_policy_digest": audit.policy_digest,
                    "provenance_candidate_block": audit.candidate_block,
                },
            )
        except (ValueError, OSError) as exc:
            raise wire.VectorError(
                "launch rewarded-set provenance reservation failed before submission: "
                f"{stable_error(exc)}"
            ) from exc
    _log_audit_events(args, audit, state_file, persist=False)
    _get_events(args).event(
        "LAUNCH_REWARDED_SET_GATE_PASS",
        stage="launch",
        status=PASS,
        artifact=audit.manifest_digest,
        detail=(
            f"source_epoch={audit.source_epoch} report_id={audit.report_id} "
            "all rewarded miners raw-replayed + vector agreement + UID agreement; "
            f"whole_epoch_assurance={audit.assurance}"
        ),
        source_epoch=audit.source_epoch,
        report_id=audit.report_id,
        vector_agrees=True,
    )
    _lifecycle(
        "LAUNCH rewarded-set gate",
        f"source_epoch={audit.source_epoch} vector_agrees=true "
        f"whole_epoch_assurance={audit.assurance}",
    )
    args._launch_rewarded_set_audit = audit
    return audit


def _revalidate_launch_after_rewarded_set_replay(
    args: Any,
    *,
    payload: dict[str, Any],
    audit: Any,
    fence_version: int,
) -> tuple[ChainPreflight, dict[str, int], dict[int, float]]:
    """Refresh every mutable chain/time input immediately before reservation."""
    accept_vector(
        payload,
        public_key_hex=args.public_key_hex,
        key_id=args.key_id,
        network=args.network,
        netuid=args.netuid,
        fence_version=fence_version,
    )
    fresh = chain_preflight(
        network=args.network,
        netuid=args.netuid,
        wallet_name=args.wallet_name,
        wallet_hotkey=args.wallet_hotkey,
    )
    _validate_resolved_chain_contract(args, fresh, require_sn39_identity=True)
    _bind_submission_identity(args, fresh)
    if fresh.block is None:
        raise wire.VectorError("fresh launch preflight has no finalized block")
    valid_from = getattr(audit, "report_valid_from_block", None)
    valid_until = getattr(audit, "report_valid_until_block", None)
    if (
        isinstance(valid_from, bool)
        or isinstance(valid_until, bool)
        or not isinstance(valid_from, int)
        or not isinstance(valid_until, int)
        or not valid_from <= fresh.block < valid_until
    ):
        raise wire.VectorError(
            "fresh finalized block is outside the provenance report validity window"
        )
    report_generated = wire._parse_canonical_utc(
        getattr(audit, "report_generated_at", None),
        field="provenance report generated_at",
    )
    report_valid_until = getattr(audit, "report_valid_until", None)
    report_expiry = wire._parse_canonical_utc(
        report_valid_until,
        field="provenance report valid_until",
    )
    if datetime.now(UTC) >= report_expiry:
        raise wire.VectorError("provenance report expired during launch replay")
    vector_generated = wire._parse_canonical_utc(
        payload.get("generated_at"),
        field="generated_at",
    )
    vector_expiry = wire._parse_canonical_utc(
        payload.get("expires_at"),
        field="expires_at",
    )
    inclusion_start = max(vector_generated, report_generated)
    inclusion_expiry = min(vector_expiry, report_expiry)
    if inclusion_start >= inclusion_expiry:
        raise wire.VectorError("launch inclusion time window is empty")

    uid_weights = vector_to_uid_weights(
        payload,
        fresh.hotkey_to_uid,
        require_policy=getattr(args, "require_policy", None),
    )
    recomputed_uid_weights = _provenance_uid_weights(
        dict(audit.recomputed),
        mechanism=getattr(args, "provenance_mechanism", MECHANISM_DEFAULT)
        or MECHANISM_DEFAULT,
        burn_hotkey=getattr(args, "provenance_burn_hotkey", None),
        hotkey_to_uid=fresh.hotkey_to_uid,
    )
    if set(recomputed_uid_weights) != set(uid_weights) or any(
        not math.isclose(
            recomputed_uid_weights[uid],
            uid_weights[uid],
            rel_tol=0.0,
            abs_tol=1e-12,
        )
        for uid in uid_weights
    ):
        raise wire.VectorError(
            "fresh launch UID mapping no longer agrees with rewarded-set recomputation"
        )
    _validate_chain_constraints(uid_weights, fresh)
    signed_rows = payload.get("weights")
    burn_snapshot = payload.get("burn_snapshot")
    if (
        fresh.hotkey_to_uid.get(fresh.validator_hotkey) != fresh.validator_uid
        or not isinstance(signed_rows, list)
        or len(signed_rows) != 1
        or not isinstance(signed_rows[0], dict)
        or not isinstance(burn_snapshot, dict)
    ):
        raise wire.VectorError(
            "fresh launch mapping differs from the immutable SN39 release boundary"
        )
    rewarded_hotkey = signed_rows[0].get("miner_hotkey")
    burn_hotkey = burn_snapshot.get("burn_hotkey")
    rewarded_uid = fresh.hotkey_to_uid.get(rewarded_hotkey)
    burn_uid = fresh.hotkey_to_uid.get(burn_hotkey)
    if (
        not isinstance(rewarded_hotkey, str)
        or not rewarded_hotkey
        or not isinstance(rewarded_uid, int)
        or burn_hotkey != getattr(args, "provenance_burn_hotkey", None)
        or burn_hotkey != fresh.subnet_owner_hotkey
        or not isinstance(burn_uid, int)
        or rewarded_uid == burn_uid
        or fresh.validator_uid in {rewarded_uid, burn_uid}
        or fresh.validator_hotkey in {rewarded_hotkey, burn_hotkey}
        or set(uid_weights) != {rewarded_uid, burn_uid}
        or not math.isclose(
            uid_weights[rewarded_uid],
            0.90,
            rel_tol=0.0,
            abs_tol=1e-12,
        )
        or not math.isclose(
            uid_weights[burn_uid],
            0.10,
            rel_tol=0.0,
            abs_tol=1e-12,
        )
    ):
        raise wire.VectorError(
            "fresh launch allocation is not the dynamically resolved rewarded-hotkey "
            "and subnet-owner burn-hotkey 90/10 release boundary"
        )
    args._launch_inclusion_policy = InclusionPolicy(
        valid_from_block=valid_from,
        valid_until_block=valid_until,
        valid_from_time=inclusion_start,
        valid_until_time=inclusion_expiry,
        expected_next_epoch_start_block=fresh.next_epoch_start_block,
    )
    _require_inclusion_policy_ready(args._launch_inclusion_policy, fresh)
    uid_safety = _require_uid_mapping_stability(
        fresh,
        {
            rewarded_uid: rewarded_hotkey,
            burn_uid: burn_hotkey,
        },
        mortal_period_blocks=args._launch_inclusion_policy.mortal_period_blocks,
    )
    _require_launch_evidence_after_rotations(
        payload=payload,
        audit=audit,
        uid_safety=uid_safety,
    )
    return fresh, fresh.hotkey_to_uid, uid_weights


def _launch_release_config_identity(args: Any) -> dict[str, Any]:
    """Exact immutable release and resolved launch profile under review."""
    release_sha = str(getattr(args, "launch_release_sha", "") or "")
    config_digest = str(getattr(args, "launch_config_sha256", "") or "")
    approval_file = Path(str(getattr(args, "launch_approval_file", "") or ""))
    if re.fullmatch(r"[0-9a-f]{40}", release_sha) is None:
        raise wire.VectorError(
            "launch preflight requires the immutable installed release SHA"
        )
    if re.fullmatch(r"sha256:[0-9a-f]{64}", config_digest) is None:
        raise wire.VectorError(
            "launch preflight requires the immutable launch-config digest"
        )
    if approval_file != SN39_LAUNCH_APPROVAL_FILE:
        raise wire.VectorError(
            "launch approval path differs from the immutable SN39 profile"
        )
    try:
        source_digest = (
            "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        )
    except OSError as exc:
        raise wire.VectorError("validator release source is unreadable") from exc
    return {
        "schema": "cathedral_sn39_launch_release_config_v1",
        "release_sha": release_sha,
        "launch_config_sha256": config_digest,
        "validator_source_sha256": source_digest,
        "network": str(args.network).strip().lower(),
        "netuid": int(args.netuid),
        "publisher_url": args.publisher_url,
        "weight_policy_public_key": args.public_key_hex,
        "weight_policy_key_id": args.key_id,
        "required_policy": args.require_policy,
        "state_file": str(Path(args.state_file)),
        "runtime_root": str(_submission_runtime_root(args)),
        "wallet_name": args.wallet_name,
        "wallet_hotkey_alias": args.wallet_hotkey,
        "evidence_url": args.evidence_url,
        "registry_keys": args.provenance_registry_keys,
        "registry_keys_digest": args.provenance_registry_keys_digest,
        "report_keys": args.provenance_report_keys,
        "report_keys_digest": args.provenance_report_keys_digest,
        "index_keys": args.provenance_index_keys,
        "index_keys_digest": args.provenance_index_keys_digest,
        "verifier_digest": args.provenance_verifier_digest,
        "producer_revision": args.provenance_source_revision,
        "mechanism": args.provenance_mechanism,
        "burn_hotkey": args.provenance_burn_hotkey,
        "controlled_dir": str(Path(args.provenance_controlled_dir)),
        "verifier_binary": str(Path(args.provenance_verifier_binary)),
        "approval_file": str(approval_file),
        "max_submissions": int(args.max_submissions),
        "weight_version_key": _weight_version_key(),
    }


def _launch_approval_bindings(
    args: Any,
    *,
    payload: dict[str, Any],
    audit: Any,
    preflight: ChainPreflight,
    uid_weights: dict[int, float],
    hotkey_to_uid: dict[str, int],
) -> dict[str, Any]:
    """Build every non-head fact an operator approves for one launch."""
    signed_vector_sha256 = (
        "sha256:" + hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    )
    signed_rows = payload.get("weights")
    burn_snapshot = payload.get("burn_snapshot")
    rewarded = sorted(set(getattr(audit, "recomputed", {}) or {}))
    replayed = sorted(set(getattr(audit, "raw_replayed_hotkeys", ()) or ()))
    receipt_hotkeys = sorted(set(getattr(audit, "receipt_hotkeys", ()) or ()))
    if (
        not isinstance(signed_rows, list)
        or not isinstance(burn_snapshot, dict)
        or not rewarded
        or rewarded != replayed
        or rewarded != receipt_hotkeys
    ):
        raise wire.VectorError(
            "launch approval requires one exact strict rewarded-set replay"
        )
    burn_hotkey = burn_snapshot.get("burn_hotkey")
    burn_uid = hotkey_to_uid.get(burn_hotkey)
    rewarded_uid_hotkeys = sorted(
        (hotkey_to_uid[hotkey], hotkey)
        for hotkey in rewarded
        if hotkey in hotkey_to_uid
    )
    ordered = sorted((int(uid), float(weight)) for uid, weight in uid_weights.items())
    uid_hotkeys = sorted(
        (int(uid), str(hotkey))
        for hotkey, uid in hotkey_to_uid.items()
        if uid in uid_weights
    )
    if (
        not isinstance(burn_hotkey, str)
        or not burn_hotkey
        or not isinstance(burn_uid, int)
        or len(rewarded_uid_hotkeys) != len(rewarded)
        or preflight.hotkey_to_uid != hotkey_to_uid
    ):
        raise wire.VectorError(
            "launch approval cannot bind the rewarded and burn hotkeys"
        )
    wire_uids, wire_weights = _wire_weights(
        [uid for uid, _weight in ordered],
        [weight for _uid, weight in ordered],
    )
    release_config = _launch_release_config_identity(args)
    return {
        "release_config": release_config,
        "release_config_digest": _sha256_document(release_config),
        "chain_genesis_hash": str(preflight.genesis_hash).lower(),
        "signer_validator_hotkey": preflight.validator_hotkey,
        "signer_validator_uid": preflight.validator_uid,
        "vector_id": payload.get("vector_id"),
        "policy_version": payload.get("policy_version"),
        "policy_contract": args.require_policy,
        "signed_vector_sha256": signed_vector_sha256,
        "rewarded_hotkeys": rewarded,
        "rewarded_uid_hotkeys": [[uid, hotkey] for uid, hotkey in rewarded_uid_hotkeys],
        "burn_hotkey": burn_hotkey,
        "burn_uid": burn_uid,
        "uid_weights": [[uid, weight] for uid, weight in ordered],
        "uid_hotkeys": [[uid, hotkey] for uid, hotkey in uid_hotkeys],
        "wire_uids": wire_uids,
        "wire_weights": wire_weights,
        "provenance": {
            "source_epoch": getattr(audit, "source_epoch", None),
            "report_id": getattr(audit, "report_id", None),
            "manifest": getattr(audit, "manifest_digest", None),
            "policy_release": getattr(audit, "policy_release", None),
            "policy_digest": getattr(audit, "policy_digest", None),
            "mechanism": getattr(audit, "mechanism", None),
            "whole_epoch_assurance": getattr(audit, "assurance", None),
            "verifier_binary_digest": getattr(audit, "verifier_binary_digest", None),
            "report_signing_key_id": getattr(audit, "report_signing_key_id", None),
            "signed_index": getattr(audit, "signed_index", None),
            "raw_replayed_hotkeys": replayed,
        },
    }


def _build_launch_approval(
    args: Any,
    *,
    payload: dict[str, Any],
    audit: Any,
    preflight: ChainPreflight,
    uid_weights: dict[int, float],
    hotkey_to_uid: dict[str, int],
) -> dict[str, Any]:
    if (
        preflight.block is None
        or preflight.block <= 0
        or _CHAIN_HASH_RE.fullmatch(str(preflight.finalized_hash).lower()) is None
    ):
        raise wire.VectorError(
            "launch approval requires a canonical finalized block and hash"
        )
    body = {
        "schema": SN39_LAUNCH_APPROVAL_SCHEMA,
        "bindings": _launch_approval_bindings(
            args,
            payload=payload,
            audit=audit,
            preflight=preflight,
            uid_weights=uid_weights,
            hotkey_to_uid=hotkey_to_uid,
        ),
        "reviewed_finalized_block": preflight.block,
        "reviewed_finalized_hash": str(preflight.finalized_hash).lower(),
        "approval_valid_until_block": (
            preflight.block + SN39_LAUNCH_APPROVAL_LIFETIME_BLOCKS
        ),
    }
    return {**body, "approval_digest": _sha256_document(body)}


def _validate_launch_approval_envelope(
    args: Any,
    document: dict[str, Any],
) -> dict[str, Any]:
    if set(document) != {
        "schema",
        "bindings",
        "reviewed_finalized_block",
        "reviewed_finalized_hash",
        "approval_valid_until_block",
        "approval_digest",
    }:
        raise wire.VectorError("launch approval fields differ from its schema")
    body = {key: value for key, value in document.items() if key != "approval_digest"}
    reviewed_block = body["reviewed_finalized_block"]
    valid_until = body["approval_valid_until_block"]
    reviewed_hash = body["reviewed_finalized_hash"]
    if (
        body["schema"] != SN39_LAUNCH_APPROVAL_SCHEMA
        or not isinstance(body["bindings"], dict)
        or isinstance(reviewed_block, bool)
        or not isinstance(reviewed_block, int)
        or reviewed_block <= 0
        or isinstance(valid_until, bool)
        or not isinstance(valid_until, int)
        or valid_until != reviewed_block + SN39_LAUNCH_APPROVAL_LIFETIME_BLOCKS
        or not isinstance(reviewed_hash, str)
        or _CHAIN_HASH_RE.fullmatch(reviewed_hash) is None
        or document["approval_digest"] != _sha256_document(body)
    ):
        raise wire.VectorError("launch approval digest or validity is malformed")
    bindings = body["bindings"]
    release_config = bindings.get("release_config")
    if (
        not isinstance(release_config, dict)
        or bindings.get("release_config_digest") != _sha256_document(release_config)
        or release_config != _launch_release_config_identity(args)
    ):
        raise wire.VectorError(
            "launch approval differs from the running release or config"
        )
    return document


def _load_launch_approval(args: Any) -> dict[str, Any]:
    path = Path(str(getattr(args, "launch_approval_file", "") or ""))
    return _validate_launch_approval_envelope(
        args,
        _read_root_launch_approval(path),
    )


def _require_launch_approval(
    args: Any,
    *,
    payload: dict[str, Any],
    audit: Any,
    preflight: ChainPreflight,
    uid_weights: dict[int, float],
    hotkey_to_uid: dict[str, int],
) -> dict[str, Any]:
    """Consume the exact operator-reviewed artifact before any reservation."""
    document = _load_launch_approval(args)
    reviewed_block = document["reviewed_finalized_block"]
    reviewed_hash = document["reviewed_finalized_hash"]
    valid_until = document["approval_valid_until_block"]
    if (
        preflight.block is None
        or preflight.block < reviewed_block
        or preflight.block + SN39_MORTAL_PERIOD_BLOCKS > valid_until
        or _CHAIN_HASH_RE.fullmatch(str(preflight.finalized_hash).lower()) is None
    ):
        raise wire.VectorError(
            "launch approval is stale or outside its finalized-head bound"
        )
    substrate = getattr(preflight.subtensor, "substrate", None)
    try:
        canonical_reviewed_hash = str(substrate.get_block_hash(reviewed_block)).lower()
        canonical_current_hash = str(substrate.get_block_hash(preflight.block)).lower()
    except (AttributeError, TypeError, ValueError) as exc:
        raise wire.VectorError(
            "launch approval finalized-head binding is unavailable"
        ) from exc
    if (
        canonical_reviewed_hash != reviewed_hash
        or canonical_current_hash != str(preflight.finalized_hash).lower()
    ):
        raise wire.VectorError(
            "launch approval finalized block/hash is no longer canonical"
        )
    expected_bindings = _launch_approval_bindings(
        args,
        payload=payload,
        audit=audit,
        preflight=preflight,
        uid_weights=uid_weights,
        hotkey_to_uid=hotkey_to_uid,
    )
    if document["bindings"] != expected_bindings:
        raise wire.VectorError(
            "launch approval differs from the fresh vector, signer, mapping, or "
            "strict provenance replay"
        )
    args._launch_approval = document
    return document


def _require_launch_journal_available(state: dict[str, Any]) -> None:
    launch_history = state.get("submission_launch_attempt_ids", [])
    if (
        state.get("submission_pending_id") is not None
        or state.get("submission_pending_phase") is not None
        or state.get("submission_launch_status") in {"pending", "finalized"}
        or not isinstance(launch_history, list)
        or bool(launch_history)
    ):
        raise wire.VectorError(
            "launch preflight requires a clear one-shot submission journal"
        )


def run_launch_preflight(args: Any, *, approval_out: Path) -> dict[str, Any]:
    """Run the exact launch gate read-only and emit a bounded operator approval."""
    if approval_out != SN39_LAUNCH_APPROVAL_FILE:
        raise wire.VectorError(
            "launch preflight output differs from the immutable approval path"
        )
    args.launch_preflight = True
    args.broadcast = False
    args.offline = False
    args.once = True
    _validate_runtime_contract(args)
    state = _read_state_without_mutation(Path(args.state_file))
    _require_launch_journal_available(state)
    fence = _state_policy_fence(state)
    payload = fetch_vector(args.publisher_url)
    accept_vector(
        payload,
        public_key_hex=args.public_key_hex,
        key_id=args.key_id,
        network=args.network,
        netuid=args.netuid,
        fence_version=fence,
    )
    preflight = chain_preflight(
        network=args.network,
        netuid=args.netuid,
        wallet_name=args.wallet_name,
        wallet_hotkey=args.wallet_hotkey,
    )
    _validate_resolved_chain_contract(args, preflight, require_sn39_identity=True)
    _bind_submission_identity(args, preflight)
    uid_weights = vector_to_uid_weights(
        payload,
        preflight.hotkey_to_uid,
        require_policy=args.require_policy,
    )
    _validate_chain_constraints(uid_weights, preflight)
    burn_hotkey = (payload.get("burn_snapshot") or {}).get("burn_hotkey")
    burn_uid = preflight.hotkey_to_uid.get(burn_hotkey)
    _require_no_validator_compute_reward(
        uid_weights,
        preflight=preflight,
        burn_uid=burn_uid,
    )
    audit = _run_launch_rewarded_set_gate(
        args,
        payload=payload,
        uid_weights=uid_weights,
        hotkey_to_uid=preflight.hotkey_to_uid,
        current_block=int(preflight.block),
        state_file=Path(args.state_file),
        state=state,
        persist=False,
    )
    fresh, hotkey_to_uid, uid_weights = _revalidate_launch_after_rewarded_set_replay(
        args,
        payload=payload,
        audit=audit,
        fence_version=fence,
    )
    approval = _build_launch_approval(
        args,
        payload=payload,
        audit=audit,
        preflight=fresh,
        uid_weights=uid_weights,
        hotkey_to_uid=hotkey_to_uid,
    )
    _write_root_launch_approval(approval_out, approval)
    _get_events(args).event(
        "LAUNCH_PREFLIGHT_APPROVED",
        stage="launch",
        status=PASS,
        artifact=approval["approval_digest"],
        detail=(
            f"read_only=true reviewed_finalized_block="
            f"{approval['reviewed_finalized_block']} "
            f"valid_until_block={approval['approval_valid_until_block']}"
        ),
        approval_digest=approval["approval_digest"],
        reviewed_finalized_block=approval["reviewed_finalized_block"],
        reviewed_finalized_hash=approval["reviewed_finalized_hash"],
        approval_valid_until_block=approval["approval_valid_until_block"],
    )
    return approval


# -- burn + uid mapping ---------------------------------------------------------


def apply_burn(
    scores_by_uid: dict[int, float],
    *,
    burn_uid: int | None,
    forced_burn_percentage: float,
) -> dict[int, float]:
    """burn% of total mass to burn_uid, remainder split proportionally across
    miners; normalized to sum 1.0. Empty miner set -> everything to burn_uid."""
    burn_frac = forced_burn_percentage / 100.0
    if burn_uid is not None:
        # burn_uid must never double-collect (miner share + forced burn);
        # any score that mapped onto it is dropped before allocation.
        scores_by_uid = {u: v for u, v in scores_by_uid.items() if u != burn_uid}
    total = sum(scores_by_uid.values())
    if total <= 0 or not scores_by_uid:
        if burn_uid is None:
            raise wire.VectorError("no miner mass and no burn_uid fallback")
        return {burn_uid: 1.0}
    out = {uid: (v / total) * (1.0 - burn_frac) for uid, v in scores_by_uid.items()}
    if burn_uid is not None and burn_frac > 0:
        out[burn_uid] = out.get(burn_uid, 0.0) + burn_frac
    norm = sum(out.values())
    return {uid: v / norm for uid, v in out.items()}


def accept_vector(
    payload: dict[str, Any],
    *,
    public_key_hex: str,
    key_id: str,
    network: str,
    netuid: int,
    fence_version: int,
) -> None:
    """Every check between 'bytes arrived' and 'safe to apply'. Raises on any
    failure — there is deliberately no partial acceptance."""
    wire.verify_signature(
        payload, public_key_hex=public_key_hex, expected_key_id=key_id
    )
    # `now_iso` is the host clock and remains the sole basis for freshness.
    # The publisher's observed `Date:` header is passed for one reason: so a
    # refusal that has already been decided can name the host clock instead of
    # reading as "Cathedral's feed is broken". It is not a time source.
    wire.invariant_check(
        payload,
        network=network,
        netuid=netuid,
        now_iso=_ms_iso_now(),
        publisher_clock=_observed_publisher_clock(),
    )
    pv = int(payload["policy_version"])
    if pv <= fence_version:
        raise wire.VectorError(
            f"rollback/replay: vector policy_version {pv} <= last accepted {fence_version}"
        )


def _confidential_tdx_v3_rows(payload: dict[str, Any]) -> list[dict[str, Any]] | None:
    metadata = payload.get("policy_metadata") or {}
    if not isinstance(metadata, dict):
        return None
    cap = metadata.get("confidential_tdx_cap") or {}
    if not isinstance(cap, dict) or cap.get("cap_version") != "v3":
        return None

    try:
        configured_fraction = float(cap["configured_fraction"])
    except (KeyError, TypeError, ValueError) as exc:
        raise wire.VectorError(
            "confidential_tdx v3 missing configured_fraction"
        ) from exc
    if not math.isfinite(configured_fraction) or not 0.0 < configured_fraction <= 0.10:
        raise wire.VectorError(
            f"confidential_tdx v3 invalid configured_fraction {configured_fraction!r}"
        )

    rows = payload.get("weights")
    if not isinstance(rows, list):
        raise wire.VectorError("confidential_tdx v3 weights must be a list")
    hotkeys: set[str] = set()
    weight_mass = 0.0
    base_mass = 0.0
    external_mass = 0.0
    for row in rows:
        if not isinstance(row, dict):
            raise wire.VectorError("confidential_tdx v3 weight row must be an object")
        try:
            weight = float(row["weight"])
            base = float(row["base_component"])
            external = float(row["external_component"])
        except (KeyError, TypeError, ValueError) as exc:
            raise wire.VectorError(
                "confidential_tdx v3 row missing or invalid attribution component"
            ) from exc
        if not all(
            math.isfinite(value) and value >= 0.0 for value in (weight, base, external)
        ):
            raise wire.VectorError(
                f"confidential_tdx v3 row {row.get('miner_hotkey')!r} "
                "has non-finite or negative attribution"
            )
        if not math.isclose(weight, base + external, rel_tol=0.0, abs_tol=1e-12):
            raise wire.VectorError(
                f"confidential_tdx v3 row {row.get('miner_hotkey')!r} "
                f"weight {weight!r} != base+external {base + external!r}"
            )
        hotkey = row.get("miner_hotkey")
        if not isinstance(hotkey, str) or not hotkey:
            raise wire.VectorError("confidential_tdx v3 row missing miner_hotkey")
        if hotkey in hotkeys:
            raise wire.VectorError(f"confidential_tdx v3 duplicate hotkey {hotkey!r}")
        hotkeys.add(hotkey)
        weight_mass = math.fsum((weight_mass, weight))
        base_mass = math.fsum((base_mass, base))
        external_mass = math.fsum((external_mass, external))

    component_mass = base_mass + external_mass
    if not math.isclose(weight_mass, component_mass, rel_tol=0.0, abs_tol=1e-12):
        raise wire.VectorError(
            f"confidential_tdx v3 weight mass {weight_mass!r} != "
            f"component mass {component_mass!r}"
        )
    if base_mass <= 0.0 or external_mass <= 0.0:
        raise wire.VectorError(
            "confidential_tdx v3 requires positive base and external mass"
        )
    realized_fraction = external_mass / component_mass
    if abs(realized_fraction - configured_fraction) > 1e-12:
        raise wire.VectorError(
            f"confidential_tdx v3 external fraction {realized_fraction!r} != "
            f"configured_fraction {configured_fraction!r}"
        )
    return rows


def _confidential_primary_meta(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Detect and strictly validate the v1 confidential-primary policy metadata.

    Returns the metadata dict when the signed contract is present, else None.
    Raises VectorError on a malformed/incompatible contract (never falls back).
    """
    metadata = payload.get("policy_metadata") or {}
    if not isinstance(metadata, dict):
        return None
    cp = metadata.get("confidential_primary")
    if cp is None:
        return None
    if not isinstance(cp, dict):
        raise wire.VectorError("confidential_primary metadata must be an object")
    if cp.get("contract_version") != "v1":
        raise wire.VectorError(
            "confidential_primary unsupported contract_version "
            f"{cp.get('contract_version')!r}"
        )
    if cp.get("source") != "cathedral_confidential_tdx":
        raise wire.VectorError(
            f"confidential_primary invalid source {cp.get('source')!r}"
        )
    try:
        base_mass = float(cp["base_mass"])
        confidential_mass = float(cp["confidential_mass"])
    except (KeyError, TypeError, ValueError) as exc:
        raise wire.VectorError(
            "confidential_primary missing base/confidential mass"
        ) from exc
    if base_mass != 0.0:
        raise wire.VectorError(
            f"confidential_primary base_mass must be 0, got {base_mass!r}"
        )
    if confidential_mass not in (0.0, 1.0):
        raise wire.VectorError(
            "confidential_primary confidential_mass must be 0 or 1, got "
            f"{confidential_mass!r}"
        )
    if not isinstance(cp.get("complete"), bool):
        raise wire.VectorError("confidential_primary complete flag must be a bool")
    # When the signed contract claims positive mass (mass=1), every liveness
    # field must be explicitly asserted. A degraded vector carries mass=0 and
    # these fields may be absent/false; that is the correct signed burn state.
    if confidential_mass == 1.0:
        if cp.get("mode") != "confidential_primary":
            raise wire.VectorError(
                "confidential_primary mass=1 requires mode=confidential_primary, "
                f"got {cp.get('mode')!r}"
            )
        if cp.get("complete") is not True:
            raise wire.VectorError("confidential_primary mass=1 requires complete=true")
        if cp.get("fresh") is not True:
            raise wire.VectorError("confidential_primary mass=1 requires fresh=true")
        if cp.get("confirmed") is not True:
            raise wire.VectorError(
                "confidential_primary mass=1 requires confirmed=true"
            )
    return cp


def _confidential_primary_scores(
    payload: dict[str, Any], cp: dict[str, Any], hotkey_to_uid: dict[str, int]
) -> dict[int, float]:
    """Map a signed confidential-primary vector to per-UID scores (mass 1.0).

    Every positive signed hotkey MUST map to exactly one current metagraph UID.
    Duplicate hotkeys, duplicate UIDs, nonfinite/negative attribution, and
    metadata/sum drift all reject the whole vector. There is no partial apply
    and no fallback. NO burn is applied here — the caller decides how the
    confidential lane's mass is placed: v2 applies the fixed 10% burn, v3 scales
    the lane to 70%. A degraded / mass-0 signed vector yields an EMPTY dict.
    """
    snap = payload["burn_snapshot"]
    confidential_mass = float(cp["confidential_mass"])
    rows = payload.get("weights")
    if not isinstance(rows, list):
        raise wire.VectorError("confidential_primary weights must be a list")

    hotkeys: set[str] = set()
    weight_mass = 0.0
    positive: list[tuple[str, float]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise wire.VectorError("confidential_primary weight row must be an object")
        if "base_component" not in row or "external_component" not in row:
            raise wire.VectorError(
                f"confidential_primary row {row.get('miner_hotkey')!r} "
                "must carry both base_component and external_component"
            )
        try:
            weight = float(row["weight"])
            base = float(row["base_component"])
            external = float(row["external_component"])
        except (KeyError, TypeError, ValueError) as exc:
            raise wire.VectorError(
                "confidential_primary row has invalid attribution"
            ) from exc
        if not all(math.isfinite(v) and v >= 0.0 for v in (weight, base, external)):
            raise wire.VectorError(
                f"confidential_primary row {row.get('miner_hotkey')!r} "
                "has non-finite or negative attribution"
            )
        if base != 0.0:
            raise wire.VectorError(
                f"confidential_primary row {row.get('miner_hotkey')!r} "
                "base_component must be 0"
            )
        if not math.isclose(weight, external, rel_tol=0.0, abs_tol=1e-12):
            raise wire.VectorError(
                f"confidential_primary row {row.get('miner_hotkey')!r} "
                "weight != external_component"
            )
        hotkey = row.get("miner_hotkey")
        if not isinstance(hotkey, str) or not hotkey:
            raise wire.VectorError("confidential_primary row missing miner_hotkey")
        if hotkey in hotkeys:
            raise wire.VectorError(f"confidential_primary duplicate hotkey {hotkey!r}")
        hotkeys.add(hotkey)
        weight_mass = math.fsum((weight_mass, weight))
        if weight > 0.0:
            positive.append((hotkey, weight))

    # Signed metadata mass must agree with the signed rows.
    if confidential_mass == 1.0:
        if not positive:
            raise wire.VectorError(
                "confidential_primary claims mass 1 but has no positive weight"
            )
        if not math.isclose(weight_mass, 1.0, rel_tol=0.0, abs_tol=1e-9):
            raise wire.VectorError(
                f"confidential_primary weight mass {weight_mass!r} != 1.0"
            )
    else:  # confidential_mass == 0.0
        if positive:
            raise wire.VectorError(
                "confidential_primary claims mass 0 but has positive weight"
            )
        if weight_mass != 0.0:
            raise wire.VectorError(
                f"confidential_primary weight mass {weight_mass!r} != 0.0"
            )

    # Every positive signed hotkey must map to exactly one current metagraph UID.
    scores: dict[int, float] = {}
    mapped_uids: set[int] = set()
    for hotkey, weight in positive:
        if hotkey not in hotkey_to_uid:
            raise wire.VectorError(
                f"confidential_primary hotkey {hotkey!r} has no current metagraph UID"
            )
        uid = hotkey_to_uid[hotkey]
        if uid == snap.get("burn_uid"):
            raise wire.VectorError(
                f"confidential_primary hotkey {hotkey!r} resolves to burn UID"
            )
        if uid in mapped_uids:
            raise wire.VectorError(
                f"confidential_primary duplicate UID {uid} in signed vector"
            )
        mapped_uids.add(uid)
        scores[uid] = weight

    return scores


def _confidential_primary_to_uid_weights(
    payload: dict[str, Any], cp: dict[str, Any], hotkey_to_uid: dict[str, int]
) -> dict[int, float]:
    """Map a signed confidential-primary vector to UID weights, all-or-nothing.

    The signed burn is applied ONLY after a fully successful mapping.
    """
    snap = payload["burn_snapshot"]
    scores = _confidential_primary_scores(payload, cp, hotkey_to_uid)
    # Signed burn applied ONLY after a fully successful mapping.
    return apply_burn(
        scores,
        burn_uid=snap.get("burn_uid"),
        forced_burn_percentage=float(snap["forced_burn_percentage"]),
    )


# Supported policy pins. When a validator opts in, ONLY the selected signed
# contract is applied; every other vector shape (legacy, v3 blend) is rejected.
REQUIRE_POLICY_CONFIDENTIAL_PRIMARY_V1 = "confidential_primary_v1"
REQUIRE_POLICY_VALIDATED_SUPPLY_V1 = "validated_supply_v1"
REQUIRE_POLICY_VALIDATED_SUPPLY_V3 = "validated_supply_v3"
REQUIRE_POLICY_CHOICES = (
    REQUIRE_POLICY_CONFIDENTIAL_PRIMARY_V1,
    REQUIRE_POLICY_VALIDATED_SUPPLY_V1,
    REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
)

# The weight policies the SN39 mainnet trust profile admits — a CLOSED set of
# exactly two named contracts, not "any validated_supply", not "anything in
# REQUIRE_POLICY_CHOICES".
#
# The trust profile exists so a tampered config cannot redirect mainnet weights,
# and it does that by comparing every pinned field to one literal. Exactly one
# field needs two admissible values, because SN39's allocation is meant to roll
# from the launch contract (90% validated supply / 10% burn) to v3 (70% Intel
# TDX / 30% CyberGym / 0% fixed burn) as a deliberate, coordinated re-pin. Every
# other field of the profile stays single-equality strict.
#
# Membership, not a predicate: adding a third economy has to be an edit to this
# tuple in a reviewed commit, exactly as adding one to the profile would be.
# confidential_primary_v1 is NOT here — it is a valid CLI pin for other subnets,
# but it is not an SN39 mainnet posture.
SN39_PINNED_REQUIRE_POLICIES = (
    REQUIRE_POLICY_VALIDATED_SUPPLY_V1,
    REQUIRE_POLICY_VALIDATED_SUPPLY_V3,
)


def _validated_supply_common(policy: dict[str, Any], payload: dict[str, Any]) -> None:
    """Burn-destination checks shared by every validated_supply contract.

    The burn hotkey must be present, match the snapshot, and NOT pin a UID (it is
    resolved by hotkey against the tick's metagraph). The per-contract fixed burn
    percentage is checked by the version-specific validator.
    """
    burn_hotkey = policy["burn_hotkey"]
    snap = payload.get("burn_snapshot") or {}
    if not isinstance(burn_hotkey, str) or not burn_hotkey:
        raise wire.VectorError("validated_supply burn_hotkey is missing")
    if snap.get("burn_hotkey") != burn_hotkey:
        raise wire.VectorError("validated_supply burn_hotkey does not match snapshot")
    if snap.get("burn_uid") is not None:
        raise wire.VectorError("validated_supply burn destination must not pin a UID")


def _validated_supply_v2_meta(
    policy: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    """Validate the launch-locked 90% TDX plus 10% fixed-burn contract (v2).

    Contract v2 makes the current launch boundary explicit: only Intel TDX can
    earn the 90% supply allocation and 10% is unconditionally burned. No GPU
    capability or future admission is represented by this signed payload.
    """
    expected = {
        "contract_version",
        "intel_tdx_allocation",
        "fixed_burn_allocation",
        "burn_hotkey",
    }
    if set(policy) != expected:
        raise wire.VectorError("validated_supply metadata fields mismatch")
    try:
        tdx = float(policy["intel_tdx_allocation"])
        fixed_burn = float(policy["fixed_burn_allocation"])
    except (TypeError, ValueError) as exc:
        raise wire.VectorError("validated_supply allocations must be numeric") from exc
    if not math.isclose(tdx, 0.90, rel_tol=0.0, abs_tol=1e-12):
        raise wire.VectorError("validated_supply Intel TDX allocation must equal 0.90")
    if not math.isclose(fixed_burn, 0.10, rel_tol=0.0, abs_tol=1e-12):
        raise wire.VectorError("validated_supply fixed burn allocation must equal 0.10")
    if not math.isclose(tdx + fixed_burn, 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise wire.VectorError("validated_supply allocations must sum to 1")
    _validated_supply_common(policy, payload)
    snap = payload.get("burn_snapshot") or {}
    try:
        burn_percentage = float(snap["forced_burn_percentage"])
    except (KeyError, TypeError, ValueError) as exc:
        raise wire.VectorError("validated_supply burn percentage is missing") from exc
    if not math.isclose(burn_percentage, 10.0, rel_tol=0.0, abs_tol=1e-12):
        raise wire.VectorError("validated_supply fixed burn allocation must burn 10%")
    return policy


def _validated_supply_v3_meta(
    policy: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    """Validate the coordinated 70% TDX / 30% CyberGym / 0% fixed-burn contract.

    v3 burns NO fixed share, but the burn hotkey is still the SINK for forfeited
    or ineligible lane mass, so it must still be present and unpinned; the fixed
    burn percentage in the snapshot must be exactly 0.
    """
    expected = {
        "contract_version",
        "intel_tdx_allocation",
        "cybergym_allocation",
        "fixed_burn_allocation",
        "burn_hotkey",
    }
    if set(policy) != expected:
        raise wire.VectorError("validated_supply v3 metadata fields mismatch")
    try:
        tdx = float(policy["intel_tdx_allocation"])
        cyber = float(policy["cybergym_allocation"])
        fixed_burn = float(policy["fixed_burn_allocation"])
    except (TypeError, ValueError) as exc:
        raise wire.VectorError("validated_supply allocations must be numeric") from exc
    if not math.isclose(tdx, 0.70, rel_tol=0.0, abs_tol=1e-12):
        raise wire.VectorError(
            "validated_supply v3 Intel TDX allocation must equal 0.70"
        )
    if not math.isclose(cyber, 0.30, rel_tol=0.0, abs_tol=1e-12):
        raise wire.VectorError(
            "validated_supply v3 CyberGym allocation must equal 0.30"
        )
    if not math.isclose(fixed_burn, 0.0, rel_tol=0.0, abs_tol=1e-12):
        raise wire.VectorError(
            "validated_supply v3 fixed burn allocation must equal 0.0"
        )
    if not math.isclose(tdx + cyber + fixed_burn, 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise wire.VectorError("validated_supply v3 allocations must sum to 1")
    _validated_supply_common(policy, payload)
    snap = payload.get("burn_snapshot") or {}
    try:
        burn_percentage = float(snap["forced_burn_percentage"])
    except (KeyError, TypeError, ValueError) as exc:
        raise wire.VectorError("validated_supply burn percentage is missing") from exc
    if not math.isclose(burn_percentage, 0.0, rel_tol=0.0, abs_tol=1e-12):
        raise wire.VectorError("validated_supply v3 fixed burn allocation must burn 0%")
    return policy


def _dry_run_contract_version(payload: dict[str, Any]) -> str | None:
    """The allocation contract a submission event should stamp, or None for v2.

    The public reproducer cross-checks the resolved `policy_pin` against this
    stamp: a v3 pin must produce a v3 result and vice versa, so neither
    direction of a pin/lane disagreement can reproduce. Nothing emitted the
    field before, which made a genuine v3 run unreproducible (it fails closed,
    reading as `contract_version=None` against a v3 pin) — this is the producer
    side of that contract.

    v2 deliberately stamps nothing: it is the launch wire contract and its
    absence is what the reproducer maps a v1 pin onto, so adding a value here
    would invalidate every existing v1 release.
    """
    # A plain read of the DECLARED contract, not a re-validation: by the time a
    # submission event is emitted the mapping path has already accepted this
    # payload (or raised with a precise message), so re-running the v3 shape
    # checks here would only add a second place to disagree. Anything that is
    # not an explicit v3 declaration stamps nothing, which a v3 pin then refuses.
    metadata = payload.get("policy_metadata")
    supply = metadata.get("validated_supply") if isinstance(metadata, dict) else None
    declared = supply.get("contract_version") if isinstance(supply, dict) else None
    return REQUIRE_POLICY_VALIDATED_SUPPLY_V3 if declared == "v3" else None


def _validated_supply_meta(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Detect and validate the signed validated_supply contract (v2 or v3).

    Returns the policy dict, or None when no validated_supply block is present.
    Raises VectorError on any malformed/unsupported contract (never falls back).
    """
    metadata = payload.get("policy_metadata") or {}
    if not isinstance(metadata, dict):
        return None
    policy = metadata.get("validated_supply")
    if policy is None:
        return None
    if not isinstance(policy, dict):
        raise wire.VectorError("validated_supply metadata must be an object")
    version = policy.get("contract_version")
    if version == "v2":
        return _validated_supply_v2_meta(policy, payload)
    if version == "v3":
        return _validated_supply_v3_meta(policy, payload)
    raise wire.VectorError("validated_supply unsupported contract_version")


def _resolve_burn_hotkey(
    payload: dict[str, Any], hotkey_to_uid: dict[str, int]
) -> dict[str, Any]:
    """Resolve a signed burn hotkey against this tick's metagraph snapshot."""
    snap = payload.get("burn_snapshot") or {}
    burn_hotkey = snap.get("burn_hotkey")
    if burn_hotkey is None:
        return payload
    if burn_hotkey not in hotkey_to_uid:
        raise wire.VectorError(
            f"burn hotkey {burn_hotkey!r} has no current metagraph UID"
        )
    resolved_uid = hotkey_to_uid[burn_hotkey]
    signed_uid = snap.get("burn_uid")
    if signed_uid is not None and int(signed_uid) != resolved_uid:
        raise wire.VectorError("signed burn UID does not match current burn hotkey")
    resolved = dict(payload)
    resolved["burn_snapshot"] = {**snap, "burn_uid": resolved_uid}
    return resolved


def _validated_supply_v3_to_uid_weights(
    payload: dict[str, Any],
    policy: dict[str, Any],
    cp: dict[str, Any] | None,
    hotkey_to_uid: dict[str, int],
) -> dict[int, float]:
    """Map a v3 (70% Intel TDX + 30% CyberGym + 0% fixed burn) vector to UID weights.

    Intel TDX lane: the signed confidential-primary rows, mapped hotkey->UID and
    scaled to intel_tdx_allocation (0.70). A degraded/revoked confidential lane
    (empty scores) sinks its whole 70% to the burn UID.

    CyberGym lane: the uid-keyed ``policy_metadata["cybergym_lane"]`` produced by
    ``cybergym_bridge.cybergym_allocation`` — re-verified here: its mass equals
    cybergym_allocation (0.30), contributing miners never collide with the burn
    UID, and any forfeited mass sits on the burn UID resolved from the burn
    hotkey against THIS tick's metagraph. Together the two lanes sum to 1.0. No
    fixed burn is applied (0%); the burn UID collects only forfeited lane mass.
    """
    snap = payload["burn_snapshot"]
    burn_uid = snap.get("burn_uid")
    if burn_uid is None:
        raise wire.VectorError("validated_supply v3 requires a resolved burn UID")
    burn_uid = int(burn_uid)
    tdx_alloc = float(policy["intel_tdx_allocation"])
    cyber_alloc = float(policy["cybergym_allocation"])

    # ---- Intel TDX lane (confidential-primary rows scaled to 70%) ----
    if cp is None:
        raise wire.VectorError(
            "validated_supply v3 requires confidential_primary evidence"
        )
    tdx_scores = _confidential_primary_scores(payload, cp, hotkey_to_uid)
    result: dict[int, float] = {}
    tdx_forfeited = 0.0
    if tdx_scores:
        tdx_mass = math.fsum(tdx_scores.values())
        if not math.isclose(tdx_mass, 1.0, rel_tol=0.0, abs_tol=1e-9):
            raise wire.VectorError(
                f"validated_supply v3 Intel TDX mass {tdx_mass!r} != 1.0"
            )
        for uid, weight in tdx_scores.items():
            if uid == burn_uid:
                raise wire.VectorError(
                    "validated_supply v3 Intel TDX hotkey resolves to burn UID"
                )
            result[uid] = result.get(uid, 0.0) + weight * tdx_alloc
    else:
        # Degraded/revoked confidential lane: the whole 70% sinks to burn.
        tdx_forfeited = tdx_alloc

    # ---- CyberGym lane (uid-keyed, 30%) ----
    metadata = payload.get("policy_metadata") or {}
    lane = metadata.get("cybergym_lane")
    if not isinstance(lane, dict):
        raise wire.VectorError("validated_supply v3 missing cybergym_lane metadata")
    if set(lane) != wire.V3_CYBERGYM_LANE_FIELDS:
        raise wire.VectorError("validated_supply v3 cybergym_lane fields mismatch")
    try:
        lane_fraction = float(lane["fraction"])
        lane_forfeited = float(lane["forfeited_fraction"] or 0.0)
    except (TypeError, ValueError) as exc:
        raise wire.VectorError(
            "validated_supply v3 cybergym_lane fraction/forfeited invalid"
        ) from exc
    if not math.isclose(lane_fraction, cyber_alloc, rel_tol=0.0, abs_tol=1e-12):
        raise wire.VectorError(
            f"validated_supply v3 cybergym_lane fraction {lane_fraction!r} != "
            f"{cyber_alloc!r}"
        )
    raw_weights = lane["weights"]
    if not isinstance(raw_weights, dict):
        raise wire.VectorError(
            "validated_supply v3 cybergym_lane weights must be an object"
        )
    lane_weights: dict[int, float] = {}
    for raw_uid, raw_weight in raw_weights.items():
        try:
            uid = int(raw_uid)
            weight = float(raw_weight)
        except (TypeError, ValueError) as exc:
            raise wire.VectorError(
                "validated_supply v3 cybergym_lane weight invalid"
            ) from exc
        if not math.isfinite(weight) or weight < 0.0:
            raise wire.VectorError(
                "validated_supply v3 cybergym_lane weight out of range"
            )
        if uid in lane_weights:
            raise wire.VectorError(
                f"validated_supply v3 cybergym_lane duplicate uid {uid}"
            )
        lane_weights[uid] = weight
    raw_uid_hotkeys = lane["uid_hotkeys"]
    if not isinstance(raw_uid_hotkeys, dict):
        raise wire.VectorError(
            "validated_supply v3 cybergym_lane uid_hotkeys must be an object"
        )
    try:
        uid_hotkeys = {int(uid): str(hotkey) for uid, hotkey in raw_uid_hotkeys.items()}
    except (TypeError, ValueError) as exc:
        raise wire.VectorError(
            "validated_supply v3 cybergym_lane uid_hotkey binding invalid"
        ) from exc
    if set(uid_hotkeys) != set(lane_weights) or any(
        not hotkey for hotkey in uid_hotkeys.values()
    ):
        raise wire.VectorError(
            "validated_supply v3 cybergym_lane uid_hotkey bindings mismatch"
        )
    for uid, hotkey in uid_hotkeys.items():
        if hotkey_to_uid.get(hotkey) != uid:
            raise wire.VectorError(
                "validated_supply v3 cybergym_lane recipient UID does not match "
                "the current hotkey"
            )
    lane_mass = math.fsum(lane_weights.values())
    if not math.isclose(lane_mass, cyber_alloc, rel_tol=0.0, abs_tol=1e-9):
        raise wire.VectorError(
            f"validated_supply v3 cybergym_lane mass {lane_mass!r} != {cyber_alloc!r}"
        )
    lane_burn_uid = lane["burn_uid"]
    if lane_forfeited > 0.0:
        if lane_burn_uid is None or int(lane_burn_uid) != burn_uid:
            # The forfeited share was resolved to a burn UID that is no longer the
            # burn hotkey's UID this tick (recycled UID / moved hotkey). Fail
            # closed rather than pay the forfeited share to whoever holds it now.
            raise wire.VectorError(
                "validated_supply v3 cybergym_lane burn UID does not match the "
                "current burn hotkey"
            )
    for uid, weight in lane_weights.items():
        if uid == burn_uid:
            # The forfeited CyberGym share; it must match the declared forfeited
            # fraction and is added to the burn sink below (not as a miner share).
            if not math.isclose(weight, lane_forfeited, rel_tol=0.0, abs_tol=1e-9):
                raise wire.VectorError(
                    "validated_supply v3 cybergym_lane burn weight != forfeited "
                    "fraction"
                )
            continue
        result[uid] = result.get(uid, 0.0) + weight

    # ---- Burn sink: 0% fixed + all forfeited lane mass ----
    burn_total = tdx_forfeited + lane_forfeited
    if burn_total > 0.0:
        result[burn_uid] = result.get(burn_uid, 0.0) + burn_total

    if not result:
        raise wire.VectorError("validated_supply v3 produced an empty vector")
    total = math.fsum(result.values())
    if not math.isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise wire.VectorError(f"validated_supply v3 weights sum {total!r} != 1.0")
    # Normalize away any sub-1e-9 float drift so the wire vector sums to exactly 1.0.
    return {uid: weight / total for uid, weight in result.items()}


def vector_to_uid_weights(
    payload: dict[str, Any],
    hotkey_to_uid: dict[str, int],
    *,
    require_policy: str | None = None,
) -> dict[int, float]:
    original_payload = payload
    validated_supply = _validated_supply_meta(original_payload)
    payload = _resolve_burn_hotkey(original_payload, hotkey_to_uid)
    snap = payload["burn_snapshot"]
    cp = _confidential_primary_meta(payload)
    supply_version = (
        validated_supply.get("contract_version") if validated_supply else None
    )
    # Pinned validators apply ONLY confidential_primary v1. A vector without a
    # valid v1 policy block is rejected here; a malformed block already raised
    # in _confidential_primary_meta. The legacy and v3 branches below are
    # unreachable while the pin is active.
    if require_policy == REQUIRE_POLICY_CONFIDENTIAL_PRIMARY_V1:
        if cp is None:
            raise wire.VectorError(
                "validator pinned to confidential_primary_v1 but vector carries "
                "no confidential_primary policy block"
            )
        return _confidential_primary_to_uid_weights(payload, cp, hotkey_to_uid)
    if require_policy == REQUIRE_POLICY_VALIDATED_SUPPLY_V1:
        if validated_supply is None:
            raise wire.VectorError(
                "validator pinned to validated_supply_v1 but vector carries "
                "no validated_supply policy block"
            )
        # A v1-pinned validator refuses any allocation drift, INCLUDING an
        # upgraded v3 contract: rolling to v3 is a coordinated re-pin, never a
        # silent acceptance under the launch pin.
        if supply_version != "v2":
            raise wire.VectorError(
                "validator pinned to validated_supply_v1 rejects "
                f"contract_version {supply_version!r}"
            )
        if cp is None:
            raise wire.VectorError(
                "validated_supply_v1 requires confidential_primary evidence"
            )
        return _confidential_primary_to_uid_weights(payload, cp, hotkey_to_uid)
    if require_policy == REQUIRE_POLICY_VALIDATED_SUPPLY_V3:
        if validated_supply is None or supply_version != "v3":
            raise wire.VectorError(
                "validator pinned to validated_supply_v3 but vector carries no v3 "
                "validated_supply policy block"
            )
        return _validated_supply_v3_to_uid_weights(
            payload, validated_supply, cp, hotkey_to_uid
        )
    # Unpinned: a signed v3 contract is applied through its own lane mapper before
    # the legacy confidential/base paths.
    if supply_version == "v3":
        return _validated_supply_v3_to_uid_weights(
            payload, validated_supply, cp, hotkey_to_uid
        )
    if cp is not None:
        return _confidential_primary_to_uid_weights(payload, cp, hotkey_to_uid)
    v3_rows = _confidential_tdx_v3_rows(payload)
    if v3_rows is not None:
        mapped_uids: set[int] = set()
        unmapped: list[str] = []
        for row in v3_rows:
            hotkey = row["miner_hotkey"]
            if hotkey not in hotkey_to_uid:
                unmapped.append(hotkey)
                continue
            uid = hotkey_to_uid[hotkey]
            if uid in mapped_uids:
                raise wire.VectorError(
                    f"confidential_tdx v3 duplicate UID {uid} in signed vector"
                )
            mapped_uids.add(uid)

        if unmapped:
            # This branch used to re-read `base_component` for EVERY row so the
            # signed 10% external cap could not be breached by the rows that
            # survived. It bought that at the price of paying an allocation
            # nobody signed: one deregistration stripped the external component
            # from rows whose own hotkey was still registered, and it announced
            # the switch with a bare print() that no journal consumer reads.
            # The signed vector is the only allocation this validator may
            # apply, so a vector it cannot map in full is refused. The refusal
            # reaches the structured stream through the callers' VECTOR_REJECTED
            # (stage=map) and TICK_FAILED events, which carry this message as
            # their `detail`.
            shown = ", ".join(sorted(unmapped)[:5])
            if len(unmapped) > 5:
                shown += f", +{len(unmapped) - 5} more"
            raise wire.VectorError(
                f"confidential_tdx v3 signed hotkeys not in the metagraph "
                f"({len(unmapped)} of {len(v3_rows)} rows): {shown}; refusing to "
                f"re-derive a base-only allocation the publisher never signed"
            )
        scores: dict[int, float] = {}
        for row in v3_rows:
            uid = hotkey_to_uid[row["miner_hotkey"]]
            value = row["weight"]
            if value > 0.0:
                scores[uid] = value
        return apply_burn(
            scores,
            burn_uid=snap.get("burn_uid"),
            forced_burn_percentage=float(snap["forced_burn_percentage"]),
        )

    scores: dict[int, float] = {}
    skipped = 0
    for w in payload["weights"]:
        uid = hotkey_to_uid.get(w["miner_hotkey"])
        if uid is None:
            skipped += 1  # deregistered since the vector was composed
            continue
        scores[uid] = scores.get(uid, 0.0) + float(w["weight"])
    if skipped:
        print(f"  ({skipped} hotkeys not in metagraph, skipped)")
    return apply_burn(
        scores,
        burn_uid=snap.get("burn_uid"),
        forced_burn_percentage=float(snap["forced_burn_percentage"]),
    )


# -- chain ----------------------------------------------------------------------


@dataclass(frozen=True)
class ChainPreflight:
    wallet: Any
    subtensor: Any
    hotkey_to_uid: dict[str, int]
    validator_hotkey: str
    validator_uid: int
    block: int | None
    min_allowed_weights: int
    max_weight_limit: float
    commit_reveal_enabled: bool = False
    genesis_hash: str = ""
    subnet_owner_hotkey: str = ""
    blocks_until_next_epoch: int | None = None
    next_epoch_start_block: int | None = None
    weights_rate_limit: int | None = None
    validator_blocks_since_last_update: int | None = None
    uid_mapping_stable_until_block: int | None = None
    replacement_safe_hotkeys: frozenset[str] = frozenset()
    subnet_free_uid_slots: int | None = None
    subnet_max_regs_per_block: int | None = None
    subnet_min_nonimmune_uids: int | None = None
    subnet_immunity_period: int | None = None
    subnet_temporally_immune_uids: int | None = None
    subnet_owner_coldkey: str = ""
    subnet_immune_owner_uids_limit: int | None = None
    subnet_owner_immortal_hotkeys: frozenset[str] = frozenset()
    subnet_max_uids: int | None = None
    subnet_registration_blocks: tuple[tuple[int, str, int], ...] = ()
    subnet_owned_hotkeys: tuple[str, ...] = ()
    # (uid, hotkey, incentive, stake, emission) at the finalized head, published
    # so a re-verifier can recompute eviction depth from the same raw inputs.
    subnet_prune_metrics: tuple[tuple[int, str, float, float, float], ...] = ()
    subnet_worst_case_evictions: int | None = None
    subnet_eviction_depth: tuple[tuple[str, int], ...] = ()
    finalized_hash: str = ""


@dataclass(frozen=True)
class ChainSubmission:
    success: bool
    extrinsic_hash: str | None = None
    block_hash: str | None = None
    block_number: int | None = None
    finalized: bool = False

    def __bool__(self) -> bool:
        return self.success


@dataclass(frozen=True)
class RecoveredSubmission:
    """Exact finalized thin transaction recovered without another write."""

    attempt_id: str
    policy_version: int
    vector_id: str
    signed_vector_sha256: str
    uid_weights: tuple[tuple[int, float], ...]
    burn_uid: int | None
    burn_share: float
    extrinsic_hash: str
    block_hash: str
    block_number: int

    @property
    def boundary_detail(self) -> str:
        vector = ",".join(f"{uid}:{weight:.6f}" for uid, weight in self.uid_weights)
        burn = (
            ""
            if self.burn_uid is None
            else f"burn_uid={self.burn_uid} burn_share={self.burn_share:.6f} "
        )
        return f"authority=thin uids={len(self.uid_weights)} {burn}vector={vector}"


@dataclass(frozen=True)
class RecoveredAuthoritySubmission:
    """Exact finalized authority-labelled launch recovered without a write."""

    attempt_id: str
    source_epoch: int
    report_id: str
    uid_weights: tuple[tuple[int, float], ...]
    burn_uid: int | None
    burn_share: float
    extrinsic_hash: str
    block_hash: str
    block_number: int

    @property
    def boundary_detail(self) -> str:
        vector = ",".join(f"{uid}:{weight:.6f}" for uid, weight in self.uid_weights)
        burn = (
            ""
            if self.burn_uid is None
            else f"burn_uid={self.burn_uid} burn_share={self.burn_share:.6f} "
        )
        return (
            f"authority=full_provenance uids={len(self.uid_weights)} "
            f"{burn}vector={vector}"
        )


def _canonical_uid30_launch_ss58(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        from bittensor_wallet import Keypair

        return str(Keypair(ss58_address=value).ss58_address) == value
    except Exception:  # noqa: BLE001 - malformed public identity is a refusal
        return False


def _uid30_successor_marked(identity: dict[str, Any]) -> bool:
    """Recognize any fragment of the sole source-owned successor schema."""

    return bool(
        {
            "successor_schema",
            "successor_contract",
            "successor_preview_sha256",
            "predecessor",
        }.intersection(identity)
    )


def _reviewed_uid30_attempt_id(identity: dict[str, Any]) -> str:
    """Hash the historical newline-terminated reviewed-UID30 identity."""

    dedup = {
        key: value
        for key, value in identity.items()
        if key not in {"mapping_block", "uid_safety", "fresh_miner_evidence"}
    }
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(dedup) + b"\n").hexdigest()


def _strict_uid30_successor_proofs(
    rows: object,
    *,
    uid_hotkeys: dict[int, str],
    mapping_block: int,
    label: str,
) -> tuple[tuple[str, int], ...]:
    """Validate two complete, distinct public HTTPS TDX proof artifacts."""

    if (
        not isinstance(rows, list)
        or len(rows) != 2
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise wire.VectorError(f"UID30 successor {label} has no two exact proofs")
    expected_by_hotkey = {hotkey: uid for uid, hotkey in uid_hotkeys.items()}
    by_hotkey = {row.get("hotkey"): row for row in rows}
    if len(by_hotkey) != 2 or set(by_hotkey) != set(expected_by_hotkey):
        raise wire.VectorError(
            f"UID30 successor {label} does not bind the two pinned hotkeys"
        )
    spkis: set[str] = set()
    endpoints: set[tuple[str, int]] = set()
    for hotkey, uid in expected_by_hotkey.items():
        row = by_hotkey[hotkey]
        raw_ip = row.get("ip")
        try:
            address = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise wire.VectorError(
                f"UID30 successor {label} miner IP is malformed"
            ) from exc
        spki = row.get("tls_spki_sha256")
        if (
            type(row.get("uid")) is not int
            or row.get("uid") != uid
            or type(row.get("port")) is not int
            or row.get("port") != 8081
            or not isinstance(address, ipaddress.IPv4Address)
            or not address.is_global
            or str(address) != raw_ip
            or row.get("qvl_status") != PASS
            or row.get("qvl_digest") != SN39_UID30_SUCCESSOR_QVL_SHA256
            or row.get("sat_rule") != SN39_UID30_SUCCESSOR_SAT_RULE
            or type(row.get("sat_units")) is not int
            or row.get("sat_units") <= 0
            or any(
                re.fullmatch(r"[0-9a-f]{64}", str(row.get(key, ""))) is None
                for key in (
                    "quote_sha256",
                    "report_data_sha256",
                    "tls_spki_sha256",
                )
            )
            or type(row.get("anchor_number")) is not int
            or row.get("anchor_number") <= 0
            or row.get("anchor_number") > mapping_block
            or re.fullmatch(r"0x[0-9a-f]{64}", str(row.get("anchor_hash", ""))) is None
        ):
            raise wire.VectorError(f"UID30 successor {label} proof is malformed")
        assert isinstance(raw_ip, str) and isinstance(spki, str)
        spkis.add(spki)
        endpoints.add((raw_ip, 8081))
    if len(spkis) != 2 or len(endpoints) != 2:
        raise wire.VectorError(
            f"UID30 successor {label} does not prove two distinct machines"
        )
    return tuple(sorted(expected_by_hotkey.items()))


def _strict_zero_burn_uid30_successor_contract(
    identity: dict[str, Any], *, lane: object
) -> dict[str, Any]:
    """Validate the one immutable two-miner UID30 successor contract."""

    raw_weights = identity.get("uid_weights")
    raw_hotkeys = identity.get("uid_hotkeys")
    if (
        not isinstance(raw_weights, list)
        or not isinstance(raw_hotkeys, list)
        or len(raw_weights) != 2
        or len(raw_hotkeys) != 2
        or any(
            not isinstance(row, list) or len(row) != 2
            for row in [*raw_weights, *raw_hotkeys]
        )
        or any(type(row[0]) is not int for row in [*raw_weights, *raw_hotkeys])
    ):
        raise wire.VectorError("UID30 successor has no exact two-row identity")
    uid_weights = {row[0]: row[1] for row in raw_weights}
    uid_hotkeys = {row[0]: row[1] for row in raw_hotkeys}
    ordered_uids = sorted(uid_weights)
    if (
        len(uid_weights) != 2
        or len(uid_hotkeys) != 2
        or raw_weights != [[uid, uid_weights[uid]] for uid in ordered_uids]
        or raw_hotkeys != [[uid, uid_hotkeys[uid]] for uid in ordered_uids]
        or set(uid_weights) != set(uid_hotkeys)
        or SN39_UID30_LAUNCH_VALIDATOR_UID in uid_weights
        or any(uid < 0 or uid > 65535 for uid in uid_weights)
        or any(
            type(weight) is not float or weight != 1.0
            for weight in uid_weights.values()
        )
        or any(type(hotkey) is not str for hotkey in uid_hotkeys.values())
        or set(uid_hotkeys.values())
        != {
            SN39_UID30_LAUNCH_MINER_HOTKEY,
            SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
        }
    ):
        raise wire.VectorError("UID30 successor rows are not the exact two hotkeys")

    mapping_block = identity.get("mapping_block")
    source_epoch = identity.get("source_epoch")
    owner = identity.get("subnet_owner_hotkey")
    preview_digest = identity.get("successor_preview_sha256")
    safety = identity.get("uid_safety")
    fresh = identity.get("fresh_miner_evidence")
    reviewed = identity.get("reviewed_preview")
    predecessor = identity.get("predecessor")
    if type(mapping_block) is not int or mapping_block <= 0:
        raise wire.VectorError("UID30 successor mapping block is malformed")
    _strict_uid30_successor_proofs(
        fresh,
        uid_hotkeys=uid_hotkeys,
        mapping_block=mapping_block,
        label="fresh evidence",
    )
    if not isinstance(reviewed, dict):
        raise wire.VectorError("UID30 successor reviewed preview is missing")
    _strict_uid30_successor_proofs(
        reviewed.get("miners"),
        uid_hotkeys=uid_hotkeys,
        mapping_block=mapping_block,
        label="reviewed evidence",
    )
    expected_vector = {
        "dests": ordered_uids,
        "weights_u16": [65535, 65535],
        "normalized": [[uid, "1.0"] for uid in ordered_uids],
        "expected_storage": [[uid, 65535] for uid in ordered_uids],
        "burn_destination": None,
        "burn_weight_u16": 0,
    }
    if reviewed.get("vector") != expected_vector:
        raise wire.VectorError("UID30 successor reviewed vector is not exact")

    predecessor_body = {
        "attempt_id": SN39_UID30_SUCCESSOR_PREDECESSOR_ID,
        "identity_sha256": SN39_UID30_SUCCESSOR_PREDECESSOR_IDENTITY_SHA256,
        "intent_sha256": SN39_UID30_SUCCESSOR_PREDECESSOR_INTENT_SHA256,
        "receipt_sha256": SN39_UID30_SUCCESSOR_PREDECESSOR_RECEIPT_SHA256,
        "uid_safety_sha256": SN39_UID30_SUCCESSOR_PREDECESSOR_UID_SAFETY_SHA256,
        "canonical_journal_filename": (
            SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
        ),
        "journal_identity_sha256": (SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_IDENTITY),
        "original_journal_sha256": (SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256),
        "extrinsic_hash": SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH,
        "block_hash": SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH,
        "block_number": SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK,
        "version_key": SN39_UID30_LAUNCH_VERSION_KEY,
        "wire": [[SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 65535]],
    }
    exact_predecessor = {
        **predecessor_body,
        "sha256": _sha256_document(predecessor_body),
    }
    if (
        lane != "authority"
        or identity.get("network") != "finney"
        or type(identity.get("netuid")) is not int
        or identity.get("netuid") != 39
        or type(identity.get("validator_uid")) is not int
        or identity.get("validator_uid") != SN39_UID30_LAUNCH_VALIDATOR_UID
        or identity.get("validator_hotkey") != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
        or identity.get("successor_schema") != SN39_UID30_SUCCESSOR_SCHEMA
        or identity.get("successor_contract") != SN39_UID30_SUCCESSOR_POLICY
        or identity.get("allocation_contract") != SN39_UID30_SUCCESSOR_POLICY
        or not isinstance(preview_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", preview_digest) is None
        or identity.get("report_id") != preview_digest
        or "burn_destination" not in identity
        or identity.get("burn_destination") is not None
        or type(identity.get("burn_share")) is not float
        or identity.get("burn_share") != 0.0
        or "burn_hotkey" in identity
        or source_epoch != mapping_block
        or not _canonical_uid30_launch_ss58(owner)
        or owner
        in {
            SN39_UID30_LAUNCH_VALIDATOR_HOTKEY,
            SN39_UID30_LAUNCH_MINER_HOTKEY,
            SN39_UID30_SUCCESSOR_SECOND_HOTKEY,
        }
        or not isinstance(safety, dict)
        or not safety
        or identity.get("uid_safety_sha256")
        != _sha256_document(safety).removeprefix("sha256:")
        or identity.get("fresh_evidence_sha256")
        != _sha256_document({"proofs": fresh}).removeprefix("sha256:")
        or type(identity.get("next_epoch_start_block")) is not int
        or identity.get("next_epoch_start_block") <= mapping_block
        or reviewed.get("valid_from_block") is None
        or reviewed.get("valid_until_block") is None
        or predecessor != exact_predecessor
        or reviewed.get("predecessor") != exact_predecessor
        or identity.get("operator_declared_authority") is not True
        or identity.get("exclusive_writer_assertion")
        != {
            "asserted": True,
            "scope": "all_other_uid30_processes_and_hosts_stopped",
        }
    ):
        raise wire.VectorError(
            "zero-burn UID30 successor differs from the exact reviewed contract"
        )
    assert isinstance(owner, str)
    return {
        "kind": "two_miner_successor",
        "owner": owner,
        "uid_weights": tuple((uid, 1.0) for uid in ordered_uids),
        "uid_hotkeys": tuple((uid, uid_hotkeys[uid]) for uid in ordered_uids),
    }


def _strict_zero_burn_uid30_contract(
    identity: dict[str, Any], *, lane: object
) -> dict[str, Any] | None:
    """Strictly classify either source-owned zero-burn UID30 contract."""

    if _uid30_successor_marked(identity):
        return _strict_zero_burn_uid30_successor_contract(identity, lane=lane)
    owner = _strict_zero_burn_uid30_owner_legacy(identity, lane=lane)
    if owner is None:
        return None
    uid = identity["uid_weights"][0][0]
    return {
        "kind": "one_miner_launch",
        "owner": owner,
        "uid_weights": ((uid, 1.0),),
        "uid_hotkeys": ((uid, SN39_UID30_LAUNCH_MINER_HOTKEY),),
    }


def _strict_zero_burn_uid30_owner_legacy(
    identity: dict[str, Any], *, lane: object
) -> str | None:
    """Return the exact UID30 launch owner, or reject a partial launch marker."""

    marker_keys = {
        "uid30_launch_schema",
        "uid30_launch_policy",
        "uid30_launch_preview_sha256",
        "allocation_contract",
    }
    if not marker_keys.intersection(identity):
        return None
    raw_uid_weights = identity.get("uid_weights")
    raw_uid_hotkeys = identity.get("uid_hotkeys")
    owner = identity.get("subnet_owner_hotkey")
    preview_digest = identity.get("uid30_launch_preview_sha256")
    reviewed = identity.get("reviewed_preview")
    fresh = identity.get("fresh_miner_evidence")
    if not isinstance(reviewed, dict) or not isinstance(fresh, dict):
        raise wire.VectorError(
            "zero-burn UID30 identity has no exact reviewed and fresh miner evidence"
        )
    reviewed_miner = reviewed.get("miner")
    reviewed_vector = reviewed.get("vector")
    if not isinstance(reviewed_miner, dict) or not isinstance(reviewed_vector, dict):
        raise wire.VectorError("zero-burn UID30 reviewed identity is malformed")
    exact_rows = bool(
        isinstance(raw_uid_weights, list)
        and len(raw_uid_weights) == 1
        and isinstance(raw_uid_weights[0], list)
        and len(raw_uid_weights[0]) == 2
        and isinstance(raw_uid_hotkeys, list)
        and len(raw_uid_hotkeys) == 1
        and isinstance(raw_uid_hotkeys[0], list)
        and len(raw_uid_hotkeys[0]) == 2
    )
    if not exact_rows:
        raise wire.VectorError("zero-burn UID30 identity is not one exact target row")
    uid = raw_uid_weights[0][0]
    weight = raw_uid_weights[0][1]
    hotkey_uid = raw_uid_hotkeys[0][0]
    miner_hotkey = raw_uid_hotkeys[0][1]
    mapping_block = identity.get("mapping_block")
    source_epoch = identity.get("source_epoch")
    burn_share = identity.get("burn_share")
    if (
        lane != "authority"
        or identity.get("network") != "finney"
        or type(identity.get("netuid")) is not int
        or identity.get("netuid") != 39
        or type(identity.get("validator_uid")) is not int
        or identity.get("validator_uid") != SN39_UID30_LAUNCH_VALIDATOR_UID
        or identity.get("validator_hotkey") != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
        or identity.get("uid30_launch_schema") != SN39_UID30_LAUNCH_SCHEMA
        or identity.get("uid30_launch_policy") != SN39_UID30_LAUNCH_POLICY
        or identity.get("allocation_contract") != SN39_UID30_LAUNCH_POLICY
        or not isinstance(preview_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", preview_digest) is None
        or identity.get("report_id") != preview_digest
        or "burn_destination" not in identity
        or identity.get("burn_destination") is not None
        or type(burn_share) is not float
        or burn_share != 0.0
        or "burn_hotkey" in identity
        or identity.get("exclusive_writer_assertion")
        != {
            "asserted": True,
            "scope": "all_other_uid30_processes_and_hosts_stopped",
        }
        or not _canonical_uid30_launch_ss58(owner)
        or owner
        in {
            SN39_UID30_LAUNCH_VALIDATOR_HOTKEY,
            SN39_UID30_LAUNCH_MINER_HOTKEY,
        }
        or type(uid) is not int
        or uid < 0
        or uid > 65535
        or uid == SN39_UID30_LAUNCH_VALIDATOR_UID
        or type(hotkey_uid) is not int
        or hotkey_uid != uid
        or miner_hotkey != SN39_UID30_LAUNCH_MINER_HOTKEY
        or type(weight) is not float
        or weight != 1.0
        or type(mapping_block) is not int
        or mapping_block <= 0
        or type(source_epoch) is not int
        or source_epoch != mapping_block
        or not isinstance(identity.get("uid_safety"), dict)
        or not identity["uid_safety"]
        or reviewed_miner.get("uid") != uid
        or reviewed_miner.get("hotkey") != SN39_UID30_LAUNCH_MINER_HOTKEY
        or fresh.get("uid") != uid
        or fresh.get("hotkey") != SN39_UID30_LAUNCH_MINER_HOTKEY
        or reviewed_vector.get("dests") != [uid]
        or reviewed_vector.get("weights_u16") != [65535]
        or reviewed_vector.get("burn_destination") is not None
        or reviewed_vector.get("burn_weight_u16") != 0
        or reviewed_vector.get("sum_u16") != 65535
    ):
        raise wire.VectorError(
            "zero-burn UID30 identity differs from the exact reviewed launch contract"
        )
    assert isinstance(owner, str)
    return owner


def _strict_zero_burn_uid30_owner(
    identity: dict[str, Any], *, lane: object
) -> str | None:
    """Return the exact zero-burn owner, rejecting every partial marker."""

    contract = _strict_zero_burn_uid30_contract(identity, lane=lane)
    return None if contract is None else str(contract["owner"])


def _classify_zero_burn_uid30_historical_weights(
    subtensor: Any,
    *,
    block_hash: str,
    wire_uids: list[int],
    wire_weights: list[int],
    reason_out: list[str] | None = None,
) -> str:
    """Prove the exact UID30 mechanism-0 storage row at inclusion.

    A decoded successful extrinsic proves what the signer asked the chain to do.
    The historical storage row proves what SN39 retained for UID30 at the same
    finalized block. Archive/RPC failures remain inconclusive so recovery stays
    fenced, while a concrete non-exact row is a terminal contradiction.
    """

    if not wire_uids or len(wire_uids) != len(wire_weights):
        return _receipt_verdict(
            reason_out,
            FAIL,
            "zero-burn UID30 storage proof did not receive one exact vector",
        )
    substrate = getattr(subtensor, "substrate", None)
    if substrate is None:
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "the subtensor client exposes no substrate interface for UID30 storage",
        )
    try:
        observed = substrate.query(
            module="SubtensorModule",
            storage_function="Weights",
            params=[
                get_mechid_storage_index(39, 0),
                SN39_UID30_LAUNCH_VALIDATOR_UID,
            ],
            block_hash=block_hash,
        )
        rows = getattr(observed, "value", observed)
    except Exception as exc:  # noqa: BLE001 - archive/RPC failure is inconclusive
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "chain read failed at substrate.query(SubtensorModule.Weights for "
            f"UID30): {stable_error(exc)}",
        )
    expected_list = [list(row) for row in zip(wire_uids, wire_weights)]
    expected_tuple = list(zip(wire_uids, wire_weights))
    if rows != expected_list and rows != expected_tuple:
        return _receipt_verdict(
            reason_out,
            FAIL,
            "UID30 mechanism-0 storage at inclusion differs from the exact "
            "reviewed zero-burn vector",
        )
    return _receipt_verdict(
        reason_out,
        PASS,
        "UID30 mechanism-0 storage at inclusion matches the exact reviewed vector",
    )


CHAIN_OPERATION_DEADLINE_SECS = 180.0
# A write is refused unless its evidence remains valid beyond the entire
# synchronous SDK deadline plus an explicit clock/RPC margin. The mortal era
# is intentionally short and is also bounded by the evidence block window.
SN39_MIN_VALIDITY_MARGIN_SECS = 60.0

# The one NOT_PROVEN reason that is a WAIT rather than a fault: the receipt's
# block exists and is canonical, but the finalized head has not reached it yet.
RECEIPT_FINALITY_LAG_REASON = "the finalized head is still behind the receipt block"
# How long to let finality catch up in-process before reporting NOT_PROVEN.
# Bittensor finalizes a few blocks behind the head, so a proof attempted
# immediately after a successful submission routinely loses this race: the
# process exits, systemd restarts it, and the fresh process proves the very
# same receipt seconds later. That restart-per-write was costing a tick every
# cycle. Waiting here changes no verdict — the receipt is still only PASSed on
# proof, and an unfinalized receipt after the bound is still NOT_PROVEN and
# still fenced — it just stops treating a known, bounded lag as a fault.
RECEIPT_FINALITY_WAIT_SECS = 48.0
RECEIPT_FINALITY_POLL_SECS = 4.0
# The era is anchored at the PROVEN FINALIZED block, not the best head, so the
# real inclusion window is this period minus the live finality lag. Measured
# finney lag is a steady 2-3 blocks, which left a 4-block era with only one or
# two blocks of validity by the time the transaction reached the pool, and it
# expired unincluded. Sixteen covers the lag plus block-author latency while
# keeping the era far shorter than an epoch.
#
# This is also the era-registration bound: worst_case_evictions scales as
# max_regs_per_block * this constant, so widening the window automatically
# tightens the UID replacement-safety proof rather than loosening it. At the
# live subnet state that means a worst case of 16 evictions against a rewarded
# target proven safe to an eviction depth of 112.
SN39_MORTAL_PERIOD_BLOCKS = 16
# A launch write must finalize comfortably before the next epoch. UID targets
# are separately proven replacement-safe for the complete mortal era; there is
# deliberately no automatic second/corrective weight write.
SN39_EPOCH_FINALITY_MARGIN_BLOCKS = 32


@dataclass(frozen=True)
class InclusionPolicy:
    """Policy facts that must still hold at the actual inclusion block."""

    valid_from_block: int
    valid_until_block: int
    valid_from_time: datetime
    valid_until_time: datetime
    require_commit_reveal_disabled: bool = True
    mortal_period_blocks: int = SN39_MORTAL_PERIOD_BLOCKS
    expected_next_epoch_start_block: int | None = None


@dataclass(frozen=True)
class ContinuousAuthorization:
    """Separate root-signed recurring-write authorization."""

    authorization_sha256: str
    submission_journal: str
    launch_attempt_id: str
    release_sha256: str
    reproducer_revision: str
    validator_hotkey: str
    genesis_hash: str
    lanes: tuple[str, ...]
    issued_at: str
    valid_from_time: str
    valid_until_time: str
    valid_from_block: int
    valid_until_block: int
    valid_from_nonce: int
    valid_until_nonce_exclusive: int
    max_attempts: int


def _canonical_policy_time(value: datetime) -> str:
    if value.tzinfo is None:
        raise wire.VectorError("inclusion policy time must be timezone-aware")
    moment = value.astimezone(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{moment.microsecond // 1000:03d}Z"
    )


def _inclusion_policy_identity(policy: InclusionPolicy) -> dict[str, Any]:
    return {
        "valid_from_block": policy.valid_from_block,
        "valid_until_block": policy.valid_until_block,
        "valid_from_time": _canonical_policy_time(policy.valid_from_time),
        "valid_until_time": _canonical_policy_time(policy.valid_until_time),
        "require_commit_reveal_disabled": policy.require_commit_reveal_disabled,
        "mortal_period_blocks": policy.mortal_period_blocks,
        "expected_next_epoch_start_block": policy.expected_next_epoch_start_block,
    }


def _continuous_authorization_identity(
    authorization: ContinuousAuthorization,
) -> dict[str, Any]:
    return {
        "authorization_sha256": authorization.authorization_sha256,
        "submission_journal": authorization.submission_journal,
        "launch_attempt_id": authorization.launch_attempt_id,
        "release_sha256": authorization.release_sha256,
        "reproducer_revision": authorization.reproducer_revision,
        "validator_hotkey": authorization.validator_hotkey,
        "genesis_hash": authorization.genesis_hash,
        "lanes": list(authorization.lanes),
        "issued_at": authorization.issued_at,
        "valid_from_time": authorization.valid_from_time,
        "valid_until_time": authorization.valid_until_time,
        "valid_from_block": authorization.valid_from_block,
        "valid_until_block": authorization.valid_until_block,
        "valid_from_nonce": authorization.valid_from_nonce,
        "valid_until_nonce_exclusive": authorization.valid_until_nonce_exclusive,
        "max_attempts": authorization.max_attempts,
    }


def _require_inclusion_policy_ready(
    policy: InclusionPolicy,
    preflight: ChainPreflight,
    *,
    now: datetime | None = None,
) -> None:
    """Refuse a write whose off-chain evidence can expire during submission."""
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        raise wire.VectorError("submission clock must be timezone-aware")
    if preflight.block is None:
        raise wire.VectorError("inclusion policy requires a finalized chain block")
    period = policy.mortal_period_blocks
    if (
        isinstance(period, bool)
        or not isinstance(period, int)
        or period < 4
        or period > 65536
        or period & (period - 1)
    ):
        raise wire.VectorError(
            "inclusion policy mortal period must be a power of two from 4 to 65536"
        )
    if not (
        policy.valid_from_block <= preflight.block < policy.valid_until_block
        and policy.valid_until_block - preflight.block >= period
    ):
        raise wire.VectorError(
            "submission lacks a full mortal era inside the evidence block window"
        )
    if not policy.valid_from_time <= moment < policy.valid_until_time:
        raise wire.VectorError(
            "submission time is outside the evidence inclusion window"
        )
    minimum = CHAIN_OPERATION_DEADLINE_SECS + SN39_MIN_VALIDITY_MARGIN_SECS
    if (policy.valid_until_time - moment).total_seconds() < minimum:
        raise wire.VectorError(
            "evidence validity remaining is shorter than the bounded submission "
            f"window ({minimum:.0f}s required)"
        )
    if policy.require_commit_reveal_disabled and preflight.commit_reveal_enabled:
        raise wire.VectorError(
            "inclusion policy requires commit-reveal disabled before submission"
        )
    rate_limit = preflight.weights_rate_limit
    blocks_since_update = preflight.validator_blocks_since_last_update
    if (
        isinstance(rate_limit, bool)
        or not isinstance(rate_limit, int)
        or rate_limit < 0
        or isinstance(blocks_since_update, bool)
        or not isinstance(blocks_since_update, int)
        or blocks_since_update < 0
    ):
        raise wire.VectorError(
            "submission cannot prove the live validator weight-update cooldown"
        )
    # The runtime currently permits equality while the locked SDK helper uses
    # strict greater-than. This direct extrinsic path conservatively observes
    # the stricter boundary so an SDK/runtime change cannot make launch timing
    # optimistic.
    if blocks_since_update <= rate_limit:
        raise wire.VectorError(
            "submission is inside the live validator weight-update cooldown"
        )
    remaining = preflight.blocks_until_next_epoch
    next_epoch = preflight.next_epoch_start_block
    required_epoch_room = (
        policy.mortal_period_blocks + SN39_EPOCH_FINALITY_MARGIN_BLOCKS
    )
    # One refusal, but six distinct reasons — and they call for opposite
    # operator responses. "The tick landed 15 blocks from the epoch boundary"
    # resolves itself on the next tick and needs nobody; "the signed vector
    # expects a different epoch than the chain reports" is a producer
    # disagreement that never resolves on its own. Collapsing them into one
    # sentence made a routine, self-clearing wait indistinguishable from a
    # stuck publisher, which is exactly the confusion issue #68 was about.
    if isinstance(remaining, bool) or not isinstance(remaining, int):
        raise wire.VectorError(
            "submission cannot prove the blocks remaining in this epoch "
            f"(got {remaining!r})"
        )
    if isinstance(next_epoch, bool) or not isinstance(next_epoch, int):
        raise wire.VectorError(
            f"submission cannot prove the next epoch start block (got {next_epoch!r})"
        )
    if next_epoch != preflight.block + remaining:
        raise wire.VectorError(
            "chain epoch arithmetic is inconsistent: next epoch start "
            f"{next_epoch} != finalized block {preflight.block} + {remaining} "
            "blocks remaining"
        )
    if policy.expected_next_epoch_start_block != next_epoch:
        raise wire.VectorError(
            "the signed inclusion policy expects next epoch start "
            f"{policy.expected_next_epoch_start_block}, but the chain reports "
            f"{next_epoch}; the vector was composed against a different epoch"
        )
    if remaining < required_epoch_room:
        raise _EpochRoomUnavailable(
            f"only {remaining} block(s) remain in this epoch; a submission "
            f"needs {required_epoch_room} "
            f"({policy.mortal_period_blocks} mortal + "
            f"{SN39_EPOCH_FINALITY_MARGIN_BLOCKS} finality margin) to prove "
            "mortal inclusion and finalized verification. This clears itself "
            f"at block {next_epoch}"
        )


def _chain_weight_cooldown_remaining_blocks(preflight: ChainPreflight) -> int | None:
    """Blocks the chain still owes this validator before it accepts a write.

    Reads only what chain preflight already sampled at the finalized head, so
    this costs no extra RPC. The boundary is the same one
    `_require_inclusion_policy_ready` enforces (`blocks_since_update` must
    exceed `weights_rate_limit`), expressed as a countdown instead of a
    verdict. `None` means the cooldown could not be read as two exact
    non-negative integers: that is NOT a routine wait and is deliberately
    left to the strict gate, which fails the tick closed.
    """
    rate_limit = preflight.weights_rate_limit
    blocks_since_update = preflight.validator_blocks_since_last_update
    if (
        isinstance(rate_limit, bool)
        or not isinstance(rate_limit, int)
        or rate_limit < 0
        or isinstance(blocks_since_update, bool)
        or not isinstance(blocks_since_update, int)
        or blocks_since_update < 0
    ):
        return None
    return max(0, rate_limit + 1 - blocks_since_update)


# Nominal Bittensor block time, used only to express the chain's own cooldown
# window as a duration for the wall-clock stand-down below. Nothing on the
# write path depends on this being exact: it sizes an alarm, not a deadline.
CHAIN_BLOCK_SECONDS = 12.0

# How many whole cooldown windows of real time may elapse with the cooldown
# still refusing before the skip is treated as a fault. Two is deliberately
# generous — on a chain that is advancing at all, the block-delta stand-down
# fires after one window of head advance and this never runs out.
CHAIN_WEIGHT_COOLDOWN_STANDDOWN_WINDOWS = 2.0

# Floor for the same bound, so a subnet with a very small `weights_rate_limit`
# cannot turn the backstop into a hair trigger on ordinary RPC jitter.
CHAIN_WEIGHT_COOLDOWN_STANDDOWN_FLOOR_SECONDS = 600.0


def _chain_weight_cooldown_standdown_seconds(preflight: ChainPreflight) -> float:
    """Real seconds the cooldown may keep refusing before it counts as a fault.

    Derived from the chain's own `weights_rate_limit` so the bound scales with
    whatever the subnet actually configures, rather than pinning a constant
    that is only right for today's SN39.
    """
    rate_limit = preflight.weights_rate_limit
    if (
        isinstance(rate_limit, bool)
        or not isinstance(rate_limit, int)
        or rate_limit < 0
    ):
        return CHAIN_WEIGHT_COOLDOWN_STANDDOWN_FLOOR_SECONDS
    window_seconds = (rate_limit + 1) * CHAIN_BLOCK_SECONDS
    return max(
        CHAIN_WEIGHT_COOLDOWN_STANDDOWN_FLOOR_SECONDS,
        window_seconds * CHAIN_WEIGHT_COOLDOWN_STANDDOWN_WINDOWS,
    )


def _reset_chain_weight_cooldown_anchor(args: Any) -> None:
    """Forget the current cooldown episode. Both anchors move together."""
    args._chain_weight_cooldown_anchor_block = None
    args._chain_weight_cooldown_anchor_monotonic = None


def _require_chain_weight_write_permitted(
    args: Any,
    preflight: ChainPreflight | None,
    *,
    monotonic: Any = time.monotonic,
) -> None:
    """Skip — never fail — a tick the subnet's own cooldown already forbids.

    Called immediately before the submission section reserves anything, so a
    skip leaves no attempt fence, no signed intent, and no chain call. The
    cooldown must be positively proven from the finalized head before a refusal
    is downgraded from a failure to a skip, and the skip stands down — stops
    skipping, and lets the strict gate raise into `TICK_FAILED` — as soon as
    *either* of two bounds is exceeded:

    * the finalized head has advanced further than one whole rate-limit window
      while the cooldown still refuses, or
    * more real time has passed than that window could honestly take.

    The first bound is the right one for a live chain and is what #76 shipped.
    It is, however, purely a function of the head ADVANCING, so it cannot see
    the one failure that matters most: an endpoint that freezes its finalized
    head while `blocks_since_last_update <= weights_rate_limit`. There
    `block == anchor` forever, `remaining` never reaches 0, and the tick logs
    `WEIGHT_COOLDOWN_SKIPPED` at INFO on every tick indefinitely — a mute
    validator, reported as routine. The second bound is the backstop for that
    dead chain, and is measured in wall-clock seconds precisely because a
    frozen head supplies no other clock.
    """
    if not bool(getattr(args, "broadcast", False)) or bool(
        getattr(args, "offline", False)
    ):
        _reset_chain_weight_cooldown_anchor(args)
        return
    if preflight is None:
        return
    remaining = _chain_weight_cooldown_remaining_blocks(preflight)
    if remaining is None:
        return
    block = preflight.block
    if remaining <= 0:
        _reset_chain_weight_cooldown_anchor(args)
        return
    if isinstance(block, bool) or not isinstance(block, int):
        return
    now = float(monotonic())
    anchor = getattr(args, "_chain_weight_cooldown_anchor_block", None)
    started = getattr(args, "_chain_weight_cooldown_anchor_monotonic", None)
    # Both anchors describe one cooldown episode, so a missing or malformed
    # half re-seeds the pair. Seeding only one would let a fresh block anchor
    # inherit a stale clock (or the reverse) and move a bound it never earned.
    if (
        isinstance(anchor, bool)
        or not isinstance(anchor, int)
        or isinstance(started, bool)
        or not isinstance(started, (int, float))
    ):
        anchor = block
        started = now
        args._chain_weight_cooldown_anchor_block = anchor
        args._chain_weight_cooldown_anchor_monotonic = started
    if block - anchor > int(preflight.weights_rate_limit):
        return
    if now - float(started) > _chain_weight_cooldown_standdown_seconds(preflight):
        return
    raise _ChainWeightCooldownActive(
        f"chain weight-update cooldown has {remaining} block(s) left; the next "
        f"write becomes possible at block {block + remaining} "
        f"(weights_rate_limit={preflight.weights_rate_limit} "
        f"blocks_since_last_update={preflight.validator_blocks_since_last_update} "
        f"finalized_block={block})"
    )


def _prove_target_hotkey_rotation(
    substrate: Any,
    *,
    block_number: int,
    coldkey: str,
    target_hotkey: str,
) -> dict[str, Any]:
    """Prove the exact successful ``swap_hotkey_v2`` that created a target.

    ``LastHotkeySwapOnNetuid`` is keyed by coldkey and therefore cannot, by
    itself, prove which hotkey was rotated. This archive proof binds the
    cooldown block to the decoded call, signer, successful execution, and the
    pallet event for the exact current target hotkey.
    """
    if (
        isinstance(block_number, bool)
        or not isinstance(block_number, int)
        or block_number <= 0
        or not coldkey
        or not target_hotkey
    ):
        raise wire.VectorError("target hotkey rotation identity is malformed")
    try:
        block_hash = str(substrate.get_block_hash(block_number)).lower()
        canonical_number = int(substrate.get_block_number(block_hash))
        block = substrate.get_block(block_hash=block_hash)
    except Exception as exc:  # noqa: BLE001 - archive proof must fail closed
        raise wire.VectorError(
            "submission cannot retrieve the target hotkey rotation block"
        ) from exc
    if (
        _CHAIN_HASH_RE.fullmatch(block_hash) is None
        or canonical_number != block_number
        or not isinstance(block, dict)
        or not isinstance(block.get("extrinsics"), (list, tuple))
    ):
        raise wire.VectorError("target hotkey rotation block is non-canonical")

    matching: list[tuple[int, dict[str, Any]]] = []
    for index, item in enumerate(block["extrinsics"]):
        observed = getattr(item, "value", None)
        if not isinstance(observed, dict):
            continue
        call = observed.get("call")
        if not isinstance(call, dict):
            continue
        if (
            observed.get("address") == coldkey
            and call.get("call_module") == "SubtensorModule"
            and call.get("call_function") == "swap_hotkey_v2"
            and _chain_call_arg(call, "new_hotkey") == target_hotkey
            and _chain_call_arg(call, "netuid") == 39
        ):
            matching.append((index, observed))
    if len(matching) != 1:
        raise wire.VectorError(
            "target hotkey rotation block has no unique exact swap_hotkey_v2 call"
        )
    extrinsic_index, observed = matching[0]
    call = observed["call"]
    extrinsic_hash = str(observed.get("extrinsic_hash", "")).lower()
    old_hotkey = _chain_call_arg(call, "hotkey")
    keep_stake = _chain_call_arg(call, "keep_stake")
    if (
        _CHAIN_HASH_RE.fullmatch(extrinsic_hash) is None
        or not isinstance(old_hotkey, str)
        or not old_hotkey
        or old_hotkey == target_hotkey
        or not isinstance(keep_stake, bool)
    ):
        raise wire.VectorError("target hotkey rotation call is malformed")
    try:
        receipt = substrate.retrieve_extrinsic_by_hash(block_hash, extrinsic_hash)
        receipt_index = getattr(receipt, "extrinsic_idx", None)
        receipt_success = getattr(receipt, "is_success", None)
        receipt_error = getattr(receipt, "error_message", None)
        triggered_events = getattr(receipt, "triggered_events", None)
        timestamp_value = substrate.query(
            module="Timestamp",
            storage_function="Now",
            block_hash=block_hash,
        )
        timestamp_ms = getattr(timestamp_value, "value", timestamp_value)
    except Exception as exc:  # noqa: BLE001 - archive proof must fail closed
        raise wire.VectorError(
            "submission cannot prove target hotkey rotation execution"
        ) from exc
    try:
        receipt_index_value = int(receipt_index)
    except (TypeError, ValueError) as exc:
        raise wire.VectorError(
            "target hotkey rotation has no exact successful execution receipt"
        ) from exc
    if (
        isinstance(receipt_index, bool)
        or receipt_index_value != extrinsic_index
        or receipt_success is not True
        or receipt_error is not None
        or not isinstance(triggered_events, (list, tuple))
        or isinstance(timestamp_ms, bool)
        or not isinstance(timestamp_ms, int)
        or timestamp_ms <= 0
    ):
        raise wire.VectorError(
            "target hotkey rotation has no exact successful execution receipt"
        )
    matching_events = []
    for event in triggered_events:
        event_data = event.get("event") if isinstance(event, dict) else None
        if (
            isinstance(event_data, dict)
            and event_data.get("module_id") == "SubtensorModule"
            and event_data.get("event_id") == "HotkeySwappedOnSubnet"
            and isinstance(event_data.get("attributes"), dict)
            and event_data["attributes"].get("coldkey") == coldkey
            and event_data["attributes"].get("old_hotkey") == old_hotkey
            and event_data["attributes"].get("new_hotkey") == target_hotkey
            and event_data["attributes"].get("netuid") == 39
        ):
            matching_events.append(event_data)
    if len(matching_events) != 1:
        raise wire.VectorError(
            "target hotkey rotation has no unique matching pallet event"
        )
    block_time = datetime.fromtimestamp(timestamp_ms / 1000, UTC)
    return {
        "call": "swap_hotkey_v2",
        "extrinsic_hash": extrinsic_hash,
        "block_hash": block_hash,
        "block_number": block_number,
        "block_timestamp": block_time.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
        "extrinsic_index": extrinsic_index,
        "coldkey": coldkey,
        "old_hotkey": old_hotkey,
        "new_hotkey": target_hotkey,
        "netuid": 39,
        "keep_stake": keep_stake,
        "event": "HotkeySwappedOnSubnet",
    }


def _require_uid_mapping_stability(
    preflight: ChainPreflight,
    uid_hotkeys: dict[int, str],
    *,
    mortal_period_blocks: int,
) -> dict[str, Any]:
    if (
        isinstance(mortal_period_blocks, bool)
        or not isinstance(mortal_period_blocks, int)
        or mortal_period_blocks != SN39_MORTAL_PERIOD_BLOCKS
        or not uid_hotkeys
    ):
        raise wire.VectorError("UID stability check has an invalid mortal vector")
    safe_hotkeys = preflight.replacement_safe_hotkeys
    if not isinstance(safe_hotkeys, frozenset) or not safe_hotkeys:
        raise wire.VectorError(
            "submission cannot prove any UID mapping replacement-safe"
        )
    unsafe = sorted(set(uid_hotkeys.values()) - safe_hotkeys)
    # An unprovable target is excluded and its mass normalized to burn by the
    # caller, not a reason to abort the whole vector: aborting pays nobody and
    # lets one unprotected UID stall every other target. Hard failure is
    # reserved for the cases where nothing can be paid safely.
    if unsafe and len(unsafe) >= len(set(uid_hotkeys.values())):
        raise wire.VectorError(
            "submission cannot prove any UID mapping stable for the complete "
            f"mortal era ({len(unsafe)} target hotkey(s) unprovable)"
        )
    # `set_mechanism_weights` binds only UIDs. A registered hotkey can be
    # replaced at the same UID by `swap_hotkey_v2` during the four-block mortal
    # era, so registration immunity alone is insufficient. On Finney, publish
    # the exact rotation-lock state of every target and refuse any target whose
    # coldkey has a pending ownership transfer. A live rotation lock is proven
    # end to end when one exists, but it is not required to submit: only the
    # target coldkey owner can rotate a target, both SN39 targets are
    # operator-controlled, and requiring a live lock would force a fresh
    # rotation to a new hotkey before every single broadcast.
    finney = str(preflight.genesis_hash).lower() == FINNEY_GENESIS_HASH
    if not finney:
        registration_safety: dict[str, Any] = {
            "status": "not_applicable_non_finney",
            "replacement_safe_hotkeys": sorted(preflight.replacement_safe_hotkeys),
        }
        rotation_safety = {
            "status": "not_applicable_non_finney",
            "mapping_block": preflight.block,
            "mortal_period_blocks": mortal_period_blocks,
            "targets": [],
        }
    else:
        if (
            preflight.block is None
            or preflight.subnet_max_uids is None
            or preflight.subnet_max_regs_per_block is None
            or preflight.subnet_immunity_period is None
            or preflight.subnet_min_nonimmune_uids is None
            or preflight.subnet_free_uid_slots is None
            or preflight.subnet_immune_owner_uids_limit is None
            or not preflight.subnet_owner_coldkey
            or not preflight.subnet_registration_blocks
        ):
            raise wire.VectorError(
                "submission cannot publish the raw UID replacement-safety inputs"
            )
        registration_rows = [
            {
                "uid": uid,
                "hotkey": hotkey,
                "block_at_registration": registered_at,
            }
            for uid, hotkey, registered_at in preflight.subnet_registration_blocks
        ]
        registration_safety = {
            "max_uids": preflight.subnet_max_uids,
            "max_regs_per_block": preflight.subnet_max_regs_per_block,
            "immunity_period": preflight.subnet_immunity_period,
            "min_nonimmune_uids": preflight.subnet_min_nonimmune_uids,
            "block_at_registration": registration_rows,
            "subnet_owner_coldkey": preflight.subnet_owner_coldkey,
            "owned_hotkeys": list(preflight.subnet_owned_hotkeys),
            "immune_owner_uids_limit": preflight.subnet_immune_owner_uids_limit,
            "free_uid_slots": preflight.subnet_free_uid_slots,
            "maximum_era_registrations": (
                preflight.subnet_max_regs_per_block * mortal_period_blocks
            ),
            "owner_immortal_hotkeys": sorted(preflight.subnet_owner_immortal_hotkeys),
            "replacement_safe_hotkeys": sorted(preflight.replacement_safe_hotkeys),
            # Raw inputs for the eviction-depth proof, so a re-verifier or the
            # public reproduction can recompute safety rather than trust it.
            "worst_case_evictions": preflight.subnet_worst_case_evictions,
            "prune_metrics": [
                {
                    "uid": uid,
                    "hotkey": hotkey,
                    "incentive": incentive,
                    "stake": stake,
                    "emission": emission,
                }
                for uid, hotkey, incentive, stake, emission in (
                    preflight.subnet_prune_metrics
                )
            ],
            "eviction_depth": [
                {"hotkey": hotkey, "depth": depth}
                for hotkey, depth in preflight.subnet_eviction_depth
            ],
        }
        subtensor = preflight.subtensor
        substrate = getattr(subtensor, "substrate", None)
        if substrate is None:
            raise wire.VectorError(
                "submission cannot prove hotkey-rotation safety without substrate"
            )

        def storage_value(name: str, params: list[Any]) -> Any:
            try:
                observed = subtensor.query_subtensor(
                    name=name,
                    params=params,
                    block=preflight.block,
                )
            except Exception as exc:  # noqa: BLE001 - fail closed at write boundary
                raise wire.VectorError(
                    f"submission cannot query {name} at the proven mapping block"
                ) from exc
            return getattr(observed, "value", observed)

        try:
            block_hash = str(substrate.get_block_hash(preflight.block)).lower()
            if _CHAIN_HASH_RE.fullmatch(block_hash) is None:
                raise ValueError("mapping block hash is malformed")

            def constant_value(name: str) -> Any:
                observed = substrate.get_constant(
                    module_name="SubtensorModule",
                    constant_name=name,
                    block_hash=block_hash,
                )
                return getattr(observed, "value", observed)

            hotkey_swap_interval = int(constant_value("HotkeySwapOnSubnetInterval"))
            coldkey_swap_delay = int(storage_value("ColdkeySwapAnnouncementDelay", []))
        except (AttributeError, TypeError, ValueError) as exc:
            raise wire.VectorError(
                "submission cannot prove the live hotkey/coldkey swap constants"
            ) from exc
        if hotkey_swap_interval < mortal_period_blocks:
            raise wire.VectorError(
                "live hotkey swap cooldown is shorter than the complete mortal era"
            )
        if coldkey_swap_delay < mortal_period_blocks:
            raise wire.VectorError(
                "live coldkey swap announcement delay is shorter than the mortal era"
            )

        era_last_block = preflight.block + mortal_period_blocks - 1
        targets: list[dict[str, Any]] = []
        for uid, hotkey in sorted(uid_hotkeys.items()):
            coldkey = str(storage_value("Owner", [hotkey]) or "")
            if not coldkey:
                raise wire.VectorError(
                    f"submission cannot prove the owner for target UID {uid}"
                )
            raw_last_swap = storage_value(
                "LastHotkeySwapOnNetuid",
                [39, coldkey],
            )
            try:
                last_swap_block = int(raw_last_swap)
            except (TypeError, ValueError) as exc:
                raise wire.VectorError(
                    f"submission cannot prove the last hotkey swap for target UID {uid}"
                ) from exc
            pending_coldkey_swap = storage_value(
                "ColdkeySwapAnnouncements",
                [coldkey],
            )
            if pending_coldkey_swap is not None:
                raise wire.VectorError(
                    f"target UID {uid} has a pending coldkey swap announcement"
                )
            if last_swap_block > 0:
                safe_until_block = last_swap_block + hotkey_swap_interval
                swap_lock = (
                    "active" if era_last_block <= safe_until_block else "expired"
                )
            else:
                safe_until_block = None
                swap_lock = "never_rotated"
            receipt: dict[str, Any] | None = None
            hotkey_root: str | None = None
            if swap_lock == "active":
                # A claimed live lock must still be proven: the exact successful
                # swap_hotkey_v2 at the cooldown block, and the lineage it left.
                receipt = _prove_target_hotkey_rotation(
                    substrate,
                    block_number=last_swap_block,
                    coldkey=coldkey,
                    target_hotkey=hotkey,
                )
                successor = storage_value("HotkeySuccessor", [39, hotkey])
                root = storage_value("HotkeyRoot", [39, hotkey])
                old_successor = storage_value(
                    "HotkeySuccessor",
                    [39, receipt["old_hotkey"]],
                )
                old_root = storage_value(
                    "HotkeyRoot",
                    [39, receipt["old_hotkey"]],
                )
                expected_root = (
                    str(old_root)
                    if old_root not in (None, "")
                    else str(receipt["old_hotkey"])
                )
                if (
                    successor not in (None, "")
                    or root in (None, "")
                    or str(old_successor) != hotkey
                    or str(root) != expected_root
                ):
                    raise wire.VectorError(
                        f"target UID {uid} hotkey lineage does not match its rotation"
                    )
                hotkey_root = str(root)
            targets.append(
                {
                    "uid": uid,
                    "hotkey": hotkey,
                    "coldkey": coldkey,
                    "last_hotkey_swap_block": last_swap_block,
                    "hotkey_swap_safe_until_block": safe_until_block,
                    "swap_lock": swap_lock,
                    "pending_coldkey_swap": None,
                    "hotkey_successor": None,
                    "hotkey_root": hotkey_root,
                    "rotation_receipt": receipt,
                    "registration_replacement_safe": hotkey in safe_hotkeys,
                }
            )
        rotation_safety = {
            "status": PASS,
            "mapping_block": preflight.block,
            "mapping_block_hash": block_hash,
            "mortal_period_blocks": mortal_period_blocks,
            "era_last_block": era_last_block,
            "hotkey_swap_on_subnet_interval": hotkey_swap_interval,
            "coldkey_swap_announcement_delay": coldkey_swap_delay,
            "targets": targets,
        }
    return {
        "schema": "cathedral_sn39_uid_safety_v2",
        # Records the launch assumption this proof rests on: every target
        # coldkey is operator-controlled, so a target hotkey cannot be replaced
        # mid-era by anyone else.
        "stability_basis": "operator_controlled_coldkeys",
        "registration": registration_safety,
        "rotation": rotation_safety,
        # Targets the caller must drop, normalizing their mass to burn.
        "excluded_hotkeys": unsafe,
    }


def _eviction_depths(
    prunable_rows: list[tuple[int, str, int]],
    metric_by_hotkey: dict[str, tuple[float, float, float]],
) -> dict[str, int]:
    """How many prunable neurons the runtime must evict before each target.

    The deployed runtime generation selects its victim as the minimum of
    (emission, block_at_registration, uid) lexicographically (subtensor
    get_neuron_to_prune; the u16 PruningScores map is retired). Strict
    dominance on all three carried metrics implies strictly lower emission,
    the primary key, so that branch is sound. On an exact metric tie the
    runtime prunes the OLDEST registration first, then the lower UID -- not
    the lower UID outright, which is what this rule previously assumed and
    which overcounted depth for exactly the mature targets the proof exists
    to protect. Anything not provably ahead counts as possibly behind the
    target, the conservative direction.
    """
    depths: dict[str, int] = {}
    for uid, hotkey, registered_at in prunable_rows:
        target_metric = metric_by_hotkey[hotkey]
        depth = 0
        for other_uid, other_hotkey, other_registered_at in prunable_rows:
            if other_hotkey == hotkey:
                continue
            other_metric = metric_by_hotkey[other_hotkey]
            strictly_weaker = all(
                other_value < target_value
                for other_value, target_value in zip(other_metric, target_metric)
            )
            tied_ahead = other_metric == target_metric and (
                other_registered_at,
                other_uid,
            ) < (registered_at, uid)
            if strictly_weaker or tied_ahead:
                depth += 1
        depths[hotkey] = depth
    return depths


def _drop_unprovable_targets(
    args: Any,
    uid_weights: dict[int, float],
    uid_safety: dict[str, Any],
    hotkey_to_uid: dict[str, int],
    burn_uid: int | None,
) -> dict[int, float]:
    """Move an unprovable target's mass to burn, keeping total mass at 1.0.

    _require_uid_mapping_stability returns excluded_hotkeys under the contract
    "targets the caller must drop, normalizing their mass to burn". An earlier
    version dropped them and returned the remainder, which summed below 1.0 and
    was rejected by _validate_emission_vector before it could reach the chain:
    the control was inert, and worse, one unprovable target halted every write
    instead of costing that target its share.

    The mass goes to BURN, not to the surviving miners. Redistributing an
    excluded miner's share among the others would let a target becoming
    unprovable silently pay everyone else more, which is an allocation change
    nobody signed. Burn is the destination the safety proof names, and it keeps
    the sum exactly 1.0 with no renormalization of anyone else's share.

    Loud on every surface: a vector that differs from the signed or recomputed
    allocation must never be a quiet event.
    """
    excluded = list(uid_safety.get("excluded_hotkeys") or [])
    if not excluded:
        return uid_weights
    excluded_uids = {
        hotkey_to_uid[hotkey] for hotkey in excluded if hotkey in hotkey_to_uid
    }
    if burn_uid is None or int(burn_uid) not in uid_weights:
        raise wire.VectorError(
            "cannot exclude an unprovable target without a burn destination "
            "in the vector to receive its mass"
        )
    burn_uid = int(burn_uid)
    if burn_uid in excluded_uids:
        # The burn destination is the subnet owner and owner-immortal, so it
        # is never prunable. If the proof says otherwise, the maps disagree
        # and nothing here is trustworthy.
        raise wire.VectorError(
            "burn destination was itself excluded as unprovable; refusing"
        )
    kept = {
        uid: weight for uid, weight in uid_weights.items() if uid not in excluded_uids
    }
    forfeited = math.fsum(
        weight for uid, weight in uid_weights.items() if uid in excluded_uids
    )
    if not forfeited:
        return uid_weights
    kept[burn_uid] = math.fsum((kept.get(burn_uid, 0.0), forfeited))
    dropped = sorted(excluded_uids & set(uid_weights))
    detail = (
        f"excluded_uids={','.join(str(uid) for uid in dropped)} "
        f"reason=uid_mapping_unprovable forfeited_to_burn={forfeited:.6f} "
        f"burn_uid={burn_uid} remaining_targets={len(kept) - 1}"
    )
    _get_events(args).event(
        "UNSAFE_TARGETS_EXCLUDED",
        stage="safety",
        status=NOT_PROVEN,
        detail=detail,
        remediation=(
            "The excluded targets' mass was burned, not redistributed. They "
            "rejoin automatically once their UID mapping is provable for a "
            "full mortal era."
        ),
    )
    _lifecycle("SAFETY excluded", detail)
    return kept


def _require_launch_evidence_after_rotations(
    *,
    payload: dict[str, Any],
    audit: Any,
    uid_safety: dict[str, Any],
) -> dict[str, Any]:
    """Bind every launch-generation boundary strictly after proven rotations.

    Targets that carry no live rotation lock contribute no receipt and no
    floor. When no target does, there is nothing for the evidence to postdate
    and the boundary records a null floor.
    """
    try:
        targets = uid_safety["rotation"]["targets"]
        receipts = [
            row["rotation_receipt"]
            for row in targets
            if row["rotation_receipt"] is not None
        ]
        rotation_blocks = [int(row["block_number"]) for row in receipts]
        rotation_times = [
            wire._parse_canonical_utc(
                row["block_timestamp"],
                field="rotation block timestamp",
            )
            for row in receipts
        ]
        candidate_block = int(getattr(audit, "candidate_block"))
        candidate_block_hash = str(getattr(audit, "candidate_block_hash"))
        report_valid_from_block = int(getattr(audit, "report_valid_from_block"))
        manifest_generated = wire._parse_canonical_utc(
            getattr(audit, "manifest_generated_at", None),
            field="evidence manifest generated_at",
        )
        report_generated = wire._parse_canonical_utc(
            getattr(audit, "report_generated_at", None),
            field="provenance report generated_at",
        )
        vector_generated = wire._parse_canonical_utc(
            payload.get("generated_at"),
            field="generated_at",
        )
        signed_index = getattr(audit, "signed_index", None)
        index_generated = wire._parse_canonical_utc(
            signed_index["generated_at"],
            field="evidence index generated_at",
        )
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise wire.VectorError(
            "launch evidence has no exact post-rotation generation boundary"
        ) from exc
    if len(targets) != 2 or _CHAIN_HASH_RE.fullmatch(candidate_block_hash) is None:
        raise wire.VectorError(
            "launch evidence does not name the two canonical targets at a "
            "canonical candidate block"
        )
    rotation_floor_block: int | None = None
    rotation_floor_timestamp: str | None = None
    if receipts:
        rotation_floor_block = max(rotation_blocks)
        rotation_floor_time = max(rotation_times)
        rotation_floor_timestamp = rotation_floor_time.isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        if (
            candidate_block <= rotation_floor_block
            or report_valid_from_block <= rotation_floor_block
            or any(
                generated <= rotation_floor_time
                for generated in (
                    manifest_generated,
                    report_generated,
                    vector_generated,
                    index_generated,
                )
            )
        ):
            raise wire.VectorError(
                "launch candidate, evidence, report, vector, and index must all "
                "be generated strictly after every proven target rotation"
            )
    return {
        "schema": "cathedral_sn39_post_rotation_evidence_v2",
        "rotation_floor_block": rotation_floor_block,
        "rotation_floor_timestamp": rotation_floor_timestamp,
        "candidate_block": candidate_block,
        "candidate_block_hash": candidate_block_hash.lower(),
        "manifest_generated_at": getattr(audit, "manifest_generated_at"),
        "report_generated_at": getattr(audit, "report_generated_at"),
        "report_valid_from_block": report_valid_from_block,
        "vector_generated_at": payload["generated_at"],
        "index_generated_at": signed_index["generated_at"],
    }


def _vector_inclusion_policy(
    payload: dict[str, Any],
    preflight: ChainPreflight,
) -> InclusionPolicy:
    if preflight.block is None:
        raise wire.VectorError("signed vector inclusion requires a finalized block")
    policy = InclusionPolicy(
        valid_from_block=preflight.block,
        valid_until_block=preflight.block + SN39_MORTAL_PERIOD_BLOCKS,
        valid_from_time=wire._parse_canonical_utc(
            payload.get("generated_at"),
            field="generated_at",
        ),
        valid_until_time=wire._parse_canonical_utc(
            payload.get("expires_at"),
            field="expires_at",
        ),
        expected_next_epoch_start_block=preflight.next_epoch_start_block,
    )
    _require_inclusion_policy_ready(policy, preflight)
    return policy


@contextlib.contextmanager
def _isolated_argv():
    """Hide sys.argv from bittensor while it builds its own config.

    bittensor parses sys.argv to build a config and defines its OWN `--config`
    flag. When this validator is launched as `cathedral-validator serve --config
    my.toml`, that `--config` leaks into bittensor, which then tries to YAML-load
    our TOML and aborts the tick with `Error loading config` (seen on some
    bittensor versions, not all). Blanking argv around bittensor construction
    keeps the two CLIs from colliding.
    """
    saved = sys.argv
    sys.argv = sys.argv[:1]
    try:
        yield
    finally:
        sys.argv = saved


@contextlib.contextmanager
def _chain_operation_deadline(label: str, seconds: float):
    """Bound one synchronous Bittensor operation in the validator process.

    Releasing a lock while an abandoned worker thread can still submit is not
    safe, so chain calls are not delegated to timeout threads. The production
    validator runs on the main POSIX thread, where ``ITIMER_REAL`` interrupts
    the call in place. Any unsupported execution context or competing process
    timer fails closed before chain access.
    """
    import signal

    if not math.isfinite(seconds) or seconds <= 0.0:
        raise wire.VectorError("chain operation deadline must be positive and finite")
    if threading.current_thread() is not threading.main_thread():
        raise wire.VectorError(
            f"{label} requires the validator main thread for a safe wall-clock deadline"
        )
    if not all(
        hasattr(signal, name) for name in ("SIGALRM", "ITIMER_REAL", "setitimer")
    ):
        raise wire.VectorError(
            f"{label} cannot establish the required process wall-clock deadline"
        )
    existing = signal.getitimer(signal.ITIMER_REAL)
    if existing[0] > 0.0 or existing[1] > 0.0:
        raise wire.VectorError(
            f"{label} refuses to replace an existing process wall-clock timer"
        )
    prior_handler = signal.getsignal(signal.SIGALRM)

    def expired(_signum, _frame):
        raise wire.VectorError(
            f"{label} exceeded its {seconds:.0f}s wall-clock deadline"
        )

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, prior_handler)


def _validate_emission_vector(uid_weights: dict[int, float]) -> None:
    if not uid_weights:
        raise wire.VectorError("chain preflight requires a non-empty vector")
    if any(
        isinstance(uid, bool)
        or not isinstance(uid, int)
        or uid < 0
        or not math.isfinite(float(value))
        or float(value) < 0.0
        for uid, value in uid_weights.items()
    ):
        raise wire.VectorError("chain preflight vector is invalid")
    total = math.fsum(float(value) for value in uid_weights.values())
    if not math.isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise wire.VectorError(f"chain preflight vector mass {total!r} != 1.0")


def _validate_chain_constraints(
    uid_weights: dict[int, float], preflight: ChainPreflight
) -> None:
    if preflight.commit_reveal_enabled:
        raise wire.VectorError(
            "SN39 release proof requires a directly applied set_mechanism_weights "
            "extrinsic; commit-reveal is enabled, so refusing before submission"
        )
    positive = [float(value) for value in uid_weights.values() if float(value) > 0.0]
    if len(positive) < preflight.min_allowed_weights:
        raise wire.VectorError(
            "chain preflight vector has fewer positives than min_allowed_weights"
        )
    limit = preflight.max_weight_limit
    if not math.isfinite(limit) or not 0.0 < limit <= 1.0:
        raise wire.VectorError("chain preflight max_weight_limit is invalid")
    if any(value > limit + 1e-9 for value in positive):
        raise wire.VectorError("chain preflight vector exceeds max_weight_limit")
    if len(positive) * limit < 1.0 - 1e-9:
        raise wire.VectorError("chain preflight vector cannot conserve mass")


def _require_no_validator_compute_reward(
    uid_weights: dict[int, float],
    *,
    preflight: ChainPreflight,
    burn_uid: int | None,
) -> None:
    """Prevent a validator from assigning validated-compute mass to itself."""
    validator_weight = float(uid_weights.get(preflight.validator_uid, 0.0))
    if validator_weight > 0.0 and preflight.validator_uid != burn_uid:
        raise wire.VectorError(
            "SN39 validator hotkey cannot receive validated-compute weight"
        )


def chain_preflight(
    *,
    network: str,
    netuid: int,
    wallet_name: str,
    wallet_hotkey: str,
    deadline_secs: float = CHAIN_OPERATION_DEADLINE_SECS,
) -> ChainPreflight:
    """Resolve validator identity and constraints under one wall-clock bound."""
    with _chain_operation_deadline("chain preflight", deadline_secs):
        return _chain_preflight_unbounded(
            network=network,
            netuid=netuid,
            wallet_name=wallet_name,
            wallet_hotkey=wallet_hotkey,
        )


def _chain_preflight_unbounded(
    *, network: str, netuid: int, wallet_name: str, wallet_hotkey: str
) -> ChainPreflight:
    with _isolated_argv():
        import bittensor as bt

        wallet = _bt_wallet(bt)(name=wallet_name, hotkey=wallet_hotkey)
        subtensor = _bt_subtensor(bt)(network=connection_target(network))
        finalized_block, _finalized_hash = _finalized_chain_head(subtensor)
        metagraph = subtensor.metagraph(netuid, block=finalized_block)
    raw_uids = (
        metagraph.uids.tolist() if hasattr(metagraph.uids, "tolist") else metagraph.uids
    )
    uids = [int(value) for value in raw_uids]
    hotkeys = [str(value) for value in metagraph.hotkeys]
    permits = [bool(value) for value in metagraph.validator_permit]
    if not (len(uids) == len(hotkeys) == len(permits)):
        raise wire.VectorError("metagraph arrays are inconsistent")
    if len(set(uids)) != len(uids) or len(set(hotkeys)) != len(hotkeys):
        raise wire.VectorError("metagraph contains duplicate UID or hotkey")
    hotkey_to_uid = dict(zip(hotkeys, uids))
    validator_hotkey = str(wallet.hotkey.ss58_address)
    if validator_hotkey not in hotkey_to_uid:
        raise wire.VectorError("validator hotkey is not registered on this subnet")
    validator_uid = hotkey_to_uid[validator_hotkey]
    index = hotkeys.index(validator_hotkey)
    if not permits[index]:
        raise wire.VectorError("validator hotkey lacks validator permit")
    block = _finalized_block(getattr(metagraph, "block", None))
    if block != finalized_block:
        raise wire.VectorError("metagraph did not resolve at the finalized chain head")
    subnet_owner_hotkey = str(
        subtensor.get_subnet_owner_hotkey(netuid, block=finalized_block) or ""
    )
    raw_blocks_until_epoch = subtensor.blocks_until_next_epoch(
        netuid,
        block=finalized_block,
    )
    raw_next_epoch_start = subtensor.get_next_epoch_start_block(
        netuid,
        block=finalized_block,
    )
    raw_weights_rate_limit = subtensor.weights_rate_limit(
        netuid,
        block=finalized_block,
    )
    raw_blocks_since_update = subtensor.blocks_since_last_update(
        netuid,
        validator_uid,
        block=finalized_block,
    )
    try:
        max_uids = int(getattr(metagraph, "max_uids"))
        hparams = getattr(metagraph, "hparams")
        max_regs_per_block = int(getattr(hparams, "max_regs_per_block"))
        immunity_period = int(getattr(hparams, "immunity_period"))
        raw_registration_blocks = getattr(metagraph, "block_at_registration")
        registration_blocks = [int(value) for value in raw_registration_blocks]
        min_nonimmune_value = subtensor.query_subtensor(
            name="MinNonImmuneUids",
            params=[netuid],
            block=finalized_block,
        )
        min_nonimmune_uids = int(
            getattr(min_nonimmune_value, "value", min_nonimmune_value)
        )
        owner_coldkey_value = subtensor.query_subtensor(
            name="SubnetOwner",
            params=[netuid],
            block=finalized_block,
        )
        subnet_owner_coldkey = str(
            getattr(owner_coldkey_value, "value", owner_coldkey_value) or ""
        )
        owned_hotkeys_value = subtensor.query_subtensor(
            name="OwnedHotkeys",
            params=[subnet_owner_coldkey],
            block=finalized_block,
        )
        owned_hotkeys = [
            str(value)
            for value in getattr(
                owned_hotkeys_value,
                "value",
                owned_hotkeys_value,
            )
        ]
        owner_limit_value = subtensor.query_subtensor(
            name="ImmuneOwnerUidsLimit",
            params=[netuid],
            block=finalized_block,
        )
        immune_owner_uids_limit = int(
            getattr(owner_limit_value, "value", owner_limit_value)
        )

        # Pruning-score inputs. The runtime exposes no PruningScores map on
        # this chain, so eviction order is derived from the metrics a scalar
        # score is monotone in. Missing series are treated as all-zero, which
        # collapses every candidate into one tie group and is conservative.
        def _metric_series(name: str) -> list[float]:
            raw = getattr(metagraph, name, None)
            if raw is None:
                return [0.0] * len(uids)
            values = [float(value) for value in raw]
            if len(values) != len(uids):
                raise ValueError(f"{name} does not cover the registered set")
            return values

        incentive_series = _metric_series("I")
        stake_series = _metric_series("S")
        emission_series = _metric_series("E")
        prune_incentive = dict(zip(hotkeys, incentive_series))
        prune_stake = dict(zip(hotkeys, stake_series))
        prune_emission = dict(zip(hotkeys, emission_series))
    except (AttributeError, TypeError, ValueError) as exc:
        raise wire.VectorError(
            "subnet registration and immunity policy is unavailable at finalized head"
        ) from exc
    if (
        max_uids < len(uids)
        or max_regs_per_block < 0
        or immunity_period < 0
        or min_nonimmune_uids < 0
        or len(registration_blocks) != len(uids)
        or not subnet_owner_coldkey
        or immune_owner_uids_limit < 0
        or any(not hotkey for hotkey in owned_hotkeys)
        or len(set(owned_hotkeys)) != len(owned_hotkeys)
    ):
        raise wire.VectorError(
            "subnet registration and owner-immunity policy is malformed at "
            "finalized head"
        )
    uid_registration_by_hotkey = {
        hotkey: (uid, registered_at)
        for hotkey, uid, registered_at in zip(
            hotkeys,
            uids,
            registration_blocks,
        )
    }
    owner_rows: list[tuple[int, int, str]] = []
    for hotkey in owned_hotkeys:
        owner_row = uid_registration_by_hotkey.get(hotkey)
        if owner_row is None:
            continue
        uid, registered_at = owner_row
        owner_rows.append((registered_at, uid, hotkey))
    owner_rows.sort()
    owner_immortal_rows = owner_rows[:immune_owner_uids_limit]
    owner_current_row = uid_registration_by_hotkey.get(subnet_owner_hotkey)
    if owner_current_row is not None and all(
        row[2] != subnet_owner_hotkey for row in owner_immortal_rows
    ):
        owner_uid, owner_registered_at = owner_current_row
        owner_immortal_rows.insert(
            0,
            (owner_registered_at, owner_uid, subnet_owner_hotkey),
        )
        owner_immortal_rows = owner_immortal_rows[:immune_owner_uids_limit]
    owner_immortal_hotkeys = {row[2] for row in owner_immortal_rows}
    free_uid_slots = max_uids - len(uids)
    maximum_era_registrations = max_regs_per_block * SN39_MORTAL_PERIOD_BLOCKS
    if max_regs_per_block == 0:
        uid_mapping_stable_until_block = raw_next_epoch_start
    else:
        uid_mapping_stable_until_block = finalized_block + (
            free_uid_slots // max_regs_per_block
        )
    capacity_protects_all = free_uid_slots >= maximum_era_registrations
    temporally_immune_hotkeys = {
        hotkey
        for hotkey, registered_at in zip(hotkeys, registration_blocks)
        if registered_at + immunity_period
        >= finalized_block + SN39_MORTAL_PERIOD_BLOCKS
    }
    prunable_nonimmune_count = sum(
        registered_at + immunity_period <= finalized_block
        and hotkey not in owner_immortal_hotkeys
        for hotkey, registered_at in zip(hotkeys, registration_blocks)
    )
    nonimmune_buffer_protects_immunity = (
        prunable_nonimmune_count
        > min_nonimmune_uids + max(0, maximum_era_registrations - free_uid_slots)
    )
    # Registration immunity protects a NEW neuron from pruning. Requiring it of
    # a reward target inverts the intent: a mature miner, whose immunity has
    # long expired, becomes permanently unrewardable even when the runtime
    # would never reach it. Weights bind UIDs, so what actually has to be
    # proven is that no sequence of registrations inside the mortal era can
    # reach this UID. That is an eviction-DEPTH question, so prove it directly
    # and keep every existing protection as an independent sufficient
    # condition.
    #
    # Worst case: every block of the era registers, each consuming a free slot
    # first and then pruning one victim. The runtime will not prune below
    # MinNonImmuneUids, which caps the reachable depth.
    prunable_rows = [
        (uid, hotkey, registered_at)
        for uid, hotkey, registered_at in zip(uids, hotkeys, registration_blocks)
        if registered_at + immunity_period <= finalized_block
        and hotkey not in owner_immortal_hotkeys
    ]
    # The MinNonImmuneUids floor is evaluated at prune time, not at this head:
    # a neuron whose immunity expires DURING the era joins the pool mid-era and
    # permits one further prune. Cap B therefore counts everyone prunable by
    # the era's LAST block. The depth competition below deliberately does not:
    # a mid-era maturer is only guaranteed prunable for part of the era, so
    # counting it as a body in front of the target would be optimistic.
    era_prunable_count = sum(
        registered_at + immunity_period <= finalized_block + SN39_MORTAL_PERIOD_BLOCKS
        and hotkey not in owner_immortal_hotkeys
        for hotkey, registered_at in zip(hotkeys, registration_blocks)
    )
    worst_case_evictions = min(
        max(0, maximum_era_registrations - free_uid_slots),
        max(0, era_prunable_count - min_nonimmune_uids),
    )
    metric_by_hotkey = {
        hotkey: (
            float(prune_incentive.get(hotkey, 0.0)),
            float(prune_stake.get(hotkey, 0.0)),
            float(prune_emission.get(hotkey, 0.0)),
        )
        for _, hotkey, _ in prunable_rows
    }
    eviction_depth = _eviction_depths(prunable_rows, metric_by_hotkey)
    eviction_safe_hotkeys = {
        hotkey
        for hotkey, depth in eviction_depth.items()
        if depth >= worst_case_evictions
    }
    replacement_safe_hotkeys = (
        set(hotkeys)
        if capacity_protects_all
        else owner_immortal_hotkeys
        | (temporally_immune_hotkeys if nonimmune_buffer_protects_immunity else set())
        | eviction_safe_hotkeys
    )
    if (
        not subnet_owner_hotkey
        or isinstance(raw_blocks_until_epoch, bool)
        or not isinstance(raw_blocks_until_epoch, int)
        or raw_blocks_until_epoch < 0
        or isinstance(raw_next_epoch_start, bool)
        or not isinstance(raw_next_epoch_start, int)
        or raw_next_epoch_start != finalized_block + raw_blocks_until_epoch
        or isinstance(raw_weights_rate_limit, bool)
        or not isinstance(raw_weights_rate_limit, int)
        or raw_weights_rate_limit < 0
        or isinstance(raw_blocks_since_update, bool)
        or not isinstance(raw_blocks_since_update, int)
        or raw_blocks_since_update < 0
        or max_uids < len(uids)
        or max_regs_per_block < 0
        or immunity_period < 0
        or min_nonimmune_uids < 0
        or len(registration_blocks) != len(uids)
        or not subnet_owner_coldkey
        or immune_owner_uids_limit < 0
    ):
        raise wire.VectorError(
            "subnet owner, exact epoch schedule, registration capacity, or "
            "validator weight cooldown is unavailable at finalized head"
        )
    result = ChainPreflight(
        wallet=wallet,
        subtensor=subtensor,
        hotkey_to_uid=hotkey_to_uid,
        validator_hotkey=validator_hotkey,
        validator_uid=validator_uid,
        block=block,
        min_allowed_weights=int(
            subtensor.min_allowed_weights(netuid=netuid, block=finalized_block)
        ),
        max_weight_limit=float(
            subtensor.max_weight_limit(netuid=netuid, block=finalized_block)
        ),
        commit_reveal_enabled=_strict_commit_reveal_state(
            subtensor.commit_reveal_enabled(netuid=netuid, block=finalized_block)
        ),
        genesis_hash=_canonical_genesis_hash(subtensor),
        subnet_owner_hotkey=subnet_owner_hotkey,
        blocks_until_next_epoch=raw_blocks_until_epoch,
        next_epoch_start_block=raw_next_epoch_start,
        weights_rate_limit=raw_weights_rate_limit,
        validator_blocks_since_last_update=raw_blocks_since_update,
        uid_mapping_stable_until_block=uid_mapping_stable_until_block,
        replacement_safe_hotkeys=frozenset(replacement_safe_hotkeys),
        subnet_prune_metrics=tuple(
            (
                uid,
                hotkey,
                prune_incentive.get(hotkey, 0.0),
                prune_stake.get(hotkey, 0.0),
                prune_emission.get(hotkey, 0.0),
            )
            for uid, hotkey in zip(uids, hotkeys)
        ),
        subnet_worst_case_evictions=worst_case_evictions,
        subnet_eviction_depth=tuple(sorted(eviction_depth.items())),
        subnet_free_uid_slots=free_uid_slots,
        subnet_max_regs_per_block=max_regs_per_block,
        subnet_min_nonimmune_uids=min_nonimmune_uids,
        subnet_immunity_period=immunity_period,
        subnet_temporally_immune_uids=len(temporally_immune_hotkeys),
        subnet_owner_coldkey=subnet_owner_coldkey,
        subnet_immune_owner_uids_limit=immune_owner_uids_limit,
        subnet_owner_immortal_hotkeys=frozenset(owner_immortal_hotkeys),
        subnet_max_uids=max_uids,
        subnet_registration_blocks=tuple(
            (uid, hotkey, registered_at)
            for uid, hotkey, registered_at in zip(
                uids,
                hotkeys,
                registration_blocks,
            )
        ),
        subnet_owned_hotkeys=tuple(owned_hotkeys),
        finalized_hash=_finalized_hash,
    )
    _lifecycle(
        "PREFLIGHT complete",
        f"validator_hotkey={validator_hotkey} validator_uid={result.validator_uid} "
        f"block={block if block is not None else 'unknown'} "
        f"min_allowed={result.min_allowed_weights} max_limit={result.max_weight_limit} "
        f"commit_reveal={str(result.commit_reveal_enabled).lower()} "
        f"blocks_until_epoch={result.blocks_until_next_epoch} "
        f"next_epoch={result.next_epoch_start_block} "
        f"weights_rate_limit={result.weights_rate_limit} "
        f"blocks_since_update={result.validator_blocks_since_last_update} "
        f"free_uid_slots={result.subnet_free_uid_slots} "
        f"max_regs_per_block={result.subnet_max_regs_per_block} "
        f"min_nonimmune_uids={result.subnet_min_nonimmune_uids} "
        f"temporally_immune_uids={result.subnet_temporally_immune_uids} "
        f"owner_immortal_uids={len(result.subnet_owner_immortal_hotkeys)} "
        f"owner_immune_limit={result.subnet_immune_owner_uids_limit} "
        f"replacement_safe_uids={len(result.replacement_safe_hotkeys)} "
        f"capacity_stable_until={result.uid_mapping_stable_until_block}",
    )
    return result


def _canonical_genesis_hash(subtensor: Any) -> str:
    """Return the exact genesis hash that namespaces a chain identity."""
    substrate = getattr(subtensor, "substrate", None)
    if substrate is None:
        raise wire.VectorError("subtensor has no substrate genesis interface")
    try:
        value = str(substrate.get_block_hash(0)).lower()
    except (AttributeError, TypeError, ValueError) as exc:
        raise wire.VectorError("cannot resolve the canonical chain genesis") from exc
    if _CHAIN_HASH_RE.fullmatch(value) is None:
        raise wire.VectorError("canonical chain genesis hash is malformed")
    return value


def _strict_commit_reveal_state(value: Any) -> bool:
    if not isinstance(value, bool):
        raise wire.VectorError("chain commit-reveal state is not an explicit boolean")
    return value


def _finalized_chain_head(subtensor: Any) -> tuple[int, str]:
    """Resolve one canonical finalized chain height/hash pair."""
    substrate = getattr(subtensor, "substrate", None)
    if substrate is None:
        raise wire.VectorError("subtensor has no substrate finality interface")
    try:
        block_hash = str(substrate.get_chain_finalised_head())
        block_number = _finalized_block(substrate.get_block_number(block_hash))
        canonical_hash = (
            str(substrate.get_block_hash(block_number))
            if block_number is not None
            else ""
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise wire.VectorError("cannot resolve the finalized chain head") from exc
    if (
        block_number is None
        or _CHAIN_HASH_RE.fullmatch(block_hash) is None
        or canonical_hash.lower() != block_hash.lower()
    ):
        raise wire.VectorError("finalized chain head is malformed or non-canonical")
    return block_number, block_hash.lower()


def _canonical_receipt_block_number(subtensor: Any, block_hash: str) -> int:
    """Resolve and reverse-check the canonical height for a finalized receipt."""
    if not isinstance(block_hash, str) or _CHAIN_HASH_RE.fullmatch(block_hash) is None:
        raise wire.VectorError("submission receipt block hash is malformed")
    substrate = getattr(subtensor, "substrate", None)
    if substrate is None:
        raise wire.VectorError("submission receipt has no canonical chain interface")
    try:
        raw_number = substrate.get_block_number(block_hash)
        canonical_number = _finalized_block(raw_number)
        canonical_hash = (
            str(substrate.get_block_hash(canonical_number))
            if canonical_number is not None
            else ""
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise wire.VectorError(
            "submission receipt block number is unavailable"
        ) from exc
    if (
        canonical_number is None
        or canonical_number <= 0
        or canonical_hash.lower() != block_hash.lower()
    ):
        raise wire.VectorError(
            "submission receipt block hash and canonical height disagree"
        )
    return canonical_number


def _weight_version_key() -> int:
    """The exact SDK version key committed into the weight extrinsic."""
    from bittensor.core.settings import version_as_int

    return int(version_as_int)


def _wire_weights(uids: list[int], weights: list[float]) -> tuple[list[int], list[int]]:
    from bittensor.utils.weight_utils import convert_and_normalize_weights_and_uids

    wire_uids, wire_values = convert_and_normalize_weights_and_uids(uids, weights)
    return [int(value) for value in wire_uids], [int(value) for value in wire_values]


def _chain_call_arg(call: dict[str, Any], name: str) -> Any:
    for item in call.get("call_args") or ():
        if isinstance(item, dict) and item.get("name") == name:
            return item.get("value")
    return None


def _classify_finalized_receipt_awaiting_finality(
    subtensor: Any,
    *,
    wait_secs: float = RECEIPT_FINALITY_WAIT_SECS,
    poll_secs: float = RECEIPT_FINALITY_POLL_SECS,
    sleep: Any = time.sleep,
    monotonic: Any = time.monotonic,
    **kwargs: Any,
) -> str:
    """Classify a receipt, letting finality catch up before calling it unproven.

    Only ONE NOT_PROVEN reason is retried here: the finalized head being behind
    the receipt's own block. That is a wait, not a fault — the block exists and
    was already checked canonical at its number, and every other refusal
    (including the FAIL verdicts) returns immediately and unchanged.

    Waiting is what the process was already doing, badly. A proof attempted
    right after a successful submission routinely loses the finality race, and
    the response was to exit non-zero so systemd could restart the process,
    which then proved the identical receipt seconds later. That cost a restart
    and a tick on every write. The verdict contract is untouched: an unfinalized
    receipt at the end of the bound is still NOT_PROVEN and still fenced.
    """
    deadline = monotonic() + max(0.0, wait_secs)
    while True:
        reason_out = kwargs.get("reason_out")
        if isinstance(reason_out, list):
            reason_out.clear()
        status = _classify_finalized_receipt(subtensor, **kwargs)
        if status != NOT_PROVEN:
            return status
        if not isinstance(reason_out, list) or RECEIPT_FINALITY_LAG_REASON not in (
            reason_out or ()
        ):
            return status
        remaining = deadline - monotonic()
        if remaining <= 0:
            return status
        sleep(min(max(0.0, poll_secs), remaining))


def _receipt_verdict(
    reason_out: list[str] | None,
    verdict: str,
    reason: str,
) -> str:
    """Record why a receipt proof reached its verdict, then return the verdict.

    ``_classify_finalized_receipt`` has more than twenty distinct exits and
    only three return values, so the verdict alone never told an operator
    which check spoke. Threading an optional collector keeps every exit a
    single expression — the control flow is unchanged, byte for byte — while
    letting the callers that surface a verdict to a human name the cause.

    The collector is optional so that callers who only need the verdict, and
    the tests that stub this function out entirely, keep working unchanged.
    """
    if reason_out is not None:
        reason_out.append(reason)
    return verdict


def _receipt_reason_suffix(reason_out: list[str]) -> str:
    """Render a collected receipt-proof reason for an operator-facing message.

    Empty when nothing was collected, so a stubbed or older classifier still
    produces exactly the message this validator has always emitted.
    """
    return f" (cause: {reason_out[-1]})" if reason_out else ""


def _classify_finalized_receipt(
    subtensor: Any,
    *,
    receipt: Any,
    extrinsic_hash: str,
    block_hash: str,
    block_number: int,
    validator_hotkey: str,
    netuid: int,
    version_key: int,
    wire_uids: list[int],
    wire_weights: list[int],
    uid_hotkeys: dict[int, str] | None = None,
    expected_subnet_owner_hotkey: str | None = None,
    inclusion_policy: InclusionPolicy | None = None,
    require_receipt: bool = True,
    reason_out: list[str] | None = None,
) -> str:
    """Classify exact finalized-call proof as PASS, FAIL, or NOT_PROVEN.

    An RPC/archive exception is not evidence of a mismatch. Keeping that case
    distinct prevents a transient read failure from authorizing any second
    chain write after a valid irreversible call.

    That broad ``except`` is deliberate and stays. What does not stay is
    discarding the exception it caught: a validator whose write cadence
    degrades because one archive call intermittently fails on a long-lived
    connection has no way to learn WHICH call, and the same receipt proving
    fine after a restart is the only clue. Passing ``reason_out`` collects a
    short, sanitized description of the exit that fired — including the name
    of the chain call in flight when a read raised — without altering a single
    verdict.
    """
    substrate = getattr(subtensor, "substrate", None)
    if substrate is None:
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "the subtensor client exposes no substrate interface",
        )
    if require_receipt:
        receipt_success = (
            getattr(receipt, "is_success", None) if receipt is not None else None
        )
        if not isinstance(receipt_success, bool):
            return _receipt_verdict(
                reason_out,
                NOT_PROVEN,
                "the submit receipt exposes no boolean is_success",
            )
        if (
            receipt_success is not True
            or getattr(receipt, "error_message", None) is not None
        ):
            return _receipt_verdict(
                reason_out,
                FAIL,
                "the submit receipt reports a failed or errored extrinsic",
            )
    # Every read below can fail transiently and independently, and only an
    # operator can tell a rate-limited endpoint from a node that never had the
    # state. Naming the call in flight is what makes that difference visible.
    step = "substrate.get_chain_finalised_head"
    try:
        finalized_hash = str(substrate.get_chain_finalised_head())
        step = "substrate.get_block_number(finalized head)"
        finalized_number = _finalized_block(substrate.get_block_number(finalized_hash))
        step = "substrate.get_block_hash(finalized number)"
        canonical_finalized_hash = (
            str(substrate.get_block_hash(finalized_number))
            if finalized_number is not None
            else ""
        )
        step = "substrate.get_block_hash(receipt block number)"
        canonical_hash = str(substrate.get_block_hash(block_number))
        step = "substrate.get_block(receipt block hash)"
        block = substrate.get_block(block_hash=block_hash)
        step = "subtensor.metagraph(receipt block)"
        inclusion_metagraph = (
            subtensor.metagraph(netuid, block=block_number)
            if uid_hotkeys is not None
            else None
        )
        if inclusion_policy is not None:
            step = "subtensor.commit_reveal_enabled(receipt block)"
            commit_reveal_at_inclusion = subtensor.commit_reveal_enabled(
                netuid=netuid,
                block=block_number,
            )
            step = "substrate.query(Timestamp.Now at receipt block)"
            timestamp_value = substrate.query(
                module="Timestamp",
                storage_function="Now",
                block_hash=block_hash,
            )
            timestamp_ms = getattr(timestamp_value, "value", timestamp_value)
            if (
                isinstance(timestamp_ms, bool)
                or not isinstance(timestamp_ms, int)
                or timestamp_ms <= 0
            ):
                return _receipt_verdict(
                    reason_out,
                    NOT_PROVEN,
                    "the inclusion block timestamp is not a positive integer",
                )
            step = "decode the inclusion block timestamp"
            inclusion_time = datetime.fromtimestamp(timestamp_ms / 1000, UTC)
            step = "subtensor.get_next_epoch_start_block(receipt block)"
            inclusion_next_epoch = (
                subtensor.get_next_epoch_start_block(
                    netuid,
                    block=block_number,
                )
                if inclusion_policy.expected_next_epoch_start_block is not None
                else None
            )
        else:
            commit_reveal_at_inclusion = None
            inclusion_time = None
            inclusion_next_epoch = None
        step = "subtensor.get_subnet_owner_hotkey(receipt block)"
        inclusion_owner_hotkey = (
            str(subtensor.get_subnet_owner_hotkey(netuid, block=block_number) or "")
            if expected_subnet_owner_hotkey is not None
            else None
        )
        step = "substrate.retrieve_extrinsic_by_hash(receipt block)"
        historical_execution = substrate.retrieve_extrinsic_by_hash(
            block_hash,
            extrinsic_hash,
        )
    except Exception as exc:  # noqa: BLE001 - archive/RPC unavailability is inconclusive
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            f"chain read failed at {step}: {stable_error(exc)}",
        )
    if not isinstance(block, dict):
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "the named block did not decode to a dict",
        )
    extrinsics = block.get("extrinsics")
    if not isinstance(extrinsics, (list, tuple)):
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "the named block carries no extrinsics list",
        )
    matching = [
        (index, item.value)
        for index, item in enumerate(extrinsics)
        if isinstance(getattr(item, "value", None), dict)
        and str(item.value.get("extrinsic_hash", "")).lower() == extrinsic_hash.lower()
    ]
    if not matching:
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "no extrinsic in the named block carries the signed hash",
        )
    if len(matching) > 1:
        return _receipt_verdict(
            reason_out,
            FAIL,
            "the named block carries the signed hash more than once",
        )
    extrinsic_index, observed = matching[0]
    if historical_execution is None:
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "the archive returned no execution record for the signed hash",
        )
    historical_success = getattr(historical_execution, "is_success", None)
    historical_index = getattr(historical_execution, "extrinsic_idx", None)
    if not isinstance(historical_success, bool) or isinstance(historical_index, bool):
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "the execution record exposes no boolean is_success or "
            "non-boolean extrinsic_idx",
        )
    try:
        historical_execution_index = int(historical_index)
    except (TypeError, ValueError):
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "the execution record extrinsic_idx is not an integer",
        )
    if (
        historical_success is not True
        or getattr(historical_execution, "error_message", None) is not None
        or historical_execution_index != extrinsic_index
    ):
        return _receipt_verdict(
            reason_out,
            FAIL,
            "the execution record reports failure or a different extrinsic index",
        )
    historical_execution_ok = True
    call = observed.get("call") or {}
    if (
        _CHAIN_HASH_RE.fullmatch(finalized_hash) is None
        or finalized_number is None
        or _CHAIN_HASH_RE.fullmatch(canonical_finalized_hash) is None
        or _CHAIN_HASH_RE.fullmatch(canonical_hash) is None
        or not isinstance(call, dict)
        or not isinstance(observed.get("address"), str)
        or not isinstance(call.get("call_module"), str)
        or not isinstance(call.get("call_function"), str)
    ):
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "a finalized-head hash, block hash, or decoded call is malformed",
        )
    if canonical_finalized_hash.lower() != finalized_hash.lower():
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "the finalized head did not re-resolve to its own canonical hash",
        )
    if canonical_hash.lower() != block_hash.lower():
        return _receipt_verdict(
            reason_out,
            FAIL,
            "the receipt block hash is not canonical at its block number",
        )
    if finalized_number < block_number:
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            RECEIPT_FINALITY_LAG_REASON,
        )
    if inclusion_policy is not None:
        if not isinstance(commit_reveal_at_inclusion, bool):
            return _receipt_verdict(
                reason_out,
                NOT_PROVEN,
                "commit-reveal state at inclusion is not a bool",
            )
        if inclusion_policy.expected_next_epoch_start_block is not None and (
            isinstance(inclusion_next_epoch, bool)
            or not isinstance(inclusion_next_epoch, int)
        ):
            return _receipt_verdict(
                reason_out,
                NOT_PROVEN,
                "the next-epoch start block at inclusion is not an integer",
            )
    if expected_subnet_owner_hotkey is not None and not inclusion_owner_hotkey:
        return _receipt_verdict(
            reason_out,
            NOT_PROVEN,
            "the subnet owner hotkey at inclusion is empty",
        )
    inclusion_bindings_ok = True
    if uid_hotkeys is not None:
        try:
            inclusion_uids = [
                int(value)
                for value in (
                    inclusion_metagraph.uids.tolist()
                    if hasattr(inclusion_metagraph.uids, "tolist")
                    else inclusion_metagraph.uids
                )
            ]
            inclusion_hotkeys = [str(value) for value in inclusion_metagraph.hotkeys]
            inclusion_map = dict(zip(inclusion_uids, inclusion_hotkeys))
            inclusion_permits = (
                [bool(value) for value in inclusion_metagraph.validator_permit]
                if netuid == 39
                else []
            )
            complete_bindings = (
                len(inclusion_uids) == len(inclusion_hotkeys)
                and len(inclusion_map) == len(inclusion_uids)
                and _finalized_block(getattr(inclusion_metagraph, "block", None))
                == block_number
                and (netuid != 39 or len(inclusion_permits) == len(inclusion_hotkeys))
            )
        except (AttributeError, TypeError, ValueError) as exc:
            return _receipt_verdict(
                reason_out,
                NOT_PROVEN,
                f"the inclusion metagraph did not decode: {stable_error(exc)}",
            )
        if not complete_bindings:
            return _receipt_verdict(
                reason_out,
                NOT_PROVEN,
                "the inclusion metagraph is incomplete at the receipt block",
            )
        inclusion_bindings_ok = all(
            inclusion_map.get(uid) == hotkey for uid, hotkey in uid_hotkeys.items()
        )
        if netuid == 39:
            validator_indexes = [
                index
                for index, hotkey in enumerate(inclusion_hotkeys)
                if hotkey == validator_hotkey
            ]
            if len(validator_indexes) != 1:
                return _receipt_verdict(
                    reason_out,
                    FAIL,
                    "the validator hotkey is not uniquely registered at the "
                    "receipt block",
                )
            inclusion_bindings_ok = (
                inclusion_bindings_ok
                and inclusion_permits[validator_indexes[0]] is True
            )
    inclusion_policy_ok = inclusion_policy is None or (
        inclusion_policy.valid_from_block
        <= block_number
        < inclusion_policy.valid_until_block
        and inclusion_policy.valid_from_time
        <= inclusion_time
        < inclusion_policy.valid_until_time
        and (
            not inclusion_policy.require_commit_reveal_disabled
            or commit_reveal_at_inclusion is False
        )
        and (
            inclusion_policy.expected_next_epoch_start_block is None
            or inclusion_next_epoch == inclusion_policy.expected_next_epoch_start_block
        )
    )
    inclusion_owner_ok = (
        expected_subnet_owner_hotkey is None
        or inclusion_owner_hotkey == expected_subnet_owner_hotkey
    )
    proven = (
        historical_execution_ok
        and observed.get("address") == validator_hotkey
        and call.get("call_module") == "SubtensorModule"
        and call.get("call_function") == "set_mechanism_weights"
        and _chain_call_arg(call, "netuid") == netuid
        and _chain_call_arg(call, "mecid") == 0
        and _chain_call_arg(call, "version_key") == version_key
        and _chain_call_arg(call, "dests") == wire_uids
        and _chain_call_arg(call, "weights") == wire_weights
        and inclusion_bindings_ok
        and inclusion_policy_ok
        and inclusion_owner_ok
    )
    if proven:
        return _receipt_verdict(
            reason_out,
            PASS,
            "the exact finalized call is proven",
        )
    # Recomputed only on the failing branch, so the verdict above keeps its
    # original short-circuit evaluation exactly. Naming which clause disagreed
    # is the difference between "mismatch" and something an operator can act
    # on, and a positive mismatch is the one verdict nobody may automate away.
    contradicted = [
        name
        for name, agreed in (
            ("signer address", observed.get("address") == validator_hotkey),
            ("call module", call.get("call_module") == "SubtensorModule"),
            ("call function", call.get("call_function") == "set_mechanism_weights"),
            ("netuid", _chain_call_arg(call, "netuid") == netuid),
            ("mechanism id", _chain_call_arg(call, "mecid") == 0),
            ("version key", _chain_call_arg(call, "version_key") == version_key),
            ("dests", _chain_call_arg(call, "dests") == wire_uids),
            ("weights", _chain_call_arg(call, "weights") == wire_weights),
            ("UID/hotkey bindings at inclusion", inclusion_bindings_ok),
            ("inclusion policy window", inclusion_policy_ok),
            ("subnet owner at inclusion", inclusion_owner_ok),
        )
        if not agreed
    ]
    return _receipt_verdict(
        reason_out,
        FAIL,
        "the finalized call contradicts "
        + ", ".join(contradicted or ["nothing named"]),
    )


def _prove_finalized_receipt(
    subtensor: Any,
    **kwargs: Any,
) -> bool:
    """Compatibility wrapper for callers that only accept a proven boolean."""
    return _classify_finalized_receipt(subtensor, **kwargs) == PASS


def _reverify_reserved_signed_vector(
    args: Any,
    *,
    identity: dict[str, Any],
    preflight: ChainPreflight,
    uid_weights: dict[int, float],
) -> None:
    """Re-prove the reserved signed vector at the irreversible write boundary.

    Every other check here compares the submission against the durable
    reservation, which makes the reservation the sole authority for what gets
    written. Writing that file needs owner access to the canonical runtime
    root, so this is defense in depth rather than a live exploit, but the
    chain write is irreversible and the evidence to do better is already on
    hand: the reservation carries the signed payload, so the boundary can
    re-derive the policy from Cathedral's signature instead of trusting the
    reservation's own summary of it.
    """
    payload = identity.get("signed_vector")
    if not isinstance(payload, dict):
        raise wire.VectorError(
            "SN39 thin reservation carries no signed vector to re-verify"
        )
    if _sha256_document(payload) != identity.get("signed_vector_sha256"):
        raise wire.VectorError(
            "SN39 reserved signed vector does not hash to its reserved digest"
        )
    # Re-load the fence rather than trusting the reservation's policy_version.
    # The fence only advances after a successful write (_write_state_fenced
    # runs after set_weights_on_chain returns), so at this point it still holds
    # the value the tick accepted against and pv > fence must still hold. The
    # launch path already re-runs accept_vector against that same pre-write
    # fence in _revalidate_launch_after_rewarded_set_replay, so this is the
    # established comparison, not a weakened one.
    fence = load_fence(Path(args.state_file))
    try:
        accept_vector(
            payload,
            public_key_hex=args.public_key_hex,
            key_id=args.key_id,
            network=args.network,
            netuid=args.netuid,
            fence_version=fence,
        )
    except Exception as exc:
        raise wire.VectorError(
            "SN39 reserved signed vector fails signature, wire invariant, or "
            f"rollback re-verification: {stable_error(exc)}"
        ) from exc
    if _validated_supply_meta(payload) is None:
        raise wire.VectorError(
            "SN39 reserved signed vector carries no fixed 90/10 supply contract"
        )
    burn_hotkey = (payload.get("burn_snapshot") or {}).get("burn_hotkey")
    if burn_hotkey != SN39_BURN_HOTKEY or identity.get("burn_hotkey") != burn_hotkey:
        raise wire.VectorError(
            "SN39 reserved signed vector does not burn to the pinned hotkey"
        )
    # Same call the tick used to produce what is about to be written, so a
    # reservation cannot redirect the allocation while keeping a valid payload.
    reverified_uid_weights = vector_to_uid_weights(
        payload,
        preflight.hotkey_to_uid,
        require_policy=getattr(args, "require_policy", None),
    )
    if set(reverified_uid_weights) != set(uid_weights) or any(
        not math.isclose(
            reverified_uid_weights[uid],
            float(uid_weights[uid]),
            rel_tol=0.0,
            abs_tol=1e-12,
        )
        for uid in reverified_uid_weights
    ):
        raise wire.VectorError(
            "SN39 chain call differs from the allocation its reserved signed "
            "vector derives"
        )


def _pending_reviewed_uid30_contract(
    runtime_contract: Any,
    *,
    attempt_id: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Classify a reviewed UID30 reservation from durable state only."""

    state = _read_state(_submission_state_path(runtime_contract))
    identity = state.get("submission_pending_identity")
    durable_kind = state.get("submission_pending_reviewed_uid30_contract")
    identity_marked = isinstance(identity, dict) and bool(
        _uid30_successor_marked(identity)
        or {
            "uid30_launch_schema",
            "uid30_launch_policy",
            "uid30_launch_preview_sha256",
        }.intersection(identity)
    )
    if durable_kind is None and not identity_marked:
        return None
    if not isinstance(identity, dict):
        raise wire.VectorError("reviewed UID30 reservation lost its durable identity")
    contract = _strict_zero_burn_uid30_contract(
        identity,
        lane=state.get("submission_pending_lane"),
    )
    if (
        contract is None
        or state.get("submission_pending_id") != attempt_id
        or (
            durable_kind != contract["kind"]
            and not (durable_kind is None and contract["kind"] == "one_miner_launch")
        )
    ):
        raise wire.VectorError(
            "reviewed UID30 durable marker and reservation identity disagree"
        )
    return state, identity, contract


def _authorize_reviewed_uid30_submission(
    runtime_contract: Any,
    *,
    preflight: ChainPreflight,
    attempt_id: str,
    version_key: int,
    wire_uids: list[int],
    wire_weights: list[int],
) -> None:
    """Authorize only the two fixed source-reviewed UID30 contracts pre-sign."""

    pending = _pending_reviewed_uid30_contract(
        runtime_contract,
        attempt_id=attempt_id,
    )
    if pending is None:
        raise wire.VectorError("reviewed UID30 signing has no durable contract")
    state, identity, contract = pending
    kind = contract["kind"]
    uid_hotkeys = dict(contract["uid_hotkeys"])
    semantic = dict(contract["uid_weights"])
    expected_uids, expected_weights = _wire_weights(
        sorted(semantic),
        [semantic[uid] for uid in sorted(semantic)],
    )
    inclusion = _policy_from_submission_identity(identity)
    runtime_digest = getattr(
        runtime_contract,
        (
            "_uid30_two_miner_successor_preview_sha256"
            if kind == "two_miner_successor"
            else "_uid30_reviewed_preview_sha256"
        ),
        None,
    )
    identity_digest = identity.get(
        "successor_preview_sha256"
        if kind == "two_miner_successor"
        else "uid30_launch_preview_sha256"
    )
    if kind == "one_miner_launch":
        target_uid = expected_uids[0] if len(expected_uids) == 1 else None
        if (
            state.get("submission_pending_lane") != "authority"
            or state.get("submission_pending_phase") != "unsigned_reserved"
            or state.get("submission_pending_broadcast_intent") is not None
            or state.get("submission_pending_receipt_candidate") is not None
            or state.get("submission_pending_proof_status") is not None
            or state.get("submission_genesis_hash") != FINNEY_GENESIS_HASH
            or state.get("provenance_netuid") != 39
            or state.get("submission_validator_hotkey")
            != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
            or preflight.genesis_hash != FINNEY_GENESIS_HASH
            or preflight.validator_uid != SN39_UID30_LAUNCH_VALIDATOR_UID
            or preflight.validator_hotkey != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
            or getattr(preflight.wallet.hotkey, "ss58_address", None)
            != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
            or contract["owner"] != preflight.subnet_owner_hotkey
            or version_key != SN39_UID30_LAUNCH_VERSION_KEY
            or expected_uids != wire_uids
            or expected_weights != wire_weights
            or not isinstance(runtime_digest, str)
            or identity_digest != "sha256:" + runtime_digest
            or identity.get("mapping_block") != preflight.block
            or identity.get("source_epoch") != preflight.block
            or identity.get("next_epoch_start_block")
            != preflight.next_epoch_start_block
            or type(target_uid) is not int
            or preflight.hotkey_to_uid.get(SN39_UID30_LAUNCH_VALIDATOR_HOTKEY)
            != SN39_UID30_LAUNCH_VALIDATOR_UID
            or preflight.hotkey_to_uid.get(SN39_UID30_LAUNCH_MINER_HOTKEY) != target_uid
            or state.get("submission_pending_launch_attempt") is not True
            or state.get("submission_pending_launch_budget_limit") != 1
            or state.get("submission_pending_budget_scope") != "launch_full_gate"
            or state.get("submission_pending_budget_limit") != 1
            or state.get("submission_launch_attempt_ids", []) != []
        ):
            raise wire.VectorError(
                "reviewed one-miner UID30 chain call differs from its reservation"
            )
        return

    state_path = _submission_state_path(runtime_contract)
    if (
        _submission_runtime_root(runtime_contract) != _VALIDATOR_RUNTIME_ROOT
        or state_path.parent != _VALIDATOR_RUNTIME_ROOT
        or state.get("submission_pending_lane") != "authority"
        or state.get("submission_pending_phase") != "unsigned_reserved"
        or state.get("submission_pending_broadcast_intent") is not None
        or state.get("submission_pending_receipt_candidate") is not None
        or state.get("submission_pending_proof_status") is not None
        or state.get("submission_active_lane") != "authority"
        or state.get("submission_genesis_hash") != FINNEY_GENESIS_HASH
        or state.get("provenance_netuid") != 39
        or state.get("submission_validator_hotkey")
        != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
        or preflight.genesis_hash != FINNEY_GENESIS_HASH
        or preflight.validator_uid != SN39_UID30_LAUNCH_VALIDATOR_UID
        or preflight.validator_hotkey != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
        or getattr(preflight.wallet.hotkey, "ss58_address", None)
        != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
        or contract["owner"] != preflight.subnet_owner_hotkey
        or version_key != SN39_UID30_LAUNCH_VERSION_KEY
        or expected_uids != wire_uids
        or expected_weights != wire_weights
        or not isinstance(runtime_digest, str)
        or identity_digest != "sha256:" + runtime_digest
        or identity.get("mapping_block") != preflight.block
        or identity.get("source_epoch") != preflight.block
        or identity.get("next_epoch_start_block") != preflight.next_epoch_start_block
        or preflight.min_allowed_weights != 1
        or not math.isclose(
            preflight.max_weight_limit,
            1.0,
            rel_tol=0.0,
            abs_tol=0.0,
        )
    ):
        raise wire.VectorError(
            "reviewed UID30 chain call differs from its exact reservation"
        )
    _require_inclusion_policy_ready(inclusion, preflight)
    observed_safety = _require_uid_mapping_stability(
        preflight,
        uid_hotkeys,
        mortal_period_blocks=inclusion.mortal_period_blocks,
    )
    uid_reverse_rows = {
        uid: sorted(
            hotkey
            for hotkey, mapped_uid in preflight.hotkey_to_uid.items()
            if mapped_uid == uid
        )
        for uid in [SN39_UID30_LAUNCH_VALIDATOR_UID, *uid_hotkeys]
    }
    if (
        identity.get("uid_safety") != observed_safety
        or identity.get("inclusion_policy") != _inclusion_policy_identity(inclusion)
        or preflight.hotkey_to_uid.get(SN39_UID30_LAUNCH_VALIDATOR_HOTKEY)
        != SN39_UID30_LAUNCH_VALIDATOR_UID
        or uid_reverse_rows.get(SN39_UID30_LAUNCH_VALIDATOR_UID)
        != [SN39_UID30_LAUNCH_VALIDATOR_HOTKEY]
        or any(
            preflight.hotkey_to_uid.get(hotkey) != uid
            or uid_reverse_rows.get(uid) != [hotkey]
            for uid, hotkey in uid_hotkeys.items()
        )
    ):
        raise wire.VectorError(
            "reviewed UID30 hotkey mappings or safety changed before signing"
        )
    launch_identity = state.get("submission_launch_identity")
    launch_intent = state.get("submission_launch_broadcast_intent")
    finalized_identity = state.get("submission_finalized_identity")
    finalized_intent = state.get("submission_finalized_broadcast_intent")
    finalized_receipt = state.get("submission_finalized_receipt")
    exact_launch_budget = {
        "launch_full_gate": {
            "limit": 1,
            "ids": [SN39_UID30_SUCCESSOR_PREDECESSOR_ID],
        }
    }
    if (
        state_path.name != SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
        or state.get("submission_pending_reviewed_uid30_contract")
        != "two_miner_successor"
        or state.get("submission_pending_predecessor_journal_sha256")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256
        or state.get("submission_pending_launch_attempt") is not False
        or state.get("submission_pending_launch_budget_limit") is not None
        or state.get("submission_pending_budget_scope") != "authority_bounded"
        or state.get("submission_pending_budget_limit") != 1
        or state.get("submission_pending_source_epoch") != identity.get("source_epoch")
        or type(preflight.block) is not int
        or type(preflight.validator_blocks_since_last_update) is not int
        or preflight.block - preflight.validator_blocks_since_last_update
        != SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK
        or state.get("submission_attempt_ids") != [SN39_UID30_SUCCESSOR_PREDECESSOR_ID]
        or state.get("submission_attempt_count") != 1
        or state.get("submission_finalized_count") != 1
        or state.get("submission_highest_source_epoch")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_SOURCE_EPOCH
        or state.get("submission_finalized_id") != SN39_UID30_SUCCESSOR_PREDECESSOR_ID
        or state.get("submission_finalized_lane") != "authority"
        or not isinstance(finalized_identity, dict)
        or not isinstance(finalized_intent, dict)
        or not isinstance(finalized_receipt, dict)
        or _sha256_document(finalized_identity).removeprefix("sha256:")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_IDENTITY_SHA256
        or _sha256_document(finalized_intent).removeprefix("sha256:")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_INTENT_SHA256
        or _sha256_document(finalized_receipt).removeprefix("sha256:")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_RECEIPT_SHA256
        or state.get("submission_extrinsic_hash")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH
        or state.get("submission_block_hash")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH
        or state.get("submission_block_number")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK
        or state.get("submission_version_key") != SN39_UID30_LAUNCH_VERSION_KEY
        or state.get("submission_launch_status") != "finalized"
        or state.get("submission_launch_attempt_id")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_ID
        or state.get("submission_launch_attempt_ids")
        != [SN39_UID30_SUCCESSOR_PREDECESSOR_ID]
        or state.get("submission_launch_budget_limit") != 1
        or state.get("submission_continuous_enabled") is not False
        or not isinstance(launch_identity, dict)
        or not isinstance(launch_intent, dict)
        or launch_identity != finalized_identity
        or launch_intent != finalized_intent
        or state.get("submission_launch_extrinsic_hash")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH
        or state.get("submission_launch_block_hash")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH
        or state.get("submission_launch_block_number")
        != SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK
        or state.get("submission_launch_version_key") != SN39_UID30_LAUNCH_VERSION_KEY
        or _sha256_document(state.get("submission_launch_uid_safety", {})).removeprefix(
            "sha256:"
        )
        != SN39_UID30_SUCCESSOR_PREDECESSOR_UID_SAFETY_SHA256
        or finalized_intent.get("wire_uids") != [SN39_UID30_SUCCESSOR_PREDECESSOR_UID]
        or finalized_intent.get("wire_weights") != [65535]
        or finalized_receipt.get("wire_uids") != [SN39_UID30_SUCCESSOR_PREDECESSOR_UID]
        or finalized_receipt.get("wire_weights") != [65535]
        or state.get("submission_attempt_budgets") != exact_launch_budget
    ):
        raise wire.VectorError("reviewed UID30 predecessor lineage changed")
    try:
        _strict_uid30_successor_unsigned_rollback(
            state,
            attempt_id=attempt_id,
            state_file=state_path,
        )
    except ValueError as exc:
        raise wire.VectorError(
            "reviewed UID30 predecessor rollback lineage changed"
        ) from exc

    substrate = getattr(preflight.subtensor, "substrate", None)
    if substrate is None or preflight.finalized_hash is None:
        raise wire.VectorError("reviewed UID30 successor has no finalized storage")
    try:
        canonical_current_hash = str(substrate.get_block_hash(preflight.block)).lower()
        if canonical_current_hash != str(preflight.finalized_hash).lower():
            raise wire.VectorError("reviewed UID30 finalized head is not canonical")
        for proof in identity["fresh_miner_evidence"]:
            if (
                type(proof.get("anchor_number")) is not int
                or proof["anchor_number"] > preflight.block
                or proof["anchor_number"] < inclusion.valid_from_block
                or str(substrate.get_block_hash(proof["anchor_number"])).lower()
                != proof["anchor_hash"]
            ):
                raise wire.VectorError(
                    "reviewed UID30 successor evidence anchor is not canonical"
                )
        version_floor = substrate.query(
            module="SubtensorModule",
            storage_function="WeightsVersionKey",
            params=[39],
            block_hash=str(preflight.finalized_hash).lower(),
        )
        current = substrate.query(
            module="SubtensorModule",
            storage_function="Weights",
            params=[get_mechid_storage_index(39, 0), 30],
            block_hash=str(preflight.finalized_hash).lower(),
        )
        historical_hash = str(
            substrate.get_block_hash(SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK)
        ).lower()
        historical = substrate.query(
            module="SubtensorModule",
            storage_function="Weights",
            params=[get_mechid_storage_index(39, 0), 30],
            block_hash=SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH,
        )
    except wire.VectorError:
        raise
    except Exception as exc:  # noqa: BLE001 - archive absence is a refusal
        raise wire.VectorError(
            "reviewed UID30 predecessor storage cannot be re-proven"
        ) from exc
    version_floor = getattr(version_floor, "value", version_floor)
    current_rows = getattr(current, "value", current)
    historical_rows = getattr(historical, "value", historical)
    historical_reason: list[str] = []
    historical_proof = _classify_finalized_receipt(
        preflight.subtensor,
        receipt=None,
        extrinsic_hash=SN39_UID30_SUCCESSOR_PREDECESSOR_EXTRINSIC_HASH,
        block_hash=SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH,
        block_number=SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK,
        validator_hotkey=SN39_UID30_LAUNCH_VALIDATOR_HOTKEY,
        netuid=39,
        version_key=SN39_UID30_LAUNCH_VERSION_KEY,
        wire_uids=[SN39_UID30_SUCCESSOR_PREDECESSOR_UID],
        wire_weights=[65535],
        uid_hotkeys={
            SN39_UID30_LAUNCH_VALIDATOR_UID: SN39_UID30_LAUNCH_VALIDATOR_HOTKEY,
            SN39_UID30_SUCCESSOR_PREDECESSOR_UID: SN39_UID30_LAUNCH_MINER_HOTKEY,
        },
        expected_subnet_owner_hotkey=str(finalized_identity["subnet_owner_hotkey"]),
        inclusion_policy=_policy_from_submission_identity(finalized_identity),
        require_receipt=False,
        reason_out=historical_reason,
    )
    if (
        type(version_floor) is not int
        or (version_floor != 0 and version_key < version_floor)
        or current_rows
        not in (
            [[SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 65535]],
            [(SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 65535)],
        )
        or historical_hash != SN39_UID30_SUCCESSOR_PREDECESSOR_BLOCK_HASH
        or historical_rows
        not in (
            [[SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 65535]],
            [(SN39_UID30_SUCCESSOR_PREDECESSOR_UID, 65535)],
        )
        or historical_proof != PASS
    ):
        raise wire.VectorError(
            "reviewed UID30 predecessor inclusion is not exact and canonical"
            + _receipt_reason_suffix(historical_reason)
        )


def _authorize_sn39_chain_submission(
    args: Any | None,
    *,
    uid_weights: dict[int, float],
    uid_hotkeys: dict[int, str] | None,
    network: str,
    netuid: int,
    wallet_name: str,
    wallet_hotkey: str,
    preflight: ChainPreflight,
    inclusion_policy: InclusionPolicy | None,
) -> None:
    """Authorize the sole repository SN39 writer at its lowest call boundary.

    Callers cannot reach the irreversible extrinsic by importing this module
    and calling ``set_weights_on_chain`` directly.  A write must carry the
    exact immutable runtime profile, resolved Finney identity, and a durable
    reservation made by the shared submission state machine. The bounded launch
    also carries its synchronous strict replay. Later recurring writes re-prove
    the independent root-signed launch seal plus a separate bounded approval.
    """
    if args is None:
        raise wire.VectorError(
            "SN39 chain submission requires an authorized validator runtime"
        )
    if (
        not bool(getattr(args, "broadcast", False))
        or bool(getattr(args, "offline", False))
        or int(getattr(args, "netuid", -1)) != netuid
        or str(getattr(args, "network", "")).strip().lower()
        != str(network).strip().lower()
        or getattr(args, "wallet_name", None) != wallet_name
        or getattr(args, "wallet_hotkey", None) != wallet_hotkey
    ):
        raise wire.VectorError(
            "SN39 chain call differs from its authorized runtime contract"
        )
    _validate_runtime_contract(args)
    _validate_resolved_chain_contract(args, preflight)
    if (
        getattr(args, "_submission_validator_hotkey", None)
        != preflight.validator_hotkey
        or str(getattr(args, "_submission_genesis_hash", "")).lower()
        != str(preflight.genesis_hash).lower()
    ):
        raise wire.VectorError(
            "SN39 chain call is not bound to the prepared signer and genesis"
        )

    state = _read_state(_submission_state_path(args))
    attempt_id = state.get("submission_pending_id")
    identity = state.get("submission_pending_identity")
    lane = state.get("submission_pending_lane")
    active_lane = state.get("submission_active_lane")
    transition_from = state.get("submission_pending_lane_transition_from")
    ordinary_lane = active_lane in {None, lane} and transition_from is None
    authorized_transition = bool(
        active_lane == "thin"
        and lane == "authority"
        and transition_from == "thin"
        and isinstance(identity, dict)
        and _authority_lane_transition_authorized(state, identity)
    )
    if (
        not isinstance(attempt_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", attempt_id) is None
        or lane not in {"thin", "authority"}
        or state.get("submission_pending_phase") != "unsigned_reserved"
        or not isinstance(identity, dict)
        or not (ordinary_lane or authorized_transition)
    ):
        raise wire.VectorError(
            "SN39 chain submission has no exact durable state-machine reservation"
        )
    try:
        reserved_uid_weights = {
            int(uid): float(weight) for uid, weight in identity["uid_weights"]
        }
        reserved_uid_hotkeys = {
            int(uid): str(hotkey) for uid, hotkey in identity["uid_hotkeys"]
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise wire.VectorError("SN39 submission reservation is malformed") from exc
    exact_weights = set(reserved_uid_weights) == set(uid_weights) and all(
        math.isclose(
            reserved_uid_weights[uid],
            float(uid_weights[uid]),
            rel_tol=0.0,
            abs_tol=1e-12,
        )
        for uid in reserved_uid_weights
    )
    exact_hotkeys = uid_hotkeys is not None and reserved_uid_hotkeys == {
        int(uid): str(hotkey) for uid, hotkey in uid_hotkeys.items()
    }
    if (
        identity.get("network") != "finney"
        or identity.get("netuid") != 39
        or identity.get("validator_hotkey") != preflight.validator_hotkey
        or not exact_weights
        or not exact_hotkeys
    ):
        raise wire.VectorError(
            "SN39 chain call differs from its exact durable reservation"
        )
    if not isinstance(inclusion_policy, InclusionPolicy):
        raise wire.VectorError(
            "SN39 chain submission requires an inclusion-time evidence policy"
        )
    try:
        _require_inclusion_policy_ready(inclusion_policy, preflight)
    except _EpochRoomUnavailable as exc:
        # Same sentence, different moment. Everywhere else this gate runs, the
        # tick has reserved nothing and running out of epoch room is a wait
        # that the next tick clears by itself. HERE the durable attempt fence
        # is already held for this exact call, so the refusal leaves journal
        # state an operator has to resolve and must keep reporting as the
        # failure it has always been. Re-raise as the plain refusal so this
        # boundary's event, status, remediation, and exit code are unchanged.
        raise wire.VectorError(str(exc)) from exc
    observed_uid_safety = _require_uid_mapping_stability(
        preflight,
        {int(uid): str(hotkey) for uid, hotkey in uid_hotkeys.items()},
        mortal_period_blocks=inclusion_policy.mortal_period_blocks,
    )
    if identity.get("uid_safety") != observed_uid_safety:
        raise wire.VectorError(
            "SN39 UID/hotkey safety differs from its exact durable reservation"
        )
    if identity.get("inclusion_policy") != _inclusion_policy_identity(inclusion_policy):
        raise wire.VectorError(
            "SN39 inclusion policy differs from its durable reservation"
        )
    if (
        preflight.block is None
        or identity.get("next_epoch_start_block") != preflight.next_epoch_start_block
    ):
        raise wire.VectorError(
            "SN39 exact next epoch differs from its durable reservation"
        )
    if lane == "thin":
        # Applies to relay, thin-continuous, and launch alike: all three relay a
        # signed vector, so the payload is the authority for what may be
        # written and re-proving it is strictly more evidence. The serialized
        # authority lane is retained for bounded UID30 launch and historical
        # recovery. Those identities have their own reviewed replay proof and
        # no signed feed vector to rebind here.
        _reverify_reserved_signed_vector(
            args,
            identity=identity,
            preflight=preflight,
            uid_weights=uid_weights,
        )

    launch = bool(getattr(args, "require_full_provenance_for_broadcast", False))
    if not launch and not _continuous_transition_required(args):
        # Relay: this runtime owes SN39 no launch of its own, so there is no
        # recurring-write authorization to re-prove. Everything that makes the
        # write safe still ran above (pinned trust profile, verified signature,
        # exact durable reservation, UID/epoch/inclusion safety). Refuse a call
        # that nonetheless claims launch or recurring approval it cannot
        # present, so the relay path can never be used to smuggle one.
        # A bounded UID30 or historical authority-labelled launch lane reaches
        # here only under the beta launch waiver. Every guarded claim remains
        # refused below for both serialized lanes.
        allowed_lanes = (
            ("thin", "authority") if _operator_declared_authority(args) else ("thin",)
        )
        if (
            lane not in allowed_lanes
            or identity.get("continuous_authorization") is not None
            or getattr(args, "_continuous_submission_authorization", None) is not None
            or state.get("submission_pending_launch_attempt") is True
            or state.get("submission_pending_budget_scope")
            not in (None, f"{lane}_bounded")
        ):
            raise wire.VectorError(
                "SN39 relay chain call claims launch or recurring-write "
                "authority it cannot present"
            )
        return
    if not launch:
        authorization = getattr(args, "_continuous_submission_authorization", None)
        if (
            not isinstance(authorization, ContinuousAuthorization)
            or identity.get("continuous_authorization")
            != _continuous_authorization_identity(authorization)
            or state.get("submission_continuous_launch_attempt_id")
            != authorization.launch_attempt_id
            or state.get("submission_continuous_release_sha256")
            != authorization.release_sha256
            or state.get("submission_continuous_reproducer_revision")
            != authorization.reproducer_revision
            or preflight.validator_hotkey != authorization.validator_hotkey
            or preflight.genesis_hash != authorization.genesis_hash
            or lane not in authorization.lanes
            or state.get("submission_pending_budget_scope")
            != authorization.authorization_sha256.removeprefix("sha256:")
            or state.get("submission_pending_budget_limit")
            != authorization.max_attempts
        ):
            raise wire.VectorError(
                "SN39 continuous chain call lacks its pre-reservation "
                "root-signed recurring-write authorization and durable budget"
            )
        try:
            from scaffold import sn39_continuous_authorization as recurring

            reverified = recurring.verify_authorization(
                expected={
                    "submission_journal": str(_submission_state_path(args)),
                    "genesis_hash": preflight.genesis_hash,
                    "validator_hotkey": preflight.validator_hotkey,
                    "launch_attempt_id": authorization.launch_attempt_id,
                    "release_sha256": authorization.release_sha256,
                    "reproducer_revision": authorization.reproducer_revision,
                    "not_before_time": state.get("submission_continuous_enabled_at"),
                },
                lane=lane,
                finalized_block=preflight.block,
            )
            reverified_authorization = ContinuousAuthorization(
                authorization_sha256=reverified.authorization_sha256,
                submission_journal=reverified.submission_journal,
                launch_attempt_id=reverified.launch_attempt_id,
                release_sha256=reverified.release_sha256,
                reproducer_revision=reverified.reproducer_revision,
                validator_hotkey=reverified.validator_hotkey,
                genesis_hash=reverified.genesis_hash,
                lanes=reverified.lanes,
                issued_at=reverified.issued_at,
                valid_from_time=reverified.valid_from_time,
                valid_until_time=reverified.valid_until_time,
                valid_from_block=reverified.valid_from_block,
                valid_until_block=reverified.valid_until_block,
                valid_from_nonce=reverified.valid_from_nonce,
                valid_until_nonce_exclusive=reverified.valid_until_nonce_exclusive,
                max_attempts=reverified.max_attempts,
            )
            if reverified_authorization != authorization:
                raise recurring.AuthorizationError(
                    "recurring-write artifact changed after reservation"
                )
            recurring.assert_still_ready(
                reverified,
                lane=lane,
                finalized_block=preflight.block,
            )
        except Exception as exc:
            raise wire.VectorError(
                "SN39 recurring-write authorization signature, bytes, expiry, "
                "or scope changed before the chain boundary"
            ) from exc
        return
    audit = getattr(args, "_launch_rewarded_set_audit", None)
    full = identity.get("full_provenance")
    rewarded = set(getattr(audit, "recomputed", {}) or {})
    receipts = set(getattr(audit, "receipt_hotkeys", ()) or ())
    replayed = set(getattr(audit, "raw_replayed_hotkeys", ()) or ())
    if (
        lane != "thin"
        or state.get("submission_pending_launch_attempt") is not True
        or state.get("submission_pending_launch_budget_limit") != 1
        or state.get("submission_launch_attempt_ids", []) != []
        or not isinstance(inclusion_policy, InclusionPolicy)
        or not isinstance(full, dict)
        or getattr(audit, "status", None) != PASS
        or getattr(audit, "agrees_with_vector", None) is not True
        or not rewarded
        or rewarded != receipts
        or rewarded != replayed
    ):
        raise wire.VectorError(
            "SN39 launch chain call lacks its one-shot rewarded-set raw-replay gate"
        )
    approval = _require_launch_approval(
        args,
        payload=identity.get("signed_vector") or {},
        audit=audit,
        preflight=preflight,
        uid_weights=uid_weights,
        hotkey_to_uid=preflight.hotkey_to_uid,
    )
    expected_approval_identity = {
        "approval_digest": approval["approval_digest"],
        "reviewed_finalized_block": approval["reviewed_finalized_block"],
        "reviewed_finalized_hash": approval["reviewed_finalized_hash"],
        "approval_valid_until_block": approval["approval_valid_until_block"],
    }
    if identity.get("launch_approval") != expected_approval_identity:
        raise wire.VectorError(
            "SN39 launch reservation differs from its root-controlled approval"
        )
    expected_freshness_boundary = _require_launch_evidence_after_rotations(
        payload=identity.get("signed_vector") or {},
        audit=audit,
        uid_safety=observed_uid_safety,
    )
    full_matches_audit = (
        full.get("source_epoch") == getattr(audit, "source_epoch", None),
        full.get("report_id") == getattr(audit, "report_id", None),
        full.get("manifest") == getattr(audit, "manifest_digest", None),
        full.get("policy_release") == getattr(audit, "policy_release", None),
        full.get("policy_digest") == getattr(audit, "policy_digest", None),
        full.get("mechanism") == getattr(audit, "mechanism", None),
        full.get("scope") in ("rewarded_set_proven", "rewarded_set_full"),
        full.get("whole_epoch_assurance") == getattr(audit, "assurance", None),
        full.get("vector_agrees") is True,
        full.get("rewarded_hotkeys") == sorted(rewarded),
        full.get("raw_replayed_hotkeys") == sorted(replayed),
        full.get("verifier_digest") == SN39_VERIFIER_DIGEST,
        full.get("verifier_binary_digest")
        == getattr(audit, "verifier_binary_digest", None),
        isinstance(full.get("verifier_binary_digest"), str),
        full.get("report_signing_key_id")
        == getattr(audit, "report_signing_key_id", None),
        isinstance(full.get("report_signing_key_id"), str),
        full.get("signed_index") == getattr(audit, "signed_index", None),
        isinstance(full.get("signed_index"), dict),
        full.get("source_revision") == SN39_PRODUCER_REVISION,
        full.get("freshness_boundary") == expected_freshness_boundary,
    )
    if not all(full_matches_audit):
        raise wire.VectorError(
            "SN39 launch reservation does not match the synchronous rewarded-set "
            "raw replay"
        )


def _require_reviewed_uid30_finalized_descendant(
    preflight: ChainPreflight,
    *,
    runtime_contract: Any,
    attempt_id: str,
    latest_finalized_block: int,
    latest_finalized_hash: str,
    wire_uids: list[int],
    wire_weights: list[int],
    version_key: int,
    mortal_period_blocks: int,
) -> None:
    """Permit the one reviewed UID30 launch to sign from a fresh descendant.

    This is not a generic head-drift relaxation.  It re-proves the exact
    zero-burn launch reservation, the target's complete-era replacement proof,
    the original finalized block's canonical hash, and both live UID mappings
    at the descendant.  A drift beyond the measured two-block read window
    remains a pre-sign retry.
    """

    if preflight.block is None:
        raise wire.VectorError("UID30 descendant signing has no mapping block")
    drift = latest_finalized_block - preflight.block
    if (
        drift <= 0
        or drift > SN39_UID30_LAUNCH_MAX_FINALIZED_DRIFT_BLOCKS
        or latest_finalized_block >= preflight.block + mortal_period_blocks
    ):
        raise _RetryablePreSignHeadDrift(
            "SN39 finalized head moved outside the reviewed UID30 launch window; "
            "refusing before signing"
        )

    state = _read_state(_submission_state_path(runtime_contract))
    lane = state.get("submission_pending_lane")
    identity = state.get("submission_pending_identity")
    if (
        state.get("submission_pending_id") != attempt_id
        or state.get("submission_pending_phase") != "unsigned_reserved"
        or state.get("submission_pending_broadcast_intent") is not None
        or state.get("submission_pending_receipt_candidate") is not None
        or state.get("submission_pending_proof_status") is not None
        # Prior generic writes are legitimate global-journal history.  The
        # launch-specific one-shot budget, not a virgin journal, proves this
        # reviewed launch has never signed before.
        or state.get("submission_launch_attempt_ids") not in (None, [])
        or lane != "authority"
        or not isinstance(identity, dict)
    ):
        raise wire.VectorError(
            "UID30 descendant signing has no pristine exact reservation"
        )
    zero_burn_owner = _strict_zero_burn_uid30_owner(identity, lane=lane)

    raw_uid_safety = identity.get("uid_safety")
    uid_safety = raw_uid_safety if isinstance(raw_uid_safety, dict) else {}
    raw_registration = uid_safety.get("registration")
    registration = raw_registration if isinstance(raw_registration, dict) else {}
    raw_rotation = uid_safety.get("rotation")
    rotation = raw_rotation if isinstance(raw_rotation, dict) else {}
    targets = rotation.get("targets")
    target_uid = wire_uids[0] if len(wire_uids) == 1 else None
    target_rows = (
        [
            target
            for target in targets
            if isinstance(target, dict)
            and target.get("uid") == target_uid
            and target.get("hotkey") == SN39_UID30_LAUNCH_MINER_HOTKEY
            and target.get("registration_replacement_safe") is True
            and target.get("pending_coldkey_swap") is None
        ]
        if isinstance(targets, list)
        else []
    )
    safe_hotkeys = registration.get("replacement_safe_hotkeys")
    expected_hash = str(preflight.finalized_hash).lower()
    raw_policy = identity.get("inclusion_policy")
    policy = raw_policy if isinstance(raw_policy, dict) else {}
    policy_from = policy.get("valid_from_block")
    policy_until = policy.get("valid_until_block")
    runtime_preview_digest = getattr(
        runtime_contract, "_uid30_reviewed_preview_sha256", None
    )
    if (
        state.get("submission_genesis_hash") != FINNEY_GENESIS_HASH
        or state.get("provenance_netuid") != 39
        or state.get("submission_validator_hotkey")
        != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
        or state.get("submission_pending_launch_attempt") is not True
        or state.get("submission_pending_launch_budget_limit") != 1
        or state.get("submission_pending_budget_scope") != "launch_full_gate"
        or state.get("submission_pending_budget_limit") != 1
        or bool(
            getattr(runtime_contract, "require_full_provenance_for_broadcast", False)
        )
        is not True
        or getattr(runtime_contract, "max_submissions", None) != 1
        or getattr(runtime_contract, "_continuous_submission_authorization", None)
        is not None
        or not isinstance(runtime_preview_digest, str)
        or identity.get("uid30_launch_preview_sha256")
        != "sha256:" + runtime_preview_digest
        or identity.get("continuous_authorization") is not None
        or preflight.genesis_hash != FINNEY_GENESIS_HASH
        or preflight.validator_hotkey != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
        or preflight.validator_uid != SN39_UID30_LAUNCH_VALIDATOR_UID
        or getattr(preflight.wallet.hotkey, "ss58_address", None)
        != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
        or zero_burn_owner != preflight.subnet_owner_hotkey
        or preflight.hotkey_to_uid.get(SN39_UID30_LAUNCH_VALIDATOR_HOTKEY)
        != SN39_UID30_LAUNCH_VALIDATOR_UID
        or type(target_uid) is not int
        or target_uid < 0
        or preflight.hotkey_to_uid.get(SN39_UID30_LAUNCH_MINER_HOTKEY) != target_uid
        or not isinstance(preflight.replacement_safe_hotkeys, frozenset)
        or SN39_UID30_LAUNCH_MINER_HOTKEY not in preflight.replacement_safe_hotkeys
        or wire_weights != [65535]
        or version_key != SN39_UID30_LAUNCH_VERSION_KEY
        or identity.get("mapping_block") != preflight.block
        or identity.get("source_epoch") != preflight.block
        or identity.get("uid_weights") != [[target_uid, 1.0]]
        or identity.get("uid_hotkeys") != [[target_uid, SN39_UID30_LAUNCH_MINER_HOTKEY]]
        or uid_safety.get("schema") != "cathedral_sn39_uid_safety_v2"
        or uid_safety.get("stability_basis") != "operator_controlled_coldkeys"
        or uid_safety.get("excluded_hotkeys") != []
        or not isinstance(safe_hotkeys, list)
        or SN39_UID30_LAUNCH_MINER_HOTKEY not in safe_hotkeys
        or rotation.get("status") != PASS
        or rotation.get("mapping_block") != preflight.block
        or str(rotation.get("mapping_block_hash", "")).lower() != expected_hash
        or rotation.get("mortal_period_blocks") != mortal_period_blocks
        or rotation.get("era_last_block") != preflight.block + mortal_period_blocks - 1
        or not isinstance(targets, list)
        or len(targets) != 1
        or len(target_rows) != 1
        or type(policy_from) is not int
        or policy_from > preflight.block
        or type(policy_until) is not int
        or policy_until < preflight.block + mortal_period_blocks
        or policy.get("mortal_period_blocks") != mortal_period_blocks
        or identity.get("next_epoch_start_block") != preflight.next_epoch_start_block
    ):
        raise wire.VectorError(
            "UID30 descendant signing differs from its reviewed mapping or era proof"
        )

    inclusion_policy = _policy_from_submission_identity(identity)
    moment = datetime.now(UTC)
    if (
        inclusion_policy.valid_from_block > preflight.block
        or latest_finalized_block < preflight.block
        or inclusion_policy.valid_until_block - latest_finalized_block
        < mortal_period_blocks
        or inclusion_policy.expected_next_epoch_start_block - latest_finalized_block
        < mortal_period_blocks * 3
        or inclusion_policy.require_commit_reveal_disabled is not True
        or preflight.commit_reveal_enabled is not False
        or not (
            inclusion_policy.valid_from_time
            <= moment
            < inclusion_policy.valid_until_time
        )
        or (inclusion_policy.valid_until_time - moment).total_seconds()
        < CHAIN_OPERATION_DEADLINE_SECS + SN39_MIN_VALIDITY_MARGIN_SECS
    ):
        raise wire.VectorError(
            "UID30 descendant signing lacks the reviewed time, block, or epoch room"
        )

    substrate = getattr(preflight.subtensor, "substrate", None)
    if substrate is None:
        raise wire.VectorError("UID30 descendant signing has no substrate interface")
    try:
        canonical_preflight_hash = str(
            substrate.get_block_hash(preflight.block)
        ).lower()
    except Exception as exc:  # noqa: BLE001 - fail closed before signing
        raise wire.VectorError(
            "UID30 descendant signing cannot re-resolve its mapping block"
        ) from exc
    if (
        _CHAIN_HASH_RE.fullmatch(expected_hash) is None
        or canonical_preflight_hash != expected_hash
        or _CHAIN_HASH_RE.fullmatch(latest_finalized_hash) is None
    ):
        raise wire.VectorError(
            "UID30 descendant signing mapping block is no longer canonical"
        )

    # Heights alone do not prove ancestry.  The exception is capped at two
    # blocks, so walking the finalized parent links is both bounded and exact.
    cursor_hash = latest_finalized_hash
    try:
        for _ in range(drift):
            observed_header = substrate.get_block_header(block_hash=cursor_hash)
            if not isinstance(observed_header, dict):
                raise ValueError("finalized header is unavailable")
            header = observed_header.get("header", observed_header)
            if not isinstance(header, dict):
                raise ValueError("finalized header is malformed")
            parent_hash = str(
                header.get("parentHash", header.get("parent_hash", ""))
            ).lower()
            if _CHAIN_HASH_RE.fullmatch(parent_hash) is None:
                raise ValueError("finalized parent hash is malformed")
            cursor_hash = parent_hash
    except Exception as exc:  # noqa: BLE001 - fail closed before signing
        raise wire.VectorError(
            "UID30 descendant signing cannot prove finalized ancestry"
        ) from exc
    if cursor_hash != expected_hash:
        raise wire.VectorError(
            "UID30 descendant signing finalized head is not a child of the review"
        )

    try:
        validator_uid_raw = substrate.query(
            module="SubtensorModule",
            storage_function="Uids",
            params=[39, SN39_UID30_LAUNCH_VALIDATOR_HOTKEY],
            block_hash=latest_finalized_hash,
        )
        validator_uid = getattr(validator_uid_raw, "value", validator_uid_raw)
        validator_hotkey_raw = substrate.query(
            module="SubtensorModule",
            storage_function="Keys",
            params=[39, SN39_UID30_LAUNCH_VALIDATOR_UID],
            block_hash=latest_finalized_hash,
        )
        live_validator_hotkey = getattr(
            validator_hotkey_raw, "value", validator_hotkey_raw
        )
        target_uid_raw = substrate.query(
            module="SubtensorModule",
            storage_function="Uids",
            params=[39, SN39_UID30_LAUNCH_MINER_HOTKEY],
            block_hash=latest_finalized_hash,
        )
        live_target_uid = getattr(target_uid_raw, "value", target_uid_raw)
        target_hotkey_raw = substrate.query(
            module="SubtensorModule",
            storage_function="Keys",
            params=[39, target_uid],
            block_hash=latest_finalized_hash,
        )
        target_hotkey = getattr(target_hotkey_raw, "value", target_hotkey_raw)
    except Exception as exc:  # noqa: BLE001 - fail closed before signing
        raise wire.VectorError(
            "UID30 descendant signing cannot re-read the live UID mappings"
        ) from exc
    if (
        isinstance(validator_uid, bool)
        or not isinstance(validator_uid, int)
        or validator_uid != SN39_UID30_LAUNCH_VALIDATOR_UID
        or str(live_validator_hotkey) != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
        or isinstance(live_target_uid, bool)
        or not isinstance(live_target_uid, int)
        or live_target_uid != target_uid
        or str(target_hotkey) != SN39_UID30_LAUNCH_MINER_HOTKEY
    ):
        raise wire.VectorError(
            "UID30 descendant signing live UID mappings differ from the review"
        )


def _submit_exact_sn39_extrinsic(
    preflight: ChainPreflight,
    *,
    runtime_contract: Any,
    attempt_id: str,
    netuid: int,
    version_key: int,
    wire_uids: list[int],
    wire_weights: list[int],
    mortal_period_blocks: int,
    allow_reviewed_uid30_finalized_descendant: bool = False,
) -> Any:
    """Sign one pinned-era SN39 call and journal its hash before broadcast.

    The generic SDK weight helper chooses its mortal-era reference block inside
    the signing call. That head can be later than the finalized block whose UID
    mappings and evidence window were authorized. SN39 therefore composes the
    same pallet call directly, pins the era to the proven finalized block, and
    fsyncs the exact signed hash and nonce before submitting it. A restart can
    identify this transaction cryptographically and never has to infer it from
    an otherwise identical call.
    """
    from bittensor.core.extrinsics.pallets import SubtensorModule
    from bittensor.core.types import ExtrinsicResponse

    if (
        preflight.block is None
        or preflight.block <= 0
        or netuid != 39
        or mortal_period_blocks != SN39_MORTAL_PERIOD_BLOCKS
        or len(wire_uids) != len(wire_weights)
        or not wire_uids
    ):
        raise wire.VectorError("SN39 exact signing contract is malformed")
    substrate = getattr(preflight.subtensor, "substrate", None)
    if substrate is None:
        raise wire.VectorError("SN39 exact signing has no substrate interface")
    latest_finalized_block, latest_finalized_hash = _finalized_chain_head(
        preflight.subtensor
    )
    exact_finalized_head = bool(
        latest_finalized_block == preflight.block
        and latest_finalized_hash == str(preflight.finalized_hash).lower()
    )
    if not exact_finalized_head:
        if allow_reviewed_uid30_finalized_descendant is not True:
            raise _RetryablePreSignHeadDrift(
                "SN39 finalized head advanced after preflight; refusing before signing"
            )
        _require_reviewed_uid30_finalized_descendant(
            preflight,
            runtime_contract=runtime_contract,
            attempt_id=attempt_id,
            latest_finalized_block=latest_finalized_block,
            latest_finalized_hash=latest_finalized_hash,
            wire_uids=wire_uids,
            wire_weights=wire_weights,
            version_key=version_key,
            mortal_period_blocks=mortal_period_blocks,
        )
    reviewed_marker = any(
        isinstance(getattr(runtime_contract, name, None), str)
        for name in (
            "_uid30_reviewed_preview_sha256",
            "_uid30_two_miner_successor_preview_sha256",
        )
    )
    # Real validator runtimes always carry enough identity to locate the
    # canonical journal. Inspect those even if mutable preview attributes were
    # stripped after reservation. Minimal generic signer test doubles carry
    # neither a reviewed marker nor a journal identity and preserve the legacy
    # no-journal contract.
    journal_identity_available = all(
        getattr(runtime_contract, name, None) is not None
        for name in (
            "network",
            "netuid",
            "_submission_validator_hotkey",
            "_submission_genesis_hash",
        )
    )
    reviewed_uid30 = (
        _pending_reviewed_uid30_contract(
            runtime_contract,
            attempt_id=attempt_id,
        )
        if reviewed_marker or journal_identity_available
        else None
    )
    if reviewed_uid30 is not None:
        _authorize_reviewed_uid30_submission(
            runtime_contract,
            preflight=preflight,
            attempt_id=attempt_id,
            version_key=version_key,
            wire_uids=wire_uids,
            wire_weights=wire_weights,
        )
    nonce = substrate.get_account_next_index(preflight.wallet.hotkey.ss58_address)
    if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
        raise wire.VectorError("SN39 validator nonce is malformed")
    # A relay has no recurring-write authorization and therefore no signed
    # nonce window to check. The launch runtime and any runtime that owes SN39
    # a launch still must present one before the account nonce is used.
    if (
        not bool(
            getattr(runtime_contract, "require_full_provenance_for_broadcast", False)
        )
        and _continuous_transition_required(runtime_contract)
        and not (
            reviewed_uid30 is not None
            and reviewed_uid30[2]["kind"] == "two_miner_successor"
        )
    ):
        authorization = getattr(
            runtime_contract,
            "_continuous_submission_authorization",
            None,
        )
        if not isinstance(authorization, ContinuousAuthorization):
            raise wire.VectorError(
                "SN39 recurring submission has no signed nonce allowance"
            )
        try:
            from scaffold import sn39_continuous_authorization as recurring

            recurring.assert_nonce_ready(
                authorization,
                account_nonce=nonce,
            )
        except Exception as exc:
            raise wire.VectorError(
                "SN39 validator account nonce is outside the signed recurring-write "
                "allowance"
            ) from exc
    unlocked = ExtrinsicResponse.unlock_wallet(
        preflight.wallet,
        True,
        "hotkey",
    )
    if getattr(unlocked, "success", None) is not True:
        raise wire.VectorError("SN39 validator hotkey could not be unlocked")
    call = SubtensorModule(preflight.subtensor).set_mechanism_weights(
        netuid=netuid,
        mecid=0,
        dests=wire_uids,
        weights=wire_weights,
        version_key=version_key,
    )
    era = {
        "period": mortal_period_blocks,
        "current": preflight.block,
    }
    signed = substrate.create_signed_extrinsic(
        call=call,
        keypair=preflight.wallet.hotkey,
        nonce=nonce,
        era=era,
    )
    try:
        extrinsic_hash = f"0x{signed.extrinsic_hash.hex()}".lower()
    except (AttributeError, TypeError, ValueError) as exc:
        raise wire.VectorError("SN39 signed extrinsic has no canonical hash") from exc
    if _CHAIN_HASH_RE.fullmatch(extrinsic_hash) is None:
        raise wire.VectorError("SN39 signed extrinsic hash is malformed")
    _record_pending_broadcast_intent(
        runtime_contract,
        attempt_id=attempt_id,
        extrinsic_hash=extrinsic_hash,
        nonce=nonce,
        era_reference_block=preflight.block,
        mortal_period_blocks=mortal_period_blocks,
        version_key=version_key,
        wire_uids=wire_uids,
        wire_weights=wire_weights,
    )
    receipt = substrate.submit_extrinsic(
        signed,
        wait_for_inclusion=True,
        wait_for_finalization=True,
    )
    returned_hash = str(getattr(receipt, "extrinsic_hash", "")).lower()
    if returned_hash != extrinsic_hash:
        if _CHAIN_HASH_RE.fullmatch(returned_hash) is not None:
            raise _PostSignedSubmissionMismatch(
                "SN39 submission receipt differs from its pre-journaled signed hash"
            )
        raise _PendingReceiptNotProven(
            "SN39 submit returned no canonical receipt hash; the exact signed "
            "attempt remains fenced for restart-only proof"
        )
    receipt_success = getattr(receipt, "is_success", None)
    if receipt_success is False:
        raise _PostSignedSubmissionMismatch(
            "SN39 signed transaction finalized without successful execution"
        )
    if receipt_success is not True:
        raise _PendingReceiptNotProven(
            "SN39 submit returned no provable execution result; the exact signed "
            "attempt remains fenced for restart-only proof"
        )
    return receipt


def _mark_tick_reached_chain_call(runtime_contract: Any) -> None:
    """Record, for failure reporting only, that this tick entered the call.

    ``primary_call_started`` is local to one submission and is gone by the
    time the loop reports a failed tick, yet it is exactly the fact the report
    needs: after this point a write may have finalized, and before it nothing
    was signed. Publishing it on the runtime contract — the same object the
    loop already holds — keeps the two in agreement without giving the loop a
    second, weaker notion of "reached the chain".

    Nothing branches on this flag. It is set beside ``primary_call_started``
    and reset at the top of every tick attempt.
    """
    if runtime_contract is None:
        return
    try:
        runtime_contract._tick_chain_call_started = True
    except (AttributeError, TypeError):  # pragma: no cover - immutable namespace
        pass


def set_weights_on_chain(
    uid_weights: dict[int, float],
    *,
    network: str,
    netuid: int,
    wallet_name: str,
    wallet_hotkey: str,
    broadcast: bool,
    preflight: ChainPreflight | None = None,
    uid_hotkeys: dict[int, str] | None = None,
    inclusion_policy: InclusionPolicy | None = None,
    runtime_contract: Any | None = None,
    deadline_secs: float = CHAIN_OPERATION_DEADLINE_SECS,
) -> ChainSubmission:
    _validate_emission_vector(uid_weights)
    ordered = sorted(uid_weights.items())
    preview = ",".join(f"{u}={w:.4f}" for u, w in ordered[:12]) + (
        " ..." if len(ordered) > 12 else ""
    )
    uids = [u for u, _ in ordered]
    vals = [w for _, w in ordered]
    primary_call_started = False
    attempt_id: str | None = None
    try:
        wire_uids, wire_values = _wire_weights(uids, vals)
        if not broadcast and preflight is None:
            _lifecycle(
                "WEIGHTS dry-run",
                f"uids={len(ordered)} wire_uids={wire_uids} "
                f"wire_weights={wire_values} vector={preview}",
            )
            return ChainSubmission(success=True)
        if preflight is None:
            preflight = chain_preflight(
                network=network,
                netuid=netuid,
                wallet_name=wallet_name,
                wallet_hotkey=wallet_hotkey,
                deadline_secs=deadline_secs,
            )
        if broadcast and netuid == 39:
            _authorize_sn39_chain_submission(
                runtime_contract,
                uid_weights=uid_weights,
                uid_hotkeys=uid_hotkeys,
                network=network,
                netuid=netuid,
                wallet_name=wallet_name,
                wallet_hotkey=wallet_hotkey,
                preflight=preflight,
                inclusion_policy=inclusion_policy,
            )
        _validate_chain_constraints(uid_weights, preflight)
        mortal_period = (
            inclusion_policy.mortal_period_blocks
            if broadcast and netuid == 39 and inclusion_policy is not None
            else 128
        )
        if not broadcast:
            _lifecycle(
                "WEIGHTS dry-run",
                f"uids={len(ordered)} wire_uids={wire_uids} "
                f"wire_weights={wire_values} vector={preview}",
            )
            return ChainSubmission(success=True)
        with _chain_operation_deadline("weight submission", deadline_secs):
            if netuid == 39:
                state = (
                    _read_state(_submission_state_path(runtime_contract))
                    if runtime_contract is not None
                    else {}
                )
                attempt_id = state.get("submission_pending_id")
                if (
                    runtime_contract is None
                    or not isinstance(attempt_id, str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", attempt_id) is None
                ):
                    raise wire.VectorError(
                        "SN39 authorized call has no durable pending attempt"
                    )
                primary_call_started = True
                _mark_tick_reached_chain_call(runtime_contract)
                receipt = _submit_exact_sn39_extrinsic(
                    preflight,
                    runtime_contract=runtime_contract,
                    attempt_id=attempt_id,
                    netuid=netuid,
                    version_key=_weight_version_key(),
                    wire_uids=wire_uids,
                    wire_weights=wire_values,
                    mortal_period_blocks=mortal_period,
                )
                resp = receipt
                ok = True
            else:
                # Non-SN39 callers retain the standard SDK helper. The exact
                # signer/journal path above is the sole SN39 write primitive.
                from bittensor.core.extrinsics.weights import set_weights_extrinsic
                from bittensor.core.settings import version_as_int

                primary_call_started = True
                _mark_tick_reached_chain_call(runtime_contract)
                resp = set_weights_extrinsic(
                    subtensor=preflight.subtensor,
                    wallet=preflight.wallet,
                    netuid=netuid,
                    mechid=0,
                    uids=uids,
                    weights=vals,
                    version_key=version_as_int,
                    mev_protection=False,
                    period=mortal_period,
                    raise_error=True,
                    wait_for_inclusion=True,
                    wait_for_finalization=True,
                    wait_for_revealed_execution=False,
                )
                receipt = getattr(resp, "extrinsic_receipt", None)
                ok = bool(getattr(resp, "success", resp))
            # Some SDK receipt properties are lazy. Materialize every field
            # while the same wall-clock bound is still active.
            response_values: dict[str, Any] = {}
            for name in ("extrinsic_hash", "block_hash", "block_number"):
                value = getattr(receipt, name, None) or getattr(resp, name, None)
                if value is not None:
                    response_values[name] = value
            receipt_block_hash_value = response_values.get("block_hash")
            if receipt_block_hash_value is not None:
                response_values["block_hash"] = str(receipt_block_hash_value).lower()
            block_number = response_values.get("block_number")
            try:
                receipt_block_number = (
                    int(block_number) if block_number is not None else None
                )
            except (TypeError, ValueError):
                receipt_block_number = None
            receipt_block_hash = response_values.get("block_hash")
            if (
                ok
                and receipt_block_number is None
                and isinstance(receipt_block_hash, str)
            ):
                receipt_block_number = _canonical_receipt_block_number(
                    preflight.subtensor,
                    receipt_block_hash,
                )
                response_values["block_number"] = receipt_block_number
            receipt_extrinsic_hash = response_values.get("extrinsic_hash")
            finalized = False
            if ok:
                if (
                    receipt_block_number is None
                    or receipt_block_number <= 0
                    or not isinstance(receipt_block_hash, str)
                    or not isinstance(receipt_extrinsic_hash, str)
                ):
                    raise wire.VectorError(
                        "submission returned success without a canonical receipt "
                        "identity; the durable attempt remains fenced"
                    )
                candidate = ChainSubmission(
                    success=True,
                    extrinsic_hash=receipt_extrinsic_hash,
                    block_hash=receipt_block_hash,
                    block_number=receipt_block_number,
                    finalized=False,
                )
                if netuid == 39:
                    if (
                        runtime_contract is None
                        or not isinstance(attempt_id, str)
                        or re.fullmatch(r"sha256:[0-9a-f]{64}", attempt_id) is None
                    ):
                        raise wire.VectorError(
                            "SN39 successful call has no durable pending attempt"
                        )
                    _record_pending_submission_receipt(
                        runtime_contract,
                        attempt_id=attempt_id,
                        submission=candidate,
                        version_key=_weight_version_key(),
                        wire_uids=wire_uids,
                        wire_weights=wire_values,
                    )
                proof_reason: list[str] = []
                # Await finality rather than exiting so a restart can wait for
                # it: same verdicts, one fewer restart per write.
                proof_status = _classify_finalized_receipt_awaiting_finality(
                    preflight.subtensor,
                    receipt=receipt,
                    extrinsic_hash=receipt_extrinsic_hash,
                    block_hash=receipt_block_hash,
                    block_number=receipt_block_number,
                    validator_hotkey=preflight.validator_hotkey,
                    netuid=netuid,
                    version_key=_weight_version_key(),
                    wire_uids=wire_uids,
                    wire_weights=wire_values,
                    uid_hotkeys=uid_hotkeys,
                    expected_subnet_owner_hotkey=(
                        SN39_BURN_HOTKEY if netuid == 39 else None
                    ),
                    inclusion_policy=inclusion_policy,
                    reason_out=proof_reason,
                )
                if netuid == 39 and isinstance(attempt_id, str):
                    _record_pending_proof_status(
                        runtime_contract,
                        attempt_id=attempt_id,
                        status=proof_status,
                    )
                finalized = proof_status == PASS
                if proof_status == NOT_PROVEN:
                    # This is the line the live unit prints every time its
                    # cadence slips. Without the cause it says only that
                    # something was unavailable; with it, the failing call is
                    # named, which is the whole point of the fence being
                    # temporary rather than terminal.
                    raise _PendingReceiptNotProven(
                        "submission receipt was recorded, but archive/RPC proof is "
                        "temporarily unavailable; restart may only re-prove this "
                        "exact receipt and must not submit again"
                        + _receipt_reason_suffix(proof_reason)
                    )
                if proof_status == FAIL:
                    raise _PostSignedSubmissionMismatch(
                        "submission receipt positively mismatches the reserved "
                        "inclusion contract; the attempt remains fenced for "
                        "operator investigation" + _receipt_reason_suffix(proof_reason)
                    )
    except Exception as exc:
        unsigned_aborted = False
        if (
            netuid == 39
            and runtime_contract is not None
            and isinstance(attempt_id, str)
        ):
            try:
                unsigned_aborted = _abort_unsigned_common_submission(
                    runtime_contract,
                    attempt_id=attempt_id,
                )
            except (OSError, ValueError):
                # Never claim a safe retry unless the fsynced common journal
                # itself confirmed that no signed intent or receipt existed.
                unsigned_aborted = False
        event = (
            "CHAIN failed"
            if unsigned_aborted or not primary_call_started
            else "CHAIN ambiguous"
        )
        _lifecycle(event, f"uids={len(ordered)} reason={type(exc).__name__}")
        if (
            event == "CHAIN ambiguous"
            and netuid == 39
            and runtime_contract is not None
            and not isinstance(
                exc,
                (_PendingReceiptNotProven, _PostSignedSubmissionMismatch),
            )
        ):
            raise _PendingReceiptNotProven(
                "the exact signed transaction may have finalized, but its submit "
                "response or durable receipt could not be proven; restart may only "
                "reconcile this signed hash and must not submit again"
            ) from exc
        raise
    # newer bittensor returns an ExtrinsicResponse object (truthy even on
    # failure) — judge success by the field, not truthiness.
    block_number = response_values.get("block_number")
    try:
        parsed_block_number = int(block_number) if block_number is not None else None
    except (TypeError, ValueError):
        parsed_block_number = None
    submission = ChainSubmission(
        success=ok,
        extrinsic_hash=(
            str(response_values["extrinsic_hash"])
            if response_values.get("extrinsic_hash")
            else None
        ),
        block_hash=(
            str(response_values["block_hash"])
            if response_values.get("block_hash")
            else None
        ),
        block_number=parsed_block_number,
        finalized=finalized,
    )
    if ok:
        try:
            submission = _require_release_grade_submission(submission)
        except wire.VectorError as exc:
            _lifecycle(
                "CHAIN ambiguous",
                f"uids={len(ordered)} success=True receipt_identity=incomplete",
            )
            if netuid == 39:
                raise _PendingReceiptNotProven(
                    "the successful SN39 response has no complete canonical receipt "
                    "identity; the exact signed attempt remains fenced"
                ) from exc
            raise
    response_details = (
        [
            f"extrinsic_hash={submission.extrinsic_hash}",
            f"block_hash={submission.block_hash}",
            f"block_number={submission.block_number}",
            "finalized=true",
        ]
        if ok
        else []
    )
    _lifecycle(
        "CHAIN submitted" if ok else "CHAIN failed",
        " ".join([f"uids={len(ordered)}", f"success={ok}", *response_details]),
    )
    return submission


_CHAIN_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


def _require_release_grade_submission(submission: Any) -> ChainSubmission:
    """Require an exact finalized transaction identity after a successful call.

    If the SDK says success but omits identity, the call is operationally
    ambiguous: keep the pre-submit pending fence and require reconciliation
    rather than recording an unverifiable launch transaction.
    """
    if not bool(submission):
        raise wire.VectorError("chain submission did not succeed")
    extrinsic_hash = getattr(submission, "extrinsic_hash", None)
    block_hash = getattr(submission, "block_hash", None)
    block_number = getattr(submission, "block_number", None)
    finalized = getattr(submission, "finalized", None)
    if (
        not isinstance(extrinsic_hash, str)
        or _CHAIN_HASH_RE.fullmatch(extrinsic_hash) is None
        or not isinstance(block_hash, str)
        or _CHAIN_HASH_RE.fullmatch(block_hash) is None
        or isinstance(block_number, bool)
        or not isinstance(block_number, int)
        or block_number <= 0
        or finalized is not True
    ):
        raise wire.VectorError(
            "chain reported success without a release-grade extrinsic hash, "
            "block hash, positive block number, and canonical finalized-head "
            "proof; submission is ambiguous "
            "and must be reconciled before another write"
        )
    return ChainSubmission(
        success=True,
        extrinsic_hash=extrinsic_hash.lower(),
        block_hash=block_hash.lower(),
        block_number=block_number,
        finalized=True,
    )


def _finalized_block(raw) -> int | None:
    """Strictly coerce a metagraph-reported block number.

    Only a positive integral number is a usable finalized block: booleans,
    fractional floats, junk strings, and non-positive values are all None.
    The recurring shadow relay tolerates None because it never anchors a report
    validity window. A strict replay caller refuses None instead of silently
    skipping report block-validity checks."""
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, float) and not raw.is_integer():
        return None
    try:
        block = int(raw)
    except (TypeError, ValueError):
        return None
    return block if block > 0 else None


def _bt_subtensor(bt):
    """bittensor renamed `subtensor` -> `Subtensor` across major versions."""
    return getattr(bt, "subtensor", None) or bt.Subtensor


def _bt_wallet(bt):
    return getattr(bt, "wallet", None) or bt.Wallet


@contextlib.contextmanager
def _chain_connection(network: str):
    """Yield a subtensor and ALWAYS close it.

    bittensor's Subtensor opens a websocket in its constructor and does NOT
    close it when the object is garbage collected — the live connection is
    owned by a background thread that keeps the instance reachable. Every
    connection built and dropped therefore strands a socket and a file
    descriptor for the remaining life of the process.

    The validator builds several of these per tick. Measured on SN39 mainnet
    at 4 stranded descriptors per 25-minute tick (~10/hour), which walks a
    long-running validator into its RLIMIT_NOFILE ceiling (1024 by default)
    in about three days. Past that it cannot open a socket at all, so it
    stops reaching the chain and silently stops writing weights.

    This first surfaced as `HTTP 429` from the shared finney entrypoint,
    because the stranded connections tripped that endpoint's per-IP
    connection cap long before the fd ceiling. Moving to a dedicated RPC
    removes the 429 but not the leak; it only changes which ceiling is hit.

    Close deterministically rather than trusting refcounting.
    """
    with _isolated_argv():
        import bittensor as bt  # import under blanked argv — bittensor parses

        subtensor = _bt_subtensor(bt)(network=connection_target(network))
    try:
        yield subtensor
    finally:
        # A failed close must never fail the tick: the caller's work is already
        # done, and a raise here would mask the real result.
        with contextlib.suppress(Exception):
            subtensor.close()


def _block_hash_lookup(network: str):
    """A callable resolving a historical block number to its hash via the
    validator's own subtensor connection (independent of Cathedral)."""

    def lookup(block: int):
        try:
            with _chain_connection(network) as subtensor:
                return subtensor.get_block_hash(block)
        except Exception:  # noqa: BLE001 - unavailable lookup is None, not a pass
            return None

    return lookup


def _validated_historical_hotkeys(raw_hotkeys, *, metagraph_block, requested_block):
    """Validate the RAW historical hotkey sequence BEFORE any set
    construction: sequence type, per-hotkey validity, exact count with
    uniqueness (a set would silently swallow duplicates), and the returned
    metagraph's block equal to the REQUESTED block. Any violation returns
    None — malformed or misaligned history is unavailable history."""
    if isinstance(metagraph_block, bool):
        return None
    try:
        if int(metagraph_block) != int(requested_block):
            return None
    except (TypeError, ValueError):
        return None
    if not isinstance(raw_hotkeys, (list, tuple)) or not raw_hotkeys:
        return None
    for hotkey in raw_hotkeys:
        if not isinstance(hotkey, str) or not 1 <= len(hotkey.encode("utf-8")) <= 512:
            return None
    if len(set(raw_hotkeys)) != len(raw_hotkeys):
        return None
    return frozenset(raw_hotkeys)


def _historical_metagraph_lookup(network: str, netuid: int):
    """A callable resolving the SN39 metagraph AT a historical block to its
    exact hotkey set via the validator's own subtensor connection
    (Subtensor.metagraph(netuid, block=block)). Returns None when the
    history is unavailable, malformed, or not actually at the requested
    block — the audit treats that as NOT_PROVEN, never a pass."""

    def lookup(block: int):
        try:
            with _chain_connection(network) as subtensor:
                mg = subtensor.metagraph(netuid, block=int(block))
                # Read the snapshot before the connection closes.
                raw_hotkeys = list(getattr(mg, "hotkeys", None) or ())
                metagraph_block = getattr(mg, "block", None)
            return _validated_historical_hotkeys(
                raw_hotkeys,
                metagraph_block=metagraph_block,
                requested_block=block,
            )
        except Exception:  # noqa: BLE001 - unavailable history is None, not a pass
            return None

    return lookup


def _metagraph_snapshot(
    *, network: str, netuid: int
) -> tuple[dict[str, int], int | None]:
    """Read the UID map at the node's exact canonical finalized head."""
    with _chain_connection(network) as subtensor:
        finalized_block, _finalized_hash = _finalized_chain_head(subtensor)
        mg = subtensor.metagraph(netuid, block=finalized_block)
        commit_reveal_enabled = _strict_commit_reveal_state(
            subtensor.commit_reveal_enabled(netuid=netuid, block=finalized_block)
        )
        # Materialise every read off the snapshot before the connection closes.
        mg_block = getattr(mg, "block", None)
        mapping = {hk: int(uid) for uid, hk in zip(mg.uids.tolist(), mg.hotkeys)}
    if commit_reveal_enabled:
        raise wire.VectorError(
            "SN39 release health requires commit-reveal disabled at the "
            "finalized snapshot"
        )
    if _finalized_block(mg_block) != finalized_block:
        raise wire.VectorError("metagraph snapshot did not resolve at finalized head")
    return mapping, finalized_block


def metagraph_hotkey_to_uid(*, network: str, netuid: int) -> dict[str, int]:
    with _chain_connection(network) as subtensor:
        mg = subtensor.metagraph(netuid)
        return {hk: int(uid) for uid, hk in zip(mg.uids.tolist(), mg.hotkeys)}


# -- main loop --------------------------------------------------------------------


def tick(args) -> bool:
    provenance_mode_early = getattr(args, "provenance", "shadow") or "shadow"
    if provenance_mode_early != "shadow":
        raise wire.VectorError(
            "recurring validator ticks support only the shadow relay runtime; "
            f"got provenance={provenance_mode_early!r}"
        )
    _lifecycle("FEED fetch", f"source={_feed_label(args.publisher_url)}")
    _prepare_tick_preflight(args)
    with _thin_tick_lock(args):
        args._continuous_submission_authorization = None
        if (
            bool(getattr(args, "broadcast", False))
            and _continuous_transition_required(args)
            and not bool(getattr(args, "require_full_provenance_for_broadcast", False))
        ):
            args._continuous_submission_authorization = (
                _require_continuous_launch_transition(args)
            )
            # The public seal can require archive/network work. Refresh every
            # mutable chain fact after it, while still holding the shared lock.
            _prepare_tick_preflight(args)
        # A missing or invalid signed feed leaves a relay with no vector to
        # submit. Propagate the classified failure so the run loop records the
        # refusal and retries on its normal cadence. Never change submission
        # authority at tick time.
        return _thin_tick_locked(args)


class _FeedUnavailableForThin(wire.VectorError):
    """The signed vector could not be fetched, so thin has nothing to follow."""


def _thin_tick_locked(args) -> bool:
    """Default thin/shadow tick under one cross-process submission lock."""
    try:
        payload = fetch_vector(args.publisher_url)
    except Exception as exc:  # noqa: BLE001 - classified, then handled by tick()
        raise _FeedUnavailableForThin(
            f"signed vector unavailable: {type(exc).__name__}"
        ) from exc
    _lifecycle(
        "FEED fetched",
        f"id={str(payload.get('vector_id', ''))[:8]} "
        f"policy_version={payload.get('policy_version')}",
    )
    state_path = Path(args.state_file)
    prior_state = _read_state(state_path)
    recovered_version = prior_state.get("thin_recovered_policy_version")
    if (
        isinstance(recovered_version, int)
        and not isinstance(recovered_version, bool)
        and payload.get("policy_version") == recovered_version
    ):
        observed_digest = _sha256_document(payload)
        if payload.get("vector_id") == prior_state.get(
            "thin_recovered_vector_id"
        ) and observed_digest == prior_state.get("thin_recovered_signed_vector_sha256"):
            wire.verify_signature(
                payload,
                public_key_hex=args.public_key_hex,
                expected_key_id=args.key_id,
            )
            _lifecycle(
                "VECTOR idle",
                f"id={str(payload.get('vector_id', ''))[:8]} "
                f"policy_version={recovered_version} already_finalized=true",
            )
            _get_events(args).event(
                "RECOVERED_VECTOR_IDLE",
                stage="result",
                status=INFO,
                artifact=str(payload.get("vector_id", ""))[:36] or None,
                detail=(
                    "exact recovered policy/vector is already finalized; "
                    "no second chain write was attempted"
                ),
            )
            return True
    fence = load_fence(Path(args.state_file))
    try:
        accept_vector(
            payload,
            public_key_hex=args.public_key_hex,
            key_id=args.key_id,
            network=args.network,
            netuid=args.netuid,
            fence_version=fence,
        )
    except Exception as e:
        _lifecycle("VERIFY failed", f"reason={type(e).__name__}")
        _lifecycle("VECTOR rejected", f"stage=accept reason={type(e).__name__}")
        raise
    _lifecycle("SIGNATURE valid", f"key_id={payload.get('key_id')}")
    _lifecycle(
        "FRESHNESS valid",
        f"network={payload.get('network')} netuid={payload.get('netuid')} "
        f"generated_at={payload.get('generated_at')} expires_at={payload.get('expires_at')}",
    )
    _lifecycle(
        "ROLLBACK valid",
        f"policy_version={payload.get('policy_version')} prior_fence={fence}",
    )
    _lifecycle(
        "VECTOR accepted",
        f"id={str(payload.get('vector_id', ''))[:8]} "
        f"policy_version={payload['policy_version']} "
        f"miners={len(payload['weights'])} "
        f"burn={payload['burn_snapshot']['forced_burn_percentage']}%",
    )
    _get_events(args).event(
        "VECTOR_ACCEPTED",
        stage="verify",
        status=PASS,
        artifact=str(payload.get("vector_id", ""))[:36] or None,
        detail=(
            f"policy_version={payload['policy_version']} "
            f"miners={len(payload['weights'])} "
            f"burn={payload['burn_snapshot']['forced_burn_percentage']}% "
            f"signature+freshness+rollback ok"
        ),
    )
    # offline is authoritative: no chain read AND no broadcast, even if
    # --broadcast was also passed (the two are contradictory; offline wins).
    preflight = None
    tick_block = None
    if args.offline:
        hk2uid = {w["miner_hotkey"]: i for i, w in enumerate(payload["weights"])}
        burn_hotkey = (payload.get("burn_snapshot") or {}).get("burn_hotkey")
        if burn_hotkey is not None and burn_hotkey not in hk2uid:
            hk2uid[burn_hotkey] = len(hk2uid)
        _lifecycle("MAP offline", "synthetic uid map, no chain access")
        broadcast = False
    else:
        broadcast = args.broadcast
        preflight = getattr(args, "_tick_preflight", None)
        if preflight is None:
            preflight = chain_preflight(
                network=args.network,
                netuid=args.netuid,
                wallet_name=args.wallet_name,
                wallet_hotkey=args.wallet_hotkey,
            )
            _bind_submission_identity(args, preflight)
        hk2uid = preflight.hotkey_to_uid
        tick_block = preflight.block
    try:
        uid_weights = vector_to_uid_weights(
            payload, hk2uid, require_policy=getattr(args, "require_policy", None)
        )
    except Exception as e:
        _lifecycle("VECTOR rejected", f"stage=map reason={type(e).__name__}")
        _get_events(args).event(
            "VECTOR_REJECTED",
            stage="map",
            status=FAIL,
            detail=f"reason={type(e).__name__}",
            remediation="The signed vector failed UID mapping; nothing was submitted.",
        )
        raise

    # Provenance work is either the bounded launch-only strict replay gate or a
    # nonblocking recurring shadow audit. It never changes the recurring writer.
    provenance_mode = getattr(args, "provenance", "shadow") or "shadow"
    submission_authority = "thin"
    launch_rewarded_set_gate = bool(
        getattr(args, "require_full_provenance_for_broadcast", False)
    )
    if launch_rewarded_set_gate:
        if args.offline or not broadcast or tick_block is None:
            raise wire.VectorError(
                "launch rewarded-set gate requires an online broadcast with a "
                "finalized block"
            )
        launch_audit = _run_launch_rewarded_set_gate(
            args,
            payload=payload,
            uid_weights=uid_weights,
            hotkey_to_uid=hk2uid,
            current_block=tick_block,
            state_file=Path(args.state_file),
            persist=False,
        )
        preflight, hk2uid, uid_weights = _revalidate_launch_after_rewarded_set_replay(
            args,
            payload=payload,
            audit=launch_audit,
            fence_version=fence,
        )
        _require_launch_approval(
            args,
            payload=payload,
            audit=launch_audit,
            preflight=preflight,
            uid_weights=uid_weights,
            hotkey_to_uid=hk2uid,
        )
        args._tick_preflight = preflight
        tick_block = preflight.block
    elif provenance_mode == "shadow":
        # ONE metagraph snapshot supplies the UID map and the current
        # block; candidate membership is proven against the HISTORICAL
        # metagraph at the manifest's anchored block, via the validator's
        # own chain connection.
        _run_provenance_stage(
            args,
            payload,
            Path(args.state_file),
            current_block=None if args.offline else tick_block,
            historical_hotkeys_lookup=(
                None
                if args.offline
                else _historical_metagraph_lookup(args.network, args.netuid)
            ),
            block_hash_lookup=(
                None if args.offline else _block_hash_lookup(args.network)
            ),
        )

    ordered = sorted(uid_weights.items())
    preview = ",".join(f"{uid}:{weight:.6f}" for uid, weight in ordered[:12])
    if len(ordered) > 12:
        preview += ",..."
    burn_hotkey = (payload.get("burn_snapshot") or {}).get("burn_hotkey")
    burn_uid = (
        hk2uid.get(burn_hotkey)
        if burn_hotkey is not None
        else (payload.get("burn_snapshot") or {}).get("burn_uid")
    )
    if preflight is not None:
        _require_no_validator_compute_reward(
            uid_weights,
            preflight=preflight,
            burn_uid=int(burn_uid) if burn_uid is not None else None,
        )
    # The bounded launch path refuses a burn destination that is not the
    # operator-pinned hotkey (see _revalidate_launch_after_rewarded_set_replay).
    # The thin tick had no equivalent, so
    # the recurring writer took the destination from the signed vector alone.
    # The pin is already in process and _validate_resolved_chain_contract has
    # already proven it is the live subnet owner, so anchoring the feed's
    # destination to it costs nothing and removes a signed vector's ability to
    # redirect the burn share on its own authority.
    pinned_burn_hotkey = getattr(args, "provenance_burn_hotkey", None)
    if (
        isinstance(pinned_burn_hotkey, str)
        and pinned_burn_hotkey
        and burn_hotkey is not None
        and burn_hotkey != pinned_burn_hotkey
    ):
        raise wire.VectorError(
            "signed vector burn destination is not the pinned burn hotkey"
        )
    burn_share = uid_weights.get(int(burn_uid), 0.0) if burn_uid is not None else 0.0
    _lifecycle(
        "MAP complete",
        f"uids={len(uid_weights)} burn_uid={burn_uid} burn_share={burn_share:.6f} "
        f"vector={preview}",
    )
    signed_vector_sha256 = _sha256_document(payload)
    if args.offline:
        wire_uids = wire_values = None
    else:
        wire_uids, wire_values = _wire_weights(
            [uid for uid, _weight in ordered],
            [weight for _uid, weight in ordered],
        )
    state_file = Path(args.state_file)
    thin_attempt_id: str | None = None
    inclusion_policy: InclusionPolicy | None = None
    if broadcast:
        # Everything above this line has already run: the vector is verified,
        # mapped, and audited. Only the write is skipped, so a cooldown tick
        # still contributes its full verification and shadow-audit evidence.
        # The one-shot launch ceremony keeps failing loudly instead: it is
        # operator-supervised, and `_launch_inclusion_policy` was already
        # proven against the cooldown upstream.
        if getattr(args, "_launch_inclusion_policy", None) is None:
            _require_chain_weight_write_permitted(args, preflight)
        inclusion_policy = getattr(args, "_launch_inclusion_policy", None)
        if inclusion_policy is None:
            inclusion_policy = _vector_inclusion_policy(payload, preflight)
        uid_safety = _require_uid_mapping_stability(
            preflight,
            {uid: hotkey for hotkey, uid in hk2uid.items() if uid in uid_weights},
            mortal_period_blocks=inclusion_policy.mortal_period_blocks,
        )
        uid_weights = _drop_unprovable_targets(
            args, uid_weights, uid_safety, hk2uid, burn_uid
        )
        # Recompute the derived views: `ordered` and the wire vectors were
        # built from the pre-exclusion weights, so a reservation minted from
        # them would describe a different allocation than the one signed.
        ordered = sorted(uid_weights.items())
        if not args.offline:
            wire_uids, wire_values = _wire_weights(
                [uid for uid, _weight in ordered],
                [weight for _uid, weight in ordered],
            )
        # Persist an ambiguity fence BEFORE the irreversible call. Mapping block
        # is retained in the exact submission record but excluded from the
        # dedup identity: advancing a block with the same signed vector and
        # resolved allocation is not new work.
        identity = {
            "network": args.network,
            "netuid": args.netuid,
            "mapping_block": tick_block,
            "validator_hotkey": preflight.validator_hotkey,
            "validator_uid": preflight.validator_uid,
            "vector_id": payload["vector_id"],
            "policy_version": int(payload["policy_version"]),
            "signed_vector_sha256": signed_vector_sha256,
            # The payload itself, not just its digest. The chain-write boundary
            # re-derives the whole policy from these bytes, so a reservation can
            # never be the sole authority for what gets written.
            "signed_vector": payload,
            "burn_hotkey": burn_hotkey,
            "uid_weights": [[uid, weight] for uid, weight in ordered],
            "uid_hotkeys": [
                [uid, hotkey]
                for hotkey, uid in sorted(hk2uid.items(), key=lambda item: item[1])
                if uid in uid_weights
            ],
            "next_epoch_start_block": (preflight.next_epoch_start_block),
            "inclusion_policy": _inclusion_policy_identity(inclusion_policy),
            "uid_safety": uid_safety,
        }
        continuous_authorization = getattr(
            args, "_continuous_submission_authorization", None
        )
        if continuous_authorization is not None:
            if not isinstance(continuous_authorization, ContinuousAuthorization):
                raise wire.VectorError(
                    "continuous authorization has an invalid runtime type"
                )
            identity["continuous_authorization"] = _continuous_authorization_identity(
                continuous_authorization
            )
        launch_audit = getattr(args, "_launch_rewarded_set_audit", None)
        if launch_audit is not None:
            freshness_boundary = _require_launch_evidence_after_rotations(
                payload=payload,
                audit=launch_audit,
                uid_safety=uid_safety,
            )
            identity["full_provenance"] = {
                "source_epoch": launch_audit.source_epoch,
                "report_id": launch_audit.report_id,
                "manifest": launch_audit.manifest_digest,
                "policy_release": launch_audit.policy_release,
                "policy_digest": launch_audit.policy_digest,
                "mechanism": launch_audit.mechanism,
                # Scope names the claim actually made: the rewarded set was
                # proven; nothing here asserts the whole epoch. The assurance
                # field carries the exact audited level alongside it.
                "scope": "rewarded_set_proven",
                "whole_epoch_assurance": launch_audit.assurance,
                "vector_agrees": launch_audit.agrees_with_vector,
                "rewarded_hotkeys": sorted(launch_audit.recomputed),
                "raw_replayed_hotkeys": sorted(launch_audit.raw_replayed_hotkeys),
                "verifier_digest": getattr(args, "provenance_verifier_digest", None),
                "verifier_binary_digest": launch_audit.verifier_binary_digest,
                "report_signing_key_id": launch_audit.report_signing_key_id,
                "signed_index": launch_audit.signed_index,
                "source_revision": getattr(args, "provenance_source_revision", None),
                "freshness_boundary": freshness_boundary,
            }
            launch_approval = getattr(args, "_launch_approval", None)
            if not isinstance(launch_approval, dict):
                raise wire.VectorError(
                    "launch reservation has no consumed operator approval"
                )
            identity["launch_approval"] = {
                "approval_digest": launch_approval.get("approval_digest"),
                "reviewed_finalized_block": launch_approval.get(
                    "reviewed_finalized_block"
                ),
                "reviewed_finalized_hash": launch_approval.get(
                    "reviewed_finalized_hash"
                ),
                "approval_valid_until_block": launch_approval.get(
                    "approval_valid_until_block"
                ),
            }
        dedup_identity = {
            key: value
            for key, value in identity.items()
            if key not in {"mapping_block", "uid_safety"}
        }
        thin_attempt_id = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    dedup_identity,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
        )
        try:
            _reserve_common_submission(
                args,
                lane="thin",
                attempt_id=thin_attempt_id,
                identity=identity,
            )
        except (ValueError, OSError) as exc:
            raise _SubmissionFenceRefused(
                "thin submission attempt fence refused before chain write: "
                f"{stable_error(exc)}"
            ) from exc
    submission = set_weights_on_chain(
        uid_weights,
        network=args.network,
        netuid=args.netuid,
        wallet_name=args.wallet_name,
        wallet_hotkey=args.wallet_hotkey,
        broadcast=broadcast,
        preflight=preflight,
        uid_hotkeys=(
            {uid: hotkey for hotkey, uid in hk2uid.items() if uid in uid_weights}
            if not args.offline
            else None
        ),
        inclusion_policy=inclusion_policy,
        runtime_contract=args,
    )
    if broadcast:
        submission = _require_release_grade_submission(submission)
    ok = bool(submission)
    # Finalize the attempt and rollback fence in ONE atomic fsync before any
    # fallible telemetry. The common journal is the release source of truth, so
    # finalize it first. A crash before the lane-local telemetry write leaves a
    # recoverable finalized launch instead of an unrecoverable common pending
    # fence.
    if ok and broadcast:
        _finalize_common_submission(
            args,
            attempt_id=thin_attempt_id,
            submission=submission,
        )
        _write_state_fenced(
            state_file,
            {
                "highest_attempted_policy_version": int(payload["policy_version"]),
                "thin_submission_attempt_id": thin_attempt_id,
                "thin_submission_attempt_status": "finalized",
                "thin_submission_finalized_id": thin_attempt_id,
                "thin_submission_finalized_at": _ms_iso_now(),
                "thin_submission_extrinsic_hash": getattr(
                    submission, "extrinsic_hash", None
                ),
                "thin_submission_block_hash": getattr(submission, "block_hash", None),
                "thin_submission_block_number": getattr(
                    submission, "block_number", None
                ),
                "thin_submission_identity": identity,
                "thin_submission_dedup_identity": dedup_identity,
                "last_accepted_policy_version": int(payload["policy_version"]),
                "last_vector_id": payload["vector_id"],
                "accepted_at": _ms_iso_now(),
                "thin_recovered_policy_version": None,
                "thin_recovered_vector_id": None,
                "thin_recovered_signed_vector_sha256": None,
            },
        )
    _get_events(args).event(
        "WEIGHTS_SUBMITTED" if (ok and broadcast) else "WEIGHTS_DRY_RUN",
        stage="submit",
        status=PASS if ok else FAIL,
        detail=(
            f"authority={submission_authority} uids={len(ordered)} "
            f"burn_uid={burn_uid} burn_share={burn_share:.6f} vector={preview}"
        ),
        artifact=str(payload.get("vector_id", ""))[:36] or None,
        authority=submission_authority,
        # The allocation contract this result was produced under. The public
        # reproducer cross-checks it against the resolved policy pin.
        contract_version=_dry_run_contract_version(payload),
        uid_count=len(ordered),
        burn_uid=burn_uid,
        burn_share=burn_share,
        uid_weights={str(uid): weight for uid, weight in ordered},
        wire_uids=wire_uids,
        wire_weights=wire_values,
        version_key=_weight_version_key() if not args.offline else None,
        vector_id=payload.get("vector_id"),
        policy_version=payload.get("policy_version"),
        signed_vector_sha256=signed_vector_sha256,
        mapping_block=tick_block,
        validator_uid=preflight.validator_uid if preflight is not None else None,
        validator_hotkey=(
            preflight.validator_hotkey if preflight is not None else None
        ),
        extrinsic_hash=getattr(submission, "extrinsic_hash", None),
        block_hash=getattr(submission, "block_hash", None),
        block_number=getattr(submission, "block_number", None),
    )
    # Dry-run/offline passes never consume a version (with the pv<=fence rule
    # that would otherwise block the subsequent live broadcast).
    return ok


_VALIDATOR_RUNTIME_ROOT = Path("/var/lib/cathedral-validator")


def _bind_submission_identity(args: Any, preflight: ChainPreflight) -> None:
    """Bind runtime fencing to the canonical signer and chain genesis."""
    validator_hotkey = str(preflight.validator_hotkey)
    genesis_hash = str(preflight.genesis_hash).lower()
    if not validator_hotkey or _CHAIN_HASH_RE.fullmatch(genesis_hash) is None:
        raise wire.VectorError(
            "chain preflight did not establish a canonical signer/genesis identity"
        )
    existing_hotkey = getattr(args, "_submission_validator_hotkey", None)
    existing_genesis = getattr(args, "_submission_genesis_hash", None)
    if existing_hotkey is not None and existing_hotkey != validator_hotkey:
        raise wire.VectorError("validator signer changed within one tick")
    if existing_genesis is not None and existing_genesis != genesis_hash:
        raise wire.VectorError("chain genesis changed within one tick")
    args._submission_validator_hotkey = validator_hotkey
    args._submission_genesis_hash = genesis_hash


def _validate_resolved_chain_contract(
    args: Any,
    preflight: ChainPreflight,
    *,
    require_sn39_identity: bool = False,
) -> None:
    """Enforce the SN39 contract against the connected chain, not its label."""
    if (
        (not bool(getattr(args, "broadcast", False)) and not require_sn39_identity)
        or bool(getattr(args, "offline", False))
        or int(getattr(args, "netuid", -1)) != 39
    ):
        return
    genesis_hash = str(preflight.genesis_hash).lower()
    if genesis_hash != FINNEY_GENESIS_HASH:
        raise wire.VectorError(
            "SN39 broadcast is supported only on the pinned Finney genesis"
        )
    if str(getattr(args, "network", "")).strip().lower() != "finney":
        raise wire.VectorError(
            "Finney SN39 broadcast requires the `finney` signed-vector audience "
            "even when a self-hosted RPC endpoint is used"
        )
    # Same closed two-value set as the startup trust profile, re-checked here
    # against the RESOLVED chain rather than the config's label. If this stayed
    # single-equality on v1, a re-pin to v3 would clear the startup profile and
    # then die at chain preflight on every tick — a validator that starts
    # cleanly and never writes.
    if getattr(args, "require_policy", None) not in SN39_PINNED_REQUIRE_POLICIES:
        raise wire.VectorError(
            "Finney SN39 broadcast requires the validated_supply_v1 or "
            "validated_supply_v3 policy"
        )
    if preflight.min_allowed_weights != 1 or not math.isclose(
        preflight.max_weight_limit,
        1.0,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise wire.VectorError(
            "Finney SN39 broadcast requires min_allowed_weights=1 and "
            "max_weight_limit=1.0 so revocation can fail safe to burn"
        )
    if preflight.commit_reveal_enabled:
        raise wire.VectorError("Finney SN39 broadcast requires commit-reveal disabled")
    expected_burn_hotkey = getattr(args, "provenance_burn_hotkey", None)
    if (
        not isinstance(expected_burn_hotkey, str)
        or not expected_burn_hotkey
        or preflight.subnet_owner_hotkey != expected_burn_hotkey
        or preflight.hotkey_to_uid.get(expected_burn_hotkey) is None
    ):
        raise wire.VectorError(
            "Finney SN39 broadcast requires the pinned burn hotkey to remain "
            "the live subnet owner"
        )
    if _submission_runtime_root(args) != _VALIDATOR_RUNTIME_ROOT:
        raise wire.VectorError(
            "Finney SN39 broadcast requires the canonical owner-only "
            f"runtime root {_VALIDATOR_RUNTIME_ROOT}"
        )


def _prepare_tick_preflight(args: Any) -> None:
    """Resolve canonical submission identity before taking its shared lock."""
    if bool(getattr(args, "offline", False)):
        args._tick_preflight = None
        return
    preflight = chain_preflight(
        network=args.network,
        netuid=args.netuid,
        wallet_name=args.wallet_name,
        wallet_hotkey=args.wallet_hotkey,
    )
    _validate_resolved_chain_contract(args, preflight)
    _bind_submission_identity(args, preflight)
    args._tick_preflight = preflight


# How many signed attempt ids `submission_attempt_ids` retains. Read the proof
# below before changing it: a window that is too small silently reopens a retry
# window on an irreversible chain write.
#
# WHY THE JOURNAL CAN BE BOUNDED AT ALL.
# Only `_commit_pending_signed_attempt` appends here, so every entry is a
# SIGNED attempt, and every entry's id is `sha256(dedup_identity)` where the
# dedup identity carries exactly one monotone field per lane:
#
#   thin      -> identity["policy_version"] = P
#   authority (serialized launch/recovery lane)
#             -> identity["source_epoch"]   = E
#
# `_reserve_common_submission` derives the lane high-water from that SAME
# field, and both the reservation (`_write_state_fenced`) and the commit refuse
# unless it strictly exceeds the stored `submission_highest_policy_version` /
# `submission_highest_source_epoch`. The commit writes the new high-water in
# the same atomic fsync that appends the id, and nothing lowers or deletes
# either high-water: they are written only by that commit, and the two clearing
# paths (`_abort_unsigned_common_submission`,
# `_expire_pending_common_submission`) drop only `submission_pending_*` keys.
#
# So for any id already in this journal, its lane high-water is >= the monotone
# value hashed into it, and re-deriving that exact id would need a reservation
# whose P (or E) is simultaneously equal to and greater than the stored
# high-water. The membership test is a second lock on a door the monotone fence
# has already bolted; evicting an old entry cannot reopen it.
#
# WHAT ACTUALLY BOUNDS THE WINDOW is therefore not replay but the two readers
# that look an id UP rather than assert it is absent:
#
#   `_expire_pending_common_submission` needs the pending signed id, which is
#   always the entry just appended; and
#   `_recover_common_finalized_submission` needs `submission_finalized_id`,
#   which trails the tail by the signed attempts committed since the last
#   proven inclusion. Every one of those consumes a slot in
#   `submission_attempt_budgets`, and one continuous authorization is capped at
#   96 attempts (`_reserve_common_submission`,
#   `_authority_lane_transition_authorized`).
#
# 512 is more than five times that 96-attempt ceiling, so
# `submission_finalized_id` survives even if five consecutive fully spent
# authorizations expired without a single inclusion. At the live SN39 rate (77
# signed attempts in ~9 days) it is about two months of history and caps the
# field near 37 KB. Both ids that ARE looked up are pinned explicitly at the
# call site regardless of the window, so the size is a retention choice rather
# than a correctness one.
SUBMISSION_ATTEMPT_ID_WINDOW = 512


def _bounded_attempt_journal(history: list[str], pinned: tuple[Any, ...]) -> list[str]:
    """The newest `SUBMISSION_ATTEMPT_ID_WINDOW` ids, oldest first.

    Any id in `pinned` is kept even when it falls outside the window: those are
    the ids a reader resolves against this journal, and losing one turns a
    recoverable restart into a fail-closed contradiction. Order is preserved so
    the journal stays chronological.
    """
    if len(history) <= SUBMISSION_ATTEMPT_ID_WINDOW:
        return list(history)
    retained = {value for value in pinned if isinstance(value, str)}
    cut = len(history) - SUBMISSION_ATTEMPT_ID_WINDOW
    return [
        *(item for item in history[:cut] if item in retained),
        *history[cut:],
    ]


def _submission_identity_digest(args: Any) -> str:
    """Hash the canonical chain/signer identity shared by every mode."""
    try:
        netuid = int(args.netuid)
    except (AttributeError, TypeError, ValueError) as exc:
        raise wire.VectorError("submission runtime identity is invalid") from exc
    validator_hotkey = getattr(args, "_submission_validator_hotkey", None)
    genesis_hash = getattr(args, "_submission_genesis_hash", None)
    if validator_hotkey is None or genesis_hash is None:
        if not bool(getattr(args, "offline", False)):
            raise wire.VectorError(
                "canonical signer/genesis must be resolved before submission locking"
            )
        # Offline reproduction never reaches a chain call. A separate namespace
        # keeps its test lock from colliding with any live signer identity.
        identity = {
            "offline": True,
            "network": str(args.network).strip().lower(),
            "netuid": netuid,
            "wallet_name": str(getattr(args, "wallet_name", "")).strip(),
            "wallet_hotkey": str(getattr(args, "wallet_hotkey", "")).strip(),
        }
    else:
        identity = {
            "genesis_hash": str(genesis_hash).lower(),
            "netuid": netuid,
            "validator_hotkey": str(validator_hotkey),
        }
    if netuid < 0 or any(value in ("", None) for value in identity.values()):
        raise wire.VectorError("submission runtime identity is incomplete")
    if not identity.get("offline") and (
        _CHAIN_HASH_RE.fullmatch(identity["genesis_hash"]) is None
    ):
        raise wire.VectorError("submission chain genesis is malformed")
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _submission_runtime_root(args: Any) -> Path:
    configured = getattr(args, "runtime_root", None)
    root = Path(configured) if configured else _VALIDATOR_RUNTIME_ROOT
    if not root.is_absolute():
        raise wire.VectorError("submission runtime root must be an absolute path")
    return root


def _submission_lock_path(args: Any) -> Path:
    """One HOME-independent lock for this chain/wallet identity."""
    return _submission_runtime_root(args) / (
        f"submission-{_submission_identity_digest(args)}.lock"
    )


def _submission_state_path(args: Any) -> Path:
    """One cross-mode ambiguity journal, independent of lane state files."""
    return _submission_runtime_root(args) / (
        f"journal-{_submission_identity_digest(args)}.json"
    )


def _reserve_common_submission(
    args: Any,
    *,
    lane: str,
    attempt_id: str,
    identity: dict[str, Any],
) -> None:
    reviewed_uid30 = _strict_zero_burn_uid30_contract(identity, lane=lane)
    reviewed_kind = None if reviewed_uid30 is None else reviewed_uid30["kind"]
    successor = reviewed_kind == "two_miner_successor"
    lane_fence: dict[str, int]
    if lane == "thin":
        policy_version = identity.get("policy_version")
        if isinstance(policy_version, bool) or not isinstance(policy_version, int):
            raise ValueError("thin submission identity has no policy version")
        lane_fence = {"submission_highest_policy_version": policy_version}
    elif lane == "authority":
        source_epoch = identity.get("source_epoch")
        if isinstance(source_epoch, bool) or not isinstance(source_epoch, int):
            raise ValueError("full-replay launch identity has no source epoch")
        lane_fence = {"submission_highest_source_epoch": source_epoch}
    else:
        raise ValueError("submission lane must be thin or authority")
    max_submissions = int(getattr(args, "max_submissions", 0) or 0)
    if max_submissions < 0:
        raise ValueError("max submissions must be nonnegative")
    launch_attempt = bool(getattr(args, "require_full_provenance_for_broadcast", False))
    authorization = getattr(args, "_continuous_submission_authorization", None)
    state_path = _submission_state_path(args)
    if successor and (
        lane != "authority"
        or launch_attempt
        or authorization is not None
        or max_submissions != 1
        or _submission_runtime_root(args) != _VALIDATOR_RUNTIME_ROOT
        or state_path.name != SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
    ):
        raise ValueError(
            "UID30 successor requires the canonical one-shot authority journal"
        )
    predecessor_rollback_bytes = (
        _encode_uid30_successor_predecessor_bytes(
            _private_state_bytes(state_path),
            expected_sha256=SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256,
        )
        if successor
        else None
    )
    # `_continuous_transition_required` is the single source of truth. Keeping
    # a separate config conjunct here let a historical full-replay lane reserve
    # without the signed authorization already demanded by the launch gate.
    recurring_required = bool(
        bool(getattr(args, "broadcast", False))
        and not bool(getattr(args, "offline", False))
        and int(getattr(args, "netuid", -1)) == 39
        and not launch_attempt
        and _continuous_transition_required(args)
        and not successor
    )
    if recurring_required and not isinstance(authorization, ContinuousAuthorization):
        raise ValueError(
            "SN39 recurring reservation lacks a separate signed authorization"
        )
    if isinstance(authorization, ContinuousAuthorization):
        authorization_identity = _continuous_authorization_identity(authorization)
        if (
            launch_attempt
            or identity.get("continuous_authorization") != authorization_identity
            or lane not in authorization.lanes
            or re.fullmatch(r"sha256:[0-9a-f]{64}", authorization.authorization_sha256)
            is None
            or authorization.max_attempts <= 0
            or authorization.max_attempts > 96
            or authorization.valid_from_nonce < 0
            or authorization.valid_until_nonce_exclusive
            != authorization.valid_from_nonce + authorization.max_attempts
            or (max_submissions > 0 and authorization.max_attempts > max_submissions)
        ):
            raise ValueError(
                "recurring authorization differs from the exact reservation "
                "or configured attempt ceiling"
            )
        # The signed artifact's digest gives each explicit renewal an
        # independent durable budget. The budget is consumed only when the
        # exact signed transaction is fsynced, never by a dry or failed tick.
        budget_updates = {
            "_submission_budget_scope": authorization.authorization_sha256.removeprefix(
                "sha256:"
            ),
            "_submission_budget_limit": authorization.max_attempts,
        }
    else:
        budget_updates = (
            {
                "_submission_budget_scope": (
                    "authority_bounded"
                    if successor
                    else "launch_full_gate"
                    if launch_attempt
                    else f"{lane}_bounded"
                ),
                "_submission_budget_limit": max_submissions,
            }
            if max_submissions
            else {}
        )
    _write_state_fenced(
        state_path,
        {
            **(
                {
                    "_expected_state_sha256": (
                        SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256
                    )
                }
                if successor
                else {}
            ),
            "submission_genesis_hash": getattr(
                args, "_submission_genesis_hash", "offline"
            ),
            "provenance_netuid": int(args.netuid),
            "submission_validator_hotkey": getattr(
                args, "_submission_validator_hotkey", "offline"
            ),
            "_provisional_submission": True,
            "_allow_authority_lane_transition": bool(
                lane == "authority"
                and (
                    (
                        isinstance(authorization, ContinuousAuthorization)
                        and "authority" in authorization.lanes
                    )
                    # A bounded beta launch has no ContinuousAuthorization to
                    # carry lanes; _authority_lane_transition_authorized still
                    # binds the historical lane to this chain, netuid and hotkey.
                    or _operator_declared_authority(args)
                )
            ),
            "_launch_attempt": launch_attempt,
            **({"_launch_budget_limit": max_submissions} if launch_attempt else {}),
            **budget_updates,
            "submission_pending_id": attempt_id,
            "submission_pending_lane": lane,
            "submission_pending_identity": identity,
            "submission_pending_reviewed_uid30_contract": reviewed_kind,
            "submission_pending_predecessor_journal_sha256": (
                SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256 if successor else None
            ),
            **(
                {
                    "submission_pending_predecessor_journal_zlib_b64": (
                        predecessor_rollback_bytes
                    )
                }
                if successor
                else {}
            ),
            "submission_pending_at": _ms_iso_now(),
            **lane_fence,
        },
    )


def _record_pending_submission_receipt(
    args: Any,
    *,
    attempt_id: str,
    submission: ChainSubmission,
    version_key: int,
    wire_uids: list[int],
    wire_weights: list[int],
) -> None:
    """Fsync the canonical receipt identity before any archive proof.

    The receipt is sufficient for a restart to re-prove the exact historical
    call. It never authorizes another submission.
    """
    if (
        not submission.success
        or not submission.extrinsic_hash
        or _CHAIN_HASH_RE.fullmatch(submission.extrinsic_hash) is None
        or not submission.block_hash
        or _CHAIN_HASH_RE.fullmatch(submission.block_hash) is None
        or not isinstance(submission.block_number, int)
        or submission.block_number <= 0
        or isinstance(version_key, bool)
        or not isinstance(version_key, int)
        or version_key < 0
        or len(wire_uids) != len(wire_weights)
    ):
        raise wire.VectorError(
            "successful chain call has no canonical restart-safe receipt identity"
        )
    _write_state_fenced(
        _submission_state_path(args),
        {
            "_record_receipt_for_submission_id": attempt_id,
            "submission_pending_receipt_candidate": {
                "extrinsic_hash": submission.extrinsic_hash,
                "block_hash": submission.block_hash,
                "block_number": submission.block_number,
                "version_key": version_key,
                "wire_uids": wire_uids,
                "wire_weights": wire_weights,
            },
            "submission_pending_proof_status": "pending",
            "submission_pending_receipt_recorded_at": _ms_iso_now(),
        },
    )


def _strict_uid30_successor_unsigned_rollback(
    current: dict[str, Any],
    *,
    attempt_id: str,
    state_file: Path,
) -> bytes:
    """Return the exact predecessor only for one pristine unsigned successor."""

    identity = current.get("submission_pending_identity")
    predecessor_sha256 = current.get("submission_pending_predecessor_journal_sha256")
    contract = (
        _strict_zero_burn_uid30_contract(identity, lane="authority")
        if isinstance(identity, dict)
        else None
    )
    if (
        state_file.parent != _VALIDATOR_RUNTIME_ROOT
        or state_file.name != SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_FILENAME
        or current.get("submission_pending_reviewed_uid30_contract")
        != "two_miner_successor"
        or contract is None
        or contract.get("kind") != "two_miner_successor"
        or _reviewed_uid30_attempt_id(identity) != attempt_id
        or predecessor_sha256 != SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256
    ):
        raise ValueError("unsigned UID30 successor rollback identity changed")
    predecessor_bytes = _decode_uid30_successor_predecessor_bytes(
        current.get("submission_pending_predecessor_journal_zlib_b64"),
        expected_sha256=predecessor_sha256,
    )
    try:
        predecessor = _strict_state_document(predecessor_bytes.decode("utf-8"))
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        raise ValueError(
            "UID30 successor predecessor rollback state is malformed"
        ) from exc
    current_nonpending = {
        key: value
        for key, value in current.items()
        if not key.startswith("submission_pending_")
    }
    predecessor_nonpending = {
        key: value
        for key, value in predecessor.items()
        if not key.startswith("submission_pending_")
    }
    pending_keys = {key for key in current if key.startswith("submission_pending_")}
    expected_pending_keys = {
        "submission_pending_id",
        "submission_pending_lane",
        "submission_pending_identity",
        "submission_pending_reviewed_uid30_contract",
        "submission_pending_predecessor_journal_sha256",
        "submission_pending_predecessor_journal_zlib_b64",
        "submission_pending_at",
        "submission_pending_phase",
        "submission_pending_launch_attempt",
        "submission_pending_launch_budget_limit",
        "submission_pending_budget_scope",
        "submission_pending_budget_limit",
        "submission_pending_policy_version",
        "submission_pending_source_epoch",
        "submission_pending_lane_transition_from",
    }
    if (
        _canonical_json_bytes(current_nonpending)
        != _canonical_json_bytes(predecessor_nonpending)
        or pending_keys != expected_pending_keys
        or current.get("submission_pending_id") != attempt_id
        or current.get("submission_pending_lane") != "authority"
        or current.get("submission_pending_phase") != "unsigned_reserved"
        or current.get("submission_pending_launch_attempt") is not False
        or current.get("submission_pending_launch_budget_limit") is not None
        or current.get("submission_pending_budget_scope") != "authority_bounded"
        or type(current.get("submission_pending_budget_limit")) is not int
        or current.get("submission_pending_budget_limit") != 1
        or current.get("submission_pending_policy_version") is not None
        or type(current.get("submission_pending_source_epoch")) is not int
        or current.get("submission_pending_source_epoch")
        != identity.get("source_epoch")
        or current.get("submission_pending_lane_transition_from") is not None
        or not isinstance(current.get("submission_pending_at"), str)
        or not current.get("submission_pending_at")
    ):
        raise ValueError(
            "unsigned UID30 successor no longer has pristine predecessor lineage"
        )
    return predecessor_bytes


def _uid30_successor_pending_fragment(current: dict[str, Any]) -> bool:
    """Recognize every durable fragment of the sole bounded successor."""

    identity = current.get("submission_pending_identity")
    return bool(
        current.get("submission_pending_reviewed_uid30_contract")
        == "two_miner_successor"
        or (isinstance(identity, dict) and _uid30_successor_marked(identity))
        or "submission_pending_predecessor_journal_zlib_b64" in current
        or current.get("submission_pending_predecessor_journal_sha256") is not None
        or (
            current.get("submission_pending_budget_scope") == "authority_bounded"
            and current.get("submission_finalized_id")
            == SN39_UID30_SUCCESSOR_PREDECESSOR_ID
        )
    )


def _commit_pending_signed_attempt(
    args: Any,
    *,
    attempt_id: str,
    intent: dict[str, Any],
) -> None:
    """Atomically turn an unsigned reservation into the one irreversible attempt."""
    import fcntl

    state_file = _submission_state_path(args)
    state_directory = _open_private_state_dir(state_file.parent)
    os.close(state_directory)
    lock_descriptor = _open_private_lock(state_file.with_suffix(".lock"))
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        current = _read_state(state_file)
        lane = current.get("submission_pending_lane")
        identity = current.get("submission_pending_identity")
        if (
            current.get("submission_pending_id") != attempt_id
            or current.get("submission_pending_phase") != "unsigned_reserved"
            or lane not in {"thin", "authority"}
            or not isinstance(identity, dict)
            or current.get("submission_pending_broadcast_intent") is not None
            or current.get("submission_pending_receipt_candidate") is not None
        ):
            raise ValueError(
                "signed intent does not match one pristine unsigned reservation"
            )

        history = current.get("submission_attempt_ids", [])
        if not isinstance(history, list) or any(
            not isinstance(item, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
            for item in history
        ):
            raise ValueError("common submission attempt journal is corrupt")
        if attempt_id in history:
            raise ValueError("signed attempt already exists in the common journal")
        active_lane = current.get("submission_active_lane")
        transition_from = current.get("submission_pending_lane_transition_from")
        if active_lane is not None and active_lane != lane:
            identity_transition = bool(
                active_lane == "thin"
                and lane == "authority"
                and transition_from == "thin"
                and _authority_lane_transition_authorized(current, identity)
            )
            if not identity_transition:
                raise ValueError(
                    "submission authority lane changed before signed-intent commit"
                )
        elif transition_from is not None:
            raise ValueError("pending submission lane transition is inconsistent")

        budget_scope = current.get("submission_pending_budget_scope")
        budget_limit = current.get("submission_pending_budget_limit")
        budgets = current.get("submission_attempt_budgets", {})
        if not isinstance(budgets, dict):
            raise ValueError("submission attempt budgets are corrupt")
        updated_budgets = dict(budgets)
        if budget_scope is not None:
            if (
                not isinstance(budget_scope, str)
                or re.fullmatch(r"[a-z0-9_]{1,64}", budget_scope) is None
                or isinstance(budget_limit, bool)
                or not isinstance(budget_limit, int)
                or budget_limit <= 0
            ):
                raise ValueError("pending submission budget is malformed")
            budget = budgets.get(budget_scope, {"limit": budget_limit, "ids": []})
            if (
                not isinstance(budget, dict)
                or set(budget) != {"limit", "ids"}
                or budget.get("limit") != budget_limit
                or not isinstance(budget.get("ids"), list)
                or any(
                    not isinstance(item, str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                    for item in budget.get("ids", [])
                )
            ):
                raise ValueError("submission attempt budget changed or is corrupt")
            if len(budget["ids"]) >= budget_limit:
                raise ValueError(
                    f"submission attempt budget {budget_limit} is exhausted"
                )
            updated_budgets[budget_scope] = {
                "limit": budget_limit,
                "ids": [*budget["ids"], attempt_id],
            }
        elif budget_limit is not None:
            raise ValueError("pending submission budget limit has no scope")

        launch_attempt = current.get("submission_pending_launch_attempt")
        launch_limit = current.get("submission_pending_launch_budget_limit")
        launch_updates: dict[str, Any] = {}
        if not isinstance(launch_attempt, bool):
            raise ValueError("pending launch marker is malformed")
        if launch_attempt:
            launch_history = current.get("submission_launch_attempt_ids", [])
            if (
                launch_limit != 1
                or not isinstance(launch_history, list)
                or any(
                    not isinstance(item, str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                    for item in launch_history
                )
                or launch_history
            ):
                raise ValueError("launch submission budget 1 is exhausted or corrupt")
            launch_updates = {
                "submission_launch_attempt_ids": [attempt_id],
                "submission_launch_budget_limit": 1,
                "submission_launch_status": "pending",
            }
        elif launch_limit is not None:
            raise ValueError("non-launch signed attempt carries a launch budget")

        lane_updates: dict[str, int]
        if lane == "thin":
            policy_version = current.get("submission_pending_policy_version")
            prior_policy = current.get("submission_highest_policy_version")
            if (
                isinstance(policy_version, bool)
                or not isinstance(policy_version, int)
                or policy_version < 0
                or (isinstance(prior_policy, int) and policy_version <= prior_policy)
            ):
                raise ValueError("common thin policy fence changed before signing")
            lane_updates = {"submission_highest_policy_version": policy_version}
        else:
            source_epoch = current.get("submission_pending_source_epoch")
            prior_source = current.get("submission_highest_source_epoch")
            if (
                isinstance(source_epoch, bool)
                or not isinstance(source_epoch, int)
                or source_epoch < 0
                or (isinstance(prior_source, int) and source_epoch <= prior_source)
            ):
                raise ValueError("common authority epoch fence changed before signing")
            lane_updates = {"submission_highest_source_epoch": source_epoch}

        if _uid30_successor_pending_fragment(current):
            _strict_uid30_successor_unsigned_rollback(
                current,
                attempt_id=attempt_id,
                state_file=state_file,
            )

        # `submission_attempt_count` is the LIFETIME total, not the retained
        # length, so it stays truthful once the window starts evicting and
        # `count - len(ids)` names exactly how many were dropped. A stored
        # count below the retained length means a downgraded or hand-edited
        # journal; fall back to the length rather than move the total
        # backwards. Nothing in this repository reads the field — it is
        # operator telemetry — but a silently shrinking counter would make a
        # routine eviction look like data loss during an incident.
        stored_count = current.get("submission_attempt_count")
        if (
            isinstance(stored_count, bool)
            or not isinstance(stored_count, int)
            or stored_count < len(history)
        ):
            stored_count = len(history)

        document = dict(current)
        document.pop("submission_pending_predecessor_journal_zlib_b64", None)
        document.update(
            {
                "submission_pending_phase": "signed_intent",
                "submission_pending_broadcast_intent": intent,
                "submission_pending_broadcast_started_at": _ms_iso_now(),
                "submission_attempt_ids": _bounded_attempt_journal(
                    [*history, attempt_id],
                    # The only two ids a reader looks UP in this journal.
                    # Everything else consults it to prove an id is ABSENT,
                    # which the lane high-water fence already guarantees for
                    # anything old enough to be evicted — see
                    # SUBMISSION_ATTEMPT_ID_WINDOW.
                    (attempt_id, current.get("submission_finalized_id")),
                ),
                "submission_attempt_budgets": updated_budgets,
                "submission_active_lane": lane,
                "submission_attempt_count": stored_count + 1,
                **lane_updates,
                **launch_updates,
            }
        )
        _replace_private_state(state_file, document)
    finally:
        os.close(lock_descriptor)


def _abort_unsigned_common_submission(args: Any, *, attempt_id: str) -> bool:
    """Release only a reservation that provably never reached signed intent."""
    import fcntl

    state_file = _submission_state_path(args)
    state_directory = _open_private_state_dir(state_file.parent)
    os.close(state_directory)
    lock_descriptor = _open_private_lock(state_file.with_suffix(".lock"))
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        current = _read_state(state_file)
        if (
            current.get("submission_pending_id") != attempt_id
            or current.get("submission_pending_phase") != "unsigned_reserved"
            or current.get("submission_pending_broadcast_intent") is not None
            or current.get("submission_pending_receipt_candidate") is not None
        ):
            return False
        if _uid30_successor_pending_fragment(current):
            predecessor_bytes = _strict_uid30_successor_unsigned_rollback(
                current,
                attempt_id=attempt_id,
                state_file=state_file,
            )
            _replace_private_bytes(state_file, predecessor_bytes)
            if (
                _private_state_sha256(state_file)
                != SN39_UID30_SUCCESSOR_PREDECESSOR_JOURNAL_SHA256
            ):
                raise ValueError(
                    "unsigned UID30 successor predecessor restore did not persist"
                )
            return True
        document = dict(current)
        for key in tuple(document):
            if key.startswith("submission_pending_"):
                document.pop(key, None)
        document["submission_pending_id"] = None
        _replace_private_state(state_file, document)
        return True
    finally:
        os.close(lock_descriptor)


def _record_pending_broadcast_intent(
    args: Any,
    *,
    attempt_id: str,
    extrinsic_hash: str,
    nonce: int,
    era_reference_block: int,
    mortal_period_blocks: int,
    version_key: int,
    wire_uids: list[int],
    wire_weights: list[int],
) -> None:
    """Fsync the exact signed transaction before its irreversible submission.

    The intent does not prove that a broadcast occurred and never authorizes a
    retry. Its signed hash gives restart recovery one cryptographic transaction
    identity to search for when the process dies after broadcast but before a
    canonical receipt is returned.
    """
    if (
        re.fullmatch(r"sha256:[0-9a-f]{64}", attempt_id) is None
        or _CHAIN_HASH_RE.fullmatch(extrinsic_hash) is None
        or isinstance(nonce, bool)
        or not isinstance(nonce, int)
        or nonce < 0
        or isinstance(era_reference_block, bool)
        or not isinstance(era_reference_block, int)
        or era_reference_block <= 0
        or mortal_period_blocks != SN39_MORTAL_PERIOD_BLOCKS
        or isinstance(version_key, bool)
        or not isinstance(version_key, int)
        or version_key < 0
        or not wire_uids
        or len(wire_uids) != len(wire_weights)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in [*wire_uids, *wire_weights]
        )
    ):
        raise wire.VectorError("pending broadcast intent is malformed")
    _commit_pending_signed_attempt(
        args,
        attempt_id=attempt_id,
        intent={
            "extrinsic_hash": extrinsic_hash.lower(),
            "nonce": nonce,
            "era_reference_block": era_reference_block,
            "mortal_period_blocks": mortal_period_blocks,
            "version_key": version_key,
            "wire_uids": wire_uids,
            "wire_weights": wire_weights,
        },
    )


def _record_pending_proof_status(
    args: Any,
    *,
    attempt_id: str,
    status: str,
) -> None:
    if status not in {PASS, FAIL, NOT_PROVEN}:
        raise ValueError("pending proof status is invalid")
    _write_state_fenced(
        _submission_state_path(args),
        {
            "_record_receipt_for_submission_id": attempt_id,
            "submission_pending_proof_status": status,
            "submission_pending_proof_checked_at": _ms_iso_now(),
        },
    )


def _finalize_common_submission(
    args: Any,
    *,
    attempt_id: str,
    submission: ChainSubmission,
    version_key: int | None = None,
) -> None:
    finalized_version_key = (
        _weight_version_key() if version_key is None else version_key
    )
    pending = _read_state(_submission_state_path(args))
    reviewed_pending = _pending_reviewed_uid30_contract(
        args,
        attempt_id=attempt_id,
    )
    if (
        pending.get("submission_pending_id") != attempt_id
        or pending.get("submission_pending_phase") != "signed_intent"
        or not isinstance(pending.get("submission_pending_broadcast_intent"), dict)
    ):
        raise ValueError("submission finalization has no matching exact signed intent")
    pending_lane = pending.get("submission_pending_lane")
    pending_identity = pending.get("submission_pending_identity")
    pending_intent = pending.get("submission_pending_broadcast_intent")
    try:
        intent_hash = str(pending_intent["extrinsic_hash"]).lower()
        intent_version_key = pending_intent["version_key"]
        intent_wire_uids = list(pending_intent["wire_uids"])
        intent_wire_weights = list(pending_intent["wire_weights"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "submission finalization has a malformed signed intent"
        ) from exc
    try:
        pending_uid_weights = {
            int(uid): float(weight) for uid, weight in pending_identity["uid_weights"]
        }
        pending_ordered = sorted(pending_uid_weights.items())
        expected_wire_uids, expected_wire_weights = _wire_weights(
            [uid for uid, _weight in pending_ordered],
            [weight for _uid, weight in pending_ordered],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "submission finalization has a malformed reserved vector"
        ) from exc
    if (
        pending_lane not in {"thin", "authority"}
        or not isinstance(pending_identity, dict)
        or not submission.success
        or submission.finalized is not True
        or not isinstance(submission.extrinsic_hash, str)
        or _CHAIN_HASH_RE.fullmatch(submission.extrinsic_hash.lower()) is None
        or submission.extrinsic_hash.lower() != intent_hash
        or not isinstance(submission.block_hash, str)
        or _CHAIN_HASH_RE.fullmatch(submission.block_hash.lower()) is None
        or isinstance(submission.block_number, bool)
        or not isinstance(submission.block_number, int)
        or submission.block_number <= 0
        or isinstance(intent_version_key, bool)
        or not isinstance(intent_version_key, int)
        or intent_version_key < 0
        or intent_version_key != finalized_version_key
        or not intent_wire_uids
        or len(intent_wire_uids) != len(intent_wire_weights)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in [*intent_wire_uids, *intent_wire_weights]
        )
        or intent_wire_uids != expected_wire_uids
        or intent_wire_weights != expected_wire_weights
    ):
        raise ValueError("submission finalization differs from its exact signed intent")
    finalized_receipt = {
        "extrinsic_hash": submission.extrinsic_hash.lower(),
        "block_hash": submission.block_hash.lower(),
        "block_number": submission.block_number,
        "version_key": finalized_version_key,
        "wire_uids": intent_wire_uids,
        "wire_weights": intent_wire_weights,
    }
    launch_updates: dict[str, Any] = {}
    launch_attempt = pending.get("submission_pending_launch_attempt")
    if not isinstance(launch_attempt, bool):
        raise ValueError("submission finalization has no durable launch marker")
    if launch_attempt:
        launch_identity = pending.get("submission_pending_identity")
        launch_intent = pending.get("submission_pending_broadcast_intent")
        if not isinstance(launch_identity, dict):
            raise ValueError("launch finalization has no exact pending identity")
        if (
            pending.get("submission_pending_phase") != "signed_intent"
            or not isinstance(launch_intent, dict)
            or not isinstance(launch_identity.get("uid_safety"), dict)
        ):
            raise ValueError(
                "launch finalization has no signed intent or UID safety proof"
            )
        launch_updates = {
            "submission_launch_status": "finalized",
            "submission_launch_attempt_id": attempt_id,
            "submission_launch_identity": launch_identity,
            "submission_launch_extrinsic_hash": submission.extrinsic_hash,
            "submission_launch_block_hash": submission.block_hash,
            "submission_launch_block_number": submission.block_number,
            "submission_launch_version_key": finalized_version_key,
            "submission_launch_broadcast_intent": launch_intent,
            "submission_launch_uid_safety": launch_identity["uid_safety"],
            "submission_continuous_enabled": False,
        }
    _write_state_fenced(
        _submission_state_path(args),
        {
            "_finalize_submission_id": attempt_id,
            "submission_finalized_id": attempt_id,
            "submission_finalized_at": _ms_iso_now(),
            "submission_extrinsic_hash": submission.extrinsic_hash,
            "submission_block_hash": submission.block_hash,
            "submission_block_number": submission.block_number,
            "submission_version_key": finalized_version_key,
            "submission_finalized_lane": pending_lane,
            "submission_finalized_identity": pending_identity,
            "submission_finalized_broadcast_intent": pending_intent,
            "submission_finalized_receipt": finalized_receipt,
            "submission_finalized_reviewed_uid30_contract": (
                None if reviewed_pending is None else reviewed_pending[2]["kind"]
            ),
            "submission_pending_proof_status": PASS,
            **launch_updates,
        },
    )


def _recover_common_finalized_submission(
    args: Any,
    state: dict[str, Any],
) -> RecoveredSubmission | RecoveredAuthoritySubmission | None:
    """Mirror a proven common finalization after a lane-telemetry crash.

    The finalized record is validated only against itself. It already carries
    its own lane, identity, broadcast intent, and receipt, so it does not need
    the `submission_pending_*` residue that finalization happened to leave
    behind. Requiring that residue wedged the writer permanently: a later
    unsigned reservation that never reached the chain is entitled to clear
    every pending key (`_abort_unsigned_common_submission`), which erased the
    mirror and made an already-proven finalization fail its own check on the
    next restart.
    """
    attempt_id = state.get("submission_finalized_id")
    lane = state.get("submission_finalized_lane")
    identity = state.get("submission_finalized_identity")
    intent = state.get("submission_finalized_broadcast_intent")
    receipt = state.get("submission_finalized_receipt")
    if attempt_id is None:
        return None
    if lane is None and identity is None and intent is None and receipt is None:
        # Compatibility with finalized journals created before the explicit
        # cross-file recovery record existed.
        return None
    history = state.get("submission_attempt_ids")
    if (
        not isinstance(attempt_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", attempt_id) is None
        or lane not in {"thin", "authority"}
        or not isinstance(identity, dict)
        or not isinstance(intent, dict)
        or not isinstance(receipt, dict)
        or not isinstance(history, list)
        or attempt_id not in history
        or state.get("submission_pending_id") is not None
        or state.get("submission_active_lane") != lane
        or set(intent)
        != {
            "extrinsic_hash",
            "nonce",
            "era_reference_block",
            "mortal_period_blocks",
            "version_key",
            "wire_uids",
            "wire_weights",
        }
        or set(receipt)
        != {
            "extrinsic_hash",
            "block_hash",
            "block_number",
            "version_key",
            "wire_uids",
            "wire_weights",
        }
    ):
        raise _PostSignedSubmissionMismatch(
            "finalized common submission recovery record is contradictory"
        )
    zero_burn_contract = _strict_zero_burn_uid30_contract(identity, lane=lane)
    zero_burn_owner_hotkey = (
        None if zero_burn_contract is None else str(zero_burn_contract["owner"])
    )
    zero_burn_uid30 = zero_burn_contract is not None
    finalized_reviewed_kind = state.get("submission_finalized_reviewed_uid30_contract")
    if (
        finalized_reviewed_kind is not None
        and (
            zero_burn_contract is None
            or finalized_reviewed_kind != zero_burn_contract["kind"]
        )
    ) or (
        zero_burn_contract is not None
        and zero_burn_contract["kind"] == "two_miner_successor"
        and finalized_reviewed_kind != "two_miner_successor"
    ):
        raise _PostSignedSubmissionMismatch(
            "finalized reviewed UID30 marker and identity disagree"
        )
    try:
        extrinsic_hash = str(receipt["extrinsic_hash"]).lower()
        block_hash = str(receipt["block_hash"]).lower()
        block_number = receipt["block_number"]
        version_key = receipt["version_key"]
        wire_uids = list(receipt["wire_uids"])
        wire_weights = list(receipt["wire_weights"])
        intent_extrinsic_hash = str(intent["extrinsic_hash"]).lower()
        intent_version_key = intent["version_key"]
        intent_wire_uids = list(intent["wire_uids"])
        intent_wire_weights = list(intent["wire_weights"])
        intent_nonce = intent["nonce"]
        intent_era_reference_block = intent["era_reference_block"]
        intent_mortal_period_blocks = intent["mortal_period_blocks"]
        uid_weights = {
            int(uid): float(weight) for uid, weight in identity["uid_weights"]
        }
        uid_hotkeys = {int(uid): str(hotkey) for uid, hotkey in identity["uid_hotkeys"]}
        ordered_weights = sorted(uid_weights.items())
        expected_wire_uids, expected_wire_weights = _wire_weights(
            [uid for uid, _weight in ordered_weights],
            [weight for _uid, weight in ordered_weights],
        )
        if zero_burn_uid30:
            assert zero_burn_owner_hotkey is not None
            burn_hotkey = zero_burn_owner_hotkey
            burn_uid = None
            burn_share = 0.0
        else:
            burn_hotkey = str(identity["burn_hotkey"])
            burn_uid = next(
                uid for uid, hotkey in uid_hotkeys.items() if hotkey == burn_hotkey
            )
            burn_share = uid_weights[burn_uid]
    except (KeyError, StopIteration, TypeError, ValueError) as exc:
        raise _PostSignedSubmissionMismatch(
            "finalized common submission identity or receipt is malformed"
        ) from exc
    if (
        identity.get("network") != "finney"
        or identity.get("netuid") != 39
        or state.get("submission_genesis_hash") != FINNEY_GENESIS_HASH
        or identity.get("validator_hotkey") != state.get("submission_validator_hotkey")
        or intent_era_reference_block != identity.get("mapping_block")
        or set(uid_hotkeys) != set(uid_weights)
        or (
            zero_burn_uid30
            and (
                not burn_hotkey
                or burn_hotkey in uid_hotkeys.values()
                or tuple(sorted(uid_weights.items()))
                != zero_burn_contract["uid_weights"]
                or tuple(sorted(uid_hotkeys.items()))
                != zero_burn_contract["uid_hotkeys"]
            )
        )
        or (not zero_burn_uid30 and list(uid_hotkeys.values()).count(burn_hotkey) != 1)
        or not math.isfinite(burn_share)
        or burn_share < 0.0
        or _CHAIN_HASH_RE.fullmatch(extrinsic_hash) is None
        or _CHAIN_HASH_RE.fullmatch(block_hash) is None
        or isinstance(block_number, bool)
        or not isinstance(block_number, int)
        or block_number <= 0
        or isinstance(version_key, bool)
        or not isinstance(version_key, int)
        or version_key < 0
        or isinstance(intent_nonce, bool)
        or not isinstance(intent_nonce, int)
        or intent_nonce < 0
        or isinstance(intent_era_reference_block, bool)
        or not isinstance(intent_era_reference_block, int)
        or intent_era_reference_block <= 0
        or intent_mortal_period_blocks != SN39_MORTAL_PERIOD_BLOCKS
        or isinstance(intent_version_key, bool)
        or not isinstance(intent_version_key, int)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in [
                *wire_uids,
                *wire_weights,
                *intent_wire_uids,
                *intent_wire_weights,
            ]
        )
        or extrinsic_hash != intent_extrinsic_hash
        or version_key != intent_version_key
        or wire_uids != intent_wire_uids
        or wire_weights != intent_wire_weights
        or wire_uids != expected_wire_uids
        or wire_weights != expected_wire_weights
        or state.get("submission_extrinsic_hash") != extrinsic_hash
        or state.get("submission_block_hash") != block_hash
        or state.get("submission_block_number") != block_number
        or state.get("submission_version_key") != version_key
    ):
        raise _PostSignedSubmissionMismatch(
            "finalized common submission does not match its durable identity"
        )

    lane_state_path = Path(args.state_file)
    try:
        lane_state = _read_state(lane_state_path)
    except ValueError as exc:
        raise _PostSignedSubmissionMismatch(
            "finalized common submission contradicts its lane state"
        ) from exc
    except OSError as exc:
        raise _PendingReceiptNotProven(
            "finalized common submission is proven, but its lane state is "
            "temporarily unavailable"
        ) from exc
    finalized_at = _ms_iso_now()
    dedup_identity = {
        key: value
        for key, value in identity.items()
        if key not in {"mapping_block", "uid_safety"}
    }
    if lane == "thin":
        try:
            policy_version = int(identity["policy_version"])
            vector_id = str(identity["vector_id"])
            signed_vector_sha256 = str(identity["signed_vector_sha256"])
        except (KeyError, TypeError, ValueError) as exc:
            raise _PostSignedSubmissionMismatch(
                "finalized common thin identity is malformed"
            ) from exc
        if (
            policy_version < 0
            or not vector_id
            or re.fullmatch(r"sha256:[0-9a-f]{64}", signed_vector_sha256) is None
        ):
            raise _PostSignedSubmissionMismatch(
                "finalized common thin identity is malformed"
            )
        mirrored = bool(
            lane_state.get("thin_submission_attempt_status") == "finalized"
            and lane_state.get("thin_submission_finalized_id") == attempt_id
            and lane_state.get("thin_submission_identity") == identity
            and lane_state.get("thin_submission_extrinsic_hash") == extrinsic_hash
            and lane_state.get("thin_submission_block_hash") == block_hash
            and lane_state.get("thin_submission_block_number") == block_number
            and lane_state.get("last_accepted_policy_version") == policy_version
            and lane_state.get("last_vector_id") == vector_id
        )
        if mirrored:
            return None
        if (
            lane_state.get("thin_submission_attempt_id") == attempt_id
            or lane_state.get("thin_submission_finalized_id") == attempt_id
        ):
            raise _PostSignedSubmissionMismatch(
                "finalized common thin submission contradicts its lane mirror"
            )
        try:
            _write_state_fenced(
                lane_state_path,
                {
                    "highest_attempted_policy_version": policy_version,
                    "thin_submission_attempt_id": attempt_id,
                    "thin_submission_attempt_status": "finalized",
                    "thin_submission_finalized_id": attempt_id,
                    "thin_submission_finalized_at": finalized_at,
                    "thin_submission_extrinsic_hash": extrinsic_hash,
                    "thin_submission_block_hash": block_hash,
                    "thin_submission_block_number": block_number,
                    "thin_submission_identity": identity,
                    "thin_submission_dedup_identity": dedup_identity,
                    "last_accepted_policy_version": policy_version,
                    "last_vector_id": vector_id,
                    "accepted_at": finalized_at,
                    "thin_recovered_policy_version": policy_version,
                    "thin_recovered_vector_id": vector_id,
                    "thin_recovered_signed_vector_sha256": signed_vector_sha256,
                },
            )
        except ValueError as exc:
            raise _PostSignedSubmissionMismatch(
                "finalized common thin submission contradicts its lane state"
            ) from exc
        except OSError as exc:
            raise _PendingReceiptNotProven(
                "finalized common thin submission is proven, but its lane mirror "
                "could not be persisted"
            ) from exc
        return RecoveredSubmission(
            attempt_id=attempt_id,
            policy_version=policy_version,
            vector_id=vector_id,
            signed_vector_sha256=signed_vector_sha256,
            uid_weights=tuple(sorted(uid_weights.items())),
            burn_uid=burn_uid,
            burn_share=burn_share,
            extrinsic_hash=extrinsic_hash,
            block_hash=block_hash,
            block_number=block_number,
        )

    try:
        source_epoch = int(identity["source_epoch"])
        report_id = str(identity["report_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise _PostSignedSubmissionMismatch(
            "finalized common FULL identity is malformed"
        ) from exc
    if source_epoch < 0 or re.fullmatch(r"sha256:[0-9a-f]{64}", report_id) is None:
        raise _PostSignedSubmissionMismatch(
            "finalized common FULL identity is malformed"
        )
    mirrored = bool(
        lane_state.get("authority_submission_attempt_status") == "finalized"
        and lane_state.get("authority_submission_finalized_id") == attempt_id
        and lane_state.get("authority_submission_identity") == identity
        and lane_state.get("authority_submission_extrinsic_hash") == extrinsic_hash
        and lane_state.get("authority_submission_block_hash") == block_hash
        and lane_state.get("authority_submission_block_number") == block_number
    )
    if mirrored:
        return None
    if (
        lane_state.get("authority_submission_attempt_id") == attempt_id
        or lane_state.get("authority_submission_finalized_id") == attempt_id
    ):
        raise _PostSignedSubmissionMismatch(
            "finalized common FULL submission contradicts its lane mirror"
        )
    try:
        _write_state_fenced(
            lane_state_path,
            {
                "authority_submission_attempt_id": attempt_id,
                "authority_submission_attempt_status": "finalized",
                "authority_submission_attempted_at": finalized_at,
                "authority_submission_identity": identity,
                "authority_submission_dedup_identity": dedup_identity,
                "authority_submission_finalized_id": attempt_id,
                "authority_submission_finalized_at": finalized_at,
                "authority_submission_extrinsic_hash": extrinsic_hash,
                "authority_submission_block_hash": block_hash,
                "authority_submission_block_number": block_number,
            },
        )
    except ValueError as exc:
        raise _PostSignedSubmissionMismatch(
            "finalized common FULL submission contradicts its lane state"
        ) from exc
    except OSError as exc:
        raise _PendingReceiptNotProven(
            "finalized common FULL submission is proven, but its lane mirror "
            "could not be persisted"
        ) from exc
    return RecoveredAuthoritySubmission(
        attempt_id=attempt_id,
        source_epoch=source_epoch,
        report_id=report_id,
        uid_weights=tuple(sorted(uid_weights.items())),
        burn_uid=burn_uid,
        burn_share=burn_share,
        extrinsic_hash=extrinsic_hash,
        block_hash=block_hash,
        block_number=block_number,
    )


def _policy_from_submission_identity(identity: dict[str, Any]) -> InclusionPolicy:
    raw = identity.get("inclusion_policy")
    if not isinstance(raw, dict):
        raise wire.VectorError("pending submission has no inclusion policy")
    try:
        policy = InclusionPolicy(
            valid_from_block=int(raw["valid_from_block"]),
            valid_until_block=int(raw["valid_until_block"]),
            valid_from_time=wire._parse_canonical_utc(
                raw["valid_from_time"],
                field="pending inclusion valid_from_time",
            ),
            valid_until_time=wire._parse_canonical_utc(
                raw["valid_until_time"],
                field="pending inclusion valid_until_time",
            ),
            require_commit_reveal_disabled=raw["require_commit_reveal_disabled"],
            mortal_period_blocks=int(raw["mortal_period_blocks"]),
            expected_next_epoch_start_block=int(raw["expected_next_epoch_start_block"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise wire.VectorError("pending inclusion policy is malformed") from exc
    if (
        not isinstance(policy.require_commit_reveal_disabled, bool)
        or identity.get("next_epoch_start_block")
        != policy.expected_next_epoch_start_block
    ):
        raise wire.VectorError("pending inclusion policy identity is inconsistent")
    return policy


def _locate_pending_broadcast_receipt(
    subtensor: Any,
    *,
    extrinsic_hash: str,
    era_reference_block: int,
    mortal_period_blocks: int,
    validator_hotkey: str,
    netuid: int,
    version_key: int,
    wire_uids: list[int],
    wire_weights: list[int],
    inclusion_policy: InclusionPolicy,
) -> tuple[str, ChainSubmission | None]:
    """Find the pre-journaled signed transaction after a crash hid its receipt.

    The search is limited to the four blocks authorized by the durable mortal
    inclusion policy and matches the signed hash, signer, and decoded call. It
    does not sign or submit anything.
    """
    substrate = getattr(subtensor, "substrate", None)
    if (
        substrate is None
        or _CHAIN_HASH_RE.fullmatch(extrinsic_hash) is None
        or isinstance(era_reference_block, bool)
        or not isinstance(era_reference_block, int)
        or era_reference_block <= 0
        or mortal_period_blocks != SN39_MORTAL_PERIOD_BLOCKS
    ):
        return NOT_PROVEN, None
    matches: list[ChainSubmission] = []
    try:
        finalized_hash = str(substrate.get_chain_finalised_head())
        finalized_number = int(substrate.get_block_number(finalized_hash))
        canonical_finalized_hash = str(substrate.get_block_hash(finalized_number))
        if (
            _CHAIN_HASH_RE.fullmatch(finalized_hash) is None
            or canonical_finalized_hash.lower() != finalized_hash.lower()
        ):
            return NOT_PROVEN, None
        search_from = max(
            inclusion_policy.valid_from_block,
            era_reference_block,
        )
        search_until = min(
            inclusion_policy.valid_until_block,
            era_reference_block + mortal_period_blocks,
        )
        if search_from >= search_until:
            return FAIL, None
        for block_number in range(search_from, search_until):
            if block_number > finalized_number:
                continue
            block_hash = str(substrate.get_block_hash(block_number))
            if _CHAIN_HASH_RE.fullmatch(block_hash) is None:
                return NOT_PROVEN, None
            block = substrate.get_block(block_hash=block_hash)
            if not isinstance(block, dict) or not isinstance(
                block.get("extrinsics"), (list, tuple)
            ):
                return NOT_PROVEN, None
            for item in block["extrinsics"]:
                observed = getattr(item, "value", None)
                if not isinstance(observed, dict):
                    continue
                observed_hash = str(observed.get("extrinsic_hash", "")).lower()
                if observed_hash != extrinsic_hash.lower():
                    continue
                call = observed.get("call") or {}
                exact_call = (
                    observed.get("address") == validator_hotkey
                    and call.get("call_module") == "SubtensorModule"
                    and call.get("call_function") == "set_mechanism_weights"
                    and _chain_call_arg(call, "netuid") == netuid
                    and _chain_call_arg(call, "mecid") == 0
                    and _chain_call_arg(call, "version_key") == version_key
                    and _chain_call_arg(call, "dests") == wire_uids
                    and _chain_call_arg(call, "weights") == wire_weights
                )
                if not exact_call:
                    return FAIL, None
                matches.append(
                    ChainSubmission(
                        success=True,
                        extrinsic_hash=extrinsic_hash.lower(),
                        block_hash=block_hash,
                        block_number=block_number,
                        finalized=True,
                    )
                )
    except Exception:  # noqa: BLE001 - archive/RPC unavailability is inconclusive
        return NOT_PROVEN, None
    if len(matches) > 1:
        return FAIL, None
    if not matches:
        if finalized_number >= search_until - 1:
            # Every block in the complete authorized mortal era was fetched
            # successfully from one reverse-checked finalized chain. Absence is
            # now terminal rather than an RPC gap: the signed transaction can no
            # longer be included, so restart recovery may retire only this exact
            # attempt without authorizing it again.
            return EXPIRED_WITHOUT_INCLUSION, None
        return NOT_PROVEN, None
    return PASS, matches[0]


def _expire_pending_common_submission(args: Any, *, attempt_id: str) -> None:
    """Retire one exhaustively absent signed attempt without erasing its budget.

    This transition is valid only after the complete mortal era has been
    finalized and read without an exact inclusion. It clears the ambiguity
    fence, but deliberately retains the signed-attempt, authorization-budget,
    policy/source high-water, and launch histories. The same attempt therefore
    remains permanently ineligible while a distinct later attempt still needs
    its own fresh vector/evidence and signed authorization.
    """
    import fcntl

    state_file = _submission_state_path(args)
    state_directory = _open_private_state_dir(state_file.parent)
    os.close(state_directory)
    lock_descriptor = _open_private_lock(state_file.with_suffix(".lock"))
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        current = _read_state(state_file)
        if (
            current.get("submission_pending_id") != attempt_id
            or current.get("submission_pending_phase") != "signed_intent"
            or not isinstance(current.get("submission_pending_broadcast_intent"), dict)
            or current.get("submission_pending_receipt_candidate") is not None
        ):
            raise ValueError(
                "expired submission does not match one receipt-free signed intent"
            )
        history = current.get("submission_attempt_ids")
        budgets = current.get("submission_attempt_budgets")
        if (
            not isinstance(history, list)
            or attempt_id not in history
            or not isinstance(budgets, dict)
        ):
            raise ValueError(
                "expired submission has no retained attempt or budget history"
            )
        terminal_attempts = current.get("submission_expired_attempts", [])
        if not isinstance(terminal_attempts, list) or any(
            not isinstance(item, dict) for item in terminal_attempts
        ):
            raise ValueError("expired submission history is malformed")
        if any(item.get("attempt_id") == attempt_id for item in terminal_attempts):
            raise ValueError("expired submission was already retired")

        lane = current.get("submission_pending_lane")
        identity = current.get("submission_pending_identity")
        intent = current.get("submission_pending_broadcast_intent")
        launch_attempt = current.get("submission_pending_launch_attempt")
        if (
            lane not in {"thin", "authority"}
            or not isinstance(identity, dict)
            or not isinstance(launch_attempt, bool)
        ):
            raise ValueError("expired submission identity is malformed")
        expired_at = _ms_iso_now()
        terminal = {
            "attempt_id": attempt_id,
            "status": EXPIRED_WITHOUT_INCLUSION,
            "expired_at": expired_at,
            "lane": lane,
            "identity": identity,
            "broadcast_intent": intent,
        }
        document = dict(current)
        for key in tuple(document):
            if key.startswith("submission_pending_"):
                document.pop(key, None)
        document.update(
            {
                "submission_pending_id": None,
                "submission_expired_status": EXPIRED_WITHOUT_INCLUSION,
                "submission_expired_id": attempt_id,
                "submission_expired_at": expired_at,
                "submission_expired_lane": lane,
                "submission_expired_identity": identity,
                "submission_expired_broadcast_intent": intent,
                "submission_expired_attempts": [*terminal_attempts, terminal],
            }
        )
        if launch_attempt:
            document.update(
                {
                    "submission_launch_status": EXPIRED_WITHOUT_INCLUSION,
                    "submission_launch_attempt_id": attempt_id,
                    "submission_launch_identity": identity,
                    "submission_launch_broadcast_intent": intent,
                    "submission_continuous_enabled": False,
                }
            )
        _replace_private_state(state_file, document)
    finally:
        os.close(lock_descriptor)


def _recover_pending_launch_receipt(
    args: Any,
) -> RecoveredSubmission | RecoveredAuthoritySubmission | None:
    """Re-prove and finalize one thin or authority-labelled launch receipt.

    This runs before every profile tick. ``None`` means there is no pending
    submission. A positive historical mismatch or unavailable archive remains
    fenced and exits nonzero; recovery never signs or submits.
    """
    if not bool(getattr(args, "broadcast", False)) or bool(
        getattr(args, "offline", False)
    ):
        return None
    # The preflight runs BEFORE the journal is opened, so nothing here can be
    # about a fenced attempt yet — and its ~8 sequential chain calls under one
    # 180s deadline fail for reasons that are mostly the operator's to fix, not
    # the chain's to resolve. Collapsing all of them into one "temporarily
    # unavailable" sentence is what made a third-party unit restart-loop 20
    # times on a message nobody could act on.
    try:
        _prepare_tick_preflight(args)
    except (_PostSignedSubmissionMismatch, _PendingReceiptNotProven):
        raise
    except wire.VectorError as exc:
        # A `VectorError` from the preflight is the preflight's own refusal,
        # and every one of them is already worded precisely: an unregistered
        # hotkey, a missing validator permit, a metagraph that would not
        # resolve at the finalized head, a lite node that cannot serve
        # `MinNonImmuneUids`/`OwnedHotkeys`, a genesis that is not Finney,
        # commit-reveal enabled, a burn hotkey that is no longer the subnet
        # owner, a runtime root that is not the canonical one, or the 180s
        # deadline naming itself. Carry that wording out instead of replacing
        # it. The exception TYPE is unchanged so the exit path, return code,
        # and emitted event stay exactly what they were.
        raise _PendingReceiptNotProven(
            f"pending receipt recovery chain preflight refused: {stable_error(exc)}",
            fenced_attempt=False,
        ) from exc
    except Exception as exc:
        # Anything else came out of the RPC/SDK layer with no curated wording
        # of its own — a closed websocket, a refused or reset connection, a
        # decode failure. Those really are transient, so the framing stays;
        # only the cause is added, sanitized, so "unavailable" stops being the
        # entire diagnosis.
        raise _PendingReceiptNotProven(
            "pending receipt recovery chain preflight is temporarily unavailable: "
            f"{stable_error(exc)}",
            fenced_attempt=False,
        ) from exc
    recovery_lock = _pending_recovery_tick_lock(args)
    recovery_lock.__enter__()
    # Reporting-only: whether the journal has actually named a signed attempt
    # by the time something fails below. Nothing branches on it except the
    # remediation text.
    signed_attempt_journaled = False
    try:
        state_path = _submission_state_path(args)
        state = _read_state(state_path)
        attempt_id = state.get("submission_pending_id")
        if attempt_id is None:
            return _recover_common_finalized_submission(args, state)
        pending_lane = state.get("submission_pending_lane")
        if (
            not isinstance(attempt_id, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", attempt_id) is None
            or pending_lane not in {"thin", "authority"}
        ):
            raise wire.VectorError("pending submission journal is malformed")
        pending_phase = state.get("submission_pending_phase")
        if pending_phase == "unsigned_reserved":
            if not _abort_unsigned_common_submission(args, attempt_id=attempt_id):
                raise wire.VectorError(
                    "unsigned reservation changed while restart recovery held the "
                    "submission lock"
                )
            _lifecycle(
                "CHAIN reservation released",
                f"attempt_id={attempt_id} signed=false broadcast=false",
            )
            return None
        if pending_phase != "signed_intent":
            raise wire.VectorError(
                "pending submission journal has no recognized unsigned or signed phase"
            )
        # From here the journal positively names a signed attempt, so every
        # remediation below may say so.
        signed_attempt_journaled = True
        if state.get("submission_pending_proof_status") == FAIL:
            raise _PostSignedSubmissionMismatch(
                "pending submission has a positive historical proof mismatch; "
                "automatic recovery is forbidden"
            )
        identity = state.get("submission_pending_identity")
        candidate = state.get("submission_pending_receipt_candidate")
        if not isinstance(identity, dict):
            raise wire.VectorError(
                "pending submission has no complete submission identity"
            )
        zero_burn_contract = _strict_zero_burn_uid30_contract(
            identity, lane=pending_lane
        )
        zero_burn_owner_hotkey = (
            None if zero_burn_contract is None else str(zero_burn_contract["owner"])
        )
        zero_burn_uid30 = zero_burn_contract is not None
        durable_reviewed_kind = state.get("submission_pending_reviewed_uid30_contract")
        if (
            durable_reviewed_kind is not None
            and (
                zero_burn_contract is None
                or durable_reviewed_kind != zero_burn_contract["kind"]
            )
        ) or (
            zero_burn_contract is not None
            and zero_burn_contract["kind"] == "two_miner_successor"
            and durable_reviewed_kind != "two_miner_successor"
        ):
            raise wire.VectorError(
                "pending reviewed UID30 marker and identity disagree"
            )
        if durable_reviewed_kind == "two_miner_successor":
            # This generic restart path proves the exact historical call and
            # inclusion storage, but it does not own the successor's stronger
            # completion contract: both reviewed miner axons, mappings, UID30
            # permit, and the complete row must remain exact at two strictly
            # later finalized heads.  Only the fixed successor recovery path
            # performs those checks before finalization.  Keep the signed
            # attempt fenced here instead of creating a second, weaker
            # recovery mode.
            raise _PendingReceiptNotProven(
                "pending two-miner UID30 successor requires "
                "`cathedral-uid30-launch successor-recover`; generic validator "
                "recovery cannot prove its two later finalized heads"
            )
        preflight = getattr(args, "_tick_preflight", None)
        if not isinstance(preflight, ChainPreflight):
            raise _PendingReceiptNotProven(
                "pending submission recovery has no available chain preflight"
            )
        try:
            uid_weights = {
                int(uid): float(weight) for uid, weight in identity["uid_weights"]
            }
            uid_hotkeys = {
                int(uid): str(hotkey) for uid, hotkey in identity["uid_hotkeys"]
            }
            ordered = sorted(uid_weights.items())
            expected_wire_uids, expected_wire_weights = _wire_weights(
                [uid for uid, _weight in ordered],
                [weight for _uid, weight in ordered],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise wire.VectorError("pending submission identity is malformed") from exc
        if zero_burn_uid30:
            assert zero_burn_owner_hotkey is not None
            if (
                preflight.validator_uid != SN39_UID30_LAUNCH_VALIDATOR_UID
                or preflight.validator_hotkey != SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
                or preflight.validator_uid in uid_weights
                or preflight.validator_hotkey in uid_hotkeys.values()
            ):
                raise wire.VectorError(
                    "pending zero-burn UID30 preflight differs from the launch signer"
                )
        inclusion_policy = _policy_from_submission_identity(identity)
        intent = state.get("submission_pending_broadcast_intent")
        if not isinstance(intent, dict):
            raise wire.VectorError(
                "pending submission predates its exact signed broadcast intent; "
                "refusing any retry"
            )
        try:
            intent_extrinsic_hash = str(intent["extrinsic_hash"]).lower()
            intent_nonce = intent["nonce"]
            intent_era_reference_block = intent["era_reference_block"]
            intent_mortal_period = intent["mortal_period_blocks"]
            version_key = intent["version_key"]
            wire_uids = list(intent["wire_uids"])
            wire_weights = list(intent["wire_weights"])
        except (KeyError, TypeError, ValueError) as exc:
            raise wire.VectorError(
                "pending signed broadcast intent is malformed"
            ) from exc
        if (
            _CHAIN_HASH_RE.fullmatch(intent_extrinsic_hash) is None
            or isinstance(intent_nonce, bool)
            or not isinstance(intent_nonce, int)
            or intent_nonce < 0
            or isinstance(intent_era_reference_block, bool)
            or not isinstance(intent_era_reference_block, int)
            or intent_era_reference_block != identity.get("mapping_block")
            or isinstance(intent_mortal_period, bool)
            or not isinstance(intent_mortal_period, int)
            or intent_mortal_period != inclusion_policy.mortal_period_blocks
            or intent_mortal_period != SN39_MORTAL_PERIOD_BLOCKS
            or isinstance(version_key, bool)
            or not isinstance(version_key, int)
            or version_key < 0
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in [*wire_uids, *wire_weights]
            )
            or wire_uids != expected_wire_uids
            or wire_weights != expected_wire_weights
        ):
            raise wire.VectorError(
                "pending signed broadcast intent differs from its reserved vector "
                "or inclusion policy"
            )
        if not isinstance(candidate, dict):
            locate_status, located = _locate_pending_broadcast_receipt(
                preflight.subtensor,
                extrinsic_hash=intent_extrinsic_hash,
                era_reference_block=intent_era_reference_block,
                mortal_period_blocks=intent_mortal_period,
                validator_hotkey=preflight.validator_hotkey,
                netuid=39,
                version_key=version_key,
                wire_uids=wire_uids,
                wire_weights=wire_weights,
                inclusion_policy=inclusion_policy,
            )
            if locate_status == EXPIRED_WITHOUT_INCLUSION and located is None:
                _expire_pending_common_submission(args, attempt_id=attempt_id)
                _lifecycle(
                    "CHAIN expired",
                    f"attempt_id={attempt_id} included=false resubmitted=false",
                )
                return None
            _record_pending_proof_status(
                args,
                attempt_id=attempt_id,
                status=locate_status,
            )
            if locate_status == FAIL:
                raise _PostSignedSubmissionMismatch(
                    "pending broadcast recovery found conflicting historical "
                    "calls; operator investigation is required"
                )
            if locate_status == NOT_PROVEN or located is None:
                raise _PendingReceiptNotProven(
                    "pending broadcast has no unique finalized exact transaction "
                    "in its authorized block window; no second chain write was "
                    "attempted"
                )
            _record_pending_submission_receipt(
                args,
                attempt_id=attempt_id,
                submission=located,
                version_key=version_key,
                wire_uids=wire_uids,
                wire_weights=wire_weights,
            )
            candidate = {
                "extrinsic_hash": located.extrinsic_hash,
                "block_hash": located.block_hash,
                "block_number": located.block_number,
                "version_key": version_key,
                "wire_uids": wire_uids,
                "wire_weights": wire_weights,
            }
        try:
            extrinsic_hash = str(candidate["extrinsic_hash"])
            block_hash = str(candidate["block_hash"])
            block_number = int(candidate["block_number"])
            version_key = int(candidate["version_key"])
            wire_uids = [int(value) for value in candidate["wire_uids"]]
            wire_weights = [int(value) for value in candidate["wire_weights"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise wire.VectorError("pending receipt candidate is malformed") from exc
        if (
            identity.get("network") != "finney"
            or identity.get("netuid") != 39
            or identity.get("validator_hotkey") != preflight.validator_hotkey
            or state.get("submission_genesis_hash") != preflight.genesis_hash
            or _CHAIN_HASH_RE.fullmatch(extrinsic_hash) is None
            or extrinsic_hash.lower() != intent_extrinsic_hash
            or _CHAIN_HASH_RE.fullmatch(block_hash) is None
            or block_number <= 0
            or wire_uids != expected_wire_uids
            or wire_weights != expected_wire_weights
            or set(uid_hotkeys) != set(uid_weights)
        ):
            raise wire.VectorError(
                "pending receipt differs from its reserved vector or chain identity"
            )
        proof_reason: list[str] = []
        try:
            with _chain_operation_deadline(
                "pending launch receipt recovery",
                CHAIN_OPERATION_DEADLINE_SECS,
            ):
                proof_status = _classify_finalized_receipt(
                    preflight.subtensor,
                    receipt=None,
                    extrinsic_hash=extrinsic_hash,
                    block_hash=block_hash,
                    block_number=block_number,
                    validator_hotkey=preflight.validator_hotkey,
                    netuid=39,
                    version_key=version_key,
                    wire_uids=wire_uids,
                    wire_weights=wire_weights,
                    uid_hotkeys=(
                        {
                            **uid_hotkeys,
                            SN39_UID30_LAUNCH_VALIDATOR_UID: (
                                SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
                            ),
                        }
                        if zero_burn_uid30
                        else uid_hotkeys
                    ),
                    expected_subnet_owner_hotkey=str(
                        identity.get(
                            "subnet_owner_hotkey" if zero_burn_uid30 else "burn_hotkey"
                        )
                        or ""
                    ),
                    inclusion_policy=inclusion_policy,
                    require_receipt=False,
                    reason_out=proof_reason,
                )
                if proof_status == PASS and zero_burn_uid30:
                    proof_status = _classify_zero_burn_uid30_historical_weights(
                        preflight.subtensor,
                        block_hash=block_hash,
                        wire_uids=wire_uids,
                        wire_weights=wire_weights,
                        reason_out=proof_reason,
                    )
        except (_PostSignedSubmissionMismatch, _PendingReceiptNotProven):
            raise
        except Exception as exc:
            raise _PendingReceiptNotProven(
                "pending receipt archive proof is temporarily unavailable: "
                f"{stable_error(exc)}"
            ) from exc
        _record_pending_proof_status(
            args,
            attempt_id=attempt_id,
            status=proof_status,
        )
        if proof_status == NOT_PROVEN:
            raise _PendingReceiptNotProven(
                "pending receipt is still not provable from the archive; "
                "no second chain write was attempted"
                + _receipt_reason_suffix(proof_reason)
            )
        if proof_status == FAIL:
            raise _PostSignedSubmissionMismatch(
                "pending receipt positively mismatches its historical "
                "inclusion contract; operator investigation is required"
                + _receipt_reason_suffix(proof_reason)
            )
        submission = ChainSubmission(
            success=True,
            extrinsic_hash=extrinsic_hash,
            block_hash=block_hash,
            block_number=block_number,
            finalized=True,
        )
        _finalize_common_submission(
            args,
            attempt_id=attempt_id,
            submission=submission,
            version_key=version_key,
        )
        try:
            if zero_burn_uid30:
                assert zero_burn_owner_hotkey is not None
                burn_hotkey = zero_burn_owner_hotkey
                burn_uid = None
                burn_share = 0.0
            else:
                burn_hotkey = str(identity["burn_hotkey"])
                burn_uid = next(
                    uid for uid, hotkey in uid_hotkeys.items() if hotkey == burn_hotkey
                )
                burn_share = float(uid_weights[burn_uid])
        except (KeyError, StopIteration, TypeError, ValueError) as exc:
            raise wire.VectorError(
                "recovered submission has no exact burn identity"
            ) from exc
        if not math.isfinite(burn_share) or burn_share < 0.0:
            raise wire.VectorError("recovered submission identity is malformed")
        lane_state_path = Path(args.state_file)
        lane_state = _read_state(lane_state_path)
        if pending_lane == "thin":
            try:
                policy_version = int(identity["policy_version"])
                vector_id = str(identity["vector_id"])
                signed_vector_sha256 = str(identity["signed_vector_sha256"])
            except (KeyError, TypeError, ValueError) as exc:
                raise wire.VectorError(
                    "recovered thin submission has no exact policy/vector identity"
                ) from exc
            if (
                policy_version < 0
                or not vector_id
                or re.fullmatch(r"sha256:[0-9a-f]{64}", signed_vector_sha256) is None
            ):
                raise wire.VectorError("recovered thin identity is malformed")
            lane_updates = {
                "thin_submission_attempt_status": "finalized",
                "thin_submission_finalized_id": attempt_id,
                "thin_submission_finalized_at": _ms_iso_now(),
                "thin_submission_extrinsic_hash": extrinsic_hash,
                "thin_submission_block_hash": block_hash,
                "thin_submission_block_number": block_number,
                "last_accepted_policy_version": policy_version,
                "last_vector_id": vector_id,
                "accepted_at": _ms_iso_now(),
                "thin_recovered_policy_version": policy_version,
                "thin_recovered_vector_id": vector_id,
                "thin_recovered_signed_vector_sha256": signed_vector_sha256,
            }
            if lane_state.get("thin_submission_attempt_id") == attempt_id:
                _write_state(lane_state_path, lane_updates)
            else:
                _write_state_fenced(
                    lane_state_path,
                    {
                        "highest_attempted_policy_version": policy_version,
                        "thin_submission_attempt_id": attempt_id,
                        "thin_submission_attempted_at": _ms_iso_now(),
                        "thin_submission_identity": identity,
                        **lane_updates,
                    },
                )
            recovered: RecoveredSubmission | RecoveredAuthoritySubmission = (
                RecoveredSubmission(
                    attempt_id=attempt_id,
                    policy_version=policy_version,
                    vector_id=vector_id,
                    signed_vector_sha256=signed_vector_sha256,
                    uid_weights=tuple(sorted(uid_weights.items())),
                    burn_uid=burn_uid,
                    burn_share=burn_share,
                    extrinsic_hash=extrinsic_hash,
                    block_hash=block_hash,
                    block_number=block_number,
                )
            )
        else:
            try:
                source_epoch = int(identity["source_epoch"])
                report_id = str(identity["report_id"])
            except (KeyError, TypeError, ValueError) as exc:
                raise wire.VectorError(
                    "recovered FULL submission has no exact evidence identity"
                ) from exc
            if (
                source_epoch < 0
                or re.fullmatch(r"sha256:[0-9a-f]{64}", report_id) is None
            ):
                raise wire.VectorError("recovered FULL identity is malformed")
            dedup_identity = {
                key: value
                for key, value in identity.items()
                if key not in {"mapping_block", "uid_safety"}
            }
            authority_updates = {
                "authority_submission_attempt_id": attempt_id,
                "authority_submission_attempt_status": "finalized",
                "authority_submission_attempted_at": _ms_iso_now(),
                "authority_submission_identity": identity,
                "authority_submission_dedup_identity": dedup_identity,
                "authority_submission_finalized_id": attempt_id,
                "authority_submission_finalized_at": _ms_iso_now(),
                "authority_submission_extrinsic_hash": extrinsic_hash,
                "authority_submission_block_hash": block_hash,
                "authority_submission_block_number": block_number,
            }
            if lane_state.get("authority_submission_attempt_id") == attempt_id:
                _write_state(lane_state_path, authority_updates)
            else:
                _write_state_fenced(lane_state_path, authority_updates)
            recovered = RecoveredAuthoritySubmission(
                attempt_id=attempt_id,
                source_epoch=source_epoch,
                report_id=report_id,
                uid_weights=tuple(sorted(uid_weights.items())),
                burn_uid=burn_uid,
                burn_share=burn_share,
                extrinsic_hash=extrinsic_hash,
                block_hash=block_hash,
                block_number=block_number,
            )
        _lifecycle(
            "CHAIN recovered",
            f"extrinsic_hash={extrinsic_hash} block_number={block_number} "
            "resubmitted=false",
        )
        return recovered
    except (_PostSignedSubmissionMismatch, _PendingReceiptNotProven):
        raise
    except OSError as exc:
        raise _PendingReceiptNotProven(
            f"pending receipt recovery state is temporarily unavailable: "
            f"{stable_error(exc)}",
            fenced_attempt=signed_attempt_journaled,
        ) from exc
    except Exception as exc:
        raise _PostSignedSubmissionMismatch(
            "pending receipt recovery found contradictory durable state: "
            f"{stable_error(exc)}"
        ) from exc
    finally:
        recovery_lock.__exit__(*sys.exc_info())


def _match_signed_public_release_to_launch(
    *,
    public_result: dict[str, Any],
    state: dict[str, Any],
    identity: dict[str, Any],
) -> dict[str, Any]:
    """Bind the mutable service journal to the root-signed public launch seal.

    The validator account owns its local journal, so that journal can establish
    crash safety but cannot authorize a permanent transition by itself.  The
    public reproducer verifies a separately signed release, the historical
    chain execution, the inclusion-time evidence window, and the frozen
    evidence checkpoint.  This matcher then requires that independently
    verified release to name the exact journaled rewarded-set-gated attempt.
    """
    try:
        release = public_result["release"]
        launch = release["attested_submission"]
        mapping = launch["mapping"]
        broadcast_intent = launch["broadcast_intent"]
        snapshot = mapping["metagraph_snapshot"]
        extrinsic = launch["extrinsic"]
        checkpoint = launch["evidence_checkpoint"]
        full = identity["full_provenance"]
        release_uid_weights = {
            int(uid): float(weight) for uid, weight in mapping["uid_weights"].items()
        }
        identity_uid_weights = {
            int(uid): float(weight) for uid, weight in identity["uid_weights"]
        }
        identity_uid_hotkeys = {
            int(uid): str(hotkey) for uid, hotkey in identity["uid_hotkeys"]
        }
        snapshot_uids = [int(value) for value in snapshot["uids"]]
        snapshot_hotkeys = [str(value) for value in snapshot["hotkeys"]]
        snapshot_uid_hotkeys = dict(zip(snapshot_uids, snapshot_hotkeys))
        if len(snapshot_uids) != len(snapshot_hotkeys) or len(
            snapshot_uid_hotkeys
        ) != len(snapshot_uids):
            raise ValueError("public launch metagraph snapshot is inconsistent")
        burn_uid = int(mapping["burn_uid"])
        burn_hotkey = snapshot_uid_hotkeys[burn_uid]
        release_uid_hotkeys = {
            uid: snapshot_uid_hotkeys[uid] for uid in sorted(release_uid_weights)
        }
        expected_uids, expected_weights = _wire_weights(
            sorted(identity_uid_weights),
            [identity_uid_weights[uid] for uid in sorted(identity_uid_weights)],
        )
        if not isinstance(broadcast_intent, dict):
            raise ValueError("public launch broadcast intent is malformed")
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise wire.VectorError(
            "root-signed public launch evidence is malformed"
        ) from exc

    exact_matches = (
        public_result.get("release_attestation") == PASS,
        public_result.get("historical_launch") == PASS,
        public_result.get("evidence_checkpoint") == PASS,
        release.get("network") == identity.get("network") == "finney",
        release.get("netuid") == identity.get("netuid") == 39,
        launch.get("vector_id") == identity.get("vector_id"),
        launch.get("policy_version") == identity.get("policy_version"),
        launch.get("signed_vector_sha256") == identity.get("signed_vector_sha256"),
        launch.get("signed_vector") == identity.get("signed_vector"),
        mapping.get("block") == identity.get("mapping_block"),
        mapping.get("validator_hotkey") == identity.get("validator_hotkey"),
        mapping.get("validator_uid") == identity.get("validator_uid"),
        snapshot.get("block") == identity.get("mapping_block"),
        mapping.get("next_epoch_start_block") == identity.get("next_epoch_start_block"),
        mapping.get("uid_safety") == identity.get("uid_safety"),
        mapping.get("uid_safety") == state.get("submission_launch_uid_safety"),
        extrinsic.get("block", 0) < mapping.get("next_epoch_start_block", 0),
        burn_uid in release_uid_weights,
        burn_hotkey == identity.get("burn_hotkey"),
        release_uid_weights == identity_uid_weights,
        release_uid_hotkeys == identity_uid_hotkeys,
        extrinsic.get("hash") == state.get("submission_launch_extrinsic_hash"),
        extrinsic.get("block_hash") == state.get("submission_launch_block_hash"),
        extrinsic.get("block") == state.get("submission_launch_block_number"),
        extrinsic.get("validator_uid") == identity.get("validator_uid"),
        extrinsic.get("uids") == expected_uids,
        extrinsic.get("weights_u16") == expected_weights,
        extrinsic.get("version_key") == state.get("submission_launch_version_key"),
        broadcast_intent == state.get("submission_launch_broadcast_intent"),
        broadcast_intent.get("extrinsic_hash") == extrinsic.get("hash"),
        broadcast_intent.get("era_reference_block") == mapping.get("block"),
        broadcast_intent.get("mortal_period_blocks") == SN39_MORTAL_PERIOD_BLOCKS,
        broadcast_intent.get("version_key") == extrinsic.get("version_key"),
        broadcast_intent.get("wire_uids") == extrinsic.get("uids"),
        broadcast_intent.get("wire_weights") == extrinsic.get("weights_u16"),
        broadcast_intent.get("era_reference_block", 0)
        <= extrinsic.get("block", -1)
        < broadcast_intent.get("era_reference_block", 0)
        + broadcast_intent.get("mortal_period_blocks", 0),
        full.get("scope") in ("rewarded_set_proven", "rewarded_set_full"),
        # An accepted vocabulary, not a rank test: this validates a recorded
        # launch approval, so it must keep parsing artifacts written before the
        # ranked levels existed as well as ones written after.
        full.get("whole_epoch_assurance") in set(ASSURANCE_RANKS),
        full.get("vector_agrees") is True,
        full.get("rewarded_hotkeys") == full.get("raw_replayed_hotkeys"),
        bool(full.get("rewarded_hotkeys")),
        full.get("source_epoch") == checkpoint.get("source_epoch"),
        full.get("report_id") == checkpoint.get("report_id"),
        full.get("manifest") == checkpoint.get("manifest"),
        full.get("policy_release") == checkpoint.get("policy_release"),
        full.get("policy_digest") == checkpoint.get("policy_digest"),
        full.get("mechanism") == checkpoint.get("reward_mechanism", {}).get("id"),
        full.get("verifier_digest") == checkpoint.get("verifier_digest"),
        full.get("verifier_binary_digest") == checkpoint.get("verifier_binary_digest"),
        full.get("report_signing_key_id") == checkpoint.get("report_signing_key_id"),
        full.get("signed_index") == checkpoint.get("signed_index"),
        full.get("source_revision")
        == release.get("source_revisions", {}).get("producer"),
    )
    if not all(exact_matches):
        raise wire.VectorError(
            "root-signed public launch evidence does not match the exact "
            "rewarded-set-gated journal and chain submission"
        )
    return {
        "release_attestation": PASS,
        "historical_launch": PASS,
        "evidence_checkpoint": PASS,
        "reproducer_revision": public_result.get("reproducer_revision"),
        "release_sha256": "sha256:"
        + hashlib.sha256(
            json.dumps(
                release,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest(),
    }


def reconcile_launch_transition(args: Any) -> dict[str, Any]:
    """Verify the signed public launch seal and enable continuous operation."""
    preflight = chain_preflight(
        network=args.network,
        netuid=args.netuid,
        wallet_name=args.wallet_name,
        wallet_hotkey=args.wallet_hotkey,
    )
    _validate_resolved_chain_contract(
        args,
        preflight,
        require_sn39_identity=True,
    )
    _bind_submission_identity(args, preflight)
    with _submission_tick_lock(args, lane="thin"):
        state_path = _submission_state_path(args)
        state = _read_state(state_path)
        if state.get("submission_pending_id") is not None:
            raise wire.VectorError(
                "launch submission remains ambiguous; reconcile it manually before "
                "enabling continuous operation"
            )
        launch_attempt_id = state.get("submission_launch_attempt_id")
        if (
            state.get("submission_launch_status") != "finalized"
            or not isinstance(launch_attempt_id, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", launch_attempt_id) is None
            or launch_attempt_id not in state.get("submission_launch_attempt_ids", [])
        ):
            raise wire.VectorError("no finalized rewarded-set-gated launch is recorded")
        identity = state.get("submission_launch_identity")
        if not isinstance(identity, dict):
            raise wire.VectorError("finalized launch identity is missing")
        try:
            uid_weights = {
                int(uid): float(weight) for uid, weight in identity["uid_weights"]
            }
            uid_hotkeys = {
                int(uid): str(hotkey) for uid, hotkey in identity["uid_hotkeys"]
            }
            wire_uids, wire_weights = _wire_weights(
                list(dict(sorted(uid_weights.items()))),
                [uid_weights[uid] for uid in sorted(uid_weights)],
            )
            extrinsic_hash = str(state["submission_launch_extrinsic_hash"])
            block_hash = str(state["submission_launch_block_hash"])
            block_number = int(state["submission_launch_block_number"])
            version_key = int(state["submission_launch_version_key"])
        except (KeyError, TypeError, ValueError) as exc:
            raise wire.VectorError("finalized launch journal is malformed") from exc
        if (
            identity.get("validator_hotkey") != preflight.validator_hotkey
            or state.get("submission_genesis_hash") != preflight.genesis_hash
            or _CHAIN_HASH_RE.fullmatch(extrinsic_hash) is None
            or _CHAIN_HASH_RE.fullmatch(block_hash) is None
            or block_number <= 0
        ):
            raise wire.VectorError("finalized launch identity differs from the chain")
        try:
            from scaffold import sn39_public_reproduction

            public_result = sn39_public_reproduction.verify_public_release()
            public_seal = _match_signed_public_release_to_launch(
                public_result=public_result,
                state=state,
                identity=identity,
            )
        except wire.VectorError:
            raise
        except Exception as exc:
            raise wire.VectorError(
                "root-signed public launch evidence did not reproduce"
            ) from exc
        with _chain_operation_deadline(
            "launch transition reconciliation", CHAIN_OPERATION_DEADLINE_SECS
        ):
            proven = _prove_finalized_receipt(
                preflight.subtensor,
                receipt=None,
                extrinsic_hash=extrinsic_hash,
                block_hash=block_hash,
                block_number=block_number,
                validator_hotkey=preflight.validator_hotkey,
                netuid=int(args.netuid),
                version_key=version_key,
                wire_uids=wire_uids,
                wire_weights=wire_weights,
                uid_hotkeys=uid_hotkeys,
                require_receipt=False,
            )
        if not proven:
            raise wire.VectorError(
                "recorded launch extrinsic, finality, or inclusion-block UID bindings "
                "did not reproduce"
            )
        _write_state_fenced(
            state_path,
            {
                "submission_continuous_enabled": True,
                "submission_continuous_enabled_at": _ms_iso_now(),
                "submission_continuous_launch_attempt_id": state[
                    "submission_launch_attempt_id"
                ],
                "submission_continuous_release_sha256": public_seal["release_sha256"],
                "submission_continuous_reproducer_revision": public_seal[
                    "reproducer_revision"
                ],
            },
        )
        return {
            "status": PASS,
            "launch_attempt_id": state["submission_launch_attempt_id"],
            "extrinsic_hash": extrinsic_hash,
            "block_hash": block_hash,
            "block_number": block_number,
            **public_seal,
        }


def _require_continuous_launch_transition(args: Any) -> ContinuousAuthorization:
    """Re-prove launch history and a separate recurring authorization.

    The service account owns its crash-safety journal and therefore cannot
    authorize itself merely by editing journal fields.  The root-signed public
    release is re-verified under the shared submission lock before every
    continuous reservation and must bind the exact historical launch attempt,
    chain receipt, and rewarded-set evidence checkpoint. A second, short-lived,
    root-controlled signed artifact must explicitly authorize recurring writes
    for this release, signer, chain, lane, and bounded attempt count. The
    returned immutable authorization is stored in the reservation; the lowest
    write boundary rechecks its time/block scope without network work after
    pending state has been fsynced.
    """
    state = _read_state(_submission_state_path(args))
    if state.get("submission_pending_id") is not None:
        raise wire.VectorError(
            "continuous submission journal has an unresolved pending attempt"
        )
    if (
        state.get("submission_continuous_enabled") is not True
        or state.get("submission_launch_status") != "finalized"
        or state.get("submission_continuous_launch_attempt_id")
        != state.get("submission_launch_attempt_id")
    ):
        raise _ContinuousLaunchLocked(
            "continuous broadcast is locked until `cathedral-validator "
            "reconcile-launch` independently verifies the finalized "
            "rewarded-set-gated "
            "launch"
        )
    identity = state.get("submission_launch_identity")
    if not isinstance(identity, dict):
        raise wire.VectorError("continuous launch identity is missing")
    try:
        from scaffold import sn39_public_reproduction

        public_result = sn39_public_reproduction.verify_public_release()
        public_seal = _match_signed_public_release_to_launch(
            public_result=public_result,
            state=state,
            identity=identity,
        )
    except wire.VectorError:
        raise
    except Exception as exc:
        raise wire.VectorError(
            "continuous broadcast could not reproduce the root-signed public "
            "launch evidence"
        ) from exc
    if (
        state.get("submission_continuous_release_sha256")
        != public_seal["release_sha256"]
        or state.get("submission_continuous_reproducer_revision")
        != public_seal["reproducer_revision"]
    ):
        raise wire.VectorError(
            "continuous journal does not match the reproduced root-signed "
            "launch authorization"
        )
    validator_hotkey = getattr(args, "_submission_validator_hotkey", None)
    genesis_hash = getattr(args, "_submission_genesis_hash", None)
    if (
        not isinstance(validator_hotkey, str)
        or not validator_hotkey
        or not isinstance(genesis_hash, str)
        or _CHAIN_HASH_RE.fullmatch(genesis_hash) is None
        or state.get("submission_validator_hotkey") != validator_hotkey
        or state.get("submission_genesis_hash") != genesis_hash
    ):
        raise wire.VectorError(
            "continuous launch authorization differs from the prepared signer "
            "or chain genesis"
        )
    attempt_id = state.get("submission_launch_attempt_id")
    if (
        not isinstance(attempt_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", attempt_id) is None
    ):
        raise wire.VectorError("continuous launch attempt identity is malformed")
    preflight = getattr(args, "_tick_preflight", None)
    if (
        not isinstance(preflight, ChainPreflight)
        or preflight.block is None
        or preflight.validator_hotkey != validator_hotkey
        or preflight.genesis_hash != genesis_hash
    ):
        raise wire.VectorError(
            "recurring authorization requires the current finalized signer snapshot"
        )
    lane = (
        "authority"
        if (getattr(args, "provenance", "shadow") or "shadow") == "authority"
        else "thin"
    )
    try:
        from scaffold import sn39_continuous_authorization as recurring

        verified = recurring.verify_authorization(
            expected={
                "submission_journal": str(_submission_state_path(args)),
                "genesis_hash": genesis_hash,
                "validator_hotkey": validator_hotkey,
                "launch_attempt_id": attempt_id,
                "release_sha256": public_seal["release_sha256"],
                "reproducer_revision": str(public_seal["reproducer_revision"]),
                "not_before_time": state.get("submission_continuous_enabled_at"),
            },
            lane=lane,
            finalized_block=preflight.block,
        )
    except Exception as exc:
        raise wire.VectorError(
            "separate root-signed recurring-write authorization is absent, "
            "invalid, expired, exhausted in scope, or does not match this "
            "release/runtime"
        ) from exc
    return ContinuousAuthorization(
        authorization_sha256=verified.authorization_sha256,
        submission_journal=verified.submission_journal,
        launch_attempt_id=attempt_id,
        release_sha256=public_seal["release_sha256"],
        reproducer_revision=str(public_seal["reproducer_revision"]),
        validator_hotkey=validator_hotkey,
        genesis_hash=genesis_hash,
        lanes=verified.lanes,
        issued_at=verified.issued_at,
        valid_from_time=verified.valid_from_time,
        valid_until_time=verified.valid_until_time,
        valid_from_block=verified.valid_from_block,
        valid_until_block=verified.valid_until_block,
        valid_from_nonce=verified.valid_from_nonce,
        valid_until_nonce_exclusive=verified.valid_until_nonce_exclusive,
        max_attempts=verified.max_attempts,
    )


def _sn39_launch_lineage(args: Any) -> bool | None:
    """Report whether this runtime's own journal records an SN39 launch.

    Returns None when the canonical signer/genesis identity is not resolved
    yet. The journal is addressed BY that identity, so before it is bound the
    question is unanswerable rather than answered "no". Every boundary that can
    actually reach an irreversible chain call resolves the identity first
    (`_prepare_tick_preflight`/`_bind_submission_identity`), so a runtime that
    has launched can never slip past the gate on an unresolved probe.
    """
    if not bool(getattr(args, "offline", False)) and (
        getattr(args, "_submission_validator_hotkey", None) is None
        or getattr(args, "_submission_genesis_hash", None) is None
    ):
        return None
    try:
        journal = _submission_state_path(args)
    except Exception:  # noqa: BLE001 - identity or root not usable here
        return None
    try:
        os.stat(journal.parent)
    except (FileNotFoundError, NotADirectoryError):
        # No runtime root yet means no journal and therefore no launch history.
        # The root itself is pinned to its canonical location separately, so
        # this cannot be used to point the probe somewhere convenient.
        return False
    except OSError:
        return True
    try:
        state = _read_state_without_mutation(journal)
    except Exception:  # noqa: BLE001
        # An unreadable, foreign-owned, or malformed journal must never read as
        # "never launched"; that is exactly how a launcher would hide its own
        # obligation. Fail closed.
        return True
    # Every marker below is written only under a launch reservation. The
    # per-reservation `submission_pending_launch_attempt` is a bool on ordinary
    # thin writes too, so it is compared against True rather than None: a relay
    # that has already reserved once must not read as launch lineage and brick
    # itself on its second tick.
    return bool(
        state.get("submission_launch_status") is not None
        or state.get("submission_launch_attempt_id") is not None
        or state.get("submission_launch_attempt_ids")
        or state.get("submission_continuous_enabled") is True
        or state.get("submission_continuous_launch_attempt_id") is not None
        or state.get("submission_pending_launch_attempt") is True
    )


def _sn39_launch_obligation(args: Any) -> bool:
    """Does THIS runtime owe SN39 its own completed one-shot launch?

    The mainnet launch is a subnet-level event, not a per-validator one. A
    third-party validator that only relays Cathedral's signed vector can never
    satisfy a per-validator launch gate, so an unconditional gate locks every
    operator except Cathedral out of SN39 entirely. The obligation therefore
    tracks the things an operator cannot simply restate in a config file:

      1. the internal ``provenance="authority"`` marker retained for bounded
         launch and historical recovery. Recurring entrypoints refuse it;
      2. the launch runtime itself, which performs the one-shot transaction;
      3. possession of, or journalled lineage from, the controlled launch
         material at the release-pinned absolute paths.

    Every branch reads code constants or this runtime's own durable journal, so
    no config value, CLI flag, endpoint label, or environment variable can
    clear an obligation the runtime actually has.
    """
    if (getattr(args, "provenance", "shadow") or "shadow") == "authority":
        return True
    if bool(getattr(args, "require_full_provenance_for_broadcast", False)):
        return True
    for path in (
        SN39_LAUNCH_CONTROLLED_DIR,
        SN39_LAUNCH_VERIFIER_BINARY,
        SN39_LAUNCH_APPROVAL_FILE,
    ):
        try:
            os.stat(path)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            # A host that cannot answer the question is treated as holding the
            # launch material; refusing the broadcast is the safe direction.
            return True
        return True
    return _sn39_launch_lineage(args) is True


def _continuous_transition_required(args: Any) -> bool:
    if (
        bool(getattr(args, "broadcast", False))
        and not bool(getattr(args, "offline", False))
        and int(getattr(args, "netuid", -1)) == 39
        and _sn39_launch_obligation(args)
        and not bool(getattr(args, "beta_skip_launch_ceremony", False))
    ):
        # No operator-controlled label, endpoint, config, or direct CLI
        # invocation may weaken the SN39 transition requirement for a runtime
        # that originates weights or holds/has held launch material.
        #
        # BETA ESCAPE, deliberate and narrow. `beta_skip_launch_ceremony`
        # waives the one-shot launch canary and the ContinuousAuthorization
        # that derives from it. Those are PROCESS controls: they make a single
        # mainnet launch event auditable. They are not what keeps a submission
        # correct. Everything that does still runs on every tick and is not
        # reachable from this flag: feed signature and key pin, freshness and
        # expiry, the monotonic rollback fence, the validated_supply contract
        # check, burn destination and burn floor, UID replacement safety, and
        # the single-writer guard.
        #
        # Set it only for an operator-owned beta on a subnet the operator
        # controls. Clear it before any launch that has to be auditable.
        return True
    explicit = getattr(args, "require_completed_launch_for_broadcast", None)
    if explicit is not None:
        return bool(explicit)
    # This asks "is this an SN39 mainnet posture?", not "is this the launch
    # contract?". Both admitted pins are that posture, so both carry the
    # continuous-authorization obligation. Left as single equality on v1, a
    # re-pin to v3 would SILENTLY DROP the obligation — a real weakening bought
    # with a one-word config change, and one nothing else would report.
    return getattr(args, "require_policy", None) in SN39_PINNED_REQUIRE_POLICIES


@contextlib.contextmanager
def _submission_tick_lock(args: Any, *, lane: str):
    """One non-blocking cross-process submission section for every mode.

    Recurring thin writes and bounded or historical authority-labelled launch
    operations contend on the same file, so only one can reach an irreversible
    chain call. Shadow audit work stays concurrent because it never enters a
    submission tick on its own.
    """
    import fcntl

    lock_path = _submission_lock_path(args)
    lock_directory = _open_private_state_dir(lock_path.parent)
    os.close(lock_directory)
    boundary = "audit or submission" if lane == "authority" else "fetch or submission"
    try:
        descriptor = _open_private_lock(lock_path)
    except (OSError, ValueError) as exc:
        raise wire.VectorError(
            f"{lane} submission lock unavailable ({stable_error(exc)}); "
            f"refusing before {boundary}"
        ) from exc
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise wire.VectorError(
                f"{lane} submission lock is unavailable or already held for "
                f"this validator/chain identity; refusing before {boundary} "
                "(cross-mode linearized single-flight)"
            ) from exc
        yield
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def _thin_tick_lock(args: Any):
    with _submission_tick_lock(args, lane="thin"):
        yield


@contextlib.contextmanager
def _pending_recovery_tick_lock(args: Any):
    """Classify lock acquisition/cleanup failure as unavailable proof.

    Exceptions raised by the recovery body pass through unchanged so durable
    contradictions can still be classified as positive failures below.
    """
    entered = False
    body_completed = False
    try:
        with _thin_tick_lock(args):
            entered = True
            yield
            body_completed = True
    except (_PostSignedSubmissionMismatch, _PendingReceiptNotProven):
        raise
    except Exception as exc:
        if entered and not body_completed:
            raise
        raise _PendingReceiptNotProven(
            "pending receipt recovery lock is temporarily unavailable"
        ) from exc


def _drain_shadow_audit_once(args) -> bool:
    """--once only: the recurring loop reports a finished shadow audit on
    the NEXT tick, which a single run never has. Wait out the in-flight
    audit within its own documented total bound (the audit deadline),
    report every completed result exactly once, and return False — a
    truthful nonzero exit — when the outcome could not be captured.
    Recurring thin ticks never call this; their non-blocking single-flight
    drain is unchanged."""
    auditor = getattr(args, "_shadow_auditor", None)
    if auditor is None:
        return True
    bound = _provenance_settings(args).audit_deadline_secs
    resolved = auditor.wait(bound)
    completed = auditor.drain()
    healthy = bool(completed)
    for finished_audit, finished_state_file in completed:
        persisted = _log_audit_events(args, finished_audit, finished_state_file)
        healthy = healthy and (
            persisted
            and finished_audit.status == "PASS"
            and assurance_rank(getattr(finished_audit, "assurance", None))
            >= _minimum_assurance_rank(args)
            and finished_audit.agrees_with_vector is True
        )
    if not resolved:
        _get_events(args).event(
            "PROVENANCE_AUDIT_UNRESOLVED",
            stage="provenance",
            status=NOT_PROVEN,
            detail=(
                f"single-run shadow audit still in flight after its "
                f"{bound:.0f}s bound; its outcome was not captured"
            ),
            remediation=(
                "re-run, extend the audit deadline, or check the evidence "
                "endpoint; the thin submission itself was unaffected"
            ),
        )
        return False
    if not healthy:
        _get_events(args).event(
            "PROVENANCE_HEALTH_GATE_FAILED",
            stage="provenance",
            status=FAIL,
            detail=(
                "single-run shadow audit did not establish the configured "
                "minimum assurance and exact agreement with the signed vector"
            ),
            remediation=(
                "inspect the preceding provenance verdict; do not treat this "
                "one-shot current-health run as launch-ready"
            ),
        )
        return False
    return True


def _validate_runtime_contract(args: Any) -> None:
    max_submissions = int(getattr(args, "max_submissions", 0) or 0)
    if max_submissions < 0:
        raise wire.VectorError("max_submissions must be nonnegative")
    # The internal authority-labelled lane is retained for bounded full replay
    # and historical journal compatibility. It derives a single-lane vector and
    # therefore cannot satisfy the signed multi-lane v3 contract.
    if (
        getattr(args, "require_policy", None) == REQUIRE_POLICY_VALIDATED_SUPPLY_V3
        and (getattr(args, "provenance", "shadow") or "shadow") == "authority"
    ):
        raise wire.VectorError(
            "require_policy=validated_supply_v3 is incompatible with the bounded "
            "full-replay launch lane: v3 requires Cathedral's signed multi-lane "
            "vector, while strict replay currently derives only the TDX lane"
        )
    launch_gate = bool(getattr(args, "require_full_provenance_for_broadcast", False))
    launch_preflight = bool(getattr(args, "launch_preflight", False))
    sn39_broadcast = (
        bool(getattr(args, "broadcast", False))
        and not bool(getattr(args, "offline", False))
        and int(getattr(args, "netuid", -1)) == 39
    )
    sn39_launch_profile = (
        int(getattr(args, "netuid", -1)) == 39
        and not bool(getattr(args, "offline", False))
        and (sn39_broadcast or launch_preflight)
    )
    if sn39_launch_profile:
        pinned = {
            "network": "finney",
            "publisher_url": SN39_PUBLISHER_URL,
            "public_key_hex": DEFAULT_PUBLIC_KEY_HEX,
            "key_id": SN39_WEIGHT_POLICY_KEY_ID,
            "evidence_url": SN39_EVIDENCE_URL,
            "provenance_registry_keys_digest": SN39_REGISTRY_KEYS_DIGEST,
            "provenance_report_keys_digest": SN39_REPORT_KEYS_DIGEST,
            "provenance_index_keys_digest": SN39_INDEX_KEYS_DIGEST,
            "provenance_verifier_digest": SN39_VERIFIER_DIGEST,
            "provenance_source_revision": SN39_PRODUCER_REVISION,
            "provenance_mechanism": MECHANISM_DEFAULT,
            "provenance_burn_hotkey": SN39_BURN_HOTKEY,
        }
        mismatches = [
            name
            for name, expected in pinned.items()
            if (
                str(getattr(args, name, "")).strip().lower()
                if name == "network"
                else getattr(args, name, None)
            )
            != expected
        ]
        # The one profile field with more than one admissible value, and it is
        # still a CLOSED membership test over two named contracts — the launch
        # pin and the v3 re-pin. A third value, including a legitimate
        # REQUIRE_POLICY_CHOICES entry like confidential_primary_v1, is a
        # mismatch. `provenance_mechanism` above stays pinned to v1 on purpose:
        # MECHANISM_ACCEPTED already admits v2/v3 evidence under a v1 pin, and
        # MECHANISM_BURN_FRACTION is looked up by the operator's own pin, so
        # widening it here would move the burn contract, not the evidence.
        if getattr(args, "require_policy", None) not in SN39_PINNED_REQUIRE_POLICIES:
            mismatches.append("require_policy")
        if Path(str(getattr(args, "state_file", ""))) != SN39_STATE_FILE:
            mismatches.append("state_file")
        provenance_mode = getattr(args, "provenance", "shadow") or "shadow"
        if provenance_mode not in {"shadow", "authority"}:
            mismatches.append("provenance")
        if mismatches:
            raise wire.VectorError(
                "SN39 mainnet broadcast differs from the immutable trust "
                f"profile: {', '.join(sorted(set(mismatches)))}"
            )
        runtime_root = _submission_runtime_root(args)
        if runtime_root != _VALIDATOR_RUNTIME_ROOT:
            raise wire.VectorError(
                "SN39 mainnet broadcast requires the canonical owner-only "
                f"runtime root {_VALIDATOR_RUNTIME_ROOT}"
            )
        # A pure relay carries Cathedral's signature to the pinned netuid and
        # burn; it has no launch of its own to complete, so demanding the gate
        # from it would only lock third parties off the subnet. A runtime that
        # originates weights or holds launch material still must set it.
        if (
            not launch_gate
            and _sn39_launch_obligation(args)
            and not bool(getattr(args, "require_completed_launch_for_broadcast", False))
            # Same beta waiver as _continuous_transition_required. Without it
            # here the waiver is self-cancelling: clearing the gate flag to
            # satisfy that branch trips this one instead.
            and not bool(getattr(args, "beta_skip_launch_ceremony", False))
        ):
            raise wire.VectorError(
                "SN39 broadcast from a weight-originating or launch-capable "
                "runtime requires the completed-launch gate"
            )
    if not launch_gate:
        return
    missing = [
        name
        for name in (
            "provenance_controlled_dir",
            "provenance_verifier_binary",
            "provenance_burn_hotkey",
        )
        if not getattr(args, name, None)
    ]
    launch_paths_match = (
        Path(str(getattr(args, "provenance_controlled_dir", "")))
        == SN39_LAUNCH_CONTROLLED_DIR
        and Path(str(getattr(args, "provenance_verifier_binary", "")))
        == SN39_LAUNCH_VERIFIER_BINARY
    )
    approval_path_match = (
        Path(str(getattr(args, "launch_approval_file", "")))
        == SN39_LAUNCH_APPROVAL_FILE
    )
    launch_action_matches = (
        launch_preflight
        and not bool(getattr(args, "broadcast", False))
        or not launch_preflight
        and bool(getattr(args, "broadcast", False))
    )
    if (
        bool(getattr(args, "offline", False))
        or not bool(getattr(args, "once", False))
        or max_submissions != 1
        or (getattr(args, "provenance", "shadow") or "shadow") != "shadow"
        or not launch_paths_match
        or not approval_path_match
        or not launch_action_matches
        or missing
    ):
        suffix = f"; missing {', '.join(missing)}" if missing else ""
        raise wire.VectorError(
            "bounded launch strict replay requires exactly one online action "
            "(read-only preflight or approved broadcast), --once, "
            "provenance=shadow, max_submissions=1, controlled evidence, verifier "
            f"binary, immutable launch/approval paths, and burn hotkey{suffix}"
        )
    _launch_release_config_identity(args)


def _pending_receipt_not_proven_remediation(exc: BaseException) -> str:
    """Tell an operator what is actually true about the durable attempt.

    The fenced-attempt wording is a claim about journal state — that an exact
    signed transaction exists, is unresolvable for now, and must never be
    replaced. It is the right thing to say after a receipt could not be
    re-proven. It is the wrong thing to say when the failure happened before
    the journal was ever opened, because it sends an operator to look for a
    transaction nobody signed, and it buries the configuration fault that the
    message now carries.
    """
    if getattr(exc, "fenced_attempt", True):
        return (
            "The exact signed attempt remains fenced. Wait for archive/RPC "
            "proof and restart to re-prove it; never submit a replacement."
        )
    return (
        "No signed attempt was recorded before this failure, so nothing is "
        "fenced and no replacement is owed. The detail above names the "
        "failing step: resolve it, then restart."
    )


def _tick_failure_remediation(args: Any) -> str:
    """Say whether this tick could have left a write behind, and nothing more.

    A failure before the chain call — a dry run, a refused gate, an
    unreachable feed, a preflight that would not resolve — signed nothing and
    submitted nothing, so telling its operator to go inspect the durable
    attempt state and a named extrinsic describes a transaction that does not
    exist. Only after ``set_weights_on_chain`` has actually entered the call
    is the ambiguity real, and that is the same marker the CHAIN failed /
    CHAIN ambiguous lifecycle split already uses.
    """
    if bool(getattr(args, "_tick_chain_call_started", False)):
        return (
            "The tick failed closed after the chain call had begun, so a write "
            "may have finalized: inspect the durable attempt state and named "
            "extrinsic before operator recovery. Automatic same-attempt retry "
            "remains blocked."
        )
    return (
        "The tick failed closed before any chain call, so nothing was signed, "
        "submitted, or finalized and there is no ambiguous write to inspect. "
        "The detail above names the cause; the next tick rebuilds every proof "
        "from a fresh finalized head."
    )


def run(args) -> int:
    """The validator loop, shared by `python -m scaffold.validator_thin` and the
    `cathedral-validator serve` console command. `args` is any object carrying
    the tick attributes (an argparse Namespace or a SimpleNamespace from the
    CLI's config loader)."""
    provenance_mode = getattr(args, "provenance", "shadow") or "shadow"
    if provenance_mode != "shadow":
        raise wire.VectorError(
            "recurring validator run supports only the shadow relay runtime; "
            f"got provenance={provenance_mode!r}"
        )
    _validate_runtime_contract(args)
    if bool(getattr(args, "require_full_provenance_for_broadcast", False)):
        if bool(getattr(args, "launch_preflight", False)):
            raise wire.VectorError(
                "read-only launch preflight must use run_launch_preflight"
            )
        args._launch_approval = _load_launch_approval(args)
    require_policy = getattr(args, "require_policy", None)
    if require_policy:
        _lifecycle("PIN active", f"policy={require_policy}")
    submission_authority, provenance_mode = "thin", "shadow"
    _lifecycle(
        "MODE active",
        "submission_authority=thin provenance=shadow "
        "(signed vector submits; provenance audits concurrently)",
    )
    _get_events(args).event(
        "STARTUP",
        stage="startup",
        status=INFO,
        detail=(
            f"submission_authority={submission_authority} "
            f"provenance={provenance_mode} policy_pin={require_policy or 'none'} "
            f"network={args.network} netuid={args.netuid}"
        ),
        authority=submission_authority,
        provenance_mode=provenance_mode,
        network=args.network,
        netuid=int(args.netuid),
        publisher_url=_safe_endpoint_label(args.publisher_url),
        weight_policy_public_key=getattr(args, "public_key_hex", None),
        weight_policy_key_id=getattr(args, "key_id", None),
        policy_pin=require_policy,
        provenance_evidence_url=_safe_endpoint_label(
            getattr(args, "evidence_url", None)
        ),
        provenance_registry_keys_digest=getattr(
            args, "provenance_registry_keys_digest", None
        ),
        provenance_report_keys_digest=getattr(
            args, "provenance_report_keys_digest", None
        ),
        provenance_index_keys_digest=getattr(
            args, "provenance_index_keys_digest", None
        ),
        provenance_verifier_digest=getattr(args, "provenance_verifier_digest", None),
        provenance_source_revision=getattr(args, "provenance_source_revision", None),
        provenance_mechanism=getattr(args, "provenance_mechanism", None),
        max_submissions=int(getattr(args, "max_submissions", 0) or 0),
        launch_full_gate=bool(
            getattr(args, "require_full_provenance_for_broadcast", False)
        ),
    )
    try:
        recovered = _recover_pending_launch_receipt(args)
    except _PostSignedSubmissionMismatch as exc:
        render.outcome(False, f"pending receipt contradiction: {stable_error(exc)}")
        _get_events(args).event(
            "PENDING_RECEIPT_CONTRADICTION",
            stage="result",
            status=FAIL,
            detail=str(exc)[:512],
            remediation=(
                "The exact signed attempt has a positive durable or historical "
                "contradiction. Keep every writer stopped and inspect the journal "
                "and named transaction; never submit a replacement."
            ),
        )
        return 1
    except _PendingReceiptNotProven as exc:
        render.outcome(False, f"pending receipt not proven: {stable_error(exc)}")
        _get_events(args).event(
            "PENDING_RECEIPT_NOT_PROVEN",
            stage="result",
            status=NOT_PROVEN,
            detail=str(exc)[:512],
            remediation=_pending_receipt_not_proven_remediation(exc),
        )
        return 1
    if recovered:
        event_fields: dict[str, Any] = {
            "stage": "result",
            "status": PASS,
            "detail": recovered.boundary_detail,
            "authority": (
                "full_provenance"
                if isinstance(recovered, RecoveredAuthoritySubmission)
                else "thin"
            ),
            "uid_count": len(recovered.uid_weights),
            "burn_uid": recovered.burn_uid,
            "burn_share": recovered.burn_share,
            "uid_weights": {str(uid): weight for uid, weight in recovered.uid_weights},
            "extrinsic_hash": recovered.extrinsic_hash,
            "block_hash": recovered.block_hash,
            "block_number": recovered.block_number,
        }
        if isinstance(recovered, RecoveredAuthoritySubmission):
            event_fields.update(
                {
                    "source_epoch": recovered.source_epoch,
                    "report_id": recovered.report_id,
                }
            )
        else:
            event_fields.update(
                {
                    "vector_id": recovered.vector_id,
                    "policy_version": recovered.policy_version,
                    "signed_vector_sha256": recovered.signed_vector_sha256,
                }
            )
        _get_events(args).event("PENDING_RECEIPT_RECOVERED", **event_fields)
        if bool(getattr(args, "once", False)):
            return 0
    consecutive_head_drift_rearms = 0
    while True:
        tick_ok = False
        head_drift_exhausted = False
        pre_sign_head_drift_retries = 0
        while True:
            # Every attempt, including each head-drift retry, starts having
            # reached no chain call. Reporting-only; see
            # `_mark_tick_reached_chain_call`.
            args._tick_chain_call_started = False
            try:
                tick_ok = tick(args)
                break
            except _RetryablePreSignHeadDrift as e:
                if pre_sign_head_drift_retries >= SN39_PRE_SIGN_HEAD_DRIFT_RETRIES:
                    head_drift_exhausted = True
                    render.outcome(
                        False, f"head drift, retries exhausted: {stable_error(e)}"
                    )
                    _get_events(args).event(
                        "PRE_SIGN_HEAD_DRIFT_RETRY_EXHAUSTED",
                        stage="submit",
                        status=FAIL,
                        detail=str(e)[:512],
                        remediation=(
                            "No transaction was signed. The next tick rebuilds "
                            "every chain, authorization, mapping, and evidence "
                            "proof from a new finalized head; it is re-armed on a "
                            "short delay instead of the full write interval "
                            "because losing this race reserves and signs nothing."
                        ),
                    )
                    break
                pre_sign_head_drift_retries += 1
                render.outcome(False, f"head drift, retrying: {stable_error(e)}")
                _get_events(args).event(
                    "PRE_SIGN_HEAD_DRIFT_RETRY",
                    stage="submit",
                    status=NOT_PROVEN,
                    detail=str(e)[:512],
                    retry=pre_sign_head_drift_retries,
                    retry_limit=SN39_PRE_SIGN_HEAD_DRIFT_RETRIES,
                    remediation=(
                        "The unsigned reservation was safely released. Rebuilding "
                        "the complete tick from a fresh finalized head now."
                    ),
                )
                # This exception can escape set_weights_on_chain only after its
                # fsynced common journal proved that no signed intent, receipt,
                # or broadcast exists. Calling tick again deliberately repeats
                # preflight, recurring authorization, UID mapping, provenance,
                # and inclusion-policy construction instead of reusing any
                # mutable proof from the aborted attempt.
                #
                # Offset first. A tick takes about one block, so retrying
                # immediately re-enters the block cycle at the phase that just
                # lost, which is what turned this budget of 8 attempts into one
                # attempt made 8 times. Nothing is reserved or signed while we
                # wait, so the only cost is latency inside a tick that would
                # otherwise be abandoned.
                phase_offset = _head_drift_phase_offset(
                    SN39_PRE_SIGN_HEAD_DRIFT_JITTER_SECS
                )
                if phase_offset > 0.0:
                    time.sleep(phase_offset)
                continue
            except _PostSignedSubmissionMismatch as e:
                render.outcome(
                    False, f"pending receipt contradiction: {stable_error(e)}"
                )
                _get_events(args).event(
                    "PENDING_RECEIPT_CONTRADICTION",
                    stage="result",
                    status=FAIL,
                    detail=str(e)[:512],
                    remediation=(
                        "The exact signed attempt has a positive durable or "
                        "historical contradiction. Keep every writer stopped and "
                        "inspect the journal and named transaction; never submit "
                        "a replacement."
                    ),
                )
                return 1
            except _PendingReceiptNotProven as e:
                render.outcome(False, f"pending receipt not proven: {stable_error(e)}")
                _get_events(args).event(
                    "PENDING_RECEIPT_NOT_PROVEN",
                    stage="result",
                    status=NOT_PROVEN,
                    detail=str(e)[:512],
                    remediation=_pending_receipt_not_proven_remediation(e),
                )
                # Restart enters the dedicated receipt-recovery path before any new
                # tick can reserve or sign another submission.
                return 1
            except _ChainWeightCooldownActive as e:
                # The subnet's `weights_rate_limit` and this unit's tick
                # interval are set independently, so a tick landing inside the
                # cooldown is routine chain behaviour, not a fault. Nothing was
                # reserved and nothing was signed, so there is no ambiguous
                # write to inspect and no remediation to offer — logging it at
                # FAIL only taught operators to ignore the log. The next tick
                # re-derives everything from a fresh finalized head; the daemon
                # owns the cadence, so this handler never sleeps or retries.
                tick_ok = True
                render.outcome(True, f"chain weight cooldown: {stable_error(e)}")
                _get_events(args).event(
                    "WEIGHT_COOLDOWN_SKIPPED",
                    stage="submit",
                    status=INFO,
                    detail=str(e)[:512],
                )
                break
            except _EpochRoomUnavailable as e:
                # The tick started too close to an epoch boundary to prove
                # mortal inclusion inside the epoch it was composed against.
                # Nothing was reserved and nothing was signed, and the refusal
                # itself names the block at which it clears — usually the very
                # next tick. That is the same shape as the chain's own
                # cooldown, so it gets the same treatment: its own code, at
                # NOT_PROVEN, out of the way of an alert on TICK_FAILED/FAIL.
                #
                # The tick still did not write, so `tick_ok` is deliberately
                # left False: a `--once` canary that skipped for epoch room
                # must not exit 0 and be read as a successful launch write.
                # Only the reporting changes here.
                render.outcome(False, f"epoch boundary too close: {stable_error(e)}")
                _get_events(args).event(
                    "EPOCH_ROOM_SKIPPED",
                    stage="submit",
                    status=NOT_PROVEN,
                    detail=str(e)[:512],
                    remediation=(
                        "No action. The tick refused before reserving or signing "
                        "anything because too few blocks remained in this epoch "
                        "to prove mortal inclusion; the detail names the block at "
                        "which it clears. Escalate only if it repeats across "
                        "several consecutive epochs."
                    ),
                )
                break
            except _ContinuousLaunchLocked as e:
                # The one refusal that will never clear on its own: this unit
                # is up and ticking and writing nothing, and will keep doing so
                # until a human runs one named command.
                render.outcome(False, f"continuous writes locked: {stable_error(e)}")
                _get_events(args).event(
                    "CONTINUOUS_LAUNCH_LOCKED",
                    stage="submit",
                    status=FAIL,
                    detail=str(e)[:512],
                    remediation=(
                        "This validator is writing no weights and will not start "
                        "on its own. Nothing was signed or submitted. Run "
                        "`cathedral-validator reconcile-launch` to independently "
                        "verify the finalized rewarded-set-gated launch, then "
                        "restart the loop."
                    ),
                )
                break
            except _SubmissionFenceRefused as e:
                # Local durable state, not the chain. The reservation is taken
                # immediately before the chain call precisely so a refusal here
                # leaves no ambiguous write — but nothing about the cause is
                # self-clearing, so this is a page.
                render.outcome(False, f"attempt fence refused: {stable_error(e)}")
                _get_events(args).event(
                    "SUBMISSION_FENCE_REFUSED",
                    stage="submit",
                    status=FAIL,
                    detail=str(e)[:512],
                    remediation=(
                        "The refusal happened before any chain call, so nothing "
                        "was signed, submitted, or finalized and there is no "
                        "ambiguous write to inspect. The cause is local and will "
                        "not clear by itself: inspect the runtime root's "
                        "durable attempt journal and lock for an unresolved "
                        "pending attempt, a second writer, or a path this unit "
                        "cannot write."
                    ),
                )
                break
            except Exception as e:  # noqa: BLE001 - loop resilience; sanitized below
                # Everything above has been lifted out of this handler because
                # it was answerable without a human. What is left is the
                # residual: TICK_FAILED at FAIL now means "a person has to look
                # at this", which is the only reading that makes an alert on it
                # worth keeping switched on.
                render.outcome(False, f"tick failed: {stable_error(e)}")
                _get_events(args).event(
                    "TICK_FAILED",
                    stage="result",
                    status=FAIL,
                    detail=str(e)[:512],
                    remediation=_tick_failure_remediation(args),
                )
                break
        if args.once:
            # A single run exits only after the background shadow audit's
            # outcome is captured and reported (bounded); a tick that ran
            # but did not succeed — or an audit outcome that could not be
            # captured — is a FAILED single run.
            shadow_ok = _drain_shadow_audit_once(args)
            return 0 if (tick_ok and shadow_ok) else 1
        # A head-drift exhaustion is the one outcome that neither reserved nor
        # signed anything AND is expected to clear within a block or two, so it
        # is the one outcome that must not cost a whole write interval. Every
        # other path (success, cooldown, contradiction, generic failure) keeps
        # the daemon's configured cadence exactly as before.
        if head_drift_exhausted and (
            consecutive_head_drift_rearms
            < SN39_PRE_SIGN_HEAD_DRIFT_REARM_MAX_CONSECUTIVE
        ):
            consecutive_head_drift_rearms += 1
            # Never lengthen a short interval: a fast cadence already re-arms
            # sooner than the drift re-arm would.
            #
            # The base delay is a whole number of block times (60s = 5 blocks),
            # so on its own it re-arms onto the same phase it just failed at.
            # The offset is what delivers the independence this re-arm was
            # always documented as having.
            rearm_secs = min(SN39_PRE_SIGN_HEAD_DRIFT_REARM_SECS, args.interval_secs)
            time.sleep(
                rearm_secs
                + _head_drift_phase_offset(SN39_PRE_SIGN_HEAD_DRIFT_JITTER_SECS)
            )
            continue
        consecutive_head_drift_rearms = 0
        time.sleep(args.interval_secs)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Cathedral thin validator (v4)")
    p.add_argument(
        "--publisher-url",
        default=os.environ.get(
            "CATHEDRAL_PUBLISHER_URL", "https://api.cathedral.computer"
        ),
    )
    p.add_argument(
        "--public-key-hex",
        default=os.environ.get(
            "CATHEDRAL_WEIGHT_POLICY_PUBLIC_KEY", DEFAULT_PUBLIC_KEY_HEX
        ),
        help="pinned Ed25519 public key (hex); defaults to Cathedral's published key",
    )
    p.add_argument(
        "--key-id",
        default=os.environ.get(
            "CATHEDRAL_WEIGHT_POLICY_KEY_ID", "cathedral-weight-policy"
        ),
    )
    p.add_argument("--network", default="finney")
    p.add_argument(
        "--chain-endpoint",
        default=os.environ.get(CHAIN_ENDPOINT_ENV, ""),
        help="connect to your own subtensor RPC node (ws/wss URL) instead of the "
        "public entrypoint; the network label is kept for signing. "
        f"Defaults to ${CHAIN_ENDPOINT_ENV}.",
    )
    p.add_argument("--netuid", type=int, default=39)
    p.add_argument(
        "--wallet-name", default=os.environ.get("BT_WALLET_NAME", "validator")
    )
    p.add_argument(
        "--wallet-hotkey", default=os.environ.get("BT_WALLET_HOTKEY", "default")
    )
    p.add_argument(
        "--state-file",
        default=os.environ.get(
            "CATHEDRAL_VALIDATOR_STATE",
            str(Path.home() / ".cathedral" / "thin_validator.json"),
        ),
    )
    p.add_argument(
        "--runtime-root",
        default=os.environ.get(
            "CATHEDRAL_VALIDATOR_RUNTIME_ROOT",
            str(_VALIDATOR_RUNTIME_ROOT),
        ),
        help="absolute owner-only submission-lock and ambiguity-journal directory",
    )
    p.add_argument("--interval-secs", type=float, default=1500.0)
    p.add_argument(
        "--max-submissions",
        type=int,
        default=int(os.environ.get("CATHEDRAL_VALIDATOR_MAX_SUBMISSIONS", "0")),
        help="optional local durable-attempt ceiling; 0 disables this extra "
        "ceiling, but SN39 recurring writes still require a separately signed "
        "bounded authorization; launch canary requires 1",
    )
    p.add_argument("--once", action="store_true", help="single tick, then exit")
    p.add_argument(
        "--offline",
        action="store_true",
        help="no chain access: verify + print only (CI / smoke)",
    )
    p.add_argument(
        "--broadcast",
        action="store_true",
        help="actually submit weights (default: dry-run)",
    )
    p.add_argument(
        "--require-full-provenance-for-broadcast",
        action="store_true",
        default=os.environ.get(
            "CATHEDRAL_VALIDATOR_REQUIRE_FULL_PROVENANCE_FOR_BROADCAST", ""
        )
        .strip()
        .lower()
        in {"1", "true", "yes", "on"},
        help="launch-only: require synchronous strict raw-evidence replay and exact "
        "vector agreement before the one permitted chain write",
    )
    p.add_argument(
        "--require-policy",
        dest="require_policy",
        default=os.environ.get("CATHEDRAL_VALIDATOR_REQUIRE_POLICY", "").strip()
        or REQUIRE_POLICY_VALIDATED_SUPPLY_V1,
        help="pin the validator to a signed policy contract. "
        "validated_supply_v1 locks the launch 90%% Intel TDX / "
        "10%% unadmitted GPU-to-burn allocation. "
        "Default: validated_supply_v1.",
    )
    # The recurring runtime has one submission posture. Authority-labelled
    # internals remain only for bounded launch-journal recovery and are not an
    # operator-selectable module mode.
    p.set_defaults(provenance="shadow")
    p.add_argument(
        "--evidence-url",
        default=os.environ.get("CATHEDRAL_EVIDENCE_URL", "") or None,
        help="public evidence base URL (default: <publisher-url>/v1/evidence)",
    )
    p.add_argument(
        "--evidence-dir",
        default=None,
        help="local evidence store directory (testing/reproduction)",
    )
    p.add_argument(
        "--provenance-registry-keys",
        default=os.environ.get("CATHEDRAL_PROVENANCE_REGISTRY_KEYS") or None,
        help="trusted policy-registry key file (JSON key_id -> base64)",
    )
    p.add_argument(
        "--provenance-registry-keys-digest",
        default=os.environ.get("CATHEDRAL_PROVENANCE_REGISTRY_KEYS_DIGEST") or None,
    )
    p.add_argument(
        "--provenance-report-keys",
        default=os.environ.get("CATHEDRAL_PROVENANCE_REPORT_KEYS") or None,
        help="trusted score-report key file (JSON key_id -> base64)",
    )
    p.add_argument(
        "--provenance-report-keys-digest",
        default=os.environ.get("CATHEDRAL_PROVENANCE_REPORT_KEYS_DIGEST") or None,
    )
    p.add_argument(
        "--provenance-index-keys",
        default=os.environ.get("CATHEDRAL_PROVENANCE_INDEX_KEYS") or None,
        help="trusted evidence-index key file (JSON key_id -> base64)",
    )
    p.add_argument(
        "--provenance-index-keys-digest",
        default=os.environ.get("CATHEDRAL_PROVENANCE_INDEX_KEYS_DIGEST") or None,
    )
    p.add_argument(
        "--provenance-verifier-digest",
        default=os.environ.get("CATHEDRAL_PROVENANCE_VERIFIER_DIGEST") or None,
        help="pinned Intel TDX verifier implementation digest (sha256:<hex>)",
    )
    p.add_argument(
        "--provenance-mechanism",
        default=os.environ.get("CATHEDRAL_PROVENANCE_MECHANISM", MECHANISM_DEFAULT),
        help="pinned versioned reward mechanism (default validated_supply_v1)",
    )
    p.add_argument(
        "--provenance-controlled-dir",
        default=os.environ.get("CATHEDRAL_PROVENANCE_CONTROLLED_DIR") or None,
        help="controlled-disclosure envelope directory (enables strict replay)",
    )
    p.add_argument(
        "--provenance-verifier-binary",
        default=os.environ.get("CATHEDRAL_PROVENANCE_VERIFIER_BINARY") or None,
        help="local pinned verifier binary for raw-evidence replay",
    )
    p.add_argument(
        "--provenance-source-revision",
        default=os.environ.get("CATHEDRAL_PROVENANCE_SOURCE_REVISION") or None,
        help="independent pin of the expected manifest source revision",
    )
    p.add_argument(
        "--provenance-burn-hotkey",
        default=os.environ.get("CATHEDRAL_PROVENANCE_BURN_HOTKEY") or None,
        help="pinned burn destination used to verify the signed vector contract",
    )
    p.add_argument("--provenance-index-max-age-secs", type=float, default=3600.0)
    p.add_argument(
        "--min-assurance",
        dest="min_assurance",
        choices=("receipts_only", "rewarded_set_proven", "full_over_epoch"),
        default=os.environ.get(
            "CATHEDRAL_PROVENANCE_MIN_ASSURANCE", "rewarded_set_proven"
        ),
        help="lowest assurance the shadow verifier treats as PROVEN (default "
        "rewarded_set_proven). NOT the thin write path's gate — attestation-"
        "verified/thin submits the signed vector after signature verification "
        "regardless. Opt down to receipts_only or up to full_over_epoch.",
    )
    p.add_argument(
        "--provenance-allow-private-hosts",
        action="store_true",
        help="testing only: permit evidence hosts on private ranges",
    )
    p.add_argument(
        "--jsonl",
        default=os.environ.get("CATHEDRAL_VALIDATOR_JSONL") or None,
        help="append the stable JSONL event stream to this file",
    )
    return p


def main() -> int:
    p = build_parser()
    args = p.parse_args()
    configured_mode = os.environ.get("CATHEDRAL_VALIDATOR_PROVENANCE", "").strip()
    if configured_mode and configured_mode.lower() != "shadow":
        p.error(
            "CATHEDRAL_VALIDATOR_PROVENANCE no longer selects a runtime mode; "
            "the recurring validator supports only the shadow relay. "
            f"authority/full was refused (got {configured_mode!r})"
        )
    if not args.public_key_hex:
        p.error(
            "--public-key-hex (or CATHEDRAL_WEIGHT_POLICY_PUBLIC_KEY) is required — "
            "validators must pin the orchestrator's signing key"
        )
    # Unconditional, NOT `if args.require_policy and ...`: the flag's default is
    # always a real pin, so an empty value is a value someone supplied, never an
    # absent one. Skipping the check on falsy conflated the two and let
    # `--require-policy ''` drop the allocation-contract pin in silence, leaving
    # one binary willing to map v2, v3, confidential_primary and legacy vectors
    # alike, which is the exact ambiguity the pin exists to remove.
    if args.require_policy not in REQUIRE_POLICY_CHOICES:
        p.error(
            f"--require-policy (or CATHEDRAL_VALIDATOR_REQUIRE_POLICY) must be one of "
            f"{', '.join(REQUIRE_POLICY_CHOICES)}; got {args.require_policy!r}"
        )
    # --chain-endpoint populates the env the resolver reads, so both the
    # validator_thin path and the ChainClient path honor it from one source.
    if args.chain_endpoint:
        os.environ[CHAIN_ENDPOINT_ENV] = args.chain_endpoint
    # A journal path this process cannot open is a configuration mistake, not a
    # crash: print the fix and exit 2. Non-zero, so a supervising unit still
    # treats it as a failed start.
    try:
        return run(args)
    except EventLogPathError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
