"""Escape room contest receipts as a weight source for the direct validator.

Decision 2026-10-27 (Fred): Escape room prizes are paid from SN94 emissions,
so this validator accepts contest receipts. The control plane
(bigailabs/polariscomputer, polaris/services/escape_contest/receipts.py) signs
each accepted break with an Ed25519 key from a pinned key set. This module
verifies receipts against that set: a key is accepted only if it was valid at
the receipt's planted_at time and is not revoked. The set is pinned by sha256
so a host cannot swap it silently. A legacy single-key .pub file still parses
as a one-key set. Receipts are counted once, kept for a fixed reward window
after the window was planted, and mapped to a UID registered at the cycle's
finalized anchor.

It is off unless the operator names a receipt source AND a positive weight
fraction. Off, the plan, its identity, its evidence digest and the signed
vector are byte-identical to a validator without this module.

The receipt body and canonical bytes mirror ``authorizing_body`` and
``_canonical`` upstream. The breaker is named by ``claim.breaker_hotkey``. The
upstream claim schema has no such field yet; because the claim sits inside the
signed body, a claim that carries it is covered by the signature without any
change to the receipt format. A receipt without it is refused here.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .direct_contract import DirectValidatorError

ESCAPE_RECEIPTS_SOURCE_ENV = "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE"
ESCAPE_WEIGHT_FRACTION_ENV = "CATHEDRAL_ESCAPE_WEIGHT_FRACTION"
ESCAPE_REWARD_WINDOW_ENV = "CATHEDRAL_ESCAPE_REWARD_WINDOW_SECONDS"

DEFAULT_REWARD_WINDOW_SECONDS = 7 * 24 * 3600
MAX_REWARD_WINDOW_SECONDS = 90 * 24 * 3600
# A receipt planted further in the future than this is refused, not deferred:
# the control plane stamps planted_at from its own clock.
MAX_FUTURE_SKEW_SECONDS = 300
MAX_FEED_BYTES = 4 * 1024 * 1024
MAX_FEED_RECEIPTS = 10_000
FEED_TIMEOUT_SECONDS = 10.0
# Leave time after the feed fetch for scoring, presign RPCs, and the write.
# A hung feed must not spend the rest of FULL_CYCLE_RESPONSE_DEADLINE_SECONDS.
FEED_DEADLINE_SLACK_SECONDS = 5.0
MAX_REPORTED_HOTKEYS = 32
# Hard cap so a mistyped 0.9 cannot give breakers almost the whole vector.
# The intended mainnet share is 5 percent (1/20), well under this.
MAX_WEIGHT_FRACTION = Fraction(1, 2)

RECEIPT_SCHEMA = "escape_stage_c_receipt_v0"
CLAIM_SCHEMA = "escape_practice_claim_v0"
NONCE_ORIGIN = "control_plane"
BREAKER_HOTKEY_FIELD = "breaker_hotkey"

# Vendored from bigailabs/polariscomputer docs/escape/contest-signer.ed25519.pub
# (also at config/escape/contest-signer.ed25519.pub). The sha256 pins the file
# bytes (the base64 key plus one newline), so a key edit here without the pin,
# or the reverse, fails at import.
PINNED_CONTEST_PUBKEY_B64 = "+aXKRPGn7pz+leENaILgiWkoQ5T/Cvcf6DJtMg83NDE="
PINNED_CONTEST_PUBKEY_FILE_SHA256 = (
    "3c0289ee9ab455bface317f1d5625987d2c50f699bc8e4da39ba5ab9c0cbe49a"
)
CONTEST_SIGNER_SET_SCHEMA = "cathedral_escape_contest_signers_v1"
LEGACY_SINGLE_KEY_ID = "legacy"
MAX_CONTEST_SIGNER_KEYS = 16
_KEY_ID_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
)
_SIGNER_SET_FIELDS = frozenset({"schema", "keys"})
_SIGNER_KEY_FIELDS = frozenset(
    {"id", "pubkey_b64", "not_before", "not_after", "revoked"}
)
# Canonical compact JSON of PINNED_CONTEST_SIGNERS_DOCUMENT plus one newline
# (the bytes of config/escape/contest-signers.json). The document and this pin
# must change together.
PINNED_CONTEST_SIGNERS_DOCUMENT: dict[str, object] = {
    "keys": [
        {
            "id": "contest-2026-10",
            "not_before": 0,
            "pubkey_b64": PINNED_CONTEST_PUBKEY_B64,
        }
    ],
    "schema": CONTEST_SIGNER_SET_SCHEMA,
}
PINNED_CONTEST_SIGNERS_SHA256 = (
    "0d958b32bbe2bedd5845ac37953f653ca6669f178d8d5041a8f392fc7fe5eb47"
)


class EscapeReceiptError(DirectValidatorError):
    """One receipt, or the receipt configuration, is refused."""


def _ed25519_public_key(pubkey_b64: str, *, label: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(pubkey_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EscapeReceiptError(f"{label} is not valid base64") from exc
    if len(raw) != 32:
        raise EscapeReceiptError(f"{label} is not 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def _pinned_public_key() -> Ed25519PublicKey:
    file_bytes = (PINNED_CONTEST_PUBKEY_B64 + "\n").encode("ascii")
    if hashlib.sha256(file_bytes).hexdigest() != PINNED_CONTEST_PUBKEY_FILE_SHA256:
        raise EscapeReceiptError("vendored contest key does not match its sha256 pin")
    return _ed25519_public_key(PINNED_CONTEST_PUBKEY_B64, label="vendored contest key")


PINNED_CONTEST_PUBKEY = _pinned_public_key()


@dataclass(frozen=True)
class ContestSignerKey:
    """One contest public key and the window in which it may sign."""

    key_id: str
    pubkey_b64: str
    not_before: float
    not_after: float | None
    revoked: bool
    public_key: Ed25519PublicKey

    def covers(self, when: float) -> bool:
        """True if this key may authorize a receipt planted at ``when``.

        Revoked keys never cover. The window is inclusive on both ends.
        """

        if self.revoked:
            return False
        if when < self.not_before:
            return False
        if self.not_after is not None and when > self.not_after:
            return False
        return True


@dataclass(frozen=True)
class ContestSignerSet:
    """Pinned contest keys. Lookup is by id; iteration is document order."""

    keys: tuple[ContestSignerKey, ...]
    source_sha256: str

    def key(self, key_id: str) -> ContestSignerKey | None:
        for item in self.keys:
            if item.key_id == key_id:
                return item
        return None


def _unix_time(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EscapeReceiptError(f"{label} must be a number")
    try:
        instant = float(value)
    except OverflowError as exc:
        raise EscapeReceiptError(f"{label} must be a number") from exc
    if not math.isfinite(instant) or instant < 0:
        raise EscapeReceiptError(f"{label} must be a number")
    return instant


def _contest_key_id(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise EscapeReceiptError("contest key id required")
    if any(ch not in _KEY_ID_CHARS for ch in value):
        raise EscapeReceiptError("contest key id is not printable ASCII")
    return value


def _parse_signer_key(row: object, *, index: int) -> ContestSignerKey:
    label = f"contest key {index}"
    if not isinstance(row, dict):
        raise EscapeReceiptError(f"{label} must be an object")
    extra = set(row) - _SIGNER_KEY_FIELDS
    if extra:
        raise EscapeReceiptError(f"{label} has unknown fields")
    key_id = _contest_key_id(row.get("id"))
    pubkey_b64 = row.get("pubkey_b64")
    if not isinstance(pubkey_b64, str) or not pubkey_b64:
        raise EscapeReceiptError(f"{label} pubkey_b64 required")
    not_before = _unix_time(row.get("not_before", 0), f"{label} not_before")
    if "not_after" in row and row["not_after"] is not None:
        not_after = _unix_time(row["not_after"], f"{label} not_after")
        if not_after < not_before:
            raise EscapeReceiptError(f"{label} not_after precedes not_before")
    else:
        not_after = None
    revoked = row.get("revoked", False)
    if not isinstance(revoked, bool):
        raise EscapeReceiptError(f"{label} revoked must be a boolean")
    return ContestSignerKey(
        key_id=key_id,
        pubkey_b64=pubkey_b64,
        not_before=not_before,
        not_after=not_after,
        revoked=revoked,
        public_key=_ed25519_public_key(pubkey_b64, label=label),
    )


def parse_contest_signers(
    document: object,
    *,
    source_sha256: str | None = None,
) -> ContestSignerSet:
    """Parse a key-set object. Does not check the sha256 pin."""

    if not isinstance(document, dict):
        raise EscapeReceiptError("contest signer set must be an object")
    extra = set(document) - _SIGNER_SET_FIELDS
    if extra:
        raise EscapeReceiptError("contest signer set has unknown fields")
    if document.get("schema") != CONTEST_SIGNER_SET_SCHEMA:
        raise EscapeReceiptError("unsupported contest signer set schema")
    rows = document.get("keys")
    if not isinstance(rows, list) or not rows:
        raise EscapeReceiptError("contest signer set keys required")
    if len(rows) > MAX_CONTEST_SIGNER_KEYS:
        raise EscapeReceiptError("contest signer set has too many keys")
    keys: list[ContestSignerKey] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        key = _parse_signer_key(row, index=index)
        if key.key_id in seen:
            raise EscapeReceiptError("contest signer set has duplicate key ids")
        seen.add(key.key_id)
        keys.append(key)
    pin = (
        source_sha256
        or hashlib.sha256(
            json.dumps(
                document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
            + b"\n"
        ).hexdigest()
    )
    return ContestSignerSet(keys=tuple(keys), source_sha256=pin)


def parse_contest_signers_bytes(raw: bytes) -> ContestSignerSet:
    """JSON key set, or a legacy one-line base64 .pub file."""

    digest = hashlib.sha256(raw).hexdigest()
    stripped = raw.strip()
    if not stripped:
        raise EscapeReceiptError("contest signer set is empty")
    if stripped.startswith(b"{"):
        try:
            document = json.loads(raw)
        except ValueError as exc:
            raise EscapeReceiptError("contest signer set is not JSON") from exc
        return parse_contest_signers(document, source_sha256=digest)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EscapeReceiptError("contest signer set is not ASCII") from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise EscapeReceiptError("legacy contest key file must be one base64 line")
    return parse_contest_signers(
        {
            "schema": CONTEST_SIGNER_SET_SCHEMA,
            "keys": [
                {
                    "id": LEGACY_SINGLE_KEY_ID,
                    "not_before": 0,
                    "pubkey_b64": lines[0],
                }
            ],
        },
        source_sha256=digest,
    )


def load_contest_signers(raw: bytes, *, expected_sha256: str) -> ContestSignerSet:
    """Parse a key set and refuse it if the bytes do not match the pin."""

    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_sha256:
        raise EscapeReceiptError("contest signer set does not match its sha256 pin")
    return parse_contest_signers_bytes(raw)


def _pinned_signer_set() -> ContestSignerSet:
    raw = (
        json.dumps(
            PINNED_CONTEST_SIGNERS_DOCUMENT,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        + b"\n"
    )
    return load_contest_signers(raw, expected_sha256=PINNED_CONTEST_SIGNERS_SHA256)


PINNED_CONTEST_SIGNERS = _pinned_signer_set()


def canonical_bytes(document: object) -> bytes:
    """The control plane's signing bytes: sorted keys, compact, ASCII."""

    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def authorizing_body(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": receipt.get("schema"),
        "window_id": receipt.get("window_id"),
        "room_id": receipt.get("room_id"),
        "host_nonce": receipt.get("host_nonce"),
        "nonce_origin": receipt.get("nonce_origin"),
        "planted_at": receipt.get("planted_at"),
        "claim": receipt.get("claim"),
    }


@dataclass(frozen=True)
class VerifiedEscape:
    digest: str
    window_id: str
    room_id: str
    breaker_hotkey: str
    planted_at: float
    key_id: str = ""


def _nonempty_str(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EscapeReceiptError(f"{label} required")
    return value


def _check_claim(
    claim: object, *, window_id: str, room_id: str, host_nonce: str
) -> str:
    """Upstream ``accept_claim`` plus the nonce match; returns the breaker."""

    if not isinstance(claim, dict):
        raise EscapeReceiptError("claim must be an object")
    if claim.get("schema") != CLAIM_SCHEMA:
        raise EscapeReceiptError("unsupported claim schema")
    if claim.get("target") != "host":
        raise EscapeReceiptError("claim target must be host")
    if claim.get("window_id") != window_id or claim.get("room_id") != room_id:
        raise EscapeReceiptError("claim window_id/room_id mismatch")
    commands = claim.get("commands")
    if not isinstance(commands, list) or not commands:
        raise EscapeReceiptError("claim commands required")
    for command in commands:
        if not isinstance(command, dict) or command.get("attested_room") != room_id:
            raise EscapeReceiptError("claim attested_room must equal room_id")
    token = claim.get("proof_token")
    if (
        not isinstance(token, dict)
        or token.get("kind") != "host_nonce"
        or token.get("window_id") != window_id
        or token.get("nonce") != host_nonce
    ):
        raise EscapeReceiptError("claim proof token does not match the host nonce")
    hotkey = claim.get(BREAKER_HOTKEY_FIELD)
    if not isinstance(hotkey, str) or not hotkey or len(hotkey) > 64:
        raise EscapeReceiptError("receipt names no breaker hotkey")
    return hotkey


def _candidate_signers(
    receipt: Mapping[str, Any],
    *,
    signers: ContestSignerSet,
    planted_at: float,
) -> tuple[ContestSignerKey, ...]:
    """Keys that may verify this receipt.

    A named ``key_id`` must exist, not be revoked, and cover ``planted_at``.
    A receipt with no ``key_id`` may match any covering key (legacy receipts).
    """

    if "key_id" in receipt:
        key = signers.key(_contest_key_id(receipt.get("key_id")))
        if key is None:
            raise EscapeReceiptError("unknown contest key id")
        if key.revoked:
            raise EscapeReceiptError("contest key is revoked")
        if not key.covers(planted_at):
            raise EscapeReceiptError("contest key was not valid at planted_at")
        return (key,)
    covering = tuple(key for key in signers.keys if key.covers(planted_at))
    if not covering:
        raise EscapeReceiptError("contest key was not valid at planted_at")
    return covering


def verify_escape_receipt(
    receipt: object,
    *,
    pubkey: Ed25519PublicKey | None = None,
    signers: ContestSignerSet | None = None,
) -> VerifiedEscape:
    """Verify one receipt against the pinned contest signer set.

    ``pubkey`` is the historical test hook: verify against exactly that key
    and ignore windows. Production callers leave it unset and use ``signers``
    or the vendored pin.
    """

    if not isinstance(receipt, dict):
        raise EscapeReceiptError("receipt must be an object")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise EscapeReceiptError("bad receipt schema")
    window_id = _nonempty_str(receipt.get("window_id"), "window_id")
    room_id = _nonempty_str(receipt.get("room_id"), "room_id")
    host_nonce = _nonempty_str(receipt.get("host_nonce"), "host_nonce")
    if receipt.get("nonce_origin") != NONCE_ORIGIN:
        raise EscapeReceiptError("nonce_origin must be control_plane")
    planted_at = receipt.get("planted_at")
    if isinstance(planted_at, bool) or not isinstance(planted_at, (int, float)):
        raise EscapeReceiptError("planted_at must be a positive number")
    # json.loads keeps integers of any size. math.isfinite() OverflowError on
    # those would abort the whole weight cycle, so convert first.
    try:
        planted = float(planted_at)
    except OverflowError as exc:
        raise EscapeReceiptError("planted_at must be a positive number") from exc
    if not math.isfinite(planted) or planted <= 0:
        raise EscapeReceiptError("planted_at must be a positive number")
    hotkey = _check_claim(
        receipt.get("claim"),
        window_id=window_id,
        room_id=room_id,
        host_nonce=host_nonce,
    )
    sig_b64 = receipt.get("sig")
    if not isinstance(sig_b64, str) or not sig_b64:
        raise EscapeReceiptError("sig required")
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EscapeReceiptError("sig is not valid base64") from exc
    body = canonical_bytes(authorizing_body(receipt))
    chosen_id = ""
    if pubkey is not None:
        try:
            pubkey.verify(sig, body)
        except InvalidSignature as exc:
            raise EscapeReceiptError(
                "contest signature rejected (non-pinned key)"
            ) from exc
        raw_id = receipt.get("key_id")
        chosen_id = raw_id if isinstance(raw_id, str) else ""
    else:
        last_exc: InvalidSignature | None = None
        matched: ContestSignerKey | None = None
        for key in _candidate_signers(
            receipt,
            signers=PINNED_CONTEST_SIGNERS if signers is None else signers,
            planted_at=planted,
        ):
            try:
                key.public_key.verify(sig, body)
            except InvalidSignature as exc:
                last_exc = exc
                continue
            matched = key
            break
        if matched is None:
            raise EscapeReceiptError(
                "contest signature rejected (non-pinned key)"
            ) from last_exc
        chosen_id = matched.key_id
    return VerifiedEscape(
        digest="sha256:" + hashlib.sha256(body).hexdigest(),
        window_id=window_id,
        room_id=room_id,
        breaker_hotkey=hotkey,
        planted_at=planted,
        key_id=chosen_id,
    )


@dataclass(frozen=True)
class EscapeReceiptConfig:
    source: str
    fraction: Fraction
    window_seconds: int = DEFAULT_REWARD_WINDOW_SECONDS


def _parse_fraction(raw: str) -> Fraction:
    try:
        value = Fraction(raw)
    except (ValueError, ZeroDivisionError) as exc:
        raise EscapeReceiptError(
            f"{ESCAPE_WEIGHT_FRACTION_ENV} is not a number"
        ) from exc
    if not 0 <= value <= MAX_WEIGHT_FRACTION:
        raise EscapeReceiptError(
            f"{ESCAPE_WEIGHT_FRACTION_ENV} must be in [0, {MAX_WEIGHT_FRACTION}]"
        )
    return value


def escape_config_from_environment(
    environ: Mapping[str, str] | None = None,
) -> EscapeReceiptConfig | None:
    """None (off) unless both a source and a positive fraction are set.

    A set but malformed value raises: an operator who asked for receipts and
    mistyped the fraction should see a refusal at start, not a silent off.
    """

    env = os.environ if environ is None else environ
    source = env.get(ESCAPE_RECEIPTS_SOURCE_ENV, "").strip()
    fraction = _parse_fraction(env.get(ESCAPE_WEIGHT_FRACTION_ENV, "").strip() or "0")
    if not source or fraction == 0:
        return None
    raw_window = env.get(ESCAPE_REWARD_WINDOW_ENV, "").strip()
    window = DEFAULT_REWARD_WINDOW_SECONDS
    if raw_window:
        try:
            window = int(raw_window)
        except ValueError as exc:
            raise EscapeReceiptError(
                f"{ESCAPE_REWARD_WINDOW_ENV} is not an integer"
            ) from exc
        if not 0 < window <= MAX_REWARD_WINDOW_SECONDS:
            raise EscapeReceiptError(
                f"{ESCAPE_REWARD_WINDOW_ENV} must be in (0, {MAX_REWARD_WINDOW_SECONDS}]"
            )
    _require_source(source)
    return EscapeReceiptConfig(source=source, fraction=fraction, window_seconds=window)


def _require_source(source: str) -> None:
    if source.startswith("https://"):
        try:
            parts = urllib.parse.urlsplit(source)
            port = parts.port
        except ValueError as exc:
            raise EscapeReceiptError("escape receipt URL is invalid") from exc
        if (
            parts.username
            or parts.password
            or parts.query
            or parts.fragment
            or not parts.hostname
            or (port is not None and not (1 <= port <= 65535))
        ):
            raise EscapeReceiptError(
                "escape receipt URL must be HTTPS with no userinfo, query or fragment"
            )
        return
    if "://" in source or not Path(source).is_absolute():
        raise EscapeReceiptError(
            "escape receipt source must be an https URL or an absolute path"
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _fetch_https(
    url: str,
    *,
    timeout: float = FEED_TIMEOUT_SECONDS,
    opener: Callable[..., Any] | None = None,
) -> bytes:
    """GET one HTTPS feed. Redirects are not followed."""

    if not math.isfinite(timeout) or timeout <= 0:
        raise EscapeReceiptError("escape receipt feed timeout is invalid")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "cathedral-validator-escape/1",
        },
        method="GET",
    )
    open_request = opener or urllib.request.build_opener(_NoRedirect()).open
    try:
        with open_request(request, timeout=timeout) as response:
            status = int(response.getcode())
            final_url = str(response.geturl())
            body = response.read(MAX_FEED_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise EscapeReceiptError(f"escape receipt feed HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        raise EscapeReceiptError("escape receipt feed is unavailable") from exc
    if status != 200:
        raise EscapeReceiptError(f"escape receipt feed HTTP {status}")
    try:
        final = urllib.parse.urlsplit(final_url)
    except ValueError as exc:
        raise EscapeReceiptError("escape receipt feed redirected off HTTPS") from exc
    if final.scheme != "https" or not final.hostname:
        raise EscapeReceiptError("escape receipt feed redirected off HTTPS")
    return body


def load_receipt_feed(
    source: str,
    *,
    fetch: Callable[[str], bytes] | None = None,
    timeout: float = FEED_TIMEOUT_SECONDS,
) -> list[object]:
    """Read a JSON list of receipts, or ``{"receipts": [...]}``."""

    _require_source(source)
    getter = (
        fetch if fetch is not None else (lambda url: _fetch_https(url, timeout=timeout))
    )
    if source.startswith("https://"):
        raw = getter(source)
    else:
        path = Path(source)
        if not path.is_file():
            raise EscapeReceiptError("escape receipt source is not a regular file")
        with path.open("rb") as handle:
            raw = handle.read(MAX_FEED_BYTES + 1)
    if len(raw) > MAX_FEED_BYTES:
        raise EscapeReceiptError("escape receipt feed is too large")
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise EscapeReceiptError("escape receipt feed is not JSON") from exc
    if isinstance(document, dict):
        document = document.get("receipts")
    if not isinstance(document, list):
        raise EscapeReceiptError("escape receipt feed is not a receipt list")
    if len(document) > MAX_FEED_RECEIPTS:
        raise EscapeReceiptError("escape receipt feed has too many receipts")
    return document


@dataclass(frozen=True)
class EscapeRound:
    """Verified, deduplicated, in-window, registered breaks for one cycle."""

    units_by_uid: tuple[tuple[int, int], ...]
    uid_hotkeys: tuple[tuple[int, str], ...]
    accepted_digests: tuple[str, ...]
    refused: Mapping[str, int] = field(default_factory=dict)
    unregistered_hotkeys: tuple[str, ...] = ()
    signer_set_sha256: str = ""
    accepted_key_ids: tuple[str, ...] = ()

    def evidence(self) -> dict[str, object]:
        return {
            "schema": "cathedral_escape_receipts_v1",
            "signer_pubkey_sha256": PINNED_CONTEST_PUBKEY_FILE_SHA256,
            "signer_set_sha256": self.signer_set_sha256
            or PINNED_CONTEST_SIGNERS_SHA256,
            "accepted_digests": list(self.accepted_digests),
            "units_by_uid": [list(row) for row in self.units_by_uid],
            "uid_hotkeys": [list(row) for row in self.uid_hotkeys],
            "accepted_key_ids": list(self.accepted_key_ids),
        }

    def summary(self) -> dict[str, object]:
        return {
            "accepted": len(self.accepted_digests),
            "units_by_uid": [list(row) for row in self.units_by_uid],
            "refused": dict(sorted(self.refused.items())),
            "unregistered_hotkeys": list(
                self.unregistered_hotkeys[:MAX_REPORTED_HOTKEYS]
            ),
        }


def score_escape_receipts(
    receipts: Iterable[object],
    *,
    registered: Mapping[str, int],
    validator_uid: int,
    now: float,
    window_seconds: int,
    pubkey: Ed25519PublicKey | None = None,
    signers: ContestSignerSet | None = None,
) -> EscapeRound:
    """One unit per receipt and per (window, room), inside the reward window.

    Replay: the same signed body seen twice (in one feed or across cycles) is
    the same digest and counts once. Two differently worded claims for one
    room in one window also count once: the first by (planted_at, digest).
    The window is measured from planted_at, which the signature binds.
    """

    refused: dict[str, int] = {}

    def refuse(reason: str) -> None:
        refused[reason] = refused.get(reason, 0) + 1

    verified: list[VerifiedEscape] = []
    for receipt in receipts:
        try:
            verified.append(
                verify_escape_receipt(receipt, pubkey=pubkey, signers=signers)
            )
        except EscapeReceiptError as exc:
            refuse("no_breaker_hotkey" if "breaker hotkey" in str(exc) else "invalid")
        except (OverflowError, ValueError, TypeError, UnicodeError):
            # One malformed feed entry must not abort miner weights.
            refuse("invalid")
    verified.sort(key=lambda item: (item.planted_at, item.digest))

    seen_digests: set[str] = set()
    seen_rooms: set[tuple[str, str]] = set()
    unregistered: list[str] = []
    units: dict[int, int] = {}
    hotkeys: dict[int, str] = {}
    accepted: list[str] = []
    accepted_key_ids: list[str] = []
    for item in verified:
        if item.digest in seen_digests:
            refuse("replay")
            continue
        seen_digests.add(item.digest)
        if item.planted_at > now + MAX_FUTURE_SKEW_SECONDS:
            refuse("future")
            continue
        if now - item.planted_at > window_seconds:
            refuse("expired")
            continue
        room = (item.window_id, item.room_id)
        if room in seen_rooms:
            refuse("duplicate_room")
            continue
        uid = registered.get(item.breaker_hotkey)
        if isinstance(uid, bool) or not isinstance(uid, int):
            refuse("unregistered")
            if item.breaker_hotkey not in unregistered:
                unregistered.append(item.breaker_hotkey)
            continue
        if uid == validator_uid:
            refuse("validator_self")
            continue
        # Only an awarded unit consumes the room. An unregistered or
        # validator-self receipt must not block a registered breaker.
        seen_rooms.add(room)
        units[uid] = units.get(uid, 0) + 1
        hotkeys[uid] = item.breaker_hotkey
        accepted.append(item.digest)
        if item.key_id and item.key_id not in accepted_key_ids:
            accepted_key_ids.append(item.key_id)
    used_pin = (
        PINNED_CONTEST_SIGNERS_SHA256 if signers is None else signers.source_sha256
    )
    return EscapeRound(
        units_by_uid=tuple(sorted(units.items())),
        uid_hotkeys=tuple(sorted(hotkeys.items())),
        accepted_digests=tuple(accepted),
        refused=refused,
        unregistered_hotkeys=tuple(unregistered),
        signer_set_sha256=used_pin,
        accepted_key_ids=tuple(accepted_key_ids),
    )


__all__ = [
    "BREAKER_HOTKEY_FIELD",
    "DEFAULT_REWARD_WINDOW_SECONDS",
    "ESCAPE_RECEIPTS_SOURCE_ENV",
    "ESCAPE_REWARD_WINDOW_ENV",
    "ESCAPE_WEIGHT_FRACTION_ENV",
    "FEED_DEADLINE_SLACK_SECONDS",
    "FEED_TIMEOUT_SECONDS",
    "MAX_FEED_BYTES",
    "MAX_FEED_RECEIPTS",
    "MAX_WEIGHT_FRACTION",
    "CONTEST_SIGNER_SET_SCHEMA",
    "ContestSignerKey",
    "ContestSignerSet",
    "EscapeReceiptConfig",
    "EscapeReceiptError",
    "EscapeRound",
    "LEGACY_SINGLE_KEY_ID",
    "PINNED_CONTEST_PUBKEY",
    "PINNED_CONTEST_PUBKEY_B64",
    "PINNED_CONTEST_PUBKEY_FILE_SHA256",
    "PINNED_CONTEST_SIGNERS",
    "PINNED_CONTEST_SIGNERS_DOCUMENT",
    "PINNED_CONTEST_SIGNERS_SHA256",
    "VerifiedEscape",
    "authorizing_body",
    "canonical_bytes",
    "escape_config_from_environment",
    "load_contest_signers",
    "load_receipt_feed",
    "parse_contest_signers",
    "parse_contest_signers_bytes",
    "score_escape_receipts",
    "verify_escape_receipt",
]
