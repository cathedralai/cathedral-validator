"""Signed validator access and bounded direct fleet discovery.

This is the validator half of cathedral-sandbox issue #60's measured-worker
contract.  It signs with an injected Bittensor hotkey object and never loads,
prints, serializes, or returns private key material.  The signature covers the
exact canonical JSON bytes sent on the wire and the TLS SPKI observed before
the request.  A different body, path, worker, subnet, or channel key therefore
needs a different signature.

The older WORK_REQUEST_V2 draft established those bindings but never shipped.
The implemented worker wire is the smaller ``cathedral_validator_request_v1``
header used here.  The server-side validator qualification snapshot is not a
request field.  Miners verify that signed artifact from their own bounded path.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from bittensor_wallet import Keypair

from cathedral_thin.independent.canonical import canonical_bytes, parse_strict_json
from cathedral_thin.independent.collect import (
    CHANNEL_BINDING_TYPE_TLS,
    ChannelBinding,
)
from cathedral_thin.independent.constants import (
    MULTICOMPUTE_FLEET_CAP,
    NETUID,
)
from cathedral_thin.independent.fetch_policy import is_globally_routable_address

from .errors import IndependentLiveError
from .https import HttpsEvidenceTransport, canonical_post_body

VALIDATOR_REQUEST_SCHEMA = "cathedral_validator_request_v1"
WORKER_FLEET_SCHEMA = "cathedral_worker_fleet_v1"
VALIDATOR_REQUEST_HEADER = "X-Cathedral-Validator-Request"
FLEET_PATH = "/v1/fleet"
NETWORK = "finney"

MAX_REQUEST_LIFETIME_SECONDS = 120
MAX_REQUEST_HEADER_BYTES = 8 * 1024
MAX_FLEET_RESPONSE_BYTES = 64 * 1024
MAX_ENDPOINT_BYTES = 512

_PROTECTED_PATHS = frozenset(
    {FLEET_PATH, "/v1/evidence", "/v1/sat-work", "/v1/capabilities"}
)
_REQUEST_KEYS = frozenset(
    {
        "schema",
        "validator_hotkey",
        "worker_hotkey",
        "network",
        "netuid",
        "method",
        "path",
        "body_sha256",
        "channel_binding_type",
        "channel_binding_digest_hex",
        "nonce_hex",
        "issued_at",
        "expires_at",
        "signature",
    }
)
_FLEET_KEYS = frozenset({"schema", "worker_hotkey", "endpoints"})


def _require_hotkey(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise IndependentLiveError(f"{label} must be a Bittensor SS58 address")
    try:
        decoded = Keypair(ss58_address=value)
        public_key = bytes(decoded.public_key)
    except Exception as exc:
        raise IndependentLiveError(f"{label} must be a Bittensor SS58 address") from exc
    if len(public_key) != 32 or str(decoded.ss58_address) != value:
        raise IndependentLiveError(f"{label} must be a Bittensor SS58 address")
    return value


def _canonical_utc(moment: datetime) -> str:
    if moment.tzinfo is None or moment.utcoffset() != timedelta(0):
        raise IndependentLiveError("validator request time must be UTC")
    if moment.microsecond:
        raise IndependentLiveError(
            "validator request time must not contain fractional seconds"
        )
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _signing_hotkey(keypair: Any) -> str:
    address = _require_hotkey(
        getattr(keypair, "ss58_address", None), "validator hotkey"
    )
    if not callable(getattr(keypair, "sign", None)):
        raise IndependentLiveError("validator hotkey has no signing operation")
    return address


def build_validator_request_header(
    *,
    keypair: Any,
    worker_hotkey: str,
    method: str,
    path: str,
    body: bytes,
    channel_binding: ChannelBinding,
    nonce: bytes,
    issued_at: datetime,
    expires_at: datetime,
) -> str:
    """Return standard-base64 canonical JSON signed by ``keypair.sign``."""

    validator_hotkey = _signing_hotkey(keypair)
    worker = _require_hotkey(worker_hotkey, "worker hotkey")
    if method != "POST" or path not in _PROTECTED_PATHS:
        raise IndependentLiveError("validator request method or path is unsupported")
    if not isinstance(body, bytes):
        raise IndependentLiveError("validator request body must be bytes")
    if (
        not isinstance(channel_binding, ChannelBinding)
        or channel_binding.binding_type != CHANNEL_BINDING_TYPE_TLS
    ):
        raise IndependentLiveError(
            "validator request requires a TLS SPKI channel binding"
        )
    if not isinstance(nonce, bytes) or len(nonce) != 32:
        raise IndependentLiveError("validator request nonce must be 32 bytes")
    if not issued_at < expires_at:
        raise IndependentLiveError("validator request validity window is invalid")
    if expires_at - issued_at > timedelta(seconds=MAX_REQUEST_LIFETIME_SECONDS):
        raise IndependentLiveError("validator request validity window exceeds 120s")

    document: dict[str, object] = {
        "schema": VALIDATOR_REQUEST_SCHEMA,
        "validator_hotkey": validator_hotkey,
        "worker_hotkey": worker,
        "network": NETWORK,
        "netuid": NETUID,
        "method": method,
        "path": path,
        "body_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
        "channel_binding_type": channel_binding.binding_type,
        "channel_binding_digest_hex": channel_binding.digest.hex(),
        "nonce_hex": nonce.hex(),
        "issued_at": _canonical_utc(issued_at),
        "expires_at": _canonical_utc(expires_at),
    }
    try:
        signature = bytes(keypair.sign(canonical_bytes(document)))
    except Exception as exc:
        raise IndependentLiveError("validator hotkey could not sign request") from exc
    if len(signature) != 64:
        raise IndependentLiveError(
            "validator hotkey signing operation did not return 64 bytes"
        )
    document["signature"] = {
        "algorithm": "sr25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    if frozenset(document) != _REQUEST_KEYS:
        raise AssertionError("validator request schema drifted")
    encoded = canonical_bytes(document)
    if len(encoded) > MAX_REQUEST_HEADER_BYTES:
        raise IndependentLiveError("validator request header exceeds 8 KiB")
    return base64.b64encode(encoded).decode("ascii")


def validate_public_worker_endpoint(value: Any) -> str:
    """Return one canonical, explicit HTTPS origin on a public IP literal."""

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or not value.isascii()
        or len(value) > MAX_ENDPOINT_BYTES
    ):
        raise IndependentLiveError("fleet endpoint is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise IndependentLiveError("fleet endpoint has an invalid port") from exc
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or port is None
        or port == 0
    ):
        raise IndependentLiveError("fleet endpoint must be an explicit HTTPS origin")
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise IndependentLiveError("fleet endpoint must use an IP literal") from exc
    if not is_globally_routable_address(address):
        raise IndependentLiveError("fleet endpoint must use a globally routable IP")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    canonical = f"https://{host}:{port}"
    if value.rstrip("/") != canonical:
        raise IndependentLiveError(
            "fleet endpoint must use canonical IP and port spelling"
        )
    return canonical


def fleet_url(origin: str) -> str:
    return validate_public_worker_endpoint(origin) + FLEET_PATH


@dataclass(frozen=True)
class FleetDiscovery:
    worker_hotkey: str
    endpoints: tuple[str, ...]
    singleton_compatibility: bool


class SignedValidatorTransport:
    """EvidenceTransport that signs every protected POST after observing SPKI."""

    def __init__(
        self,
        transport: HttpsEvidenceTransport,
        *,
        keypair: Any,
        worker_hotkey: str,
        clock: Callable[[], datetime] | None = None,
        nonce_factory: Callable[[int], bytes] | None = None,
        expected_spki: bytes | None = None,
    ) -> None:
        if not isinstance(transport, HttpsEvidenceTransport):
            raise IndependentLiveError(
                "signed validator access requires the hardened HTTPS transport"
            )
        self.transport = transport
        self.keypair = keypair
        self.validator_hotkey = _signing_hotkey(keypair)
        self.worker_hotkey = _require_hotkey(worker_hotkey, "worker hotkey")
        self.clock = clock or (lambda: datetime.now(UTC))
        self.nonce_factory = nonce_factory or secrets.token_bytes
        if expected_spki is not None and (
            not isinstance(expected_spki, bytes) or len(expected_spki) != 32
        ):
            raise IndependentLiveError("expected TLS SPKI must be 32 bytes")
        self.expected_spki = expected_spki

    @property
    def last_spki(self) -> bytes | None:
        return self.transport.last_spki

    def observe_binding(self, url: str) -> ChannelBinding:
        return self.transport.observe_binding(url)

    def post(self, url: str, body: Mapping[str, object]) -> tuple[int, bytes]:
        try:
            path = urlsplit(url).path
        except ValueError as exc:
            raise IndependentLiveError("signed request URL is invalid") from exc
        if path not in _PROTECTED_PATHS:
            raise IndependentLiveError("signed request URL path is unsupported")
        encoded_body = canonical_post_body(body)
        binding = self.transport.observe_binding(url)
        if self.expected_spki is not None and binding.digest != self.expected_spki:
            raise IndependentLiveError(
                "TLS SPKI is not the attested chain-axon channel"
            )
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise IndependentLiveError("validator request clock must return UTC")
        issued_at = now.replace(microsecond=0)
        expires_at = issued_at + timedelta(seconds=MAX_REQUEST_LIFETIME_SECONDS)
        nonce = self.nonce_factory(32)
        if not isinstance(nonce, bytes) or len(nonce) != 32:
            raise IndependentLiveError("validator request nonce source failed")
        header = build_validator_request_header(
            keypair=self.keypair,
            worker_hotkey=self.worker_hotkey,
            method="POST",
            path=path,
            body=encoded_body,
            channel_binding=binding,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        answer = self.transport.post_authorized(url, body, header)
        if self.transport.last_spki != binding.digest:
            raise IndependentLiveError(
                "TLS SPKI changed between validator authorization and POST"
            )
        if (
            self.expected_spki is not None
            and self.transport.last_spki != self.expected_spki
        ):
            raise IndependentLiveError(
                "TLS SPKI changed away from the attested chain-axon channel"
            )
        return answer


def fetch_worker_fleet(
    *,
    primary_origin: str,
    worker_hotkey: str,
    transport: SignedValidatorTransport,
) -> FleetDiscovery:
    """Fetch one bounded fleet, with a 404-only singleton migration path."""

    primary = validate_public_worker_endpoint(primary_origin)
    hotkey = _require_hotkey(worker_hotkey, "worker hotkey")
    if not isinstance(transport, SignedValidatorTransport):
        raise IndependentLiveError("fleet discovery requires signed validator access")
    if transport.worker_hotkey != hotkey:
        raise IndependentLiveError("fleet transport is bound to another worker")
    status, raw = transport.post(primary + FLEET_PATH, {})
    if status == 404:
        return FleetDiscovery(hotkey, (primary,), True)
    if status != 200:
        raise IndependentLiveError(
            f"fleet POST answered {status}; only 200 or legacy 404 is accepted"
        )
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_FLEET_RESPONSE_BYTES:
        raise IndependentLiveError("fleet response exceeds its 64 KiB bound")
    try:
        document = parse_strict_json(bytes(raw), max_bytes=MAX_FLEET_RESPONSE_BYTES)
    except Exception as exc:
        raise IndependentLiveError("fleet response is not strict JSON") from exc
    if not isinstance(document, dict) or frozenset(document) != _FLEET_KEYS:
        raise IndependentLiveError("fleet response fields are invalid")
    if document["schema"] != WORKER_FLEET_SCHEMA or document["worker_hotkey"] != hotkey:
        raise IndependentLiveError("fleet response identity is invalid")
    raw_endpoints = document["endpoints"]
    if (
        not isinstance(raw_endpoints, list)
        or not raw_endpoints
        or len(raw_endpoints) > MULTICOMPUTE_FLEET_CAP
    ):
        raise IndependentLiveError(
            f"fleet endpoints must contain 1..{MULTICOMPUTE_FLEET_CAP} entries"
        )
    endpoints = tuple(validate_public_worker_endpoint(row) for row in raw_endpoints)
    if len(set(endpoints)) != len(endpoints):
        raise IndependentLiveError("fleet response contains duplicate endpoints")
    if endpoints[0] != primary or primary not in endpoints:
        raise IndependentLiveError(
            "fleet response does not retain its chain axon first"
        )
    return FleetDiscovery(hotkey, endpoints, False)


__all__ = [
    "FLEET_PATH",
    "MAX_FLEET_RESPONSE_BYTES",
    "MAX_REQUEST_HEADER_BYTES",
    "MAX_REQUEST_LIFETIME_SECONDS",
    "NETWORK",
    "VALIDATOR_REQUEST_HEADER",
    "VALIDATOR_REQUEST_SCHEMA",
    "WORKER_FLEET_SCHEMA",
    "FleetDiscovery",
    "SignedValidatorTransport",
    "build_validator_request_header",
    "fetch_worker_fleet",
    "fleet_url",
    "validate_public_worker_endpoint",
]
