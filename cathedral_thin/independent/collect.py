"""Dry-run collect of one miner's TDX evidence over ``POST /v1/evidence``.

The miner's wire contract is COPIED here, not imported. The sandbox package that
serves this endpoint also carries a dispatcher, a scoring path, and a chain
writer; depending on it would drag all of that into a lineage whose whole claim
is that it has none. So the four things that have to agree byte-for-byte -- the
channel-binding canonical encoding, the tagged ``REPORT_DATA`` v2 preimage, the
request key set, and the response key set -- are restated here and pinned by a
test vector, the same way ``fetch_policy`` restated the feed client's peer rules
instead of calling them.

What this collect refuses, all fail-closed:

* anything but ``report_data_version=2`` with a channel binding. v1 bound a
  nonce and a hotkey but not the key that owns the transport, so a v1 quote
  proves a machine answered, not that THIS connection reached it;
* evidence *bundles* (``{"evidence": [tdx, gpu]}``) and any ``kind`` other than
  ``tdx``. The GPU path has its own collateral story and this lineage does not
  have it;
* any status other than 200, redirects included and named as such, so a 302 to
  somewhere else is a refusal rather than a hop;
* an unknown or missing key in either direction, a nonce or hotkey or binding
  that does not match what was asked, an unbounded body, an unbounded quote, an
  unbounded certificate chain, and a duplicate JSON key.

The transport is INJECTED and has no default. A default that dialed would make
"collect from a miner" reachable from a unit test and from a misconfigured
operator run, and there is no discovery yet to tell either one which axon is a
real miner -- that is still open in `cathedralai/cathedral-validator#120`.
Nothing here extracts a TLS SPKI from a live peer either; the caller supplies
the ``ChannelBinding`` it observed.

A PASS verdict from ``verify_collected`` is not mass. The live runner binds
integer ``verified_mass`` on a pinned-QVL ``ComputeAdapter`` after it has
re-derived work units. Until that happens, ``ComputeAdapter.probe`` returns
nothing and a funded Compute row still composes to ``BROADCAST_BLOCKED``.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from .canonical import parse_strict_json
from .compute import MAX_QUOTE_BYTES, ComputeAdapter, QuoteVerdict
from .constants import COMPUTE_FLEET_CAP
from .errors import CollectError, PolicyBundleError, PolicyFetchError
from .fetch_policy import validate_policy_url

# The nonce is 32 bytes: 16 attributing it to this validator, 16 of caller
# entropy. The prefix is not a secret and is not freshness; it exists so a quote
# collected by someone else cannot be replayed at this validator as its own
# challenge.
NONCE_BYTES = 32
NONCE_PREFIX_BYTES = 16
NONCE_ENTROPY_BYTES = 16

# The miner serves the CPU evidence response under this bound; a body over it is
# refused rather than truncated and parsed.
MAX_EVIDENCE_RESPONSE_BYTES = 128 * 1024
MAX_EVIDENCE_CERTIFICATES = 8
# Tighter than the serving side's per-certificate bound on purpose: the whole
# response is already capped, and a chain is a handful of X.509 leaves.
MAX_CERTIFICATE_BYTES = 16 * 1024
MAX_HOTKEY_BYTES = 256
# The hotkey bound inside REPORT_DATA is the serving side's, and it must be the
# serving side's exactly or the preimage differs.
MAX_REPORT_HOTKEY_BYTES = 512

CHANNEL_BINDING_DIGEST_BYTES = 32
CHANNEL_BINDING_TYPE_TLS = "tls_spki_sha256"
CHANNEL_BINDING_CANONICAL_PREFIX = b"cathedral.channel-binding\x00"

EVIDENCE_KIND_TDX = "tdx"
EVIDENCE_PATH = "/v1/evidence"

REPORT_DATA_V2_DOMAIN = b"cathedral.report-data\x00"
REPORT_DATA_V2_VERSION = 2

EVIDENCE_V2_REQUEST_KEYS = frozenset(
    {
        "nonce_hex",
        "assigned_hotkey",
        "report_data_version",
        "channel_binding_type",
        "channel_binding_digest_hex",
    }
)
EVIDENCE_V2_RESPONSE_KEYS = frozenset(
    {
        "kind",
        "quote_hex",
        "nonce_hex",
        "assigned_hotkey",
        "cert_chain_hex",
        "report_data_version",
        "channel_binding_type",
        "channel_binding_digest_hex",
    }
)

# Mixed case is tolerated on the wire for the quote and the certificate chain,
# because a serving side may hex-encode either way and the bytes are the same.
# It is NOT tolerated for the nonce: that one is compared against a string this
# process produced, so equality is the check.
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


@dataclass(frozen=True)
class ChannelBinding:
    """The digest of the public key that must own the protected channel.

    Only ``tls_spki_sha256`` is collected here. ``application_key_sha256`` is a
    second binding type the serving side supports, and admitting it would mean
    accepting a quote bound to a key that does not terminate the TLS connection
    the quote arrived over -- which is the property this whole exchange buys.
    """

    binding_type: str
    digest: bytes

    def __post_init__(self) -> None:
        if self.binding_type != CHANNEL_BINDING_TYPE_TLS:
            raise CollectError(
                f"channel binding type must be {CHANNEL_BINDING_TYPE_TLS!r}, "
                f"not {self.binding_type!r}"
            )
        if (
            not isinstance(self.digest, bytes)
            or len(self.digest) != CHANNEL_BINDING_DIGEST_BYTES
        ):
            raise CollectError(
                f"a channel binding digest must be exactly "
                f"{CHANNEL_BINDING_DIGEST_BYTES} bytes"
            )

    def canonical_bytes(self) -> bytes:
        """The domain-separated, length-delimited encoding of this binding."""
        name = self.binding_type.encode("ascii")
        return (
            CHANNEL_BINDING_CANONICAL_PREFIX
            + struct.pack(">H", len(name))
            + name
            + self.digest
        )


@dataclass(frozen=True)
class CollectedEvidence:
    """One miner's TDX evidence, checked against what was asked for.

    ``report_data`` is derived from the request's nonce, hotkey, and binding --
    never read off the response -- so the value handed to a quote verifier is
    the one this validator committed to before the miner answered.
    """

    kind: str
    quote: bytes
    nonce: bytes
    assigned_hotkey: str
    cert_chain: tuple[bytes, ...]
    channel_binding: ChannelBinding
    report_data: bytes


@dataclass(frozen=True)
class FleetTarget:
    """One machine in a miner's advertised fleet, with its own challenge."""

    url: str
    nonce: bytes
    channel_binding: ChannelBinding


@runtime_checkable
class EvidenceTransport(Protocol):
    """Performs one evidence POST and returns ``(status, raw_body)``.

    Injected by the caller. There is no implementation in this package: writing
    one would put a dialer behind a function whose destination nothing has
    validated as a miner yet.
    """

    def post(self, url: str, body: Mapping[str, object]) -> tuple[int, bytes]: ...


def _report_field(tag: int, value: bytes) -> bytes:
    if not 0 <= tag <= 255 or len(value) > 65535:
        raise CollectError("a REPORT_DATA field is out of bounds")
    return bytes((tag,)) + struct.pack(">H", len(value)) + value


def report_data_v2(
    nonce: bytes, miner_hotkey: str, channel_binding: ChannelBinding
) -> bytes:
    """The 64-byte ``REPORT_DATA`` a v2 quote must carry.

    Every variable-length field is tagged and length-delimited before SHA-512,
    so no two different (nonce, hotkey, binding) triples can share a preimage by
    sliding a byte from one field into the next. The encoding is fixed by the
    serving side and pinned by a test vector; changing it silently would make
    every honest quote fail verification.
    """
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
        raise CollectError(f"REPORT_DATA v2 nonce must be exactly {NONCE_BYTES} bytes")
    if not isinstance(miner_hotkey, str):
        raise CollectError("REPORT_DATA v2 hotkey must be a string")
    try:
        hotkey = miner_hotkey.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CollectError("REPORT_DATA v2 hotkey must be valid UTF-8") from exc
    if not hotkey or len(hotkey) > MAX_REPORT_HOTKEY_BYTES:
        raise CollectError(
            f"REPORT_DATA v2 hotkey must be 1..{MAX_REPORT_HOTKEY_BYTES} UTF-8 bytes"
        )
    if not isinstance(channel_binding, ChannelBinding):
        raise CollectError("REPORT_DATA v2 requires a supported channel binding")
    payload = b"".join(
        (
            REPORT_DATA_V2_DOMAIN,
            struct.pack(">H", REPORT_DATA_V2_VERSION),
            _report_field(1, nonce),
            _report_field(2, hotkey),
            _report_field(3, channel_binding.binding_type.encode("ascii")),
            _report_field(4, channel_binding.digest),
        )
    )
    return hashlib.sha512(payload).digest()


def mint_nonce(validator_ss58: str, *, entropy: bytes) -> bytes:
    """Return ``sha256(ss58)[:16] || entropy``, a nonce attributable to one key.

    The entropy is supplied by the caller (``os.urandom(16)`` in production).
    This function draws no process randomness of its own, so the audit-seed
    tests that deny ``random`` still hold on the collect path, and a test can
    pin a nonce without monkeypatching a global.
    """
    if (
        not isinstance(validator_ss58, str)
        or not validator_ss58
        or not validator_ss58.isascii()
    ):
        raise CollectError("the validator ss58 must be a non-empty ASCII string")
    if not isinstance(entropy, (bytes, bytearray)):
        raise CollectError("nonce entropy must be raw bytes")
    if len(entropy) != NONCE_ENTROPY_BYTES:
        raise CollectError(
            f"nonce entropy must be exactly {NONCE_ENTROPY_BYTES} bytes, "
            f"got {len(entropy)}"
        )
    prefix = hashlib.sha256(validator_ss58.encode("ascii")).digest()
    return prefix[:NONCE_PREFIX_BYTES] + bytes(entropy)


def evidence_url(url: str) -> str:
    """Return the validated ``/v1/evidence`` URL to POST, or raise.

    The transport rules are the policy fetch's rules. The path is then required
    to BE the evidence path: an operator naming a base URL gets the path
    appended, an operator naming the evidence endpoint gets it used as given,
    and anything else is a refusal rather than a rewrite of a reviewed config
    into a different resource.
    """
    try:
        endpoint = validate_policy_url(url)
    except PolicyFetchError as exc:
        raise CollectError(
            f"the miner evidence URL is not a hardened public HTTPS URL: {exc}"
        ) from exc
    if endpoint.path not in ("/", EVIDENCE_PATH):
        raise CollectError(
            f"the miner evidence URL path must be {EVIDENCE_PATH!r} or empty, "
            f"not {endpoint.path!r}"
        )
    return f"https://{endpoint.host_header}{EVIDENCE_PATH}"


def _require_exact_keys(
    document: Mapping[str, Any], expected: frozenset[str], label: str
) -> None:
    present = set(document)
    unknown = sorted(present - expected)
    missing = sorted(expected - present)
    if unknown or missing:
        raise CollectError(
            f"{label} has unknown keys {unknown} and is missing {missing}; "
            f"v2 collect accepts exactly {sorted(expected)}"
        )


def _decode_hex(value: Any, label: str, *, max_bytes: int) -> bytes:
    """Decode a bounded, non-empty, even-length hex string.

    The character set is checked before ``bytes.fromhex`` because that function
    tolerates embedded whitespace, and ``"de ad"`` is not a hex encoding of
    anything a serving side produced.
    """
    if not isinstance(value, str) or not value or len(value) % 2:
        raise CollectError(f"{label} must be a non-empty even-length hex string")
    if any(character not in _HEX_DIGITS for character in value):
        raise CollectError(f"{label} is not hex")
    decoded = bytes.fromhex(value)
    if len(decoded) > max_bytes:
        raise CollectError(
            f"{label} decodes to {len(decoded)} bytes, over the {max_bytes} byte bound"
        )
    return decoded


def _require_assigned_hotkey(assigned_hotkey: str) -> str:
    if (
        not isinstance(assigned_hotkey, str)
        or not assigned_hotkey
        or not assigned_hotkey.isascii()
    ):
        raise CollectError("assigned_hotkey must be a non-empty ASCII string")
    if len(assigned_hotkey) > MAX_HOTKEY_BYTES:
        raise CollectError(
            f"assigned_hotkey is {len(assigned_hotkey)} characters, over the "
            f"{MAX_HOTKEY_BYTES} bound"
        )
    return assigned_hotkey


def _require_nonce(nonce: bytes) -> bytes:
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
        raise CollectError(f"the challenge nonce must be exactly {NONCE_BYTES} bytes")
    return nonce


def _response_channel_binding(response: Mapping[str, Any]) -> ChannelBinding:
    binding_type = response["channel_binding_type"]
    if not isinstance(binding_type, str):
        raise CollectError("the response channel binding type must be a string")
    digest = _decode_hex(
        response["channel_binding_digest_hex"],
        "channel_binding_digest_hex",
        max_bytes=CHANNEL_BINDING_DIGEST_BYTES,
    )
    return ChannelBinding(binding_type=binding_type, digest=digest)


def _post(
    transport: EvidenceTransport, url: str, body: Mapping[str, object]
) -> tuple[int, bytes]:
    if transport is None or not callable(getattr(transport, "post", None)):
        raise CollectError(
            "collect requires an injected EvidenceTransport; this package ships "
            "no dialer, because no discovery has validated that a URL is a miner"
        )
    answer = transport.post(url, body)
    if not isinstance(answer, tuple) or len(answer) != 2:
        raise CollectError("the evidence transport must return (status, body)")
    status, raw = answer
    if isinstance(status, bool) or not isinstance(status, int):
        raise CollectError("the evidence transport must return an integer status")
    if not isinstance(raw, (bytes, bytearray)):
        raise CollectError("the evidence transport must return a raw byte body")
    return status, bytes(raw)


def collect_evidence(
    *,
    url: str,
    assigned_hotkey: str,
    nonce: bytes,
    channel_binding: ChannelBinding,
    transport: EvidenceTransport,
) -> CollectedEvidence:
    """POST one v2 evidence challenge and return the checked response.

    Nothing about the returned evidence is taken on the miner's word: the nonce,
    the hotkey, and the binding are all compared against what was asked, and the
    expected ``REPORT_DATA`` is derived from the request rather than read from
    the response. The quote itself is not verified here -- that is the mandatory
    ``ComputeAdapter`` verifier's job, and it still yields no mass.
    """
    target = evidence_url(url)
    hotkey = _require_assigned_hotkey(assigned_hotkey)
    challenge = _require_nonce(nonce)
    if not isinstance(channel_binding, ChannelBinding):
        raise CollectError("collect requires a validated ChannelBinding")

    request: dict[str, object] = {
        "nonce_hex": challenge.hex(),
        "assigned_hotkey": hotkey,
        "report_data_version": REPORT_DATA_V2_VERSION,
        "channel_binding_type": channel_binding.binding_type,
        "channel_binding_digest_hex": channel_binding.digest.hex(),
    }
    _require_exact_keys(request, EVIDENCE_V2_REQUEST_KEYS, "the evidence request")

    status, raw = _post(transport, target, request)
    if status != 200:
        raise CollectError(
            f"the miner evidence POST answered {status}; only 200 is accepted "
            "and redirects are never followed"
        )
    if len(raw) > MAX_EVIDENCE_RESPONSE_BYTES:
        raise CollectError(
            f"the evidence response is {len(raw)} bytes, over the "
            f"{MAX_EVIDENCE_RESPONSE_BYTES} byte bound"
        )
    try:
        response = parse_strict_json(raw, max_bytes=MAX_EVIDENCE_RESPONSE_BYTES)
    except PolicyBundleError as exc:
        raise CollectError(f"the evidence response is not strict JSON: {exc}") from exc
    if not isinstance(response, dict):
        raise CollectError("the evidence response must be a JSON object")
    _require_exact_keys(response, EVIDENCE_V2_RESPONSE_KEYS, "the evidence response")

    version = response["report_data_version"]
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != REPORT_DATA_V2_VERSION
    ):
        raise CollectError(
            f"collect accepts report_data_version {REPORT_DATA_V2_VERSION} only; "
            f"v1 binds no channel and is refused"
        )
    if response["nonce_hex"] != challenge.hex():
        raise CollectError("the evidence response nonce does not match the challenge")
    if response["assigned_hotkey"] != hotkey:
        raise CollectError("the evidence response hotkey does not match the request")
    if _response_channel_binding(response) != channel_binding:
        raise CollectError("the evidence response channel binding does not match")
    if response["kind"] != EVIDENCE_KIND_TDX:
        raise CollectError(
            f"collect accepts kind {EVIDENCE_KIND_TDX!r} only, not {response['kind']!r}"
        )

    quote = _decode_hex(response["quote_hex"], "quote_hex", max_bytes=MAX_QUOTE_BYTES)
    chain_raw = response["cert_chain_hex"]
    if not isinstance(chain_raw, list) or len(chain_raw) > MAX_EVIDENCE_CERTIFICATES:
        raise CollectError(
            f"cert_chain_hex must be a JSON array of at most "
            f"{MAX_EVIDENCE_CERTIFICATES} entries"
        )
    cert_chain = tuple(
        _decode_hex(entry, "a cert_chain_hex entry", max_bytes=MAX_CERTIFICATE_BYTES)
        for entry in chain_raw
    )
    return CollectedEvidence(
        kind=EVIDENCE_KIND_TDX,
        quote=quote,
        nonce=challenge,
        assigned_hotkey=hotkey,
        cert_chain=cert_chain,
        channel_binding=channel_binding,
        report_data=report_data_v2(challenge, hotkey, channel_binding),
    )


def collect_miner_fleet(
    targets: Sequence[FleetTarget],
    *,
    assigned_hotkey: str,
    transport: EvidenceTransport,
) -> tuple[CollectedEvidence, ...]:
    """Collect from every machine one miner advertises, or from none of them.

    Over the cap the WHOLE miner is refused rather than the list being truncated
    to the first ``COMPUTE_FLEET_CAP`` entries. A miner that could pad its fleet
    until only the machines it chose get audited has a cheaper cheat than
    running the fleet it advertised.
    """
    if not isinstance(targets, Sequence) or isinstance(targets, (str, bytes)):
        raise CollectError("a miner fleet must be a sequence of FleetTarget")
    if any(not isinstance(target, FleetTarget) for target in targets):
        raise CollectError("a miner fleet must be a sequence of FleetTarget")
    if len(targets) > COMPUTE_FLEET_CAP:
        raise CollectError(
            f"the miner advertised {len(targets)} machines, over the "
            f"{COMPUTE_FLEET_CAP} cap; the whole miner is refused for this epoch "
            "rather than the fleet being truncated"
        )
    nonces = {target.nonce for target in targets}
    if len(nonces) != len(targets):
        raise CollectError(
            "each machine in a fleet must be challenged with its own nonce"
        )
    return tuple(
        collect_evidence(
            url=target.url,
            assigned_hotkey=assigned_hotkey,
            nonce=target.nonce,
            channel_binding=target.channel_binding,
            transport=transport,
        )
        for target in targets
    )


def verify_collected(
    adapter: ComputeAdapter, collected: CollectedEvidence
) -> QuoteVerdict:
    """Hand collected evidence to the lane's mandatory quote verifier.

    A ``PASS`` here means one quote verified against the ``REPORT_DATA`` this
    validator committed to. It is not mass: Compute broadcast allocation is 0,
    and the dry-run verifier behind this adapter has no published build digest
    anyone outside could reproduce a verdict with.
    """
    if not isinstance(collected, CollectedEvidence):
        raise CollectError("verify_collected takes CollectedEvidence")
    if not isinstance(adapter, ComputeAdapter):
        raise CollectError("verify_collected takes a ComputeAdapter")
    return adapter.verify_quote(
        collected.quote, expected_report_data=collected.report_data
    )


__all__ = [
    "CHANNEL_BINDING_CANONICAL_PREFIX",
    "CHANNEL_BINDING_DIGEST_BYTES",
    "CHANNEL_BINDING_TYPE_TLS",
    "EVIDENCE_KIND_TDX",
    "EVIDENCE_PATH",
    "EVIDENCE_V2_REQUEST_KEYS",
    "EVIDENCE_V2_RESPONSE_KEYS",
    "MAX_CERTIFICATE_BYTES",
    "MAX_EVIDENCE_CERTIFICATES",
    "MAX_EVIDENCE_RESPONSE_BYTES",
    "MAX_HOTKEY_BYTES",
    "MAX_REPORT_HOTKEY_BYTES",
    "NONCE_BYTES",
    "NONCE_ENTROPY_BYTES",
    "NONCE_PREFIX_BYTES",
    "REPORT_DATA_V2_DOMAIN",
    "REPORT_DATA_V2_VERSION",
    "ChannelBinding",
    "CollectError",
    "CollectedEvidence",
    "EvidenceTransport",
    "FleetTarget",
    "collect_evidence",
    "collect_miner_fleet",
    "evidence_url",
    "mint_nonce",
    "report_data_v2",
    "verify_collected",
]
