"""Public-HTTPS transport for miner ``POST /v1/evidence`` and ``/v1/sat-work``.

Pinned TCP to a globally-routable address, TLS SNI for the original host,
no redirects, bounded body. The TLS SPKI digest is observed from the peer
certificate so collect can bind v2 REPORT_DATA to this connection.

The same transport carries the audit-work POST: the request path comes from the
validated URL, so a ``/v1/sat-work`` endpoint is dialed as itself. No
``Authorization`` header is sent, because this validator holds no miner bearer
token. A protocol-compliant axon serves the canonical audit instance
credential-free, the same way it serves ``/v1/evidence``. An axon that still
answers 401 yields zero units rather than a guess.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import time
from typing import Any, Mapping

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import load_der_x509_certificate

from cathedral_thin.independent.collect import (
    CHANNEL_BINDING_TYPE_TLS,
    EVIDENCE_PATH,
    MAX_EVIDENCE_RESPONSE_BYTES,
    ChannelBinding,
)
from cathedral_thin.independent.constants import POLICY_USER_AGENT
from cathedral_thin.independent.fetch_policy import (
    getaddrinfo_bounded,
    validate_policy_url,
    validated_peer_ips,
)
from cathedral_thin.independent.sat import MAX_SAT_RESPONSE_BYTES, SAT_WORK_PATH

from .errors import IndependentLiveError

DEFAULT_TIMEOUT = 30.0
VALIDATOR_REQUEST_HEADER = "X-Cathedral-Validator-Request"
MAX_VALIDATOR_REQUEST_HEADER_BYTES = 16 * 1024


def canonical_post_body(body: Mapping[str, object]) -> bytes:
    """Encode the exact JSON bytes sent to a miner.

    The signed validator request hashes these bytes.  Keeping the encoder in
    the transport module prevents the authorization document and the HTTP
    request from drifting onto two merely equivalent JSON encodings.
    """
    if not isinstance(body, Mapping):
        raise IndependentLiveError("evidence POST body must be a mapping")
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def tls_context_for_evidence(host: str) -> ssl.SSLContext:
    """TLS context for one evidence POST.

    Miner axons are advertised as IPs and terminate TLS *inside* the measured
    guest with a self-signed certificate. No public CA has ever seen that key,
    so CA/hostname verification cannot authenticate the peer: requiring it
    would refuse every honest TDX axon rather than catch a dishonest one.
    ``CERT_NONE`` for IP literals is the trust model here, not a relaxation of
    it.

    What authenticates the peer is the v2 REPORT_DATA binding of the TLS SPKI
    this connection observed, plus the guest refusing any ``channel_binding``
    that is not its own in-guest key. A different certificate on the wire has
    a different SPKI, so an honest guest will not quote it and the pinned QVL
    will not match REPORT_DATA against the SPKI that was observed.

    Public hostnames are authenticable the ordinary way and keep the default
    verification of ``ssl.create_default_context``.
    """
    context = ssl.create_default_context()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return context
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def spki_sha256(certificate_der: bytes) -> bytes:
    """SHA-256 of the peer certificate's SubjectPublicKeyInfo."""
    if not isinstance(certificate_der, bytes) or not certificate_der:
        raise IndependentLiveError("peer certificate is missing")
    certificate = load_der_x509_certificate(certificate_der)
    spki = certificate.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).digest()


def require_cert_chain_matches_peer(
    cert_chain: tuple[bytes, ...], peer_spki: bytes
) -> None:
    """Bind a collected ``cert_chain`` to the peer this connection hashed.

    Collect parses the chain out of the evidence body; only the process that
    ran the handshake knows which certificate the peer actually presented. An
    axon that echoes somebody else's leaf is refused here instead of leaving
    the field unread.

    An empty chain is allowed: the collect contract permits an empty
    ``cert_chain_hex``, and the SPKI binding does not depend on the miner
    echoing its own certificate back. Intermediates are neither walked nor
    pinned -- the leaf carries the key REPORT_DATA is bound to, and nothing
    above it is authenticable for a self-signed in-guest cert anyway.
    """
    if not isinstance(peer_spki, bytes) or len(peer_spki) != 32:
        raise IndependentLiveError("the observed peer SPKI digest must be 32 bytes")
    if not cert_chain:
        return
    leaf = cert_chain[0]
    try:
        load_der_x509_certificate(leaf)
    except Exception as exc:
        raise IndependentLiveError(
            f"the collected cert_chain leaf is not an X.509 certificate: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if spki_sha256(leaf) != peer_spki:
        raise IndependentLiveError(
            "the collected cert_chain is not the TLS peer this connection hashed"
        )


class HttpsEvidenceTransport:
    """Injected EvidenceTransport that dials public HTTPS and records SPKI."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        deadline_monotonic: float | None = None,
    ) -> None:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise IndependentLiveError("evidence transport timeout must be positive")
        if deadline_monotonic is not None and (
            isinstance(deadline_monotonic, bool)
            or not isinstance(deadline_monotonic, (int, float))
        ):
            raise IndependentLiveError("evidence transport deadline must be numeric")
        self.timeout = float(timeout)
        self.deadline_monotonic = (
            None if deadline_monotonic is None else float(deadline_monotonic)
        )
        self.last_spki: bytes | None = None

    def observe_binding(self, url: str) -> ChannelBinding:
        """Handshake and return the TLS SPKI binding without posting."""
        self._round_trip(url, None)
        if self.last_spki is None:
            raise IndependentLiveError("TLS handshake produced no SPKI digest")
        return ChannelBinding(CHANNEL_BINDING_TYPE_TLS, self.last_spki)

    def post(self, url: str, body: Mapping[str, object]) -> tuple[int, bytes]:
        return self._round_trip(url, canonical_post_body(body))

    def post_authorized(
        self,
        url: str,
        body: Mapping[str, object],
        authorization: str,
    ) -> tuple[int, bytes]:
        """POST with the one reviewed validator-request header.

        No generic header mapping is accepted.  In particular, callers cannot
        replace ``Host``, content framing, or the media type while continuing
        to claim the request bytes signed here were the bytes on the wire.
        """
        if (
            not isinstance(authorization, str)
            or not authorization
            or not authorization.isascii()
            or len(authorization) > MAX_VALIDATOR_REQUEST_HEADER_BYTES
            or "\r" in authorization
            or "\n" in authorization
        ):
            raise IndependentLiveError("validator request header is invalid")
        return self._round_trip(
            url,
            canonical_post_body(body),
            authorization=authorization,
        )

    def _round_trip(
        self,
        url: str,
        body: bytes | None,
        *,
        authorization: str | None = None,
    ) -> tuple[int, bytes]:
        endpoint = validate_policy_url(url)
        deadline = time.monotonic() + self.timeout
        if self.deadline_monotonic is not None:
            deadline = min(deadline, self.deadline_monotonic)

        def remaining() -> float:
            left = deadline - time.monotonic()
            if left <= 0:
                raise IndependentLiveError("evidence request exceeded its deadline")
            return left

        peer_ips = validated_peer_ips(
            getaddrinfo_bounded(endpoint.host, endpoint.port, remaining())
        )
        last_error: Exception | None = None
        for peer_ip in peer_ips:
            try:
                if authorization is None:
                    # Preserve the reviewed private seam used by legacy tests
                    # and injected transports byte-for-byte.
                    return self._post_peer(endpoint, peer_ip, body, remaining)
                return self._post_peer(
                    endpoint, peer_ip, body, remaining, authorization=authorization
                )
            except OSError as exc:
                # Connectivity only. IndependentLiveError is a contract
                # refusal from the peer we already reached (oversize SAT
                # body, missing SPKI, deadline). Failover would let another
                # A-record answer 200 and get paid. fetch_policy retries
                # OSError the same way and does not retry PolicyFetchError.
                last_error = exc
        raise IndependentLiveError(
            f"evidence host unreachable: {type(last_error).__name__}: {last_error}"
        )

    def _post_peer(
        self,
        endpoint: Any,
        peer_ip: str,
        body: bytes | None,
        remaining: Any,
        *,
        authorization: str | None = None,
    ) -> tuple[int, bytes]:
        class _Pinned(http.client.HTTPSConnection):
            chosen_ip = peer_ip

            def connect(self) -> None:
                raw = socket.create_connection(
                    (self.chosen_ip, endpoint.port), remaining()
                )
                raw.settimeout(remaining())
                self.sock = self._context.wrap_socket(
                    raw, server_hostname=endpoint.host
                )

        connection = _Pinned(
            endpoint.host,
            endpoint.port,
            timeout=remaining(),
            context=tls_context_for_evidence(endpoint.host),
        )
        try:
            connection.connect()
            peer_socket = connection.sock
            if peer_socket is None:
                raise IndependentLiveError("TLS handshake produced no peer socket")
            peer_cert = peer_socket.getpeercert(binary_form=True)
            self.last_spki = spki_sha256(bytes(peer_cert))
            if body is None:
                return 0, b""
            headers = {
                "Host": endpoint.host_header,
                "User-Agent": POLICY_USER_AGENT,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            if authorization is not None:
                headers[VALIDATOR_REQUEST_HEADER] = authorization
            peer_socket.settimeout(remaining())
            path = endpoint.path if endpoint.path else EVIDENCE_PATH
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            chunks: list[bytes] = []
            # The bound belongs to the resource, not to the transport: the
            # sealed SAT contract refuses a work body over 64 KiB rather than
            # truncating it, so a body the contract forbids is never handed
            # back here. Evidence keeps the 128 KiB collect bound.
            if path == SAT_WORK_PATH:
                budget = MAX_SAT_RESPONSE_BYTES
                oversize = "work response exceeded the sat-work body bound"
            else:
                budget = MAX_EVIDENCE_RESPONSE_BYTES
                oversize = "evidence response exceeded the collect body bound"
            while not response.isclosed():
                peer_socket.settimeout(remaining())
                chunk = response.read(min(65536, budget + 1))
                if not chunk:
                    break
                budget -= len(chunk)
                if budget < 0:
                    raise IndependentLiveError(oversize)
                chunks.append(chunk)
            return int(response.status), b"".join(chunks)
        finally:
            connection.close()


def _axon_origin(ip: str, port: int) -> str:
    if not isinstance(ip, str) or not ip:
        raise IndependentLiveError("axon ip must be a non-empty string")
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        raise IndependentLiveError("axon port must be in 1..65535")
    host = f"[{ip}]" if ":" in ip else ip
    return f"https://{host}:{port}"


def axon_origin(ip: str, port: int) -> str:
    """Public HTTPS origin for a serving axon."""

    return _axon_origin(ip, port)


def axon_evidence_url(ip: str, port: int) -> str:
    """Build a collect URL from a serving axon. IPv6 is bracketed."""
    return f"{_axon_origin(ip, port)}{EVIDENCE_PATH}"


def axon_sat_work_url(ip: str, port: int) -> str:
    """Build the audit-work URL from a serving axon. IPv6 is bracketed.

    Built from the axon, not by rewriting the evidence URL, so a config that
    named one resource never silently becomes a POST to the other.
    """
    return f"{_axon_origin(ip, port)}{SAT_WORK_PATH}"
