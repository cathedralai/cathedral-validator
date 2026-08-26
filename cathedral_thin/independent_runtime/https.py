"""Public-HTTPS EvidenceTransport for miner ``POST /v1/evidence``.

Pinned TCP to a globally-routable address, TLS SNI for the original host,
no redirects, bounded body. The TLS SPKI digest is observed from the peer
certificate so collect can bind v2 REPORT_DATA to this connection.
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
    MAX_EVIDENCE_RESPONSE_BYTES,
    ChannelBinding,
)
from cathedral_thin.independent.constants import POLICY_USER_AGENT
from cathedral_thin.independent.fetch_policy import (
    getaddrinfo_bounded,
    validate_policy_url,
    validated_peer_ips,
)

from .errors import IndependentLiveError

DEFAULT_TIMEOUT = 30.0


def tls_context_for_evidence(host: str) -> ssl.SSLContext:
    """TLS context for one evidence POST.

    Miner axons are advertised as IPs and typically present an in-guest
    self-signed certificate. Hostname/CA verification cannot authenticate
    that peer. v2 REPORT_DATA binds the observed TLS SPKI, so a different
    cert cannot satisfy the quote. Public hostnames still use default
    verification.
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


class HttpsEvidenceTransport:
    """Injected EvidenceTransport that dials public HTTPS and records SPKI."""

    def __init__(self, *, timeout: float = DEFAULT_TIMEOUT) -> None:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise IndependentLiveError("evidence transport timeout must be positive")
        self.timeout = float(timeout)
        self.last_spki: bytes | None = None

    def observe_binding(self, url: str) -> ChannelBinding:
        """Handshake and return the TLS SPKI binding without posting."""
        self._round_trip(url, None)
        if self.last_spki is None:
            raise IndependentLiveError("TLS handshake produced no SPKI digest")
        return ChannelBinding(CHANNEL_BINDING_TYPE_TLS, self.last_spki)

    def post(self, url: str, body: Mapping[str, object]) -> tuple[int, bytes]:
        if not isinstance(body, Mapping):
            raise IndependentLiveError("evidence POST body must be a mapping")
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return self._round_trip(url, encoded)

    def _round_trip(self, url: str, body: bytes | None) -> tuple[int, bytes]:
        endpoint = validate_policy_url(url)
        deadline = time.monotonic() + self.timeout

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
                return self._post_peer(endpoint, peer_ip, body, remaining)
            except (OSError, IndependentLiveError) as exc:
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
            peer_cert = connection.sock.getpeercert(binary_form=True)
            self.last_spki = spki_sha256(bytes(peer_cert))
            if body is None:
                return 0, b""
            headers = {
                "Host": endpoint.host_header,
                "User-Agent": POLICY_USER_AGENT,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            connection.sock.settimeout(remaining())
            path = endpoint.path if endpoint.path else "/v1/evidence"
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            chunks: list[bytes] = []
            budget = MAX_EVIDENCE_RESPONSE_BYTES
            while True:
                connection.sock.settimeout(remaining())
                chunk = response.read(min(65536, budget + 1))
                if not chunk:
                    break
                budget -= len(chunk)
                if budget < 0:
                    raise IndependentLiveError(
                        "evidence response exceeded the collect body bound"
                    )
                chunks.append(chunk)
            return int(response.status), b"".join(chunks)
        finally:
            connection.close()


def axon_evidence_url(ip: str, port: int) -> str:
    """Build a collect URL from a serving axon. IPv6 is bracketed."""
    if not isinstance(ip, str) or not ip:
        raise IndependentLiveError("axon ip must be a non-empty string")
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        raise IndependentLiveError("axon port must be in 1..65535")
    host = f"[{ip}]" if ":" in ip else ip
    return f"https://{host}:{port}/v1/evidence"
