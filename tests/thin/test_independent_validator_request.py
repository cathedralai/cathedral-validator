from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime

import pytest
import sr25519
from bittensor_wallet import Keypair

from cathedral_thin.independent.collect import ChannelBinding
from cathedral_thin.independent_runtime.errors import IndependentLiveError
from cathedral_thin.independent_runtime.https import HttpsEvidenceTransport
from cathedral_thin.independent_runtime.validator_request import (
    FLEET_PATH,
    VALIDATOR_REQUEST_HEADER,
    VALIDATOR_REQUEST_SCHEMA,
    WORKER_FLEET_SCHEMA,
    SignedValidatorTransport,
    build_validator_request_header,
    fetch_worker_fleet,
    validate_public_worker_endpoint,
)

NOW = datetime(2026, 8, 29, 12, 0, 0, tzinfo=UTC)
PRIMARY = "https://1.1.1.1:8081"
SECOND = "https://8.8.8.8:8081"
BINDING = ChannelBinding("tls_spki_sha256", b"s" * 32)


def alice() -> Keypair:
    return Keypair.create_from_uri("//Alice")


def bob() -> Keypair:
    return Keypair.create_from_uri("//Bob")


def decode_header(value: str) -> dict:
    return json.loads(base64.b64decode(value, validate=True))


def test_request_header_cross_verifies_with_worker_sr25519_primitive():
    keypair = alice()
    body = b'{"assigned_hotkey":"worker","seed":7}'
    header = build_validator_request_header(
        keypair=keypair,
        worker_hotkey=bob().ss58_address,
        method="POST",
        path="/v1/sat-work",
        body=body,
        channel_binding=BINDING,
        nonce=b"n" * 32,
        issued_at=NOW,
        expires_at=NOW.replace(second=59),
    )
    document = decode_header(header)
    signature = base64.b64decode(document.pop("signature")["value_base64"])
    canonical = json.dumps(
        document, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")
    assert sr25519.verify(signature, canonical, bytes(keypair.public_key)) is True
    assert document == {
        "schema": VALIDATOR_REQUEST_SCHEMA,
        "validator_hotkey": keypair.ss58_address,
        "worker_hotkey": bob().ss58_address,
        "network": "finney",
        "netuid": 39,
        "method": "POST",
        "path": "/v1/sat-work",
        "body_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
        "channel_binding_type": "tls_spki_sha256",
        "channel_binding_digest_hex": (b"s" * 32).hex(),
        "nonce_hex": (b"n" * 32).hex(),
        "issued_at": "2026-08-29T12:00:00Z",
        "expires_at": "2026-08-29T12:00:59Z",
    }


class StubHttps(HttpsEvidenceTransport):
    def __init__(self, status: int, response: bytes) -> None:
        super().__init__()
        self.status = status
        self.response = response
        self.authorized: list[tuple[str, dict, str]] = []

    def observe_binding(self, url: str) -> ChannelBinding:
        del url
        self.last_spki = BINDING.digest
        return BINDING

    def post_authorized(self, url: str, body: dict, authorization: str):
        self.authorized.append((url, body, authorization))
        self.last_spki = BINDING.digest
        return self.status, self.response


def signed_transport(
    status: int, response: bytes
) -> tuple[SignedValidatorTransport, StubHttps]:
    base = StubHttps(status, response)
    transport = SignedValidatorTransport(
        base,
        keypair=alice(),
        worker_hotkey=bob().ss58_address,
        clock=lambda: NOW,
        nonce_factory=lambda size: b"n" * size,
    )
    return transport, base


def fleet_body(endpoints=(PRIMARY, SECOND), **changes) -> bytes:
    document = {
        "schema": WORKER_FLEET_SCHEMA,
        "worker_hotkey": bob().ss58_address,
        "endpoints": list(endpoints),
    }
    document.update(changes)
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def test_signed_transport_hashes_the_exact_body_and_binds_observed_spki():
    transport, base = signed_transport(200, b"{}")
    assert transport.post(PRIMARY + FLEET_PATH, {}) == (200, b"{}")
    ((url, body, header),) = base.authorized
    assert url == PRIMARY + FLEET_PATH
    assert body == {}
    document = decode_header(header)
    assert document["body_sha256"] == "sha256:" + hashlib.sha256(b"{}").hexdigest()
    assert document["channel_binding_digest_hex"] == BINDING.digest.hex()
    assert VALIDATOR_REQUEST_HEADER == "X-Cathedral-Validator-Request"


def test_attested_primary_spki_must_stay_fixed_for_fleet_discovery():
    base = StubHttps(200, fleet_body())
    transport = SignedValidatorTransport(
        base,
        keypair=alice(),
        worker_hotkey=bob().ss58_address,
        expected_spki=b"x" * 32,
        clock=lambda: NOW,
        nonce_factory=lambda size: b"n" * size,
    )
    with pytest.raises(IndependentLiveError, match="attested chain-axon channel"):
        fetch_worker_fleet(
            primary_origin=PRIMARY,
            worker_hotkey=bob().ss58_address,
            transport=transport,
        )
    assert base.authorized == []


def test_fleet_fetch_is_bounded_and_primary_first():
    transport, _base = signed_transport(200, fleet_body())
    fleet = fetch_worker_fleet(
        primary_origin=PRIMARY,
        worker_hotkey=bob().ss58_address,
        transport=transport,
    )
    assert fleet.endpoints == (PRIMARY, SECOND)
    assert fleet.singleton_compatibility is False


def test_only_404_uses_the_single_chain_axon_compatibility_path():
    transport, _base = signed_transport(404, b"")
    fleet = fetch_worker_fleet(
        primary_origin=PRIMARY,
        worker_hotkey=bob().ss58_address,
        transport=transport,
    )
    assert fleet.endpoints == (PRIMARY,)
    assert fleet.singleton_compatibility is True
    for status in (400, 401, 403, 405, 500):
        transport, _base = signed_transport(status, b"")
        with pytest.raises(IndependentLiveError, match="only 200 or legacy 404"):
            fetch_worker_fleet(
                primary_origin=PRIMARY,
                worker_hotkey=bob().ss58_address,
                transport=transport,
            )


@pytest.mark.parametrize(
    "response, message",
    [
        (fleet_body(worker_hotkey=alice().ss58_address), "identity"),
        (fleet_body(endpoints=(PRIMARY, PRIMARY)), "duplicate"),
        (fleet_body(endpoints=(SECOND, PRIMARY)), "chain axon first"),
        (fleet_body(endpoints=()), "1..32"),
        (
            fleet_body(
                endpoints=tuple(f"https://1.1.1.1:{port}" for port in range(8000, 8033))
            ),
            "1..32",
        ),
        (b'{"schema":"cathedral_worker_fleet_v1","schema":"x"}', "strict JSON"),
    ],
)
def test_malformed_or_over_cap_fleet_never_falls_back(response, message):
    transport, _base = signed_transport(200, response)
    with pytest.raises(IndependentLiveError, match=message):
        fetch_worker_fleet(
            primary_origin=PRIMARY,
            worker_hotkey=bob().ss58_address,
            transport=transport,
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://1.1.1.1:8081",
        "https://1.1.1.1:0",
        "https://127.0.0.1:8081",
        "https://[64:ff9b::7f00:1]:8081",
        "https://[64:ff9b:1::7f00:1]:8081",
        "https://[::ffff:127.0.0.1]:8081",
        "https://[::7f00:1]:8081",
        "https://worker.example:8081",
        "https://user:pass@1.1.1.1:8081",
        "https://1.1.1.1:8081/v1/evidence",
        "https://1.1.1.1:8081?x=1",
    ],
)
def test_fleet_candidates_are_public_https_origins(endpoint):
    with pytest.raises(IndependentLiveError):
        validate_public_worker_endpoint(endpoint)
