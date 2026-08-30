"""Live runner: Workers listing, integer mass, and contributing compose."""

from __future__ import annotations

import argparse
import ast
import http.client
import http.server
import json
import ssl
import stat
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from _independent_fixtures import (
    ANCHOR_HASH,
    BOB,
    BURN_UID,
    CHARLIE,
    commitment_for,
)
from cathedral_thin.independent.collect import (
    CHANNEL_BINDING_TYPE_TLS,
    EVIDENCE_PATH,
    MAX_EVIDENCE_RESPONSE_BYTES,
    ChannelBinding,
    CollectedEvidence,
)
from cathedral_thin.independent.compose import STATUS_COMPOSED, compose_dry_run
from cathedral_thin.independent.compute import (
    COMPUTE_LANE,
    ComputeAdapter,
    QuoteVerdict,
)
from cathedral_thin.independent.constants import (
    BURN_HOTKEY,
    CANARY_HOTKEY,
    FINNEY_GENESIS_HASH,
    H,
    INDEPENDENT_CANARY_FILE,
    INDEPENDENT_STATE_FILE,
    REFUSE_HOTKEYS,
    TEMPO_BLOCKS,
)
from cathedral_thin.independent.errors import SatWorkError
from cathedral_thin.independent.inclusion import MetagraphView
from cathedral_thin.independent.journal import load_journal
from cathedral_thin.independent.sat import (
    MAX_SAT_RESPONSE_BYTES,
    SAT_WORK_PATH,
    SAT_WORK_UNIT_RULE,
    canonical_work_item,
    sat_work_url,
)
from cathedral_thin.independent_runtime import run as run_module
from cathedral_thin.independent_runtime.chain import (
    AXON_SKIP_REASONS,
    ServingAxon,
    scan_axons,
)
from cathedral_thin.independent_runtime.errors import (
    ChainClientError,
    IndependentLiveError,
    QuoteVerifyError,
)
from cathedral_thin.independent_runtime import https as https_mod
from cathedral_thin.independent_runtime.https import (
    HttpsEvidenceTransport,
    axon_evidence_url,
    axon_sat_work_url,
    require_cert_chain_matches_peer,
    spki_sha256,
    tls_context_for_evidence,
)
from cathedral_thin.independent_runtime.local_policy import (
    COMPUTE_ALLOCATION,
    funded_compute_bundle,
)
from cathedral_thin.independent_runtime.qvl import LAUNCH_QVL_DIGEST, load_verifier
from cathedral_thin.independent_runtime.run import DEFAULT_STATE_DIR, prepare_state_dir
from cathedral_thin.independent_runtime.score import mass_from_units
from cathedral_thin.independent_runtime.tempo import (
    closed_epoch_anchor,
    closed_epoch_open,
)
from cathedral_thin.independent_runtime.workers import (
    WorkersApiError,
    WorkersClient,
    tdx_create_enabled,
    tdx_workers,
)
from test_independent_compute import (
    ANCHOR,
    INTEL_COLLATERAL,
    MINER_UID,
    MockQuoteVerifier,
    PINNED_QVL,
)


def test_workers_client_refuses_a_non_cathedral_key():
    with pytest.raises(WorkersApiError, match="cat_sk_"):
        WorkersClient("sk-not-cathedral")


def test_list_workers_parses_tdx_rows():
    payload = {
        "workers": [
            {
                "id": "w-tdx",
                "name": "sealed",
                "status": "ready",
                "resources": {"hardware_class": "tdx_cpu"},
                "ip": "203.0.113.9",
            },
            {
                "id": "w-fast",
                "name": "fast",
                "status": "ready",
                "resources": {"hardware_class": "standard_cpu"},
            },
        ]
    }

    def transport(method, url, headers, body):
        assert method == "GET"
        assert url.endswith("/v1/workers")
        assert headers["Authorization"] == "Bearer cat_sk_test"
        return 200, json.dumps(payload).encode("utf-8")

    client = WorkersClient("cat_sk_test", transport=transport)
    records = client.list_workers()
    assert [record.worker_id for record in records] == ["w-tdx", "w-fast"]
    tdx = tdx_workers(records)
    assert len(tdx) == 1
    assert tdx[0].ip == "203.0.113.9"
    assert tdx[0].ready is True


def test_create_persistent_tdx_sends_intel_tdx_not_fast_cpu():
    captured: dict = {}

    def transport(method, url, headers, body):
        captured["method"] = method
        captured["url"] = url
        captured["headers"] = dict(headers)
        captured["body"] = json.loads(body.decode("utf-8"))
        return 202, json.dumps(
            {
                "id": "w-new",
                "name": "independent-canary-miner",
                "status": "provisioning",
                "resources": {"hardware_class": "tdx_cpu"},
            }
        ).encode("utf-8")

    client = WorkersClient("cat_sk_test", transport=transport)
    record = client.create_persistent_tdx(name="independent-canary-miner")
    assert record.worker_id == "w-new"
    assert captured["method"] == "POST"
    assert captured["body"]["resources"]["hardware_class"] == "tdx_cpu"
    assert captured["body"]["profile"] == "custom.v1"
    assert captured["body"]["lifetime"]["mode"] == "bounded_service"
    assert captured["body"]["lifetime"]["reuse"] == "allowed"
    assert captured["body"]["resources"]["cpu"] == 4
    assert captured["body"]["resources"]["memory_gib"] == 16
    assert "Idempotency-Key" in captured["headers"]


def test_list_workers_401_is_named():
    def transport(method, url, headers, body):
        return 401, b'{"error":"Not authenticated"}'

    client = WorkersClient("cat_sk_test", transport=transport)
    with pytest.raises(WorkersApiError, match="401"):
        client.list_workers()


def test_mass_from_units_gives_a_lone_miner_the_whole_allocation():
    assert mass_from_units(COMPUTE_ALLOCATION, {BOB: 1}) == {BOB: COMPUTE_ALLOCATION}


def test_mass_from_units_omits_zero_and_splits_two_miners():
    charlie = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y"
    masses = mass_from_units(100, {BOB: 1, charlie: 1})
    assert sum(masses.values()) == 100
    assert set(masses) == {BOB, charlie}


def test_mass_from_units_leaves_integer_remainder_for_burn():
    charlie = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y"
    masses = mass_from_units(100, {BOB: 2, charlie: 1})
    assert masses == {BOB: 66, charlie: 33}
    assert sum(masses.values()) == 99


def test_axon_evidence_url_brackets_ipv6():
    assert (
        axon_evidence_url("2001:db8::1", 8443)
        == "https://[2001:db8::1]:8443/v1/evidence"
    )
    assert (
        axon_evidence_url("203.0.113.9", 443) == "https://203.0.113.9:443/v1/evidence"
    )


def test_axon_sat_work_url_is_built_from_the_axon_not_the_evidence_url():
    assert (
        axon_sat_work_url("2001:db8::1", 8443)
        == "https://[2001:db8::1]:8443/v1/sat-work"
    )
    assert (
        axon_sat_work_url("203.0.113.9", 443) == "https://203.0.113.9:443/v1/sat-work"
    )
    axon = ServingAxon(uid=MINER_UID, hotkey=BOB, ip="203.0.113.9", port=8443)
    assert axon.evidence_url() == "https://203.0.113.9:8443/v1/evidence"
    assert axon.sat_work_url() == "https://203.0.113.9:8443/v1/sat-work"
    # The work URL is validated as itself, and an evidence URL is never
    # rewritten into one.
    assert sat_work_url(axon.sat_work_url()) == axon.sat_work_url()
    with pytest.raises(SatWorkError):
        sat_work_url(axon.evidence_url())


def test_local_funded_bundle_composes_when_compute_has_verified_mass(tmp_path):
    bundle, registry = funded_compute_bundle()
    paying = ComputeAdapter(
        MockQuoteVerifier(),
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=PINNED_QVL,
        verified_mass={BOB: COMPUTE_ALLOCATION},
    )
    view = MetagraphView.from_uid_map({BURN_UID: BURN_HOTKEY, MINER_UID: BOB})
    result = compose_dry_run(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=view,
        inclusion_view=view,
        adapters={COMPUTE_LANE: paying},
        journal_path=tmp_path / INDEPENDENT_STATE_FILE.name,
    )
    assert result.status == STATUS_COMPOSED
    assert MINER_UID in result.dests
    assert sum(result.weights) == 65535
    assert result.record["h_map"][str(MINER_UID)]["m"] == COMPUTE_ALLOCATION
    assert result.record["h_map"][str(BURN_UID)]["m"] == H - COMPUTE_ALLOCATION


def test_tls_context_for_an_ip_skips_hostname_verification():
    """An IP axon terminates TLS in the guest, so CERT_NONE is deliberate.

    Requiring a CA here would refuse every honest self-signed TDX axon. The
    peer is authenticated by the v2 REPORT_DATA binding of the observed SPKI,
    not by a chain. A public hostname keeps ordinary verification.
    """
    ip_context = tls_context_for_evidence("203.0.113.9")
    assert ip_context.check_hostname is False
    assert ip_context.verify_mode == ssl.CERT_NONE
    host_context = tls_context_for_evidence("miner.example.test")
    assert host_context.check_hostname is True
    assert host_context.verify_mode == ssl.CERT_REQUIRED


def self_signed_der(common_name: str = "axon.test") -> bytes:
    """A throwaway self-signed leaf, the way an in-guest axon presents one."""
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, algorithm=None)
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class BoundedTlsPeer:
    """The live-side handle on the TLS fixture: port, log, and served body."""

    def __init__(self, port: int, requests: list[tuple[str, bytes, str | None]]):
        self.port = port
        self.requests = requests
        self.response_body = b'{"bounded":true}'

    def serve_bytes(self, length: int) -> None:
        """Answer the next POST with exactly ``length`` bytes."""
        self.response_body = b"x" * length

    def post(self, path: str, body: object = None, *, timeout: float = 10.0):
        """Drive ``_post_peer`` against this peer on ``path``."""
        endpoint = type(
            "Endpoint",
            (),
            {
                "host": "127.0.0.1",
                "port": self.port,
                "path": path,
                "host_header": f"127.0.0.1:{self.port}",
            },
        )()
        encoded = json.dumps(
            {"route": path} if body is None else body,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        transport = HttpsEvidenceTransport(timeout=timeout)
        return transport._post_peer(endpoint, "127.0.0.1", encoded, lambda: timeout)


@pytest.fixture
def content_length_close_tls_server(tmp_path):
    """One real TLS/http.client peer that closes after a bounded response."""

    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, algorithm=None)
    )
    certificate_path = tmp_path / "peer.crt"
    private_key_path = tmp_path / "peer.key"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private_key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    requests: list[tuple[str, bytes, str | None]] = []
    peer: list[BoundedTlsPeer] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            requests.append(
                (self.path, self.rfile.read(length), self.headers.get("Authorization"))
            )
            response_body = peer[0].response_body
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            # A client that refuses an oversize body hangs up mid-write; that
            # is the behaviour under test, not a server fault.
            try:
                self.wfile.write(response_body)
                self.wfile.flush()
            except OSError:
                pass
            self.close_connection = True

        def log_message(self, _format: str, *args: object) -> None:
            del args

    class Server(http.server.HTTPServer):
        def handle_error(self, request, client_address) -> None:
            del request, client_address

    server = Server(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, private_key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    peer.append(BoundedTlsPeer(server.server_port, requests))
    try:
        yield peer[0]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("path", [EVIDENCE_PATH, SAT_WORK_PATH])
def test_https_transport_reads_content_length_before_connection_close(
    content_length_close_tls_server, path
):
    """A complete short body must not dereference http.client's cleared socket."""

    peer = content_length_close_tls_server
    expected_response = peer.response_body

    status, response_body = peer.post(path, timeout=2.0)

    assert status == 200
    assert response_body == expected_response
    assert peer.requests == [
        (
            path,
            json.dumps({"route": path}, sort_keys=True, separators=(",", ":")).encode(),
            None,
        )
    ]


def test_https_transport_refuses_a_sat_work_body_over_the_sat_bound(
    content_length_close_tls_server,
):
    """64 KiB + 1 on ``/v1/sat-work`` never reaches the SAT parser.

    The sealed contract refuses a work body over ``MAX_SAT_RESPONSE_BYTES``
    rather than truncating it, so the live transport must not deliver those
    bytes just because they fit under the larger collect bound.
    """

    peer = content_length_close_tls_server
    peer.serve_bytes(MAX_SAT_RESPONSE_BYTES + 1)

    with pytest.raises(IndependentLiveError) as raised:
        peer.post(SAT_WORK_PATH)

    assert "exceeded the sat-work body bound" in str(raised.value)
    assert "evidence" not in str(raised.value)
    assert "collect" not in str(raised.value)


def test_https_transport_accepts_a_sat_work_body_at_the_sat_bound(
    content_length_close_tls_server,
):
    """Exactly 64 KiB is inside the contract and must still be delivered."""

    peer = content_length_close_tls_server
    peer.serve_bytes(MAX_SAT_RESPONSE_BYTES)

    status, response_body = peer.post(SAT_WORK_PATH)

    assert status == 200
    assert len(response_body) == MAX_SAT_RESPONSE_BYTES


def test_https_transport_keeps_the_collect_bound_for_evidence(
    content_length_close_tls_server,
):
    """The SAT cap must not silently tighten ``/v1/evidence`` to 64 KiB."""

    peer = content_length_close_tls_server
    peer.serve_bytes(MAX_SAT_RESPONSE_BYTES + 1)

    status, response_body = peer.post(EVIDENCE_PATH)

    assert status == 200
    assert len(response_body) == MAX_SAT_RESPONSE_BYTES + 1


def test_https_transport_refuses_an_evidence_body_over_the_collect_bound(
    content_length_close_tls_server,
):
    """128 KiB + 1 on ``/v1/evidence`` keeps the #151 refusal and wording."""

    peer = content_length_close_tls_server
    peer.serve_bytes(MAX_EVIDENCE_RESPONSE_BYTES + 1)

    with pytest.raises(
        IndependentLiveError, match="evidence response exceeded the collect body bound"
    ):
        peer.post(EVIDENCE_PATH)


def _public_sat_endpoint():
    return type(
        "Endpoint",
        (),
        {
            "host": "203.0.113.9",
            "port": 8443,
            "path": SAT_WORK_PATH,
            "host_header": "203.0.113.9:8443",
        },
    )()


def _stub_round_trip_peers(monkeypatch, peer_ips: list[str]) -> None:
    """Let ``_round_trip`` run without DNS or the public-IP check."""

    monkeypatch.setattr(
        https_mod, "validate_policy_url", lambda url: _public_sat_endpoint()
    )
    monkeypatch.setattr(https_mod, "getaddrinfo_bounded", lambda *args, **kwargs: [])
    monkeypatch.setattr(https_mod, "validated_peer_ips", lambda infos: list(peer_ips))


def test_round_trip_reuses_one_absolute_candidate_deadline(monkeypatch):
    _stub_round_trip_peers(monkeypatch, ["203.0.113.9"])
    cutoff = time.monotonic() + 0.2
    transport = HttpsEvidenceTransport(timeout=30.0, deadline_monotonic=cutoff)
    observed: list[float] = []

    def fake_post_peer(endpoint, peer_ip, body, remaining):
        del endpoint, peer_ip, body
        observed.append(remaining())
        return 200, b"ok"

    monkeypatch.setattr(transport, "_post_peer", fake_post_peer)
    transport.post("https://203.0.113.9:8443/v1/sat-work", {"first": True})
    time.sleep(0.02)
    transport.post("https://203.0.113.9:8443/v1/sat-work", {"second": True})

    assert 0 < observed[1] < observed[0] <= 0.2


def test_round_trip_does_not_failover_a_sat_oversize_refusal(monkeypatch):
    """A SAT bound refusal is terminal. The next A-record must not be tried.

    ``collect_sat_work`` calls ``transport.post``, which goes through
    ``_round_trip``. #154 tested ``_post_peer`` only, so a second IP that
    answered 200 after an oversize refusal would have been paid.
    """

    _stub_round_trip_peers(monkeypatch, ["203.0.113.9", "198.51.100.10"])
    transport = HttpsEvidenceTransport(timeout=2.0)
    calls: list[str] = []

    def fake_post_peer(endpoint, peer_ip, body, remaining):
        del endpoint, body, remaining
        calls.append(peer_ip)
        raise IndependentLiveError("work response exceeded the sat-work body bound")

    monkeypatch.setattr(transport, "_post_peer", fake_post_peer)

    with pytest.raises(IndependentLiveError) as raised:
        transport.post("https://203.0.113.9:8443/v1/sat-work", {"k": "v"})

    assert "sat-work body bound" in str(raised.value)
    assert "evidence host unreachable" not in str(raised.value)
    assert calls == ["203.0.113.9"]


def test_round_trip_does_not_return_a_second_peer_200_after_sat_oversize(
    monkeypatch,
):
    """Failover after a SAT refusal is the payment fail-open #154 missed."""

    _stub_round_trip_peers(monkeypatch, ["203.0.113.9", "198.51.100.10"])
    transport = HttpsEvidenceTransport(timeout=2.0)
    calls: list[str] = []

    def fake_post_peer(endpoint, peer_ip, body, remaining):
        del endpoint, body, remaining
        calls.append(peer_ip)
        if peer_ip == "203.0.113.9":
            raise IndependentLiveError("work response exceeded the sat-work body bound")
        return 200, b'{"satisfiable":true}'

    monkeypatch.setattr(transport, "_post_peer", fake_post_peer)

    with pytest.raises(IndependentLiveError) as raised:
        transport.post("https://203.0.113.9:8443/v1/sat-work", {"k": "v"})

    assert "sat-work body bound" in str(raised.value)
    assert "evidence host unreachable" not in str(raised.value)
    assert calls == ["203.0.113.9"]


def test_round_trip_failovers_oserror_to_the_next_peer(monkeypatch):
    """Connect/reset still tries the next validated address."""

    _stub_round_trip_peers(monkeypatch, ["203.0.113.9", "198.51.100.10"])
    transport = HttpsEvidenceTransport(timeout=2.0)
    calls: list[str] = []

    def fake_post_peer(endpoint, peer_ip, body, remaining):
        del endpoint, body, remaining
        calls.append(peer_ip)
        if peer_ip == "203.0.113.9":
            raise OSError("connection reset")
        return 200, b"ok"

    monkeypatch.setattr(transport, "_post_peer", fake_post_peer)

    status, response_body = transport.post(
        "https://203.0.113.9:8443/v1/sat-work", {"k": "v"}
    )

    assert status == 200
    assert response_body == b"ok"
    assert calls == ["203.0.113.9", "198.51.100.10"]


def test_round_trip_wraps_exhausted_oserror_as_unreachable(monkeypatch):
    """All addresses refusing to connect is still connectivity, not a SAT parse."""

    _stub_round_trip_peers(monkeypatch, ["203.0.113.9"])
    transport = HttpsEvidenceTransport(timeout=2.0)

    def fake_post_peer(endpoint, peer_ip, body, remaining):
        del endpoint, peer_ip, body, remaining
        raise OSError("connection refused")

    monkeypatch.setattr(transport, "_post_peer", fake_post_peer)

    with pytest.raises(
        IndependentLiveError, match="evidence host unreachable"
    ) as raised:
        transport.post("https://203.0.113.9:8443/v1/sat-work", {"k": "v"})

    assert "OSError" in str(raised.value)


def test_a_collected_chain_whose_leaf_is_the_peer_is_accepted():
    leaf = self_signed_der()
    require_cert_chain_matches_peer((leaf,), spki_sha256(leaf))


def test_a_collected_chain_naming_another_certificate_is_refused():
    """The gap the unused ``cert_chain`` field left: an echoed foreign leaf."""
    peer = self_signed_der("peer.test")
    with pytest.raises(IndependentLiveError, match="not the TLS peer"):
        require_cert_chain_matches_peer(
            (self_signed_der("someone-else.test"),), spki_sha256(peer)
        )


def test_an_empty_collected_chain_is_allowed():
    """``cert_chain_hex: []`` is in the collect contract; SPKI still binds."""
    require_cert_chain_matches_peer((), spki_sha256(self_signed_der()))


def test_a_collected_chain_leaf_that_is_not_x509_is_refused():
    with pytest.raises(IndependentLiveError, match="not an X.509 certificate"):
        require_cert_chain_matches_peer(
            (b"x509-leaf" * 8,), spki_sha256(self_signed_der())
        )


@pytest.mark.parametrize("digest", [b"", b"\x01" * 31, b"\x01" * 33])
def test_a_peer_digest_that_is_not_a_sha256_is_refused(digest):
    with pytest.raises(IndependentLiveError, match="32 bytes"):
        require_cert_chain_matches_peer((self_signed_der(),), digest)


def test_list_workers_reads_connection_ip():
    payload = {
        "workers": [
            {
                "id": "w-nested",
                "name": "sealed",
                "status": "running",
                "trust": {"hardware_class": "tdx_cpu"},
                "connection": {
                    "ip": "198.51.100.8",
                    "ssh": {"host": "box.cathedral.computer"},
                },
            }
        ]
    }

    def transport(method, url, headers, body):
        return 200, json.dumps(payload).encode("utf-8")

    client = WorkersClient("cat_sk_test", transport=transport)
    record = client.list_workers()[0]
    assert record.ip == "198.51.100.8"
    assert record.ssh_host == "box.cathedral.computer"
    assert record.ready is True
    assert record.is_tdx is True


def test_wait_until_ready_polls_until_running():
    calls = {"n": 0}

    def transport(method, url, headers, body):
        calls["n"] += 1
        status = "provisioning" if calls["n"] == 1 else "running"
        return 200, json.dumps(
            {
                "id": "w-wait",
                "name": "sealed",
                "status": status,
                "resources": {"hardware_class": "tdx_cpu"},
                "ip": "198.51.100.9",
            }
        ).encode("utf-8")

    client = WorkersClient("cat_sk_test", transport=transport)
    record = client.wait_until_ready("w-wait", timeout_seconds=5, interval_seconds=0.0)
    assert record.status == "running"
    assert calls["n"] == 2


def test_create_refuses_a_sub_dollar_budget():
    client = WorkersClient("cat_sk_test", transport=lambda *a: (200, b"{}"))
    with pytest.raises(WorkersApiError, match="1.00"):
        client.create_persistent_tdx(name="too-cheap", max_spend_usd=0.5)


def test_closed_epoch_anchor_names_a_produced_block():
    block = TEMPO_BLOCKS * 10 + 7
    epoch_open = closed_epoch_open(block)
    assert epoch_open == TEMPO_BLOCKS * 10
    assert epoch_open <= block
    anchor = closed_epoch_anchor(block, "ab" * 32)
    assert anchor.epoch_open == epoch_open
    assert anchor.anchor_number == epoch_open - 1
    assert anchor.anchor_hash == "0x" + "ab" * 32


def test_closed_epoch_anchor_refuses_a_missing_hash():
    with pytest.raises(ChainClientError, match="missing"):
        closed_epoch_anchor(TEMPO_BLOCKS * 2, None)


def test_load_verifier_refuses_a_binary_that_is_not_the_launch_pin(tmp_path):
    path = tmp_path / "fake-qvl"
    path.write_text("#!/bin/sh\necho no\n", encoding="utf-8")
    path.chmod(0o755)
    with pytest.raises(QuoteVerifyError, match="launch pin"):
        load_verifier(str(path))


def test_launch_qvl_digest_is_the_binary_blob_pin():
    assert LAUNCH_QVL_DIGEST == (
        "35bb55f89f411d5dcf5f72be90488e999ee68c41dfc0429a0dcb8cc2b448b6bb"
    )
    assert LAUNCH_QVL_DIGEST != (
        "8292b085e4dbe228f8ffd2ec7046a1c0f1324ff5e7a29d1574ce16963f9b098f"
    )


def test_live_runner_does_not_bind_mass_from_a_quote_pass():
    """The SAT path assigns units; nothing else in the runner may.

    ``verified_units[...] = ...`` is now a legal statement -- the audit
    re-derivation is exactly what fills it -- so the claim is checked by AST
    rather than by banning the subscript: every value assigned into
    ``verified_units`` must be the local the SAT helper returned, never a pass
    count, a quote length, or a verdict.
    """
    source = Path(run_module.__file__).read_text(encoding="utf-8")
    assert "verified_units.get" not in source
    assert "Attestation is admission" in source
    assert DEFAULT_STATE_DIR == "/var/lib/cathedral-validator"
    assert "/tmp" not in DEFAULT_STATE_DIR

    assigned: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == "verified_units"
            ):
                assert isinstance(node.value, ast.Name), ast.dump(node.value)
                assigned.append(node.value.id)
    assert assigned == ["units"]


def test_run_parser_defaults_are_fail_closed():
    parser = run_module._build_parser()
    options = parser.parse_args(["run"])
    assert options.state_dir == DEFAULT_STATE_DIR
    assert options.confirm_canary is False


def test_prepare_state_dir_is_owner_only_and_refuses_symlinks(tmp_path):
    path = prepare_state_dir(tmp_path / "state")
    assert path.is_dir()
    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(IndependentLiveError, match="symlink"):
        prepare_state_dir(link)


def test_tdx_create_enabled_requires_custom_v1_tdx_not_fast_cpu():
    enabled = {
        "profiles": [
            {
                "id": "custom.v1",
                "hardware_classes": [
                    {"id": "tdx_cpu", "availability": "live_testing"},
                    {
                        "id": "standard_cpu",
                        "availability": "available",
                        "customer_enabled": True,
                    },
                ],
            }
        ]
    }
    unavailable = {
        "profiles": [
            {
                "id": "custom.v1",
                "hardware_classes": [
                    {"id": "tdx_cpu", "availability": "unavailable"},
                ],
            }
        ]
    }
    fast_only = {
        "profiles": [
            {
                "id": "custom.v1",
                "hardware_classes": [
                    {
                        "id": "standard_cpu",
                        "availability": "available",
                        "customer_enabled": True,
                    },
                ],
            }
        ]
    }
    disabled = {
        "profiles": [
            {
                "id": "custom.v1",
                "hardware_classes": [
                    {
                        "id": "tdx_cpu",
                        "availability": "live_testing",
                        "customer_enabled": False,
                    },
                ],
            }
        ]
    }
    assert tdx_create_enabled(enabled) is True
    assert tdx_create_enabled(unavailable) is False
    assert tdx_create_enabled(fast_only) is False
    assert tdx_create_enabled(disabled) is False
    assert tdx_create_enabled({}) is False


class FakeAxon:
    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port
        self.is_serving = port > 0


class FakeMetagraph:
    def __init__(self, uids, hotkeys, *, port: int = 8443) -> None:
        self.uids = list(uids)
        self.hotkeys = list(hotkeys)
        self.axons = [FakeAxon("1.1.1.1", port) for _ in self.uids]


class RowMetagraph:
    """One axon row per UID so skip reasons can be tested independently."""

    def __init__(self, rows: list[tuple[int, str, FakeAxon]]) -> None:
        self.uids = [uid for uid, _hotkey, _axon in rows]
        self.hotkeys = [hotkey for _uid, hotkey, _axon in rows]
        self.axons = [axon for _uid, _hotkey, axon in rows]


RELAY_HOTKEY = sorted(REFUSE_HOTKEYS - {BURN_HOTKEY})[0]


def test_scan_axons_counts_every_skip_reason_and_keeps_only_dialable_rows():
    """Empty serving_axons must still say why. Counts, never a refused URL."""
    silent = FakeAxon("1.1.1.1", 0)
    advertised_but_down = FakeAxon("1.1.1.1", 8443)
    advertised_but_down.is_serving = False
    loopback = FakeAxon("127.0.0.1", 8443)
    unspecified = FakeAxon("0.0.0.0", 8091)
    bad_ip = FakeAxon("", 8443)
    bad_ip.ip = None
    live = FakeAxon("1.1.1.1", 8443)
    refuse_even_if_serving = FakeAxon("198.51.100.7", 8443)
    canary_even_if_serving = FakeAxon("198.51.100.8", 8443)
    scan = scan_axons(
        RowMetagraph(
            [
                (0, BOB, silent),
                (1, CHARLIE, advertised_but_down),
                (2, "5FakeLoopbackHotkeyAAAAAAAAAAAAAAAAAAAAAAAAAAA", loopback),
                (3, "5FakeUnspecifiedHotkeyAAAAAAAAAAAAAAAAAAAAAAAA", unspecified),
                (4, "5FakeUnusableIpHotkeyAAAAAAAAAAAAAAAAAAAAAAAAA", bad_ip),
                (MINER_UID, "5DialableMinerHotkeyAAAAAAAAAAAAAAAAAAAAAAAAAA", live),
                (30, RELAY_HOTKEY, refuse_even_if_serving),
                (136, BURN_HOTKEY, refuse_even_if_serving),
                (200, CANARY_HOTKEY, canary_even_if_serving),
            ]
        )
    )
    assert AXON_SKIP_REASONS == (
        "refuse_or_canary",
        "port_zero",
        "not_serving",
        "unroutable",
        "unusable_ip",
    )
    assert scan.skipped == {
        "refuse_or_canary": 3,
        "port_zero": 1,
        "not_serving": 1,
        "unroutable": 2,
        "unusable_ip": 1,
    }
    assert [axon.uid for axon in scan.serving] == [MINER_UID]
    assert scan.serving[0].ip == "1.1.1.1"
    assert scan.serving[0].port == 8443


@pytest.mark.parametrize(
    "ip",
    (
        "10.0.0.1",
        "100.64.0.1",
        "127.254.1.2",
        "169.254.1.1",
        "224.0.0.1",
        "203.0.113.9",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "2001:4860:4860::8888%en0",
        "::ffff:1.1.1.1",
        "::1.1.1.1",
        "64:ff9b::101:101",
        "2002:0101:0101::",
        "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
    ),
)
def test_scan_axons_skips_every_non_global_chain_address(ip: str) -> None:
    scan = scan_axons(
        RowMetagraph(
            [
                (
                    MINER_UID,
                    "5NonGlobalMinerHotkeyAAAAAAAAAAAAAAAAAAAAAAA",
                    FakeAxon(ip, 8443),
                )
            ]
        )
    )

    assert scan.serving == ()
    assert scan.skipped["unroutable"] == 1


def test_scan_axons_accepts_and_canonicalizes_global_ipv6() -> None:
    scan = scan_axons(
        RowMetagraph(
            [
                (
                    MINER_UID,
                    "5GlobalIpv6MinerHotkeyAAAAAAAAAAAAAAAAAAAAAAA",
                    FakeAxon("2606:4700:4700:0:0:0:0:1111", 8443),
                )
            ]
        )
    )

    assert scan.skipped["unroutable"] == 0
    assert scan.serving == (
        ServingAxon(
            MINER_UID,
            "5GlobalIpv6MinerHotkeyAAAAAAAAAAAAAAAAAAAAAAA",
            "2606:4700:4700::1111",
            8443,
        ),
    )


def test_scan_axons_does_not_treat_the_live_relay_as_dialable():
    serving_relay = FakeAxon("203.0.113.50", 8443)
    scan = scan_axons(RowMetagraph([(30, RELAY_HOTKEY, serving_relay)]))
    assert scan.serving == ()
    assert scan.skipped["refuse_or_canary"] == 1


class OrderRecordingSubtensor:
    """Records the order of the RPCs the epoch snapshot makes.

    ``metagraph`` raises for a historical block when ``archive`` is false, which
    is what a pruning Finney endpoint does.
    """

    def __init__(self, head: int, *, archive: bool = True) -> None:
        self.head = head
        self.archive = archive
        self.calls: list[str] = []
        self.metagraph_blocks: list[object] = []

    def get_current_block(self) -> int:
        self.calls.append("get_current_block")
        return self.head

    def get_block_hash(self, number: int) -> str:
        self.calls.append(f"get_block_hash:{number}")
        return "0x" + "cd" * 32

    def metagraph(self, netuid: int, block: int | None = None):
        assert netuid == 39
        self.calls.append("metagraph" if block is None else f"metagraph:{block}")
        self.metagraph_blocks.append(block)
        if block is not None and not self.archive:
            raise RuntimeError("state already discarded for block")
        return FakeMetagraph([BURN_UID, MINER_UID], [BURN_HOTKEY, BOB])


def test_the_anchor_is_frozen_before_the_metagraph_is_snapshotted():
    """Order is the claim: a view read first belongs to the wrong tempo."""
    head = TEMPO_BLOCKS * 17_000 + 41
    subtensor = OrderRecordingSubtensor(head)
    snapshot = run_module.snapshot_epoch(subtensor)
    epoch_open = TEMPO_BLOCKS * 17_000
    assert subtensor.calls == [
        "get_current_block",
        f"get_block_hash:{epoch_open - 1}",
        f"metagraph:{epoch_open - 1}",
    ]
    assert snapshot.anchor.epoch_open == epoch_open
    assert snapshot.anchor.anchor_number == epoch_open - 1
    assert snapshot.at_anchor is True
    assert snapshot.note == ""
    assert snapshot.anchor_view.uid_to_hotkey[BURN_UID] == BURN_HOTKEY
    assert [axon.uid for axon in snapshot.axons] == [MINER_UID]
    assert snapshot.skipped["refuse_or_canary"] == 1
    assert snapshot.skipped["port_zero"] == 0


def test_a_pruning_node_snapshots_the_head_and_says_so():
    head = TEMPO_BLOCKS * 17_000 + 41
    subtensor = OrderRecordingSubtensor(head, archive=False)
    snapshot = run_module.snapshot_epoch(subtensor)
    epoch_open = TEMPO_BLOCKS * 17_000
    assert subtensor.calls == [
        "get_current_block",
        f"get_block_hash:{epoch_open - 1}",
        f"metagraph:{epoch_open - 1}",
        "metagraph",
    ]
    assert snapshot.at_anchor is False
    assert "could not serve the metagraph at anchor block" in snapshot.note
    assert snapshot.anchor.epoch_open == epoch_open
    assert snapshot.as_report()["at_anchor"] is False


def test_a_pruned_anchor_stops_before_worker_spend_or_miner_dial(
    monkeypatch, tmp_path, capsys
):
    """A head snapshot is diagnostic evidence, never a payable anchor view."""
    head = TEMPO_BLOCKS * 17_000 + 41

    class PrunedRunnerSubtensor(RunnerSubtensor):
        def metagraph(self, netuid: int, block: int | None = None):
            if block is not None:
                self.metagraph_blocks.append(block)
                raise RuntimeError("state already discarded for block")
            return super().metagraph(netuid, block=block)

    subtensor = PrunedRunnerSubtensor(head, port=8443)
    monkeypatch.setattr(run_module, "_connect_subtensor", lambda: subtensor)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("a pruned anchor must stop before Worker or miner I/O")

    monkeypatch.setattr(run_module, "fetch_public_json", forbidden)
    monkeypatch.setattr(run_module, "_workers", forbidden)
    monkeypatch.setattr(run_module, "_try_collect", forbidden)

    code = run_module.cmd_run(run_options(tmp_path, rent=True))
    report = json.loads(capsys.readouterr().out)
    epoch_open = TEMPO_BLOCKS * 17_000

    assert code == 2
    assert subtensor.metagraph_blocks == [epoch_open - 1, None]
    assert report["anchor"]["at_anchor"] is False
    assert any("head fallback is diagnostic only" in row for row in report["blockers"])
    assert report["catalog"] is None
    assert report["workers"] == []
    assert report["collect"] == []
    assert report["compose"] is None
    assert not (tmp_path / "state").exists()


class FakeGenesisSubstrate:
    def get_block_hash(self, number: int) -> str:
        assert number == 0
        return FINNEY_GENESIS_HASH


class RunnerSubtensor:
    """Enough of a Subtensor for ``cmd_run``.

    ``port=0`` means no axon serves, so nothing dials. A positive port makes the
    miner collectable, which is what the SAT wiring test needs.

    ``extra_miners`` are ``(uid, hotkey)`` rows appended after BOB. They are on
    the metagraph AND serving, so inclusion maps them to a UID and the composer
    can pay them, which is what the two-axon rounds need.
    """

    def __init__(self, head: int, *, port: int = 0, extra_miners=()) -> None:
        self.head = head
        self.port = port
        self.extra_miners = tuple(extra_miners)
        self.substrate = FakeGenesisSubstrate()
        self.metagraph_blocks: list[object] = []

    def get_current_block(self) -> int:
        return self.head

    def get_block_hash(self, number: int) -> str:
        return "0x" + "cd" * 32

    def metagraph(self, netuid: int, block: int | None = None):
        assert netuid == 39
        self.metagraph_blocks.append(block)
        uids = [BURN_UID, MINER_UID, *(uid for uid, _hotkey in self.extra_miners)]
        hotkeys = [BURN_HOTKEY, BOB, *(hotkey for _uid, hotkey in self.extra_miners)]
        return FakeMetagraph(uids, hotkeys, port=self.port)


class FakePinnedVerifier:
    digest = PINNED_QVL

    def verify(self, quote: bytes, *, expected_report_data: bytes) -> QuoteVerdict:
        del quote, expected_report_data
        return QuoteVerdict.PASS


def run_options(tmp_path, **overrides) -> argparse.Namespace:
    values = {
        "command": "run",
        "name": "independent-canary-miner",
        "rent": False,
        "qvl": None,
        "wait": 0,
        "state_dir": str(tmp_path / "state"),
        "confirm_canary": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def prepared_runner(
    monkeypatch,
    head: int,
    *,
    bind_mass: bool = True,
    port: int = 0,
    extra_miners=(),
) -> RunnerSubtensor:
    """A ``cmd_run`` that reaches COMPOSED without a network or a wallet.

    ``RunnerSubtensor`` serves no axon by default, so nothing collects and
    nothing re-derives units. With ``bind_mass`` the ``mass_from_units`` stub
    stands in for that missing audit round, which is what makes the gates AFTER
    compose reachable at all. With ``bind_mass=False`` the runner is left
    exactly as production is: a pinned QVL that would PASS, and no units.
    """
    monkeypatch.delenv("CATHEDRAL_API_KEY", raising=False)
    monkeypatch.delenv("CATHEDRAL_CANARY_HOTKEY_JSON", raising=False)
    monkeypatch.setattr(run_module, "fetch_public_json", lambda path: {})
    subtensor = RunnerSubtensor(head, port=port, extra_miners=extra_miners)
    monkeypatch.setattr(run_module, "_connect_subtensor", lambda: subtensor)
    monkeypatch.setattr(run_module, "load_verifier", lambda path: FakePinnedVerifier())
    if bind_mass:
        monkeypatch.setattr(
            run_module, "mass_from_units", lambda amount, units: {BOB: amount}
        )
    return subtensor


def composed_run(monkeypatch, tmp_path, capsys, **overrides):
    head = TEMPO_BLOCKS * 17_000 + 41
    subtensor = prepared_runner(monkeypatch, head)
    code = run_module.cmd_run(run_options(tmp_path, **overrides))
    report = json.loads(capsys.readouterr().out)
    return code, report, subtensor


def state_files(tmp_path) -> tuple[Path, Path]:
    state = tmp_path / "state"
    return state / INDEPENDENT_STATE_FILE.name, state / INDEPENDENT_CANARY_FILE.name


def test_an_unconfirmed_epoch_journals_a_compose_but_never_a_submission(
    monkeypatch, tmp_path, capsys
):
    code, report, _subtensor = composed_run(monkeypatch, tmp_path, capsys)
    assert code == 2
    assert report["compose"]["status"] == STATUS_COMPOSED
    assert any("--confirm-canary is required" in row for row in report["blockers"])
    journal, canary = state_files(tmp_path)
    record = load_journal(journal)
    assert record["status"] == STATUS_COMPOSED
    assert "submission" not in record
    assert not canary.exists()


def test_a_confirmed_epoch_without_a_wallet_journals_no_submission_either(
    monkeypatch, tmp_path, capsys
):
    code, report, _subtensor = composed_run(
        monkeypatch, tmp_path, capsys, confirm_canary=True
    )
    assert code == 2
    assert any("CATHEDRAL_CANARY_HOTKEY_JSON" in row for row in report["blockers"])
    journal, canary = state_files(tmp_path)
    assert "submission" not in load_journal(journal)
    assert not canary.exists()


def test_the_runner_snapshots_the_anchor_first_then_re_reads_at_the_head(
    monkeypatch, tmp_path, capsys
):
    code, report, subtensor = composed_run(monkeypatch, tmp_path, capsys)
    assert code == 2
    epoch_open = TEMPO_BLOCKS * 17_000
    assert subtensor.metagraph_blocks == [epoch_open - 1, None]
    assert report["anchor"]["epoch_open"] == epoch_open
    assert report["anchor"]["anchor_number"] == epoch_open - 1
    assert report["anchor"]["at_anchor"] is True
    assert report["compose"]["epoch_open"] == epoch_open


SAT_UNITS = 20
AXON_SAT_URL = "https://1.1.1.1:8443/v1/sat-work"
ONE_SPKI = bytes(range(32, 64))
OTHER_SPKI = bytes(range(64, 96))
SECOND_MINER_UID = 9


def collected_for(hotkey: str = BOB, *, digest: bytes = ONE_SPKI) -> CollectedEvidence:
    """A CollectedEvidence the way ``collect_evidence`` would have returned it.

    ``digest`` is the observed TLS SPKI, which is also the machine identity, so
    two miners can be given one machine or two.
    """
    binding = ChannelBinding(binding_type=CHANNEL_BINDING_TYPE_TLS, digest=digest)
    return CollectedEvidence(
        kind="tdx",
        quote=b"tdx-quote" * 16,
        nonce=bytes(range(32)),
        assigned_hotkey=hotkey,
        cert_chain=(),
        channel_binding=binding,
        report_data=bytes(64),
    )


class FakeWorkTransport:
    """A work transport for the SAT round that never opens a socket.

    ``_units_after_quote`` builds its own transport, so a ``cmd_run`` test that
    stubs ``collect_sat_work`` gets one of these instead. ``last_spki`` starts
    unobserved, exactly as it does before a real POST, and the stub records
    whatever SPKI the round is meant to have seen on the wire.
    """

    def __init__(self, *, timeout: float = 30.0) -> None:
        del timeout
        self.last_spki: bytes | None = None

    def observe_binding(self, url: str) -> ChannelBinding:
        raise AssertionError(f"the fake work transport must not dial {url}")

    def post(self, url: str, body) -> tuple[int, bytes]:
        del body
        raise AssertionError(f"the fake work transport must not dial {url}")


def install_work_transport(monkeypatch) -> None:
    monkeypatch.setattr(run_module, "HttpsEvidenceTransport", FakeWorkTransport)


def paying_sat_work(monkeypatch, spki: dict[str, bytes | None]) -> None:
    """Stub a successful SAT round that observed ``spki`` per miner.

    A miner mapped to ``None`` is one whose work POST left no SPKI behind.
    """
    install_work_transport(monkeypatch)

    def fake_sat_work(*, url, assigned_hotkey, item, transport):
        del url, item
        transport.last_spki = spki[assigned_hotkey]
        return SAT_UNITS

    monkeypatch.setattr(run_module, "collect_sat_work", fake_sat_work)


def one_axon_runner(monkeypatch, *, digest: bytes = ONE_SPKI) -> CollectedEvidence:
    """A runner with BOB alone registered and serving, bound to ``digest``."""
    prepared_runner(monkeypatch, TEMPO_BLOCKS * 17_000 + 41, bind_mass=False, port=8443)
    collected = collected_for(digest=digest)

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        del validator_ss58
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "collected": collected,
        }

    monkeypatch.setattr(run_module, "_try_collect", fake_collect)
    return collected


def test_a_qvl_pass_without_re_derived_units_binds_no_compute_mass(
    monkeypatch, tmp_path, capsys
):
    """The behavioural half of "attestation is admission".

    Nothing is monkeypatched into ``mass_from_units`` here, and no axon serves,
    so the epoch has a pinned QVL that would PASS and still no units. The
    funded Compute row must stay unpayable.
    """
    prepared_runner(monkeypatch, TEMPO_BLOCKS * 17_000 + 41, bind_mass=False)
    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["verified_units"] == {}
    assert report["verified_mass"] == {}
    assert report["sat_work_rule"] == SAT_WORK_UNIT_RULE
    assert report["compose"]["status"] != STATUS_COMPOSED
    assert any(
        "no independently re-derived work units" in row for row in report["blockers"]
    )


def test_re_derived_sat_units_are_what_makes_the_runner_compose(
    monkeypatch, tmp_path, capsys
):
    """A serving axon, a PASS quote, and 20 re-derived units compose COMPOSED.

    ``mass_from_units`` is NOT stubbed: the integer mass under the funded
    allocation comes from the units the audit returned. ``collect_sat_work`` is
    stubbed only so no socket opens, and the URL it is handed proves the runner
    POSTs to the axon's own work endpoint rather than to the evidence URL. The
    stubbed POST records the attested SPKI, which is what the round is paid on.
    """
    subtensor = prepared_runner(
        monkeypatch, TEMPO_BLOCKS * 17_000 + 41, bind_mass=False, port=8443
    )
    install_work_transport(monkeypatch)
    collected = collected_for()
    seen: dict = {}

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        seen["evidence_url"] = url
        seen["sat_url"] = sat_work_url_value
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "quote_bytes": len(collected.quote),
            "kind": collected.kind,
            "collected": collected,
        }

    def fake_sat_work(*, url, assigned_hotkey, item, transport):
        seen["asked"] = (url, assigned_hotkey, item.challenge_id)
        transport.last_spki = collected.channel_binding.digest
        return SAT_UNITS

    monkeypatch.setattr(run_module, "_try_collect", fake_collect)
    monkeypatch.setattr(run_module, "collect_sat_work", fake_sat_work)

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)

    assert seen["evidence_url"] == "https://1.1.1.1:8443/v1/evidence"
    assert seen["sat_url"] == AXON_SAT_URL
    assert seen["asked"][0] == AXON_SAT_URL
    assert seen["asked"][1] == BOB
    assert report["qvl_pass_count"] == 1
    assert report["verified_units"] == {BOB: SAT_UNITS}
    assert report["verified_mass"] == {BOB: COMPUTE_ALLOCATION}
    ((row,),) = (report["collect"],)
    assert row["sat_units"] == SAT_UNITS
    assert row["sat_rule"] == SAT_WORK_UNIT_RULE
    assert row["verdict"] == "PASS"
    assert report["compose"]["status"] == STATUS_COMPOSED
    assert MINER_UID in report["compose"]["dests"]
    assert sum(report["compose"]["weights"]) == 65535
    # Composed, but nothing was submitted: the canary still needs confirmation.
    assert code == 2
    assert any("--confirm-canary is required" in row for row in report["blockers"])
    assert subtensor.metagraph_blocks == [TEMPO_BLOCKS * 17_000 - 1, None]


def test_a_refused_sat_round_admits_the_miner_and_pays_it_nothing(
    monkeypatch, tmp_path, capsys
):
    """A machine that attests but produces no witness is admitted, unpaid."""
    prepared_runner(monkeypatch, TEMPO_BLOCKS * 17_000 + 41, bind_mass=False, port=8443)
    collected = collected_for()

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "quote_bytes": len(collected.quote),
            "kind": collected.kind,
            "collected": collected,
        }

    def refusing_sat_work(*, url, assigned_hotkey, item, transport):
        raise SatWorkError("the assignment leaves a clause unsatisfied")

    monkeypatch.setattr(run_module, "_try_collect", fake_collect)
    monkeypatch.setattr(run_module, "collect_sat_work", refusing_sat_work)

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["qvl_pass_count"] == 1
    assert report["verified_units"] == {}
    assert report["verified_mass"] == {}
    ((row,),) = (report["collect"],)
    assert row["verdict"] == "PASS"
    assert "SatWorkError" in row["sat_error"]
    assert "sat_units" not in row
    assert report["compose"]["status"] != STATUS_COMPOSED


def two_axon_runner(monkeypatch, digests: dict[str, bytes]) -> None:
    """A runner with BOB and CHARLIE both registered and both serving.

    ``digests`` hands each hotkey the TLS SPKI its evidence was bound to, so a
    round can put the two miners on one machine or on two.
    """
    prepared_runner(
        monkeypatch,
        TEMPO_BLOCKS * 17_000 + 41,
        bind_mass=False,
        port=8443,
        extra_miners=((SECOND_MINER_UID, CHARLIE),),
    )
    evidence = {
        hotkey: collected_for(hotkey, digest=digest)
        for hotkey, digest in digests.items()
    }

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "collected": evidence[hotkey],
        }

    monkeypatch.setattr(run_module, "_try_collect", fake_collect)


def collect_rows(report) -> dict[str, dict]:
    return {row["hotkey"]: row for row in report["collect"]}


def test_a_flaky_sat_http_exception_does_not_abort_the_epoch(
    monkeypatch, tmp_path, capsys
):
    """A flaky axon costs its own miner the round, never the whole epoch.

    ``http.client.HTTPException`` is not an ``OSError``, so a transport that
    only caught the named errors let one truncated response abort ``cmd_run``
    for every other miner on the subnet.
    """
    two_axon_runner(monkeypatch, {BOB: ONE_SPKI, CHARLIE: OTHER_SPKI})
    install_work_transport(monkeypatch)

    def flaky_sat_work(*, url, assigned_hotkey, item, transport):
        if assigned_hotkey == BOB:
            raise http.client.HTTPException("incomplete read")
        transport.last_spki = OTHER_SPKI
        return SAT_UNITS

    monkeypatch.setattr(run_module, "collect_sat_work", flaky_sat_work)

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["qvl_pass_count"] == 2
    assert report["verified_units"] == {CHARLIE: SAT_UNITS}
    assert report["verified_mass"] == {CHARLIE: COMPUTE_ALLOCATION}
    rows = collect_rows(report)
    assert "HTTPException" in rows[BOB]["sat_error"]
    assert "sat_units" not in rows[BOB]
    assert rows[CHARLIE]["sat_units"] == SAT_UNITS
    assert report["compose"]["status"] == STATUS_COMPOSED
    assert SECOND_MINER_UID in report["compose"]["dests"]


def test_two_hotkeys_on_one_tls_spki_are_both_unpaid(monkeypatch, tmp_path, capsys):
    """One audited machine under two registered hotkeys pays neither.

    Both quotes PASS and both work rounds return units, so this is the exact
    shape of the duplicate-registration cheat: without the per-epoch machine
    ledger each hotkey would collect a full Compute share off one machine.
    """
    two_axon_runner(monkeypatch, {BOB: ONE_SPKI, CHARLIE: ONE_SPKI})
    paying_sat_work(monkeypatch, {BOB: ONE_SPKI, CHARLIE: ONE_SPKI})

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    # Admitted, unpaid: both quotes passed, neither hotkey earned anything.
    assert report["qvl_pass_count"] == 2
    assert report["verified_units"] == {}
    assert report["verified_mass"] == {}
    rows = collect_rows(report)
    for hotkey in (BOB, CHARLIE):
        assert "MachineIdentityConflict" in rows[hotkey]["sat_error"]
        assert "sat_units" not in rows[hotkey]
        assert "sat_rule" not in rows[hotkey]
    assert any("machine-identity" in row for row in report["blockers"])
    assert report["compose"]["status"] != STATUS_COMPOSED


def test_duplicate_machine_cannot_hide_behind_a_failing_sat(
    monkeypatch, tmp_path, capsys
):
    """A duplicate quote forfeits both identities before either SAT outcome matters."""
    two_axon_runner(monkeypatch, {BOB: ONE_SPKI, CHARLIE: ONE_SPKI})
    install_work_transport(monkeypatch)
    sat_calls: list[str] = []

    def second_sat_would_fail(*, url, assigned_hotkey, item, transport):
        del url, item
        sat_calls.append(assigned_hotkey)
        if assigned_hotkey == CHARLIE:
            raise SatWorkError("deliberate duplicate-side failure")
        transport.last_spki = ONE_SPKI
        return SAT_UNITS

    monkeypatch.setattr(run_module, "collect_sat_work", second_sat_would_fail)

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)

    assert code == 2
    assert sat_calls == [BOB]
    assert report["qvl_pass_count"] == 2
    assert report["verified_units"] == {}
    assert report["verified_mass"] == {}
    rows = collect_rows(report)
    for hotkey in (BOB, CHARLIE):
        assert "MachineIdentityConflict" in rows[hotkey]["sat_error"]
        assert "sat_units" not in rows[hotkey]
        assert "sat_rule" not in rows[hotkey]
    assert any("machine-identity" in row for row in report["blockers"])
    assert report["compose"]["status"] != STATUS_COMPOSED


def test_two_hotkeys_on_distinct_tls_spki_are_both_paid(monkeypatch, tmp_path, capsys):
    """Two machines are two machines. The ledger only refuses duplicates."""
    two_axon_runner(monkeypatch, {BOB: ONE_SPKI, CHARLIE: OTHER_SPKI})
    paying_sat_work(monkeypatch, {BOB: ONE_SPKI, CHARLIE: OTHER_SPKI})

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["qvl_pass_count"] == 2
    assert report["verified_units"] == {BOB: SAT_UNITS, CHARLIE: SAT_UNITS}
    assert set(report["verified_mass"]) == {BOB, CHARLIE}
    assert sum(report["verified_mass"].values()) == COMPUTE_ALLOCATION
    assert report["compose"]["status"] == STATUS_COMPOSED
    assert MINER_UID in report["compose"]["dests"]
    assert SECOND_MINER_UID in report["compose"]["dests"]
    assert sum(report["compose"]["weights"]) == 65535


def test_a_work_post_with_no_observed_tls_spki_is_unpaid(monkeypatch, tmp_path, capsys):
    """Fail-closed: an unobserved SPKI is not a match, it is a refusal.

    A stubbed audit round can return units without the runner ever having
    watched a handshake -- which is also what a transport that answered from
    somewhere other than the attested channel would look like. Units nobody
    saw arrive over the quoted channel are not payable.
    """
    one_axon_runner(monkeypatch)
    paying_sat_work(monkeypatch, {BOB: None})

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)

    assert code == 2
    assert report["qvl_pass_count"] == 1
    assert report["verified_units"] == {}
    assert report["verified_mass"] == {}
    ((row,),) = (report["collect"],)
    assert row["verdict"] == "PASS"
    assert "SatWorkError" in row["sat_error"]
    assert "not the attested channel binding" in row["sat_error"]
    assert "sat_units" not in row
    assert "sat_rule" not in row
    assert report["compose"]["status"] != STATUS_COMPOSED


def test_a_work_post_on_another_tls_spki_is_unpaid(monkeypatch, tmp_path, capsys):
    """The work POST has to have reached the machine the quote was bound to."""
    one_axon_runner(monkeypatch, digest=ONE_SPKI)
    paying_sat_work(monkeypatch, {BOB: OTHER_SPKI})

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)

    assert code == 2
    assert report["qvl_pass_count"] == 1
    assert report["verified_units"] == {}
    assert report["verified_mass"] == {}
    ((row,),) = (report["collect"],)
    assert row["verdict"] == "PASS"
    assert "SatWorkError" in row["sat_error"]
    assert "not the attested channel binding" in row["sat_error"]
    assert "sat_units" not in row
    assert report["compose"]["status"] != STATUS_COMPOSED


@pytest.mark.parametrize("observed", [None, OTHER_SPKI])
def test_units_after_quote_refuses_a_work_spki_that_is_not_the_binding(
    monkeypatch, observed
):
    """The helper itself refuses, so every caller of it inherits the refusal."""
    install_work_transport(monkeypatch)
    collected = collected_for(digest=ONE_SPKI)

    def fake_sat_work(*, url, assigned_hotkey, item, transport):
        del url, assigned_hotkey, item
        transport.last_spki = observed
        return SAT_UNITS

    monkeypatch.setattr(run_module, "collect_sat_work", fake_sat_work)
    with pytest.raises(SatWorkError, match="not the attested channel binding"):
        run_module._units_after_quote(
            anchor_hash=ANCHOR_HASH,
            collected=collected,
            sat_url=AXON_SAT_URL,
        )


def test_units_after_quote_pays_when_the_work_spki_is_the_binding(monkeypatch):
    install_work_transport(monkeypatch)
    collected = collected_for(digest=ONE_SPKI)

    def fake_sat_work(*, url, assigned_hotkey, item, transport):
        del url, assigned_hotkey, item
        transport.last_spki = ONE_SPKI
        return SAT_UNITS

    monkeypatch.setattr(run_module, "collect_sat_work", fake_sat_work)
    assert (
        run_module._units_after_quote(
            anchor_hash=ANCHOR_HASH,
            collected=collected,
            sat_url=AXON_SAT_URL,
        )
        == SAT_UNITS
    )


def test_a_failing_quote_is_never_asked_for_work(monkeypatch, tmp_path, capsys):
    prepared_runner(monkeypatch, TEMPO_BLOCKS * 17_000 + 41, bind_mass=False, port=8443)
    collected = collected_for()

    class FailingVerifier:
        digest = PINNED_QVL

        def verify(self, quote: bytes, *, expected_report_data: bytes):
            del quote, expected_report_data
            return QuoteVerdict.FAIL

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "collected": collected,
        }

    def deny(**kwargs):
        raise AssertionError("a FAIL quote must never be asked for work")

    monkeypatch.setattr(run_module, "load_verifier", lambda path: FailingVerifier())
    monkeypatch.setattr(run_module, "_try_collect", fake_collect)
    monkeypatch.setattr(run_module, "collect_sat_work", deny)

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["qvl_pass_count"] == 0
    assert report["verified_units"] == {}
    ((row,),) = (report["collect"],)
    assert row["verdict"] == "FAIL"
    assert "sat_error" not in row


def test_one_qvl_infra_result_blocks_mass_for_the_whole_epoch(
    monkeypatch, tmp_path, capsys
):
    """Validator infrastructure failure never becomes another miner's windfall."""
    two_axon_runner(monkeypatch, {BOB: ONE_SPKI, CHARLIE: OTHER_SPKI})
    evidence = {
        BOB: CollectedEvidence(
            **{**collected_for(BOB, digest=ONE_SPKI).__dict__, "quote": b"infra"}
        ),
        CHARLIE: CollectedEvidence(
            **{**collected_for(CHARLIE, digest=OTHER_SPKI).__dict__, "quote": b"pass"}
        ),
    }

    class MixedVerifier:
        digest = PINNED_QVL

        def verify(self, quote: bytes, *, expected_report_data: bytes):
            del expected_report_data
            return QuoteVerdict.INFRA if quote == b"infra" else QuoteVerdict.PASS

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        del validator_ss58
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "collected": evidence[hotkey],
        }

    monkeypatch.setattr(run_module, "load_verifier", lambda path: MixedVerifier())
    monkeypatch.setattr(run_module, "_try_collect", fake_collect)
    paying_sat_work(monkeypatch, {BOB: ONE_SPKI, CHARLIE: OTHER_SPKI})

    code = run_module.cmd_run(run_options(tmp_path, confirm_canary=True))
    report = json.loads(capsys.readouterr().out)

    assert code == 2
    assert report["qvl_pass_count"] == 1
    assert report["verified_units"] == {CHARLIE: SAT_UNITS}
    assert report["verified_mass"] == {}
    assert any("epoch remains uncomposed" in row for row in report["blockers"])
    assert report["compose"] is None
    assert not (tmp_path / "state").exists()


def test_the_runner_asks_for_the_anchor_bound_challenge(monkeypatch, tmp_path, capsys):
    """The challenge is derived from the frozen anchor and the observed channel.

    The seed material is the anchor hash, the miner hotkey and the TLS SPKI
    digest as observed -- not re-hashed -- so this asserts the exact item the
    runner committed to.
    """
    prepared_runner(monkeypatch, TEMPO_BLOCKS * 17_000 + 41, bind_mass=False, port=8443)
    collected = collected_for()
    expected = canonical_work_item(
        anchor_hash="0x" + "cd" * 32,
        miner_ss58=BOB,
        machine_id=collected.channel_binding.digest.hex(),
    )
    asked: list = []

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "collected": collected,
        }

    def fake_sat_work(*, url, assigned_hotkey, item, transport):
        asked.append(item)
        transport.last_spki = collected.channel_binding.digest
        return SAT_UNITS

    install_work_transport(monkeypatch)
    monkeypatch.setattr(run_module, "_try_collect", fake_collect)
    monkeypatch.setattr(run_module, "collect_sat_work", fake_sat_work)
    run_module.cmd_run(run_options(tmp_path))
    capsys.readouterr()
    ((item,),) = (asked,)
    assert item == expected
    assert item.challenge_id == expected.challenge_id
    assert item.seed == expected.seed
    assert (
        expected.challenge_id
        != canonical_work_item(
            anchor_hash=ANCHOR_HASH,
            miner_ss58=BOB,
            machine_id=collected.channel_binding.digest.hex(),
        ).challenge_id
    )


def test_local_policy_keys_are_ephemeral_and_not_repeating_bytes():
    _bundle_a, registry_a = funded_compute_bundle()
    _bundle_b, registry_b = funded_compute_bundle()
    assert registry_a["economics-a"] != registry_b["economics-a"]
    known = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
    public = known.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert public not in registry_a.values()
