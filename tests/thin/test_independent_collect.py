"""The collect client talks the miner's v2 contract, and still pays nothing.

Four separate claims:

1. the copied wire contract matches the serving side byte-for-byte. The
   ``REPORT_DATA`` v2 preimage is pinned to a literal vector rather than
   recomputed from the package that serves it, so a drift in either tree fails
   here instead of turning every honest quote into a verification failure;
2. the nonce is attributable to one validator and is never drawn from process
   randomness -- the caller supplies the entropy;
3. every way a miner can answer with something other than what was asked
   (wrong nonce, wrong hotkey, wrong binding, wrong kind, v1, a bundle, extra
   keys, a duplicate key, a redirect, an oversize body) is a refusal;
4. a PASS verdict on a collected quote does not lift Compute allocation 0: the
   same funded row still composes to ``BROADCAST_BLOCKED`` naming #120.

No socket is opened. The transport is a fake, and one test proves the claim by
denying ``socket`` outright.
"""

from __future__ import annotations

import hashlib
import json
import random
import socket
from pathlib import Path

import pytest

from _independent_fixtures import (
    ANCHOR_HASH,
    BOB,
    BURN_UID,
    CHARLIE,
    EPOCH_OPEN,
    burn_only_view,
    commitment_for,
    economics_document,
    lane_row,
    signed_bundle,
)
from _independent_fixtures import COMPUTE_LANE as COMPUTE_LANE_DOCUMENT
from cathedral_thin.independent import collect as collect_module
from cathedral_thin.independent.collect import (
    CHANNEL_BINDING_CANONICAL_PREFIX,
    CHANNEL_BINDING_TYPE_TLS,
    EVIDENCE_V2_REQUEST_KEYS,
    EVIDENCE_V2_RESPONSE_KEYS,
    MAX_CERTIFICATE_BYTES,
    MAX_EVIDENCE_CERTIFICATES,
    MAX_EVIDENCE_RESPONSE_BYTES,
    NONCE_BYTES,
    NONCE_ENTROPY_BYTES,
    NONCE_PREFIX_BYTES,
    ChannelBinding,
    CollectedEvidence,
    FleetTarget,
    collect_evidence,
    collect_miner_fleet,
    evidence_url,
    mint_nonce,
    report_data_v2,
    verify_collected,
)
from cathedral_thin.independent.compose import (
    STATUS_BROADCAST_BLOCKED,
    EpochAnchor,
    compose_dry_run,
)
from cathedral_thin.independent.compute import (
    COMPUTE_BLOCK_REASON,
    COMPUTE_FLEET_CAP,
    COMPUTE_LANE,
    MAX_QUOTE_BYTES,
    QuoteVerdict,
)
from cathedral_thin.independent.constants import H, INDEPENDENT_STATE_FILE
from cathedral_thin.independent.errors import CollectError
from test_independent_compute import MockQuoteVerifier, adapter

ANCHOR = EpochAnchor(
    epoch_open=EPOCH_OPEN, anchor_number=EPOCH_OPEN - 1, anchor_hash=ANCHOR_HASH
)

URL = "https://miner.example.test/v1/evidence"
NONCE = bytes(range(NONCE_BYTES))
DIGEST = bytes(range(32, 64))
BINDING = ChannelBinding(binding_type=CHANNEL_BINDING_TYPE_TLS, digest=DIGEST)
QUOTE = b"tdx-quote" * 16
CERT = b"x509-leaf" * 8

# The one vector this copied contract is pinned to. Computed from the serving
# side's encoding; if either tree moves, this literal fails first.
PINNED_REPORT_DATA = (
    "02335dd84194593bde0ffc28d60b13e02774c02f4b1e72a030bc2000cde00f58"
    "deabbc5f6e643de9195509ff05157561e03902bfc71c9a73aa44cb483dd1714b"
)


class FakeTransport:
    """Answers with canned bytes and remembers exactly what it was asked."""

    def __init__(self, status: int = 200, body: bytes = b"{}") -> None:
        self.calls: list[tuple[str, dict]] = []
        self.status = status
        self.body = body

    def post(self, url: str, body) -> tuple[int, bytes]:
        self.calls.append((url, dict(body)))
        return self.status, self.body


def v2_response(**overrides) -> dict:
    response = {
        "kind": "tdx",
        "quote_hex": QUOTE.hex(),
        "nonce_hex": NONCE.hex(),
        "assigned_hotkey": BOB,
        "cert_chain_hex": [CERT.hex()],
        "report_data_version": 2,
        "channel_binding_type": CHANNEL_BINDING_TYPE_TLS,
        "channel_binding_digest_hex": DIGEST.hex(),
    }
    response.update(overrides)
    return response


def transport_for(**overrides) -> FakeTransport:
    return FakeTransport(body=json.dumps(v2_response(**overrides)).encode("utf-8"))


def collect(transport, **kwargs) -> CollectedEvidence:
    return collect_evidence(
        url=kwargs.pop("url", URL),
        assigned_hotkey=kwargs.pop("assigned_hotkey", BOB),
        nonce=kwargs.pop("nonce", NONCE),
        channel_binding=kwargs.pop("channel_binding", BINDING),
        transport=transport,
        **kwargs,
    )


def journal_path(tmp_path):
    return tmp_path / INDEPENDENT_STATE_FILE.name


def funded_compute_bundle():
    economics = economics_document(
        burn_amount=H - 10**11,
        allocations=[lane_row(COMPUTE_LANE_DOCUMENT, 10**11)],
    )
    return signed_bundle(economics=economics)


# --- the copied wire contract ------------------------------------------------


def test_report_data_v2_matches_the_pinned_serving_side_vector():
    assert report_data_v2(NONCE, BOB, BINDING).hex() == PINNED_REPORT_DATA
    assert len(report_data_v2(NONCE, BOB, BINDING)) == 64


def test_report_data_v2_separates_every_field():
    """A tagged, length-delimited preimage: no two triples can collide."""
    other = ChannelBinding(binding_type=CHANNEL_BINDING_TYPE_TLS, digest=bytes(32))
    baseline = report_data_v2(NONCE, BOB, BINDING)
    assert baseline != report_data_v2(bytes(NONCE_BYTES), BOB, BINDING)
    assert baseline != report_data_v2(NONCE, CHARLIE, BINDING)
    assert baseline != report_data_v2(NONCE, BOB, other)


@pytest.mark.parametrize(
    "nonce, hotkey",
    [
        (b"\x00" * 31, BOB),
        (bytearray(NONCE), BOB),
        (NONCE, ""),
        (NONCE, "a" * 513),
        (NONCE, 7),
    ],
)
def test_report_data_v2_refuses_out_of_bounds_inputs(nonce, hotkey):
    with pytest.raises(CollectError):
        report_data_v2(nonce, hotkey, BINDING)


def test_report_data_v2_requires_a_validated_binding():
    with pytest.raises(CollectError, match="channel binding"):
        report_data_v2(NONCE, BOB, object())


def test_the_channel_binding_canonical_encoding_is_length_delimited():
    expected = (
        CHANNEL_BINDING_CANONICAL_PREFIX + b"\x00\x0f" + b"tls_spki_sha256" + DIGEST
    )
    assert BINDING.canonical_bytes() == expected


@pytest.mark.parametrize(
    "binding_type, digest",
    [
        ("application_key_sha256", DIGEST),
        ("tls_spki_sha512", DIGEST),
        ("", DIGEST),
        (CHANNEL_BINDING_TYPE_TLS, DIGEST[:31]),
        (CHANNEL_BINDING_TYPE_TLS, bytearray(DIGEST)),
        (CHANNEL_BINDING_TYPE_TLS, DIGEST.hex()),
        (CHANNEL_BINDING_TYPE_TLS, None),
    ],
)
def test_only_a_32_byte_tls_spki_binding_is_collectable(binding_type, digest):
    with pytest.raises(CollectError):
        ChannelBinding(binding_type=binding_type, digest=digest)


# --- the nonce ---------------------------------------------------------------


def test_mint_nonce_is_a_validator_prefix_plus_caller_entropy():
    entropy = bytes(range(NONCE_ENTROPY_BYTES))
    nonce = mint_nonce(BOB, entropy=entropy)
    assert len(nonce) == NONCE_BYTES
    assert (
        nonce
        == hashlib.sha256(BOB.encode("ascii")).digest()[:NONCE_PREFIX_BYTES] + entropy
    )
    assert nonce == mint_nonce(BOB, entropy=bytearray(entropy))
    assert (
        nonce[:NONCE_PREFIX_BYTES]
        != mint_nonce(CHARLIE, entropy=entropy)[:NONCE_PREFIX_BYTES]
    )
    assert nonce[NONCE_PREFIX_BYTES:] == entropy


@pytest.mark.parametrize(
    "ss58, entropy",
    [
        (BOB, b""),
        (BOB, b"\x00" * 15),
        (BOB, b"\x00" * 17),
        (BOB, True),
        (BOB, "0" * 16),
        (BOB, None),
        ("", b"\x00" * 16),
        ("miner\u00e9", b"\x00" * 16),
        (None, b"\x00" * 16),
    ],
)
def test_mint_nonce_refuses_a_bad_identity_or_entropy(ss58, entropy):
    with pytest.raises(CollectError):
        mint_nonce(ss58, entropy=entropy)


def test_minting_a_nonce_never_draws_process_randomness(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("the collect nonce must not draw process randomness")

    for name in ("random", "randbytes", "getrandbits", "seed", "randint"):
        monkeypatch.setattr(random, name, deny)
    assert len(mint_nonce(BOB, entropy=b"\x01" * NONCE_ENTROPY_BYTES)) == NONCE_BYTES


# --- the request -------------------------------------------------------------


def test_the_request_carries_exactly_the_v2_keys_to_the_evidence_path():
    transport = transport_for()
    collect(transport)
    ((url, body),) = transport.calls
    assert url == URL
    assert set(body) == EVIDENCE_V2_REQUEST_KEYS
    assert body["nonce_hex"] == NONCE.hex()
    assert body["nonce_hex"] == body["nonce_hex"].lower()
    assert body["assigned_hotkey"] == BOB
    assert body["report_data_version"] == 2
    assert body["report_data_version"] is not True
    assert body["channel_binding_type"] == CHANNEL_BINDING_TYPE_TLS
    assert body["channel_binding_digest_hex"] == DIGEST.hex()


def test_a_base_url_gets_the_evidence_path_and_anything_else_is_refused():
    assert evidence_url("https://miner.example.test") == URL
    assert evidence_url("https://miner.example.test/") == URL
    assert evidence_url(URL) == URL
    assert (
        evidence_url("https://miner.example.test:8443/v1/evidence")
        == "https://miner.example.test:8443/v1/evidence"
    )
    ipv6 = "https://[2001:db8::1]/v1/evidence"
    assert evidence_url(ipv6) == ipv6
    assert evidence_url("https://[2001:db8::1]") == ipv6
    assert (
        evidence_url("https://[2001:db8::1]:8443/v1/evidence")
        == "https://[2001:db8::1]:8443/v1/evidence"
    )
    transport = transport_for()
    collect(transport, url=ipv6)
    assert transport.calls[0][0] == ipv6
    for bad in (
        "https://miner.example.test/v1/sat-work",
        "https://miner.example.test/v2/evidence",
        "https://miner.example.test/v1/evidence/",
        "http://miner.example.test/v1/evidence",
        "https://user:pass@miner.example.test/v1/evidence",
        "https://miner.example.test/v1/evidence?nonce=1",
        "https://miner.example.test/v1/evidence#frag",
        "",
        None,
    ):
        with pytest.raises(CollectError):
            evidence_url(bad)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"assigned_hotkey": ""},
        {"assigned_hotkey": "a" * 257},
        {"assigned_hotkey": "miner\u00e9"},
        {"assigned_hotkey": 7},
        {"nonce": b"\x00" * 31},
        {"nonce": bytearray(NONCE)},
        {"nonce": NONCE.hex()},
        {"channel_binding": None},
        {"channel_binding": {"binding_type": CHANNEL_BINDING_TYPE_TLS}},
    ],
)
def test_a_malformed_challenge_never_reaches_the_transport(kwargs):
    transport = transport_for()
    with pytest.raises(CollectError):
        collect(transport, **kwargs)
    assert transport.calls == []


def test_collect_has_no_default_transport():
    with pytest.raises(CollectError, match="injected EvidenceTransport"):
        collect(None)
    with pytest.raises(CollectError, match="injected EvidenceTransport"):
        collect(object())


@pytest.mark.parametrize("answer", [None, (200,), b"", (200, "{}"), (True, b"{}")])
def test_a_transport_that_answers_nonsense_is_refused(answer):
    class BadTransport:
        def post(self, url, body):
            return answer

    with pytest.raises(CollectError, match="transport must return"):
        collect(BadTransport())


# --- the happy path ----------------------------------------------------------


def test_a_well_formed_v2_answer_becomes_checked_evidence():
    transport = transport_for()
    collected = collect(transport)
    assert collected.kind == "tdx"
    assert collected.quote == QUOTE
    assert collected.nonce == NONCE
    assert collected.assigned_hotkey == BOB
    assert collected.cert_chain == (CERT,)
    assert collected.channel_binding == BINDING
    assert collected.report_data.hex() == PINNED_REPORT_DATA


def test_the_verifier_is_asked_about_the_report_data_this_validator_derived():
    gated, verifier = adapter(QuoteVerdict.PASS)
    collected = collect(transport_for())
    assert verify_collected(gated, collected) is QuoteVerdict.PASS
    assert verifier.calls == [(QUOTE, collected.report_data)]
    assert verifier.calls[0][1].hex() == PINNED_REPORT_DATA


def test_a_failing_verdict_is_reported_rather_than_swallowed():
    gated, _verifier = adapter(QuoteVerdict.FAIL)
    assert verify_collected(gated, collect(transport_for())) is QuoteVerdict.FAIL


def test_verify_collected_takes_the_gated_adapter_and_real_evidence():
    gated, _verifier = adapter()
    with pytest.raises(CollectError, match="CollectedEvidence"):
        verify_collected(gated, object())
    with pytest.raises(CollectError, match="ComputeAdapter"):
        verify_collected(MockQuoteVerifier(), collect(transport_for()))


def test_an_empty_certificate_chain_is_allowed_and_bounded():
    collected = collect(transport_for(cert_chain_hex=[]))
    assert collected.cert_chain == ()
    chain = [CERT.hex()] * MAX_EVIDENCE_CERTIFICATES
    assert len(collect(transport_for(cert_chain_hex=chain)).cert_chain) == (
        MAX_EVIDENCE_CERTIFICATES
    )


def test_mixed_case_quote_hex_is_accepted_but_embedded_space_is_not():
    assert collect(transport_for(quote_hex=QUOTE.hex().upper())).quote == QUOTE
    # `bytes.fromhex` ignores embedded whitespace; the character set is checked
    # first so a padded string is not silently the same quote.
    with pytest.raises(CollectError, match="not hex"):
        collect(transport_for(quote_hex=" " + QUOTE.hex() + " "))


# --- every refusal -----------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"nonce_hex": bytes(32).hex()},
        {"nonce_hex": NONCE.hex().upper()},
        {"nonce_hex": 7},
        {"assigned_hotkey": CHARLIE},
        {"channel_binding_digest_hex": bytes(32).hex()},
        {"channel_binding_type": "application_key_sha256"},
        {"channel_binding_type": 7},
        {"channel_binding_digest_hex": DIGEST.hex()[:62]},
        {"kind": "gpu_cc"},
        {"kind": 7},
        {"report_data_version": 1},
        {"report_data_version": True},
        {"report_data_version": 2.0},
        {"report_data_version": "2"},
        {"quote_hex": ""},
        {"quote_hex": "abc"},
        {"quote_hex": "00" * (MAX_QUOTE_BYTES + 1)},
        {"cert_chain_hex": CERT.hex()},
        {"cert_chain_hex": [""]},
        {"cert_chain_hex": [CERT.hex()] * (MAX_EVIDENCE_CERTIFICATES + 1)},
        {"cert_chain_hex": ["00" * (MAX_CERTIFICATE_BYTES + 1)]},
        {"cert_chain_hex": [None]},
    ],
)
def test_an_answer_that_is_not_what_was_asked_for_is_refused(overrides):
    with pytest.raises(CollectError):
        collect(transport_for(**overrides))


def test_a_strict_sev_snp_answer_is_collected_without_tdx_fallback():
    evidence = collect(transport_for(kind="sev_snp"))
    assert evidence.kind == "sev_snp"


def test_a_v1_answer_is_refused_because_it_binds_no_channel():
    body = v2_response()
    for key in (
        "report_data_version",
        "channel_binding_type",
        "channel_binding_digest_hex",
    ):
        body.pop(key)
    transport = FakeTransport(body=json.dumps(body).encode("utf-8"))
    with pytest.raises(CollectError, match="missing"):
        collect(transport)


def test_an_evidence_bundle_is_refused_because_this_lane_is_cpu_only():
    bundle = {"evidence": [v2_response(), v2_response(kind="gpu_cc")]}
    transport = FakeTransport(body=json.dumps(bundle).encode("utf-8"))
    with pytest.raises(CollectError, match="unknown keys"):
        collect(transport)


def test_an_extra_key_is_refused_rather_than_ignored():
    transport = transport_for(composite_jwt="a.b.c")
    with pytest.raises(CollectError, match="composite_jwt"):
        collect(transport)


@pytest.mark.parametrize("status", [201, 204, 301, 302, 307, 400, 403, 500, 0, -1])
def test_any_status_but_200_is_a_refusal_and_redirects_are_never_followed(status):
    transport = FakeTransport(
        status=status, body=json.dumps(v2_response()).encode("utf-8")
    )
    with pytest.raises(CollectError, match="redirects are never followed"):
        collect(transport)


def test_an_oversize_body_is_refused_before_it_is_parsed():
    padded = v2_response(quote_hex="ab" * 1024)
    padded["assigned_hotkey"] = BOB
    raw = json.dumps(padded).encode("utf-8")
    raw = raw + b" " * (MAX_EVIDENCE_RESPONSE_BYTES + 1 - len(raw))
    with pytest.raises(CollectError, match="byte bound"):
        collect(FakeTransport(body=raw))


def test_a_duplicate_json_key_is_refused_by_the_strict_parser():
    raw = json.dumps(v2_response()).encode("utf-8")
    duplicated = raw[:-1] + b',"kind":"gpu_cc"}'
    with pytest.raises(CollectError, match="duplicate key"):
        collect(FakeTransport(body=duplicated))


@pytest.mark.parametrize(
    "raw",
    [b"", b"not json", b"[]", b'"tdx"', b"null", b"\xff\xfe", b"{}"],
)
def test_a_body_that_is_not_a_v2_json_object_is_refused(raw):
    with pytest.raises(CollectError):
        collect(FakeTransport(body=raw))


# --- the fleet cap -----------------------------------------------------------


def fleet_targets(count: int) -> list[FleetTarget]:
    return [
        FleetTarget(
            url=f"https://machine-{index}.example.test/v1/evidence",
            nonce=index.to_bytes(NONCE_BYTES, "big"),
            channel_binding=BINDING,
        )
        for index in range(count)
    ]


def test_an_over_cap_fleet_refuses_the_whole_miner_rather_than_truncating():
    transport = transport_for()
    with pytest.raises(CollectError, match="rather than the fleet being truncated"):
        collect_miner_fleet(
            fleet_targets(COMPUTE_FLEET_CAP + 1),
            assigned_hotkey=BOB,
            transport=transport,
        )
    assert transport.calls == []


def test_a_fleet_within_the_cap_is_collected_machine_by_machine():
    targets = fleet_targets(3)
    bodies = [
        json.dumps(v2_response(nonce_hex=target.nonce.hex())).encode("utf-8")
        for target in targets
    ]

    class ScriptedTransport:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict]] = []

        def post(self, url, body):
            self.calls.append((url, dict(body)))
            return 200, bodies[len(self.calls) - 1]

    transport = ScriptedTransport()
    collected = collect_miner_fleet(targets, assigned_hotkey=BOB, transport=transport)
    assert [item.nonce for item in collected] == [t.nonce for t in targets]
    assert [url for url, _body in transport.calls] == [t.url for t in targets]


def test_two_machines_may_not_share_one_challenge_nonce():
    targets = fleet_targets(2)
    shared = [
        FleetTarget(url=t.url, nonce=NONCE, channel_binding=BINDING) for t in targets
    ]
    with pytest.raises(CollectError, match="its own nonce"):
        collect_miner_fleet(shared, assigned_hotkey=BOB, transport=transport_for())


@pytest.mark.parametrize("targets", ["https://a.test/v1/evidence", [object()], 7])
def test_a_fleet_must_be_a_sequence_of_targets(targets):
    with pytest.raises(CollectError, match="FleetTarget"):
        collect_miner_fleet(targets, assigned_hotkey=BOB, transport=transport_for())


# --- collect still moves no mass ---------------------------------------------


def test_a_passing_collect_leaves_compute_at_allocation_zero(tmp_path):
    gated, verifier = adapter(QuoteVerdict.PASS)
    collected = collect(transport_for())
    assert verify_collected(gated, collected) is QuoteVerdict.PASS
    assert gated.probe(anchor=ANCHOR, view=burn_only_view()) == {}
    assert gated.contributing is False

    bundle, registry = funded_compute_bundle()
    result = compose_dry_run(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=burn_only_view(),
        inclusion_view=burn_only_view(),
        adapters={COMPUTE_LANE: gated},
        journal_path=journal_path(tmp_path),
    )
    assert result.status == STATUS_BROADCAST_BLOCKED
    assert result.broadcast_eligible is False
    assert (result.dests, result.weights) == ((BURN_UID,), (65535,))
    assert "cathedralai/cathedral-validator#120" in result.reason
    assert "allocation 0" in result.reason
    assert [block.reason for block in result.blocks] == [COMPUTE_BLOCK_REASON]
    # Composing asked the adapter nothing; the only verify call is the collect.
    assert len(verifier.calls) == 1


def test_nothing_on_the_collect_path_opens_a_socket(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("the collect path must not dial anything")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    gated, _verifier = adapter()
    collected = collect(transport_for())
    assert verify_collected(gated, collected) is QuoteVerdict.PASS
    assert evidence_url("https://miner.example.test") == URL


def test_the_collect_module_names_no_writer_and_no_cathedral_host():
    source = Path(collect_module.__file__).read_text(encoding="utf-8")
    for needle in (
        "SatLane",
        "neuron.validator",
        "api.cathedral.computer",
        "weights/next",
        "thin-state.json",
        "fetch_vector",
        "set_weights",
        "import random",
        "/v1/sat-work",
    ):
        assert needle not in source, needle


def test_the_response_key_set_is_the_request_key_set_plus_the_evidence():
    assert EVIDENCE_V2_RESPONSE_KEYS - EVIDENCE_V2_REQUEST_KEYS == {
        "kind",
        "quote_hex",
        "cert_chain_hex",
    }
    assert EVIDENCE_V2_REQUEST_KEYS < EVIDENCE_V2_RESPONSE_KEYS
