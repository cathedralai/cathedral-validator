"""The Compute lane is named, gated on QVL, and still worth zero mass.

Three separate claims, because they fail in different ways:

1. the adapter cannot be constructed without a quote verifier, and cannot be
   pointed at collateral served by anyone but Intel's public PCS;
2. a constructed adapter with a verifier that PASSes everything still probes to
   no mass, and a funded Compute row with that adapter registered is still
   ``BROADCAST_BLOCKED`` -- with the #120 / QVL reason, not a generic one;
3. machine identity is the bound key's digest, so two hotkeys cannot both hold
   one machine, and the audit seed is derived rather than drawn.

Nothing here reaches the network: the verifier is injected, and the collateral
URL is validated without a lookup. One test proves that by denying sockets.
"""

from __future__ import annotations

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
from cathedral_thin.independent import compute as compute_module
from cathedral_thin.independent.compose import (
    STATUS_BROADCAST_BLOCKED,
    EpochAnchor,
    compose_dry_run,
    mass_map,
)
from cathedral_thin.independent.compute import (
    COMPUTE_BLOCK_REASON,
    COMPUTE_FLEET_CAP,
    COMPUTE_LANE,
    INTEL_PCS_HOSTS,
    MAX_QUOTE_BYTES,
    REPORT_DATA_BYTES,
    ComputeAdapter,
    QuoteVerdict,
    assert_machine_identity,
    canonical_seed_material,
    fleet_over_cap,
    machine_id_from_key,
    require_compute_adapter,
    validate_collateral_url,
)
from cathedral_thin.independent.constants import H, INDEPENDENT_STATE_FILE
from cathedral_thin.independent.errors import (
    AdapterUnavailable,
    BroadcastDisabled,
    CollateralSourceError,
    ComputeEvidenceError,
    ConfigError,
    MachineIdentityConflict,
)
from cathedral_thin.independent.journal import load_journal

ANCHOR = EpochAnchor(
    epoch_open=EPOCH_OPEN, anchor_number=EPOCH_OPEN - 1, anchor_hash=ANCHOR_HASH
)

INTEL_COLLATERAL = "https://api.trustedservices.intel.com/sgx/certification/v4/"
CATHEDRAL_COLLATERAL = "https://api.cathedral.computer/v1/qvl/collateral"

QUOTE = b"tdx-quote" * 16
REPORT_DATA = bytes(range(REPORT_DATA_BYTES))
BOUND_KEY = bytes(range(32))


class MockQuoteVerifier:
    """A verifier that answers whatever it was told to, and remembers asking."""

    def __init__(self, result: QuoteVerdict = QuoteVerdict.PASS) -> None:
        self.result = result
        self.calls: list[tuple[bytes, bytes]] = []

    def verify(self, quote: bytes, *, expected_report_data: bytes) -> QuoteVerdict:
        self.calls.append((quote, expected_report_data))
        return self.result


def adapter(
    result: QuoteVerdict = QuoteVerdict.PASS, **kwargs
) -> tuple[ComputeAdapter, MockQuoteVerifier]:
    verifier = MockQuoteVerifier(result)
    return ComputeAdapter(
        verifier, collateral_base_url=INTEL_COLLATERAL, **kwargs
    ), verifier


def journal_path(tmp_path):
    return tmp_path / INDEPENDENT_STATE_FILE.name


def funded_compute_bundle():
    economics = economics_document(
        burn_amount=H - 10**11,
        allocations=[lane_row(COMPUTE_LANE_DOCUMENT, 10**11)],
    )
    return signed_bundle(economics=economics)


def test_the_lane_id_is_the_one_the_signed_document_names():
    assert COMPUTE_LANE.as_dict() == COMPUTE_LANE_DOCUMENT


def test_an_adapter_without_a_quote_verifier_does_not_exist():
    with pytest.raises(AdapterUnavailable, match="cpu_quote_verifier=None"):
        ComputeAdapter(None, collateral_base_url=INTEL_COLLATERAL)
    with pytest.raises(AdapterUnavailable, match="no verify"):
        ComputeAdapter(object(), collateral_base_url=INTEL_COLLATERAL)
    with pytest.raises(AdapterUnavailable, match="cpu_quote_verifier=None"):
        require_compute_adapter(None)
    verifier = MockQuoteVerifier()
    assert require_compute_adapter(verifier) is verifier


def test_a_verify_attribute_that_is_not_callable_is_not_a_verifier():
    class NotAVerifier:
        verify = "definitely"

    with pytest.raises(AdapterUnavailable, match="no verify"):
        ComputeAdapter(NotAVerifier(), collateral_base_url=INTEL_COLLATERAL)


@pytest.mark.parametrize("host", sorted(INTEL_PCS_HOSTS))
def test_intel_pcs_collateral_is_accepted(host):
    endpoint = validate_collateral_url(f"https://{host}/sgx/certification/v4/")
    assert (endpoint.host, endpoint.port) == (host, 443)


@pytest.mark.parametrize(
    "url",
    [
        CATHEDRAL_COLLATERAL,
        "https://cathedral.computer/qvl",
        "http://api.trustedservices.intel.com/sgx/",
        "https://api.trustedservices.intel.com.evil.test/sgx/",
        "https://user:pass@api.trustedservices.intel.com/sgx/",
        "https://api.trustedservices.intel.com:8443/sgx/",
        "https://api.trustedservices.intel.com/sgx/?tcb=latest",
    ],
)
def test_collateral_from_anywhere_but_intel_pcs_is_refused(url):
    with pytest.raises(CollateralSourceError):
        validate_collateral_url(url)
    with pytest.raises(CollateralSourceError):
        ComputeAdapter(MockQuoteVerifier(), collateral_base_url=url)


def test_the_qvl_digest_is_an_unfilled_pin_rather_than_a_default():
    unpinned, _verifier = adapter()
    assert unpinned.qvl_digest is None
    assert unpinned.qvl_unpinned is True
    pinned, _verifier = adapter(qvl_digest="ab" * 32)
    assert pinned.qvl_unpinned is False
    with pytest.raises(ConfigError, match="64 lowercase hex"):
        adapter(qvl_digest="AB" * 32)
    with pytest.raises(ConfigError, match="64 lowercase hex"):
        adapter(qvl_digest="ab")


def test_probe_returns_no_mass_even_when_the_verifier_passes():
    passing, verifier = adapter(QuoteVerdict.PASS)
    assert passing.verify_quote(QUOTE, expected_report_data=REPORT_DATA) is (
        QuoteVerdict.PASS
    )
    assert verifier.calls == [(QUOTE, REPORT_DATA)]
    assert passing.probe(anchor=ANCHOR, view=burn_only_view()) == {}
    assert passing.contributing is False


def test_evidence_is_bounded_and_typed_before_the_verifier_sees_it():
    gated, verifier = adapter()
    with pytest.raises(ComputeEvidenceError, match="non-empty bytes"):
        gated.verify_quote(b"", expected_report_data=REPORT_DATA)
    with pytest.raises(ComputeEvidenceError, match="non-empty bytes"):
        gated.verify_quote("not bytes", expected_report_data=REPORT_DATA)
    with pytest.raises(ComputeEvidenceError, match="byte bound"):
        gated.verify_quote(
            b"\x00" * (MAX_QUOTE_BYTES + 1), expected_report_data=REPORT_DATA
        )
    with pytest.raises(ComputeEvidenceError, match="REPORT_DATA"):
        gated.verify_quote(QUOTE, expected_report_data=b"\x00" * 32)
    assert verifier.calls == []


def test_a_verifier_that_answers_nonsense_is_infra_not_a_pass():
    class ConfusedVerifier:
        def verify(self, quote, *, expected_report_data):
            return True

    confused = ComputeAdapter(ConfusedVerifier(), collateral_base_url=INTEL_COLLATERAL)
    verdict = confused.verify_quote(QUOTE, expected_report_data=REPORT_DATA)
    assert verdict is QuoteVerdict.INFRA


def test_a_funded_compute_row_with_a_qvl_adapter_names_its_blockers(tmp_path):
    bundle, registry = funded_compute_bundle()
    gated, verifier = adapter(QuoteVerdict.PASS)
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
    # The unpayable mass folds to burn; it is never spread over survivors.
    assert (result.dests, result.weights) == ((BURN_UID,), (65535,))
    assert "allocation 0" in result.reason
    assert "cathedralai/cathedral-validator#120" in result.reason
    assert "QVL" in result.reason
    assert [block.reason for block in result.blocks] == [COMPUTE_BLOCK_REASON]
    assert [block.amount for block in result.blocks] == [10**11]
    # Composing never asked the adapter anything: the allocation is the gate.
    assert verifier.calls == []

    record = load_journal(journal_path(tmp_path))
    assert record["status"] == STATUS_BROADCAST_BLOCKED
    assert record["broadcast"] is False
    assert record["blocks"][0]["lane_contract_id"] == COMPUTE_LANE_DOCUMENT
    assert record["blocks"][0]["reason"] == COMPUTE_BLOCK_REASON


def test_a_funded_compute_row_without_an_adapter_is_still_blocked(tmp_path):
    bundle, registry = funded_compute_bundle()
    result = compose_dry_run(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=burn_only_view(),
        inclusion_view=burn_only_view(),
        adapters={},
        journal_path=journal_path(tmp_path),
    )
    assert result.status == STATUS_BROADCAST_BLOCKED
    assert "no adapter" in result.reason
    assert result.dests == (BURN_UID,)


def test_a_non_compute_adapter_on_the_compute_lane_gets_the_generic_reason():
    """The named reason belongs to the gated adapter, not to the lane row."""
    bundle, _registry = funded_compute_bundle()
    _dests, blocks = mass_map(
        bundle, burn_uid=BURN_UID, adapters={COMPUTE_LANE: object()}
    )
    assert [block.reason for block in blocks] != [COMPUTE_BLOCK_REASON]
    assert "deferred at allocation 0" in blocks[0].reason


def test_a_compute_adapter_never_makes_broadcast_reachable(tmp_path):
    bundle, registry = funded_compute_bundle()
    gated, _verifier = adapter()
    with pytest.raises(BroadcastDisabled, match="no chain writer"):
        compose_dry_run(
            bundle=bundle,
            key_registry=registry,
            commitment=commitment_for(bundle),
            anchor=ANCHOR,
            anchor_view=burn_only_view(),
            inclusion_view=burn_only_view(),
            adapters={COMPUTE_LANE: gated},
            journal_path=journal_path(tmp_path),
            broadcast=True,
        )
    assert not journal_path(tmp_path).exists()


def test_the_machine_identity_is_the_bound_key_digest():
    machine_id = machine_id_from_key(BOUND_KEY)
    assert machine_id == machine_id_from_key(bytearray(BOUND_KEY))
    assert len(machine_id) == 64
    assert machine_id != machine_id_from_key(bytes(range(1, 33)))
    for bad in (b"", b"\x00" * 31, True, "ab" * 32, None, 32):
        with pytest.raises(ComputeEvidenceError):
            machine_id_from_key(bad)


def test_two_hotkeys_claiming_one_machine_are_both_unproven():
    machine_id = machine_id_from_key(BOUND_KEY)
    claimed: dict[str, str] = {}
    assert_machine_identity(machine_id, BOB, claimed)
    # A miner re-advertising its own machine is not a conflict.
    assert_machine_identity(machine_id, BOB, claimed)
    assert claimed == {machine_id: BOB}
    with pytest.raises(MachineIdentityConflict, match="NOT_PROVEN"):
        assert_machine_identity(machine_id, CHARLIE, claimed)
    assert claimed == {machine_id: BOB}
    with pytest.raises(ComputeEvidenceError, match="64 lowercase hex"):
        assert_machine_identity("nope", BOB, {})
    with pytest.raises(ComputeEvidenceError, match="ASCII"):
        assert_machine_identity(machine_id, "", {})


def test_an_over_cap_fleet_zeros_the_miner_rather_than_being_truncated():
    assert COMPUTE_FLEET_CAP == 256
    assert fleet_over_cap(0) is False
    assert fleet_over_cap(COMPUTE_FLEET_CAP) is False
    assert fleet_over_cap(COMPUTE_FLEET_CAP + 1) is True
    for bad in (True, -1, 2.0, "12"):
        with pytest.raises(ComputeEvidenceError):
            fleet_over_cap(bad)


def test_the_audit_seed_is_derived_and_never_drawn(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("the audit seed must not use process randomness")

    for name in ("random", "randbytes", "getrandbits", "seed", "randint"):
        monkeypatch.setattr(random, name, deny)
    machine_id = machine_id_from_key(BOUND_KEY)
    material = canonical_seed_material(
        anchor_hash=ANCHOR_HASH, miner_ss58=BOB, machine_id=machine_id
    )
    assert len(material) == 32
    assert material == canonical_seed_material(
        anchor_hash=ANCHOR_HASH, miner_ss58=BOB, machine_id=machine_id
    )
    assert material != canonical_seed_material(
        anchor_hash=ANCHOR_HASH, miner_ss58=CHARLIE, machine_id=machine_id
    )
    assert material != canonical_seed_material(
        anchor_hash=ANCHOR_HASH,
        miner_ss58=BOB,
        machine_id=machine_id_from_key(bytes(range(1, 33))),
    )
    assert material != canonical_seed_material(
        anchor_hash="0x" + "cd" * 32, miner_ss58=BOB, machine_id=machine_id
    )
    for bad_anchor in ("0xabc", "ab" * 32, "0x" + "AB" * 32):
        with pytest.raises(ComputeEvidenceError, match="anchor_hash"):
            canonical_seed_material(
                anchor_hash=bad_anchor, miner_ss58=BOB, machine_id=machine_id
            )


def test_nothing_on_this_path_opens_a_socket(monkeypatch, tmp_path):
    def deny(*args, **kwargs):
        raise AssertionError("the Compute path must not dial anything")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    gated, _verifier = adapter()
    assert gated.collateral_endpoint.host in INTEL_PCS_HOSTS
    assert gated.probe(anchor=ANCHOR, view=burn_only_view()) == {}
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


def test_the_compute_module_names_no_dispatcher_and_no_cathedral_host():
    source = Path(compute_module.__file__).read_text(encoding="utf-8")
    for needle in (
        "SatLane",
        "neuron.validator",
        "api.cathedral.computer",
        "import random",
        "set_weights",
    ):
        assert needle not in source, needle
