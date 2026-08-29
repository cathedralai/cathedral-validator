from __future__ import annotations

import hashlib
from dataclasses import replace
from itertools import permutations
from types import SimpleNamespace

import pytest

from _independent_fixtures import BOB, CHARLIE
from cathedral_thin.independent.constants import (
    MAX_DESTS,
    MULTICOMPUTE_FLEET_CAP,
    MULTICOMPUTE_MACHINE_WORK_UNIT_CAP,
)
from cathedral_thin.independent.compute import machine_id_from_stable_platform_id
from cathedral_thin.independent.compute import (
    ComputeAdapter,
    QuoteIdentityVerdict,
    QuoteVerdict,
)
from cathedral_thin.independent.collect import ChannelBinding, CollectedEvidence
from cathedral_thin.independent.constants import CANARY_HOTKEY
from cathedral_thin.independent.errors import ComputeEvidenceError
from cathedral_thin.independent_runtime.multicompute import (
    REASON_DUPLICATE_ENDPOINT,
    REASON_DUPLICATE_CHANNEL,
    REASON_DUPLICATE_HARDWARE,
    REASON_FLEET_OVER_CAP,
    REASON_STALE_WINDOW,
    REASON_WORK_OVER_CAP,
    MachineWorkObservation,
    aggregate_multicompute_units,
)
from cathedral_thin.independent_runtime.score import mass_from_units
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.errors import IndependentLiveError
from cathedral_thin.independent_runtime.https import HttpsEvidenceTransport
from cathedral_thin.independent_runtime.validator_request import FleetDiscovery
from cathedral_thin.independent_runtime import fleet_score

WINDOW = "0x" + "ab" * 32
OTHER_WINDOW = "0x" + "cd" * 32
PLATFORM_A = "tdx-platform-sha256:" + "a" * 64
PLATFORM_B = "tdx-platform-sha256:" + "b" * 64
PLATFORM_C = "tdx-platform-sha256:" + "c" * 64


def observation(
    *,
    uid: int = 8,
    hotkey: str = BOB,
    endpoint: str = "https://1.1.1.1:8081",
    platform: str = PLATFORM_A,
    channel: str | None = None,
    window: str = WINDOW,
    units: int | None = 20,
) -> MachineWorkObservation:
    return MachineWorkObservation(
        scoring_window=window,
        uid=uid,
        miner_hotkey=hotkey,
        endpoint=endpoint,
        channel_id=channel or hashlib.sha256(endpoint.encode()).hexdigest(),
        machine_id=machine_id_from_stable_platform_id(platform),
        evidence_fresh=True,
        hardware_verified=True,
        channel_bound=True,
        work_units=units,
    )


def test_raw_uid_score_is_sum_of_distinct_verified_work_only():
    rows = (
        observation(),
        observation(endpoint="https://8.8.8.8:8081", platform=PLATFORM_B),
        observation(
            uid=124,
            hotkey=CHARLIE,
            endpoint="https://9.9.9.9:8081",
            platform=PLATFORM_C,
        ),
    )
    score = aggregate_multicompute_units(rows, scoring_window=WINDOW)
    assert score.uid_units == {8: 40, 124: 20}
    assert score.hotkey_units == {BOB: 40, CHARLIE: 20}
    assert all(row.paid for row in score.machines)
    mass = mass_from_units(600, score.hotkey_units)
    assert mass == {BOB: 400, CHARLIE: 200}


def test_equal_verified_work_earns_equal_regardless_of_fleet_size():
    rows = (
        observation(units=10),
        observation(
            uid=124,
            hotkey=CHARLIE,
            endpoint="https://8.8.8.8:8081",
            platform=PLATFORM_B,
            units=10,
        ),
    )
    score = aggregate_multicompute_units(rows, scoring_window=WINDOW)
    assert score.hotkey_units == {BOB: 10, CHARLIE: 10}
    assert mass_from_units(100, score.hotkey_units) == {BOB: 50, CHARLIE: 50}


def test_duplicate_endpoint_zeros_every_claimant_without_iteration_winner():
    rows = (
        observation(),
        observation(
            uid=124,
            hotkey=CHARLIE,
            platform=PLATFORM_B,
        ),
        observation(
            endpoint="https://8.8.8.8:8081",
            platform=PLATFORM_C,
        ),
    )
    score = aggregate_multicompute_units(rows, scoring_window=WINDOW)
    assert score.hotkey_units == {BOB: 20}
    duplicate_rows = [
        row for row in score.machines if REASON_DUPLICATE_ENDPOINT in row.reasons
    ]
    assert len(duplicate_rows) == 2
    assert {row.miner_hotkey for row in duplicate_rows} == {BOB, CHARLIE}
    assert all(row.units == 0 for row in duplicate_rows)


def test_duplicate_stable_platform_id_zeros_every_endpoint_and_uid():
    rows = (
        observation(),
        observation(
            uid=124,
            hotkey=CHARLIE,
            endpoint="https://8.8.8.8:8081",
            platform=PLATFORM_A,
        ),
        observation(
            endpoint="https://9.9.9.9:8081",
            platform=PLATFORM_C,
        ),
    )
    score = aggregate_multicompute_units(rows, scoring_window=WINDOW)
    assert score.hotkey_units == {BOB: 20}
    duplicates = [
        row for row in score.machines if REASON_DUPLICATE_HARDWARE in row.reasons
    ]
    assert len(duplicates) == 2
    assert all(row.units == 0 for row in duplicates)


def test_duplicate_tls_channel_zeros_distinct_verified_platforms():
    copied_channel = "d" * 64
    score = aggregate_multicompute_units(
        (
            observation(channel=copied_channel),
            observation(
                uid=124,
                hotkey=CHARLIE,
                endpoint="https://8.8.8.8:8081",
                platform=PLATFORM_B,
                channel=copied_channel,
            ),
        ),
        scoring_window=WINDOW,
    )
    assert score.hotkey_units == {}
    assert all(REASON_DUPLICATE_CHANNEL in row.reasons for row in score.machines)


def test_duplicate_conflicts_and_totals_are_invariant_to_batch_order():
    rows = (
        observation(),
        observation(
            uid=124,
            hotkey=CHARLIE,
            platform=PLATFORM_B,
        ),
        observation(
            endpoint="https://8.8.8.8:8081",
            platform=PLATFORM_C,
        ),
        observation(
            uid=124,
            hotkey=CHARLIE,
            endpoint="https://9.9.9.9:8081",
            platform=PLATFORM_C,
        ),
    )
    expected = aggregate_multicompute_units(rows, scoring_window=WINDOW)
    for order in permutations(rows):
        assert aggregate_multicompute_units(order, scoring_window=WINDOW) == expected


def test_over_cap_zeros_the_entire_uid_but_not_another_uid():
    rows = [
        observation(
            endpoint=f"https://1.1.1.1:{8000 + index}",
            platform="tdx-platform-sha256:" + f"{index + 1:064x}",
        )
        for index in range(MULTICOMPUTE_FLEET_CAP + 1)
    ]
    rows.append(
        observation(
            uid=124,
            hotkey=CHARLIE,
            endpoint="https://8.8.8.8:8081",
            platform=PLATFORM_C,
        )
    )
    score = aggregate_multicompute_units(rows, scoring_window=WINDOW)
    assert score.hotkey_units == {CHARLIE: 20}
    bob_rows = [row for row in score.machines if row.miner_hotkey == BOB]
    assert len(bob_rows) == MULTICOMPUTE_FLEET_CAP + 1
    assert all(REASON_FLEET_OVER_CAP in row.reasons for row in bob_rows)


def test_stale_or_over_unit_machine_is_zero_not_clipped():
    rows = (
        observation(window=OTHER_WINDOW),
        observation(
            endpoint="https://8.8.8.8:8081",
            platform=PLATFORM_B,
            units=MULTICOMPUTE_MACHINE_WORK_UNIT_CAP + 1,
        ),
    )
    score = aggregate_multicompute_units(rows, scoring_window=WINDOW)
    assert score.hotkey_units == {}
    assert REASON_STALE_WINDOW in score.machines[0].reasons
    assert REASON_WORK_OVER_CAP in score.machines[1].reasons


@pytest.mark.parametrize(
    "changes",
    [
        {"hardware_verified": False},
        {"channel_bound": False},
        {"evidence_fresh": False},
        {"work_units": None},
        {"work_units": 0},
    ],
)
def test_every_unverified_fact_fails_closed(changes):
    if not changes.get("hardware_verified", True) or not changes.get(
        "evidence_fresh", True
    ):
        changes["machine_id"] = None
    row = replace(observation(), **changes)
    score = aggregate_multicompute_units((row,), scoring_window=WINDOW)
    assert score.hotkey_units == {}
    assert score.machines[0].paid is False


def test_unverified_manifest_claim_does_not_poison_a_verified_endpoint():
    failed = replace(
        observation(uid=124, hotkey=CHARLIE),
        machine_id=None,
        evidence_fresh=False,
        hardware_verified=False,
        channel_bound=False,
        work_units=None,
    )
    score = aggregate_multicompute_units((observation(), failed), scoring_window=WINDOW)
    assert score.hotkey_units == {BOB: 20}
    assert REASON_DUPLICATE_ENDPOINT not in score.machines[0].reasons


def test_capacity_declarations_are_not_part_of_the_score_contract():
    with pytest.raises(TypeError):
        MachineWorkObservation(
            **observation().__dict__,
            declared_vcpus=96,
        )


def test_uid_hotkey_mapping_and_platform_identity_are_strict():
    with pytest.raises(ComputeEvidenceError, match="one-to-one"):
        aggregate_multicompute_units(
            (
                observation(),
                observation(hotkey=CHARLIE, endpoint="https://8.8.8.8:8081"),
            ),
            scoring_window=WINDOW,
        )
    with pytest.raises(ComputeEvidenceError, match="machine_id"):
        aggregate_multicompute_units(
            (replace(observation(), machine_id="not-a-machine-id"),),
            scoring_window=WINDOW,
        )


class _IdentityVerifier:
    def verify(self, quote, *, expected_report_data):
        del quote, expected_report_data
        return QuoteVerdict.PASS

    def verify_with_identity(self, quote, *, expected_report_data):
        del expected_report_data
        marker = quote[-1]
        if marker == 255:
            return QuoteIdentityVerdict(QuoteVerdict.PASS, None, False)
        return QuoteIdentityVerdict(
            QuoteVerdict.PASS,
            "tdx-platform-sha256:" + f"{marker:064x}",
            True,
        )


class _NoNetworkHttps(HttpsEvidenceTransport):
    pass


def _runtime_adapter() -> ComputeAdapter:
    return ComputeAdapter(
        _IdentityVerifier(),
        collateral_base_url="https://api.trustedservices.intel.com/sgx/certification/v4/",
        qvl_digest="a" * 64,
    )


def _runtime_collected(hotkey: str, *, marker: int, spki: bytes) -> CollectedEvidence:
    return CollectedEvidence(
        kind="tdx",
        quote=b"quote" + bytes([marker]),
        nonce=b"n" * 32,
        assigned_hotkey=hotkey,
        cert_chain=(),
        channel_binding=ChannelBinding("tls_spki_sha256", spki),
        report_data=b"r" * 64,
    )


def _runtime_keypair():
    return SimpleNamespace(ss58_address=CANARY_HOTKEY, sign=lambda _body: b"s" * 64)


def test_runtime_attests_chain_axon_before_trusting_fleet_and_scores_two(monkeypatch):
    events: list[str] = []
    root = "https://1.1.1.1:8081"
    second = "https://8.8.8.8:8081"
    evidence = {
        root: _runtime_collected(BOB, marker=1, spki=b"a" * 32),
        second: _runtime_collected(BOB, marker=2, spki=b"b" * 32),
    }

    def collect(*, evidence_url, sat_url, hotkey, validator_ss58, keypair):
        del validator_ss58, sat_url, keypair
        endpoint = evidence_url.removesuffix("/v1/evidence")
        events.append(f"evidence:{endpoint}")
        return {
            "hotkey": hotkey,
            "sat_url": endpoint + "/v1/sat-work",
            "collected": evidence[endpoint],
        }

    def fleet(*, primary_origin, worker_hotkey, transport):
        assert events == [f"evidence:{root}"]
        assert worker_hotkey == BOB
        assert transport.expected_spki == b"a" * 32
        events.append("fleet")
        return FleetDiscovery(BOB, (primary_origin, second), False)

    def units(*, anchor_hash, collected, sat_url, keypair):
        del anchor_hash, sat_url
        del keypair
        return 20

    monkeypatch.setattr(fleet_score, "HttpsEvidenceTransport", _NoNetworkHttps)
    monkeypatch.setattr(fleet_score, "_try_collect", collect)
    monkeypatch.setattr(fleet_score, "fetch_worker_fleet", fleet)
    monkeypatch.setattr(fleet_score, "_units_after_quote", units)
    result = fleet_score.score_multicompute_round(
        axons=(ServingAxon(8, BOB, "1.1.1.1", 8081),),
        keypair=_runtime_keypair(),
        anchor_hash=WINDOW,
        verifier_adapter=_runtime_adapter(),
    )
    assert events == [f"evidence:{root}", "fleet", f"evidence:{second}"]
    assert result.verified_units == {BOB: 40}
    assert [row["counted_units"] for row in result.rows] == [20, 20]
    assert result.feature_blocked is False


def test_unverified_root_never_authorizes_its_fleet(monkeypatch):
    called = False

    def collect(*, evidence_url, sat_url, hotkey, validator_ss58, keypair):
        del evidence_url, validator_ss58, sat_url, keypair
        return {
            "hotkey": hotkey,
            "sat_url": "https://1.1.1.1:8081/v1/sat-work",
            "collected": _runtime_collected(hotkey, marker=255, spki=b"a" * 32),
        }

    def fleet(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("unverified root must not authorize fleet discovery")

    monkeypatch.setattr(fleet_score, "HttpsEvidenceTransport", _NoNetworkHttps)
    monkeypatch.setattr(fleet_score, "_try_collect", collect)
    monkeypatch.setattr(fleet_score, "fetch_worker_fleet", fleet)
    result = fleet_score.score_multicompute_round(
        axons=(ServingAxon(8, BOB, "1.1.1.1", 8081),),
        keypair=_runtime_keypair(),
        anchor_hash=WINDOW,
        verifier_adapter=_runtime_adapter(),
    )
    assert called is False
    assert result.verified_units == {}
    assert result.feature_blocked is False
    assert result.blockers == ()


def test_missing_verifier_identity_capability_blocks_before_any_miner_request(
    monkeypatch,
):
    class LegacyVerifier:
        def verify(self, quote, *, expected_report_data):
            del quote, expected_report_data
            return QuoteVerdict.PASS

    adapter = ComputeAdapter(
        LegacyVerifier(),
        collateral_base_url=(
            "https://api.trustedservices.intel.com/sgx/certification/v4/"
        ),
        qvl_digest="a" * 64,
    )
    monkeypatch.setattr(
        fleet_score,
        "_try_collect",
        lambda **_kwargs: pytest.fail("capability failure reached miner evidence"),
    )
    result = fleet_score.score_multicompute_round(
        axons=(ServingAxon(8, BOB, "1.1.1.1", 8081),),
        keypair=_runtime_keypair(),
        anchor_hash=WINDOW,
        verifier_adapter=adapter,
    )
    assert result.feature_blocked is True
    assert result.verified_units == {}
    assert result.rows == ()
    assert result.fleet == ()
    assert result.blockers == (
        "QVL does not expose verified stable platform identity; "
        "multi-machine scoring remains disabled",
    )


def test_one_missing_identity_does_not_poison_another_verified_uid(monkeypatch):
    def collect(*, evidence_url, sat_url, hotkey, validator_ss58, keypair):
        del validator_ss58, sat_url, keypair
        marker = 1 if hotkey == BOB else 255
        spki = b"a" * 32 if hotkey == BOB else b"b" * 32
        endpoint = evidence_url.removesuffix("/v1/evidence")
        return {
            "hotkey": hotkey,
            "sat_url": endpoint + "/v1/sat-work",
            "collected": _runtime_collected(hotkey, marker=marker, spki=spki),
        }

    def fleet(*, primary_origin, worker_hotkey, transport):
        del transport
        return FleetDiscovery(worker_hotkey, (primary_origin,), True)

    monkeypatch.setattr(fleet_score, "HttpsEvidenceTransport", _NoNetworkHttps)
    monkeypatch.setattr(fleet_score, "_try_collect", collect)
    monkeypatch.setattr(fleet_score, "fetch_worker_fleet", fleet)
    monkeypatch.setattr(fleet_score, "_units_after_quote", lambda **_kwargs: 20)
    result = fleet_score.score_multicompute_round(
        axons=(
            ServingAxon(8, BOB, "1.1.1.1", 8081),
            ServingAxon(124, CHARLIE, "8.8.8.8", 8081),
        ),
        keypair=_runtime_keypair(),
        anchor_hash=WINDOW,
        verifier_adapter=_runtime_adapter(),
    )
    assert result.verified_units == {BOB: 20}
    assert result.feature_blocked is False


@pytest.mark.parametrize("fleet_failure", ("HTTP 401", "malformed response"))
@pytest.mark.parametrize("duplicate_kind", ("endpoint", "channel", "hardware"))
@pytest.mark.parametrize("failed_first", (True, False))
def test_verified_root_with_failed_fleet_cannot_hide_global_duplicate(
    monkeypatch, fleet_failure, duplicate_kind, failed_first
):
    failed_hotkey = BOB
    survivor_hotkey = CHARLIE
    endpoint_by_hotkey = {
        BOB: "https://1.1.1.1:8081",
        CHARLIE: (
            "https://1.1.1.1:8081"
            if duplicate_kind == "endpoint"
            else "https://8.8.8.8:8081"
        ),
    }
    marker_by_hotkey = {
        BOB: 1,
        CHARLIE: 1 if duplicate_kind == "hardware" else 2,
    }
    spki_by_hotkey = {
        BOB: b"a" * 32,
        CHARLIE: b"a" * 32 if duplicate_kind == "channel" else b"b" * 32,
    }
    sat_calls: list[str] = []

    def collect(*, evidence_url, sat_url, hotkey, validator_ss58, keypair):
        del validator_ss58, sat_url, keypair
        endpoint = evidence_url.removesuffix("/v1/evidence")
        assert endpoint == endpoint_by_hotkey[hotkey]
        return {
            "hotkey": hotkey,
            "sat_url": endpoint + "/v1/sat-work",
            "collected": _runtime_collected(
                hotkey,
                marker=marker_by_hotkey[hotkey],
                spki=spki_by_hotkey[hotkey],
            ),
        }

    def fleet(*, primary_origin, worker_hotkey, transport):
        del transport
        if worker_hotkey == failed_hotkey:
            raise IndependentLiveError(fleet_failure)
        return FleetDiscovery(worker_hotkey, (primary_origin,), True)

    def units(*, anchor_hash, collected, sat_url, keypair):
        del anchor_hash, collected, keypair
        sat_calls.append(sat_url)
        return 20

    axons_by_hotkey = {
        BOB: ServingAxon(8, BOB, "1.1.1.1", 8081),
        CHARLIE: ServingAxon(
            124,
            CHARLIE,
            "1.1.1.1" if duplicate_kind == "endpoint" else "8.8.8.8",
            8081,
        ),
    }
    order = (
        (failed_hotkey, survivor_hotkey)
        if failed_first
        else (survivor_hotkey, failed_hotkey)
    )
    monkeypatch.setattr(fleet_score, "HttpsEvidenceTransport", _NoNetworkHttps)
    monkeypatch.setattr(fleet_score, "_try_collect", collect)
    monkeypatch.setattr(fleet_score, "fetch_worker_fleet", fleet)
    monkeypatch.setattr(fleet_score, "_units_after_quote", units)
    result = fleet_score.score_multicompute_round(
        axons=tuple(axons_by_hotkey[hotkey] for hotkey in order),
        keypair=_runtime_keypair(),
        anchor_hash=WINDOW,
        verifier_adapter=_runtime_adapter(),
    )

    expected_reason = {
        "endpoint": REASON_DUPLICATE_ENDPOINT,
        "channel": REASON_DUPLICATE_CHANNEL,
        "hardware": REASON_DUPLICATE_HARDWARE,
    }[duplicate_kind]
    assert result.verified_units == {}
    assert sat_calls == []
    assert len(result.rows) == 2
    assert all(row["counted_units"] == 0 for row in result.rows)
    assert all(expected_reason in row["score_reasons"] for row in result.rows)
    failed_row = next(row for row in result.rows if row["hotkey"] == failed_hotkey)
    assert fleet_failure in failed_row["fleet_error"]
    assert failed_row["sat_error"].startswith("fleet_discovery_failed")


@pytest.mark.parametrize(
    "axons,message",
    (
        ((), "bounded range"),
        (
            tuple(
                ServingAxon(uid, f"hotkey-{uid}", "1.1.1.1", 8081)
                for uid in range(MAX_DESTS + 1)
            ),
            "bounded range",
        ),
        (
            (
                ServingAxon(8, BOB, "1.1.1.1", 8081),
                ServingAxon(8, CHARLIE, "8.8.8.8", 8081),
            ),
            "repeat",
        ),
        (
            (ServingAxon(8, BOB, "127.0.0.1", 8081),),
            "globally routable",
        ),
    ),
)
def test_runtime_input_caps_and_identity_fail_before_any_miner_request(
    monkeypatch, axons, message
):
    monkeypatch.setattr(
        fleet_score,
        "_try_collect",
        lambda **_kwargs: pytest.fail("invalid batch reached miner evidence"),
    )
    with pytest.raises(IndependentLiveError, match=message):
        fleet_score.score_multicompute_round(
            axons=axons,
            keypair=_runtime_keypair(),
            anchor_hash=WINDOW,
            verifier_adapter=_runtime_adapter(),
        )
