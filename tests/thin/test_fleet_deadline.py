"""A fleet loop which reaches the discovery deadline keeps what it verified.

The direct reward counts distinct verified machines per UID.  A UID's extra
fleet machines are probed one after another inside the discovery deadline, so a
UID which declares more endpoints than fit in that window reaches the deadline
part-way through its fleet.  These tests pin that such a UID keeps every
machine whose evidence and verification finished at or before the deadline,
while a machine which was never reached, was still in flight, or finished late
earns nothing and carries an explicit deadline reason.
"""

from __future__ import annotations

import copy
import hashlib
import threading
import time
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from _independent_fixtures import BOB, CHARLIE
from cathedral_thin.independent.collect import ChannelBinding, CollectedEvidence
from cathedral_thin.independent.compute import (
    ComputeAdapter,
    QuoteIdentityVerdict,
    QuoteVerdict,
)
from cathedral_thin.independent.constants import (
    CANARY_HOTKEY,
    MULTICOMPUTE_FLEET_CAP,
)
from cathedral_thin.independent_runtime import fleet_score
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.https import HttpsEvidenceTransport
from cathedral_thin.independent_runtime.multicompute import REASON_DUPLICATE_HARDWARE
from cathedral_thin.independent_runtime.validator_request import FleetDiscovery

WINDOW = "0x" + "ab" * 32
DEADLINE_REASON = "discovery_response_deadline_exceeded"
QVL_BUDGET_REASON = "insufficient discovery budget for bounded QVL"
UNVERIFIED_MARKER = 255
INFRA_MARKER = 254
UNITS = 20


def _endpoint(octet: int) -> str:
    return f"https://1.1.1.{octet}:8081"


BOB_AXON = ServingAxon(8, BOB, "1.1.1.1", 8081)
BOB_FLEET = tuple(_endpoint(octet) for octet in range(1, MULTICOMPUTE_FLEET_CAP + 1))
CHARLIE_AXON = ServingAxon(124, CHARLIE, "8.8.8.8", 8081)
CHARLIE_ROOT = "https://8.8.8.8:8081"


class _Clock:
    """Monotonic time which moves only when a fake miner call spends it."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def monotonic(self) -> float:
        return self.now

    def monotonic_ns(self) -> int:
        return round(self.now * 1_000_000_000)

    def spend(self, seconds: float) -> None:
        self.now += seconds


class _NoNetworkHttps(HttpsEvidenceTransport):
    pass


class _Verifier:
    """QVL stand-in: a quote's last byte names its platform and its QVL cost."""

    def __init__(self, cost: Callable[[int], None]) -> None:
        self._cost = cost

    def verify(self, quote, *, expected_report_data):
        del quote, expected_report_data
        return QuoteVerdict.PASS

    def verify_with_identity(
        self, quote, *, expected_report_data, deadline_monotonic=None
    ):
        del expected_report_data, deadline_monotonic
        marker = quote[-1]
        self._cost(marker)
        if marker == UNVERIFIED_MARKER:
            return QuoteIdentityVerdict(QuoteVerdict.PASS, None, False)
        if marker == INFRA_MARKER:
            return QuoteIdentityVerdict(QuoteVerdict.INFRA, None, False)
        return QuoteIdentityVerdict(
            QuoteVerdict.PASS, "tdx-platform-sha256:" + f"{marker:064x}", True
        )


def _collected(hotkey: str, *, marker: int, endpoint: str) -> CollectedEvidence:
    return CollectedEvidence(
        kind="tdx",
        quote=b"quote" + bytes([marker]),
        nonce=b"n" * 32,
        assigned_hotkey=hotkey,
        cert_chain=(),
        channel_binding=ChannelBinding(
            "tls_spki_sha256", hashlib.sha256(endpoint.encode()).digest()
        ),
        report_data=b"r" * 64,
    )


def _install_miners(
    monkeypatch,
    *,
    fleets: dict[str, tuple[str, ...]],
    markers: dict[str, int],
    evidence_cost: Callable[[str], None],
    fleet_cost: Callable[[], None],
) -> list[str]:
    """Route every worker call to fakes; return the endpoints SAT challenged."""

    sat_endpoints: list[str] = []

    def collect(
        *,
        evidence_url,
        sat_url,
        hotkey,
        validator_ss58,
        keypair,
        deadline_monotonic=None,
    ):
        del validator_ss58, keypair, deadline_monotonic
        endpoint = evidence_url.removesuffix("/v1/evidence")
        evidence_cost(endpoint)
        return {
            "url": evidence_url,
            "sat_url": sat_url,
            "hotkey": hotkey,
            "ok": True,
            "collected": _collected(
                hotkey, marker=markers[endpoint], endpoint=endpoint
            ),
        }

    def fleet(*, primary_origin, worker_hotkey, transport):
        del transport
        fleet_cost()
        endpoints = fleets[worker_hotkey]
        assert endpoints[0] == primary_origin
        return FleetDiscovery(worker_hotkey, endpoints, False)

    def units(*, anchor_hash, collected, sat_url, keypair, deadline_monotonic=None):
        del anchor_hash, collected, keypair, deadline_monotonic
        sat_endpoints.append(sat_url.removesuffix("/v1/sat-work"))
        return UNITS

    monkeypatch.setattr(fleet_score, "HttpsEvidenceTransport", _NoNetworkHttps)
    monkeypatch.setattr(fleet_score, "_try_collect", collect)
    monkeypatch.setattr(fleet_score, "fetch_worker_fleet", fleet)
    monkeypatch.setattr(fleet_score, "_units_after_quote", units)
    return sat_endpoints


def _score(
    axons: tuple[ServingAxon, ...],
    *,
    qvl_cost: Callable[[int], None],
    cycle_deadline_monotonic: float,
) -> fleet_score.MultiComputeRound:
    return fleet_score.score_multicompute_round(
        axons=axons,
        keypair=SimpleNamespace(
            ss58_address=CANARY_HOTKEY, sign=lambda _body: b"s" * 64
        ),
        anchor_hash=WINDOW,
        verifier_adapter=ComputeAdapter(
            _Verifier(qvl_cost),
            collateral_base_url=(
                "https://api.trustedservices.intel.com/sgx/certification/v4/"
            ),
            qvl_digest="a" * 64,
        ),
        cycle_deadline_monotonic=cycle_deadline_monotonic,
    )


def _fake_clock_round(
    monkeypatch,
    *,
    markers: dict[str, int] | None = None,
    qvl_seconds: dict[int, float] | None = None,
    fleet_seconds: float = 0.5,
) -> tuple[fleet_score.MultiComputeRound, list[str], list[str]]:
    """Score BOB's full-cap fleet with production deadlines on a fake clock.

    Every machine costs 1.6 s of binding plus evidence and 2 s of QVL unless
    ``qvl_seconds`` overrides one quote marker.
    """

    clock = _Clock()
    fleet_calls: list[str] = []
    monkeypatch.setattr(
        fleet_score,
        "time",
        SimpleNamespace(monotonic=clock.monotonic, monotonic_ns=clock.monotonic_ns),
    )

    def fleet_cost() -> None:
        fleet_calls.append(BOB)
        clock.spend(fleet_seconds)

    sat_endpoints = _install_miners(
        monkeypatch,
        fleets={BOB: BOB_FLEET},
        markers=markers
        or {endpoint: octet for octet, endpoint in enumerate(BOB_FLEET, start=1)},
        evidence_cost=lambda _endpoint: clock.spend(1.6),
        fleet_cost=fleet_cost,
    )
    result = _score(
        (BOB_AXON,),
        qvl_cost=lambda marker: clock.spend((qvl_seconds or {}).get(marker, 2.0)),
        cycle_deadline_monotonic=(
            clock.now + fleet_score.FULL_CYCLE_RESPONSE_DEADLINE_SECONDS
        ),
    )
    return result, sat_endpoints, fleet_calls


def _rows_by_endpoint(
    result: fleet_score.MultiComputeRound,
) -> dict[str, dict[str, Any]]:
    rows = {row["endpoint"]: row for row in result.rows}
    assert len(rows) == len(result.rows)
    return rows


def test_uid_keeps_the_machines_it_verified_before_its_fleet_loop_hit_the_deadline(
    monkeypatch,
):
    # The worked example behind this fix, on production deadlines: QVL starts
    # only while more than its own 30 s bound plus margin remains, so the chain
    # axon and the next seven fleet machines verify by 29.3 s.  The loop then
    # collects evidence without QVL budget until it runs into the 60 s
    # discovery deadline part-way through a 32-endpoint fleet.
    result, sat_endpoints, _fleet_calls = _fake_clock_round(monkeypatch)

    verified = BOB_FLEET[:8]
    unverified = BOB_FLEET[8:27]
    deadline = BOB_FLEET[27:]
    rows = _rows_by_endpoint(result)
    assert result.verified_units == {BOB: len(verified) * UNITS}
    assert sorted(sat_endpoints) == sorted(verified)
    assert set(rows) == set(BOB_FLEET)
    assert {
        endpoint for endpoint, row in rows.items() if row["counted_units"] > 0
    } == set(verified)
    assert all(rows[endpoint]["counted_units"] == UNITS for endpoint in verified)
    assert all(
        rows[endpoint]["deadline_error"] == QVL_BUDGET_REASON
        and rows[endpoint]["counted_units"] == 0
        for endpoint in unverified
    )
    assert all(
        rows[endpoint]["deadline_error"] == DEADLINE_REASON
        and rows[endpoint]["counted_units"] == 0
        and rows[endpoint]["ok"] is False
        and "verdict" not in rows[endpoint]
        and tuple(rows[endpoint]["phase_timings_ms"]) == fleet_score.PHASE_TIMING_FIELDS
        for endpoint in deadline
    )
    assert len(result.fleet) == 1
    assert result.fleet[0]["ok"] is True
    assert result.fleet[0]["singleton_compatibility"] is False
    assert result.fleet[0]["endpoints"] == list(BOB_FLEET)
    assert result.fleet[0]["deadline_error"] == DEADLINE_REASON
    assert result.exclusions == (f"fleet uid {BOB_AXON.uid}: {DEADLINE_REASON}",)
    assert result.pass_count == len(verified)
    assert result.qvl_infra_count == 0
    assert result.snp_infra_count == 0


def test_machine_which_verifies_only_after_the_deadline_is_excluded(monkeypatch):
    # The third machine's QVL overruns past the discovery deadline and then
    # answers PASS.  Its verdict must not reach the round: only the two
    # machines which finished in time are kept, and the loop stops there.
    result, sat_endpoints, _fleet_calls = _fake_clock_round(
        monkeypatch, qvl_seconds={3: 55.0}
    )

    rows = _rows_by_endpoint(result)
    late = BOB_FLEET[2]
    assert result.verified_units == {BOB: 2 * UNITS}
    assert sorted(sat_endpoints) == sorted(BOB_FLEET[:2])
    assert set(rows) == set(BOB_FLEET)
    assert rows[late]["deadline_error"] == DEADLINE_REASON
    assert rows[late]["counted_units"] == 0
    assert "verdict" not in rows[late]
    assert "machine_id" not in rows[late]
    assert all(
        rows[endpoint]["deadline_error"] == DEADLINE_REASON
        and rows[endpoint]["counted_units"] == 0
        for endpoint in BOB_FLEET[2:]
    )
    assert result.pass_count == 2
    assert result.fleet[0]["ok"] is True


@pytest.mark.parametrize("late", (False, True))
def test_infra_verdict_counts_toward_the_round_abort_only_if_it_finished_in_time(
    monkeypatch, late
):
    # The round-level INFRA abort rule is unchanged: a kept machine's INFRA
    # verdict counts exactly as it would for a UID whose fleet loop finished,
    # while an INFRA verdict which lands after the deadline never reaches the
    # round, as before.
    markers = {endpoint: octet for octet, endpoint in enumerate(BOB_FLEET, start=1)}
    markers[BOB_FLEET[1]] = INFRA_MARKER
    result, sat_endpoints, _fleet_calls = _fake_clock_round(
        monkeypatch,
        markers=markers,
        qvl_seconds={INFRA_MARKER: 55.0} if late else {},
    )

    rows = _rows_by_endpoint(result)
    if late:
        assert result.qvl_infra_count == 0
        assert rows[BOB_FLEET[1]]["deadline_error"] == DEADLINE_REASON
        assert "verdict" not in rows[BOB_FLEET[1]]
        assert result.verified_units == {BOB: UNITS}
        assert sat_endpoints == [BOB_FLEET[0]]
    else:
        assert result.qvl_infra_count == 1
        assert rows[BOB_FLEET[1]]["verdict"] == QuoteVerdict.INFRA.value
        assert rows[BOB_FLEET[1]]["counted_units"] == 0
        kept = (BOB_FLEET[0], *BOB_FLEET[2:8])
        assert result.verified_units == {BOB: len(kept) * UNITS}
        assert sorted(sat_endpoints) == sorted(kept)
    assert result.snp_infra_count == 0


@pytest.mark.parametrize(
    "case",
    ("root_unverified", "root_verified_after_deadline", "fleet_after_deadline"),
)
def test_uid_whose_chain_axon_is_not_verified_in_time_still_earns_nothing(
    monkeypatch, case
):
    markers = {endpoint: octet for octet, endpoint in enumerate(BOB_FLEET, start=1)}
    qvl_seconds: dict[int, float] = {}
    fleet_seconds = 0.5
    if case == "root_unverified":
        markers[BOB_FLEET[0]] = UNVERIFIED_MARKER
    elif case == "root_verified_after_deadline":
        qvl_seconds[1] = 70.0
    else:
        fleet_seconds = 60.0

    result, sat_endpoints, fleet_calls = _fake_clock_round(
        monkeypatch,
        markers=markers,
        qvl_seconds=qvl_seconds,
        fleet_seconds=fleet_seconds,
    )

    assert result.verified_units == {}
    assert sat_endpoints == []
    # An identity-less chain axon still passed QVL; a late one never counts.
    assert result.pass_count == (1 if case == "root_unverified" else 0)
    assert len(result.fleet) == 1
    assert result.fleet[0]["ok"] is False
    assert all(row["counted_units"] == 0 for row in result.rows)
    if case == "root_unverified":
        assert fleet_calls == []
        assert [row["endpoint"] for row in result.rows] == [BOB_FLEET[0]]
        assert "stable_platform_id" in result.fleet[0]["error"]
    else:
        assert result.rows == ()
        assert result.fleet[0]["error"] == DEADLINE_REASON
        assert result.exclusions == (f"fleet uid {BOB_AXON.uid}: {DEADLINE_REASON}",)


@pytest.mark.parametrize("duplicate", (False, True))
def test_machine_in_flight_at_the_deadline_is_excluded_and_cannot_publish_later(
    monkeypatch, duplicate
):
    # Real threads and a real clock: BOB's fourth machine is still inside QVL
    # when the discovery deadline passes, so its worker thread is still
    # running.  The machines BOB finished earlier are kept and meet the same
    # global duplicate rule as every other verified machine.  When the stuck
    # QVL later answers PASS, nothing in the returned round changes.
    fleet = BOB_FLEET[:5]
    in_flight_marker = 4
    markers = {endpoint: octet for octet, endpoint in enumerate(fleet, start=1)}
    markers[CHARLIE_ROOT] = 2 if duplicate else 100
    release = threading.Event()
    in_flight = threading.Event()
    worker_done = {BOB: threading.Event(), CHARLIE: threading.Event()}

    def qvl_cost(marker: int) -> None:
        if marker == in_flight_marker:
            in_flight.set()
            release.wait(timeout=10.0)

    original = fleet_score._collect_miner_evidence

    def tracked(**kwargs):
        try:
            return original(**kwargs)
        finally:
            worker_done[kwargs["axon"].hotkey].set()

    sat_endpoints = _install_miners(
        monkeypatch,
        fleets={BOB: fleet, CHARLIE: (CHARLIE_ROOT,)},
        markers=markers,
        evidence_cost=lambda _endpoint: None,
        fleet_cost=lambda: None,
    )
    monkeypatch.setattr(fleet_score, "_collect_miner_evidence", tracked)
    monkeypatch.setattr(fleet_score, "DISCOVERY_RESPONSE_DEADLINE_SECONDS", 1.0)
    monkeypatch.setattr(fleet_score, "MINER_RESPONSE_DEADLINE_SECONDS", 2.0)
    # QVL may start while more than its margin remains of this short deadline.
    monkeypatch.setattr(fleet_score, "QVL_TIMEOUT_SECONDS", 0.0)
    try:
        result = _score(
            (BOB_AXON, CHARLIE_AXON),
            qvl_cost=qvl_cost,
            cycle_deadline_monotonic=time.monotonic() + 3.0,
        )
        assert in_flight.is_set()
        assert not worker_done[BOB].is_set()
        frozen = copy.deepcopy(result)
    finally:
        release.set()
    assert worker_done[BOB].wait(timeout=5.0)
    assert result == frozen

    rows = _rows_by_endpoint(result)
    assert set(rows) == set(fleet) | {CHARLIE_ROOT}
    assert all(
        rows[endpoint]["deadline_error"] == DEADLINE_REASON
        and rows[endpoint]["counted_units"] == 0
        and "verdict" not in rows[endpoint]
        for endpoint in fleet[3:]
    )
    fleet_rows = {row["hotkey"]: row for row in result.fleet}
    assert fleet_rows[BOB]["ok"] is True
    assert fleet_rows[BOB]["deadline_error"] == DEADLINE_REASON
    assert fleet_rows[CHARLIE]["ok"] is True
    assert "deadline_error" not in fleet_rows[CHARLIE]
    if duplicate:
        assert result.verified_units == {BOB: 2 * UNITS}
        assert sorted(sat_endpoints) == sorted((fleet[0], fleet[2]))
        for endpoint in (fleet[1], CHARLIE_ROOT):
            assert rows[endpoint]["counted_units"] == 0
            assert REASON_DUPLICATE_HARDWARE in rows[endpoint]["score_reasons"]
    else:
        assert result.verified_units == {BOB: 3 * UNITS, CHARLIE: UNITS}
        assert sorted(sat_endpoints) == sorted((*fleet[:3], CHARLIE_ROOT))
