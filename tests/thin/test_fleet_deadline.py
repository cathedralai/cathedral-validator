"""A fleet loop which reaches the discovery deadline keeps what it verified.

The direct reward counts distinct verified machines per UID.  A UID's extra
fleet machines are probed one after another inside the discovery deadline, so a
UID which declares more endpoints than fit in that window reaches the deadline
part-way through its fleet.  These tests pin that such a UID keeps every
machine whose evidence and verification finished at or before the deadline,
while a machine which was never reached, was still in flight, or finished late
earns nothing and carries an explicit deadline reason.  A live-step error is
settled by when it reached the miner's record, never by when the scheduler
happened to look at the worker.
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
from cathedral_thin.independent.collect import (
    EVIDENCE_KIND_SEV_SNP,
    EVIDENCE_KIND_TDX,
    ChannelBinding,
    CollectedEvidence,
)
from cathedral_thin.independent.compute import (
    ComputeAdapter,
    QuoteIdentityVerdict,
    QuoteVerdict,
)
from cathedral_thin.independent.constants import (
    CANARY_HOTKEY,
    MULTICOMPUTE_FLEET_CAP,
)
from cathedral_thin.independent_runtime import direct_validator, fleet_score
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.direct_contract import (
    FinalizedMetagraphSnapshot,
)
from cathedral_thin.independent_runtime.errors import QuoteVerifyError
from cathedral_thin.independent_runtime.https import HttpsEvidenceTransport
from cathedral_thin.independent_runtime.multicompute import REASON_DUPLICATE_HARDWARE
from cathedral_thin.independent_runtime.snp_production import SnpVerificationResult
from cathedral_thin.independent_runtime.validator_request import FleetDiscovery

WINDOW = "0x" + "ab" * 32
DEADLINE_REASON = "discovery_response_deadline_exceeded"
QVL_BUDGET_REASON = "insufficient discovery budget for bounded QVL"
SNP_BUDGET_REASON = "snp_response_left_insufficient_verification_budget"
UNVERIFIED_MARKER = 255
INFRA_MARKER = 254
ERROR_MARKER = 253
LIVE_ERROR = "QuoteVerifyError: QVL binary changed while loading"
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
        if marker == ERROR_MARKER:
            raise QuoteVerifyError(LIVE_ERROR.removeprefix("QuoteVerifyError: "))
        return QuoteIdentityVerdict(
            QuoteVerdict.PASS, "tdx-platform-sha256:" + f"{marker:064x}", True
        )


class _SnpVerifier:
    """AMD verifier stand-in which spends ``seconds`` and derives a chip ID."""

    digest = "b" * 64
    policy_digest = "c" * 64

    def __init__(self, cost: Callable[[], None]) -> None:
        self._cost = cost

    def verify(self, collected, *, deadline_monotonic):
        del deadline_monotonic
        self._cost()
        return SnpVerificationResult(
            QuoteVerdict.PASS,
            hashlib.sha256(b"snp-chip" + collected.quote).hexdigest(),
            self.digest,
            self.policy_digest,
        )


def _collected(
    hotkey: str, *, marker: int, endpoint: str, kind: str = EVIDENCE_KIND_TDX
) -> CollectedEvidence:
    return CollectedEvidence(
        kind=kind,
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
    snp_endpoints: frozenset[str] = frozenset(),
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
                hotkey,
                marker=markers[endpoint],
                endpoint=endpoint,
                kind=(
                    EVIDENCE_KIND_SEV_SNP
                    if endpoint in snp_endpoints
                    else EVIDENCE_KIND_TDX
                ),
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


def _keypair() -> SimpleNamespace:
    return SimpleNamespace(ss58_address=CANARY_HOTKEY, sign=lambda _body: b"s" * 64)


def _adapter(qvl_cost: Callable[[int], None]) -> ComputeAdapter:
    return ComputeAdapter(
        _Verifier(qvl_cost),
        collateral_base_url=(
            "https://api.trustedservices.intel.com/sgx/certification/v4/"
        ),
        qvl_digest="a" * 64,
    )


def _score(
    axons: tuple[ServingAxon, ...],
    *,
    qvl_cost: Callable[[int], None],
    cycle_deadline_monotonic: float,
    snp_verifier: _SnpVerifier | None = None,
) -> fleet_score.MultiComputeRound:
    return fleet_score.score_multicompute_round(
        axons=axons,
        keypair=_keypair(),
        anchor_hash=WINDOW,
        verifier_adapter=_adapter(qvl_cost),
        snp_verifier=snp_verifier,
        cycle_deadline_monotonic=cycle_deadline_monotonic,
    )


def _fake_clock_round(
    monkeypatch,
    *,
    markers: dict[str, int] | None = None,
    qvl_seconds: dict[int, float] | None = None,
    fleet_seconds: float = 0.5,
    snp_endpoints: frozenset[str] = frozenset(),
) -> tuple[fleet_score.MultiComputeRound, list[str], list[str]]:
    """Score BOB's full-cap fleet with production deadlines on a fake clock.

    Every machine costs 1.6 s of binding plus evidence and 2 s of QVL unless
    ``qvl_seconds`` overrides one quote marker.  An SNP machine spends 3 s in
    the AMD verifier instead of QVL.
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
        snp_endpoints=snp_endpoints,
    )
    result = _score(
        (BOB_AXON,),
        qvl_cost=lambda marker: clock.spend((qvl_seconds or {}).get(marker, 2.0)),
        cycle_deadline_monotonic=(
            clock.now + fleet_score.FULL_CYCLE_RESPONSE_DEADLINE_SECONDS
        ),
        snp_verifier=_SnpVerifier(lambda: clock.spend(3.0)),
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


def test_truncated_uid_is_paid_for_its_eight_machines_in_the_direct_plan(
    monkeypatch,
):
    # End to end through the direct plan: the truncated UID is paid for each
    # distinct machine it verified in time, and nothing for the rest.
    result, _sat_endpoints, _fleet_calls = _fake_clock_round(monkeypatch)
    snapshot = FinalizedMetagraphSnapshot(
        block_number=100,
        block_hash=WINDOW,
        validator_uid=7,
        validator_hotkey=CANARY_HOTKEY,
        miners=(BOB_AXON,),
        skipped_axons={},
    )

    plan = direct_validator.build_direct_plan(snapshot, result)

    rows = _rows_by_endpoint(result)
    paid_machine_ids = sorted(
        rows[endpoint]["machine_id"] for endpoint in BOB_FLEET[:8]
    )
    assert len(set(paid_machine_ids)) == 8
    assert plan.raw_scores == ((BOB_AXON.uid, 8),)
    assert plan.machine_ids_by_uid == ((BOB_AXON.uid, tuple(paid_machine_ids)),)
    assert plan.wire_uids == (BOB_AXON.uid,)
    assert plan.wire_weights == (65535,)
    # Telemetry which dashboards read: the truncated fleet is no longer a
    # failed fleet, and its 24 unpaid rows are excluded machine rows.
    summary = direct_validator._evidence_cycle_summary(snapshot, result, plan)
    assert summary["exclusions"]["failed_fleets"] == 0
    assert summary["exclusions"]["excluded_machine_rows"] == 24
    assert summary["exclusions"]["reported_categories"]["fleet"] == 1


def test_snp_machines_in_a_truncated_fleet_are_kept_like_tdx_machines(monkeypatch):
    # Octets 3 and 12 are SNP machines verified in time.  Octet 14 is an SNP
    # machine which reaches the AMD verifier with less than its reserved 21 s
    # left, so it fails on budget; that is its own miner's deadline, never AMD
    # infrastructure.  The loop still runs into the 60 s deadline at octet 25.
    snp = frozenset((BOB_FLEET[2], BOB_FLEET[11], BOB_FLEET[13]))
    result, sat_endpoints, _fleet_calls = _fake_clock_round(
        monkeypatch, snp_endpoints=snp
    )

    rows = _rows_by_endpoint(result)
    kept = (*BOB_FLEET[:8], BOB_FLEET[11])
    assert result.verified_units == {BOB: len(kept) * UNITS}
    assert sorted(sat_endpoints) == sorted(kept)
    for endpoint in (BOB_FLEET[2], BOB_FLEET[11]):
        assert rows[endpoint]["tee_kind"] == EVIDENCE_KIND_SEV_SNP
        assert rows[endpoint]["verdict"] == QuoteVerdict.PASS.value
        assert rows[endpoint]["platform_identity_verified"] is True
        assert rows[endpoint]["counted_units"] == UNITS
    assert rows[BOB_FLEET[13]]["tee_kind"] == EVIDENCE_KIND_SEV_SNP
    assert rows[BOB_FLEET[13]]["identity_error"] == SNP_BUDGET_REASON
    assert rows[BOB_FLEET[13]]["counted_units"] == 0
    assert all(
        rows[endpoint]["deadline_error"] == DEADLINE_REASON
        and rows[endpoint]["counted_units"] == 0
        and "verdict" not in rows[endpoint]
        for endpoint in BOB_FLEET[24:]
    )
    # Octet 24 is the last machine to finish in time: evidence, no QVL budget.
    assert rows[BOB_FLEET[23]]["deadline_error"] == QVL_BUDGET_REASON
    assert result.pass_count == len(kept)
    assert result.snp_infra_count == 0
    assert result.qvl_infra_count == 0
    assert result.fleet[0]["ok"] is True
    assert result.fleet[0]["deadline_error"] == DEADLINE_REASON


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


@pytest.mark.parametrize("late", (False, True))
def test_live_step_error_is_settled_by_when_it_reached_the_record(monkeypatch, late):
    # The third machine's verifier raises a live-step error.  Raised in time,
    # it zeroes the whole UID with that error as its reason, as it always
    # has.  Raised after the deadline, it is a late result like any other: the
    # two machines verified in time stand.
    markers = {endpoint: octet for octet, endpoint in enumerate(BOB_FLEET, start=1)}
    markers[BOB_FLEET[2]] = ERROR_MARKER
    result, sat_endpoints, _fleet_calls = _fake_clock_round(
        monkeypatch,
        markers=markers,
        qvl_seconds={ERROR_MARKER: 55.0} if late else {},
    )

    assert len(result.fleet) == 1
    if late:
        rows = _rows_by_endpoint(result)
        assert result.verified_units == {BOB: 2 * UNITS}
        assert sorted(sat_endpoints) == sorted(BOB_FLEET[:2])
        assert result.fleet[0]["ok"] is True
        assert result.fleet[0]["deadline_error"] == DEADLINE_REASON
        assert all(
            rows[endpoint]["deadline_error"] == DEADLINE_REASON
            for endpoint in BOB_FLEET[2:]
        )
        assert result.exclusions == (f"fleet uid {BOB_AXON.uid}: {DEADLINE_REASON}",)
    else:
        assert result.verified_units == {}
        assert sat_endpoints == []
        assert result.rows == ()
        assert result.pass_count == 0
        assert result.fleet[0]["ok"] is False
        assert result.fleet[0]["error"] == LIVE_ERROR
        assert result.exclusions == (f"fleet uid {BOB_AXON.uid}: {LIVE_ERROR}",)


def test_live_step_error_recorded_in_time_zeroes_a_worker_still_running_at_the_deadline(
    monkeypatch,
):
    # Real threads: the error reaches BOB's record in time, but his worker is
    # then held until after the deadline, so the scheduler never sees it
    # return.  The outcome comes from the record, not from that timing: BOB is
    # zeroed with the error as its reason.
    fleet = BOB_FLEET[:5]
    markers = {endpoint: octet for octet, endpoint in enumerate(fleet, start=1)}
    markers[fleet[2]] = ERROR_MARKER
    release = threading.Event()
    recorded = threading.Event()
    original_fail = fleet_score._FleetProgress.fail

    def fail_then_stall(self, reason):
        accepted = original_fail(self, reason)
        recorded.set()
        release.wait(timeout=10.0)
        return accepted

    sat_endpoints = _install_miners(
        monkeypatch,
        fleets={BOB: fleet},
        markers=markers,
        evidence_cost=lambda _endpoint: None,
        fleet_cost=lambda: None,
    )
    monkeypatch.setattr(fleet_score._FleetProgress, "fail", fail_then_stall)
    monkeypatch.setattr(fleet_score, "DISCOVERY_RESPONSE_DEADLINE_SECONDS", 1.0)
    monkeypatch.setattr(fleet_score, "MINER_RESPONSE_DEADLINE_SECONDS", 2.0)
    # QVL may start while more than its margin remains of this short deadline.
    monkeypatch.setattr(fleet_score, "QVL_TIMEOUT_SECONDS", 0.0)
    try:
        result = _score(
            (BOB_AXON,),
            qvl_cost=lambda _marker: None,
            cycle_deadline_monotonic=time.monotonic() + 3.0,
        )
        assert recorded.is_set()
    finally:
        release.set()

    assert result.verified_units == {}
    assert sat_endpoints == []
    assert result.rows == ()
    assert result.fleet[0]["ok"] is False
    assert result.fleet[0]["error"] == LIVE_ERROR


def _machine(endpoint: str) -> fleet_score._Machine:
    """One machine as the worker builds it, from the installed fake miners."""

    return fleet_score._collect_candidate(
        candidate=fleet_score.FleetCandidate(BOB_AXON.uid, BOB, endpoint),
        keypair=_keypair(),
        validator_ss58=CANARY_HOTKEY,
        anchor_hash=WINDOW,
        verifier_adapter=_adapter(lambda _marker: None),
        snp_verifier=None,
    )


def test_a_closed_record_refuses_a_late_worker_and_hands_out_copies(monkeypatch):
    # Closed well before the deadline, so only the closed flag refuses what
    # follows.  Nothing the worker or a reader does to rows it holds can
    # change what the record hands out next.
    clock = _Clock()
    monkeypatch.setattr(
        fleet_score,
        "time",
        SimpleNamespace(monotonic=clock.monotonic, monotonic_ns=clock.monotonic_ns),
    )
    _install_miners(
        monkeypatch,
        fleets={BOB: BOB_FLEET[:4]},
        markers={endpoint: octet for octet, endpoint in enumerate(BOB_FLEET, 1)},
        evidence_cost=lambda _endpoint: None,
        fleet_cost=lambda: None,
    )
    progress = fleet_score._FleetProgress(BOB_AXON, clock.now + 60.0)
    root = _machine(BOB_FLEET[0])
    second = _machine(BOB_FLEET[1])
    fleet_row = {
        "uid": BOB_AXON.uid,
        "hotkey": BOB,
        "primary": BOB_FLEET[0],
        "ok": True,
        "singleton_compatibility": False,
        "candidate_count": 4,
        "endpoints": list(BOB_FLEET[:4]),
        "phase_timings_ms": {"fleet": 5},
    }
    assert progress.start(
        anchor_hash=WINDOW, fleet_row=fleet_row, endpoints=BOB_FLEET[:4], root=root
    )
    assert progress.record(second)
    # The worker keeps references to what it recorded; changing them later
    # must not reach the record.
    root[0]["verdict"] = QuoteVerdict.FAIL.value
    second[0]["phase_timings_ms"]["qvl"] = 999
    fleet_row["endpoints"].append("https://9.9.9.9:8081")
    fleet_row["phase_timings_ms"]["fleet"] = 999

    first = progress.close()
    assert not progress.record(_machine(BOB_FLEET[2]))
    assert not progress.fail(LIVE_ERROR)
    assert not progress.start(
        anchor_hash=WINDOW, fleet_row=fleet_row, endpoints=BOB_FLEET, root=root
    )
    # A reader of the first result, such as SAT, mutates its rows.
    first.rows[0]["counted_units"] = UNITS
    first.rows[1]["phase_timings_ms"]["sat"] = 1
    first.fleet_row["phase_timings_ms"]["fleet"] = 0
    first.fleet_row["endpoints"].clear()

    again = progress.close()
    assert [row["endpoint"] for row in again.rows] == list(BOB_FLEET[:4])
    assert again.rows[0]["verdict"] == QuoteVerdict.PASS.value
    assert "counted_units" not in again.rows[0]
    assert again.rows[1]["phase_timings_ms"]["qvl"] != 999
    assert again.rows[1]["phase_timings_ms"]["sat"] is None
    assert all(
        row["deadline_error"] == DEADLINE_REASON and "verdict" not in row
        for row in again.rows[2:]
    )
    assert [row.endpoint for row in again.observations] == list(BOB_FLEET[:2])
    assert set(again.collected_by_key) == {(BOB_AXON.uid, e) for e in BOB_FLEET[:2]}
    assert again.fleet_row["endpoints"] == list(BOB_FLEET[:4])
    assert again.fleet_row["phase_timings_ms"]["fleet"] == 5
    assert again.pass_count == 2


def test_record_accepts_up_to_the_deadline_and_keeps_an_error_raised_in_time(
    monkeypatch,
):
    clock = _Clock()
    monkeypatch.setattr(
        fleet_score,
        "time",
        SimpleNamespace(monotonic=clock.monotonic, monotonic_ns=clock.monotonic_ns),
    )
    _install_miners(
        monkeypatch,
        fleets={BOB: BOB_FLEET[:3]},
        markers={endpoint: octet for octet, endpoint in enumerate(BOB_FLEET, 1)},
        evidence_cost=lambda _endpoint: None,
        fleet_cost=lambda: None,
    )
    fleet_row = {"uid": BOB_AXON.uid, "ok": True, "phase_timings_ms": {"fleet": 1}}
    deadline = clock.now + 60.0

    kept = fleet_score._FleetProgress(BOB_AXON, deadline)
    assert kept.start(
        anchor_hash=WINDOW,
        fleet_row=fleet_row,
        endpoints=BOB_FLEET[:3],
        root=_machine(BOB_FLEET[0]),
    )
    clock.now = deadline
    assert kept.record(_machine(BOB_FLEET[1]))
    clock.spend(0.001)
    assert not kept.record(_machine(BOB_FLEET[2]))
    assert not kept.fail(LIVE_ERROR)
    assert [row.endpoint for row in kept.close().observations] == list(BOB_FLEET[:2])

    clock.now = deadline - 30.0
    failed = fleet_score._FleetProgress(BOB_AXON, deadline)
    assert failed.start(
        anchor_hash=WINDOW,
        fleet_row=fleet_row,
        endpoints=BOB_FLEET[:3],
        root=_machine(BOB_FLEET[0]),
    )
    assert failed.fail(LIVE_ERROR)
    assert not failed.record(_machine(BOB_FLEET[1]))
    clock.now = deadline + 30.0
    for evidence in (failed.close(), failed.close()):
        assert evidence.rows == []
        assert evidence.observations == []
        assert evidence.fleet_row["ok"] is False
        assert evidence.fleet_row["error"] == LIVE_ERROR
        assert evidence.exclusions == [f"fleet uid {BOB_AXON.uid}: {LIVE_ERROR}"]


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


@pytest.mark.parametrize(
    "duplicate,late_error", ((False, False), (True, False), (False, True))
)
def test_machine_in_flight_at_the_deadline_is_excluded_and_cannot_publish_later(
    monkeypatch, duplicate, late_error
):
    # Real threads and a real clock: BOB's fourth machine is still inside QVL
    # when the discovery deadline passes, so its worker thread is still
    # running.  The machines BOB finished earlier are kept and meet the same
    # global duplicate rule as every other verified machine.  When the stuck
    # QVL later answers PASS, or raises a live-step error, nothing in the
    # returned round changes.
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
            if late_error:
                raise QuoteVerifyError("QVL binary changed while loading")

    original = fleet_score._collect_bounded_miner_evidence

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
    monkeypatch.setattr(fleet_score, "_collect_bounded_miner_evidence", tracked)
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
