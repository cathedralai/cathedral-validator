"""Live runner: Workers listing, integer mass, and contributing compose."""

from __future__ import annotations

import json

import pytest

from _independent_fixtures import BOB, BURN_UID, commitment_for
from cathedral_thin.independent.compose import STATUS_COMPOSED, compose_dry_run
from cathedral_thin.independent.compute import COMPUTE_LANE, ComputeAdapter
from cathedral_thin.independent.constants import BURN_HOTKEY, H, INDEPENDENT_STATE_FILE
from cathedral_thin.independent.inclusion import MetagraphView
from cathedral_thin.independent_runtime.https import (
    axon_evidence_url,
    tls_context_for_evidence,
)
from cathedral_thin.independent_runtime.local_policy import (
    COMPUTE_ALLOCATION,
    funded_compute_bundle,
)
from cathedral_thin.independent_runtime.score import mass_from_units
from cathedral_thin.independent_runtime.workers import (
    WorkersApiError,
    WorkersClient,
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


def test_axon_evidence_url_brackets_ipv6():
    assert (
        axon_evidence_url("2001:db8::1", 8443)
        == "https://[2001:db8::1]:8443/v1/evidence"
    )
    assert (
        axon_evidence_url("203.0.113.9", 443) == "https://203.0.113.9:443/v1/evidence"
    )


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
    ip_context = tls_context_for_evidence("203.0.113.9")
    assert ip_context.check_hostname is False
    host_context = tls_context_for_evidence("miner.example.test")
    assert host_context.check_hostname is True


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
