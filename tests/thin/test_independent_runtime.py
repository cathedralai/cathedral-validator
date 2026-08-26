"""Live runner: Workers listing, integer mass, and contributing compose."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from _independent_fixtures import BOB, BURN_UID, commitment_for
from cathedral_thin.independent.compose import STATUS_COMPOSED, compose_dry_run
from cathedral_thin.independent.compute import COMPUTE_LANE, ComputeAdapter
from cathedral_thin.independent.constants import (
    BURN_HOTKEY,
    H,
    INDEPENDENT_STATE_FILE,
    TEMPO_BLOCKS,
)
from cathedral_thin.independent.inclusion import MetagraphView
from cathedral_thin.independent_runtime import run as run_module
from cathedral_thin.independent_runtime.errors import (
    ChainClientError,
    IndependentLiveError,
    QuoteVerifyError,
)
from cathedral_thin.independent_runtime.https import (
    axon_evidence_url,
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
    source = Path(run_module.__file__).read_text(encoding="utf-8")
    assert "verified_units.get" not in source
    assert "verified_units[" not in source
    assert "Attestation is admission" in source
    assert DEFAULT_STATE_DIR == "/var/lib/cathedral-validator"
    assert "/tmp" not in DEFAULT_STATE_DIR


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
