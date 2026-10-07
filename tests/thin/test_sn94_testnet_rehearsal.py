"""Only network pins change; no localnet or verifier shortcut is installed."""

from __future__ import annotations

import base64
import dataclasses
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from bittensor_wallet import Keypair

from cathedral_thin.independent.collect import CHANNEL_BINDING_TYPE_TLS, ChannelBinding
from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH
from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import testnet as rehearsal
from cathedral_thin.independent_runtime.axon import observed_genesis_hash
from cathedral_thin.independent_runtime.direct_writer import (
    DirectSubmissionAmbiguous,
    DirectWeightWriter,
    direct_state_scope,
)
from cathedral_thin.independent_runtime.errors import ChainClientError
from cathedral_thin.independent_runtime.telemetry import (
    TelemetryError,
    build_telemetry_snapshot,
    validate_public_telemetry_event,
)
from cathedral_thin.independent_runtime.telemetry_exporter import _parser
from cathedral_thin.independent_runtime.validator_request import (
    build_validator_request_header,
    validate_public_worker_endpoint,
)
from tests.thin.test_direct_telemetry import (
    VALIDATOR_KEYPAIR,
    TDX_MINER_KEYPAIR,
    SNP_MINER_KEYPAIR,
    _plan,
    _receipt,
    _row,
)


@pytest.fixture(autouse=True)
def clean_mode(monkeypatch):
    monkeypatch.delenv(rehearsal.TESTNET_ENV, raising=False)
    monkeypatch.delenv("CATHEDRAL_LOCALNET", raising=False)


@pytest.mark.parametrize("value", ["true", "0", "yes", " 1"])
def test_bad_mode_refuses(value, monkeypatch):
    monkeypatch.setenv(rehearsal.TESTNET_ENV, value)
    with pytest.raises(SystemExit, match="exactly 1"):
        rehearsal.testnet_active()


def test_localnet_is_not_a_shortcut(monkeypatch):
    monkeypatch.setenv("CATHEDRAL_LOCALNET", "1")
    with pytest.raises(SystemExit, match="no localnet"):
        runtime._pinned_network("finney")


def test_production_pins_and_scope_are_unchanged():
    # Production takes its netuid from deploy configuration only; the testnet
    # is selected by CATHEDRAL_TESTNET and its pinned chain, never by a netuid.
    configured = {"CATHEDRAL_VALIDATOR_NETUID": "94"}
    assert runtime._pinned_network("finney") == "finney"
    assert runtime._configured_netuid(None, configured) == 94
    assert rehearsal.expected_genesis_hash() == FINNEY_GENESIS_HASH
    assert direct_state_scope(94) == "finney-sn94-mechanism-0"
    with pytest.raises(SystemExit):
        runtime._pinned_network("test")
    with pytest.raises(SystemExit, match="no netuid is configured"):
        runtime._configured_netuid(None, {})


def test_rehearsal_ignores_the_production_netuid_setting(monkeypatch):
    monkeypatch.setenv(rehearsal.TESTNET_ENV, "1")
    configured = {"CATHEDRAL_VALIDATOR_NETUID": "94"}
    assert runtime._configured_netuid(["584"], configured) == 584
    with pytest.raises(SystemExit, match="explicit --netuid 584"):
        runtime._configured_netuid(None, configured)


def test_rehearsal_requires_exact_chain_and_explicit_subnet(monkeypatch):
    monkeypatch.setenv(rehearsal.TESTNET_ENV, "1")
    assert runtime._pinned_network("test") == "test"
    assert (
        runtime._pinned_network(rehearsal.TESTNET_ENDPOINT)
        == rehearsal.TESTNET_ENDPOINT
    )
    assert runtime._configured_netuid(["584"]) == 584
    for value in (None, ["94"], ["0584"], ["584", "584"], ["0"]):
        with pytest.raises(SystemExit):
            runtime._configured_netuid(value)
    for network in ("finney", "ws://127.0.0.1:9944", "wss://test.finney.opentensor.ai"):
        with pytest.raises(SystemExit):
            runtime._pinned_network(network)
    assert direct_state_scope(584) == "testnet-sn584-mechanism-0"


def test_rehearsal_rejects_finney_before_wallet_or_verifier(monkeypatch):
    monkeypatch.setenv(rehearsal.TESTNET_ENV, "1")
    monkeypatch.setattr(
        runtime, "make_wallet", lambda *_a, **_k: pytest.fail("wallet reached")
    )
    monkeypatch.setattr(
        runtime,
        "load_direct_validator_verifier",
        lambda *_a: pytest.fail("verifier reached"),
    )
    with pytest.raises(SystemExit, match="pinned public testnet"):
        runtime.main(
            [
                "--network",
                "finney",
                "--netuid",
                "584",
                "--expected-hotkey",
                "unused",
                "--qvl",
                "unused",
                "--snp-policy",
                "unused",
                "--snpguest",
                "unused",
                "--confirm-direct-write",
            ]
        )


def test_genesis_pin_cannot_cross_networks(monkeypatch):
    def node(genesis):
        return SimpleNamespace(
            substrate=SimpleNamespace(get_block_hash=lambda _n: genesis)
        )

    with pytest.raises(ChainClientError):
        observed_genesis_hash(node(rehearsal.TESTNET_GENESIS_HASH))
    monkeypatch.setenv(rehearsal.TESTNET_ENV, "1")
    assert (
        observed_genesis_hash(node(rehearsal.TESTNET_GENESIS_HASH))
        == rehearsal.TESTNET_GENESIS_HASH
    )
    with pytest.raises(ChainClientError):
        observed_genesis_hash(node(FINNEY_GENESIS_HASH))


@pytest.mark.parametrize("testnet", (False, True))
def test_recovery_genesis_guard_uses_the_selected_chain_not_client_cache(
    monkeypatch, testnet
):
    if testnet:
        monkeypatch.setenv(rehearsal.TESTNET_ENV, "1")
    expected = rehearsal.expected_genesis_hash()
    wrong = FINNEY_GENESIS_HASH if testnet else rehearsal.TESTNET_GENESIS_HASH
    reads = []
    response = [expected]

    def node_rpc(method, params):
        reads.append((method, params))
        return {"result": response[0]}

    instance = DirectWeightWriter(
        subtensor=SimpleNamespace(
            substrate=SimpleNamespace(
                rpc_request=node_rpc, get_block_hash=lambda _n: expected
            )
        ),
        keypair=VALIDATOR_KEYPAIR,
        netuid=584 if testnet else 94,
    )
    instance._require_recovery_genesis()
    response[0] = wrong
    with pytest.raises(DirectSubmissionAmbiguous, match="pinned .* genesis"):
        instance._require_recovery_genesis()
    assert reads == [("chain_getBlockHash", [0]), ("chain_getBlockHash", [0])]


@pytest.mark.parametrize(
    "ip", ["10.10.20.17", "192.168.1.5", "100.103.39.86", "127.0.0.2"]
)
def test_rehearsal_keeps_public_address_only_dialing(monkeypatch, ip):
    monkeypatch.setenv(rehearsal.TESTNET_ENV, "1")
    with pytest.raises(Exception):
        validate_public_worker_endpoint(f"https://{ip}:8081")


def test_signed_request_uses_test_network(monkeypatch):
    monkeypatch.setenv(rehearsal.TESTNET_ENV, "1")
    now = datetime(2026, 10, 5, 22, 0, tzinfo=UTC)
    header = build_validator_request_header(
        keypair=Keypair.create_from_uri("//TestnetValidator"),
        worker_hotkey=TDX_MINER_KEYPAIR.ss58_address,
        method="POST",
        path="/v1/evidence",
        body=b"{}",
        channel_binding=ChannelBinding(CHANNEL_BINDING_TYPE_TLS, bytes(range(32))),
        nonce=bytes(32),
        issued_at=now,
        expires_at=now + timedelta(seconds=60),
        netuid=584,
    )
    document = json.loads(base64.b64decode(header))
    assert document["network"] == "test"
    assert document["netuid"] == 584


def test_real_signed_testnet_event_is_not_a_relabeled_fixture(monkeypatch):
    monkeypatch.setenv(rehearsal.TESTNET_ENV, "1")
    plan = _plan()
    plan = dataclasses.replace(
        plan, snapshot=dataclasses.replace(plan.snapshot, netuid=584)
    )
    event = build_telemetry_snapshot(
        result_rows=(
            _row(41, TDX_MINER_KEYPAIR.ss58_address, "tdx", 10),
            _row(42, SNP_MINER_KEYPAIR.ss58_address, "sev_snp", 20),
        ),
        plan=plan,
        receipt=_receipt(),
        keypair=VALIDATOR_KEYPAIR,
        observed_at=datetime(2026, 10, 5, 22, 0, tzinfo=UTC),
    )
    assert event["network"] == "test" and event["netuid"] == 584
    assert validate_public_telemetry_event(event, netuid=584) == event
    monkeypatch.delenv(rehearsal.TESTNET_ENV)
    with pytest.raises(TelemetryError):
        validate_public_telemetry_event(event, netuid=584)


def test_exporter_has_explicit_nonabbreviated_netuid():
    args = [
        "--spool",
        "unused",
        "--endpoint",
        "unused",
        "--ingest-token-file",
        "unused",
        "--sites-authorization-file",
        "unused",
        "--reader-group",
        "unused",
    ]
    assert _parser().parse_args([*args, "--netuid", "584"]).netuid == ["584"]
    with pytest.raises(SystemExit):
        _parser().parse_args([*args, "--netu", "584"])
