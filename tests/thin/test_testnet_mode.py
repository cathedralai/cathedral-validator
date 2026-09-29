"""Testnet mode keeps every production verifier and can never reach Finney."""

from __future__ import annotations

import base64
import ipaddress
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from bittensor_wallet import Keypair

from cathedral_thin.independent.collect import CHANNEL_BINDING_TYPE_TLS, ChannelBinding
from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH, NETUID
from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import localnet
from cathedral_thin.independent_runtime import qvl as qvl_runtime
from cathedral_thin.independent_runtime.axon import observed_genesis_hash
from cathedral_thin.independent_runtime.direct_writer import direct_state_scope
from cathedral_thin.independent_runtime.errors import ChainClientError, QuoteVerifyError
from cathedral_thin.independent_runtime.validator_request import (
    build_validator_request_header,
)

ROOT = Path(__file__).resolve().parents[2]
STUB = ROOT / "localnet" / "stub_tdx_verifier.py"
MINER = Keypair.create_from_uri("//TestnetMiner").ss58_address


@pytest.fixture
def production(monkeypatch):
    monkeypatch.delenv(localnet.TESTNET_ENV, raising=False)
    monkeypatch.delenv(localnet.LOCALNET_ENV, raising=False)


@pytest.fixture
def testnet(monkeypatch, production):
    monkeypatch.setenv(localnet.TESTNET_ENV, "1")


def _substrate(genesis: str) -> SimpleNamespace:
    return SimpleNamespace(substrate=SimpleNamespace(get_block_hash=lambda _n: genesis))


def test_mode_is_off_unless_exactly_one(monkeypatch, production) -> None:
    assert localnet.testnet_active() is False
    monkeypatch.setenv(localnet.TESTNET_ENV, "true")
    with pytest.raises(SystemExit):
        localnet.testnet_active()


def test_testnet_and_localnet_cannot_both_be_on(monkeypatch, testnet) -> None:
    monkeypatch.setenv(localnet.LOCALNET_ENV, "1")
    with pytest.raises(SystemExit):
        localnet.testnet_active()
    with pytest.raises(SystemExit):
        localnet.localnet_active()


def test_testnet_pins_its_own_genesis_and_never_finney(testnet) -> None:
    assert localnet.expected_genesis_hash() == localnet.TESTNET_GENESIS_HASH
    assert localnet.TESTNET_GENESIS_HASH != FINNEY_GENESIS_HASH
    genesis = localnet.TESTNET_GENESIS_HASH
    assert observed_genesis_hash(_substrate(genesis)) == genesis
    with pytest.raises(ChainClientError):
        observed_genesis_hash(_substrate(FINNEY_GENESIS_HASH))


def test_production_still_refuses_the_testnet_genesis(production) -> None:
    with pytest.raises(ChainClientError):
        observed_genesis_hash(_substrate(localnet.TESTNET_GENESIS_HASH))


@pytest.mark.parametrize(
    "network",
    [
        "finney",
        "local",
        "wss://entrypoint-finney.opentensor.ai:443",
        "wss://test.finney.opentensor.ai",
        "ws://127.0.0.1:9944",
        None,
        5,
    ],
)
def test_testnet_network_refuses_everything_but_testnet(testnet, network) -> None:
    with pytest.raises(SystemExit):
        runtime._pinned_network(network)


def test_network_pins(testnet, monkeypatch) -> None:
    assert runtime._pinned_network("test") == "test"
    assert runtime._pinned_network(localnet.TESTNET_ENDPOINT) == localnet.TESTNET_ENDPOINT
    monkeypatch.delenv(localnet.TESTNET_ENV)
    assert runtime._pinned_network("finney") == "finney"
    with pytest.raises(SystemExit):
        runtime._pinned_network("test")


def test_testnet_needs_an_explicit_netuid(testnet) -> None:
    with pytest.raises(SystemExit, match="explicit --netuid"):
        runtime._configured_netuid(None)
    assert runtime._configured_netuid(["421"]) == 421
    for bad in (["0"], ["0421"], ["-1"], ["65536"], ["1", "2"]):
        with pytest.raises(SystemExit):
            runtime._configured_netuid(bad)


def test_production_netuid_pin_is_unchanged(production) -> None:
    assert NETUID == 94
    assert runtime._configured_netuid(None) == 94
    assert runtime._configured_netuid(["94"]) == 94
    with pytest.raises(SystemExit, match="not the netuid this release was built for"):
        runtime._configured_netuid(["421"])


def test_main_refuses_finney_in_testnet_mode_before_the_chain(
    testnet, monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(
        runtime, "make_subtensor", lambda *_a, **_k: pytest.fail("reached the chain")
    )
    with pytest.raises(SystemExit, match="testnet mode accepts only"):
        runtime.main(
            [
                "--network",
                "finney",
                "--netuid",
                "421",
                "--expected-hotkey",
                "5Validator",
                "--qvl",
                "unused",
                "--snp-policy",
                str(tmp_path / "policy.json"),
                "--snpguest",
                "unused",
                "--confirm-direct-write",
            ]
        )


def test_main_refuses_telemetry_in_testnet_mode_before_the_chain(
    testnet, monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(
        runtime, "make_subtensor", lambda *_a, **_k: pytest.fail("reached the chain")
    )
    with pytest.raises(SystemExit, match="telemetry publishes Finney events only"):
        runtime.main(
            [
                "--network",
                "test",
                "--netuid",
                "421",
                "--expected-hotkey",
                "5Validator",
                "--qvl",
                "unused",
                "--snp-policy",
                str(tmp_path / "policy.json"),
                "--snpguest",
                "unused",
                "--telemetry-spool",
                str(tmp_path / "spool"),
                "--telemetry-reader-group",
                "staff",
                "--confirm-direct-write",
            ]
        )


def test_testnet_keeps_the_release_qvl_pin(testnet) -> None:
    assert (
        qvl_runtime.expected_direct_validator_qvl_digest()
        == qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
    )
    with pytest.raises(QuoteVerifyError):
        qvl_runtime.load_direct_validator_verifier(str(STUB))


@pytest.mark.parametrize("ip", ["10.10.20.17", "192.168.1.5", "100.103.39.86", "127.0.0.2"])
def test_testnet_never_dials_private_miner_addresses(testnet, ip) -> None:
    assert not localnet.allows_private_miner_address(ipaddress.ip_address(ip))


def _header(network: str | None, netuid: int) -> str:
    now = datetime.now(UTC).replace(microsecond=0)
    return build_validator_request_header(
        keypair=Keypair.create_from_uri("//TestnetValidator"),
        worker_hotkey=MINER,
        method="POST",
        path="/v1/evidence",
        body=b"{}",
        channel_binding=ChannelBinding(CHANNEL_BINDING_TYPE_TLS, bytes(range(32))),
        nonce=bytes(32),
        issued_at=now,
        expires_at=now + timedelta(seconds=60),
        network=network,
        netuid=netuid,
    )


def test_validator_requests_name_test_and_the_testnet_netuid(testnet) -> None:
    document = json.loads(base64.b64decode(_header(None, 421)))
    assert document["network"] == "test"
    assert document["netuid"] == 421


def test_journal_scope_never_says_finney_in_testnet_mode(monkeypatch, production) -> None:
    assert direct_state_scope(94) == "finney-sn94-mechanism-0"
    monkeypatch.setenv(localnet.TESTNET_ENV, "1")
    assert direct_state_scope(421) == "testnet-sn421-mechanism-0"
