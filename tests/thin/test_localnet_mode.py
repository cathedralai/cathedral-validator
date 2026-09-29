"""Development localnet mode stays inert on Finney and refuses Finney when on."""

from __future__ import annotations

import hashlib
import ipaddress
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from bittensor_wallet import Keypair

from cathedral_thin.independent.collect import (
    CHANNEL_BINDING_TYPE_TLS,
    ChannelBinding,
    report_data_v2,
)
from cathedral_thin.independent.compute import QuoteVerdict
from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH
from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import localnet
from cathedral_thin.independent_runtime import qvl as qvl_runtime
from cathedral_thin.independent_runtime.axon import observed_genesis_hash, scan_axons
from cathedral_thin.independent_runtime.direct_writer import direct_state_scope
from cathedral_thin.independent_runtime.errors import ChainClientError, QuoteVerifyError
from cathedral_thin.independent_runtime.errors import IndependentLiveError
from cathedral_thin.independent_runtime.validator_request import (
    build_validator_request_header,
    validate_public_worker_endpoint,
)

ROOT = Path(__file__).resolve().parents[2]
STUB = ROOT / "localnet" / "stub_tdx_verifier.py"
STUB_MAGIC = b"CATHEDRAL-LOCALNET-STUB-TDX-QUOTE-V1\x00"
LOCAL_GENESIS = "0x" + "c5" * 32
MINER = Keypair.create_from_uri("//LocalnetMiner").ss58_address


@pytest.fixture
def production(monkeypatch):
    monkeypatch.delenv(localnet.LOCALNET_ENV, raising=False)
    monkeypatch.delenv(localnet.LOCALNET_GENESIS_ENV, raising=False)


@pytest.fixture
def local(monkeypatch):
    monkeypatch.setenv(localnet.LOCALNET_ENV, "1")
    monkeypatch.setenv(localnet.LOCALNET_GENESIS_ENV, LOCAL_GENESIS)


def _substrate(genesis: str) -> SimpleNamespace:
    return SimpleNamespace(substrate=SimpleNamespace(get_block_hash=lambda _n: genesis))


def _metagraph(ip: str) -> SimpleNamespace:
    return SimpleNamespace(
        uids=[0],
        hotkeys=[MINER],
        axons=[SimpleNamespace(ip=ip, port=8091, is_serving=True)],
    )


def test_mode_is_off_unless_exactly_one(monkeypatch, production) -> None:
    assert localnet.localnet_active() is False
    monkeypatch.setenv(localnet.LOCALNET_ENV, "true")
    with pytest.raises(SystemExit):
        localnet.localnet_active()


def test_stub_digest_pin_matches_the_committed_stub() -> None:
    digest = hashlib.sha256(STUB.read_bytes()).hexdigest()
    assert digest == localnet.LOCALNET_STUB_QVL_DIGEST
    assert os.stat(STUB).st_mode & 0o111


@pytest.mark.parametrize("genesis", [FINNEY_GENESIS_HASH, "", "0x1234", "c5" * 32])
def test_local_genesis_pin_refuses_finney_and_malformed_values(
    monkeypatch, local, genesis: str
) -> None:
    monkeypatch.setenv(localnet.LOCALNET_GENESIS_ENV, genesis)
    with pytest.raises(SystemExit):
        localnet.expected_genesis_hash()


def test_genesis_pin_is_finney_in_production(production) -> None:
    assert observed_genesis_hash(_substrate(FINNEY_GENESIS_HASH)) == FINNEY_GENESIS_HASH
    with pytest.raises(ChainClientError):
        observed_genesis_hash(_substrate(LOCAL_GENESIS))


def test_localnet_accepts_only_its_pinned_genesis(local) -> None:
    assert observed_genesis_hash(_substrate(LOCAL_GENESIS)) == LOCAL_GENESIS
    with pytest.raises(ChainClientError):
        observed_genesis_hash(_substrate(FINNEY_GENESIS_HASH))


@pytest.mark.parametrize(
    "network",
    [
        "finney",
        "test",
        "wss://entrypoint-finney.opentensor.ai:443",
        "ws://10.0.0.1:9944",
        "ws://127.0.0.1",
        "ws://127.0.0.1:9944/path",
        "http://127.0.0.1:9944",
    ],
)
def test_localnet_network_refuses_everything_but_a_local_ws_port(
    local, network
) -> None:
    with pytest.raises(SystemExit):
        runtime._pinned_network(network)


def test_network_pins(local, monkeypatch) -> None:
    assert runtime._pinned_network("ws://127.0.0.1:9944") == "ws://127.0.0.1:9944"
    assert runtime._pinned_network("ws://localhost:9945") == "ws://localhost:9945"
    monkeypatch.delenv(localnet.LOCALNET_ENV)
    assert runtime._pinned_network("finney") == "finney"
    with pytest.raises(SystemExit):
        runtime._pinned_network("ws://127.0.0.1:9944")


def test_main_refuses_finney_in_localnet_mode_before_the_chain(
    local, monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(
        runtime, "make_subtensor", lambda *_a, **_k: pytest.fail("reached the chain")
    )
    with pytest.raises(SystemExit, match="refuses the Finney network"):
        runtime.main(
            [
                "--network",
                "finney",
                "--expected-hotkey",
                "5Validator",
                "--qvl",
                str(STUB),
                "--snp-policy",
                str(tmp_path / "policy.json"),
                "--snpguest",
                "unused",
                "--confirm-direct-write",
            ]
        )


def test_qvl_pin_is_the_release_pin_in_production(production) -> None:
    assert (
        qvl_runtime.expected_direct_validator_qvl_digest()
        == qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
    )
    with pytest.raises(QuoteVerifyError):
        qvl_runtime.load_direct_validator_verifier(str(STUB))


def _binding() -> ChannelBinding:
    return ChannelBinding(CHANNEL_BINDING_TYPE_TLS, bytes(range(32)))


def test_stub_verifier_accepts_only_a_stub_quote_with_its_report_data(local) -> None:
    verifier = qvl_runtime.load_direct_validator_verifier(str(STUB))
    assert verifier.digest == localnet.LOCALNET_STUB_QVL_DIGEST
    report_data = report_data_v2(bytes(32), MINER, _binding())
    quote = STUB_MAGIC + report_data + bytes(range(32))

    passed = verifier.verify_with_identity(quote, expected_report_data=report_data)
    assert passed.verdict is QuoteVerdict.PASS
    assert passed.platform_identity_verified is True
    assert passed.stable_platform_id.startswith("tdx-platform-sha256:")

    other = report_data_v2(bytes(range(32)), MINER, _binding())
    assert verifier.verify(quote, expected_report_data=other) is QuoteVerdict.FAIL
    assert verifier.verify(
        b"\x04\x00" + bytes(1000), expected_report_data=report_data
    ) is (QuoteVerdict.FAIL)


@pytest.mark.parametrize(
    "ip", ["10.10.20.17", "192.168.1.5", "100.103.39.86", "127.0.0.2"]
)
def test_private_axons_are_dialable_only_in_localnet_mode(monkeypatch, ip) -> None:
    monkeypatch.delenv(localnet.LOCALNET_ENV, raising=False)
    scan = scan_axons(_metagraph(ip))
    assert scan.serving == () and scan.skipped["unroutable"] == 1
    with pytest.raises(IndependentLiveError):
        validate_public_worker_endpoint(f"https://{ip}:8091")

    monkeypatch.setenv(localnet.LOCALNET_ENV, "1")
    assert [axon.ip for axon in scan_axons(_metagraph(ip)).serving] == [ip]
    assert validate_public_worker_endpoint(f"https://{ip}:8091") == f"https://{ip}:8091"


def test_localnet_never_admits_unspecified_or_multicast(local) -> None:
    for ip in ("0.0.0.0", "224.0.0.1", "fd00::1"):
        assert not localnet.allows_private_miner_address(ipaddress.ip_address(ip))


def _header(network: str | None) -> str:
    now = datetime.now(UTC).replace(microsecond=0)
    return build_validator_request_header(
        keypair=Keypair.create_from_uri("//LocalnetValidator"),
        worker_hotkey=MINER,
        method="POST",
        path="/v1/evidence",
        body=b"{}",
        channel_binding=_binding(),
        nonce=bytes(32),
        issued_at=now,
        expires_at=now + timedelta(seconds=60),
        network=network,
    )


def _signed_network(header: str) -> str:
    import base64
    import json

    return json.loads(base64.b64decode(header))["network"]


def test_validator_requests_name_local_only_in_localnet_mode(monkeypatch) -> None:
    monkeypatch.delenv(localnet.LOCALNET_ENV, raising=False)
    assert _signed_network(_header(None)) == "finney"
    with pytest.raises(IndependentLiveError):
        _header("local")
    monkeypatch.setenv(localnet.LOCALNET_ENV, "1")
    assert _signed_network(_header(None)) == "local"


def test_journal_scope_never_says_finney_in_localnet_mode(monkeypatch) -> None:
    monkeypatch.delenv(localnet.LOCALNET_ENV, raising=False)
    assert direct_state_scope(94) == "finney-sn94-mechanism-0"
    monkeypatch.setenv(localnet.LOCALNET_ENV, "1")
    assert direct_state_scope(94) == "localnet-sn94-mechanism-0"
