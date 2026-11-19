"""AB#820: an operator can point every validator path at their own subtensor node.

One setting: ``--subtensor.chain_endpoint`` / ``SUBTENSOR_CHAIN_ENDPOINT``
(``CATHEDRAL_CHAIN_ENDPOINT`` still works) and ``--subtensor.network`` /
``SUBTENSOR_NETWORK``. The endpoint only moves the connection; the pinned
Finney genesis still refuses any other chain.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from bittensor_wallet import Keypair

from cathedral_thin import chain_target
from cathedral_thin import preflight as preflight_cli
from cathedral_thin.chain_target import (
    ENDPOINT_ENV,
    LEGACY_ENDPOINT_ENV,
    NETWORK_ENV,
    ChainTargetError,
    add_chain_arguments,
    redact_endpoint,
    resolve_chain_target,
)
from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH
from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import direct_writer as writer_runtime
from cathedral_thin.independent_runtime import failed_write_recovery as record_cli
from cathedral_thin.independent_runtime import qvl as qvl_runtime
from cathedral_thin.independent_runtime import run as run_module
from cathedral_thin.independent_runtime.direct_writer import STATUS_CONFIRMED
from cathedral_thin.independent_runtime.testnet import TESTNET_GENESIS_HASH

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = Keypair.create_from_uri("//Alice")
LOCAL = "ws://127.0.0.1:9944"
CLI_ARGS = (
    "--qvl",
    "/reviewed/qvl",
    "--snp-policy",
    "/reviewed/snp-policy.json",
    "--snpguest",
    "/reviewed/snpguest",
    f"--expected-hotkey={VALIDATOR.ss58_address}",
    "--once",
    "--confirm-direct-write",
)
ALL_ENV = (NETWORK_ENV, ENDPOINT_ENV, LEGACY_ENDPOINT_ENV, "CATHEDRAL_TESTNET")


@pytest.fixture(autouse=True)
def _clean_chain_env(monkeypatch) -> None:
    for name in ALL_ENV:
        monkeypatch.delenv(name, raising=False)


# Resolver -------------------------------------------------------------------


def test_default_is_the_network_entrypoint_with_no_endpoint() -> None:
    target = resolve_chain_target(None, None, default_network="finney", environ={})
    assert target.network == "finney"
    assert target.endpoint is None
    assert target.connect_to == "finney"
    assert target.event() == {"network": "finney", "endpoint": "default"}


def test_flag_sets_the_endpoint_and_keeps_the_finney_label() -> None:
    target = resolve_chain_target(None, LOCAL, default_network="finney", environ={})
    assert (target.network, target.endpoint, target.endpoint_source) == (
        "finney",
        LOCAL,
        "--subtensor.chain_endpoint",
    )
    assert target.connect_to == LOCAL


@pytest.mark.parametrize("name", (ENDPOINT_ENV, LEGACY_ENDPOINT_ENV))
def test_each_environment_name_sets_the_endpoint(name: str) -> None:
    target = resolve_chain_target(
        None, None, default_network="finney", environ={name: LOCAL}
    )
    assert (target.endpoint, target.endpoint_source) == (LOCAL, name)


def test_endpoint_precedence_is_flag_then_subtensor_then_cathedral() -> None:
    env = {
        ENDPOINT_ENV: "ws://127.0.0.1:2",
        LEGACY_ENDPOINT_ENV: "ws://127.0.0.1:3",
    }
    flag = resolve_chain_target(
        None, "ws://127.0.0.1:1", default_network="finney", environ=env
    )
    assert flag.endpoint == "ws://127.0.0.1:1"
    standard = resolve_chain_target(None, None, default_network="finney", environ=env)
    assert (standard.endpoint, standard.endpoint_source) == (
        "ws://127.0.0.1:2",
        ENDPOINT_ENV,
    )
    legacy = resolve_chain_target(
        None,
        None,
        default_network="finney",
        environ={LEGACY_ENDPOINT_ENV: "ws://127.0.0.1:3"},
    )
    assert legacy.endpoint == "ws://127.0.0.1:3"


def test_network_precedence_is_flag_then_environment_then_default() -> None:
    assert (
        resolve_chain_target(
            "finney", None, default_network="x", environ={NETWORK_ENV: "finney"}
        ).network
        == "finney"
    )
    assert (
        resolve_chain_target(
            None, None, default_network="x", environ={NETWORK_ENV: "test"}
        ).network
        == "test"
    )
    assert (
        resolve_chain_target(None, None, default_network="x", environ={}).network == "x"
    )


def test_a_conflicting_network_label_in_the_environment_is_refused_not_ignored() -> (
    None
):
    # The unit always passes --network=finney; SUBTENSOR_NETWORK=local must not
    # silently leave the validator on the public entrypoint.
    with pytest.raises(ChainTargetError, match="To use your own node set"):
        resolve_chain_target(
            "finney", None, default_network="finney", environ={NETWORK_ENV: "local"}
        )


def test_a_url_in_subtensor_network_is_honoured_even_with_the_unit_flag() -> None:
    target = resolve_chain_target(
        "finney", None, default_network="finney", environ={NETWORK_ENV: LOCAL}
    )
    assert (target.network, target.endpoint, target.endpoint_source) == (
        "finney",
        LOCAL,
        NETWORK_ENV,
    )
    ranked = resolve_chain_target(
        "finney",
        None,
        default_network="finney",
        environ={NETWORK_ENV: LOCAL, ENDPOINT_ENV: "ws://127.0.0.1:2"},
    )
    assert ranked.endpoint == "ws://127.0.0.1:2"


def test_empty_environment_values_are_unset() -> None:
    target = resolve_chain_target(
        None,
        None,
        default_network="finney",
        environ={NETWORK_ENV: " ", ENDPOINT_ENV: "", LEGACY_ENDPOINT_ENV: LOCAL},
    )
    assert (target.network, target.endpoint, target.endpoint_source) == (
        "finney",
        LOCAL,
        LEGACY_ENDPOINT_ENV,
    )


def test_a_url_given_as_the_network_is_the_endpoint_and_the_label_stays() -> None:
    target = resolve_chain_target(LOCAL, None, default_network="finney", environ={})
    assert (target.network, target.endpoint) == ("finney", LOCAL)
    from_env = resolve_chain_target(
        None, None, default_network="finney", environ={NETWORK_ENV: LOCAL}
    )
    assert (from_env.network, from_env.endpoint, from_env.endpoint_source) == (
        "finney",
        LOCAL,
        NETWORK_ENV,
    )
    explicit = resolve_chain_target(
        LOCAL, "ws://127.0.0.1:1", default_network="finney", environ={}
    )
    assert explicit.endpoint == "ws://127.0.0.1:1"


@pytest.mark.parametrize(
    "value",
    (
        "ws://127.0.0.1:9944",
        "ws://localhost:9944",
        "ws://[::1]:9944",
        "ws://10.1.2.3:9944",
        "ws://192.168.1.20:9944",
        "ws://subtensor:9944",
        "ws://host.docker.internal:9944",
        "ws://100.101.102.103:9944",
        "wss://entrypoint-finney.opentensor.ai:443",
        "wss://node.example.com/ws/some-key",
    ),
)
def test_accepted_endpoints(value: str) -> None:
    assert chain_target.validate_endpoint(value, source="x") == value


@pytest.mark.parametrize(
    "value",
    (
        "http://127.0.0.1:9944",
        "127.0.0.1:9944",
        "ws://",
        "ws://127.0.0.1:9944#x",
        "ws://127.0.0.1:99999",
        "ws://node.example.com:9944",
        "ws://8.8.8.8:9944",
        "wss://exa mple.com",
    ),
)
def test_refused_endpoints(value: str) -> None:
    with pytest.raises(ChainTargetError):
        resolve_chain_target(None, value, default_network="finney", environ={})


def test_redaction_keeps_only_scheme_host_and_port() -> None:
    assert (
        redact_endpoint("wss://user:pass@node.example.com:443/ws/SECRETKEY?token=T")
        == "wss://node.example.com:443"
    )
    assert redact_endpoint("ws://[::1]:9944/x") == "ws://[::1]:9944"
    event = resolve_chain_target(
        None,
        "wss://node.example.com/SECRETKEY",
        default_network="finney",
        environ={},
    ).event()
    assert "SECRETKEY" not in json.dumps(event)


def test_both_flag_names_share_one_destination() -> None:
    parser = argparse.ArgumentParser()
    add_chain_arguments(parser)
    assert parser.parse_args(["--subtensor.network", "finney"]).network == "finney"
    assert parser.parse_args(["--network=finney"]).network == "finney"
    parsed = parser.parse_args([f"--subtensor.chain_endpoint={LOCAL}"])
    assert parsed.chain_endpoint == LOCAL


# Released validator -----------------------------------------------------------


class _Chain:
    def __init__(self, genesis: str = FINNEY_GENESIS_HASH) -> None:
        self.genesis_reads = 0
        self.genesis = genesis
        self.substrate = SimpleNamespace(
            retry_timeout=60.0, max_retries=5, get_block_hash=self._block_hash
        )

    def _block_hash(self, number: int) -> str:
        assert number == 0
        self.genesis_reads += 1
        return self.genesis


def _stub_validator(monkeypatch, chain: _Chain, seen: dict[str, object]) -> None:
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    monkeypatch.setattr(
        runtime,
        "load_direct_validator_verifier",
        lambda _path: SimpleNamespace(digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST),
    )
    monkeypatch.setattr(
        runtime,
        "ComputeAdapter",
        lambda *_args, **_kwargs: SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        ),
    )
    monkeypatch.setattr(runtime, "load_snp_policy", lambda _path: object())
    monkeypatch.setattr(runtime, "SnpProductionVerifier", lambda **_kwargs: object())
    monkeypatch.setattr(
        runtime,
        "make_wallet",
        lambda *_args, **_kwargs: SimpleNamespace(hotkey=VALIDATOR),
    )

    def make_subtensor(_bt, *, network):
        seen["connect_to"] = network
        return chain

    def writer(**_kwargs):
        seen["writer"] = True
        return SimpleNamespace(recover=lambda: None)

    monkeypatch.setattr(runtime, "make_subtensor", make_subtensor)
    monkeypatch.setattr(writer_runtime, "DirectWeightWriter", writer)
    monkeypatch.setattr(
        runtime, "run_direct_cycle", lambda **_kwargs: {"status": STATUS_CONFIRMED}
    )


def _events(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def test_default_validator_connects_to_finney_without_a_startup_genesis_read(
    monkeypatch, capsys
) -> None:
    chain, seen = _Chain(), {}
    _stub_validator(monkeypatch, chain, seen)

    assert runtime.main(list(CLI_ARGS)) == 0

    assert seen["connect_to"] == "finney"
    assert chain.genesis_reads == 0
    # The default path's stdout is unchanged: no chain line, no extra RPC.
    assert not any("chain" in row for row in _events(capsys.readouterr().out))


def test_validator_uses_the_endpoint_from_the_environment_file(
    monkeypatch, capsys
) -> None:
    chain, seen = _Chain(), {}
    _stub_validator(monkeypatch, chain, seen)
    monkeypatch.setenv(ENDPOINT_ENV, "wss://node.example.com:443/SECRETKEY")

    # The systemd unit still passes --network=finney: the endpoint is honoured.
    assert runtime.main(["--network=finney", *CLI_ARGS]) == 0

    assert seen["connect_to"] == "wss://node.example.com:443/SECRETKEY"
    assert chain.genesis_reads == 1
    out = capsys.readouterr().out
    assert "SECRETKEY" not in out
    assert {
        "chain": {
            "network": "finney",
            "endpoint": "wss://node.example.com:443",
            "endpoint_source": ENDPOINT_ENV,
            "genesis": FINNEY_GENESIS_HASH,
        }
    } in _events(out)


def test_validator_flag_beats_both_environment_names(monkeypatch) -> None:
    chain, seen = _Chain(), {}
    _stub_validator(monkeypatch, chain, seen)
    monkeypatch.setenv(ENDPOINT_ENV, "ws://127.0.0.1:2")
    monkeypatch.setenv(LEGACY_ENDPOINT_ENV, "ws://127.0.0.1:3")

    assert (
        runtime.main([*CLI_ARGS, "--subtensor.chain_endpoint", "ws://127.0.0.1:1"]) == 0
    )
    assert seen["connect_to"] == "ws://127.0.0.1:1"


def test_validator_keeps_honouring_the_older_cathedral_name(monkeypatch) -> None:
    chain, seen = _Chain(), {}
    _stub_validator(monkeypatch, chain, seen)
    monkeypatch.setenv(LEGACY_ENDPOINT_ENV, LOCAL)

    assert runtime.main(list(CLI_ARGS)) == 0
    assert seen["connect_to"] == LOCAL


@pytest.mark.parametrize("genesis", (TESTNET_GENESIS_HASH, "0x" + "ab" * 32))
def test_validator_refuses_a_node_on_another_chain_before_the_writer(
    monkeypatch, genesis: str
) -> None:
    chain, seen = _Chain(genesis=genesis), {}
    _stub_validator(monkeypatch, chain, seen)
    monkeypatch.setenv(ENDPOINT_ENV, LOCAL)

    with pytest.raises(SystemExit) as refused:
        runtime.main(list(CLI_ARGS))

    message = refused.value.code
    assert isinstance(message, str)  # status 1: never the unit's no-restart 2
    assert "is not the pinned Finney genesis" in message
    assert "writer" not in seen


def test_validator_refuses_a_node_whose_genesis_cannot_be_read(monkeypatch) -> None:
    chain, seen = _Chain(), {}

    def broken(_number):
        raise ConnectionError("refused")

    chain.substrate.get_block_hash = broken
    _stub_validator(monkeypatch, chain, seen)
    monkeypatch.setenv(ENDPOINT_ENV, LOCAL)

    with pytest.raises(SystemExit) as refused:
        runtime.main(list(CLI_ARGS))
    assert "could not read genesis hash" in str(refused.value.code)
    assert "writer" not in seen


def test_validator_still_refuses_a_network_other_than_finney(monkeypatch) -> None:
    for name in ("load_direct_validator_verifier", "make_wallet", "make_subtensor"):
        monkeypatch.setattr(
            runtime,
            name,
            lambda *_a, _name=name, **_k: pytest.fail(f"{_name} ran"),
        )
    monkeypatch.setenv(NETWORK_ENV, "test")
    with pytest.raises(SystemExit, match="pinned to the Finney network"):
        runtime.main(list(CLI_ARGS))


@pytest.mark.parametrize(
    "value", ("http://127.0.0.1:9944", "ws://node.example.com:9944")
)
def test_validator_refuses_a_bad_endpoint_with_status_one_before_chain_access(
    monkeypatch, value: str
) -> None:
    monkeypatch.setattr(
        runtime, "make_subtensor", lambda *_a, **_k: pytest.fail("connected")
    )
    monkeypatch.setenv(ENDPOINT_ENV, value)
    with pytest.raises(SystemExit) as refused:
        runtime.main(list(CLI_ARGS))
    assert isinstance(refused.value.code, str)
    assert refused.value.code.startswith("chain endpoint refused:")


def test_testnet_rehearsal_accepts_an_endpoint_and_pins_testnet_genesis(
    monkeypatch,
) -> None:
    chain, seen = _Chain(genesis=FINNEY_GENESIS_HASH), {}
    _stub_validator(monkeypatch, chain, seen)
    monkeypatch.setenv("CATHEDRAL_TESTNET", "1")
    monkeypatch.setenv(ENDPOINT_ENV, LOCAL)

    with pytest.raises(SystemExit, match="pinned testnet genesis"):
        runtime.main(["--network=test", "--netuid=584", *CLI_ARGS])


# record-failed-write, weekly-report, canary runtime, legacy CLIs ---------------


def _record(monkeypatch, seen: list[str]) -> None:
    class Writer:
        def __init__(self, *, subtensor, keypair, netuid) -> None:
            del subtensor, keypair, netuid

        def record_finalized_failure(self) -> dict[str, object]:
            return {}

    def make_subtensor(_bt, *, network):
        seen.append(network)
        return SimpleNamespace(
            substrate=SimpleNamespace(retry_timeout=60.0, max_retries=5)
        )

    monkeypatch.setattr(record_cli, "make_subtensor", make_subtensor)
    monkeypatch.setattr(record_cli, "DirectWeightWriter", Writer)


RECORD = (
    runtime.RECORD_FAILED_WRITE_COMMAND,
    f"--expected-hotkey={VALIDATOR.ss58_address}",
)


def test_record_command_uses_the_configured_endpoint(monkeypatch) -> None:
    seen: list[str] = []
    _record(monkeypatch, seen)
    monkeypatch.setenv(ENDPOINT_ENV, LOCAL)
    assert runtime.main(list(RECORD)) == 0
    assert seen == [LOCAL]


def test_record_command_archive_endpoint_wins(monkeypatch) -> None:
    seen: list[str] = []
    _record(monkeypatch, seen)
    monkeypatch.setenv(ENDPOINT_ENV, LOCAL)
    archive = "wss://archive.chain.opentensor.ai:443"
    assert runtime.main([*RECORD, f"--archive-endpoint={archive}"]) == 0
    assert seen == [archive]


def test_record_command_default_is_unchanged(monkeypatch) -> None:
    seen: list[str] = []
    _record(monkeypatch, seen)
    assert runtime.main([*RECORD, "--network=finney"]) == 0
    assert seen == ["finney"]


def test_canary_runtime_connects_to_the_configured_endpoint(
    monkeypatch, capsys
) -> None:
    seen: list[str] = []
    monkeypatch.setattr(
        run_module.bt,
        "Subtensor",
        lambda *, network: seen.append(network) or object(),
    )
    options = run_module._build_parser().parse_args(
        ["probe-sn94", "--subtensor.chain_endpoint", LOCAL]
    )
    run_module._connect_subtensor(options)
    monkeypatch.setenv(ENDPOINT_ENV, "ws://127.0.0.1:2")
    run_module._connect_subtensor(None)
    assert seen == [LOCAL, "ws://127.0.0.1:2"]
    monkeypatch.delenv(ENDPOINT_ENV)
    run_module._connect_subtensor(None)
    assert seen[-1] == "finney"


def _legacy_args(**overrides) -> argparse.Namespace:
    parser = preflight_cli.build_parser()
    args = parser.parse_args(["--role", "validator"])
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def test_preflight_honours_the_endpoint_and_checks_finney_genesis(
    monkeypatch, capsys
) -> None:
    seen: list[str] = []
    chain = _Chain()
    monkeypatch.setattr(
        "cathedral_thin.bt_compat.make_subtensor",
        lambda _bt, *, network: seen.append(network) or chain,
    )
    monkeypatch.setenv(ENDPOINT_ENV, LOCAL)
    args = _legacy_args()
    target = chain_target.resolve_args(args, default_network="finney")
    assert chain_target.connect_legacy(object(), target) is chain
    assert seen == [LOCAL] and chain.genesis_reads == 1
    assert args.network == "finney"

    chain.genesis = TESTNET_GENESIS_HASH
    with pytest.raises(SystemExit, match="not the pinned finney genesis"):
        chain_target.connect_legacy(object(), target)

    test_target = chain_target.resolve_chain_target(
        "test", LOCAL, default_network="local", environ={}
    )
    chain.genesis = FINNEY_GENESIS_HASH
    with pytest.raises(SystemExit, match="not the pinned test genesis"):
        chain_target.connect_legacy(object(), test_target)
    local_target = chain_target.resolve_chain_target(
        "local", LOCAL, default_network="local", environ={}
    )
    assert chain_target.connect_legacy(object(), local_target) is chain


def test_legacy_validator_keeps_its_local_default_and_reads_subtensor_network(
    monkeypatch,
) -> None:
    from cathedral_thin import validator as legacy

    args = legacy.build_parser().parse_args([])
    assert chain_target.resolve_args(args, default_network="local").network == "local"
    monkeypatch.setenv(NETWORK_ENV, "test")
    args = legacy.build_parser().parse_args([])
    assert chain_target.resolve_args(args, default_network="local").network == "test"


def test_scaffold_chain_keeps_its_older_name_and_redacts_the_log(
    monkeypatch, capsys
) -> None:
    from scaffold import chain as scaffold_chain

    monkeypatch.setattr(scaffold_chain, "_announced", False)
    # The owner tools keep CATHEDRAL_CHAIN_ENDPOINT only: the generic name an
    # operator exports for validators must not redirect them.
    monkeypatch.setenv(ENDPOINT_ENV, "ws://127.0.0.1:2")
    assert scaffold_chain.connection_target("finney") == "finney"
    monkeypatch.setenv(LEGACY_ENDPOINT_ENV, "wss://node.example.com/SECRETKEY")
    assert (
        scaffold_chain.connection_target("finney") == "wss://node.example.com/SECRETKEY"
    )
    assert "SECRETKEY" not in capsys.readouterr().out


def test_connection_errors_never_print_the_full_endpoint(monkeypatch, capsys) -> None:
    secret = "wss://node.example.com/SECRETKEY"

    def explode(*_a, **_k):
        raise ConnectionError(f"cannot reach {secret}")

    monkeypatch.setattr(runtime, "make_subtensor", explode)
    with pytest.raises(SystemExit) as refused:
        runtime._connect(resolve_chain_target(None, secret, default_network="finney"))
    assert "SECRETKEY" not in str(refused.value.code)

    monkeypatch.setattr(record_cli, "make_subtensor", explode)
    monkeypatch.setenv(ENDPOINT_ENV, secret)
    assert runtime.main(list(RECORD)) == record_cli.EXIT_REFUSED
    assert "SECRETKEY" not in capsys.readouterr().out


# Unit and docs ----------------------------------------------------------------


def test_direct_unit_reads_the_optional_subtensor_env_file_and_execstart_is_unchanged() -> (
    None
):
    unit = (
        ROOT / "deploy/validator-update/cathedral-validator-direct.service"
    ).read_text()
    assert "EnvironmentFile=-/etc/cathedral-validator/direct-subtensor.env\n" in unit
    exec_start = next(
        line for line in unit.splitlines() if line.startswith("ExecStart=")
    )
    assert "--network=finney" in exec_start
    assert "chain_endpoint" not in exec_start


def test_validator_guide_has_the_exact_env_line_and_command() -> None:
    guide = (ROOT / "VALIDATOR.md").read_text()
    assert "## Use your own subtensor node" in guide
    assert "SUBTENSOR_CHAIN_ENDPOINT=ws://127.0.0.1:9944" in guide
    assert "/etc/cathedral-validator/direct-subtensor.env" in guide
    assert "\u2014" not in guide
