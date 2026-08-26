"""Live runner: Workers listing, integer mass, and contributing compose."""

from __future__ import annotations

import argparse
import ast
import http.client
import json
import stat
from pathlib import Path

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from _independent_fixtures import (
    ANCHOR_HASH,
    BOB,
    BURN_UID,
    CHARLIE,
    commitment_for,
)
from cathedral_thin.independent.collect import (
    CHANNEL_BINDING_TYPE_TLS,
    ChannelBinding,
    CollectedEvidence,
)
from cathedral_thin.independent.compose import STATUS_COMPOSED, compose_dry_run
from cathedral_thin.independent.compute import (
    COMPUTE_LANE,
    ComputeAdapter,
    QuoteVerdict,
)
from cathedral_thin.independent.constants import (
    BURN_HOTKEY,
    FINNEY_GENESIS_HASH,
    H,
    INDEPENDENT_CANARY_FILE,
    INDEPENDENT_STATE_FILE,
    TEMPO_BLOCKS,
)
from cathedral_thin.independent.errors import SatWorkError
from cathedral_thin.independent.inclusion import MetagraphView
from cathedral_thin.independent.journal import load_journal
from cathedral_thin.independent.sat import (
    SAT_WORK_UNIT_RULE,
    canonical_work_item,
    sat_work_url,
)
from cathedral_thin.independent_runtime import run as run_module
from cathedral_thin.independent_runtime.chain import ServingAxon
from cathedral_thin.independent_runtime.errors import (
    ChainClientError,
    IndependentLiveError,
    QuoteVerifyError,
)
from cathedral_thin.independent_runtime.https import (
    axon_evidence_url,
    axon_sat_work_url,
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


def test_axon_sat_work_url_is_built_from_the_axon_not_the_evidence_url():
    assert (
        axon_sat_work_url("2001:db8::1", 8443)
        == "https://[2001:db8::1]:8443/v1/sat-work"
    )
    assert (
        axon_sat_work_url("203.0.113.9", 443) == "https://203.0.113.9:443/v1/sat-work"
    )
    axon = ServingAxon(uid=MINER_UID, hotkey=BOB, ip="203.0.113.9", port=8443)
    assert axon.evidence_url() == "https://203.0.113.9:8443/v1/evidence"
    assert axon.sat_work_url() == "https://203.0.113.9:8443/v1/sat-work"
    # The work URL is validated as itself, and an evidence URL is never
    # rewritten into one.
    assert sat_work_url(axon.sat_work_url()) == axon.sat_work_url()
    with pytest.raises(SatWorkError):
        sat_work_url(axon.evidence_url())


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
    """The SAT path assigns units; nothing else in the runner may.

    ``verified_units[...] = ...`` is now a legal statement -- the audit
    re-derivation is exactly what fills it -- so the claim is checked by AST
    rather than by banning the subscript: every value assigned into
    ``verified_units`` must be the local the SAT helper returned, never a pass
    count, a quote length, or a verdict.
    """
    source = Path(run_module.__file__).read_text(encoding="utf-8")
    assert "verified_units.get" not in source
    assert "Attestation is admission" in source
    assert DEFAULT_STATE_DIR == "/var/lib/cathedral-validator"
    assert "/tmp" not in DEFAULT_STATE_DIR

    assigned: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == "verified_units"
            ):
                assert isinstance(node.value, ast.Name), ast.dump(node.value)
                assigned.append(node.value.id)
    assert assigned == ["units"]


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


class FakeAxon:
    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port
        self.is_serving = port > 0


class FakeMetagraph:
    def __init__(self, uids, hotkeys, *, port: int = 8443) -> None:
        self.uids = list(uids)
        self.hotkeys = list(hotkeys)
        self.axons = [FakeAxon("203.0.113.9", port) for _ in self.uids]


class OrderRecordingSubtensor:
    """Records the order of the RPCs the epoch snapshot makes.

    ``metagraph`` raises for a historical block when ``archive`` is false, which
    is what a pruning Finney endpoint does.
    """

    def __init__(self, head: int, *, archive: bool = True) -> None:
        self.head = head
        self.archive = archive
        self.calls: list[str] = []
        self.metagraph_blocks: list[object] = []

    def get_current_block(self) -> int:
        self.calls.append("get_current_block")
        return self.head

    def get_block_hash(self, number: int) -> str:
        self.calls.append(f"get_block_hash:{number}")
        return "0x" + "cd" * 32

    def metagraph(self, netuid: int, block: int | None = None):
        assert netuid == 39
        self.calls.append("metagraph" if block is None else f"metagraph:{block}")
        self.metagraph_blocks.append(block)
        if block is not None and not self.archive:
            raise RuntimeError("state already discarded for block")
        return FakeMetagraph([BURN_UID, MINER_UID], [BURN_HOTKEY, BOB])


def test_the_anchor_is_frozen_before_the_metagraph_is_snapshotted():
    """Order is the claim: a view read first belongs to the wrong tempo."""
    head = TEMPO_BLOCKS * 17_000 + 41
    subtensor = OrderRecordingSubtensor(head)
    snapshot = run_module.snapshot_epoch(subtensor)
    epoch_open = TEMPO_BLOCKS * 17_000
    assert subtensor.calls == [
        "get_current_block",
        f"get_block_hash:{epoch_open - 1}",
        f"metagraph:{epoch_open - 1}",
    ]
    assert snapshot.anchor.epoch_open == epoch_open
    assert snapshot.anchor.anchor_number == epoch_open - 1
    assert snapshot.at_anchor is True
    assert snapshot.note == ""
    assert snapshot.anchor_view.uid_to_hotkey[BURN_UID] == BURN_HOTKEY
    assert [axon.uid for axon in snapshot.axons] == [MINER_UID]


def test_a_pruning_node_snapshots_the_head_and_says_so():
    head = TEMPO_BLOCKS * 17_000 + 41
    subtensor = OrderRecordingSubtensor(head, archive=False)
    snapshot = run_module.snapshot_epoch(subtensor)
    epoch_open = TEMPO_BLOCKS * 17_000
    assert subtensor.calls == [
        "get_current_block",
        f"get_block_hash:{epoch_open - 1}",
        f"metagraph:{epoch_open - 1}",
        "metagraph",
    ]
    assert snapshot.at_anchor is False
    assert "could not serve the metagraph at anchor block" in snapshot.note
    assert snapshot.anchor.epoch_open == epoch_open
    assert snapshot.as_report()["at_anchor"] is False


class FakeGenesisSubstrate:
    def get_block_hash(self, number: int) -> str:
        assert number == 0
        return FINNEY_GENESIS_HASH


class RunnerSubtensor:
    """Enough of a Subtensor for ``cmd_run``.

    ``port=0`` means no axon serves, so nothing dials. A positive port makes the
    miner collectable, which is what the SAT wiring test needs.

    ``extra_miners`` are ``(uid, hotkey)`` rows appended after BOB. They are on
    the metagraph AND serving, so inclusion maps them to a UID and the composer
    can pay them, which is what the two-axon rounds need.
    """

    def __init__(self, head: int, *, port: int = 0, extra_miners=()) -> None:
        self.head = head
        self.port = port
        self.extra_miners = tuple(extra_miners)
        self.substrate = FakeGenesisSubstrate()
        self.metagraph_blocks: list[object] = []

    def get_current_block(self) -> int:
        return self.head

    def get_block_hash(self, number: int) -> str:
        return "0x" + "cd" * 32

    def metagraph(self, netuid: int, block: int | None = None):
        assert netuid == 39
        self.metagraph_blocks.append(block)
        uids = [BURN_UID, MINER_UID, *(uid for uid, _hotkey in self.extra_miners)]
        hotkeys = [BURN_HOTKEY, BOB, *(hotkey for _uid, hotkey in self.extra_miners)]
        return FakeMetagraph(uids, hotkeys, port=self.port)


class FakePinnedVerifier:
    digest = PINNED_QVL

    def verify(self, quote: bytes, *, expected_report_data: bytes) -> QuoteVerdict:
        del quote, expected_report_data
        return QuoteVerdict.PASS


def run_options(tmp_path, **overrides) -> argparse.Namespace:
    values = {
        "command": "run",
        "name": "independent-canary-miner",
        "rent": False,
        "qvl": None,
        "wait": 0,
        "state_dir": str(tmp_path / "state"),
        "confirm_canary": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def prepared_runner(
    monkeypatch,
    head: int,
    *,
    bind_mass: bool = True,
    port: int = 0,
    extra_miners=(),
) -> RunnerSubtensor:
    """A ``cmd_run`` that reaches COMPOSED without a network or a wallet.

    ``RunnerSubtensor`` serves no axon by default, so nothing collects and
    nothing re-derives units. With ``bind_mass`` the ``mass_from_units`` stub
    stands in for that missing audit round, which is what makes the gates AFTER
    compose reachable at all. With ``bind_mass=False`` the runner is left
    exactly as production is: a pinned QVL that would PASS, and no units.
    """
    monkeypatch.delenv("CATHEDRAL_API_KEY", raising=False)
    monkeypatch.delenv("CATHEDRAL_CANARY_HOTKEY_JSON", raising=False)
    monkeypatch.setattr(run_module, "fetch_public_json", lambda path: {})
    subtensor = RunnerSubtensor(head, port=port, extra_miners=extra_miners)
    monkeypatch.setattr(run_module, "_connect_subtensor", lambda: subtensor)
    monkeypatch.setattr(run_module, "load_verifier", lambda path: FakePinnedVerifier())
    if bind_mass:
        monkeypatch.setattr(
            run_module, "mass_from_units", lambda amount, units: {BOB: amount}
        )
    return subtensor


def composed_run(monkeypatch, tmp_path, capsys, **overrides):
    head = TEMPO_BLOCKS * 17_000 + 41
    subtensor = prepared_runner(monkeypatch, head)
    code = run_module.cmd_run(run_options(tmp_path, **overrides))
    report = json.loads(capsys.readouterr().out)
    return code, report, subtensor


def state_files(tmp_path) -> tuple[Path, Path]:
    state = tmp_path / "state"
    return state / INDEPENDENT_STATE_FILE.name, state / INDEPENDENT_CANARY_FILE.name


def test_an_unconfirmed_epoch_journals_a_compose_but_never_a_submission(
    monkeypatch, tmp_path, capsys
):
    code, report, _subtensor = composed_run(monkeypatch, tmp_path, capsys)
    assert code == 2
    assert report["compose"]["status"] == STATUS_COMPOSED
    assert any("--confirm-canary is required" in row for row in report["blockers"])
    journal, canary = state_files(tmp_path)
    record = load_journal(journal)
    assert record["status"] == STATUS_COMPOSED
    assert "submission" not in record
    assert not canary.exists()


def test_a_confirmed_epoch_without_a_wallet_journals_no_submission_either(
    monkeypatch, tmp_path, capsys
):
    code, report, _subtensor = composed_run(
        monkeypatch, tmp_path, capsys, confirm_canary=True
    )
    assert code == 2
    assert any("CATHEDRAL_CANARY_HOTKEY_JSON" in row for row in report["blockers"])
    journal, canary = state_files(tmp_path)
    assert "submission" not in load_journal(journal)
    assert not canary.exists()


def test_the_runner_snapshots_the_anchor_first_then_re_reads_at_the_head(
    monkeypatch, tmp_path, capsys
):
    code, report, subtensor = composed_run(monkeypatch, tmp_path, capsys)
    assert code == 2
    epoch_open = TEMPO_BLOCKS * 17_000
    assert subtensor.metagraph_blocks == [epoch_open - 1, None]
    assert report["anchor"]["epoch_open"] == epoch_open
    assert report["anchor"]["anchor_number"] == epoch_open - 1
    assert report["anchor"]["at_anchor"] is True
    assert report["compose"]["epoch_open"] == epoch_open


SAT_UNITS = 20
AXON_SAT_URL = "https://203.0.113.9:8443/v1/sat-work"
ONE_SPKI = bytes(range(32, 64))
OTHER_SPKI = bytes(range(64, 96))
SECOND_MINER_UID = 9


def collected_for(hotkey: str = BOB, *, digest: bytes = ONE_SPKI) -> CollectedEvidence:
    """A CollectedEvidence the way ``collect_evidence`` would have returned it.

    ``digest`` is the observed TLS SPKI, which is also the machine identity, so
    two miners can be given one machine or two.
    """
    binding = ChannelBinding(binding_type=CHANNEL_BINDING_TYPE_TLS, digest=digest)
    return CollectedEvidence(
        kind="tdx",
        quote=b"tdx-quote" * 16,
        nonce=bytes(range(32)),
        assigned_hotkey=hotkey,
        cert_chain=(),
        channel_binding=binding,
        report_data=bytes(64),
    )


def test_a_qvl_pass_without_re_derived_units_binds_no_compute_mass(
    monkeypatch, tmp_path, capsys
):
    """The behavioural half of "attestation is admission".

    Nothing is monkeypatched into ``mass_from_units`` here, and no axon serves,
    so the epoch has a pinned QVL that would PASS and still no units. The
    funded Compute row must stay unpayable.
    """
    prepared_runner(monkeypatch, TEMPO_BLOCKS * 17_000 + 41, bind_mass=False)
    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["verified_units"] == {}
    assert report["verified_mass"] == {}
    assert report["sat_work_rule"] == SAT_WORK_UNIT_RULE
    assert report["compose"]["status"] != STATUS_COMPOSED
    assert any(
        "no independently re-derived work units" in row for row in report["blockers"]
    )


def test_re_derived_sat_units_are_what_makes_the_runner_compose(
    monkeypatch, tmp_path, capsys
):
    """A serving axon, a PASS quote, and 20 re-derived units compose COMPOSED.

    ``mass_from_units`` is NOT stubbed: the integer mass under the funded
    allocation comes from the units the audit returned. ``collect_sat_work`` is
    stubbed only so no socket opens, and the URL it is handed proves the runner
    POSTs to the axon's own work endpoint rather than to the evidence URL.
    """
    subtensor = prepared_runner(
        monkeypatch, TEMPO_BLOCKS * 17_000 + 41, bind_mass=False, port=8443
    )
    collected = collected_for()
    seen: dict = {}

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        seen["evidence_url"] = url
        seen["sat_url"] = sat_work_url_value
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "quote_bytes": len(collected.quote),
            "kind": collected.kind,
            "collected": collected,
        }

    def fake_sat_work(*, url, assigned_hotkey, item, transport):
        seen["asked"] = (url, assigned_hotkey, item.challenge_id)
        return SAT_UNITS

    monkeypatch.setattr(run_module, "_try_collect", fake_collect)
    monkeypatch.setattr(run_module, "collect_sat_work", fake_sat_work)

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)

    assert seen["evidence_url"] == "https://203.0.113.9:8443/v1/evidence"
    assert seen["sat_url"] == AXON_SAT_URL
    assert seen["asked"][0] == AXON_SAT_URL
    assert seen["asked"][1] == BOB
    assert report["qvl_pass_count"] == 1
    assert report["verified_units"] == {BOB: SAT_UNITS}
    assert report["verified_mass"] == {BOB: COMPUTE_ALLOCATION}
    ((row,),) = (report["collect"],)
    assert row["sat_units"] == SAT_UNITS
    assert row["sat_rule"] == SAT_WORK_UNIT_RULE
    assert row["verdict"] == "PASS"
    assert report["compose"]["status"] == STATUS_COMPOSED
    assert MINER_UID in report["compose"]["dests"]
    assert sum(report["compose"]["weights"]) == 65535
    # Composed, but nothing was submitted: the canary still needs confirmation.
    assert code == 2
    assert any("--confirm-canary is required" in row for row in report["blockers"])
    assert subtensor.metagraph_blocks == [TEMPO_BLOCKS * 17_000 - 1, None]


def test_a_refused_sat_round_admits_the_miner_and_pays_it_nothing(
    monkeypatch, tmp_path, capsys
):
    """A machine that attests but produces no witness is admitted, unpaid."""
    prepared_runner(monkeypatch, TEMPO_BLOCKS * 17_000 + 41, bind_mass=False, port=8443)
    collected = collected_for()

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "quote_bytes": len(collected.quote),
            "kind": collected.kind,
            "collected": collected,
        }

    def refusing_sat_work(*, url, assigned_hotkey, item, transport):
        raise SatWorkError("the assignment leaves a clause unsatisfied")

    monkeypatch.setattr(run_module, "_try_collect", fake_collect)
    monkeypatch.setattr(run_module, "collect_sat_work", refusing_sat_work)

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["qvl_pass_count"] == 1
    assert report["verified_units"] == {}
    assert report["verified_mass"] == {}
    ((row,),) = (report["collect"],)
    assert row["verdict"] == "PASS"
    assert "SatWorkError" in row["sat_error"]
    assert "sat_units" not in row
    assert report["compose"]["status"] != STATUS_COMPOSED


def two_axon_runner(monkeypatch, digests: dict[str, bytes]) -> None:
    """A runner with BOB and CHARLIE both registered and both serving.

    ``digests`` hands each hotkey the TLS SPKI its evidence was bound to, so a
    round can put the two miners on one machine or on two.
    """
    prepared_runner(
        monkeypatch,
        TEMPO_BLOCKS * 17_000 + 41,
        bind_mass=False,
        port=8443,
        extra_miners=((SECOND_MINER_UID, CHARLIE),),
    )
    evidence = {
        hotkey: collected_for(hotkey, digest=digest)
        for hotkey, digest in digests.items()
    }

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "collected": evidence[hotkey],
        }

    monkeypatch.setattr(run_module, "_try_collect", fake_collect)


def collect_rows(report) -> dict[str, dict]:
    return {row["hotkey"]: row for row in report["collect"]}


def test_a_flaky_sat_http_exception_does_not_abort_the_epoch(
    monkeypatch, tmp_path, capsys
):
    """A flaky axon costs its own miner the round, never the whole epoch.

    ``http.client.HTTPException`` is not an ``OSError``, so a transport that
    only caught the named errors let one truncated response abort ``cmd_run``
    for every other miner on the subnet.
    """
    two_axon_runner(monkeypatch, {BOB: ONE_SPKI, CHARLIE: OTHER_SPKI})

    def flaky_sat_work(*, url, assigned_hotkey, item, transport):
        if assigned_hotkey == BOB:
            raise http.client.HTTPException("incomplete read")
        return SAT_UNITS

    monkeypatch.setattr(run_module, "collect_sat_work", flaky_sat_work)

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["qvl_pass_count"] == 2
    assert report["verified_units"] == {CHARLIE: SAT_UNITS}
    assert report["verified_mass"] == {CHARLIE: COMPUTE_ALLOCATION}
    rows = collect_rows(report)
    assert "HTTPException" in rows[BOB]["sat_error"]
    assert "sat_units" not in rows[BOB]
    assert rows[CHARLIE]["sat_units"] == SAT_UNITS
    assert report["compose"]["status"] == STATUS_COMPOSED
    assert SECOND_MINER_UID in report["compose"]["dests"]


def test_two_hotkeys_on_one_tls_spki_are_both_unpaid(monkeypatch, tmp_path, capsys):
    """One audited machine under two registered hotkeys pays neither.

    Both quotes PASS and both work rounds return units, so this is the exact
    shape of the duplicate-registration cheat: without the per-epoch machine
    ledger each hotkey would collect a full Compute share off one machine.
    """
    two_axon_runner(monkeypatch, {BOB: ONE_SPKI, CHARLIE: ONE_SPKI})

    def fake_sat_work(*, url, assigned_hotkey, item, transport):
        return SAT_UNITS

    monkeypatch.setattr(run_module, "collect_sat_work", fake_sat_work)

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    # Admitted, unpaid: both quotes passed, neither hotkey earned anything.
    assert report["qvl_pass_count"] == 2
    assert report["verified_units"] == {}
    assert report["verified_mass"] == {}
    rows = collect_rows(report)
    for hotkey in (BOB, CHARLIE):
        assert "MachineIdentityConflict" in rows[hotkey]["sat_error"]
        assert "sat_units" not in rows[hotkey]
        assert "sat_rule" not in rows[hotkey]
    assert any("machine-identity" in row for row in report["blockers"])
    assert report["compose"]["status"] != STATUS_COMPOSED


def test_two_hotkeys_on_distinct_tls_spki_are_both_paid(monkeypatch, tmp_path, capsys):
    """Two machines are two machines. The ledger only refuses duplicates."""
    two_axon_runner(monkeypatch, {BOB: ONE_SPKI, CHARLIE: OTHER_SPKI})

    def fake_sat_work(*, url, assigned_hotkey, item, transport):
        return SAT_UNITS

    monkeypatch.setattr(run_module, "collect_sat_work", fake_sat_work)

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["qvl_pass_count"] == 2
    assert report["verified_units"] == {BOB: SAT_UNITS, CHARLIE: SAT_UNITS}
    assert set(report["verified_mass"]) == {BOB, CHARLIE}
    assert sum(report["verified_mass"].values()) == COMPUTE_ALLOCATION
    assert report["compose"]["status"] == STATUS_COMPOSED
    assert MINER_UID in report["compose"]["dests"]
    assert SECOND_MINER_UID in report["compose"]["dests"]
    assert sum(report["compose"]["weights"]) == 65535


def test_a_failing_quote_is_never_asked_for_work(monkeypatch, tmp_path, capsys):
    prepared_runner(monkeypatch, TEMPO_BLOCKS * 17_000 + 41, bind_mass=False, port=8443)
    collected = collected_for()

    class FailingVerifier:
        digest = PINNED_QVL

        def verify(self, quote: bytes, *, expected_report_data: bytes):
            del quote, expected_report_data
            return QuoteVerdict.FAIL

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "collected": collected,
        }

    def deny(**kwargs):
        raise AssertionError("a FAIL quote must never be asked for work")

    monkeypatch.setattr(run_module, "load_verifier", lambda path: FailingVerifier())
    monkeypatch.setattr(run_module, "_try_collect", fake_collect)
    monkeypatch.setattr(run_module, "collect_sat_work", deny)

    code = run_module.cmd_run(run_options(tmp_path))
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["qvl_pass_count"] == 0
    assert report["verified_units"] == {}
    ((row,),) = (report["collect"],)
    assert row["verdict"] == "FAIL"
    assert "sat_error" not in row


def test_the_runner_asks_for_the_anchor_bound_challenge(monkeypatch, tmp_path, capsys):
    """The challenge is derived from the frozen anchor and the observed channel.

    The seed material is the anchor hash, the miner hotkey and the TLS SPKI
    digest as observed -- not re-hashed -- so this asserts the exact item the
    runner committed to.
    """
    prepared_runner(monkeypatch, TEMPO_BLOCKS * 17_000 + 41, bind_mass=False, port=8443)
    collected = collected_for()
    expected = canonical_work_item(
        anchor_hash="0x" + "cd" * 32,
        miner_ss58=BOB,
        machine_id=collected.channel_binding.digest.hex(),
    )
    asked: list = []

    def fake_collect(url, hotkey, validator_ss58, sat_work_url_value):
        return {
            "url": url,
            "sat_url": sat_work_url_value,
            "ok": True,
            "hotkey": hotkey,
            "collected": collected,
        }

    def fake_sat_work(*, url, assigned_hotkey, item, transport):
        asked.append(item)
        return SAT_UNITS

    monkeypatch.setattr(run_module, "_try_collect", fake_collect)
    monkeypatch.setattr(run_module, "collect_sat_work", fake_sat_work)
    run_module.cmd_run(run_options(tmp_path))
    capsys.readouterr()
    ((item,),) = (asked,)
    assert item == expected
    assert item.challenge_id == expected.challenge_id
    assert item.seed == expected.seed
    assert (
        expected.challenge_id
        != canonical_work_item(
            anchor_hash=ANCHOR_HASH,
            miner_ss58=BOB,
            machine_id=collected.channel_binding.digest.hex(),
        ).challenge_id
    )


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
