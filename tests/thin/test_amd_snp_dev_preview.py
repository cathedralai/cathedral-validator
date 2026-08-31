from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tomllib
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cathedral_thin.independent_runtime import amd_snp_dev_preview as preview
from cathedral_thin.independent_runtime.multicompute import MachineWorkObservation

VALIDATOR = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
MINER = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
WINDOW = "0x" + "ab" * 32
MEASUREMENT = "cd" * 48
CHIP_ID = bytes(range(64))


def _document(*, targets: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "schema": preview.CONFIG_SCHEMA,
        "environment": "development",
        "network": "finney",
        "netuid": 39,
        "validator_hotkey": VALIDATOR,
        "validator_wallet": {"name": "cathedral", "hotkey": "default", "path": None},
        "scoring_window": WINDOW,
        "review_challenge_hex": "11" * 32,
        "snpguest_path": "/opt/cathedral/bin/snpguest",
        "processor_generation": "milan",
        "allowed_measurements": [MEASUREMENT],
        "minimum_reported_tcb": "0x0101000000000101",
        "timeout_seconds": 30,
        "targets": targets
        or [
            {
                "uid": 124,
                "miner_hotkey": MINER,
                "endpoint": "https://1.1.1.1:8081",
                "tls_ca_cert": "/etc/cathedral/miner-1.pem",
            }
        ],
    }


def _config(
    *, targets: tuple[preview.TargetConfig, ...] | None = None
) -> preview.DevPreviewConfig:
    return preview.parse_config_document(
        _document(
            targets=[
                {
                    "uid": target.uid,
                    "miner_hotkey": target.miner_hotkey,
                    "endpoint": target.endpoint,
                    "tls_ca_cert": target.tls_ca_cert,
                }
                for target in targets
            ]
            if targets is not None
            else None
        )
    )


def _observation(
    endpoint: str,
    *,
    machine_id: str,
    channel_id: str,
) -> MachineWorkObservation:
    return MachineWorkObservation(
        scoring_window=WINDOW,
        uid=124,
        miner_hotkey=MINER,
        endpoint=endpoint,
        channel_id=channel_id,
        machine_id=machine_id,
        evidence_fresh=True,
        hardware_verified=True,
        channel_bound=True,
        work_units=20,
    )


def test_config_is_strict_development_only_and_same_uid_hotkey():
    config = preview.parse_config_document(_document())
    assert config.environment == "development"
    assert config.uid == 124
    assert config.processor_generation == "milan"
    assert config.minimum_reported_tcb == 0x0101000000000101

    extra = _document()
    extra["production"] = True
    with pytest.raises(preview.AmdSnpDevPreviewError, match="unknown keys"):
        preview.parse_config_document(extra)

    mixed = _document(
        targets=[
            _document()["targets"][0],
            {
                "uid": 125,
                "miner_hotkey": MINER,
                "endpoint": "https://8.8.8.8:8081",
                "tls_ca_cert": "/etc/cathedral/miner-2.pem",
            },
        ]
    )
    with pytest.raises(preview.AmdSnpDevPreviewError, match="same UID"):
        preview.parse_config_document(mixed)


def test_config_target_batch_is_bounded_at_32():
    base = _document()["targets"][0]
    targets = [
        dict(base, endpoint=f"https://1.1.1.1:{8000 + index}") for index in range(33)
    ]
    with pytest.raises(preview.AmdSnpDevPreviewError, match="1..32"):
        preview.parse_config_document(_document(targets=targets))


def test_config_loader_refuses_symlink(tmp_path):
    target = tmp_path / "config.json"
    target.write_text(json.dumps(_document()), encoding="utf-8")
    link = tmp_path / "linked.json"
    link.symlink_to(target)

    with pytest.raises(preview.AmdSnpDevPreviewError, match="regular file"):
        preview.load_config(link)


def test_config_loader_requires_owner_only_mode(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")
    path.chmod(0o666)

    with pytest.raises(
        preview.AmdSnpDevPreviewError, match="owner-controlled mode 0600"
    ):
        preview.load_config(path)


def test_tls_ca_rejects_group_or_world_writable_file(tmp_path):
    path = tmp_path / "ca.pem"
    path.write_bytes(b"certificate")
    path.chmod(0o622)

    with pytest.raises(preview._TargetRefusal, match="not_owner_controlled"):
        preview._read_tls_ca_cert(path)


def test_tls_ca_reads_opened_inode_when_path_is_replaced(monkeypatch, tmp_path):
    path = tmp_path / "ca.pem"
    original = b"reviewed-ca-bytes"
    path.write_bytes(original)
    path.chmod(0o600)
    replacement = tmp_path / "replacement.pem"
    replacement.write_bytes(b"attacker-ca-bytes")
    replacement.chmod(0o600)
    real_open = preview.os.open

    def replace_after_open(candidate, flags, *args):
        descriptor = real_open(candidate, flags, *args)
        if Path(candidate) == path:
            replacement.replace(path)
        return descriptor

    monkeypatch.setattr(preview.os, "open", replace_after_open)

    assert preview._read_tls_ca_cert(path) == original


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("environment", "production", "environment must be development"),
        ("netuid", 39.0, "pinned to finney SN39"),
        ("processor_generation", "rome", "one of milan, genoa, or turin"),
        ("processor_generation", ["milan"], "one of milan, genoa, or turin"),
        ("minimum_reported_tcb", "0x0000000000000000", "must be nonzero"),
    ),
)
def test_config_refuses_production_type_coercion_and_zero_tcb(field, value, message):
    document = _document()
    document[field] = value
    with pytest.raises(preview.AmdSnpDevPreviewError, match=message):
        preview.parse_config_document(document)


@pytest.mark.parametrize(
    ("processor_generation", "minimum_tcb", "expected"),
    (
        ("milan", "0x0101000000000101", 0x0101000000000101),
        ("genoa", "0x0203000000000405", 0x0203000000000405),
        ("turin", "0x0600000005040302", 0x0600000005040302),
    ),
)
def test_minimum_tcb_uses_generation_specific_component_bytes(
    processor_generation, minimum_tcb, expected
):
    document = _document()
    document["processor_generation"] = processor_generation
    document["minimum_reported_tcb"] = minimum_tcb

    config = preview.parse_config_document(document)

    assert config.processor_generation == processor_generation
    assert config.minimum_reported_tcb == expected


@pytest.mark.parametrize(
    ("processor_generation", "minimum_tcb"),
    (
        # Milan and Genoa reserve little-endian bytes 2 through 5.
        ("milan", "0x0000000001060203"),
        ("genoa", "0x0000000001060203"),
        # Turin reserves little-endian bytes 4 through 6.
        ("turin", "0x0001020300000001"),
    ),
)
def test_minimum_tcb_refuses_reserved_bytes_for_generation(
    processor_generation, minimum_tcb
):
    document = _document()
    document["processor_generation"] = processor_generation
    document["minimum_reported_tcb"] = minimum_tcb

    with pytest.raises(preview.AmdSnpDevPreviewError, match="sets reserved bytes"):
        preview.parse_config_document(document)


def test_fake_compute_client_wires_hotkey_signer_and_scores_same_channel(monkeypatch):
    binding_type = object()
    evidence_kind = object()
    tier = object()
    binding = SimpleNamespace(binding_type=binding_type, digest=b"t" * 32)
    evidence = SimpleNamespace(
        kind=evidence_kind,
        report_data_version=2,
        channel_binding=binding,
        quote=b"raw-quote-must-not-serialize",
    )
    captured: dict[str, object] = {}
    events: list[str] = []

    class Client:
        def fetch_evidence(self, nonce):
            assert nonce == b"n" * 32
            events.append("evidence")
            return evidence

        def confirm_channel_binding(self, supplied):
            assert supplied is evidence
            events.append("channel")
            return binding

        def confirm_signed_validator_access_required(self, supplied):
            assert supplied is evidence
            events.append("signed-access")

        def do_sat_work(self, item):
            assert item == "canonical-item"
            events.append("sat")
            return "sat-result"

    def remote_miner(endpoint, hotkey, **kwargs):
        captured.update(endpoint=endpoint, hotkey=hotkey, **kwargs)
        return Client()

    class Lane:
        def __init__(self, *, namespace):
            assert len(namespace) == 32

        def dispatch(self, hotkey, budget):
            assert (hotkey, budget) == (MINER, 20)
            return "canonical-item"

        def verify(self, item, result):
            assert (item, result) == ("canonical-item", "sat-result")
            return "verified-certificate"

        def score(self, hotkey, certificates):
            assert (hotkey, certificates) == (MINER, ["verified-certificate"])
            return 20.0

    contract = SimpleNamespace(
        RemoteMiner=remote_miner,
        issue_nonce=lambda: b"n" * 32,
        EvidenceKind=SimpleNamespace(SEV_SNP=evidence_kind),
        ChannelBindingType=SimpleNamespace(TLS_SPKI_SHA256=binding_type),
        Policy=lambda **kwargs: SimpleNamespace(**kwargs),
        Tier=SimpleNamespace(CC_CPU_SNP=tier),
        verify_snp=lambda *args, **kwargs: SimpleNamespace(
            tier=tier,
            chain_verified=True,
            verification_status="VERIFIED",
            chip_id=CHIP_ID.hex(),
        ),
        parse_snp_report=lambda _quote: SimpleNamespace(
            guest_policy=preview.AMD_GUEST_POLICY_SINGLE_SOCKET,
            chip_id=CHIP_ID.hex(),
        ),
        snp_generation=lambda _parsed: "milan",
        SatLane=Lane,
    )
    keypair = SimpleNamespace(
        ss58_address=VALIDATOR,
        sign=lambda message: hashlib.sha512(message).digest(),
    )
    monkeypatch.setattr(
        preview, "_client_tls_context", lambda _target: "verified-context"
    )
    config = _config()
    observation = preview._score_target(
        config,
        config.targets[0],
        keypair=keypair,
        contract=contract,
    )

    assert observation.work_units == 20
    assert observation.hardware_verified is True
    assert observation.channel_id == (b"t" * 32).hex()
    assert observation.machine_id != CHIP_ID.hex()
    assert captured["endpoint"] == "https://1.1.1.1:8081"
    assert captured["hotkey"] == MINER
    assert captured["validator_hotkey"] == VALIDATOR
    assert captured["validator_network"] == "finney"
    assert captured["validator_netuid"] == 39
    assert captured["ssl_context"] == "verified-context"
    assert (
        captured["validator_signer"](b"signed-body")
        == hashlib.sha512(b"signed-body").digest()
    )
    assert events == ["evidence", "channel", "signed-access", "sat"]


def test_single_socket_guest_policy_bit_is_required_before_identity_eligibility(
    monkeypatch,
):
    binding_type = object()
    evidence_kind = object()
    tier = object()
    binding = SimpleNamespace(binding_type=binding_type, digest=b"t" * 32)
    evidence = SimpleNamespace(
        kind=evidence_kind,
        report_data_version=2,
        channel_binding=binding,
        quote=b"quote",
    )
    client = SimpleNamespace(fetch_evidence=lambda _nonce: evidence)
    contract = SimpleNamespace(
        RemoteMiner=lambda *_args, **_kwargs: client,
        issue_nonce=lambda: b"n" * 32,
        EvidenceKind=SimpleNamespace(SEV_SNP=evidence_kind),
        ChannelBindingType=SimpleNamespace(TLS_SPKI_SHA256=binding_type),
        Policy=lambda **kwargs: SimpleNamespace(**kwargs),
        Tier=SimpleNamespace(CC_CPU_SNP=tier),
        verify_snp=lambda *args, **kwargs: SimpleNamespace(
            tier=tier,
            chain_verified=True,
            verification_status="VERIFIED",
            chip_id=CHIP_ID.hex(),
        ),
        parse_snp_report=lambda _quote: SimpleNamespace(
            guest_policy=0,
            chip_id=CHIP_ID.hex(),
        ),
        snp_generation=lambda _parsed: "milan",
    )
    monkeypatch.setattr(preview, "_client_tls_context", lambda _target: "context")
    config = _config()
    observation = preview._score_target(
        config,
        config.targets[0],
        keypair=SimpleNamespace(sign=lambda _body: b"s" * 64),
        contract=contract,
    )
    assert observation.hardware_verified is False
    assert observation.machine_id is None
    assert observation.work_units is None
    assert observation._dev_reason == "amd_single_socket_guest_policy_bit_not_asserted"


def test_report_processor_generation_must_match_config(monkeypatch):
    binding_type = object()
    evidence_kind = object()
    binding = SimpleNamespace(binding_type=binding_type, digest=b"t" * 32)
    evidence = SimpleNamespace(
        kind=evidence_kind,
        report_data_version=2,
        channel_binding=binding,
        quote=b"quote",
    )
    contract = SimpleNamespace(
        RemoteMiner=lambda *_args, **_kwargs: SimpleNamespace(
            fetch_evidence=lambda _nonce: evidence
        ),
        issue_nonce=lambda: b"n" * 32,
        EvidenceKind=SimpleNamespace(SEV_SNP=evidence_kind),
        ChannelBindingType=SimpleNamespace(TLS_SPKI_SHA256=binding_type),
        parse_snp_report=lambda _quote: SimpleNamespace(),
        snp_generation=lambda _parsed: "genoa",
    )
    monkeypatch.setattr(preview, "_client_tls_context", lambda _target: "context")
    config = _config()

    observation = preview._score_target(
        config,
        config.targets[0],
        keypair=SimpleNamespace(sign=lambda _body: b"s" * 64),
        contract=contract,
    )

    assert observation.hardware_verified is False
    assert observation._dev_reason == "snp_processor_generation_mismatch"


def test_worker_accepting_unsigned_access_is_refused_before_sat(monkeypatch):
    binding_type = object()
    evidence_kind = object()
    tier = object()
    binding = SimpleNamespace(binding_type=binding_type, digest=b"t" * 32)
    evidence = SimpleNamespace(
        kind=evidence_kind,
        report_data_version=2,
        channel_binding=binding,
        quote=b"quote",
    )
    sat_called = False

    class Client:
        def fetch_evidence(self, _nonce):
            return evidence

        def confirm_channel_binding(self, _evidence):
            return binding

        def confirm_signed_validator_access_required(self, _evidence):
            raise RuntimeError("worker accepted unsigned access")

        def do_sat_work(self, _item):
            nonlocal sat_called
            sat_called = True
            raise AssertionError("SAT must not run")

    contract = SimpleNamespace(
        RemoteMiner=lambda *_args, **_kwargs: Client(),
        issue_nonce=lambda: b"n" * 32,
        EvidenceKind=SimpleNamespace(SEV_SNP=evidence_kind),
        ChannelBindingType=SimpleNamespace(TLS_SPKI_SHA256=binding_type),
        Policy=lambda **kwargs: SimpleNamespace(**kwargs),
        Tier=SimpleNamespace(CC_CPU_SNP=tier),
        verify_snp=lambda *_args, **_kwargs: SimpleNamespace(
            tier=tier,
            chain_verified=True,
            verification_status="VERIFIED",
            chip_id=CHIP_ID.hex(),
        ),
        parse_snp_report=lambda _quote: SimpleNamespace(
            guest_policy=preview.AMD_GUEST_POLICY_SINGLE_SOCKET,
            chip_id=CHIP_ID.hex(),
        ),
        snp_generation=lambda _parsed: "milan",
    )
    monkeypatch.setattr(preview, "_client_tls_context", lambda _target: "context")
    config = _config()

    observation = preview._score_target(
        config,
        config.targets[0],
        keypair=SimpleNamespace(sign=lambda _body: b"s" * 64),
        contract=contract,
    )

    assert observation.hardware_verified is False
    assert observation._dev_reason == "signed_validator_access_not_required"
    assert sat_called is False

    delattr(Client, "confirm_signed_validator_access_required")
    missing_check = preview._score_target(
        config,
        config.targets[0],
        keypair=SimpleNamespace(sign=lambda _body: b"s" * 64),
        contract=contract,
    )
    assert missing_check._dev_reason == "signed_validator_access_check_unavailable"
    assert sat_called is False


def test_vendor_verifier_infrastructure_failure_is_not_blame_on_miner(monkeypatch):
    class VerifierUnavailable(Exception):
        pass

    binding_type = object()
    evidence_kind = object()
    binding = SimpleNamespace(binding_type=binding_type, digest=b"t" * 32)
    evidence = SimpleNamespace(
        kind=evidence_kind,
        report_data_version=2,
        channel_binding=binding,
        quote=b"quote",
    )
    client = SimpleNamespace(fetch_evidence=lambda _nonce: evidence)

    def unavailable(*_args, **_kwargs):
        raise VerifierUnavailable

    contract = SimpleNamespace(
        RemoteMiner=lambda *_args, **_kwargs: client,
        issue_nonce=lambda: b"n" * 32,
        EvidenceKind=SimpleNamespace(SEV_SNP=evidence_kind),
        ChannelBindingType=SimpleNamespace(TLS_SPKI_SHA256=binding_type),
        Policy=lambda **kwargs: SimpleNamespace(**kwargs),
        parse_snp_report=lambda _quote: SimpleNamespace(),
        snp_generation=lambda _parsed: "milan",
        verify_snp=unavailable,
        SnpVerifierUnavailable=VerifierUnavailable,
    )
    monkeypatch.setattr(preview, "_client_tls_context", lambda _target: "context")
    config = _config()

    observation = preview._score_target(
        config,
        config.targets[0],
        keypair=SimpleNamespace(sign=lambda _body: b"s" * 64),
        contract=contract,
    )

    assert observation.hardware_verified is False
    assert observation._dev_reason == "snp_verifier_infrastructure_unavailable"


def test_distinct_sockets_get_twenty_each_and_duplicates_zero_globally():
    targets = (
        preview.TargetConfig(124, MINER, "https://1.1.1.1:8081", "/tmp/one.pem"),
        preview.TargetConfig(124, MINER, "https://8.8.8.8:8081", "/tmp/two.pem"),
    )
    config = _config(targets=targets)
    distinct = (
        _observation(targets[0].endpoint, machine_id="1" * 64, channel_id="a" * 64),
        _observation(targets[1].endpoint, machine_id="2" * 64, channel_id="b" * 64),
    )
    document = preview.build_preview_document(
        config,
        distinct,
        compute_commit="c" * 40,
        snpguest_digest="d" * 64,
        snpguest_version="0.10.0",
    )
    assert document["status"] == preview.STATUS
    assert document["raw_uid_units"] == 40
    assert document["verified_distinct_socket_count"] == 2
    assert document["all_configured_targets_passed"] is True
    assert document["signed_validator_access_enforcement_requirement"] is True
    assert document["fresh_report_data_version_requirement"] == 2
    assert document["tls_spki_binding_requirement"] == "sha256"
    assert document["same_channel_canonical_sat_requirement"] is True
    assert document["policy"]["processor_generation"] == "milan"
    assert "signed_validator_https" not in document

    duplicate = (distinct[0], replace(distinct[1], machine_id="1" * 64))
    refused = preview.build_preview_document(
        config,
        duplicate,
        compute_commit="c" * 40,
        snpguest_digest="d" * 64,
        snpguest_version="0.10.0",
    )
    assert refused["status"] == preview.NOT_PROVEN_STATUS
    assert refused["raw_uid_units"] == 0
    assert all(
        "duplicate_hardware_identity" in row["reasons"] for row in refused["machines"]
    )


def test_preview_never_serializes_raw_chip_id_or_quote():
    config = _config()
    pseudonym = preview._hardware_pseudonym(config.review_challenge, CHIP_ID)
    observations = (
        _observation(
            config.targets[0].endpoint,
            machine_id=pseudonym,
            channel_id="a" * 64,
        ),
    )
    document = preview.build_preview_document(
        config,
        observations,
        compute_commit="c" * 40,
        snpguest_digest="d" * 64,
        snpguest_version="0.10.0",
    )
    encoded = json.dumps(document, sort_keys=True)
    assert CHIP_ID.hex() not in encoded
    assert "raw-quote-must-not-serialize" not in encoded
    assert "quote_hex" not in encoded
    assert "chip_id" not in encoded


def test_cli_output_is_owner_only_create_once(monkeypatch, tmp_path, capsys):
    config = _config()
    observation = _observation(
        config.targets[0].endpoint,
        machine_id="1" * 64,
        channel_id="a" * 64,
    )
    document = preview.build_preview_document(
        config,
        (observation,),
        compute_commit="c" * 40,
        snpguest_digest="d" * 64,
        snpguest_version="0.10.0",
    )
    monkeypatch.setattr(preview, "load_config", lambda _path: config)
    monkeypatch.setattr(preview, "collect_preview", lambda _config: document)
    tmp_path.chmod(0o700)
    output = tmp_path / "snp-preview.json"
    assert preview.main(["--config", "/config.json", "--output", str(output)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["authorized_for_chain_write"] is False
    assert report["weight_submitted"] is False
    assert report["burn"] == 0
    assert output.stat().st_mode & 0o777 == 0o600

    assert preview.main(["--config", "/config.json", "--output", str(output)]) == 2
    refusal = json.loads(capsys.readouterr().err)
    assert refusal["status"] == "REFUSED_DEVELOPMENT_NO_WRITE"


def test_preview_import_graph_loads_no_writer():
    forbidden = {
        "cathedral_thin.independent.canary",
        "cathedral_thin.independent.journal",
        "cathedral_thin.independent.submit",
        "cathedral_thin.independent_runtime.chain",
        "cathedral_thin.independent_runtime.run",
        "cathedral_thin.independent_runtime.workers",
        "cathedral_thin.uid30_fleet_submit",
        "cathedral_thin.uid30_launch",
        "scaffold.publisher",
        "scaffold.validator_thin",
    }
    script = (
        "import json,sys; "
        "import cathedral_thin.independent_runtime.amd_snp_dev_preview; "
        f"print(json.dumps(sorted(set(sys.modules) & {forbidden!r})))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout) == []


def test_packaging_keeps_the_compute_pin_exact():
    with (Path(__file__).parents[2] / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    expected = "8dde6eaca27116eed53386a1fa33ec70b74a01fb"
    assert preview.COMPUTE_CONTRACT_COMMIT == expected
    assert project["optional-dependencies"]["snp-dev"] == [
        "cathedral @ git+https://github.com/cathedralai/"
        f"cathedral-sandbox.git@{expected}"
    ]
    assert project["optional-dependencies"]["snp-production"] == [
        "cathedral @ git+https://github.com/cathedralai/"
        f"cathedral-sandbox.git@{expected}"
    ]
    assert (
        project["scripts"]["cathedral-amd-sev-snp-dev-preview"]
        == "cathedral_thin.independent_runtime.amd_snp_dev_preview:main"
    )


def _production_pex(path: Path, info: dict[str, object]) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        bundle.writestr("PEX-INFO", json.dumps(info))
    path.write_bytes(b"#!/usr/bin/python3.12\n" + output.getvalue())
    path.chmod(0o555)


def _production_pex_info() -> dict[str, object]:
    return {
        "entry_point": "cathedral_thin.independent_runtime.direct_validator:main",
        "inherit_path": "false",
        "pex_path": "",
        "pex_paths": [],
        "inject_env": {},
        "strip_pex_env": True,
        "distributions": {
            "bittensor-10.5.0-py3-none-any.whl": "1" * 64,
            "cathedral-0.0.0-py3-none-any.whl": "2" * 64,
            "cathedral_scaffold-1.2.3-py3-none-any.whl": "3" * 64,
            "cryptography-48.0.0-py3-none-any.whl": "4" * 64,
            "numpy-2.5.2-py3-none-any.whl": "5" * 64,
        },
        "requirements": [
            "cathedral-scaffold[snp-production]@file:///reviewed/validator.whl",
            "cathedral@git+https://github.com/cathedralai/"
            f"cathedral-sandbox.git@{preview.COMPUTE_CONTRACT_COMMIT}",
        ],
    }


def test_production_pex_provenance_requires_root_metadata_and_exact_contract(
    monkeypatch, tmp_path
):
    pex = tmp_path / "cathedral-validator.pex"
    _production_pex(pex, _production_pex_info())
    monkeypatch.setattr(preview, "PEX_METADATA_OWNER_UID", os.geteuid())
    monkeypatch.setattr(sys, "argv", [str(pex)])

    assert preview._running_pex_compute_provenance() == preview.COMPUTE_CONTRACT_COMMIT

    monkeypatch.setattr(preview, "PEX_METADATA_OWNER_UID", os.geteuid() + 1)
    with pytest.raises(preview.AmdSnpDevPreviewError, match="not root-controlled"):
        preview._running_pex_compute_provenance()


def test_production_pex_provenance_uses_runtime_pex_when_interpreting_a_script(
    monkeypatch, tmp_path
):
    pex = tmp_path / "cathedral-validator.pex"
    _production_pex(pex, _production_pex_info())
    script = tmp_path / "release-smoke.py"
    script.write_text("raise SystemExit('not executed')\n")
    monkeypatch.setattr(preview, "PEX_METADATA_OWNER_UID", os.geteuid())
    monkeypatch.setattr(sys, "argv", [str(script)])
    monkeypatch.setenv("PEX", str(pex))

    assert preview._running_pex_compute_provenance() == preview.COMPUTE_CONTRACT_COMMIT


def test_claimed_runtime_pex_fails_closed_when_it_is_not_a_pex(monkeypatch, tmp_path):
    script = tmp_path / "release-smoke.py"
    script.write_text("print('not a PEX')\n")
    monkeypatch.setenv("PEX", str(script))

    with pytest.raises(preview.AmdSnpDevPreviewError, match="metadata is invalid"):
        preview._running_pex_compute_provenance()


def test_production_pex_provenance_refuses_wrong_entrypoint_or_requirement(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(preview, "PEX_METADATA_OWNER_UID", os.geteuid())
    for index, mutation in enumerate(
        (
            lambda info: info.update(entry_point="other:main"),
            lambda info: info.update(requirements=[]),
            lambda info: info.update(distributions={"cathedral-0.0.0.whl": "0" * 64}),
        )
    ):
        info = _production_pex_info()
        mutation(info)
        pex = tmp_path / f"invalid-{index}.pex"
        _production_pex(pex, info)
        monkeypatch.setattr(sys, "argv", [str(pex)])
        with pytest.raises(preview.AmdSnpDevPreviewError, match="exact SNP provenance"):
            preview._running_pex_compute_provenance()


def test_compute_contract_provenance_refuses_placeholder_and_wrong_commit(monkeypatch):
    monkeypatch.setattr(preview, "COMPUTE_CONTRACT_COMMIT", "COMPUTE_CONTRACT_COMMIT")
    with pytest.raises(preview.AmdSnpDevPreviewError, match="has not been replaced"):
        preview._installed_compute_commit()

    expected = "a" * 40
    monkeypatch.setattr(preview, "COMPUTE_CONTRACT_COMMIT", expected)
    distribution = SimpleNamespace(
        read_text=lambda _name: json.dumps(
            {
                "url": "https://github.com/cathedralai/cathedral-sandbox.git",
                "vcs_info": {
                    "vcs": "git",
                    "requested_revision": expected,
                    "commit_id": "b" * 40,
                },
            }
        )
    )
    monkeypatch.setattr(
        preview.importlib.metadata, "distribution", lambda _name: distribution
    )
    with pytest.raises(preview.AmdSnpDevPreviewError, match="not the pinned contract"):
        preview._installed_compute_commit()

    distribution.read_text = lambda _name: json.dumps(
        {
            "url": "https://github.com/cathedralai/cathedral-sandbox.git",
            "vcs_info": {
                "vcs": "git",
                "requested_revision": expected,
                "commit_id": expected,
            },
        }
    )
    assert preview._installed_compute_commit() == expected

    distribution.read_text = lambda _name: json.dumps(
        {"url": "file:///tmp/editable-compute", "dir_info": {"editable": True}}
    )
    with pytest.raises(preview.AmdSnpDevPreviewError, match="no verifiable VCS"):
        preview._installed_compute_commit()


def test_loaded_compute_imports_must_match_distribution_record(monkeypatch, tmp_path):
    for name in tuple(sys.modules):
        if name == "cathedral" or name.startswith("cathedral."):
            monkeypatch.delitem(sys.modules, name)
    installed = tmp_path / "site-packages" / "cathedral" / "__init__.py"
    installed.parent.mkdir(parents=True)
    body = b"PINNED = True\n"
    installed.write_bytes(body)
    digest = (
        base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
    )

    class Entry:
        hash = SimpleNamespace(mode="sha256", value=digest)
        size = len(body)

        def __str__(self):
            return "cathedral/__init__.py"

    entry = Entry()
    distribution = SimpleNamespace(
        files=[entry],
        locate_file=lambda item: tmp_path / "site-packages" / str(item),
    )
    monkeypatch.setattr(preview, "_REQUIRED_COMPUTE_FILES", {"cathedral/__init__.py"})
    monkeypatch.setattr(
        preview.importlib.util,
        "find_spec",
        lambda _name: SimpleNamespace(origin=str(installed)),
    )
    recorded = preview._verify_compute_distribution_before_import(distribution)

    shadow = tmp_path / "shadow" / "cathedral" / "common.py"
    shadow.parent.mkdir(parents=True)
    shadow.write_bytes(body)
    monkeypatch.setitem(
        sys.modules,
        "cathedral.common",
        SimpleNamespace(__file__=str(shadow)),
    )
    with pytest.raises(preview.AmdSnpDevPreviewError, match="outside the pinned"):
        preview._verify_loaded_compute_imports(recorded)


def test_compute_distribution_refuses_a_preloaded_compute_module(monkeypatch):
    monkeypatch.setitem(sys.modules, "cathedral", SimpleNamespace())

    class UnreadableDistribution:
        @property
        def files(self):
            raise AssertionError("distribution data must not be read after preload")

    with pytest.raises(
        preview.AmdSnpDevPreviewError,
        match="Compute modules were loaded before provenance verification",
    ):
        preview._verify_compute_distribution_before_import(UnreadableDistribution())


def test_recorded_sha256_accepts_an_empty_source_module(tmp_path):
    source = tmp_path / "__init__.py"
    source.write_bytes(b"")

    digest, size = preview._recorded_sha256(
        source, maximum=preview.MAX_COMPUTE_MODULE_BYTES
    )

    assert digest == "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
    assert size == 0


def test_pythonpath_shadow_is_refused_before_top_level_code_executes(tmp_path):
    pinned = tmp_path / "pinned"
    shadow = tmp_path / "shadow"
    sentinel = tmp_path / "shadow-executed"
    expected = "a" * 40
    required = sorted(preview._REQUIRED_COMPUTE_FILES)
    record_rows: list[str] = []
    for relative in required:
        path = pinned / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        body = b"# reviewed pinned source\n"
        path.write_bytes(body)
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(body).digest())
            .rstrip(b"=")
            .decode()
        )
        record_rows.append(f"{relative},sha256={digest},{len(body)}")
    dist_info = pinned / "cathedral-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: cathedral\nVersion: 1.0\n",
        encoding="utf-8",
    )
    (dist_info / "direct_url.json").write_text(
        json.dumps(
            {
                "url": "https://github.com/cathedralai/cathedral-sandbox.git",
                "vcs_info": {
                    "vcs": "git",
                    "requested_revision": expected,
                    "commit_id": expected,
                },
            }
        ),
        encoding="utf-8",
    )
    (dist_info / "RECORD").write_text("\n".join(record_rows) + "\n", encoding="utf-8")

    shadow_package = shadow / "cathedral"
    shadow_package.mkdir(parents=True)
    (shadow_package / "__init__.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "Path(os.environ['CATHEDRAL_TEST_SENTINEL']).write_text('executed')\n",
        encoding="utf-8",
    )
    repository = Path(__file__).parents[2]
    script = (
        "from cathedral_thin.independent_runtime import amd_snp_dev_preview as p\n"
        f"p.COMPUTE_CONTRACT_COMMIT = {expected!r}\n"
        "try:\n"
        "    p.load_compute_contract()\n"
        "except p.AmdSnpDevPreviewError:\n"
        "    pass\n"
        "else:\n"
        "    raise SystemExit('shadow was not refused')\n"
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(shadow), str(pinned), str(repository)]
    )
    environment["CATHEDRAL_TEST_SENTINEL"] = str(sentinel)
    subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert not sentinel.exists()
