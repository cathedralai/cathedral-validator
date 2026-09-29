"""Local public-config tests; no wallet, quote verifier, service, or chain."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from cathedral_thin.independent_runtime import direct_validator, service_config
from cathedral_thin.independent_runtime.delivery_plan import DeliveryPlanError
from cathedral_thin.independent_runtime.qvl import DIRECT_VALIDATOR_QVL_DIGEST


def _write(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def inputs(tmp_path, monkeypatch):
    monkeypatch.setattr(service_config, "OWNER_UID", os.getuid())
    policy = _write(
        tmp_path / "policy.json",
        {
            "schema": "cathedral_sn94_delivery_policy_v1",
            "netuid": 94,
            "mode": "write",
            "window_seconds": 3600,
            "burn_bps": 1000,
            "burn_uid": 0,
            "burn_hotkey": "burn",
            "allowed_measurements": ["tdx-measurement-sha256:" + "33" * 32],
            "verifier_path": service_config.VERIFIER_PATH,
            "verifier_sha256": DIRECT_VALIDATOR_QVL_DIGEST,
            "control_plane_keys": {"authority": "11" * 32},
        },
    )
    bundle = _write(
        tmp_path / "bundle.json",
        {
            "window_start": (int(time.time()) // 3600 - 1) * 3600,
            "uid_hotkeys": [[0, "burn"]],
            "entries": [],
        },
    )
    ledger = tmp_path / "ledger.sqlite3"
    config = _write(
        tmp_path / "service.json",
        {
            "schema": service_config.SCHEMA,
            "mechanism": "sn94_delivery_v1",
            "policy_path": str(policy),
            "policy_sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
            "bundle_path": str(bundle),
            "ledger_path": str(ledger),
        },
    )
    return config, policy, bundle, ledger


def test_check_validates_without_creating_or_opening_a_ledger(tmp_path, monkeypatch):
    config, _policy, _bundle, ledger = inputs(tmp_path, monkeypatch)
    assert service_config.check(config)["mechanism"] == "sn94_delivery_v1"
    assert not ledger.exists()


@pytest.mark.parametrize(
    "fault",
    [
        "missing_feed",
        "symlink_feed",
        "writable_config",
        "changed_policy",
        "bad_pin",
        "future_window",
        "symlink_ledger",
        "duplicate_config",
    ],
)
def test_refusal_cases(tmp_path, monkeypatch, fault):
    config, policy, bundle, ledger = inputs(tmp_path, monkeypatch)
    if fault == "missing_feed":
        bundle.unlink()
    elif fault == "symlink_feed":
        target = bundle.with_suffix(".saved")
        bundle.rename(target)
        bundle.symlink_to(target)
    elif fault == "writable_config":
        config.chmod(0o666)
    elif fault == "changed_policy":
        policy.write_text(policy.read_text() + " ")
    elif fault == "bad_pin":
        value = json.loads(policy.read_text())
        value["verifier_sha256"] = "aa" * 32
        _write(policy, value)
        value = json.loads(config.read_text())
        value["policy_sha256"] = hashlib.sha256(policy.read_bytes()).hexdigest()
        _write(config, value)
    elif fault == "future_window":
        value = json.loads(bundle.read_text())
        value["window_start"] = (int(time.time()) // 3600 + 1) * 3600
        _write(bundle, value)
    elif fault == "symlink_ledger":
        ledger.symlink_to(tmp_path / "absent")
    else:
        config.write_text('{"schema":"one","schema":"two"}')
    with pytest.raises((DeliveryPlanError, OSError)):
        service_config.check(config)
    assert not ledger.exists()


def test_sat_schema_is_separate_and_cannot_smuggle_delivery(tmp_path, monkeypatch):
    config, *_ = inputs(tmp_path, monkeypatch)
    _write(config, {"schema": service_config.SCHEMA, "mechanism": "sat"})
    assert service_config.check(config)["mechanism"] == "sat"
    _write(
        config,
        {"schema": service_config.SCHEMA, "mechanism": "sat", "policy_path": "/tmp/p"},
    )
    with pytest.raises(DeliveryPlanError):
        service_config.check(config)


def test_actual_cli_dispatch_refuses_missing_feed_without_wallet(
    tmp_path, monkeypatch, capsys
):
    config, _policy, bundle, _ledger = inputs(tmp_path, monkeypatch)
    bundle.unlink()
    monkeypatch.setattr(
        direct_validator, "make_wallet", lambda *_a, **_k: pytest.fail("wallet opened")
    )
    assert direct_validator.main(["service-config-check", "--config", str(config)]) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "service_config_refused"


def test_service_unit_checks_before_wallet_copy_and_passes_same_configuration():
    unit = (
        Path(__file__).parents[2]
        / "deploy/validator-update/cathedral-validator-direct.service"
    ).read_text()
    assert unit.index("service-config-check") < unit.index(
        "ExecStartPre=/usr/bin/install"
    )
    assert "--config=/etc/cathedral-validator/service-config.json" in unit
    assert "--service-config=/etc/cathedral-validator/service-config.json" in unit


def test_direct_entrypoint_rechecks_config_before_wallet(tmp_path, monkeypatch):
    config, _policy, bundle, _ledger = inputs(tmp_path, monkeypatch)
    bundle.unlink()
    monkeypatch.setattr(direct_validator, "_expected_hotkey", lambda value: value)
    monkeypatch.setattr(
        direct_validator, "make_wallet", lambda *_a, **_k: pytest.fail("wallet opened")
    )
    with pytest.raises(SystemExit, match="configuration refused before wallet"):
        direct_validator.main(
            [
                "--qvl",
                service_config.VERIFIER_PATH,
                "--snp-policy",
                "/nonexistent/snp-policy",
                "--snpguest",
                "/nonexistent/snpguest",
                "--confirm-direct-write",
                "--netuid",
                "94",
                "--expected-hotkey",
                "synthetic",
                "--service-config",
                str(config),
            ]
        )


def test_direct_entrypoint_uses_exact_service_delivery_paths(tmp_path, monkeypatch):
    from cathedral_thin.independent_runtime import delivery_runtime

    config, policy, bundle, ledger = inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(direct_validator, "_expected_hotkey", lambda value: value)
    monkeypatch.setattr(
        direct_validator, "make_wallet", lambda *_a, **_k: pytest.fail("wallet opened")
    )
    original = delivery_runtime.DeliveryContext
    observed = []

    def context(**kwargs):
        observed.append(kwargs)
        return original(**kwargs)

    def no_verifier_start(*_a, **_k):
        raise RuntimeError("reached verifier startup before wallet")

    monkeypatch.setattr(delivery_runtime, "DeliveryContext", context)
    monkeypatch.setattr(
        direct_validator, "load_direct_validator_verifier", no_verifier_start
    )
    with pytest.raises(RuntimeError, match="before wallet"):
        direct_validator.main(
            [
                "--qvl",
                service_config.VERIFIER_PATH,
                "--snp-policy",
                "/nonexistent/snp-policy",
                "--snpguest",
                "/nonexistent/snpguest",
                "--confirm-direct-write",
                "--netuid",
                "94",
                "--expected-hotkey",
                "synthetic",
                "--service-config",
                str(config),
            ]
        )
    assert observed == [
        {"policy_path": policy, "bundle_path": bundle, "ledger_path": ledger}
    ]
    assert not ledger.exists()
