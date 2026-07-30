"""The non-writing `cathedral-validator-integration-preview` CLI.

Builds a preview bundle (signed config + CPU/Distill receipts anchored to a
hardware-free key registry) and proves the CLI verifies it, composes the feed, and
prints the audit — without any chain write. Skipped unless the '.[integration]'
extra (cathedral-distill) is installed.
"""

from __future__ import annotations

import base64
import json

import pytest

pytest.importorskip("cathedral_distill.integrated_feed")
pytest.importorskip("cathedral_distill.testing")

from cathedral_distill.testing import IntegrationFixtures  # noqa: E402

from cathedral_thin import integration_cli as cli  # noqa: E402

LANE_CPU = "cathedral_confidential_tdx"
LANE_DISTILL = "cathedral_distill"
LANE_GPU = "cathedral_confidential_gpu"
LANE_CYBERGYM = "cathedral_cybergym"


def _policy(fx, tmp_path):
    """Every gate a funded lane requires, expressed in bundle form."""
    return {
        "allowed_measurements": [fx.tdx_measurement, fx.sev_measurement],
        "allowed_tcb_statuses": ["UpToDate"],
        # an explicit empty list: no advisory is tolerated. This is a policy, not
        # an omission, and the CLI must treat the two differently.
        "allowed_advisories": [],
        "current_block": 6_000_100,
        "ledger_path": str(tmp_path / "consumption.sqlite"),
    }


def _bundle(fx, allocations, receipts, **over):
    pub = base64.b64encode(fx.key.public_key().public_bytes_raw()).decode()
    bundle = {
        "network": "finney",
        "netuid": 39,
        "source_epoch": 11,
        "now": "2026-07-25T12:30:00Z",
        "now_iso": "2026-07-25T12:30:00.000000Z",
        "burn_config": json.loads(fx.burn_config().decode()),
        "allocation_config": json.loads(fx.allocation_config(allocations).decode()),
        "keys": {"compute-1": pub, "distill-1": pub, "config-1": pub},
        "receipts": receipts,
    }
    bundle.update(over)
    return bundle


def _write(tmp_path, bundle):
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(bundle))
    return str(p)


def test_preview_cli_composes_cpu_and_distill(tmp_path):
    fx = IntegrationFixtures()
    allocations = [
        {"lane": LANE_CPU, "allocation": "0.45", "enabled": True},
        {"lane": LANE_DISTILL, "allocation": "0.45", "enabled": True},
    ]
    receipts = [
        {"kind": "compute_cpu", "lane": LANE_CPU, "receipt": fx.cpu_receipt()},
        {"kind": "distill", "lane": LANE_DISTILL, "receipt": fx.distill_receipt()},
    ]
    bundle_path = _write(
        tmp_path, _bundle(fx, allocations, receipts, **_policy(fx, tmp_path))
    )
    out = tmp_path / "out.json"

    assert cli.main(["--bundle", bundle_path, "--out", str(out)]) == 0
    result = json.loads(out.read_text())
    feed, audit = result["feed"], result["audit"]
    assert {w["miner_hotkey"] for w in feed["weights"]} == {
        "5CpuMiner",
        "5DistillMiner",
    }
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(10.0)
    assert audit["verdicts"] == {"pass": 2, "fail": 0, "not_proven": 0}
    assert audit["schema"] == "cathedral_integration_audit_v1"
    # per-lane gate visibility: the operator sees which gates actually ran
    assert result["gates"]["omitted_gates"] == []
    assert result["gates"]["replay_mode"] == "inspection"
    for lane in (LANE_CPU, LANE_DISTILL):
        row = result["gates"]["lanes"][lane]
        assert row["reward_lane"] and row["measurement_policy"]
        assert row["consumption_ledger"]
        # the block window was configured but neither kind in these lanes reads it
        assert row["supplied"]["block_window"] is True
        assert row["block_window"] is False


def test_preview_cli_reports_gpu_not_proven_without_a_verifier(tmp_path):
    fx = IntegrationFixtures()
    allocations = [
        {"lane": LANE_CPU, "allocation": "0.45", "enabled": True},
        {"lane": LANE_GPU, "allocation": "0.45", "enabled": True},
    ]
    receipts = [
        {"kind": "compute_cpu", "lane": LANE_CPU, "receipt": fx.cpu_receipt()},
        {"kind": "compute_gpu", "lane": LANE_GPU, "receipt": fx.gpu_receipt()},
    ]
    bundle_path = _write(
        tmp_path, _bundle(fx, allocations, receipts, **_policy(fx, tmp_path))
    )
    out = tmp_path / "out.json"
    assert cli.main(["--bundle", bundle_path, "--out", str(out)]) == 0
    audit = json.loads(out.read_text())["audit"]
    # a CLI carries no live GPU verifier -> the GPU lane is NOT_PROVEN, its share burns
    assert audit["verdicts"]["not_proven"] == 1
    gpu = next(r for r in audit["receipts"] if r["kind"] == "compute_gpu")
    assert gpu["verdict"] == "NOT_PROVEN"


def test_preview_cli_rejects_a_rolled_back_config(tmp_path):
    fx = IntegrationFixtures()
    allocations = [
        {"lane": LANE_CPU, "allocation": "0.45", "enabled": True},
        {"lane": LANE_DISTILL, "allocation": "0.45", "enabled": True},
    ]
    receipts = [{"kind": "compute_cpu", "lane": LANE_CPU, "receipt": fx.cpu_receipt()}]
    bundle = _bundle(
        fx, allocations, receipts, min_burn_version=5
    )  # config is v1 < fence 5
    bundle_path = _write(tmp_path, bundle)
    assert cli.main(["--bundle", bundle_path]) == 2  # fails closed


def test_preview_cli_missing_field_fails_closed(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"network": "finney"}))
    assert cli.main(["--bundle", str(p)]) == 2


def _funded_cpu_bundle(fx, tmp_path, **over):
    allocations = [{"lane": LANE_CPU, "allocation": "0.90", "enabled": True}]
    receipts = [{"kind": "compute_cpu", "lane": LANE_CPU, "receipt": fx.cpu_receipt()}]
    return _bundle(fx, allocations, receipts, **over)


def test_preview_cli_refuses_a_funded_lane_without_policy(tmp_path, capsys):
    """A warning is not a gate: an unpoliced funded lane must fail closed."""
    fx = IntegrationFixtures()
    path = _write(tmp_path, _funded_cpu_bundle(fx, tmp_path))
    assert cli.main(["--bundle", path]) == 2
    err = capsys.readouterr().err
    assert "allowed_measurements" in err and "current_block" in err
    assert "allow_unpoliced_preview" in err or "allow-unpoliced-preview" in err


def test_preview_cli_unpoliced_opt_out_is_explicit_and_reported(tmp_path, capsys):
    fx = IntegrationFixtures()
    path = _write(tmp_path, _funded_cpu_bundle(fx, tmp_path))
    out = tmp_path / "out.json"
    assert (
        cli.main(["--bundle", path, "--out", str(out), "--allow-unpoliced-preview"])
        == 0
    )
    err = capsys.readouterr().err
    assert "UNPOLICED" in err
    gates = json.loads(out.read_text())["gates"]
    assert gates["unpoliced_preview"] is True
    assert set(gates["omitted_gates"]) == {
        "allowed_measurements",
        "allowed_tcb_statuses",
        "allowed_advisories",
        "current_block",
        "consumption_ledger",
    }


def test_preview_cli_empty_measurement_list_is_a_policy_not_an_omission(tmp_path):
    """An empty measurement list satisfies the gate and admits nothing."""
    fx = IntegrationFixtures()
    policy = _policy(fx, tmp_path)
    policy["allowed_measurements"] = []
    path = _write(tmp_path, _funded_cpu_bundle(fx, tmp_path, **policy))
    out = tmp_path / "out.json"
    assert cli.main(["--bundle", path, "--out", str(out)]) == 0  # gate satisfied
    result = json.loads(out.read_text())
    assert result["gates"]["omitted_gates"] == []
    # and enforced: nothing is admitted under an empty measurement allow-list
    (receipt,) = result["audit"]["receipts"]
    assert receipt["verdict"] == "FAIL"
    assert "measurement" in receipt["detail"]


def test_preview_cli_empty_advisory_list_still_admits_an_advisory_free_receipt(
    tmp_path,
):
    """The reference launch policy has an EMPTY advisory list and still credits."""
    fx = IntegrationFixtures()
    policy = _policy(fx, tmp_path)
    assert policy["allowed_advisories"] == []
    path = _write(tmp_path, _funded_cpu_bundle(fx, tmp_path, **policy))
    out = tmp_path / "out.json"
    assert cli.main(["--bundle", path, "--out", str(out)]) == 0
    (receipt,) = json.loads(out.read_text())["audit"]["receipts"]
    assert receipt["verdict"] == "PASS"


@pytest.mark.parametrize("value", ["false", "0", 1, {"unpoliced": True}])
def test_run_bundle_refuses_a_non_boolean_opt_out(tmp_path, value):
    """`bool("false")` is True, so the opt-out is never read as a truthy value."""
    fx = IntegrationFixtures()
    bundle = _funded_cpu_bundle(fx, tmp_path)
    with pytest.raises(cli.PreviewError, match="must be the boolean"):
        cli.run_bundle(bundle, allow_unpoliced_preview=value)


def test_preview_cli_rejects_an_unknown_receipt_kind(tmp_path):
    fx = IntegrationFixtures()
    receipts = [{"kind": "sat_solve", "lane": LANE_CPU, "receipt": fx.cpu_receipt()}]
    allocations = [{"lane": LANE_CPU, "allocation": "0.90", "enabled": True}]
    path = _write(
        tmp_path,
        _bundle(fx, allocations, receipts, **_policy(fx, tmp_path)),
    )
    assert cli.main(["--bundle", path]) == 2


def test_lanes_flag_prints_the_versioned_lane_surface(capsys):
    # `--lanes` documents every lane in one place without needing a bundle, so an
    # operator (or a miner) can read the whole configuration surface at once.
    rc = cli.main(["--lanes"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["schema"] == "cathedral_validator_lane_contract_v1"
    kinds = {lane["kind"]: lane for lane in out["lanes"]}
    assert set(kinds) == {"compute_cpu", "compute_gpu", "distill", "cybergym"}
    assert kinds["cybergym"]["lane_id"] == LANE_CYBERGYM
    # the per-kind gates match what the contract actually reads
    assert kinds["cybergym"]["reward_gates_read"] == [
        "block_window",
        "consumption_ledger",
    ]
    # a lane that cannot PASS burns its share; it is never renormalized
    assert "burn" in out["unproven_lane_behavior"]


def test_bundle_is_required_without_lanes(capsys):
    rc = cli.main([])
    assert rc == 2
    assert "--bundle is required" in capsys.readouterr().err
