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
    bundle_path = _write(tmp_path, _bundle(fx, allocations, receipts))
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
    bundle_path = _write(tmp_path, _bundle(fx, allocations, receipts))
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
