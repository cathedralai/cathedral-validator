"""The default-OFF Compute+Distill integration lane (issue #1).

Proves the validator can independently verify one Compute CPU receipt, one Compute
GPU receipt, and one Distill receipt against a Cathedral-signed burn + allocation
config, compose one deterministic audited vector, and stream PASS / FAIL /
NOT_PROVEN through its own event pipeline — all non-writing. Skipped unless the
'.[integration]' extra (cathedral-distill) is installed.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest

# Skip unless the integration extra ships the shared contract modules (so this
# skips cleanly against an older cathedral-distill, rather than erroring).
_NEEDS_CONTRACT = (
    "needs the shared cathedral-distill contract: pip install -e '.[integration]'. "
    "Without it this module is skipped whole, and the nine modules that do so "
    "together drop ~168 thin tests without failing anything."
)

pytest.importorskip("cathedral_distill.integrated_feed", reason=_NEEDS_CONTRACT)
pytest.importorskip("cathedral_distill.testing", reason=_NEEDS_CONTRACT)

from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402

from cathedral_thin import integration as ig  # noqa: E402
from scaffold.events import EventLogger  # noqa: E402

NOW_DT = datetime(2026, 7, 25, 12, 30, tzinfo=UTC)
NOW_ISO = "2026-07-25T12:30:00.000000Z"

LANE_CPU = "cathedral_confidential_tdx"
LANE_GPU = "cathedral_confidential_gpu"
LANE_DISTILL = "cathedral_distill"

_ALLOCATIONS = [
    {"lane": LANE_CPU, "allocation": "0.30", "enabled": True},
    {"lane": LANE_GPU, "allocation": "0.20", "enabled": True},
    {"lane": LANE_DISTILL, "allocation": "0.40", "enabled": True},
]


def _logger():
    buf = io.StringIO()
    # tty is an explicit non-terminal so nothing writes to stdout in tests
    return EventLogger(mode="shadow", jsonl=buf, tty=io.StringIO()), buf


def _events(buf):
    return [json.loads(line) for line in buf.getvalue().splitlines()]


def _receipts(fx, *, gpu_bound=None, distill=None):
    return [
        ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, fx.cpu_receipt()),
        ig.LaneReceipt(
            itf.KIND_COMPUTE_GPU,
            LANE_GPU,
            fx.gpu_receipt(bound=gpu_bound) if gpu_bound else fx.gpu_receipt(),
        ),
        ig.LaneReceipt(itf.KIND_DISTILL, LANE_DISTILL, distill or fx.distill_receipt()),
    ]


def _preview(fx, receipts, **kw):
    # These cases exercise the composition and event vocabulary, not the launch
    # policy, so they take the documented opt-out. A funded lane refuses without
    # it: see tests/thin/test_integration_policy_gate.py.
    kw.setdefault("allow_unpoliced_preview", True)
    return ig.preview_integrated_vector(
        burn_config=fx.burn_config(),
        allocation_config=fx.allocation_config(_ALLOCATIONS),
        key_registry=fx.registry,
        receipts=receipts,
        network="finney",
        netuid=39,
        source_epoch=11,
        now=NOW_DT,
        now_iso=NOW_ISO,
        **kw,
    )


def test_cpu_gpu_distill_preview_through_the_event_pipeline():
    fx = IntegrationFixtures()
    events, buf = _logger()
    out = _preview(
        fx, _receipts(fx), gpu_attestation_verifier=lambda _g: True, events=events
    )

    feed, audit = out["feed"], out["audit"]
    assert {w["miner_hotkey"] for w in feed["weights"]} == {
        "5CpuMiner",
        "5GpuMiner",
        "5DistillMiner",
    }
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(10.0)
    assert audit["verdicts"] == {"pass": 3, "fail": 0, "not_proven": 0}

    codes = [e["event"] for e in _events(buf)]
    assert "INTEGRATION_CONFIG" in codes
    assert codes.count("INTEGRATION_RECEIPT") == 3
    assert "INTEGRATION_VECTOR" in codes
    # every emitted event carries the validator's mode + a valid status
    assert all(
        e["status"] in ("PASS", "FAIL", "NOT_PROVEN", "INFO") for e in _events(buf)
    )
    assert all(e["mode"] == "shadow" for e in _events(buf))


def test_gpu_without_verifier_is_not_proven_and_burns_its_share():
    fx = IntegrationFixtures()
    events, buf = _logger()
    out = _preview(fx, _receipts(fx), events=events)  # no GPU verifier

    feed = out["feed"]
    assert "5GpuMiner" not in {w["miner_hotkey"] for w in feed["weights"]}
    assert feed["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(
        30.0
    )  # 0.10 + 0.20
    receipt_events = {
        e["kind"]: e for e in _events(buf) if e["event"] == "INTEGRATION_RECEIPT"
    }
    assert receipt_events["compute_gpu"]["status"] == "NOT_PROVEN"


def test_tampered_distill_fails_and_burns_its_lane():
    fx = IntegrationFixtures()
    tampered = fx.distill_receipt()
    tampered["work"]["work_units"] = "999"
    events, buf = _logger()
    out = _preview(
        fx,
        _receipts(fx, distill=tampered),
        gpu_attestation_verifier=lambda _g: True,
        events=events,
    )
    assert "5DistillMiner" not in {w["miner_hotkey"] for w in out["feed"]["weights"]}
    receipt_events = {
        e["kind"]: e for e in _events(buf) if e["event"] == "INTEGRATION_RECEIPT"
    }
    assert receipt_events["distill"]["status"] == "FAIL"


def test_rolled_back_burn_config_is_refused_with_a_fail_event():
    fx = IntegrationFixtures()
    events, buf = _logger()
    with pytest.raises(ig.IntegrationError, match="signed config rejected"):
        ig.preview_integrated_vector(
            burn_config=fx.burn_config(version=3),
            allocation_config=fx.allocation_config(_ALLOCATIONS),
            key_registry=fx.registry,
            receipts=_receipts(fx),
            network="finney",
            netuid=39,
            source_epoch=11,
            now=NOW_DT,
            now_iso=NOW_ISO,
            min_burn_version=5,
            allow_unpoliced_preview=True,
            events=events,
        )  # applied fence is 5; v3 is a rollback
    config_events = [e for e in _events(buf) if e["event"] == "INTEGRATION_CONFIG"]
    assert config_events and config_events[-1]["status"] == "FAIL"


def test_preview_never_reports_a_chain_write():
    fx = IntegrationFixtures()
    events, buf = _logger()
    _preview(fx, _receipts(fx), gpu_attestation_verifier=lambda _g: True, events=events)
    # no WEIGHTS/CHAIN stage is ever emitted by the preview path
    assert all(e["stage"] == "INTEGRATION" for e in _events(buf))
    vector = next(e for e in _events(buf) if e["event"] == "INTEGRATION_VECTOR")
    assert "preview only" in vector["detail"]
