"""A funded reward lane must refuse to preview without the launch policy.

The seam used to accept `current_block=None`, `consumption_ledger=None` and
`allowed_*=None` and simply not apply those gates; the CLI printed a warning and
carried on. A warning is not a gate: the resulting preview says PASS for a
receipt that no launch policy ever admitted, which is exactly the evidence an
activation decision would rest on.

So: omission is refused for any lane with a nonzero allocation, unless the
operator opts out in as many words. An EMPTY allow-list is not an omission, it is
a deliberate deny-everything policy, and the two must stay distinguishable.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest

pytest.importorskip("cathedral_distill.integrated_feed")
pytest.importorskip("cathedral_distill.testing")

from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill.consumption_ledger import ConsumptionLedger  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402

from cathedral_thin import integration as ig  # noqa: E402
from scaffold.events import EventLogger  # noqa: E402

NOW_DT = datetime(2026, 7, 25, 12, 30, tzinfo=UTC)
NOW_ISO = "2026-07-25T12:30:00.000000Z"
LANE_CPU = "cathedral_confidential_tdx"


def _logger():
    buf = io.StringIO()
    return EventLogger(mode="shadow", jsonl=buf, tty=io.StringIO()), buf


def _events(buf):
    return [json.loads(line) for line in buf.getvalue().splitlines()]


def _policy(fx, **over):
    gates = {
        "allowed_measurements": frozenset({fx.tdx_measurement}),
        "allowed_tcb_statuses": frozenset({"UpToDate"}),
        "allowed_advisories": frozenset(),
        "current_block": 6_000_100,
        "consumption_ledger": ConsumptionLedger(":memory:"),
    }
    gates.update(over)
    return gates


def _preview(fx, *, allocation="0.90", burn="0.10", receipts=None, **kw):
    return ig.preview_integrated_vector(
        burn_config=fx.burn_config(fraction=burn),
        allocation_config=fx.allocation_config(
            [{"lane": LANE_CPU, "allocation": allocation, "enabled": True}]
        ),
        key_registry=fx.registry,
        receipts=receipts
        if receipts is not None
        else [ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, fx.cpu_receipt())],
        network="finney",
        netuid=39,
        source_epoch=11,
        now=NOW_DT,
        now_iso=NOW_ISO,
        **kw,
    )


def test_funded_lane_refuses_every_omitted_gate():
    fx = IntegrationFixtures()
    events, buf = _logger()
    with pytest.raises(ig.IntegrationPolicyError) as excinfo:
        _preview(fx, events=events)
    message = str(excinfo.value)
    for gate in ig.REQUIRED_REWARD_GATES:
        assert gate in message
    assert LANE_CPU in message
    policy_events = [e for e in _events(buf) if e["event"] == "INTEGRATION_POLICY"]
    assert policy_events and policy_events[-1]["status"] == "FAIL"
    # the refusal happens before any receipt is verified
    assert not [e for e in _events(buf) if e["event"] == "INTEGRATION_RECEIPT"]


@pytest.mark.parametrize("omit", ig.REQUIRED_REWARD_GATES)
def test_each_single_omission_refuses_on_its_own(omit):
    fx = IntegrationFixtures()
    gates = _policy(fx)
    gates[omit] = None
    with pytest.raises(ig.IntegrationPolicyError, match=omit):
        _preview(fx, **gates)


def test_a_policy_error_is_an_integration_error():
    """Callers that already handle IntegrationError keep failing closed."""
    assert issubclass(ig.IntegrationPolicyError, ig.IntegrationError)


def test_the_documented_opt_out_keeps_a_shadow_preview_usable():
    fx = IntegrationFixtures()
    events, buf = _logger()
    out = _preview(fx, allow_unpoliced_preview=True, events=events)
    assert out["audit"]["verdicts"]["pass"] == 1
    assert out["gates"]["unpoliced_preview"] is True
    assert set(out["gates"]["omitted_gates"]) == set(ig.REQUIRED_REWARD_GATES)
    policy = next(e for e in _events(buf) if e["event"] == "INTEGRATION_POLICY")
    assert policy["status"] == "NOT_PROVEN"


def test_fully_policed_preview_records_every_gate_as_applied():
    fx = IntegrationFixtures()
    events, buf = _logger()
    out = _preview(fx, events=events, **_policy(fx))
    assert out["audit"]["verdicts"]["pass"] == 1
    assert out["gates"]["omitted_gates"] == []
    assert out["gates"]["reward_lanes"] == [LANE_CPU]
    lane = out["gates"]["lanes"][LANE_CPU]
    assert lane["reward_lane"] is True
    assert lane["measurement_policy"] and lane["tcb_policy"] and lane["advisory_policy"]
    assert lane["block_window"] and lane["consumption_ledger"]
    policy = next(e for e in _events(buf) if e["event"] == "INTEGRATION_POLICY")
    assert policy["status"] == "PASS"


def test_an_empty_allow_list_is_a_policy_and_is_enforced():
    """`frozenset()` satisfies the gate and denies everything. `None` does not."""
    fx = IntegrationFixtures()
    out = _preview(fx, **_policy(fx, allowed_measurements=frozenset()))
    assert out["gates"]["omitted_gates"] == []  # expressed, not omitted
    (receipt,) = out["audit"]["receipts"]
    assert receipt["verdict"] == itf.FAIL
    assert "measurement is not admitted by policy" in receipt["detail"]
    assert out["feed"]["weights"] == []  # the lane's whole share burns


def test_an_unfunded_lane_needs_no_policy():
    """The gate is about reward. A zero-allocation lane cannot pay anyone."""
    fx = IntegrationFixtures()
    out = _preview(fx, allocation="0.00", burn="1.00")
    assert out["gates"]["reward_lanes"] == []
    assert out["gates"]["lanes"][LANE_CPU]["reward_lane"] is False
    assert out["feed"]["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(
        100.0
    )
