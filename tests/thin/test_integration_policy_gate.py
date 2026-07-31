"""A funded reward lane must refuse to preview without the launch policy.

The seam used to accept `current_block=None`, `consumption_ledger=None` and
`allowed_*=None` and simply not apply those gates; the CLI printed a warning and
carried on. A warning is not a gate: the resulting preview says PASS for a
receipt that no launch policy ever admitted, which is exactly the evidence an
activation decision would rest on.

So: omission is refused for any lane with a nonzero allocation, unless the
operator opts out in as many words, as the boolean True and nothing else.

An EMPTY allow-list is not an omission, it is a policy, and what that policy
admits is per list: empty measurements or empty TCB statuses admit nothing (every
receipt carries exactly one of each), while an empty advisory list admits only
receipts that carry no advisory, because the advisory check is a subset test.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest

_NEEDS_CONTRACT = (
    "needs the shared cathedral-distill contract: pip install -e '.[integration]'. "
    "Without it this module is skipped whole, and the nine modules that do so "
    "together drop ~168 thin tests without failing anything."
)

pytest.importorskip("cathedral_distill.integrated_feed", reason=_NEEDS_CONTRACT)
pytest.importorskip("cathedral_distill.testing", reason=_NEEDS_CONTRACT)

from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402
from _durable_ledger import durable_ledger  # noqa: E402

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


def _receipt_with_advisory(fx, advisory: str):
    """A real signed CPU receipt whose TCB reports one advisory."""
    from cathedral_distill import compute_receipt as cr

    body = fx._compute_body(
        "5CpuMiner",
        "30",
        {"class": cr.PLATFORM_CPU, "cpu_tee": cr.CPU_TEE_TDX},
        cr.CPU_TEE_TDX,
    )
    body["tcb"]["advisory_ids"] = [advisory]
    return cr.build_receipt(body, fx.key, signing_key_id="compute-1")


def _policy(fx, **over):
    gates = {
        "allowed_measurements": frozenset({fx.tdx_measurement}),
        "allowed_tcb_statuses": frozenset({"UpToDate"}),
        "allowed_advisories": frozenset(),
        "current_block": 6_000_100,
        "consumption_ledger": durable_ledger(),
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


def test_fully_policed_preview_reports_the_gates_its_receipts_actually_read():
    """Supplied is not applied.

    A compute receipt carries no block window, so `current_block` gates nothing for
    it. Reporting block_window=yes for a lane of compute receipts overstated the
    assurance in the one document an activation decision reads, and a
    `current_block=0` typo looked like an applied gate.
    """
    fx = IntegrationFixtures()
    events, buf = _logger()
    out = _preview(fx, events=events, **_policy(fx))
    assert out["audit"]["verdicts"]["pass"] == 1
    assert out["gates"]["omitted_gates"] == []
    assert out["gates"]["reward_lanes"] == [LANE_CPU]
    # everything the operator configured
    assert all(out["gates"]["supplied"].values())
    lane = out["gates"]["lanes"][LANE_CPU]
    assert lane["reward_lane"] is True
    assert lane["measurement_policy"] and lane["tcb_policy"] and lane["advisory_policy"]
    assert lane["consumption_ledger"]
    # ... and the honest part: the block window was supplied but never read here
    assert lane["block_window"] is False
    assert lane["supplied"]["block_window"] is True
    assert lane["kinds"] == {
        itf.KIND_COMPUTE_CPU: {
            "measurement_policy": True,
            "tcb_policy": True,
            "advisory_policy": True,
            "block_window": False,
            "consumption_ledger": True,
        }
    }
    policy = next(e for e in _events(buf) if e["event"] == "INTEGRATION_POLICY")
    assert policy["status"] == "PASS"


def test_a_lane_with_no_receipts_reports_no_gates_applied():
    fx = IntegrationFixtures()
    out = _preview(fx, receipts=[], **_policy(fx))
    lane = out["gates"]["lanes"][LANE_CPU]
    assert lane["kinds"] == {}
    assert not any(lane[name] for name in ig._GATE_NAMES)
    assert all(lane["supplied"].values())


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("false", id="string-false"),
        pytest.param("0", id="string-zero"),
        pytest.param("", id="empty-string"),
        pytest.param(1, id="int-one"),
        pytest.param(0, id="int-zero"),
        pytest.param({"unpoliced": True}, id="object"),
        pytest.param(None, id="none"),
    ],
)
def test_the_opt_out_refuses_anything_that_is_not_a_boolean(value):
    """Truthiness is not authorization.

    Every non-empty string is truthy, so `allow_unpoliced_preview="false"` used to
    produce a funded PASS preview with all five gates omitted: the exact opposite
    of what the value says. A value that is not literally True or False is refused
    rather than interpreted.
    """
    fx = IntegrationFixtures()
    with pytest.raises(ig.IntegrationPolicyError, match="must be the boolean"):
        _preview(fx, allow_unpoliced_preview=value)


def test_the_opt_out_still_accepts_the_two_real_booleans():
    fx = IntegrationFixtures()
    assert _preview(fx, allow_unpoliced_preview=True)["gates"]["unpoliced_preview"]
    with pytest.raises(ig.IntegrationPolicyError, match="previewed without"):
        _preview(fx, allow_unpoliced_preview=False)


def test_an_empty_measurement_allow_list_admits_nothing():
    """Every receipt carries exactly one measurement, so empty denies all of them."""
    fx = IntegrationFixtures()
    out = _preview(fx, **_policy(fx, allowed_measurements=frozenset()))
    assert out["gates"]["omitted_gates"] == []  # expressed, not omitted
    (receipt,) = out["audit"]["receipts"]
    assert receipt["verdict"] == itf.FAIL
    assert "measurement is not admitted by policy" in receipt["detail"]
    assert out["feed"]["weights"] == []  # the lane's whole share burns


def test_an_empty_tcb_status_allow_list_admits_nothing():
    fx = IntegrationFixtures()
    out = _preview(fx, **_policy(fx, allowed_tcb_statuses=frozenset()))
    assert out["gates"]["omitted_gates"] == []
    (receipt,) = out["audit"]["receipts"]
    assert receipt["verdict"] == itf.FAIL
    assert "tcb" in receipt["detail"]
    assert out["feed"]["weights"] == []


def test_an_empty_advisory_allow_list_admits_only_advisory_free_receipts():
    """The advisory check is a subset test, so empty is NOT deny-everything.

    An advisory-free receipt passes an empty advisory allow-list, and the fully
    policed reference fixtures rely on exactly that. A receipt that carries an
    advisory is refused until the advisory is named.
    """
    fx = IntegrationFixtures()
    advisory = "INTEL-SA-00615"

    clean = _preview(fx, **_policy(fx, allowed_advisories=frozenset()))
    (admitted,) = clean["audit"]["receipts"]
    assert admitted["verdict"] == itf.PASS  # no advisory to disallow

    flagged = _preview(
        fx,
        receipts=[
            ig.LaneReceipt(
                itf.KIND_COMPUTE_CPU, LANE_CPU, _receipt_with_advisory(fx, advisory)
            )
        ],
        **_policy(fx, allowed_advisories=frozenset()),
    )
    (refused,) = flagged["audit"]["receipts"]
    assert refused["verdict"] == itf.FAIL
    assert "advisor" in refused["detail"]

    named = _preview(
        fx,
        receipts=[
            ig.LaneReceipt(
                itf.KIND_COMPUTE_CPU, LANE_CPU, _receipt_with_advisory(fx, advisory)
            )
        ],
        **_policy(fx, allowed_advisories=frozenset({advisory})),
    )
    (allowed,) = named["audit"]["receipts"]
    assert allowed["verdict"] == itf.PASS


def test_an_unfunded_lane_needs_no_policy():
    """The gate is about reward. A zero-allocation lane cannot pay anyone."""
    fx = IntegrationFixtures()
    out = _preview(fx, allocation="0.00", burn="1.00")
    assert out["gates"]["reward_lanes"] == []
    assert out["gates"]["lanes"][LANE_CPU]["reward_lane"] is False
    assert out["feed"]["burn_snapshot"]["forced_burn_percentage"] == pytest.approx(
        100.0
    )
