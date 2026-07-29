"""The validator seam must be able to reach the admission gates distill ships.

Before this change `preview_integrated_vector` accepted neither `current_block`,
`consumption_ledger`, nor the signed measurement/TCB/advisory policy, so the
validator's composition path was strictly weaker than `admission.verify_admission`
for the same receipt — the exact asymmetry distill PR #8 was written to remove,
reintroduced one repo downstream. A confidential-GPU launch cannot be gated on a
preview that structurally cannot apply the launch policy.
"""

from __future__ import annotations

import inspect

import pytest

pytest.importorskip("cathedral_distill.integrated_feed")
pytest.importorskip("cathedral_distill.testing")

from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402

from cathedral_thin import integration as ig  # noqa: E402

LANE_CPU = "cathedral_confidential_tdx"


def test_preview_exposes_every_admission_gate_the_contract_implements():
    params = inspect.signature(ig.preview_integrated_vector).parameters
    for name in (
        "current_block",
        "consumption_ledger",
        "allowed_measurements",
        "allowed_tcb_statuses",
        "allowed_advisories",
    ):
        assert name in params, f"validator seam cannot reach the {name} gate"


def test_admission_arguments_reach_verify_lane_receipt(monkeypatch):
    """Proves the parameters are forwarded, not merely accepted and dropped."""
    seen: dict = {}
    real = itf.verify_lane_receipt

    def spy(kind, receipt, **kw):
        seen.update(kw)
        return real(kind, receipt, **kw)

    monkeypatch.setattr(itf, "verify_lane_receipt", spy)

    fx = IntegrationFixtures()
    ledger = object()
    try:
        ig.preview_integrated_vector(
            burn_config=fx.burn_config(),
            allocation_config=fx.allocation_config(
                [{"lane": LANE_CPU, "allocation": "0.90", "enabled": True}]
            ),
            key_registry=fx.registry,
            receipts=[ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, fx.cpu_receipt())],
            network="finney",
            netuid=39,
            source_epoch=11,
            now=__import__("datetime").datetime(
                2026, 7, 25, 12, 30, tzinfo=__import__("datetime").UTC
            ),
            now_iso="2026-07-25T12:30:00.000000Z",
            current_block=123456,
            consumption_ledger=ledger,
            allowed_measurements=frozenset({"tdx-measurement-sha256:" + "a" * 64}),
            allowed_tcb_statuses=frozenset({"UpToDate"}),
            allowed_advisories=frozenset(),
        )
    except Exception:
        # The receipt may legitimately be refused by the policy we just supplied;
        # what matters is that the gates were handed down to the verifier.
        pass

    assert seen.get("current_block") == 123456
    assert seen.get("consumption_ledger") is ledger
    assert seen.get("allowed_measurements") == frozenset(
        {"tdx-measurement-sha256:" + "a" * 64}
    )
    assert seen.get("allowed_tcb_statuses") == frozenset({"UpToDate"})
    assert seen.get("allowed_advisories") == frozenset()


def test_defaults_preserve_the_previous_behaviour():
    """Omitting every new argument must not change the existing preview."""
    fx = IntegrationFixtures()
    out = ig.preview_integrated_vector(
        burn_config=fx.burn_config(),
        allocation_config=fx.allocation_config(
            [{"lane": LANE_CPU, "allocation": "0.90", "enabled": True}]
        ),
        key_registry=fx.registry,
        receipts=[ig.LaneReceipt(itf.KIND_COMPUTE_CPU, LANE_CPU, fx.cpu_receipt())],
        network="finney",
        netuid=39,
        source_epoch=11,
        now=__import__("datetime").datetime(
            2026, 7, 25, 12, 30, tzinfo=__import__("datetime").UTC
        ),
        now_iso="2026-07-25T12:30:00.000000Z",
    )
    assert out["audit"]["verdicts"]["pass"] == 1
