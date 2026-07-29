"""The integration preview cannot reach a chain writer. Proven, not asserted.

`cathedral_thin.integration` documents itself as non-writing and default-OFF, and
the repo's chain writers hard-refuse SN39. Those are the two properties an owner
activation decision leans on, so they are pinned here as tests:

1. structural: neither the seam nor its CLI imports scaffold at all, so no import
   path exists from the integration lane to a writer;
2. the writers refuse SN39 and finney on their own, independently of this lane;
3. behavioural: a full preview runs with every writer replaced by a booby trap
   that raises if touched, and still composes its vector.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime

import pytest

pytest.importorskip("cathedral_distill.integrated_feed")
pytest.importorskip("cathedral_distill.testing")

from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill.consumption_ledger import ConsumptionLedger  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures  # noqa: E402

from cathedral_thin import integration as ig  # noqa: E402
from scaffold import chain as scaffold_chain  # noqa: E402
from scaffold.publisher import mechanism_weightset as mws  # noqa: E402

NOW_DT = datetime(2026, 7, 25, 12, 30, tzinfo=UTC)
NOW_ISO = "2026-07-25T12:30:00.000000Z"
LANE_CPU = "cathedral_confidential_tdx"


# --------------------------------------------------------------------------- #
# 1. No import path from the integration lane to a chain writer
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "module", ["cathedral_thin.integration", "cathedral_thin.integration_cli"]
)
def test_importing_the_lane_never_loads_scaffold(module):
    """A fresh interpreter: importing the lane must not pull in any writer."""
    code = (
        "import importlib, sys; importlib.import_module(%r); "
        "print([m for m in sys.modules if m.split('.')[0] == 'scaffold'])" % module
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert proc.stdout.strip() == "[]", proc.stdout


def test_the_lane_source_imports_nothing_that_could_write():
    """No import statement in either module names scaffold, bittensor or a wallet."""
    import ast
    from pathlib import Path

    for name in ("integration.py", "integration_cli.py"):
        tree = ast.parse(
            (Path(ig.__file__).resolve().parent / name).read_text(encoding="utf-8")
        )
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        roots = {module.split(".")[0] for module in imported}
        assert not roots & {"scaffold", "bittensor", "substrateinterface"}, (
            f"{name} imports {sorted(roots)}"
        )


# --------------------------------------------------------------------------- #
# 2. The writers refuse SN39 on their own
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "network,netuid",
    [("finney", 39), ("finney", 1), ("mainnet", 7), ("test", 39), ("unknown", 2)],
)
def test_legacy_mechanism_writer_hard_refuses(network, netuid):
    with pytest.raises(mws.UnsafeNetworkError):
        mws.set_weights(
            {1: 1.0},
            netuid=netuid,
            network=network,
            signing_key_hex="00" * 32,
            confirm=True,
            broadcast_fn=lambda _artifact: pytest.fail("callback was invoked"),
        )


def test_scaffold_chain_writer_refuses_sn39_even_when_broadcast_is_requested():
    chain = scaffold_chain.ChainClient(
        network="finney",
        netuid=39,
        wallet_name="w",
        hotkey="hk",
        broadcast=True,
    )
    result = chain.set_weights(scaffold_chain.WeightVector(by_uid={1: 1.0}))
    assert result["submitted"] is False
    assert "disabled on SN39" in result["reason"]


# --------------------------------------------------------------------------- #
# 3. A full preview runs with every writer booby-trapped
# --------------------------------------------------------------------------- #


def _policed(fx):
    return {
        "allowed_measurements": frozenset({fx.tdx_measurement}),
        "allowed_tcb_statuses": frozenset({"UpToDate"}),
        "allowed_advisories": frozenset(),
        "current_block": 6_000_100,
        "consumption_ledger": ConsumptionLedger(":memory:"),
    }


def test_preview_completes_with_every_chain_writer_booby_trapped(monkeypatch):
    def trap(*_args, **_kw):
        raise AssertionError("the preview reached a chain writer")

    monkeypatch.setattr(mws, "set_weights", trap)
    monkeypatch.setattr(mws, "publish_next", trap)
    monkeypatch.setattr(scaffold_chain.ChainClient, "set_weights", trap)
    monkeypatch.setattr(scaffold_chain.ChainClient, "map_weights", trap)

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
        now=NOW_DT,
        now_iso=NOW_ISO,
        **_policed(fx),
    )
    assert out["audit"]["verdicts"]["pass"] == 1
    assert out["feed"]["weights"]  # a vector was composed
    assert "burn_snapshot" in out["feed"]  # and it is a preview object, not a write


def test_preview_returns_the_vector_and_reports_no_submission():
    """The seam's only output is data: nothing in it claims a chain submission."""
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
        now=NOW_DT,
        now_iso=NOW_ISO,
        **_policed(fx),
    )
    assert set(out) == {"feed", "audit", "gates"}
    assert "submitted" not in out["feed"] and "extrinsic" not in out["feed"]
