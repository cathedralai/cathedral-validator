"""The CyberGym lane, configured and visible at the validator seam.

Before this file the repo had no reference to cybergym at all: a cybergym receipt
composed only because the kind string happened to pass through to the shared
contract, no bundle could name the lane, and nothing told an operator whether the
block window had been applied to it. The lane is the one kind whose authorization
IS a finalized block window, so an unapplied window is not a cosmetic gap.

Configuration and visibility only. No transport and no scoring live here.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import pytest

pytest.importorskip("cathedral_distill.integrated_feed")
pytest.importorskip("cathedral_distill.testing")

from cathedral_distill import cybergym as cg  # noqa: E402
from cathedral_distill import cybergym_batch as cb  # noqa: E402
from cathedral_distill import cybergym_receipt as cr  # noqa: E402
from cathedral_distill import cybergym_validator as cv  # noqa: E402
from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill.consumption_ledger import ConsumptionLedger  # noqa: E402
from cathedral_distill.receipt_keys import ReceiptKeyRegistry  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures, digest  # noqa: E402

from cathedral_thin import integration as ig  # noqa: E402
from cathedral_thin import integration_cli as cli  # noqa: E402

NOW_DT = datetime(2026, 7, 25, 12, 30, tzinfo=UTC)
NOW_ISO = "2026-07-25T12:30:00.000000Z"
SOURCE_EPOCH = 11

LANE_CYBERGYM = ig.LANE_CYBERGYM
LANE_CPU = ig.LANE_COMPUTE_CPU

VALID_FROM_BLOCK = 100
VALID_UNTIL_BLOCK = 460
IN_WINDOW = 200
PAST_WINDOW = 999

_DISCLOSED = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
_CUTOFF = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


def _fixtures():
    """Fixtures whose registry also resolves the cybergym signing key id."""
    fx = IntegrationFixtures(source_epoch=SOURCE_EPOCH)
    pub = fx.key.public_key().public_bytes_raw()
    fx.registry = ReceiptKeyRegistry.from_keys(
        {"compute-1": pub, "distill-1": pub, "config-1": pub, "cybergym-1": pub}
    )
    return fx


def cybergym_receipt(fx, *, miner="5CyberMiner", epoch=SOURCE_EPOCH):
    """A real signed CyberGym receipt, built through the shared contract."""
    tasks = [
        cb.PooledTask(
            task_id=f"arvo:{n}",
            level=cg.Level(level),
            binary_digest=digest(f"bin-{n}"),
            disclosed_at=_DISCLOSED,
        )
        for n, level in enumerate((0, 1, 2), start=1)
    ]
    nonce = cb.derive_batch_nonce(
        block=VALID_FROM_BLOCK,
        block_hash="0x" + "cd" * 32,
        network="finney",
        netuid=39,
        source_epoch=epoch,
        miner_hotkey=miner,
        model_commitment=digest("ckpt"),
    )
    batch = cb.draw_batch(
        cb.TaskPool(tasks), size=3, nonce=nonce, as_of=_DISCLOSED, cutoff=_CUTOFF
    )
    submissions = [
        cg.PoCSubmission(
            task_id=task.task_id,
            poc_sha256=cr.holdout_digest([task.task_id]),
            result=cv.verify_poc(
                task,
                b"poc-" + task.task_id.encode(),
                lambda tid, poc, mode: (
                    1 if (tid in ("arvo:1", "arvo:2") and mode == "vul") else 0
                ),
            ),
        )
        for task in batch.tasks
    ]
    score = cg.score_batch(batch.batch_id, list(batch.tasks), submissions)
    return cr.build_receipt(
        score,
        network="finney",
        netuid=39,
        source_epoch=epoch,
        validator_hotkey="5Validator",
        miner_hotkey=miner,
        nonce=nonce,
        holdout_digest_value=cr.holdout_digest(list(batch.task_ids)),
        valid_from_block=VALID_FROM_BLOCK,
        valid_until_block=VALID_UNTIL_BLOCK,
        issued_at="2026-07-27T12:00:00.000000Z",
        private_key=fx.key,
        signing_key_id="cybergym-1",
    )


_ALLOCATIONS = [
    {"lane": LANE_CPU, "allocation": "0.45", "enabled": True},
    {"lane": LANE_CYBERGYM, "allocation": "0.45", "enabled": True},
]


def _policy(fx, ledger=None, **over):
    gates = {
        "allowed_measurements": frozenset({fx.tdx_measurement}),
        "allowed_tcb_statuses": frozenset({"UpToDate"}),
        "allowed_advisories": frozenset(),
        "current_block": IN_WINDOW,
        "consumption_ledger": ledger
        if ledger is not None
        else ConsumptionLedger(":memory:"),
    }
    gates.update(over)
    return gates


def _preview(fx, receipts, **kw):
    return ig.preview_integrated_vector(
        burn_config=fx.burn_config(),
        allocation_config=fx.allocation_config(_ALLOCATIONS),
        key_registry=fx.registry,
        receipts=receipts,
        network="finney",
        netuid=39,
        source_epoch=SOURCE_EPOCH,
        now=NOW_DT,
        now_iso=NOW_ISO,
        **kw,
    )


def _lane_receipt(receipt):
    return ig.LaneReceipt(itf.KIND_CYBERGYM, LANE_CYBERGYM, receipt)


# --------------------------------------------------------------------------- #
# The lane is addressable and its gates are reported
# --------------------------------------------------------------------------- #


def test_the_cybergym_lane_has_a_canonical_id_for_its_kind():
    assert ig.DEFAULT_LANE_FOR_KIND[itf.KIND_CYBERGYM] == LANE_CYBERGYM
    assert set(ig.DEFAULT_LANE_FOR_KIND) == {
        itf.KIND_COMPUTE_CPU,
        itf.KIND_COMPUTE_GPU,
        itf.KIND_DISTILL,
        itf.KIND_CYBERGYM,
    }


def test_a_policed_cybergym_receipt_passes_and_reports_its_gates():
    fx = _fixtures()
    out = _preview(fx, [_lane_receipt(cybergym_receipt(fx))], **_policy(fx))
    (receipt,) = out["audit"]["receipts"]
    assert receipt["verdict"] == itf.PASS
    assert receipt["lane"] == LANE_CYBERGYM
    assert "5CyberMiner" in {w["miner_hotkey"] for w in out["feed"]["weights"]}
    lane = out["gates"]["lanes"][LANE_CYBERGYM]
    assert lane["reward_lane"] and lane["block_window"] and lane["consumption_ledger"]
    assert out["gates"]["omitted_gates"] == []


def test_the_cybergym_lane_refuses_to_preview_without_the_block_window():
    """The window IS the authorization for this lane, so its absence fails closed."""
    fx = _fixtures()
    with pytest.raises(ig.IntegrationPolicyError, match="current_block"):
        _preview(
            fx, [_lane_receipt(cybergym_receipt(fx))], **_policy(fx, current_block=None)
        )


# --------------------------------------------------------------------------- #
# B7(c) stale block window, B7(e) tampering
# --------------------------------------------------------------------------- #


def test_a_receipt_outside_its_finalized_block_window_is_refused():
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        **_policy(fx, current_block=PAST_WINDOW),
    )
    (receipt,) = out["audit"]["receipts"]
    assert receipt["verdict"] == itf.FAIL
    assert "outside authorized window" in receipt["detail"]
    assert out["feed"]["weights"] == []


def test_a_receipt_before_its_window_opens_is_refused():
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        **_policy(fx, current_block=VALID_FROM_BLOCK - 1),
    )
    (receipt,) = out["audit"]["receipts"]
    assert receipt["verdict"] == itf.FAIL and "outside" in receipt["detail"]


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda r: r["score"].__setitem__("work_units", "999"), id="units"),
        pytest.param(
            lambda r: r["score"].__setitem__("solved_tasks", 3), id="solved_tasks"
        ),
        pytest.param(
            lambda r: r.__setitem__("miner_hotkey", "5Attacker"), id="miner_hotkey"
        ),
        pytest.param(
            lambda r: r.__setitem__("valid_until_block", VALID_UNTIL_BLOCK + 10_000),
            id="window",
        ),
    ],
)
def test_a_tampered_cybergym_receipt_is_refused(mutate):
    fx = _fixtures()
    receipt = cybergym_receipt(fx)
    mutate(receipt)
    out = _preview(fx, [_lane_receipt(receipt)], **_policy(fx))
    (audited,) = out["audit"]["receipts"]
    assert audited["verdict"] == itf.FAIL
    assert out["feed"]["weights"] == []


def test_an_epoch_mismatched_receipt_is_refused():
    fx = _fixtures()
    out = _preview(
        fx, [_lane_receipt(cybergym_receipt(fx, epoch=SOURCE_EPOCH + 1))], **_policy(fx)
    )
    (audited,) = out["audit"]["receipts"]
    assert audited["verdict"] == itf.FAIL


# --------------------------------------------------------------------------- #
# The CLI: a bundle can name the lane, and reports what it applied
# --------------------------------------------------------------------------- #


def _bundle(fx, tmp_path, receipts, **over):
    pub = base64.b64encode(fx.key.public_key().public_bytes_raw()).decode()
    bundle = {
        "network": "finney",
        "netuid": 39,
        "source_epoch": SOURCE_EPOCH,
        "now": "2026-07-25T12:30:00Z",
        "now_iso": NOW_ISO,
        "burn_config": json.loads(fx.burn_config().decode()),
        "allocation_config": json.loads(fx.allocation_config(_ALLOCATIONS).decode()),
        "keys": {
            "compute-1": pub,
            "distill-1": pub,
            "config-1": pub,
            "cybergym-1": pub,
        },
        "receipts": receipts,
        "allowed_measurements": [fx.tdx_measurement],
        "allowed_tcb_statuses": ["UpToDate"],
        "allowed_advisories": [],
        "current_block": IN_WINDOW,
        "ledger_path": str(tmp_path / "consumption.sqlite"),
    }
    bundle.update(over)
    return bundle


def test_a_bundle_can_omit_the_lane_and_still_reach_the_cybergym_lane(tmp_path, capsys):
    fx = _fixtures()
    bundle = _bundle(
        fx, tmp_path, [{"kind": "cybergym", "receipt": cybergym_receipt(fx)}]
    )
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    out = tmp_path / "out.json"
    assert cli.main(["--bundle", str(path), "--out", str(out)]) == 0
    result = json.loads(out.read_text())
    (receipt,) = result["audit"]["receipts"]
    assert receipt["lane"] == LANE_CYBERGYM and receipt["verdict"] == itf.PASS
    status = capsys.readouterr().err
    assert LANE_CYBERGYM in status
    assert "block_window=yes" in status and "ledger=yes" in status


def test_the_cli_reports_a_stale_window_per_lane(tmp_path):
    fx = _fixtures()
    bundle = _bundle(
        fx,
        tmp_path,
        [{"kind": "cybergym", "receipt": cybergym_receipt(fx)}],
        current_block=PAST_WINDOW,
    )
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    out = tmp_path / "out.json"
    assert cli.main(["--bundle", str(path), "--out", str(out)]) == 0
    result = json.loads(out.read_text())
    (receipt,) = result["audit"]["receipts"]
    assert receipt["verdict"] == itf.FAIL
    assert result["gates"]["lanes"][LANE_CYBERGYM]["block_window"] is True
