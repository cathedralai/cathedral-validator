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
import hashlib
import hmac

from datetime import UTC, datetime

import pytest

from cathedral_thin import cybergym_epoch_proof as ep

pytest.importorskip("cathedral_distill.integrated_feed")
pytest.importorskip("cathedral_distill.testing")

from cathedral_distill import cybergym as cg  # noqa: E402
from cathedral_distill import cybergym_batch as cb  # noqa: E402
from cathedral_distill import cybergym_receipt as cr  # noqa: E402
from cathedral_distill import cybergym_validator as cv  # noqa: E402
from cathedral_distill import integrated_feed as itf  # noqa: E402
from cathedral_distill.receipt_keys import ReceiptKeyRegistry  # noqa: E402
from cathedral_distill.testing import IntegrationFixtures, digest  # noqa: E402
from _durable_ledger import durable_ledger  # noqa: E402

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
        "consumption_ledger": ledger if ledger is not None else durable_ledger(),
    }
    gates.update(over)
    return gates


PROOF_SECRET = "cybergym-epoch-proof-secret"


def epoch_proof(
    *,
    scores=None,
    miners=("5CyberMiner",),
    score=12.0,
    epoch=SOURCE_EPOCH,
    network="finney",
    netuid=39,
    complete=True,
    generated_at=None,
    secret=PROOF_SECRET,
    tamper=None,
    body_text=None,
):
    """The producer's signed epoch report, carried as the EXACT authenticated bytes.

    `body` is what the publisher intake authenticates: the raw request body. The
    HMAC is taken over those bytes on both sides, so this exercises the real wire
    contract rather than a re-serialization. `tamper` mutates the document after
    signing (a modified report), which is distinct from re-signing it. The default
    score is 12.0 because that is the work_units the fixture receipt derives, and the
    validator now binds the credited value to the attested score.
    """
    document = {
        "producer_hotkey": "5Producer",
        "network": network,
        "netuid": netuid,
        "source_epoch": epoch,
        "generated_at": generated_at or "2026-07-25T12:29:00.000Z",
        "complete": complete,
        "score_units": "cybergym_points_v1",
        "scores": dict(scores) if scores is not None else {m: score for m in miners},
        "evidence_sha256": "c" * 64,
    }
    if tamper is not None:
        signed = dict(document)
        document = {**document, **tamper}
    else:
        signed = document
    raw = (
        body_text
        if body_text is not None
        else json.dumps(
            signed if tamper is None else signed, sort_keys=True, separators=(",", ":")
        )
    )
    if tamper is not None:
        # sign the pre-tamper bytes, then ship the tampered ones
        raw_signed = json.dumps(signed, sort_keys=True, separators=(",", ":"))
        signature = (
            "sha256="
            + hmac.new(
                secret.encode("utf-8"), raw_signed.encode("utf-8"), hashlib.sha256
            ).hexdigest()
        )
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"))
        return {"body": raw, "signature": signature}
    signature = (
        "sha256="
        + hmac.new(
            secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256
        ).hexdigest()
    )
    return {"body": raw, "signature": signature}


def _preview(fx, receipts, **kw):
    # A funded CyberGym lane now requires a verified producer epoch-completeness
    # proof, so supply a valid one by default: each test below keeps testing the
    # property it was written for, and the proof-specific cases pass their own.
    kw.setdefault("cybergym_epoch_proof", epoch_proof())
    kw.setdefault("cybergym_epoch_proof_secret", PROOF_SECRET)
    # Fill only ABSENT policy gates, so a test that deliberately passes a gate as
    # None still exercises the omission refusal.
    for name, value in _policy(fx).items():
        kw.setdefault(name, value)
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
    # honest per-kind reporting: a cybergym receipt carries no TEE evidence, so
    # the measurement/TCB/advisory policy gates nothing for it even when supplied
    assert lane["supplied"]["measurement_policy"] is True
    assert lane["measurement_policy"] is False
    assert lane["kinds"][itf.KIND_CYBERGYM] == {
        "measurement_policy": False,
        "tcb_policy": False,
        "advisory_policy": False,
        "block_window": True,
        "consumption_ledger": True,
    }


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
    # A funded cybergym lane needs the producer proof in the bundle; the secret is
    # read from the environment by the CLI, never from the bundle file.
    over.setdefault("cybergym_epoch_proof", epoch_proof())
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


def test_a_bundle_can_omit_the_lane_and_still_reach_the_cybergym_lane(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.setenv(ep.EPOCH_PROOF_SECRET_ENV, PROOF_SECRET)
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


def test_the_cli_reports_a_stale_window_per_lane(tmp_path, monkeypatch):
    monkeypatch.setenv(ep.EPOCH_PROOF_SECRET_ENV, PROOF_SECRET)
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


# --------------------------------------------------------------------------- #
# Producer epoch completeness, verified by the validator itself
#
# A receipt proves one miner solved. It cannot prove the producer FINISHED scoring
# the epoch, and distill's cybergym_epoch_status table never crosses the
# authenticated HTTP boundary. So the signed report that says complete: true is
# what the validator has to check, and every way it can fail has to burn the lane
# rather than pay a possibly partial epoch.
# --------------------------------------------------------------------------- #
def _cybergym_burned(out):
    """The cybergym lane contributed nothing and its share forfeited to burn."""
    lane = out["feed"]["lanes"]
    row = next(entry for entry in lane if entry["lane"] == LANE_CYBERGYM)
    return row["contributing"] is False and row["burned_allocation"] == "0.45"


def _only_reason(out):
    (receipt,) = [r for r in out["audit"]["receipts"] if r["lane"] == LANE_CYBERGYM]
    return receipt["verdict"], receipt["detail"]


def test_a_verified_epoch_proof_lets_the_lane_pay(fx=None):
    fx = _fixtures()
    out = _preview(fx, [_lane_receipt(cybergym_receipt(fx))])
    verdict, _ = _only_reason(out)
    assert verdict == itf.PASS
    assert out["gates"]["cybergym_epoch_proof"]["verified"] is True
    assert out["gates"]["cybergym_epoch_proof"]["required"] == [LANE_CYBERGYM]


def test_a_missing_proof_burns_the_lane():
    # Restart-lost or never-supplied: the operator has no completeness evidence.
    fx = _fixtures()
    out = _preview(fx, [_lane_receipt(cybergym_receipt(fx))], cybergym_epoch_proof=None)
    verdict, detail = _only_reason(out)
    assert verdict == itf.FAIL and "epoch-completeness proof" in detail
    assert _cybergym_burned(out)
    assert out["gates"]["cybergym_epoch_proof"]["verified"] is False


def test_an_incomplete_epoch_burns_the_lane():
    # complete=False is the producer saying scoring has not finished.
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        cybergym_epoch_proof=epoch_proof(complete=False),
    )
    verdict, _ = _only_reason(out)
    assert verdict == itf.FAIL and _cybergym_burned(out)
    assert "epoch_not_complete" in out["gates"]["cybergym_epoch_proof"]["reason"]


@pytest.mark.parametrize("truthy", ["false", "0", "", 1, "yes", None])
def test_a_truthy_complete_stand_in_never_passes_as_closed(truthy):
    # Identity, not truthiness: bool("false") is True, and that must not close an epoch.
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        cybergym_epoch_proof=epoch_proof(complete=truthy),
    )
    verdict, _ = _only_reason(out)
    assert verdict == itf.FAIL and _cybergym_burned(out)


def test_a_stale_proof_burns_the_lane():
    # One captured report must not authorize every later epoch.
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        cybergym_epoch_proof=epoch_proof(generated_at="2026-07-20T12:00:00.000Z"),
    )
    verdict, _ = _only_reason(out)
    assert verdict == itf.FAIL and _cybergym_burned(out)
    assert "stale_proof" in out["gates"]["cybergym_epoch_proof"]["reason"]


def test_a_future_dated_proof_burns_the_lane():
    # A future date computes a negative age and would never expire.
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        cybergym_epoch_proof=epoch_proof(generated_at="2027-01-01T00:00:00.000Z"),
    )
    verdict, _ = _only_reason(out)
    assert verdict == itf.FAIL and _cybergym_burned(out)
    assert "proof_in_future" in out["gates"]["cybergym_epoch_proof"]["reason"]


def test_a_tampered_proof_burns_the_lane():
    # Mutated after signing: the HMAC no longer matches the canonical document.
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        cybergym_epoch_proof=epoch_proof(tamper={"score_units": "inflated_points"}),
    )
    verdict, _ = _only_reason(out)
    assert verdict == itf.FAIL and _cybergym_burned(out)
    assert "invalid_signature" in out["gates"]["cybergym_epoch_proof"]["reason"]


def test_a_proof_signed_with_the_wrong_secret_burns_the_lane():
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        cybergym_epoch_proof=epoch_proof(secret="not-the-operator-secret"),
    )
    verdict, _ = _only_reason(out)
    assert verdict == itf.FAIL and _cybergym_burned(out)


def test_an_unset_secret_burns_the_lane_rather_than_passing():
    fx = _fixtures()
    out = _preview(
        fx, [_lane_receipt(cybergym_receipt(fx))], cybergym_epoch_proof_secret=None
    )
    verdict, _ = _only_reason(out)
    assert verdict == itf.FAIL and _cybergym_burned(out)
    assert "secret_not_configured" in out["gates"]["cybergym_epoch_proof"]["reason"]


@pytest.mark.parametrize(
    "over,reason",
    [
        ({"epoch": SOURCE_EPOCH + 1}, "wrong_epoch"),
        ({"network": "test"}, "wrong_audience"),
        ({"netuid": 1}, "wrong_audience"),
    ],
)
def test_a_proof_for_another_epoch_or_audience_burns_the_lane(over, reason):
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        cybergym_epoch_proof=epoch_proof(**over),
    )
    verdict, _ = _only_reason(out)
    assert verdict == itf.FAIL and _cybergym_burned(out)
    assert reason in out["gates"]["cybergym_epoch_proof"]["reason"]


def test_a_subject_the_producer_never_scored_is_refused():
    # The producer's attested scored set is the authority on who solved the epoch.
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        cybergym_epoch_proof=epoch_proof(miners=("5SomeoneElse",)),
    )
    verdict, detail = _only_reason(out)
    assert verdict == itf.FAIL
    # both halves of the mismatch are named: the scored miner has no receipt, and
    # the submitted miner was never scored above zero
    assert "no verified receipt for producer-scored 5SomeoneElse" in detail
    assert "credited but not scored above zero by the producer: 5CyberMiner" in detail
    assert _cybergym_burned(out)


def test_an_unfunded_cybergym_lane_needs_no_proof():
    # The gate applies to a FUNDED lane. With the lane allocated zero there is no
    # reward to protect, so a preview must not start demanding producer evidence.
    fx = _fixtures()
    out = ig.preview_integrated_vector(
        burn_config=fx.burn_config(),
        allocation_config=fx.allocation_config(
            [
                {"lane": LANE_CPU, "allocation": "0.90", "enabled": True},
                {"lane": LANE_CYBERGYM, "allocation": "0.00", "enabled": True},
            ]
        ),
        key_registry=fx.registry,
        receipts=[_lane_receipt(cybergym_receipt(fx))],
        network="finney",
        netuid=39,
        source_epoch=SOURCE_EPOCH,
        now=NOW_DT,
        now_iso=NOW_ISO,
        **_policy(fx),
    )
    assert out["gates"]["cybergym_epoch_proof"]["required"] == []


# --------------------------------------------------------------------------- #
# Exact set and value binding
#
# Membership in the attested set is NOT sufficient, and both holes below were
# reproduced before the binding pass existed: an omitted contributor let the
# submitted miner take the whole lane (weight 1.0, nothing burned) because a lane
# normalizes work units within itself, and a miner the producer scored 0.0 was
# credited from a positive receipt.
# --------------------------------------------------------------------------- #
def test_an_omitted_contributor_burns_the_lane_instead_of_reallocating():
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx, miner="5CyberMiner"))],
        cybergym_epoch_proof=epoch_proof(miners=("5CyberMiner", "5OtherMiner")),
    )
    verdict, detail = _only_reason(out)
    assert verdict == itf.FAIL
    assert "no verified receipt for producer-scored 5OtherMiner" in detail
    # the crux: the present miner must NOT absorb the absent miner's share
    assert out["feed"]["weights"] == []
    assert _cybergym_burned(out)


def test_a_zero_scored_miner_cannot_be_credited():
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx, miner="5CyberMiner"))],
        cybergym_epoch_proof=epoch_proof(scores={"5CyberMiner": 0.0}),
    )
    verdict, detail = _only_reason(out)
    assert verdict == itf.FAIL
    assert "credited but not scored above zero" in detail
    assert out["feed"]["weights"] == [] and _cybergym_burned(out)


def test_a_work_unit_value_that_disagrees_with_the_attested_score_burns():
    # Two derivations of the same level-weighted quantity disagreeing means one of
    # them is wrong, so the lane burns rather than picking a winner.
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx, miner="5CyberMiner"))],
        cybergym_epoch_proof=epoch_proof(scores={"5CyberMiner": 99.0}),
    )
    verdict, detail = _only_reason(out)
    assert verdict == itf.FAIL
    assert "do not equal the producer's attested score" in detail
    assert _cybergym_burned(out)


def test_the_exact_matching_set_and_values_pay():
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx, miner="5CyberMiner"))],
        cybergym_epoch_proof=epoch_proof(scores={"5CyberMiner": 12.0}),
    )
    verdict, _ = _only_reason(out)
    assert verdict == itf.PASS
    assert [w["miner_hotkey"] for w in out["feed"]["weights"]] == ["5CyberMiner"]


def test_a_prior_failure_keeps_its_own_reason():
    # The binding pass must not overwrite a receipt that already failed for its own
    # reason: an operator needs the window/signature diagnosis, and it is not paying.
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        current_block=VALID_UNTIL_BLOCK + 10,
    )
    _, detail = _only_reason(out)
    assert "outside authorized window" in detail


# --------------------------------------------------------------------------- #
# The REAL cross-repository contract
#
# Everything above signs with this file's helper, which cannot catch a divergence
# between what cathedral's producer/intake actually authenticates and what this
# validator recomputes. These drive cathedral's own cybergym_contract module.
# --------------------------------------------------------------------------- #
_CATHEDRAL_CONTRACT_PATH = (
    "/Users/dreamboat/Documents/PROJECTS/cathedral-fable-prs-20260729/repos/cathedral"
    "/scaffold/publisher/cybergym_contract.py"
)


def _cathedral_contract():
    """cathedral's producer/intake contract module, loaded by FILE PATH, or skip.

    Loaded via importlib rather than by putting the cathedral checkout on sys.path:
    that repo also ships `game/`, and making it importable breaks the boundary
    invariant tests/boundary/test_no_game_dependency.py exists to protect (it caught
    exactly that when this test first put the repo root on the path). The module is
    stdlib-only, so a file-path load is faithful.

    Private sibling: CI holds no credential for it, so this SKIPS there. A skip is
    never evidence of compatibility; read the counts from an environment that has
    the sibling checked out.
    """
    import importlib.util
    import os

    if not os.path.exists(_CATHEDRAL_CONTRACT_PATH):
        pytest.skip("cathedral sibling checkout not present")
    spec = importlib.util.spec_from_file_location(
        "_cathedral_cybergym_contract", _CATHEDRAL_CONTRACT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_validator_verifies_what_cathedrals_producer_actually_signs():
    contract = _cathedral_contract()
    fx = _fixtures()
    document = {
        "producer_hotkey": "5Producer",
        "network": "finney",
        "netuid": 39,
        "source_epoch": SOURCE_EPOCH,
        "generated_at": "2026-07-25T12:29:00.000Z",
        "complete": True,
        "score_units": "cybergym_points_v1",
        "scores": {"5CyberMiner": 12.0},
        "evidence_sha256": "c" * 64,
    }
    # Exactly what the producer puts on the wire and the intake authenticates.
    body = contract.canonical_report_bytes(
        contract.normalize_semantic_document(document)
    )
    signature = "sha256=" + contract.body_hmac_hex(body, PROOF_SECRET)
    # sanity: cathedral's own intake check accepts this pair
    assert contract.constant_time_equal(
        contract.strip_sha256_prefix(signature),
        contract.body_hmac_hex(body, PROOF_SECRET),
    )

    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx, miner="5CyberMiner"))],
        cybergym_epoch_proof={"body": body.decode("utf-8"), "signature": signature},
    )
    verdict, detail = _only_reason(out)
    assert verdict == itf.PASS, detail
    assert out["gates"]["cybergym_epoch_proof"]["verified"] is True


def test_a_noncanonical_wire_body_still_verifies_over_its_exact_bytes():
    # cathedral's intake authenticates the RAW body it received, and its 0048->0049
    # backfill re-verifies legacy non-canonical bytes. So a pretty-printed body whose
    # HMAC covers those exact bytes must verify here too: what is authenticated is
    # the byte string the producer signed, not a re-serialization of it.
    contract = _cathedral_contract()
    fx = _fixtures()
    document = contract.normalize_semantic_document(
        {
            "producer_hotkey": "5Producer",
            "network": "finney",
            "netuid": 39,
            "source_epoch": SOURCE_EPOCH,
            "generated_at": "2026-07-25T12:29:00.000Z",
            "complete": True,
            "score_units": "cybergym_points_v1",
            "scores": {"5CyberMiner": 12.0},
            "evidence_sha256": "c" * 64,
        }
    )
    pretty = json.dumps(document, indent=2, sort_keys=True)  # NOT canonical
    assert pretty.encode("utf-8") != contract.canonical_report_bytes(document)
    signature = "sha256=" + contract.body_hmac_hex(pretty.encode("utf-8"), PROOF_SECRET)

    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx, miner="5CyberMiner"))],
        cybergym_epoch_proof={"body": pretty, "signature": signature},
    )
    verdict, detail = _only_reason(out)
    assert verdict == itf.PASS, detail


def test_a_document_only_proof_is_refused_as_ambiguous():
    # Without the exact bytes we cannot know what was signed, so guessing a
    # canonical re-serialization would verify a different byte string.
    fx = _fixtures()
    out = _preview(
        fx,
        [_lane_receipt(cybergym_receipt(fx))],
        cybergym_epoch_proof={"document": {"a": 1}, "signature": "sha256=00"},
    )
    verdict, _ = _only_reason(out)
    assert verdict == itf.FAIL and _cybergym_burned(out)
    assert "invalid_proof" in out["gates"]["cybergym_epoch_proof"]["reason"]


def test_the_shared_contract_literals_have_not_drifted():
    contract = _cathedral_contract()
    assert tuple(contract.SEMANTIC_KEYS) == ep.SEMANTIC_KEYS
    assert contract.HMAC_SECRET_ENV == ep.EPOCH_PROOF_SECRET_ENV
