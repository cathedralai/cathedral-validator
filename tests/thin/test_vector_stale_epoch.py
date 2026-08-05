"""A stale signed vector is CLASSIFIED, never forgiven.

The publisher signs and caches a weight vector for up to a minute while the
evidence index flips to the next 311s epoch, so an audit can legitimately hold
epoch N's vector beside epoch N+1's evidence. The comparison in
``cathedral.provenance`` refuses to guess about that — equal proportions never
prove an equal epoch — so it reported the one event that is supposed to mean
"a bad vector landed" every ~26 minutes on a benign, self-resolving race.

The fix is not a tolerance. When the ONLY discrepancy is the epoch binding,
the WHOLE comparison runs again against the epoch the vector names, reached
through the signed index's own ``recent`` window: that epoch's manifest, its
policy registry, its score report and receipts are verified and recomputed,
and the vector is compared against THAT result with THAT manifest's report
body digest. Only if the second comparison agrees is the vector stale.

These tests pin both halves: the serving race is classified, and everything
that is not provably a serving race — an epoch outside the signed window,
evidence that fails to verify, a body digest that does not match its own
epoch's manifest, shares that do not match its own epoch's recomputation, a
budget too small to re-verify — stays a mismatch at FAIL.
"""

from __future__ import annotations

import hashlib
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from scaffold import provenance_audit as pa
from scaffold import sn39_public_reproduction as repro
from scaffold import validator_thin

NETWORK = "finney"
NETUID = 39
MECHANISM = "validated_supply_v2"
VERIFIER_DIGEST = "sha256:" + "a" * 64
GENERATED_AT = "2026-08-04T12:00:00+00:00"
POLICY_RELEASE = 7
STALE_EPOCH = 1000
LATEST_EPOCH = 1001
SHARES = {"miner-a": 0.75, "miner-b": 0.25}
OTHER_SHARES = {"miner-a": 0.5, "miner-b": 0.5}


class _FakeProvenanceError(Exception):
    pass


def _wire(epoch: int) -> str:
    return "sha256:" + hashlib.sha256(f"wire-{epoch}".encode()).hexdigest()


@pytest.fixture()
def fake_cathedral(monkeypatch):
    """A cathedral library stand-in that keeps the two contracts that matter.

    ``verify_and_recompute`` recomputes an epoch's shares ONLY from that
    epoch's own signed report, and refuses a report whose registry, receipts,
    or work artifacts are missing or belong elsewhere — so a classification
    that skipped a fetch or crossed epochs cannot pass here.

    ``compare_with_vector`` reproduces the real function's ORDERING: the epoch
    binding is checked first and early-returns a single discrepancy, so the
    body digest and the share comparison behind it genuinely never ran. That
    ordering is the whole reason the re-verification has to be a full second
    comparison rather than a reading of the first one's message.
    """
    provenance = types.ModuleType("cathedral.provenance")
    provenance.ProvenanceError = _FakeProvenanceError

    def verify_and_recompute(
        *,
        report_bytes,
        receipts_by_id,
        registry_bytes,
        work_artifacts_by_receipt,
        expected_network,
        expected_netuid,
        now=None,
        **_kwargs,
    ):
        document = json.loads(report_bytes)
        if document.get("forged"):
            raise _FakeProvenanceError("score report signature is invalid")
        if expected_network != NETWORK or expected_netuid != NETUID:
            raise _FakeProvenanceError("report network/netuid mismatch")
        if json.loads(registry_bytes).get("registry_for") != document["source_epoch"]:
            raise _FakeProvenanceError("policy registry belongs to another epoch")
        if now is None or now.tzinfo is None:
            raise _FakeProvenanceError("a superseded epoch needs its issue moment")
        for receipt_id in document["receipts"]:
            if receipt_id not in receipts_by_id:
                raise _FakeProvenanceError(f"receipt {receipt_id} is missing")
            if receipt_id not in (work_artifacts_by_receipt or {}):
                raise _FakeProvenanceError(f"work artifacts for {receipt_id} missing")
        return SimpleNamespace(
            source_epoch=int(document["source_epoch"]),
            report_id=str(document["report_id"]),
            policy_release=POLICY_RELEASE,
            recomputed_hotkey_weights=dict(document["shares"]),
        )

    def compare_with_vector(result, signed_vector, *, wire_report_sha256=None):
        external = signed_vector["policy_metadata"]["external_scores"]
        if int(external["latest_epoch"]) != int(result.source_epoch):
            return False, [
                (
                    f"signed vector is bound to ingested source epoch "
                    f"{external['latest_epoch']}, not the verified evidence "
                    f"epoch {result.source_epoch}; same proportions never "
                    f"prove the same epoch"
                )
            ]
        if external["latest_body_sha256"] != wire_report_sha256:
            return False, [
                (
                    "signed vector external_scores.latest_body_sha256 does not "
                    "match the evidence manifest's wire_report_sha256; the "
                    "vector was built from a DIFFERENT ingested report body"
                )
            ]
        recomputed = result.recomputed_hotkey_weights
        signed = {
            row["miner_hotkey"]: row["external_component"]
            for row in signed_vector["weights"]
        }
        return (recomputed == signed), [
            f"{hotkey}: recomputed_share={recomputed.get(hotkey, 0.0)!r} "
            f"signed_external_share={signed.get(hotkey, 0.0)!r}"
            for hotkey in sorted(set(recomputed) | set(signed))
            if recomputed.get(hotkey, 0.0) != signed.get(hotkey, 0.0)
        ]

    provenance.verify_and_recompute = verify_and_recompute
    provenance.compare_with_vector = compare_with_vector
    evidence = types.ModuleType("cathedral.evidence")
    evidence.parse_manifest = json.loads
    package = types.ModuleType("cathedral")
    package.provenance = provenance
    package.evidence = evidence
    monkeypatch.setitem(sys.modules, "cathedral", package)
    monkeypatch.setitem(sys.modules, "cathedral.provenance", provenance)
    monkeypatch.setitem(sys.modules, "cathedral.evidence", evidence)
    return provenance


class _BlobStore:
    """Content-addressed blob fake that counts every fetch it serves."""

    def __init__(self, remaining=256):
        self.blobs: dict[str, bytes] = {}
        self.calls = 0
        self.remaining = remaining
        self.artifacts_remaining = lambda: self.remaining

    def add(self, payload) -> str:
        data = json.dumps(payload).encode()
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        self.blobs[digest] = data
        return digest

    def __call__(self, digest: str) -> bytes:
        self.calls += 1
        return self.blobs[digest]


RECEIPT_IDS = ("receipt-1", "receipt-2")


def _epoch_row(store, epoch, *, shares, wire=None, forged=False, **manifest_over):
    """One signed-index ``recent`` row plus the whole epoch behind it."""
    report = {
        "generated_at": GENERATED_AT,
        "source_epoch": epoch,
        "report_id": f"report-{epoch}",
        "receipts": list(RECEIPT_IDS),
        "shares": dict(shares),
        "forged": forged,
    }
    manifest = {
        "network": NETWORK,
        "netuid": NETUID,
        "source_epoch": epoch,
        "reward_mechanism": {"id": MECHANISM},
        "verifier": {"digest": VERIFIER_DIGEST},
        "policy_registry": {
            "release": POLICY_RELEASE,
            "digest": "policy-digest-7",
            "blob": store.add({"registry_for": epoch}),
        },
        "score_report": {"blob": store.add(report), "report_id": f"report-{epoch}"},
        "receipts": [
            {
                "receipt_id": receipt_id,
                "blob": store.add({"receipt": receipt_id, "epoch": epoch}),
                "work_item_blob": store.add({"work": receipt_id, "epoch": epoch}),
                "result_blob": store.add({"result": receipt_id, "epoch": epoch}),
            }
            for receipt_id in RECEIPT_IDS
        ],
        "candidate_set": {"block": 4321, "block_hash": "0x" + "b" * 64},
        "wire_report_sha256": _wire(epoch) if wire is None else wire,
    }
    manifest.update(manifest_over)
    return {"source_epoch": epoch, "manifest": store.add(manifest)}


def _vector(*, epoch, shares, body_digest=None):
    return {
        "weights": [
            {"miner_hotkey": hotkey, "external_component": share}
            for hotkey, share in sorted(shares.items())
        ],
        "policy_metadata": {
            "external_scores": {
                "latest_epoch": epoch,
                "latest_body_sha256": (
                    _wire(epoch) if body_digest is None else body_digest
                ),
            }
        },
    }


def _latest_result(shares=None):
    """The audit's own verified result for the CURRENT evidence epoch."""
    return SimpleNamespace(
        source_epoch=LATEST_EPOCH,
        report_id=f"report-{LATEST_EPOCH}",
        policy_release=POLICY_RELEASE,
        recomputed_hotkey_weights=dict(SHARES if shares is None else shares),
    )


def _classify(provenance, store, vector, *, rows, result=None, **over):
    """Compare exactly as run_audit does, then classify what came back."""
    result = _latest_result() if result is None else result
    agree, discrepancies = provenance.compare_with_vector(
        result, vector, wire_report_sha256=_wire(LATEST_EPOCH)
    )
    assert not agree, "these tests are about a comparison that DISAGREED"
    kwargs = {
        "settings": pa.ProvenanceSettings(
            mode="shadow",
            evidence_url="https://api.example.test/v1/evidence",
            verifier_digest=VERIFIER_DIGEST,
            mechanism=MECHANISM,
        ),
        "network": NETWORK,
        "netuid": NETUID,
        "registry_keys": {},
        "report_keys": {},
        "recent_rows": rows,
        "load_blob": store,
    }
    kwargs.update(over)
    return pa._classify_stale_vector(result, vector, discrepancies, **kwargs)


# -- (a) the serving race is classified, not alarmed on ----------------------


def test_a_vector_one_epoch_behind_verifies_against_its_own_epoch(fake_cathedral):
    store = _BlobStore()
    rows = [
        _epoch_row(store, STALE_EPOCH, shares=SHARES),
        _epoch_row(store, LATEST_EPOCH, shares=SHARES),
    ]
    stale = _classify(
        fake_cathedral,
        store,
        _vector(epoch=STALE_EPOCH, shares=SHARES),
        rows=rows,
    )
    assert stale == STALE_EPOCH
    # The named epoch was re-verified WHOLE: manifest, registry, report, and
    # every receipt with both of its work artifacts.
    assert store.calls == (
        pa.STALE_REVERIFY_FIXED_BLOBS
        + pa.STALE_REVERIFY_BLOBS_PER_RECEIPT * len(RECEIPT_IDS)
    )


def test_a_stale_vector_is_still_a_disagreement_run_audit_records(fake_cathedral):
    # The classification names the epoch; it never asserts agreement, because
    # a correct vector for a superseded epoch is still not this epoch's vector.
    store = _BlobStore()
    rows = [_epoch_row(store, STALE_EPOCH, shares=SHARES)]
    audit = pa.ProvenanceAudit(status="PASS", source_epoch=LATEST_EPOCH)
    audit.agrees_with_vector = False
    audit.vector_stale_epoch = _classify(
        fake_cathedral, store, _vector(epoch=STALE_EPOCH, shares=SHARES), rows=rows
    )
    assert audit.vector_stale_epoch == STALE_EPOCH
    assert audit.agrees_with_vector is False


# -- (b) a genuinely wrong vector is still a mismatch ------------------------


def test_wrong_shares_at_the_current_epoch_are_never_classified(fake_cathedral):
    # The epoch binding agrees, so the disagreement is the share comparison
    # itself. Nothing here even looks like a serving race, and no evidence is
    # fetched to consider one.
    store = _BlobStore()
    rows = [_epoch_row(store, STALE_EPOCH, shares=SHARES)]
    vector = _vector(
        epoch=LATEST_EPOCH, shares=OTHER_SHARES, body_digest=_wire(LATEST_EPOCH)
    )
    assert _classify(fake_cathedral, store, vector, rows=rows) is None
    assert store.calls == 0


def test_wrong_shares_at_the_named_epoch_stay_a_mismatch(fake_cathedral):
    # A vector that names an older epoch AND pays a different set of miners
    # than that epoch's own recomputation is exactly what the alarm is for.
    store = _BlobStore()
    rows = [_epoch_row(store, STALE_EPOCH, shares=SHARES)]
    vector = _vector(epoch=STALE_EPOCH, shares=OTHER_SHARES)
    assert _classify(fake_cathedral, store, vector, rows=rows) is None


def test_evidence_that_fails_to_verify_stays_a_mismatch(fake_cathedral):
    store = _BlobStore()
    rows = [_epoch_row(store, STALE_EPOCH, shares=SHARES, forged=True)]
    vector = _vector(epoch=STALE_EPOCH, shares=SHARES)
    assert _classify(fake_cathedral, store, vector, rows=rows) is None


# -- (c) an epoch outside the signed window fails closed ---------------------


def test_an_epoch_absent_from_the_signed_window_is_not_downgraded(fake_cathedral):
    # The ONLY reachable evidence is what the signed index vouches for. An
    # epoch it does not carry cannot be re-verified, so it cannot be excused.
    store = _BlobStore()
    rows = [_epoch_row(store, LATEST_EPOCH, shares=SHARES)]
    vector = _vector(epoch=STALE_EPOCH, shares=SHARES)
    assert _classify(fake_cathedral, store, vector, rows=rows) is None
    assert store.calls == 0


def test_an_empty_recent_window_is_not_downgraded(fake_cathedral):
    store = _BlobStore()
    vector = _vector(epoch=STALE_EPOCH, shares=SHARES)
    assert _classify(fake_cathedral, store, vector, rows=()) is None
    assert store.calls == 0


def test_a_vector_naming_a_later_epoch_is_not_a_serving_race(fake_cathedral):
    # A vector ahead of the verified evidence claims an epoch this audit never
    # verified. The index's rollback fences own that case, not this one.
    store = _BlobStore()
    ahead = LATEST_EPOCH + 1
    rows = [_epoch_row(store, ahead, shares=SHARES)]
    assert (
        _classify(fake_cathedral, store, _vector(epoch=ahead, shares=SHARES), rows=rows)
        is None
    )
    assert store.calls == 0


def test_a_budget_too_small_to_re_verify_stays_a_mismatch(fake_cathedral):
    # An unclassifiable disagreement is a mismatch. Refuse BEFORE spending the
    # artifacts the rest of the audit was never going to get back.
    store = _BlobStore(remaining=pa.STALE_REVERIFY_FIXED_BLOBS - 1)
    rows = [_epoch_row(store, STALE_EPOCH, shares=SHARES)]
    vector = _vector(epoch=STALE_EPOCH, shares=SHARES)
    assert _classify(fake_cathedral, store, vector, rows=rows) is None
    assert store.calls == 0


def test_a_budget_short_of_the_receipts_stays_a_mismatch(fake_cathedral):
    store = _BlobStore(
        remaining=pa.STALE_REVERIFY_FIXED_BLOBS
        + pa.STALE_REVERIFY_BLOBS_PER_RECEIPT * len(RECEIPT_IDS)
        - 1
    )
    rows = [_epoch_row(store, STALE_EPOCH, shares=SHARES)]
    vector = _vector(epoch=STALE_EPOCH, shares=SHARES)
    assert _classify(fake_cathedral, store, vector, rows=rows) is None
    # Only the manifest was read, and the walk stopped once the receipt count
    # was known to be unaffordable.
    assert store.calls == 1


def test_a_local_store_walk_is_not_budget_bounded(fake_cathedral):
    store = _BlobStore(remaining=None)
    rows = [_epoch_row(store, STALE_EPOCH, shares=SHARES)]
    vector = _vector(epoch=STALE_EPOCH, shares=SHARES)
    assert _classify(fake_cathedral, store, vector, rows=rows) == STALE_EPOCH


# -- (d) the body digest still binds, at the vector's own epoch --------------


def test_a_body_digest_mismatch_at_the_named_epoch_stays_a_mismatch(fake_cathedral):
    # Same proportions, same epoch number, DIFFERENT ingested report body: the
    # exact substitution the digest comparison exists to catch. Reaching it
    # required the epoch check to stop failing first, which is why the
    # re-verification runs the whole comparison instead of the epoch alone.
    store = _BlobStore()
    rows = [_epoch_row(store, STALE_EPOCH, shares=SHARES)]
    vector = _vector(epoch=STALE_EPOCH, shares=SHARES, body_digest="sha256:" + "c" * 64)
    assert _classify(fake_cathedral, store, vector, rows=rows) is None


def test_a_manifest_that_does_not_belong_to_the_named_epoch_is_refused(fake_cathedral):
    # A signed row pointing at another epoch's manifest is not evidence for
    # the epoch the vector names.
    store = _BlobStore()
    row = _epoch_row(store, STALE_EPOCH, shares=SHARES, source_epoch=LATEST_EPOCH)
    vector = _vector(epoch=STALE_EPOCH, shares=SHARES)
    assert _classify(fake_cathedral, store, vector, rows=[row]) is None


def test_a_foreign_subnet_manifest_is_refused(fake_cathedral):
    store = _BlobStore()
    row = _epoch_row(store, STALE_EPOCH, shares=SHARES, netuid=1)
    vector = _vector(epoch=STALE_EPOCH, shares=SHARES)
    assert _classify(fake_cathedral, store, vector, rows=[row]) is None


def test_an_unpinned_verifier_at_the_named_epoch_is_refused(fake_cathedral):
    store = _BlobStore()
    row = _epoch_row(
        store, STALE_EPOCH, shares=SHARES, verifier={"digest": "sha256:" + "d" * 64}
    )
    vector = _vector(epoch=STALE_EPOCH, shares=SHARES)
    assert _classify(fake_cathedral, store, vector, rows=[row]) is None


# -- the event stream says which one happened -------------------------------


class _Events:
    def __init__(self):
        self.emitted = []

    def event(self, name, **fields):
        self.emitted.append((name, fields))


def _emit(monkeypatch, audit):
    events = _Events()
    monkeypatch.setattr(validator_thin, "_get_events", lambda _a: events)
    monkeypatch.setattr(validator_thin, "_lifecycle", lambda *a, **k: None)
    persisted = validator_thin._log_audit_events(
        SimpleNamespace(), audit, Path("unused-state.json"), persist=False
    )
    return events, persisted


def _disagreeing_audit(**over):
    audit = pa.ProvenanceAudit(status="PASS", source_epoch=LATEST_EPOCH)
    audit.agrees_with_vector = False
    audit.discrepancies = ["signed vector is bound to ingested source epoch 1000"]
    for name, value in over.items():
        setattr(audit, name, value)
    return audit


def test_a_stale_vector_emits_its_own_event_and_never_the_alarm(monkeypatch):
    events, persisted = _emit(
        monkeypatch, _disagreeing_audit(vector_stale_epoch=STALE_EPOCH)
    )
    names = [name for name, _fields in events.emitted]
    assert names == ["PROVENANCE_VECTOR_STALE_EPOCH"]
    fields = events.emitted[0][1]
    assert fields["status"] == validator_thin.NOT_PROVEN
    assert fields["vector_agrees"] is False
    assert str(STALE_EPOCH) in fields["detail"]
    # Still a disagreement: no PASS, and nothing was persisted as proven.
    assert persisted is False


def test_an_unclassified_disagreement_still_fires_the_alarm_at_fail(monkeypatch):
    events, persisted = _emit(monkeypatch, _disagreeing_audit())
    names = [name for name, _fields in events.emitted]
    assert names == ["PROVENANCE_VECTOR_MISMATCH"]
    assert events.emitted[0][1]["status"] == validator_thin.FAIL
    assert persisted is False


def test_disagreement_is_still_reported_before_the_assurance_early_return(monkeypatch):
    # The ordering property the mismatch branch was written for: a
    # receipts-only audit must still be able to report on the vector, so the
    # stale classification has to sit in the SAME branch, above the
    # partial-assurance return.
    audit = _disagreeing_audit(vector_stale_epoch=STALE_EPOCH)
    audit.assurance = "receipts_only"
    events, _persisted = _emit(monkeypatch, audit)
    assert [name for name, _fields in events.emitted] == [
        "PROVENANCE_VECTOR_STALE_EPOCH"
    ]


# -- the public reproduction fails closed on the alarm, not on the race ------


def _dry_run_stream(tmp_path, *event_documents):
    startup = {
        "event": "STARTUP",
        "ts": "2026-08-04T12:00:00.000Z",
        "status": "INFO",
        "detail": "mode=thin submission_authority=thin provenance=shadow",
        **repro.EXPECTED_STARTUP,
    }
    path = tmp_path / "validator-events.jsonl"
    path.write_text(
        "\n".join(json.dumps(document) for document in (startup, *event_documents)),
        encoding="utf-8",
    )
    return path


def test_the_reproduction_does_not_fail_closed_on_a_stale_vector(tmp_path):
    path = _dry_run_stream(
        tmp_path,
        {
            "event": "PROVENANCE_VECTOR_STALE_EPOCH",
            "ts": "2026-08-04T12:01:00.000Z",
            "status": "NOT_PROVEN",
            "detail": f"signed vector re-verified against epoch {STALE_EPOCH}",
        },
    )
    # It fails later, on the missing dry-run result this stream never carries;
    # what matters is that it got past the fail-closed set.
    with pytest.raises(repro.ReproductionError, match="no-write thin result"):
        repro.assert_current_dry_run(path)


def test_the_reproduction_still_fails_closed_on_a_real_mismatch(tmp_path):
    path = _dry_run_stream(
        tmp_path,
        {
            "event": "PROVENANCE_VECTOR_MISMATCH",
            "ts": "2026-08-04T12:01:00.000Z",
            "status": "FAIL",
            "detail": "miner-a: recomputed_share=0.750000000",
        },
    )
    with pytest.raises(repro.ReproductionError, match="PROVENANCE_VECTOR_MISMATCH"):
        repro.assert_current_dry_run(path)


# -- the deployed alert matches the alarm, not the classification -----------


def test_the_deployed_alert_script_does_not_match_the_stale_event():
    script = (
        Path(__file__).resolve().parents[2]
        / "deploy"
        / "sn39"
        / "cathedral-mismatch-check"
    ).read_text(encoding="utf-8")
    alerting = [
        line
        for line in script.splitlines()
        if line.startswith(("RECENT=", "FAILS=", "PASSES="))
    ]
    assert alerting, "the alert script no longer builds its match lines here"
    for escaped in alerting:
        line = escaped.replace("\\", "")
        assert '"event":"' in line, (
            "alerting must match the event FIELD, or a future event whose name "
            "contains an alerting name would alert too"
        )
        assert "PROVENANCE_VECTOR_STALE_EPOCH" not in line


# -- the lag bound is the safety of the whole classification -----------------


def test_a_vector_lagging_more_than_one_epoch_is_not_stale_but_wrong(fake_cathedral):
    """Beyond one epoch it is not a serving race.

    A publisher that stopped advancing, or a replay of an older genuinely
    signed vector, must keep firing PROVENANCE_VECTOR_MISMATCH: the recurring
    thin tick submits the signed vector whatever the audit concludes, so
    classifying this as merely stale would pin SN39 weights to an old epoch
    while emitting only the non-alerting event.
    """
    store = _BlobStore()
    # A POSITIVE epoch, three behind the verified one — so this exercises the
    # lag bound itself, not the negative-epoch guard beside it.
    older = STALE_EPOCH - 2
    rows = [
        _epoch_row(store, older, shares=SHARES),
        _epoch_row(store, STALE_EPOCH, shares=SHARES),
        _epoch_row(store, LATEST_EPOCH, shares=SHARES),
    ]
    assert (
        _classify(fake_cathedral, store, _vector(epoch=older, shares=SHARES), rows=rows)
        is None
    )


def test_the_lag_bound_is_exactly_one_epoch():
    assert pa.MAX_STALE_VECTOR_LAG_EPOCHS == 1
