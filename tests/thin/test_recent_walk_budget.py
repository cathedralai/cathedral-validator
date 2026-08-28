"""The recent-chain walk sizes itself to the audit's artifact budget.

Each walked link costs RECENT_WALK_BLOBS_PER_LINK fetches (manifest, policy
registry, score report) against the audit's one artifact cap, and the audit
has already spent on the index, the latest manifest/registry/report, and every
receipt before the bridge runs. MAX_RECENT_WALK=96 was therefore never
affordable: a tip more than ~84 links behind died mid-walk on "audit exceeded
its artifact cap", and once the tip aged out of the bounded window entirely
the first walked link's predecessor check reported a chain break that never
happened (issue #64).

The bridge now distinguishes three conditions BEFORE spending any fetches:
a tip that aged out of the signed window, a gap wider than the remaining
budget affords (both require a future reviewed reconciliation command), and a
link that fails inside the walk — only that last one is a chain break.
"""

from __future__ import annotations

import hashlib
import json
import sys
import types

import pytest

from scaffold import provenance_audit as pa

NETWORK = "finney"
NETUID = 39
GENERATED_AT = "2026-08-04T12:00:00+00:00"


class _FakeProvenanceError(Exception):
    pass


@pytest.fixture()
def fake_cathedral(monkeypatch):
    """A cathedral library stand-in: JSON manifests, chain-checking reports.

    verify_report_structure enforces exactly the contract the bridge leans
    on — the report must cite the expected predecessor — and raises the
    library's real complaint text on a mismatch so the tests can assert the
    bridge no longer surfaces it for an unreachable tip.
    """
    provenance = types.ModuleType("cathedral.provenance")
    provenance.ProvenanceError = _FakeProvenanceError

    def load_registry(blob, keys, **_kwargs):
        return json.loads(blob)

    def verify_report_structure(report_bytes, *, expected_previous_report_id, **_kw):
        document = json.loads(report_bytes)
        if document["previous_report_id"] != expected_previous_report_id:
            raise _FakeProvenanceError(
                "score report previous_report_id breaks the recorded export chain"
            )
        return document

    provenance.load_registry = load_registry
    provenance.verify_report_structure = verify_report_structure
    evidence = types.ModuleType("cathedral.evidence")
    evidence.parse_manifest = json.loads
    package = types.ModuleType("cathedral")
    package.provenance = provenance
    package.evidence = evidence
    monkeypatch.setitem(sys.modules, "cathedral", package)
    monkeypatch.setitem(sys.modules, "cathedral.provenance", provenance)
    monkeypatch.setitem(sys.modules, "cathedral.evidence", evidence)


class _BlobStore:
    """Content-addressed blob fake that counts every fetch it serves."""

    def __init__(self):
        self.blobs: dict[str, bytes] = {}
        self.calls = 0

    def add(self, payload) -> str:
        data = json.dumps(payload).encode()
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        self.blobs[digest] = data
        return digest

    def __call__(self, digest: str) -> bytes:
        self.calls += 1
        return self.blobs[digest]


def _chain(store, epochs, *, tip_report_id, tip_epoch=100, forge_previous_at=None):
    """Signed-index rows for ``epochs``, each link citing its predecessor.

    The window opens with the tip's own row at ``tip_epoch`` (pass None to
    model a tip that aged out of the window); the walk filters it out, so it
    is never fetched. ``forge_previous_at`` makes that epoch's report cite a
    fabricated predecessor: a genuine in-walk chain break.
    """
    rows = []
    if tip_epoch is not None:
        rows.append({"source_epoch": tip_epoch, "manifest": store.add({"tip": True})})
    previous = tip_report_id
    for epoch in epochs:
        report_id = f"report-{epoch}"
        cited = "report-forged" if epoch == forge_previous_at else previous
        report = {
            "generated_at": GENERATED_AT,
            "source_epoch": epoch,
            "report_id": report_id,
            "previous_report_id": cited,
        }
        manifest = {
            "network": NETWORK,
            "netuid": NETUID,
            "source_epoch": epoch,
            "policy_registry": {
                "release": 7,
                "digest": "policy-digest-7",
                "blob": store.add({"registry_for": epoch}),
            },
            "score_report": {"blob": store.add(report), "report_id": report_id},
        }
        rows.append({"source_epoch": epoch, "manifest": store.add(manifest)})
        previous = report_id
    return rows, previous


def _bridge(recent_rows, load_blob, **over):
    kwargs = {
        "settings": pa.ProvenanceSettings(
            mode="shadow",
            evidence_url="https://api.example.test/v1/evidence",
            verifier_digest="sha256:" + "0" * 64,
        ),
        "network": NETWORK,
        "netuid": NETUID,
        "registry_keys": {},
        "report_keys": {},
        "state": {},
        "last_epoch": 100,
        "last_report_id": "report-100",
        "latest_epoch": 1000,
        "latest_previous_report_id": None,
        "load_blob": load_blob,
        "artifacts_remaining": 252,
    }
    kwargs.update(over)
    return pa._verify_recent_chain_bridge(recent_rows, **kwargs)


# -- the healthy path stays healthy -----------------------------------------


def test_a_short_walk_within_budget_still_passes(fake_cathedral):
    store = _BlobStore()
    rows, final_report_id = _chain(store, [200, 300], tip_report_id="report-100")
    _bridge(rows, store, latest_previous_report_id=final_report_id)


def test_each_walked_link_costs_exactly_the_declared_blob_count(fake_cathedral):
    # The affordability arithmetic rests on this constant matching the loop.
    store = _BlobStore()
    rows, final_report_id = _chain(store, [200, 300, 400], tip_report_id="report-100")
    _bridge(rows, store, latest_previous_report_id=final_report_id)
    assert store.calls == 3 * pa.RECENT_WALK_BLOBS_PER_LINK


def test_a_local_store_walk_is_not_budget_bounded(fake_cathedral):
    # evidence_dir audits carry no artifact cap; None must mean unlimited,
    # never zero.
    store = _BlobStore()
    rows, final_report_id = _chain(store, [200, 300], tip_report_id="report-100")
    _bridge(
        rows,
        store,
        latest_previous_report_id=final_report_id,
        artifacts_remaining=None,
    )


# -- an unreachable tip names its condition, before spending anything -------


def test_a_gap_beyond_the_affordable_walk_requires_reviewed_reconciliation(
    fake_cathedral,
):
    store = _BlobStore()
    rows, final_report_id = _chain(
        store, [200, 300, 400, 500], tip_report_id="report-100"
    )
    # 11 remaining artifacts afford 3 links; the gap is 4 links wide.
    with pytest.raises(
        pa.ProvenanceAuditError,
        match=r"4 links behind.*affords only 3 links.*reconciliation command",
    ) as excinfo:
        _bridge(
            rows,
            store,
            latest_previous_report_id=final_report_id,
            artifacts_remaining=11,
        )
    assert "breaks the recorded export chain" not in str(excinfo.value)
    assert "artifact cap" not in str(excinfo.value)
    # Fail-closed BEFORE the walk: an unaffordable gap must not burn budget
    # the rest of the audit was never going to get back.
    assert store.calls == 0


def test_a_tip_that_aged_out_requires_reviewed_reconciliation(fake_cathedral):
    store = _BlobStore()
    # No row at or below the tip's epoch survives in the signed window, so
    # continuity back to the tip is unprovable — not broken.
    rows, final_report_id = _chain(
        store, [200, 300], tip_report_id="report-150", tip_epoch=None
    )
    with pytest.raises(
        pa.ProvenanceAuditError,
        match=r"aged out.*oldest retained epoch 200.*reconciliation command",
    ) as excinfo:
        _bridge(rows, store, latest_previous_report_id=final_report_id)
    assert "breaks the recorded export chain" not in str(excinfo.value)
    assert "does not chain" not in str(excinfo.value)
    assert store.calls == 0


def test_the_hard_window_bound_still_backstops_a_verifier_regression(fake_cathedral):
    store = _BlobStore()
    epochs = [200 + 10 * step for step in range(pa.MAX_RECENT_WALK + 1)]
    rows, final_report_id = _chain(store, epochs, tip_report_id="report-100")
    with pytest.raises(pa.ProvenanceAuditError, match="exceeds the bounded window"):
        _bridge(
            rows,
            store,
            latest_previous_report_id=final_report_id,
            latest_epoch=10_000,
            artifacts_remaining=10_000,
        )
    assert store.calls == 0


@pytest.mark.parametrize("bad", [True, "252", 2.5])
def test_a_non_integer_budget_is_refused(fake_cathedral, bad):
    store = _BlobStore()
    rows, final_report_id = _chain(store, [200], tip_report_id="report-100")
    with pytest.raises(pa.ProvenanceAuditError, match="integer artifact budget"):
        _bridge(
            rows,
            store,
            latest_previous_report_id=final_report_id,
            artifacts_remaining=bad,
        )


# -- a genuine break inside the walk is still a break -----------------------


def test_an_in_walk_predecessor_mismatch_is_still_a_chain_break(fake_cathedral):
    store = _BlobStore()
    rows, final_report_id = _chain(
        store, [200, 300], tip_report_id="report-100", forge_previous_at=300
    )
    with pytest.raises(
        pa.ProvenanceAuditError,
        match=r"link for epoch 300 failed verification.*breaks the recorded",
    ) as excinfo:
        _bridge(rows, store, latest_previous_report_id=final_report_id)
    assert "reconciliation command" not in str(excinfo.value)


def test_a_completed_walk_whose_last_link_is_not_cited_is_still_a_break(
    fake_cathedral,
):
    store = _BlobStore()
    rows, _final = _chain(store, [200, 300], tip_report_id="report-100")
    with pytest.raises(
        pa.ProvenanceAuditError, match="does not chain from the last audited"
    ):
        _bridge(rows, store, latest_previous_report_id="report-somewhere-else")


# -- the live budget is exposed where run_audit reads it --------------------


def test_the_network_fetcher_exposes_its_live_artifact_budget(monkeypatch):
    monkeypatch.setattr(
        pa,
        "_getaddrinfo_bounded",
        lambda host, port, timeout: [(None, None, None, None, ("203.0.113.5", 443))],
    )
    settings = pa.ProvenanceSettings(
        mode="shadow",
        evidence_url="https://api.example.test/v1/evidence",
        allow_private_hosts=True,
    )
    _load_index, load_blob = pa._fetcher(settings)
    assert load_blob.artifacts_remaining() == 256


def test_the_local_store_fetcher_reports_no_cap(tmp_path):
    settings = pa.ProvenanceSettings(mode="shadow", evidence_dir=str(tmp_path))
    _load_index, load_blob = pa._fetcher(settings)
    assert load_blob.artifacts_remaining() is None
