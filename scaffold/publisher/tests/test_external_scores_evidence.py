"""A positive external score must be evidenced, or be visibly refusable.

The normalized entry schema carried no receipt, quote, attestation or
signature-over-work field, so ``{"miner_hotkey": "X", "score": 1.0}`` was full
credit on a shared-secret HMAC over the request body alone. These tests pin the
optional per-entry evidence field, the default-permissive warning that tells an
operator how much of the live vector is unevidenced, and the fail-closed
enforcement path that is off by default.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import pytest

from scaffold.publisher import external_scores
from scaffold.publisher.external_scores import ExternalScoreError

LOGGER_NAME = "scaffold.publisher.external_scores"
# Literal, not the module constant: this must fail on behaviour, not on a name.
REQUIRE_EVIDENCE_ENV = "CATHEDRAL_EXTERNAL_SCORES_REQUIRE_EVIDENCE"
EVIDENCE_DIGEST = "a" * 64


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _report(scores, *, source="violet_audio", epoch=7):
    return {
        "source": source,
        "epoch": epoch,
        "complete": True,
        "generated_at": _iso(datetime.now(timezone.utc)),
        "scores": scores,
    }


def _tdx_report(scores, *, epoch=41):
    report = _report(scores, source="cathedral_confidential_tdx", epoch=epoch)
    report["network"] = "finney"
    report["netuid"] = 39
    return report


@pytest.fixture
def tdx_audience(monkeypatch):
    monkeypatch.setenv(external_scores.WEIGHT_POLICY_NETWORK_ENV, "finney")
    monkeypatch.setenv(external_scores.WEIGHT_POLICY_NETUID_ENV, "39")


def test_unevidenced_positive_score_warns_while_permissive(caplog):
    """Default (permissive) intake still tells the operator what it just took."""
    payload = _report([{"miner_hotkey": "5Fminer", "score": 1.0}])
    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        report = external_scores.normalize_report(payload)

    assert report["scores"][0]["score"] == 1.0  # permissive: still full credit
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("5Fminer" in message for message in warnings), warnings
    assert any("unevidenced" in message for message in warnings), warnings


def test_enforcement_zeroes_an_unevidenced_positive_score(monkeypatch):
    """Fail closed: no evidence is zero credit, never a discounted score."""
    monkeypatch.setenv(REQUIRE_EVIDENCE_ENV, "1")
    payload = _report([
        {"miner_hotkey": "5Fminer", "score": 1.0},
        {"miner_hotkey": "5Fother", "score": 0.4},
    ])
    report = external_scores.normalize_report(payload)
    assert [s["score"] for s in report["scores"]] == [0.0, 0.0]


def test_evidenced_score_keeps_full_credit_under_enforcement(monkeypatch):
    monkeypatch.setenv(REQUIRE_EVIDENCE_ENV, "1")
    payload = _report([{
        "miner_hotkey": "5Fminer",
        "score": 1.0,
        "evidence": {
            "evidence_sha256": EVIDENCE_DIGEST,
            "kind": "cybergym_receipt_manifest",
            "receipt_id": "receipt-1",
        },
    }])
    entry = external_scores.normalize_report(payload)["scores"][0]
    assert entry["score"] == 1.0
    assert entry["evidence"] == {
        "evidence_sha256": EVIDENCE_DIGEST,
        "kind": "cybergym_receipt_manifest",
        "receipt_id": "receipt-1",
    }


@pytest.mark.parametrize("evidence", [
    "just-a-string",
    {},
    {"evidence_sha256": "not-a-digest"},
    {"evidence_sha256": EVIDENCE_DIGEST.upper()},
    {"evidence_sha256": EVIDENCE_DIGEST, "surprise": "field"},
    {"evidence_sha256": EVIDENCE_DIGEST, "kind": ""},
])
def test_malformed_evidence_is_rejected_even_while_permissive(evidence):
    """A junk evidence block must be a hard reject, not a silently dropped key."""
    payload = _report([{"miner_hotkey": "5Fminer", "score": 1.0, "evidence": evidence}])
    with pytest.raises(ExternalScoreError) as exc:
        external_scores.normalize_report(payload)
    assert exc.value.reason == "invalid_evidence_0"


def test_permissive_default_leaves_the_report_digest_untouched():
    """Merging this alone changes nothing in production.

    ``report_sha256`` is the epoch fence and the idempotent-retry key, so an
    unevidenced report must canonicalize to the exact bytes it did before the
    evidence field existed. The digest below was computed on the unmodified
    module.
    """
    payload = _report([{"miner_hotkey": "5Fminer", "score": 1.0}])
    payload["generated_at"] = "2026-08-13T00:00:00.000Z"
    report = external_scores.normalize_report(
        payload, now=datetime(2026, 8, 13, 0, 0, 30, tzinfo=timezone.utc)
    )
    assert "evidence" not in report["scores"][0]
    assert report["report_sha256"] == (
        "a22876bf9f0e4995b8eea930f5b9d0c62b06b05fc01a70868ca33b4b52be2bf0"
    )


def test_live_shaped_tdx_report_is_fully_refused_under_enforcement(
    monkeypatch, tdx_audience, caplog
):
    """How much of a realistic live vector would enforcement refuse today.

    The 90% confidential-TDX lane emits the schema below and nothing else, so
    the answer is all of it.
    """
    live_scores = [
        {"miner_hotkey": f"5F{index:038d}", "uid": index, "score": 0.9,
         "tasks_scored": 12, "meta": {"lane": "tdx"}}
        for index in range(64)
    ]
    payload = _tdx_report(live_scores)

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        permissive = external_scores.normalize_report(payload)
    credited_permissive = sum(1 for s in permissive["scores"] if s["score"] > 0)
    assert credited_permissive == 64

    monkeypatch.setenv(REQUIRE_EVIDENCE_ENV, "1")
    enforced = external_scores.normalize_report(payload)
    credited_enforced = sum(1 for s in enforced["scores"] if s["score"] > 0)
    refused_fraction = 1.0 - (credited_enforced / credited_permissive)
    assert refused_fraction == 1.0

    warned = [r.getMessage() for r in caplog.records if "unevidenced" in r.getMessage()]
    assert len(warned) >= 64  # one per unevidenced positive score
