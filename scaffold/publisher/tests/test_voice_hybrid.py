"""Publisher admission gates for source=cathedral_voice_hybrid."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from scaffold.publisher import external_scores, weights
from scaffold.publisher import voice_hybrid


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _measurement(*, simulated: bool = False, hotkey: str = "5Alice") -> dict:
    return {
        "format": voice_hybrid.MEASUREMENT_FORMAT,
        "mrtd": "00" * 48,
        "quote": "aa" * 32,
        "hotkey": hotkey,
        "simulated": simulated,
        "debug": False,
    }


def _receipt(*, hotkey: str = "5Alice", simulated: bool = False, **overrides) -> dict:
    base = {
        "version": voice_hybrid.RECEIPT_VERSION,
        "status": "ok",
        "miner_hotkey": hotkey,
        "request_hash": "bb" * 32,
        "audio_content_hash": "cc" * 32,
        "signature": "dd" * 32,
        "gpu_attested": False,
        "gpu_memory_confidential": False,
        "controller_measurement": _measurement(simulated=simulated, hotkey=hotkey),
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def _local_audience(monkeypatch):
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_NETWORK", "finney")
    monkeypatch.setenv("CATHEDRAL_WEIGHT_POLICY_NETUID", "39")


def _hybrid_report(*, scores=None, metadata=None, complete=True, **overrides) -> dict:
    report = {
        "source": "cathedral_voice_hybrid",
        "network": "finney",
        "netuid": 39,
        "epoch": 1,
        "complete": complete,
        "generated_at": _iso(_now()),
        "metadata": metadata
        if metadata is not None
        else {
            "receipt_verified": True,
            "gpu_attested": False,
            "gpu_memory_confidential": False,
        },
        "scores": scores
        if scores is not None
        else [
            {
                "miner_hotkey": "5Alice",
                "score": 0.7,
                "receipt": _receipt(),
            }
        ],
    }
    report.update(overrides)
    return report


def test_voice_hybrid_source_allowed():
    assert "cathedral_voice_hybrid" in external_scores.ALLOWED_ENDPOINT_SOURCES
    assert "cathedral_voice_hybrid" in external_scores.COMPLETE_REQUIRED_SOURCES
    assert "cathedral_voice_hybrid" in external_scores.MANDATORY_HMAC_SOURCES
    assert "cathedral_voice_hybrid" not in weights.EXTERNAL_SCORES_FRACTION_EXEMPT_SOURCES
    assert "cathedral_voice_hybrid" in weights.EXTERNAL_SCORES_NO_PRIMARY_SOURCES
    assert "cathedral_voice_hybrid" not in weights.EXTERNAL_SCORES_GLOBAL_CAP_SOURCES
    assert "cathedral_voice_hybrid" not in weights.CONFIDENTIAL_PRIMARY_SOURCES


def test_voice_hybrid_requires_local_audience(monkeypatch):
    now = _now()
    with pytest.raises(
        external_scores.ExternalScoreError, match="invalid_score_audience"
    ):
        external_scores.normalize_report(
            _hybrid_report(network=None, netuid=None),
            now=now,
        )


def test_voice_hybrid_rejects_audience_mismatch():
    now = _now()
    with pytest.raises(
        external_scores.ExternalScoreError, match="score_audience_mismatch"
    ):
        external_scores.normalize_report(
            _hybrid_report(network="test", netuid=292),
            now=now,
        )


def test_voice_hybrid_fails_closed_when_audience_unconfigured(monkeypatch):
    monkeypatch.delenv("CATHEDRAL_WEIGHT_POLICY_NETWORK", raising=False)
    monkeypatch.delenv("CATHEDRAL_WEIGHT_POLICY_NETUID", raising=False)
    now = _now()
    with pytest.raises(
        external_scores.ExternalScoreError, match="score_audience_not_configured"
    ):
        external_scores.normalize_report(_hybrid_report(), now=now)


def test_voice_hybrid_requires_complete_true():
    now = _now()
    with pytest.raises(
        external_scores.ExternalScoreError, match="complete_required_for_source"
    ):
        external_scores.normalize_report(
            _hybrid_report(complete=False),
            now=now,
        )


def test_voice_hybrid_requires_receipt_verified_metadata():
    now = _now()
    with pytest.raises(
        external_scores.ExternalScoreError, match="receipt_verified_required"
    ):
        external_scores.normalize_report(
            _hybrid_report(metadata={}),
            now=now,
        )


def test_voice_hybrid_rejects_positive_score_without_receipt():
    now = _now()
    with pytest.raises(external_scores.ExternalScoreError, match="receipt_missing_0"):
        external_scores.normalize_report(
            _hybrid_report(
                scores=[{"miner_hotkey": "5Alice", "score": 0.5}],
            ),
            now=now,
        )


def test_voice_hybrid_allows_zero_score_without_receipt():
    now = _now()
    report = external_scores.normalize_report(
        _hybrid_report(
            scores=[{"miner_hotkey": "5Alice", "score": 0.0}],
        ),
        now=now,
    )
    assert report["scores"][0]["score"] == 0.0
    assert "receipt" not in report["scores"][0]


def test_voice_hybrid_rejects_gpu_attested_claims():
    now = _now()
    with pytest.raises(
        external_scores.ExternalScoreError, match="gpu_attested_forbidden_0"
    ):
        external_scores.normalize_report(
            _hybrid_report(
                scores=[
                    {
                        "miner_hotkey": "5Alice",
                        "score": 0.5,
                        "receipt": _receipt(gpu_attested=True),
                    }
                ],
            ),
            now=now,
        )


def test_voice_hybrid_rejects_simulated_tdx_by_default(monkeypatch):
    monkeypatch.delenv("CATHEDRAL_VOICE_HYBRID_ALLOW_SIMULATION", raising=False)
    now = _now()
    with pytest.raises(
        external_scores.ExternalScoreError, match="tdx_simulation_forbidden_0"
    ):
        external_scores.normalize_report(
            _hybrid_report(
                scores=[
                    {
                        "miner_hotkey": "5Alice",
                        "score": 0.5,
                        "receipt": _receipt(simulated=True),
                    }
                ],
            ),
            now=now,
        )


def test_voice_hybrid_allows_simulation_when_explicitly_enabled(monkeypatch):
    monkeypatch.setenv("CATHEDRAL_VOICE_HYBRID_ALLOW_SIMULATION", "1")
    now = _now()
    report = external_scores.normalize_report(
        _hybrid_report(
            scores=[
                {
                    "miner_hotkey": "5Alice",
                    "score": 0.5,
                    "receipt": _receipt(simulated=True),
                }
            ],
        ),
        now=now,
    )
    assert report["scores"][0]["receipt"]["version"] == voice_hybrid.RECEIPT_VERSION


def test_voice_hybrid_preserves_receipt_on_normalize():
    now = _now()
    report = external_scores.normalize_report(_hybrid_report(), now=now)
    assert report["source"] == "cathedral_voice_hybrid"
    assert report["complete"] is True
    assert report["scores"][0]["receipt"]["miner_hotkey"] == "5Alice"
    assert report["metadata"]["receipt_verified"] is True


def test_voice_hybrid_external_primary_blocked(monkeypatch):
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_SOURCE", "cathedral_voice_hybrid")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_MODE", "external_primary")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_PRIMARY_CONFIRM", "true")
    assert weights.external_scores_mode() == "blend"


def test_voice_hybrid_requires_explicit_fraction(monkeypatch):
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_ENABLED", "1")
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_SOURCE", "cathedral_voice_hybrid")
    monkeypatch.delenv("CATHEDRAL_EXTERNAL_SCORES_FRACTION", raising=False)
    monkeypatch.delenv("CATHEDRAL_EXTERNAL_SCORES_BASE_WEIGHT", raising=False)
    monkeypatch.delenv("CATHEDRAL_EXTERNAL_SCORES_WEIGHT", raising=False)
    base_w, ext_w, frac = weights._external_blend_weights()
    assert abs(base_w - 1.0) < 1e-9
    assert abs(ext_w - 0.0) < 1e-9
    assert abs(frac - 0.0) < 1e-9


def test_voice_hybrid_dedicated_token_isolated(monkeypatch):
    monkeypatch.setenv(
        "CATHEDRAL_EXTERNAL_SCORES_TOKEN_CATHEDRAL_VOICE_HYBRID",
        "hybrid_token",
    )
    monkeypatch.setenv("CATHEDRAL_EXTERNAL_SCORES_TOKEN", "shared_token")
    assert not external_scores.bearer_authorized_for_source(
        "cathedral_voice_hybrid",
        authorization="Bearer shared_token",
    )
    assert external_scores.bearer_authorized_for_source(
        "cathedral_voice_hybrid",
        authorization="Bearer hybrid_token",
    )
    assert not external_scores.bearer_authorized_for_source(
        "violet_audio",
        authorization="Bearer hybrid_token",
    )


def test_voice_hybrid_hmac_mandatory(monkeypatch):
    monkeypatch.delenv(
        "CATHEDRAL_EXTERNAL_SCORES_HMAC_SECRET_CATHEDRAL_VOICE_HYBRID",
        raising=False,
    )
    monkeypatch.delenv("CATHEDRAL_EXTERNAL_SCORES_HMAC_SECRET", raising=False)
    ok, required = external_scores.verify_hmac_for_source(
        "cathedral_voice_hybrid",
        b"{}",
        None,
    )
    assert required is True
    assert ok is False
