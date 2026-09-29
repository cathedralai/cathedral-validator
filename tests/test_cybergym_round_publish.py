"""Carrying a round's scores to the publisher -- the step that turns them into weights.

The producer does NOT set weights: SN39 composes ONE vector (compute 0.70 + cybergym 0.30) at the
publisher, so a producer broadcasting its own would be a second writer for the same subnet.
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from cathedral_thin.cybergym_round_publish import (
    SCORE_UNITS, PublisherConfig, PublishError, RoundScorePublisher, round_report,
)

CONFIG = PublisherConfig(url="https://publisher.example/v1/cybergym/scores",
                         bearer_token="tok", hmac_secret="sec",
                         producer_hotkey="5Validator", network="finney", netuid=39)


def _report(**kw):
    kw.setdefault("nonce", "round-nonce")
    kw.setdefault("dispatched_units", 25.0)
    return round_report(kw.pop("round_id", 4), kw.pop("scores", {"5A": 100, "5B": 50}),
                        config=CONFIG, **kw)


class TestTheDocument:
    def test_the_round_id_is_the_epoch(self):
        """The ingest fences epochs strictly increasing per audience, and round ids already are."""
        assert _report(round_id=7)["source_epoch"] == 7

    def test_it_carries_exactly_what_the_ingest_accepts(self):
        doc = _report()
        assert set(doc) == {"producer_hotkey", "network", "netuid", "source_epoch", "generated_at",
                            "complete", "score_units", "scores", "evidence_sha256",
                            "nonce", "dispatched_units"}
        assert doc["complete"] is True and doc["score_units"] == SCORE_UNITS
        assert doc["network"] == "finney" and doc["netuid"] == 39

    def test_a_report_is_the_full_truth_at_its_round(self):
        """`complete: true` means an omitted miner scores zero rather than keeping a previous
        round's value -- the same rule single-round scoring pays by."""
        assert _report(scores={"5A": 100})["complete"] is True

    def test_the_tournament_inputs_are_required_here_even_though_the_wire_calls_them_optional(self):
        """Without a nonce the publisher composes a proportional split instead of the KING board,
        which is a different mechanism arriving silently."""
        with pytest.raises(PublishError, match="nonce is required"):
            round_report(4, {"5A": 1}, config=CONFIG, nonce="", dispatched_units=25.0)

    def test_an_unnamed_producer_is_refused(self):
        with pytest.raises(PublishError, match="producer_hotkey"):
            round_report(4, {"5A": 1}, config=PublisherConfig(), nonce="n", dispatched_units=1.0)

    def test_scores_become_plain_numbers(self):
        doc = _report(scores={"5A": Decimal("87.5"), "5B": "12", "5C": 0})
        assert doc["scores"] == {"5A": 87.5, "5B": 12.0, "5C": 0.0}

    def test_a_nonsense_score_is_refused_rather_than_coerced(self):
        with pytest.raises(PublishError, match="not a number"):
            _report(scores={"5A": "not-a-score"})
        with pytest.raises(PublishError, match="negative"):
            _report(scores={"5A": -1})

    def test_the_evidence_digest_covers_the_scores_that_were_sent(self):
        one, two = _report(scores={"5A": 1}), _report(scores={"5A": 2})
        assert one["evidence_sha256"] != two["evidence_sha256"]
        assert len(one["evidence_sha256"]) == 64


class TestPublishing:
    def test_it_is_off_until_credentials_exist(self):
        """Publishing is an explicit act. An unconfigured deployment keeps its local trail."""
        publisher = RoundScorePublisher(config=PublisherConfig(producer_hotkey="5Validator"))
        assert publisher.publish(4, {"5A": 1}, nonce="n", dispatched_units=1.0) is None
        assert publisher.published == []

    def test_what_is_missing_is_named(self):
        config = PublisherConfig(url="https://x/y", producer_hotkey="5Validator")
        assert "TOKEN" in config.why_disabled() and "HMAC_SECRET" in config.why_disabled()
        assert "URL" not in config.why_disabled()

    def test_it_sends_the_round_and_records_it(self):
        sent = {}

        def sender(document, config):
            sent.update(document=document, url=config.url)
            return {"accepted": True}

        publisher = RoundScorePublisher(config=CONFIG, sender=sender)
        assert publisher.publish(4, {"5A": 100}, nonce="n", dispatched_units=25.0)["accepted"]
        assert publisher.published == [4]
        assert sent["document"]["source_epoch"] == 4
        assert sent["document"]["scores"] == {"5A": 100.0}
        assert sent["url"] == CONFIG.url

    def test_the_wire_form_is_distills_canonical_bytes(self):
        """The body is authenticated by an HMAC over its EXACT bytes, so producer and publisher
        must agree byte-for-byte. Skipped where distill is not installed -- the box has it."""
        pytest.importorskip("cathedral_distill.cybergym_score_report")
        from cathedral_distill.cybergym_score_report import (
            canonical_report_bytes, normalize_report,
        )
        from cathedral_thin.cybergym_round_publish import send_via_distill

        captured = {}

        def fake_publish(*, url, body, bearer_token, hmac_secret, timeout_seconds):
            captured["body"] = body
            return {"accepted": True}

        import cathedral_distill.cybergym_score_report as report_module

        original = report_module.publish_score_report
        report_module.publish_score_report = fake_publish
        try:
            doc = _report()
            send_via_distill(doc, CONFIG)
        finally:
            report_module.publish_score_report = original
        assert captured["body"] == canonical_report_bytes(normalize_report(dict(doc)))

    def test_a_refusal_is_raised_with_the_reason_and_without_the_credentials(self):
        """The intake's own 4xx detail is the diagnosis; the bearer and HMAC secret are not."""
        def sender(document, config):
            raise RuntimeError("score intake refused the report with HTTP 409: epoch_too_old")

        publisher = RoundScorePublisher(config=CONFIG, sender=sender)
        with pytest.raises(PublishError) as exc:
            publisher.publish(4, {"5A": 1}, nonce="n", dispatched_units=1.0)
        assert "epoch_too_old" in str(exc.value)
        assert "tok" not in str(exc.value) and "sec" not in str(exc.value)
        assert publisher.published == []


def test_config_reads_the_environment(monkeypatch):
    monkeypatch.setenv("CYBERGYM_PUBLISH_URL", "https://p/v1/cybergym/scores")
    monkeypatch.setenv("CYBERGYM_PUBLISH_TOKEN", "t")
    monkeypatch.setenv("CYBERGYM_PUBLISH_HMAC_SECRET", "h")
    monkeypatch.setenv("CYBERGYM_VALIDATOR_HOTKEY", "5Validator")
    config = PublisherConfig.from_environment()
    assert config.enabled and config.producer_hotkey == "5Validator" and config.netuid == 39


class TestTheDenominatorDoesNotRescaleTheField:
    """The publisher computes `100 * solved / dispatched`. A round average is ALREADY base-100, so
    the only denominator that passes it through unchanged is 100 — and because that helper also
    CLAMPS solved > dispatched, a smaller one would not merely rescale the field, it would flatten
    every miner above the denominator to 100."""

    def test_the_constant_is_one_hundred(self):
        from cathedral_thin.cybergym_round_runtime import PUBLISHED_SCORE_DENOMINATOR

        assert PUBLISHED_SCORE_DENOMINATOR == 100.0

    def test_round_trip_through_the_publishers_own_formula_is_identity(self):
        pytest.importorskip("scaffold.publisher.cybergym_tournament")
        from scaffold.publisher.cybergym_tournament import epoch_score_base100

        from cathedral_thin.cybergym_round_runtime import PUBLISHED_SCORE_DENOMINATOR

        for score in ("0", "7.5", "42", "99.9", "100"):
            assert epoch_score_base100(score, PUBLISHED_SCORE_DENOMINATOR) == Decimal(score)

    def test_a_wrong_denominator_would_flatten_the_field(self):
        """Stated as a test so the constant is never 'simplified' to the round's task count.

        Through the adapter's own path, which CLAMPS solved to dispatched before dividing: send
        base-100 averages with the task count as the denominator and two clearly different miners
        become a tie, which the tie-break then decides by digest. The raw helper raises instead of
        clamping, so the failure mode depends on the path -- flattening here, a burnt lane there.
        """
        pytest.importorskip("scaffold.publisher.mechanism_cybergym_adapter")
        from scaffold.publisher.mechanism_cybergym_adapter import _epoch_base100

        doc = {"scores": {"5A": 40.0, "5B": 90.0}, "dispatched_units": 25}
        assert _epoch_base100(doc) == {"5A": Decimal(100), "5B": Decimal(100)}

        right = {"scores": {"5A": 40.0, "5B": 90.0}, "dispatched_units": 100}
        assert _epoch_base100(right) == {"5A": Decimal(40), "5B": Decimal(90)}


class TestTheProducerPathIsWiredEndToEnd:
    """The wiring is the whole point: a publisher that exists but is never called turns no scores
    into weights, and nothing else in the system would notice."""

    def test_composing_a_round_publishes_its_scores(self):
        from cathedral_thin.cybergym_round_runtime import compose_and_set

        published = {}

        class Recorder:
            def publish(self, round_id, scores, *, nonce, dispatched_units):
                published.update(round_id=round_id, scores=dict(scores), nonce=nonce,
                                 dispatched_units=dispatched_units)
                return {"accepted": True}

        class Client:
            def fetch_average_scores(self, round_id):
                return {"5A": Decimal("100"), "5B": Decimal("40")}

        board = compose_and_set(3, client=Client(), set_weights=lambda w: None,
                                nonce=bytes([1, 2]), publisher=Recorder())
        assert board.winners == ("5A", "5B")
        # the SCORES, not the composed shares: the publisher runs the tournament itself
        assert published["scores"] == {"5A": Decimal("100"), "5B": Decimal("40")}
        assert published["round_id"] == 3 and published["dispatched_units"] == 100.0
        assert published["nonce"] == "0102"

    def test_a_round_with_no_publisher_still_composes_and_records(self):
        from cathedral_thin.cybergym_round_runtime import compose_and_set

        recorded = []

        class Client:
            def fetch_average_scores(self, round_id):
                return {"5A": Decimal("100")}

        board = compose_and_set(3, client=Client(), set_weights=recorded.append,
                                nonce=bytes([1]), publisher=None)
        assert board.winners == ("5A",) and len(recorded) == 1

    def test_the_daemon_carries_the_publisher_into_the_step(self):
        import inspect

        from cathedral_thin.cybergym_round_daemon import RoundDaemon

        assert "publisher" in inspect.signature(RoundDaemon).parameters
        source = inspect.getsource(RoundDaemon.tick)
        assert "publisher=self.publisher" in source, "the daemon must pass it to step()"
