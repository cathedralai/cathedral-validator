"""Carry a finished round's scores to the publisher, which is what turns them into weights.

The v2 round daemon does NOT set weights. SN39 has ONE weight vector -- the publisher composes the
compute lane's 0.70 with the CyberGym lane's 0.30 and sends a single `set_weights` -- so a producer
that broadcast its own vector would be a second writer for the same subnet from the same hotkey,
and the last writer would win. `FileWeightSink` is therefore the CORRECT local behaviour for a
producer, not a placeholder for a chain call.

What was missing is the transport: `cybergym_ingest` on the publisher exists precisely because
"nothing previously carried [producer scores] into the publisher's database". This module is the
producer end of that wire.

**It reuses distill's canonicalisation rather than reimplementing it.** The body is authenticated
by an HMAC over its EXACT bytes, so producer and publisher must agree byte-for-byte on how a report
is serialised. Two implementations of that would agree until the day they did not, and the failure
would look like an authentication error at the compose block. `cathedral_distill.cybergym_score_report`
already owns those bytes (`normalize_report`, `canonical_report_bytes`, `body_hmac`,
`publish_score_report`), so this builds the document and hands it over.

Default OFF: without an endpoint, a bearer token and an HMAC secret, a deployment keeps recording
to its file and says so. Publishing is an explicit act with credentials behind it.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Mapping

#: The unit label that travels with the scores. The lane reports a base-100 round score -- the
#: share of the round's authoritative task set a miner actually solved, benchmarked by validators.
SCORE_UNITS = "cybergym_round_base100"


class PublishError(RuntimeError):
    """The round's scores could not be published. Never carries the bearer or the HMAC secret."""


@dataclass
class PublisherConfig:
    """Where the producer posts, and who it claims to be. All of it from the environment."""

    url: str = ""
    bearer_token: str = ""
    hmac_secret: str = ""
    producer_hotkey: str = ""
    network: str = "finney"
    netuid: int = 39
    timeout_seconds: float = 15.0
    allow_unattested: bool = False

    @classmethod
    def from_environment(cls) -> "PublisherConfig":
        return cls(
            url=os.environ.get("CYBERGYM_PUBLISH_URL", "").strip(),
            bearer_token=os.environ.get("CYBERGYM_PUBLISH_TOKEN", "").strip(),
            hmac_secret=os.environ.get("CYBERGYM_PUBLISH_HMAC_SECRET", "").strip(),
            producer_hotkey=os.environ.get("CYBERGYM_VALIDATOR_HOTKEY", "").strip(),
            network=os.environ.get("CYBERGYM_NETWORK", "finney").strip() or "finney",
            netuid=int(os.environ.get("CYBERGYM_NETUID", "39")),
            timeout_seconds=float(os.environ.get("CYBERGYM_PUBLISH_TIMEOUT", "15")),
        )

    @property
    def enabled(self) -> bool:
        return bool(self.url and self.bearer_token and self.hmac_secret)

    def why_disabled(self) -> str:
        """What is missing, named. 'Publishing is off' with no reason is an operator's bad day."""
        missing = [
            name
            for name, value in (
                ("CYBERGYM_PUBLISH_URL", self.url),
                ("CYBERGYM_PUBLISH_TOKEN", self.bearer_token),
                ("CYBERGYM_PUBLISH_HMAC_SECRET", self.hmac_secret),
            )
            if not value
        ]
        return ", ".join(missing)


def round_report(
    round_id: int,
    scores: Mapping[str, Decimal | float | int | str],
    *,
    config: PublisherConfig,
    nonce: str,
    dispatched_units: float,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """The document the publisher's ingest accepts, for ONE round.

    ``source_epoch`` is the round id: the ingest fences epochs strictly increasing per audience,
    and round ids already are. ``complete`` is always true, which is the ingest's own posture --
    a round report is the full truth at its epoch, so a miner omitted here scores zero rather than
    keeping a previous round's value. That is the same rule the lane scores by.

    ``nonce`` and ``dispatched_units`` are the optional tournament inputs; without them the
    publisher falls back to a proportional split instead of the KING curve, so they are required
    HERE even though the wire treats them as optional.
    """
    if not config.producer_hotkey:
        raise PublishError(
            "producer_hotkey is required: the ingest binds one signer per audience"
        )
    if not nonce:
        raise PublishError(
            "nonce is required: without it the publisher composes a proportional split rather "
            "than the round's KING board"
        )
    numeric: dict[str, float] = {}
    for hotkey, value in scores.items():
        try:
            numeric[str(hotkey)] = float(Decimal(str(value)))
        except Exception as exc:
            raise PublishError(
                f"score for {hotkey!r} is not a number: {value!r}"
            ) from exc
        if numeric[str(hotkey)] < 0:
            raise PublishError(f"score for {hotkey!r} is negative")
    document = {
        "producer_hotkey": config.producer_hotkey,
        "network": config.network,
        "netuid": int(config.netuid),
        "source_epoch": int(round_id),
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "complete": True,
        "score_units": SCORE_UNITS,
        "scores": numeric,
        # The round's own evidence: the scores as the producer composed them. It is a digest of
        # what was sent, so a stored report can be checked against a producer's own record.
        "evidence_sha256": hashlib.sha256(
            json.dumps(numeric, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "nonce": nonce,
        "dispatched_units": float(dispatched_units),
    }
    return document


def send_via_distill(document: Mapping[str, Any], config: PublisherConfig) -> dict:
    """Serialise and POST, using distill's canonical bytes.

    Kept as one step on purpose: the body is authenticated by an HMAC over its EXACT bytes, so the
    serialisation and the send must never drift apart -- and distill owns that form. A second
    implementation here would agree until the day it did not, and the failure would surface as an
    authentication error at the compose block.
    """
    try:
        from cathedral_distill.cybergym_score_report import (
            canonical_report_bytes,
            normalize_report,
            publish_score_report,
        )
    except ImportError as exc:  # pragma: no cover - exercised by the box, not by CI
        raise PublishError(
            "cathedral_distill is required to publish: it owns the canonical byte form the "
            "publisher authenticates. Install the distill extra or put it on PYTHONPATH."
        ) from exc
    body = canonical_report_bytes(normalize_report(dict(document)))
    return publish_score_report(
        url=config.url,
        body=body,
        bearer_token=config.bearer_token,
        hmac_secret=config.hmac_secret,
        timeout_seconds=config.timeout_seconds,
    )


@dataclass
class RoundScorePublisher:
    """Posts one round's scores, once. Failure is reported, never silently swallowed."""

    config: PublisherConfig = field(default_factory=PublisherConfig)
    #: (document, config) -> result. Injected by tests; production serialises via distill.
    sender: Callable[[Mapping[str, Any], PublisherConfig], dict] = send_via_distill
    published: list[int] = field(default_factory=list)

    def publish(
        self,
        round_id: int,
        scores: Mapping[str, Any],
        *,
        nonce: str,
        dispatched_units: float,
    ) -> dict | None:
        """Publish, or return None when publishing is not configured."""
        if not self.config.enabled:
            return None
        document = round_report(
            round_id,
            scores,
            config=self.config,
            nonce=nonce,
            dispatched_units=dispatched_units,
        )
        try:
            result = self.sender(document, self.config)
        except PublishError:
            raise
        except Exception as exc:
            # The message may quote the intake's response; it never quotes our credentials.
            raise PublishError(f"round {round_id} was not published: {exc}") from exc
        self.published.append(int(round_id))
        return result


__all__ = [
    "PublisherConfig",
    "RoundScorePublisher",
    "PublishError",
    "round_report",
    "send_via_distill",
    "SCORE_UNITS",
]
