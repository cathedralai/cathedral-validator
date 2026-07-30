"""Independent validator-side verification that a CyberGym producer epoch closed COMPLETE.

Why this exists. The integration seam verifies each CyberGym *receipt*: signature,
anchored key, epoch, and the finalized block window. Nothing proved the other half of
the reward question, which is a property of the epoch rather than of any one receipt:
did the producer finish scoring that epoch, and is the set of miners it scored the
complete set?

That gap is not academic. cathedral-distill records completeness in its own
``cybergym_epoch_status`` table, in a SQLite file on the host that writes the scores.
The publisher receives scores over an authenticated HTTP intake, so that marker never
crosses the boundary: a consumer on the far side cannot read it, and a consumer that
assumes it can will treat "scoring is still running" and "nobody solved" as the same
observation. Composing on that assumption pays a partial epoch as if it were whole and
silently zeroes every miner the producer had not scored yet.

What DOES cross the boundary is the producer's report: a canonical document whose
``complete: true`` sits inside the HMAC-authenticated body. This module verifies that
document independently, in the validator, with no database and no trust in the
publisher's own stored row:

  * exact semantic key set, so a derived column cannot enter the signed material;
  * ``complete is True`` by identity, never truthiness, so "false", 0 and "" cannot
    pass as completeness;
  * raw-body HMAC over the canonical bytes, constant-time, with an unset secret
    refusing rather than passing;
  * audience binding: the proof must name this network and netuid;
  * epoch binding: the proof must name the epoch being composed;
  * freshness in both directions: a stale proof and a future-dated proof are both
    refused, so one captured document cannot authorize every later epoch and a
    clock-skewed producer cannot mint an unexpiring one.

The canonicalization, key set and HMAC construction mirror
``scaffold/publisher/cybergym_contract.py`` in cathedral byte for byte. They are
duplicated rather than imported because no import spans the two repositories;
``test_cybergym_epoch_proof.py`` pins the shared literals so drift fails a test here
instead of silently failing to verify a real producer document in production.

What this does NOT claim. A shared-secret HMAC proves possession of the secret, not
producer identity: it authenticates the report against a rotated-or-unset secret and
binds it to this audience and epoch, and that is all. Establishing a producer public
key or a real Cathedral TDX quote for this document is an owner contract decision,
not something this module can infer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping

# Mirrors cathedral's cybergym_contract.HMAC_SECRET_ENV so one operator secret serves
# the producer, the publisher intake, and this verifier.
EPOCH_PROOF_SECRET_ENV = "CATHEDRAL_CYBERGYM_SCORES_HMAC_SECRET"

# Mirrors cybergym_contract.SEMANTIC_KEYS exactly, including order.
SEMANTIC_KEYS = (
    "producer_hotkey",
    "network",
    "netuid",
    "source_epoch",
    "generated_at",
    "complete",
    "score_units",
    "scores",
    "evidence_sha256",
)

DEFAULT_MAX_AGE_SECS = 3600.0
DEFAULT_MAX_FUTURE_SKEW_SECS = 120.0


class EpochProofError(RuntimeError):
    """The epoch-completeness proof did not verify. ``reason`` is machine-readable.

    Raised for every failure mode, so a caller can contain it to the CyberGym lane
    (whose share then forfeits to burn) instead of aborting an otherwise valid vector
    for the honest lanes.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason if not detail else f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class VerifiedEpochProof:
    """The verified facts, including the score VALUES.

    ``scores`` is retained rather than reduced to a key set because the caller has
    to bind the credited contributions to it exactly. Keeping only the hotkeys let
    two things through: a proof scoring two miners while only one receipt was
    submitted (the submitted miner then took the whole lane, because a lane
    normalizes within itself, so an omission reallocates the absent miner's share
    instead of burning it), and a miner the producer scored 0.0 being credited from
    a positive receipt.
    """

    producer_hotkey: str
    network: str
    netuid: int
    source_epoch: int
    generated_at: str
    score_units: str
    evidence_sha256: str
    scores: Mapping[str, float]

    @property
    def scored_hotkeys(self) -> frozenset:
        """Every hotkey the producer listed, including any scored zero."""
        return frozenset(self.scores)

    @property
    def earning_hotkeys(self) -> frozenset:
        """The hotkeys the producer scored ABOVE zero: the set that may earn.

        A zero score is the producer stating the miner earned nothing this epoch,
        which is different from not being listed, and neither may be credited.
        """
        return frozenset(k for k, v in self.scores.items() if float(v) > 0.0)

    @property
    def score_count(self) -> int:
        return len(self.scores)


def canonical_bytes(document: Mapping) -> bytes:
    """sort_keys + compact separators + UTF-8: the one canonicalization.

    Byte-identical to cathedral's ``cybergym_contract.canonical_report_bytes``; the
    HMAC is taken over exactly these bytes on both sides.
    """
    return json.dumps(
        dict(document), sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _strip_sha256_prefix(signature: str) -> str:
    supplied = (signature or "").strip()
    if supplied.startswith("sha256="):
        supplied = supplied[len("sha256=") :]
    return supplied


def normalize(document: Any) -> dict:
    """The one normalized semantic form, or ``EpochProofError``.

    Mirrors ``cybergym_contract.normalize_semantic_document``. Normalizing before
    verifying is what binds the bytes we authenticate to the fields we then act on,
    rather than trusting two independently supplied representations.
    """
    if not isinstance(document, Mapping):
        raise EpochProofError("invalid_document", "not an object")
    keys = set(document)
    missing = [key for key in SEMANTIC_KEYS if key not in keys]
    if missing:
        raise EpochProofError("invalid_document", "missing " + ",".join(missing))
    if keys != set(SEMANTIC_KEYS):
        unexpected = sorted(keys - set(SEMANTIC_KEYS))
        raise EpochProofError(
            "invalid_document", "unexpected fields " + ",".join(unexpected)
        )

    producer = document["producer_hotkey"]
    network = document["network"]
    netuid = document["netuid"]
    source_epoch = document["source_epoch"]
    generated_at = document["generated_at"]
    complete = document["complete"]
    score_units = document["score_units"]
    scores = document["scores"]
    evidence = document["evidence_sha256"]

    if (
        not isinstance(producer, str)
        or not isinstance(network, str)
        or isinstance(netuid, bool)
        or not isinstance(netuid, int)
        or isinstance(source_epoch, bool)
        or not isinstance(source_epoch, int)
        or not isinstance(generated_at, str)
        or not isinstance(score_units, str)
        or not isinstance(scores, Mapping)
        or not isinstance(evidence, str)
    ):
        raise EpochProofError("invalid_document", "field types")
    # Identity, not truthiness: the whole point of this proof is that a truthy
    # stand-in ("false", 1, "yes") must never read as a closed epoch.
    if complete is not True:
        raise EpochProofError(
            "epoch_not_complete",
            f"complete={complete!r}; only an epoch the producer closed may compose",
        )
    if source_epoch < 0:
        raise EpochProofError("invalid_document", "negative source_epoch")

    try:
        parsed_at = datetime.fromisoformat(generated_at.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise EpochProofError("invalid_generated_at", str(exc)) from exc
    if parsed_at.tzinfo is None:
        parsed_at = parsed_at.replace(tzinfo=UTC)
    parsed_at = parsed_at.astimezone(UTC)
    canonical_at = parsed_at.strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{parsed_at.microsecond // 1000:03d}Z"
    )

    normalized_scores: dict = {}
    for hotkey, value in scores.items():
        if (
            not isinstance(hotkey, str)
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
        ):
            raise EpochProofError("invalid_score", "score type")
        score = float(value)
        if not math.isfinite(score) or score < 0.0:
            raise EpochProofError("invalid_score", "score value")
        normalized_hotkey = hotkey.strip()
        if not normalized_hotkey or normalized_hotkey in normalized_scores:
            raise EpochProofError("invalid_score", "score hotkey")
        normalized_scores[normalized_hotkey] = score

    return {
        "producer_hotkey": producer.strip(),
        "network": network,
        "netuid": netuid,
        "source_epoch": source_epoch,
        "generated_at": canonical_at,
        "complete": True,
        "score_units": score_units,
        "scores": normalized_scores,
        "evidence_sha256": evidence,
    }


def verify_epoch_proof(
    proof: Any,
    *,
    secret: str | None,
    network: str,
    netuid: int,
    source_epoch: int,
    now: datetime,
    max_age_secs: float = DEFAULT_MAX_AGE_SECS,
    max_future_skew_secs: float = DEFAULT_MAX_FUTURE_SKEW_SECS,
) -> VerifiedEpochProof:
    """Verify one epoch-completeness proof, or raise ``EpochProofError``.

    ``proof`` is ``{"document": <semantic document>, "signature": "sha256=<hex>"}``:
    exactly what the producer signed and the publisher intake authenticated, carried
    to the validator so it can check the same bytes for itself.
    """
    if not isinstance(proof, Mapping):
        raise EpochProofError("invalid_proof", "not an object")
    unknown = set(proof) - {"body", "signature"}
    if unknown:
        raise EpochProofError(
            "invalid_proof", "unknown keys " + ",".join(sorted(unknown))
        )
    if "body" not in proof or "signature" not in proof:
        # `body` is the EXACT authenticated bytes, not a re-serializable object.
        # Cathedral's intake authenticates the raw HTTP body it received and stores
        # those bytes; re-serializing a parsed object here would verify a different
        # byte string than the producer signed, so a document-only proof is refused
        # as ambiguous rather than guessed at.
        raise EpochProofError(
            "invalid_proof",
            "needs body (the exact authenticated bytes) and signature",
        )

    raw = proof["body"]
    if isinstance(raw, str):
        body_bytes = raw.encode("utf-8")
    elif isinstance(raw, (bytes, bytearray)):
        body_bytes = bytes(raw)
    else:
        raise EpochProofError("invalid_proof", "body must be text or bytes")
    if not body_bytes:
        raise EpochProofError("invalid_proof", "empty body")

    # An unset secret must refuse, never pass. A rotated or missing secret makes the
    # proof unverifiable, and an unverifiable completeness claim is exactly the case
    # that has to burn rather than compose.
    if not secret:
        raise EpochProofError(
            "secret_not_configured",
            f"set {EPOCH_PROOF_SECRET_ENV} to verify the producer's epoch proof",
        )
    signature = proof["signature"]
    if not isinstance(signature, str) or not signature.strip():
        raise EpochProofError("invalid_signature", "empty")
    # Over the RAW bytes, exactly as cathedral's intake authenticates the request
    # body it received. Non-canonical spacing or key order is therefore fine: what
    # is authenticated is the byte string the producer actually signed.
    expected = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(_strip_sha256_prefix(signature), expected):
        raise EpochProofError(
            "invalid_signature",
            "HMAC does not match the authenticated body under the configured secret",
        )

    # Only now derive semantics, and derive them from the bytes we authenticated.
    try:
        parsed = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EpochProofError("invalid_body", str(exc)) from exc
    document = normalize(parsed)

    if str(document["network"]) != str(network) or int(document["netuid"]) != int(
        netuid
    ):
        raise EpochProofError(
            "wrong_audience",
            f"proof is for {document['network']}/{document['netuid']}, "
            f"composing {network}/{netuid}",
        )
    if int(document["source_epoch"]) != int(source_epoch):
        raise EpochProofError(
            "wrong_epoch",
            f"proof closes epoch {document['source_epoch']}, composing {source_epoch}",
        )

    generated = datetime.fromisoformat(
        str(document["generated_at"]).replace("Z", "+00:00")
    ).astimezone(UTC)
    now_utc = now.astimezone(UTC) if now.tzinfo is not None else now.replace(tzinfo=UTC)
    ahead = (generated - now_utc).total_seconds()
    if ahead > float(max_future_skew_secs):
        # A future-dated proof computes a negative age and never expires, so one
        # document would authorize every later epoch.
        raise EpochProofError("proof_in_future", f"{ahead:.0f}s ahead of now")
    age = (now_utc - generated).total_seconds()
    if age > float(max_age_secs):
        raise EpochProofError("stale_proof", f"{age:.0f}s old")

    return VerifiedEpochProof(
        producer_hotkey=str(document["producer_hotkey"]),
        network=str(document["network"]),
        netuid=int(document["netuid"]),
        source_epoch=int(document["source_epoch"]),
        generated_at=str(document["generated_at"]),
        score_units=str(document["score_units"]),
        evidence_sha256=str(document["evidence_sha256"]),
        scores=dict(document["scores"]),
    )


__all__ = [
    "EPOCH_PROOF_SECRET_ENV",
    "SEMANTIC_KEYS",
    "DEFAULT_MAX_AGE_SECS",
    "DEFAULT_MAX_FUTURE_SKEW_SECS",
    "EpochProofError",
    "VerifiedEpochProof",
    "canonical_bytes",
    "normalize",
    "verify_epoch_proof",
]
