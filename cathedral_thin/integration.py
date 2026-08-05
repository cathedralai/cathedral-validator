"""Default-OFF integration lane: independently verify Compute + Distill, PREVIEW one
audited SN39 vector.

Issue cathedral-validator#1 makes this validator the single one that independently
verifies both Compute (Intel TDX CPU and confidential-GPU) and Distill receipts and
produces one auditable weight vector. The receipt/lane/config machinery is the
shared contract shipped by ``cathedral-distill`` (``cathedral_distill.*``); this
module is the validator-side seam that drives it **through the validator's own event
pipeline** — the same PASS / FAIL / NOT_PROVEN vocabulary the thin tick uses.

**This is non-writing and default-OFF.** It never touches the live
``validated_supply_v2`` thin path and never calls ``set_weights``; it composes and
audits a preview vector only. Turning that preview into a broadcast vector — and
choosing the live allocation — is a separate owner activation decision, exactly as
the issue requires.

Install the optional dependency to enable it::

    python -m pip install -e '.[integration]'
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal

from cathedral_thin import cybergym_epoch_proof as _epoch_proof
from cathedral_thin import cybergym_epoch_state as _epoch_state
from cathedral_thin import cybergym_evidence_manifest as _evidence
from hashlib import sha256
import inspect
import json
from typing import Any, Callable, Mapping, Sequence

_STAGE = "INTEGRATION"
_AUTHORITATIVE_EPOCH_TOKEN_KIND = "integration_authoritative_epoch"
_AUTHORITATIVE_EPOCH_TOKEN_PREFIX = "cathedral-integration-authoritative-epoch-v1"
DISTILL_CONTRACT_COMMIT = "480a61aeff835987bbebc882c381fdaa5cc9d711"

# This seam passes these named gates into the shared Distill contract. An older
# pin that merely imports but does not accept one of them must fail before any
# receipt is classified. Converting that contract mismatch into one receipt FAIL
# produces a plausible 100% burn vector, which is the most dangerous possible
# response to incompatible validator code.
_REQUIRED_DISTILL_VERIFIER_PARAMETERS = frozenset(
    {
        "lane",
        "key_registry",
        "source_epoch",
        "now_iso",
        "current_block",
        "gpu_attestation_verifier",
        "cpu_quote_verifier",
        "consumption_ledger",
        "defer_consumption",
        "allowed_measurements",
        "allowed_tcb_statuses",
        "allowed_advisories",
        "work_evidence",
    }
)

# The authoritative pass defers consumption to `compose_integrated`, because that
# is the only place that knows all five composition rules and so the only place
# that can burn a one-time token for a contribution that is actually credited.
# A pin whose composer cannot accept the ledger cannot be driven safely.
_REQUIRED_DISTILL_COMPOSER_PARAMETERS = frozenset({"consumption_ledger"})


class IntegrationUnavailable(RuntimeError):
    """The cathedral-distill dependency is absent or contract-incompatible."""


class IntegrationError(RuntimeError):
    """The integration preview could not be produced (e.g. an invalid config)."""


class IntegrationPolicyError(IntegrationError):
    """A funded reward lane was previewed without a required admission gate.

    Omitting a gate is allowed only as a deliberate act: pass
    ``allow_unpoliced_preview=True`` for a shadow/exploratory run. A lane that
    carries a nonzero allocation refuses instead, because a preview that could
    not apply the launch policy is not evidence that the receipt would be
    admitted under it.
    """


class IntegrationLedgerError(IntegrationError):
    """The replay ledger is not usable, or could not record a consumption.

    Shared infrastructure failing is a preview-level failure, not a per-receipt
    verdict. A ledger outage that is reported as one FAIL per receipt composes a
    100% burn vector and still calls the preview a success, which denies every
    legitimate miner while looking like a normal result.
    """


# The gates a funded (nonzero-allocation) lane must be able to apply. Each
# allow-list is REQUIRED but MAY BE EMPTY, and what empty means is per list:
# an empty measurement or TCB-status allow-list denies every receipt (each
# receipt carries exactly one of each), while an empty advisory allow-list admits
# only receipts that carry no advisory at all (the check is a subset test). All
# three are still different from `None`, which means the operator never expressed
# a policy; only `None` is refused.
REQUIRED_REWARD_GATES = (
    "allowed_measurements",
    "allowed_tcb_statuses",
    "allowed_advisories",
    "current_block",
    "consumption_ledger",
)

# Canonical lane ids for the four receipt kinds the shared contract verifies.
# The signed allocation config names its own lanes, so these are defaults rather
# than a schema: they let a bundle say "cybergym" and get the lane the launch
# config is expected to fund, instead of silently composing into a lane nobody
# configured.
LANE_COMPUTE_CPU = "cathedral_confidential_tdx"
LANE_COMPUTE_GPU = "cathedral_confidential_gpu"
LANE_DISTILL = "cathedral_distill"
LANE_CYBERGYM = "cathedral_cybergym"
DEFAULT_LANE_FOR_KIND = {
    "compute_cpu": LANE_COMPUTE_CPU,
    "compute_gpu": LANE_COMPUTE_GPU,
    "distill": LANE_DISTILL,
    "cybergym": LANE_CYBERGYM,
}

# Which gates each receipt kind actually reads in the shared contract. Supplying a
# gate a kind never reads does not gate anything, so the report must not claim it
# did: `current_block` is inert for a compute or distill receipt (only a CyberGym
# receipt carries a block window), and the measurement/TCB/advisory policy is inert
# for a CyberGym receipt (it carries no TEE evidence of its own).
GATES_READ_BY_KIND = {
    "compute_cpu": frozenset(
        {"measurement_policy", "tcb_policy", "advisory_policy", "consumption_ledger"}
    ),
    "compute_gpu": frozenset(
        {"measurement_policy", "tcb_policy", "advisory_policy", "consumption_ledger"}
    ),
    "distill": frozenset(
        {"measurement_policy", "tcb_policy", "advisory_policy", "consumption_ledger"}
    ),
    "cybergym": frozenset({"block_window", "consumption_ledger"}),
}
_GATE_NAMES = (
    "measurement_policy",
    "tcb_policy",
    "advisory_policy",
    "block_window",
    "consumption_ledger",
)


# One versioned, documented description of every lane this runtime can compose,
# so an operator (and a miner deciding what to submit) can read the whole lane
# surface in one place instead of tracing kinds, lane ids and per-kind gates
# across the shared contract. Adding a lane is a one-place edit here plus the
# shared contract; it does not require either side to understand repo topology.
# This is a documentation/consolidation view over the constants above, not a new
# schema: the signed allocation config remains the authority on which lanes are
# funded and by how much.
LANE_CONTRACT_VERSION = "cathedral_validator_lane_contract_v1"

_LANE_EVIDENCE_NOTE = {
    "compute_cpu": "Intel TDX CPU assurance receipt plus replayable SAT work evidence; "
    "PASS needs measurement/TCB/advisory policy and a durable replay ledger.",
    "compute_gpu": "GPU confidential-compute receipt; with no GPU attestation "
    "verifier supplied it is reported NOT_PROVEN and its share burns.",
    "distill": "Distill result receipt; PASS needs the admission policy and a "
    "durable replay ledger.",
    "cybergym": "CyberGym result receipt; the finalized block window IS the "
    "authorization, so PASS needs current_block and a replay ledger.",
}


def describe_lanes() -> dict[str, Any]:
    """Return the versioned lane surface: for each receipt kind, its canonical lane
    id, the reward gates that kind actually reads, and a one-line evidence note.
    A funded lane that cannot PASS (missing gate, no verifier, invalid/stale/absent
    receipt) forfeits its share to burn; it is never renormalized onto other lanes.
    This is the read-only "what lanes exist and what each needs" surface; the
    ``--lanes`` CLI prints it."""
    return {
        "schema": LANE_CONTRACT_VERSION,
        "distill_contract_commit": DISTILL_CONTRACT_COMMIT,
        "required_reward_gates": list(REQUIRED_REWARD_GATES),
        "unproven_lane_behavior": "forfeit share to burn (never renormalized)",
        "lanes": [
            {
                "kind": kind,
                "lane_id": DEFAULT_LANE_FOR_KIND[kind],
                "reward_gates_read": sorted(GATES_READ_BY_KIND[kind]),
                "evidence": _LANE_EVIDENCE_NOTE[kind],
            }
            for kind in DEFAULT_LANE_FOR_KIND
        ],
    }


def _require_distill():
    try:
        from cathedral_distill import integrated_feed, signed_config  # noqa: F401
        from cathedral_distill.consumption_ledger import (  # noqa: F401
            NO_REPLAY_LEDGER,
            ReplayError,
        )
    except ImportError as exc:  # pragma: no cover - exercised via the test's skip
        raise IntegrationUnavailable(
            "the Compute+Distill integration needs the cathedral-distill package; "
            "install it with: python -m pip install -e '.[integration]'"
        ) from exc

    try:
        parameters = inspect.signature(integrated_feed.verify_lane_receipt).parameters
    except (TypeError, ValueError) as exc:
        raise IntegrationUnavailable(
            "the installed cathedral-distill verifier contract cannot be inspected; "
            "install the exact commit pinned by the integration extra"
        ) from exc
    missing = sorted(_REQUIRED_DISTILL_VERIFIER_PARAMETERS - set(parameters))
    if missing:
        raise IntegrationUnavailable(
            "the installed cathedral-distill verifier contract is incompatible: "
            "verify_lane_receipt is missing "
            + ", ".join(missing)
            + "; install the exact commit pinned by the integration extra"
        )
    try:
        composer = inspect.signature(integrated_feed.compose_integrated).parameters
    except (TypeError, ValueError) as exc:
        raise IntegrationUnavailable(
            "the installed cathedral-distill composer contract cannot be inspected; "
            "install the exact commit pinned by the integration extra"
        ) from exc
    missing = sorted(_REQUIRED_DISTILL_COMPOSER_PARAMETERS - set(composer))
    if missing:
        raise IntegrationUnavailable(
            "the installed cathedral-distill composer contract is incompatible: "
            "compose_integrated is missing "
            + ", ".join(missing)
            + ", so a deferred consumption cannot be recorded at the only point "
            "that knows the contribution is credited; install the exact commit "
            "pinned by the integration extra"
        )
    return integrated_feed, signed_config


@dataclass(frozen=True)
class LaneReceipt:
    """One receipt to verify, tagged with its kind and the lane it feeds."""

    kind: str  # integrated_feed.KIND_COMPUTE_CPU / _GPU / _DISTILL / _CYBERGYM
    lane: str  # the lane id in the signed allocation config
    receipt: Mapping[str, Any]
    # Required for a positive Compute lane contribution.  It carries the exact
    # canonical SAT item/result bytes committed by the signed receipt.
    work_evidence: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        """Accept an explicit sidecar from an in-memory transport wrapper.

        JSON bundles always pass ``work_evidence`` as their own field.  This
        small adapter keeps programmatic callers free to use a mapping subtype
        that transports a verified sidecar alongside the receipt; the sidecar is
        still independently parsed, receipt-id-bound, and replayed by Distill.
        A plain mapping without explicit evidence remains a hard refusal.
        """
        if self.work_evidence is None:
            attached = getattr(self.receipt, "work_evidence", None)
            if isinstance(attached, Mapping):
                object.__setattr__(self, "work_evidence", attached)


def _emit(events, code: str, *, status: str, **fields: Any) -> None:
    if events is not None:
        events.event(code, stage=_STAGE, status=status, **fields)


def _raw_field(receipt: Any, *keys: str) -> str:
    """Best-effort identity from a receipt that failed before verification."""
    for key in keys:
        value = receipt.get(key) if isinstance(receipt, Mapping) else None
        if isinstance(value, str) and value:
            return value
    return "<unverified>"


def _refused(integrated_feed, item: LaneReceipt, detail: str, *, hotkey: str = ""):
    """A FAIL decision for a receipt the seam refuses before or after verifying."""
    return integrated_feed.ReceiptDecision(
        item.lane,
        item.kind,
        _raw_field(item.receipt, "receipt_id"),
        hotkey or _raw_field(item.receipt, "subject_hotkey", "miner_hotkey"),
        integrated_feed.FAIL,
        Decimal(0),
        detail,
    )


def _bind_to_epoch_proof(integrated_feed, decisions, *, proof, lanes, credited_rows):
    """Bind each funded CyberGym lane's FINAL credited set and values to the proof.

    ``credited_rows`` is the outcome of a DRY composition: the same decisions with
    any deferred replay marker cleared and no ledger, so it credits exactly what the
    five admission rules allow, after the replay read has already dropped anything a
    previous pass consumed.

    Three properties, each of which was a separate reward-theft route before:

    * **Keyed by (lane, hotkey), and by LANE not by kind.** The composer pays by
      lane, and `lane` is a caller-supplied tag the shared contract deliberately
      does not check against `kind`. Filtering this binding to cybergym-kind rows
      therefore left a plain compute or distill receipt, tagged into the funded
      CyberGym lane, invisible to the check AND exempt from the refusal: it took up
      to 100% of a lane the producer never attested, while the gate reported
      `bound: true`. Every credited row in a governed lane is bound, whatever its
      kind, and a row whose kind the producer does not attest simply cannot match.
    * **Per lane, not unioned.** Checking set equality against the union of all
      governed lanes hid a per-lane mismatch: two funded CyberGym lanes could pay a
      miner twice their share while the union still matched.
    * **Every credited row, not one row per hotkey.** Keying by hotkey alone meant
      that with several credited rows for one miner only the last survived the
      value check, and which one that was depended on a sha256 tiebreak, so the same
      inputs could bind or not bind.

    Any mismatch refuses EVERY decision in that lane, so its whole share forfeits to
    burn. Burning on an omission is deliberate: paying the present subset IS the
    reallocation. This runs before the epoch claim and before any receipt token is
    consumed.
    """
    attested = dict(proof.scores)
    earning = {k for k, v in attested.items() if float(v) > 0.0}
    problems: list[str] = []
    bad_lanes: set[str] = set()

    for lane in sorted(lanes):
        rows = [
            row
            for row in credited_rows
            if row.get("credited") and row.get("lane") == lane
        ]
        credited_here = {str(row.get("miner_hotkey")) for row in rows}
        missing = sorted(earning - credited_here)
        extra = sorted(credited_here - earning)
        lane_problems: list[str] = []
        if missing:
            lane_problems.append(
                "no credited contribution for producer-scored " + ",".join(missing)
            )
        if extra:
            lane_problems.append(
                "credited but not scored above zero by the producer: " + ",".join(extra)
            )
        for row in rows:
            hotkey = str(row.get("miner_hotkey"))
            expected = attested.get(hotkey)
            if expected is None:
                continue  # already reported as `extra`
            # Exact equality against the value COMPOSED, per credited row.
            if Decimal(str(expected)) != Decimal(str(row.get("work_units"))):
                lane_problems.append(
                    f"{hotkey} composed work units {row.get('work_units')} do not "
                    f"equal the producer's attested score {expected}"
                )
        # REAL evidence binding, not a pin. Rebuild the canonical manifest from the
        # receipts THIS validator admitted for THIS lane and require the producer's
        # signed evidence_sha256 to equal it exactly. A producer that scored a
        # different set, different amounts, or different receipts cannot produce a
        # matching digest. An empty funded lane uses the deterministic empty-manifest
        # digest, so "nobody scored" is attested rather than indistinguishable from a
        # missing manifest. Per lane for the same reason the value check is: a union
        # digest would let one lane's surplus mask another's shortfall.
        try:
            recomputed = _evidence.manifest_digest(
                network=proof.network,
                netuid=proof.netuid,
                source_epoch=proof.source_epoch,
                entries=[
                    {
                        "miner_hotkey": str(row.get("miner_hotkey")),
                        "receipt_id": str(row.get("receipt_id")),
                        "work_units": row.get("work_units"),
                    }
                    for row in rows
                ],
            )
        except _evidence.EvidenceManifestError as exc:
            lane_problems.append(f"credited set cannot be digested: {exc}")
            recomputed = None
        if recomputed is not None and recomputed != str(proof.evidence_sha256).lower():
            lane_problems.append(
                "the signed evidence digest does not commit to the credited set: "
                f"report says {proof.evidence_sha256}, the admitted receipts digest "
                f"to {recomputed}"
            )

        if lane_problems:
            bad_lanes.add(lane)
            problems.append(f"{lane}: " + "; ".join(lane_problems))

    if not problems:
        return list(decisions), None

    detail = (
        "producer epoch proof does not match the finally credited set ("
        + " | ".join(problems)
        + f"); the lane's share burns for epoch {proof.source_epoch}"
    )
    out = []
    for d in decisions:
        # Refuse by LANE, whatever the kind: otherwise a foreign-kind receipt in a
        # burning lane survives the refusal and takes the share the lane was
        # supposed to forfeit. A decision that already failed keeps its own reason,
        # since it is not paying either way and the diagnosis matters.
        if d.creditable and d.lane in bad_lanes:
            out.append(
                integrated_feed.ReceiptDecision(
                    d.lane,
                    d.kind,
                    d.receipt_id,
                    d.miner_hotkey,
                    integrated_feed.FAIL,
                    Decimal(0),
                    detail,
                )
            )
        else:
            out.append(d)
    return out, detail


def _decide(
    integrated_feed,
    item: LaneReceipt,
    *,
    known_lanes: set[str],
    burn_hotkey: str,
    **gates: Any,
):
    """Verify one receipt with every failure contained to that receipt.

    The shared contract returns FAIL for the three typed receipt errors, but a
    receipt can also fail *outside* them: an unknown kind, an exception raised by
    an injected verifier or by the ledger. `verify_lane_receipt` raises
    `IntegratedFeedError` for an unknown kind rather than returning a decision, so
    without this containment one malformed contribution aborted the whole preview
    and destroyed every honest lane's vector too.
    """
    if item.lane not in known_lanes:
        # The composer drops a decision naming a lane the signed config does not
        # know, so this is not containment: it is a seam policy that such a
        # receipt is refused outright rather than verified and then dropped, so
        # nothing about it reaches an injected verifier or the ledger.
        return _refused(
            integrated_feed,
            item,
            f"lane {item.lane!r} is not a funded lane in the allocation config",
        )
    claimed = _raw_field(item.receipt, "subject_hotkey", "miner_hotkey")
    if claimed == burn_hotkey:
        # The burn destination is not a subject. Refuse before verifying, so a
        # burn-subject receipt never consumes a ledger token either.
        return _refused(
            integrated_feed,
            item,
            "subject is the configured burn hotkey, which can never earn weight",
            hotkey=claimed,
        )
    try:
        decision = integrated_feed.verify_lane_receipt(
            item.kind,
            item.receipt,
            lane=item.lane,
            work_evidence=item.work_evidence,
            **gates,
        )
    except Exception as exc:
        return _refused(
            integrated_feed,
            item,
            f"receipt refused at the lane boundary: {type(exc).__name__}: {exc}",
        )
    if decision.creditable and decision.miner_hotkey == burn_hotkey:
        # Belt and braces: the verified subject is what earns, so gate on it too.
        return _refused(
            integrated_feed,
            item,
            "subject is the configured burn hotkey, which can never earn weight",
            hotkey=decision.miner_hotkey,
        )
    return decision


def _composition_order(decisions: Sequence[Any]) -> list[int]:
    """Positions of `decisions` in the canonical order the composer should see.

    Deduplication is the composer's job, not this seam's. `compose_integrated`
    applies all five drop rules itself, and it applies them INCREMENTALLY: a
    contribution only claims its lane's per-miner slot at the moment it is
    actually credited. Re-deriving the same rules here from a precomputed winner
    map got that wrong, because a precomputed map cannot know that a candidate
    lost its slot for an unrelated reason. One receipt tagged into two lanes took
    the second lane's per-miner slot, was then refused there as already credited
    elsewhere, and the miner's own second, entirely valid receipt in that lane was
    refused for a reason that was not true: "miner already has a credited receipt
    in lane X" naming a receipt that lane never credited.

    What the seam owes the composer instead is a canonical ORDER, because the
    composer's rules are first-wins and the caller's submission order must not
    decide who earns. Sorting by `(receipt_id, lane, kind)` makes the outcome a
    pure function of the receipt set:

    * two credited receipts from one miner in one lane -> the lowest `receipt_id`
      is credited, whichever order they were submitted in;
    * one receipt tagged into several lanes -> it earns in the lowest lane id, and
      the other lanes see it dropped without their slots being consumed.

    Returns positions rather than reordering, so the audit trail can be restored
    to submission order afterwards.
    """
    return sorted(
        range(len(decisions)),
        key=lambda i: (decisions[i].receipt_id, decisions[i].lane, decisions[i].kind),
    )


def _no_replay_sentinel():
    """The shared contract's typed "no replay protection" marker, if it ships one."""
    try:
        from cathedral_distill.consumption_ledger import NO_REPLAY_LEDGER
    except ImportError:  # older contract without the sentinel
        return None
    return NO_REPLAY_LEDGER


def _no_replay_sentinel_or_none() -> Any:
    """The contract's typed "no replay protection" marker, or None on an older pin.

    Passing the sentinel explicitly is what makes the inspection path forward
    compatible with a contract that requires an explicit replay decision, while
    still working against a pin that predates the sentinel.
    """
    return _no_replay_sentinel()


def _usable_ledger(ledger: Any) -> Any:
    """Return a ledger that can actually record and answer, or None.

    Presence is not a gate. `NO_REPLAY_LEDGER` is the contract's explicit "no
    replay protection" marker, so it counts as no ledger rather than as an applied
    one, and an object that cannot record or cannot be queried is refused outright
    instead of being reported as a gate that ran.
    """
    if ledger is None:
        return None
    sentinel = _no_replay_sentinel()
    if sentinel is not None and ledger is sentinel:
        return None
    missing = [
        name
        for name in ("consume", "is_consumed")
        if not callable(getattr(ledger, name, None))
    ]
    if missing:
        raise IntegrationLedgerError(
            "the configured consumption ledger cannot be used: it does not implement "
            + ", ".join(missing)
            + ". A consumption that cannot be recorded and read back is not replay "
            "protection; pass a cathedral_distill.consumption_ledger.ConsumptionLedger "
            "on a durable path, or NO_REPLAY_LEDGER to state that this preview has none"
        )
    return ledger


def _authoritative_epoch_token(*, network: str, netuid: int, source_epoch: int) -> str:
    """Stable, collision-resistant identity for one subnet epoch's mutation pass."""
    body = json.dumps(
        {
            "network": str(network),
            "netuid": int(netuid),
            "source_epoch": int(source_epoch),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{_AUTHORITATIVE_EPOCH_TOKEN_PREFIX}:sha256:{sha256(body).hexdigest()}"


def _claim_authoritative_epoch(
    ledger: Any,
    *,
    network: str,
    netuid: int,
    source_epoch: int,
    events: Any = None,
) -> str:
    """Atomically elect the only receipt-consuming pass for an epoch.

    This is intentionally a narrow single-flight guarantee, not an atomic batch:
    the epoch claim is durable before any receipt token is consumed. If the
    winner crashes after claiming, the epoch stays locked and must be recovered
    by operator review rather than re-run speculatively. That can withhold one
    epoch, but it cannot let two overlapping processes compose competing vectors
    or split the credited receipt set.
    """
    from cathedral_distill.consumption_ledger import ReplayError

    token = _authoritative_epoch_token(
        network=network, netuid=netuid, source_epoch=source_epoch
    )

    def recorded() -> bool:
        try:
            return bool(ledger.is_consumed(token))
        except Exception as exc:
            detail = (
                "authoritative epoch claim ledger could not be queried for "
                f"{network}/{netuid} epoch {source_epoch}: {exc}"
            )
            _emit(events, "INTEGRATION_EPOCH_CLAIM", status="FAIL", detail=detail)
            raise IntegrationLedgerError(detail) from exc

    try:
        ledger.consume(
            token,
            kind=_AUTHORITATIVE_EPOCH_TOKEN_KIND,
            source_epoch=source_epoch,
        )
    except ReplayError as exc:
        if recorded():
            detail = (
                "authoritative epoch already claimed for "
                f"{network}/{netuid} epoch {source_epoch}; refusing overlapping "
                "or repeated receipt consumption"
            )
        else:
            detail = (
                "authoritative epoch claim was not recorded for "
                f"{network}/{netuid} epoch {source_epoch}: {exc}"
            )
        _emit(events, "INTEGRATION_EPOCH_CLAIM", status="FAIL", detail=detail)
        raise IntegrationLedgerError(detail) from exc
    except Exception as exc:
        detail = (
            "authoritative epoch claim failed for "
            f"{network}/{netuid} epoch {source_epoch}: {type(exc).__name__}: {exc}"
        )
        _emit(events, "INTEGRATION_EPOCH_CLAIM", status="FAIL", detail=detail)
        raise IntegrationLedgerError(detail) from exc
    if not recorded():
        detail = (
            "authoritative epoch claim reported success but was not recorded for "
            f"{network}/{netuid} epoch {source_epoch}"
        )
        _emit(events, "INTEGRATION_EPOCH_CLAIM", status="FAIL", detail=detail)
        raise IntegrationLedgerError(detail)
    _emit(
        events,
        "INTEGRATION_EPOCH_CLAIM",
        status="PASS",
        network=network,
        netuid=netuid,
        source_epoch=source_epoch,
        token=token,
    )
    return token


def _read_replay_gate(
    integrated_feed,
    decisions: Sequence[Any],
    *,
    ledger: Any,
    events: Any = None,
) -> list[Any]:
    """Refuse any creditable receipt whose token is already on record. READ only.

    This gate never writes, in either mode. It answers the question "has this
    receipt already been credited by an earlier pass", which is a read, and it
    answers it before composition so a replay is a per-receipt ``FAIL`` with a
    reason rather than a silently uncredited row.

    **Recording the consumption is deliberately NOT done here.** It happens inside
    ``compose_integrated``, which is the only place that knows all five of its drop
    rules and therefore the only place that can burn a one-time token for a
    contribution that is genuinely being credited. Consuming out here covered four
    of those five rules and missed the fifth: a receipt aimed at a lane the signed
    config enables but funds with zero had its token burned and was then dropped as
    "allocated zero and cannot pay", so it earned nothing and could never be
    credited again in any later epoch. That is denial of reward with no forgery,
    which is the exact failure the shared contract moved consumption into
    composition to prevent.

    A ledger that cannot answer is a preview-level ``IntegrationLedgerError``: it is
    shared infrastructure, and turning its outage into one FAIL per receipt would
    compose a 100% burn vector and report PASS while denying every legitimate miner.
    """
    if ledger is None:
        return list(decisions)

    def recorded(decision) -> bool:
        try:
            return bool(ledger.is_consumed(decision.receipt_id))
        except Exception as exc:
            detail = (
                f"replay ledger unusable while screening {decision.receipt_id}: "
                f"is_consumed failed: {exc}"
            )
            _emit(events, "INTEGRATION_LEDGER", status="FAIL", detail=detail)
            raise IntegrationLedgerError(detail) from exc

    def replayed(decision):
        detail = f"token already consumed: {decision.receipt_id}"
        _emit(
            events,
            "INTEGRATION_REPLAY",
            status="FAIL",
            hotkey=decision.miner_hotkey,
            lane=decision.lane,
            receipt_id=decision.receipt_id,
            detail=detail,
        )
        return integrated_feed.ReceiptDecision(
            decision.lane,
            decision.kind,
            decision.receipt_id,
            decision.miner_hotkey,
            integrated_feed.FAIL,
            Decimal(0),
            detail,
        )

    out: list[Any] = []
    for decision in decisions:
        if not decision.creditable:
            out.append(decision)
            continue
        out.append(replayed(decision) if recorded(decision) else decision)
    return out


def _audit_ledger_invariants(
    audit_rows: Sequence[Mapping[str, Any]],
    deferred: Mapping[str, Any],
    *,
    expected_credited: frozenset[str] | set[str],
    ledger: Any,
    events: Any = None,
) -> None:
    """Hold the authoritative pass's ledger effects to the audit it just produced.

    Composition records consumptions itself, and it reports a consumption failure
    as one dropped contribution. For a single receipt that is the right call, but
    an outage drops every contribution the same way, which composes a 100% burn
    vector and still returns successfully. So the effects are checked against
    state, never against message text, once composition is done:

    * the ledger must still answer at all (a liveness probe on a token that cannot
      exist), because otherwise every drop is indistinguishable from an outage;
    * a receipt credited anywhere must have its token on record, or the ledger
      reported a consume it did not keep and the receipt is creditable again next
      epoch;
    * a receipt credited NOWHERE must not have its token on record, which is the
      invariant whose violation was the zero-allocation token burn;
    * every receipt the composer's five rules WOULD have credited must actually be
      credited. ``expected_credited`` comes from composing the same decisions with
      no ledger at all, so the composer is its own oracle: the two runs differ only
      in the consume step, and a receipt that falls out of the second one lost its
      credit to the ledger rather than to a rule. Without this, a ledger whose
      writes fail turns into one dropped contribution per receipt and the pass
      still returns a burn vector and calls itself a success.

    The unit is the `receipt_id`, not the audit row. One receipt tagged into several
    lanes produces several rows sharing one token, and exactly one of them is
    credited: judging each row on its own would read the credited row's legitimate
    consumption as the uncredited rows' stolen token.

    Any violation is an ``IntegrationLedgerError``: the pass wrote something it
    cannot stand behind, so its vector is not evidence of anything.
    """
    if ledger is None or not deferred:
        return

    def fail(detail: str) -> IntegrationLedgerError:
        _emit(events, "INTEGRATION_LEDGER", status="FAIL", detail=detail)
        return IntegrationLedgerError(detail)

    probe = f"{_AUTHORITATIVE_EPOCH_TOKEN_PREFIX}:liveness-probe:never-consumed"
    try:
        if ledger.is_consumed(probe):
            raise fail(
                "replay ledger reports a token that was never consumed as consumed; "
                "its answers cannot be trusted for this pass"
            )
    except IntegrationLedgerError:
        raise
    except Exception as exc:
        raise fail(
            "replay ledger stopped answering during the authoritative pass, so a "
            f"dropped contribution cannot be told from an outage: {exc}"
        ) from exc

    credited_anywhere: dict[str, bool] = {}
    reasons: dict[str, str] = {}
    for row in audit_rows:
        receipt_id = row.get("receipt_id")
        if receipt_id not in deferred:
            continue
        credited_anywhere[receipt_id] = credited_anywhere.get(
            receipt_id, False
        ) or bool(row.get("credited"))
        if not row.get("credited") and row.get("drop_reason"):
            reasons.setdefault(receipt_id, str(row["drop_reason"]))

    lost = sorted(
        receipt_id
        for receipt_id, credited in credited_anywhere.items()
        if not credited and receipt_id in expected_credited
    )
    if lost:
        raise fail(
            "the composer's own rules would have credited "
            + ", ".join(lost)
            + " and it did not, so the replay ledger refused the consumption rather "
            "than any admission rule refusing the receipt: "
            + "; ".join(
                reasons.get(receipt_id, "no reason recorded") for receipt_id in lost
            )
        )

    for receipt_id, credited in credited_anywhere.items():
        try:
            on_record = bool(ledger.is_consumed(receipt_id))
        except Exception as exc:
            raise fail(
                f"replay ledger could not be read back for {receipt_id}: {exc}"
            ) from exc
        if credited and not on_record:
            raise fail(
                f"{receipt_id} was credited but its one-time token is not on record; "
                "the consumption was reported and not kept, so the same receipt "
                "would be creditable again in a later epoch"
            )
        if not credited and on_record:
            raise fail(
                f"{receipt_id} was credited nowhere but its one-time token was "
                f"consumed ({reasons.get(receipt_id) or 'no reason recorded'}); the "
                "receipt can never be credited again, so it has been denied its reward"
            )


def _restore_submission_order(
    rows: Sequence[Mapping[str, Any]], order: Sequence[int]
) -> list[dict[str, Any]]:
    """Undo the composition sort so the audit trail reads in submission order.

    The composer emits one row per decision it was given, in that order, so the
    rows come back in canonical order. `order[position]` is the submission index
    that row belongs to, which inverts the permutation exactly. Every row is the
    composer's own, so they all carry the same keys, including the ones describing
    a lane the signed config does not fund.
    """
    restored: list[dict[str, Any] | None] = [None] * len(rows)
    for position, index in enumerate(order):
        restored[index] = dict(rows[position])
    return [row for row in restored if row is not None]


def preview_integrated_vector(
    *,
    burn_config: bytes,
    allocation_config: bytes,
    key_registry: Any,
    receipts: Sequence[LaneReceipt],
    network: str,
    netuid: int,
    source_epoch: int,
    now: datetime,
    now_iso: str,
    gpu_attestation_verifier: Callable[[Mapping[str, Any]], bool] | None = None,
    cpu_quote_verifier: Callable[[Mapping[str, Any]], bool] | None = None,
    expected_burn_hotkey: str | None = None,
    min_burn_version: int = 0,
    min_allocation_version: int = 0,
    # Admission gates the shared contract already implements but this seam never
    # reached, so the validator was strictly weaker than distill's own
    # admission verifier for the same receipt:
    #   current_block        -> the finalized block-window check (distill PR #8)
    #   consumption_ledger   -> once-only receipt_id consumption (replay)
    #   allowed_*            -> signed measurement / TCB / advisory policy gating
    # All default to None, which preserves the previous behaviour exactly.
    current_block: int | None = None,
    consumption_ledger: Any = None,
    allowed_measurements: frozenset[str] | set[str] | None = None,
    allowed_tcb_statuses: frozenset[str] | set[str] | None = None,
    allowed_advisories: frozenset[str] | set[str] | None = None,
    # Explicit, documented opt-out for a shadow / exploratory preview that
    # deliberately runs without the launch policy. A funded lane refuses
    # otherwise: omission must be an act, never a default.
    allow_unpoliced_preview: bool = False,
    # A preview READS the replay ledger by default and writes nothing, so it can
    # be run repeatedly and returns the same vector every time. Recording the
    # consumption is the authoritative pass, at most once per epoch, and has to be
    # asked for.
    consume_receipts: bool = False,
    # Producer epoch-completeness proof for the CyberGym lane. Verifying each
    # receipt answers "is this contribution real"; it never answered "did the
    # producer finish scoring this epoch, and is this the complete scored set".
    # cathedral-distill records that in its own local cybergym_epoch_status table,
    # which does not cross the authenticated HTTP boundary, so the validator has to
    # verify the producer's signed report for itself or it cannot tell a partial
    # epoch from an epoch nobody solved. Required for a FUNDED CyberGym lane;
    # anything unverifiable forfeits that lane's share to burn.
    cybergym_epoch_proof: Mapping[str, Any] | None = None,
    cybergym_epoch_proof_secret: str | None = None,
    # Possessing the shared HMAC secret is not producer identity, so the operator
    # pins WHICH producer this validator will compose. Required for a funded lane.
    cybergym_expected_producer_hotkey: str | None = None,
    # Optional pin for the signed evidence bundle digest.
    cybergym_expected_evidence_sha256: str | None = None,
    # Durable per-audience monotonic epoch state. REQUIRED for an authoritative pass
    # on a funded lane: without it, epoch 12 then epoch 11 both compose and both earn,
    # because each proof correctly names its own epoch and burns a distinct per-epoch
    # token. That is an epoch rollback, and it re-pays a superseded scored set.
    cybergym_epoch_state_path: str | None = None,
    events: Any = None,
) -> dict[str, Any]:
    """Verify the signed config and every lane receipt, then compose + audit one
    preview vector. Emits validator events at each stage and RETURNS
    ``{feed, audit, gates}``. It never writes weights.

    Fails closed:

    * an invalid burn/allocation config raises ``IntegrationError`` (after a FAIL
      event);
    * a funded lane (nonzero allocation) with any of ``REQUIRED_REWARD_GATES``
      omitted raises ``IntegrationPolicyError`` unless
      ``allow_unpoliced_preview`` is the boolean ``True``; any other value is
      itself refused, so a deserialized ``"false"`` cannot authorize an unpoliced
      preview;
    * a replay ledger that cannot record, cannot be queried, or reports a consume
      it did not record raises ``IntegrationLedgerError``: shared infrastructure
      failing is a preview-level failure, never a per-receipt verdict that still
      composes a vector;
    * a receipt whose subject is the configured burn hotkey is FAIL, never a
      reward subject;
    * an individual receipt that cannot be verified, for any reason including an
      unexpected error inside an injected verifier, becomes a FAIL/NOT_PROVEN
      receipt whose lane share goes to burn, never another lane and never an
      aborted vector;
    * one receipt earns at most once across the whole preview, and a miner with
      two credited receipts in one lane keeps exactly one, deterministically: the
      composer's rules decide it and this seam supplies a canonical order, so the
      outcome is a pure function of the receipt set and not of its order;
    * a receipt that is not credited keeps its one-time replay token, for EVERY
      reason it might not be credited, including a lane the signed config enables
      but funds with zero. Consumption is deferred into ``compose_integrated``,
      which is the only point that knows all five of its drop rules, and the
      recorded effects are then checked back against the audit.

    Repeatable by default: the replay gate is a read unless
    ``consume_receipts=True``, so an operator can run the same preview as often as
    they like and get the same vector. ``consume_receipts=True`` atomically claims
    the epoch before recording any credited receipt. A second or overlapping
    authoritative pass fails closed. If the winner crashes after the claim, the
    epoch stays locked for operator review rather than being retried and possibly
    splitting the credited set.

    ``gates`` records, per lane AND per receipt kind, which admission gates were
    actually applied to the receipts in that lane, so an operator sees the gates
    that ran rather than the arguments that were supplied. ``audit["receipts"]`` is
    in submission order and every row carries the same keys.
    """
    integrated_feed, signed_config = _require_distill()

    # 1. Verify the remote-signed burn + allocation config (signer, target,
    #    freshness, rollback, burn destination). A bad config yields no vector.
    try:
        burn = signed_config.verify_burn_config(
            burn_config,
            key_registry,
            network=network,
            netuid=netuid,
            now=now,
            min_version=min_burn_version,
            expected_burn_hotkey=expected_burn_hotkey,
        )
        allocation = signed_config.verify_allocation_config(
            allocation_config,
            key_registry,
            network=network,
            netuid=netuid,
            now=now,
            min_version=min_allocation_version,
        )
        resolved = signed_config.resolve_allocation(burn, allocation)
    except signed_config.SignedConfigError as exc:
        _emit(events, "INTEGRATION_CONFIG", status="FAIL", detail=str(exc))
        raise IntegrationError(f"signed config rejected: {exc}") from exc
    _emit(
        events,
        "INTEGRATION_CONFIG",
        status="PASS",
        burn_version=resolved.config_versions[0],
        allocation_version=resolved.config_versions[1],
        base_burn=str(resolved.burn_fraction),
    )

    # 2. Admission-gate audit. A funded lane must be able to apply the launch
    #    policy; omitting a gate is a deliberate opt-out or a refusal, never a
    #    silent default that reads as "policy verified".
    #
    #    The opt-out is checked by identity, not truthiness. Every non-empty
    #    string is truthy in Python, so a config or CLI deserialization that
    #    produced "false" or "0" would otherwise authorize exactly the unpoliced
    #    preview the value says to avoid. Refuse to guess.
    for name, value in (
        ("allow_unpoliced_preview", allow_unpoliced_preview),
        ("consume_receipts", consume_receipts),
    ):
        if value is not True and value is not False:
            detail = (
                f"{name} must be the boolean True or False, not "
                f"{type(value).__name__} {value!r}; refusing to infer whether "
                "an unpoliced or authoritative run was authorized"
            )
            _emit(events, "INTEGRATION_POLICY", status="FAIL", detail=detail)
            raise IntegrationPolicyError(detail)
    ledger = _usable_ledger(consumption_ledger)
    supplied = {
        "allowed_measurements": allowed_measurements,
        "allowed_tcb_statuses": allowed_tcb_statuses,
        "allowed_advisories": allowed_advisories,
        "current_block": current_block,
        "consumption_ledger": ledger,
    }
    omitted = [name for name in REQUIRED_REWARD_GATES if supplied[name] is None]
    reward_lanes = sorted(
        lane for lane, alloc in resolved.lane_allocations.items() if alloc > 0
    )
    # What was supplied, and separately what each lane's receipts actually read.
    # Reporting a supplied argument as an applied gate overstates the assurance:
    # `current_block` gates nothing for a compute receipt, so a lane of compute
    # receipts must not print block_window=yes just because a number was passed.
    gate_supplied = {
        "measurement_policy": allowed_measurements is not None,
        "tcb_policy": allowed_tcb_statuses is not None,
        "advisory_policy": allowed_advisories is not None,
        "block_window": current_block is not None,
        "consumption_ledger": ledger is not None,
    }
    kinds_in_lane: dict[str, set[str]] = {
        lane: set() for lane in resolved.lane_allocations
    }
    for item in receipts:
        if item.lane in kinds_in_lane:
            kinds_in_lane[item.lane].add(str(item.kind))

    def applied_for_kind(kind: str) -> dict[str, bool]:
        read = GATES_READ_BY_KIND.get(kind, frozenset())
        return {name: gate_supplied[name] and name in read for name in _GATE_NAMES}

    gates = {
        "reward_lanes": reward_lanes,
        "omitted_gates": omitted,
        "unpoliced_preview": allow_unpoliced_preview is True,
        "replay_mode": "authoritative" if consume_receipts is True else "inspection",
        "authoritative_epoch_claim": None,
        "supplied": dict(gate_supplied),
        # Genuinely applied: this gate ran against at least one receipt somewhere in
        # the preview. Keyed like `supplied` so the two are directly comparable, and
        # they DO differ: a compute-only preview with `current_block` passed reports
        # block_window supplied=yes, applied=no, because no compute receipt reads it.
        # An earlier revision computed this from "was the argument not None", which
        # made it a second copy of `supplied` under a name that claimed more.
        "applied": {
            name: any(
                applied_for_kind(kind)[name]
                for kinds in kinds_in_lane.values()
                for kind in kinds
            )
            for name in _GATE_NAMES
        },
        "lanes": {
            lane: {
                "allocation": str(alloc),
                "reward_lane": alloc > 0,
                "kinds": {
                    kind: applied_for_kind(kind)
                    for kind in sorted(kinds_in_lane.get(lane, ()))
                },
                # supplied is the operator's configuration; the per-gate booleans
                # below are what the receipts in THIS lane actually had applied.
                "supplied": dict(gate_supplied),
                **{
                    name: any(
                        applied_for_kind(kind)[name]
                        for kind in kinds_in_lane.get(lane, ())
                    )
                    for name in _GATE_NAMES
                },
            }
            for lane, alloc in sorted(resolved.lane_allocations.items())
        },
    }
    if omitted and reward_lanes and allow_unpoliced_preview is not True:
        detail = (
            "funded reward lanes "
            + ", ".join(reward_lanes)
            + " previewed without "
            + ", ".join(omitted)
            + "; pass allow_unpoliced_preview=True for a deliberately unpoliced "
            "shadow preview, or supply the gate (an explicitly empty allow-list is "
            "a valid policy: empty measurements or TCB statuses admit nothing, an "
            "empty advisory list admits only advisory-free receipts)"
        )
        _emit(events, "INTEGRATION_POLICY", status="FAIL", detail=detail)
        raise IntegrationPolicyError(detail)
    if omitted:
        _emit(
            events,
            "INTEGRATION_POLICY",
            status="NOT_PROVEN",
            detail="unpoliced preview: " + ", ".join(omitted) + " not applied",
        )
    else:
        _emit(
            events,
            "INTEGRATION_POLICY",
            status="PASS",
            detail="every required admission gate was applied",
        )

    # 3. Verify every receipt. The authoritative pass DEFERS its consumption to
    #    composition (`defer_consumption=True` marks the decision REPLAY_PENDING
    #    without touching the ledger); an inspection pass verifies with no ledger
    #    at all, so it can never write. Either way nothing is consumed here, because
    #    consumption is irreversible and the credited set is still undecided. Every
    #    failure is contained: one malformed contribution can never abort the vector.
    known_lanes = set(resolved.lane_allocations)
    authoritative = consume_receipts is True
    if authoritative and ledger is None:
        detail = (
            "an authoritative pass requires a usable durable consumption ledger "
            "to claim the epoch, even when no receipt is creditable"
        )
        _emit(events, "INTEGRATION_EPOCH_CLAIM", status="FAIL", detail=detail)
        raise IntegrationPolicyError(detail)
    # 3b. Producer epoch completeness, verified here rather than assumed.
    #     A CyberGym receipt proves one miner's solve; it cannot prove the producer
    #     finished scoring the epoch. If the CyberGym lane is FUNDED and any
    #     cybergym receipt is present, the signed report that says `complete: true`
    #     must verify against this audience and this epoch, and every credited
    #     subject must appear in the set the producer attested to. Anything else
    #     (absent, stale, future-dated, tampered, wrong audience/epoch, not
    #     complete, unverifiable secret) refuses those receipts, so the lane's
    #     share forfeits to burn while every honest lane still composes.
    cybergym_kinds = {"cybergym"}
    cybergym_lanes = {
        item.lane for item in receipts if str(item.kind) in cybergym_kinds
    }
    funded_cybergym = {
        lane
        for lane in cybergym_lanes
        if resolved.lane_allocations.get(lane, Decimal(0)) > 0
    }
    # A funded CyberGym lane with NO receipts at all still has to prove the epoch
    # closed. Otherwise "the producer sent nothing" and "the epoch never finished"
    # are indistinguishable, and an operator could fund the lane, submit nothing, and
    # have it burn silently without anyone establishing which of the two happened.
    # The share burns either way; the difference is whether the burn is evidenced.
    funded_cybergym |= {
        lane
        for lane, allocation in resolved.lane_allocations.items()
        if allocation > 0 and lane == LANE_CYBERGYM
    }
    epoch_proof = None
    epoch_proof_error: str | None = None
    if funded_cybergym:
        try:
            if not cybergym_expected_producer_hotkey:
                raise _epoch_proof.EpochProofError(
                    "producer_not_pinned",
                    "a funded CyberGym lane requires cybergym_expected_producer_hotkey: "
                    "the shared HMAC secret authenticates the body, it does not "
                    "establish which producer signed it",
                )
            epoch_proof = _epoch_proof.verify_epoch_proof(
                cybergym_epoch_proof,
                secret=cybergym_epoch_proof_secret,
                network=network,
                netuid=netuid,
                source_epoch=source_epoch,
                # TRUSTED LOCAL time, deliberately not the bundle's `now`. The bundle
                # is operator input; letting it set the clock would let a backdated
                # bundle revive a stale proof, which is the freshness check's whole
                # purpose. `now` still drives receipt freshness, which is bound by
                # the signed receipt itself.
                now=datetime.now(UTC),
                expected_producer_hotkey=cybergym_expected_producer_hotkey,
                expected_evidence_sha256=cybergym_expected_evidence_sha256,
                # The pin is now optional defence in depth: the real binding is the
                # manifest recomputation below, which does not depend on an operator
                # typing a digest correctly.
                require_evidence_pin=False,
            )
        except _epoch_proof.EpochProofError as exc:
            epoch_proof_error = (
                f"{exc.reason}: {exc.detail}" if exc.detail else exc.reason
            )
        except Exception as exc:  # noqa: BLE001 - never abort honest lanes
            epoch_proof_error = f"{type(exc).__name__}: {exc}"
        _emit(
            events,
            "INTEGRATION_EPOCH_PROOF",
            status="PASS" if epoch_proof is not None else "FAIL",
            detail=epoch_proof_error
            or (
                f"producer {epoch_proof.producer_hotkey} closed epoch "
                f"{epoch_proof.source_epoch} with {epoch_proof.score_count} scored"
            ),
            lanes=",".join(sorted(funded_cybergym)),
        )
    proof_body_sha256 = None
    proof_semantic_sha256 = None
    if epoch_proof is not None and isinstance(cybergym_epoch_proof, Mapping):
        raw_body = cybergym_epoch_proof.get("body")
        if isinstance(raw_body, (str, bytes, bytearray)):
            body_bytes = (
                raw_body.encode("utf-8")
                if isinstance(raw_body, str)
                else bytes(raw_body)
            )
            proof_body_sha256 = sha256(body_bytes).hexdigest()
            proof_semantic_sha256 = sha256(
                _epoch_proof.canonical_bytes(
                    {
                        "producer_hotkey": epoch_proof.producer_hotkey,
                        "network": epoch_proof.network,
                        "netuid": epoch_proof.netuid,
                        "source_epoch": epoch_proof.source_epoch,
                        "generated_at": epoch_proof.generated_at,
                        "complete": True,
                        "score_units": epoch_proof.score_units,
                        "scores": dict(epoch_proof.scores),
                        "evidence_sha256": epoch_proof.evidence_sha256,
                    }
                )
            ).hexdigest()

    gates["cybergym_epoch_proof"] = {
        "required": sorted(funded_cybergym),
        "verified": epoch_proof is not None,
        "bound": None,
        "reason": epoch_proof_error,
        # A count, so name it a count. It previously read `scored_hotkeys`, which
        # invites a consumer to treat it as the set.
        "scored_hotkey_count": (
            epoch_proof.score_count if epoch_proof is not None else None
        ),
        # The exact digests, persisted into the audit so an activation decision can
        # point at WHICH bytes were authenticated rather than trusting that something
        # was. `body_sha256` covers the exact authenticated bytes; `semantic_sha256`
        # covers the normalized semantic document, which is what the producer's report
        # digest is taken over on the Cathedral side.
        "body_sha256": proof_body_sha256,
        "semantic_sha256": proof_semantic_sha256,
        # Surfaced so an operator reading the audit can see WHAT was attested and by
        # whom, rather than having to trust that something was checked.
        "producer_hotkey": (
            epoch_proof.producer_hotkey if epoch_proof is not None else None
        ),
        "producer_pinned": bool(cybergym_expected_producer_hotkey),
        "evidence_sha256": (
            epoch_proof.evidence_sha256 if epoch_proof is not None else None
        ),
        "evidence_pinned": bool(cybergym_expected_evidence_sha256),
        # Precise, so nobody reads the pin as provenance.
        "evidence_binding": (
            "recomputed from the admitted receipts as "
            f"{_evidence.SCHEMA}: the signed evidence digest must equal the canonical "
            "manifest over the finally credited (miner_hotkey, receipt_id, work_units) "
            "set for this audience epoch"
        ),
        "score_units": (epoch_proof.score_units if epoch_proof is not None else None),
        "authentication": (
            "shared-secret HMAC: authenticates the body and binds it to this audience "
            "and epoch. It is NOT public proof of producer identity."
        ),
    }

    verified = []
    for item in receipts:
        if (
            str(item.kind) in cybergym_kinds
            and item.lane in funded_cybergym
            and epoch_proof is None
        ):
            verified.append(
                _refused(
                    integrated_feed,
                    item,
                    "no verified producer epoch-completeness proof for this epoch "
                    f"({epoch_proof_error}); the lane's share burns rather than "
                    "paying a possibly partial epoch",
                )
            )
            continue
        verified.append(
            _decide(
                integrated_feed,
                item,
                known_lanes=known_lanes,
                burn_hotkey=resolved.burn_hotkey,
                key_registry=key_registry,
                source_epoch=source_epoch,
                now_iso=now_iso,
                current_block=current_block,
                gpu_attestation_verifier=gpu_attestation_verifier,
                cpu_quote_verifier=cpu_quote_verifier,
                allowed_measurements=allowed_measurements,
                allowed_tcb_statuses=allowed_tcb_statuses,
                allowed_advisories=allowed_advisories,
                # A deferred consumption needs the ledger threaded through the
                # verifier so the decision carries REPLAY_PENDING and its source
                # epoch; the contract reads nothing and writes nothing under it.
                #
                # In inspection mode the seam runs its own replay gate afterwards
                # (`_read_replay_gate`), so the per-receipt verifier does no replay
                # work. State that with the contract's typed opt-out instead of by
                # omission: the shared contract is closing a fail-open default where
                # an omitted ledger silently meant "no replay protection", and an
                # omission would then raise for every receipt, contain to a FAIL, and
                # compose a plausible 100% burn vector. NO_REPLAY_LEDGER is accepted
                # by both the current and the hardened contract.
                **(
                    {"consumption_ledger": ledger, "defer_consumption": True}
                    if authoritative
                    else {"consumption_ledger": _no_replay_sentinel_or_none()}
                ),
            )
        )

    # 4. Screen for receipts an EARLIER pass already credited, as a read. Then claim
    #    the epoch, so exactly one pass per epoch can record anything at all.
    #    Deduplication WITHIN this preview is not done here: composition owns all
    #    five of its drop rules and applies them incrementally, so the seam only
    #    owes it a canonical order (see `_composition_order`).
    decisions = _read_replay_gate(
        integrated_feed, verified, ledger=ledger, events=events
    )
    # 4b. Bind the producer epoch proof to the FINAL credited set, before the epoch
    #     claim and before any token is consumed. A dry composition (deferred marker
    #     cleared, no ledger) is the oracle for what the five admission rules will
    #     actually credit AFTER the replay read has dropped anything a previous pass
    #     consumed. Binding earlier let a replayed receipt drop out afterwards and
    #     hand its share to the survivor.
    if epoch_proof is not None and funded_cybergym:
        probe_order = _composition_order(decisions)
        probe = integrated_feed.compose_integrated(
            resolved,
            [
                replace(d, replay=integrated_feed.REPLAY_NONE)
                if d.replay == integrated_feed.REPLAY_PENDING
                else d
                for d in (decisions[i] for i in probe_order)
            ],
            consumption_ledger=None,
        )
        decisions, bind_detail = _bind_to_epoch_proof(
            integrated_feed,
            decisions,
            proof=epoch_proof,
            lanes=funded_cybergym,
            credited_rows=probe["audit"]["receipts"],
        )
        gates["cybergym_epoch_proof"]["bound"] = bind_detail is None
        if bind_detail is not None:
            gates["cybergym_epoch_proof"]["reason"] = bind_detail
            _emit(events, "INTEGRATION_EPOCH_PROOF", status="FAIL", detail=bind_detail)

    # 4c. Durable monotonic epoch admission for the authoritative pass. Runs BEFORE
    #     the epoch claim so a rolled-back or conflicting epoch claims nothing and
    #     consumes nothing. Keyed by audience, so two subnets cannot interfere.
    if authoritative and funded_cybergym and epoch_proof is not None:
        if not cybergym_epoch_state_path:
            detail = (
                "an authoritative pass on a funded CyberGym lane requires "
                "cybergym_epoch_state_path: without durable per-audience epoch state, "
                "a later epoch does not stop an earlier one from composing again, and "
                "each rollback burns its own distinct per-epoch token so replay "
                "protection does not catch it"
            )
            _emit(events, "INTEGRATION_EPOCH_STATE", status="FAIL", detail=detail)
            raise IntegrationPolicyError(detail)
        try:
            state = _epoch_state.CyberGymEpochState(cybergym_epoch_state_path)
            state.admit(
                network=network,
                netuid=netuid,
                source_epoch=source_epoch,
                # The digest of the exact authenticated bytes, so re-running the same
                # epoch is permitted only with byte-identical evidence.
                proof_digest=sha256(
                    _epoch_proof.canonical_bytes(
                        {
                            "signature": str(cybergym_epoch_proof.get("signature")),
                            "body": str(cybergym_epoch_proof.get("body")),
                        }
                    )
                ).hexdigest(),
                recorded_at=now.astimezone(UTC).isoformat(),
            )
        except _epoch_state.EpochStateError as exc:
            detail = f"{exc.reason}: {exc.detail}" if exc.detail else exc.reason
            _emit(events, "INTEGRATION_EPOCH_STATE", status="FAIL", detail=detail)
            raise IntegrationPolicyError(detail) from exc
        gates["cybergym_epoch_proof"]["epoch_state"] = "admitted"

    if authoritative:
        gates["authoritative_epoch_claim"] = _claim_authoritative_epoch(
            ledger,
            network=network,
            netuid=netuid,
            source_epoch=source_epoch,
            events=events,
        )
    for decision in decisions:
        _emit(
            events,
            "INTEGRATION_RECEIPT",
            status=decision.verdict,
            hotkey=decision.miner_hotkey,
            detail=decision.detail,
            lane=decision.lane,
            kind=decision.kind,
            receipt_id=decision.receipt_id,
            work_units=str(decision.work_units),
        )

    # 5. Compose one deterministic vector (missing/invalid lane -> burn) + audit.
    #    Every decision goes in, including one naming a lane the signed config does
    #    not fund: composition drops it with a reason and still emits its audit row,
    #    so the trail is complete and uniform without the seam rebuilding any row.
    #    The authoritative pass hands composition the ledger, because composition is
    #    the only point that knows a contribution is actually being credited and so
    #    the only safe place to burn a one-time token.
    order = _composition_order(decisions)
    deferred = {
        d.receipt_id: d
        for d in decisions
        if authoritative and d.replay == integrated_feed.REPLAY_PENDING
    }
    ordered = [decisions[i] for i in order]
    try:
        # The composer as its own oracle: the same decisions with the deferred
        # marker cleared and no ledger, which skips the consume step entirely and so
        # credits exactly what the five admission rules allow. Comparing that with
        # the real pass isolates a ledger refusal from a rule refusal without
        # reading either one's message text.
        expected_credited: set[str] = set()
        if authoritative:
            dry = integrated_feed.compose_integrated(
                resolved,
                [
                    replace(d, replay=integrated_feed.REPLAY_NONE)
                    if d.receipt_id in deferred
                    else d
                    for d in ordered
                ],
                consumption_ledger=None,
            )
            expected_credited = {
                row["receipt_id"] for row in dry["audit"]["receipts"] if row["credited"]
            }
        out = integrated_feed.compose_integrated(
            resolved,
            ordered,
            consumption_ledger=ledger if authoritative else None,
        )
    except Exception as exc:  # composition must not be reachable with bad input
        _emit(events, "INTEGRATION_VECTOR", status="FAIL", detail=str(exc))
        raise IntegrationError(f"composition rejected: {exc}") from exc
    feed, audit = out["feed"], out["audit"]
    audit["receipts"] = _restore_submission_order(audit["receipts"], order)
    # Composition reports a consume failure as one dropped contribution, which is
    # right for one receipt and catastrophic for an outage. Check its ledger effects
    # against the audit it just produced, by state.
    _audit_ledger_invariants(
        audit["receipts"],
        deferred,
        expected_credited=expected_credited,
        ledger=ledger,
        events=events,
    )
    for lane in audit["lanes"]:
        _emit(
            events,
            "INTEGRATION_LANE",
            status="PASS" if lane["contributing"] else "NOT_PROVEN",
            lane=lane["lane"],
            allocation=lane["allocation"],
            burned_allocation=lane["burned_allocation"],
        )
    _emit(
        events,
        "INTEGRATION_VECTOR",
        status="PASS",
        miners=len(feed["weights"]),
        forced_burn_percentage=feed["burn_snapshot"]["forced_burn_percentage"],
        effective_burn=audit["burn"]["effective_fraction"],
        detail="preview only, no chain write",
    )
    out["gates"] = gates
    return out


__all__ = [
    "IntegrationUnavailable",
    "IntegrationError",
    "IntegrationPolicyError",
    "IntegrationLedgerError",
    "REQUIRED_REWARD_GATES",
    "GATES_READ_BY_KIND",
    "DEFAULT_LANE_FOR_KIND",
    "LANE_CONTRACT_VERSION",
    "describe_lanes",
    "LANE_COMPUTE_CPU",
    "LANE_COMPUTE_GPU",
    "LANE_DISTILL",
    "LANE_CYBERGYM",
    "DISTILL_CONTRACT_COMMIT",
    "LaneReceipt",
    "preview_integrated_vector",
]
