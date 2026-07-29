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

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Callable, Mapping, Sequence

_STAGE = "INTEGRATION"


class IntegrationUnavailable(RuntimeError):
    """The cathedral-distill integration dependency is not installed."""


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


# The gates a funded (nonzero-allocation) lane must be able to apply. Each
# allow-list is REQUIRED but MAY BE EMPTY: `frozenset()` is a deliberate
# deny-everything policy, and it is a different state from `None`, which means
# the operator never expressed a policy at all. Only the second is refused.
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


def _require_distill():
    try:
        from cathedral_distill import integrated_feed, signed_config  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised via the test's skip
        raise IntegrationUnavailable(
            "the Compute+Distill integration needs the cathedral-distill package; "
            "install it with: python -m pip install -e '.[integration]'"
        ) from exc
    return integrated_feed, signed_config


@dataclass(frozen=True)
class LaneReceipt:
    """One receipt to verify, tagged with its kind and the lane it feeds."""

    kind: str  # integrated_feed.KIND_COMPUTE_CPU / _GPU / _DISTILL / _CYBERGYM
    lane: str  # the lane id in the signed allocation config
    receipt: Mapping[str, Any]


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
    receipt can also fail *outside* them: an unknown kind, a lane the signed
    allocation does not fund, an exception raised by an injected verifier or by
    the ledger. Those escaped the seam unwrapped and aborted the whole preview,
    so one malformed contribution destroyed every honest lane's vector too.
    """
    if item.lane not in known_lanes:
        # `compose_integrated` raises on an unfunded lane. A receipt naming a
        # lane the config does not fund cannot earn, but it must not be able to
        # abort the vector either.
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
            item.kind, item.receipt, lane=item.lane, **gates
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


def _deduplicate(integrated_feed, decisions: Sequence[Any]) -> list[Any]:
    """Credit each receipt once and each miner once per lane, deterministically.

    `compose_integrated` raises when a miner has two credited receipts in one
    lane, which aborts the entire preview for a case that is not even
    adversarial: a miner may legitimately hold two valid receipts in one epoch.
    Resolve it here instead, and resolve it independently of submission order:
    the lowest `receipt_id` is credited and every other candidate is refused with
    an explicit reason. The same receipt replayed into two lanes earns once.
    """
    winner_for_receipt: dict[str, tuple] = {}
    winner_for_miner: dict[tuple[str, str], str] = {}
    for d in decisions:
        if not d.creditable:
            continue
        rank = (d.lane, d.kind)
        if (
            d.receipt_id not in winner_for_receipt
            or rank < winner_for_receipt[d.receipt_id]
        ):
            winner_for_receipt[d.receipt_id] = rank
        key = (d.lane, d.miner_hotkey)
        if key not in winner_for_miner or d.receipt_id < winner_for_miner[key]:
            winner_for_miner[key] = d.receipt_id

    def refuse(decision, detail: str):
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
    credited_receipts: set[str] = set()
    credited_miners: set[tuple[str, str]] = set()
    for d in decisions:
        if not d.creditable:
            out.append(d)
            continue
        if d.receipt_id in credited_receipts or winner_for_receipt[d.receipt_id] != (
            d.lane,
            d.kind,
        ):
            out.append(
                refuse(
                    d,
                    f"receipt {d.receipt_id} is credited once only; it is already "
                    "credited elsewhere in this preview",
                )
            )
            continue
        key = (d.lane, d.miner_hotkey)
        if key in credited_miners or winner_for_miner[key] != d.receipt_id:
            out.append(
                refuse(
                    d,
                    f"miner already has a credited receipt in lane {d.lane}; "
                    f"{winner_for_miner[key]} is the credited one",
                )
            )
            continue
        credited_receipts.add(d.receipt_id)
        credited_miners.add(key)
        out.append(d)
    return out


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
      ``allow_unpoliced_preview=True``;
    * a receipt whose subject is the configured burn hotkey is FAIL, never a
      reward subject;
    * an individual receipt that cannot be verified, for any reason including an
      unexpected error inside an injected verifier, becomes a FAIL/NOT_PROVEN
      receipt whose lane share goes to burn, never another lane and never an
      aborted vector;
    * one receipt earns at most once across the whole preview, and a miner with
      two credited receipts in one lane keeps exactly one, deterministically.

    ``gates`` records, per lane, which admission gates were actually applied, so
    an operator can see a policy omission instead of inferring it from silence.
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
    supplied = {
        "allowed_measurements": allowed_measurements,
        "allowed_tcb_statuses": allowed_tcb_statuses,
        "allowed_advisories": allowed_advisories,
        "current_block": current_block,
        "consumption_ledger": consumption_ledger,
    }
    omitted = [name for name in REQUIRED_REWARD_GATES if supplied[name] is None]
    reward_lanes = sorted(
        lane for lane, alloc in resolved.lane_allocations.items() if alloc > 0
    )
    gates = {
        "reward_lanes": reward_lanes,
        "omitted_gates": omitted,
        "unpoliced_preview": bool(allow_unpoliced_preview),
        "applied": {name: supplied[name] is not None for name in REQUIRED_REWARD_GATES},
        "lanes": {
            lane: {
                "allocation": str(alloc),
                "reward_lane": alloc > 0,
                "measurement_policy": allowed_measurements is not None,
                "tcb_policy": allowed_tcb_statuses is not None,
                "advisory_policy": allowed_advisories is not None,
                "block_window": current_block is not None,
                "consumption_ledger": consumption_ledger is not None,
            }
            for lane, alloc in sorted(resolved.lane_allocations.items())
        },
    }
    if omitted and reward_lanes and not allow_unpoliced_preview:
        detail = (
            "funded reward lanes "
            + ", ".join(reward_lanes)
            + " previewed without "
            + ", ".join(omitted)
            + "; pass allow_unpoliced_preview=True for a deliberately unpoliced "
            "shadow preview, or supply the gate (an empty allow-list is a valid, "
            "explicit deny-everything policy)"
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

    # 3. Independently verify each lane receipt. Every failure is contained here:
    #    one malformed contribution can never abort the complete vector.
    known_lanes = set(resolved.lane_allocations)
    verified = []
    for item in receipts:
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
                consumption_ledger=consumption_ledger,
                allowed_measurements=allowed_measurements,
                allowed_tcb_statuses=allowed_tcb_statuses,
                allowed_advisories=allowed_advisories,
            )
        )

    # 4. Deduplicate before composing: one receipt earns once across the whole
    #    preview, and a miner with two credited receipts in one lane keeps
    #    exactly one. Both cases raise inside `compose_integrated`, which would
    #    abort the vector for every honest lane too.
    decisions = _deduplicate(integrated_feed, verified)
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
    #    A refusal against a lane the config does not fund cannot be composed at
    #    all (composition rejects the unknown lane, by design), so it is kept out
    #    of the composition and folded back into the audit afterwards: no
    #    contribution is lost from the trail, and no contribution can abort it.
    composable = [d for d in decisions if d.lane in known_lanes]
    unfunded = [d for d in decisions if d.lane not in known_lanes]
    try:
        out = integrated_feed.compose_integrated(resolved, composable)
    except Exception as exc:  # composition must not be reachable with bad input
        _emit(events, "INTEGRATION_VECTOR", status="FAIL", detail=str(exc))
        raise IntegrationError(f"composition rejected: {exc}") from exc
    feed, audit = out["feed"], out["audit"]
    for d in unfunded:
        audit["receipts"].append(
            {
                "receipt_id": d.receipt_id,
                "kind": d.kind,
                "lane": d.lane,
                "verdict": d.verdict,
                "detail": d.detail,
                "miner_hotkey": d.miner_hotkey,
                "work_units": str(d.work_units),
                "lane_allocation": "0",
                "final_weight": 0.0,
            }
        )
        audit["verdicts"][d.verdict.lower()] += 1
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
    "REQUIRED_REWARD_GATES",
    "DEFAULT_LANE_FOR_KIND",
    "LANE_COMPUTE_CPU",
    "LANE_COMPUTE_GPU",
    "LANE_DISTILL",
    "LANE_CYBERGYM",
    "LaneReceipt",
    "preview_integrated_vector",
]
