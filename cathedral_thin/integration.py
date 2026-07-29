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
from typing import Any, Callable, Mapping, Sequence

_STAGE = "INTEGRATION"


class IntegrationUnavailable(RuntimeError):
    """The cathedral-distill integration dependency is not installed."""


class IntegrationError(RuntimeError):
    """The integration preview could not be produced (e.g. an invalid config)."""


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
    events: Any = None,
) -> dict[str, Any]:
    """Verify the signed config and every lane receipt, then compose + audit one
    preview vector. Emits validator events at each stage and RETURNS the
    ``{feed, audit}`` — it never writes weights.

    Fails closed: an invalid burn/allocation config raises ``IntegrationError``
    (after a FAIL event); an individual receipt that cannot be verified becomes a
    FAIL/NOT_PROVEN lane whose share goes to burn, never another lane.
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

    # 2. Independently verify each lane receipt; one event per receipt carries its
    #    PASS / FAIL / NOT_PROVEN verdict.
    decisions = []
    for item in receipts:
        decision = integrated_feed.verify_lane_receipt(
            item.kind,
            item.receipt,
            lane=item.lane,
            key_registry=key_registry,
            source_epoch=source_epoch,
            now_iso=now_iso,
            gpu_attestation_verifier=gpu_attestation_verifier,
            cpu_quote_verifier=cpu_quote_verifier,
        )
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
        decisions.append(decision)

    # 3. Compose one deterministic vector (missing/invalid lane -> burn) + audit.
    out = integrated_feed.compose_integrated(resolved, decisions)
    feed, audit = out["feed"], out["audit"]
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
        detail="preview only — no chain write",
    )
    return out


__all__ = [
    "IntegrationUnavailable",
    "IntegrationError",
    "LaneReceipt",
    "preview_integrated_vector",
]
