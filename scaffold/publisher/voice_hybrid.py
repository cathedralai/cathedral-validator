"""Admission gates for source=cathedral_voice_hybrid external scores.

Mirrors Cathedral Voice Brief 3 / production checklist:
- complete snapshots only
- every positive score must carry cathedral_voice_receipt_v1
- honest GPU boundary flags (never attested / confidential GPU memory)
- optional rejection of simulated TDX measurements
"""
from __future__ import annotations

import json
import os
from typing import Any


RECEIPT_VERSION = "cathedral_voice_receipt_v1"
SOURCE = "cathedral_voice_hybrid"
MEASUREMENT_FORMAT = "cathedral_tdx_measurement_v1"


class VoiceHybridError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def allow_simulation() -> bool:
    """CI / dry-run only. Production must leave this unset/false."""
    return _env_bool("CATHEDRAL_VOICE_HYBRID_ALLOW_SIMULATION", False)


def require_tdx_measurement() -> bool:
    return _env_bool("CATHEDRAL_VOICE_HYBRID_REQUIRE_TDX", True)


def _parse_measurement(raw: Any) -> dict[str, Any] | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise VoiceHybridError("invalid_controller_measurement")
    try:
        data = json.loads(raw)
    except Exception as exc:
        raise VoiceHybridError("invalid_controller_measurement") from exc
    if not isinstance(data, dict):
        raise VoiceHybridError("invalid_controller_measurement")
    return data


def validate_receipt_object(
    receipt: Any,
    *,
    miner_hotkey: str,
    score: float,
) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise VoiceHybridError("receipt_missing")
    version = str(receipt.get("version") or "")
    if version != RECEIPT_VERSION:
        raise VoiceHybridError("invalid_receipt_version")
    status = str(receipt.get("status") or "")
    if status != "ok":
        raise VoiceHybridError("receipt_not_ok")
    hk = str(receipt.get("miner_hotkey") or "").strip()
    if not hk or hk != miner_hotkey:
        raise VoiceHybridError("receipt_hotkey_mismatch")
    if not str(receipt.get("request_hash") or "").strip():
        raise VoiceHybridError("receipt_request_hash_missing")
    if not str(receipt.get("audio_content_hash") or "").strip():
        raise VoiceHybridError("receipt_audio_hash_missing")
    if not str(receipt.get("signature") or "").strip():
        raise VoiceHybridError("receipt_signature_missing")

    # Honest hybrid boundary — never accept GPU attestation claims.
    if bool(receipt.get("gpu_attested")):
        raise VoiceHybridError("gpu_attested_forbidden")
    if bool(receipt.get("gpu_memory_confidential")):
        raise VoiceHybridError("gpu_memory_confidential_forbidden")

    measurement = _parse_measurement(receipt.get("controller_measurement"))
    if require_tdx_measurement() and measurement is None:
        raise VoiceHybridError("tdx_measurement_required")
    if measurement is not None:
        fmt = str(measurement.get("format") or "")
        if fmt and fmt != MEASUREMENT_FORMAT:
            raise VoiceHybridError("invalid_measurement_format")
        if bool(measurement.get("debug")):
            raise VoiceHybridError("tdx_debug_forbidden")
        if bool(measurement.get("simulated")) and not allow_simulation():
            raise VoiceHybridError("tdx_simulation_forbidden")
        if not str(measurement.get("mrtd") or "").strip():
            raise VoiceHybridError("tdx_mrtd_missing")
        if not str(measurement.get("quote") or "").strip():
            raise VoiceHybridError("tdx_quote_missing")
        m_hk = str(measurement.get("hotkey") or "").strip()
        if m_hk and m_hk != miner_hotkey:
            raise VoiceHybridError("tdx_hotkey_mismatch")

    # Zero scores may still carry receipts (revoke), but positive scores must.
    if score > 0.0 and status != "ok":
        raise VoiceHybridError("positive_score_requires_ok_receipt")
    return receipt


def validate_report_metadata(metadata: Any) -> dict[str, Any]:
    meta = metadata if isinstance(metadata, dict) else {}
    if meta.get("receipt_verified") is not True:
        raise VoiceHybridError("receipt_verified_required")
    if bool(meta.get("gpu_attested")):
        raise VoiceHybridError("gpu_attested_forbidden")
    if bool(meta.get("gpu_memory_confidential")):
        raise VoiceHybridError("gpu_memory_confidential_forbidden")
    return meta


def validate_hybrid_score_row(
    *,
    miner_hotkey: str,
    score: float,
    receipt: Any,
    report_metadata: Any,
) -> dict[str, Any]:
    """Fail-closed per-row gate used during normalize_report."""
    validate_report_metadata(report_metadata)
    if score > 0.0 and receipt is None:
        raise VoiceHybridError("receipt_missing")
    if receipt is None:
        # complete revoke row without receipt is allowed only for score==0
        return {}
    return validate_receipt_object(receipt, miner_hotkey=miner_hotkey, score=score)
