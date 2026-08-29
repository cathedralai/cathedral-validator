"""Coherent launch profiles instead of per-feature env sprawl.

One operator-facing knob selects a self-consistent mechanism configuration.
Fine-grained CATHEDRAL_V2_* flags still exist for tests and surgical rollout,
but deployments should set exactly one CATHEDRAL_LAUNCH_PROFILE and stop.

Profiles:
  (unset)        -- development/compatibility behavior, byte-identical: every
                    feature keeps its own default (off unless its env says
                    otherwise). Production refuses this posture.
  v2-converged   -- the single unified miner protocol:
                    * V2 surface on (CATHEDRAL_V2_ENABLED)
                    * bitset submit on (CATHEDRAL_V2_SUBMIT_BITSET_ENABLED)
                    * lazy issuance on (CATHEDRAL_V2_LAZY_ISSUANCE)
                    * PM payout bridge on (CATHEDRAL_V2_PM_PAYOUT_BRIDGE)
                    * startup env pinning on (no V2 per-request env lock)
                    * production pins the repository's canonical recurring
                      validated_supply_v1 producer contract: v2, 90% validated
                      TDX, 10% fixed burn, confidential-primary input, plus the
                      proportional / bonus / payable-off / planted posture
                    V1 miner routes are blocked by the production origin guard;
                    validators consume the unchanged signed weight vector.

Fail-closed: contradictory explicit env under a profile is a boot error, not a
silent precedence rule. Dangerous combos (split V2 DB with the payout bridge,
missing submit-token secret) refuse to boot.

Production is explicit. CATHEDRAL_ENV=production requires a named profile and
one shared Postgres store. The profile then enables strict parsing:
unknown economic modes, malformed numeric values, and development bypasses are
startup errors. Compatibility behavior remains available only when production
is not selected.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from typing import Any
from urllib.parse import urlsplit

from ..wire_vector import MAX_VECTOR_LIFETIME_SECONDS

PROFILE_ENV = "CATHEDRAL_LAUNCH_PROFILE"
V2_CONVERGED = "v2-converged"
_KNOWN_PROFILES = {"", V2_CONVERGED}
_FALSY = {"0", "false", "no", "off"}
_TRUTHY = {"1", "true", "yes", "on"}
_LEGACY_PRODUCTION_VALUES = {"prod", "production", "mainnet"}
_SN39_BURN_HOTKEY = "5GP7c3fFazW9GXK8Up3qgu2DJBk8inu4aK9TZy3RuoSWVCMi"
_SN39_WEIGHT_POLICY_KEY_ID = "cathedral-weight-policy"
_SN39_WEIGHT_POLICY_PUBLIC_KEY_HEX = (
    "10890a66aa752479cb3b634f366d7bd27c374324d83f88d2d6b69ab066f25e26"
)

# V2 challenge identity and credit are one code-owned production contract.
# Production rejects per-process env overrides and pins these exact values into
# the legacy generator once at startup. This keeps API and verifier replicas on
# identical epochs, CNF hashes, allotments, and credited tier weights.
V2_CONVERGED_PERMINER_CONTRACT: dict[str, Any] = {
    "epoch_bucket_hours": 1,
    "max_page_limit": 50,
    "tiers": {
        "1": {
            "allotment": 10_000,
            "weight": 1.0,
            "method": "biased",
            "nvars": 400,
            "nclauses": 1704,
        },
        "2": {
            "allotment": 10_000,
            "weight": 2.0,
            "method": "ajm",
            "nvars": 400,
            "nclauses": 1704,
        },
    },
}

V2_CONVERGED_PERMINER_LEGACY_ENV = {
    "CATHEDRAL_PERMINER_EPOCH_BUCKET_HOURS": "1",
    "CATHEDRAL_PERMINER_MAX_PAGE_LIMIT": "50",
    "CATHEDRAL_PERMINER_ALLOTMENT_T1": "10000",
    "CATHEDRAL_PERMINER_ALLOTMENT_T2": "10000",
    "CATHEDRAL_PERMINER_WEIGHT_T1": "1",
    "CATHEDRAL_PERMINER_WEIGHT_T2": "2",
    "CATHEDRAL_PERMINER_METHOD_T1": "biased",
    "CATHEDRAL_PERMINER_METHOD_T2": "ajm",
    "CATHEDRAL_PERMINER_NVARS_T1": "400",
    "CATHEDRAL_PERMINER_NVARS_T2": "400",
    "CATHEDRAL_PERMINER_NCLAUSES_T1": "1704",
    "CATHEDRAL_PERMINER_NCLAUSES_T2": "1704",
}

_V2_PERMINER_PROFILE_OVERRIDE_ENVS = {
    *V2_CONVERGED_PERMINER_LEGACY_ENV,
    "CATHEDRAL_PERMINER_EPOCH_HOURS",
    "CATHEDRAL_PERMINER_SEED_SECRET",
    "CATHEDRAL_REFILL_SEED_SECRET",
    "CATHEDRAL_PUBLISHER_SEED_SECRET",
    "CATHEDRAL_V2_PERMINER_EPOCH_HOURS",
    "CATHEDRAL_V2_PERMINER_EPOCH_BUCKET_HOURS",
    "CATHEDRAL_V2_PERMINER_MAX_PAGE_LIMIT",
    "CATHEDRAL_V2_PERMINER_ALLOTMENT_T1",
    "CATHEDRAL_V2_PERMINER_ALLOTMENT_T2",
    "CATHEDRAL_V2_PERMINER_WEIGHT_T1",
    "CATHEDRAL_V2_PERMINER_WEIGHT_T2",
    "CATHEDRAL_V2_PERMINER_METHOD_T1",
    "CATHEDRAL_V2_PERMINER_METHOD_T2",
    "CATHEDRAL_V2_PERMINER_NVARS_T1",
    "CATHEDRAL_V2_PERMINER_NVARS_T2",
    "CATHEDRAL_V2_PERMINER_NCLAUSES_T1",
    "CATHEDRAL_V2_PERMINER_NCLAUSES_T2",
}

_STRICT_ENUMS: dict[str, tuple[str, ...]] = {
    "CATHEDRAL_WEIGHTS_MODE": (
        "proportional",
        "flat_recent",
        "row_score_recent",
    ),
    "CATHEDRAL_PERMINER_SCORING_MODE": (
        "bonus",
        "pm_primary",
        "assigned_only",
    ),
    "CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS": ("off", "mark", "filter"),
    "CATHEDRAL_V2_CHALLENGE_SOURCE": ("planted", "combinatorial", "corpus"),
    "CATHEDRAL_V2_COMBINATORIAL_KIND": ("coloring", "latin"),
    "CATHEDRAL_EXTERNAL_SCORES_MODE": (
        "blend",
        "external_primary",
        "confidential_primary",
    ),
    "CATHEDRAL_ALLOCATION_CONTRACT": ("v2", "v3"),
    "CATHEDRAL_SERVICE_ROLE": ("all", "read", "submit", "worker"),
    "CATHEDRAL_CLIENT_IP_MODE": ("headers", "railway", "socket"),
}

# These are escape hatches, not production features. Explicitly setting one to
# false is harmless and accepted so generated EnvironmentFiles remain usable.
_PRODUCTION_FORBIDDEN_TRUTHY = {
    "CATHEDRAL_ARENA_EVAL_ENABLED",
    "CATHEDRAL_ARENA_PAYOUT_ENABLED",
    "CATHEDRAL_ASYNC_VERIFY_ENABLED",
    "CATHEDRAL_ATTEST_ENABLED",
    "CATHEDRAL_ATTEST_ALLOW_STUB",
    "CATHEDRAL_AUDIT_SCANNER_ENABLED",
    "CATHEDRAL_ABUSE_LIMIT_ENABLED",
    "CATHEDRAL_CYBERGYM_INGEST_ENABLED",
    "CATHEDRAL_EXTERNAL_SCORES_ALLOW_UNAUTHENTICATED",
    "CATHEDRAL_MECH_WEIGHTSET_ALLOW_MAINNET",
    "CATHEDRAL_PERMINER_SHADOW",
    "CATHEDRAL_PM_ASYNC_SHADOW",
    "CATHEDRAL_PM_SUBMIT_ASYNC_ENABLED",
    "CATHEDRAL_REFILL_ENABLED",
    "CATHEDRAL_SAT_GENERATOR_ENABLED",
    "CATHEDRAL_SEED_ON_BOOT",
    "CATHEDRAL_SUBMIT_ASYNC_ENABLED",
    "CATHEDRAL_PERMINER_ENABLED",
    "CATHEDRAL_PER_HOTKEY_LIMIT_ENABLED",
    "CATHEDRAL_RETENTION_ENABLED",
    "CATHEDRAL_SUBMIT_HARD_CAP_BYPASS",
    "CATHEDRAL_V2_INGRESS_DISABLE_PROCESS_LOCK",
    "CATHEDRAL_V2_INGRESS_ALLOW_MULTI_WORKER",
    "CATHEDRAL_V2_SUBMIT_BACKPRESSURE_ENABLED",
    "CATHEDRAL_V2_SHADOW_V1_ENABLED",
}

# One profile must mean one economic posture. A different valid value is not a
# deployment-time tweak; it needs a separately named, reviewed launch profile.
_PRODUCTION_PINNED_VALUES = {
    "CATHEDRAL_ALLOCATION_CONTRACT": "v2",
    "CATHEDRAL_VALIDATED_SUPPLY_ENABLED": "true",
    "CATHEDRAL_WEIGHTS_MODE": "proportional",
    "CATHEDRAL_PERMINER_SCORING_MODE": "bonus",
    "CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS": "off",
    "CATHEDRAL_PERMINER_REQUIRE_COLDKEY": "true",
    "CATHEDRAL_V2_CHALLENGE_SOURCE": "planted",
    "CATHEDRAL_V2_VERIFY_WORKER_ENABLED": "true",
    "CATHEDRAL_SERVICE_ROLE": "all",
    "CATHEDRAL_CLIENT_IP_MODE": "headers",
    "CATHEDRAL_DASHBOARD_SNAPSHOT_ENABLED": "false",
    "CATHEDRAL_MATERIALIZED_SNAPSHOT_ENABLED": "false",
    "CATHEDRAL_TEE_GPU_ENABLED": "false",
    "CATHEDRAL_EXTERNAL_SCORES_ENABLED": "true",
    "CATHEDRAL_EXTERNAL_SCORES_INGEST_ENABLED": "true",
    "CATHEDRAL_EXTERNAL_SCORES_MODE": "confidential_primary",
    "CATHEDRAL_EXTERNAL_SCORES_SOURCE": "cathedral_confidential_tdx",
    "CATHEDRAL_EXTERNAL_SCORES_PRIMARY_CONFIRM": "true",
    "CATHEDRAL_EXTERNAL_SCORES_REQUIRE_REGISTERED": "true",
    "CATHEDRAL_EXTERNAL_SCORES_REQUIRE_EVIDENCE": "false",
    # These defaults are security and protocol behavior, not tuning knobs.
    # Pin them explicitly so a stale vector is never served as healthy, public
    # submit-token minting is never silently narrowed, and otherwise-valid
    # submissions do not gain a replica-specific metadata requirement.
    "CATHEDRAL_WEIGHTS_ORIGIN_FAILCLOSED": "true",
    "CATHEDRAL_V2_SUBMIT_TOKEN_ALLOWLIST": "",
    "CATHEDRAL_V2_REQUIRE_SOLVER_META": "false",
    "CATHEDRAL_V2_BLOB_UPLOAD_ENABLED": "false",
    "CATHEDRAL_V2_CNF_ARTIFACTS_ENABLED": "false",
    "CATHEDRAL_V2_RESULTS_PUBLISH_ENABLED": "false",
    "CATHEDRAL_WEIGHTS_COLDKEY_COLLAPSE": "false",
    # An empty aggregate map selects the separately pinned tier-2 multiplier.
    "CATHEDRAL_WEIGHTS_TIER_WEIGHTS": "",
    "CATHEDRAL_WEIGHT_POLICY_NETWORK": "finney",
    "CATHEDRAL_WEIGHT_POLICY_NETUID": "39",
    "CATHEDRAL_WEIGHT_POLICY_KEY_ID": _SN39_WEIGHT_POLICY_KEY_ID,
    "CATHEDRAL_WEIGHT_POLICY_BURN_HOTKEY": _SN39_BURN_HOTKEY,
    # Empty is intentional and must be explicit: production resolves the burn
    # UID from the pinned hotkey at each finalized metagraph read.
    "CATHEDRAL_WEIGHT_POLICY_BURN_UID": "",
}

_PRODUCTION_PINNED_NUMERICS = {
    "CATHEDRAL_WEIGHTS_WINDOW_HOURS": 24.0,
    "CATHEDRAL_WEIGHTS_TIER2_MULT": 3.0,
    "CATHEDRAL_PERMINER_BONUS_MULT": 0.2,
    "CATHEDRAL_PERMINER_HISTORY_FLOOR": 0.25,
    "CATHEDRAL_V2_REAL_FRACTION": 0.0,
    "CATHEDRAL_V2_SUBMIT_TOKEN_TTL_SECS": 300.0,
    "CATHEDRAL_V2_SUBMIT_BITSET_MAX_BODY_BYTES": 16_384.0,
    "CATHEDRAL_EXTERNAL_SCORES_WINDOW_SECS": 3600.0,
    "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_AGE_SECS": 3600.0,
    "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_FUTURE_SECS": 120.0,
    "CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS_MAX_AGE_SECS": 600.0,
    "CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2": 10.0,
    "CATHEDRAL_WEIGHT_POLICY_VALID_FOR_SECS": 1800.0,
    "CATHEDRAL_EXTERNAL_SCORES_MAX_SCORES": 4096.0,
    "CATHEDRAL_EXTERNAL_SCORES_MAX_BODY_BYTES": 1_048_576.0,
    "CATHEDRAL_RATELIMIT_RPM": 120.0,
    "CATHEDRAL_TRUSTED_PROXY_HOPS": 1.0,
    # The configured ceiling stays at 24 while the reviewed hard cap clamps
    # bitset admission to 8. Pin both so 0 cannot disable the bound.
    "CATHEDRAL_SUBMIT_MAX_CONCURRENCY": 24.0,
    "CATHEDRAL_SUBMIT_HARD_CAP": 8.0,
    "CATHEDRAL_SUBMIT_BUSY_WAIT_SECS": 0.35,
}

_STRICT_BOOLEAN_ENVS = {
    name
    for name, value in _PRODUCTION_PINNED_VALUES.items()
    if value in {"true", "false"}
}

_PRODUCTION_REQUIRED_SECRETS = (
    "CATHEDRAL_EXTERNAL_SCORES_TOKEN_CATHEDRAL_CONFIDENTIAL_TDX",
    "CATHEDRAL_EXTERNAL_SCORES_HMAC_SECRET_CATHEDRAL_CONFIDENTIAL_TDX",
)

_PROFILE_OWNED_ON_FLAGS = (
    "CATHEDRAL_V2_ENABLED",
    "CATHEDRAL_V2_SUBMIT_BITSET_ENABLED",
    "CATHEDRAL_V2_LAZY_ISSUANCE",
    "CATHEDRAL_V2_PM_PAYOUT_BRIDGE",
    "CATHEDRAL_V2_PERMINER_ENABLED",
    "CATHEDRAL_V2_VERIFY_WORKER_ENABLED",
)

# Economic and protocol numbers whose previous helpers silently substituted a
# default on malformed input. Validation happens before the app opens its
# store, so a typo never reaches vector composition under the named profile.
_STRICT_FLOAT_ENVS = {
    "CATHEDRAL_CYBERGYM_WEIGHT_FRACTION",
    "CATHEDRAL_EXTERNAL_SCORES_BASE_WEIGHT",
    "CATHEDRAL_EXTERNAL_SCORES_FRACTION",
    "CATHEDRAL_EXTERNAL_SCORES_MAX_FRACTION",
    "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_AGE_SECS",
    "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_FUTURE_SECS",
    "CATHEDRAL_EXTERNAL_SCORES_WEIGHT",
    "CATHEDRAL_EXTERNAL_SCORES_WINDOW_SECS",
    "CATHEDRAL_V2_ERROR_BACKOFF_CAP_SECS",
    "CATHEDRAL_V2_ERROR_BACKOFF_FLOOR_SECS",
    "CATHEDRAL_PERMINER_BONUS_MULT",
    "CATHEDRAL_PERMINER_HISTORY_FLOOR",
    "CATHEDRAL_PERMINER_REAL_FRACTION",
    "CATHEDRAL_PERMINER_SCORE_TARGET",
    "CATHEDRAL_SUBMIT_BUSY_WAIT_SECS",
    "CATHEDRAL_V2_REAL_FRACTION",
    "CATHEDRAL_V2_VERIFY_LOCK_SECS",
    "CATHEDRAL_V2_WEIGHTS_VALID_FOR_SECS",
    "CATHEDRAL_V2_WEIGHTS_WINDOW_HOURS",
    "CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS_MAX_AGE_SECS",
    "CATHEDRAL_WEIGHTS_TIER2_MULT",
    "CATHEDRAL_WEIGHTS_WINDOW_HOURS",
    "CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2",
    "CATHEDRAL_WEIGHT_POLICY_VALID_FOR_SECS",
}
_STRICT_INT_ENVS = {
    "CATHEDRAL_PG_CONNECT_TIMEOUT",
    "CATHEDRAL_PG_POOL_MAX",
    "CATHEDRAL_PG_POOL_MIN",
    "CATHEDRAL_PG_STATEMENT_TIMEOUT_MS",
    "CATHEDRAL_DASHBOARD_PM_LIMIT",
    "CATHEDRAL_EXTERNAL_SCORES_MAX_SCORES",
    "CATHEDRAL_RATELIMIT_RPM",
    "CATHEDRAL_TRUSTED_PROXY_HOPS",
    "CATHEDRAL_PERMINER_EPOCH_BUCKET_HOURS",
    "CATHEDRAL_PERMINER_EPOCH_HOURS",
    "CATHEDRAL_PERMINER_MAX_PAGE_LIMIT",
    "CATHEDRAL_PERMINER_RECOVER_INDEX_CACHE",
    "CATHEDRAL_PM_READ_HARD_CAP",
    "CATHEDRAL_PM_READ_MIN_CAP",
    "CATHEDRAL_PM_SUBMIT_MAX_SOLUTION_BYTES",
    "CATHEDRAL_SUBMIT_HARD_CAP",
    "CATHEDRAL_SUBMIT_MAX_CONCURRENCY",
    "CATHEDRAL_SUBMIT_MAX_SOLUTION_BYTES",
    "CATHEDRAL_SUBMIT_MIN_INTERVAL_SECS",
    "CATHEDRAL_SUBMIT_QUEUE_MAX_PENDING",
    "CATHEDRAL_V2_PERMINER_EPOCH_HOURS",
    "CATHEDRAL_V2_PERMINER_MAX_PAGE_LIMIT",
    "CATHEDRAL_V2_SUBMIT_BITSET_MAX_BODY_BYTES",
    "CATHEDRAL_V2_SUBMIT_TOKEN_TTL_SECS",
    "CATHEDRAL_V2_VERIFY_BATCH_SIZE",
    "CATHEDRAL_V2_VERIFY_MAX_BLOB_BYTES",
    "CATHEDRAL_WEIGHT_POLICY_BURN_UID",
    "CATHEDRAL_WEIGHT_POLICY_NETUID",
}
_STRICT_INT_PATTERN = re.compile(
    r"^CATHEDRAL_(?:(?:V2_)?PERMINER_(?:ALLOTMENT|NCLAUSES|NVARS)|"
    r"V2_COLORING_(?:COLORS|NODES)|V2_LATIN_ORDER)_T[0-9]+$"
)
_STRICT_FLOAT_PATTERN = re.compile(
    r"^CATHEDRAL_(?:V2_)?PERMINER_WEIGHT_T[0-9]+$"
)
_STRICT_METHOD_PATTERN = re.compile(
    r"^CATHEDRAL_(?:V2_)?PERMINER_METHOD_T[0-9]+$"
)
_STRICT_BYTES_ENVS = {"CATHEDRAL_EXTERNAL_SCORES_MAX_BODY_BYTES"}
_NONNEGATIVE_FLOAT_ENVS = {
    "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_AGE_SECS",
    "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_FUTURE_SECS",
}
_POSITIVE_INT_ENVS = {"CATHEDRAL_EXTERNAL_SCORES_MAX_SCORES"}
_SECRET_PLACEHOLDER_RE = re.compile(
    r"<[^>]+>|placeholder|change[-_ ]?me|replace[-_ ]?me|example",
    re.IGNORECASE,
)

_SECRET_NAME_PARTS = (
    "ACCESS_KEY",
    "DATABASE_URL",
    "HMAC_SECRET",
    "PRIVATE_KEY",
    "SECRET_KEY",
    "SEED_SECRET",
    "SIGNING_KEY",
    "TOKEN",
)


def profile() -> str:
    return os.environ.get(PROFILE_ENV, "").strip().lower()


def converged() -> bool:
    return profile() == V2_CONVERGED


def production() -> bool:
    """The one canonical Publisher production detector."""
    return os.environ.get("CATHEDRAL_ENV", "") == "production"


def strict() -> bool:
    """Named profiles always use strict parsing, including staging tests."""
    return converged()


def _validate_production_marker(errors: list[str]) -> None:
    canonical = os.environ.get("CATHEDRAL_ENV", "")
    if canonical and canonical != "production":
        errors.append(
            f"unsupported CATHEDRAL_ENV={canonical!r}; set exactly "
            "CATHEDRAL_ENV=production for production or leave it unset for "
            "development/compatibility"
        )

    for name in ("ENV", "APP_ENV", "CATHEDRAL_PRODUCTION"):
        value = os.environ.get(name, "")
        if value:
            errors.append(
                f"{name} is a legacy production marker; remove it and "
                "set exactly CATHEDRAL_ENV=production"
            )


def _validate_strict_values(errors: list[str]) -> None:
    for name in sorted(_STRICT_BOOLEAN_ENVS):
        raw = os.environ.get(name)
        if raw is None or raw == "":
            continue
        if raw.strip().lower() not in _TRUTHY | _FALSY:
            errors.append(
                f"invalid boolean {name}={raw!r}; expected true or false"
            )

    for name, choices in _STRICT_ENUMS.items():
        raw = os.environ.get(name)
        if raw is None or not raw.strip():
            continue
        value = raw.strip().lower()
        if value not in choices:
            errors.append(
                f"invalid {name}={value!r}; expected one of {', '.join(choices)}"
            )

    float_names = set(_STRICT_FLOAT_ENVS)
    float_names.update(name for name in os.environ if _STRICT_FLOAT_PATTERN.match(name))
    for name in sorted(float_names):
        raw = os.environ.get(name)
        if raw is None or not raw.strip():
            continue
        try:
            value = float(raw)
        except ValueError:
            errors.append(f"invalid numeric {name}={raw!r}")
            continue
        if not math.isfinite(value):
            errors.append(f"invalid finite numeric {name}={raw!r}")
            continue
        if name in _NONNEGATIVE_FLOAT_ENVS and value < 0.0:
            errors.append(f"invalid nonnegative numeric {name}={raw!r}")
        if name == "CATHEDRAL_WEIGHT_POLICY_VALID_FOR_SECS" and not (
            0.0 < value <= MAX_VECTOR_LIFETIME_SECONDS
        ):
            errors.append(
                f"invalid bounded numeric {name}={raw!r}; expected 0 < value <= "
                f"{MAX_VECTOR_LIFETIME_SECONDS:g}"
            )

    integer_names = set(_STRICT_INT_ENVS)
    integer_names.update(name for name in os.environ if _STRICT_INT_PATTERN.match(name))
    for name in sorted(integer_names):
        raw = os.environ.get(name)
        if raw is None or not raw.strip():
            continue
        try:
            value = int(raw)
        except ValueError:
            errors.append(f"invalid integer {name}={raw!r}")
            continue
        if name in _POSITIVE_INT_ENVS and value <= 0:
            errors.append(f"invalid positive integer {name}={raw!r}")

    method_names = sorted(
        name for name in os.environ if _STRICT_METHOD_PATTERN.match(name)
    )
    for name in method_names:
        raw = os.environ.get(name, "")
        if raw and raw.strip().lower() not in {"biased", "ajm"}:
            errors.append(
                f"invalid {name}={raw.strip().lower()!r}; expected biased or ajm"
            )

    for name in sorted(_STRICT_BYTES_ENVS):
        raw = os.environ.get(name)
        if raw is None or not raw.strip():
            continue
        if _parse_positive_bytes(raw) is None:
            errors.append(f"invalid positive byte count {name}={raw!r}")

    _validate_tier_weights(errors)


def _parse_positive_bytes(raw: str) -> int | None:
    match = re.fullmatch(r"([+]?[0-9]+)(MIB|MI|M)?", raw.strip(), re.IGNORECASE)
    if match is None:
        return None
    value = int(match.group(1))
    if value <= 0:
        return None
    if match.group(2):
        value *= 1024 * 1024
    return value


def _validate_tier_weights(errors: list[str]) -> None:
    name = "CATHEDRAL_WEIGHTS_TIER_WEIGHTS"
    raw = os.environ.get(name, "").strip()
    if not raw:
        return
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        items: list[tuple[Any, Any]] = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                errors.append(f"invalid atomic {name}: empty entry")
                return
            separator = "=" if "=" in part else ":" if ":" in part else None
            if separator is None:
                errors.append(f"invalid atomic {name}: {part!r} has no separator")
                return
            items.append(tuple(part.split(separator, 1)))
    else:
        if isinstance(decoded, dict):
            items = list(decoded.items())
        elif isinstance(decoded, list):
            items = list(enumerate(decoded, start=1))
        else:
            errors.append(f"invalid atomic {name}: expected object, list, or tier map")
            return

    if not items:
        errors.append(f"invalid atomic {name}: at least one tier is required")
        return
    tiers: set[int] = set()
    for raw_tier, raw_weight in items:
        if isinstance(raw_tier, bool) or isinstance(raw_weight, bool):
            errors.append(f"invalid atomic {name}: boolean tier or weight")
            return
        try:
            tier = int(str(raw_tier).strip())
            weight = float(raw_weight)
        except (TypeError, ValueError):
            errors.append(
                f"invalid atomic {name}: tier {raw_tier!r} weight {raw_weight!r}"
            )
            return
        if tier <= 0 or tier in tiers or not math.isfinite(weight) or weight <= 0.0:
            errors.append(
                f"invalid atomic {name}: tier {raw_tier!r} weight {raw_weight!r}"
            )
            return
        tiers.add(tier)


def _is_sensitive_name(name: str) -> bool:
    if name.endswith(("_KEY_ID", "_KEY_PREFIX", "_PUBLIC_KEY", "_PUBLIC_KEY_HEX")):
        return False
    if "HOTKEY" in name:
        return False
    return any(part in name for part in _SECRET_NAME_PARTS)


def _secret_quality_error(value: str, *, min_bytes: int = 32) -> str | None:
    if _SECRET_PLACEHOLDER_RE.search(value):
        return "is still a documented placeholder"
    encoded = value.encode("utf-8")
    if len(encoded) < min_bytes:
        return f"must contain at least {min_bytes} bytes"
    if len(set(encoded)) < 8:
        return "has insufficient character diversity"
    return None


def _private_key_error(value: str) -> str | None:
    if _SECRET_PLACEHOLDER_RE.search(value):
        return "is still a documented placeholder"
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return "must be 32-byte Ed25519 private-key hex"
    if len(raw) != 32:
        return "must be 32-byte Ed25519 private-key hex"
    if len(set(raw)) < 8:
        return "has insufficient byte diversity"
    return None


def _weight_policy_private_key(signing_key_hex: str | None) -> str:
    return (
        (signing_key_hex or "").strip()
        or os.environ.get("CATHEDRAL_EVAL_SIGNING_KEY", "").strip()
        or os.environ.get("CATHEDRAL_WEIGHT_POLICY_SIGNING_KEY", "").strip()
    )


def _derived_weight_policy_public_key(signing_key_hex: str | None) -> str | None:
    private_key = _weight_policy_private_key(signing_key_hex)
    if _private_key_error(private_key) is not None:
        return None
    from . import rows

    return rows.public_key_hex(private_key)


def _effective_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in _TRUTHY


def _effective_percentage(name: str, default: float = 0.0) -> float:
    """Mirror the publisher's clamped percentage for the startup record."""
    try:
        value = float(os.environ.get(name, "") or default)
    except ValueError:
        value = default
    return min(100.0, max(0.0, value))


def _effective_float(name: str, default: float) -> float:
    """Parse one finite numeric for the redacted startup record."""
    try:
        value = float(os.environ.get(name, "") or default)
    except ValueError:
        return default
    return value if math.isfinite(value) else default


def _effective_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _effective_submit_int(name: str, default: int) -> int:
    """Mirror submit admission's special empty-string-to-zero parsing."""
    raw = os.environ.get(name)
    try:
        return int(str(default) if raw is None else (raw or "0"))
    except ValueError:
        return default


def _effective_submit_max_concurrency() -> int:
    """Mirror the runtime hard-cap clamp in the effective configuration."""
    configured = _effective_submit_int("CATHEDRAL_SUBMIT_MAX_CONCURRENCY", 24)
    hard_cap = _effective_submit_int("CATHEDRAL_SUBMIT_HARD_CAP", 8)
    bypass = _effective_bool("CATHEDRAL_SUBMIT_HARD_CAP_BYPASS")
    if hard_cap > 0 and configured > 0 and not bypass:
        return min(configured, hard_cap)
    return configured


def _effective_submit_busy_wait_secs() -> float:
    """Mirror the runtime's default, empty-value behavior, and clamp."""
    raw = os.environ.get("CATHEDRAL_SUBMIT_BUSY_WAIT_SECS")
    try:
        value = float("0.35" if raw is None else (raw or "0"))
    except ValueError:
        return 0.35
    if not math.isfinite(value):
        return 0.35
    return max(0.0, min(2.0, value))


def _fingerprint(label: str, value: str) -> str | None:
    if not value:
        return None
    return hashlib.sha256(f"{label}\0{value}".encode("utf-8")).hexdigest()


def _database_identity_fingerprint(database_url: str) -> str | None:
    if not database_url:
        return None
    parsed = urlsplit(database_url)
    scheme = "postgresql" if parsed.scheme in {"postgres", "postgresql"} else (
        parsed.scheme.lower()
    )
    try:
        port = parsed.port or 5432
    except ValueError:
        port = 0
    # Deliberately omit username, password, and query values. Replicas using
    # rotated credentials for the same host/database should compare equal, and
    # the effective record must not make credential guessing easier.
    safe_identity = "|".join(
        (scheme, (parsed.hostname or "").lower(), str(port), parsed.path or "/")
    )
    return _fingerprint("cathedral-database-identity-v1", safe_identity)


def replica_identity_summary() -> dict[str, str | None]:
    """Non-secret deployment identity operators can compare across replicas."""
    return {
        "schema": "cathedral_publisher_replica_identity_v1",
        "publisher_generation_id": os.environ.get(
            "CATHEDRAL_PUBLISHER_GENERATION_ID", ""
        ).strip() or None,
        "database_identity_fingerprint": _database_identity_fingerprint(
            os.environ.get("DATABASE_URL", "").strip()
        ),
    }


def v2_perminer_contract_digest() -> str:
    payload = json.dumps(
        V2_CONVERGED_PERMINER_CONTRACT,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def effective_config_summary(
    *,
    database_path: str,
    service_role: str,
    storage_backend: str,
    signing_key_hex: str | None = None,
) -> dict[str, Any]:
    """Return the small redacted startup contract operators need to compare."""
    challenge_source = (
        os.environ.get("CATHEDRAL_V2_CHALLENGE_SOURCE", "planted").strip().lower()
        or "planted"
    )
    summary: dict[str, Any] = {
        "schema": "cathedral_publisher_effective_config_v1",
        "environment": "production" if production() else "development_compatibility",
        "launch_profile": profile() or "unset_compatibility",
        "service_role": service_role,
        "storage_backend": storage_backend,
        "database_path_configured": bool(database_path),
        "replica_identity": replica_identity_summary(),
        "signer": {
            "key_id": os.environ.get(
                "CATHEDRAL_WEIGHT_POLICY_KEY_ID", "cathedral-weight-policy"
            ).strip(),
            "public_key_hex": _derived_weight_policy_public_key(signing_key_hex),
            "network": os.environ.get(
                "CATHEDRAL_WEIGHT_POLICY_NETWORK", "finney"
            ).strip(),
            "netuid": os.environ.get("CATHEDRAL_WEIGHT_POLICY_NETUID", "39").strip(),
        },
        "economics": {
            "allocation_contract": (
                os.environ.get("CATHEDRAL_ALLOCATION_CONTRACT", "v2").strip().lower()
                or "v2"
            ),
            "weights_mode": (
                os.environ.get("CATHEDRAL_WEIGHTS_MODE", "proportional").strip().lower()
                or "proportional"
            ),
            "perminer_scoring_mode": (
                os.environ.get("CATHEDRAL_PERMINER_SCORING_MODE", "bonus").strip().lower()
                or "bonus"
            ),
            "perminer_bonus_multiplier": _effective_float(
                "CATHEDRAL_PERMINER_BONUS_MULT", 0.2
            ),
            "perminer_history_floor": _effective_float(
                "CATHEDRAL_PERMINER_HISTORY_FLOOR", 0.25
            ),
            "perminer_require_coldkey": _effective_bool(
                "CATHEDRAL_PERMINER_REQUIRE_COLDKEY", True
            ),
            "weights_window_hours": _effective_float(
                "CATHEDRAL_WEIGHTS_WINDOW_HOURS", 24.0
            ),
            "weights_tier2_multiplier": _effective_float(
                "CATHEDRAL_WEIGHTS_TIER2_MULT", 3.0
            ),
            "payable_hotkeys_mode": (
                os.environ.get("CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS", "off").strip().lower()
                or "off"
            ),
            "external_scores_mode": (
                os.environ.get("CATHEDRAL_EXTERNAL_SCORES_MODE", "blend").strip().lower()
                or "blend"
            ),
            "external_scores_enabled": _effective_bool(
                "CATHEDRAL_EXTERNAL_SCORES_ENABLED"
            ),
            "external_scores_ingest_enabled": _effective_bool(
                "CATHEDRAL_EXTERNAL_SCORES_INGEST_ENABLED"
            ),
            "external_scores_primary_confirmed": _effective_bool(
                "CATHEDRAL_EXTERNAL_SCORES_PRIMARY_CONFIRM"
            ),
            "external_scores_require_registered": _effective_bool(
                "CATHEDRAL_EXTERNAL_SCORES_REQUIRE_REGISTERED", True
            ),
            "external_scores_require_evidence": _effective_bool(
                "CATHEDRAL_EXTERNAL_SCORES_REQUIRE_EVIDENCE"
            ),
            "external_scores_source": (
                os.environ.get(
                    "CATHEDRAL_EXTERNAL_SCORES_SOURCE", "violet_audio"
                ).strip()
                or "violet_audio"
            ),
            "external_scores_window_secs": _effective_float(
                "CATHEDRAL_EXTERNAL_SCORES_WINDOW_SECS", 3600.0
            ),
            "external_scores_max_report_age_secs": _effective_float(
                "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_AGE_SECS", 3600.0
            ),
            "external_scores_max_report_future_secs": _effective_float(
                "CATHEDRAL_EXTERNAL_SCORES_MAX_REPORT_FUTURE_SECS", 120.0
            ),
            "external_scores_max_scores": _effective_int(
                "CATHEDRAL_EXTERNAL_SCORES_MAX_SCORES", 4096
            ),
            "external_scores_max_body_bytes": _effective_int(
                "CATHEDRAL_EXTERNAL_SCORES_MAX_BODY_BYTES", 1_048_576
            ),
            "registration_snapshot_max_age_secs": _effective_float(
                "CATHEDRAL_WEIGHTS_PAYABLE_HOTKEYS_MAX_AGE_SECS", 600.0
            ),
            "coldkey_collapse_enabled": _effective_bool(
                "CATHEDRAL_WEIGHTS_COLDKEY_COLLAPSE"
            ),
            "validated_supply_enabled": _effective_bool(
                "CATHEDRAL_VALIDATED_SUPPLY_ENABLED"
            ),
            "forced_burn_percentage": _effective_percentage(
                "CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2"
            ),
            "burn_hotkey": (
                os.environ.get("CATHEDRAL_WEIGHT_POLICY_BURN_HOTKEY", "").strip()
                or None
            ),
            "burn_uid": (
                os.environ.get("CATHEDRAL_WEIGHT_POLICY_BURN_UID", "204").strip()
                or None
            ),
        },
        "protocol": {
            "v2_converged": converged(),
            "challenge_source": challenge_source,
            "real_challenge_fraction": _effective_float(
                "CATHEDRAL_V2_REAL_FRACTION", 0.0
            ),
            "weights_origin_failclosed": _effective_bool(
                "CATHEDRAL_WEIGHTS_ORIGIN_FAILCLOSED", True
            ),
            "submit_token_allowlist_enabled": bool(
                os.environ.get("CATHEDRAL_V2_SUBMIT_TOKEN_ALLOWLIST", "").strip()
            ),
            "submit_token_ttl_secs": _effective_float(
                "CATHEDRAL_V2_SUBMIT_TOKEN_TTL_SECS", 300.0
            ),
            "submit_bitset_max_body_bytes": _effective_float(
                "CATHEDRAL_V2_SUBMIT_BITSET_MAX_BODY_BYTES", 16_384.0
            ),
            "submit_max_concurrency_configured": _effective_submit_int(
                "CATHEDRAL_SUBMIT_MAX_CONCURRENCY", 24
            ),
            "submit_hard_cap": _effective_submit_int(
                "CATHEDRAL_SUBMIT_HARD_CAP", 8
            ),
            "submit_max_concurrency_effective": _effective_submit_max_concurrency(),
            "submit_busy_wait_secs": _effective_submit_busy_wait_secs(),
            "require_solver_metadata": _effective_bool(
                "CATHEDRAL_V2_REQUIRE_SOLVER_META"
            ),
            "manifest_blob_compat_enabled": _effective_bool(
                "CATHEDRAL_V2_BLOB_UPLOAD_ENABLED", converged()
            ),
            "cnf_artifacts_enabled": _effective_bool(
                "CATHEDRAL_V2_CNF_ARTIFACTS_ENABLED"
            ),
            "results_publish_enabled": _effective_bool(
                "CATHEDRAL_V2_RESULTS_PUBLISH_ENABLED"
            ),
            "perminer_contract": V2_CONVERGED_PERMINER_CONTRACT,
            "perminer_contract_sha256": v2_perminer_contract_digest(),
            "verify_worker_enabled": _effective_bool(
                "CATHEDRAL_V2_VERIFY_WORKER_ENABLED", converged()
            ),
            "client_ip_mode": (
                os.environ.get("CATHEDRAL_CLIENT_IP_MODE", "headers").strip().lower()
                or "headers"
            ),
            "trusted_proxy_hops": _effective_int(
                "CATHEDRAL_TRUSTED_PROXY_HOPS", 1
            ),
            "global_ratelimit_rpm": _effective_int(
                "CATHEDRAL_RATELIMIT_RPM", 120
            ),
        },
        "secrets": {
            name: "<redacted:set>"
            for name, value in sorted(os.environ.items())
            if name.startswith("CATHEDRAL_") and value and _is_sensitive_name(name)
        },
    }
    if os.environ.get("DATABASE_URL", "").strip():
        summary["secrets"]["DATABASE_URL"] = "<redacted:set>"
    return summary


def emit_effective_config(
    *,
    database_path: str,
    service_role: str,
    storage_backend: str,
    signing_key_hex: str | None = None,
) -> None:
    print(
        "[publisher_config] "
        + json.dumps(
            effective_config_summary(
                database_path=database_path,
                service_role=service_role,
                storage_backend=storage_backend,
                signing_key_hex=signing_key_hex,
            ),
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def validate_env(*, signing_key_hex: str | None = None) -> list[str]:
    """Return fatal misconfiguration errors for the active profile."""
    errors: list[str] = []
    _validate_production_marker(errors)
    p = profile()
    if p not in _KNOWN_PROFILES:
        errors.append(
            f"unknown {PROFILE_ENV}={p!r}; known: {sorted(_KNOWN_PROFILES - {''})}")
        return errors
    if production() and not p:
        errors.append(
            f"production requires an explicit {PROFILE_ENV}; "
            f"set {PROFILE_ENV}={V2_CONVERGED}"
        )
        return errors
    if not converged():
        return errors

    _validate_strict_values(errors)

    if production():
        if os.environ.get("CATHEDRAL_DB_PATH", ""):
            errors.append(
                "production forbids legacy CATHEDRAL_DB_PATH; DATABASE_URL is "
                "the only storage selector"
            )
        raw_database_url = os.environ.get("DATABASE_URL", "")
        database_url = raw_database_url.strip()
        if not database_url:
            errors.append(
                "production requires DATABASE_URL for the shared Postgres store; "
                "SQLite is development/compatibility only"
            )
        elif raw_database_url != database_url:
            errors.append(
                "production DATABASE_URL must not contain surrounding whitespace"
            )
        elif not database_url.startswith(("postgres://", "postgresql://")):
            errors.append(
                "production DATABASE_URL must select the Postgres backend"
            )
        elif _SECRET_PLACEHOLDER_RE.search(database_url):
            errors.append("production DATABASE_URL is still a documented placeholder")
        raw_generation_id = os.environ.get("CATHEDRAL_PUBLISHER_GENERATION_ID", "")
        generation_id = raw_generation_id.strip()
        if not generation_id:
            errors.append(
                "production requires non-secret CATHEDRAL_PUBLISHER_GENERATION_ID "
                "for replica and rollout comparison"
            )
        elif raw_generation_id != generation_id or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", generation_id
        ):
            errors.append(
                "invalid CATHEDRAL_PUBLISHER_GENERATION_ID; expected 8-128 "
                "letters, digits, dots, underscores, colons, or hyphens"
            )
        elif _SECRET_PLACEHOLDER_RE.search(generation_id):
            errors.append(
                "CATHEDRAL_PUBLISHER_GENERATION_ID is still a documented placeholder"
            )
        from . import v2_pipeline

        internally_pinned_perminer_env: dict[str, str] = {}
        if v2_pipeline.v2_pm_env_pinned():
            internally_pinned_perminer_env.update(
                V2_CONVERGED_PERMINER_LEGACY_ENV
            )
            internally_pinned_perminer_env[
                "CATHEDRAL_PERMINER_SEED_SECRET"
            ] = os.environ.get("CATHEDRAL_V2_PERMINER_SEED_SECRET", "")
        for name in sorted(_V2_PERMINER_PROFILE_OVERRIDE_ENVS):
            if name in os.environ:
                if (
                    name in internally_pinned_perminer_env
                    and os.environ[name] == internally_pinned_perminer_env[name]
                ):
                    continue
                errors.append(
                    f"production profile owns the V2 per-miner tier contract; "
                    f"remove legacy or per-process override {name}. A policy "
                    "change requires a separately named and reviewed launch profile"
                )
        for name in sorted(os.environ):
            if name.startswith("CATHEDRAL_TEE_GPU_") and name != (
                "CATHEDRAL_TEE_GPU_ENABLED"
            ):
                errors.append(
                    f"production CPU SAT profile forbids {name}; TEE-GPU and "
                    "Chutes intake or execution require a separately named profile"
                )
        for name, expected in _PRODUCTION_PINNED_VALUES.items():
            raw = os.environ.get(name)
            value = raw if raw is not None else None
            if value != expected:
                received = "<unset>" if value is None else repr(value)
                errors.append(
                    f"production profile pins {name}={expected}; "
                    f"received {received}. A policy change requires a separately "
                    "named and reviewed launch profile"
                )
        for name, expected in _PRODUCTION_PINNED_NUMERICS.items():
            raw = os.environ.get(name)
            try:
                value = float(raw) if raw is not None and raw.strip() else None
            except ValueError:
                value = None
            if value is None or not math.isclose(
                value, expected, rel_tol=0.0, abs_tol=1e-12
            ):
                received = "<unset/invalid>" if value is None else repr(value)
                errors.append(
                    f"production profile pins {name}={expected:g}; "
                    f"received {received}. A policy change requires a separately "
                    "named and reviewed launch profile"
                )
        for name in _PRODUCTION_REQUIRED_SECRETS:
            value = os.environ.get(name, "").strip()
            if not value:
                errors.append(
                    f"production validated_supply_v1 intake requires {name}"
                )
                continue
            if quality_error := _secret_quality_error(value):
                errors.append(f"invalid production secret {name}: {quality_error}")

        for name in (
            "CATHEDRAL_EVAL_SIGNING_KEY",
            "CATHEDRAL_WEIGHT_POLICY_SIGNING_KEY",
        ):
            value = os.environ.get(name, "").strip()
            if value and (key_error := _private_key_error(value)):
                errors.append(f"invalid production secret {name}: {key_error}")
        if signing_key_hex and (key_error := _private_key_error(signing_key_hex)):
            errors.append(f"invalid production signing key argument: {key_error}")

        configured_signing_keys = {
            name: value
            for name, value in (
                (
                    "CATHEDRAL_EVAL_SIGNING_KEY",
                    os.environ.get("CATHEDRAL_EVAL_SIGNING_KEY", "").strip(),
                ),
                (
                    "CATHEDRAL_WEIGHT_POLICY_SIGNING_KEY",
                    os.environ.get(
                        "CATHEDRAL_WEIGHT_POLICY_SIGNING_KEY", ""
                    ).strip(),
                ),
                ("build_app signing_key_hex", (signing_key_hex or "").strip()),
            )
            if value
        }
        if len(set(configured_signing_keys.values())) > 1:
            errors.append(
                "production requires one canonical Ed25519 signing identity; "
                "CATHEDRAL_EVAL_SIGNING_KEY, "
                "CATHEDRAL_WEIGHT_POLICY_SIGNING_KEY, and any build_app "
                "signing_key_hex argument must contain identical key bytes"
            )

        derived_public_key = _derived_weight_policy_public_key(signing_key_hex)
        if derived_public_key is None:
            errors.append(
                "production requires a valid 32-byte Ed25519 weight-policy "
                "signing key"
            )
        elif derived_public_key != _SN39_WEIGHT_POLICY_PUBLIC_KEY_HEX:
            errors.append(
                "production weight-policy signing key derives public key "
                f"{derived_public_key}, but canonical validators pin "
                f"{_SN39_WEIGHT_POLICY_PUBLIC_KEY_HEX}"
            )
        for name in sorted(_PRODUCTION_FORBIDDEN_TRUTHY):
            raw = os.environ.get(name)
            if raw is None or raw == "":
                continue
            value = raw.strip().lower()
            if value not in _TRUTHY | _FALSY:
                errors.append(
                    f"invalid boolean {name}={raw!r}; expected true or false"
                )
            elif value in _TRUTHY:
                errors.append(
                    f"{name} is a development/bypass flag and is forbidden in production"
                )

    for name in _PROFILE_OWNED_ON_FLAGS:
        raw = os.environ.get(name)
        if raw is None or raw == "":
            continue
        value = raw.strip().lower()
        if value not in _TRUTHY | _FALSY:
            errors.append(
                f"invalid boolean {name}={raw!r}; expected true or false"
            )
        elif value not in _TRUTHY:
            errors.append(
                f"{name} is explicitly off but {PROFILE_ENV}={V2_CONVERGED} "
                "implies it on; remove the override or drop the profile")
    if not os.environ.get("CATHEDRAL_V2_SUBMIT_TOKEN_SECRET", "").strip():
        errors.append(
            f"{PROFILE_ENV}={V2_CONVERGED} requires CATHEDRAL_V2_SUBMIT_TOKEN_SECRET")
    if not signing_key_hex and not os.environ.get(
        "CATHEDRAL_EVAL_SIGNING_KEY", ""
    ).strip():
        errors.append(
            f"{PROFILE_ENV}={V2_CONVERGED} requires CATHEDRAL_EVAL_SIGNING_KEY; "
            "do not launch with a generated dev key because validators pin the "
            "weight-signing identity")
    submit_secret = os.environ.get("CATHEDRAL_V2_SUBMIT_TOKEN_SECRET", "").strip()
    if production() and submit_secret:
        if quality_error := _secret_quality_error(submit_secret):
            errors.append(
                "invalid production secret CATHEDRAL_V2_SUBMIT_TOKEN_SECRET: "
                + quality_error
            )
    seed_secret = os.environ.get("CATHEDRAL_V2_PERMINER_SEED_SECRET", "").strip()
    if not production():
        seed_secret = seed_secret or os.environ.get(
            "CATHEDRAL_PERMINER_SEED_SECRET", ""
        ).strip()
    if not seed_secret:
        errors.append(
            f"{PROFILE_ENV}={V2_CONVERGED} requires a stable per-miner seed "
            "in CATHEDRAL_V2_PERMINER_SEED_SECRET; "
            "an ephemeral per-process seed would fork instance derivation across "
            "processes and epochs")
    elif production() and (quality_error := _secret_quality_error(seed_secret)):
        errors.append(f"invalid production per-miner seed secret: {quality_error}")
    if (os.environ.get("CATHEDRAL_V2_DATABASE_URL", "").strip()
            or os.environ.get("CATHEDRAL_V2_DB_PATH", "").strip()):
        errors.append(
            f"{PROFILE_ENV}={V2_CONVERGED} implies the payout bridge, which "
            "requires V2 to share the main store; unset "
            "CATHEDRAL_V2_DATABASE_URL/CATHEDRAL_V2_DB_PATH")
    return errors
