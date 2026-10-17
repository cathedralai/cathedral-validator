"""Validator-signed roster of verified SEV-SNP machines for the Cathedral join.

Each cycle that wrote weights can post one ``cathedral_validator_roster_v1``
document to the Cathedral API (polariscomputer issue #1469, step 3). It lists
the AMD SEV-SNP machines this round paid: uid, miner hotkey, verified endpoint
and machine_id. The validator hotkey signs it. The API pins that hotkey,
checks the signature, and treats each row only as a place to look for a
customer guest on the same chip. A roster grants nothing: the API verifies
every customer guest natively before it can seal one.

Unlike telemetry, this document carries endpoints and machine identifiers on
purpose, so it is never spooled for the public exporter. It goes from this
process straight to the private intake route, with a bearer token that is
transport only.

Off unless ``CATHEDRAL_SNP_ROSTER_URL`` is set. Configured by environment, not
flags, so a runtime from before this setting ignores it instead of exiting 2
on an unknown flag after an update rollback. Posting happens after the cycle's
weight write and never raises into the cycle: a roster problem can never
change weights or stop writes.

Wire contract: polariscomputer ``docs/SNP_JOIN_ROSTER.schema.json`` and
``polaris/services/cathedral_snp_roster.py`` (PR #1473).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cathedral_thin.independent.collect import EVIDENCE_KIND_SEV_SNP

from .telemetry_exporter import (
    TelemetryExportError,
    _https_endpoint,
    _NoRedirect,
    _secret,
)

SCHEMA = "cathedral_validator_roster_v1"
SIGNING_DOMAIN = b"cathedral-validator-roster-v1\x00"
SR25519_CRYPTO_TYPE = 1
# The API's bounds (cathedral_snp_roster.MAX_ROSTER_BYTES / MAX_ROSTER_ROWS).
MAX_ROSTER_BYTES = 256 * 1024
MAX_ROSTER_ROWS = 256
MAX_RESPONSE_BYTES = 16 * 1024
MAX_REASON_CHARS = 160
DEFAULT_TIMEOUT_SECONDS = 10.0
NETWORKS = frozenset({"finney", "test"})
ROSTER_URL_ENV = "CATHEDRAL_SNP_ROSTER_URL"
ROSTER_TOKEN_FILE_ENV = "CATHEDRAL_SNP_ROSTER_TOKEN_FILE"
_HEX = frozenset("0123456789abcdef")


class SnpRosterError(RuntimeError):
    """A roster could not be built, signed or delivered. Never fatal to a cycle."""


@dataclass(frozen=True)
class SnpRosterExport:
    """Where this validator posts its roster, and the transport token's file."""

    url: str
    token_file: Path
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS


def _canonical(document: Mapping[str, Any]) -> bytes:
    """The API's canonical JSON: sorted keys, no spaces, ASCII, no NaN."""

    try:
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise SnpRosterError("roster is not canonical JSON data") from exc


def roster_id(document: Mapping[str, Any]) -> str:
    body = {k: v for k, v in document.items() if k not in {"roster_id", "signature"}}
    return "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()


def signature_message(identity: object) -> bytes:
    if (
        not isinstance(identity, str)
        or len(identity) != 71
        or not identity.startswith("sha256:")
        or not set(identity[7:]) <= _HEX
    ):
        raise SnpRosterError("roster identity is invalid")
    return SIGNING_DOMAIN + identity.encode("ascii")


def _stamp(when: datetime) -> str:
    if when.tzinfo is None or when.utcoffset() != UTC.utcoffset(when):
        raise SnpRosterError("roster time must be UTC")
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _int(value: object, high: int) -> bool:
    return type(value) is int and 0 <= value <= high


def build_snp_roster(
    *,
    healthy_rows: Sequence[Mapping[str, Any]],
    network: str,
    netuid: int,
    block_number: int,
    validator_uid: int,
    validator_hotkey: str,
    generated_at: datetime,
) -> dict[str, Any]:
    """Project one round's paid machine rows into the unsigned roster.

    ``healthy_rows`` are the cycle's positive rows (the ones the weights pay
    for). Only SEV-SNP rows are listed: the join seals AMD chips. A row the
    API would refuse fails the whole roster here rather than at the API.

    ``sequence`` is the finalized block the round was scored at. It rises with
    every cycle, survives reinstalls and needs no local state; the API refuses
    a sequence that is not newer than the last it accepted from this hotkey.
    """

    if network not in NETWORKS:
        raise SnpRosterError("roster network is not finney or test")
    if not _int(netuid, 65535) or not _int(validator_uid, 65535):
        raise SnpRosterError("roster netuid or validator uid is invalid")
    if not _int(block_number, 2**62):
        raise SnpRosterError("roster block is invalid")
    if not isinstance(validator_hotkey, str) or not validator_hotkey:
        raise SnpRosterError("roster validator hotkey is invalid")
    rows: list[dict[str, Any]] = []
    for source in healthy_rows:
        if source.get("tee_kind") != EVIDENCE_KIND_SEV_SNP:
            continue
        row = {
            "uid": source.get("uid"),
            "hotkey": source.get("hotkey"),
            "endpoint": source.get("endpoint"),
            "machine_id": source.get("machine_id"),
        }
        machine_id = row["machine_id"]
        if (
            not _int(row["uid"], 65535)
            or not isinstance(row["hotkey"], str)
            or not row["hotkey"]
            or not isinstance(row["endpoint"], str)
            or not row["endpoint"].startswith("https://")
            or len(row["endpoint"]) > 255
            or not isinstance(machine_id, str)
            or len(machine_id) != 64
            or not set(machine_id) <= _HEX
        ):
            raise SnpRosterError("a paid SEV-SNP row is not a valid roster row")
        rows.append(row)
    if len(rows) > MAX_ROSTER_ROWS:
        raise SnpRosterError("roster has more rows than the API accepts")
    rows.sort(key=lambda r: (r["uid"], r["machine_id"], r["endpoint"]))
    for field in ("machine_id", "endpoint"):
        if len({row[field] for row in rows}) != len(rows):
            raise SnpRosterError(f"roster repeats a {field}")
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "network": network,
        "netuid": netuid,
        "validator": {"uid": validator_uid, "hotkey": validator_hotkey},
        "sequence": block_number,
        "block": block_number,
        "generated_at": _stamp(generated_at),
        "rows": rows,
    }
    document["roster_id"] = roster_id(document)
    return document


def sign_snp_roster(document: Mapping[str, Any], *, keypair: Any) -> dict[str, Any]:
    """Sign the roster identity with the validator hotkey (sr25519)."""

    signed = dict(document)
    if signed.get("roster_id") != roster_id(signed):
        raise SnpRosterError("roster identity differs from its content")
    validator = signed.get("validator")
    if (
        not isinstance(validator, Mapping)
        or validator.get("hotkey") != str(getattr(keypair, "ss58_address", ""))
        or getattr(keypair, "crypto_type", None) != SR25519_CRYPTO_TYPE
        or not callable(getattr(keypair, "sign", None))
    ):
        raise SnpRosterError("roster signer does not match the validator hotkey")
    try:
        signature = bytes(keypair.sign(signature_message(signed["roster_id"])))
    except SnpRosterError:
        raise
    except Exception as exc:
        raise SnpRosterError("validator hotkey could not sign the roster") from exc
    if len(signature) != 64:
        raise SnpRosterError("roster signature must be 64 bytes")
    signed["signature"] = {
        "algorithm": "sr25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return signed


def post_snp_roster(
    *,
    url: str,
    document: Mapping[str, Any],
    token: str,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """POST the canonical roster bytes once, without following redirects.

    Returns the API's acknowledgement. Raises SnpRosterError on anything but
    an acknowledgement of this exact roster.
    """

    try:
        target = _https_endpoint(url)
    except TelemetryExportError as exc:
        raise SnpRosterError("roster URL must be a plain HTTPS URL") from exc
    body = _canonical(document)
    if len(body) > MAX_ROSTER_BYTES:
        raise SnpRosterError("roster exceeds the API's size bound")
    request = urllib.request.Request(
        target,
        data=body,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "cathedral-validator-roster/1",
        },
        method="POST",
    )
    open_request = opener or urllib.request.build_opener(_NoRedirect()).open
    try:
        with open_request(request, timeout=timeout_seconds) as response:
            status = int(response.getcode())
            content_type = str(response.headers.get("Content-Type", ""))
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise SnpRosterError(
            f"API refused the roster with HTTP {exc.code}{_reason(exc)}"
        ) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise SnpRosterError("roster API is unavailable") from exc
    if status not in {200, 201, 202}:
        raise SnpRosterError(f"roster API returned unexpected HTTP {status}")
    if (
        len(response_body) > MAX_RESPONSE_BYTES
        or "application/json" not in content_type.lower()
    ):
        raise SnpRosterError("roster API response is not bounded JSON")
    try:
        acknowledgement = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnpRosterError("roster API response is invalid JSON") from exc
    if (
        not isinstance(acknowledgement, dict)
        or acknowledgement.get("accepted") is not True
        or acknowledgement.get("roster_id") != document.get("roster_id")
    ):
        raise SnpRosterError("roster API did not acknowledge the exact roster")
    return acknowledgement


def _reason(exc: urllib.error.HTTPError) -> str:
    """The API's refusal reason names a check, never content; keep it short."""

    try:
        detail = json.loads(exc.read(MAX_RESPONSE_BYTES).decode("utf-8")).get("detail")
        reason = detail.get("reason") if isinstance(detail, dict) else None
    except Exception:  # noqa: BLE001 - a reason is best effort
        return ""
    if not isinstance(reason, str) or not reason.isascii():
        return ""
    return f": {reason[:MAX_REASON_CHARS]}"


def export_cycle_roster(
    export: SnpRosterExport,
    *,
    healthy_rows: Sequence[Mapping[str, Any]],
    network: str,
    netuid: int,
    block_number: int,
    validator_uid: int,
    keypair: Any,
    generated_at: datetime | None = None,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Build, sign and post one cycle's roster. Returns the cycle event field."""

    document = build_snp_roster(
        healthy_rows=healthy_rows,
        network=network,
        netuid=netuid,
        block_number=block_number,
        validator_uid=validator_uid,
        validator_hotkey=str(getattr(keypair, "ss58_address", "")),
        generated_at=generated_at or datetime.now(UTC),
    )
    signed = sign_snp_roster(document, keypair=keypair)
    try:
        # Read every cycle, so a rotated token needs no restart.
        token = _secret(export.token_file, label="roster ingest token")
    except TelemetryExportError as exc:
        raise SnpRosterError(str(exc)) from exc
    post_snp_roster(
        url=export.url,
        document=signed,
        token=token,
        timeout_seconds=export.timeout_seconds,
        opener=opener,
    )
    return {
        "status": "POSTED",
        "roster_id": signed["roster_id"],
        "sequence": signed["sequence"],
        "rows": len(signed["rows"]),
    }


def snp_roster_from_environment(
    environ: Mapping[str, str] | None = None,
) -> tuple[SnpRosterExport | None, dict[str, Any] | None]:
    """Read the optional roster export settings.

    Returns ``(export, startup_event)``. Unset or empty URL means off and no
    event. A half or invalid configuration is reported and leaves the export
    off: the roster must never stop a validator that pays today.
    """

    env = os.environ if environ is None else environ
    url = env.get(ROSTER_URL_ENV, "").strip()
    token_file = env.get(ROSTER_TOKEN_FILE_ENV, "").strip()
    if not url:
        if token_file:
            return None, {
                "snp_roster": {
                    "status": "DISABLED",
                    "error": f"{ROSTER_TOKEN_FILE_ENV} is set without {ROSTER_URL_ENV}",
                }
            }
        return None, None
    try:
        _https_endpoint(url)
    except TelemetryExportError:
        return None, {
            "snp_roster": {
                "status": "DISABLED",
                "error": f"{ROSTER_URL_ENV} must be a plain HTTPS URL",
            }
        }
    path = Path(token_file) if token_file else None
    if path is None or not path.is_absolute():
        return None, {
            "snp_roster": {
                "status": "DISABLED",
                "error": f"{ROSTER_TOKEN_FILE_ENV} must be an absolute path",
            }
        }
    export = SnpRosterExport(url=url, token_file=path)
    return export, {"snp_roster": {"status": "ENABLED", "url": url}}


__all__ = [
    "MAX_ROSTER_ROWS",
    "ROSTER_TOKEN_FILE_ENV",
    "ROSTER_URL_ENV",
    "SCHEMA",
    "SIGNING_DOMAIN",
    "SnpRosterError",
    "SnpRosterExport",
    "build_snp_roster",
    "export_cycle_roster",
    "post_snp_roster",
    "roster_id",
    "sign_snp_roster",
    "signature_message",
    "snp_roster_from_environment",
]
