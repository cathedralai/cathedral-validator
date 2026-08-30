"""Sanitized, non-blocking telemetry for the direct SN39 validator.

The score path owns the facts in this document.  The exporter only transports
the already-sanitized snapshot and has no wallet, chain client, evidence, TLS
identity, endpoint, or machine identifier.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from cathedral_thin.independent.constants import W

from .direct_contract import DirectSubmissionReceipt, DirectWeightPlan
from .preview_io import canonical_document_bytes

TELEMETRY_SCHEMA = "cathedral_validator_telemetry_v2"
TELEMETRY_PENDING_SCHEMA = "cathedral_validator_telemetry_pending_v3"
TELEMETRY_STATE_SCHEMA = "cathedral_validator_telemetry_export_state_v2"
TELEMETRY_SIGNING_DOMAIN = b"cathedral-validator-telemetry-v2\x00"
SR25519_CRYPTO_TYPE = 1
MAX_TELEMETRY_EVENT_BYTES = 256 * 1024
MAX_TELEMETRY_HISTORY_BYTES = 16 * 1024 * 1024
MAX_TELEMETRY_HISTORY_EVENTS = 720
SUPPORTED_TEE_KINDS = frozenset({"tdx", "sev_snp"})
FINALIZED_SUBMISSION_STATUSES = frozenset({"CONFIRMED", "RECOVERED_CONFIRMED"})


class TelemetryError(RuntimeError):
    """A telemetry artifact is unsafe or malformed.

    Callers on the scoring path must catch this error.  Telemetry is never an
    input to scoring and must never prevent a weight decision.
    """


def _canonical_json_bytes(document: Mapping[str, Any]) -> bytes:
    """Return canonical JSON without the preview writer's trailing newline."""

    return canonical_document_bytes(document).removesuffix(b"\n")


def _expected_event_id(document: Mapping[str, Any]) -> str:
    base = dict(document)
    base.pop("event_id", None)
    base.pop("signature", None)
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(base)).hexdigest()


def _signature_message(event_id: object) -> bytes:
    if (
        not isinstance(event_id, str)
        or len(event_id) != 71
        or not event_id.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in event_id[7:])
    ):
        raise TelemetryError("telemetry event identity is invalid")
    return TELEMETRY_SIGNING_DOMAIN + event_id.encode("ascii")


def _sign_telemetry_event(
    document: Mapping[str, Any],
    *,
    keypair: Any,
) -> dict[str, Any]:
    event = dict(document)
    validator = event.get("validator")
    signing_hotkey = str(getattr(keypair, "ss58_address", ""))
    if (
        not isinstance(validator, Mapping)
        or validator.get("hotkey") != signing_hotkey
        or getattr(keypair, "crypto_type", None) != SR25519_CRYPTO_TYPE
        or not callable(getattr(keypair, "sign", None))
    ):
        raise TelemetryError("telemetry signer does not match the validator hotkey")
    try:
        signature = bytes(keypair.sign(_signature_message(event.get("event_id"))))
    except Exception as exc:
        raise TelemetryError("validator hotkey could not sign telemetry") from exc
    if len(signature) != 64:
        raise TelemetryError("validator telemetry signature must be 64 bytes")
    event["signature"] = {
        "algorithm": "sr25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return validate_public_telemetry_event(event)


def _verify_telemetry_signature(document: Mapping[str, Any]) -> None:
    signature_document = document.get("signature")
    validator = document.get("validator")
    if (
        not isinstance(signature_document, Mapping)
        or set(signature_document) != {"algorithm", "value_base64"}
        or signature_document.get("algorithm") != "sr25519"
        or not isinstance(signature_document.get("value_base64"), str)
        or not isinstance(validator, Mapping)
        or not isinstance(validator.get("hotkey"), str)
    ):
        raise TelemetryError("validator telemetry signature is invalid")
    encoded = signature_document["value_base64"]
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TelemetryError("validator telemetry signature is invalid") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
        raise TelemetryError("validator telemetry signature is invalid")
    try:
        from bittensor_wallet import Keypair

        valid = Keypair(ss58_address=validator["hotkey"]).verify(
            _signature_message(document.get("event_id")),
            signature,
        )
    except Exception as exc:
        raise TelemetryError("validator telemetry hotkey is invalid") from exc
    if not valid:
        raise TelemetryError("validator telemetry signature verification failed")


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _tee_kind(row: Mapping[str, Any]) -> str:
    value = row.get("tee_kind", row.get("kind", "tdx"))
    return value if value in SUPPORTED_TEE_KINDS else "unknown"


def _verification_elapsed_ms(row: Mapping[str, Any]) -> int | None:
    timings = row.get("phase_timings_ms")
    if not isinstance(timings, Mapping):
        return None
    values = [
        value for value in timings.values() if _nonnegative_int(value) is not None
    ]
    return sum(values) if values else None


def _positive_rows(rows: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    positive = []
    for row in rows:
        sat_units = _nonnegative_int(row.get("sat_units"))
        counted = _nonnegative_int(row.get("counted_units"))
        if (
            row.get("verdict") == "PASS"
            and row.get("platform_identity_verified") is True
            and sat_units is not None
            and sat_units > 0
            and counted == sat_units
            and not row.get("score_reasons")
            and not row.get("sat_error")
        ):
            positive.append(row)
    return tuple(positive)


def _build_telemetry_snapshot_base(
    *,
    result_rows: Sequence[Mapping[str, Any]],
    plan: DirectWeightPlan,
    receipt: DirectSubmissionReceipt,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Build one unsigned public-safe snapshot from a direct write.

    No raw failure strings are copied.  Those strings can contain endpoints,
    paths, subprocess output, vendor certificate detail, or other private
    evidence.  A failed machine is represented only by its absence from the
    verified count.
    """

    if not isinstance(plan, DirectWeightPlan):
        raise TelemetryError("telemetry requires a direct weight plan")
    if not isinstance(receipt, DirectSubmissionReceipt):
        raise TelemetryError("telemetry requires a direct submission receipt")
    if isinstance(result_rows, (str, bytes)) or not isinstance(result_rows, Sequence):
        raise TelemetryError("telemetry rows must be a sequence")
    if any(not isinstance(row, Mapping) for row in result_rows):
        raise TelemetryError("telemetry rows must be mappings")

    when = observed_at or datetime.now(UTC)
    if when.tzinfo is None or when.utcoffset() != UTC.utcoffset(when):
        raise TelemetryError("telemetry time must be UTC")
    observed = when.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")

    uid_hotkeys = dict(plan.uid_hotkeys)
    score_by_uid = dict(plan.raw_scores)
    admitted_machine_ids = {
        uid: frozenset(machine_ids) for uid, machine_ids in plan.machine_ids_by_uid
    }
    weight_by_uid = dict(zip(plan.wire_uids, plan.wire_weights, strict=True))
    rows_by_uid: dict[int, list[Mapping[str, Any]]] = {uid: [] for uid in uid_hotkeys}
    for row in _positive_rows(result_rows):
        uid = row.get("uid")
        hotkey = row.get("hotkey")
        machine_id = row.get("machine_id")
        if (
            isinstance(uid, int)
            and uid_hotkeys.get(uid) == hotkey
            and isinstance(machine_id, str)
            and machine_id in admitted_machine_ids.get(uid, ())
        ):
            rows_by_uid[uid].append(row)

    miners: list[dict[str, Any]] = []
    for uid in sorted(uid_hotkeys):
        rows = rows_by_uid[uid]
        tee_counts = {"tdx": 0, "sev_snp": 0}
        sat_units = 0
        verification_samples: list[int] = []
        for row in rows:
            tee = _tee_kind(row)
            if tee in tee_counts:
                tee_counts[tee] += 1
            units = _nonnegative_int(row.get("sat_units"))
            if units is not None:
                sat_units += units
            elapsed = _verification_elapsed_ms(row)
            if elapsed is not None:
                verification_samples.append(elapsed)
        declared_count = score_by_uid.get(uid)
        if declared_count != len(rows):
            raise TelemetryError("telemetry positive rows differ from the plan")
        miners.append(
            {
                "uid": uid,
                "hotkey": uid_hotkeys[uid],
                "distinct_verified_compute": len(rows),
                "tee_counts": tee_counts,
                "sat_units": sat_units,
                "verification_ms": {
                    "samples": len(verification_samples),
                    "average": (
                        sum(verification_samples) // len(verification_samples)
                        if verification_samples
                        else None
                    ),
                    "maximum": max(verification_samples)
                    if verification_samples
                    else None,
                },
                "weight_u16": weight_by_uid.get(uid, 0),
                "verified_at": observed if rows else None,
                "status": "weighted"
                if weight_by_uid.get(uid, 0) > 0
                else "not_verified",
            }
        )

    base: dict[str, Any] = {
        "schema": TELEMETRY_SCHEMA,
        "observed_at": observed,
        "network": "finney",
        "netuid": 39,
        "validator": {
            "uid": plan.snapshot.validator_uid,
            "hotkey": plan.snapshot.validator_hotkey,
            "permit": True,
        },
        "anchor": {
            "block_number": plan.snapshot.block_number,
            "block_hash": plan.snapshot.block_hash,
        },
        "submission": {
            "status": receipt.status,
            "block_number": receipt.block_number,
            "block_hash": receipt.block_hash,
            "recovered": receipt.recovered,
        },
        "evidence_digest": plan.evidence_digest,
        "burn_weight": 0,
        "miners": miners,
    }
    return base


def build_telemetry_snapshot(
    *,
    result_rows: Sequence[Mapping[str, Any]],
    plan: DirectWeightPlan,
    receipt: DirectSubmissionReceipt,
    keypair: Any,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Build and hotkey-sign one snapshot from a finalized direct write."""

    if (
        not isinstance(receipt, DirectSubmissionReceipt)
        or receipt.status not in FINALIZED_SUBMISSION_STATUSES
    ):
        raise TelemetryError("telemetry requires a finalized successful receipt")
    event = _build_telemetry_snapshot_base(
        result_rows=result_rows,
        plan=plan,
        receipt=receipt,
        observed_at=observed_at,
    )
    event["event_id"] = _expected_event_id(event)
    return _sign_telemetry_event(event, keypair=keypair)


def build_telemetry_candidate(
    *,
    result_rows: Sequence[Mapping[str, Any]],
    plan: DirectWeightPlan,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Build the sanitized round facts before the writer knows its receipt."""

    placeholder = DirectSubmissionReceipt(
        status="PENDING",
        attempt_id="pending",
        extrinsic_hash="pending",
        block_hash=None,
        block_number=None,
        recovered=False,
    )
    event = _build_telemetry_snapshot_base(
        result_rows=result_rows,
        plan=plan,
        receipt=placeholder,
        observed_at=observed_at,
    )
    event.pop("submission")
    return event


def finalize_telemetry_candidate(
    candidate: Mapping[str, Any],
    receipt: DirectSubmissionReceipt,
    *,
    keypair: Any,
) -> dict[str, Any]:
    """Bind durable sanitized round facts to one finalized chain receipt."""

    if not isinstance(candidate, Mapping) or set(candidate) != {
        "schema",
        "observed_at",
        "network",
        "netuid",
        "validator",
        "anchor",
        "evidence_digest",
        "burn_weight",
        "miners",
    }:
        raise TelemetryError("pending telemetry candidate is invalid")
    if (
        not isinstance(receipt, DirectSubmissionReceipt)
        or receipt.status not in FINALIZED_SUBMISSION_STATUSES
    ):
        raise TelemetryError("telemetry requires a finalized successful receipt")
    event = {
        **dict(candidate),
        "submission": {
            "status": receipt.status,
            "block_number": receipt.block_number,
            "block_hash": receipt.block_hash,
            "recovered": receipt.recovered,
        },
    }
    event["event_id"] = _expected_event_id(event)
    return _sign_telemetry_event(event, keypair=keypair)


def validate_public_telemetry_event(document: Mapping[str, Any]) -> dict[str, Any]:
    """Refuse unknown fields before a separate process exports the event."""

    if not isinstance(document, Mapping):
        raise TelemetryError("telemetry event is not an object")
    if set(document) != {
        "schema",
        "observed_at",
        "network",
        "netuid",
        "validator",
        "anchor",
        "submission",
        "evidence_digest",
        "burn_weight",
        "miners",
        "event_id",
        "signature",
    }:
        raise TelemetryError("telemetry event fields are not public-safe")
    if (
        document.get("schema") != TELEMETRY_SCHEMA
        or document.get("network") != "finney"
        or document.get("netuid") != 39
        or document.get("burn_weight") != 0
        or document.get("event_id") != _expected_event_id(document)
    ):
        raise TelemetryError("telemetry event identity is invalid")

    validator = document.get("validator")
    anchor = document.get("anchor")
    submission = document.get("submission")
    miners = document.get("miners")
    if not isinstance(validator, Mapping) or set(validator) != {
        "uid",
        "hotkey",
        "permit",
    }:
        raise TelemetryError("telemetry validator fields are invalid")
    if not isinstance(anchor, Mapping) or set(anchor) != {"block_number", "block_hash"}:
        raise TelemetryError("telemetry anchor fields are invalid")
    if not isinstance(submission, Mapping) or set(submission) != {
        "status",
        "block_number",
        "block_hash",
        "recovered",
    }:
        raise TelemetryError("telemetry submission fields are invalid")
    if not isinstance(miners, list):
        raise TelemetryError("telemetry miners are invalid")
    if not isinstance(document.get("observed_at"), str):
        raise TelemetryError("telemetry observation time is invalid")
    try:
        observed_at = datetime.strptime(document["observed_at"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise TelemetryError("telemetry observation time is invalid") from exc
    if observed_at.tzinfo is not None:
        raise TelemetryError("telemetry observation time is invalid")
    if (
        _nonnegative_int(validator.get("uid")) is None
        or not isinstance(validator.get("hotkey"), str)
        or not validator["hotkey"]
        or validator.get("permit") is not True
        or _nonnegative_int(anchor.get("block_number")) is None
        or not isinstance(anchor.get("block_hash"), str)
        or not anchor["block_hash"]
        or submission.get("status") not in FINALIZED_SUBMISSION_STATUSES
        or _nonnegative_int(submission.get("block_number")) is None
        or not isinstance(submission.get("block_hash"), str)
        or not submission["block_hash"]
        or not isinstance(submission.get("recovered"), bool)
        or submission["recovered"] != (submission["status"] == "RECOVERED_CONFIRMED")
        or not isinstance(document.get("evidence_digest"), str)
        or len(document["evidence_digest"]) != 71
        or not document["evidence_digest"].startswith("sha256:")
        or any(
            character not in "0123456789abcdef"
            for character in document["evidence_digest"][7:]
        )
    ):
        raise TelemetryError("telemetry finalized submission fields are invalid")
    seen_uids: set[int] = set()
    total_weight = 0
    for miner in miners:
        if not isinstance(miner, Mapping) or set(miner) != {
            "uid",
            "hotkey",
            "distinct_verified_compute",
            "tee_counts",
            "sat_units",
            "verification_ms",
            "weight_u16",
            "verified_at",
            "status",
        }:
            raise TelemetryError("telemetry miner fields are invalid")
        tee_counts = miner.get("tee_counts")
        verification = miner.get("verification_ms")
        if not isinstance(tee_counts, Mapping) or set(tee_counts) != {"tdx", "sev_snp"}:
            raise TelemetryError("telemetry TEE counts are invalid")
        if not isinstance(verification, Mapping) or set(verification) != {
            "samples",
            "average",
            "maximum",
        }:
            raise TelemetryError("telemetry verification fields are invalid")
        uid = _nonnegative_int(miner.get("uid"))
        distinct_compute = _nonnegative_int(miner.get("distinct_verified_compute"))
        tdx_count = _nonnegative_int(tee_counts.get("tdx"))
        snp_count = _nonnegative_int(tee_counts.get("sev_snp"))
        sat_units = _nonnegative_int(miner.get("sat_units"))
        samples = _nonnegative_int(verification.get("samples"))
        average = verification.get("average")
        maximum = verification.get("maximum")
        weight = _nonnegative_int(miner.get("weight_u16"))
        status = miner.get("status")
        verified_at = miner.get("verified_at")
        if (
            uid is None
            or uid in seen_uids
            or not isinstance(miner.get("hotkey"), str)
            or not miner["hotkey"]
            or distinct_compute is None
            or tdx_count is None
            or snp_count is None
            or tdx_count + snp_count != distinct_compute
            or sat_units is None
            or samples != distinct_compute
            or weight is None
            or weight > W
            or status not in {"weighted", "not_verified"}
        ):
            raise TelemetryError("telemetry miner values are invalid")
        if distinct_compute == 0:
            valid_timing = average is None and maximum is None
            valid_status = (
                status == "not_verified" and weight == 0 and verified_at is None
            )
        else:
            valid_timing = (
                _nonnegative_int(average) is not None
                and _nonnegative_int(maximum) is not None
                and average <= maximum
            )
            valid_status = (
                status == "weighted"
                and weight > 0
                and verified_at == document["observed_at"]
            )
        if not valid_timing or not valid_status:
            raise TelemetryError("telemetry miner values are invalid")
        seen_uids.add(uid)
        total_weight += weight
    if not miners or total_weight != W:
        raise TelemetryError("telemetry weights do not match a finalized vector")
    _verify_telemetry_signature(document)
    return dict(document)


def canonical_telemetry_path(state_path: Path) -> Path:
    """Place telemetry beside, never inside, the writer's recovery document."""

    if not isinstance(state_path, Path) or state_path.name != "state.json":
        raise TelemetryError("writer state path is not canonical")
    return state_path.parent / "telemetry" / "events.jsonl"


def _secure_parent(path: Path, *, reader_gid: int | None = None) -> None:
    parent = path.parent
    if parent.is_symlink():
        raise TelemetryError("telemetry parent is a symlink")
    try:
        parent.mkdir(
            mode=0o750 if reader_gid is not None else 0o700, parents=True, exist_ok=True
        )
        if reader_gid is not None:
            os.chown(parent, -1, reader_gid)
            os.chmod(parent, 0o750)
        metadata = parent.stat()
    except OSError as exc:
        raise TelemetryError("telemetry parent is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or (reader_gid is None and stat.S_IMODE(metadata.st_mode) != 0o700)
        or (
            reader_gid is not None
            and (
                metadata.st_gid != reader_gid or stat.S_IMODE(metadata.st_mode) != 0o750
            )
        )
    ):
        raise TelemetryError("telemetry parent is not owner-only")


def _event_line(event: Mapping[str, Any]) -> bytes:
    body = _canonical_json_bytes(validate_public_telemetry_event(event))
    if len(body) > MAX_TELEMETRY_EVENT_BYTES:
        raise TelemetryError("telemetry event is too large")
    return body + b"\n"


def _bounded_history(existing: bytes, line: bytes) -> bytes:
    lines = [item for item in existing.splitlines() if item]
    lines.append(line.rstrip(b"\n"))
    lines = lines[-MAX_TELEMETRY_HISTORY_EVENTS:]
    while lines and sum(len(item) + 1 for item in lines) > MAX_TELEMETRY_HISTORY_BYTES:
        lines.pop(0)
    return b"".join(item + b"\n" for item in lines)


class TelemetrySpool:
    """Owner-only bounded JSONL history, written atomically per cycle."""

    def __init__(self, path: Path, *, reader_gid: int | None = None) -> None:
        self.path = path
        self.reader_gid = reader_gid

    def append(self, event: Mapping[str, Any]) -> None:
        line = _event_line(event)
        _secure_parent(self.path, reader_gid=self.reader_gid)
        existing = b""
        if self.path.exists():
            if self.path.is_symlink():
                raise TelemetryError("telemetry spool is a symlink")
            metadata = self.path.stat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode)
                != (0o640 if self.reader_gid is not None else 0o600)
                or (self.reader_gid is not None and metadata.st_gid != self.reader_gid)
                or metadata.st_size > MAX_TELEMETRY_HISTORY_BYTES
            ):
                raise TelemetryError("telemetry spool is not owner-only and bounded")
            try:
                existing = self.path.read_bytes()
            except OSError as exc:
                raise TelemetryError("telemetry spool cannot be read") from exc
        body = _bounded_history(existing, line)
        temporary: str | None = None
        try:
            descriptor, temporary = tempfile.mkstemp(
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            if self.reader_gid is not None:
                os.chown(temporary, -1, self.reader_gid)
            os.chmod(temporary, 0o640 if self.reader_gid is not None else 0o600)
            os.replace(temporary, self.path)
            temporary = None
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise TelemetryError("telemetry spool cannot be persisted") from exc
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass


def _stored_submission_receipt(document: object) -> DirectSubmissionReceipt:
    if not isinstance(document, Mapping) or set(document) != {
        "status",
        "attempt_id",
        "extrinsic_hash",
        "block_hash",
        "block_number",
        "recovered",
        "confirmation_heads",
    }:
        raise TelemetryError("pending telemetry receipt is malformed")
    try:
        receipt = DirectSubmissionReceipt(
            status=document["status"],
            attempt_id=document["attempt_id"],
            extrinsic_hash=document["extrinsic_hash"],
            block_hash=document["block_hash"],
            block_number=document["block_number"],
            recovered=document["recovered"],
            confirmation_heads=tuple(
                (int(row[0]), str(row[1])) for row in document["confirmation_heads"]
            ),
        )
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise TelemetryError("pending telemetry receipt is invalid") from exc
    if receipt.as_document() != dict(document):
        raise TelemetryError("pending telemetry receipt is not canonical")
    return receipt


class PendingTelemetryStore:
    """Durable bridge from one submitted plan to its signed telemetry."""

    def __init__(self, spool: TelemetrySpool) -> None:
        self.spool = spool
        self.path = spool.path.with_name("pending.json")

    def prepare(
        self,
        candidate: Mapping[str, Any],
        plan: DirectWeightPlan,
        receipt: DirectSubmissionReceipt | None,
    ) -> None:
        if not isinstance(plan, DirectWeightPlan):
            raise TelemetryError("pending telemetry requires a direct weight plan")
        if receipt is not None and (
            not isinstance(receipt, DirectSubmissionReceipt)
            or receipt.status not in FINALIZED_SUBMISSION_STATUSES
        ):
            raise TelemetryError("pending telemetry requires a finalized receipt")
        plan_identity_sha256 = (
            "sha256:"
            + hashlib.sha256(canonical_document_bytes(plan.identity())).hexdigest()
        )
        document = {
            "schema": TELEMETRY_PENDING_SCHEMA,
            "plan_identity_sha256": plan_identity_sha256,
            "candidate": dict(candidate),
            "receipt": receipt.as_document() if receipt is not None else None,
        }
        body = canonical_document_bytes(document)
        if len(body) > MAX_TELEMETRY_EVENT_BYTES:
            raise TelemetryError("pending telemetry exceeds its bound")
        _secure_parent(self.path, reader_gid=self.spool.reader_gid)
        temporary: str | None = None
        try:
            descriptor, temporary = tempfile.mkstemp(
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            if self.spool.reader_gid is not None:
                os.chown(temporary, -1, self.spool.reader_gid)
            os.chmod(
                temporary,
                0o640 if self.spool.reader_gid is not None else 0o600,
            )
            os.replace(temporary, self.path)
            temporary = None
            self._sync_parent()
        except OSError as exc:
            raise TelemetryError("pending telemetry cannot be persisted") from exc
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        if self.path.is_symlink():
            raise TelemetryError("pending telemetry is a symlink")
        try:
            metadata = self.path.stat()
            raw = self.path.read_bytes()
        except OSError as exc:
            raise TelemetryError("pending telemetry is unavailable") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode)
            != (0o640 if self.spool.reader_gid is not None else 0o600)
            or (
                self.spool.reader_gid is not None
                and metadata.st_gid != self.spool.reader_gid
            )
            or not 1 <= len(raw) <= MAX_TELEMETRY_EVENT_BYTES
        ):
            raise TelemetryError("pending telemetry is not owner-only and bounded")
        try:
            document = json.loads(raw.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TelemetryError("pending telemetry is invalid JSON") from exc
        if (
            not isinstance(document, dict)
            or set(document)
            != {"schema", "plan_identity_sha256", "candidate", "receipt"}
            or document.get("schema") != TELEMETRY_PENDING_SCHEMA
            or not isinstance(document.get("plan_identity_sha256"), str)
            or len(document["plan_identity_sha256"]) != 71
            or not document["plan_identity_sha256"].startswith("sha256:")
            or any(
                character not in "0123456789abcdef"
                for character in document["plan_identity_sha256"][7:]
            )
            or not isinstance(document.get("candidate"), dict)
            or (
                document.get("receipt") is not None
                and not isinstance(document.get("receipt"), dict)
            )
        ):
            raise TelemetryError("pending telemetry is malformed")
        if canonical_document_bytes(document) != raw:
            raise TelemetryError("pending telemetry is not canonical JSON")
        if document.get("receipt") is not None:
            _stored_submission_receipt(document["receipt"])
        return document

    def plan_identity_sha256(self) -> str | None:
        document = self._load()
        return None if document is None else str(document["plan_identity_sha256"])

    def finalize(
        self,
        *,
        keypair: Any,
        expected_receipt: DirectSubmissionReceipt | None = None,
    ) -> dict[str, Any] | None:
        document = self._load()
        if document is None:
            return None
        stored_receipt = (
            _stored_submission_receipt(document["receipt"])
            if document["receipt"] is not None
            else None
        )
        if (
            expected_receipt is not None
            and stored_receipt is not None
            and stored_receipt != expected_receipt
        ):
            raise TelemetryError("pending telemetry receipt differs from the writer")
        receipt = expected_receipt or stored_receipt
        if receipt is None:
            raise TelemetryError("pending telemetry awaits writer recovery")
        if receipt.status == "EXPIRED_WITHOUT_INCLUSION":
            self.clear()
            return None
        event = finalize_telemetry_candidate(
            document["candidate"],
            receipt,
            keypair=keypair,
        )
        self.spool.append(event)
        self.clear()
        return event

    def clear(self) -> None:
        if self.path.is_symlink():
            raise TelemetryError("pending telemetry is a symlink")
        try:
            self.path.unlink(missing_ok=True)
            self._sync_parent()
        except OSError as exc:
            raise TelemetryError("pending telemetry cannot be cleared") from exc

    def _sync_parent(self) -> None:
        directory = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _direct_writer_journal(state_path: Path) -> dict[str, Any]:
    if state_path.is_symlink():
        raise TelemetryError("direct writer journal is a symlink")
    try:
        metadata = state_path.stat()
        raw = state_path.read_bytes()
    except OSError as exc:
        raise TelemetryError("direct writer journal is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not 1 <= len(raw) <= 1_048_576
    ):
        raise TelemetryError("direct writer journal is not owner-only and bounded")
    try:
        state = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelemetryError("direct writer journal is invalid JSON") from exc
    if (
        not isinstance(state, dict)
        or set(state) != {"schema", "pending", "last_attempt"}
        or state.get("schema") != "cathedral_direct_validator_state_v1"
        or canonical_document_bytes(state) != raw
    ):
        raise TelemetryError("direct writer journal is malformed")
    return state


def _plan_identity_sha256(identity: object) -> str:
    if not isinstance(identity, Mapping):
        raise TelemetryError("direct writer plan identity is malformed")
    return "sha256:" + hashlib.sha256(canonical_document_bytes(identity)).hexdigest()


def journal_pending_plan_matches(
    state_path: Path,
    plan_identity_sha256: str,
) -> bool:
    """Check one post-submit ambiguity against the writer's durable intent."""

    state = _direct_writer_journal(state_path)
    pending = state["pending"]
    if pending is None:
        return False
    if not isinstance(pending, Mapping):
        raise TelemetryError("direct writer pending intent is malformed")
    return _plan_identity_sha256(pending.get("identity")) == plan_identity_sha256


def journal_receipt_for_plan(
    state_path: Path,
    plan_identity_sha256: str,
) -> DirectSubmissionReceipt | None:
    """Bind recovered telemetry to the writer's finalized plan and receipt."""

    state = _direct_writer_journal(state_path)
    last = state["last_attempt"]
    if last is None:
        return None
    if not isinstance(last, Mapping):
        raise TelemetryError("direct writer last attempt is malformed")
    if _plan_identity_sha256(last.get("identity")) != plan_identity_sha256:
        return None
    return _stored_submission_receipt(last.get("receipt"))


def latest_telemetry_event(
    path: Path,
    *,
    expected_reader_gid: int | None = None,
) -> dict[str, Any]:
    """Read and validate the latest event for the separate exporter."""

    if path.is_symlink():
        raise TelemetryError("telemetry spool is a symlink")
    try:
        metadata = path.stat()
        raw = path.read_bytes()
    except OSError as exc:
        raise TelemetryError("telemetry spool is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (
            expected_reader_gid is None
            and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            )
        )
        or (
            expected_reader_gid is not None
            and (
                metadata.st_gid != expected_reader_gid
                or stat.S_IMODE(metadata.st_mode) != 0o640
                or expected_reader_gid not in {*os.getgroups(), os.getegid()}
            )
        )
        or not raw
        or len(raw) > MAX_TELEMETRY_HISTORY_BYTES
    ):
        raise TelemetryError("telemetry spool is not owner-only and bounded")
    line = raw.splitlines()[-1]
    try:
        document = json.loads(line.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelemetryError("latest telemetry event is invalid JSON") from exc
    if not isinstance(document, dict):
        raise TelemetryError("latest telemetry event schema is invalid")
    if _canonical_json_bytes(document) != line:
        raise TelemetryError("latest telemetry event is not canonical JSON")
    return validate_public_telemetry_event(document)


__all__ = [
    "MAX_TELEMETRY_EVENT_BYTES",
    "MAX_TELEMETRY_HISTORY_BYTES",
    "PendingTelemetryStore",
    "TELEMETRY_SCHEMA",
    "TelemetryError",
    "TelemetrySpool",
    "build_telemetry_snapshot",
    "build_telemetry_candidate",
    "canonical_telemetry_path",
    "latest_telemetry_event",
    "finalize_telemetry_candidate",
    "journal_pending_plan_matches",
    "journal_receipt_for_plan",
    "validate_public_telemetry_event",
]
