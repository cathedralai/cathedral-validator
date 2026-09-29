"""Shadow scoring of SN94 prober capacity receipts.

The SN94 owner's prober probes each registered Cathedral runtime box every
round and signs a receipt of the capacity it verified (cathedral-sandbox
``cathedral.capacity``). This module is the validator's side, on any netuid:

* fetch this validator's own receipts for the round, answering a fresh nonce,
  from the receipt feed named in the policy;
* verify each receipt against the pinned prober keys (signature, netuid,
  nonce, round, freshness, and that the challenge proves the capacity paid
  for);
* record each TEE receipt's evidence (receipt v2: the SHA-256 of the quote or
  report the prober verified, its launch measurement, the verifier's digest,
  the attested TLS key's SPKI hash, the nonce the quote's REPORT_DATA was made
  over and when the prober verified it) in its row and in the inventory, and,
  only when the policy sets ``max_evidence_age_seconds``, refuse a receipt
  whose evidence is older than that;
* optionally check that measurement against the owner's measurement policy
  files (cathedral-validator #256's ``cathedral_tdx_measurement_policy_v1``,
  and the SEV-SNP variant from the library's admission module): in
  ``enforce`` an unlisted measurement is refused, in ``shadow`` it is only
  recorded;
* refuse bare-metal boxes unless the policy sets ``admit_bare_metal`` (TEE
  boxes come first; bare metal is deferred);
* refuse a box id seen twice, and hardware claimed under two hotkeys; keep one
  box per hardware id for a single hotkey;
* optionally recompute one sampled challenge lane per receipt, within a memory
  and time budget. The recheck runs the library's pure-Python reference, and
  the budget is smaller than the library's smallest lane (MIN_LANE_BYTES), so
  today every admissible receipt is ``skipped``: the recheck is effectively off
  until a native checker exists (docs/CAPACITY_RECEIPTS.md);
* value each box at the market price of its verified capacity, from a price
  table the SN94 owner signs and the policy pins.

It only records. Its result goes into the cycle event after the weight write
has returned, and nothing it computes reaches the plan, so it never changes
who is paid. An error becomes a ``FAILED`` record, never a failed cycle, and a
receipt that makes verification or valuation raise anything is refused on its
own, never failing the round.

Without ``CATHEDRAL_CAPACITY_POLICY`` (a path) nothing runs.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from cathedral_thin.independent.canonical import PolicyBundleError, parse_strict_json
from cathedral_thin.independent_runtime.capacity_inventory import (
    BARE_METAL_REFUSED,
    MEASUREMENT_REFUSED,
    NOT_ADMITTED,
    record_cycle,
)
from cathedral_thin.independent.fetch_policy import (
    PolicyFetchError,
    fetch_policy_bytes,
    validate_policy_url,
)

POLICY_SCHEMA = "cathedral_capacity_policy_v1"
FEED_SCHEMA = "cathedral_capacity_receipt_feed_v1"
CAPACITY_POLICY_ENV = "CATHEDRAL_CAPACITY_POLICY"
MODES = ("shadow",)
MAX_POLICY_BYTES = 128 * 1024
MAX_FEED_BYTES = 1_048_576
MAX_RECEIPTS = 1024
MAX_KEYS = 16
# The recheck recomputes a lane with the library's pure-Python reference, which
# needs the lane's whole memory and about 1.5 us per step. The library refuses
# claims with less than MIN_LANE_BYTES (512 MiB) of lane per vCPU, and such a
# lane takes about a minute in pure Python, the whole time budget, with no way to
# stop it once started. So the cap stays well below one real lane: every
# receipt a current prober can issue is "skipped", and the recheck is off in
# effect until a native checker exists. The machinery stays for that checker.
MAX_RECHECK_MIB = 64
RECHECK_BUDGET_SECONDS = 60.0
# The record is one journal line, so every list and map in it is capped; the
# inventory file keeps every box. MAX_EVENT_LINE_BYTES is the worst case the
# tests build, with margin under journald's default 48 KiB LineMax.
MAX_EVENT_ROWS = 24
MAX_EVENT_UNITS = 64
MAX_EVENT_REASONS = 16
MAX_EVENT_LINE_BYTES = 40_000
FETCH_TIMEOUT_SECONDS = 30.0
MAX_ERROR_CHARS = 200
_HEX64 = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"[A-Za-z0-9._:-]{1,64}")
_POLICY_KEYS = frozenset(
    {
        "schema",
        "mode",
        "receipts_url",
        "prober_keys",
        "price_keys",
        "price_table",
        "recheck_max_mib",
    }
)
_OPTIONAL_POLICY_KEYS = frozenset(
    {
        "inventory_path",
        "admit_bare_metal",
        "minimum_price_table_sequence",
        "price_table_digest",
        "measurement_policies",
        "max_evidence_age_seconds",
    }
)
# A TEE receipt's evidence is the attestation from the box's admission, or
# from its last relaunch between customers, reused for every round's receipt
# until the next one. An idle box is not relaunched, so its evidence can be
# any age while the box is healthy. The age bound is therefore opt-in, like
# the library's verify_receipt: without max_evidence_age_seconds nothing is
# refused for age. An operator sets it only when their prober re-attests on a
# known cadence.
MAX_EVIDENCE_AGE_SECONDS = 7 * 24 * 3600
MAX_PRICE_TABLE_SEQUENCE = 2**63 - 1
BARE_METAL = "bare_metal"
# What a v2 TEE receipt's evidence carries (cathedral.capacity.receipt.ReceiptEvidence).
EVIDENCE_FIELDS = (
    "evidence_kind",
    "evidence_sha256",
    "measurement",
    "verifier_digest",
    "tls_spki_sha256",
    "attestation_nonce",
    "attested_at",
)

ACCEPTED = "ACCEPTED"


class CapacityPolicyError(Exception):
    """The capacity policy is unreadable or malformed, or the library is missing."""


def _library() -> tuple[Any, Any, Any]:
    try:
        from cathedral.capacity import challenge, pricing, receipt  # noqa: PLC0415
    except ImportError as exc:
        raise CapacityPolicyError(
            "the installed cathedral-sandbox has no cathedral.capacity library"
        ) from exc
    return challenge, pricing, receipt


def _admission() -> Any:
    try:
        from cathedral.capacity import admission  # noqa: PLC0415
    except ImportError as exc:
        raise CapacityPolicyError(
            "measurement_policies needs a cathedral-sandbox with"
            " cathedral.capacity.admission"
        ) from exc
    return admission


@dataclass(frozen=True)
class CapacityPolicy:
    mode: str
    receipts_url: str
    prober_keys: Mapping[str, Any]
    price_table: Any
    recheck_max_mib: int
    digest: str
    inventory_path: Path | None = None
    admit_bare_metal: bool = False
    minimum_price_table_sequence: int = 1
    price_table_digest: str | None = None
    # tee_kind -> the library's MeasurementPolicy; empty means record only.
    measurement_policies: Mapping[str, Any] = field(default_factory=dict)
    # verify_receipt refuses a TEE receipt whose evidence is older than this;
    # None (the default) sets no bound.
    max_evidence_age: timedelta | None = None


def _safe_bytes(path: Path) -> bytes:
    if not path.is_absolute():
        raise CapacityPolicyError("capacity policy path must be absolute")
    try:
        fd = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise CapacityPolicyError(
            f"capacity policy is unreadable: {type(exc).__name__}"
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise CapacityPolicyError("capacity policy must be a regular file")
        if info.st_mode & stat.S_IWOTH:
            raise CapacityPolicyError("capacity policy must not be world-writable")
        if info.st_size > MAX_POLICY_BYTES:
            raise CapacityPolicyError("capacity policy is too large")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(MAX_POLICY_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_POLICY_BYTES:
        raise CapacityPolicyError("capacity policy is too large")
    return data


def _ed25519_keys(value: object, label: str) -> dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PublicKey,
    )

    if not isinstance(value, dict) or not 1 <= len(value) <= MAX_KEYS:
        raise CapacityPolicyError(f"{label} must map 1 to {MAX_KEYS} key ids to keys")
    keys: dict[str, Any] = {}
    for key_id, raw in value.items():
        if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
            raise CapacityPolicyError(f"{label} has a malformed key id")
        if not isinstance(raw, str) or _HEX64.fullmatch(raw) is None:
            raise CapacityPolicyError(
                f"{label} keys must be 64 lowercase hex characters (raw Ed25519)"
            )
        keys[key_id] = Ed25519PublicKey.from_public_bytes(bytes.fromhex(raw))
    return keys


def _measurement_policies(value: object) -> dict[str, Any]:
    """One measurement policy file per TEE kind, in #256's format, read as
    safely as the capacity policy itself and parsed by the library."""

    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 2
        or any(not isinstance(item, str) for item in value)
    ):
        raise CapacityPolicyError(
            "measurement_policies must list one or two measurement policy paths"
        )
    admission = _admission()
    policies: dict[str, Any] = {}
    for path in value:
        try:
            parsed = admission.parse_policy(_safe_bytes(Path(path)))
        except admission.AdmissionError as exc:
            raise CapacityPolicyError(f"measurement policy {path}: {exc}") from exc
        except CapacityPolicyError as exc:
            raise CapacityPolicyError(f"measurement policy {path}: {exc}") from exc
        if parsed.kind in policies:
            raise CapacityPolicyError(
                f"measurement_policies names two {parsed.kind} policies"
            )
        policies[parsed.kind] = parsed
    return policies


def parse_capacity_policy(raw: bytes, *, now: datetime) -> CapacityPolicy:
    _challenge, pricing, _receipt = _library()
    try:
        document = parse_strict_json(raw, max_bytes=MAX_POLICY_BYTES)
    except (PolicyBundleError, ValueError, RecursionError) as exc:
        raise CapacityPolicyError(f"capacity policy: {exc}") from exc
    if not isinstance(document, dict) or not (
        _POLICY_KEYS <= set(document) <= _POLICY_KEYS | _OPTIONAL_POLICY_KEYS
    ):
        raise CapacityPolicyError(
            f"capacity policy must have exactly {sorted(_POLICY_KEYS)}"
            f" and optionally {sorted(_OPTIONAL_POLICY_KEYS)}"
        )
    if document["schema"] != POLICY_SCHEMA:
        raise CapacityPolicyError("capacity policy schema is unsupported")
    if document["mode"] not in MODES:
        raise CapacityPolicyError(
            "capacity policy mode must be shadow: this build records, it does not pay"
        )
    url = document["receipts_url"]
    try:
        validate_policy_url(url)
    except PolicyFetchError as exc:
        raise CapacityPolicyError(f"receipts_url: {exc}") from exc
    if url.endswith("/"):
        raise CapacityPolicyError("receipts_url must not end with /")
    prober_keys = _ed25519_keys(document["prober_keys"], "prober_keys")
    price_keys = _ed25519_keys(document["price_keys"], "price_keys")
    admit_bare_metal = document.get("admit_bare_metal", False)
    if not isinstance(admit_bare_metal, bool):
        raise CapacityPolicyError("admit_bare_metal must be true or false")
    # The signed table sits in this local file, so these two guard against
    # pasting in an older signed table (or a different one at the same sequence).
    minimum_sequence = document.get("minimum_price_table_sequence", 1)
    if (
        not isinstance(minimum_sequence, int)
        or isinstance(minimum_sequence, bool)
        or not 1 <= minimum_sequence <= MAX_PRICE_TABLE_SEQUENCE
    ):
        raise CapacityPolicyError(
            "minimum_price_table_sequence must be an integer from 1 to"
            f" {MAX_PRICE_TABLE_SEQUENCE}"
        )
    pinned_digest = document.get("price_table_digest")
    if pinned_digest is not None and (
        not isinstance(pinned_digest, str) or _HEX64.fullmatch(pinned_digest) is None
    ):
        raise CapacityPolicyError(
            "price_table_digest must be 64 lowercase hex characters"
        )
    try:
        table = pricing.load_price_table(
            document["price_table"],
            owner_keys=price_keys,
            now=now,
            minimum_sequence=minimum_sequence,
            pinned_digest=pinned_digest,
        )
    except pricing.PriceTableError as exc:
        raise CapacityPolicyError(f"price_table: {exc}") from exc
    recheck = document["recheck_max_mib"]
    if (
        not isinstance(recheck, int)
        or isinstance(recheck, bool)
        or not 0 <= recheck <= MAX_RECHECK_MIB
    ):
        raise CapacityPolicyError(
            f"recheck_max_mib must be an integer from 0 to {MAX_RECHECK_MIB}"
        )
    inventory = document.get("inventory_path")
    if inventory is not None and (
        not isinstance(inventory, str)
        or not inventory.startswith("/")
        or not inventory.endswith(".json")
        or "\x00" in inventory
        or ".." in Path(inventory).parts
    ):
        raise CapacityPolicyError(
            "inventory_path must be an absolute path to a .json file"
        )
    max_evidence_age = document.get("max_evidence_age_seconds")
    if "max_evidence_age_seconds" in document and (
        not isinstance(max_evidence_age, int)
        or isinstance(max_evidence_age, bool)
        or not 1 <= max_evidence_age <= MAX_EVIDENCE_AGE_SECONDS
    ):
        raise CapacityPolicyError(
            "max_evidence_age_seconds must be an integer from 1 to"
            f" {MAX_EVIDENCE_AGE_SECONDS}"
        )
    measurement_policies = (
        _measurement_policies(document["measurement_policies"])
        if "measurement_policies" in document
        else {}
    )
    return CapacityPolicy(
        mode=document["mode"],
        receipts_url=url,
        prober_keys=prober_keys,
        price_table=table,
        recheck_max_mib=recheck,
        digest="sha256:" + hashlib.sha256(bytes(raw)).hexdigest(),
        inventory_path=Path(inventory) if inventory is not None else None,
        admit_bare_metal=admit_bare_metal,
        minimum_price_table_sequence=minimum_sequence,
        price_table_digest=pinned_digest,
        measurement_policies=measurement_policies,
        max_evidence_age=(
            None if max_evidence_age is None else timedelta(seconds=max_evidence_age)
        ),
    )


def load_capacity_policy(path: str | Path, *, now: datetime) -> CapacityPolicy:
    return parse_capacity_policy(_safe_bytes(Path(path)), now=now)


def _parse_feed(raw: bytes, *, netuid: int, nonce: str) -> tuple[int, list[Any]]:
    try:
        document = parse_strict_json(raw, max_bytes=MAX_FEED_BYTES)
    except PolicyBundleError as exc:
        raise CapacityPolicyError(f"receipt feed: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "netuid",
        "round",
        "validator_nonce",
        "receipts",
    }:
        raise CapacityPolicyError("receipt feed has the wrong fields")
    if document["schema"] != FEED_SCHEMA:
        raise CapacityPolicyError("receipt feed schema is unsupported")
    if document["netuid"] != netuid or document["validator_nonce"] != nonce:
        raise CapacityPolicyError("receipt feed answers another netuid or nonce")
    round_ = document["round"]
    if not isinstance(round_, int) or isinstance(round_, bool) or round_ < 0:
        raise CapacityPolicyError("receipt feed round must be a non-negative integer")
    receipts = document["receipts"]
    if not isinstance(receipts, list) or len(receipts) > MAX_RECEIPTS:
        raise CapacityPolicyError(
            f"receipt feed must list at most {MAX_RECEIPTS} receipts"
        )
    return round_, receipts


def _reason(text: str) -> str:
    """A refusal reason that is at most MAX_ERROR_CHARS bytes on the journal
    line: printable ASCII only, with nothing JSON has to escape."""

    return "".join(
        char if " " <= char <= "~" and char not in '"\\' else "?"
        for char in text[:MAX_ERROR_CHARS]
    )


def _short(exc: BaseException) -> str:
    text = str(exc)
    name = type(exc).__name__
    return (f"{name}: {text}" if text else name)[:MAX_ERROR_CHARS]


def _evidence_row(evidence: Any) -> dict[str, str] | None:
    if evidence is None:
        return None
    return {name: getattr(evidence, name) for name in EVIDENCE_FIELDS}


def score_receipts(
    receipts: Iterable[Any],
    *,
    policy: CapacityPolicy,
    netuid: int,
    nonce: str,
    round_: int,
    hotkey_to_uid: Mapping[str, int],
    now: datetime,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Verify, deduplicate, recheck and value one round's receipts.

    Each receipt is contained on its own: whatever verifying or valuing it
    raises refuses that receipt and the round goes on.
    """

    challenge, _pricing, receipt_lib = _library()
    rows: list[dict[str, Any]] = []
    verified: list[tuple[dict[str, Any], Any]] = []
    for item in receipts:
        try:
            parsed = receipt_lib.verify_receipt(
                item,
                prober_keys=policy.prober_keys,
                netuid=netuid,
                validator_nonce=nonce,
                now=now,
                expected_round=round_,
                max_evidence_age=policy.max_evidence_age,
            )
            row = {
                "box_id": parsed.box_id,
                "miner_hotkey": parsed.miner_hotkey,
                "uid": hotkey_to_uid.get(parsed.miner_hotkey),
                "kind": parsed.kind,
                "tee_kind": parsed.tee_kind,
                "hardware_id_kind": parsed.hardware_id_kind,
                "hardware_id": parsed.hardware_id,
                "vcpus": parsed.vcpus,
                "memory_gib": parsed.memory_gib,
                "value": policy.price_table.value(
                    kind=parsed.kind, vcpus=parsed.vcpus, memory_gib=parsed.memory_gib
                ),
                # A v2 receipt carries evidence exactly for a TEE box; the
                # library refuses a TEE receipt without it.
                "evidence": _evidence_row(parsed.evidence),
                "measurement_allowed": None,
                "recheck": "off",
                "verdict": ACCEPTED,
            }
            measurement_policy = (
                policy.measurement_policies.get(parsed.evidence.evidence_kind)
                if parsed.evidence is not None
                else None
            )
            if measurement_policy is not None:
                row["measurement_allowed"] = measurement_policy.allows(
                    parsed.evidence.measurement
                )
        except receipt_lib.ReceiptError as exc:
            rows.append({"verdict": "REFUSED", "reason": _reason(str(exc))})
            continue
        except Exception as exc:  # noqa: BLE001 - one receipt never fails the round
            # The message is kept (bounded), so a library bug that refuses every
            # receipt still reads as that bug in the record's refused counts.
            rows.append({"verdict": "REFUSED", "reason": _reason(_short(exc))})
            continue
        if parsed.kind == BARE_METAL and not policy.admit_bare_metal:
            row["verdict"] = "REFUSED"
            row["reason"] = BARE_METAL_REFUSED
        elif (
            row["measurement_allowed"] is False and measurement_policy.mode == "enforce"
        ):
            row["verdict"] = "REFUSED"
            row["reason"] = MEASUREMENT_REFUSED
        rows.append(row)
        verified.append((row, parsed))

    def refuse(row: dict[str, Any], reason: str) -> None:
        if row["verdict"] == ACCEPTED:
            row["verdict"] = "REFUSED"
            row["reason"] = reason

    by_box: dict[str, list[dict[str, Any]]] = {}
    by_hardware: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row, _parsed in verified:
        if row.get("reason") in NOT_ADMITTED:
            # A box that is not admitted takes no part in dedup, so a cheap
            # bare-metal receipt (or a TEE box running an unlisted image)
            # cannot knock out an admitted box sharing its box id or hardware.
            continue
        by_box.setdefault(row["box_id"], []).append(row)
        by_hardware.setdefault(
            (row["hardware_id_kind"], row["hardware_id"]), []
        ).append(row)
    for same_box in by_box.values():
        if len(same_box) > 1:
            for row in same_box:
                refuse(row, "the feed carries this box more than once")
    for same_hardware in by_hardware.values():
        if len({row["miner_hotkey"] for row in same_hardware}) > 1:
            for row in same_hardware:
                refuse(row, "this hardware is claimed under several hotkeys")
            continue
        ordered = sorted(same_hardware, key=lambda row: (-row["value"], row["box_id"]))
        for row in ordered[1:]:
            refuse(row, "another box of this hotkey has the same hardware")
    for row, _parsed in verified:
        if row["uid"] is None:
            refuse(row, "the hotkey is not a serving miner on this netuid")
        elif row["value"] <= 0:
            refuse(row, "below every consumer profile's minimum shape")

    budget_ends = clock() + RECHECK_BUDGET_SECONDS
    limit = policy.recheck_max_mib * (1 << 20)
    for row, parsed in verified:
        if row["verdict"] != ACCEPTED or limit == 0:
            continue
        if (
            parsed.challenge.blocks * challenge.BLOCK_BYTES > limit
            or clock() >= budget_ends
        ):
            row["recheck"] = "skipped"
            continue
        # The prober's own nonce picked these lanes after the box committed; the
        # validator's nonce picks which of them it recomputes.
        lanes = sorted(parsed.sampled_outputs)
        pick = hashlib.sha256(bytes.fromhex(nonce) + row["box_id"].encode()).digest()
        lane = lanes[int.from_bytes(pick[:8], "big") % len(lanes)]
        try:
            recomputed = challenge.lane_output(parsed.challenge, lane)
        except Exception as exc:  # noqa: BLE001 - one receipt never fails the round
            row["recheck"] = "error"
            refuse(row, _reason(_short(exc)))
            continue
        if recomputed == parsed.sampled_outputs[lane]:
            row["recheck"] = "passed"
        else:
            row["recheck"] = "failed"
            refuse(row, "a sampled challenge lane does not recompute")

    units: dict[int, int] = {}
    for row, _parsed in verified:
        if row["verdict"] == ACCEPTED:
            units[row["uid"]] = units.get(row["uid"], 0) + row["value"]
    refused: dict[str, int] = {}
    for row in rows:
        if row["verdict"] != ACCEPTED:
            refused[row["reason"]] = refused.get(row["reason"], 0) + 1
    return {
        "receipts": len(rows),
        "accepted": sum(1 for row in rows if row["verdict"] == ACCEPTED),
        "refused": dict(sorted(refused.items())),
        "recheck_failures": sum(1 for row in rows if row.get("recheck") == "failed"),
        "units": [[uid, value] for uid, value in sorted(units.items())],
        "rows": rows,
    }


def _event_fields(scored: Mapping[str, Any]) -> dict[str, Any]:
    """``score_receipts``'s result, capped for the one journal line: the first
    MAX_EVENT_ROWS rows, the MAX_EVENT_UNITS most valuable UIDs (``units_total``
    still sums every UID) and the MAX_EVENT_REASONS most common refusal reasons
    (``refused_omitted`` counts the receipts refused for the rest)."""

    rows = scored["rows"]
    units = sorted(scored["units"], key=lambda item: (-item[1], item[0]))
    refused = sorted(scored["refused"].items(), key=lambda item: (-item[1], item[0]))
    return {
        "receipts": scored["receipts"],
        "accepted": scored["accepted"],
        "refused": dict(sorted(refused[:MAX_EVENT_REASONS])),
        "refused_omitted": sum(count for _reason, count in refused[MAX_EVENT_REASONS:]),
        "recheck_failures": scored["recheck_failures"],
        "units": sorted(units[:MAX_EVENT_UNITS]),
        "units_omitted": max(0, len(units) - MAX_EVENT_UNITS),
        "units_total": sum(value for _uid, value in units),
        "rows": rows[:MAX_EVENT_ROWS],
        "rows_omitted": max(0, len(rows) - MAX_EVENT_ROWS),
    }


class CapacityShadow:
    """One validator's shadow capacity scoring, run once per cycle."""

    def __init__(
        self,
        policy: CapacityPolicy,
        *,
        fetch: Callable[[str], bytes] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.policy = policy
        self._fetch = fetch or (
            lambda url: fetch_policy_bytes(url, timeout=FETCH_TIMEOUT_SECONDS)
        )
        self._now = now or (lambda: datetime.now(timezone.utc))

    def record(
        self, *, netuid: int, hotkey_to_uid: Mapping[str, int]
    ) -> dict[str, Any]:
        """Score this round's receipts, or describe why not. Never raises.

        ``hotkey_to_uid`` names this cycle's serving miners. The record is
        capped (``_event_fields``) so the cycle's one journal line stays under
        MAX_EVENT_LINE_BYTES; the inventory file, when the policy names one,
        covers every receipt's box.
        """

        head = {
            "mode": self.policy.mode,
            "policy_digest": self.policy.digest,
            "price_table_sequence": self.policy.price_table.sequence,
            "currency": self.policy.price_table.currency,
            "unit": "micro-currency per hour",
        }
        measurement_policies = getattr(self.policy, "measurement_policies", None)
        if measurement_policies:
            head["measurement_policies"] = {
                kind: {"mode": item.mode, "digest": item.digest}
                for kind, item in sorted(measurement_policies.items())
            }
        try:
            nonce = secrets.token_hex(32)
            raw = self._fetch(f"{self.policy.receipts_url}/{netuid}/{nonce}")
            if len(raw) > MAX_FEED_BYTES:
                raise CapacityPolicyError("receipt feed is too large")
            round_, receipts = _parse_feed(raw, netuid=netuid, nonce=nonce)
            now = self._now()
            scored = score_receipts(
                receipts,
                policy=self.policy,
                netuid=netuid,
                nonce=nonce,
                round_=round_,
                hotkey_to_uid=hotkey_to_uid,
                now=now,
            )
        except Exception as exc:  # noqa: BLE001 - a shadow record never fails the cycle
            return {**head, "status": "FAILED", "error": _short(exc)}
        rows = scored["rows"]
        record = {
            **head,
            "status": "RECORDED",
            "round": round_,
            **_event_fields(scored),
        }
        if self.policy.inventory_path is not None:
            try:
                aggregate = record_cycle(
                    self.policy.inventory_path,
                    rows,
                    netuid=netuid,
                    round_=round_,
                    now=now,
                )
                record["inventory"] = {"status": "WRITTEN", "aggregate": aggregate}
            except Exception as exc:  # noqa: BLE001 - the inventory never fails the record
                record["inventory"] = {"status": "FAILED", "error": _short(exc)}
        return record


__all__ = [
    "CAPACITY_POLICY_ENV",
    "CapacityPolicy",
    "CapacityPolicyError",
    "CapacityShadow",
    "load_capacity_policy",
    "parse_capacity_policy",
    "score_receipts",
]
