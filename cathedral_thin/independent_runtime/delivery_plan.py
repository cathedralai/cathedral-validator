"""SN94 delivered-resource accounting, with no SAT or unattested fallback.

The durable plan reserves every receipt and interval atomically. A retry loads
that same plan; it never rebuilds a window using a changed policy or new feed.
The delivery-plan CLI never writes chain state. delivery_runtime connects an
explicit write policy to the existing journaled writer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

W = 65535
SCHEMA = "cathedral_sn94_delivery_plan_v1"
POLICY_SCHEMA = "cathedral_sn94_delivery_policy_v1"
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_RECEIPTS = 1000


class DeliveryPlanError(ValueError):
    """Unusable admission, accounting, policy or durable plan input."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def policy_check(document: object) -> dict[str, Any]:
    fields = {
        "schema",
        "netuid",
        "mode",
        "window_seconds",
        "burn_bps",
        "burn_uid",
        "burn_hotkey",
        "allowed_measurements",
        "verifier_path",
        "verifier_sha256",
        "control_plane_keys",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise DeliveryPlanError("delivery policy fields differ from v1")
    if (
        document["schema"] != POLICY_SCHEMA
        or type(document["netuid"]) is not int
        or document["netuid"] != 94
    ):
        raise DeliveryPlanError("delivery mode is SN94 only")
    if document["mode"] not in {"plan_only", "write"}:
        raise DeliveryPlanError("delivery submission is disabled in this build")
    for name, minimum, maximum in [
        ("window_seconds", 1, 86400),
        ("burn_bps", 0, 10000),
        ("burn_uid", 0, 65535),
    ]:
        value = document[name]
        if type(value) is not int or not minimum <= value <= maximum:
            raise DeliveryPlanError("invalid " + name)
    if not isinstance(document["burn_hotkey"], str) or not document["burn_hotkey"]:
        raise DeliveryPlanError("burn destination must pin a hotkey")
    values = document["allowed_measurements"]
    if (
        not isinstance(values, list)
        or not values
        or len(values) != len(set(values))
        or any(
            not isinstance(x, str)
            or not x.startswith("tdx-measurement-sha256:")
            or len(x) != 87
            for x in values
        )
    ):
        raise DeliveryPlanError("approved measurement list is required")
    keys = document["control_plane_keys"]
    if not isinstance(keys, dict) or not keys:
        raise DeliveryPlanError("control-plane public keys are required")
    try:
        for key_id, key in keys.items():
            if not isinstance(key_id, str) or not key_id:
                raise ValueError("key id")
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
        if len(bytes.fromhex(document["verifier_sha256"])) != 32:
            raise ValueError("digest")
        if not Path(document["verifier_path"]).is_absolute():
            raise ValueError("path")
    except (TypeError, ValueError) as exc:
        raise DeliveryPlanError("invalid public key or verifier pin") from exc
    return json.loads(canonical(document))


def build_plan(
    *,
    policy: Mapping[str, Any],
    window_start: int,
    uid_hotkeys: Mapping[int, str],
    admitted: Sequence[Any],
    rejected: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    from cathedral_delivery import AdmittedDelivery

    checked = policy_check(dict(policy))
    seconds = checked["window_seconds"]
    if type(window_start) is not int or window_start < 0 or window_start % seconds:
        raise DeliveryPlanError("window must align with policy")
    if not isinstance(uid_hotkeys, dict) or any(
        type(uid) is not int
        or not 0 <= uid <= W
        or not isinstance(hotkey, str)
        or not hotkey
        for uid, hotkey in uid_hotkeys.items()
    ):
        raise DeliveryPlanError("invalid finalized identity map")
    if len(set(uid_hotkeys.values())) != len(uid_hotkeys):
        raise DeliveryPlanError("duplicate miner hotkey")
    burn_uid = checked["burn_uid"]
    if uid_hotkeys.get(burn_uid) != checked["burn_hotkey"]:
        raise DeliveryPlanError("burn destination differs from identity map")
    hotkey_uids = {hotkey: uid for uid, hotkey in uid_hotkeys.items()}
    rows = []
    receipts = set()
    attempts = set()
    intervals = {}
    scores = {}
    for item in admitted:
        if not isinstance(item, AdmittedDelivery):
            raise DeliveryPlanError(
                "receipt lacks independently verified TDX admission"
            )
        body = dict(item.receipt.body)
        if (
            item.verifier_digest != checked["verifier_sha256"]
            or body["measurement"] not in checked["allowed_measurements"]
        ):
            raise DeliveryPlanError("admission differs from plan policy")
        if (
            body["window_start"] != window_start
            or body["window_end"] != window_start + seconds
        ):
            raise DeliveryPlanError("receipt is for another accounting window")
        uid = hotkey_uids.get(body["miner_hotkey"])
        if uid is None or uid == burn_uid or item.receipt.resource_seconds <= 0:
            raise DeliveryPlanError("receipt has no eligible miner identity")
        if body["receipt_id"] in receipts or body["attempt_id"] in attempts:
            raise DeliveryPlanError("duplicate receipt or attempt/window")
        receipts.add(body["receipt_id"])
        attempts.add(body["attempt_id"])
        for start, end in intervals.setdefault(body["sandbox_id"], []):
            if body["started_at"] < end and body["ended_at"] > start:
                raise DeliveryPlanError("overlapping delivery on one sandbox")
        intervals[body["sandbox_id"]].append((body["started_at"], body["ended_at"]))
        scores[uid] = scores.get(uid, 0) + item.receipt.resource_seconds
        rows.append(
            {
                "receipt_id": body["receipt_id"],
                "receipt_digest": item.receipt.digest,
                "attempt_id": body["attempt_id"],
                "sandbox_id": body["sandbox_id"],
                "miner_hotkey": body["miner_hotkey"],
                "hardware_id": body["hardware_id"],
                "executor_key_sha256": item.executor_key_sha256,
                "started_at": body["started_at"],
                "ended_at": body["ended_at"],
                "retention_until": body["retention_until"],
                "vcpu": body["vcpu"],
                "memory_gib": body["memory_gib"],
                "vcpu_seconds": body["vcpu_seconds"],
                "gib_seconds": body["gib_seconds"],
                "uid": uid,
            }
        )
    total = sum(scores.values())
    pay_budget = W * (10000 - checked["burn_bps"]) // 10000 if total else 0
    weights = (
        {uid: score * pay_budget // total for uid, score in scores.items()}
        if total
        else {}
    )
    if total:
        order = sorted(
            scores,
            key=lambda uid: (
                -(scores[uid] * pay_budget % total),
                uid_hotkeys[uid],
                uid,
            ),
        )
        for uid in order[: pay_budget - sum(weights.values())]:
            weights[uid] += 1
    weights[burn_uid] = W - sum(weights.values())
    document = {
        "schema": SCHEMA,
        "mode": checked["mode"],
        "netuid": 94,
        "window_start": window_start,
        "window_end": window_start + seconds,
        "policy": checked,
        "policy_digest": digest(checked),
        "uid_hotkeys": [[uid, hotkey] for uid, hotkey in sorted(uid_hotkeys.items())],
        "receipts": sorted(rows, key=lambda row: row["receipt_id"]),
        "rejected": sorted(
            [dict(row) for row in rejected],
            key=lambda row: str(row.get("receipt_id", "")),
        ),
        "raw_scores": [[uid, score] for uid, score in sorted(scores.items())],
        "wire_uids": [uid for uid, value in sorted(weights.items()) if value],
        "wire_weights": [value for uid, value in sorted(weights.items()) if value],
        "burn_uid": burn_uid,
        "burn_weight": weights[burn_uid],
        "chain_write": False,
    }
    return {**document, "plan_id": digest(document)}


class DeliveryLedger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if self.path.is_symlink():
            raise DeliveryPlanError("ledger must not be a symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if self.path.stat().st_mode & 0o077:
            raise DeliveryPlanError("ledger must be private")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS plans(plan_id TEXT PRIMARY KEY,window_start INTEGER UNIQUE NOT NULL,
            policy_digest TEXT NOT NULL,body TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS deliveries(receipt_id TEXT PRIMARY KEY,digest TEXT NOT NULL,
            attempt_id TEXT NOT NULL,sandbox_id TEXT NOT NULL,miner_hotkey TEXT NOT NULL,
            hardware_id TEXT NOT NULL,executor_key TEXT NOT NULL,start INTEGER NOT NULL,end INTEGER NOT NULL,
            window_start INTEGER NOT NULL,plan_id TEXT NOT NULL REFERENCES plans(plan_id),
            UNIQUE(attempt_id,window_start));
        """)

    def close(self):
        self.db.close()

    def prepare(self, plan: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
        validate_saved_plan(plan)
        document = dict(plan)
        plan_id = document.pop("plan_id", None)
        if (
            plan_id != digest(document)
            or document.get("schema") != SCHEMA
            or document.get("chain_write") is not False
        ):
            raise DeliveryPlanError("invalid immutable delivery plan")
        if digest(document["policy"]) != document["policy_digest"]:
            raise DeliveryPlanError("plan policy digest differs")
        document["plan_id"] = plan_id
        encoded = canonical(document).decode()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            prior = self.db.execute(
                "SELECT body FROM plans WHERE window_start=?",
                (document["window_start"],),
            ).fetchone()
            if prior:
                if prior[0] != encoded:
                    raise DeliveryPlanError(
                        "window is reserved by another immutable plan"
                    )
                self.db.execute("COMMIT")
                return json.loads(prior[0]), True
            for row in document["receipts"]:
                if self.db.execute(
                    "SELECT 1 FROM deliveries WHERE receipt_id=?", (row["receipt_id"],)
                ).fetchone():
                    raise DeliveryPlanError("receipt already consumed")
                binding = self.db.execute(
                    "SELECT sandbox_id,miner_hotkey,hardware_id,executor_key FROM deliveries WHERE attempt_id=? LIMIT 1",
                    (row["attempt_id"],),
                ).fetchone()
                if binding and binding != (
                    row["sandbox_id"],
                    row["miner_hotkey"],
                    row["hardware_id"],
                    row["executor_key_sha256"],
                ):
                    raise DeliveryPlanError("attempt identity changed across windows")
                if self.db.execute(
                    "SELECT 1 FROM deliveries WHERE sandbox_id=? AND start<? AND end>?",
                    (row["sandbox_id"], row["ended_at"], row["started_at"]),
                ).fetchone():
                    raise DeliveryPlanError("delivery interval was already consumed")
            self.db.execute(
                "INSERT INTO plans VALUES(?,?,?,?)",
                (plan_id, document["window_start"], document["policy_digest"], encoded),
            )
            for row in document["receipts"]:
                self.db.execute(
                    "INSERT INTO deliveries VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        row["receipt_id"],
                        row["receipt_digest"],
                        row["attempt_id"],
                        row["sandbox_id"],
                        row["miner_hotkey"],
                        row["hardware_id"],
                        row["executor_key_sha256"],
                        row["started_at"],
                        row["ended_at"],
                        document["window_start"],
                        plan_id,
                    ),
                )
            self.db.execute("COMMIT")
            return document, False
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def recover(self, window_start: int, policy_digest: str) -> dict[str, Any]:
        prior = self.db.execute(
            "SELECT policy_digest,body FROM plans WHERE window_start=?", (window_start,)
        ).fetchone()
        if prior is None or prior[0] != policy_digest:
            raise DeliveryPlanError("no reserved plan for this window and policy")
        document = json.loads(prior[1])
        claimed = document.pop("plan_id")
        if digest(document) != claimed:
            raise DeliveryPlanError("stored plan digest differs")
        return {**document, "plan_id": claimed}


def consume_bundle(
    bundle: Mapping[str, Any], policy: Mapping[str, Any], *, now: int
) -> dict[str, Any]:
    from cathedral_delivery import DeliveryError, admit_delivery, verify_receipt

    checked = policy_check(dict(policy))
    if not isinstance(bundle, dict) or set(bundle) != {
        "window_start",
        "uid_hotkeys",
        "entries",
    }:
        raise DeliveryPlanError("invalid delivery bundle")
    entries = bundle["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_RECEIPTS:
        raise DeliveryPlanError("receipt count exceeds limit")
    identities = bundle["uid_hotkeys"]
    if not isinstance(identities, list):
        raise DeliveryPlanError("invalid identity list")
    uid_hotkeys = {}
    for row in identities:
        if not isinstance(row, list) or len(row) != 2 or row[0] in uid_hotkeys:
            raise DeliveryPlanError("duplicate or invalid UID")
        uid_hotkeys[row[0]] = row[1]
    if (
        type(bundle["window_start"]) is not int
        or bundle["window_start"] + checked["window_seconds"] > now
    ):
        raise DeliveryPlanError("accounting window has not closed")
    admitted = []
    rejected = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "receipt",
            "executor_public_key",
            "quote_hex",
        }:
            raise DeliveryPlanError("invalid receipt entry")
        try:
            body = entry["receipt"]["body"]
            central = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(
                    checked["control_plane_keys"][body["control_plane_key_id"]]
                )
            )
            executor = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(entry["executor_public_key"])
            )
            receipt = verify_receipt(
                entry["receipt"],
                executor_key=executor,
                control_plane_key=central,
                now=now,
            )
            if receipt.resource_seconds <= 0:
                rejected.append(
                    {
                        "receipt_id": body["receipt_id"],
                        "reason": "unattested_or_lost",
                        "score": 0,
                    }
                )
                continue
            admission = admit_delivery(
                receipt,
                quote=bytes.fromhex(entry["quote_hex"]),
                executor_key=executor,
                allowed_measurements=frozenset(checked["allowed_measurements"]),
                verifier_path=checked["verifier_path"],
                verifier_sha256=checked["verifier_sha256"],
            )
            admitted.append(admission)
        except (DeliveryError, ValueError, KeyError, TypeError) as exc:
            # An invalid feed is not an empty fleet and cannot silently burn its
            # budget. Leave this window unconsumed until the same feed is fixed.
            raise DeliveryPlanError("receipt or quote admission refused") from exc
    return build_plan(
        policy=checked,
        window_start=bundle["window_start"],
        uid_hotkeys=uid_hotkeys,
        admitted=admitted,
        rejected=rejected,
    )


def _read_json(path: str, limit: int) -> dict[str, Any]:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise DeliveryPlanError("duplicate JSON key")
            value[key] = item
        return value

    candidate = Path(path)
    if candidate.is_symlink():
        raise DeliveryPlanError("input must not be a symlink")
    with candidate.open("rb") as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise DeliveryPlanError("input exceeds limit")
    return json.loads(raw, object_pairs_hook=unique)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cathedral-validator delivery-plan")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--bundle")
    parser.add_argument("--ledger")
    parser.add_argument("--recover-window", type=int)
    args = parser.parse_args(argv)
    ledger = None
    try:
        policy = policy_check(_read_json(args.policy, 65536))
        if not args.ledger:
            raise DeliveryPlanError("a durable ledger is required")
        if args.recover_window is not None:
            if args.bundle:
                raise DeliveryPlanError("recovery never accepts a replacement bundle")
            ledger = DeliveryLedger(args.ledger)
            plan = ledger.recover(args.recover_window, digest(policy))
            recovered = True
        else:
            if not args.bundle:
                raise DeliveryPlanError("a receipt bundle is required")
            plan = consume_bundle(
                _read_json(args.bundle, MAX_BUNDLE_BYTES), policy, now=int(time.time())
            )
            ledger = DeliveryLedger(args.ledger)
            plan, recovered = ledger.prepare(plan)
        print(
            json.dumps(
                {
                    "status": "RECOVERED_PLAN" if recovered else "PREPARED_PLAN",
                    "chain_write": False,
                    "plan": plan,
                },
                sort_keys=True,
            )
        )
        return 0
    except (
        DeliveryPlanError,
        ImportError,
        ValueError,
        TypeError,
        KeyError,
        OSError,
        sqlite3.Error,
    ):
        print(json.dumps({"code": "delivery_plan_refused", "chain_write": False}))
        return 2
    finally:
        if ledger is not None:
            ledger.close()


def validate_saved_plan(plan: Mapping[str, Any]) -> None:
    """Recompute the accounting identity before either submit or recovery."""
    document = dict(plan)
    claimed = document.pop("plan_id", None)
    if (
        claimed != digest(document)
        or document.get("schema") != SCHEMA
        or document.get("netuid") != 94
    ):
        raise DeliveryPlanError("saved delivery identity differs")
    policy = policy_check(document["policy"])
    if document["policy_digest"] != digest(policy):
        raise DeliveryPlanError("saved policy differs")
    start = document["window_start"]
    end = document["window_end"]
    if (
        type(start) is not int
        or start < 0
        or start % policy["window_seconds"]
        or end != start + policy["window_seconds"]
    ):
        raise DeliveryPlanError("saved accounting window differs")
    identities = {}
    for uid, hotkey in document["uid_hotkeys"]:
        if (
            type(uid) is not int
            or not 0 <= uid <= W
            or uid in identities
            or not isinstance(hotkey, str)
        ):
            raise DeliveryPlanError("saved miner identities differ")
        identities[uid] = hotkey
    if identities.get(policy["burn_uid"]) != policy["burn_hotkey"]:
        raise DeliveryPlanError("saved burn identity differs")
    scores = {}
    ids = set()
    attempts = set()
    intervals = {}
    for row in document["receipts"]:
        if row["receipt_id"] in ids or row["attempt_id"] in attempts:
            raise DeliveryPlanError("duplicate saved delivery")
        ids.add(row["receipt_id"])
        attempts.add(row["attempt_id"])
        if (
            identities.get(row["uid"]) != row["miner_hotkey"]
            or row["uid"] == policy["burn_uid"]
        ):
            raise DeliveryPlanError("saved delivery owner differs")
        if not start <= row["started_at"] < row["ended_at"] <= end:
            raise DeliveryPlanError("saved interval differs")
        seconds = row["ended_at"] - row["started_at"]
        if (
            type(row["vcpu"]) is not int
            or not 1 <= row["vcpu"] <= 16
            or type(row["memory_gib"]) is not int
            or not 1 <= row["memory_gib"] <= 64
            or type(row["vcpu_seconds"]) is not int
            or row["vcpu_seconds"] != row["vcpu"] * seconds
            or type(row["gib_seconds"]) is not int
            or row["gib_seconds"] != row["memory_gib"] * seconds
        ):
            raise DeliveryPlanError("saved resource arithmetic differs")
        for old_start, old_end in intervals.setdefault(row["sandbox_id"], []):
            if row["started_at"] < old_end and row["ended_at"] > old_start:
                raise DeliveryPlanError("overlapping saved deliveries")
        intervals[row["sandbox_id"]].append((row["started_at"], row["ended_at"]))
        scores[row["uid"]] = (
            scores.get(row["uid"], 0) + row["vcpu_seconds"] + row["gib_seconds"]
        )
    if document["raw_scores"] != [
        [uid, score] for uid, score in sorted(scores.items())
    ]:
        raise DeliveryPlanError("saved resource scores differ")
    total = sum(scores.values())
    budget = W * (10000 - policy["burn_bps"]) // 10000 if total else 0
    weights = (
        {uid: score * budget // total for uid, score in scores.items()} if total else {}
    )
    if total:
        order = sorted(
            scores,
            key=lambda uid: (-(scores[uid] * budget % total), identities[uid], uid),
        )
        for uid in order[: budget - sum(weights.values())]:
            weights[uid] += 1
    weights[policy["burn_uid"]] = W - sum(weights.values())
    if (
        document["wire_uids"]
        != [uid for uid, score in sorted(weights.items()) if score]
        or document["wire_weights"]
        != [score for uid, score in sorted(weights.items()) if score]
        or document["burn_uid"] != policy["burn_uid"]
        or document["burn_weight"] != weights[policy["burn_uid"]]
    ):
        raise DeliveryPlanError("saved delivery weight vector differs")
