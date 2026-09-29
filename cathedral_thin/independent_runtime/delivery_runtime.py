"""Explicit SN94 delivered-resource mode using the existing direct chain writer.

No delivery policy means the existing SAT mode. This module never substitutes
SAT scores when receipt delivery is unavailable. A reserved window can start
one submission; ambiguity is reconciled through the writer's existing journal.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cathedral_thin.independent.submit import build_mechanism_weights_kwargs

from .delivery_plan import (
    MAX_BUNDLE_BYTES,
    DeliveryLedger,
    DeliveryPlanError,
    _read_json,
    consume_bundle,
    digest,
    policy_check,
    validate_saved_plan,
)
from .direct_contract import (
    DirectValidatorError,
    DirectWeightPlan,
    FinalizedMetagraphSnapshot,
)
from .qvl import DIRECT_VALIDATOR_QVL_DIGEST

DELIVERY_WEIGHT_SCHEMA = "cathedral_sn94_delivery_weight_plan_v1"


@dataclass(frozen=True)
class DeliveryWeightPlan(DirectWeightPlan):
    delivery: Mapping[str, Any]

    def identity(self) -> dict[str, object]:
        return {
            "schema": DELIVERY_WEIGHT_SCHEMA,
            "anchor": self.snapshot.identity(),
            "qvl_digest": self.qvl_digest,
            "evidence_digest": self.evidence_digest,
            "uid_hotkeys": [list(row) for row in self.uid_hotkeys],
            "raw_scores": [list(row) for row in self.raw_scores],
            "burn_uid": self.delivery["burn_uid"],
            "burn_weight": self.delivery["burn_weight"],
            "call": "SubtensorModule.set_mechanism_weights",
            "kwargs": self.kwargs(),
            "delivery": json.loads(json.dumps(self.delivery)),
        }


def weight_plan(
    snapshot: FinalizedMetagraphSnapshot, delivery: Mapping[str, Any]
) -> DeliveryWeightPlan:
    validate_saved_plan(delivery)
    policy = delivery["policy"]
    if (
        snapshot.netuid != 94
        or policy["mode"] != "write"
        or policy["verifier_sha256"] != DIRECT_VALIDATOR_QVL_DIGEST
    ):
        raise DeliveryPlanError(
            "delivery writing requires SN94 and the release-pinned QVL"
        )
    identities = tuple(sorted((miner.uid, miner.hotkey) for miner in snapshot.miners))
    if [list(row) for row in identities] != delivery["uid_hotkeys"]:
        raise DeliveryPlanError(
            "delivery identities differ from finalized miner identities"
        )
    if snapshot.validator_uid in delivery["wire_uids"]:
        raise DeliveryPlanError("validator cannot be a delivery destination")
    return DeliveryWeightPlan(
        snapshot=snapshot,
        qvl_digest=DIRECT_VALIDATOR_QVL_DIGEST,
        evidence_digest="sha256:" + delivery["plan_id"],
        machine_ids_by_uid=(),
        raw_scores=tuple(tuple(row) for row in delivery["raw_scores"]),
        uid_hotkeys=identities,
        wire_uids=tuple(delivery["wire_uids"]),
        wire_weights=tuple(delivery["wire_weights"]),
        delivery=delivery,
    )


def validate_delivery_identity(
    identity: Mapping[str, Any], *, policy_digest: str | None, netuid: int
) -> None:
    try:
        if (
            netuid != 94
            or policy_digest is None
            or identity["schema"] != DELIVERY_WEIGHT_SCHEMA
        ):
            raise DeliveryPlanError("delivery mode is not explicitly configured")
        delivery = identity["delivery"]
        validate_saved_plan(delivery)
        policy = delivery["policy"]
        if policy["mode"] != "write" or delivery["policy_digest"] != policy_digest:
            raise DeliveryPlanError("delivery policy differs from configured writer")
        if (
            policy["verifier_sha256"] != DIRECT_VALIDATOR_QVL_DIGEST
            or identity["qvl_digest"] != DIRECT_VALIDATOR_QVL_DIGEST
        ):
            raise DeliveryPlanError("delivery verifier differs from release")
        if identity["evidence_digest"] != "sha256:" + delivery["plan_id"]:
            raise DeliveryPlanError("delivery evidence identity differs")
        identities = {row["uid"]: row["hotkey"] for row in identity["anchor"]["miners"]}
        if (
            len(identities) != len(identity["anchor"]["miners"])
            or sorted(map(list, identities.items())) != delivery["uid_hotkeys"]
        ):
            raise DeliveryPlanError("delivery finalized identities differ")
        expected = build_mechanism_weights_kwargs(
            dests=delivery["wire_uids"],
            weights=delivery["wire_weights"],
            netuid=94,
            expected_netuid=94,
        )
        if (
            identity["kwargs"] != expected
            or identity["uid_hotkeys"] != delivery["uid_hotkeys"]
            or identity["raw_scores"] != delivery["raw_scores"]
            or identity["burn_uid"] != delivery["burn_uid"]
            or identity["burn_weight"] != delivery["burn_weight"]
            or identity["anchor"]["validator"]["uid"] in delivery["wire_uids"]
        ):
            raise DeliveryPlanError("delivery weight identity differs")
    except (KeyError, TypeError, ValueError) as exc:
        raise DirectValidatorError(
            "delivery plan or configured policy is inconsistent"
        ) from exc


def validate_writer_plan(plan: DeliveryWeightPlan, *, writer: Any) -> dict[str, Any]:
    if plan.netuid != writer.netuid:
        raise DirectValidatorError("delivery plan belongs to another subnet")
    identity = plan.identity()
    validate_delivery_identity(
        identity, policy_digest=writer.delivery_policy_digest, netuid=writer.netuid
    )
    if str(
        getattr(writer.keypair, "ss58_address", "")
    ) != plan.snapshot.validator_hotkey or not callable(
        getattr(writer.keypair, "sign", None)
    ):
        raise DirectValidatorError(
            "delivery writer key differs from finalized validator"
        )
    return plan.kwargs()


class DeliveryContext:
    def __init__(self, *, policy_path: Path, bundle_path: Path, ledger_path: Path):
        self.policy = policy_check(_read_json(str(policy_path), 65536))
        if (
            self.policy["mode"] != "write"
            or self.policy["verifier_sha256"] != DIRECT_VALIDATOR_QVL_DIGEST
        ):
            raise DeliveryPlanError(
                "delivery mode needs explicit write policy and release QVL pin"
            )
        if not bundle_path.is_absolute() or not ledger_path.is_absolute():
            raise DeliveryPlanError("delivery paths must be absolute")
        self.policy_digest = digest(self.policy)
        self.bundle_path = bundle_path
        self.ledger_path = ledger_path

    def run(
        self, *, subtensor: Any, keypair: Any, writer: Any, snapshot_reader: Any
    ) -> dict[str, Any]:
        # run_direct_cycle already owns the writer cycle lock. Recovery is always
        # first, even if the receipt feed or current policy files are unavailable.
        recovered = writer.recover()
        ledger = DeliveryLedger(self.ledger_path)
        try:
            ledger.db.execute(
                "CREATE TABLE IF NOT EXISTS submissions(plan_id TEXT PRIMARY KEY REFERENCES plans(plan_id),state TEXT NOT NULL,receipt TEXT)"
            )
            unresolved = ledger.db.execute(
                "SELECT plan_id FROM submissions WHERE state='STARTED'"
            ).fetchall()
            if len(unresolved) > 1:
                raise DeliveryPlanError("multiple unresolved delivery submissions")
            if unresolved:
                plan_id = unresolved[0][0]
                record = writer.delivery_record(plan_id)
                if record is None:
                    return {
                        "status": "NOT_PROVEN",
                        "mechanism": "sn94_delivery_v1",
                        "plan_id": plan_id,
                        "chain_write": False,
                    }
                ledger.db.execute(
                    "UPDATE submissions SET state='SETTLED',receipt=? WHERE plan_id=?",
                    (json.dumps(record, sort_keys=True), plan_id),
                )
                return {
                    "status": record["status"],
                    "mechanism": "sn94_delivery_v1",
                    "plan_id": plan_id,
                    "recovered": True,
                }
            if recovered is not None:
                return {
                    "status": recovered.status,
                    "mechanism": "sn94_delivery_v1",
                    "recovery": recovered.as_document(),
                }
            bundle = _read_json(str(self.bundle_path), MAX_BUNDLE_BYTES)
            window = bundle.get("window_start")
            prior = ledger.db.execute(
                "SELECT body FROM plans WHERE window_start=?", (window,)
            ).fetchone()
            if prior:
                delivery = ledger.recover(window, self.policy_digest)
                status = ledger.db.execute(
                    "SELECT state,receipt FROM submissions WHERE plan_id=?",
                    (delivery["plan_id"],),
                ).fetchone()
                if status:
                    return {
                        "status": "WINDOW_ALREADY_CONSUMED",
                        "mechanism": "sn94_delivery_v1",
                        "plan_id": delivery["plan_id"],
                        "chain_write": False,
                    }
            else:
                snapshot = snapshot_reader(subtensor, keypair, 94)
                # A feed cannot choose the miner identities used for a write.
                bundle["uid_hotkeys"] = [
                    [miner.uid, miner.hotkey]
                    for miner in sorted(snapshot.miners, key=lambda m: m.uid)
                ]
                delivery = consume_bundle(bundle, self.policy, now=int(time.time()))
                delivery, _ = ledger.prepare(delivery)
            snapshot = snapshot_reader(subtensor, keypair, 94)
            plan = weight_plan(snapshot, delivery)
            writer._validate_plan(plan)
            # Persist before any call into the signer. Even a crash before its
            # journal exists is NOT_PROVEN, never permission to sign again.
            ledger.db.execute(
                "INSERT INTO submissions VALUES(?,?,NULL)",
                (delivery["plan_id"], "STARTED"),
            )
            receipt = writer.submit(
                plan, cycle_deadline_monotonic=time.monotonic() + 180
            )
            ledger.db.execute(
                "UPDATE submissions SET state='SETTLED',receipt=? WHERE plan_id=?",
                (
                    json.dumps(receipt.as_document(), sort_keys=True),
                    delivery["plan_id"],
                ),
            )
            return {
                "status": receipt.status,
                "mechanism": "sn94_delivery_v1",
                "plan_id": delivery["plan_id"],
                "raw_scores": delivery["raw_scores"],
                "wire_uids": delivery["wire_uids"],
                "wire_weights": delivery["wire_weights"],
                "receipt": receipt.as_document(),
            }
        finally:
            ledger.close()
