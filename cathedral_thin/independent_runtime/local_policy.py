"""A local funded-Compute PolicyBundle for the first independent canary.

SN39 does not yet carry an on-chain ``CATHPOL1`` commitment this runner can
fetch. The live canary therefore signs its own genesis EconomicsSet with
ephemeral 2-of-3 keys, funds Compute, and composes against the live
metagraph. The resulting vector is this validator's origin, not the owner
feed. CyberGym and Voice stay at allocation 0.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from cathedral_thin.independent.constants import (
    BURN_HOTKEY,
    ECONOMICS_SET_SCHEMA,
    GENESIS_PREVIOUS_DIGEST,
    H,
    NETUID,
    POLICY_BUNDLE_SCHEMA,
)
from cathedral_thin.independent.policy import (
    PolicyBundle,
    encode_commitment,
    parse_policy_bundle,
    signing_payload,
)

COMPUTE_LANE = {"schema": "cathedral_compute_receipt_v1", "platform": "intel_tdx_cpu"}
CYBERGYM_LANE = {"schema": "cathedral_cybergym_report_v1", "platform": "cybergym"}
VOICE_LANE = {"schema": "cathedral_voice_report_v1", "platform": "voice"}

COMPUTE_ALLOCATION = 10**11


def _economics_keys() -> tuple[dict[str, Any], dict[str, bytes]]:
    private: dict[str, Any] = {}
    registry: dict[str, bytes] = {}
    for index, key_id in enumerate(("economics-a", "economics-b", "economics-c")):
        key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([index + 1]) * 32)
        private[key_id] = key
        registry[key_id] = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    return private, registry


def funded_compute_bundle() -> tuple[PolicyBundle, dict[str, bytes]]:
    """Genesis bundle with Compute at 10^11 and the rest burned."""
    private, registry = _economics_keys()
    document = {
        "schema": POLICY_BUNDLE_SCHEMA,
        "economics": {
            "schema": ECONOMICS_SET_SCHEMA,
            "version": 1,
            "previous_digest": GENESIS_PREVIOUS_DIGEST,
            "netuid": NETUID,
            "burn": {"amount": H - COMPUTE_ALLOCATION, "burn_hotkey": BURN_HOTKEY},
            "allocations": [
                {
                    "lane_contract_id": dict(COMPUTE_LANE),
                    "amount": COMPUTE_ALLOCATION,
                    "enabled": True,
                },
                {
                    "lane_contract_id": dict(CYBERGYM_LANE),
                    "amount": 0,
                    "enabled": True,
                },
                {
                    "lane_contract_id": dict(VOICE_LANE),
                    "amount": 0,
                    "enabled": True,
                },
            ],
            "explicit_burn_only": False,
        },
        "measurement_registry": {},
        "receipt_key_registry": {},
        "signatures": [],
    }
    payload = signing_payload(document)
    document["signatures"] = [
        {"key_id": key_id, "sig": private[key_id].sign(payload).hex()}
        for key_id in ("economics-a", "economics-b")
    ]
    return parse_policy_bundle(document), registry


def commitment_for(bundle: PolicyBundle, epoch: int) -> bytes:
    return encode_commitment(bundle.economics.netuid, epoch, bundle.digest())
