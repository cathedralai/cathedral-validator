"""Shared builders for the `independent_v1` composer tests.

Deliberately dependency-light: `cryptography` is a runtime dependency of this
package, so these fixtures never reach for an optional extra. The independent
path must be testable in an environment where nothing optional is installed --
that is the whole point of it reimplementing canonical bytes locally.

The ss58 strings below are the well-known Substrate development addresses. They
are used only as opaque, ordered identifiers: nothing here signs with them.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from cathedral_thin.independent import canonical_bytes
from cathedral_thin.independent.constants import (
    BURN_HOTKEY,
    ECONOMICS_SET_SCHEMA,
    GENESIS_PREVIOUS_DIGEST,
    H,
    NETUID,
    POLICY_BUNDLE_SCHEMA,
)
from cathedral_thin.independent.inclusion import MetagraphView
from cathedral_thin.independent.policy import (
    PolicyBundle,
    encode_commitment,
    parse_policy_bundle,
    signing_payload,
)

# Ordered by ss58 ascending: DAVE < BOB < CHARLIE < ALICE. The Hamilton
# remainder tie-break depends on that order, so the tests name it explicitly.
DAVE = "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy"
BOB = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
CHARLIE = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y"
ALICE = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"

BURN_UID = 136
EPOCH_OPEN = 6_120_000
ANCHOR_HASH = "0x" + "ab" * 32

COMPUTE_LANE = {"schema": "cathedral_compute_receipt_v1", "platform": "intel_tdx_cpu"}
CYBERGYM_LANE = {"schema": "cathedral_cybergym_report_v1", "platform": "cybergym"}
VOICE_LANE = {"schema": "cathedral_voice_report_v1", "platform": "voice"}


def lane_row(lane: Mapping[str, str], amount: int, *, enabled: bool = True) -> dict:
    return {
        "lane_contract_id": dict(lane),
        "amount": amount,
        "enabled": enabled,
    }


def economics_document(
    *,
    burn_amount: int = H,
    allocations: Sequence[Mapping[str, Any]] | None = None,
    explicit_burn_only: bool | None = None,
    version: int = 1,
    previous_digest: str = GENESIS_PREVIOUS_DIGEST,
    netuid: int = NETUID,
) -> dict[str, Any]:
    """A `cathedral_economics_set_v1` object. Genesis defaults to burn-only."""
    if allocations is None:
        allocations = [
            lane_row(COMPUTE_LANE, 0),
            lane_row(CYBERGYM_LANE, 0),
            lane_row(VOICE_LANE, 0),
        ]
    if explicit_burn_only is None:
        explicit_burn_only = burn_amount == H
    return {
        "schema": ECONOMICS_SET_SCHEMA,
        "version": version,
        "previous_digest": previous_digest,
        "netuid": netuid,
        "burn": {"amount": burn_amount, "burn_hotkey": BURN_HOTKEY},
        "allocations": [dict(row) for row in allocations],
        "explicit_burn_only": explicit_burn_only,
    }


def bundle_document(
    *,
    economics: Mapping[str, Any] | None = None,
    measurement_registry: Mapping[str, Any] | None = None,
    receipt_key_registry: Mapping[str, Any] | None = None,
    signatures: Sequence[Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    """A `cathedral_policy_bundle_v1` object, unsigned unless told otherwise."""
    return {
        "schema": POLICY_BUNDLE_SCHEMA,
        "economics": dict(economics if economics is not None else economics_document()),
        "measurement_registry": dict(
            measurement_registry if measurement_registry is not None else {}
        ),
        "receipt_key_registry": dict(
            receipt_key_registry if receipt_key_registry is not None else {}
        ),
        "signatures": [dict(row) for row in (signatures or [])],
    }


def economics_keys() -> tuple[dict[str, Any], dict[str, bytes]]:
    """Three deterministic Ed25519 signers plus the pinned public-key registry."""
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


def sign_document(
    document: Mapping[str, Any],
    private: Mapping[str, Any],
    key_ids: Iterable[str],
) -> dict[str, Any]:
    """Return ``document`` with ``signatures`` over its canonical bytes."""
    payload = signing_payload(document)
    signed = dict(document)
    signed["signatures"] = [
        {"key_id": key_id, "sig": private[key_id].sign(payload).hex()}
        for key_id in key_ids
    ]
    return signed


def signed_bundle_bytes(
    *,
    economics: Mapping[str, Any] | None = None,
    key_ids: Sequence[str] = ("economics-a", "economics-b"),
) -> tuple[bytes, dict[str, bytes]]:
    """Serialised signed bundle bytes plus the pinned key registry."""
    private, registry = economics_keys()
    document = sign_document(bundle_document(economics=economics), private, key_ids)
    return json.dumps(document).encode("utf-8"), registry


def signed_bundle(
    *,
    economics: Mapping[str, Any] | None = None,
    key_ids: Sequence[str] = ("economics-a", "economics-b"),
) -> tuple[PolicyBundle, dict[str, bytes]]:
    """A parsed signed bundle plus the pinned key registry."""
    private, registry = economics_keys()
    document = sign_document(bundle_document(economics=economics), private, key_ids)
    return parse_policy_bundle(document), registry


def commitment_for(bundle: PolicyBundle, *, epoch: int = EPOCH_OPEN) -> bytes:
    """The 50-byte commitment a mock anchor would carry for ``bundle``."""
    return encode_commitment(bundle.economics.netuid, epoch, bundle.digest())


def metagraph(**uids: str) -> MetagraphView:
    """A view from ``uid=<hotkey>`` keyword pairs, e.g. ``metagraph(**{"7": BOB})``."""
    return MetagraphView.from_uid_map(
        {int(uid): hotkey for uid, hotkey in uids.items()}
    )


def burn_only_view() -> MetagraphView:
    return MetagraphView.from_uid_map({BURN_UID: BURN_HOTKEY})


def canonical(document: Mapping[str, Any]) -> bytes:
    return canonical_bytes(document)
