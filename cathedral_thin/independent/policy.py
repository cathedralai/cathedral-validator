"""PolicyBundle: one signed document, one on-chain digest.

The whole economics of an epoch is one atomic document. There is no per-lane
file that can be swapped independently, and there is no separately fetched
"current burn" that can disagree with the allocation table: the burn amount and
every lane allocation are integers out of ``H`` inside a single object, signed
2-of-3, and committed on chain as one 50-byte digest at a frozen anchor.

That shape is what makes last-good safe. A cached bundle may only be reused
while the anchor's commitment still names its digest, so a stale bundle cannot
outrun the chain, and a cold start accepts only the committed document rather
than the oldest thing an HTTPS mirror still serves.

The signature covers the bundle WITHOUT its ``signatures`` key, so the
measurement registry and the receipt-key registry are inside the same signed
digest as the amounts. Signing the economics alone would let a registry be
substituted under a valid signature.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from .canonical import (
    canonical_bytes,
    exact_keys,
    parse_strict_json,
    strict_bool,
    strict_int,
    strict_object,
    strict_str,
)
from .constants import (
    BURN_HOTKEY,
    COMMITMENT_LENGTH,
    COMMITMENT_MAGIC,
    ECONOMICS_SET_SCHEMA,
    GENESIS_PREVIOUS_DIGEST,
    GENESIS_VERSION,
    H,
    MAX_POLICY_BUNDLE_BYTES,
    MAX_POLICY_SIGNATURES,
    NETUID,
    POLICY_BUNDLE_SCHEMA,
    POLICY_KEY_IDS,
    POLICY_SIGNATURE_THRESHOLD,
)
from .errors import CommitmentError, PolicyBundleError, PolicyLineageError

_BUNDLE_KEYS = frozenset(
    {
        "schema",
        "economics",
        "measurement_registry",
        "receipt_key_registry",
        "signatures",
    }
)
_ECONOMICS_KEYS = frozenset(
    {
        "schema",
        "version",
        "previous_digest",
        "netuid",
        "burn",
        "allocations",
        "explicit_burn_only",
    }
)
_BURN_KEYS = frozenset({"amount", "burn_hotkey"})
_ALLOCATION_KEYS = frozenset({"lane_contract_id", "amount", "enabled"})
_LANE_CONTRACT_KEYS = frozenset({"schema", "platform"})
_SIGNATURE_KEYS = frozenset({"key_id", "sig"})

# One document cannot fund more rows than the chain can carry destinations for,
# and a legal allocation table is far smaller than this.
MAX_ALLOCATIONS = 64

_HEX_DIGEST_LENGTH = 64
_SIGNATURE_HEX_LENGTH = 128


@dataclass(frozen=True)
class LaneContractId:
    """The composer's name for a lane. An adapter never names its own lane."""

    schema: str
    platform: str

    def as_dict(self) -> dict[str, str]:
        return {"schema": self.schema, "platform": self.platform}

    def __str__(self) -> str:
        return f"{self.schema}/{self.platform}"


@dataclass(frozen=True)
class Allocation:
    lane_contract_id: LaneContractId
    amount: int
    enabled: bool

    @property
    def funded(self) -> bool:
        """A row that would move mass: enabled and carrying a positive amount."""
        return self.enabled and self.amount > 0


@dataclass(frozen=True)
class BurnTarget:
    amount: int
    burn_hotkey: str


@dataclass(frozen=True)
class EconomicsSet:
    version: int
    previous_digest: str
    netuid: int
    burn: BurnTarget
    allocations: tuple[Allocation, ...]
    explicit_burn_only: bool

    @property
    def burn_only(self) -> bool:
        return self.burn.amount == H


@dataclass(frozen=True)
class PolicySignature:
    key_id: str
    sig: bytes


@dataclass(frozen=True)
class PolicyBundle:
    """A parsed, structurally valid bundle plus the exact document it came from.

    ``document`` is retained because the digest is over the document's canonical
    bytes, not over this dataclass. Re-serialising a dataclass is how a parser
    and a verifier drift apart.
    """

    economics: EconomicsSet
    measurement_registry: Mapping[str, Any]
    receipt_key_registry: Mapping[str, Any]
    signatures: tuple[PolicySignature, ...]
    document: Mapping[str, Any]

    def signing_payload(self) -> bytes:
        return signing_payload(self.document)

    def digest(self) -> bytes:
        return bundle_digest(self.document)


def _parse_lane_contract_id(raw: Any) -> LaneContractId:
    document = strict_object(raw, "lane_contract_id")
    exact_keys(document, _LANE_CONTRACT_KEYS, "lane_contract_id")
    return LaneContractId(
        schema=strict_str(document["schema"], "lane_contract_id.schema"),
        platform=strict_str(document["platform"], "lane_contract_id.platform"),
    )


def _parse_allocation(raw: Any, index: int) -> Allocation:
    document = strict_object(raw, f"allocations[{index}]")
    exact_keys(document, _ALLOCATION_KEYS, f"allocations[{index}]")
    return Allocation(
        lane_contract_id=_parse_lane_contract_id(document["lane_contract_id"]),
        amount=strict_int(
            document["amount"], f"allocations[{index}].amount", low=0, high=H
        ),
        enabled=strict_bool(document["enabled"], f"allocations[{index}].enabled"),
    )


def _parse_burn(raw: Any) -> BurnTarget:
    document = strict_object(raw, "burn")
    exact_keys(document, _BURN_KEYS, "burn")
    burn_hotkey = strict_str(document["burn_hotkey"], "burn.burn_hotkey")
    if burn_hotkey != BURN_HOTKEY:
        # The pin is the point. A document naming any other destination is not
        # this subnet's economics, whoever signed it.
        raise PolicyBundleError("burn.burn_hotkey is not the pinned burn hotkey")
    return BurnTarget(
        amount=strict_int(document["amount"], "burn.amount", low=0, high=H),
        burn_hotkey=burn_hotkey,
    )


def parse_economics_set(raw: Any) -> EconomicsSet:
    """Parse and validate one ``cathedral_economics_set_v1`` object."""
    document = strict_object(raw, "economics")
    exact_keys(document, _ECONOMICS_KEYS, "economics")
    if document["schema"] != ECONOMICS_SET_SCHEMA:
        raise PolicyBundleError(f"economics.schema must be {ECONOMICS_SET_SCHEMA!r}")
    version = strict_int(
        document["version"], "economics.version", low=1, high=2**63 - 1
    )
    previous_digest = strict_str(
        document["previous_digest"], "economics.previous_digest", max_length=64
    )
    if len(previous_digest) != _HEX_DIGEST_LENGTH or any(
        character not in "0123456789abcdef" for character in previous_digest
    ):
        raise PolicyBundleError(
            "economics.previous_digest must be 64 lowercase hex characters"
        )
    if version == GENESIS_VERSION and previous_digest != GENESIS_PREVIOUS_DIGEST:
        raise PolicyLineageError(
            "economics.version 1 must carry the genesis previous_digest"
        )
    netuid = strict_int(document["netuid"], "economics.netuid", low=0, high=65535)
    if netuid != NETUID:
        raise PolicyBundleError(f"economics.netuid must be {NETUID}, got {netuid}")
    burn = _parse_burn(document["burn"])
    raw_allocations = document["allocations"]
    if not isinstance(raw_allocations, list):
        raise PolicyBundleError("economics.allocations must be a JSON array")
    if len(raw_allocations) > MAX_ALLOCATIONS:
        raise PolicyBundleError(
            f"economics.allocations has {len(raw_allocations)} rows, "
            f"over the {MAX_ALLOCATIONS} row bound"
        )
    allocations = tuple(
        _parse_allocation(row, index) for index, row in enumerate(raw_allocations)
    )
    seen: set[tuple[str, str]] = set()
    for allocation in allocations:
        key = (allocation.lane_contract_id.schema, allocation.lane_contract_id.platform)
        if key in seen:
            raise PolicyBundleError(
                f"economics.allocations names {allocation.lane_contract_id} twice"
            )
        seen.add(key)
    explicit_burn_only = strict_bool(
        document["explicit_burn_only"], "economics.explicit_burn_only"
    )

    # Disabled rows do NOT fold into burn automatically. The signer re-sums the
    # document; a validator that silently redirected a disabled row's mass would
    # be paying from numbers nobody signed.
    enabled_total = sum(row.amount for row in allocations if row.enabled)
    total = enabled_total + burn.amount
    if total != H:
        raise PolicyBundleError(
            f"enabled allocations plus burn sum to {total}, not H={H}"
        )
    if burn.amount <= 0:
        raise PolicyBundleError("burn.amount must be positive in a legal set")
    if burn.amount == H and not explicit_burn_only:
        raise PolicyBundleError("burn.amount == H requires explicit_burn_only = true")
    if burn.amount != H and explicit_burn_only:
        raise PolicyBundleError("explicit_burn_only is set but burn.amount is not H")
    return EconomicsSet(
        version=version,
        previous_digest=previous_digest,
        netuid=netuid,
        burn=burn,
        allocations=allocations,
        explicit_burn_only=explicit_burn_only,
    )


def _parse_signature(raw: Any, index: int) -> PolicySignature:
    document = strict_object(raw, f"signatures[{index}]")
    exact_keys(document, _SIGNATURE_KEYS, f"signatures[{index}]")
    key_id = strict_str(document["key_id"], f"signatures[{index}].key_id")
    sig_hex = strict_str(document["sig"], f"signatures[{index}].sig", max_length=128)
    if len(sig_hex) != _SIGNATURE_HEX_LENGTH:
        raise PolicyBundleError(
            f"signatures[{index}].sig must be {_SIGNATURE_HEX_LENGTH} hex characters"
        )
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError as exc:
        raise PolicyBundleError(f"signatures[{index}].sig is not hex") from exc
    return PolicySignature(key_id=key_id, sig=sig)


def parse_policy_bundle(raw: Any) -> PolicyBundle:
    """Parse and validate one ``cathedral_policy_bundle_v1`` object."""
    document = strict_object(raw, "policy bundle")
    exact_keys(document, _BUNDLE_KEYS, "policy bundle")
    if document["schema"] != POLICY_BUNDLE_SCHEMA:
        raise PolicyBundleError(f"schema must be {POLICY_BUNDLE_SCHEMA!r}")
    economics = parse_economics_set(document["economics"])
    measurement_registry = strict_object(
        document["measurement_registry"], "measurement_registry"
    )
    receipt_key_registry = strict_object(
        document["receipt_key_registry"], "receipt_key_registry"
    )
    raw_signatures = document["signatures"]
    if not isinstance(raw_signatures, list):
        raise PolicyBundleError("signatures must be a JSON array")
    if not raw_signatures:
        raise PolicyBundleError("signatures is empty")
    if len(raw_signatures) > MAX_POLICY_SIGNATURES:
        raise PolicyBundleError(
            f"signatures has {len(raw_signatures)} entries, "
            f"over the {MAX_POLICY_SIGNATURES} entry bound"
        )
    signatures = tuple(
        _parse_signature(row, index) for index, row in enumerate(raw_signatures)
    )
    # The canonical walk refuses floats anywhere in the document, including
    # inside either registry, before anything is hashed.
    canonical_bytes(_without_signatures(document))
    return PolicyBundle(
        economics=economics,
        measurement_registry=MappingProxyType(dict(measurement_registry)),
        receipt_key_registry=MappingProxyType(dict(receipt_key_registry)),
        signatures=signatures,
        document=MappingProxyType(dict(document)),
    )


def _without_signatures(document: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "signatures"}


def signing_payload(document: Mapping[str, Any]) -> bytes:
    """The exact bytes the 2-of-3 signs: the bundle without ``signatures``."""
    return canonical_bytes(_without_signatures(document))


def bundle_digest(document: Mapping[str, Any]) -> bytes:
    """sha256 over the canonical bundle without ``signatures``."""
    return hashlib.sha256(signing_payload(document)).digest()


def verify_signatures(
    bundle: PolicyBundle, key_registry: Mapping[str, bytes]
) -> frozenset[str]:
    """Return the distinct pinned key ids that signed, or raise.

    A key id outside the pin set does not count, and a duplicate key id does not
    count twice. An invalid signature from a pinned key halts outright rather
    than being skipped: a document carrying a bad signature from a real signer
    is evidence of tampering, not of a merely under-signed document.
    """
    payload = bundle.signing_payload()
    verified: set[str] = set()
    for index, signature in enumerate(bundle.signatures):
        if signature.key_id not in POLICY_KEY_IDS:
            continue
        public_bytes = key_registry.get(signature.key_id)
        if public_bytes is None:
            continue
        if not _ed25519_verify(public_bytes, signature.sig, payload, index):
            raise PolicyBundleError(
                f"signatures[{index}] from {signature.key_id} does not verify"
            )
        verified.add(signature.key_id)
    if len(verified) < POLICY_SIGNATURE_THRESHOLD:
        raise PolicyBundleError(
            f"policy bundle has {len(verified)} distinct pinned signatures, "
            f"needs {POLICY_SIGNATURE_THRESHOLD}"
        )
    return frozenset(verified)


def _ed25519_verify(
    public_bytes: bytes, signature: bytes, payload: bytes, index: int
) -> bool:
    if not isinstance(public_bytes, (bytes, bytearray)) or len(public_bytes) != 32:
        raise PolicyBundleError(
            f"signatures[{index}] names a key id whose pinned public key is not "
            "32 raw ed25519 bytes"
        )
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(bytes(public_bytes))
    except ValueError as exc:
        raise PolicyBundleError(
            f"signatures[{index}] names an unusable pinned public key"
        ) from exc
    try:
        key.verify(signature, payload)
    except InvalidSignature:
        return False
    return True


def load_policy_bundle(
    raw: bytes, key_registry: Mapping[str, bytes]
) -> tuple[PolicyBundle, frozenset[str]]:
    """Parse bytes and verify 2-of-3 in one fail-closed step."""
    document = parse_strict_json(raw, max_bytes=MAX_POLICY_BUNDLE_BYTES)
    bundle = parse_policy_bundle(document)
    return bundle, verify_signatures(bundle, key_registry)


def encode_commitment(netuid: int, epoch: int, digest: bytes) -> bytes:
    """The 50-byte on-chain commitment for one bundle at one epoch.

    ``CATHPOL1 || netuid_u16be || epoch_u64be || sha256`` -- one digest, not
    three. Three digests overflow a 128-character commitment field once the SDK
    hex-encodes them, which is a size failure discovered on chain rather than
    here.
    """
    if isinstance(netuid, bool) or not isinstance(netuid, int):
        raise CommitmentError("netuid must be an integer")
    if isinstance(epoch, bool) or not isinstance(epoch, int):
        raise CommitmentError("epoch must be an integer")
    if not (0 <= netuid <= 0xFFFF):
        raise CommitmentError(f"netuid {netuid} does not fit in u16")
    if not (0 <= epoch <= 0xFFFFFFFFFFFFFFFF):
        raise CommitmentError(f"epoch {epoch} does not fit in u64")
    if not isinstance(digest, (bytes, bytearray)) or len(digest) != 32:
        raise CommitmentError("bundle digest must be 32 bytes")
    raw = (
        COMMITMENT_MAGIC
        + netuid.to_bytes(2, "big")
        + epoch.to_bytes(8, "big")
        + bytes(digest)
    )
    if len(raw) != COMMITMENT_LENGTH:
        raise CommitmentError(
            f"commitment is {len(raw)} bytes, expected {COMMITMENT_LENGTH}"
        )
    return raw


def decode_commitment(raw: bytes) -> tuple[int, int, bytes]:
    """Return ``(netuid, epoch, digest)`` from a 50-byte commitment."""
    if not isinstance(raw, (bytes, bytearray)):
        raise CommitmentError("commitment must be bytes")
    raw = bytes(raw)
    if len(raw) != COMMITMENT_LENGTH:
        raise CommitmentError(
            f"commitment is {len(raw)} bytes, expected {COMMITMENT_LENGTH}"
        )
    if not raw.startswith(COMMITMENT_MAGIC):
        raise CommitmentError("commitment does not carry the policy magic")
    netuid = int.from_bytes(raw[8:10], "big")
    epoch = int.from_bytes(raw[10:18], "big")
    return netuid, epoch, raw[18:]


def commitment_matches(
    raw: bytes, *, netuid: int, epoch: int, document: Mapping[str, Any]
) -> bool:
    """Whether an anchor commitment names exactly this document at this epoch."""
    observed_netuid, observed_epoch, digest = decode_commitment(raw)
    return (
        observed_netuid == netuid
        and observed_epoch == epoch
        and digest == bundle_digest(document)
    )


def require_commitment(
    raw: bytes, *, netuid: int, epoch: int, document: Mapping[str, Any]
) -> bytes:
    """Return the digest the anchor commits to, or halt.

    A mismatch is never downgraded to last-good: the cached document would be
    exactly the thing the chain says is no longer current.
    """
    observed_netuid, observed_epoch, digest = decode_commitment(raw)
    if observed_netuid != netuid:
        raise CommitmentError(
            f"commitment names netuid {observed_netuid}, composing for {netuid}"
        )
    if observed_epoch != epoch:
        raise CommitmentError(
            f"commitment names epoch {observed_epoch}, composing epoch {epoch}"
        )
    expected = bundle_digest(document)
    if digest != expected:
        raise CommitmentError(
            "commitment digest does not match the fetched policy bundle"
        )
    return digest


def genesis_lineage_fields() -> dict[str, Any]:
    """The two lineage fields a genesis EconomicsSet must carry."""
    return {
        "version": GENESIS_VERSION,
        "previous_digest": GENESIS_PREVIOUS_DIGEST,
    }


def successor_lineage_fields(previous: Mapping[str, Any]) -> dict[str, Any]:
    """The lineage fields for the bundle that follows ``previous``."""
    economics = strict_object(
        strict_object(previous, "policy bundle")["economics"], "economics"
    )
    version = strict_int(
        economics["version"], "economics.version", low=1, high=2**63 - 2
    )
    return {
        "version": version + 1,
        "previous_digest": bundle_digest(previous).hex(),
    }


def is_genesis(economics: EconomicsSet) -> bool:
    return (
        economics.version == GENESIS_VERSION
        and economics.previous_digest == GENESIS_PREVIOUS_DIGEST
    )


def require_lineage(
    bundle: PolicyBundle, last_good: PolicyBundle | None = None
) -> None:
    """Refuse a bundle that cannot follow genesis or ``last_good``.

    Version 1 must name the empty digest. A different successor must increment
    the previously accepted version by one and name that bundle's digest. The
    same digest as ``last_good`` is reuse of the current document, not a
    successor: a cached v2 may be composed again while the anchor still names
    it, but a v2 without any previously accepted bundle is a fork.
    """
    economics = bundle.economics
    if last_good is None:
        if not is_genesis(economics):
            raise PolicyLineageError(
                "economics is not genesis, and no previously accepted bundle "
                "was supplied"
            )
        return
    if last_good.digest() == bundle.digest():
        return
    expected_version = last_good.economics.version + 1
    expected_digest = last_good.digest().hex()
    if economics.version != expected_version:
        raise PolicyLineageError(
            f"economics.version {economics.version} does not follow last-good "
            f"version {last_good.economics.version}"
        )
    if economics.previous_digest != expected_digest:
        raise PolicyLineageError(
            "economics.previous_digest does not name the previously accepted bundle"
        )


def funded_lanes(economics: EconomicsSet) -> tuple[Allocation, ...]:
    return tuple(row for row in economics.allocations if row.funded)


def lane_contract_ids(economics: EconomicsSet) -> Sequence[LaneContractId]:
    return tuple(row.lane_contract_id for row in economics.allocations)


__all__ = [
    "MAX_ALLOCATIONS",
    "Allocation",
    "BurnTarget",
    "EconomicsSet",
    "LaneContractId",
    "PolicyBundle",
    "PolicySignature",
    "bundle_digest",
    "commitment_matches",
    "decode_commitment",
    "encode_commitment",
    "funded_lanes",
    "genesis_lineage_fields",
    "is_genesis",
    "lane_contract_ids",
    "load_policy_bundle",
    "parse_economics_set",
    "parse_policy_bundle",
    "require_commitment",
    "require_lineage",
    "signing_payload",
    "successor_lineage_fields",
    "verify_signatures",
]
