"""The Compute lane: named, QVL-gated, and payable only from pinned verified mass.

This module exists so the composer can NAME Compute and either pay it from
integer mass a caller already verified, or refuse it for a stated reason.
A dry-run mock verifier still cannot move SN39 mass: ``contributing`` is true
only when the QVL build digest is pinned AND the adapter was constructed with
non-empty ``verified_mass``. Collecting a quote and getting ``PASS`` from an
unpinned mock does not bind mass.

Broadcast stays blocked unless a caller supplies integer mass after collecting
from a listed machine, verifying its quote with a pinned QVL, and re-deriving
work units. The dedicated fleet preview now performs those checks without
chain authority. This adapter still performs none of the network operations.

Two rules are enforced at construction, not at use:

* **The quote verifier is mandatory.** There is no attestation-optional mode to
  fall out of, because an adapter built without a verifier does not exist: the
  constructor raises. That removes the code path that would otherwise reach a
  quote nobody checked.
* **Collateral comes from Intel's public PCS.** A verdict is only worth
  something to a third party if that party can refetch the same collateral and
  reach the same answer. Collateral served by whoever also operates the lane
  cannot distinguish an honest verdict from a convenient one.

``probe`` returns the bound verified mass when the adapter is contributing, and
nothing otherwise. A PASS verdict from ``verify_quote`` still does not bind
mass by itself: the live runner has to put integer units into
``verified_mass`` after a pinned QVL check.

The legacy singleton audit seed uses the quote-bound TLS key digest. It is a
channel identity, not a physical-machine identity. Multi-machine scoring uses
only a QVL-verified, quote-bound stable platform identifier, then globally
zeros every duplicate endpoint, TLS channel, or stable platform claimant.

Nothing here imports ``compose`` at runtime -- the dependency runs the other
way, because the composer imports this module to name the Compute block reason.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Mapping, Protocol, runtime_checkable

from .constants import (
    COMPUTE_FLEET_CAP,
    COMPUTE_LANE_PLATFORM,
    COMPUTE_LANE_SCHEMA,
    H,
    INTEL_PCS_HOSTS,
)
from .errors import (
    AdapterUnavailable,
    CollateralSourceError,
    ComputeEvidenceError,
    ConfigError,
    MachineIdentityConflict,
    PolicyFetchError,
)
from .fetch_policy import PolicyEndpoint, validate_policy_url
from .policy import LaneContractId

if TYPE_CHECKING:
    # Annotation-only. ``compose`` imports this module, so importing it back at
    # runtime would be a cycle; nothing here reads either object.
    from .compose import EpochAnchor
    from .inclusion import MetagraphView

COMPUTE_LANE = LaneContractId(
    schema=COMPUTE_LANE_SCHEMA,
    platform=COMPUTE_LANE_PLATFORM,
)

# The reason a funded Compute row is refused when the adapter cannot pay.
# Stated once, so the journal and the composer's status carry the same
# sentence a reviewer can check. A contributing adapter with a pinned QVL
# digest and non-empty verified mass does not use this sentence.
COMPUTE_BLOCK_REASON = (
    "Compute broadcast is deferred at allocation 0: the adapter is not "
    "contributing. No pinned-QVL, independently re-derived integer work mass "
    "was supplied. A PASS verdict or declared fleet size is not mass any miner "
    "earned. cathedralai/cathedral-validator#120 remains the governing direct-"
    "verification contract"
)

# TDX REPORT_DATA is 64 bytes. A binding checked against anything else is not
# the binding the quote carries.
REPORT_DATA_BYTES = 64
# A TDX quote with its certification data is a few KiB; this is a hard bound, so
# an oversized blob is refused rather than handed to a verifier.
MAX_QUOTE_BYTES = 65_536
# Raw Ed25519 is 32 bytes; a DER SPKI wrapping of it is longer but still small.
MIN_BOUND_KEY_BYTES = 32
MAX_BOUND_KEY_BYTES = 512

# Domain separation for the audit seed. The seed is derived from the anchor, the
# miner, and the machine and from nothing else: no process randomness and no
# per-validator namespace, so two independent validators auditing one machine in
# one epoch ask it the same question.
SEED_DOMAIN = b"cathedral-independent-sat-seed-v1"

_HEX = frozenset("0123456789abcdef")


class QuoteVerdict(enum.Enum):
    """What a quote verification attempt concluded.

    ``INFRA`` is deliberately not ``FAIL``: a collateral fetch that timed out or
    a verifier binary missing at runtime says nothing about the miner, so it
    blocks this validator rather than penalising the machine.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    INFRA = "INFRA"


@runtime_checkable
class QuoteVerifier(Protocol):
    """Verifies one TDX quote against collateral, and binds REPORT_DATA."""

    def verify(self, quote: bytes, *, expected_report_data: bytes) -> QuoteVerdict: ...


@dataclass(frozen=True)
class QuoteIdentityVerdict:
    """QVL verdict plus a vendor-verified stable TDX platform identity.

    TLS SPKI remains the channel identity.  It is not a hardware identity: one
    physical platform can generate several TLS keys.  Multi-machine scoring is
    enabled only when the QVL result independently verifies the package-stable
    PCK/PPID-derived identifier.
    """

    verdict: QuoteVerdict
    stable_platform_id: str | None
    platform_identity_verified: bool


@runtime_checkable
class QuoteIdentityVerifier(Protocol):
    def verify_with_identity(
        self,
        quote: bytes,
        *,
        expected_report_data: bytes,
        deadline_monotonic: float | None = None,
    ) -> QuoteIdentityVerdict: ...


def require_stable_platform_id(value: object) -> str:
    prefix = "tdx-platform-sha256:"
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or len(value) != len(prefix) + 64
        or any(character not in _HEX for character in value[len(prefix) :])
    ):
        raise ComputeEvidenceError(
            "stable platform identity must be tdx-platform-sha256 plus 64 lowercase hex"
        )
    return value


def machine_id_from_stable_platform_id(value: object) -> str:
    """Domain-preserving raw digest used by the profile-neutral aggregator.

    Hashing the validated tagged identity keeps the TDX PPID-derived digest
    separate from the production SNP verifier's generation-bound CHIP_ID
    domain, even if both preimages contain the same bytes.
    """

    stable = require_stable_platform_id(value)
    return hashlib.sha256(stable.encode("ascii")).hexdigest()


def require_compute_adapter(verifier: QuoteVerifier | None) -> QuoteVerifier:
    """Return the verifier a Compute adapter requires, or refuse to build one."""
    if verifier is None:
        raise AdapterUnavailable(
            "QVL is mandatory; cpu_quote_verifier=None is not a verifier"
        )
    if not isinstance(verifier, QuoteVerifier) or not callable(verifier.verify):
        raise AdapterUnavailable(
            "QVL is mandatory; the configured quote verifier has no verify()"
        )
    return verifier


def validate_collateral_url(url: str) -> PolicyEndpoint:
    """Return the validated Intel PCS collateral endpoint, or raise.

    The transport rules are the policy fetch's rules -- https, credential-free,
    no query or fragment -- and the host is then checked against the pin. A
    lane-operator-hosted mirror is refused here rather than being noticed later
    in a verdict nobody can reproduce.
    """
    try:
        endpoint = validate_policy_url(url)
    except PolicyFetchError as exc:
        raise CollateralSourceError(
            f"the DCAP collateral URL is not a hardened public HTTPS URL: {exc}"
        ) from exc
    if endpoint.host.lower() not in INTEL_PCS_HOSTS:
        raise CollateralSourceError(
            f"DCAP collateral must come from Intel PCS; {endpoint.host} is not "
            f"one of {sorted(INTEL_PCS_HOSTS)}"
        )
    if endpoint.port != 443:
        raise CollateralSourceError(
            f"DCAP collateral must be served on port 443, not {endpoint.port}"
        )
    return endpoint


def validate_qvl_digest(digest: str | None) -> str | None:
    """Return a validated QVL build digest pin, or ``None`` if it is unpinned.

    ``None`` is accepted because no open QVL build has been published to pin,
    and inventing a digest here would be a pin that proves nothing. It is not a
    default that quietly becomes acceptable: an unpinned adapter is one of the
    reasons Compute allocation is 0.
    """
    if digest is None:
        return None
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in _HEX for character in digest)
    ):
        raise ConfigError("qvl_digest must be 64 lowercase hex characters")
    return digest


def machine_id_from_key(key: bytes) -> str:
    """Legacy channel identity for one in-guest bound public key.

    ``sha256`` over the key bytes as the quote binds them (raw Ed25519 or its
    DER SPKI wrapping). This remains the deterministic SAT seed input for the
    legacy singleton path. A guest can rotate or generate more than one TLS
    key, so this digest does not identify a physical machine and must never be
    used for multi-machine deduplication or credit.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise ComputeEvidenceError("a bound public key must be raw bytes")
    key = bytes(key)
    if not (MIN_BOUND_KEY_BYTES <= len(key) <= MAX_BOUND_KEY_BYTES):
        raise ComputeEvidenceError(
            f"a bound public key of {len(key)} bytes is not in "
            f"[{MIN_BOUND_KEY_BYTES}, {MAX_BOUND_KEY_BYTES}]"
        )
    return hashlib.sha256(key).hexdigest()


def require_machine_id(machine_id: str, label: str = "machine_id") -> str:
    """Return ``machine_id`` if it is a sha256 digest in lowercase hex."""
    if (
        not isinstance(machine_id, str)
        or len(machine_id) != 64
        or any(character not in _HEX for character in machine_id)
    ):
        raise ComputeEvidenceError(f"{label} must be 64 lowercase hex characters")
    return machine_id


def require_miner_ss58(miner_ss58: str) -> str:
    """Return ``miner_ss58`` if it is usable as an opaque ASCII identifier."""
    if not isinstance(miner_ss58, str) or not miner_ss58 or not miner_ss58.isascii():
        raise ComputeEvidenceError("miner ss58 must be a non-empty ASCII string")
    return miner_ss58


def require_verified_mass(masses: Mapping[str, int] | None) -> dict[str, int]:
    """Return a copy of integer miner mass, or empty.

    Empty is the dry-run default. Non-empty values must be positive integers
    that sum to at most ``H``. Duplicate hotkeys are refused rather than
    silently merged.
    """
    if masses is None:
        return {}
    if not isinstance(masses, Mapping):
        raise ComputeEvidenceError(
            "verified mass must be a mapping of miner ss58 to integer units"
        )
    result: dict[str, int] = {}
    total = 0
    for ss58, mass in masses.items():
        key = require_miner_ss58(ss58)
        if key in result:
            raise ComputeEvidenceError(f"verified mass names {key} twice")
        if isinstance(mass, bool) or not isinstance(mass, int) or mass <= 0:
            raise ComputeEvidenceError(
                f"verified mass for {key} must be a positive integer"
            )
        if mass > H:
            raise ComputeEvidenceError(f"verified mass for {key} exceeds H={H}")
        total += mass
        if total > H:
            raise ComputeEvidenceError("verified mass sums above H")
        result[key] = mass
    return result


def assert_machine_identity(
    machine_id: str, miner_ss58: str, claimed: dict[str, str]
) -> None:
    """Record which miner owns a machine identity, refusing a second claimant.

    ``claimed`` is the caller's per-epoch conflict ledger and is mutated in
    place. The first row is retained only so a later duplicate identifies both
    claimants. A caller must zero both rather than choose a winner.
    """
    require_machine_id(machine_id)
    require_miner_ss58(miner_ss58)
    if not isinstance(claimed, dict):
        raise ComputeEvidenceError("the machine identity ledger must be a dict")
    owner = claimed.get(machine_id)
    if owner is None:
        claimed[machine_id] = miner_ss58
        return
    if owner != miner_ss58:
        raise MachineIdentityConflict(
            f"machine {machine_id} is claimed by {owner} and {miner_ss58}; "
            "both are NOT_PROVEN for this epoch"
        )


def fleet_over_cap(machine_count: int) -> bool:
    """Whether an advertised fleet is over the pinned per-miner cap.

    Over the cap that miner zeros for the epoch. The list is not truncated to
    the first ``COMPUTE_FLEET_CAP`` entries: a miner that could choose which of
    its machines a validator audits has a cheaper cheat than running them.
    """
    if (
        isinstance(machine_count, bool)
        or not isinstance(machine_count, int)
        or machine_count < 0
    ):
        raise ComputeEvidenceError(
            "an advertised machine count must be a non-negative integer"
        )
    return machine_count > COMPUTE_FLEET_CAP


def canonical_seed_material(
    *, anchor_hash: str, miner_ss58: str, machine_id: str
) -> bytes:
    """The domain-separated seed bytes a future audit instance would use.

    Deterministic in the anchor, the miner, and the machine. It dispatches
    nothing and generates nothing: no instance generator is pinned in this
    lineage, and Compute allocation is 0 either way. It lives here so the seed
    two validators derive is provably the same one when a generator is pinned.
    """
    if not isinstance(anchor_hash, str) or not anchor_hash.startswith("0x"):
        raise ComputeEvidenceError("anchor_hash must be a 0x-prefixed block hash")
    body = anchor_hash[2:]
    if len(body) != 64 or any(character not in _HEX for character in body):
        raise ComputeEvidenceError(
            "anchor_hash must be 0x plus 64 lowercase hex characters"
        )
    require_miner_ss58(miner_ss58)
    require_machine_id(machine_id)
    return hashlib.sha256(
        SEED_DOMAIN
        + bytes.fromhex(body)
        + miner_ss58.encode("ascii")
        + bytes.fromhex(machine_id)
    ).digest()


class ComputeAdapter:
    """A registered Compute adapter.

    Without a pinned QVL digest and bound ``verified_mass`` this adapter exists
    only so the composer can name why a funded Compute row is refused. Binding
    integer mass is how a live runner, after a pinned QVL check, makes the lane
    contributing. There is no flag that pays from a mock.
    """

    def __init__(
        self,
        verifier: QuoteVerifier | None,
        *,
        collateral_base_url: str,
        qvl_digest: str | None = None,
        verified_mass: Mapping[str, int] | None = None,
    ) -> None:
        self._verifier = require_compute_adapter(verifier)
        self.collateral_endpoint = validate_collateral_url(collateral_base_url)
        self.qvl_digest = validate_qvl_digest(qvl_digest)
        mass = require_verified_mass(verified_mass)
        if mass and self.qvl_digest is None:
            raise AdapterUnavailable(
                "verified Compute mass requires a pinned QVL digest; "
                "an unpinned dry-run verifier cannot move SN39 mass"
            )
        self._verified_mass = mass

    @property
    def qvl_unpinned(self) -> bool:
        """Whether the QVL build digest is still unpinned."""
        return self.qvl_digest is None

    @property
    def contributing(self) -> bool:
        """Whether this adapter can move SN39 mass.

        True only with a pinned QVL digest and non-empty verified integer mass.
        A PASS quote from an unpinned mock stays false.
        """
        return self.qvl_digest is not None and bool(self._verified_mass)

    @property
    def supports_stable_platform_identity(self) -> bool:
        """Whether the verifier exposes the required physical-identity API.

        This is a verifier capability check. It does not depend on any
        miner-supplied quote, so one malformed or incomplete quote cannot turn
        a per-machine exclusion into a batch-wide feature failure.
        """

        return callable(getattr(self._verifier, "verify_with_identity", None))

    def verify_quote(
        self, quote: bytes, *, expected_report_data: bytes
    ) -> QuoteVerdict:
        """Verify one quote through the injected verifier.

        Bounds and type-checks the evidence before the verifier sees it, and
        treats a verifier that answers something other than a verdict as an
        infrastructure failure. A broken verifier never means PASS.
        """
        if not isinstance(quote, (bytes, bytearray)) or not quote:
            raise ComputeEvidenceError("a TDX quote must be non-empty bytes")
        if len(quote) > MAX_QUOTE_BYTES:
            raise ComputeEvidenceError(
                f"a TDX quote of {len(quote)} bytes is over the "
                f"{MAX_QUOTE_BYTES} byte bound"
            )
        if (
            not isinstance(expected_report_data, (bytes, bytearray))
            or len(expected_report_data) != REPORT_DATA_BYTES
        ):
            raise ComputeEvidenceError(
                f"expected REPORT_DATA must be exactly {REPORT_DATA_BYTES} bytes"
            )
        verdict = self._verifier.verify(
            bytes(quote), expected_report_data=bytes(expected_report_data)
        )
        if not isinstance(verdict, QuoteVerdict):
            return QuoteVerdict.INFRA
        return verdict

    def verify_quote_with_identity(
        self,
        quote: bytes,
        *,
        expected_report_data: bytes,
        deadline_monotonic: float | None = None,
    ) -> QuoteIdentityVerdict:
        """Verify quote and require the verifier's stable-identity interface.

        This method is separate from ``verify_quote`` so the single-machine
        path retains its reviewed PASS/FAIL/INFRA behavior.  A verifier that
        exposes only a boolean PASS is insufficient for global hardware
        deduplication and therefore cannot enable multi-machine score.
        """

        self._validate_quote_inputs(quote, expected_report_data=expected_report_data)
        method = getattr(self._verifier, "verify_with_identity", None)
        if not callable(method):
            raise AdapterUnavailable(
                "multi-machine scoring requires QVL stable platform identity output"
            )
        kwargs: dict[str, object] = {
            "expected_report_data": bytes(expected_report_data)
        }
        if deadline_monotonic is not None:
            kwargs["deadline_monotonic"] = deadline_monotonic
        result = method(bytes(quote), **kwargs)
        if not isinstance(result, QuoteIdentityVerdict):
            return QuoteIdentityVerdict(QuoteVerdict.INFRA, None, False)
        if result.verdict is not QuoteVerdict.PASS:
            return QuoteIdentityVerdict(result.verdict, None, False)
        if not result.platform_identity_verified:
            return QuoteIdentityVerdict(QuoteVerdict.PASS, None, False)
        try:
            identity = require_stable_platform_id(result.stable_platform_id)
        except ComputeEvidenceError:
            return QuoteIdentityVerdict(QuoteVerdict.PASS, None, False)
        return QuoteIdentityVerdict(QuoteVerdict.PASS, identity, True)

    @staticmethod
    def _validate_quote_inputs(quote: bytes, *, expected_report_data: bytes) -> None:
        if not isinstance(quote, (bytes, bytearray)) or not quote:
            raise ComputeEvidenceError("a TDX quote must be non-empty bytes")
        if len(quote) > MAX_QUOTE_BYTES:
            raise ComputeEvidenceError(
                f"a TDX quote of {len(quote)} bytes is over the "
                f"{MAX_QUOTE_BYTES} byte bound"
            )
        if (
            not isinstance(expected_report_data, (bytes, bytearray))
            or len(expected_report_data) != REPORT_DATA_BYTES
        ):
            raise ComputeEvidenceError(
                f"expected REPORT_DATA must be exactly {REPORT_DATA_BYTES} bytes"
            )

    def probe(self, *, anchor: EpochAnchor, view: MetagraphView) -> Mapping[str, int]:
        """Return the miner mass this lane earned.

        Both arguments are accepted so this satisfies the composer's adapter
        protocol. They are unread here: UID resolution and leftover-to-burn
        happen in ``mass_map``, which already has the views. Returning bound
        mass is not dispatching work.
        """
        del anchor, view
        if not self.contributing:
            return {}
        return dict(self._verified_mass)


__all__ = [
    "COMPUTE_BLOCK_REASON",
    "COMPUTE_FLEET_CAP",
    "COMPUTE_LANE",
    "INTEL_PCS_HOSTS",
    "MAX_BOUND_KEY_BYTES",
    "MAX_QUOTE_BYTES",
    "MIN_BOUND_KEY_BYTES",
    "REPORT_DATA_BYTES",
    "SEED_DOMAIN",
    "ComputeAdapter",
    "QuoteIdentityVerdict",
    "QuoteIdentityVerifier",
    "QuoteVerdict",
    "QuoteVerifier",
    "assert_machine_identity",
    "canonical_seed_material",
    "fleet_over_cap",
    "machine_id_from_key",
    "machine_id_from_stable_platform_id",
    "require_compute_adapter",
    "require_machine_id",
    "require_miner_ss58",
    "require_stable_platform_id",
    "require_verified_mass",
    "validate_collateral_url",
    "validate_qvl_digest",
]
