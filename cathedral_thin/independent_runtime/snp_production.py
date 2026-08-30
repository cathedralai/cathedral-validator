"""Fail-closed AMD SEV-SNP verification for the direct SN39 validator.

This is deliberately a verifier boundary, not a second scoring mode.  A miner
either supplies one of the two admitted CPU evidence kinds and satisfies its
TEE's production policy, or it earns zero.  In particular, SNP is never sent
to QVL as a compatibility fallback.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cathedral_thin.independent.collect import CollectedEvidence
from cathedral_thin.independent.compute import QuoteVerdict
from .amd_snp_dev_preview import (
    AMD_GUEST_POLICY_SINGLE_SOCKET,
    AmdSnpDevPreviewError,
    load_compute_contract,
)

# The exact reviewed AMD production contract merged by cathedral-sandbox#189.
SANDBOX_CONTRACT_COMMIT = "8dde6eaca27116eed53386a1fa33ec70b74a01fb"
POLICY_SCHEMA = "cathedral_amd_sev_snp_policy_v1"
MAX_POLICY_BYTES = 128 * 1024
_MEASUREMENT = re.compile(r"[0-9a-f]{96}")
_TCB = re.compile(r"0x[0-9a-f]{16}")
_GENERATIONS = frozenset({"milan", "genoa", "turin"})
_HARDWARE_DOMAIN = b"cathedral.amd-sev-snp.hardware-v1\x00"
# AMD guest-policy bits.  Debug or migration-agent guests are not production
# confidential execution, even if their VCEK chain verifies.
AMD_GUEST_POLICY_DEBUG = 1 << 19
AMD_GUEST_POLICY_MIGRATION_AGENT = 1 << 18


class SnpProductionError(Exception):
    """A local production SNP policy or verifier boundary failed."""


@dataclass(frozen=True)
class SnpGenerationPolicy:
    allowed_measurements: frozenset[str]
    minimum_tcb: int


@dataclass(frozen=True)
class SnpPolicy:
    generations: Mapping[str, SnpGenerationPolicy]
    digest: str


@dataclass(frozen=True)
class SnpVerificationResult:
    verdict: QuoteVerdict
    machine_id: str | None
    verifier_digest: str
    policy_digest: str
    reason: str | None = None


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SnpProductionError("SNP policy repeats a JSON key")
        value[key] = item
    return value


def _safe_policy_bytes(path: Path) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise SnpProductionError("safe SNP policy loading is unavailable")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise SnpProductionError("SNP policy is not a readable regular file") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 1 <= before.st_size <= MAX_POLICY_BYTES
        ):
            raise SnpProductionError(
                "SNP policy must be root or operator owned and not group writable"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, MAX_POLICY_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_POLICY_BYTES:
                raise SnpProductionError("SNP policy exceeds its size bound")
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or len(raw) != before.st_size:
            raise SnpProductionError("SNP policy changed while it was read")
        return raw
    finally:
        os.close(fd)


def load_snp_policy(path: str | Path) -> SnpPolicy:
    """Load an immutable owner-controlled generation-specific SNP policy."""
    raw = _safe_policy_bytes(Path(path))
    try:
        document = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnpProductionError("SNP policy is not strict JSON") from exc
    if not isinstance(document, dict) or set(document) != {"schema", "generations"}:
        raise SnpProductionError(
            "SNP policy must contain exactly schema and generations"
        )
    if document["schema"] != POLICY_SCHEMA or not isinstance(
        document["generations"], dict
    ):
        raise SnpProductionError("SNP policy schema is unsupported")
    policies: dict[str, SnpGenerationPolicy] = {}
    for generation, value in document["generations"].items():
        if (
            generation not in _GENERATIONS
            or not isinstance(value, dict)
            or set(value) != {"allowed_measurements", "minimum_tcb"}
        ):
            raise SnpProductionError("SNP policy generation is malformed")
        measurements = value["allowed_measurements"]
        tcb = value["minimum_tcb"]
        if (
            not isinstance(measurements, list)
            or not measurements
            or measurements != sorted(measurements)
            or len(set(measurements)) != len(measurements)
            or any(
                not isinstance(item, str) or _MEASUREMENT.fullmatch(item) is None
                for item in measurements
            )
            or not isinstance(tcb, str)
            or _TCB.fullmatch(tcb) is None
        ):
            raise SnpProductionError("SNP policy measurements or TCB are malformed")
        minimum = int(tcb, 16)
        if minimum == 0:
            raise SnpProductionError("SNP policy minimum TCB must be nonzero")
        encoded_tcb = minimum.to_bytes(8, "little")
        reserved = range(2, 6) if generation in {"milan", "genoa"} else range(4, 7)
        if any(encoded_tcb[index] for index in reserved):
            raise SnpProductionError(
                "SNP policy TCB sets reserved bytes for its generation"
            )
        policies[generation] = SnpGenerationPolicy(frozenset(measurements), minimum)
    if not policies:
        raise SnpProductionError("SNP policy has no admitted processor generation")
    return SnpPolicy(
        generations=policies,
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def _verify_snpguest(path: Path, contract: Any) -> str:
    try:
        if not hasattr(os, "O_NOFOLLOW"):
            raise SnpProductionError("safe snpguest loading is unavailable")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except SnpProductionError:
        raise
    except OSError as exc:
        raise SnpProductionError("snpguest could not be read") from exc
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not metadata.st_mode & 0o111
            or not 1 <= metadata.st_size <= int(contract.MAX_SNPGUEST_BYTES)
        ):
            raise SnpProductionError("snpguest is not an immutable executable")
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(
                fd, min(1024 * 1024, int(contract.MAX_SNPGUEST_BYTES) + 1 - copied)
            )
            if not chunk:
                break
            copied += len(chunk)
            if copied > int(contract.MAX_SNPGUEST_BYTES):
                raise SnpProductionError("snpguest exceeds its size bound")
            digest.update(chunk)
        after = os.fstat(fd)
        if copied != metadata.st_size or (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise SnpProductionError("snpguest changed while it was read")
        visible = os.stat(path, follow_symlinks=False)
        if (visible.st_dev, visible.st_ino, visible.st_size, visible.st_mtime_ns) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        ):
            raise SnpProductionError("snpguest changed while it was read")
    except SnpProductionError:
        raise
    except OSError as exc:
        raise SnpProductionError("snpguest could not be read") from exc
    finally:
        os.close(fd)
    if digest.hexdigest() != contract.PINNED_SNPGUEST_SHA256:
        raise SnpProductionError("snpguest does not match the pinned SHA-256")
    return digest.hexdigest()


def _machine_id(generation: str, chip_id: bytes) -> str:
    if generation not in _GENERATIONS:
        raise SnpProductionError("verified SNP generation is unsupported")
    if len(chip_id) != 64:
        raise SnpProductionError("verified SNP CHIP_ID has the wrong length")
    return hashlib.sha256(
        _HARDWARE_DOMAIN + generation.encode("ascii") + b"\x00" + chip_id
    ).hexdigest()


def _tcb_meets_minimum(candidate: object, required: int, generation: str) -> bool:
    """Compare the processor-defined component SVNs, not the packed integer."""

    if (
        isinstance(candidate, bool)
        or not isinstance(candidate, int)
        or not 0 <= candidate < 1 << 64
        or not 0 <= required < 1 << 64
    ):
        return False
    candidate_bytes = candidate.to_bytes(8, "little")
    required_bytes = required.to_bytes(8, "little")
    component_indexes = (
        (0, 1, 6, 7) if generation in {"milan", "genoa"} else (0, 1, 2, 3, 7)
    )
    return all(
        candidate_bytes[index] >= required_bytes[index] for index in component_indexes
    )


class SnpProductionVerifier:
    """Pinned Compute contract plus policy for direct-validator SNP evidence."""

    def __init__(self, *, policy: SnpPolicy, snpguest_path: str | Path) -> None:
        try:
            contract = load_compute_contract()
        except AmdSnpDevPreviewError as exc:
            raise SnpProductionError(str(exc)) from exc
        if contract.commit != SANDBOX_CONTRACT_COMMIT:
            raise SnpProductionError(
                "installed Compute contract does not match the SNP production pin"
            )
        self._contract = contract
        self._policy = policy
        self._snpguest_path = str(Path(snpguest_path).absolute())
        self._snpguest_digest = _verify_snpguest(Path(self._snpguest_path), contract)
        self.digest = (
            "sha256:"
            + hashlib.sha256(
                (
                    "cathedral.snp-verifier-v1\x00"
                    + contract.commit
                    + "\x00"
                    + self._snpguest_digest
                ).encode("ascii")
            ).hexdigest()
        )

    @property
    def policy_digest(self) -> str:
        return self._policy.digest

    def verify(
        self, collected: CollectedEvidence, *, deadline_monotonic: float | None = None
    ) -> SnpVerificationResult:
        if not isinstance(collected, CollectedEvidence) or collected.kind != "sev_snp":
            return SnpVerificationResult(
                QuoteVerdict.FAIL,
                None,
                self.digest,
                self.policy_digest,
                "evidence_kind_not_sev_snp",
            )
        vendor_deadline: float | None = None
        if deadline_monotonic is not None:
            if (
                isinstance(deadline_monotonic, bool)
                or not isinstance(deadline_monotonic, (int, float))
                or not math.isfinite(float(deadline_monotonic))
            ):
                return SnpVerificationResult(
                    QuoteVerdict.INFRA,
                    None,
                    self.digest,
                    self.policy_digest,
                    "snp_verifier_deadline_invalid",
                )
            vendor_deadline = float(deadline_monotonic) - 1.0
            if vendor_deadline <= time.monotonic():
                return SnpVerificationResult(
                    QuoteVerdict.INFRA,
                    None,
                    self.digest,
                    self.policy_digest,
                    "snp_verifier_deadline_unavailable",
                )
        try:
            parsed = self._contract.parse_snp_report(collected.quote)
            generation = self._contract.snp_generation(parsed)
            policy = self._policy.generations.get(generation)
            if policy is None:
                return SnpVerificationResult(
                    QuoteVerdict.FAIL,
                    None,
                    self.digest,
                    self.policy_digest,
                    "snp_processor_generation_not_admitted",
                )
            guest_policy = getattr(parsed, "guest_policy", None)
            vmpl = getattr(parsed, "vmpl", None)
            if not isinstance(guest_policy, int) or vmpl != 0:
                return SnpVerificationResult(
                    QuoteVerdict.FAIL,
                    None,
                    self.digest,
                    self.policy_digest,
                    "snp_vmpl0_required",
                )
            if guest_policy & (
                AMD_GUEST_POLICY_DEBUG | AMD_GUEST_POLICY_MIGRATION_AGENT
            ):
                return SnpVerificationResult(
                    QuoteVerdict.FAIL,
                    None,
                    self.digest,
                    self.policy_digest,
                    "snp_debug_or_migration_guest_refused",
                )
            if not guest_policy & AMD_GUEST_POLICY_SINGLE_SOCKET:
                return SnpVerificationResult(
                    QuoteVerdict.FAIL,
                    None,
                    self.digest,
                    self.policy_digest,
                    "snp_single_socket_required",
                )
            evidence = self._contract.Evidence(
                kind=self._contract.EvidenceKind.SEV_SNP,
                quote=collected.quote,
                nonce=collected.nonce,
                miner_hotkey=collected.assigned_hotkey,
                cert_chain=list(collected.cert_chain),
                report_data_version=2,
                channel_binding=self._contract.ChannelBinding(
                    binding_type=self._contract.ChannelBindingType.TLS_SPKI_SHA256,
                    digest=collected.channel_binding.digest,
                ),
            )
            if (
                self._contract.evidence_report_data(evidence, collected.nonce)
                != collected.report_data
            ):
                return SnpVerificationResult(
                    QuoteVerdict.FAIL,
                    None,
                    self.digest,
                    self.policy_digest,
                    "snp_report_data_contract_mismatch",
                )
            verify_kwargs: dict[str, Any] = {
                "snpguest_path": self._snpguest_path,
                "raise_on_verifier_unavailable": True,
            }
            if vendor_deadline is not None:
                verify_kwargs["deadline_monotonic"] = vendor_deadline
            attested = self._contract.verify_snp(
                evidence,
                collected.nonce,
                self._contract.Policy(
                    allowed_measurements=policy.allowed_measurements,
                    min_tcb=policy.minimum_tcb,
                ),
                **verify_kwargs,
            )
            if (
                attested is None
                or attested.tier is not self._contract.Tier.CC_CPU_SNP
                or attested.chain_verified is not True
                or attested.verification_status != "VERIFIED"
                or getattr(parsed, "chip_id", None) != attested.chip_id
            ):
                return SnpVerificationResult(
                    QuoteVerdict.FAIL,
                    None,
                    self.digest,
                    self.policy_digest,
                    "snp_vendor_policy_verification_failed",
                )
            try:
                tcb = getattr(parsed, "tcb", None)
                if tcb is None or any(
                    not _tcb_meets_minimum(value, policy.minimum_tcb, generation)
                    for value in (
                        getattr(tcb, "current", None),
                        getattr(tcb, "reported", None),
                        getattr(tcb, "committed", None),
                        getattr(tcb, "launch", None),
                    )
                ):
                    return SnpVerificationResult(
                        QuoteVerdict.FAIL,
                        None,
                        self.digest,
                        self.policy_digest,
                        "snp_tcb_floor_not_met",
                    )
                machine_id = _machine_id(generation, bytes.fromhex(attested.chip_id))
            except (TypeError, ValueError, SnpProductionError):
                return SnpVerificationResult(
                    QuoteVerdict.FAIL,
                    None,
                    self.digest,
                    self.policy_digest,
                    "snp_identity_invalid",
                )
            return SnpVerificationResult(
                QuoteVerdict.PASS, machine_id, self.digest, self.policy_digest
            )
        except self._contract.SnpVerifierUnavailable:
            return SnpVerificationResult(
                QuoteVerdict.INFRA,
                None,
                self.digest,
                self.policy_digest,
                "snp_verifier_infrastructure_unavailable",
            )
        except Exception:
            # Everything inside this boundary is driven by miner-supplied
            # evidence. Only the explicit vendor-infrastructure exception
            # above is allowed to halt a round. A malformed report, an
            # unexpected parser exception, or any other evidence-triggered
            # verifier failure scores this machine zero instead of giving one
            # miner a validator-wide denial-of-service primitive.
            return SnpVerificationResult(
                QuoteVerdict.FAIL,
                None,
                self.digest,
                self.policy_digest,
                "snp_verification_failed",
            )


__all__ = [
    "POLICY_SCHEMA",
    "SANDBOX_CONTRACT_COMMIT",
    "SnpPolicy",
    "SnpProductionError",
    "SnpProductionVerifier",
    "SnpVerificationResult",
    "load_snp_policy",
]
