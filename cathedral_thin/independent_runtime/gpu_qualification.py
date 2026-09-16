"""No-chain GPU admission, real work, deduplication and direct score planning.

This module has no wallet loader, extrinsic builder or submission operation.
The supplied signer signs only bounded validator HTTP access requests. The
prelaunch conversion below is deliberately not a live reward allocation.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
from typing import Any, Mapping, Sequence

from cathedral_thin.independent.canonical import canonical_bytes, parse_strict_json
from .axon import ServingAxon, finalized_head, scan_axons
from .direct_contract import zero_burn_vector
from .errors import IndependentLiveError
from .https import HttpsEvidenceTransport, axon_origin
from .validator_request import SignedValidatorTransport, fetch_worker_fleet, _require_hotkey

CONFIG_SCHEMA = "cathedral_gpu_prelaunch_v1"
DIRECTORY_SCHEMA = "cathedral.gpu.providers.v1"
PLAN_SCHEMA = "cathedral_gpu_direct_prelaunch_plan_v1"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_MINERS = 256
G4_WORKER_PROFILE_ID = "gcp-g4-rtx-pro-6000-sev-v1"
G4_BUNDLE_PROFILE_ID = "gcp-g4-rtx-pro-6000-8gpu-v1"
G4_BUNDLE_SIZE = 8
GPU_PATHS = frozenset({"/v1/gpu-capabilities", "/v1/gpu-evidence", "/v1/gpu-work"})


def _utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _read_json(path: str | Path) -> Any:
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_CONFIG_BYTES + 1)
    return parse_strict_json(data, max_bytes=MAX_CONFIG_BYTES)


def atomic_json(path: str | Path, document: object) -> None:
    """Publish a complete sanitized snapshot with one atomic replacement."""
    target = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".gpu-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(document) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@dataclass(frozen=True)
class GpuPrelaunchConfig:
    network: str
    netuid: int
    validator_hotkey: str
    units_per_device: int
    registry_path: str
    trusted_keys: Mapping[str, bytes]
    minimum_registry_release: int
    registry_state_path: str
    profile_ids: tuple[str, ...]

    @classmethod
    def load(cls, path: str | Path) -> "GpuPrelaunchConfig":
        data = _read_json(path)
        keys = {"schema", "enabled", "network", "netuid", "validator_hotkey",
                "units_per_device", "registry_path", "trusted_keys_hex",
                "minimum_registry_release", "registry_state_path", "profile_ids"}
        if not isinstance(data, dict) or set(data) != keys:
            raise IndependentLiveError("GPU prelaunch config has invalid schema")
        if data["schema"] != CONFIG_SCHEMA or data["enabled"] is not True:
            raise IndependentLiveError("GPU qualification is not explicitly enabled")
        if (data["network"] not in {"finney", "test"}
                or type(data["netuid"]) is not int or not 0 <= data["netuid"] <= 65535
                or type(data["units_per_device"]) is not int
                or not 1 <= data["units_per_device"] <= 65535
                or type(data["minimum_registry_release"]) is not int
                or data["minimum_registry_release"] < 1):
            raise IndependentLiveError("GPU prelaunch scoring or chain context is invalid")
        _require_hotkey(data["validator_hotkey"], "validator hotkey")
        for key in ("registry_path", "registry_state_path"):
            if not isinstance(data[key], str) or not Path(data[key]).is_absolute():
                raise IndependentLiveError("GPU registry paths must be absolute")
        ids = data["profile_ids"]
        if (not isinstance(ids, list) or not ids or len(ids) > 32
                or any(not isinstance(v, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", v) is None for v in ids)
                or len(set(ids)) != len(ids)):
            raise IndependentLiveError("GPU profile IDs must be a nonempty unique list")
        raw_keys = data["trusted_keys_hex"]
        if not isinstance(raw_keys, dict) or not raw_keys or len(raw_keys) > 32:
            raise IndependentLiveError("GPU registry trust roots are missing")
        try:
            trusted = {key: bytes.fromhex(value) for key, value in raw_keys.items()}
        except (ValueError, TypeError):
            raise IndependentLiveError("GPU registry trust roots are invalid") from None
        if any(not isinstance(k, str) or not k or len(v) != 32 for k, v in trusted.items()):
            raise IndependentLiveError("GPU registry trust roots are invalid")
        return cls(data["network"], data["netuid"], data["validator_hotkey"],
                   data["units_per_device"], data["registry_path"], trusted,
                   data["minimum_registry_release"], data["registry_state_path"], tuple(ids))


class GpuEndpointUnavailable(IndependentLiveError):
    def __init__(self, status):
        super().__init__("GPU worker request refused")
        self.status = status


class ProductionGpuVerifier:
    """Signed registry plus actual production TDX and GPU verification backends."""
    def __init__(self, config: GpuPrelaunchConfig):
        from cathedral.gpu import gpu_profile_from_registry, gpu_verifier_from_env
        from cathedral.policy_registry import PolicyRegistryState, verify_registry
        from cathedral.verify import preflight_tdx_verifier
        raw = Path(config.registry_path).read_bytes()
        if len(raw) > MAX_CONFIG_BYTES:
            raise IndependentLiveError("GPU registry exceeds bound")
        snapshot = verify_registry(raw, config.trusted_keys)
        state = PolicyRegistryState(config.registry_state_path, production_mode=True,
                                    minimum_release=config.minimum_registry_release)
        state.accept(snapshot)
        self.cpu_policy = snapshot.to_policy()
        self.profiles = {name: gpu_profile_from_registry(snapshot, name)
                         for name in config.profile_ids}
        self.verifier = gpu_verifier_from_env(production_mode=True)
        preflight_tdx_verifier(self.cpu_policy)
        for profile in self.profiles.values():
            if not profile.production_ready_for(self.cpu_policy):
                raise IndependentLiveError("GPU profile is not production verifiable")
            self.verifier.preflight(profile)
        self.registry_digest = snapshot.digest

    def verify(self, components, nonce, hotkey, binding, profile_id):
        from cathedral.common import ChannelBinding, ChannelBindingType, EvidenceKind
        from cathedral.gpu import verify_composite_gpu, gpu_identity_policy_digest
        from cathedral.gpu_work import parse_composite
        if not isinstance(components, list) or len(components) != 2:
            raise IndependentLiveError("GPU composite requires exactly two components")
        expected_binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, binding)
        evidence = parse_composite(components, nonce, hotkey, expected_binding)
        by_kind = {item.kind: item for item in evidence}
        if set(by_kind) != {EvidenceKind.TDX, EvidenceKind.GPU_CC}:
            raise IndependentLiveError("GPU composite must contain TDX and GPU evidence")
        result = verify_composite_gpu(by_kind[EvidenceKind.TDX], by_kind[EvidenceKind.GPU_CC],
                                      nonce, self.cpu_policy, self.profiles[profile_id], self.verifier)
        identities = tuple(sorted(gpu_identity_policy_digest(v)
                                  for v in result.gpu_component.identity_set))
        return {"device_identity_digests": identities,
                "machine_id": result.attested.chip_id,
                "component_digest": result.gpu_component.digest}


@dataclass(frozen=True)
class GpuRound:
    rows: tuple[dict[str, Any], ...]
    observed_at: str
    registry_digest: str


def _document(transport, origin: str, path: str, body: dict) -> dict:
    from cathedral.common import MAX_EVIDENCE_RESPONSE_BODY
    status, raw = transport.post(origin + path, body)
    if status != 200:
        raise GpuEndpointUnavailable(status)
    result = parse_strict_json(raw, max_bytes=MAX_EVIDENCE_RESPONSE_BODY)
    if not isinstance(result, dict):
        raise IndependentLiveError("GPU worker response is not an object")
    return result


def _admit(origin, miner, transport, verifier, row):
    from cathedral.gpu_work import ELEMENTS, WORKLOAD_ID, EVIDENCE_SCHEMA
    capability = _document(transport, origin, "/v1/gpu-capabilities", {})
    if (set(capability) != {"schema", "profile_id", "device_identity_digests", "workload_id",
                           "elements", "status", "verified"}
            or capability["schema"] != "cathedral_gpu_capability_v1"
            or capability["workload_id"] != WORKLOAD_ID
            or type(capability["elements"]) is not int or capability["elements"] != ELEMENTS
            or capability["status"] != "registered" or capability["verified"] is not False):
        raise IndependentLiveError("GPU capability schema is invalid")
    profile_id = capability["profile_id"]
    if not isinstance(profile_id, str) or profile_id not in verifier.profiles:
        raise IndependentLiveError("GPU profile is not enabled")
    profile = verifier.profiles[profile_id]
    expected = tuple(sorted(profile.expected_device_identity_digests))
    if profile_id == G4_WORKER_PROFILE_ID:
        reported = capability["device_identity_digests"]
        if (not isinstance(reported, list) or len(reported) != 1
                or not isinstance(reported[0], str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", reported[0]) is None):
            raise IndependentLiveError("G4 worker must declare exactly one GPU")
        expected = tuple(reported)
    if capability["device_identity_digests"] != list(expected):
        raise IndependentLiveError("GPU capability device set differs from signed profile")
    row.update(profile_id=profile_id, gpu_count=len(expected), declared_device_identity_digests=expected)
    binding = transport.last_spki
    if not isinstance(binding, bytes) or len(binding) != 32:
        raise IndependentLiveError("GPU capability has no TLS binding")
    transport.expected_spki = binding
    nonce = secrets.token_bytes(32)
    body = {"nonce_hex": nonce.hex(), "assigned_hotkey": miner.hotkey,
            "report_data_version": 2, "channel_binding_type": "tls_spki_sha256",
            "channel_binding_digest_hex": binding.hex()}
    envelope = _document(transport, origin, "/v1/gpu-evidence", body)
    expected_schema = "cathedral_gpu_provider_evidence_v1" if profile_id == G4_WORKER_PROFILE_ID else EVIDENCE_SCHEMA
    if set(envelope) != {"schema", "evidence"} or envelope["schema"] != expected_schema:
        raise IndependentLiveError("GPU evidence envelope is invalid")
    verified = verifier.verify(envelope["evidence"], nonce, miner.hotkey, binding, profile_id)
    if verified["device_identity_digests"] != expected:
        raise IndependentLiveError("GPU verified device set differs from signed profile")
    if profile_id == G4_WORKER_PROFILE_ID:
        instance = verified.get("provider_instance_id")
        if not isinstance(instance, str) or not instance or len(instance) > 512:
            raise IndependentLiveError("G4 provider instance identity is not verified")
        row["provider_instance_id"] = instance
    return {"profile_id": profile_id, "gpu_count": len(expected), "verified": True,
            "channel_id": binding.hex(), "device_identity_digests": expected,
            "machine_id": verified["machine_id"],
            "admission_digest": verified["component_digest"],
            "evidence_digest": verified["component_digest"], "verified_at": _utc()}


def _work(row, transport, verifier):
    from cathedral.gpu_work import (WORK_SCHEMA, RESULT_SCHEMA, ELEMENTS, WORKLOAD_ID,
                                    challenge_id, request_digest, expected_output_digest,
                                    completion_nonce)
    request = {"schema": WORK_SCHEMA, "nonce": secrets.token_hex(32),
               "assigned_hotkey": row["hotkey"], "profile_id": row["profile_id"],
               "device_identity_digests": list(row["device_identity_digests"]),
               "seed": secrets.token_hex(32), "elements": ELEMENTS, "workload_id": WORKLOAD_ID}
    request["challenge_id"] = challenge_id(request)
    result = _document(transport, row["endpoint"], "/v1/gpu-work", request)
    if (set(result) != {"schema", "request_digest", "output_digest", "device_identity_digests",
                       "completion_evidence"}
            or result["schema"] != RESULT_SCHEMA
            or result["request_digest"] != request_digest(request)
            or result["device_identity_digests"] != request["device_identity_digests"]
            or result["output_digest"] != expected_output_digest(request)):
        raise IndependentLiveError("GPU work result does not match challenge")
    verified = verifier.verify(result["completion_evidence"],
                               completion_nonce(request, result["output_digest"]),
                               row["hotkey"], bytes.fromhex(row["channel_id"]), row["profile_id"])
    if (verified["device_identity_digests"] != row["device_identity_digests"]
            or verified["machine_id"] != row["machine_id"]
            or (row["profile_id"] == G4_WORKER_PROFILE_ID
                and verified.get("provider_instance_id") != row.get("provider_instance_id"))):
        raise IndependentLiveError("GPU completion changed admitted device or CPU identity")
    return _digest({"request": request, "output_digest": result["output_digest"],
                    "admission_digest": row["admission_digest"],
                    "completion_digest": verified["component_digest"]})


def reject_duplicate_devices(rows: list[dict]) -> None:
    """Zero every verified claimant, even a claimant whose work later fails."""
    verified = [row for row in rows if row.get("verified") is True]
    identities = Counter(device for row in verified for device in row["device_identity_digests"])
    channels = Counter(row["channel_id"] for row in verified)
    endpoints = Counter(row["endpoint"] for row in verified)
    instances = Counter(row["provider_instance_id"] for row in verified if row.get("provider_instance_id"))
    for row in verified:
        if (any(identities[v] > 1 for v in row["device_identity_digests"])
                or channels[row["channel_id"]] > 1 or endpoints[row["endpoint"]] > 1
                or (row.get("provider_instance_id") and instances[row["provider_instance_id"]] > 1)):
            row.update(eligible=False, reason="duplicate_gpu_or_channel")


def qualify_gpu_round(miners: Sequence[ServingAxon], *, config: GpuPrelaunchConfig,
                      keypair: Any, verifier: ProductionGpuVerifier,
                      transport_factory=HttpsEvidenceTransport) -> GpuRound:
    if str(getattr(keypair, "ss58_address", "")) != config.validator_hotkey:
        raise IndependentLiveError("GPU access signer differs from configured validator")
    if len(miners) > MAX_MINERS or len({m.uid for m in miners}) != len(miners):
        raise IndependentLiveError("GPU miner snapshot is invalid or exceeds round bound")
    rows, transports = [], {}
    deadline = time.monotonic() + 300
    for miner in miners:
        if time.monotonic() >= deadline:
            raise IndependentLiveError("GPU round deadline exceeded before complete deduplication")
        primary = axon_origin(miner.ip, miner.port)
        def signed():
            return SignedValidatorTransport(transport_factory(timeout=90, deadline_monotonic=deadline), keypair=keypair,
                worker_hotkey=miner.hotkey, network=config.network, netuid=config.netuid)
        try:
            fleet = fetch_worker_fleet(primary_origin=primary, worker_hotkey=miner.hotkey,
                                       transport=signed())
            if fleet.singleton_compatibility:
                raise IndependentLiveError("GPU fleet must be explicitly signed")
            endpoints = fleet.endpoints
        except Exception:
            rows.append({"uid": miner.uid, "hotkey": miner.hotkey, "profile_id": None,
                         "gpu_count": 0, "verified": None, "eligible": False,
                         "reason": "fleet_unavailable", "evidence_digest": None})
            continue
        for endpoint in endpoints:
            if len(rows) >= 1024:
                raise IndependentLiveError("GPU directory scan exceeds endpoint bound")
            if time.monotonic() >= deadline:
                raise IndependentLiveError("GPU round deadline exceeded before complete deduplication")
            row = {"uid": miner.uid, "hotkey": miner.hotkey, "endpoint": endpoint,
                   "profile_id": None, "gpu_count": 0, "verified": False,
                   "eligible": False, "reason": "admission_failed", "evidence_digest": None}
            transport = signed()
            try:
                row.update(_admit(endpoint, miner, transport, verifier, row))
                row["reason"] = "work_pending"
                transports[id(row)] = transport
            except GpuEndpointUnavailable as exc:
                row["reason"] = "no_gpu" if exc.status == 404 and row["profile_id"] is None else "endpoint_unavailable"
            except Exception as exc:
                # Never publish arbitrary verifier/HTTP errors or embedded secrets.
                row["reason"] = "admission_" + (getattr(exc, "category", "failed")
                    if getattr(exc, "category", "failed") in {"unavailable", "profile_inactive",
                    "invalid_evidence", "gpu_policy_denied", "gpu_component_denied",
                    "cpu_component_denied", "composite_binding_denied"} else "failed")
            rows.append(row)
    reject_duplicate_devices(rows)
    for row in rows:
        if row["reason"] != "work_pending":
            continue
        if time.monotonic() >= deadline:
            row.update(eligible=False, reason="work_deadline")
            continue
        try:
            row["evidence_digest"] = _work(row, transports[id(row)], verifier)
            row.update(eligible=True, reason="verified_work", verified_at=_utc())
        except Exception:
            row.update(eligible=False, reason="work_or_completion_failed")
    enforce_g4_bundles(rows)
    return GpuRound(tuple(rows), _utc(), verifier.registry_digest)


def enforce_g4_bundles(rows: list[dict]) -> None:
    """One miner offer is exactly eight separately verified single-GPU VMs."""
    grouped = {}
    for row in rows:
        if row.get("profile_id") == G4_WORKER_PROFILE_ID:
            grouped.setdefault((row["uid"], row["hotkey"]), []).append(row)
    for members in grouped.values():
        complete = (len(members) == G4_BUNDLE_SIZE
                    and all(row.get("verified") is True and row.get("eligible") is True
                            and len(row.get("device_identity_digests", ())) == 1 for row in members)
                    and len({row.get("provider_instance_id") for row in members}) == G4_BUNDLE_SIZE
                    and all(row.get("provider_instance_id") for row in members)
                    and len({row["device_identity_digests"][0] for row in members}) == G4_BUNDLE_SIZE)
        if not complete:
            for row in members:
                row["eligible"] = False
                if row.get("reason") == "verified_work":
                    row["reason"] = "g4_requires_eight_verified_instances"


def direct_gpu_plan(result: GpuRound, config: GpuPrelaunchConfig,
                    miners: Sequence[ServingAxon], *, cpu_machine_ids: Mapping[int, tuple[str, ...]] | None = None):
    """Same direct integer normalization, explicit test units, no chain call.

    CPU inputs are already-verified unique machine rows from the CPU scorer.
    Default CPU-only live scoring remains untouched. Callers may supply those
    rows to inspect a mixed plan without inventing a mainnet allocation.
    """
    hotkeys = {m.uid: m.hotkey for m in miners}
    checked = [dict(row) for row in result.rows]
    enforce_g4_bundles(checked)
    devices = {uid: [] for uid in hotkeys}
    all_devices = set()
    for row in checked:
        if row.get("eligible") is not True:
            continue
        uid = row["uid"]
        ids = row.get("device_identity_digests", ())
        if (hotkeys.get(uid) != row["hotkey"] or row.get("verified") is not True
                or row.get("reason") != "verified_work" or not row.get("evidence_digest")
                or not ids or len(set(ids)) != len(ids) or any(v in all_devices for v in ids)):
            raise IndependentLiveError("GPU positive score has invalid identity or work proof")
        all_devices.update(ids)
        devices[uid].extend(ids)
    cpu = dict(cpu_machine_ids or {})
    if set(cpu) - set(hotkeys):
        raise IndependentLiveError("CPU score belongs to unknown miner")
    flattened = [item for ids in cpu.values() for item in ids]
    if len(set(flattened)) != len(flattened):
        raise IndependentLiveError("CPU score repeats a machine")
    scores = tuple((uid, len(cpu.get(uid, ())) + len(devices[uid]) * config.units_per_device)
                   for uid in sorted(hotkeys))
    uids, weights = zero_burn_vector(scores, hotkeys) if any(v for _, v in scores) else ((), ())
    return {"schema": PLAN_SCHEMA, "prelaunch_only": True, "chain_write": False,
            "network": config.network, "netuid": config.netuid,
            "scoring_policy": {"cpu_machine_units": 1, "gpu_device_units": config.units_per_device,
                               "workload_id": "cuda_i32_vector_v1"},
            "raw_scores": [list(v) for v in scores], "uids": list(uids), "weights": list(weights),
            "gpu_ids_by_uid": [[uid, sorted(ids)] for uid, ids in sorted(devices.items())],
            "verification_policy_digest": result.registry_digest,
            "private_customer_work": False, "evidence_digest": _digest(result.rows)}


def provider_directory(result: GpuRound, config: GpuPrelaunchConfig, verifier: ProductionGpuVerifier):
    # Unknown fleets/capabilities cannot truthfully become an empty inventory.
    if any(row.get("profile_id") is None and row.get("reason") != "no_gpu" for row in result.rows):
        return {"schema": "cathedral.gpu.providers.unavailable.v1", "observed_at": result.observed_at,
                "reason": "incomplete_scan"}
    grouped = {}
    for row in result.rows:
        if row.get("profile_id") is not None:
            public_profile = G4_BUNDLE_PROFILE_ID if row["profile_id"] == G4_WORKER_PROFILE_ID else row["profile_id"]
            grouped.setdefault((row["uid"], row["hotkey"], public_profile), []).append(row)
    providers = []
    for (uid, hotkey, profile_id), rows in sorted(grouped.items()):
        verified = all(row["verified"] is True for row in rows)
        work = all(row["eligible"] is True for row in rows)
        if profile_id == G4_BUNDLE_PROFILE_ID:
            count = len({v for row in rows for v in row.get("declared_device_identity_digests", ())})
            if not 1 <= count <= G4_BUNDLE_SIZE:
                return {"schema": "cathedral.gpu.providers.unavailable.v1",
                        "observed_at": result.observed_at, "reason": "invalid_g4_bundle_size"}
            verified = (verified and len(rows) == G4_BUNDLE_SIZE and count == G4_BUNDLE_SIZE
                        and len({row.get("provider_instance_id") for row in rows}) == G4_BUNDLE_SIZE
                        and all(row.get("provider_instance_id") for row in rows)
                        and not any(row["reason"] == "duplicate_gpu_or_channel" for row in rows))
            work = work and verified
        else:
            count = len(verifier.profiles[profile_id].expected_device_identity_digests)
        reason = "verified_work_prelaunch" if work else (
            "duplicate_gpu_or_channel" if any(row["reason"] == "duplicate_gpu_or_channel" for row in rows)
            else "g4_requires_eight_verified_instances" if profile_id == G4_BUNDLE_PROFILE_ID and not verified
            else "verified_admission_work_failed" if verified else "admission_failed")
        material = [{"admission": row.get("admission_digest"), "work": row.get("evidence_digest")}
                    for row in rows]
        providers.append({"uid": uid, "hotkey": hotkey, "profile_id": profile_id,
                          "gpu_count": count,
                          "registered": True, "verified": verified, "eligible": False,
                          "reason": reason, "evidence_digest": _digest(material) if verified else None,
                          "verified_at": max(row["verified_at"] for row in rows) if verified else None})
    return {"schema": DIRECTORY_SCHEMA, "observed_at": result.observed_at,
            "network": config.network, "netuid": config.netuid,
            "admission": {"open": True, "reason": "Configured profiles accept qualification; live rewards are not enabled."},
            "profiles": [{"id": G4_BUNDLE_PROFILE_ID if profile.profile_id == G4_WORKER_PROFILE_ID else profile.profile_id,
                          "model": ", ".join(sorted(profile.allowed_models)),
                          "gpu_count": G4_BUNDLE_SIZE if profile.profile_id == G4_WORKER_PROFILE_ID else len(profile.expected_device_identity_digests),
                          "cpu_tee": "amd_sev" if profile.profile_id == G4_WORKER_PROFILE_ID else "intel_tdx",
                          "status": "qualification",
                          "reason": "CPU host attestation not verified; eight single-GPU VMs; no live rewards." if profile.profile_id == G4_WORKER_PROFILE_ID else "Prelaunch hardware and work qualification; no chain writes."}
                         for profile in verifier.profiles.values()], "providers": providers}


class AccessRequestSigner:
    """Explicit executable signer restricted to the HTTP access document domain."""
    def __init__(self, executable: str, config: GpuPrelaunchConfig):
        if not Path(executable).is_absolute() or not Path(executable).is_file():
            raise IndependentLiveError("request signer must be an explicit executable path")
        self.executable, self.config = executable, config
        self.ss58_address = config.validator_hotkey

    def sign(self, payload: bytes) -> bytes:
        request = parse_strict_json(payload, max_bytes=8192)
        if (not isinstance(request, dict) or request.get("schema") != "cathedral_validator_request_v1"
                or request.get("validator_hotkey") != self.ss58_address
                or request.get("network") != self.config.network
                or request.get("netuid") != self.config.netuid
                or request.get("method") != "POST"
                or request.get("path") not in GPU_PATHS | {"/v1/fleet"}
                or "signature" in request):
            raise IndependentLiveError("request signer refuses non-GPU-access payload")
        result = subprocess.run([self.executable], input=payload, capture_output=True,
                                timeout=10, check=False)
        if result.returncode != 0 or len(result.stdout) > 128:
            raise IndependentLiveError("request signer failed")
        try:
            signature = base64.b64decode(result.stdout.strip(), validate=True)
        except ValueError:
            raise IndependentLiveError("request signer returned an invalid signature") from None
        if len(signature) != 64:
            raise IndependentLiveError("request signer returned an invalid signature")
        return signature


def read_registered_miners(subtensor, config, expected_genesis_hash):
    """Read one finalized snapshot. No wallet, nonce, compose or submit calls."""
    genesis = str(subtensor.substrate.get_block_hash(0)).lower()
    if (not isinstance(expected_genesis_hash, str) or len(expected_genesis_hash) != 66
            or re.fullmatch(r"0x[0-9a-fA-F]{64}", expected_genesis_hash) is None
            or genesis != expected_genesis_hash.lower()):
        raise IndependentLiveError("GPU qualification chain genesis differs from explicit target")
    number, block_hash = finalized_head(subtensor)
    metagraph = subtensor.metagraph(config.netuid, block=number)
    if int(metagraph.block) != number:
        raise IndependentLiveError("GPU metagraph is not finalized at requested block")
    uids = [int(uid) for uid in metagraph.uids]
    hotkeys = list(metagraph.hotkeys)
    permits = []
    for value in metagraph.validator_permit:
        value = getattr(value, "value", value)
        if callable(getattr(value, "item", None)):
            value = value.item()
        if type(value) is not bool:
            raise IndependentLiveError("GPU validator permit is not an explicit boolean")
        permits.append(value)
    if (len(uids) != len(hotkeys) or len(uids) != len(permits)
            or len(set(uids)) != len(uids) or len(set(hotkeys)) != len(hotkeys)
            or config.validator_hotkey not in hotkeys
            or not permits[hotkeys.index(config.validator_hotkey)]):
        raise IndependentLiveError("GPU qualification validator identity or permit is invalid")
    validator_uids = {uid for uid, permit in zip(uids, permits) if permit}
    miners = tuple(m for m in scan_axons(metagraph).serving if m.uid not in validator_uids)
    identities = dict(zip(uids, hotkeys))
    if any(identities.get(m.uid) != m.hotkey for m in miners):
        raise IndependentLiveError("GPU miner identities differ from finalized snapshot")
    return miners, {"number": number, "hash": block_hash, "genesis_hash": genesis}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="GPU hardware/work qualification, never chain writes")
    parser.add_argument("--config", required=True)
    parser.add_argument("--request-signer-executable", required=True)
    parser.add_argument("--expected-genesis-hash", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--gpu-directory-output")
    args = parser.parse_args(argv)
    config = None
    try:
        config = GpuPrelaunchConfig.load(args.config)
        verifier = ProductionGpuVerifier(config)
        signer = AccessRequestSigner(args.request_signer_executable, config)
        import bittensor as bt
        from cathedral_thin.bt_compat import make_subtensor
        subtensor = make_subtensor(bt, network=config.network)
        try:
            miners, anchor = read_registered_miners(subtensor, config, args.expected_genesis_hash)
            result = qualify_gpu_round(miners, config=config, keypair=signer, verifier=verifier)
        finally:
            close = getattr(subtensor, "close", None)
            if callable(close):
                close()
        plan = direct_gpu_plan(result, config, miners)
        document = {"schema": "cathedral_gpu_qualification_v1", "chain_write": False,
                    "verdict": "PASS" if plan["uids"] else "NOT_PROVEN", "anchor": anchor,
                    "observed_at": result.observed_at, "plan": plan,
                    "providers": provider_directory(result, config, verifier)}
        atomic_json(args.output, document)
        if args.gpu_directory_output:
            atomic_json(args.gpu_directory_output, document["providers"])
        print(json.dumps({"verdict": document["verdict"], "chain_write": False,
                          "eligible_providers": sum(row["eligible"] is True for row in result.rows)}))
        return 0 if plan["uids"] else 2
    except Exception as exc:
        failure = {"schema": "cathedral_gpu_qualification_v1", "verdict": "NOT_PROVEN",
                   "chain_write": False, "reason": type(exc).__name__, "observed_at": _utc()}
        atomic_json(args.output, failure)
        if args.gpu_directory_output:
            atomic_json(args.gpu_directory_output, {"schema": "cathedral.gpu.providers.unavailable.v1",
                "observed_at": failure["observed_at"], "reason": "qualification_unavailable"})
        print(json.dumps(failure))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
