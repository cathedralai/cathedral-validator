"""Bounded AMD SEV-SNP development preview with no chain authority.

This command is deliberately separate from the live TDX scorer and every
weight writer.  It loads the exact Compute contract only when invoked, signs
worker HTTPS requests with an already configured validator hotkey, verifies
fresh SEV-SNP evidence, and replays one canonical SAT item on the attested TLS
channel.  Its only durable effect is an owner-only, create-once JSON preview.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib
import importlib.metadata
import importlib.util
import json
import os
import re
import ssl
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from cathedral_thin.independent.constants import (
    MULTICOMPUTE_FLEET_CAP,
    NETUID,
)
from cathedral_thin.independent_runtime.multicompute import (
    MachineWorkObservation,
    MultiComputeScore,
    aggregate_multicompute_units,
)
from cathedral_thin.independent_runtime.preview_io import (
    PreviewWriteError,
    write_owner_only_preview,
)
from cathedral_thin.independent_runtime.validator_request import (
    _require_hotkey,
    validate_public_worker_endpoint,
)

# Exact reviewed cathedral-compute merge commit from cathedral-sandbox#181.
# Runtime provenance checks prevent a local, mutable, wheel-only, or different
# Compute tree from silently becoming this verifier contract.
COMPUTE_CONTRACT_COMMIT = "5268443104fd7717b95ce4c398ddf6229ec4f461"

CONFIG_SCHEMA = "cathedral_amd_sev_snp_development_preview_config_v1"
PREVIEW_SCHEMA = "cathedral_amd_sev_snp_development_preview_v1"
STATUS = "PROVEN_DEVELOPMENT_NO_WRITE"
NOT_PROVEN_STATUS = "NOT_PROVEN_DEVELOPMENT_NO_WRITE"
ENVIRONMENT = "development"
NETWORK = "finney"
MAX_CONFIG_BYTES = 128 * 1024
MAX_PATH_BYTES = 4096
MAX_COMPUTE_MODULE_BYTES = 8 * 1024 * 1024
MAX_TLS_CA_BYTES = 1024 * 1024
MAX_TARGETS = MULTICOMPUTE_FLEET_CAP
EXPECTED_WORK_UNITS = 20
AMD_GUEST_POLICY_SINGLE_SOCKET = 1 << 20
PROCESSOR_GENERATIONS = frozenset({"milan", "genoa", "turin"})

_HEX_32_RE = re.compile(r"[0-9a-f]{64}")
_MEASUREMENT_RE = re.compile(r"[0-9a-f]{96}")
_BLOCK_HASH_RE = re.compile(r"0x[0-9a-f]{64}")
_TCB_RE = re.compile(r"0x[0-9a-f]{16}")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_COMPUTE_REPOSITORY_URLS = frozenset(
    {
        "https://github.com/cathedralai/cathedral-compute",
        "https://github.com/cathedralai/cathedral-compute.git",
    }
)
_REQUIRED_COMPUTE_FILES = frozenset(
    {
        "cathedral/__init__.py",
        "cathedral/common.py",
        "cathedral/lanes/__init__.py",
        "cathedral/lanes/sat.py",
        "cathedral/remote.py",
        "cathedral/verify/__init__.py",
        "cathedral/verify/snp.py",
    }
)
_CONFIG_KEYS = frozenset(
    {
        "schema",
        "environment",
        "network",
        "netuid",
        "validator_hotkey",
        "validator_wallet",
        "scoring_window",
        "review_challenge_hex",
        "snpguest_path",
        "processor_generation",
        "allowed_measurements",
        "minimum_reported_tcb",
        "timeout_seconds",
        "targets",
    }
)
_WALLET_KEYS = frozenset({"name", "hotkey", "path"})
_TARGET_KEYS = frozenset({"uid", "miner_hotkey", "endpoint", "tls_ca_cert"})
_PSEUDONYM_DOMAIN = b"cathedral.amd-sev-snp.dev-hardware-v1\x00"
_REVIEW_SCOPE_DOMAIN = b"cathedral.amd-sev-snp.dev-review-scope-v1\x00"


class AmdSnpDevPreviewError(Exception):
    """The development preview refused without reaching chain authority."""


class _TargetRefusal(Exception):
    """One target failed with a bounded public reason code."""


@dataclass(frozen=True)
class WalletConfig:
    name: str
    hotkey: str
    path: str | None


@dataclass(frozen=True)
class TargetConfig:
    uid: int
    miner_hotkey: str
    endpoint: str
    tls_ca_cert: str


@dataclass(frozen=True)
class DevPreviewConfig:
    validator_hotkey: str
    validator_wallet: WalletConfig
    scoring_window: str
    review_challenge: bytes
    snpguest_path: str
    processor_generation: str
    allowed_measurements: frozenset[str]
    minimum_reported_tcb: int
    timeout_seconds: float
    targets: tuple[TargetConfig, ...]
    network: str = NETWORK
    netuid: int = NETUID
    environment: str = ENVIRONMENT

    @property
    def uid(self) -> int:
        return self.targets[0].uid

    @property
    def miner_hotkey(self) -> str:
        return self.targets[0].miner_hotkey


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AmdSnpDevPreviewError(f"configuration repeats key {key!r}")
        result[key] = value
    return result


def _exact_mapping(
    value: Any, keys: frozenset[str], *, label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AmdSnpDevPreviewError(f"{label} must be a JSON object")
    present = frozenset(value)
    if present != keys:
        unknown = sorted(present - keys)
        missing = sorted(keys - present)
        raise AmdSnpDevPreviewError(
            f"{label} has unknown keys {unknown} and is missing {missing}"
        )
    return value


def _bounded_ascii(value: Any, *, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or not value.isascii()
        or len(value) > maximum
    ):
        raise AmdSnpDevPreviewError(f"{label} must be a bounded non-empty ASCII string")
    return value


def _absolute_path(value: Any, *, label: str) -> str:
    try:
        encoded_length = len(os.fsencode(value)) if isinstance(value, str) else 0
    except (UnicodeEncodeError, ValueError):
        encoded_length = MAX_PATH_BYTES + 1
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or encoded_length > MAX_PATH_BYTES
        or not Path(value).is_absolute()
    ):
        raise AmdSnpDevPreviewError(f"{label} must be a bounded absolute path")
    return value


def _ss58(value: Any, *, label: str) -> str:
    try:
        return _require_hotkey(value, label)
    except Exception as exc:
        raise AmdSnpDevPreviewError(
            f"{label} must be a Bittensor SS58 address"
        ) from exc


def parse_config_document(document: Any) -> DevPreviewConfig:
    root = _exact_mapping(document, _CONFIG_KEYS, label="configuration")
    if root["schema"] != CONFIG_SCHEMA:
        raise AmdSnpDevPreviewError("configuration schema is unsupported")
    if root["environment"] != ENVIRONMENT:
        raise AmdSnpDevPreviewError(
            "AMD SEV-SNP preview environment must be development"
        )
    if (
        root["network"] != NETWORK
        or isinstance(root["netuid"], bool)
        or not isinstance(root["netuid"], int)
        or root["netuid"] != NETUID
    ):
        raise AmdSnpDevPreviewError(
            "AMD SEV-SNP development preview is pinned to finney SN39"
        )

    validator_hotkey = _ss58(root["validator_hotkey"], label="validator_hotkey")
    raw_wallet = _exact_mapping(
        root["validator_wallet"], _WALLET_KEYS, label="validator_wallet"
    )
    wallet_path = raw_wallet["path"]
    if wallet_path is not None:
        wallet_path = _absolute_path(wallet_path, label="validator_wallet.path")
    wallet = WalletConfig(
        name=_bounded_ascii(
            raw_wallet["name"], label="validator_wallet.name", maximum=128
        ),
        hotkey=_bounded_ascii(
            raw_wallet["hotkey"], label="validator_wallet.hotkey", maximum=128
        ),
        path=wallet_path,
    )

    scoring_window = root["scoring_window"]
    if (
        not isinstance(scoring_window, str)
        or _BLOCK_HASH_RE.fullmatch(scoring_window) is None
    ):
        raise AmdSnpDevPreviewError(
            "scoring_window must be a lowercase 0x-prefixed hash"
        )
    review_challenge_hex = root["review_challenge_hex"]
    if (
        not isinstance(review_challenge_hex, str)
        or _HEX_32_RE.fullmatch(review_challenge_hex) is None
        or review_challenge_hex == "0" * 64
    ):
        raise AmdSnpDevPreviewError(
            "review_challenge_hex must be a nonzero 32-byte value"
        )

    snpguest_path = _absolute_path(root["snpguest_path"], label="snpguest_path")

    processor_generation = root["processor_generation"]
    if (
        not isinstance(processor_generation, str)
        or processor_generation not in PROCESSOR_GENERATIONS
    ):
        raise AmdSnpDevPreviewError(
            "processor_generation must be one of milan, genoa, or turin"
        )

    raw_measurements = root["allowed_measurements"]
    if (
        not isinstance(raw_measurements, list)
        or not raw_measurements
        or len(raw_measurements) > MAX_TARGETS
        or any(
            not isinstance(value, str) or _MEASUREMENT_RE.fullmatch(value) is None
            for value in raw_measurements
        )
        or len(set(raw_measurements)) != len(raw_measurements)
    ):
        raise AmdSnpDevPreviewError(
            f"allowed_measurements must contain 1..{MAX_TARGETS} unique 48-byte hex values"
        )
    if raw_measurements != sorted(raw_measurements):
        raise AmdSnpDevPreviewError("allowed_measurements must be sorted")

    raw_tcb = root["minimum_reported_tcb"]
    if not isinstance(raw_tcb, str) or _TCB_RE.fullmatch(raw_tcb) is None:
        raise AmdSnpDevPreviewError(
            "minimum_reported_tcb must be a 0x-prefixed 8-byte lowercase hex value"
        )
    minimum_tcb = int(raw_tcb, 16)
    if minimum_tcb == 0:
        raise AmdSnpDevPreviewError("minimum_reported_tcb must be nonzero")
    minimum_tcb_bytes = minimum_tcb.to_bytes(8, "little")
    reserved_indices = (
        range(2, 6) if processor_generation in {"milan", "genoa"} else range(4, 7)
    )
    if any(minimum_tcb_bytes[index] for index in reserved_indices):
        raise AmdSnpDevPreviewError(
            "minimum_reported_tcb sets reserved bytes for processor_generation"
        )

    timeout = root["timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 1 <= float(timeout) <= 60
    ):
        raise AmdSnpDevPreviewError("timeout_seconds must be a number in 1..60")

    raw_targets = root["targets"]
    if (
        not isinstance(raw_targets, list)
        or not raw_targets
        or len(raw_targets) > MAX_TARGETS
    ):
        raise AmdSnpDevPreviewError(f"targets must contain 1..{MAX_TARGETS} entries")
    targets: list[TargetConfig] = []
    for index, raw_target in enumerate(raw_targets):
        target = _exact_mapping(raw_target, _TARGET_KEYS, label=f"targets[{index}]")
        uid = target["uid"]
        if isinstance(uid, bool) or not isinstance(uid, int) or not 0 <= uid <= 65_535:
            raise AmdSnpDevPreviewError(f"targets[{index}].uid must be in 0..65535")
        miner_hotkey = _ss58(
            target["miner_hotkey"], label=f"targets[{index}].miner_hotkey"
        )
        try:
            endpoint = validate_public_worker_endpoint(target["endpoint"])
        except Exception as exc:
            raise AmdSnpDevPreviewError(
                f"targets[{index}].endpoint must be a canonical public HTTPS origin"
            ) from exc
        tls_ca_cert = _absolute_path(
            target["tls_ca_cert"], label=f"targets[{index}].tls_ca_cert"
        )
        targets.append(TargetConfig(uid, miner_hotkey, endpoint, tls_ca_cert))

    if len({target.uid for target in targets}) != 1:
        raise AmdSnpDevPreviewError("all targets must explicitly name the same UID")
    if len({target.miner_hotkey for target in targets}) != 1:
        raise AmdSnpDevPreviewError(
            "all targets must explicitly name the same miner hotkey"
        )

    return DevPreviewConfig(
        validator_hotkey=validator_hotkey,
        validator_wallet=wallet,
        scoring_window=scoring_window,
        review_challenge=bytes.fromhex(review_challenge_hex),
        snpguest_path=snpguest_path,
        processor_generation=processor_generation,
        allowed_measurements=frozenset(raw_measurements),
        minimum_reported_tcb=minimum_tcb,
        timeout_seconds=float(timeout),
        targets=tuple(targets),
    )


def load_config(path: Path) -> DevPreviewConfig:
    if not hasattr(os, "O_NOFOLLOW"):
        raise AmdSnpDevPreviewError("safe configuration loading is unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AmdSnpDevPreviewError("configuration must be a regular file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AmdSnpDevPreviewError("configuration must be a regular file")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AmdSnpDevPreviewError(
                "configuration must be owner-controlled mode 0600"
            )
        if metadata.st_size > MAX_CONFIG_BYTES:
            raise AmdSnpDevPreviewError("configuration exceeds its 128 KiB bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_CONFIG_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_CONFIG_BYTES:
                raise AmdSnpDevPreviewError("configuration exceeds its 128 KiB bound")
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) != metadata.st_size or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_uid,
            stat.S_IMODE(after.st_mode),
        ) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
        ):
            raise AmdSnpDevPreviewError("configuration changed while it was read")
        document = json.loads(raw, object_pairs_hook=_strict_object)
    except AmdSnpDevPreviewError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AmdSnpDevPreviewError("configuration is not strict bounded JSON") from exc
    finally:
        os.close(descriptor)
    return parse_config_document(document)


def _installed_compute_provenance() -> tuple[str, Any]:
    expected = COMPUTE_CONTRACT_COMMIT
    if _COMMIT_RE.fullmatch(expected) is None:
        raise AmdSnpDevPreviewError(
            "the snp-dev Compute dependency pin has not been replaced with a reviewed commit"
        )
    try:
        distribution = importlib.metadata.distribution("cathedral")
        direct_url = distribution.read_text("direct_url.json")
        document = json.loads(direct_url or "")
        if not isinstance(document, Mapping) or frozenset(document) != {
            "url",
            "vcs_info",
        }:
            raise ValueError
        if document["url"] not in _COMPUTE_REPOSITORY_URLS:
            raise ValueError
        vcs = document["vcs_info"]
        if not isinstance(vcs, Mapping) or frozenset(vcs) != {
            "vcs",
            "requested_revision",
            "commit_id",
        }:
            raise ValueError
        if vcs["vcs"] != "git" or vcs["requested_revision"] != expected:
            raise ValueError
        installed = vcs["commit_id"]
    except Exception as exc:
        raise AmdSnpDevPreviewError(
            "the installed Compute package has no verifiable VCS commit provenance"
        ) from exc
    if installed != expected:
        raise AmdSnpDevPreviewError(
            "the installed Compute package is not the pinned contract"
        )
    return expected, distribution


def _installed_compute_commit() -> str:
    """Compatibility helper used by the pin regression tests."""

    return _installed_compute_provenance()[0]


def _recorded_sha256(path: Path, *, maximum: int) -> tuple[str, int]:
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > maximum
        ):
            raise AmdSnpDevPreviewError(
                "a Compute module is not a bounded regular file"
            )
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except AmdSnpDevPreviewError:
        raise
    except OSError as exc:
        raise AmdSnpDevPreviewError("a Compute module could not be read") from exc
    encoded = base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")
    return encoded, metadata.st_size


def _verify_compute_distribution_before_import(distribution: Any) -> dict[Path, Any]:
    if any(
        name == "cathedral" or name.startswith("cathedral.") for name in sys.modules
    ):
        raise AmdSnpDevPreviewError(
            "Compute modules were loaded before provenance verification"
        )
    files = distribution.files
    if not files:
        raise AmdSnpDevPreviewError(
            "the installed Compute package has no RECORD manifest"
        )
    recorded: dict[Path, Any] = {}
    recorded_names: set[str] = set()
    try:
        for entry in files:
            name = str(entry)
            if not name.startswith("cathedral/") or not name.endswith(".py"):
                continue
            path = Path(distribution.locate_file(entry)).resolve(strict=True)
            record_hash = getattr(entry, "hash", None)
            if record_hash is None or record_hash.mode != "sha256":
                raise AmdSnpDevPreviewError(
                    "a Compute source module is missing its RECORD SHA-256"
                )
            digest, size = _recorded_sha256(path, maximum=MAX_COMPUTE_MODULE_BYTES)
            recorded_size = getattr(entry, "size", None)
            if digest != record_hash.value or (
                recorded_size is not None and size != recorded_size
            ):
                raise AmdSnpDevPreviewError(
                    "a Compute source module differs from RECORD"
                )
            recorded[path] = entry
            recorded_names.add(name)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise AmdSnpDevPreviewError(
            "the installed Compute RECORD manifest is invalid"
        ) from exc
    missing = sorted(_REQUIRED_COMPUTE_FILES - recorded_names)
    if missing:
        raise AmdSnpDevPreviewError(
            f"the Compute RECORD is missing required files {missing}"
        )

    expected_package = Path(distribution.locate_file("cathedral/__init__.py")).resolve(
        strict=True
    )
    spec = importlib.util.find_spec("cathedral")
    origin = getattr(spec, "origin", None)
    try:
        resolved_origin = (
            Path(origin).resolve(strict=True) if isinstance(origin, str) else None
        )
    except (OSError, RuntimeError):
        resolved_origin = None
    if resolved_origin != expected_package:
        raise AmdSnpDevPreviewError(
            "the cathedral import resolves outside the pinned Compute distribution"
        )
    return recorded


def _verify_loaded_compute_imports(recorded: Mapping[Path, Any]) -> None:
    verified = 0
    for name, module in tuple(sys.modules.items()):
        if name != "cathedral" and not name.startswith("cathedral."):
            continue
        module_file = getattr(module, "__file__", None)
        if not isinstance(module_file, str):
            raise AmdSnpDevPreviewError(
                "an imported Compute module has no source provenance"
            )
        try:
            path = Path(module_file).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise AmdSnpDevPreviewError(
                "an imported Compute module path is invalid"
            ) from exc
        entry = recorded.get(path)
        record_hash = getattr(entry, "hash", None)
        if entry is None or record_hash is None or record_hash.mode != "sha256":
            raise AmdSnpDevPreviewError(
                "an imported Compute module is outside the pinned distribution"
            )
        digest, size = _recorded_sha256(path, maximum=MAX_COMPUTE_MODULE_BYTES)
        recorded_size = getattr(entry, "size", None)
        if digest != record_hash.value or (
            recorded_size is not None and size != recorded_size
        ):
            raise AmdSnpDevPreviewError(
                "an imported Compute module differs from RECORD"
            )
        verified += 1
    if verified == 0:
        raise AmdSnpDevPreviewError("no Compute modules were provenance-verified")


def load_compute_contract() -> Any:
    """Load only the exact optional Compute verifier/client contract."""

    commit, distribution = _installed_compute_provenance()
    recorded = _verify_compute_distribution_before_import(distribution)
    try:
        common = importlib.import_module("cathedral.common")
        sat = importlib.import_module("cathedral.lanes.sat")
        remote = importlib.import_module("cathedral.remote")
        snp = importlib.import_module("cathedral.verify.snp")
    except ImportError as exc:
        raise AmdSnpDevPreviewError(
            "install the validator with its exact [snp-dev] Compute dependency"
        ) from exc
    _verify_loaded_compute_imports(recorded)
    return SimpleNamespace(
        commit=commit,
        ChannelBindingType=common.ChannelBindingType,
        EvidenceKind=common.EvidenceKind,
        Policy=common.Policy,
        Tier=common.Tier,
        issue_nonce=common.issue_nonce,
        SatLane=sat.SatLane,
        RemoteMiner=remote.RemoteMiner,
        MAX_SNPGUEST_BYTES=snp.MAX_SNPGUEST_BYTES,
        PINNED_SNPGUEST_SHA256=snp.PINNED_SNPGUEST_SHA256,
        PINNED_SNPGUEST_VERSION=snp.PINNED_SNPGUEST_VERSION,
        SnpVerifierUnavailable=snp.SnpVerifierUnavailable,
        parse_snp_report=snp.parse_snp_report,
        snp_generation=snp.snp_generation,
        verify_snp=snp.verify_snp,
    )


def _file_sha256(path: Path, *, maximum: int) -> str:
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            raise AmdSnpDevPreviewError("snpguest is not a bounded regular file")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except AmdSnpDevPreviewError:
        raise
    except OSError as exc:
        raise AmdSnpDevPreviewError("snpguest could not be read") from exc


def verify_snpguest(config: DevPreviewConfig, contract: Any) -> str:
    path = Path(config.snpguest_path)
    if not os.access(path, os.X_OK):
        raise AmdSnpDevPreviewError("snpguest is not executable")
    digest = _file_sha256(path, maximum=int(contract.MAX_SNPGUEST_BYTES))
    if digest != contract.PINNED_SNPGUEST_SHA256:
        raise AmdSnpDevPreviewError("snpguest does not match the pinned SHA-256")
    return digest


def load_validator_hotkey(config: DevPreviewConfig) -> Any:
    """Open only ``wallet.hotkey``.  This path never asks for a coldkey."""

    try:
        import bittensor as bt

        from cathedral_thin.bt_compat import make_wallet

        wallet = make_wallet(
            bt,
            name=config.validator_wallet.name,
            hotkey=config.validator_wallet.hotkey,
            path=config.validator_wallet.path,
        )
        keypair = wallet.hotkey
    except Exception as exc:
        raise AmdSnpDevPreviewError(
            "validator hotkey wallet could not be opened"
        ) from exc
    if str(
        getattr(keypair, "ss58_address", "")
    ) != config.validator_hotkey or not callable(getattr(keypair, "sign", None)):
        raise AmdSnpDevPreviewError(
            "validator wallet does not contain the configured hotkey"
        )
    return keypair


def _read_tls_ca_cert(path: Path) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _TargetRefusal("tls_ca_cert_safe_open_unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise _TargetRefusal("tls_ca_cert_invalid") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 1 <= metadata.st_size <= MAX_TLS_CA_BYTES
        ):
            raise _TargetRefusal("tls_ca_cert_not_owner_controlled")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_TLS_CA_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_TLS_CA_BYTES:
                raise _TargetRefusal("tls_ca_cert_too_large")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_uid,
            stat.S_IMODE(after.st_mode),
        ) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
        ):
            raise _TargetRefusal("tls_ca_cert_changed_while_reading")
        body = b"".join(chunks)
        if len(body) != metadata.st_size:
            raise _TargetRefusal("tls_ca_cert_changed_while_reading")
        return body
    except OSError:
        raise _TargetRefusal("tls_ca_cert_invalid") from None
    finally:
        os.close(descriptor)


def _client_tls_context(target: TargetConfig) -> ssl.SSLContext:
    body = _read_tls_ca_cert(Path(target.tls_ca_cert))
    try:
        cadata: str | bytes = (
            body.decode("ascii") if b"-----BEGIN CERTIFICATE-----" in body else body
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=cadata)
        return context
    except (UnicodeDecodeError, ValueError, ssl.SSLError):
        raise _TargetRefusal("tls_ca_cert_invalid") from None


def new_compute_client(
    contract: Any,
    target: TargetConfig,
    *,
    keypair: Any,
    validator_hotkey: str,
    timeout_seconds: float,
) -> Any:
    """Wire signed validator access into Compute's hardened HTTPS client."""

    return contract.RemoteMiner(
        target.endpoint,
        target.miner_hotkey,
        timeout=timeout_seconds,
        ssl_context=_client_tls_context(target),
        validator_hotkey=validator_hotkey,
        validator_signer=keypair.sign,
        validator_network=NETWORK,
        validator_netuid=NETUID,
    )


def _hardware_pseudonym(review_challenge: bytes, raw_chip_id: bytes) -> str:
    if len(review_challenge) != 32 or len(raw_chip_id) != 64:
        raise _TargetRefusal("snp_identity_invalid")
    return hmac.new(
        review_challenge,
        _PSEUDONYM_DOMAIN + raw_chip_id,
        hashlib.sha256,
    ).hexdigest()


def _sat_namespace(config: DevPreviewConfig, pseudonym: str) -> str:
    return hashlib.sha256(
        b"cathedral.amd-sev-snp.dev-sat-v1\x00"
        + config.scoring_window.encode("ascii")
        + config.miner_hotkey.encode("ascii")
        + pseudonym.encode("ascii")
    ).hexdigest()[:32]


def _score_target(
    config: DevPreviewConfig,
    target: TargetConfig,
    *,
    keypair: Any,
    contract: Any,
) -> MachineWorkObservation:
    channel_id: str | None = None
    try:
        client = new_compute_client(
            contract,
            target,
            keypair=keypair,
            validator_hotkey=config.validator_hotkey,
            timeout_seconds=config.timeout_seconds,
        )
        nonce = contract.issue_nonce()
        if not isinstance(nonce, bytes) or len(nonce) != 32:
            raise _TargetRefusal("fresh_nonce_invalid")
        evidence = client.fetch_evidence(nonce)
        if evidence.kind is not contract.EvidenceKind.SEV_SNP:
            raise _TargetRefusal("evidence_kind_not_sev_snp")
        binding = evidence.channel_binding
        if (
            evidence.report_data_version != 2
            or binding is None
            or binding.binding_type is not contract.ChannelBindingType.TLS_SPKI_SHA256
            or not isinstance(binding.digest, bytes)
            or len(binding.digest) != 32
        ):
            raise _TargetRefusal("evidence_not_v2_tls_spki_bound")
        channel_id = binding.digest.hex()

        parsed = contract.parse_snp_report(evidence.quote)
        if contract.snp_generation(parsed) != config.processor_generation:
            raise _TargetRefusal("snp_processor_generation_mismatch")

        policy = contract.Policy(
            allowed_measurements=config.allowed_measurements,
            min_tcb=config.minimum_reported_tcb,
        )
        attested = contract.verify_snp(
            evidence,
            nonce,
            policy,
            snpguest_path=config.snpguest_path,
            raise_on_verifier_unavailable=True,
        )
        if (
            attested is None
            or attested.tier is not contract.Tier.CC_CPU_SNP
            or attested.chain_verified is not True
            or attested.verification_status != "VERIFIED"
        ):
            raise _TargetRefusal("snp_vendor_policy_verification_failed")

        if not bool(parsed.guest_policy & AMD_GUEST_POLICY_SINGLE_SOCKET):
            raise _TargetRefusal("amd_single_socket_guest_policy_bit_not_asserted")
        if parsed.chip_id != attested.chip_id:
            raise _TargetRefusal("snp_verified_identity_mismatch")
        try:
            raw_chip_id = bytes.fromhex(attested.chip_id)
        except (TypeError, ValueError):
            raise _TargetRefusal("snp_identity_invalid") from None
        machine_id = _hardware_pseudonym(config.review_challenge, raw_chip_id)

        confirmed = client.confirm_channel_binding(evidence)
        if confirmed != binding:
            raise _TargetRefusal("attested_channel_confirmation_failed")
        signed_access_check = getattr(
            client, "confirm_signed_validator_access_required", None
        )
        if not callable(signed_access_check):
            raise _TargetRefusal("signed_validator_access_check_unavailable")
        try:
            signed_access_check(evidence)
        except Exception:
            raise _TargetRefusal("signed_validator_access_not_required") from None

        lane = contract.SatLane(namespace=_sat_namespace(config, machine_id))
        item = lane.dispatch(target.miner_hotkey, EXPECTED_WORK_UNITS)
        result = client.do_sat_work(item)
        certificate = lane.verify(item, result)
        if certificate is None:
            raise _TargetRefusal("canonical_sat_witness_failed")
        units = lane.score(target.miner_hotkey, [certificate])
        if units != float(EXPECTED_WORK_UNITS):
            raise _TargetRefusal("canonical_sat_units_not_twenty")
        return MachineWorkObservation(
            scoring_window=config.scoring_window,
            uid=target.uid,
            miner_hotkey=target.miner_hotkey,
            endpoint=target.endpoint,
            channel_id=channel_id,
            machine_id=machine_id,
            evidence_fresh=True,
            hardware_verified=True,
            channel_bound=True,
            work_units=EXPECTED_WORK_UNITS,
        )
    except _TargetRefusal as exc:
        reason = str(exc)
    except contract.SnpVerifierUnavailable:
        reason = "snp_verifier_infrastructure_unavailable"
    except Exception:
        # No exception text crosses the preview boundary. Vendor tools and
        # clients can include raw evidence or local filesystem details.
        reason = "target_verification_failed"
    observation = MachineWorkObservation(
        scoring_window=config.scoring_window,
        uid=target.uid,
        miner_hotkey=target.miner_hotkey,
        endpoint=target.endpoint,
        channel_id=None,
        machine_id=None,
        evidence_fresh=False,
        hardware_verified=False,
        channel_bound=False,
        work_units=None,
    )
    object.__setattr__(observation, "_dev_reason", reason)
    return observation


def _review_scope(config: DevPreviewConfig) -> str:
    return hashlib.sha256(_REVIEW_SCOPE_DOMAIN + config.review_challenge).hexdigest()


def build_preview_document(
    config: DevPreviewConfig,
    observations: Sequence[MachineWorkObservation],
    *,
    score: MultiComputeScore | None = None,
    compute_commit: str,
    snpguest_digest: str,
    snpguest_version: str,
) -> dict[str, Any]:
    if score is None:
        score = aggregate_multicompute_units(
            observations, scoring_window=config.scoring_window
        )
    machine_rows: list[dict[str, Any]] = []
    for row in score.machines:
        source_reason = next(
            (
                getattr(observation, "_dev_reason", None)
                for observation in observations
                if observation.endpoint == row.endpoint
                and observation.machine_id == row.machine_id
                and observation.channel_id == row.channel_id
            ),
            None,
        )
        reasons = list(row.reasons)
        if isinstance(source_reason, str) and source_reason not in reasons:
            reasons.insert(0, source_reason)
        machine_rows.append(
            {
                "uid": row.uid,
                "miner_hotkey": row.miner_hotkey,
                "endpoint": row.endpoint,
                "tls_spki_sha256": row.channel_id,
                "hardware_identity_pseudonym": row.machine_id,
                "units": row.units,
                "reasons": reasons,
            }
        )

    expected_total = EXPECTED_WORK_UNITS * len(config.targets)
    actual_total = score.uid_units.get(config.uid, 0)
    proven = (
        len(score.machines) == len(config.targets)
        and all(row.paid for row in score.machines)
        and actual_total == expected_total
    )
    return {
        "schema": PREVIEW_SCHEMA,
        "status": STATUS if proven else NOT_PROVEN_STATUS,
        "environment": ENVIRONMENT,
        "production_eligible": False,
        "authorized_for_chain_write": False,
        "weight_signed": False,
        "weight_submitted": False,
        "burn": 0,
        "network": config.network,
        "netuid": config.netuid,
        "scoring_window": config.scoring_window,
        "review_scope_sha256": _review_scope(config),
        "validator_hotkey": config.validator_hotkey,
        "uid": config.uid,
        "miner_hotkey": config.miner_hotkey,
        "configured_target_count": len(config.targets),
        "verified_distinct_socket_count": sum(1 for row in score.machines if row.paid),
        "expected_units_per_distinct_socket": EXPECTED_WORK_UNITS,
        "raw_uid_units": actual_total,
        "all_configured_targets_passed": proven,
        "signed_validator_access_enforcement_requirement": True,
        "fresh_report_data_version_requirement": 2,
        "tls_spki_binding_requirement": "sha256",
        "amd_single_socket_guest_policy_bit_requirement": 20,
        "same_channel_canonical_sat_requirement": True,
        "compute_contract_commit": compute_commit,
        "snpguest": {
            "version": snpguest_version,
            "sha256": snpguest_digest,
        },
        "policy": {
            "processor_generation": config.processor_generation,
            "allowed_measurements": sorted(config.allowed_measurements),
            "minimum_reported_tcb": f"0x{config.minimum_reported_tcb:016x}",
            "tcb_comparison": "componentwise_by_amd_generation",
        },
        "machines": machine_rows,
    }


def collect_preview(
    config: DevPreviewConfig,
    *,
    contract_loader: Callable[[], Any] = load_compute_contract,
    keypair_loader: Callable[[DevPreviewConfig], Any] = load_validator_hotkey,
) -> dict[str, Any]:
    contract = contract_loader()
    snpguest_digest = verify_snpguest(config, contract)
    keypair = keypair_loader(config)
    observations = tuple(
        _score_target(config, target, keypair=keypair, contract=contract)
        for target in config.targets
    )
    score = aggregate_multicompute_units(
        observations, scoring_window=config.scoring_window
    )
    return build_preview_document(
        config,
        observations,
        score=score,
        compute_commit=contract.commit,
        snpguest_digest=snpguest_digest,
        snpguest_version=contract.PINNED_SNPGUEST_VERSION,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cathedral-amd-sev-snp-dev-preview", allow_abbrev=False
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    return parser


def _refusal(exc: Exception) -> dict[str, Any]:
    return {
        "status": "REFUSED_DEVELOPMENT_NO_WRITE",
        "error": str(exc),
        "environment": ENVIRONMENT,
        "production_eligible": False,
        "authorized_for_chain_write": False,
        "weight_signed": False,
        "weight_submitted": False,
        "burn": 0,
    }


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        config = load_config(Path(options.config))
        document = collect_preview(config)
        path, digest_path, digest = write_owner_only_preview(
            document, Path(options.output)
        )
    except (AmdSnpDevPreviewError, PreviewWriteError, OSError, ValueError) as exc:
        print(json.dumps(_refusal(exc), sort_keys=True), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": document["status"],
                "preview": str(path),
                "detached_sha256": str(digest_path),
                "sha256": digest,
                "environment": ENVIRONMENT,
                "production_eligible": False,
                "authorized_for_chain_write": False,
                "weight_signed": False,
                "weight_submitted": False,
                "burn": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if document["status"] == STATUS else 2


if __name__ == "__main__":
    raise SystemExit(main())
