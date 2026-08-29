"""Digest-authorized SN39 announcement for one verified Cathedral miner.

This is a narrow port of the uncommitted independent-E2E implementation from
cathedral_thin/independent_runtime/miner_axon.py in the protected
codex/independent-e2e-hardening worktree. It deliberately excludes rent,
registration, server startup, and every weight path.

The default command only creates a canonical owner-only preview. The live path
requires the exact reviewed SHA256, recollects a nonce-bound TDX quote and
canonical SAT work, rechecks finalized registration and coldkey ownership, then
permits one serve_axon call behind a durable ambiguity journal.
"""

from __future__ import annotations

import fcntl
import hashlib
import inspect
import ipaddress
import json
import os
import re
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from bittensor_wallet import Keypair

from cathedral_thin.bt_compat import listify, make_axon
from cathedral_thin.independent.compute import ComputeAdapter, QuoteVerdict
from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH
from cathedral_thin.independent.sat import SAT_WORK_UNIT_RULE

from .chain import observed_genesis_hash
from .errors import IndependentLiveError
from .https import axon_evidence_url, axon_sat_work_url
from .qvl import LAUNCH_QVL_DIGEST, load_verifier
from .run import INTEL_COLLATERAL, _try_collect, _units_after_quote, snapshot_epoch

NETWORK = "finney"
NETUID = 39
SN39_HTTPS_PORT = 8081
ANNOUNCEMENT_PERIOD_BLOCKS = 128
FINALIZED_SUCCESSOR_UID = 124
UID124_GENERATION2_ENDPOINT_IP = "35.222.166.235"
UID124_GENERATION1_PREVIEW_NAME = "miner-axon-preview-r2-20260828T1940Z.json"
UID124_GENERATION1_PREVIEW_SHA256 = (
    "27ef74f1f1f9b2cecf762dd850ebe81aa8d0ab03e42c1dc9023961cc7a89ee29"
)
UID124_GENERATION1_JOURNAL_SHA256 = (
    "b5b401ad8a1610471b15f2a75546f1ecba19c160d9cc35a361995a5274e48c8f"
)

VALIDATOR_HOTKEY = (
    "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"  # pragma: allowlist secret
)
MINER_HOTKEY = (
    "5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G"  # pragma: allowlist secret
)
CATHEDRAL_COLDKEY = (
    "5G6mgvL59o6AM8rFRYbbUpbzjjGwcVLUidpQ1vsz5UkZyw2o"  # pragma: allowlist secret
)

SECOND_MINER_HOTKEY = (
    "5Ct2DBJPULeQxGmFiKrpGvvWuYVxgYEX8tRfNjWYRga8VRbq"  # pragma: allowlist secret
)
SECOND_MINER_ENDPOINT_IP = "34.46.19.69"

PREVIEW_SCHEMA = "cathedral_sn39_miner_axon_preview_v1"
JOURNAL_SCHEMA = "cathedral_sn39_miner_axon_journal_v1"
SUCCESSOR_JOURNAL_SCHEMA = "cathedral_sn39_miner_axon_successor_journal_v1"
SUCCESSOR_JOURNAL_KIND = "finalized_successor"
SUCCESSOR_ATTEMPT_DOMAIN = "cathedral_sn39_miner_axon_successor_attempt_v1"
PREVIEW_READY = "READY_FOR_OPERATOR_REVIEW"
PREVIEW_ALREADY = "ALREADY_ANNOUNCED_NO_WRITE_REQUIRED"
AMBIGUOUS_STATUSES = frozenset(
    {
        "submission_started",
        "submission_ambiguous",
        "finalized_readback_unproven",
    }
)
FINAL_STATUSES = frozenset({"finalized_proven", "finalized_recovered"})

DEFAULT_RUNTIME_ROOT = Path("/var/lib/cathedral-validator")
DEFAULT_PREVIEW = DEFAULT_RUNTIME_ROOT / "miner-axon-preview.json"
JOURNAL_NAME = "miner-axon-announcement.json"
LOCK_NAME = ".miner-axon-announcement.lock"
MAX_DOCUMENT_BYTES = 1_048_576


@dataclass(frozen=True)
class MinerAxonContract:
    """Immutable identity and local lineage for one bounded axon writer.

    The old UID124 launch remains the default contract for compatibility. A
    second miner must use a different contract rather than changing module
    globals, sharing a journal, or inheriting UID124's consumed attempt fence.
    """

    contract_id: str
    miner_hotkey: str
    coldkey: str
    validator_hotkey: str
    runtime_root: Path
    preview_name: str
    journal_name: str
    lock_name: str
    preview_schema: str
    journal_schema: str
    endpoint_ip: str | None = None
    endpoint_port: int = SN39_HTTPS_PORT
    fixed_uid: int | None = None
    supports_legacy_successor: bool = False
    first_announcement_only: bool = False
    require_proven_success_receipt: bool = False
    successor_generation: int | None = None
    predecessor_preview_name: str | None = None
    predecessor_preview_sha256: str | None = None
    predecessor_journal_sha256: str | None = None

    @property
    def preview_path(self) -> Path:
        return self.runtime_root / self.preview_name


UID124_AXON_CONTRACT = MinerAxonContract(
    contract_id="cathedral_sn39_uid124_axon_v1",
    miner_hotkey=MINER_HOTKEY,
    coldkey=CATHEDRAL_COLDKEY,
    validator_hotkey=VALIDATOR_HOTKEY,
    runtime_root=DEFAULT_RUNTIME_ROOT,
    preview_name=DEFAULT_PREVIEW.name,
    journal_name=JOURNAL_NAME,
    lock_name=LOCK_NAME,
    preview_schema=PREVIEW_SCHEMA,
    journal_schema=JOURNAL_SCHEMA,
    supports_legacy_successor=True,
)

UID124_GENERATION2_AXON_CONTRACT = MinerAxonContract(
    contract_id="cathedral_sn39_uid124_axon_generation2_v1",
    miner_hotkey=MINER_HOTKEY,
    coldkey=CATHEDRAL_COLDKEY,
    validator_hotkey=VALIDATOR_HOTKEY,
    runtime_root=DEFAULT_RUNTIME_ROOT,
    preview_name="uid124-axon-generation2-preview.json",
    journal_name=JOURNAL_NAME,
    lock_name=LOCK_NAME,
    preview_schema="cathedral_sn39_uid124_axon_generation2_preview_v1",
    journal_schema=JOURNAL_SCHEMA,
    endpoint_ip=UID124_GENERATION2_ENDPOINT_IP,
    endpoint_port=SN39_HTTPS_PORT,
    fixed_uid=FINALIZED_SUCCESSOR_UID,
    supports_legacy_successor=True,
    require_proven_success_receipt=True,
    successor_generation=2,
    predecessor_preview_name=UID124_GENERATION1_PREVIEW_NAME,
    predecessor_preview_sha256=UID124_GENERATION1_PREVIEW_SHA256,
    predecessor_journal_sha256=UID124_GENERATION1_JOURNAL_SHA256,
)

SECOND_MINER_RUNTIME_ROOT = Path("/var/lib/cathedral-validator/second-miner-axon")
SECOND_MINER_AXON_CONTRACT = MinerAxonContract(
    contract_id="cathedral_sn39_second_miner_first_axon_v1",
    miner_hotkey=SECOND_MINER_HOTKEY,
    coldkey=CATHEDRAL_COLDKEY,
    validator_hotkey=VALIDATOR_HOTKEY,
    runtime_root=SECOND_MINER_RUNTIME_ROOT,
    preview_name="second-miner-axon-preview.json",
    journal_name="second-miner-axon-announcement.json",
    lock_name=".second-miner-axon-announcement.lock",
    preview_schema="cathedral_sn39_second_miner_axon_preview_v1",
    journal_schema="cathedral_sn39_second_miner_axon_journal_v1",
    endpoint_ip=SECOND_MINER_ENDPOINT_IP,
    first_announcement_only=True,
    require_proven_success_receipt=True,
)

_CHAIN_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, threading.Lock] = {}


class MinerAxonError(IndependentLiveError):
    """The contract refused before a chain result became uncertain."""


class MinerAxonAmbiguous(MinerAxonError):
    """A serve intent exists and must not be retried without reconciliation."""


def _contract_runtime_root(contract: MinerAxonContract) -> Path:
    """Honor the historical test/runtime override only for the UID124 path."""

    if contract is UID124_AXON_CONTRACT:
        return Path(DEFAULT_RUNTIME_ROOT)
    return Path(contract.runtime_root)


def _contract_preview_path(contract: MinerAxonContract) -> Path:
    return _contract_runtime_root(contract) / contract.preview_name


@dataclass(frozen=True)
class FinalizedMinerState:
    """The pinned miner row observed at one finalized SN39 head."""

    block_number: int
    block_hash: str
    uid: int
    hotkey: str
    coldkey: str
    ip: str
    port: int
    is_serving: bool

    def artifact(self) -> dict[str, Any]:
        return {
            "finalized_block_number": self.block_number,
            "finalized_block_hash": self.block_hash,
            "uid": self.uid,
            "hotkey": self.hotkey,
            "coldkey": self.coldkey,
            "axon": {
                "ip": self.ip,
                "port": self.port,
                "is_serving": self.is_serving,
            },
        }


@dataclass(frozen=True)
class EndpointProof:
    """Fresh TDX and canonical SAT evidence for the requested HTTPS endpoint."""

    hotkey: str
    validator_hotkey: str
    ip: str
    port: int
    qvl: str
    qvl_digest: str
    sat_units: int
    sat_rule: str
    tls_spki_sha256: str
    nonce_sha256: str
    quote_sha256: str
    report_data_sha256: str
    anchor_number: int
    anchor_hash: str

    def artifact(self) -> dict[str, Any]:
        return {
            "hotkey": self.hotkey,
            "validator_hotkey": self.validator_hotkey,
            "ip": self.ip,
            "port": self.port,
            "qvl": self.qvl,
            "qvl_digest": self.qvl_digest,
            "sat_units": self.sat_units,
            "sat_rule": self.sat_rule,
            "tls_spki_sha256": self.tls_spki_sha256,
            "nonce_sha256": self.nonce_sha256,
            "quote_sha256": self.quote_sha256,
            "report_data_sha256": self.report_data_sha256,
            "anchor_number": self.anchor_number,
            "anchor_hash": self.anchor_hash,
        }


@dataclass(frozen=True)
class _ValidatedSuccessorJournal:
    """Strict immutable and resolution state for one durable successor intent."""

    preflight: FinalizedMinerState
    stored_readback: FinalizedMinerState | None

    @property
    def minimum_readback_block(self) -> int:
        target_floor = self.preflight.block_number + 1
        if self.stored_readback is None:
            return target_floor
        return max(target_floor, self.stored_readback.block_number)


def _raw_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _strict_nonnegative_int(value: Any, *, label: str) -> int:
    raw = _raw_value(value)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise MinerAxonError(f"{label} is not a non-negative integer")
    return raw


def _canonical_hash(value: Any, *, label: str) -> str:
    try:
        if isinstance(value, str):
            text = value
        elif hasattr(value, "hex"):
            text = str(value.hex())
        else:
            text = bytes(value).hex()
    except (AttributeError, TypeError, ValueError) as exc:
        raise MinerAxonError(f"{label} is not a usable chain hash") from exc
    text = text.lower()
    if not text.startswith("0x"):
        text = "0x" + text
    if _CHAIN_HASH_RE.fullmatch(text) is None:
        raise MinerAxonError(f"{label} is not a canonical chain hash")
    return text


def _digest(value: object, *, label: str) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("sha256:"):
        text = text.removeprefix("sha256:")
    if _SHA256_RE.fullmatch(text) is None:
        raise MinerAxonError(f"{label} is not one lowercase SHA256")
    return text


def _looks_like_successor_journal(document: Mapping[str, Any]) -> bool:
    attempt_id = str(document.get("attempt_id", ""))
    return (
        document.get("schema") == SUCCESSOR_JOURNAL_SCHEMA
        or "journal_kind" in document
        or "journal_generation" in document
        or "predecessor_lineage" in document
        or attempt_id.startswith("successor-sha256:")
    )


def _require_ss58(value: object, *, label: str) -> str:
    address = str(value or "")
    try:
        parsed = str(Keypair(ss58_address=address).ss58_address)
    except Exception as exc:
        raise MinerAxonError(f"{label} is not a valid SS58 address") from exc
    if parsed != address:
        raise MinerAxonError(f"{label} is not a canonical SS58 address")
    return address


def _global_ipv4(
    value: object, *, contract: MinerAxonContract = UID124_AXON_CONTRACT
) -> str:
    if not isinstance(value, str) or not value:
        raise MinerAxonError("miner service IP must be a non-empty string")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise MinerAxonError("miner service IP is invalid") from exc
    if parsed.version != 4 or not parsed.is_global or str(parsed) != value:
        raise MinerAxonError("miner service IP must be one canonical global IPv4")
    if contract.endpoint_ip is not None and value != contract.endpoint_ip:
        raise MinerAxonError(
            f"miner service IP differs from the bounded {contract.contract_id} endpoint"
        )
    return value


def _service_port(
    value: object, *, contract: MinerAxonContract = UID124_AXON_CONTRACT
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MinerAxonError("miner service port must be an integer")
    if value != contract.endpoint_port:
        raise MinerAxonError(f"miner service port must be {contract.endpoint_port}")
    return value


def _canonical_json_bytes(document: Mapping[str, Any]) -> bytes:
    try:
        payload = (
            json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise MinerAxonError(f"document is not canonical JSON: {exc}") from exc
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise MinerAxonError("document exceeds its size bound")
    return payload


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _wallet_public_identity(
    wallet: Any, *, contract: MinerAxonContract = UID124_AXON_CONTRACT
) -> tuple[str, str]:
    public_hotkey = getattr(wallet, "hotkeypub", None)
    if public_hotkey is None:
        public_hotkey = getattr(wallet, "hotkey", None)
    hotkey = str(getattr(public_hotkey, "ss58_address", "") or "")
    coldkey = str(
        getattr(getattr(wallet, "coldkeypub", None), "ss58_address", "") or ""
    )
    _require_ss58(hotkey, label="announcement wallet public hotkey")
    _require_ss58(coldkey, label="announcement wallet coldkey")
    if hotkey != contract.miner_hotkey:
        raise MinerAxonError("announcement wallet is not the pinned Cathedral miner")
    if coldkey != contract.coldkey:
        raise MinerAxonError(
            "announcement wallet coldkey is not the pinned Cathedral coldkey"
        )
    return hotkey, coldkey


def _wallet_identity(
    wallet: Any, *, contract: MinerAxonContract = UID124_AXON_CONTRACT
) -> tuple[str, str]:
    """Require the signing hotkey only on the explicitly confirmed live path."""

    hotkey = str(getattr(getattr(wallet, "hotkey", None), "ss58_address", "") or "")
    coldkey = str(
        getattr(getattr(wallet, "coldkeypub", None), "ss58_address", "") or ""
    )
    _require_ss58(hotkey, label="announcement signing hotkey")
    _require_ss58(coldkey, label="announcement wallet coldkey")
    if hotkey != contract.miner_hotkey:
        raise MinerAxonError("announcement wallet is not the pinned Cathedral miner")
    if coldkey != contract.coldkey:
        raise MinerAxonError(
            "announcement wallet coldkey is not the pinned Cathedral coldkey"
        )
    return hotkey, coldkey


def _strict_axon_endpoint(axon: Any) -> tuple[str, int, bool]:
    raw_ip = getattr(axon, "ip", None)
    if isinstance(raw_ip, int) and not isinstance(raw_ip, bool):
        try:
            raw_ip = str(ipaddress.ip_address(raw_ip))
        except ValueError as exc:
            raise MinerAxonError("finalized axon IP is malformed") from exc
    if not isinstance(raw_ip, str) or not raw_ip:
        raise MinerAxonError("finalized axon IP is unavailable")
    try:
        parsed = ipaddress.ip_address(raw_ip)
    except ValueError as exc:
        raise MinerAxonError("finalized axon IP is malformed") from exc
    if str(parsed) != raw_ip:
        raise MinerAxonError("finalized axon IP is not canonical")
    raw_port = getattr(axon, "port", None)
    if (
        isinstance(raw_port, bool)
        or not isinstance(raw_port, int)
        or not 0 <= raw_port <= 65535
    ):
        raise MinerAxonError("finalized axon port is malformed")
    serving = getattr(axon, "is_serving", None)
    if not isinstance(serving, bool):
        raise MinerAxonError("finalized axon serving flag is malformed")
    return raw_ip, raw_port, serving


def _registered_row(
    metagraph: Any, *, contract: MinerAxonContract = UID124_AXON_CONTRACT
) -> tuple[int, str, str, Any]:
    try:
        uids = [
            _strict_nonnegative_int(value, label="miner UID")
            for value in listify(metagraph.uids)
        ]
        hotkeys = [str(value) for value in listify(metagraph.hotkeys)]
        coldkeys = [str(value) for value in listify(metagraph.coldkeys)]
        axons = list(metagraph.axons)
    except MinerAxonError:
        raise
    except Exception as exc:
        raise MinerAxonError("SN39 metagraph identity rows are malformed") from exc
    if not (len(uids) == len(hotkeys) == len(coldkeys) == len(axons)):
        raise MinerAxonError("SN39 metagraph identity rows are ragged")
    matches = [
        (uid, hotkey, coldkey, axon)
        for uid, hotkey, coldkey, axon in zip(uids, hotkeys, coldkeys, axons)
        if hotkey == contract.miner_hotkey
    ]
    if len(matches) != 1:
        raise MinerAxonError(
            "the pinned Cathedral miner is not registered exactly once on SN39"
        )
    uid, hotkey, coldkey, axon = matches[0]
    _require_ss58(hotkey, label="registered miner hotkey")
    _require_ss58(coldkey, label="registered miner coldkey")
    if coldkey != contract.coldkey:
        raise MinerAxonError(
            "the registered miner is not owned by the pinned Cathedral coldkey"
        )
    if contract.fixed_uid is not None and uid != contract.fixed_uid:
        raise MinerAxonError(
            f"the registered miner UID differs from the {contract.contract_id} pin"
        )
    return uid, hotkey, coldkey, axon


def finalized_miner_state(
    subtensor: Any, *, contract: MinerAxonContract = UID124_AXON_CONTRACT
) -> FinalizedMinerState:
    """Read the pinned miner registration and axon at one finalized head."""

    observed_genesis_hash(subtensor)
    substrate = subtensor.substrate
    try:
        block_hash = _canonical_hash(
            substrate.get_chain_finalised_head(), label="finalized head"
        )
        block_number = _strict_nonnegative_int(
            substrate.get_block_number(block_hash), label="finalized block number"
        )
        metagraph = subtensor.metagraph(NETUID, lite=True, block=block_number)
    except MinerAxonError:
        raise
    except Exception as exc:
        raise MinerAxonError(
            f"finalized SN39 metagraph is unavailable: {type(exc).__name__}"
        ) from exc
    uid, hotkey, coldkey, axon = _registered_row(metagraph, contract=contract)
    ip, port, serving = _strict_axon_endpoint(axon)
    return FinalizedMinerState(
        block_number=block_number,
        block_hash=block_hash,
        uid=uid,
        hotkey=hotkey,
        coldkey=coldkey,
        ip=ip,
        port=port,
        is_serving=serving,
    )


def collect_endpoint_proof(
    subtensor: Any,
    *,
    qvl_path: str,
    ip: str,
    port: int,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> EndpointProof:
    """Collect through the reviewed attested-SPKI transport and replay SAT.

    For an IP literal, HttpsEvidenceTransport does not authenticate the
    self-signed certificate through a CA or IP SAN. It authenticates the SPKI
    observed on the wire by requiring fresh TDX REPORT_DATA and QVL to bind it,
    then requires the canonical SAT POST to retain that same SPKI. This is not
    compatibility with an ordinary CA/hostname RemoteMiner client.
    """

    service_ip = _global_ipv4(ip, contract=contract)
    service_port = _service_port(port, contract=contract)
    observed_genesis_hash(subtensor)
    snapshot = snapshot_epoch(subtensor)
    evidence_url = axon_evidence_url(service_ip, service_port)
    sat_url = axon_sat_work_url(service_ip, service_port)
    collected_row = _try_collect(
        evidence_url,
        contract.miner_hotkey,
        contract.validator_hotkey,
        sat_url,
    )
    collected = collected_row.get("collected")
    if collected is None:
        raise MinerAxonError(
            f"miner evidence collection failed: {collected_row.get('error')}"
        )
    if collected.assigned_hotkey != contract.miner_hotkey:
        raise MinerAxonError("collected quote is assigned to a different miner")
    verifier = load_verifier(qvl_path)
    verdict = ComputeAdapter(
        verifier,
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=verifier.digest,
    ).verify_quote(collected.quote, expected_report_data=collected.report_data)
    if verdict is not QuoteVerdict.PASS:
        raise MinerAxonError("the pinned miner quote did not pass the pinned QVL")
    try:
        units = _units_after_quote(
            anchor_hash=snapshot.anchor.anchor_hash,
            collected=collected,
            sat_url=sat_url,
        )
    except Exception as exc:
        raise MinerAxonError(
            f"canonical SAT replay failed: {type(exc).__name__}: {exc}"
        ) from exc
    if isinstance(units, bool) or not isinstance(units, int) or units <= 0:
        raise MinerAxonError(
            "the pinned miner returned no positive canonical SAT units"
        )
    proof = EndpointProof(
        hotkey=contract.miner_hotkey,
        validator_hotkey=contract.validator_hotkey,
        ip=service_ip,
        port=service_port,
        qvl=verdict.value,
        qvl_digest=verifier.digest,
        sat_units=units,
        sat_rule=SAT_WORK_UNIT_RULE,
        tls_spki_sha256=collected.channel_binding.digest.hex(),
        nonce_sha256=_sha256(collected.nonce),
        quote_sha256=_sha256(collected.quote),
        report_data_sha256=_sha256(collected.report_data),
        anchor_number=snapshot.anchor.anchor_number,
        anchor_hash=snapshot.anchor.anchor_hash,
    )
    validate_endpoint_proof(proof, ip=service_ip, port=service_port, contract=contract)
    return proof


def validate_endpoint_proof(
    proof: EndpointProof,
    *,
    ip: str,
    port: int,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> EndpointProof:
    service_ip = _global_ipv4(ip, contract=contract)
    service_port = _service_port(port, contract=contract)
    if proof.hotkey != contract.miner_hotkey:
        raise MinerAxonError("endpoint proof is assigned to the wrong miner")
    if proof.validator_hotkey != contract.validator_hotkey:
        raise MinerAxonError("endpoint proof nonce is not attributed to UID30")
    if proof.ip != service_ip or proof.port != service_port:
        raise MinerAxonError("endpoint proof does not match the requested endpoint")
    if proof.qvl != QuoteVerdict.PASS.value:
        raise MinerAxonError("endpoint proof does not carry QVL PASS")
    if proof.qvl_digest != LAUNCH_QVL_DIGEST:
        raise MinerAxonError("endpoint proof does not use the launch QVL digest")
    if (
        isinstance(proof.sat_units, bool)
        or not isinstance(proof.sat_units, int)
        or proof.sat_units <= 0
        or proof.sat_rule != SAT_WORK_UNIT_RULE
    ):
        raise MinerAxonError("endpoint proof does not carry positive canonical SAT")
    for label, value in (
        ("TLS SPKI", proof.tls_spki_sha256),
        ("nonce", proof.nonce_sha256),
        ("quote", proof.quote_sha256),
        ("REPORT_DATA", proof.report_data_sha256),
    ):
        _digest(value, label=f"{label} digest")
    _strict_nonnegative_int(proof.anchor_number, label="SAT anchor number")
    _canonical_hash(proof.anchor_hash, label="SAT anchor hash")
    return proof


def _same_endpoint(state: FinalizedMinerState, *, ip: str, port: int) -> bool:
    return (state.ip, state.port, state.is_serving) == (ip, port, True)


def _require_first_announcement_posture(
    state: FinalizedMinerState,
    *,
    ip: str,
    port: int,
    contract: MinerAxonContract,
) -> None:
    """Refuse to turn a first-time contract into an unjournaled successor."""

    if not contract.first_announcement_only or _same_endpoint(state, ip=ip, port=port):
        return
    if (state.ip, state.port, state.is_serving) != ("0.0.0.0", 0, False):
        raise MinerAxonError(
            "first-time axon contract requires a canonical unannounced row; "
            "a different existing axon needs an explicit successor lineage"
        )


def _announcement_paths(
    runtime_root: Path, *, contract: MinerAxonContract = UID124_AXON_CONTRACT
) -> tuple[Path, Path]:
    root = Path(runtime_root)
    if not root.is_absolute():
        raise MinerAxonError("runtime root must be absolute")
    return root / contract.lock_name, root / contract.journal_name


def _successor_contract_artifact(
    runtime_root: Path, *, contract: MinerAxonContract
) -> dict[str, Any] | None:
    """Describe an exact pinned predecessor without making it configurable."""

    generation = contract.successor_generation
    if generation is None:
        return None
    if generation != 2:
        raise MinerAxonError("dedicated successor generation is not bounded to two")
    if (
        contract.predecessor_preview_name is None
        or contract.predecessor_preview_sha256 is None
        or contract.predecessor_journal_sha256 is None
    ):
        raise MinerAxonError("dedicated successor predecessor pins are incomplete")
    preview_digest = _digest(
        contract.predecessor_preview_sha256,
        label="pinned predecessor preview digest",
    )
    journal_digest = _digest(
        contract.predecessor_journal_sha256,
        label="pinned predecessor journal digest",
    )
    predecessor_preview = runtime_root / contract.predecessor_preview_name
    _, predecessor_journal = _announcement_paths(runtime_root, contract=contract)
    return {
        "journal_generation": generation,
        "predecessor_preview": str(predecessor_preview),
        "predecessor_preview_sha256": "sha256:" + preview_digest,
        "predecessor_journal": str(predecessor_journal),
        "predecessor_journal_sha256": "sha256:" + journal_digest,
        "replacement_limit": "exactly_one_generation_2_attempt",
    }


def build_preview(
    *,
    state: FinalizedMinerState,
    proof: EndpointProof,
    runtime_root: Path | None = None,
    created_at: str | None = None,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> dict[str, Any]:
    """Build the review artifact. This function signs and submits nothing."""

    root = (
        _contract_runtime_root(contract) if runtime_root is None else Path(runtime_root)
    )
    if state.hotkey != contract.miner_hotkey or state.coldkey != contract.coldkey:
        raise MinerAxonError("finalized miner identity differs from the launch pins")
    if contract.fixed_uid is not None and state.uid != contract.fixed_uid:
        raise MinerAxonError("finalized miner UID differs from the launch pin")
    validate_endpoint_proof(proof, ip=proof.ip, port=proof.port, contract=contract)
    lock_path, journal_path = _announcement_paths(root, contract=contract)
    _require_first_announcement_posture(
        state, ip=proof.ip, port=proof.port, contract=contract
    )
    already = _same_endpoint(state, ip=proof.ip, port=proof.port)
    document: dict[str, Any] = {
        "schema": contract.preview_schema,
        "status": PREVIEW_ALREADY if already else PREVIEW_READY,
        "created_at": created_at
        or datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "network": {
            "name": NETWORK,
            "netuid": NETUID,
            "genesis_hash": FINNEY_GENESIS_HASH,
        },
        "miner": {
            "uid": state.uid,
            "hotkey": contract.miner_hotkey,
            "coldkey": contract.coldkey,
        },
        "requested_endpoint": {
            "ip": proof.ip,
            "port": proof.port,
            "protocol": "https",
        },
        "chain_at_preview": state.artifact(),
        "endpoint_proof": proof.artifact(),
        "chain_action": {
            "call": "SubtensorModule.serve_axon",
            "period_blocks": ANNOUNCEMENT_PERIOD_BLOCKS,
            "would_replace_current": not already,
            "extrinsic_built": False,
            "signed": False,
            "serve_axon_called": False,
            "submitted": False,
            "finalized_readback": None,
            "rent_called": False,
            "registration_called": False,
            "registration_burn_tao": "0.0",
            "weights_called": False,
            "maximum_serve_axon_attempts": 1,
            "transaction_fee": "NOT_ESTIMATED_BY_THIS_ARTIFACT",
        },
        "local_state": {
            "runtime_root": str(root),
            "announcement_lock": str(lock_path),
            "ambiguity_journal": str(journal_path),
            "remote_exclusivity": "operator_assertion_required",
        },
        "trust_boundary": {
            "qvl_binary_sha256": LAUNCH_QVL_DIGEST,
            "quote_binds": ["fresh_nonce", "miner_hotkey", "tls_spki"],
            "collector_validator_hotkey": contract.validator_hotkey,
            "sat_rule": SAT_WORK_UNIT_RULE,
            "fresh_evidence_recollected_before_submission": True,
            "tls_authentication": "tdx_report_data_binds_observed_spki",
            "ip_literal_ca_hostname_validation": "NOT_USED",
            "ordinary_remote_miner_ca_path": "OUT_OF_SCOPE_INCOMPATIBLE",
            "oci_image_digest": "NOT_PROVEN_BY_THIS_VALIDATOR_ARTIFACT",
            "serve_axon_signer": "pinned_miner_hotkey",
            "coldkey_check": "public_ownership_only",
        },
    }
    successor_contract = _successor_contract_artifact(root, contract=contract)
    if successor_contract is not None:
        document["successor_contract"] = successor_contract
    return validate_preview(document, contract=contract)


def validate_preview(
    document: Mapping[str, Any],
    *,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> dict[str, Any]:
    preview = dict(document)
    expected_top = {
        "schema",
        "status",
        "created_at",
        "network",
        "miner",
        "requested_endpoint",
        "chain_at_preview",
        "endpoint_proof",
        "chain_action",
        "local_state",
        "trust_boundary",
    }
    if contract.successor_generation is not None:
        expected_top.add("successor_contract")
    if set(preview) != expected_top:
        raise MinerAxonError("preview top-level fields differ from the launch schema")
    if preview.get("schema") != contract.preview_schema:
        raise MinerAxonError("preview schema differs from the launch pin")
    if preview.get("status") not in {PREVIEW_READY, PREVIEW_ALREADY}:
        raise MinerAxonError("preview status differs from the launch contract")
    if not isinstance(preview.get("created_at"), str) or not str(
        preview["created_at"]
    ).endswith("Z"):
        raise MinerAxonError("preview timestamp is not canonical UTC")
    network = preview.get("network")
    miner = preview.get("miner")
    requested = preview.get("requested_endpoint")
    chain = preview.get("chain_at_preview")
    proof = preview.get("endpoint_proof")
    action = preview.get("chain_action")
    local = preview.get("local_state")
    trust = preview.get("trust_boundary")
    if not all(
        isinstance(value, Mapping)
        for value in (network, miner, requested, chain, proof, action, local, trust)
    ):
        raise MinerAxonError("preview is missing a required object")
    assert isinstance(network, Mapping)
    assert isinstance(miner, Mapping)
    assert isinstance(requested, Mapping)
    assert isinstance(chain, Mapping)
    assert isinstance(proof, Mapping)
    assert isinstance(action, Mapping)
    assert isinstance(local, Mapping)
    assert isinstance(trust, Mapping)
    if dict(network) != {
        "name": NETWORK,
        "netuid": NETUID,
        "genesis_hash": FINNEY_GENESIS_HASH,
    }:
        raise MinerAxonError("preview network is not pinned Finney SN39")
    uid = _strict_nonnegative_int(miner.get("uid"), label="preview miner UID")
    if dict(miner) != {
        "uid": uid,
        "hotkey": contract.miner_hotkey,
        "coldkey": contract.coldkey,
    }:
        raise MinerAxonError("preview miner identity differs from the Cathedral pins")
    if contract.fixed_uid is not None and uid != contract.fixed_uid:
        raise MinerAxonError("preview miner UID differs from the launch pin")
    ip = _global_ipv4(requested.get("ip"), contract=contract)
    port = _service_port(requested.get("port"), contract=contract)
    if dict(requested) != {"ip": ip, "port": port, "protocol": "https"}:
        raise MinerAxonError("preview endpoint differs from the HTTPS launch contract")
    if (
        chain.get("uid") != uid
        or chain.get("hotkey") != contract.miner_hotkey
        or chain.get("coldkey") != contract.coldkey
    ):
        raise MinerAxonError("preview finalized registration differs from the pins")
    if set(chain) != {
        "finalized_block_number",
        "finalized_block_hash",
        "uid",
        "hotkey",
        "coldkey",
        "axon",
    }:
        raise MinerAxonError("preview finalized registration fields differ from schema")
    _strict_nonnegative_int(
        chain.get("finalized_block_number"), label="preview finalized block"
    )
    _canonical_hash(
        chain.get("finalized_block_hash"), label="preview finalized block hash"
    )
    current_axon = chain.get("axon")
    if not isinstance(current_axon, Mapping):
        raise MinerAxonError("preview has no finalized axon row")
    if set(current_axon) != {"ip", "port", "is_serving"}:
        raise MinerAxonError("preview finalized axon fields differ from schema")
    current_ip = str(current_axon.get("ip", ""))
    try:
        if str(ipaddress.ip_address(current_ip)) != current_ip:
            raise ValueError
    except ValueError as exc:
        raise MinerAxonError("preview finalized axon IP is not canonical") from exc
    current_port = _strict_nonnegative_int(
        current_axon.get("port"), label="preview finalized axon port"
    )
    if current_port > 65535 or not isinstance(current_axon.get("is_serving"), bool):
        raise MinerAxonError("preview finalized axon row is malformed")
    current_state = FinalizedMinerState(
        block_number=_strict_nonnegative_int(
            chain.get("finalized_block_number"), label="preview finalized block"
        ),
        block_hash=_canonical_hash(
            chain.get("finalized_block_hash"), label="preview finalized block hash"
        ),
        uid=uid,
        hotkey=contract.miner_hotkey,
        coldkey=contract.coldkey,
        ip=current_ip,
        port=current_port,
        is_serving=current_axon["is_serving"],
    )
    _require_first_announcement_posture(
        current_state, ip=ip, port=port, contract=contract
    )
    proof_object = EndpointProof(
        hotkey=str(proof.get("hotkey", "")),
        validator_hotkey=str(proof.get("validator_hotkey", "")),
        ip=str(proof.get("ip", "")),
        port=proof.get("port"),  # type: ignore[arg-type]
        qvl=str(proof.get("qvl", "")),
        qvl_digest=str(proof.get("qvl_digest", "")),
        sat_units=proof.get("sat_units"),  # type: ignore[arg-type]
        sat_rule=str(proof.get("sat_rule", "")),
        tls_spki_sha256=str(proof.get("tls_spki_sha256", "")),
        nonce_sha256=str(proof.get("nonce_sha256", "")),
        quote_sha256=str(proof.get("quote_sha256", "")),
        report_data_sha256=str(proof.get("report_data_sha256", "")),
        anchor_number=proof.get("anchor_number"),  # type: ignore[arg-type]
        anchor_hash=str(proof.get("anchor_hash", "")),
    )
    validate_endpoint_proof(proof_object, ip=ip, port=port, contract=contract)
    if set(proof) != set(proof_object.artifact()):
        raise MinerAxonError("preview endpoint proof fields differ from the schema")
    already = (current_ip, current_port, current_axon["is_serving"]) == (
        ip,
        port,
        True,
    )
    if preview["status"] != (PREVIEW_ALREADY if already else PREVIEW_READY):
        raise MinerAxonError("preview status disagrees with the finalized axon")
    if dict(action) != {
        "call": "SubtensorModule.serve_axon",
        "period_blocks": ANNOUNCEMENT_PERIOD_BLOCKS,
        "would_replace_current": not already,
        "extrinsic_built": False,
        "signed": False,
        "serve_axon_called": False,
        "submitted": False,
        "finalized_readback": None,
        "rent_called": False,
        "registration_called": False,
        "registration_burn_tao": "0.0",
        "weights_called": False,
        "maximum_serve_axon_attempts": 1,
        "transaction_fee": "NOT_ESTIMATED_BY_THIS_ARTIFACT",
    }:
        raise MinerAxonError("preview does not prove the exact no-write posture")
    runtime_root = Path(str(local.get("runtime_root", "")))
    lock_path, journal_path = _announcement_paths(runtime_root, contract=contract)
    if dict(local) != {
        "runtime_root": str(runtime_root),
        "announcement_lock": str(lock_path),
        "ambiguity_journal": str(journal_path),
        "remote_exclusivity": "operator_assertion_required",
    }:
        raise MinerAxonError("preview local-state boundary differs from the launch pin")
    if dict(trust) != {
        "qvl_binary_sha256": LAUNCH_QVL_DIGEST,
        "quote_binds": ["fresh_nonce", "miner_hotkey", "tls_spki"],
        "collector_validator_hotkey": contract.validator_hotkey,
        "sat_rule": SAT_WORK_UNIT_RULE,
        "fresh_evidence_recollected_before_submission": True,
        "tls_authentication": "tdx_report_data_binds_observed_spki",
        "ip_literal_ca_hostname_validation": "NOT_USED",
        "ordinary_remote_miner_ca_path": "OUT_OF_SCOPE_INCOMPATIBLE",
        "oci_image_digest": "NOT_PROVEN_BY_THIS_VALIDATOR_ARTIFACT",
        "serve_axon_signer": "pinned_miner_hotkey",
        "coldkey_check": "public_ownership_only",
    }:
        raise MinerAxonError("preview trust boundary differs from the launch pin")
    if contract.successor_generation is not None:
        successor_contract = preview.get("successor_contract")
        if not isinstance(successor_contract, Mapping) or dict(
            successor_contract
        ) != _successor_contract_artifact(runtime_root, contract=contract):
            raise MinerAxonError(
                "preview successor lineage differs from the exact predecessor pins"
            )
    return preview


def _check_owner_parent(parent: Path, *, create: bool) -> None:
    try:
        if create:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = parent.lstat()
    except OSError as exc:
        raise MinerAxonError(
            f"owner-controlled directory is unavailable: {parent}"
        ) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise MinerAxonError(
            f"directory must be owned by this user and not group/world writable: {parent}"
        )


def _require_owner_only_file(path: Path, *, max_bytes: int) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise MinerAxonError(f"owner-only file is unavailable: {path}") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > max_bytes
    ):
        raise MinerAxonError(f"file must be owner-controlled mode 0600: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MinerAxonError(f"owner-only file could not be opened: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise MinerAxonError("owner-only file changed while opening")
        data = os.read(descriptor, max_bytes + 1)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino)
            or after.st_size != info.st_size
            or len(data) != after.st_size
        ):
            raise MinerAxonError("owner-only file changed while reading")
    finally:
        os.close(descriptor)
    if len(data) > max_bytes:
        raise MinerAxonError("owner-only file exceeds its size bound")
    return data


def _write_exclusive_owner_only(path: Path, data: bytes) -> None:
    _check_owner_parent(path.parent, create=True)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise MinerAxonError(f"refusing to overwrite launch artifact {path}") from exc
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise MinerAxonError("launch artifact write was short")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_preview(
    document: Mapping[str, Any],
    path: Path | str,
    *,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> tuple[Path, Path, str]:
    """Create immutable owner-only canonical JSON plus a detached SHA256."""

    validated = validate_preview(document, contract=contract)
    target = Path(path)
    if not target.is_absolute():
        raise MinerAxonError("preview output path must be absolute")
    digest_path = target.with_suffix(target.suffix + ".sha256")
    payload = _canonical_json_bytes(validated)
    digest = _sha256(payload)
    _write_exclusive_owner_only(target, payload)
    _write_exclusive_owner_only(digest_path, (digest + "\n").encode("ascii"))
    return target, digest_path, digest


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise MinerAxonError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MinerAxonError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise MinerAxonError(f"{label} is not a JSON object")
    if _canonical_json_bytes(document) != raw:
        raise MinerAxonError(f"{label} bytes are not canonical JSON")
    return document


def load_reviewed_preview(
    path: Path | str,
    *,
    reviewed_sha256: str,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> tuple[dict[str, Any], str]:
    target = Path(path)
    supplied = _digest(reviewed_sha256, label="reviewed preview digest")
    raw = _require_owner_only_file(target, max_bytes=MAX_DOCUMENT_BYTES)
    if _sha256(raw) != supplied:
        raise MinerAxonError("reviewed digest does not match the preview bytes")
    detached_path = target.with_suffix(target.suffix + ".sha256")
    detached_raw = _require_owner_only_file(detached_path, max_bytes=128)
    try:
        detached = _digest(
            detached_raw.decode("ascii"), label="detached preview digest"
        )
    except UnicodeDecodeError as exc:
        raise MinerAxonError("detached preview digest is not ASCII") from exc
    if detached != supplied:
        raise MinerAxonError("detached preview digest differs from reviewed digest")
    preview = validate_preview(_strict_json(raw, label="preview"), contract=contract)
    return preview, supplied


def _write_state(path: Path, document: Mapping[str, Any], *, exclusive: bool) -> None:
    """Durably create or replace one owner-only canonical state document."""

    _check_owner_parent(path.parent, create=False)
    if not exclusive:
        _require_owner_only_file(path, max_bytes=MAX_DOCUMENT_BYTES)
    payload = _canonical_json_bytes(document)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise MinerAxonError("an announcement journal already exists") from exc
            temporary.unlink()
        else:
            os.replace(temporary, path)
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _load_journal(
    path: Path, *, contract: MinerAxonContract = UID124_AXON_CONTRACT
) -> dict[str, Any] | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise MinerAxonAmbiguous(
            "announcement journal path is unreadable; preserve it and do not retry"
        ) from exc
    try:
        raw = _require_owner_only_file(path, max_bytes=MAX_DOCUMENT_BYTES)
        journal = _strict_json(raw, label="announcement journal")
    except MinerAxonError as exc:
        raise MinerAxonAmbiguous(
            "existing announcement journal is unreadable; preserve it and do not retry"
        ) from exc
    accepted_schemas = {contract.journal_schema}
    if contract.supports_legacy_successor:
        accepted_schemas.add(SUCCESSOR_JOURNAL_SCHEMA)
    if journal.get("schema") not in accepted_schemas:
        raise MinerAxonAmbiguous(
            "existing announcement journal schema is unrecognized; preserve it and do not retry"
        )
    return journal


def _local_lock(path: Path) -> threading.Lock:
    key = str(path.absolute())
    with _LOCAL_LOCKS_GUARD:
        return _LOCAL_LOCKS.setdefault(key, threading.Lock())


@contextmanager
def _announcement_lock(
    runtime_root: Path, *, contract: MinerAxonContract = UID124_AXON_CONTRACT
) -> Iterator[None]:
    lock_path, _ = _announcement_paths(runtime_root, contract=contract)
    _check_owner_parent(lock_path.parent, create=False)
    local = _local_lock(lock_path)
    if not local.acquire(blocking=False):
        raise MinerAxonError("another local miner announcement is active")
    descriptor: int | None = None
    locked = False
    try:
        flags = (
            os.O_CREAT
            | os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(lock_path, flags, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise MinerAxonError("announcement lock is not owner-only mode 0600")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError as exc:
            raise MinerAxonError("another process holds the announcement lock") from exc
        yield
    finally:
        if descriptor is not None:
            try:
                if locked:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        local.release()


def _current_matches_preview(
    state: FinalizedMinerState,
    preview: Mapping[str, Any],
    *,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> None:
    miner = preview["miner"]
    chain = preview["chain_at_preview"]
    assert isinstance(miner, Mapping)
    assert isinstance(chain, Mapping)
    preview_block = _strict_nonnegative_int(
        chain.get("finalized_block_number"), label="preview finalized block"
    )
    if state.block_number < preview_block:
        raise MinerAxonError("finalized chain head is older than the reviewed preview")
    if (
        state.uid != miner["uid"]
        or state.hotkey != contract.miner_hotkey
        or state.coldkey != contract.coldkey
    ):
        raise MinerAxonError("finalized miner registration changed after preview")
    current = chain["axon"]
    assert isinstance(current, Mapping)
    if (state.ip, state.port, state.is_serving) != (
        current["ip"],
        current["port"],
        current["is_serving"],
    ):
        raise MinerAxonError("finalized miner axon changed after preview")


def _fresh_matches_preview(
    fresh: EndpointProof,
    preview: Mapping[str, Any],
    *,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> None:
    requested = preview["requested_endpoint"]
    reviewed = preview["endpoint_proof"]
    assert isinstance(requested, Mapping)
    assert isinstance(reviewed, Mapping)
    validate_endpoint_proof(
        fresh,
        ip=str(requested["ip"]),
        port=int(requested["port"]),
        contract=contract,
    )
    for key in (
        "hotkey",
        "validator_hotkey",
        "ip",
        "port",
        "qvl",
        "qvl_digest",
        "tls_spki_sha256",
    ):
        if fresh.artifact()[key] != reviewed[key]:
            raise MinerAxonError(
                f"fresh endpoint {key} differs from the reviewed preview"
            )


def _receipt_fields(response: Any) -> dict[str, Any]:
    receipt = getattr(response, "extrinsic_receipt", None)

    def optional_hash(value: Any, *, label: str) -> str | None:
        if value is None:
            return None
        return _canonical_hash(value, label=label)

    block_number_raw = getattr(receipt, "block_number", None)
    block_number = (
        None
        if block_number_raw is None
        else _strict_nonnegative_int(block_number_raw, label="receipt block number")
    )
    return {
        "extrinsic_hash": optional_hash(
            getattr(receipt, "extrinsic_hash", None)
            or getattr(response, "extrinsic_hash", None),
            label="receipt extrinsic hash",
        ),
        "block_hash": optional_hash(
            getattr(receipt, "block_hash", None), label="receipt block hash"
        ),
        "block_number": block_number,
        "success": getattr(response, "success", None) is True,
    }


def _finalized_readback(
    subtensor: Any,
    *,
    ip: str,
    port: int,
    receipt: Mapping[str, Any] | None = None,
    state_loader: Callable[[Any], FinalizedMinerState] = finalized_miner_state,
    minimum_block_number: int | None = None,
    receipt_after_block_number: int | None = None,
    require_canonical_state: bool = False,
) -> Mapping[str, Any]:
    state = state_loader(subtensor)
    if not _same_endpoint(state, ip=ip, port=port):
        raise MinerAxonAmbiguous(
            "finalized SN39 axon differs from the authorized HTTPS endpoint"
        )
    if minimum_block_number is not None and state.block_number < minimum_block_number:
        raise MinerAxonAmbiguous("finalized successor readback predates its preflight")
    if require_canonical_state:
        try:
            _canonical_state_block(
                subtensor, state, label="successor finalized readback"
            )
        except MinerAxonError as exc:
            raise MinerAxonAmbiguous(
                "successor finalized readback block is not canonical"
            ) from exc
    if receipt is not None and receipt.get("block_number") is not None:
        receipt_number = _strict_nonnegative_int(
            receipt["block_number"], label="receipt block number"
        )
        receipt_floor = (
            minimum_block_number
            if receipt_after_block_number is None
            else receipt_after_block_number
        )
        if receipt_floor is not None and receipt_number <= receipt_floor:
            raise MinerAxonAmbiguous(
                "successor receipt does not postdate its finalized preflight"
            )
        if receipt_number > state.block_number:
            raise MinerAxonAmbiguous("receipt block is not finalized")
        receipt_hash = receipt.get("block_hash")
        if receipt_hash is not None:
            try:
                canonical = _canonical_hash(
                    subtensor.substrate.get_block_hash(receipt_number),
                    label="canonical receipt block hash",
                )
            except Exception as exc:
                raise MinerAxonAmbiguous(
                    "receipt block could not be resolved on the finalized chain"
                ) from exc
            if canonical != receipt_hash:
                raise MinerAxonAmbiguous(
                    "receipt block is not canonical on the finalized chain"
                )
    return state.artifact()


def _journal_identity(
    *,
    preview: Mapping[str, Any],
    preview_sha256: str,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> dict[str, Any]:
    requested = preview["requested_endpoint"]
    miner = preview["miner"]
    assert isinstance(requested, Mapping)
    assert isinstance(miner, Mapping)
    return {
        "network": NETWORK,
        "netuid": NETUID,
        "preview_sha256": "sha256:" + preview_sha256,
        "uid": miner["uid"],
        "hotkey": contract.miner_hotkey,
        "coldkey": contract.coldkey,
        "ip": requested["ip"],
        "port": requested["port"],
    }


def _state_from_artifact(
    value: object,
    *,
    label: str,
    require_serving: bool = False,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> FinalizedMinerState:
    """Parse one exact finalized miner artifact without trusting journal fields."""

    if not isinstance(value, Mapping):
        raise MinerAxonError(f"{label} is not a finalized miner state")
    if set(value) != {
        "finalized_block_number",
        "finalized_block_hash",
        "uid",
        "hotkey",
        "coldkey",
        "axon",
    }:
        raise MinerAxonError(f"{label} fields differ from the finalized-state schema")
    uid = _strict_nonnegative_int(value.get("uid"), label=f"{label} UID")
    hotkey = _require_ss58(value.get("hotkey"), label=f"{label} hotkey")
    coldkey = _require_ss58(value.get("coldkey"), label=f"{label} coldkey")
    if (
        hotkey != contract.miner_hotkey
        or coldkey != contract.coldkey
        or (contract.fixed_uid is not None and uid != contract.fixed_uid)
    ):
        raise MinerAxonError(f"{label} identity differs from the Cathedral pins")
    axon = value.get("axon")
    if not isinstance(axon, Mapping) or set(axon) != {"ip", "port", "is_serving"}:
        raise MinerAxonError(f"{label} axon fields differ from the schema")
    ip = str(axon.get("ip", ""))
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise MinerAxonError(f"{label} axon IP is malformed") from exc
    if parsed_ip.version != 4 or str(parsed_ip) != ip:
        raise MinerAxonError(f"{label} axon IP is not canonical IPv4")
    port = _strict_nonnegative_int(axon.get("port"), label=f"{label} axon port")
    serving = axon.get("is_serving")
    if port > 65535 or not isinstance(serving, bool):
        raise MinerAxonError(f"{label} axon row is malformed")
    if require_serving and not serving:
        raise MinerAxonError(f"{label} does not prove a serving axon")
    return FinalizedMinerState(
        block_number=_strict_nonnegative_int(
            value.get("finalized_block_number"), label=f"{label} block number"
        ),
        block_hash=_canonical_hash(
            value.get("finalized_block_hash"), label=f"{label} block hash"
        ),
        uid=uid,
        hotkey=hotkey,
        coldkey=coldkey,
        ip=ip,
        port=port,
        is_serving=serving,
    )


def _endpoint_proof_from_artifact(
    value: object,
    *,
    label: str,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> EndpointProof:
    if not isinstance(value, Mapping):
        raise MinerAxonError(f"{label} is not an endpoint proof")
    proof = EndpointProof(
        hotkey=str(value.get("hotkey", "")),
        validator_hotkey=str(value.get("validator_hotkey", "")),
        ip=str(value.get("ip", "")),
        port=value.get("port"),  # type: ignore[arg-type]
        qvl=str(value.get("qvl", "")),
        qvl_digest=str(value.get("qvl_digest", "")),
        sat_units=value.get("sat_units"),  # type: ignore[arg-type]
        sat_rule=str(value.get("sat_rule", "")),
        tls_spki_sha256=str(value.get("tls_spki_sha256", "")),
        nonce_sha256=str(value.get("nonce_sha256", "")),
        quote_sha256=str(value.get("quote_sha256", "")),
        report_data_sha256=str(value.get("report_data_sha256", "")),
        anchor_number=value.get("anchor_number"),  # type: ignore[arg-type]
        anchor_hash=str(value.get("anchor_hash", "")),
    )
    if set(value) != set(proof.artifact()):
        raise MinerAxonError(f"{label} fields differ from the endpoint-proof schema")
    return validate_endpoint_proof(
        proof, ip=proof.ip, port=proof.port, contract=contract
    )


def _validated_receipt(
    value: object, *, required_success: bool, label: str = "predecessor"
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "extrinsic_hash",
        "block_hash",
        "block_number",
        "success",
    }:
        raise MinerAxonError(f"{label} receipt fields differ from the SDK schema")
    for key in ("extrinsic_hash", "block_hash"):
        if value[key] is not None:
            _canonical_hash(value[key], label=f"{label} receipt {key}")
    if value["block_number"] is not None:
        _strict_nonnegative_int(
            value["block_number"], label=f"{label} receipt block number"
        )
    if not isinstance(value["success"], bool):
        raise MinerAxonError(f"{label} receipt success is not boolean")
    if required_success and value["success"] is not True:
        raise MinerAxonError(f"finalized {label} receipt is not successful")
    return value


def _validated_first_announcement_receipt(
    value: object, *, preflight: FinalizedMinerState
) -> Mapping[str, Any]:
    receipt = _validated_receipt(
        value, required_success=True, label="first-announcement"
    )
    if any(
        receipt[key] is None for key in ("extrinsic_hash", "block_hash", "block_number")
    ):
        raise MinerAxonError(
            "successful first-announcement receipt lacks finalized inclusion fields"
        )
    block_number = _strict_nonnegative_int(
        receipt["block_number"], label="first-announcement receipt block number"
    )
    if block_number <= preflight.block_number:
        raise MinerAxonError(
            "successful first-announcement receipt does not postdate preflight"
        )
    return receipt


def _validated_final_predecessor(
    journal: Mapping[str, Any],
    *,
    preview: Mapping[str, Any] | None = None,
    preview_sha256: str | None = None,
) -> tuple[FinalizedMinerState, str]:
    """Require a complete, unambiguous first-generation finalized journal."""

    if _looks_like_successor_journal(journal):
        raise MinerAxonError("the bounded finalized successor was already consumed")
    expected_fields = {
        "schema",
        "status",
        "attempt_id",
        "identity",
        "preflight",
        "fresh_endpoint_proof",
        "remote_exclusive_announcer_asserted",
        "serve_axon_call_authorized",
        "serve_axon_outcome",
        "receipt",
        "readback",
        "retry_allowed",
    }
    if set(journal) != expected_fields or journal.get("schema") != JOURNAL_SCHEMA:
        raise MinerAxonError("predecessor journal fields differ from the launch schema")
    status = journal.get("status")
    if status not in FINAL_STATUSES:
        raise MinerAxonError("predecessor announcement is not finalized and proven")
    if (
        journal.get("retry_allowed") is not False
        or journal.get("remote_exclusive_announcer_asserted") is not True
        or journal.get("serve_axon_call_authorized") is not True
    ):
        raise MinerAxonError(
            "predecessor journal does not retain the one-attempt fence"
        )
    identity = journal.get("identity")
    if not isinstance(identity, Mapping):
        raise MinerAxonError("predecessor journal identity is missing")
    if preview is not None and preview_sha256 is not None:
        if dict(identity) != _journal_identity(
            preview=preview, preview_sha256=preview_sha256
        ):
            raise MinerAxonError(
                "predecessor journal differs from its reviewed preview"
            )
    expected_attempt = "sha256:" + _sha256(_canonical_json_bytes(dict(identity)))
    if journal.get("attempt_id") != expected_attempt:
        raise MinerAxonError("predecessor attempt ID is not derived from its identity")
    expected_identity = {
        "network": NETWORK,
        "netuid": NETUID,
        "preview_sha256": identity.get("preview_sha256"),
        "uid": identity.get("uid"),
        "hotkey": identity.get("hotkey"),
        "coldkey": identity.get("coldkey"),
        "ip": identity.get("ip"),
        "port": identity.get("port"),
    }
    if dict(identity) != expected_identity:
        raise MinerAxonError(
            "predecessor identity fields differ from the launch schema"
        )
    _digest(identity.get("preview_sha256"), label="predecessor preview digest")
    if (
        identity.get("network") != NETWORK
        or identity.get("netuid") != NETUID
        or identity.get("hotkey") != MINER_HOTKEY
        or identity.get("coldkey") != CATHEDRAL_COLDKEY
    ):
        raise MinerAxonError("predecessor identity differs from the Cathedral pins")
    uid = _strict_nonnegative_int(identity.get("uid"), label="predecessor UID")
    if uid != FINALIZED_SUCCESSOR_UID:
        raise MinerAxonError(
            f"finalized successor is pinned to miner UID {FINALIZED_SUCCESSOR_UID}"
        )
    ip = _global_ipv4(identity.get("ip"))
    port = _service_port(identity.get("port"))
    preflight = _state_from_artifact(
        journal.get("preflight"), label="predecessor preflight"
    )
    proof = _endpoint_proof_from_artifact(
        journal.get("fresh_endpoint_proof"), label="predecessor endpoint proof"
    )
    readback = _state_from_artifact(
        journal.get("readback"),
        label="predecessor finalized readback",
        require_serving=True,
    )
    if any(
        state.uid != uid
        or state.hotkey != MINER_HOTKEY
        or state.coldkey != CATHEDRAL_COLDKEY
        for state in (preflight, readback)
    ):
        raise MinerAxonError("predecessor state identity differs from its journal")
    if preview is not None:
        _current_matches_preview(preflight, preview)
    if (proof.ip, proof.port) != (ip, port):
        raise MinerAxonError("predecessor proof endpoint differs from its identity")
    if (preflight.ip, preflight.port, preflight.is_serving) == (ip, port, True):
        raise MinerAxonError("predecessor preflight already has its identity endpoint")
    if preview is not None:
        _fresh_matches_preview(proof, preview)
    if (readback.ip, readback.port, readback.is_serving) != (ip, port, True):
        raise MinerAxonError("predecessor readback differs from its identity endpoint")
    if readback.block_number <= preflight.block_number:
        raise MinerAxonError("predecessor readback does not postdate its preflight")
    receipt = journal.get("receipt")
    if status == "finalized_proven":
        if journal.get("serve_axon_outcome") != "SUCCESS":
            raise MinerAxonError("finalized predecessor outcome is not SUCCESS")
        validated_receipt = _validated_receipt(receipt, required_success=True)
    else:
        if journal.get("serve_axon_outcome") != "FINALIZED_BY_READBACK":
            raise MinerAxonError("recovered predecessor outcome is not exact")
        if receipt is not None:
            validated_receipt = _validated_receipt(receipt, required_success=False)
        else:
            validated_receipt = None
    if (
        validated_receipt is not None
        and validated_receipt["block_number"] is not None
        and validated_receipt["block_number"] > readback.block_number
    ):
        raise MinerAxonError("predecessor receipt postdates its finalized readback")
    return readback, expected_attempt


def _validated_predecessor_lineage(
    journal: Mapping[str, Any],
) -> FinalizedMinerState:
    """Return the immediate finalized predecessor for generation one or two."""

    if "predecessor_lineage" not in journal:
        raise MinerAxonError("successor predecessor lineage is missing")
    generation = _strict_nonnegative_int(
        journal.get("journal_generation"), label="successor journal generation"
    )
    if generation not in {1, 2}:
        raise MinerAxonError("successor journal generation is outside the bounded set")
    lineage = journal.get("predecessor_lineage")
    if not isinstance(lineage, Mapping) or set(lineage) != {
        "generation",
        "journal_sha256",
        "journal",
    }:
        raise MinerAxonError("successor predecessor lineage fields differ from schema")
    if lineage.get("generation") != generation:
        raise MinerAxonError("successor predecessor generation disagrees with journal")
    predecessor = lineage.get("journal")
    if not isinstance(predecessor, Mapping):
        raise MinerAxonError("successor predecessor journal is missing")
    expected = _digest(
        lineage.get("journal_sha256"), label="predecessor journal digest"
    )
    if _sha256(_canonical_json_bytes(dict(predecessor))) != expected:
        raise MinerAxonError("embedded predecessor journal digest does not match")
    if generation == 1:
        readback, _ = _validated_final_predecessor(predecessor)
        return readback
    if predecessor.get("journal_generation") != 1:
        raise MinerAxonError(
            "generation-2 predecessor is not the exact generation-1 journal"
        )
    validated = _validated_successor_journal(predecessor)
    if predecessor.get("status") not in FINAL_STATUSES:
        raise MinerAxonError("generation-2 predecessor is not finalized")
    if validated.stored_readback is None:
        raise MinerAxonError("generation-2 predecessor has no finalized readback")
    return validated.stored_readback


def _successor_attempt_id(
    *,
    generation: int,
    identity: Mapping[str, Any],
    preflight: Mapping[str, Any],
    fresh_endpoint_proof: Mapping[str, Any],
    predecessor_lineage: Mapping[str, Any],
) -> str:
    lineage_digest = "sha256:" + _sha256(
        _canonical_json_bytes(dict(predecessor_lineage))
    )
    material = {
        "domain": SUCCESSOR_ATTEMPT_DOMAIN,
        "schema": SUCCESSOR_JOURNAL_SCHEMA,
        "journal_kind": SUCCESSOR_JOURNAL_KIND,
        "journal_generation": generation,
        "identity": dict(identity),
        "preflight": dict(preflight),
        "fresh_endpoint_proof": dict(fresh_endpoint_proof),
        "remote_exclusive_announcer_asserted": True,
        "serve_axon_call_authorized": True,
        "retry_allowed": False,
        "predecessor_lineage_sha256": lineage_digest,
    }
    return "successor-sha256:" + _sha256(_canonical_json_bytes(material))


def _validated_successor_identity(
    value: object, *, contract: MinerAxonContract = UID124_AXON_CONTRACT
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "network",
        "netuid",
        "preview_sha256",
        "uid",
        "hotkey",
        "coldkey",
        "ip",
        "port",
    }:
        raise MinerAxonError("successor identity fields differ from schema")
    identity = dict(value)
    expected_uid = (
        FINALIZED_SUCCESSOR_UID if contract.fixed_uid is None else contract.fixed_uid
    )
    if (
        identity["network"] != NETWORK
        or identity["netuid"] != NETUID
        or identity["hotkey"] != contract.miner_hotkey
        or identity["coldkey"] != contract.coldkey
        or _strict_nonnegative_int(identity["uid"], label="successor UID")
        != expected_uid
    ):
        raise MinerAxonError("successor identity differs from the UID124 launch pins")
    _digest(identity["preview_sha256"], label="successor preview digest")
    _global_ipv4(identity["ip"], contract=contract)
    _service_port(identity["port"], contract=contract)
    return identity


def _validated_successor_receipt(
    value: object,
    *,
    required_success: bool,
    preflight: FinalizedMinerState,
    readback: FinalizedMinerState | None,
    require_inclusion_fields: bool = False,
) -> Mapping[str, Any]:
    receipt = _validated_receipt(
        value, required_success=required_success, label="successor"
    )
    if require_inclusion_fields and any(
        receipt[key] is None for key in ("extrinsic_hash", "block_hash", "block_number")
    ):
        raise MinerAxonError(
            "successful generation-2 receipt lacks finalized inclusion fields"
        )
    block_number = receipt["block_number"]
    if block_number is not None:
        if receipt["block_hash"] is None:
            raise MinerAxonError("numbered successor receipt has no block hash")
        if block_number <= preflight.block_number:
            raise MinerAxonError("successor receipt does not postdate preflight")
        if readback is not None and block_number > readback.block_number:
            raise MinerAxonError("successor receipt postdates stored readback")
    return receipt


def _validated_successor_journal(
    journal: Mapping[str, Any],
    *,
    preview: Mapping[str, Any] | None = None,
    preview_sha256: str | None = None,
    require_complete_success_receipt: bool = False,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> _ValidatedSuccessorJournal:
    """Strictly validate every persisted field of one successor intent."""

    expected_fields = {
        "schema",
        "journal_kind",
        "journal_generation",
        "status",
        "attempt_id",
        "identity",
        "preflight",
        "fresh_endpoint_proof",
        "remote_exclusive_announcer_asserted",
        "serve_axon_call_authorized",
        "serve_axon_outcome",
        "receipt",
        "readback",
        "retry_allowed",
        "predecessor_lineage",
    }
    if set(journal) != expected_fields:
        raise MinerAxonError("successor journal fields differ from schema")
    generation = _strict_nonnegative_int(
        journal.get("journal_generation"), label="successor journal generation"
    )
    expected_uid = (
        FINALIZED_SUCCESSOR_UID if contract.fixed_uid is None else contract.fixed_uid
    )
    if (
        journal.get("schema") != SUCCESSOR_JOURNAL_SCHEMA
        or journal.get("journal_kind") != SUCCESSOR_JOURNAL_KIND
        or generation not in {1, 2}
    ):
        raise MinerAxonError("successor journal markers differ from the launch pin")
    if (preview is None) != (preview_sha256 is None):
        raise MinerAxonError("successor review identity is incomplete")
    predecessor = _validated_predecessor_lineage(journal)
    lineage = journal["predecessor_lineage"]
    if not isinstance(lineage, Mapping):
        raise MinerAxonError("successor predecessor lineage is missing")
    identity = _validated_successor_identity(journal.get("identity"), contract=contract)
    if preview is not None and preview_sha256 is not None:
        if identity != _journal_identity(
            preview=preview,
            preview_sha256=preview_sha256,
            contract=contract,
        ):
            raise MinerAxonError("successor journal differs from its reviewed preview")
    predecessor_journal = lineage["journal"]
    if not isinstance(predecessor_journal, Mapping):
        raise MinerAxonError("successor embedded predecessor journal is missing")
    predecessor_identity = predecessor_journal.get("identity")
    if not isinstance(predecessor_identity, Mapping):
        raise MinerAxonError("successor embedded predecessor identity is missing")
    if contract.successor_generation == 2 and generation == 2:
        if contract.predecessor_journal_sha256 is None or _digest(
            lineage.get("journal_sha256"),
            label="generation-2 predecessor journal digest",
        ) != _digest(
            contract.predecessor_journal_sha256,
            label="pinned predecessor journal digest",
        ):
            raise MinerAxonError(
                "generation-2 journal does not embed the exact pinned predecessor"
            )
        if contract.predecessor_preview_sha256 is None or _digest(
            predecessor_identity.get("preview_sha256"),
            label="generation-1 reviewed preview digest",
        ) != _digest(
            contract.predecessor_preview_sha256,
            label="pinned predecessor preview digest",
        ):
            raise MinerAxonError(
                "generation-2 journal predecessor preview differs from the pin"
            )
    if _digest(identity["preview_sha256"], label="successor preview digest") == _digest(
        predecessor_identity.get("preview_sha256"),
        label="embedded predecessor preview digest",
    ):
        raise MinerAxonError(
            "successor preview digest does not differ from predecessor"
        )
    preflight = _state_from_artifact(
        journal.get("preflight"),
        label="successor journal preflight",
        contract=contract,
    )
    _current_matches_predecessor(preflight, predecessor)
    if preflight.block_number - predecessor.block_number < ANNOUNCEMENT_PERIOD_BLOCKS:
        raise MinerAxonError("successor journal does not preserve the 128-block fence")
    proof = _endpoint_proof_from_artifact(
        journal.get("fresh_endpoint_proof"),
        label="successor endpoint proof",
        contract=contract,
    )
    if (proof.ip, proof.port) != (identity["ip"], identity["port"]):
        raise MinerAxonError("successor proof endpoint differs from identity")
    if (proof.ip, proof.port) == (predecessor.ip, predecessor.port):
        raise MinerAxonError("successor endpoint does not differ from predecessor")
    if preview is not None:
        _current_matches_preview(preflight, preview, contract=contract)
        _fresh_matches_preview(proof, preview, contract=contract)
    if (
        journal.get("remote_exclusive_announcer_asserted") is not True
        or journal.get("serve_axon_call_authorized") is not True
        or journal.get("retry_allowed") is not False
    ):
        raise MinerAxonError("successor journal authorization fence is incomplete")
    preflight_value = journal.get("preflight")
    proof_value = journal.get("fresh_endpoint_proof")
    if not isinstance(preflight_value, Mapping) or not isinstance(proof_value, Mapping):
        raise MinerAxonError("successor immutable intent artifacts are malformed")
    if journal.get("attempt_id") != _successor_attempt_id(
        generation=generation,
        identity=identity,
        preflight=preflight_value,
        fresh_endpoint_proof=proof_value,
        predecessor_lineage=lineage,
    ):
        raise MinerAxonError(
            "successor attempt ID is not bound to exact immutable intent"
        )

    status = journal.get("status")
    outcome = journal.get("serve_axon_outcome")
    receipt = journal.get("receipt")
    readback_value = journal.get("readback")
    stored_readback: FinalizedMinerState | None = None
    if status == "submission_started":
        if outcome != "UNKNOWN" or receipt is not None or readback_value is not None:
            raise MinerAxonError("started successor journal has contradictory outcome")
    elif status == "submission_ambiguous":
        allowed = {
            "SDK_EXCEPTION": None,
            "SDK_RESPONSE_UNPROVEN": None,
            "SDK_UNSUCCESSFUL": False,
            "FINALIZED_READBACK_UNPROVEN": True,
        }
        if outcome not in allowed or readback_value is not None:
            raise MinerAxonError(
                "ambiguous successor journal has contradictory outcome"
            )
        expected_success = allowed[outcome]
        if expected_success is None:
            if receipt is not None:
                raise MinerAxonError("ambiguous successor receipt must be absent")
        else:
            validated = _validated_successor_receipt(
                receipt,
                required_success=expected_success,
                preflight=preflight,
                readback=None,
            )
            if validated["success"] is not expected_success:
                raise MinerAxonError("ambiguous successor receipt success disagrees")
    elif status in FINAL_STATUSES:
        stored_readback = _state_from_artifact(
            readback_value,
            label="successor stored finalized readback",
            require_serving=True,
            contract=contract,
        )
        if (
            stored_readback.block_number <= preflight.block_number
            or stored_readback.uid != expected_uid
            or stored_readback.hotkey != contract.miner_hotkey
            or stored_readback.coldkey != contract.coldkey
            or (stored_readback.ip, stored_readback.port)
            != (identity["ip"], identity["port"])
        ):
            raise MinerAxonError("successor stored readback differs from exact target")
        if status == "finalized_proven":
            if outcome != "SUCCESS":
                raise MinerAxonError("proven successor outcome is not SUCCESS")
            _validated_successor_receipt(
                receipt,
                required_success=True,
                preflight=preflight,
                readback=stored_readback,
                require_inclusion_fields=require_complete_success_receipt,
            )
        else:
            if outcome != "FINALIZED_BY_READBACK":
                raise MinerAxonError("recovered successor outcome is not exact")
            if receipt is not None:
                _validated_successor_receipt(
                    receipt,
                    required_success=False,
                    preflight=preflight,
                    readback=stored_readback,
                )
    else:
        raise MinerAxonError("successor journal status is not recognized")
    return _ValidatedSuccessorJournal(
        preflight=preflight,
        stored_readback=stored_readback,
    )


def _successor_minimum_readback(journal: Mapping[str, Any]) -> int | None:
    """Return the strict successor preflight, or None for a true baseline journal."""

    if not _looks_like_successor_journal(journal):
        return None
    return _validated_successor_journal(journal).minimum_readback_block


def _journal_for_attempt(
    *,
    preview: Mapping[str, Any],
    preview_sha256: str,
    fresh: EndpointProof,
    state: FinalizedMinerState,
    predecessor_lineage: Mapping[str, Any] | None = None,
    successor_generation: int = 1,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> dict[str, Any]:
    identity = _journal_identity(
        preview=preview, preview_sha256=preview_sha256, contract=contract
    )
    successor = predecessor_lineage is not None
    if successor and not contract.supports_legacy_successor:
        raise MinerAxonError(
            "this axon contract does not permit a legacy successor lineage"
        )
    if successor and successor_generation not in {1, 2}:
        raise MinerAxonError("successor generation is outside the bounded set")
    attempt_id = (
        _successor_attempt_id(
            generation=successor_generation,
            identity=identity,
            preflight=state.artifact(),
            fresh_endpoint_proof=fresh.artifact(),
            predecessor_lineage=predecessor_lineage,
        )
        if predecessor_lineage is not None
        else "sha256:" + _sha256(_canonical_json_bytes(identity))
    )
    journal = {
        "schema": SUCCESSOR_JOURNAL_SCHEMA if successor else contract.journal_schema,
        "status": "submission_started",
        "attempt_id": attempt_id,
        "identity": identity,
        "preflight": state.artifact(),
        "fresh_endpoint_proof": fresh.artifact(),
        "remote_exclusive_announcer_asserted": True,
        "serve_axon_call_authorized": True,
        "serve_axon_outcome": "UNKNOWN",
        "receipt": None,
        "readback": None,
        "retry_allowed": False,
    }
    if predecessor_lineage is not None:
        journal["journal_kind"] = SUCCESSOR_JOURNAL_KIND
        journal["journal_generation"] = successor_generation
        journal["predecessor_lineage"] = dict(predecessor_lineage)
    return journal


def _validated_serve_axon_call(
    call: Callable[..., Any], *, advertisement: Any
) -> dict[str, Any]:
    """Bind the exact SDK call before creating the no-retry journal.

    Once the journal exists, any exception from ``serve_axon`` is ambiguous
    because the SDK might have signed or broadcast before transport failed.
    An incompatible Python call signature is different: it is provably a local
    pre-call failure. Binding here keeps that failure before the durable intent
    while preserving the one-attempt fence for every exception after entry.
    """

    kwargs = {
        "netuid": NETUID,
        "axon": advertisement,
        "mev_protection": False,
        "period": ANNOUNCEMENT_PERIOD_BLOCKS,
        "raise_error": True,
        "wait_for_inclusion": True,
        "wait_for_finalization": True,
    }
    try:
        inspect.signature(call).bind(**kwargs)
    except (TypeError, ValueError) as exc:
        raise MinerAxonError(
            "serve_axon SDK contract is incompatible before submission; "
            "no announcement journal was created"
        ) from exc
    return kwargs


def _journal_matches(
    journal: Mapping[str, Any],
    *,
    preview: Mapping[str, Any],
    digest: str,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> None:
    if journal.get("identity") != _journal_identity(
        preview=preview, preview_sha256=digest, contract=contract
    ):
        raise MinerAxonError(
            "announcement journal belongs to a different reviewed preview"
        )
    if journal.get("retry_allowed") is not False:
        raise MinerAxonError("announcement journal does not carry the no-retry fence")


def _recoverable_successor_validation(
    journal: Mapping[str, Any],
    *,
    preview: Mapping[str, Any],
    digest: str,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> _ValidatedSuccessorJournal | None:
    """Keep every malformed successor intent behind the ambiguity fence."""

    if not _looks_like_successor_journal(journal):
        _journal_matches(journal, preview=preview, digest=digest, contract=contract)
        return None
    try:
        return _validated_successor_journal(
            journal,
            preview=preview,
            preview_sha256=digest,
            require_complete_success_receipt=contract.require_proven_success_receipt,
            contract=contract,
        )
    except Exception as exc:
        raise MinerAxonAmbiguous(
            "successor intent journal is contradictory; preserve it and do not retry"
        ) from exc


def _post_intent_successor_validation(
    journal: Mapping[str, Any],
    *,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> _ValidatedSuccessorJournal | None:
    if not _looks_like_successor_journal(journal):
        return None
    try:
        return _validated_successor_journal(
            journal,
            require_complete_success_receipt=contract.require_proven_success_receipt,
            contract=contract,
        )
    except Exception as exc:
        raise MinerAxonAmbiguous(
            "successor intent validation failed after persistence; do not retry"
        ) from exc


def _strict_baseline_preflight(
    journal: Mapping[str, Any],
    *,
    preview: Mapping[str, Any],
    contract: MinerAxonContract,
) -> FinalizedMinerState | None:
    """Validate the stored first-attempt fence before trusting its readback."""

    if not contract.require_proven_success_receipt:
        return None
    preflight = _state_from_artifact(
        journal.get("preflight"),
        label="first-announcement preflight",
        contract=contract,
    )
    _current_matches_preview(preflight, preview, contract=contract)
    proof = _endpoint_proof_from_artifact(
        journal.get("fresh_endpoint_proof"),
        label="first-announcement fresh endpoint proof",
        contract=contract,
    )
    _fresh_matches_preview(proof, preview, contract=contract)
    return preflight


def _recover_existing_journal(
    *,
    journal: dict[str, Any],
    journal_path: Path,
    preview: Mapping[str, Any],
    digest: str,
    subtensor: Any,
    state_loader: Callable[[Any], FinalizedMinerState],
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> Mapping[str, Any]:
    if contract.successor_generation == 2:
        pinned_predecessor = contract.predecessor_journal_sha256
        if pinned_predecessor is None:
            raise MinerAxonError("generation-2 predecessor journal pin is missing")
        if _sha256(_canonical_json_bytes(journal)) == _digest(
            pinned_predecessor,
            label="pinned predecessor journal digest",
        ):
            raise MinerAxonError(
                "no generation-2 intent exists yet; run announce with the reviewed "
                "generation-2 preview"
            )
    successor_validation = _recoverable_successor_validation(
        journal, preview=preview, digest=digest, contract=contract
    )
    successor_minimum = (
        successor_validation.minimum_readback_block
        if successor_validation is not None
        else None
    )
    try:
        baseline_preflight = (
            None
            if successor_validation is not None
            else _strict_baseline_preflight(journal, preview=preview, contract=contract)
        )
    except Exception as exc:
        raise MinerAxonAmbiguous(
            "first-announcement intent journal is contradictory; do not retry"
        ) from exc
    if baseline_preflight is not None:
        try:
            _canonical_state_block(
                subtensor,
                baseline_preflight,
                label="first-announcement stored preflight",
            )
        except Exception as exc:
            raise MinerAxonAmbiguous(
                "first-announcement preflight is no longer canonical; do not retry"
            ) from exc
    minimum_readback = (
        successor_minimum
        if successor_minimum is not None
        else (
            baseline_preflight.block_number + 1
            if baseline_preflight is not None
            else None
        )
    )
    if successor_validation is not None:
        try:
            _canonical_state_block(
                subtensor,
                successor_validation.preflight,
                label="successor stored preflight",
            )
            if successor_validation.stored_readback is not None:
                _canonical_state_block(
                    subtensor,
                    successor_validation.stored_readback,
                    label="successor stored finalized readback",
                )
        except Exception as exc:
            raise MinerAxonAmbiguous(
                "successor stored chain proof is no longer canonical; do not retry"
            ) from exc
    requested = preview["requested_endpoint"]
    assert isinstance(requested, Mapping)
    ip = str(requested["ip"])
    port = int(requested["port"])
    status = journal.get("status")
    if status not in AMBIGUOUS_STATUSES | FINAL_STATUSES:
        if minimum_readback is not None:
            raise MinerAxonAmbiguous(
                "announcement intent status is contradictory; preserve it and do not retry"
            )
        raise MinerAxonError(
            f"announcement journal status is not recognized: {status!r}"
        )
    try:
        readback = _finalized_readback(
            subtensor,
            ip=ip,
            port=port,
            receipt=journal.get("receipt"),
            state_loader=state_loader,
            minimum_block_number=minimum_readback,
            receipt_after_block_number=(
                successor_validation.preflight.block_number
                if successor_validation is not None
                else (
                    baseline_preflight.block_number
                    if baseline_preflight is not None
                    else None
                )
            ),
            require_canonical_state=minimum_readback is not None,
        )
    except Exception as exc:
        if status in FINAL_STATUSES:
            raise MinerAxonAmbiguous(
                "finalized journal no longer matches the current finalized axon"
            ) from exc
        raise MinerAxonAmbiguous(
            "prior serve intent is unresolved; do not retry serve_axon"
        ) from exc
    if status in FINAL_STATUSES:
        return dict(journal)
    recovered = dict(journal)
    recovered.update(
        {
            "status": "finalized_recovered",
            "serve_axon_outcome": "FINALIZED_BY_READBACK",
            "readback": dict(readback),
            "retry_allowed": False,
        }
    )
    if successor_validation is not None:
        try:
            _validated_successor_journal(
                recovered,
                preview=preview,
                preview_sha256=digest,
                require_complete_success_receipt=contract.require_proven_success_receipt,
                contract=contract,
            )
        except Exception as exc:
            raise MinerAxonAmbiguous(
                "successor recovery state is contradictory; do not retry"
            ) from exc
    try:
        _write_state(journal_path, recovered, exclusive=False)
    except Exception as exc:
        if minimum_readback is not None:
            raise MinerAxonAmbiguous(
                "endpoint was read back but recovery persistence failed; do not retry"
            ) from exc
        raise
    return recovered


def _resolve_after_call(
    *,
    journal: dict[str, Any],
    journal_path: Path,
    preview: Mapping[str, Any],
    subtensor: Any,
    state_loader: Callable[[Any], FinalizedMinerState],
    receipt: Mapping[str, Any] | None,
    failure_kind: str,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> Mapping[str, Any]:
    requested = preview["requested_endpoint"]
    assert isinstance(requested, Mapping)
    successor_validation = _post_intent_successor_validation(journal, contract=contract)
    successor_minimum = (
        successor_validation.minimum_readback_block
        if successor_validation is not None
        else None
    )
    try:
        baseline_preflight = (
            None
            if successor_validation is not None
            else _strict_baseline_preflight(journal, preview=preview, contract=contract)
        )
        if baseline_preflight is not None:
            _canonical_state_block(
                subtensor,
                baseline_preflight,
                label="first-announcement preflight",
            )
    except Exception as exc:
        raise MinerAxonAmbiguous(
            "first-announcement intent validation failed after persistence; do not retry"
        ) from exc
    minimum_readback = (
        successor_minimum
        if successor_minimum is not None
        else (
            baseline_preflight.block_number + 1
            if baseline_preflight is not None
            else None
        )
    )
    if successor_validation is not None:
        expected_success = {
            "SDK_EXCEPTION": None,
            "SDK_RESPONSE_UNPROVEN": None,
            "SDK_UNSUCCESSFUL": False,
            "FINALIZED_READBACK_UNPROVEN": True,
        }.get(failure_kind)
        if expected_success is None:
            receipt = None
        else:
            try:
                validated_receipt = _validated_successor_receipt(
                    receipt,
                    required_success=expected_success,
                    preflight=successor_validation.preflight,
                    readback=None,
                )
                if validated_receipt["success"] is not expected_success:
                    raise MinerAxonError(
                        "successor SDK outcome disagrees with its receipt"
                    )
            except Exception:
                receipt = None
                failure_kind = "SDK_RESPONSE_UNPROVEN"
    try:
        readback = _finalized_readback(
            subtensor,
            ip=str(requested["ip"]),
            port=int(requested["port"]),
            receipt=receipt,
            state_loader=state_loader,
            minimum_block_number=minimum_readback,
            receipt_after_block_number=(
                successor_validation.preflight.block_number
                if successor_validation is not None
                else (
                    baseline_preflight.block_number
                    if baseline_preflight is not None
                    else None
                )
            ),
            require_canonical_state=minimum_readback is not None,
        )
    except Exception as exc:
        ambiguous = dict(journal)
        ambiguous.update(
            {
                "status": "submission_ambiguous",
                "serve_axon_outcome": failure_kind,
                "receipt": dict(receipt) if receipt is not None else None,
                "readback": None,
                "retry_allowed": False,
            }
        )
        if successor_validation is not None:
            try:
                _validated_successor_journal(
                    ambiguous,
                    require_complete_success_receipt=contract.require_proven_success_receipt,
                    contract=contract,
                )
            except Exception as validation_exc:
                raise MinerAxonAmbiguous(
                    "successor resolution state is contradictory; do not retry"
                ) from validation_exc
        try:
            _write_state(journal_path, ambiguous, exclusive=False)
        except Exception:
            pass
        raise MinerAxonAmbiguous(
            "serve_axon intent is unresolved; preserve the journal and do not retry"
        ) from exc
    recovered = dict(journal)
    recovered.update(
        {
            "status": "finalized_recovered",
            "serve_axon_outcome": "FINALIZED_BY_READBACK",
            "receipt": dict(receipt) if receipt is not None else None,
            "readback": dict(readback),
            "retry_allowed": False,
        }
    )
    if successor_validation is not None:
        try:
            _validated_successor_journal(
                recovered,
                require_complete_success_receipt=contract.require_proven_success_receipt,
                contract=contract,
            )
        except Exception as exc:
            raise MinerAxonAmbiguous(
                "successor recovered state is contradictory; do not retry"
            ) from exc
    try:
        _write_state(journal_path, recovered, exclusive=False)
    except Exception as exc:
        raise MinerAxonAmbiguous(
            "finalized endpoint was read back but proof persistence failed; do not retry"
        ) from exc
    return recovered


def _canonical_state_block(
    subtensor: Any, state: FinalizedMinerState, *, label: str
) -> None:
    try:
        canonical = _canonical_hash(
            subtensor.substrate.get_block_hash(state.block_number),
            label=f"{label} canonical block hash",
        )
    except MinerAxonError:
        raise
    except Exception as exc:
        raise MinerAxonError(f"{label} block could not be resolved") from exc
    if canonical != state.block_hash:
        raise MinerAxonError(f"{label} block is not canonical")


def _canonical_predecessor_receipt(subtensor: Any, journal: Mapping[str, Any]) -> None:
    receipt = journal.get("receipt")
    if not isinstance(receipt, Mapping) or receipt.get("block_number") is None:
        return
    block_number = _strict_nonnegative_int(
        receipt["block_number"], label="predecessor receipt block number"
    )
    block_hash = receipt.get("block_hash")
    if block_hash is None:
        raise MinerAxonError("numbered predecessor receipt has no block hash")
    try:
        canonical = _canonical_hash(
            subtensor.substrate.get_block_hash(block_number),
            label="predecessor receipt canonical block hash",
        )
    except MinerAxonError:
        raise
    except Exception as exc:
        raise MinerAxonError("predecessor receipt block could not be resolved") from exc
    if canonical != _canonical_hash(block_hash, label="predecessor receipt block hash"):
        raise MinerAxonError("predecessor receipt block is not canonical")


def _current_matches_predecessor(
    state: FinalizedMinerState, predecessor: FinalizedMinerState
) -> None:
    if state.block_number < predecessor.block_number:
        raise MinerAxonError("current finalized head predates predecessor readback")
    if (
        state.uid != predecessor.uid
        or state.uid != FINALIZED_SUCCESSOR_UID
        or state.hotkey != predecessor.hotkey
        or state.hotkey != MINER_HOTKEY
        or state.coldkey != predecessor.coldkey
        or state.coldkey != CATHEDRAL_COLDKEY
    ):
        raise MinerAxonError(
            "current finalized miner identity differs from predecessor"
        )
    if (state.ip, state.port, state.is_serving) != (
        predecessor.ip,
        predecessor.port,
        predecessor.is_serving,
    ):
        raise MinerAxonError("current finalized axon differs from predecessor readback")


def _persist_submission_intent(
    *,
    journal_path: Path,
    journal: Mapping[str, Any],
    replace_finalized_predecessor: bool,
) -> None:
    """Classify failures around the atomic predecessor-to-successor replacement."""

    try:
        _write_state(
            journal_path,
            journal,
            exclusive=not replace_finalized_predecessor,
        )
        return
    except Exception as exc:
        if not replace_finalized_predecessor:
            raise
        lineage = journal.get("predecessor_lineage")
        predecessor = lineage.get("journal") if isinstance(lineage, Mapping) else None
        try:
            observed = _load_journal(journal_path)
        except Exception as observation_exc:
            raise MinerAxonAmbiguous(
                "successor intent persistence failed and canonical state is unreadable; "
                "do not retry"
            ) from observation_exc
        if (
            isinstance(predecessor, Mapping)
            and observed is not None
            and _canonical_json_bytes(observed) == _canonical_json_bytes(predecessor)
        ):
            raise MinerAxonError(
                "successor intent was not installed; predecessor remains exact"
            ) from exc
        raise MinerAxonAmbiguous(
            "successor intent persistence crossed the atomic replacement boundary; "
            "preserve the journal and do not retry"
        ) from exc


def _submit_journaled_axon(
    *,
    journal: dict[str, Any],
    journal_path: Path,
    replace_finalized_predecessor: bool,
    preview: Mapping[str, Any],
    subtensor: Any,
    state_loader: Callable[[Any], FinalizedMinerState],
    call: Callable[..., Any],
    call_kwargs: Mapping[str, Any],
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> Mapping[str, Any]:
    """Persist one no-retry intent, call once, and resolve only by final state."""

    _persist_submission_intent(
        journal_path=journal_path,
        journal=journal,
        replace_finalized_predecessor=replace_finalized_predecessor,
    )
    try:
        response = call(**dict(call_kwargs))
    except Exception:
        return _resolve_after_call(
            journal=journal,
            journal_path=journal_path,
            preview=preview,
            subtensor=subtensor,
            state_loader=state_loader,
            receipt=None,
            failure_kind="SDK_EXCEPTION",
            contract=contract,
        )
    try:
        receipt = _receipt_fields(response)
    except Exception:
        return _resolve_after_call(
            journal=journal,
            journal_path=journal_path,
            preview=preview,
            subtensor=subtensor,
            state_loader=state_loader,
            receipt=None,
            failure_kind="SDK_RESPONSE_UNPROVEN",
            contract=contract,
        )
    if receipt["success"] is not True:
        return _resolve_after_call(
            journal=journal,
            journal_path=journal_path,
            preview=preview,
            subtensor=subtensor,
            state_loader=state_loader,
            receipt=receipt,
            failure_kind="SDK_UNSUCCESSFUL",
            contract=contract,
        )
    requested = preview["requested_endpoint"]
    assert isinstance(requested, Mapping)
    successor_validation = _post_intent_successor_validation(journal, contract=contract)
    successor_minimum = (
        successor_validation.minimum_readback_block
        if successor_validation is not None
        else None
    )
    try:
        baseline_preflight = (
            None
            if successor_validation is not None
            else _strict_baseline_preflight(journal, preview=preview, contract=contract)
        )
    except Exception as exc:
        raise MinerAxonAmbiguous(
            "first-announcement intent validation failed after persistence; do not retry"
        ) from exc
    if baseline_preflight is not None:
        try:
            _validated_first_announcement_receipt(receipt, preflight=baseline_preflight)
        except Exception:
            return _resolve_after_call(
                journal=journal,
                journal_path=journal_path,
                preview=preview,
                subtensor=subtensor,
                state_loader=state_loader,
                receipt=None,
                failure_kind="SDK_RESPONSE_UNPROVEN",
                contract=contract,
            )
    minimum_readback = (
        successor_minimum
        if successor_minimum is not None
        else (
            baseline_preflight.block_number + 1
            if baseline_preflight is not None
            else None
        )
    )
    if successor_validation is not None:
        try:
            _validated_successor_receipt(
                receipt,
                required_success=True,
                preflight=successor_validation.preflight,
                readback=None,
                require_inclusion_fields=contract.require_proven_success_receipt,
            )
        except Exception:
            return _resolve_after_call(
                journal=journal,
                journal_path=journal_path,
                preview=preview,
                subtensor=subtensor,
                state_loader=state_loader,
                receipt=None,
                failure_kind="SDK_RESPONSE_UNPROVEN",
                contract=contract,
            )
    try:
        readback = _finalized_readback(
            subtensor,
            ip=str(requested["ip"]),
            port=int(requested["port"]),
            receipt=receipt,
            state_loader=state_loader,
            minimum_block_number=minimum_readback,
            receipt_after_block_number=(
                successor_validation.preflight.block_number
                if successor_validation is not None
                else (
                    baseline_preflight.block_number
                    if baseline_preflight is not None
                    else None
                )
            ),
            require_canonical_state=minimum_readback is not None,
        )
    except Exception:
        return _resolve_after_call(
            journal=journal,
            journal_path=journal_path,
            preview=preview,
            subtensor=subtensor,
            state_loader=state_loader,
            receipt=receipt,
            failure_kind="FINALIZED_READBACK_UNPROVEN",
            contract=contract,
        )
    finalized = dict(journal)
    finalized.update(
        {
            "status": "finalized_proven",
            "serve_axon_outcome": "SUCCESS",
            "receipt": receipt,
            "readback": dict(readback),
            "retry_allowed": False,
        }
    )
    if successor_validation is not None:
        try:
            _validated_successor_journal(
                finalized,
                require_complete_success_receipt=contract.require_proven_success_receipt,
                contract=contract,
            )
        except Exception as exc:
            raise MinerAxonAmbiguous(
                "successor finalized state is contradictory; do not retry"
            ) from exc
    try:
        _write_state(journal_path, finalized, exclusive=False)
    except Exception as exc:
        raise MinerAxonAmbiguous(
            "serve_axon finalized but proof persistence failed; do not retry"
        ) from exc
    return finalized


def _announce_finalized_successor_locked(
    *,
    bt_module: Any,
    subtensor: Any,
    wallet: Any,
    preview: Mapping[str, Any],
    digest: str,
    predecessor_preview_path: Path | str,
    predecessor_reviewed_sha256: str,
    qvl_path: str,
    state_loader: Callable[[Any], FinalizedMinerState],
    proof_loader: Callable[..., EndpointProof],
    serve_call: Callable[..., Any] | None,
    runtime_root: Path,
    journal_path: Path,
    existing: dict[str, Any] | None,
    contract: MinerAxonContract,
) -> Mapping[str, Any]:
    """Authorize the single bounded successor while the canonical lock is held."""

    if existing is None:
        raise MinerAxonError("finalized successor requires the canonical predecessor")
    generation = contract.successor_generation or 1
    if generation not in {1, 2}:
        raise MinerAxonError("successor generation is outside the bounded set")
    if generation == 2 and existing.get("journal_generation") == 2:
        return _recover_existing_journal(
            journal=existing,
            journal_path=journal_path,
            preview=preview,
            digest=digest,
            subtensor=subtensor,
            state_loader=state_loader,
            contract=contract,
        )
    predecessor_bytes = _canonical_json_bytes(existing)
    predecessor_sha256 = _sha256(predecessor_bytes)
    if (
        contract.predecessor_journal_sha256 is not None
        and predecessor_sha256
        != _digest(
            contract.predecessor_journal_sha256,
            label="pinned predecessor journal digest",
        )
    ):
        raise MinerAxonError(
            "canonical predecessor journal differs from the generation-2 pin"
        )
    if contract.predecessor_preview_name is not None:
        expected_predecessor_path = runtime_root / contract.predecessor_preview_name
        if Path(predecessor_preview_path).resolve(
            strict=False
        ) != expected_predecessor_path.resolve(strict=False):
            raise MinerAxonError(
                "predecessor preview path differs from the generation-2 pin"
            )
    if contract.predecessor_preview_sha256 is not None and _digest(
        predecessor_reviewed_sha256,
        label="reviewed predecessor preview digest",
    ) != _digest(
        contract.predecessor_preview_sha256,
        label="pinned predecessor preview digest",
    ):
        raise MinerAxonError(
            "predecessor preview digest differs from the generation-2 pin"
        )
    predecessor_preview, predecessor_digest = load_reviewed_preview(
        predecessor_preview_path,
        reviewed_sha256=predecessor_reviewed_sha256,
    )
    predecessor_local = predecessor_preview["local_state"]
    assert isinstance(predecessor_local, Mapping)
    if Path(str(predecessor_local["runtime_root"])).resolve(
        strict=False
    ) != runtime_root.resolve(strict=False):
        raise MinerAxonError("predecessor preview names a different runtime root")
    if generation == 1:
        if _looks_like_successor_journal(existing):
            _post_intent_successor_validation(existing, contract=contract)
            if existing.get("status") in FINAL_STATUSES:
                raise MinerAxonError(
                    "the bounded finalized successor was already consumed"
                )
            raise MinerAxonAmbiguous(
                "existing successor intent is unresolved; preserve it and do not retry"
            )
        predecessor, _ = _validated_final_predecessor(
            existing,
            preview=predecessor_preview,
            preview_sha256=predecessor_digest,
        )
    else:
        if not _looks_like_successor_journal(existing):
            raise MinerAxonError(
                "generation-2 successor requires the finalized generation-1 journal"
            )
        predecessor_validation = _validated_successor_journal(
            existing,
            preview=predecessor_preview,
            preview_sha256=predecessor_digest,
        )
        if existing.get("journal_generation") != 1:
            if existing.get("journal_generation") == 2:
                raise MinerAxonError(
                    "the bounded generation-2 successor was already consumed"
                )
            raise MinerAxonError(
                "generation-2 predecessor is not the exact generation-1 journal"
            )
        if (
            existing.get("status") not in FINAL_STATUSES
            or predecessor_validation.stored_readback is None
        ):
            raise MinerAxonAmbiguous(
                "generation-1 predecessor is unresolved; preserve it and do not retry"
            )
        predecessor = predecessor_validation.stored_readback
    _canonical_state_block(
        subtensor, predecessor, label="predecessor finalized readback"
    )
    _canonical_predecessor_receipt(subtensor, existing)
    if digest == predecessor_digest:
        raise MinerAxonError("successor requires a distinct reviewed preview digest")
    requested = preview["requested_endpoint"]
    assert isinstance(requested, Mapping)
    ip = _global_ipv4(requested["ip"], contract=contract)
    port = _service_port(requested["port"], contract=contract)
    if (ip, port) == (predecessor.ip, predecessor.port):
        raise MinerAxonError("successor endpoint must differ from predecessor endpoint")
    if preview.get("status") != PREVIEW_READY:
        raise MinerAxonError("successor preview is not a replacement-ready artifact")
    preview_state = _state_from_artifact(
        preview.get("chain_at_preview"),
        label="successor preview chain state",
        contract=contract,
    )
    if preview_state.block_number < predecessor.block_number:
        raise MinerAxonError(
            "successor preview predates predecessor finalized readback"
        )
    _current_matches_predecessor(preview_state, predecessor)
    _canonical_state_block(subtensor, preview_state, label="successor preview")

    before = state_loader(subtensor)
    _current_matches_preview(before, preview, contract=contract)
    _current_matches_predecessor(before, predecessor)
    _canonical_state_block(subtensor, before, label="successor preflight")
    elapsed = before.block_number - predecessor.block_number
    if elapsed < ANNOUNCEMENT_PERIOD_BLOCKS:
        raise MinerAxonError(
            "successor announcement period has not elapsed: "
            f"{elapsed} < {ANNOUNCEMENT_PERIOD_BLOCKS} finalized blocks"
        )

    fresh = proof_loader(subtensor, qvl_path=qvl_path, ip=ip, port=port)
    _fresh_matches_preview(fresh, preview, contract=contract)
    after = state_loader(subtensor)
    if (
        after.uid != before.uid
        or after.hotkey != before.hotkey
        or after.coldkey != before.coldkey
        or after.block_number < before.block_number
        or (after.ip, after.port, after.is_serving)
        != (before.ip, before.port, before.is_serving)
    ):
        raise MinerAxonError(
            "finalized miner registration or predecessor axon changed during evidence collection"
        )
    _current_matches_predecessor(after, predecessor)
    _canonical_state_block(subtensor, after, label="successor evidence recheck")

    call = serve_call or subtensor.serve_axon
    call_kwargs = _validated_serve_axon_call(call, advertisement=object())
    _wallet_identity(wallet, contract=contract)
    advertisement = make_axon(
        bt_module,
        wallet=wallet,
        port=port,
        external_ip=ip,
        external_port=port,
        max_workers=2,
    )
    call_kwargs["axon"] = advertisement
    lineage = {
        "generation": generation,
        "journal_sha256": "sha256:" + predecessor_sha256,
        "journal": dict(existing),
    }
    journal = _journal_for_attempt(
        preview=preview,
        preview_sha256=digest,
        fresh=fresh,
        state=after,
        predecessor_lineage=lineage,
        successor_generation=generation,
        contract=contract,
    )
    _validated_successor_journal(
        journal,
        preview=preview,
        preview_sha256=digest,
        require_complete_success_receipt=contract.require_proven_success_receipt,
        contract=contract,
    )
    return _submit_journaled_axon(
        journal=journal,
        journal_path=journal_path,
        replace_finalized_predecessor=True,
        preview=preview,
        subtensor=subtensor,
        state_loader=state_loader,
        call=call,
        call_kwargs=call_kwargs,
        contract=contract,
    )


def announce_reviewed_preview(
    *,
    bt_module: Any,
    subtensor: Any,
    wallet: Any,
    preview_path: Path | str,
    reviewed_sha256: str,
    qvl_path: str,
    confirm: bool,
    exclusive_announcer_asserted: bool,
    state_loader: Callable[[Any], FinalizedMinerState] | None = None,
    proof_loader: Callable[..., EndpointProof] | None = None,
    serve_call: Callable[..., Any] | None = None,
    runtime_root: Path | None = None,
    allow_finalized_successor: bool = False,
    predecessor_preview_path: Path | str | None = None,
    predecessor_reviewed_sha256: str | None = None,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> Mapping[str, Any]:
    """Authorize at most one serve_axon call from an exact reviewed preview."""

    if confirm is not True:
        raise MinerAxonError(
            "--confirm-miner-announce is required; no serve_axon call made"
        )
    if exclusive_announcer_asserted is not True:
        raise MinerAxonError(
            "--assert-exclusive-announcer is required; stop every other miner announcer"
        )
    predecessor_supplied = (
        predecessor_preview_path is not None or predecessor_reviewed_sha256 is not None
    )
    if (
        contract.successor_generation is not None
        and allow_finalized_successor is not True
    ):
        raise MinerAxonError(
            "dedicated generation-2 contract requires its pinned predecessor lineage"
        )
    if allow_finalized_successor is True:
        if not contract.supports_legacy_successor:
            raise MinerAxonError(
                "this axon contract has no legacy successor authorization"
            )
        if predecessor_preview_path is None or predecessor_reviewed_sha256 is None:
            raise MinerAxonError(
                "--allow-finalized-successor requires the reviewed predecessor preview and digest"
            )
    elif predecessor_supplied:
        raise MinerAxonError(
            "predecessor arguments require --allow-finalized-successor"
        )
    preview, digest = load_reviewed_preview(
        preview_path, reviewed_sha256=reviewed_sha256, contract=contract
    )
    canonical_root = _contract_runtime_root(contract)
    root = Path(canonical_root if runtime_root is None else runtime_root)
    if root.resolve(strict=False) != canonical_root.resolve(strict=False):
        raise MinerAxonError(
            f"live announcement requires canonical runtime root {canonical_root}"
        )
    local = preview["local_state"]
    assert isinstance(local, Mapping)
    if Path(str(local["runtime_root"])).resolve(strict=False) != root.resolve(
        strict=False
    ):
        raise MinerAxonError("reviewed preview names a different runtime root")
    requested = preview["requested_endpoint"]
    assert isinstance(requested, Mapping)
    ip = _global_ipv4(requested["ip"], contract=contract)
    port = _service_port(requested["port"], contract=contract)
    _, journal_path = _announcement_paths(root, contract=contract)
    state_reader = state_loader or (
        lambda selected: finalized_miner_state(selected, contract=contract)
    )
    proof_reader = proof_loader or (
        lambda selected, **kwargs: collect_endpoint_proof(
            selected, contract=contract, **kwargs
        )
    )
    if allow_finalized_successor is True:
        assert predecessor_preview_path is not None
        assert predecessor_reviewed_sha256 is not None
        with _announcement_lock(root, contract=contract):
            return _announce_finalized_successor_locked(
                bt_module=bt_module,
                subtensor=subtensor,
                wallet=wallet,
                preview=preview,
                digest=digest,
                predecessor_preview_path=predecessor_preview_path,
                predecessor_reviewed_sha256=predecessor_reviewed_sha256,
                qvl_path=qvl_path,
                state_loader=state_reader,
                proof_loader=proof_reader,
                serve_call=serve_call,
                runtime_root=root,
                journal_path=journal_path,
                existing=_load_journal(journal_path, contract=contract),
                contract=contract,
            )

    with _announcement_lock(root, contract=contract):
        existing = _load_journal(journal_path, contract=contract)
        if existing is not None:
            return _recover_existing_journal(
                journal=existing,
                journal_path=journal_path,
                preview=preview,
                digest=digest,
                subtensor=subtensor,
                state_loader=state_reader,
                contract=contract,
            )
        before = state_reader(subtensor)
        _require_first_announcement_posture(before, ip=ip, port=port, contract=contract)
        if _same_endpoint(before, ip=ip, port=port):
            return {
                "schema": contract.journal_schema,
                "status": "already_announced_no_write",
                "identity": _journal_identity(
                    preview=preview, preview_sha256=digest, contract=contract
                ),
                "readback": before.artifact(),
                "remote_exclusive_announcer_asserted": True,
                "serve_axon_called": False,
                "retry_allowed": False,
            }
        _current_matches_preview(before, preview, contract=contract)
        fresh = proof_reader(subtensor, qvl_path=qvl_path, ip=ip, port=port)
        _fresh_matches_preview(fresh, preview, contract=contract)
        after = state_reader(subtensor)
        _require_first_announcement_posture(after, ip=ip, port=port, contract=contract)
        if (
            after.uid != before.uid
            or after.hotkey != before.hotkey
            or after.coldkey != before.coldkey
            or after.block_number < before.block_number
            or (after.ip, after.port, after.is_serving)
            != (before.ip, before.port, before.is_serving)
        ):
            if _same_endpoint(after, ip=ip, port=port):
                return {
                    "schema": contract.journal_schema,
                    "status": "already_announced_no_write",
                    "identity": _journal_identity(
                        preview=preview,
                        preview_sha256=digest,
                        contract=contract,
                    ),
                    "readback": after.artifact(),
                    "remote_exclusive_announcer_asserted": True,
                    "serve_axon_called": False,
                    "retry_allowed": False,
                }
            raise MinerAxonError(
                "finalized miner registration or axon changed during evidence collection"
            )
        advertisement = make_axon(
            bt_module,
            wallet=wallet,
            port=port,
            external_ip=ip,
            external_port=port,
            max_workers=2,
        )
        call = serve_call or subtensor.serve_axon
        call_kwargs = _validated_serve_axon_call(
            call,
            advertisement=advertisement,
        )
        journal = _journal_for_attempt(
            preview=preview,
            preview_sha256=digest,
            fresh=fresh,
            state=after,
            contract=contract,
        )
        _wallet_identity(wallet, contract=contract)
        return _submit_journaled_axon(
            journal=journal,
            journal_path=journal_path,
            replace_finalized_predecessor=False,
            preview=preview,
            subtensor=subtensor,
            state_loader=state_reader,
            call=call,
            call_kwargs=call_kwargs,
            contract=contract,
        )


def recover_ambiguous_preview(
    *,
    subtensor: Any,
    preview_path: Path | str,
    reviewed_sha256: str,
    state_loader: Callable[[Any], FinalizedMinerState] | None = None,
    runtime_root: Path | None = None,
    contract: MinerAxonContract = UID124_AXON_CONTRACT,
) -> Mapping[str, Any]:
    """Read finalized state for an existing intent. Never signs or resubmits."""

    preview, digest = load_reviewed_preview(
        preview_path, reviewed_sha256=reviewed_sha256, contract=contract
    )
    canonical_root = _contract_runtime_root(contract)
    root = Path(canonical_root if runtime_root is None else runtime_root)
    if root.resolve(strict=False) != canonical_root.resolve(strict=False):
        raise MinerAxonError(
            f"recovery requires canonical runtime root {canonical_root}"
        )
    _, journal_path = _announcement_paths(root, contract=contract)
    state_reader = state_loader or (
        lambda selected: finalized_miner_state(selected, contract=contract)
    )
    with _announcement_lock(root, contract=contract):
        journal = _load_journal(journal_path, contract=contract)
        if journal is None:
            raise MinerAxonError("no announcement journal exists to recover")
        return _recover_existing_journal(
            journal=journal,
            journal_path=journal_path,
            preview=preview,
            digest=digest,
            subtensor=subtensor,
            state_loader=state_reader,
            contract=contract,
        )


__all__ = [
    "ANNOUNCEMENT_PERIOD_BLOCKS",
    "CATHEDRAL_COLDKEY",
    "DEFAULT_PREVIEW",
    "DEFAULT_RUNTIME_ROOT",
    "EndpointProof",
    "FINAL_STATUSES",
    "FINALIZED_SUCCESSOR_UID",
    "FinalizedMinerState",
    "JOURNAL_SCHEMA",
    "MINER_HOTKEY",
    "MinerAxonContract",
    "MinerAxonAmbiguous",
    "MinerAxonError",
    "NETWORK",
    "NETUID",
    "PREVIEW_ALREADY",
    "PREVIEW_READY",
    "PREVIEW_SCHEMA",
    "SN39_HTTPS_PORT",
    "SECOND_MINER_AXON_CONTRACT",
    "SECOND_MINER_ENDPOINT_IP",
    "SECOND_MINER_HOTKEY",
    "SECOND_MINER_RUNTIME_ROOT",
    "UID124_AXON_CONTRACT",
    "UID124_GENERATION1_JOURNAL_SHA256",
    "UID124_GENERATION1_PREVIEW_NAME",
    "UID124_GENERATION1_PREVIEW_SHA256",
    "UID124_GENERATION2_AXON_CONTRACT",
    "UID124_GENERATION2_ENDPOINT_IP",
    "VALIDATOR_HOTKEY",
    "announce_reviewed_preview",
    "build_preview",
    "collect_endpoint_proof",
    "finalized_miner_state",
    "load_reviewed_preview",
    "recover_ambiguous_preview",
    "validate_endpoint_proof",
    "validate_preview",
    "write_preview",
]
