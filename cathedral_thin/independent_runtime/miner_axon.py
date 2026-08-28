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

VALIDATOR_HOTKEY = (
    "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"  # pragma: allowlist secret
)
MINER_HOTKEY = (
    "5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G"  # pragma: allowlist secret
)
CATHEDRAL_COLDKEY = (
    "5G6mgvL59o6AM8rFRYbbUpbzjjGwcVLUidpQ1vsz5UkZyw2o"  # pragma: allowlist secret
)

PREVIEW_SCHEMA = "cathedral_sn39_miner_axon_preview_v1"
JOURNAL_SCHEMA = "cathedral_sn39_miner_axon_journal_v1"
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

_CHAIN_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, threading.Lock] = {}


class MinerAxonError(IndependentLiveError):
    """The contract refused before a chain result became uncertain."""


class MinerAxonAmbiguous(MinerAxonError):
    """A serve intent exists and must not be retried without reconciliation."""


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


def _require_ss58(value: object, *, label: str) -> str:
    address = str(value or "")
    try:
        parsed = str(Keypair(ss58_address=address).ss58_address)
    except Exception as exc:
        raise MinerAxonError(f"{label} is not a valid SS58 address") from exc
    if parsed != address:
        raise MinerAxonError(f"{label} is not a canonical SS58 address")
    return address


def _global_ipv4(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise MinerAxonError("miner service IP must be a non-empty string")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise MinerAxonError("miner service IP is invalid") from exc
    if parsed.version != 4 or not parsed.is_global or str(parsed) != value:
        raise MinerAxonError("miner service IP must be one canonical global IPv4")
    return value


def _service_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MinerAxonError("miner service port must be an integer")
    if value != SN39_HTTPS_PORT:
        raise MinerAxonError(f"miner service port must be {SN39_HTTPS_PORT}")
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


def _wallet_public_identity(wallet: Any) -> tuple[str, str]:
    public_hotkey = getattr(wallet, "hotkeypub", None)
    if public_hotkey is None:
        public_hotkey = getattr(wallet, "hotkey", None)
    hotkey = str(getattr(public_hotkey, "ss58_address", "") or "")
    coldkey = str(
        getattr(getattr(wallet, "coldkeypub", None), "ss58_address", "") or ""
    )
    _require_ss58(hotkey, label="announcement wallet public hotkey")
    _require_ss58(coldkey, label="announcement wallet coldkey")
    if hotkey != MINER_HOTKEY:
        raise MinerAxonError("announcement wallet is not the pinned Cathedral miner")
    if coldkey != CATHEDRAL_COLDKEY:
        raise MinerAxonError(
            "announcement wallet coldkey is not the pinned Cathedral coldkey"
        )
    return hotkey, coldkey


def _wallet_identity(wallet: Any) -> tuple[str, str]:
    """Require the signing hotkey only on the explicitly confirmed live path."""

    hotkey = str(getattr(getattr(wallet, "hotkey", None), "ss58_address", "") or "")
    coldkey = str(
        getattr(getattr(wallet, "coldkeypub", None), "ss58_address", "") or ""
    )
    _require_ss58(hotkey, label="announcement signing hotkey")
    _require_ss58(coldkey, label="announcement wallet coldkey")
    if hotkey != MINER_HOTKEY:
        raise MinerAxonError("announcement wallet is not the pinned Cathedral miner")
    if coldkey != CATHEDRAL_COLDKEY:
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


def _registered_row(metagraph: Any) -> tuple[int, str, str, Any]:
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
        if hotkey == MINER_HOTKEY
    ]
    if len(matches) != 1:
        raise MinerAxonError(
            "the pinned Cathedral miner is not registered exactly once on SN39"
        )
    uid, hotkey, coldkey, axon = matches[0]
    _require_ss58(hotkey, label="registered miner hotkey")
    _require_ss58(coldkey, label="registered miner coldkey")
    if coldkey != CATHEDRAL_COLDKEY:
        raise MinerAxonError(
            "the registered miner is not owned by the pinned Cathedral coldkey"
        )
    return uid, hotkey, coldkey, axon


def finalized_miner_state(subtensor: Any) -> FinalizedMinerState:
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
    uid, hotkey, coldkey, axon = _registered_row(metagraph)
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
    subtensor: Any, *, qvl_path: str, ip: str, port: int
) -> EndpointProof:
    """Collect through the reviewed attested-SPKI transport and replay SAT.

    For an IP literal, HttpsEvidenceTransport does not authenticate the
    self-signed certificate through a CA or IP SAN. It authenticates the SPKI
    observed on the wire by requiring fresh TDX REPORT_DATA and QVL to bind it,
    then requires the canonical SAT POST to retain that same SPKI. This is not
    compatibility with an ordinary CA/hostname RemoteMiner client.
    """

    service_ip = _global_ipv4(ip)
    service_port = _service_port(port)
    observed_genesis_hash(subtensor)
    snapshot = snapshot_epoch(subtensor)
    evidence_url = axon_evidence_url(service_ip, service_port)
    sat_url = axon_sat_work_url(service_ip, service_port)
    collected_row = _try_collect(
        evidence_url,
        MINER_HOTKEY,
        VALIDATOR_HOTKEY,
        sat_url,
    )
    collected = collected_row.get("collected")
    if collected is None:
        raise MinerAxonError(
            f"miner evidence collection failed: {collected_row.get('error')}"
        )
    if collected.assigned_hotkey != MINER_HOTKEY:
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
        hotkey=MINER_HOTKEY,
        validator_hotkey=VALIDATOR_HOTKEY,
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
    validate_endpoint_proof(proof, ip=service_ip, port=service_port)
    return proof


def validate_endpoint_proof(
    proof: EndpointProof, *, ip: str, port: int
) -> EndpointProof:
    service_ip = _global_ipv4(ip)
    service_port = _service_port(port)
    if proof.hotkey != MINER_HOTKEY:
        raise MinerAxonError("endpoint proof is assigned to the wrong miner")
    if proof.validator_hotkey != VALIDATOR_HOTKEY:
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


def _announcement_paths(runtime_root: Path) -> tuple[Path, Path]:
    root = Path(runtime_root)
    if not root.is_absolute():
        raise MinerAxonError("runtime root must be absolute")
    return root / LOCK_NAME, root / JOURNAL_NAME


def build_preview(
    *,
    state: FinalizedMinerState,
    proof: EndpointProof,
    runtime_root: Path = DEFAULT_RUNTIME_ROOT,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build the review artifact. This function signs and submits nothing."""

    if state.hotkey != MINER_HOTKEY or state.coldkey != CATHEDRAL_COLDKEY:
        raise MinerAxonError("finalized miner identity differs from the launch pins")
    validate_endpoint_proof(proof, ip=proof.ip, port=proof.port)
    lock_path, journal_path = _announcement_paths(Path(runtime_root))
    already = _same_endpoint(state, ip=proof.ip, port=proof.port)
    document: dict[str, Any] = {
        "schema": PREVIEW_SCHEMA,
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
            "hotkey": MINER_HOTKEY,
            "coldkey": CATHEDRAL_COLDKEY,
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
            "runtime_root": str(Path(runtime_root)),
            "announcement_lock": str(lock_path),
            "ambiguity_journal": str(journal_path),
            "remote_exclusivity": "operator_assertion_required",
        },
        "trust_boundary": {
            "qvl_binary_sha256": LAUNCH_QVL_DIGEST,
            "quote_binds": ["fresh_nonce", "miner_hotkey", "tls_spki"],
            "collector_validator_hotkey": VALIDATOR_HOTKEY,
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
    return validate_preview(document)


def validate_preview(document: Mapping[str, Any]) -> dict[str, Any]:
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
    if set(preview) != expected_top:
        raise MinerAxonError("preview top-level fields differ from the launch schema")
    if preview.get("schema") != PREVIEW_SCHEMA:
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
        "hotkey": MINER_HOTKEY,
        "coldkey": CATHEDRAL_COLDKEY,
    }:
        raise MinerAxonError("preview miner identity differs from the Cathedral pins")
    ip = _global_ipv4(requested.get("ip"))
    port = _service_port(requested.get("port"))
    if dict(requested) != {"ip": ip, "port": port, "protocol": "https"}:
        raise MinerAxonError("preview endpoint differs from the HTTPS launch contract")
    if (
        chain.get("uid") != uid
        or chain.get("hotkey") != MINER_HOTKEY
        or chain.get("coldkey") != CATHEDRAL_COLDKEY
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
    validate_endpoint_proof(proof_object, ip=ip, port=port)
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
    lock_path, journal_path = _announcement_paths(runtime_root)
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
        "collector_validator_hotkey": VALIDATOR_HOTKEY,
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
    document: Mapping[str, Any], path: Path | str
) -> tuple[Path, Path, str]:
    """Create immutable owner-only canonical JSON plus a detached SHA256."""

    validated = validate_preview(document)
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
    path: Path | str, *, reviewed_sha256: str
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
    preview = validate_preview(_strict_json(raw, label="preview"))
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


def _load_journal(path: Path) -> dict[str, Any] | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    raw = _require_owner_only_file(path, max_bytes=MAX_DOCUMENT_BYTES)
    journal = _strict_json(raw, label="announcement journal")
    if journal.get("schema") != JOURNAL_SCHEMA:
        raise MinerAxonError("announcement journal schema differs from the launch pin")
    return journal


def _local_lock(path: Path) -> threading.Lock:
    key = str(path.absolute())
    with _LOCAL_LOCKS_GUARD:
        return _LOCAL_LOCKS.setdefault(key, threading.Lock())


@contextmanager
def _announcement_lock(runtime_root: Path) -> Iterator[None]:
    lock_path, _ = _announcement_paths(runtime_root)
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
    state: FinalizedMinerState, preview: Mapping[str, Any]
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
        or state.hotkey != MINER_HOTKEY
        or state.coldkey != CATHEDRAL_COLDKEY
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


def _fresh_matches_preview(fresh: EndpointProof, preview: Mapping[str, Any]) -> None:
    requested = preview["requested_endpoint"]
    reviewed = preview["endpoint_proof"]
    assert isinstance(requested, Mapping)
    assert isinstance(reviewed, Mapping)
    validate_endpoint_proof(fresh, ip=str(requested["ip"]), port=int(requested["port"]))
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
) -> Mapping[str, Any]:
    state = state_loader(subtensor)
    if not _same_endpoint(state, ip=ip, port=port):
        raise MinerAxonAmbiguous(
            "finalized SN39 axon differs from the authorized HTTPS endpoint"
        )
    if receipt is not None and receipt.get("block_number") is not None:
        receipt_number = _strict_nonnegative_int(
            receipt["block_number"], label="receipt block number"
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
    *, preview: Mapping[str, Any], preview_sha256: str
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
        "hotkey": MINER_HOTKEY,
        "coldkey": CATHEDRAL_COLDKEY,
        "ip": requested["ip"],
        "port": requested["port"],
    }


def _journal_for_attempt(
    *,
    preview: Mapping[str, Any],
    preview_sha256: str,
    fresh: EndpointProof,
    state: FinalizedMinerState,
) -> dict[str, Any]:
    identity = _journal_identity(preview=preview, preview_sha256=preview_sha256)
    attempt_id = "sha256:" + _sha256(_canonical_json_bytes(identity))
    return {
        "schema": JOURNAL_SCHEMA,
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


def _journal_matches(
    journal: Mapping[str, Any], *, preview: Mapping[str, Any], digest: str
) -> None:
    if journal.get("identity") != _journal_identity(
        preview=preview, preview_sha256=digest
    ):
        raise MinerAxonError(
            "announcement journal belongs to a different reviewed preview"
        )
    if journal.get("retry_allowed") is not False:
        raise MinerAxonError("announcement journal does not carry the no-retry fence")


def _recover_existing_journal(
    *,
    journal: dict[str, Any],
    journal_path: Path,
    preview: Mapping[str, Any],
    digest: str,
    subtensor: Any,
    state_loader: Callable[[Any], FinalizedMinerState],
) -> Mapping[str, Any]:
    _journal_matches(journal, preview=preview, digest=digest)
    requested = preview["requested_endpoint"]
    assert isinstance(requested, Mapping)
    ip = str(requested["ip"])
    port = int(requested["port"])
    status = journal.get("status")
    if status not in AMBIGUOUS_STATUSES | FINAL_STATUSES:
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
    _write_state(journal_path, recovered, exclusive=False)
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
) -> Mapping[str, Any]:
    requested = preview["requested_endpoint"]
    assert isinstance(requested, Mapping)
    try:
        readback = _finalized_readback(
            subtensor,
            ip=str(requested["ip"]),
            port=int(requested["port"]),
            receipt=receipt,
            state_loader=state_loader,
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
    try:
        _write_state(journal_path, recovered, exclusive=False)
    except Exception as exc:
        raise MinerAxonAmbiguous(
            "finalized endpoint was read back but proof persistence failed; do not retry"
        ) from exc
    return recovered


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
    state_loader: Callable[[Any], FinalizedMinerState] = finalized_miner_state,
    proof_loader: Callable[..., EndpointProof] = collect_endpoint_proof,
    serve_call: Callable[..., Any] | None = None,
    runtime_root: Path | None = None,
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
    preview, digest = load_reviewed_preview(
        preview_path, reviewed_sha256=reviewed_sha256
    )
    root = Path(DEFAULT_RUNTIME_ROOT if runtime_root is None else runtime_root)
    if root.resolve(strict=False) != DEFAULT_RUNTIME_ROOT.resolve(strict=False):
        raise MinerAxonError(
            f"live announcement requires canonical runtime root {DEFAULT_RUNTIME_ROOT}"
        )
    local = preview["local_state"]
    assert isinstance(local, Mapping)
    if Path(str(local["runtime_root"])).resolve(strict=False) != root.resolve(
        strict=False
    ):
        raise MinerAxonError("reviewed preview names a different runtime root")
    _wallet_identity(wallet)
    requested = preview["requested_endpoint"]
    assert isinstance(requested, Mapping)
    ip = _global_ipv4(requested["ip"])
    port = _service_port(requested["port"])
    _, journal_path = _announcement_paths(root)
    with _announcement_lock(root):
        existing = _load_journal(journal_path)
        if existing is not None:
            return _recover_existing_journal(
                journal=existing,
                journal_path=journal_path,
                preview=preview,
                digest=digest,
                subtensor=subtensor,
                state_loader=state_loader,
            )
        before = state_loader(subtensor)
        if _same_endpoint(before, ip=ip, port=port):
            return {
                "schema": JOURNAL_SCHEMA,
                "status": "already_announced_no_write",
                "identity": _journal_identity(preview=preview, preview_sha256=digest),
                "readback": before.artifact(),
                "remote_exclusive_announcer_asserted": True,
                "serve_axon_called": False,
                "retry_allowed": False,
            }
        _current_matches_preview(before, preview)
        fresh = proof_loader(subtensor, qvl_path=qvl_path, ip=ip, port=port)
        _fresh_matches_preview(fresh, preview)
        after = state_loader(subtensor)
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
                    "schema": JOURNAL_SCHEMA,
                    "status": "already_announced_no_write",
                    "identity": _journal_identity(
                        preview=preview, preview_sha256=digest
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
        journal = _journal_for_attempt(
            preview=preview,
            preview_sha256=digest,
            fresh=fresh,
            state=after,
        )
        _write_state(journal_path, journal, exclusive=True)
        call = serve_call or subtensor.serve_axon
        try:
            response = call(
                netuid=NETUID,
                axon=advertisement,
                mev_protection=False,
                period=ANNOUNCEMENT_PERIOD_BLOCKS,
                raise_error=True,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
        except Exception:
            return _resolve_after_call(
                journal=journal,
                journal_path=journal_path,
                preview=preview,
                subtensor=subtensor,
                state_loader=state_loader,
                receipt=None,
                failure_kind="SDK_EXCEPTION",
            )
        receipt = _receipt_fields(response)
        if getattr(response, "success", None) is not True:
            return _resolve_after_call(
                journal=journal,
                journal_path=journal_path,
                preview=preview,
                subtensor=subtensor,
                state_loader=state_loader,
                receipt=receipt,
                failure_kind="SDK_UNSUCCESSFUL",
            )
        try:
            readback = _finalized_readback(
                subtensor,
                ip=ip,
                port=port,
                receipt=receipt,
                state_loader=state_loader,
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
        try:
            _write_state(journal_path, finalized, exclusive=False)
        except Exception as exc:
            raise MinerAxonAmbiguous(
                "serve_axon finalized but proof persistence failed; do not retry"
            ) from exc
        return finalized


def recover_ambiguous_preview(
    *,
    subtensor: Any,
    preview_path: Path | str,
    reviewed_sha256: str,
    state_loader: Callable[[Any], FinalizedMinerState] = finalized_miner_state,
    runtime_root: Path | None = None,
) -> Mapping[str, Any]:
    """Read finalized state for an existing intent. Never signs or resubmits."""

    preview, digest = load_reviewed_preview(
        preview_path, reviewed_sha256=reviewed_sha256
    )
    root = Path(DEFAULT_RUNTIME_ROOT if runtime_root is None else runtime_root)
    if root.resolve(strict=False) != DEFAULT_RUNTIME_ROOT.resolve(strict=False):
        raise MinerAxonError(
            f"recovery requires canonical runtime root {DEFAULT_RUNTIME_ROOT}"
        )
    _, journal_path = _announcement_paths(root)
    with _announcement_lock(root):
        journal = _load_journal(journal_path)
        if journal is None:
            raise MinerAxonError("no announcement journal exists to recover")
        return _recover_existing_journal(
            journal=journal,
            journal_path=journal_path,
            preview=preview,
            digest=digest,
            subtensor=subtensor,
            state_loader=state_loader,
        )


__all__ = [
    "ANNOUNCEMENT_PERIOD_BLOCKS",
    "CATHEDRAL_COLDKEY",
    "DEFAULT_PREVIEW",
    "DEFAULT_RUNTIME_ROOT",
    "EndpointProof",
    "FINAL_STATUSES",
    "FinalizedMinerState",
    "JOURNAL_SCHEMA",
    "MINER_HOTKEY",
    "MinerAxonAmbiguous",
    "MinerAxonError",
    "NETWORK",
    "NETUID",
    "PREVIEW_ALREADY",
    "PREVIEW_READY",
    "PREVIEW_SCHEMA",
    "SN39_HTTPS_PORT",
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
