"""Durable direct SN39 weight writer with hash-only restart recovery.

The signed extrinsic hash, nonce, era, exact call, and evidence identity reach
disk before broadcast.  A restart with a pending intent only searches finalized
blocks for that hash.  Recovery never signs and never resubmits.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import stat
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from bittensor.core.extrinsics.pallets import SubtensorModule
from bittensor.utils import get_mechid_storage_index

from cathedral_thin.independent.constants import (
    COMMIT_REVEAL_ENABLED,
    MAX_WEIGHT_LIMIT,
    MECID,
    MIN_ALLOWED_WEIGHTS,
    NETUID,
    SN39_MORTAL_PERIOD_BLOCKS,
    VERSION_KEY,
    W,
)
from cathedral_thin.independent.submit import build_mechanism_weights_kwargs

from .axon import finalized_head, observed_genesis_hash
from .direct_contract import (
    DIRECT_PLAN_SCHEMA,
    DirectSubmissionReceipt,
    DirectValidatorError,
    DirectWeightPlan,
    FinalizedMetagraphSnapshot,
    zero_burn_vector,
)
from .preview_io import canonical_document_bytes
from .qvl import DIRECT_VALIDATOR_QVL_DIGEST

STATE_SCHEMA = "cathedral_direct_validator_state_v1"
STATUS_CONFIRMED = "CONFIRMED"
STATUS_RECOVERED = "RECOVERED_CONFIRMED"
STATUS_EXPIRED = "EXPIRED_WITHOUT_INCLUSION"
MAX_STATE_BYTES = 1_048_576
DIRECT_STATE_ROOT = Path.home() / ".local/state/cathedral-validator/direct-writer"
DIRECT_STATE_SCOPE = "finney-sn39-mechanism-0"
CONFIRMATION_WAIT_SECONDS = 60.0
CONFIRMATION_POLL_SECONDS = 2.0
_CHAIN_HASH_HEX = frozenset("0123456789abcdef")
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, threading.Lock] = {}
_STATUS_EXTRINSIC_FINALIZED = "EXTRINSIC_FINALIZED"


class DirectSubmissionAmbiguous(DirectValidatorError):
    """One exact signed hash is fenced and must be recovered, never retried."""


class DirectSubmissionContradiction(DirectSubmissionAmbiguous):
    """Finalized history or durable state contradicts the signed intent."""


def _presign_deadline(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise DirectValidatorError(
            "pre-sign deadline must be a finite monotonic timestamp"
        )
    return float(value)


def _require_presign_time(deadline: float, *, stage: str) -> None:
    if time.monotonic() >= deadline:
        raise DirectValidatorError(f"pre-sign deadline expired during {stage}")


def _canonical_hash(value: object, *, label: str) -> str:
    try:
        if isinstance(value, str):
            text = value
        elif hasattr(value, "hex"):
            text = str(value.hex())
        else:
            text = bytes(value).hex()
    except (AttributeError, TypeError, ValueError) as exc:
        raise DirectSubmissionAmbiguous(f"{label} is not a usable hash") from exc
    text = text.lower()
    if not text.startswith("0x"):
        text = "0x" + text
    body = text[2:]
    if len(body) != 64 or any(character not in _CHAIN_HASH_HEX for character in body):
        raise DirectSubmissionAmbiguous(f"{label} is not a canonical chain hash")
    return text


def _strict_json(raw: bytes) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DirectSubmissionContradiction(f"direct state repeats key {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(raw.decode("ascii"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DirectSubmissionContradiction("direct state is not strict JSON") from exc
    if not isinstance(document, dict):
        raise DirectSubmissionContradiction("direct state is not an object")
    return document


def _initial_state() -> dict[str, object]:
    return {"schema": STATE_SCHEMA, "pending": None, "last_attempt": None}


def _attempt_id(identity: Mapping[str, Any], intent: Mapping[str, Any]) -> str:
    exact = {"identity": identity, "intent": intent}
    return "sha256:" + hashlib.sha256(canonical_document_bytes(exact)).hexdigest()


def _local_lock(path: Path) -> threading.Lock:
    key = str(path.absolute())
    with _LOCAL_LOCKS_GUARD:
        return _LOCAL_LOCKS.setdefault(key, threading.Lock())


def _chain_call_arg(call: Mapping[str, Any], name: str) -> Any:
    for item in call.get("call_args") or ():
        if isinstance(item, Mapping) and item.get("name") == name:
            return item.get("value")
    return None


def _raw_value(value: Any) -> Any:
    value = getattr(value, "value", value)
    if hasattr(value, "tolist"):
        value = value.tolist()
    if hasattr(value, "item"):
        value = value.item()
    return value


def _nonnegative_int(value: Any, *, label: str) -> int:
    value = _raw_value(value)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DirectValidatorError(f"{label} is not a non-negative integer")
    return value


def _balance_rao(value: Any, *, label: str) -> int:
    return _nonnegative_int(getattr(value, "rao", value), label=label)


def _strict_bool(value: Any, *, label: str) -> bool:
    value = _raw_value(value)
    item = getattr(value, "item", None)
    if callable(item):
        value = item()
    if type(value) is not bool:
        raise DirectValidatorError(f"{label} is not an explicit boolean")
    return value


def _stored_weight_rows(value: Any) -> tuple[tuple[int, int], ...]:
    raw = _raw_value(value)
    if not isinstance(raw, (list, tuple)):
        raise DirectSubmissionAmbiguous("stored mechanism weights are unavailable")
    result: list[tuple[int, int]] = []
    for row in raw:
        row = _raw_value(row)
        if not isinstance(row, (list, tuple)) or len(row) != 2:
            raise DirectSubmissionAmbiguous("stored mechanism weight row is malformed")
        uid = _raw_value(row[0])
        weight = _raw_value(row[1])
        if (
            isinstance(uid, bool)
            or not isinstance(uid, int)
            or not 0 <= uid <= W
            or isinstance(weight, bool)
            or not isinstance(weight, int)
            or not 0 < weight <= W
        ):
            raise DirectSubmissionAmbiguous("stored mechanism weight value is invalid")
        result.append((uid, weight))
    return tuple(result)


def _read_fresh_snapshot(subtensor: Any, keypair: Any) -> FinalizedMetagraphSnapshot:
    # Keep the writer's contract module independent of the collection runtime.
    from .direct_validator import finalized_serving_miners_snapshot

    return finalized_serving_miners_snapshot(subtensor, keypair)


def canonical_state_path(keypair: Any) -> Path:
    """Return the one operational journal path for this Finney SN39 signer."""

    hotkey = str(getattr(keypair, "ss58_address", ""))
    if not hotkey or not hotkey.isascii() or not hotkey.isalnum() or len(hotkey) > 64:
        raise DirectValidatorError("direct writer hotkey is not path-safe")
    return DIRECT_STATE_ROOT / DIRECT_STATE_SCOPE / hotkey / "state.json"


class DirectWeightWriter:
    """One in-process writer. The journal is its sole retry authority."""

    def __init__(
        self,
        *,
        subtensor: Any,
        keypair: Any,
        snapshot_reader: Callable[[Any, Any], FinalizedMetagraphSnapshot] | None = None,
        call_builder: Callable[[Mapping[str, Any]], Any] | None = None,
    ) -> None:
        self.subtensor = subtensor
        self.keypair = keypair
        self.state_path = canonical_state_path(keypair)
        self.snapshot_reader = snapshot_reader or _read_fresh_snapshot
        self.call_builder = call_builder or self._build_call

    def _prepare_parent(self) -> None:
        parent = self.state_path.parent
        if parent.is_symlink():
            raise DirectValidatorError("direct state parent is a symlink")
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise DirectValidatorError("direct state parent is unusable") from exc
        metadata = parent.stat()
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise DirectValidatorError("direct state parent is not owner-controlled")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._prepare_parent()
        local = _local_lock(self.state_path)
        if not local.acquire(blocking=False):
            raise DirectSubmissionAmbiguous("another direct writer holds this state")
        descriptor: int | None = None
        try:
            flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.state_path.with_suffix(".lock"), flags, 0o600)
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise DirectSubmissionAmbiguous(
                    "another process holds the direct writer lock"
                ) from exc
            yield
        finally:
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)
            local.release()

    def _read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return _initial_state()
        if self.state_path.is_symlink():
            raise DirectSubmissionContradiction("direct state is a symlink")
        metadata = self.state_path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_STATE_BYTES
        ):
            raise DirectSubmissionContradiction("direct state file is not owner-only")
        try:
            raw = self.state_path.read_bytes()
        except OSError as exc:
            raise DirectSubmissionAmbiguous("direct state could not be read") from exc
        document = _strict_json(raw)
        if (
            set(document) != {"schema", "pending", "last_attempt"}
            or document.get("schema") != STATE_SCHEMA
        ):
            raise DirectSubmissionContradiction("direct state schema is invalid")
        if document["pending"] is not None and not isinstance(
            document["pending"], dict
        ):
            raise DirectSubmissionContradiction("direct pending state is invalid")
        if document["last_attempt"] is not None and not isinstance(
            document["last_attempt"], dict
        ):
            raise DirectSubmissionContradiction("direct last attempt is invalid")
        return document

    def _write_state(self, document: Mapping[str, Any]) -> None:
        if set(document) != {"schema", "pending", "last_attempt"}:
            raise DirectSubmissionContradiction("direct state fields are invalid")
        body = canonical_document_bytes(document)
        if len(body) > MAX_STATE_BYTES:
            raise DirectSubmissionContradiction("direct state exceeds 1 MiB")
        temporary: str | None = None
        try:
            descriptor, temporary = tempfile.mkstemp(
                dir=self.state_path.parent,
                prefix=f".{self.state_path.name}.",
                suffix=".tmp",
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.state_path)
            temporary = None
            directory = os.open(self.state_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise DirectSubmissionAmbiguous(
                "direct state could not be persisted"
            ) from exc
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _build_call(self, kwargs: Mapping[str, Any]) -> Any:
        return SubtensorModule(self.subtensor).set_mechanism_weights(
            netuid=int(kwargs["netuid"]),
            mecid=int(kwargs["mecid"]),
            dests=list(kwargs["dests"]),
            weights=list(kwargs["weights"]),
            version_key=int(kwargs["version_key"]),
        )

    def _validate_plan(self, plan: DirectWeightPlan) -> dict[str, Any]:
        if not isinstance(plan, DirectWeightPlan):
            raise DirectValidatorError("direct writer requires a DirectWeightPlan")
        kwargs = plan.kwargs()
        expected = build_mechanism_weights_kwargs(
            dests=list(plan.wire_uids), weights=list(plan.wire_weights)
        )
        if kwargs != expected or kwargs != {
            "netuid": NETUID,
            "mecid": MECID,
            "dests": list(plan.wire_uids),
            "weights": list(plan.wire_weights),
            "version_key": VERSION_KEY,
        }:
            raise DirectValidatorError("direct plan is not an exact zero-burn vector")
        uid_hotkeys = dict(plan.uid_hotkeys)
        raw_scores = dict(plan.raw_scores)
        machine_ids = dict(plan.machine_ids_by_uid)
        snapshot_hotkeys = {miner.uid: miner.hotkey for miner in plan.snapshot.miners}
        expected_uids, expected_weights = zero_burn_vector(plan.raw_scores, uid_hotkeys)
        if (
            len(uid_hotkeys) != len(plan.uid_hotkeys)
            or len(raw_scores) != len(plan.raw_scores)
            or len(machine_ids) != len(plan.machine_ids_by_uid)
            or uid_hotkeys != snapshot_hotkeys
            or set(raw_scores) != set(uid_hotkeys)
            or set(machine_ids) != set(uid_hotkeys)
            or any(
                not isinstance(ids, tuple)
                or len(ids) != raw_scores[uid]
                or len(ids) != len(set(ids))
                or any(not isinstance(value, str) or not value for value in ids)
                for uid, ids in machine_ids.items()
            )
            or len({value for ids in machine_ids.values() for value in ids})
            != sum(len(ids) for ids in machine_ids.values())
            or plan.wire_uids != expected_uids
            or plan.wire_weights != expected_weights
            or set(plan.wire_uids)
            != {uid for uid, score in raw_scores.items() if score > 0}
            or any(uid not in uid_hotkeys for uid in plan.wire_uids)
            or plan.snapshot.validator_uid in plan.wire_uids
            or sum(plan.wire_weights) != 0xFFFF
            or plan.qvl_digest != DIRECT_VALIDATOR_QVL_DIGEST
            or not isinstance(plan.evidence_digest, str)
            or not plan.evidence_digest.startswith("sha256:")
            or len(plan.evidence_digest) != 71
            or any(
                character not in _CHAIN_HASH_HEX
                for character in plan.evidence_digest[7:]
            )
        ):
            raise DirectValidatorError("direct plan UID identities are inconsistent")
        if str(getattr(self.keypair, "ss58_address", "")) != (
            plan.snapshot.validator_hotkey
        ) or not callable(getattr(self.keypair, "sign", None)):
            raise DirectValidatorError("direct writer key does not match the plan")
        return kwargs

    def _require_fresh_snapshot(
        self,
        plan: DirectWeightPlan,
        fresh: FinalizedMetagraphSnapshot,
        *,
        presign_deadline: float,
    ) -> None:
        _require_presign_time(presign_deadline, stage="freshness preflight")
        anchor = plan.snapshot
        anchor_miners = anchor.miner_by_uid()
        fresh_miners = fresh.miner_by_uid()
        if (
            fresh.block_number < anchor.block_number
            or fresh.block_number - anchor.block_number >= SN39_MORTAL_PERIOD_BLOCKS
            or fresh.validator_uid != anchor.validator_uid
            or fresh.validator_hotkey != anchor.validator_hotkey
            or fresh.miners != anchor.miners
            or fresh_miners != anchor_miners
        ):
            raise DirectValidatorError(
                "validator or serving miner set changed before direct signing"
            )
        try:
            canonical = _canonical_hash(
                self.subtensor.substrate.get_block_hash(anchor.block_number),
                label="evidence anchor",
            )
        except DirectSubmissionAmbiguous as exc:
            raise DirectValidatorError("evidence anchor cannot be rechecked") from exc
        _require_presign_time(presign_deadline, stage="anchor freshness RPC")
        if canonical != anchor.block_hash:
            raise DirectValidatorError("evidence anchor is no longer canonical")

    def _require_finalized_eligibility(
        self,
        plan: DirectWeightPlan,
        fresh: FinalizedMetagraphSnapshot,
        *,
        presign_deadline: float,
    ) -> dict[str, object]:
        """Refuse every deterministic chain-policy failure before signing."""

        block = fresh.block_number
        try:
            _require_presign_time(presign_deadline, stage="eligibility preflight")
            rate_limit = _nonnegative_int(
                self.subtensor.weights_rate_limit(NETUID, block=block),
                label="SN39 weight cooldown",
            )
            _require_presign_time(presign_deadline, stage="weight cooldown RPC")
            blocks_since = _nonnegative_int(
                self.subtensor.blocks_since_last_update(
                    NETUID, fresh.validator_uid, block=block
                ),
                label="validator blocks since last update",
            )
            _require_presign_time(presign_deadline, stage="last-update RPC")
            min_allowed = _nonnegative_int(
                self.subtensor.min_allowed_weights(netuid=NETUID, block=block),
                label="SN39 minimum allowed weights",
            )
            _require_presign_time(presign_deadline, stage="minimum-weights RPC")
            max_weight = float(
                _raw_value(self.subtensor.max_weight_limit(netuid=NETUID, block=block))
            )
            _require_presign_time(presign_deadline, stage="maximum-weight RPC")
            commit_reveal = _strict_bool(
                self.subtensor.commit_reveal_enabled(netuid=NETUID, block=block),
                label="SN39 commit-reveal state",
            )
            _require_presign_time(presign_deadline, stage="commit-reveal RPC")
            mechanism_count = _nonnegative_int(
                self.subtensor.get_mechanism_count(NETUID, block=block),
                label="SN39 mechanism count",
            )
            _require_presign_time(presign_deadline, stage="mechanism-count RPC")
            metagraph = self.subtensor.metagraph(NETUID, block=block)
            _require_presign_time(presign_deadline, stage="eligibility metagraph RPC")
            if (
                _nonnegative_int(
                    int(getattr(metagraph, "block", -1)),
                    label="eligibility metagraph block",
                )
                != block
            ):
                raise DirectValidatorError(
                    "eligibility metagraph is not at the finalized sign head"
                )
            uids = [int(value) for value in list(metagraph.uids)]
            hotkeys = [str(value) for value in list(metagraph.hotkeys)]
            permits = list(metagraph.validator_permit)
            last_updates = [
                _nonnegative_int(int(value), label="validator last update")
                for value in list(metagraph.last_update)
            ]
            info = self.subtensor.get_metagraph_info(NETUID, MECID, block=block)
            _require_presign_time(presign_deadline, stage="metagraph-info RPC")
            if info is None or int(getattr(info, "block", -1)) != block:
                raise DirectValidatorError(
                    "SN39 metagraph info is not at the finalized sign head"
                )
            info_hotkeys = [str(value) for value in list(info.hotkeys)]
            info_permits = tuple(
                _strict_bool(value, label="finalized metagraph-info permit")
                for value in list(info.validator_permit)
            )
            info_stakes = list(info.total_stake)
            stake_threshold = _nonnegative_int(
                self.subtensor.substrate.query(
                    module="SubtensorModule",
                    storage_function="StakeThreshold",
                    params=[],
                    block_hash=fresh.block_hash,
                ),
                label="weight stake threshold",
            )
            _require_presign_time(presign_deadline, stage="stake-threshold RPC")
            version_key = _nonnegative_int(
                self.subtensor.substrate.query(
                    module="SubtensorModule",
                    storage_function="WeightsVersionKey",
                    params=[NETUID],
                    block_hash=fresh.block_hash,
                ),
                label="SN39 weight version",
            )
            _require_presign_time(presign_deadline, stage="weight-version RPC")
        except DirectValidatorError:
            raise
        except Exception as exc:
            raise DirectValidatorError(
                "finalized direct-write eligibility is unavailable"
            ) from exc

        strict_permits = tuple(
            _strict_bool(value, label="finalized validator permit") for value in permits
        )
        if (
            not (len(uids) == len(hotkeys) == len(permits) == len(last_updates))
            or len(set(uids)) != len(uids)
            or len(set(hotkeys)) != len(hotkeys)
        ):
            raise DirectValidatorError("finalized eligibility rows are inconsistent")
        matches = [
            index
            for index, value in enumerate(hotkeys)
            if value == fresh.validator_hotkey
        ]
        if (
            len(matches) != 1
            or uids[matches[0]] != fresh.validator_uid
            or strict_permits[matches[0]] is not True
        ):
            raise DirectValidatorError("validator is not eligible at the sign head")
        if not (
            len(info_hotkeys) == len(info_permits) == len(info_stakes)
            and 0 <= fresh.validator_uid < len(info_hotkeys)
            and info_hotkeys[fresh.validator_uid] == fresh.validator_hotkey
            and info_permits[fresh.validator_uid] is True
        ):
            raise DirectValidatorError(
                "validator metagraph-info eligibility is inconsistent"
            )
        validator_stake = _balance_rao(
            info_stakes[fresh.validator_uid], label="validator effective stake"
        )
        if validator_stake < stake_threshold:
            raise DirectValidatorError(
                "validator is below the finalized weight stake threshold"
            )
        last_update = last_updates[matches[0]]
        if block - last_update != blocks_since:
            raise DirectValidatorError(
                "validator last update and cooldown distance disagree"
            )
        if rate_limit < SN39_MORTAL_PERIOD_BLOCKS:
            raise DirectValidatorError("SN39 cooldown is shorter than the mortal era")
        if blocks_since < rate_limit:
            raise DirectValidatorError(
                "validator is inside the finalized weight cooldown"
            )
        if min_allowed != MIN_ALLOWED_WEIGHTS or len(plan.wire_uids) < min_allowed:
            raise DirectValidatorError("direct vector violates minimum weight count")
        if max_weight != MAX_WEIGHT_LIMIT or max(plan.wire_weights) / W > max_weight:
            raise DirectValidatorError(
                "direct vector violates the maximum weight limit"
            )
        if commit_reveal is not COMMIT_REVEAL_ENABLED:
            raise DirectValidatorError("SN39 commit-reveal policy blocks direct writes")
        if mechanism_count <= MECID:
            raise DirectValidatorError("SN39 mechanism 0 is unavailable")
        if version_key != 0 and VERSION_KEY < version_key:
            raise DirectValidatorError(
                "direct weight version is below the chain minimum"
            )
        return {
            "block_number": block,
            "block_hash": fresh.block_hash,
            "validator_last_update": last_update,
            "blocks_since_last_update": blocks_since,
            "weights_rate_limit": rate_limit,
            "min_allowed_weights": min_allowed,
            "max_weight_limit": max_weight,
            "commit_reveal_enabled": commit_reveal,
            "mechanism_count": mechanism_count,
            "weights_version_key": version_key,
            "validator_stake_rao": validator_stake,
            "stake_threshold_rao": stake_threshold,
        }

    def _last_anchor(self, state: Mapping[str, Any]) -> int | None:
        last = state.get("last_attempt")
        if last is None:
            return None
        try:
            value = last["identity"]["anchor"]["block_number"]
        except (KeyError, TypeError) as exc:
            raise DirectSubmissionContradiction(
                "last direct attempt lost its anchor"
            ) from exc
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise DirectSubmissionContradiction("last direct anchor is invalid")
        return value

    def _pending(self, state: Mapping[str, Any]) -> dict[str, Any] | None:
        pending = state.get("pending")
        if pending is None:
            return None
        required = {"attempt_id", "phase", "identity", "intent", "receipt", "error"}
        if not isinstance(pending, dict) or set(pending) != required:
            raise DirectSubmissionContradiction("pending direct intent is malformed")
        attempt_id = pending.get("attempt_id")
        if (
            not isinstance(attempt_id, str)
            or not attempt_id.startswith("sha256:")
            or len(attempt_id) != 71
            or not isinstance(pending.get("identity"), dict)
            or not isinstance(pending.get("intent"), dict)
        ):
            raise DirectSubmissionContradiction("pending direct identity is malformed")
        digest = _attempt_id(pending["identity"], pending["intent"])
        if digest != attempt_id:
            raise DirectSubmissionContradiction("pending direct attempt id is wrong")
        return pending

    def _exact_call(
        self, observed: Mapping[str, Any], intent: Mapping[str, Any]
    ) -> bool:
        call = observed.get("call")
        kwargs = intent.get("kwargs")
        if not isinstance(call, Mapping) or not isinstance(kwargs, Mapping):
            return False
        return (
            str(observed.get("address")) == str(intent.get("validator_hotkey"))
            and call.get("call_module") == "SubtensorModule"
            and call.get("call_function") == "set_mechanism_weights"
            and _chain_call_arg(call, "netuid") == kwargs.get("netuid")
            and _chain_call_arg(call, "mecid") == kwargs.get("mecid")
            and _chain_call_arg(call, "version_key") == kwargs.get("version_key")
            and _chain_call_arg(call, "dests") == kwargs.get("dests")
            and _chain_call_arg(call, "weights") == kwargs.get("weights")
        )

    def _confirmation_contract(
        self, pending: Mapping[str, Any]
    ) -> tuple[int, str, dict[int, str], tuple[int, ...], tuple[int, ...]]:
        identity = pending.get("identity")
        intent = pending.get("intent")
        if not isinstance(identity, Mapping) or not isinstance(intent, Mapping):
            raise DirectSubmissionContradiction("confirmation identity is unavailable")
        anchor = identity.get("anchor")
        validator = anchor.get("validator") if isinstance(anchor, Mapping) else None
        miners = anchor.get("miners") if isinstance(anchor, Mapping) else None
        uid_rows = identity.get("uid_hotkeys")
        kwargs = intent.get("kwargs")
        if (
            identity.get("schema") != DIRECT_PLAN_SCHEMA
            or identity.get("qvl_digest") != DIRECT_VALIDATOR_QVL_DIGEST
            or identity.get("burn_uid") is not None
            or identity.get("burn_weight") != 0
            or identity.get("kwargs") != kwargs
            or not isinstance(validator, Mapping)
            or not isinstance(miners, list)
            or not isinstance(uid_rows, list)
            or not isinstance(kwargs, Mapping)
        ):
            raise DirectSubmissionContradiction("confirmation identity is malformed")
        validator_uid = validator.get("uid")
        validator_hotkey = validator.get("hotkey")
        if (
            isinstance(validator_uid, bool)
            or not isinstance(validator_uid, int)
            or not isinstance(validator_hotkey, str)
            or not validator_hotkey
            or intent.get("validator_hotkey") != validator_hotkey
        ):
            raise DirectSubmissionContradiction(
                "confirmation signer identity is malformed"
            )
        uid_hotkeys: dict[int, str] = {}
        for row in uid_rows:
            if (
                not isinstance(row, list)
                or len(row) != 2
                or isinstance(row[0], bool)
                or not isinstance(row[0], int)
                or not isinstance(row[1], str)
                or not row[1]
                or row[0] in uid_hotkeys
            ):
                raise DirectSubmissionContradiction(
                    "confirmation miner identity is malformed"
                )
            uid_hotkeys[row[0]] = row[1]
        anchor_hotkeys: dict[int, str] = {}
        for row in miners:
            if not isinstance(row, Mapping):
                raise DirectSubmissionContradiction(
                    "confirmation anchor miner is malformed"
                )
            uid = row.get("uid")
            hotkey = row.get("hotkey")
            if (
                isinstance(uid, bool)
                or not isinstance(uid, int)
                or not isinstance(hotkey, str)
                or not hotkey
                or uid in anchor_hotkeys
            ):
                raise DirectSubmissionContradiction(
                    "confirmation anchor miner identity is malformed"
                )
            anchor_hotkeys[uid] = hotkey
        try:
            dests = tuple(kwargs["dests"])
            weights = tuple(kwargs["weights"])
        except (KeyError, TypeError) as exc:
            raise DirectSubmissionContradiction(
                "confirmation weight vector is malformed"
            ) from exc
        if (
            uid_hotkeys != anchor_hotkeys
            or not dests
            or len(dests) != len(weights)
            or set(dests) - set(uid_hotkeys)
            or validator_uid in dests
        ):
            raise DirectSubmissionContradiction(
                "confirmation weight identities disagree"
            )
        try:
            expected_kwargs = build_mechanism_weights_kwargs(
                dests=dests, weights=weights
            )
        except Exception as exc:
            raise DirectSubmissionContradiction(
                "confirmation weight vector is invalid"
            ) from exc
        if expected_kwargs != dict(kwargs):
            raise DirectSubmissionContradiction(
                "confirmation weight identities disagree"
            )
        return validator_uid, validator_hotkey, uid_hotkeys, dests, weights

    def _prove_stored_state(
        self,
        *,
        block_number: int,
        block_hash: str,
        validator_uid: int,
        validator_hotkey: str,
        uid_hotkeys: Mapping[int, str],
        dests: tuple[int, ...],
        weights: tuple[int, ...],
        require_dest_mapping: bool,
    ) -> None:
        try:
            canonical = _canonical_hash(
                self.subtensor.substrate.get_block_hash(block_number),
                label="confirmation block",
            )
            metagraph = self.subtensor.metagraph(NETUID, block=block_number)
            metagraph_block = int(getattr(metagraph, "block", -1))
            uids = [int(value) for value in list(metagraph.uids)]
            hotkeys = [str(value) for value in list(metagraph.hotkeys)]
            permits = tuple(
                _strict_bool(value, label="confirmation validator permit")
                for value in list(metagraph.validator_permit)
            )
            stored = self.subtensor.substrate.query(
                module="SubtensorModule",
                storage_function="Weights",
                params=[get_mechid_storage_index(NETUID, MECID), validator_uid],
                block_hash=block_hash,
            )
            stored_rows = _stored_weight_rows(stored)
        except DirectSubmissionContradiction:
            raise
        except DirectSubmissionAmbiguous:
            raise
        except Exception as exc:
            raise DirectSubmissionAmbiguous(
                f"finalized confirmation block {block_number} is unavailable"
            ) from exc
        if canonical != block_hash or metagraph_block != block_number:
            raise DirectSubmissionAmbiguous(
                f"finalized confirmation block {block_number} is not canonical"
            )
        if (
            not (len(uids) == len(hotkeys) == len(permits))
            or len(set(uids)) != len(uids)
            or len(set(hotkeys)) != len(hotkeys)
        ):
            raise DirectSubmissionAmbiguous(
                f"finalized metagraph at {block_number} is inconsistent"
            )
        uid_to_index = {uid: index for index, uid in enumerate(uids)}
        validator_index = uid_to_index.get(validator_uid)
        if (
            validator_index is None
            or hotkeys[validator_index] != validator_hotkey
            or permits[validator_index] is not True
        ):
            raise DirectSubmissionContradiction(
                f"validator mapping changed at finalized block {block_number}"
            )
        if require_dest_mapping:
            for uid in dests:
                index = uid_to_index.get(uid)
                if index is None or hotkeys[index] != uid_hotkeys[uid]:
                    raise DirectSubmissionContradiction(
                        "weighted miner mapping changed at finalized block "
                        f"{block_number}"
                    )
        if stored_rows != tuple(zip(dests, weights)):
            raise DirectSubmissionContradiction(
                f"stored mechanism row differs at finalized block {block_number}"
            )

    def _confirm_finalized_effect(
        self,
        pending: Mapping[str, Any],
        located: DirectSubmissionReceipt,
        *,
        recovered: bool,
    ) -> DirectSubmissionReceipt:
        if located.block_number is None or located.block_hash is None:
            raise DirectSubmissionContradiction(
                "finalized extrinsic has no inclusion block"
            )
        deadline = time.monotonic() + CONFIRMATION_WAIT_SECONDS
        while True:
            try:
                finalized_number, _finalized_hash = finalized_head(self.subtensor)
            except Exception as exc:
                raise DirectSubmissionAmbiguous(
                    "later finalized heads are unavailable"
                ) from exc
            if finalized_number >= located.block_number + 2:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DirectSubmissionAmbiguous(
                    "two later finalized heads are not available yet"
                )
            time.sleep(min(CONFIRMATION_POLL_SECONDS, remaining))
        contract = self._confirmation_contract(pending)
        block_numbers = (
            located.block_number,
            located.block_number + 1,
            located.block_number + 2,
        )
        proven: list[tuple[int, str]] = []
        for block_number in block_numbers:
            try:
                raw_block_hash = self.subtensor.substrate.get_block_hash(block_number)
            except Exception as exc:
                raise DirectSubmissionAmbiguous(
                    f"confirmation block {block_number} hash is unavailable"
                ) from exc
            try:
                block_hash = _canonical_hash(raw_block_hash, label="confirmation block")
            except DirectSubmissionAmbiguous as exc:
                raise DirectSubmissionAmbiguous(
                    f"confirmation block {block_number} hash is invalid"
                ) from exc
            if (
                block_number == located.block_number
                and block_hash != located.block_hash
            ):
                raise DirectSubmissionContradiction(
                    "finalized inclusion hash is no longer canonical"
                )
            self._prove_stored_state(
                block_number=block_number,
                block_hash=block_hash,
                validator_uid=contract[0],
                validator_hotkey=contract[1],
                uid_hotkeys=contract[2],
                dests=contract[3],
                weights=contract[4],
                require_dest_mapping=block_number == located.block_number,
            )
            proven.append((block_number, block_hash))
        return DirectSubmissionReceipt(
            status=STATUS_RECOVERED if recovered else STATUS_CONFIRMED,
            attempt_id=located.attempt_id,
            extrinsic_hash=located.extrinsic_hash,
            block_hash=located.block_hash,
            block_number=located.block_number,
            recovered=recovered,
            confirmation_heads=tuple(proven),
        )

    def _locate(
        self, pending: Mapping[str, Any]
    ) -> tuple[str, DirectSubmissionReceipt | None]:
        intent = pending["intent"]
        try:
            extrinsic_hash = _canonical_hash(
                intent["extrinsic_hash"], label="signed extrinsic"
            )
            era_reference = intent["era_reference_block"]
            period = intent["mortal_period_blocks"]
            kwargs = intent["kwargs"]
        except (KeyError, TypeError) as exc:
            raise DirectSubmissionContradiction(
                "pending signed intent is incomplete"
            ) from exc
        if not isinstance(kwargs, Mapping):
            raise DirectSubmissionContradiction("pending signed kwargs are invalid")
        try:
            expected_kwargs = build_mechanism_weights_kwargs(
                dests=list(kwargs.get("dests", ())),
                weights=list(kwargs.get("weights", ())),
            )
        except Exception as exc:
            raise DirectSubmissionContradiction(
                "pending signed weight vector is invalid"
            ) from exc
        if (
            isinstance(era_reference, bool)
            or not isinstance(era_reference, int)
            or era_reference <= 0
            or period != SN39_MORTAL_PERIOD_BLOCKS
            or kwargs != expected_kwargs
        ):
            raise DirectSubmissionContradiction("pending signed intent is invalid")

        try:
            finalized_number, _finalized_hash = finalized_head(self.subtensor)
        except Exception as exc:
            raise DirectSubmissionAmbiguous(
                "finalized head is unavailable during recovery"
            ) from exc
        substrate = self.subtensor.substrate
        matches: list[DirectSubmissionReceipt] = []
        for block_number in range(era_reference, era_reference + period):
            if block_number > finalized_number:
                continue
            try:
                block_hash = _canonical_hash(
                    substrate.get_block_hash(block_number), label="recovery block"
                )
                block = substrate.get_block(block_hash=block_hash)
            except Exception as exc:
                raise DirectSubmissionAmbiguous(
                    "authorized mortal era is not fully readable"
                ) from exc
            extrinsics = block.get("extrinsics") if isinstance(block, Mapping) else None
            if not isinstance(extrinsics, (list, tuple)):
                raise DirectSubmissionAmbiguous("recovery block has no extrinsics")
            for item in extrinsics:
                observed = getattr(item, "value", item)
                if not isinstance(observed, Mapping):
                    continue
                raw_hash = getattr(item, "extrinsic_hash", None)
                if raw_hash is None:
                    raw_hash = observed.get("extrinsic_hash")
                if raw_hash is None:
                    raise DirectSubmissionAmbiguous("recovery extrinsic has no hash")
                try:
                    observed_hash = _canonical_hash(
                        raw_hash, label="recovery extrinsic"
                    )
                except DirectSubmissionAmbiguous as exc:
                    raise DirectSubmissionAmbiguous(
                        "recovery extrinsic has an invalid hash"
                    ) from exc
                if observed_hash != extrinsic_hash:
                    continue
                if not self._exact_call(observed, intent):
                    raise DirectSubmissionContradiction(
                        "signed hash resolved to a different chain call"
                    )
                try:
                    receipt = substrate.retrieve_extrinsic_by_hash(
                        block_hash, extrinsic_hash
                    )
                    success = getattr(receipt, "is_success", None)
                    error = getattr(receipt, "error_message", None)
                except Exception as exc:
                    raise DirectSubmissionAmbiguous(
                        "exact chain call has no execution receipt"
                    ) from exc
                if success is not True or error is not None:
                    return "failed", None
                matches.append(
                    DirectSubmissionReceipt(
                        status=_STATUS_EXTRINSIC_FINALIZED,
                        attempt_id=str(pending["attempt_id"]),
                        extrinsic_hash=extrinsic_hash,
                        block_hash=block_hash,
                        block_number=block_number,
                        recovered=True,
                    )
                )
        if len(matches) > 1:
            raise DirectSubmissionContradiction(
                "signed hash appeared more than once in finalized history"
            )
        if matches:
            return "finalized", matches[0]
        if finalized_number >= era_reference + period - 1:
            return "expired", DirectSubmissionReceipt(
                status=STATUS_EXPIRED,
                attempt_id=str(pending["attempt_id"]),
                extrinsic_hash=extrinsic_hash,
                block_hash=None,
                block_number=None,
                recovered=True,
            )
        return "pending", None

    def _finish(
        self,
        state: dict[str, Any],
        pending: Mapping[str, Any],
        receipt: DirectSubmissionReceipt,
    ) -> DirectSubmissionReceipt:
        state["last_attempt"] = {
            "attempt_id": pending["attempt_id"],
            "status": receipt.status,
            "identity": pending["identity"],
            "intent": pending["intent"],
            "receipt": receipt.as_document(),
        }
        state["pending"] = None
        self._write_state(state)
        return receipt

    def recover(self) -> DirectSubmissionReceipt | None:
        """Confirm one signed hash and stored row without signing or resubmitting."""

        with self._locked():
            state = self._read_state()
            pending = self._pending(state)
            if pending is None:
                return None
            status, receipt = self._locate(pending)
            if status == "finalized" and receipt is not None:
                try:
                    confirmed = self._confirm_finalized_effect(
                        pending, receipt, recovered=True
                    )
                except DirectSubmissionContradiction as exc:
                    pending["phase"] = "confirmation_contradiction"
                    pending["receipt"] = receipt.as_document()
                    pending["error"] = type(exc).__name__
                    state["pending"] = pending
                    self._write_state(state)
                    raise
                except DirectSubmissionAmbiguous as exc:
                    pending["phase"] = "included_awaiting_confirmation"
                    pending["receipt"] = receipt.as_document()
                    pending["error"] = type(exc).__name__
                    state["pending"] = pending
                    self._write_state(state)
                    raise
                return self._finish(state, pending, confirmed)
            if status == "expired" and receipt is not None:
                return self._finish(state, pending, receipt)
            if status == "failed":
                pending["phase"] = "finalized_failed"
                state["pending"] = pending
                self._write_state(state)
                raise DirectSubmissionContradiction(
                    "signed direct extrinsic finalized with failure"
                )
            raise DirectSubmissionAmbiguous(
                "signed direct extrinsic is unresolved; recovery will not retry it"
            )

    def submit(
        self,
        plan: DirectWeightPlan,
        *,
        cycle_deadline_monotonic: float,
    ) -> DirectSubmissionReceipt:
        """Persist one signed intent, broadcast once, and prove stored finality."""

        presign_deadline = _presign_deadline(cycle_deadline_monotonic)
        _require_presign_time(presign_deadline, stage="writer entry")
        kwargs = self._validate_plan(plan)
        _require_presign_time(presign_deadline, stage="plan validation")
        with self._locked():
            _require_presign_time(presign_deadline, stage="writer lock acquisition")
            state = self._read_state()
            _require_presign_time(presign_deadline, stage="journal preflight")
            if self._pending(state) is not None:
                raise DirectSubmissionAmbiguous(
                    "a prior signed direct intent must be recovered first"
                )
            previous_anchor = self._last_anchor(state)
            if (
                previous_anchor is not None
                and plan.snapshot.block_number <= previous_anchor
            ):
                raise DirectValidatorError(
                    "direct validator already attempted this finalized anchor"
                )

            _require_presign_time(presign_deadline, stage="before genesis RPC")
            observed_genesis_hash(self.subtensor)
            _require_presign_time(presign_deadline, stage="genesis RPC")
            fresh = self.snapshot_reader(self.subtensor, self.keypair)
            _require_presign_time(presign_deadline, stage="fresh snapshot RPC")
            self._require_fresh_snapshot(plan, fresh, presign_deadline=presign_deadline)
            eligibility = self._require_finalized_eligibility(
                plan, fresh, presign_deadline=presign_deadline
            )
            _require_presign_time(presign_deadline, stage="eligibility preflight")
            substrate = self.subtensor.substrate
            try:
                nonce = substrate.get_account_next_index(plan.snapshot.validator_hotkey)
                _require_presign_time(presign_deadline, stage="nonce RPC")
                if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
                    raise ValueError("account nonce is invalid")
                call = self.call_builder(kwargs)
                _require_presign_time(
                    presign_deadline, stage="immediately before signing"
                )
                signed = substrate.create_signed_extrinsic(
                    call=call,
                    keypair=self.keypair,
                    nonce=nonce,
                    era={
                        "period": SN39_MORTAL_PERIOD_BLOCKS,
                        "current": fresh.block_number,
                    },
                )
                extrinsic_hash = _canonical_hash(
                    getattr(signed, "extrinsic_hash", None),
                    label="signed extrinsic",
                )
            except DirectSubmissionAmbiguous:
                raise
            except DirectValidatorError:
                raise
            except Exception as exc:
                raise DirectValidatorError(
                    "direct extrinsic could not be signed"
                ) from exc

            identity = plan.identity()
            intent = {
                "extrinsic_hash": extrinsic_hash,
                "validator_hotkey": plan.snapshot.validator_hotkey,
                "nonce": nonce,
                "era_reference_block": fresh.block_number,
                "mortal_period_blocks": SN39_MORTAL_PERIOD_BLOCKS,
                "kwargs": kwargs,
                "eligibility": eligibility,
            }
            attempt_id = _attempt_id(identity, intent)
            pending: dict[str, Any] = {
                "attempt_id": attempt_id,
                "phase": "signed_intent",
                "identity": identity,
                "intent": intent,
                "receipt": None,
                "error": None,
            }
            state["pending"] = pending
            self._write_state(state)

            try:
                response = substrate.submit_extrinsic(
                    signed,
                    wait_for_inclusion=True,
                    wait_for_finalization=True,
                )
                response_hash = getattr(response, "extrinsic_hash", None)
                if (
                    response_hash is not None
                    and _canonical_hash(response_hash, label="submission response")
                    != extrinsic_hash
                ):
                    raise DirectSubmissionContradiction(
                        "submission response names another extrinsic"
                    )
            except Exception as exc:
                pending["phase"] = "ambiguous"
                pending["error"] = type(exc).__name__
                state["pending"] = pending
                self._write_state(state)
                if isinstance(exc, DirectSubmissionContradiction):
                    raise
                raise DirectSubmissionAmbiguous(
                    "direct submission result is ambiguous; recover, never retry"
                ) from exc

            status, located = self._locate(pending)
            if status == "finalized" and located is not None:
                try:
                    confirmed = self._confirm_finalized_effect(
                        pending, located, recovered=False
                    )
                except DirectSubmissionContradiction as exc:
                    pending["phase"] = "confirmation_contradiction"
                    pending["receipt"] = located.as_document()
                    pending["error"] = type(exc).__name__
                    state["pending"] = pending
                    self._write_state(state)
                    raise
                except DirectSubmissionAmbiguous as exc:
                    pending["phase"] = "included_awaiting_confirmation"
                    pending["receipt"] = located.as_document()
                    pending["error"] = type(exc).__name__
                    state["pending"] = pending
                    self._write_state(state)
                    raise
                return self._finish(state, pending, confirmed)
            if status == "failed":
                pending["phase"] = "finalized_failed"
                state["pending"] = pending
                self._write_state(state)
                raise DirectSubmissionContradiction(
                    "direct extrinsic finalized with failure"
                )
            pending["phase"] = "ambiguous"
            state["pending"] = pending
            self._write_state(state)
            raise DirectSubmissionAmbiguous(
                "submission returned without exact finalized history; recover"
            )


__all__ = [
    "DirectSubmissionAmbiguous",
    "DirectSubmissionContradiction",
    "DirectSubmissionReceipt",
    "DirectWeightWriter",
    "CONFIRMATION_WAIT_SECONDS",
    "DIRECT_STATE_ROOT",
    "DIRECT_STATE_SCOPE",
    "STATE_SCHEMA",
    "STATUS_CONFIRMED",
    "STATUS_EXPIRED",
    "STATUS_RECOVERED",
    "canonical_state_path",
]
