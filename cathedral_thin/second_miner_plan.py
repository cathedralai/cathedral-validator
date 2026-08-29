"""Read-only launch plan for Cathedral's dedicated second SN39 miner.

This module deliberately has no wallet loader and no chain mutation path.  It
reads one finalized Finney snapshot, proves the fixed public identities, and
renders the exact equal-semantic UID30 row that a future, separately reviewed
successor writer would have to authorize.

The output is planning evidence, never submission authority.  In particular,
the planner does not register a hotkey, announce an axon, collect TDX evidence,
or set weights.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bittensor.utils import get_mechid_storage_index
from bittensor.utils.weight_utils import convert_and_normalize_weights_and_uids
from bittensor_wallet import Keypair

from cathedral_thin.bt_compat import listify, make_subtensor
from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH

SCHEMA = "cathedral_sn39_second_miner_equal_plan_v1"
NETWORK = "finney"
NETUID = 39
MECID = 0
UID30 = 30
HTTPS_PROTOCOL = 4
HTTPS_PORT = 8081
W = 65535

CATHEDRAL_COLDKEY = (
    "5G6mgvL59o6AM8rFRYbbUpbzjjGwcVLUidpQ1vsz5UkZyw2o"  # pragma: allowlist secret
)
UID30_HOTKEY = (
    "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"  # pragma: allowlist secret
)
PRIMARY_MINER_WALLET_HOTKEY = "serge_sat_test"
PRIMARY_MINER_HOTKEY = (
    "5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G"  # pragma: allowlist secret
)
SECOND_MINER_WALLET_HOTKEY = "serge_sat_test_2"
SECOND_MINER_HOTKEY = (
    "5Ct2DBJPULeQxGmFiKrpGvvWuYVxgYEX8tRfNjWYRga8VRbq"  # pragma: allowlist secret
)

STATUS_UNREGISTERED = "BLOCKED_SECOND_MINER_UNREGISTERED"
STATUS_AXON = "BLOCKED_MINER_AXON_CONTRACT"
STATUS_PROOF = "CHAIN_READY_FRESH_QVL_SAT_REQUIRED"


class SecondMinerPlanError(Exception):
    """The finalized snapshot contradicts the fixed second-miner contract."""


@dataclass(frozen=True)
class Neuron:
    uid: int
    hotkey: str
    coldkey: str
    validator_permit: bool
    last_update: int
    ip: str | None
    port: int
    protocol: int
    serving: bool

    def identity(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "hotkey": self.hotkey,
            "coldkey": self.coldkey,
        }

    def axon(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "serving": self.serving,
        }


@dataclass(frozen=True)
class FinalizedSnapshot:
    block_number: int
    block_hash: str
    genesis_hash: str
    neurons: tuple[Neuron, ...]
    uid30_weights: tuple[tuple[int, int], ...]


def _ss58(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SecondMinerPlanError(f"{label} is not an SS58 address")
    try:
        canonical = Keypair(ss58_address=value).ss58_address
    except Exception as exc:
        raise SecondMinerPlanError(f"{label} is not an SS58 address") from exc
    if canonical != value:
        raise SecondMinerPlanError(f"{label} is not canonical SS58")
    return value


def _nonnegative(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SecondMinerPlanError(f"{label} is not a non-negative integer")
    return value


def _chain_hash(value: object, *, label: str) -> str:
    text = str(value).lower()
    if len(text) != 66 or not text.startswith("0x"):
        raise SecondMinerPlanError(f"{label} is not a canonical chain hash")
    try:
        int(text[2:], 16)
    except ValueError as exc:
        raise SecondMinerPlanError(f"{label} is not a canonical chain hash") from exc
    return text


def _raw(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _ip(raw: object) -> str | None:
    if raw in (None, "", 0, "0.0.0.0"):
        return None
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise SecondMinerPlanError(f"axon IP {raw!r} is invalid") from exc


def _rows(value: Any) -> tuple[tuple[int, int], ...]:
    raw = _raw(value)
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        raise SecondMinerPlanError("UID30 weights are not a sequence")
    rows: list[tuple[int, int]] = []
    for index, row in enumerate(raw):
        if not isinstance(row, (list, tuple)) or len(row) != 2:
            raise SecondMinerPlanError(f"UID30 weight row {index} is malformed")
        uid = _nonnegative(row[0], label=f"UID30 weight row {index} UID")
        weight = _nonnegative(row[1], label=f"UID30 weight row {index} weight")
        if uid > W or weight > W:
            raise SecondMinerPlanError(f"UID30 weight row {index} does not fit u16")
        rows.append((uid, weight))
    return tuple(rows)


def _neuron_rows(metagraph: Any) -> tuple[Neuron, ...]:
    try:
        uids = [int(value) for value in listify(metagraph.uids)]
        hotkeys = [str(value) for value in listify(metagraph.hotkeys)]
        coldkeys = [str(value) for value in listify(metagraph.coldkeys)]
        permits = [bool(value) for value in listify(metagraph.validator_permit)]
        last_updates = [int(value) for value in listify(metagraph.last_update)]
        axons = list(metagraph.axons)
    except Exception as exc:
        raise SecondMinerPlanError("SN39 metagraph fields are unavailable") from exc
    lengths = {
        len(uids),
        len(hotkeys),
        len(coldkeys),
        len(permits),
        len(last_updates),
        len(axons),
    }
    if len(lengths) != 1:
        raise SecondMinerPlanError("SN39 metagraph identity arrays are ragged")
    rows: list[Neuron] = []
    for uid, hotkey, coldkey, permit, last_update, axon in zip(
        uids, hotkeys, coldkeys, permits, last_updates, axons
    ):
        port = int(getattr(axon, "port", 0) or 0)
        protocol = int(getattr(axon, "protocol", 0) or 0)
        ip = _ip(getattr(axon, "ip", None))
        rows.append(
            Neuron(
                uid=uid,
                hotkey=_ss58(hotkey, label=f"UID{uid} hotkey"),
                coldkey=_ss58(coldkey, label=f"UID{uid} coldkey"),
                validator_permit=permit,
                last_update=_nonnegative(last_update, label=f"UID{uid} last update"),
                ip=ip,
                port=port,
                protocol=protocol,
                serving=bool(ip is not None and port > 0),
            )
        )
    return tuple(rows)


def read_finalized_snapshot(
    *, subtensor_factory: Callable[..., Any] | None = None
) -> FinalizedSnapshot:
    """Read only the finalized Finney state needed by the plan."""

    if subtensor_factory is None:
        import bittensor as bt

        def subtensor_factory(*, network: str) -> Any:
            return make_subtensor(bt, network=network)

    subtensor = subtensor_factory(network=NETWORK)
    substrate = subtensor.substrate
    try:
        genesis = _chain_hash(substrate.get_block_hash(0), label="Finney genesis")
        finalized_hash = _chain_hash(
            substrate.get_chain_finalised_head(), label="finalized block hash"
        )
        finalized_number = _nonnegative(
            int(substrate.get_block_number(finalized_hash)),
            label="finalized block number",
        )
    except SecondMinerPlanError:
        raise
    except Exception as exc:
        raise SecondMinerPlanError("finalized SN39 read failed") from exc
    return read_snapshot_at(
        subtensor=subtensor,
        block_number=finalized_number,
        block_hash=finalized_hash,
        genesis_hash=genesis,
    )


def read_snapshot_at(
    *,
    subtensor: Any,
    block_number: int,
    block_hash: str,
    genesis_hash: str,
) -> FinalizedSnapshot:
    """Read planner fields at one reverse-bound caller-proven finalized block."""

    block_number = _nonnegative(block_number, label="snapshot block number")
    block_hash = _chain_hash(block_hash, label="snapshot block hash")
    genesis_hash = _chain_hash(genesis_hash, label="snapshot genesis hash")
    substrate = subtensor.substrate
    try:
        if (
            _chain_hash(substrate.get_block_hash(0), label="Finney genesis")
            != genesis_hash
        ):
            raise SecondMinerPlanError("requested snapshot is on a different chain")
        if (
            _chain_hash(
                substrate.get_block_hash(block_number),
                label="canonical snapshot block hash",
            )
            != block_hash
        ):
            raise SecondMinerPlanError(
                "requested snapshot block number and hash do not match"
            )
        metagraph = subtensor.metagraph(
            NETUID,
            lite=True,
            block=block_number,
            mechid=MECID,
        )
        metagraph_block = _raw(getattr(metagraph, "block", None))
        if hasattr(metagraph_block, "item"):
            metagraph_block = metagraph_block.item()
        metagraph_block = _nonnegative(metagraph_block, label="metagraph block")
        if metagraph_block != block_number:
            raise SecondMinerPlanError(
                "SN39 metagraph is not at the requested snapshot block"
            )
        weights = substrate.query(
            module="SubtensorModule",
            storage_function="Weights",
            params=[get_mechid_storage_index(NETUID, MECID), UID30],
            block_hash=block_hash,
        )
    except SecondMinerPlanError:
        raise
    except Exception as exc:
        raise SecondMinerPlanError("requested SN39 snapshot read failed") from exc
    return FinalizedSnapshot(
        block_number=block_number,
        block_hash=block_hash,
        genesis_hash=genesis_hash,
        neurons=_neuron_rows(metagraph),
        uid30_weights=_rows(weights),
    )


def _one(rows: tuple[Neuron, ...], hotkey: str, *, required: bool) -> Neuron | None:
    matches = [row for row in rows if row.hotkey == hotkey]
    if len(matches) > 1:
        raise SecondMinerPlanError(f"hotkey {hotkey} occupies multiple SN39 UIDs")
    if not matches:
        if required:
            raise SecondMinerPlanError(f"required hotkey {hotkey} is not on SN39")
        return None
    return matches[0]


def equal_wire(primary_uid: int, second_uid: int) -> tuple[list[int], list[int]]:
    """Return Bittensor's exact max-normalized wire row for equal scores."""

    primary_uid = _nonnegative(primary_uid, label="primary miner UID")
    second_uid = _nonnegative(second_uid, label="second miner UID")
    if primary_uid == second_uid or UID30 in {primary_uid, second_uid}:
        raise SecondMinerPlanError("miner UIDs are not two distinct non-validator UIDs")
    ordered = sorted([primary_uid, second_uid])
    wire_uids, wire_weights = convert_and_normalize_weights_and_uids(
        ordered, [1.0, 1.0]
    )
    uids = [int(value) for value in wire_uids]
    weights = [int(value) for value in wire_weights]
    if uids != ordered or weights != [W, W]:
        raise SecondMinerPlanError(
            "installed Bittensor does not encode equal semantic weights as two 65535 rows"
        )
    return uids, weights


def _is_https_axon(neuron: Neuron) -> bool:
    return (
        neuron.serving
        and neuron.port == HTTPS_PORT
        and neuron.protocol == HTTPS_PROTOCOL
    )


def build_plan(snapshot: FinalizedSnapshot) -> dict[str, Any]:
    """Validate fixed identities and build one non-authorizing plan artifact."""

    _ss58(CATHEDRAL_COLDKEY, label="Cathedral coldkey pin")
    _ss58(UID30_HOTKEY, label="UID30 hotkey pin")
    _ss58(PRIMARY_MINER_HOTKEY, label="primary miner hotkey pin")
    _ss58(SECOND_MINER_HOTKEY, label="second miner hotkey pin")
    if snapshot.genesis_hash != FINNEY_GENESIS_HASH:
        raise SecondMinerPlanError("snapshot is not pinned Finney genesis")
    validator = _one(snapshot.neurons, UID30_HOTKEY, required=True)
    primary = _one(snapshot.neurons, PRIMARY_MINER_HOTKEY, required=True)
    second = _one(snapshot.neurons, SECOND_MINER_HOTKEY, required=False)
    assert validator is not None and primary is not None
    if validator.uid != UID30 or validator.coldkey != CATHEDRAL_COLDKEY:
        raise SecondMinerPlanError("Cathedral validator is not the pinned SN39 UID30")
    if validator.validator_permit is not True:
        raise SecondMinerPlanError("Cathedral UID30 does not have a validator permit")
    if primary.coldkey != CATHEDRAL_COLDKEY:
        raise SecondMinerPlanError(
            "primary miner is not owned by the Cathedral coldkey"
        )

    status = STATUS_UNREGISTERED
    blockers = [
        "register serge_sat_test_2 once and confirm its finalized UID and coldkey"
    ]
    wire: dict[str, Any] | None = None
    second_identity: dict[str, Any] = {
        "wallet_hotkey": SECOND_MINER_WALLET_HOTKEY,
        "hotkey": SECOND_MINER_HOTKEY,
        "coldkey": CATHEDRAL_COLDKEY,
        "uid": None,
    }
    second_axon: dict[str, Any] | None = None
    if second is not None:
        if second.coldkey != CATHEDRAL_COLDKEY:
            raise SecondMinerPlanError(
                "second miner is not owned by the Cathedral coldkey"
            )
        if second.uid in {UID30, primary.uid}:
            raise SecondMinerPlanError(
                "second miner UID collides with a pinned identity"
            )
        second_identity = {
            "wallet_hotkey": SECOND_MINER_WALLET_HOTKEY,
            **second.identity(),
        }
        second_axon = second.axon()
        uids, weights = equal_wire(primary.uid, second.uid)
        wire = {
            "dests": uids,
            "weights_u16": weights,
            "expected_storage": [list(row) for row in zip(uids, weights)],
        }
        invalid_axons = [
            name
            for name, neuron in (("primary", primary), ("second", second))
            if not _is_https_axon(neuron)
        ]
        if invalid_axons:
            status = STATUS_AXON
            blockers = [
                f"{name} miner must have a finalized HTTPS 8081 protocol-4 axon"
                for name in invalid_axons
            ]
            blockers.append(
                "any axon change requires a separately reviewed one-shot writer"
            )
            blockers.append("confirm each changed axon at two later finalized heads")
        else:
            status = STATUS_PROOF
            blockers = [
                "collect fresh QVL PASS and canonical SAT from both finalized axons",
                "require two distinct TLS SPKI machine identities",
                "review a separate one-write UID30 successor authorization",
            ]

    return {
        "schema": SCHEMA,
        "status": status,
        "authorized_for_chain_write": False,
        "network": {
            "name": NETWORK,
            "genesis_hash": snapshot.genesis_hash,
            "netuid": NETUID,
            "mechanism_id": MECID,
            "finalized_block": snapshot.block_number,
            "finalized_hash": snapshot.block_hash,
        },
        "validator": {
            **validator.identity(),
            "validator_permit": validator.validator_permit,
            "last_update": validator.last_update,
        },
        "primary_miner": {
            "wallet_hotkey": PRIMARY_MINER_WALLET_HOTKEY,
            **primary.identity(),
            "axon": primary.axon(),
        },
        "second_miner": {
            **second_identity,
            "axon": second_axon,
        },
        "requested_outcome": {
            "semantic_scores": {
                PRIMARY_MINER_HOTKEY: "1/1",
                SECOND_MINER_HOTKEY: "1/1",
            },
            "wire": wire,
            "burn_destination": None,
            "burn_weight": 0,
            "replaces_complete_uid30_row": True,
        },
        "current_uid30_storage": [list(row) for row in snapshot.uid30_weights],
        "blockers": blockers,
        "proof_boundary": (
            "This artifact performs finalized public reads and deterministic weight "
            "encoding only. It is not registration, axon, QVL, SAT, submission, "
            "validator acceptance, emission, or earnings proof."
        ),
    }


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_plan(path: Path | str, plan: Mapping[str, Any]) -> tuple[Path, Path, str]:
    """Write one owner-only plan and detached digest without overwriting files."""

    output = Path(path).expanduser()
    if not output.is_absolute():
        raise SecondMinerPlanError("plan output path must be absolute")
    digest_path = Path(str(output) + ".sha256")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = output.parent.stat()
    if (
        output.parent.is_symlink()
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise SecondMinerPlanError("plan output parent is not owner-controlled")
    body = _canonical_bytes(plan)
    digest = hashlib.sha256(body).hexdigest()
    opened: list[Path] = []
    try:
        for target, payload in (
            (output, body),
            (digest_path, f"{digest}  {output.name}\n".encode()),
        ):
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target, flags, 0o600)
            opened.append(target)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("plan artifact write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            info = target.stat()
            if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid():
                raise SecondMinerPlanError("plan artifact is not owner-only mode 0600")
    except Exception:
        for target in opened:
            try:
                target.unlink()
            except OSError:
                pass
        raise
    return output, digest_path, digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cathedral-second-miner-plan")
    sub = parser.add_subparsers(dest="command", required=True)
    preview = sub.add_parser(
        "preview", help="read finalized SN39 state and write a no-authority plan"
    )
    preview.add_argument(
        "--output", required=True, help="absolute owner-only JSON path"
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    reader: Callable[[], FinalizedSnapshot] = read_finalized_snapshot,
    writer: Callable[
        [Path | str, Mapping[str, Any]], tuple[Path, Path, str]
    ] = write_plan,
) -> int:
    options = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if options.command != "preview":
            raise SecondMinerPlanError(f"unsupported command {options.command}")
        plan = build_plan(reader())
        output, digest_path, digest = writer(options.output, plan)
    except SecondMinerPlanError as exc:
        print(f"SecondMinerPlanError: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": plan["status"],
                "authorized_for_chain_write": False,
                "output": str(output),
                "sha256_file": str(digest_path),
                "sha256": digest,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
