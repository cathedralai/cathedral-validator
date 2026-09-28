"""A signed, per-cycle inventory of the supply pool this validator scored.

Each proven cycle can publish one ``cathedral_pool_inventory_v1`` document:
every machine the round probed, with whether it answered (``available``) and
whether it met the same rule the weights pay for (``healthy``). The validator
hotkey signs it, so a reader can check which validator saw what at which
finalized block without trusting the host that serves the file.

``assigned`` is always zero here: no customer work reaches miner machines yet,
and the document says so in ``assignment_source`` rather than leaving it out.

The signature covers a header, not the machine list: the header carries the
RFC 6962 Merkle root over one leaf per probed machine. So each machine also
gets a ``cathedral_machine_receipt_v1``: the signed header, its own leaf, and
an inclusion proof. Anyone holding a receipt and nothing else can check, with
the validator's public hotkey, what that validator recorded for that machine
in that round, paid or not, and why.

Publishing is opt-in, happens after the cycle's weight write, and never raises
into the cycle: an inventory problem can never change weights or stop writes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

SCHEMA = "cathedral_pool_inventory_v1"
SIGNING_DOMAIN = b"cathedral-pool-inventory-v1\x00"
RECEIPT_SCHEMA = "cathedral_machine_receipt_v1"
MERKLE_ALGORITHM = "rfc6962-sha256"
MAX_RECEIPT_LEAVES = 65_536
ROUTE = "/v1/pool/inventory"
RECEIPT_ROUTE = "/v1/pool/receipt"
MAX_RECEIPT_QUERY_BYTES = 2048
MAX_INVENTORY_BYTES = 4 * 1024 * 1024
MAX_REASON_CHARS = 160
STATE_HEALTHY = "healthy"
STATE_UNVERIFIED = "unverified"
STATE_UNREACHABLE = "unreachable"
_STATES = frozenset({STATE_HEALTHY, STATE_UNVERIFIED, STATE_UNREACHABLE})
_DOCUMENT_KEYS = frozenset(
    {
        "schema",
        "network",
        "netuid",
        "anchor",
        "validator",
        "generated_at",
        "totals",
        "assignment_source",
        "receipts",
        "machines",
        "inventory_id",
        "signature",
    }
)
_HEADER_KEYS = _DOCUMENT_KEYS - {"machines", "inventory_id", "signature"}
_RECEIPTS_KEYS = frozenset({"algorithm", "leaves", "merkle_root"})
_RECEIPT_KEYS = frozenset(
    {"schema", "header", "inventory_id", "signature", "leaf", "index", "proof"}
)
_MACHINE_KEYS = frozenset(
    {"uid", "miner_hotkey", "endpoint", "tee_kind", "machine_id", "state", "reason"}
)
_TOTAL_KEYS = frozenset({"miners", "machines", "available", "healthy", "assigned"})


class PoolInventoryError(ValueError):
    """A pool inventory could not be built, signed, verified or read."""


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _header(document: Mapping[str, Any]) -> dict[str, Any]:
    return {key: document[key] for key in _HEADER_KEYS if key in document}


def _inventory_id(document: Mapping[str, Any]) -> str:
    """The signed identity: a hash of the header, which commits to the machines."""

    return "sha256:" + hashlib.sha256(_canonical(_header(document))).hexdigest()


def _leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(size: int) -> int:
    """The largest power of two strictly below ``size`` (RFC 6962 section 2.1)."""

    split = 1
    while split << 1 < size:
        split <<= 1
    return split


def merkle_root(leaf_hashes: Sequence[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over already-hashed leaves."""

    if not leaf_hashes:
        return hashlib.sha256(b"").digest()
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    split = _split(len(leaf_hashes))
    return _node_hash(
        merkle_root(leaf_hashes[:split]), merkle_root(leaf_hashes[split:])
    )


def inclusion_proof(index: int, leaf_hashes: Sequence[bytes]) -> list[bytes]:
    """RFC 6962 audit path for the leaf at ``index``."""

    if not 0 <= index < len(leaf_hashes):
        raise PoolInventoryError("receipt index is outside the tree")
    if len(leaf_hashes) == 1:
        return []
    split = _split(len(leaf_hashes))
    if index < split:
        return inclusion_proof(index, leaf_hashes[:split]) + [
            merkle_root(leaf_hashes[split:])
        ]
    return inclusion_proof(index - split, leaf_hashes[split:]) + [
        merkle_root(leaf_hashes[:split])
    ]


def root_from_proof(
    leaf_hash: bytes, index: int, size: int, proof: Sequence[bytes]
) -> bytes:
    """RFC 9162 section 2.1.3.2: the root an inclusion proof commits to."""

    if not 0 <= index < size:
        raise PoolInventoryError("receipt index is outside the tree")
    fn, sn, result = index, size - 1, leaf_hash
    for sibling in proof:
        if sn == 0:
            raise PoolInventoryError("receipt proof is longer than its tree")
        if fn & 1 or fn == sn:
            result = _node_hash(sibling, result)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            result = _node_hash(result, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise PoolInventoryError("receipt proof is shorter than its tree")
    return result


def _machine_leaves(machines: Sequence[Mapping[str, Any]]) -> list[bytes]:
    return [_leaf_hash(_canonical(machine)) for machine in machines]


def _receipts_header(machines: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if len(machines) > MAX_RECEIPT_LEAVES:
        raise PoolInventoryError(
            "inventory has more machines than a receipt tree holds"
        )
    return {
        "algorithm": MERKLE_ALGORITHM,
        "leaves": len(machines),
        "merkle_root": merkle_root(_machine_leaves(machines)).hex(),
    }


def _reason(row: Mapping[str, Any]) -> str | None:
    for field in ("sat_error", "identity_error", "deadline_error", "error"):
        value = row.get(field)
        if isinstance(value, str) and value:
            return value[:MAX_REASON_CHARS]
    reasons = row.get("score_reasons")
    if isinstance(reasons, (list, tuple)) and reasons:
        return ", ".join(str(item) for item in reasons)[:MAX_REASON_CHARS]
    return None


def build_pool_inventory(
    *,
    rows: Sequence[Mapping[str, Any]],
    healthy_rows: Sequence[Mapping[str, Any]],
    miner_count: int,
    network: str,
    netuid: int,
    block_number: int,
    block_hash: str,
    validator_uid: int,
    validator_hotkey: str,
    generated_at: datetime,
) -> dict[str, Any]:
    """Project one scored round into the unsigned inventory document.

    ``rows`` are every machine the round probed; ``healthy_rows`` are the
    subset the weight plan counted. A machine is healthy only by that rule.
    """

    if generated_at.tzinfo is None or generated_at.utcoffset() != UTC.utcoffset(None):
        raise PoolInventoryError("inventory time must be UTC")
    healthy = {(int(row["uid"]), str(row["endpoint"])) for row in healthy_rows}
    machines: list[dict[str, Any]] = []
    for row in rows:
        uid = row.get("uid")
        endpoint = row.get("endpoint")
        if (
            isinstance(uid, bool)
            or not isinstance(uid, int)
            or not isinstance(endpoint, str)
        ):
            raise PoolInventoryError("probed machine has no uid or endpoint")
        key = (uid, endpoint)
        if key in healthy:
            state = STATE_HEALTHY
        elif row.get("ok") is True:
            state = STATE_UNVERIFIED
        else:
            state = STATE_UNREACHABLE
        tee_kind = row.get("tee_kind")
        machine_id = row.get("machine_id")
        machines.append(
            {
                "uid": uid,
                "miner_hotkey": str(row.get("hotkey", "")),
                "endpoint": endpoint,
                "tee_kind": tee_kind if isinstance(tee_kind, str) else None,
                "machine_id": machine_id if isinstance(machine_id, str) else None,
                "state": state,
                "reason": None if state == STATE_HEALTHY else _reason(row),
            }
        )
    machines.sort(key=lambda machine: (machine["uid"], machine["endpoint"]))
    if len({(m["uid"], m["endpoint"]) for m in machines}) != len(machines):
        raise PoolInventoryError("probed machines repeat a uid and endpoint")
    if not healthy <= {(m["uid"], m["endpoint"]) for m in machines}:
        raise PoolInventoryError("a counted machine is missing from the probed rows")
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "network": network,
        "netuid": netuid,
        "anchor": {"block_number": block_number, "block_hash": block_hash},
        "validator": {"uid": validator_uid, "hotkey": validator_hotkey},
        "generated_at": generated_at.replace(microsecond=0).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "totals": {
            "miners": miner_count,
            "machines": len(machines),
            "available": sum(m["state"] != STATE_UNREACHABLE for m in machines),
            "healthy": sum(m["state"] == STATE_HEALTHY for m in machines),
            "assigned": 0,
        },
        "assignment_source": None,
        "receipts": _receipts_header(machines),
        "machines": machines,
    }
    document["inventory_id"] = _inventory_id(document)
    return document


def sign_pool_inventory(document: Mapping[str, Any], *, keypair: Any) -> dict[str, Any]:
    """Sign with the validator hotkey that the document names."""

    signed = dict(document)
    if signed.get("inventory_id") != _inventory_id(signed):
        raise PoolInventoryError("inventory identity does not match its contents")
    validator = signed.get("validator")
    if (
        not isinstance(validator, Mapping)
        or validator.get("hotkey") != str(getattr(keypair, "ss58_address", ""))
        or not callable(getattr(keypair, "sign", None))
    ):
        raise PoolInventoryError("inventory signer does not match the validator hotkey")
    try:
        signature = bytes(
            keypair.sign(SIGNING_DOMAIN + signed["inventory_id"].encode("ascii"))
        )
    except Exception as exc:
        raise PoolInventoryError(
            "validator hotkey could not sign the inventory"
        ) from exc
    if len(signature) != 64:
        raise PoolInventoryError("inventory signature must be 64 bytes")
    signed["signature"] = {
        "algorithm": "sr25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return signed


def verify_pool_inventory(document: object) -> dict[str, Any]:
    """Check shape, identity and the validator's signature; return the document."""

    if not isinstance(document, dict) or frozenset(document) != _DOCUMENT_KEYS:
        raise PoolInventoryError("inventory fields are invalid")
    if document["schema"] != SCHEMA:
        raise PoolInventoryError("inventory schema is unsupported")
    totals = document["totals"]
    machines = document["machines"]
    if (
        not isinstance(totals, dict)
        or frozenset(totals) != _TOTAL_KEYS
        or not isinstance(machines, list)
        or any(
            not isinstance(m, dict) or frozenset(m) != _MACHINE_KEYS for m in machines
        )
        or any(m["state"] not in _STATES for m in machines)
    ):
        raise PoolInventoryError("inventory machines or totals are invalid")
    if (
        totals["machines"] != len(machines)
        or totals["available"] != sum(m["state"] != STATE_UNREACHABLE for m in machines)
        or totals["healthy"] != sum(m["state"] == STATE_HEALTHY for m in machines)
        or totals["assigned"] != 0
        or document["assignment_source"] is not None
    ):
        raise PoolInventoryError("inventory totals do not match its machines")
    if document["receipts"] != _receipts_header(machines):
        raise PoolInventoryError("inventory receipt root does not match its machines")
    if document["inventory_id"] != _inventory_id(document):
        raise PoolInventoryError("inventory identity does not match its contents")
    _verify_signature(
        document["inventory_id"], document["signature"], document["validator"]
    )
    return document


def _verify_signature(
    inventory_id: object, signature: object, validator: object
) -> None:
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "value_base64"}
        or signature["algorithm"] != "sr25519"
        or not isinstance(signature["value_base64"], str)
        or not isinstance(validator, dict)
        or not isinstance(validator.get("hotkey"), str)
    ):
        raise PoolInventoryError("inventory signature is invalid")
    if not isinstance(inventory_id, str) or not inventory_id.isascii():
        raise PoolInventoryError("inventory identity is invalid")
    try:
        raw = base64.b64decode(signature["value_base64"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PoolInventoryError("inventory signature is invalid") from exc
    if len(raw) != 64:
        raise PoolInventoryError("inventory signature is invalid")
    try:
        from bittensor_wallet import Keypair

        valid = Keypair(ss58_address=validator["hotkey"]).verify(
            SIGNING_DOMAIN + inventory_id.encode("ascii"), raw
        )
    except Exception as exc:
        raise PoolInventoryError("inventory validator hotkey is invalid") from exc
    if not valid:
        raise PoolInventoryError("inventory signature verification failed")


def machine_receipt(
    document: Mapping[str, Any], *, uid: int, endpoint: str
) -> dict[str, Any]:
    """The receipt for one machine of a verified, signed inventory."""

    verified = verify_pool_inventory(dict(document))
    machines = verified["machines"]
    matches = [
        index
        for index, machine in enumerate(machines)
        if machine["uid"] == uid and machine["endpoint"] == endpoint
    ]
    if len(matches) != 1:
        raise PoolInventoryError(
            "the inventory has no machine at that uid and endpoint"
        )
    index = matches[0]
    proof = inclusion_proof(index, _machine_leaves(machines))
    return {
        "schema": RECEIPT_SCHEMA,
        "header": _header(verified),
        "inventory_id": verified["inventory_id"],
        "signature": verified["signature"],
        "leaf": machines[index],
        "index": index,
        "proof": [node.hex() for node in proof],
    }


def verify_machine_receipt(receipt: object) -> dict[str, Any]:
    """Check a receipt alone: its proof reaches the root the validator signed."""

    if not isinstance(receipt, dict) or frozenset(receipt) != _RECEIPT_KEYS:
        raise PoolInventoryError("receipt fields are invalid")
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise PoolInventoryError("receipt schema is unsupported")
    header = receipt["header"]
    if (
        not isinstance(header, dict)
        or frozenset(header) != _HEADER_KEYS
        or header.get("schema") != SCHEMA
    ):
        raise PoolInventoryError("receipt header is invalid")
    receipts = header["receipts"]
    if (
        not isinstance(receipts, dict)
        or frozenset(receipts) != _RECEIPTS_KEYS
        or receipts["algorithm"] != MERKLE_ALGORITHM
        or isinstance(receipts["leaves"], bool)
        or not isinstance(receipts["leaves"], int)
        or not 1 <= receipts["leaves"] <= MAX_RECEIPT_LEAVES
        or not isinstance(receipts["merkle_root"], str)
        or len(receipts["merkle_root"]) != 64
    ):
        raise PoolInventoryError("receipt tree is invalid")
    leaf = receipt["leaf"]
    index = receipt["index"]
    proof = receipt["proof"]
    if (
        not isinstance(leaf, dict)
        or frozenset(leaf) != _MACHINE_KEYS
        or leaf["state"] not in _STATES
        or isinstance(index, bool)
        or not isinstance(index, int)
        or not isinstance(proof, list)
        or len(proof) > 64
        or any(not isinstance(node, str) or len(node) != 64 for node in proof)
    ):
        raise PoolInventoryError("receipt leaf or proof is invalid")
    try:
        siblings = [bytes.fromhex(node) for node in proof]
        root = bytes.fromhex(receipts["merkle_root"])
    except ValueError as exc:
        raise PoolInventoryError("receipt proof is not hex") from exc
    if receipt["inventory_id"] != _inventory_id(header):
        raise PoolInventoryError("receipt header does not match its signed identity")
    reached = root_from_proof(
        _leaf_hash(_canonical(leaf)), index, receipts["leaves"], siblings
    )
    if reached != root:
        raise PoolInventoryError("receipt proof does not reach the signed root")
    _verify_signature(
        receipt["inventory_id"], receipt["signature"], header["validator"]
    )
    return receipt


def write_pool_inventory(path: Path, document: Mapping[str, Any]) -> None:
    """Replace the published inventory atomically; the directory must exist."""

    encoded = _canonical(document)
    if len(encoded) > MAX_INVENTORY_BYTES:
        raise PoolInventoryError("inventory exceeds its size limit")
    directory = path.parent
    if path.is_symlink() or not directory.is_dir() or directory.is_symlink():
        raise PoolInventoryError("inventory path is unsafe")
    descriptor, temporary = tempfile.mkstemp(prefix=".pool-inventory.", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read_pool_inventory(path: Path) -> bytes:
    """Read the published file with the same bounds the server applies."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise PoolInventoryError("inventory is unavailable") from exc
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INVENTORY_BYTES:
            raise PoolInventoryError("inventory is not a bounded regular file")
        return handle.read(MAX_INVENTORY_BYTES + 1)


def publish_cycle_inventory(
    path: Path,
    *,
    snapshot: Any,
    result: Any,
    healthy_rows: Sequence[Mapping[str, Any]],
    network: str,
    keypair: Any,
    now: datetime | None = None,
) -> str:
    """Build, sign and write one cycle's inventory; return its identity."""

    document = build_pool_inventory(
        rows=result.rows,
        healthy_rows=healthy_rows,
        miner_count=len(snapshot.miners),
        network=network,
        netuid=snapshot.netuid,
        block_number=snapshot.block_number,
        block_hash=snapshot.block_hash,
        validator_uid=snapshot.validator_uid,
        validator_hotkey=snapshot.validator_hotkey,
        generated_at=now or datetime.now(UTC),
    )
    signed = sign_pool_inventory(document, keypair=keypair)
    write_pool_inventory(path, signed)
    return str(signed["inventory_id"])


def make_inventory_server(path: Path, host: str, port: int) -> ThreadingHTTPServer:
    """A read-only server for the signed file and per-machine receipts.

    GET /v1/pool/inventory returns the published file. GET
    /v1/pool/receipt?uid=N&endpoint=URL returns that machine's receipt, built
    from the same file after verifying it.
    """

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            pass

        def _reply(self, code: int, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            route, _, query = self.path.partition("?")
            if route not in {ROUTE, RECEIPT_ROUTE}:
                self._reply(404, b'{"error":"not found"}')
                return
            try:
                body = read_pool_inventory(path)
            except PoolInventoryError:
                self._reply(503, b'{"error":"inventory unavailable"}')
                return
            if route == ROUTE:
                self._reply(200, body)
                return
            from urllib.parse import parse_qs

            if len(query) > MAX_RECEIPT_QUERY_BYTES:
                self._reply(400, b'{"error":"receipt query is too long"}')
                return
            params = parse_qs(query, strict_parsing=False)
            uids = params.get("uid", [])
            endpoints = params.get("endpoint", [])
            if (
                len(uids) != 1
                or len(endpoints) != 1
                or not uids[0].isascii()
                or not uids[0].isdigit()
            ):
                self._reply(400, b'{"error":"receipt needs one uid and one endpoint"}')
                return
            try:
                receipt = machine_receipt(
                    json.loads(body), uid=int(uids[0]), endpoint=endpoints[0]
                )
            except (PoolInventoryError, ValueError):
                self._reply(404, b'{"error":"no receipt for that machine"}')
                return
            self._reply(200, _canonical(receipt))

    return ThreadingHTTPServer((host, port), _Handler)


def main(argv: Sequence[str]) -> int:
    """``cathedral-validator pool-inventory serve|verify|receipt|verify-receipt``."""

    import argparse

    parser = argparse.ArgumentParser(
        prog="cathedral-validator pool-inventory", allow_abbrev=False
    )
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="serve the signed inventory read-only")
    serve.add_argument("--inventory", required=True, type=Path)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8094)
    verify = commands.add_parser("verify", help="verify a published inventory file")
    verify.add_argument("--inventory", required=True, type=Path)
    receipt = commands.add_parser("receipt", help="print one machine's receipt")
    receipt.add_argument("--inventory", required=True, type=Path)
    receipt.add_argument("--uid", required=True, type=int)
    receipt.add_argument("--endpoint", required=True)
    check = commands.add_parser("verify-receipt", help="verify a machine receipt file")
    check.add_argument("--receipt", required=True, type=Path)
    options = parser.parse_args(list(argv))
    if options.command == "receipt":
        try:
            document = json.loads(read_pool_inventory(options.inventory))
            print(
                json.dumps(
                    machine_receipt(
                        document, uid=options.uid, endpoint=options.endpoint
                    ),
                    sort_keys=True,
                )
            )
        except (PoolInventoryError, ValueError) as exc:
            print(f"MACHINE_RECEIPT_UNAVAILABLE: {exc}")
            return 1
        return 0
    if options.command == "verify-receipt":
        try:
            verified = verify_machine_receipt(
                json.loads(read_pool_inventory(options.receipt))
            )
        except (PoolInventoryError, ValueError) as exc:
            print(f"MACHINE_RECEIPT_INVALID: {exc}")
            return 1
        print(
            json.dumps(
                {
                    "status": "MACHINE_RECEIPT_VALID",
                    "inventory_id": verified["inventory_id"],
                    "validator": verified["header"]["validator"]["hotkey"],
                    "block_number": verified["header"]["anchor"]["block_number"],
                    "machine": verified["leaf"],
                },
                sort_keys=True,
            )
        )
        return 0
    if options.command == "verify":
        try:
            document = verify_pool_inventory(
                json.loads(read_pool_inventory(options.inventory))
            )
        except (PoolInventoryError, ValueError) as exc:
            print(f"POOL_INVENTORY_INVALID: {exc}")
            return 1
        print(
            json.dumps(
                {
                    "status": "POOL_INVENTORY_VALID",
                    "inventory_id": document["inventory_id"],
                    "validator": document["validator"]["hotkey"],
                    "block_number": document["anchor"]["block_number"],
                    "totals": document["totals"],
                },
                sort_keys=True,
            )
        )
        return 0
    server = make_inventory_server(options.inventory, options.host, options.port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0
