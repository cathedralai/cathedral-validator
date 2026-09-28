"""A signed, per-cycle inventory of the supply pool this validator scored.

Each proven cycle can publish one ``cathedral_pool_inventory_v1`` document:
every machine the round probed, with whether it answered (``available``) and
whether it met the same rule the weights pay for (``healthy``). The validator
hotkey signs it, so a reader can check which validator saw what at which
finalized block without trusting the host that serves the file.

``assigned`` is always zero here: no customer work reaches miner machines yet,
and the document says so in ``assignment_source`` rather than leaving it out.

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
ROUTE = "/v1/pool/inventory"
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
        "machines",
        "inventory_id",
        "signature",
    }
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


def _inventory_id(document: Mapping[str, Any]) -> str:
    unsigned = {
        key: value
        for key, value in document.items()
        if key not in {"inventory_id", "signature"}
    }
    return "sha256:" + hashlib.sha256(_canonical(unsigned)).hexdigest()


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
    healthy = {
        (int(row["uid"]), str(row["endpoint"])) for row in healthy_rows
    }
    machines: list[dict[str, Any]] = []
    for row in rows:
        uid = row.get("uid")
        endpoint = row.get("endpoint")
        if isinstance(uid, bool) or not isinstance(uid, int) or not isinstance(endpoint, str):
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
        "generated_at": generated_at.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "totals": {
            "miners": miner_count,
            "machines": len(machines),
            "available": sum(m["state"] != STATE_UNREACHABLE for m in machines),
            "healthy": sum(m["state"] == STATE_HEALTHY for m in machines),
            "assigned": 0,
        },
        "assignment_source": None,
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
        signature = bytes(keypair.sign(SIGNING_DOMAIN + signed["inventory_id"].encode("ascii")))
    except Exception as exc:
        raise PoolInventoryError("validator hotkey could not sign the inventory") from exc
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
        or any(not isinstance(m, dict) or frozenset(m) != _MACHINE_KEYS for m in machines)
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
    if document["inventory_id"] != _inventory_id(document):
        raise PoolInventoryError("inventory identity does not match its contents")
    signature = document["signature"]
    validator = document["validator"]
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "value_base64"}
        or signature["algorithm"] != "sr25519"
        or not isinstance(signature["value_base64"], str)
        or not isinstance(validator, dict)
        or not isinstance(validator.get("hotkey"), str)
    ):
        raise PoolInventoryError("inventory signature is invalid")
    try:
        raw = base64.b64decode(signature["value_base64"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PoolInventoryError("inventory signature is invalid") from exc
    if len(raw) != 64:
        raise PoolInventoryError("inventory signature is invalid")
    try:
        from bittensor_wallet import Keypair

        valid = Keypair(ss58_address=validator["hotkey"]).verify(
            SIGNING_DOMAIN + document["inventory_id"].encode("ascii"), raw
        )
    except Exception as exc:
        raise PoolInventoryError("inventory validator hotkey is invalid") from exc
    if not valid:
        raise PoolInventoryError("inventory signature verification failed")
    return document


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
    """A read-only server: GET /v1/pool/inventory returns the signed file."""

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
            if self.path.partition("?")[0] != ROUTE:
                self._reply(404, b'{"error":"not found"}')
                return
            try:
                body = read_pool_inventory(path)
            except PoolInventoryError:
                self._reply(503, b'{"error":"inventory unavailable"}')
                return
            self._reply(200, body)

    return ThreadingHTTPServer((host, port), _Handler)


def main(argv: Sequence[str]) -> int:
    """``cathedral-validator pool-inventory serve|verify``."""

    import argparse

    parser = argparse.ArgumentParser(prog="cathedral-validator pool-inventory", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="serve the signed inventory read-only")
    serve.add_argument("--inventory", required=True, type=Path)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8094)
    verify = commands.add_parser("verify", help="verify a published inventory file")
    verify.add_argument("--inventory", required=True, type=Path)
    options = parser.parse_args(list(argv))
    if options.command == "verify":
        try:
            document = verify_pool_inventory(json.loads(read_pool_inventory(options.inventory)))
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
