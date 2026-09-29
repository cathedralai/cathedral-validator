#!/usr/bin/env python3
"""Small local-chain helper for the localnet harness (bittensor 10.x).

Subcommands:
  genesis     print the chain's genesis hash; refuses the Finney genesis
  serve-axon  advertise a miner worker's IP and port on netuid 94
  wait-permit wait until the validator hotkey holds a validator permit
  check       prove the loop from chain state: the validator's weight row
              names a miner UID, and that miner's incentive and emission > 0

Every subcommand refuses endpoints other than ws://127.0.0.1 or ws://localhost.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import bittensor as bt
from bittensor_wallet import Wallet

FINNEY_GENESIS_HASH = (
    "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"
)
NETUID = 94


def connect(endpoint: str) -> bt.Subtensor:
    parsed = urlsplit(endpoint)
    if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise SystemExit("refusing a non-local endpoint")
    subtensor = bt.Subtensor(network=endpoint)
    genesis = str(subtensor.substrate.get_block_hash(0)).lower()
    if genesis == FINNEY_GENESIS_HASH:
        raise SystemExit("refusing the Finney genesis")
    return subtensor


def query(subtensor: bt.Subtensor, name: str, params: list):
    value = subtensor.substrate.query("SubtensorModule", name, params)
    return getattr(value, "value", value)


def cmd_genesis(args: argparse.Namespace) -> int:
    subtensor = connect(args.network)
    print(str(subtensor.substrate.get_block_hash(0)).lower())
    return 0


def cmd_serve_axon(args: argparse.Namespace) -> int:
    subtensor = connect(args.network)
    wallet = Wallet(name=args.wallet_name, hotkey="default", path=str(args.wallet_path))
    hotkey = wallet.hotkey
    address = ipaddress.IPv4Address(args.ip)
    uid = query(subtensor, "Uids", [NETUID, hotkey.ss58_address])
    if uid is None:
        raise SystemExit(f"{args.wallet_name} is not registered on netuid {NETUID}")
    current = query(subtensor, "Axons", [NETUID, hotkey.ss58_address])
    if current and int(current.get("ip", 0)) == int(address) and int(current.get("port", 0)) == args.port:
        print(json.dumps({"step": "axon already served", "uid": uid, "ip": args.ip, "port": args.port}))
        return 0
    call = subtensor.substrate.compose_call(
        call_module="SubtensorModule",
        call_function="serve_axon",
        call_params={
            "netuid": NETUID,
            "version": 1,
            "ip": int(address),
            "port": args.port,
            "ip_type": 4,
            "protocol": 4,
            "placeholder1": 0,
            "placeholder2": 0,
        },
    )
    for attempt in range(30):
        extrinsic = subtensor.substrate.create_signed_extrinsic(call=call, keypair=hotkey)
        receipt = subtensor.substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
        if receipt.is_success:
            break
        error = str(receipt.error_message)
        if "ServingRateLimitExceeded" not in error:
            raise SystemExit(f"serve_axon failed: {error}")
        time.sleep(2)
    else:
        raise SystemExit("serve_axon stayed rate limited")
    current = query(subtensor, "Axons", [NETUID, hotkey.ss58_address])
    if int(current.get("ip", 0)) != int(address) or int(current.get("port", 0)) != args.port:
        raise SystemExit("serve_axon did not take effect")
    print(json.dumps({"step": "axon served", "uid": uid, "ip": args.ip, "port": args.port,
                      "hotkey": hotkey.ss58_address}))
    return 0


def cmd_wait_permit(args: argparse.Namespace) -> int:
    subtensor = connect(args.network)
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        metagraph = subtensor.metagraph(NETUID)
        hotkeys = list(metagraph.hotkeys)
        if args.hotkey in hotkeys:
            uid = hotkeys.index(args.hotkey)
            if bool(metagraph.validator_permit[uid]):
                print(json.dumps({"step": "permit", "uid": uid, "block": int(metagraph.block)}))
                return 0
        time.sleep(3)
    raise SystemExit("validator permit did not appear in time")


def cmd_check(args: argparse.Namespace) -> int:
    subtensor = connect(args.network)
    block = int(subtensor.get_current_block())
    metagraph = subtensor.metagraph(NETUID)
    hotkeys = [str(value) for value in metagraph.hotkeys]
    if args.validator_hotkey not in hotkeys:
        raise SystemExit("validator hotkey is not registered")
    validator_uid = hotkeys.index(args.validator_hotkey)
    raw_row = query(subtensor, "Weights", [NETUID, validator_uid]) or []
    weights = [(int(uid), int(weight)) for uid, weight in raw_row]
    rows = []
    for uid, hotkey in enumerate(hotkeys):
        axon = metagraph.axons[uid]
        rows.append({
            "uid": uid,
            "hotkey": hotkey,
            "stake": float(metagraph.S[uid]),
            "validator_permit": bool(metagraph.validator_permit[uid]),
            "incentive": float(metagraph.I[uid]),
            "emission": float(metagraph.E[uid]),
            "dividends": float(metagraph.D[uid]),
            "consensus": float(metagraph.C[uid]),
            "last_update": int(metagraph.last_update[uid]),
            "axon": f"{axon.ip}:{axon.port}" if int(axon.port) else None,
        })
    weighted = {uid for uid, weight in weights if weight > 0}
    miners = [row for row in rows if row["uid"] in weighted]
    paid = [row for row in miners if row["incentive"] > 0 and row["emission"] > 0]
    verdict = "PASS" if weighted and paid else "NOT_YET"
    result = {
        "verdict": verdict,
        "block": block,
        "metagraph_block": int(metagraph.block),
        "netuid": NETUID,
        "tempo": query(subtensor, "Tempo", [NETUID]),
        "validator_uid": validator_uid,
        "validator_last_update": rows[validator_uid]["last_update"],
        "validator_weights": weights,
        "rows": rows,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.require_pass and verdict != "PASS":
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--network", default="ws://127.0.0.1:9944")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("genesis").set_defaults(func=cmd_genesis)
    serve = sub.add_parser("serve-axon")
    serve.add_argument("--wallet-path", required=True, type=Path)
    serve.add_argument("--wallet-name", required=True)
    serve.add_argument("--ip", required=True)
    serve.add_argument("--port", required=True, type=int)
    serve.set_defaults(func=cmd_serve_axon)
    permit = sub.add_parser("wait-permit")
    permit.add_argument("--hotkey", required=True)
    permit.add_argument("--timeout", type=float, default=120.0)
    permit.set_defaults(func=cmd_wait_permit)
    check = sub.add_parser("check")
    check.add_argument("--validator-hotkey", required=True)
    check.add_argument("--require-pass", action="store_true")
    check.set_defaults(func=cmd_check)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
