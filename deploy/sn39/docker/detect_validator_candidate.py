"""Detect a valid SN39 validator candidate from a local wallet + the live chain.

`cathedral run` calls this before starting the validator: it enumerates the coldkey's
hotkeys, reads the live SN39 metagraph, and reports which hotkey (if any) can actually
validate — registered on the subnet, and ideally already holding a validator permit.
It NEVER moves funds, registers, or sets weights; it only reads the chain and prints a
verdict so the operator picks the right hotkey (or learns none qualifies yet).

Exit codes: 0 = a usable candidate was found (printed as CANDIDATE_HOTKEY=<ss58>),
2 = the wallet has hotkeys but none are registered, 3 = no wallet/hotkeys found,
1 = the chain could not be read. `--json` prints the full picture for tooling.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _wallet_hotkeys(wallet_path: Path, wallet_name: str) -> list[tuple[str, str]]:
    """Return [(hotkey_name, ss58)] for every hotkey under the coldkey, or []."""
    hk_dir = wallet_path / wallet_name / "hotkeys"
    out: list[tuple[str, str]] = []
    if not hk_dir.is_dir():
        return out
    for f in sorted(hk_dir.iterdir()):
        if not f.is_file() or f.name.endswith("pub.txt"):
            # `<name>pub.txt` is the public-key sidecar, not a distinct hotkey.
            continue
        try:
            data = json.loads(f.read_text())
        except (ValueError, OSError):
            continue
        ss58 = data.get("ss58Address")
        if isinstance(ss58, str) and ss58:
            out.append((f.name, ss58))
    return out


def _live_metagraph(network: str, netuid: int):
    """[(uid, hotkey, permit, stake)] from the live chain, or None on failure."""
    try:
        import bittensor as bt  # noqa: PLC0415
    except Exception as exc:  # pragma: no cover - environment issue
        print(f"error: bittensor is not importable ({exc})", file=sys.stderr)
        return None
    try:
        subtensor = bt.Subtensor(network=network)
        mg = subtensor.metagraph(netuid=netuid)
    except Exception as exc:
        print(f"error: could not read the {network} netuid {netuid} metagraph: {exc}",
              file=sys.stderr)
        return None
    rows = []
    n = int(mg.n)
    for i in range(n):
        try:
            stake = float(mg.S[i])
        except Exception:
            stake = 0.0
        rows.append((i, mg.hotkeys[i], bool(mg.validator_permit[i]), stake))
    return rows


def detect(*, wallet_path: Path, wallet_name: str, network: str, netuid: int) -> dict:
    hotkeys = _wallet_hotkeys(wallet_path, wallet_name)
    result: dict = {
        "wallet_name": wallet_name,
        "network": network,
        "netuid": netuid,
        "wallet_hotkeys": [{"name": n, "ss58": s} for n, s in hotkeys],
        "candidate": None,
        "registered": [],
        "status": None,
    }
    if not hotkeys:
        result["status"] = "no_wallet_hotkeys"
        return result

    mg = _live_metagraph(network, netuid)
    if mg is None:
        result["status"] = "chain_unreadable"
        return result

    by_hotkey = {hk: (uid, permit, stake) for uid, hk, permit, stake in mg}
    registered = []
    for name, ss58 in hotkeys:
        info = by_hotkey.get(ss58)
        if info is None:
            continue
        uid, permit, stake = info
        registered.append(
            {"name": name, "ss58": ss58, "uid": uid, "validator_permit": permit,
             "stake": round(stake, 4)}
        )
    result["registered"] = registered

    if not registered:
        result["status"] = "none_registered"
        return result

    # Prefer a hotkey that already holds a validator permit; then the highest stake.
    # (A permit is what lets set_weights actually count; stake is what earns it.)
    registered.sort(key=lambda r: (r["validator_permit"], r["stake"]), reverse=True)
    best = registered[0]
    result["candidate"] = best
    result["status"] = "ok" if best["validator_permit"] else "registered_no_permit"
    return result


def _render(result: dict) -> None:
    print(f"# SN39 validator-candidate check ({result['network']} netuid {result['netuid']})")
    print(f"#   wallet: {result['wallet_name']}  hotkeys found: {len(result['wallet_hotkeys'])}")
    status = result["status"]
    if status == "no_wallet_hotkeys":
        print("# NO hotkeys under this coldkey. Create one, then register it on SN39:")
        print(f"#   btcli wallet new_hotkey --wallet.name {result['wallet_name']} --wallet.hotkey validator")
        print(f"#   btcli subnet register --netuid {result['netuid']} --wallet.name {result['wallet_name']} --wallet.hotkey validator")
        return
    if status == "chain_unreadable":
        print("# Could not read the chain — check network connectivity / --network.")
        return
    for r in result["registered"]:
        flag = "PERMIT" if r["validator_permit"] else "no-permit"
        print(f"#   registered: {r['name']} (uid {r['uid']}, stake {r['stake']}, {flag})")
    if status == "none_registered":
        print("# None of this wallet's hotkeys are registered on SN39. Register one:")
        print(f"#   btcli subnet register --netuid {result['netuid']} --wallet.name {result['wallet_name']} --wallet.hotkey <hotkey>")
        return
    best = result["candidate"]
    if status == "registered_no_permit":
        print(f"# CANDIDATE: {best['name']} (uid {best['uid']}) is registered but has NO validator permit yet.")
        print("#   It can run in shadow now; a permit (enough stake to reach the validator set)")
        print("#   is required before its weights count on-chain.")
    else:
        print(f"# CANDIDATE: {best['name']} (uid {best['uid']}) is registered AND holds a validator permit. Ready to validate.")
    # The one machine-readable line `cathedral run` consumes:
    print(f"CANDIDATE_HOTKEY={best['name']}")
    print(f"CANDIDATE_UID={best['uid']}")
    print(f"CANDIDATE_HAS_PERMIT={'1' if best['validator_permit'] else '0'}")


_STATUS_EXIT = {
    "ok": 0,
    "registered_no_permit": 0,
    "none_registered": 2,
    "no_wallet_hotkeys": 3,
    "chain_unreadable": 1,
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Detect a valid SN39 validator candidate.")
    ap.add_argument("--wallet-path", default=os.environ.get(
        "BT_WALLET_PATH", str(Path.home() / ".bittensor" / "wallets")))
    ap.add_argument("--wallet-name", default=os.environ.get("BT_WALLET_NAME", "default"))
    ap.add_argument("--network", default=os.environ.get("CATHEDRAL_NETWORK", "finney"))
    ap.add_argument("--netuid", type=int, default=int(os.environ.get("CATHEDRAL_NETUID", "39")))
    ap.add_argument("--json", action="store_true", help="print the full result as JSON")
    args = ap.parse_args(argv)

    result = detect(
        wallet_path=Path(args.wallet_path).expanduser(),
        wallet_name=args.wallet_name, network=args.network, netuid=args.netuid,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _render(result)
    return _STATUS_EXIT.get(result["status"], 1)


if __name__ == "__main__":
    raise SystemExit(main())
