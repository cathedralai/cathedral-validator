#!/usr/bin/env python3
"""Prepare a local subtensor chain so the compiled netuid 94 exists and is ours.

Idempotent. Every step reads chain state first and only writes what is
missing, then reads the chain again to prove the write had its effect.

What it does on the local chain only:

1. Refuses unless the endpoint is ws://127.0.0.1 or ws://localhost and the
   chain genesis is not the Finney genesis.
2. Creates fresh development wallets under --wallet-path (never
   ~/.bittensor/wallets): an owner, one validator, and N miners.
3. Uses the well-known development sudo key //Alice to make subnet creation
   cheap, then creates placeholder subnets until the next free netuid is 94 and
   registers 94 with the owner wallet, so the validator's compiled NETUID stays
   untouched.
4. Starts emission on 94 and sets its hyperparameters: commit-reveal off,
   short tempo, a weights rate limit the direct writer accepts (it refuses a
   limit shorter than its 16-block mortal era), open registration, cheap burn.
5. Registers the validator and miner hotkeys and stakes to the validator so it
   holds a permit at the next epoch.

Run it with a Python that has bittensor 10.x installed (the validator's pin).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import bittensor as bt
from bittensor_wallet import Keypair, Wallet

FINNEY_GENESIS_HASH = (
    "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"
)
TARGET_NETUID = 94
RAO = 10**9
ALICE_URI = "//Alice"


def log(message: str, **fields: object) -> None:
    payload = {"step": message, **fields}
    print(json.dumps(payload, sort_keys=True, default=str), flush=True)


def require_local_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise SystemExit(
            "setup_chain refuses any endpoint but ws://127.0.0.1:<port> or "
            "ws://localhost:<port>"
        )
    return endpoint


class Chain:
    def __init__(self, endpoint: str) -> None:
        self.subtensor = bt.Subtensor(network=require_local_endpoint(endpoint))
        self.substrate = self.subtensor.substrate
        genesis = str(self.substrate.get_block_hash(0)).lower()
        if genesis == FINNEY_GENESIS_HASH:
            raise SystemExit("setup_chain refuses the Finney genesis")
        self.genesis = genesis
        self.alice = Keypair.create_from_uri(ALICE_URI)
        sudo_key = self.query("Sudo", "Key")
        if sudo_key != self.alice.ss58_address:
            raise SystemExit("this chain's sudo key is not the //Alice development key")

    def query(self, module: str, name: str, params: list | None = None):
        result = self.substrate.query(module, name, params or [])
        return getattr(result, "value", result)

    def block(self) -> int:
        return int(self.subtensor.get_current_block())

    def submit(self, keypair: Keypair, module: str, function: str, params: dict, *, label: str):
        call = self.substrate.compose_call(
            call_module=module, call_function=function, call_params=params
        )
        return self._submit_call(keypair, call, label=label)

    def sudo(self, function: str, params: dict, *, module: str = "AdminUtils"):
        inner = self.substrate.compose_call(
            call_module=module, call_function=function, call_params=params
        )
        call = self.substrate.compose_call(
            call_module="Sudo", call_function="sudo", call_params={"call": inner}
        )
        return self._submit_call(self.alice, call, label=f"sudo {function}")

    def _submit_call(self, keypair: Keypair, call, *, label: str):
        last_error = None
        for attempt in range(5):
            extrinsic = self.substrate.create_signed_extrinsic(call=call, keypair=keypair)
            try:
                receipt = self.substrate.submit_extrinsic(
                    extrinsic, wait_for_inclusion=True, wait_for_finalization=False
                )
            except Exception as exc:  # pool rejections such as a stale nonce
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(1.0)
                continue
            if receipt.is_success:
                # Sudo reports the inner dispatch result as an event, not as
                # the extrinsic result.
                for event in receipt.triggered_events:
                    value = getattr(event, "value", event)
                    body = value.get("event", {}) if isinstance(value, dict) else {}
                    if body.get("module_id") == "Sudo" and body.get("event_id") == "Sudid":
                        outcome = body.get("attributes", {})
                        text = json.dumps(outcome, default=str)
                        if "Err" in text:
                            raise SystemExit(f"{label}: sudo dispatch failed: {text}")
                return receipt
            last_error = receipt.error_message
            raise SystemExit(f"{label} failed on chain: {last_error}")
        raise SystemExit(f"{label} could not be submitted: {last_error}")


def ensure_wallet(path: Path, name: str) -> Wallet:
    wallet = Wallet(name=name, hotkey="default", path=str(path))
    wallet.create_if_non_existent(coldkey_use_password=False, hotkey_use_password=False)
    return wallet


def fund(chain: Chain, address: str, minimum_tao: int, *, label: str) -> None:
    balance = chain.subtensor.get_balance(address).rao
    if balance >= minimum_tao * RAO:
        log("fund skipped", wallet=label, balance_tao=balance / RAO)
        return
    amount = minimum_tao * RAO - balance + RAO
    chain.submit(
        chain.alice,
        "Balances",
        "transfer_keep_alive",
        {"dest": address, "value": amount},
        label=f"fund {label}",
    )
    after = chain.subtensor.get_balance(address).rao
    if after < minimum_tao * RAO:
        raise SystemExit(f"funding {label} did not take effect")
    log("funded", wallet=label, balance_tao=after / RAO)


def netuids(chain: Chain) -> list[int]:
    return sorted(int(n) for n in chain.subtensor.get_all_subnets_netuid())


def set_if_needed(chain: Chain, storage: str, params: list, want, function: str, call_params: dict):
    current = chain.query("SubtensorModule", storage, params)
    if current == want:
        return
    chain.sudo(function, call_params)
    after = chain.query("SubtensorModule", storage, params)
    if after != want:
        raise SystemExit(f"{function} did not take effect: {storage}={after!r}, want {want!r}")
    log("set", storage=storage, params=params, value=after)


def make_subnet_creation_cheap(chain: Chain) -> None:
    set_if_needed(chain, "NetworkRateLimit", [], 0, "sudo_set_network_rate_limit", {"rate_limit": 0})
    set_if_needed(
        chain, "NetworkLockReductionInterval", [], 1,
        "sudo_set_lock_reduction_interval", {"interval": 1},
    )
    set_if_needed(
        chain, "NetworkMinLockCost", [], RAO, "sudo_set_network_min_lock_cost", {"lock_cost": RAO}
    )
    set_if_needed(chain, "AdminFreezeWindow", [], 0, "sudo_set_admin_freeze_window", {"window": 0})
    set_if_needed(chain, "StartCallDelay", [], 0, "sudo_set_start_call_delay", {"delay": 0})


def wait_for_cheap_lock(chain: Chain, ceiling_rao: int) -> int:
    for _ in range(40):
        cost = chain.subtensor.get_subnet_burn_cost()
        cost_rao = int(getattr(cost, "rao", cost))
        if cost_rao <= ceiling_rao:
            return cost_rao
        time.sleep(0.5)
    raise SystemExit("subnet lock cost stayed above its ceiling")


def create_subnets(chain: Chain, owner: Wallet) -> None:
    existing = netuids(chain)
    if TARGET_NETUID in existing:
        owner_coldkey = chain.query("SubtensorModule", "SubnetOwner", [TARGET_NETUID])
        if owner_coldkey != owner.coldkeypub.ss58_address:
            raise SystemExit(
                f"netuid {TARGET_NETUID} exists but is owned by {owner_coldkey}, not this owner wallet"
            )
        log("netuid exists", netuid=TARGET_NETUID, owner=owner_coldkey)
        return
    alice_hotkey = chain.alice.ss58_address
    started = time.monotonic()
    while True:
        existing = netuids(chain)
        free = next(n for n in range(1, 65536) if n not in existing)
        if free > TARGET_NETUID:
            raise SystemExit(f"next free netuid {free} is past {TARGET_NETUID}; restart the chain")
        cost = wait_for_cheap_lock(chain, 4 * RAO)
        if free < TARGET_NETUID:
            chain.submit(
                chain.alice, "SubtensorModule", "register_network",
                {"hotkey": alice_hotkey}, label=f"register placeholder netuid {free}",
            )
            if free % 10 == 0:
                log("placeholder subnets", next_free=free, lock_rao=cost,
                    elapsed_s=round(time.monotonic() - started, 1))
            continue
        chain.submit(
            owner.coldkey, "SubtensorModule", "register_network",
            {"hotkey": owner.hotkey.ss58_address}, label=f"register netuid {TARGET_NETUID}",
        )
        break
    owner_coldkey = chain.query("SubtensorModule", "SubnetOwner", [TARGET_NETUID])
    if owner_coldkey != owner.coldkeypub.ss58_address:
        raise SystemExit(f"netuid {TARGET_NETUID} registration did not land on the owner wallet")
    log("netuid created", netuid=TARGET_NETUID, owner=owner_coldkey,
        elapsed_s=round(time.monotonic() - started, 1))


def start_emission(chain: Chain, owner: Wallet) -> None:
    first = chain.query("SubtensorModule", "FirstEmissionBlockNumber", [TARGET_NETUID])
    if first is None:
        chain.submit(
            owner.coldkey, "SubtensorModule", "start_call", {"netuid": TARGET_NETUID},
            label="start_call",
        )
        first = chain.query("SubtensorModule", "FirstEmissionBlockNumber", [TARGET_NETUID])
        if first is None:
            raise SystemExit("start_call did not set FirstEmissionBlockNumber")
    enabled = chain.query("SubtensorModule", "SubtokenEnabled", [TARGET_NETUID])
    if enabled is not True:
        raise SystemExit("subtoken is not enabled on the target netuid after start_call")
    log("emission started", netuid=TARGET_NETUID, first_emission_block=first)


def configure_hyperparameters(chain: Chain, args: argparse.Namespace) -> None:
    n = TARGET_NETUID
    wanted = [
        ("CommitRevealWeightsEnabled", False, "sudo_set_commit_reveal_weights_enabled",
         {"netuid": n, "enabled": False}),
        ("Tempo", args.tempo, "sudo_set_tempo", {"netuid": n, "tempo": args.tempo}),
        ("WeightsSetRateLimit", args.weights_rate_limit, "sudo_set_weights_set_rate_limit",
         {"netuid": n, "weights_set_rate_limit": args.weights_rate_limit}),
        ("ImmunityPeriod", args.immunity_period, "sudo_set_immunity_period",
         {"netuid": n, "immunity_period": args.immunity_period}),
        ("NetworkRegistrationAllowed", True, "sudo_set_network_registration_allowed",
         {"netuid": n, "registration_allowed": True}),
        ("MaxRegistrationsPerBlock", 16, "sudo_set_max_registrations_per_block",
         {"netuid": n, "max_registrations_per_block": 16}),
        ("TargetRegistrationsPerInterval", 16, "sudo_set_target_registrations_per_interval",
         {"netuid": n, "target_registrations_per_interval": 16}),
        ("MinAllowedWeights", 1, "sudo_set_min_allowed_weights",
         {"netuid": n, "min_allowed_weights": 1}),
        ("WeightsVersionKey", 0, "sudo_set_weights_version_key",
         {"netuid": n, "weights_version_key": 0}),
        ("MaxAllowedValidators", args.max_validators, "sudo_set_max_allowed_validators",
         {"netuid": n, "max_allowed_validators": args.max_validators}),
        # With the owner cut on, the owner hotkey (UID 0) accrues most of the
        # subnet's stake every tempo without ever setting weights. Yuma then
        # takes its all-zero row as the stake-weighted consensus and clips
        # every miner to zero. Mainnet validators outweigh the owner; a fresh
        # local subnet cannot buy that much alpha from its tiny pool.
        ("OwnerCutEnabled", False, "sudo_set_owner_cut_enabled", {"netuid": n, "enabled": False}),
    ]
    for storage, value, function, params in wanted:
        set_if_needed(chain, storage, [n], value, function, params)
    burn = chain.query("SubtensorModule", "Burn", [n])
    log("hyperparameters", netuid=n, burn_rao=burn, tempo=args.tempo,
        weights_rate_limit=args.weights_rate_limit)


def uid_of(chain: Chain, hotkey: str) -> int | None:
    uid = chain.query("SubtensorModule", "Uids", [TARGET_NETUID, hotkey])
    return None if uid is None else int(uid)


def register(chain: Chain, wallet: Wallet, label: str) -> int:
    hotkey = wallet.hotkey.ss58_address
    uid = uid_of(chain, hotkey)
    if uid is not None:
        log("registered", wallet=label, uid=uid, hotkey=hotkey)
        return uid
    chain.submit(
        wallet.coldkey, "SubtensorModule", "burned_register",
        {"netuid": TARGET_NETUID, "hotkey": hotkey}, label=f"burned_register {label}",
    )
    uid = uid_of(chain, hotkey)
    if uid is None:
        raise SystemExit(f"{label} registration did not take effect")
    log("registered", wallet=label, uid=uid, hotkey=hotkey)
    return uid


def delegate_owner_stake(chain: Chain, owner: Wallet, validator: Wallet) -> None:
    """Move the owner's alpha onto the validator hotkey.

    A new subnet's owner hotkey (UID 0) holds nearly all of its stake and
    never sets weights. Yuma takes that all-zero row as the stake-weighted
    consensus and clips every miner to zero. On mainnet the validators
    outweigh the owner; a fresh local pool is too shallow to buy that much
    alpha (add_stake fails with InsufficientLiquidity), so the owner coldkey
    delegates its alpha to the validator hotkey instead, as an owner can on
    mainnet. No swap is involved, so pool liquidity does not matter.
    """

    owner_hotkey = owner.hotkey.ss58_address
    owner_coldkey = owner.coldkeypub.ss58_address
    validator_hotkey = validator.hotkey.ss58_address
    current = stake_rao(chain, owner_hotkey, owner_coldkey)
    if current == 0:
        log("owner stake already delegated", owner_hotkey=owner_hotkey)
        return
    chain.submit(
        owner.coldkey, "SubtensorModule", "move_stake",
        {
            "origin_hotkey": owner_hotkey,
            "destination_hotkey": validator_hotkey,
            "origin_netuid": TARGET_NETUID,
            "destination_netuid": TARGET_NETUID,
            "alpha_amount": current,
        },
        label="move_stake owner to validator",
    )
    left = stake_rao(chain, owner_hotkey, owner_coldkey)
    delegated = stake_rao(chain, validator_hotkey, owner_coldkey)
    log("owner stake delegated", moved_alpha_rao=current, owner_left_alpha_rao=left,
        validator_delegated_alpha_rao=delegated)
    if delegated <= 0 or left * 10 > delegated:
        raise SystemExit("owner stake did not move to the validator hotkey")


def stake_rao(chain: Chain, hotkey: str, coldkey: str) -> int:
    stake = chain.subtensor.get_stake(coldkey, hotkey, TARGET_NETUID)
    return int(getattr(stake, "rao", stake))


def ensure_stake(chain: Chain, validator: Wallet, tao: int) -> None:
    hotkey = validator.hotkey.ss58_address
    coldkey = validator.coldkeypub.ss58_address
    current = stake_rao(chain, hotkey, coldkey)
    if current > 0:
        log("stake present", alpha_rao=current, hotkey=hotkey)
        return
    # A fresh local pool holds very little alpha, so a large purchase fails
    # with InsufficientLiquidity. Any nonzero stake is enough for the only
    # permit once the owner's stake is back in the pool.
    amounts = [tao * RAO, RAO, RAO // 10, RAO // 100]
    last_error = None
    for amount in amounts:
        try:
            chain.submit(
                validator.coldkey, "SubtensorModule", "add_stake",
                {"hotkey": hotkey, "netuid": TARGET_NETUID, "amount_staked": amount},
                label="add_stake validator",
            )
            break
        except SystemExit as exc:
            last_error = str(exc)
            if "InsufficientLiquidity" not in last_error:
                raise
            log("stake retry", amount_rao=amount, error="InsufficientLiquidity")
    else:
        # Not fatal: the delegated owner stake already gives the validator
        # hotkey the permit. The validator's own coldkey stake is a bonus.
        log("validator own stake skipped", error=last_error)
        return
    after = stake_rao(chain, hotkey, coldkey)
    if after <= 0:
        raise SystemExit("validator stake did not take effect")
    log("staked", alpha_rao=after, hotkey=hotkey)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--network", default="ws://127.0.0.1:9944")
    parser.add_argument("--wallet-path", required=True, type=Path)
    parser.add_argument("--miners", type=int, default=2)
    parser.add_argument("--tempo", type=int, default=40)
    parser.add_argument("--weights-rate-limit", type=int, default=20)
    parser.add_argument("--immunity-period", type=int, default=100)
    parser.add_argument("--max-validators", type=int, default=1)
    parser.add_argument("--validator-stake-tao", type=int, default=10)
    parser.add_argument("--out", type=Path, help="write the resulting identities as JSON")
    args = parser.parse_args()
    if args.weights_rate_limit < 16:
        raise SystemExit("the direct writer refuses a weights rate limit below its 16-block era")
    if not 1 <= args.miners <= 8:
        raise SystemExit("--miners must be 1..8")
    wallet_path = args.wallet_path.expanduser().resolve()
    if wallet_path == (Path.home() / ".bittensor" / "wallets").resolve():
        raise SystemExit("use a dedicated --wallet-path, never ~/.bittensor/wallets")
    wallet_path.mkdir(parents=True, exist_ok=True, mode=0o700)

    chain = Chain(args.network)
    log("connected", endpoint=args.network, genesis=chain.genesis, block=chain.block())

    owner = ensure_wallet(wallet_path, "localnet-owner")
    validator = ensure_wallet(wallet_path, "localnet-validator")
    miners = [ensure_wallet(wallet_path, f"localnet-miner{i}") for i in range(1, args.miners + 1)]
    fund(chain, owner.coldkeypub.ss58_address, 1000, label="owner")
    fund(chain, validator.coldkeypub.ss58_address, args.validator_stake_tao + 1000, label="validator")
    for index, miner in enumerate(miners, start=1):
        fund(chain, miner.coldkeypub.ss58_address, 100, label=f"miner{index}")

    make_subnet_creation_cheap(chain)
    create_subnets(chain, owner)
    start_emission(chain, owner)
    configure_hyperparameters(chain, args)

    validator_uid = register(chain, validator, "validator")
    miner_uids = [register(chain, miner, f"miner{i}") for i, miner in enumerate(miners, start=1)]
    delegate_owner_stake(chain, owner, validator)
    ensure_stake(chain, validator, args.validator_stake_tao)

    result = {
        "network": args.network,
        "genesis": chain.genesis,
        "netuid": TARGET_NETUID,
        "block": chain.block(),
        "owner": {"coldkey": owner.coldkeypub.ss58_address, "hotkey": owner.hotkey.ss58_address},
        "validator": {
            "wallet_name": "localnet-validator",
            "hotkey": validator.hotkey.ss58_address,
            "uid": validator_uid,
        },
        "miners": [
            {"wallet_name": f"localnet-miner{i}", "hotkey": miner.hotkey.ss58_address, "uid": uid}
            for i, (miner, uid) in enumerate(zip(miners, miner_uids), start=1)
        ],
        "wallet_path": str(wallet_path),
    }
    if args.out:
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    log("done", **result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
