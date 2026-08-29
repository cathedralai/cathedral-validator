"""Historical miner-axon recovery.

The preview and announcement implementation remains importable for exact
journal recovery tests, but every shipped command selects the recovery-only
parser. This keeps stale installed console-script shims fail closed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from cathedral_thin.bt_compat import make_subtensor, make_wallet

from .errors import IndependentLiveError
from .miner_axon import (
    NETWORK,
    SN39_HTTPS_PORT,
    UID124_AXON_CONTRACT,
    MinerAxonContract,
    MinerAxonAmbiguous,
    MinerAxonError,
    _contract_preview_path,
    _contract_runtime_root,
    _wallet_public_identity,
    announce_reviewed_preview,
    build_preview,
    collect_endpoint_proof,
    finalized_miner_state,
    recover_ambiguous_preview,
    write_preview,
)

WALLET_NAME = "cathedral"
WALLET_HOTKEY = "serge_sat_test"
MappingResult = dict[str, Any]


def _parser(
    *,
    prog: str,
    contract: MinerAxonContract,
    recovery_only: bool = False,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog)
    sub = parser.add_subparsers(dest="command", required=True)

    if not recovery_only:
        preview = sub.add_parser(
            "preview", help="write the default no-chain-write announcement artifact"
        )
        preview.add_argument("--ip", required=True, help="verified public miner IPv4")
        preview.add_argument("--port", type=int, default=SN39_HTTPS_PORT)
        preview.add_argument("--qvl", required=True, help="pinned TDX QVL executable")
        preview.add_argument("--output", default=str(_contract_preview_path(contract)))
        preview.add_argument("--wallet-path", default=None)

        announce = sub.add_parser(
            "announce", help="make one digest-authorized serve_axon attempt"
        )
        announce.add_argument(
            "--preview", default=str(_contract_preview_path(contract))
        )
        announce.add_argument("--reviewed-sha256", required=True)
        announce.add_argument("--qvl", required=True, help="pinned TDX QVL executable")
        announce.add_argument("--wallet-path", default=None)
        announce.add_argument("--confirm-miner-announce", action="store_true")
        announce.add_argument(
            "--assert-exclusive-announcer",
            action="store_true",
            help="assert every other process or host able to announce this miner is stopped",
        )
        if contract.supports_legacy_successor and contract.successor_generation is None:
            announce.add_argument(
                "--allow-finalized-successor",
                action="store_true",
                help="allow the one reviewed successor to a strictly proven final journal",
            )
            announce.add_argument(
                "--predecessor-preview",
                help="owner-only reviewed preview for the finalized predecessor",
            )
            announce.add_argument(
                "--predecessor-reviewed-sha256",
                help="exact reviewed SHA256 for the finalized predecessor preview",
            )

    recover = sub.add_parser(
        "recover",
        help="read finalized SN39 state for one ambiguous intent without resubmitting",
    )
    recover.add_argument("--preview", default=str(_contract_preview_path(contract)))
    recover.add_argument("--reviewed-sha256", required=True)
    return parser


def _wallet(bt: Any, *, path: str | None, wallet_hotkey: str) -> Any:
    return make_wallet(
        bt,
        name=WALLET_NAME,
        hotkey=wallet_hotkey,
        path=path,
    )


def _preview(
    options: argparse.Namespace,
    *,
    contract: MinerAxonContract,
    wallet_hotkey: str,
) -> MappingResult:
    try:
        import bittensor as bt
    except ImportError as exc:
        raise MinerAxonError("bittensor is required for the live SN39 path") from exc
    subtensor = make_subtensor(bt, network=NETWORK)
    wallet = _wallet(bt, path=options.wallet_path, wallet_hotkey=wallet_hotkey)
    _wallet_public_identity(wallet, contract=contract)
    before = finalized_miner_state(subtensor, contract=contract)
    proof = collect_endpoint_proof(
        subtensor,
        qvl_path=options.qvl,
        ip=options.ip,
        port=options.port,
        contract=contract,
    )
    after = finalized_miner_state(subtensor, contract=contract)
    if (
        after.uid != before.uid
        or after.hotkey != before.hotkey
        or after.coldkey != before.coldkey
        or after.block_number < before.block_number
        or (after.ip, after.port, after.is_serving)
        != (before.ip, before.port, before.is_serving)
    ):
        raise MinerAxonError(
            "finalized miner registration or axon changed during preview evidence"
        )
    document = build_preview(state=after, proof=proof, contract=contract)
    path, digest_path, digest = write_preview(
        document, Path(options.output), contract=contract
    )
    return {
        "status": document["status"],
        "preview": str(path),
        "detached_sha256": str(digest_path),
        "sha256": digest,
        "miner_hotkey": contract.miner_hotkey,
        "serve_axon_called": False,
        "rent_called": False,
        "registration_called": False,
        "weights_called": False,
    }


def run_contract_cli(
    argv: Sequence[str] | None = None,
    *,
    prog: str,
    wallet_hotkey: str,
    contract: MinerAxonContract,
    recovery_only: bool = False,
) -> int:
    options = _parser(
        prog=prog, contract=contract, recovery_only=recovery_only
    ).parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if options.command == "preview":
            result = _preview(options, contract=contract, wallet_hotkey=wallet_hotkey)
        elif options.command == "announce":
            try:
                import bittensor as bt
            except ImportError as exc:
                raise MinerAxonError(
                    "bittensor is required for the live SN39 path"
                ) from exc
            subtensor = make_subtensor(bt, network=NETWORK)
            wallet = _wallet(bt, path=options.wallet_path, wallet_hotkey=wallet_hotkey)
            pinned_successor = contract.successor_generation is not None
            predecessor_preview = (
                _contract_runtime_root(contract) / contract.predecessor_preview_name
                if pinned_successor and contract.predecessor_preview_name is not None
                else getattr(options, "predecessor_preview", None)
            )
            predecessor_digest = (
                contract.predecessor_preview_sha256
                if pinned_successor
                else getattr(options, "predecessor_reviewed_sha256", None)
            )
            result = dict(
                announce_reviewed_preview(
                    bt_module=bt,
                    subtensor=subtensor,
                    wallet=wallet,
                    preview_path=Path(options.preview),
                    reviewed_sha256=options.reviewed_sha256,
                    qvl_path=options.qvl,
                    confirm=options.confirm_miner_announce,
                    exclusive_announcer_asserted=options.assert_exclusive_announcer,
                    allow_finalized_successor=pinned_successor
                    or getattr(options, "allow_finalized_successor", False),
                    predecessor_preview_path=predecessor_preview,
                    predecessor_reviewed_sha256=predecessor_digest,
                    contract=contract,
                )
            )
        elif options.command == "recover":
            try:
                import bittensor as bt
            except ImportError as exc:
                raise MinerAxonError(
                    "bittensor is required for the live SN39 path"
                ) from exc
            subtensor = make_subtensor(bt, network=NETWORK)
            result = dict(
                recover_ambiguous_preview(
                    subtensor=subtensor,
                    preview_path=Path(options.preview),
                    reviewed_sha256=options.reviewed_sha256,
                    contract=contract,
                )
            )
        else:
            raise MinerAxonError(f"unhandled command {options.command}")
    except MinerAxonAmbiguous as exc:
        print(
            json.dumps(
                {
                    "status": "AMBIGUOUS_DO_NOT_RETRY",
                    "error": str(exc),
                    "serve_axon_retry_allowed": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 3
    except (MinerAxonError, IndependentLiveError, OSError) as exc:
        print(
            json.dumps(
                {
                    "status": "REFUSED_NO_CHAIN_WRITE",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return run_contract_cli(
        argv,
        prog="python -m cathedral_thin.independent_runtime.miner_axon_cli",
        wallet_hotkey=WALLET_HOTKEY,
        contract=UID124_AXON_CONTRACT,
        recovery_only=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
