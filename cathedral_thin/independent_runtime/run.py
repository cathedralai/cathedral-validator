"""CLI: list Cathedral compute, collect evidence, compose, canary-submit.

Subcommands:

* ``profiles`` -- public ``GET /v1/profiles`` (no API key)
* ``list-workers`` -- ``GET /v1/workers``
* ``rent`` -- ``POST`` a sealed Intel TDX Worker (``bounded_service``)
* ``probe-sn39`` -- snapshot the live metagraph and serving axons
* ``run`` -- list or rent a TDX Worker, collect from SN39 axons, compose,
  and submit ``set_mechanism_weights`` through the one-write canary if a
  dedicated canary wallet and a pinned QVL are present

Never uses the live relay wallet. Never touches the thin journal.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any, Sequence

import bittensor as bt

from cathedral_thin.independent.canary import submit_canary_once
from cathedral_thin.independent.collect import collect_evidence, mint_nonce
from cathedral_thin.independent.compose import EpochAnchor, compose_dry_run
from cathedral_thin.independent.compute import (
    COMPUTE_LANE,
    ComputeAdapter,
    QuoteVerdict,
)
from cathedral_thin.independent.constants import (
    CANARY_HOTKEY,
    INDEPENDENT_CANARY_FILE,
    INDEPENDENT_STATE_FILE,
    NETUID,
    REFUSE_HOTKEYS,
    TEMPO_BLOCKS,
)
from cathedral_thin.independent.errors import (
    CanaryIneligible,
    CanarySpent,
    CanaryStateError,
    CanaryTransportError,
    RefuseListError,
)
from cathedral_thin.independent.submit import prepare_mechanism_weights

from .chain import (
    SubstrateCanaryTransport,
    load_keypair,
    metagraph_view,
    observed_genesis_hash,
    serving_axons,
)
from .errors import (
    ChainClientError,
    IndependentLiveError,
    QuoteVerifyError,
    WorkersApiError,
)
from .https import HttpsEvidenceTransport
from .local_policy import COMPUTE_ALLOCATION, commitment_for, funded_compute_bundle
from .qvl import load_verifier
from .score import mass_from_units
from .workers import WorkersClient, fetch_public_json, tdx_workers

INTEL_COLLATERAL = "https://api.trustedservices.intel.com/sgx/certification/v4/"
GUEST_PROBE = (
    "echo HOST:$(hostname); "
    "echo IPS:$(hostname -I 2>/dev/null); "
    "if [ -d /sys/kernel/config/tsm/report ]; then echo TSM:ready; "
    "else echo TSM:missing; fi; "
    "python3 --version 2>/dev/null || echo PYTHON:missing"
)


def _api_key() -> str:
    key = os.environ.get("CATHEDRAL_API_KEY", "")
    if not key:
        raise WorkersApiError(
            "CATHEDRAL_API_KEY is not set; create a cat_sk_* key at "
            "https://cathedral.computer/account/?intent=key"
        )
    return key


def _workers() -> WorkersClient:
    return WorkersClient(_api_key())


def cmd_profiles(_options: argparse.Namespace) -> int:
    document = fetch_public_json("/v1/profiles")
    print(json.dumps(document, indent=2, sort_keys=True, default=str))
    return 0


def cmd_list_workers(_options: argparse.Namespace) -> int:
    client = _workers()
    records = client.list_workers()
    payload = {
        "count": len(records),
        "tdx": [
            {
                "id": record.worker_id,
                "name": record.name,
                "status": record.status,
                "hardware_class": record.hardware_class,
                "ip": record.ip,
                "ssh_host": record.ssh_host,
                "ready": record.ready,
            }
            for record in tdx_workers(records)
        ],
        "all": [
            {
                "id": record.worker_id,
                "name": record.name,
                "status": record.status,
                "hardware_class": record.hardware_class,
            }
            for record in records
        ],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_rent(options: argparse.Namespace) -> int:
    client = _workers()
    record = client.create_persistent_tdx(
        name=options.name,
        max_runtime_minutes=options.max_runtime_minutes,
        max_spend_usd=options.max_spend_usd,
    )
    if options.wait:
        record = client.wait_until_ready(record.worker_id, timeout_seconds=options.wait)
    print(
        json.dumps(
            {
                "id": record.worker_id,
                "name": record.name,
                "status": record.status,
                "hardware_class": record.hardware_class,
                "ip": record.ip,
                "ssh_host": record.ssh_host,
                "ready": record.ready,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _connect_subtensor() -> Any:
    return bt.Subtensor(network="finney")


def cmd_probe_sn39(_options: argparse.Namespace) -> int:
    subtensor = _connect_subtensor()
    genesis = observed_genesis_hash(subtensor)
    metagraph = subtensor.metagraph(NETUID)
    view = metagraph_view(metagraph)
    axons = serving_axons(metagraph)
    print(
        json.dumps(
            {
                "genesis": genesis,
                "netuid": NETUID,
                "uids": len(view.uid_to_hotkey),
                "serving_axons": [
                    {
                        "uid": axon.uid,
                        "hotkey": axon.hotkey,
                        "ip": axon.ip,
                        "port": axon.port,
                        "evidence_url": axon.evidence_url(),
                    }
                    for axon in axons
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _epoch_anchor(subtensor: Any) -> EpochAnchor:
    block = int(subtensor.get_current_block())
    epoch_index = block // TEMPO_BLOCKS
    epoch_open = (epoch_index + 1) * TEMPO_BLOCKS
    anchor_number = epoch_open - 1
    raw_hash = str(subtensor.get_block_hash(anchor_number)).lower()
    if not raw_hash.startswith("0x"):
        raw_hash = "0x" + raw_hash
    return EpochAnchor(
        epoch_open=epoch_open, anchor_number=anchor_number, anchor_hash=raw_hash
    )


def _try_collect(url: str, hotkey: str, validator_ss58: str) -> dict[str, Any]:
    transport = HttpsEvidenceTransport()
    try:
        binding = transport.observe_binding(url)
        nonce = mint_nonce(validator_ss58, entropy=os.urandom(16))
        collected = collect_evidence(
            url=url,
            assigned_hotkey=hotkey,
            nonce=nonce,
            channel_binding=binding,
            transport=transport,
        )
    except Exception as exc:
        return {
            "url": url,
            "hotkey": hotkey,
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "url": url,
        "ok": True,
        "hotkey": collected.assigned_hotkey,
        "quote_bytes": len(collected.quote),
        "kind": collected.kind,
        "collected": collected,
    }


def _summarize_catalog(document: Any) -> dict[str, Any]:
    rows = document.get("profiles") if isinstance(document, dict) else document
    if not isinstance(rows, list):
        rows = []
    summarized = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        classes = row.get("hardware_classes") or row.get("resources") or []
        summarized.append(
            {
                "id": row.get("id"),
                "hardware_classes": [
                    {
                        "id": item.get("id") or item.get("hardware_class"),
                        "execution_class": item.get("execution_class"),
                        "availability": item.get("availability"),
                        "customer_enabled": item.get("customer_enabled"),
                        "lifetimes": item.get("lifetimes"),
                    }
                    for item in classes
                    if isinstance(item, dict)
                ],
            }
        )
    return {"count": len(summarized), "profiles": summarized}


def cmd_run(options: argparse.Namespace) -> int:
    report: dict[str, Any] = {
        "lineage": "independent_v1",
        "canary_hotkey": CANARY_HOTKEY,
        "refuse": sorted(REFUSE_HOTKEYS),
        "catalog": None,
        "workers": [],
        "collect": [],
        "compose": None,
        "canary": None,
        "blockers": [],
    }
    try:
        report["catalog"] = _summarize_catalog(fetch_public_json("/v1/profiles"))
    except WorkersApiError as exc:
        report["blockers"].append(f"catalog: {exc}")

    listed = []
    try:
        client = _workers()
        existing = client.list_workers()
        listed = list(tdx_workers(existing))
        if options.rent and not listed:
            created = client.create_persistent_tdx(name=options.name)
            listed = [created]
        if options.wait:
            listed = [
                client.wait_until_ready(record.worker_id, timeout_seconds=options.wait)
                if not record.ready
                else record
                for record in listed
            ]
        report["workers"] = [
            {
                "id": record.worker_id,
                "status": record.status,
                "hardware_class": record.hardware_class,
                "ip": record.ip,
                "ssh_host": record.ssh_host,
                "ready": record.ready,
            }
            for record in listed
        ]
        for record in listed:
            if not record.ready:
                continue
            try:
                probe = client.run_command(record.worker_id, GUEST_PROBE)
                report.setdefault("guest_probes", []).append(
                    {"id": record.worker_id, "probe": probe}
                )
            except WorkersApiError as exc:
                report.setdefault("guest_probes", []).append(
                    {"id": record.worker_id, "error": str(exc)}
                )
            try:
                attested = client.attest(record.worker_id, nonce=secrets.token_hex(16))
                report.setdefault("worker_attest", []).append(
                    {
                        "id": record.worker_id,
                        "status": attested.get("status")
                        if isinstance(attested, dict)
                        else None,
                        "verified": (attested.get("evidence") or {}).get("verified")
                        if isinstance(attested, dict)
                        else None,
                    }
                )
            except WorkersApiError as exc:
                report.setdefault("worker_attest", []).append(
                    {"id": record.worker_id, "error": str(exc)}
                )
    except WorkersApiError as exc:
        report["blockers"].append(f"workers: {exc}")

    try:
        subtensor = _connect_subtensor()
        report["genesis"] = observed_genesis_hash(subtensor)
        metagraph = subtensor.metagraph(NETUID)
        view = metagraph_view(metagraph)
        axons = serving_axons(metagraph)
        report["sn39"] = {
            "uids": len(view.uid_to_hotkey),
            "serving_axons": [
                {
                    "uid": axon.uid,
                    "hotkey": axon.hotkey,
                    "ip": axon.ip,
                    "port": axon.port,
                    "evidence_url": axon.evidence_url(),
                }
                for axon in axons
            ],
        }
    except Exception as exc:
        report["blockers"].append(f"chain: {type(exc).__name__}: {exc}")
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 2

    validator_ss58 = CANARY_HOTKEY
    collect_hits: list[dict[str, Any]] = []
    # A rented Cathedral Worker is a listed machine. It is not an SN39 miner
    # unless it serves POST /v1/evidence under a registered hotkey. Collect
    # from serving axons with those hotkeys, never with the canary identity.
    for axon in axons:
        collect_hits.append(
            _try_collect(axon.evidence_url(), axon.hotkey, validator_ss58)
        )
    report["collect"] = [
        {key: value for key, value in row.items() if key != "collected"}
        for row in collect_hits
    ]

    verified_units: dict[str, int] = {}
    qvl = None
    try:
        qvl = load_verifier(options.qvl)
        report["qvl_digest"] = qvl.digest
    except QuoteVerifyError as exc:
        report["blockers"].append(f"qvl: {exc}")

    if qvl is not None:
        verifier_adapter = ComputeAdapter(
            qvl,
            collateral_base_url=INTEL_COLLATERAL,
            qvl_digest=qvl.digest,
        )
        for row in collect_hits:
            collected = row.get("collected")
            if collected is None:
                continue
            verdict = verifier_adapter.verify_quote(
                collected.quote, expected_report_data=collected.report_data
            )
            row["verdict"] = verdict.value
            if verdict is QuoteVerdict.PASS:
                # Attestation is admission. One verified machine that answered
                # this validator's nonce is one integer work unit of liveness
                # until SAT work-report dispatch is wired for this guest.
                verified_units[collected.assigned_hotkey] = (
                    verified_units.get(collected.assigned_hotkey, 0) + 1
                )
            elif verdict is QuoteVerdict.FAIL:
                continue
            elif verdict is QuoteVerdict.INFRA:
                report["blockers"].append("qvl: infrastructure failure on a quote")
            else:
                never: QuoteVerdict = verdict
                raise IndependentLiveError(f"unhandled quote verdict {never}")

    # Product truth: attestation is not payment. Only bind mass when the QVL
    # is pinned AND at least one quote PASSed. CyberGym/Voice stay at 0.
    verified_mass = mass_from_units(COMPUTE_ALLOCATION, verified_units)
    report["verified_units"] = dict(verified_units)
    report["verified_mass"] = dict(verified_mass)
    if not verified_mass:
        report["blockers"].append(
            "no pinned-QVL PASS collect; Compute stays non-contributing"
        )

    bundle, registry = funded_compute_bundle()
    anchor = _epoch_anchor(subtensor)
    paying = ComputeAdapter(
        qvl or _RejectingVerifier(),
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=None if qvl is None else qvl.digest,
        verified_mass=verified_mass or None,
    )
    state_dir = Path(options.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    journal = state_dir / INDEPENDENT_STATE_FILE.name
    result = compose_dry_run(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle, anchor.epoch_open),
        anchor=anchor,
        anchor_view=view,
        inclusion_view=view,
        adapters={COMPUTE_LANE: paying},
        journal_path=journal,
    )
    report["compose"] = {
        "status": result.status,
        "dests": list(result.dests),
        "weights": list(result.weights),
        "reason": result.reason,
        "epoch_open": anchor.epoch_open,
        "anchor_hash": anchor.anchor_hash,
    }

    if result.status != "COMPOSED":
        report["blockers"].append(f"compose status {result.status} is not a canary")
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 2

    kwargs = prepare_mechanism_weights(result=result, journal_path=journal)
    wallet_json = os.environ.get("CATHEDRAL_CANARY_HOTKEY_JSON", "")
    if not wallet_json:
        report["blockers"].append(
            "CATHEDRAL_CANARY_HOTKEY_JSON is not set; composed but not submitted"
        )
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 2
    if Path(wallet_json).is_file():
        wallet_json = Path(wallet_json).read_text(encoding="utf-8")
    try:
        keypair = load_keypair(wallet_json)
        transport = SubstrateCanaryTransport(subtensor, keypair)
        receipt = submit_canary_once(
            result=result,
            kwargs=kwargs,
            bundle=bundle,
            hotkey=str(keypair.ss58_address),
            transport=transport,
            state_path=state_dir / INDEPENDENT_CANARY_FILE.name,
        )
    except (
        ChainClientError,
        IndependentLiveError,
        CanaryIneligible,
        CanarySpent,
        CanaryStateError,
        CanaryTransportError,
        RefuseListError,
        OSError,
    ) as exc:
        report["blockers"].append(f"canary: {type(exc).__name__}: {exc}")
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 2
    report["canary"] = {
        "hotkey": receipt.hotkey,
        "receipt": receipt.receipt,
        "kwargs": dict(receipt.kwargs),
        "state_path": str(receipt.state_path),
    }
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0


class _RejectingVerifier:
    def verify(self, quote: bytes, *, expected_report_data: bytes) -> QuoteVerdict:
        del quote, expected_report_data
        return QuoteVerdict.FAIL


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cathedral-independent-live")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("profiles", help="public GET /v1/profiles")
    sub.add_parser("list-workers", help="GET /v1/workers for this API key")

    rent = sub.add_parser("rent", help="create a sealed Intel TDX Worker")
    rent.add_argument("--name", default="independent-canary-miner")
    rent.add_argument("--max-runtime-minutes", type=int, default=120)
    rent.add_argument("--max-spend-usd", type=float, default=2.0)
    rent.add_argument(
        "--wait",
        type=int,
        default=600,
        help="seconds to wait until the Worker is ready (0 skips wait)",
    )

    sub.add_parser("probe-sn39", help="snapshot SN39 metagraph and serving axons")

    run = sub.add_parser("run", help="list/rent, collect, compose, canary submit")
    run.add_argument("--name", default="independent-canary-miner")
    run.add_argument(
        "--rent", action="store_true", help="create a TDX Worker if none listed"
    )
    run.add_argument("--qvl", default=None, help="path to the TDX QVL executable")
    run.add_argument(
        "--wait",
        type=int,
        default=600,
        help="seconds to wait until listed Workers are ready (0 skips wait)",
    )
    run.add_argument(
        "--state-dir",
        default="/tmp/cathedral-independent",
        help="directory for independent-state.json and independent-canary.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    options = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if options.command == "profiles":
            return cmd_profiles(options)
        if options.command == "list-workers":
            return cmd_list_workers(options)
        if options.command == "rent":
            return cmd_rent(options)
        if options.command == "probe-sn39":
            return cmd_probe_sn39(options)
        if options.command == "run":
            return cmd_run(options)
    except IndependentLiveError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    never: str = options.command
    raise IndependentLiveError(f"unhandled command {never}")


if __name__ == "__main__":
    raise SystemExit(main())
