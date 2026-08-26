"""CLI: list Cathedral compute, collect evidence, compose, canary-submit.

Subcommands:

* ``profiles`` -- public ``GET /v1/profiles`` (no API key)
* ``list-workers`` -- ``GET /v1/workers``
* ``rent`` -- ``POST`` a sealed Intel TDX Worker (``bounded_service``)
* ``probe-sn39`` -- snapshot the live metagraph and serving axons
* ``run`` -- list or rent a TDX Worker, collect from SN39 axons, re-derive
  audit work units over ``POST /v1/sat-work`` for every quote a pinned QVL
  passed, compose, and submit ``set_mechanism_weights`` through the one-write
  canary if a dedicated canary wallet and a pinned QVL are present

Never uses the live relay wallet. Never touches the thin journal.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import bittensor as bt

from cathedral_thin.independent.canary import submit_canary_once
from cathedral_thin.independent.collect import (
    CollectedEvidence,
    collect_evidence,
    mint_nonce,
)
from cathedral_thin.independent.compose import EpochAnchor, compose_dry_run
from cathedral_thin.independent.compute import (
    COMPUTE_LANE,
    ComputeAdapter,
    QuoteVerdict,
    assert_machine_identity,
)
from cathedral_thin.independent.constants import (
    CANARY_HOTKEY,
    INDEPENDENT_CANARY_FILE,
    INDEPENDENT_STATE_FILE,
    NETUID,
    REFUSE_HOTKEYS,
)
from cathedral_thin.independent.errors import (
    BroadcastBlocked,
    CanaryIneligible,
    CanarySpent,
    CanaryStateError,
    CanaryTransportError,
    HamiltonError,
    IndependentValidatorError,
    MachineIdentityConflict,
    RefuseListError,
    SatWorkError,
)
from cathedral_thin.independent.inclusion import MetagraphView
from cathedral_thin.independent.sat import (
    SAT_WORK_UNIT_RULE,
    canonical_work_item,
    collect_sat_work,
)
from cathedral_thin.independent.submit import prepare_mechanism_weights

from .chain import (
    ServingAxon,
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
from .tempo import closed_epoch_anchor, closed_epoch_open
from .workers import WorkersClient, fetch_public_json, tdx_create_enabled, tdx_workers

DEFAULT_STATE_DIR = str(INDEPENDENT_STATE_FILE.parent)
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
    catalog = fetch_public_json("/v1/profiles")
    if not tdx_create_enabled(catalog):
        raise WorkersApiError("live catalog does not enable custom.v1 Intel TDX create")
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
    epoch_open = closed_epoch_open(block)
    return closed_epoch_anchor(block, subtensor.get_block_hash(epoch_open - 1))


@dataclass(frozen=True)
class EpochSnapshot:
    """The frozen anchor and the metagraph view taken against it."""

    anchor: EpochAnchor
    anchor_view: MetagraphView
    axons: tuple[ServingAxon, ...]
    at_anchor: bool
    note: str

    def as_report(self) -> dict[str, Any]:
        return {
            "epoch_open": self.anchor.epoch_open,
            "anchor_number": self.anchor.anchor_number,
            "anchor_hash": self.anchor.anchor_hash,
            "at_anchor": self.at_anchor,
            "note": self.note,
        }


def snapshot_epoch(subtensor: Any) -> EpochSnapshot:
    """Freeze the closed-tempo anchor FIRST, then snapshot the metagraph.

    The order is the whole point. A view read before the anchor block is chosen
    belongs to whatever tempo the head happened to be in when it was read, and
    the composer would then check destinations against a view that predates the
    epoch it is paying for.

    Finney's public endpoints prune historical state, so a node that cannot
    answer at ``anchor_number`` answers at the head instead. That is a weaker
    view, not a silent one: ``at_anchor`` is false and ``note`` says why, and
    the inclusion re-check still runs against a second, later snapshot.
    """
    anchor = _epoch_anchor(subtensor)
    at_anchor = True
    note = ""
    try:
        metagraph = subtensor.metagraph(NETUID, block=anchor.anchor_number)
    except Exception as exc:
        at_anchor = False
        note = (
            f"the node could not serve the metagraph at anchor block "
            f"{anchor.anchor_number} ({type(exc).__name__}: {exc}); the view was "
            "taken at the head immediately after the anchor was frozen"
        )
        metagraph = subtensor.metagraph(NETUID)
    return EpochSnapshot(
        anchor=anchor,
        anchor_view=metagraph_view(metagraph),
        axons=serving_axons(metagraph),
        at_anchor=at_anchor,
        note=note,
    )


def _try_collect(
    url: str, hotkey: str, validator_ss58: str, sat_work_url: str
) -> dict[str, Any]:
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
        if transport.last_spki != binding.digest:
            raise IndependentLiveError(
                "TLS SPKI changed between the binding handshake and the evidence POST"
            )
    except Exception as exc:
        return {
            "url": url,
            "sat_url": sat_work_url,
            "hotkey": hotkey,
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "url": url,
        # Carried from the axon, so the PASS branch can ask this machine for
        # work without rewriting a reviewed evidence URL into another resource.
        "sat_url": sat_work_url,
        "ok": True,
        "hotkey": collected.assigned_hotkey,
        "quote_bytes": len(collected.quote),
        "kind": collected.kind,
        "collected": collected,
    }


def _units_after_quote(
    *, anchor_hash: str, collected: CollectedEvidence, sat_url: str
) -> int:
    """Re-derive integer audit units from a machine whose quote just passed.

    The machine identity is the observed TLS SPKI digest, which v2 REPORT_DATA
    already bound and the verifier already checked, so the seed is tied to the
    connection the quote arrived over. It is used as-is rather than re-hashed:
    it is already a sha256 digest. Until quote-bound key extraction exists, that
    observed channel identity IS the machine identity for the audit seed.

    A SPKI change between the evidence POST and this one is a refusal, not a
    retry: the two exchanges have to have reached the same machine.
    """
    item = canonical_work_item(
        anchor_hash=anchor_hash,
        miner_ss58=collected.assigned_hotkey,
        machine_id=collected.channel_binding.digest.hex(),
    )
    transport = HttpsEvidenceTransport()
    units = collect_sat_work(
        url=sat_url,
        assigned_hotkey=collected.assigned_hotkey,
        item=item,
        transport=transport,
    )
    if (
        transport.last_spki is not None
        and transport.last_spki != collected.channel_binding.digest
    ):
        raise SatWorkError(
            "the TLS SPKI on the work POST is not the attested channel binding"
        )
    return units


def _forfeit_machine_conflict(
    *,
    rows: list[dict[str, Any]],
    verified_units: dict[str, int],
    hotkeys: set[str],
    reason: str,
) -> None:
    """Zero every hotkey that claimed one machine identity this epoch.

    Neither claimant is picked over the other, and units already credited to
    the first one are forfeited rather than kept: an operator who registers a
    second UID against one audited machine has to lose the round for both, or
    the duplicate is cheaper than the machine.
    """
    for hotkey in hotkeys:
        verified_units.pop(hotkey, None)
    for row in rows:
        if row.get("hotkey") in hotkeys:
            row.pop("sat_units", None)
            row.pop("sat_rule", None)
            row["sat_error"] = reason


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


def prepare_state_dir(path: Path | str) -> Path:
    """Create a 0o700 journal directory. Symlinks are refused.

    The default is ``/var/lib/cathedral-validator``, the same parent as the
    independent journal pin. ``/tmp`` is not the default: a world-writable
    parent lets another user own the one-write canary lock.
    """
    raw = Path(path)
    if raw.is_symlink():
        raise IndependentLiveError(f"state dir {raw} is a symlink")
    parent = raw.parent
    if parent.exists() and parent.is_symlink():
        raise IndependentLiveError(f"state dir parent {parent} is a symlink")
    try:
        raw.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(raw, 0o700)
    except OSError as exc:
        raise IndependentLiveError(f"state dir {raw} is unusable: {exc}") from exc
    if raw.is_symlink() or not raw.is_dir():
        raise IndependentLiveError(f"state dir {raw} is not a usable directory")
    return raw


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
        "tdx_create_enabled": False,
        "qvl_pass_count": 0,
    }
    catalog: Any = None
    try:
        catalog = fetch_public_json("/v1/profiles")
        report["catalog"] = _summarize_catalog(catalog)
        report["tdx_create_enabled"] = tdx_create_enabled(catalog)
    except WorkersApiError as exc:
        report["blockers"].append(f"catalog: {exc}")

    listed = []
    try:
        client = _workers()
        existing = client.list_workers()
        listed = list(tdx_workers(existing))
        if options.rent and not listed:
            if not tdx_create_enabled(catalog or {}):
                report["blockers"].append(
                    "catalog: custom.v1 Intel TDX create is not enabled; not renting"
                )
            else:
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
        # The closed-tempo anchor is chosen before any metagraph is read, so
        # the anchor view belongs to the epoch this vector pays for.
        snapshot = snapshot_epoch(subtensor)
        anchor = snapshot.anchor
        anchor_view = snapshot.anchor_view
        axons = snapshot.axons
        report["anchor"] = snapshot.as_report()
        report["sn39"] = {
            "uids": len(anchor_view.uid_to_hotkey),
            "serving_axons": [
                {
                    "uid": axon.uid,
                    "hotkey": axon.hotkey,
                    "ip": axon.ip,
                    "port": axon.port,
                    "evidence_url": axon.evidence_url(),
                    "sat_work_url": axon.sat_work_url(),
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
            _try_collect(
                axon.evidence_url(),
                axon.hotkey,
                validator_ss58,
                axon.sat_work_url(),
            )
        )

    verified_units: dict[str, int] = {}
    # Which hotkey owns which audited machine for this epoch. Two registered
    # UIDs advertising one machine is one machine's worth of work, not two.
    claimed: dict[str, str] = {}
    pass_count = 0
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
                if collected.assigned_hotkey == CANARY_HOTKEY:
                    report["blockers"].append(
                        "qvl: PASS quote is the canary identity; not mass"
                    )
                    continue
                # Attestation is admission, not payment. The PASS admits this
                # machine to the audit and is recorded so operators can see
                # liveness; the only thing that binds mass is the integer unit
                # count re-derived from the challenge below.
                pass_count += 1
                sat_url = row.get("sat_url")
                if not isinstance(sat_url, str) or not sat_url:
                    row["sat_error"] = "the axon carried no work URL"
                    continue
                try:
                    units = _units_after_quote(
                        anchor_hash=anchor.anchor_hash,
                        collected=collected,
                        sat_url=sat_url,
                    )
                except Exception as exc:
                    # Admitted, unpaid. A machine that attests but will not
                    # produce a checkable witness earns nothing this epoch.
                    # Exception, not BaseException: one flaky axon must not
                    # cost every other miner its round, while KeyboardInterrupt
                    # and SystemExit still stop the process.
                    row["sat_error"] = f"{type(exc).__name__}: {exc}"
                    continue
                # The machine identity is the observed TLS SPKI digest, already
                # 64 lowercase hex, so it is the ledger key as-is.
                machine_id = collected.channel_binding.digest.hex()
                try:
                    assert_machine_identity(
                        machine_id, collected.assigned_hotkey, claimed
                    )
                except MachineIdentityConflict as exc:
                    _forfeit_machine_conflict(
                        rows=collect_hits,
                        verified_units=verified_units,
                        hotkeys={claimed[machine_id], collected.assigned_hotkey},
                        reason=f"{type(exc).__name__}: {exc}",
                    )
                    report["blockers"].append(f"machine-identity: {exc}")
                    continue
                row["sat_units"] = units
                row["sat_rule"] = SAT_WORK_UNIT_RULE
                verified_units[collected.assigned_hotkey] = units
            elif verdict is QuoteVerdict.FAIL:
                continue
            elif verdict is QuoteVerdict.INFRA:
                report["blockers"].append("qvl: infrastructure failure on a quote")
            else:
                never: QuoteVerdict = verdict
                raise IndependentLiveError(f"unhandled quote verdict {never}")

    report["collect"] = [
        {key: value for key, value in row.items() if key != "collected"}
        for row in collect_hits
    ]
    report["qvl_pass_count"] = pass_count
    # Product truth: attestation is not payment. The only entries here are
    # integer units re-derived from POST /v1/sat-work under
    # sat_work_units_v1 -- never a pass count, never quote bytes, never a
    # miner's own claim. CyberGym/Voice stay at 0.
    report["sat_work_rule"] = SAT_WORK_UNIT_RULE
    verified_mass = mass_from_units(COMPUTE_ALLOCATION, verified_units)
    report["verified_units"] = dict(verified_units)
    report["verified_mass"] = dict(verified_mass)
    if not verified_mass:
        report["blockers"].append(
            "no independently re-derived work units; Compute stays non-contributing"
        )

    try:
        inclusion_metagraph = subtensor.metagraph(NETUID)
        inclusion_view = metagraph_view(inclusion_metagraph)
    except Exception as exc:
        report["blockers"].append(f"inclusion snapshot: {type(exc).__name__}: {exc}")
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 2

    bundle, registry = funded_compute_bundle()
    paying = ComputeAdapter(
        qvl or _RejectingVerifier(),
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=None if qvl is None else qvl.digest,
        verified_mass=verified_mass or None,
    )
    try:
        state_dir = prepare_state_dir(options.state_dir)
    except IndependentLiveError as exc:
        report["blockers"].append(f"state-dir: {exc}")
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 2
    journal = state_dir / INDEPENDENT_STATE_FILE.name
    result = compose_dry_run(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle, anchor.epoch_open),
        anchor=anchor,
        anchor_view=anchor_view,
        inclusion_view=inclusion_view,
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

    # Every refusal that stops this epoch from submitting runs BEFORE the
    # submission is built. prepare_mechanism_weights journals a `submission`
    # block, and an epoch nobody confirmed must not leave one on disk for a
    # future runtime to read and send.
    if not getattr(options, "confirm_canary", False):
        report["blockers"].append(
            "--confirm-canary is required to spend the one-write canary; "
            "wallet JSON alone is not a write"
        )
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 2
    wallet_json = os.environ.get("CATHEDRAL_CANARY_HOTKEY_JSON", "")
    if not wallet_json:
        report["blockers"].append(
            "CATHEDRAL_CANARY_HOTKEY_JSON is not set; composed but not submitted"
        )
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 2
    if Path(wallet_json).is_file():
        wallet_json = Path(wallet_json).read_text(encoding="utf-8")
    canary_lock = state_dir / INDEPENDENT_CANARY_FILE.name
    try:
        keypair = load_keypair(wallet_json)
        transport = SubstrateCanaryTransport(subtensor, keypair, state_path=canary_lock)
        kwargs = prepare_mechanism_weights(result=result, journal_path=journal)
        receipt = submit_canary_once(
            result=result,
            kwargs=kwargs,
            bundle=bundle,
            hotkey=str(keypair.ss58_address),
            transport=transport,
            state_path=canary_lock,
        )
    except (
        BroadcastBlocked,
        ChainClientError,
        HamiltonError,
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
        default=DEFAULT_STATE_DIR,
        help=(
            "directory for independent-state.json and independent-canary.json "
            f"(default {DEFAULT_STATE_DIR})"
        ),
    )
    run.add_argument(
        "--confirm-canary",
        action="store_true",
        help=(
            "required to spend the one-write canary; a wallet in the "
            "environment is not enough by itself"
        ),
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
    except IndependentValidatorError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    never: str = options.command
    raise IndependentLiveError(f"unhandled command {never}")


if __name__ == "__main__":
    raise SystemExit(main())
