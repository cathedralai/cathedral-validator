"""`cathedral-validator-integration-preview` — a NON-WRITING operator preview.

Runs the default-OFF Compute+Distill integration lane over inputs from one JSON
bundle and prints the composed feed + audit trail. It verifies the signed burn +
allocation config and every lane receipt, composes one deterministic vector (a
missing/invalid lane's share goes to burn), and emits the audit — but it never
opens a chain client and never calls set_weights. It is a preview, exactly as
`cathedral_thin.integration` documents; activation is a separate owner decision.

    cathedral-validator-integration-preview --bundle preview.json

Bundle shape:

    {
      "network": "finney", "netuid": 39, "source_epoch": 11,
      "now": "2026-07-25T12:30:00Z",              # config verification time (UTC)
      "now_iso": "2026-07-25T12:30:00.000000Z",   # receipt freshness time
      "burn_config": { ...signed cathedral_burn_config_v1... },
      "allocation_config": { ...signed cathedral_lane_allocation_v1... },
      "keys": { "cathedral-config-1": "<base64 pubkey>", ... },   # hardware-free registry
      # OR, for the anchored path:
      # "registry": { ...signed key registry... },
      # "trusted_roots": { "cathedral-root-1": "<base64 root pubkey>" },

      # Admission policy. REQUIRED for any lane with a nonzero allocation. An
      # empty list is a policy, not an omission, and what it admits is per list:
      # empty measurements or TCB statuses admit nothing, while an empty advisory
      # list admits only receipts that carry no advisory (it is a subset test).
      "allowed_measurements": ["tdx-measurement-sha256:..."],
      "allowed_tcb_statuses": ["UpToDate"],
      "allowed_advisories": [],
      "current_block": 6000100,           # finalized height for the block window
      "ledger_path": "/var/lib/cathedral/consumption.sqlite",   # replay ledger

      "receipts": [ {"kind": "compute_cpu", "lane": "cathedral_confidential_tdx",
                     "receipt": { ... }},
                    # "lane" may be omitted: each kind has a canonical lane id
                    # (compute_cpu, compute_gpu, distill, cybergym).
                    {"kind": "cybergym", "receipt": { ... }} ]
    }

Fail-closed by default: a funded lane whose measurement/TCB/advisory policy, block
window, or consumption ledger is missing is REFUSED. `--allow-unpoliced-preview` is
the deliberate opt-out for a shadow run, and it says so on stderr and in the output.

Repeatable by default: the replay ledger is READ, never written, so running the same
bundle again returns the same vector. `--consume-receipts` is the authoritative pass
that records each credited receipt so it can never be credited again; run it at most
once per epoch, and use the plain form for inspection.

A GPU lane with no attestation verifier is reported NOT_PROVEN. A CLI cannot carry
a live verifier callable, so a real GPU proof runs through the library API, not here.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cathedral_thin.integration import (
    DEFAULT_LANE_FOR_KIND,
    IntegrationError,
    IntegrationUnavailable,
    LaneReceipt,
    preview_integrated_vector,
)


class PreviewError(RuntimeError):
    """The preview bundle could not be run. Fails closed."""


def _parse_now(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise PreviewError("bundle 'now' must be a UTC timestamp string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise PreviewError(f"bundle 'now' is not a valid timestamp: {value!r}") from exc
    return (
        parsed.astimezone(UTC)
        if parsed.tzinfo is not None
        else parsed.replace(tzinfo=UTC)
    )


def _build_registry(bundle: dict, now: datetime):
    # Deferred import so `--help` and a missing extra give a clean message.
    from cathedral_distill.receipt_keys import ReceiptKeyRegistry, verify_key_registry

    if "keys" in bundle:
        keys = bundle["keys"]
        if not isinstance(keys, dict):
            raise PreviewError(
                "bundle 'keys' must be an object of key_id -> base64 pubkey"
            )
        try:
            return ReceiptKeyRegistry.from_keys(
                {str(k): base64.b64decode(v, validate=True) for k, v in keys.items()}
            )
        except Exception as exc:
            raise PreviewError(f"invalid 'keys': {exc}") from exc
    if "registry" in bundle and "trusted_roots" in bundle:
        try:
            roots = {
                str(k): base64.b64decode(v, validate=True)
                for k, v in bundle["trusted_roots"].items()
            }
            return verify_key_registry(
                json.dumps(bundle["registry"]).encode(),
                roots,
                now=now,
                max_age_seconds=10**12,
            )
        except Exception as exc:
            raise PreviewError(f"signed key registry did not verify: {exc}") from exc
    raise PreviewError(
        "bundle needs either 'keys' (hardware-free) or 'registry' + 'trusted_roots'"
    )


def _open_ledger(bundle: dict):
    """Build the replay ledger from `ledger_path`. Absent -> no ledger (refused
    for a funded lane unless the operator opts out explicitly)."""
    path = bundle.get("ledger_path")
    if path is None:
        return None
    if not isinstance(path, str) or not path:
        raise PreviewError("bundle 'ledger_path' must be a non-empty string")
    from cathedral_distill.consumption_ledger import ConsumptionLedger

    try:
        return ConsumptionLedger(path)
    except Exception as exc:
        raise PreviewError(
            f"consumption ledger {path!r} could not be opened: {exc}"
        ) from exc


_GATE_LABELS = (
    ("measurement", "measurement_policy"),
    ("tcb", "tcb_policy"),
    ("advisory", "advisory_policy"),
    ("block_window", "block_window"),
    ("ledger", "consumption_ledger"),
)


def _flags(row: dict) -> str:
    return " ".join(
        f"{label}={'yes' if row[key] else 'no'}" for label, key in _GATE_LABELS
    )


def _gate_status(gates: dict) -> str:
    """Per lane and per receipt kind: which gates actually ran.

    A supplied argument is not an applied gate. `current_block` gates nothing for
    a compute or distill receipt, and the measurement/TCB/advisory policy gates
    nothing for a cybergym receipt, so the per-kind lines are what an activation
    decision should read; `supplied` is the configuration that produced them.
    """
    lines = [
        f"replay mode: {gates['replay_mode']}"
        + (
            " (tokens recorded; run this at most once per epoch)"
            if gates["replay_mode"] == "authoritative"
            else " (nothing is consumed; safe to re-run)"
        ),
        "configured: " + _flags(gates["supplied"]),
        "gates applied (measurement/tcb/advisory policy, block window, ledger):",
    ]
    for lane, row in gates["lanes"].items():
        role = "reward" if row["reward_lane"] else "unfunded"
        lines.append(f"  {lane} [{role} allocation={row['allocation']}] {_flags(row)}")
        for kind, applied in row["kinds"].items():
            lines.append(f"    {kind}: {_flags(applied)}")
        if not row["kinds"]:
            lines.append("    no receipts in this lane; its share burns")
    if gates["omitted_gates"]:
        lines.append(
            "  UNPOLICED: " + ", ".join(gates["omitted_gates"]) + " not applied; "
            "this preview is not evidence that a receipt would be admitted under a "
            "real launch policy"
        )
    return "\n".join(lines)


def run_bundle(
    bundle: dict,
    *,
    allow_unpoliced_preview: bool = False,
    consume_receipts: bool = False,
) -> dict[str, Any]:
    for field in (
        "network",
        "netuid",
        "source_epoch",
        "now",
        "now_iso",
        "burn_config",
        "allocation_config",
        "receipts",
    ):
        if field not in bundle:
            raise PreviewError(f"bundle is missing {field!r}")
    now = _parse_now(bundle["now"])
    registry = _build_registry(bundle, now)
    receipts = []
    for item in bundle["receipts"]:
        if not isinstance(item, dict) or {"kind", "receipt"} - set(item):
            raise PreviewError("each receipt entry needs kind and receipt")
        unknown = set(item) - {"kind", "lane", "receipt"}
        if unknown:
            raise PreviewError(
                "receipt entry has unknown keys: " + ", ".join(sorted(unknown))
            )
        kind = str(item["kind"])
        if kind not in DEFAULT_LANE_FOR_KIND:
            raise PreviewError(
                f"unknown receipt kind {kind!r}; expected one of "
                + ", ".join(sorted(DEFAULT_LANE_FOR_KIND))
            )
        # Each kind has a canonical lane id, so a bundle can name the lane
        # explicitly or rely on the documented default (this is what makes the
        # cybergym lane addressable from a bundle at all).
        lane = str(item["lane"]) if item.get("lane") else DEFAULT_LANE_FOR_KIND[kind]
        receipts.append(LaneReceipt(kind, lane, item["receipt"]))

    # Admission policy from the bundle. A key that is absent means the operator
    # expressed no policy; an empty list is a policy (deny-all for measurements
    # and TCB statuses, advisory-free-only for advisories). Those are different
    # states, and only the first is refused for a funded lane, because otherwise
    # an enclave measurement nobody ever approved is credited PASS (the exact
    # failure attestation.py exists to prevent).
    def _set(key):
        value = bundle.get(key)
        if value is None:
            return None
        if not isinstance(value, list):
            raise PreviewError(f"bundle {key!r} must be a list of strings")
        return frozenset(str(v) for v in value)

    allowed_measurements = _set("allowed_measurements")
    allowed_tcb_statuses = _set("allowed_tcb_statuses")
    allowed_advisories = _set("allowed_advisories")
    current_block = bundle.get("current_block")
    current_block = int(current_block) if current_block is not None else None
    ledger = _open_ledger(bundle)

    try:
        return preview_integrated_vector(
            burn_config=json.dumps(bundle["burn_config"]).encode(),
            allocation_config=json.dumps(bundle["allocation_config"]).encode(),
            key_registry=registry,
            receipts=receipts,
            network=str(bundle["network"]),
            netuid=int(bundle["netuid"]),
            source_epoch=int(bundle["source_epoch"]),
            now=now,
            now_iso=str(bundle["now_iso"]),
            min_burn_version=int(bundle.get("min_burn_version", 0)),
            min_allocation_version=int(bundle.get("min_allocation_version", 0)),
            expected_burn_hotkey=bundle.get("expected_burn_hotkey"),
            current_block=current_block,
            consumption_ledger=ledger,
            allowed_measurements=allowed_measurements,
            allowed_tcb_statuses=allowed_tcb_statuses,
            allowed_advisories=allowed_advisories,
            # passed through uncoerced on purpose: bool("false") is True, so
            # coercing here would turn a config mistake into an authorization
            allow_unpoliced_preview=allow_unpoliced_preview,
            consume_receipts=consume_receipts,
        )
    except IntegrationUnavailable as exc:
        raise PreviewError(str(exc)) from exc
    except IntegrationError as exc:
        raise PreviewError(f"preview rejected: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cathedral-validator-integration-preview",
        description="Non-writing Compute+Distill integration preview (no chain writes).",
    )
    parser.add_argument("--bundle", required=True, help="preview bundle JSON file")
    parser.add_argument(
        "--out", help="write the {feed, audit, gates} JSON here (default: stdout)"
    )
    parser.add_argument(
        "--allow-unpoliced-preview",
        action="store_true",
        help=(
            "deliberately preview a funded lane WITHOUT the measurement/TCB/advisory "
            "policy, block window, or replay ledger. Shadow runs only: the result is "
            "not evidence that a receipt would be admitted under a launch policy."
        ),
    )
    parser.add_argument(
        "--consume-receipts",
        action="store_true",
        help=(
            "the AUTHORITATIVE pass: record each credited receipt in the replay "
            "ledger so it can never be credited again. Without this flag the "
            "preview only reads the ledger, so it can be re-run and returns the "
            "same vector every time. Run the authoritative pass at most once per "
            "epoch."
        ),
    )
    args = parser.parse_args(argv)

    try:
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
        if not isinstance(bundle, dict):
            raise PreviewError("bundle must be a JSON object")
        result = run_bundle(
            bundle,
            allow_unpoliced_preview=args.allow_unpoliced_preview,
            consume_receipts=args.consume_receipts,
        )
    except (PreviewError, OSError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    sys.stderr.write(_gate_status(result["gates"]) + "\n")
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out and args.out != "-":
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    sys.stderr.write("preview only, no chain write\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
