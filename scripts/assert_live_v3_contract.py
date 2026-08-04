#!/usr/bin/env python3
"""Pre-cutover gate for the v3 (70% TDX / 30% CyberGym / 0% burn) re-pin.

Run this BEFORE re-pinning a validator from ``validated_supply_v1`` to
``validated_supply_v3``. Exit 0 means the LIVE publisher is emitting a vector that
a v3-pinned validator will accept; non-zero means re-pinning now would fail closed
to the burn UID from the first tick.

Why it exists. Rolling to v3 is a coordinated re-pin across every SN39 validator
(``validator_thin`` refuses v3 while pinned to v1, by design). If one operator
re-pins before the publisher is emitting v3 -- or the publisher flips to v3 before
the operators re-pin -- that validator rejects every vector and sinks its whole
weight to burn until the mismatch is fixed. This gate lets each operator confirm
the feed is ready for their re-pin, and lets the publisher confirm the feed is
emitting exactly what a v3 validator accepts, using the SAME function the
validator runs (``vector_to_uid_weights``) rather than a second copy of the
contract that could drift.

It deliberately calls the validator's OWN ``vector_to_uid_weights`` with
``require_policy=validated_supply_v3``: a pass here IS the computation a
v3-pinned validator performs on its first tick.

Usage:
    python scripts/assert_live_v3_contract.py --network finney --netuid 39
    python scripts/assert_live_v3_contract.py --publisher https://api.cathedral.computer
    python scripts/assert_live_v3_contract.py --json
    python scripts/assert_live_v3_contract.py --offline vector.json   # a captured feed
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scaffold import validator_thin  # noqa: E402
from scaffold import wire_vector as wire  # noqa: E402

DEFAULT_PUBLISHER = "https://api.cathedral.computer"
WEIGHTS_PATH = "/v1/validator/weights/next"
MAX_BYTES = 4 * 1024 * 1024
TIMEOUT_SECS = 30
V3_PIN = validator_thin.REQUIRE_POLICY_VALIDATED_SUPPLY_V3


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is a different host answering; the validator refuses any
    non-200, so the gate must not silently follow one either."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise SystemExit(f"FAIL  {req.full_url} redirected ({code}); refusing to follow")


def fetch_vector(publisher: str) -> dict:
    url = publisher.rstrip("/") + WEIGHTS_PATH
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cathedral-v3-precutover/1", "Accept": "application/json"},
    )
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=TIMEOUT_SECS) as response:
        if response.status != 200:
            raise SystemExit(f"FAIL  {url} returned HTTP {response.status}")
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise SystemExit(f"FAIL  {url} returned more than {MAX_BYTES} bytes")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise SystemExit(f"FAIL  {url} did not return JSON: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--publisher", default=DEFAULT_PUBLISHER)
    parser.add_argument("--network", default="finney")
    parser.add_argument("--netuid", type=int, default=39)
    parser.add_argument("--offline", help="read the vector from a JSON file instead of the network")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    # The vector.
    if args.offline:
        try:
            payload = json.loads(Path(args.offline).read_text())
        except (OSError, ValueError) as exc:
            print(f"FAIL  could not read {args.offline}: {exc}", file=sys.stderr)
            return 2
    else:
        try:
            payload = fetch_vector(args.publisher)
        except (urllib.error.URLError, OSError) as exc:
            print(f"FAIL  could not reach {args.publisher}{WEIGHTS_PATH}: {exc}", file=sys.stderr)
            return 2

    # A v3-pinned validator's first tick runs accept_vector BEFORE mapping:
    # pinned-key signature, then freshness/network/netuid invariants. Without
    # these, a well-formed v3 payload with a bad or stale signature would PASS
    # the gate and still be refused by every validator — the exact sink-to-burn
    # outcome this gate exists to prevent. (The per-host rollback fence is the
    # one accept_vector check that cannot run here.) Runs before any chain
    # access: a vector no validator accepts needs no metagraph.
    signature_checked = "_hotkey_to_uid" not in payload
    if signature_checked:
        try:
            wire.verify_signature(
                payload,
                public_key_hex=validator_thin.DEFAULT_PUBLIC_KEY_HEX,
                expected_key_id=validator_thin.SN39_WEIGHT_POLICY_KEY_ID,
            )
            wire.invariant_check(
                payload,
                network=args.network,
                netuid=args.netuid,
                now_iso=validator_thin._ms_iso_now(),
            )
        except wire.VectorError as exc:
            detail = {"ok": False, "stage": "accept", "error": str(exc)}
            print(json.dumps(detail) if args.as_json else f"FAIL  {exc}", file=sys.stderr)
            print(
                "\nDO NOT RE-PIN TO v3. The feed failed signature/freshness "
                "acceptance — every validator refuses this vector regardless of "
                "its contract version.",
                file=sys.stderr,
            )
            return 1

    # The metagraph the mapping resolves burn/TDX/CyberGym UIDs against. A v3
    # vector's burn UID and lane UIDs are meaningless without THIS tick's map, so
    # the gate resolves it the same way a running validator does. Offline runs may
    # embed a `_hotkey_to_uid` for a hermetic check — that run validates the file
    # against itself (mapping AND signature unchecked) and must never be the
    # basis of a re-pin decision.
    hotkey_to_uid = payload.get("_hotkey_to_uid")
    if hotkey_to_uid is None:
        try:
            hotkey_to_uid = validator_thin.metagraph_hotkey_to_uid(
                network=args.network, netuid=args.netuid
            )
        except Exception as exc:  # noqa: BLE001 - a chain failure is a gate failure
            print(f"FAIL  could not resolve the metagraph for netuid {args.netuid}: {exc}",
                  file=sys.stderr)
            return 2
    else:
        hotkey_to_uid = {str(k): int(v) for k, v in hotkey_to_uid.items()}

    # The one thing that matters: does a v3-PINNED validator accept this vector?
    try:
        weights = validator_thin.vector_to_uid_weights(
            payload, hotkey_to_uid, require_policy=V3_PIN
        )
    except wire.VectorError as exc:
        detail = {"ok": False, "error": str(exc)}
        print(json.dumps(detail) if args.as_json else f"FAIL  {exc}", file=sys.stderr)
        print(
            "\nDO NOT RE-PIN TO v3. A validator pinned to validated_supply_v3 refuses "
            "this vector, so every tick would sink to the burn UID from the first one. "
            "The feed is not emitting a v3 contract yet (it is likely still v2). Re-pin "
            "only once this gate passes, in one coordinated window with the publisher "
            "flip.",
            file=sys.stderr,
        )
        return 1

    total = sum(weights.values())
    snap = payload.get("burn_snapshot") or {}
    burn_uid = snap.get("burn_uid")
    try:
        burn_share = weights.get(int(burn_uid), 0.0) if burn_uid is not None else None
    except (TypeError, ValueError):
        print(f"FAIL  burn_snapshot.burn_uid is not an integer: {burn_uid!r}",
              file=sys.stderr)
        return 1
    result = {
        "ok": True,
        "publisher": args.publisher if not args.offline else args.offline,
        "accepted_by": V3_PIN,
        # False only for hermetic fixtures carrying an embedded _hotkey_to_uid;
        # such a run validates the file against itself and MUST NOT be used as
        # a re-pin decision.
        "signature_checked": signature_checked,
        "uids_weighted": len(weights),
        "weight_sum": round(total, 12),
        "burn_uid": burn_uid,
        "burn_share": None if burn_share is None else round(burn_share, 12),
    }
    if args.as_json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("PASS  a validator pinned to validated_supply_v3 accepts the live feed")
        for key in (
            "accepted_by",
            "signature_checked",
            "uids_weighted",
            "weight_sum",
            "burn_uid",
            "burn_share",
        ):
            print(f"  {key:16} {result[key]}")
        if not signature_checked:
            print(
                "\n  WARNING: hermetic fixture (embedded _hotkey_to_uid) — the "
                "signature and metagraph were NOT independently verified. Never "
                "re-pin on this output."
            )
        print("\nComputed with the validator's own vector_to_uid_weights, so a pass "
              "here is the mapping the v3-pinned validator will perform. A high "
              "burn_share is not a gate failure -- it is forfeited TDX/CyberGym lane "
              "mass sinking to burn (an operational signal), not a rejected vector.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
