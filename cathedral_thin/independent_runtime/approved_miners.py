"""Owner-approved miner hotkeys for the SN94 compute lane.

Only a hotkey on this list earns compute weight. The list ships inside the
signed validator release, the same way the escape contest signer set does: the
document below is the reviewed copy, ``config/compute/approved-miners.json``
holds the same bytes, and the sha256 pins them, so an edit to one without the
others fails at import. Nothing on the validator host can change it. A miner is
added by owner approval through a reviewed change to these three places and a
new signed release (docs/GATED_COMPUTE.md).
"""

from __future__ import annotations

import hashlib
import json

from cathedral_thin.independent.constants import NETUID

from .errors import IndependentLiveError

APPROVED_MINERS_SCHEMA = "cathedral_approved_compute_miners_v1"
MAX_APPROVED_MINERS = 256
_SS58_CHARS = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

# Canonical compact JSON of this document plus one newline is the content of
# config/compute/approved-miners.json. Entries are sorted by hotkey and unique.
# A listed hotkey that is not registered, or has no verified machine, simply
# receives nothing, so the owner can register these later without a release.
# Seeded 12 Nov 2026 with the owner's three compute-miner hotkeys, read from
# the public address files of the owner's wallet. None was registered on
# netuid 94 at Finney block 9489224; the chain named the owner's coldkey as
# the owner of each.
_BUILD_NOTE = (
    "owner's own miner hotkey; not registered on netuid 94 at build time "
    "(Finney block 9489224)"
)
PINNED_APPROVED_MINERS_DOCUMENT: dict[str, object] = {
    "miners": [
        {
            "hotkey": "5Ci4hDP6Fc7CDMy5uxZUnjQF2QgdK2HYpLt1MrWmV2vi9ujw",  # pragma: allowlist secret
            "label": "owner-miner-3",
            "note": _BUILD_NOTE,
        },
        {
            "hotkey": "5FTS68kHHrG7c9XYDyiCzfVnuqNJBk1uWV1D9vN4YwkQ3Ztq",  # pragma: allowlist secret
            "label": "owner-miner-2",
            "note": _BUILD_NOTE,
        },
        {
            "hotkey": "5GejPbqLvfrLGdrjLzHN59TQ5c7KuWWDVajFAz8r7pSG2TKq",  # pragma: allowlist secret
            "label": "owner-miner-1",
            "note": _BUILD_NOTE,
        },
    ],
    "netuid": NETUID,
    "schema": APPROVED_MINERS_SCHEMA,
}
PINNED_APPROVED_MINERS_SHA256 = (
    "1e2e9b7a77c7b2963ec51332fa1b5e9cda7d8232efcf48d2f22cc1fb1a0faa76"
)


class ApprovedMinersError(IndependentLiveError):
    """The approved-miner list is malformed or does not match its pin."""


def load_approved_miners(raw: bytes, *, expected_sha256: str) -> frozenset[str]:
    """Parse the list and refuse it if the bytes do not match the pin."""

    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ApprovedMinersError("approved miner list does not match its sha256 pin")
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ApprovedMinersError("approved miner list is not ASCII JSON") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"miners", "netuid", "schema"}
        or document["schema"] != APPROVED_MINERS_SCHEMA
        or isinstance(document["netuid"], bool)
        or document["netuid"] != NETUID
        or not isinstance(document["miners"], list)
        or len(document["miners"]) > MAX_APPROVED_MINERS
    ):
        raise ApprovedMinersError("approved miner list fields are invalid")
    miners = document["miners"]
    if any(
        not isinstance(miner, dict)
        or set(miner) != {"hotkey", "label", "note"}
        or any(not isinstance(value, str) or not value for value in miner.values())
        for miner in miners
    ):
        raise ApprovedMinersError("approved miner entry is malformed")
    hotkeys = [miner["hotkey"] for miner in miners]
    if any(
        not 47 <= len(hotkey) <= 48 or not set(hotkey) <= _SS58_CHARS
        for hotkey in hotkeys
    ) or hotkeys != sorted(set(hotkeys)):
        raise ApprovedMinersError("approved miner hotkeys are not sorted unique SS58")
    return frozenset(hotkeys)


def _pinned_approved_miners() -> frozenset[str]:
    raw = (
        json.dumps(
            PINNED_APPROVED_MINERS_DOCUMENT,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        + b"\n"
    )
    return load_approved_miners(raw, expected_sha256=PINNED_APPROVED_MINERS_SHA256)


APPROVED_COMPUTE_HOTKEYS = _pinned_approved_miners()

__all__ = [
    "APPROVED_COMPUTE_HOTKEYS",
    "APPROVED_MINERS_SCHEMA",
    "ApprovedMinersError",
    "PINNED_APPROVED_MINERS_DOCUMENT",
    "PINNED_APPROVED_MINERS_SHA256",
    "load_approved_miners",
]
