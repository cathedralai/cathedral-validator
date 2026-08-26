"""Pinned constants for the independent SN39 composer (`independent_v1`).

Everything the composer treats as chain or policy truth lives here, in one
module, so a review can read the whole pin set at once. Nothing in this package
reads an environment variable for any of it: an operator-tunable burn target or
netuid is the same thing as no pin at all.

The burn destination is a hotkey, never a UID. The subnet owner hotkey moved
once already, and a hardcoded UID silently pays whoever occupies the old slot.
The UID is resolved from this hotkey against the anchor metagraph and re-checked
against the inclusion metagraph.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

# Integer mass unit for the whole mix path. Lane allocations and the burn
# amount are integers summing to H; no float ever touches a weight.
H = 10**12
# u16 weight budget the chain expects a mechanism weight vector to sum to.
W = 65535

NETUID = 39
MECID = 0
VERSION_KEY = 10005000
TEMPO_BLOCKS = 360
# Transaction mortality, in blocks, measured from the SIGNED head -- not from
# the anchor. Mixing the two makes the extrinsic dead on arrival.
SN39_MORTAL_PERIOD_BLOCKS = 16

# Chain contract values that must hold at the anchor. `max_weight_limit` must
# be exactly 1.0: any smaller cap makes a legal burn-heavy vector overweight.
MIN_ALLOWED_WEIGHTS = 1
MAX_WEIGHT_LIMIT = 1.0
COMMIT_REVEAL_ENABLED = False
# Chain cap on the number of destinations in one mechanism weight vector.
MAX_DESTS = 256

# A nested measurement registry does not fit in a 64 KiB document, and this is
# still a hard bound: the body is refused past it rather than truncated.
MAX_POLICY_BUNDLE_BYTES = 1_048_576

FINNEY_GENESIS_HASH = (
    "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"
)

# Subnet owner hotkey. DESTINATION ONLY -- this key never signs anything here,
# and the refuse-list below stops a runtime from starting as it.
BURN_HOTKEY = (
    "5GP7c3fFazW9GXK8Up3qgu2DJBk8inu4aK9TZy3RuoSWVCMi"  # pragma: allowlist secret
)

# Hotkeys this runtime refuses to start as. The live relay identity and the
# owner/burn identity are both operationally load-bearing elsewhere; an
# independent composer that boots as either one can be mistaken for them.
REFUSE_HOTKEYS = frozenset(
    {
        "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw",  # pragma: allowlist secret
        BURN_HOTKEY,
    }
)

# The independent journal. It is a DIFFERENT file from the thin validator's
# durable journal on purpose: the two lineages must never read or fence each
# other's reservations, and a shared path would let one clobber the other.
INDEPENDENT_STATE_FILE = Path("/var/lib/cathedral-validator/independent-state.json")

LINEAGE = "independent_v1"

COMMITMENT_MAGIC = b"CATHPOL1"
COMMITMENT_LENGTH = len(COMMITMENT_MAGIC) + 2 + 8 + 32  # 50
# The u64 in that 50-byte commitment is the frozen `epoch_open` block number
# (start of the next tempo), the same value persisted in the journal. It is
# not `anchor_number // TEMPO_BLOCKS`; both identify the closed tempo, and
# this is the identifier the process already froze on disk.

POLICY_BUNDLE_SCHEMA = "cathedral_policy_bundle_v1"
ECONOMICS_SET_SCHEMA = "cathedral_economics_set_v1"

# Pinned economics signer key ids. 2-of-3 over the canonical bundle.
POLICY_KEY_IDS = ("economics-a", "economics-b", "economics-c")
POLICY_SIGNATURE_THRESHOLD = 2
# Bound the signature list so a hostile document cannot make verification
# expensive; three pinned key ids need nowhere near this many entries.
MAX_POLICY_SIGNATURES = 8

# Genesis EconomicsSet lineage: version 1 chained to the empty digest.
GENESIS_VERSION = 1
GENESIS_PREVIOUS_DIGEST = hashlib.sha256(b"").hexdigest()

POLICY_USER_AGENT = "cathedral-independent-validator/1.0"

__all__ = [
    "BURN_HOTKEY",
    "COMMITMENT_LENGTH",
    "COMMITMENT_MAGIC",
    "COMMIT_REVEAL_ENABLED",
    "ECONOMICS_SET_SCHEMA",
    "FINNEY_GENESIS_HASH",
    "GENESIS_PREVIOUS_DIGEST",
    "GENESIS_VERSION",
    "H",
    "INDEPENDENT_STATE_FILE",
    "LINEAGE",
    "MAX_DESTS",
    "MAX_POLICY_BUNDLE_BYTES",
    "MAX_POLICY_SIGNATURES",
    "MAX_WEIGHT_LIMIT",
    "MECID",
    "MIN_ALLOWED_WEIGHTS",
    "NETUID",
    "POLICY_BUNDLE_SCHEMA",
    "POLICY_KEY_IDS",
    "POLICY_SIGNATURE_THRESHOLD",
    "POLICY_USER_AGENT",
    "REFUSE_HOTKEYS",
    "SN39_MORTAL_PERIOD_BLOCKS",
    "TEMPO_BLOCKS",
    "VERSION_KEY",
    "W",
]
