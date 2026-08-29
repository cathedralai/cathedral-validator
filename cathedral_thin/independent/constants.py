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
# Intel's public PCS collateral root used by every TDX QVL adapter. Keeping it
# here lets read-only proof modules avoid importing the live runner.
INTEL_COLLATERAL = "https://api.trustedservices.intel.com/sgx/certification/v4/"
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

# One-write canary lock. A different file from the compose journal on purpose:
# a spent canary must not look like an epoch composition, and a composed epoch
# must not look like a spent canary. The name is the pin; the directory is the
# operator's.
INDEPENDENT_CANARY_FILE = Path("/var/lib/cathedral-validator/independent-canary.json")

# Well-known Substrate development keys (sr25519, stash, and ed25519 variants).
# These are public; anyone can derive them. They may appear as opaque miner
# identifiers in tests, but they are never a canary identity. They are NOT on
# REFUSE_HOTKEYS: that set stays exactly the live relay plus the burn dest.
WELL_KNOWN_DEV_HOTKEYS = frozenset(
    {
        "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",  # //Alice
        "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",  # //Bob
        "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y",  # //Charlie
        "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy",  # //Dave
        "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEZcCj68kUMaw",  # //Eve
        "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2DjL",  # //Ferdie
        "5GNJqTPyNqANBkUVMN1LPPrxXnFouWXoe2wNSmmEoLctxiZY",  # //Alice//stash
        "5HpG9w8EBLe5XCrbczpwq5TSXvedjrBGCwqxK1iQ7qUsSWFc",  # //Bob//stash
        "5Ck5SLSHYac6WFt5UZRSsdJjwmpSZq85fd5TRNAdZQVzEAPT",  # //Charlie//stash
        "5HKPmK9GYtE1PSLsS1qiYU9xQ9Si1NcEhdeCq9sw5bqu4ns8",  # //Dave//stash
        "5FCfAonRZgTFrTd9HREEyeJjDpT397KMzizE6T3DvebLFE7n",  # //Eve//stash
        "5CRmqmsiNFExV6VbdmPJViVxrWmkaXXvBrSX8oqBT8R9vmWk",  # //Ferdie//stash
        "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu",  # //Alice ed25519
        "5GoNkf6WdbxCFnPdAnYYQyCjAKPJgLNxXwPjwTh6DGg6gN3E",  # //Bob ed25519
        "5DbKjhNLpqX3zqZdNBc9BGb4fHU1cRBaDhJUskrvkwfraDi6",  # //Charlie ed25519
        "5ECTwv6cZ5nJQPk6tWfaTrEk8YH2L7X1VT4EL5Tx2ikfFwb7",  # //Dave ed25519
        "5Ck2miBfCe1JQ4cY3NDsXyBaD6EcsgiVmEFTWwqNSs25XDEq",  # //Eve ed25519
        "5E2BmpVFzYGd386XRCZ76cDePMB3sfbZp5ZKGUsrG1m6gomN",  # //Ferdie ed25519
    }
)

# The only identity submit_canary_once will even attempt to submit as. It is
# also on neither refuse-list entry and is not a well-known development key.
# The seed is not in this repository. A production canary wallet is a pin
# change, not a CLI flag and not a second runtime signing as the live relay.
CANARY_HOTKEY = (
    "5G246nVyX3W9FUSj3VgwzxnnUzvp47jmLQPxKdDukHBtetzm"  # pragma: allowlist secret
)

# Public identities for the canonical UID30 validator and consolidation miner.
# Read-only fleet tools keep these outside the monolithic writer so importing
# a proof command never imports chain-submission code.
UID30_VALIDATOR_UID = 30
UID30_VALIDATOR_HOTKEY = (
    "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"  # pragma: allowlist secret
)
UID30_MINER_HOTKEY = (
    "5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G"  # pragma: allowlist secret
)

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

# The Compute lane exactly as a signed policy document names it. The composer
# stamps this pair onto whatever adapter is registered for it; an adapter never
# names its own lane, so a compromised one cannot claim another lane's mass.
COMPUTE_LANE_SCHEMA = "cathedral_compute_receipt_v1"
COMPUTE_LANE_PLATFORM = "intel_tdx_cpu"

# DCAP collateral and TCB info come from Intel's public PCS. Collateral served
# by whoever also operates the lane is not evidence: nobody outside could refetch
# it and reach the same verdict, which is the only property that makes a quote
# verdict worth anything to a third party.
INTEL_PCS_HOSTS = frozenset(
    {"api.trustedservices.intel.com", "trustedservices.intel.com"}
)

# Machines one miner may advertise for one epoch. Over the cap that miner zeros
# for the epoch; the fleet is never truncated to the first entries, because
# letting a miner choose which of its machines get audited is cheaper than
# actually running the fleet.
COMPUTE_FLEET_CAP = 256

# Direct validator-to-miner fleet discovery is deliberately narrower than the
# older sealed collect helper.  It matches the measured worker's
# ``cathedral_worker_fleet_v1`` response bound.  One canonical SAT challenge is
# worth 20 independently re-derived units, so one UID can contribute at most
# 32 * 20 = 640 raw units in one scoring window.  Neither number is supplied by
# a miner.
MULTICOMPUTE_FLEET_CAP = 32
MULTICOMPUTE_MACHINE_WORK_UNIT_CAP = 20

__all__ = [
    "BURN_HOTKEY",
    "CANARY_HOTKEY",
    "COMMITMENT_LENGTH",
    "COMMITMENT_MAGIC",
    "COMMIT_REVEAL_ENABLED",
    "COMPUTE_FLEET_CAP",
    "MULTICOMPUTE_FLEET_CAP",
    "MULTICOMPUTE_MACHINE_WORK_UNIT_CAP",
    "COMPUTE_LANE_PLATFORM",
    "COMPUTE_LANE_SCHEMA",
    "ECONOMICS_SET_SCHEMA",
    "FINNEY_GENESIS_HASH",
    "GENESIS_PREVIOUS_DIGEST",
    "GENESIS_VERSION",
    "H",
    "INDEPENDENT_CANARY_FILE",
    "INDEPENDENT_STATE_FILE",
    "INTEL_PCS_HOSTS",
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
    "UID30_MINER_HOTKEY",
    "UID30_VALIDATOR_HOTKEY",
    "UID30_VALIDATOR_UID",
    "VERSION_KEY",
    "W",
    "WELL_KNOWN_DEV_HOTKEYS",
]
