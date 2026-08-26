"""`independent_v1`: an independent SN39 composer with no chain writer.

This package composes a mechanism weight vector from a signed, on-chain
committed policy document and journals it. It has no writer, no substrate
client, and no path to one: there is nothing here that can set weights, and the
import-graph tests in ``tests/thin`` prove it rather than asserting it.

What it does own, end to end:

* the policy document contract (one atomic bundle, 2-of-3 Ed25519 over its
  canonical bytes, one 50-byte on-chain commitment at a frozen anchor);
* a hardened HTTPS fetch for that document, with the thin feed client's peer
  rules copied rather than called;
* integer-mass Hamilton apportionment to u16 destinations and weights;
* inclusion-time UID safety, where a remapped destination forfeits its mass to
  burn instead of paying whoever now holds the slot;
* its own journal, separate from every other lineage's state.

Importing this package has no side effects, reads no environment variable, and
opens no socket.
"""

from __future__ import annotations

from .canonical import canonical_bytes, parse_strict_json
from .compose import (
    STATUS_BROADCAST_BLOCKED,
    STATUS_COMPOSED,
    STATUS_DEGRADED,
    ComposeResult,
    EpochAnchor,
    LaneAdapter,
    LaneBlock,
    compose_dry_run,
    last_good_is_usable,
    mass_map,
    require_last_good,
)
from .constants import (
    BURN_HOTKEY,
    COMMITMENT_LENGTH,
    COMMITMENT_MAGIC,
    FINNEY_GENESIS_HASH,
    H,
    INDEPENDENT_STATE_FILE,
    LINEAGE,
    MAX_POLICY_BUNDLE_BYTES,
    MECID,
    NETUID,
    REFUSE_HOTKEYS,
    SN39_MORTAL_PERIOD_BLOCKS,
    TEMPO_BLOCKS,
    VERSION_KEY,
    W,
)
from .errors import (
    BroadcastBlocked,
    BroadcastDisabled,
    CommitmentError,
    ConfigError,
    GenesisPinError,
    HamiltonError,
    IndependentValidatorError,
    InclusionHalt,
    JournalError,
    PolicyBundleError,
    PolicyFetchError,
    RefuseListError,
)
from .fetch_policy import fetch_policy_bytes, validate_policy_url
from .hamilton import Dest, HamiltonResult, apportion
from .inclusion import (
    Forfeit,
    InclusionOutcome,
    MetagraphView,
    apply_inclusion_forfeit,
    resolve_burn_uid,
)
from .journal import load_journal, write_journal
from .launcher import IndependentConfig, check_genesis_pin, load_config, refuse_wallet
from .policy import (
    Allocation,
    BurnTarget,
    EconomicsSet,
    LaneContractId,
    PolicyBundle,
    PolicySignature,
    bundle_digest,
    decode_commitment,
    encode_commitment,
    load_policy_bundle,
    parse_policy_bundle,
    require_commitment,
    signing_payload,
    verify_signatures,
)
from .refuse import is_refused, require_permitted_hotkey
from .submit import (
    MECHANISM_WEIGHTS_CALL,
    build_mechanism_weights_kwargs,
    prepare_mechanism_weights,
)

__all__ = [
    "BURN_HOTKEY",
    "COMMITMENT_LENGTH",
    "COMMITMENT_MAGIC",
    "FINNEY_GENESIS_HASH",
    "H",
    "INDEPENDENT_STATE_FILE",
    "LINEAGE",
    "MAX_POLICY_BUNDLE_BYTES",
    "MECHANISM_WEIGHTS_CALL",
    "MECID",
    "NETUID",
    "REFUSE_HOTKEYS",
    "SN39_MORTAL_PERIOD_BLOCKS",
    "STATUS_BROADCAST_BLOCKED",
    "STATUS_COMPOSED",
    "STATUS_DEGRADED",
    "TEMPO_BLOCKS",
    "VERSION_KEY",
    "W",
    "Allocation",
    "BroadcastBlocked",
    "BroadcastDisabled",
    "BurnTarget",
    "CommitmentError",
    "ComposeResult",
    "ConfigError",
    "Dest",
    "EconomicsSet",
    "EpochAnchor",
    "Forfeit",
    "GenesisPinError",
    "HamiltonError",
    "HamiltonResult",
    "InclusionHalt",
    "InclusionOutcome",
    "IndependentConfig",
    "IndependentValidatorError",
    "JournalError",
    "LaneAdapter",
    "LaneBlock",
    "LaneContractId",
    "MetagraphView",
    "PolicyBundle",
    "PolicyBundleError",
    "PolicyFetchError",
    "PolicySignature",
    "RefuseListError",
    "apply_inclusion_forfeit",
    "apportion",
    "build_mechanism_weights_kwargs",
    "bundle_digest",
    "canonical_bytes",
    "check_genesis_pin",
    "compose_dry_run",
    "decode_commitment",
    "encode_commitment",
    "fetch_policy_bytes",
    "is_refused",
    "last_good_is_usable",
    "load_config",
    "load_journal",
    "load_policy_bundle",
    "mass_map",
    "parse_policy_bundle",
    "parse_strict_json",
    "prepare_mechanism_weights",
    "refuse_wallet",
    "require_commitment",
    "require_last_good",
    "require_permitted_hotkey",
    "resolve_burn_uid",
    "signing_payload",
    "validate_policy_url",
    "verify_signatures",
    "write_journal",
]
