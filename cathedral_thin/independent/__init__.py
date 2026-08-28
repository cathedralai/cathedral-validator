"""`independent_v1`: an independent SN39 composer with no chain client.

This package composes a mechanism weight vector from a signed, on-chain
committed policy document and journals it. It has no substrate client and no
default dialer: import-graph tests in ``tests/thin`` prove there is no import
path from this lineage to a writer in this repo.

What it does own, end to end:

* the policy document contract (one atomic bundle, 2-of-3 Ed25519 over its
  canonical bytes, one 50-byte on-chain commitment at a frozen anchor);
* a hardened HTTPS fetch for that document, with the thin feed client's peer
  rules copied rather than called;
* integer-mass Hamilton apportionment to u16 destinations and weights;
* inclusion-time UID safety, where a remapped destination forfeits its mass to
  burn instead of paying whoever now holds the slot;
* a named Compute lane whose adapter pays only from pinned-QVL verified integer
  mass: the quote verifier is mandatory, collateral is pinned to Intel's public
  PCS, and an unpinned dry-run mock still contributes nothing;
* a dry-run collect client for that lane, which speaks the miner's v2
  ``POST /v1/evidence`` contract over an injected transport and derives the
  expected ``REPORT_DATA`` from its own challenge -- collect still binds no
  mass by itself;
* the audit-work half of that lane: a ``POST /v1/sat-work`` client, also over
  an injected transport, which commits to an instance derived from material
  already pinned for the epoch, re-checks the returned witness clause by
  clause, and returns the integer units it derived itself. Attestation is
  admission; only these units bind mass;
* a one-write canary gate that will call an injected transport exactly once
  after a ``COMPOSED`` vector, a funded Compute row, a dry-run u16 match, and
  the dedicated canary identity -- and that still ships no chain client;
* its own journal, separate from every other lineage's state.

Importing this package has no side effects, reads no environment variable, and
opens no socket.
"""

from __future__ import annotations

from .canonical import canonical_bytes, parse_strict_json
from .canary import (
    CanaryReceipt,
    CanaryTransport,
    load_canary_state,
    require_canary_hotkey,
    submit_canary_once,
)
from .collect import (
    EVIDENCE_V2_REQUEST_KEYS,
    EVIDENCE_V2_RESPONSE_KEYS,
    ChannelBinding,
    CollectedEvidence,
    EvidenceTransport,
    FleetTarget,
    collect_evidence,
    collect_miner_fleet,
    evidence_url,
    mint_nonce,
    report_data_v2,
    verify_collected,
)
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
from .compute import (
    COMPUTE_BLOCK_REASON,
    COMPUTE_LANE,
    INTEL_PCS_HOSTS,
    ComputeAdapter,
    QuoteVerdict,
    QuoteVerifier,
    assert_machine_identity,
    canonical_seed_material,
    fleet_over_cap,
    machine_id_from_key,
    require_compute_adapter,
    require_verified_mass,
    validate_collateral_url,
)
from .constants import (
    BURN_HOTKEY,
    CANARY_HOTKEY,
    COMPUTE_FLEET_CAP,
    COMMITMENT_LENGTH,
    COMMITMENT_MAGIC,
    FINNEY_GENESIS_HASH,
    H,
    INDEPENDENT_CANARY_FILE,
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
    AdapterUnavailable,
    BroadcastBlocked,
    BroadcastDisabled,
    CanaryIneligible,
    CanarySpent,
    CanaryStateError,
    CanaryTransportError,
    CollateralSourceError,
    CollectError,
    CommitmentError,
    ComputeEvidenceError,
    ConfigError,
    GenesisPinError,
    HamiltonError,
    IndependentValidatorError,
    InclusionHalt,
    JournalError,
    MachineIdentityConflict,
    PolicyBundleError,
    PolicyFetchError,
    PolicyLineageError,
    RefuseListError,
    SatWorkError,
)
from .fetch_policy import fetch_policy_bytes, validate_policy_url
from .hamilton import Dest, HamiltonResult, apportion
from .inclusion import (
    FORFEIT_REFUSED,
    FORFEIT_REMAPPED,
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
    require_lineage,
    signing_payload,
    verify_signatures,
)
from .refuse import is_refused, is_refused_destination, require_permitted_hotkey
from .sat import (
    MAX_SAT_RESPONSE_BYTES,
    SAT_REQUEST_KEYS,
    SAT_RESPONSE_KEYS,
    SAT_WORK_PATH,
    SAT_WORK_UNIT_RULE,
    SatInstance,
    SatWorkItem,
    canonical_instance,
    canonical_work_item,
    collect_sat_work,
    compute_challenge_id,
    derived_work_units,
    instance_equals_canonical,
    sat_work_url,
    seed_from_material,
)
from .submit import (
    MECHANISM_WEIGHTS_CALL,
    build_mechanism_weights_kwargs,
    prepare_mechanism_weights,
)

__all__ = [
    "BURN_HOTKEY",
    "CANARY_HOTKEY",
    "COMMITMENT_LENGTH",
    "COMMITMENT_MAGIC",
    "COMPUTE_BLOCK_REASON",
    "COMPUTE_FLEET_CAP",
    "COMPUTE_LANE",
    "EVIDENCE_V2_REQUEST_KEYS",
    "EVIDENCE_V2_RESPONSE_KEYS",
    "FINNEY_GENESIS_HASH",
    "FORFEIT_REFUSED",
    "FORFEIT_REMAPPED",
    "H",
    "INDEPENDENT_CANARY_FILE",
    "INDEPENDENT_STATE_FILE",
    "INTEL_PCS_HOSTS",
    "LINEAGE",
    "MAX_POLICY_BUNDLE_BYTES",
    "MAX_SAT_RESPONSE_BYTES",
    "MECHANISM_WEIGHTS_CALL",
    "MECID",
    "NETUID",
    "REFUSE_HOTKEYS",
    "SAT_REQUEST_KEYS",
    "SAT_RESPONSE_KEYS",
    "SAT_WORK_PATH",
    "SAT_WORK_UNIT_RULE",
    "SN39_MORTAL_PERIOD_BLOCKS",
    "STATUS_BROADCAST_BLOCKED",
    "STATUS_COMPOSED",
    "STATUS_DEGRADED",
    "TEMPO_BLOCKS",
    "VERSION_KEY",
    "W",
    "AdapterUnavailable",
    "Allocation",
    "BroadcastBlocked",
    "BroadcastDisabled",
    "BurnTarget",
    "CanaryIneligible",
    "CanaryReceipt",
    "CanarySpent",
    "CanaryStateError",
    "CanaryTransport",
    "CanaryTransportError",
    "ChannelBinding",
    "CollateralSourceError",
    "CollectError",
    "CollectedEvidence",
    "CommitmentError",
    "ComposeResult",
    "ComputeAdapter",
    "ComputeEvidenceError",
    "ConfigError",
    "Dest",
    "EconomicsSet",
    "EpochAnchor",
    "EvidenceTransport",
    "FleetTarget",
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
    "MachineIdentityConflict",
    "MetagraphView",
    "PolicyBundle",
    "PolicyBundleError",
    "PolicyFetchError",
    "PolicyLineageError",
    "PolicySignature",
    "QuoteVerdict",
    "QuoteVerifier",
    "RefuseListError",
    "SatInstance",
    "SatWorkError",
    "SatWorkItem",
    "apply_inclusion_forfeit",
    "apportion",
    "assert_machine_identity",
    "build_mechanism_weights_kwargs",
    "bundle_digest",
    "canonical_bytes",
    "canonical_instance",
    "canonical_seed_material",
    "canonical_work_item",
    "check_genesis_pin",
    "collect_evidence",
    "collect_miner_fleet",
    "collect_sat_work",
    "compose_dry_run",
    "compute_challenge_id",
    "decode_commitment",
    "derived_work_units",
    "encode_commitment",
    "evidence_url",
    "fetch_policy_bytes",
    "fleet_over_cap",
    "instance_equals_canonical",
    "is_refused",
    "is_refused_destination",
    "last_good_is_usable",
    "load_canary_state",
    "load_config",
    "load_journal",
    "load_policy_bundle",
    "machine_id_from_key",
    "mass_map",
    "mint_nonce",
    "parse_policy_bundle",
    "parse_strict_json",
    "prepare_mechanism_weights",
    "refuse_wallet",
    "report_data_v2",
    "require_canary_hotkey",
    "require_commitment",
    "require_compute_adapter",
    "require_last_good",
    "require_lineage",
    "require_permitted_hotkey",
    "require_verified_mass",
    "resolve_burn_uid",
    "sat_work_url",
    "seed_from_material",
    "signing_payload",
    "submit_canary_once",
    "validate_collateral_url",
    "validate_policy_url",
    "verify_collected",
    "verify_signatures",
    "write_journal",
]
