"""Finney / SN39 client living outside `cathedral_thin.independent`.

Reads the metagraph, observes genesis, and submits ``set_mechanism_weights``
as the dedicated canary hotkey. The live relay and burn destination refuse
lists are enforced here as well as in the composer package.

``SubstrateCanaryTransport`` is a transport, not a writer that decides anything.
It signs only what the sealed package has already committed to on disk: the
one-write canary lock must already exist, be ``pending``, name this hotkey, and
carry byte-identical kwargs. The transport never claims that lock -- claiming it
here would give this module its own path to an extrinsic, which is the whole
thing the one-write design is trying to prevent. It also rebuilds the kwargs
through ``build_mechanism_weights_kwargs`` rather than trusting them, because a
caller that reaches this method directly has skipped every compose-time check.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from bittensor.core.extrinsics.pallets import SubtensorModule
from bittensor_wallet import Keypair

from cathedral_thin.independent.canary import load_canary_state, require_canary_hotkey
from cathedral_thin.independent.constants import (
    LINEAGE,
    MECID,
    NETUID,
    SN39_MORTAL_PERIOD_BLOCKS,
    VERSION_KEY,
)
from cathedral_thin.independent.errors import IndependentValidatorError
from cathedral_thin.independent.submit import (
    MECHANISM_WEIGHTS_CALL,
    build_mechanism_weights_kwargs,
)

from .errors import ChainClientError
from .axon import (  # noqa: F401 - compatibility re-exports
    AXON_SKIP_REASONS,
    AxonScan,
    ServingAxon,
    metagraph_view,
    observed_genesis_hash,
    scan_axons,
    serving_axons,
)

CANARY_LOCK_PENDING = "pending"


def _pinned_scalar(kwargs: Mapping[str, Any], name: str, pin: int) -> int:
    """The pinned integer ``name`` carries, or refuse. A string is not an int."""
    value = kwargs.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ChainClientError(
            f"canary transport is pinned to {name} {pin}; {value!r} is not an integer"
        )
    if value != pin:
        raise ChainClientError(
            f"canary transport is pinned to {name} {pin}, got {value}"
        )
    return value


def load_keypair(document: Mapping[str, Any] | str) -> Any:
    """Load an sr25519 keypair from a bittensor wallet JSON object or string."""
    if isinstance(document, str):
        try:
            parsed = json.loads(document)
        except json.JSONDecodeError as exc:
            raise ChainClientError("canary hotkey JSON is not valid JSON") from exc
    else:
        parsed = dict(document)
    if not isinstance(parsed, Mapping):
        raise ChainClientError("canary hotkey JSON must be an object")
    seed = parsed.get("secretSeed") or parsed.get("secret_seed")
    if not isinstance(seed, str) or not seed:
        raise ChainClientError("canary hotkey JSON has no secretSeed")
    if seed.startswith("0x"):
        seed = seed[2:]
    try:
        keypair = Keypair.create_from_seed("0x" + seed)
    except Exception as exc:
        raise ChainClientError(f"canary hotkey seed is unusable: {exc}") from exc
    require_canary_hotkey(str(keypair.ss58_address))
    return keypair


class SubstrateCanaryTransport:
    """CanaryTransport that submits ``SubtensorModule.set_mechanism_weights``.

    ``state_path`` is the one-write canary lock ``submit_canary_once`` claims.
    It is required: a transport without it is a naked writer, and the default
    that made it optional is how a direct call reaches ``submit_extrinsic``.
    """

    def __init__(self, subtensor: Any, keypair: Any, *, state_path: Path | str) -> None:
        require_canary_hotkey(str(getattr(keypair, "ss58_address", "")))
        if state_path is None:
            raise ChainClientError(
                "the canary transport requires the one-write lock path; it "
                "signs nothing the sealed package has not already claimed"
            )
        self.subtensor = subtensor
        self.keypair = keypair
        self.state_path = Path(state_path)

    def _canonical_kwargs(self, kwargs: Mapping[str, Any]) -> dict[str, Any]:
        """Rebuild the kwargs from scratch and refuse anything that differs."""
        if not isinstance(kwargs, Mapping):
            raise ChainClientError("mechanism weight kwargs must be a mapping")
        netuid = _pinned_scalar(kwargs, "netuid", NETUID)
        mecid = _pinned_scalar(kwargs, "mecid", MECID)
        version_key = _pinned_scalar(kwargs, "version_key", VERSION_KEY)
        dests = kwargs.get("dests")
        weights = kwargs.get("weights")
        if not isinstance(dests, (list, tuple)) or not isinstance(
            weights, (list, tuple)
        ):
            raise ChainClientError("dests and weights must both be sequences")
        try:
            expected = build_mechanism_weights_kwargs(
                dests=list(dests),
                weights=list(weights),
                netuid=netuid,
                mecid=mecid,
                version_key=version_key,
            )
        except IndependentValidatorError as exc:
            raise ChainClientError(
                f"the vector is not a legal u16 mechanism weight submission: {exc}"
            ) from exc
        if dict(kwargs) != expected:
            raise ChainClientError(
                "the submitted kwargs are not the canonical mechanism weight "
                "kwargs for this vector"
            )
        return expected

    def _require_pending_lock(self, expected: Mapping[str, Any]) -> None:
        """Refuse unless the one-write slot is already claimed for this vector."""
        try:
            record = load_canary_state(self.state_path)
        except IndependentValidatorError as exc:
            raise ChainClientError(
                f"the one-write canary lock at {self.state_path} is not usable "
                f"({exc}); this transport never claims it and never submits "
                "without it"
            ) from exc
        if record.get("lineage") != LINEAGE or record.get("kind") != "canary":
            raise ChainClientError(
                f"the lock at {self.state_path} is not an {LINEAGE} canary record"
            )
        if record.get("status") != CANARY_LOCK_PENDING:
            raise ChainClientError(
                f"the canary lock status is {record.get('status')!r}, not "
                f"{CANARY_LOCK_PENDING!r}; a spent slot is never resubmitted"
            )
        if record.get("broadcast") is not False:
            raise ChainClientError("the canary lock does not state broadcast = false")
        if record.get("call") != MECHANISM_WEIGHTS_CALL:
            raise ChainClientError(
                f"the canary lock names {record.get('call')!r}, not "
                f"{MECHANISM_WEIGHTS_CALL}"
            )
        if record.get("hotkey") != str(self.keypair.ss58_address):
            raise ChainClientError(
                "the canary lock was claimed for a different hotkey than the "
                "one this transport signs with"
            )
        if record.get("kwargs") != dict(expected):
            raise ChainClientError(
                "the canary lock kwargs are not the vector being signed"
            )

    def submit_mechanism_weights(self, kwargs: Mapping[str, Any]) -> str:
        expected = self._canonical_kwargs(kwargs)
        self._require_pending_lock(expected)
        observed_genesis_hash(self.subtensor)
        substrate = self.subtensor.substrate
        try:
            header = substrate.get_block_header()
            block_number = int(header["header"]["number"])
        except Exception as exc:
            raise ChainClientError(f"could not read sign-time head: {exc}") from exc
        try:
            nonce = substrate.get_account_next_index(self.keypair.ss58_address)
            call = SubtensorModule(self.subtensor).set_mechanism_weights(
                netuid=int(expected["netuid"]),
                mecid=int(expected["mecid"]),
                dests=list(expected["dests"]),
                weights=list(expected["weights"]),
                version_key=int(expected["version_key"]),
            )
            era = {"period": SN39_MORTAL_PERIOD_BLOCKS, "current": block_number}
            signed = substrate.create_signed_extrinsic(
                call=call,
                keypair=self.keypair,
                nonce=nonce,
                era=era,
            )
            receipt = substrate.submit_extrinsic(
                signed, wait_for_inclusion=True, wait_for_finalization=False
            )
        except Exception as exc:
            raise ChainClientError(f"set_mechanism_weights failed: {exc}") from exc
        extrinsic_hash = getattr(receipt, "extrinsic_hash", None) or getattr(
            signed, "extrinsic_hash", None
        )
        if extrinsic_hash is None:
            raise ChainClientError("submission returned no extrinsic hash")
        text = (
            extrinsic_hash
            if isinstance(extrinsic_hash, str)
            else f"0x{bytes(extrinsic_hash).hex()}"
        )
        if not text.startswith("0x"):
            text = "0x" + text
        return text.lower()
