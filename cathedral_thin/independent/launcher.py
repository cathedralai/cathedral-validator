"""Start-up gates for `independent_v1`.

Nothing here connects to a chain. These are the checks that decide whether the
process is allowed to exist at all: the identity it would run as, the chain it
believes it is on, the file it would journal to, and whether the configuration
is asking for a broadcast this lineage cannot perform.

There is no ``--broadcast`` flag, and adding one is not an oversight to fix
later: the flag would have to be wired to a writer, and the writer does not
exist. A configuration that sets ``broadcast = true`` fails to load.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .constants import (
    BURN_HOTKEY,
    COMMIT_REVEAL_ENABLED,
    FINNEY_GENESIS_HASH,
    INDEPENDENT_STATE_FILE,
    LINEAGE,
    MAX_WEIGHT_LIMIT,
    MECID,
    MIN_ALLOWED_WEIGHTS,
    NETUID,
    SN39_MORTAL_PERIOD_BLOCKS,
    TEMPO_BLOCKS,
    VERSION_KEY,
)
from .errors import (
    BroadcastDisabled,
    ConfigError,
    GenesisPinError,
    IndependentValidatorError,
)
from .fetch_policy import validate_policy_url
from .refuse import require_permitted_hotkey

MAX_CONFIG_BYTES = 65_536

_REQUIRED_SECTIONS = ("network", "lineage", "policy", "weights", "runtime")


@dataclass(frozen=True)
class IndependentConfig:
    """A validated `independent_v1` operator configuration."""

    network: str
    netuid: int
    genesis_hash: str
    wallet_name: str
    validator_hotkey: str
    lineage: str
    policy_url: str
    burn_hotkey: str
    version_key: int
    mecid: int
    tempo: int
    commit_reveal_enabled: bool
    min_allowed_weights: int
    max_weight_limit: float
    mortal_period_blocks: int
    state_file: Path
    broadcast: bool

    def summary(self) -> dict[str, Any]:
        """The resolved pins, safe to print. Never the raw policy URL."""
        endpoint = validate_policy_url(self.policy_url)
        return {
            "lineage": self.lineage,
            "network": self.network,
            "netuid": self.netuid,
            "genesis_hash": self.genesis_hash,
            "policy_endpoint": endpoint.label,
            "burn_hotkey": self.burn_hotkey,
            "version_key": self.version_key,
            "mecid": self.mecid,
            "tempo": self.tempo,
            "commit_reveal_enabled": self.commit_reveal_enabled,
            "mortal_period_blocks": self.mortal_period_blocks,
            "state_file": str(self.state_file),
            "broadcast": self.broadcast,
        }


def refuse_wallet(ss58: object) -> str:
    """Refuse to start as a refuse-listed hotkey."""
    return require_permitted_hotkey(ss58)


def check_genesis_pin(observed: object) -> str:
    """Return the observed genesis hash if it is the pinned Finney genesis.

    A composer on the wrong chain would read a metagraph that has nothing to do
    with SN39 and resolve a burn UID from it.
    """
    if not isinstance(observed, str) or not observed:
        raise GenesisPinError("no chain genesis hash was observed")
    if observed.strip().lower() != FINNEY_GENESIS_HASH:
        raise GenesisPinError(
            f"observed chain genesis {observed} is not the pinned Finney genesis "
            f"{FINNEY_GENESIS_HASH}"
        )
    return FINNEY_GENESIS_HASH


def _section(document: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = document.get(name)
    if not isinstance(value, dict):
        raise ConfigError(f"configuration is missing the [{name}] section")
    return value


def _config_int(section: Mapping[str, Any], name: str, label: str) -> int:
    value = section.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{label} must be an integer")
    return value


def _config_str(section: Mapping[str, Any], name: str, label: str) -> str:
    value = section.get(name)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{label} must be a non-empty string")
    return value


def _config_bool(section: Mapping[str, Any], name: str, label: str) -> bool:
    value = section.get(name)
    if not isinstance(value, bool):
        raise ConfigError(f"{label} must be a boolean")
    return value


def parse_config(document: Mapping[str, Any]) -> IndependentConfig:
    """Validate a parsed configuration document against every pin."""
    if not isinstance(document, Mapping):
        raise ConfigError("configuration must be a table")
    unknown = sorted(set(document) - set(_REQUIRED_SECTIONS))
    if unknown:
        raise ConfigError(f"configuration has unknown sections: {', '.join(unknown)}")
    network = _section(document, "network")
    lineage = _section(document, "lineage")
    policy = _section(document, "policy")
    weights = _section(document, "weights")
    runtime = _section(document, "runtime")

    lineage_name = _config_str(lineage, "name", "lineage.name")
    if lineage_name != LINEAGE:
        raise ConfigError(f"lineage.name must be {LINEAGE!r}, got {lineage_name!r}")

    netuid = _config_int(network, "netuid", "network.netuid")
    if netuid != NETUID:
        raise ConfigError(f"network.netuid must be {NETUID}, got {netuid}")
    genesis_hash = _config_str(network, "genesis_hash", "network.genesis_hash")
    check_genesis_pin(genesis_hash)
    network_name = _config_str(network, "name", "network.name")
    if network_name != "finney":
        raise ConfigError(
            f"network.name must be 'finney' to match the pinned genesis, "
            f"got {network_name!r}"
        )

    # A wallet label is a local name, but an operator who pastes an ss58 into it
    # must still be refused rather than told the label looks odd.
    validator_hotkey = _config_str(
        network, "validator_hotkey", "network.validator_hotkey"
    )
    require_permitted_hotkey(validator_hotkey, label="network.validator_hotkey")

    policy_url = _config_str(policy, "url", "policy.url")
    validate_policy_url(policy_url)
    burn_hotkey = _config_str(policy, "burn_hotkey", "policy.burn_hotkey")
    if burn_hotkey != BURN_HOTKEY:
        raise ConfigError("policy.burn_hotkey is not the pinned burn hotkey")

    version_key = _config_int(weights, "version_key", "weights.version_key")
    if version_key != VERSION_KEY:
        raise ConfigError(f"weights.version_key must be {VERSION_KEY}")
    mecid = _config_int(weights, "mecid", "weights.mecid")
    if mecid != MECID:
        raise ConfigError(f"weights.mecid must be {MECID}")
    tempo = _config_int(weights, "tempo", "weights.tempo")
    if tempo != TEMPO_BLOCKS:
        raise ConfigError(f"weights.tempo must be {TEMPO_BLOCKS}")
    commit_reveal_enabled = _config_bool(
        weights, "commit_reveal_enabled", "weights.commit_reveal_enabled"
    )
    if commit_reveal_enabled is not COMMIT_REVEAL_ENABLED:
        raise ConfigError("weights.commit_reveal_enabled must be false")
    min_allowed_weights = _config_int(
        weights, "min_allowed_weights", "weights.min_allowed_weights"
    )
    if min_allowed_weights != MIN_ALLOWED_WEIGHTS:
        raise ConfigError(f"weights.min_allowed_weights must be {MIN_ALLOWED_WEIGHTS}")
    raw_limit = weights.get("max_weight_limit")
    if isinstance(raw_limit, bool) or not isinstance(raw_limit, (int, float)):
        raise ConfigError("weights.max_weight_limit must be a number")
    if not math.isclose(float(raw_limit), MAX_WEIGHT_LIMIT):
        # Anything below 1.0 makes a legal burn-heavy vector overweight, and the
        # chain rejects the extrinsic instead of the configuration.
        raise ConfigError(
            f"weights.max_weight_limit must be {MAX_WEIGHT_LIMIT}, got {raw_limit}"
        )
    mortal_period_blocks = _config_int(
        weights, "mortal_period_blocks", "weights.mortal_period_blocks"
    )
    if mortal_period_blocks != SN39_MORTAL_PERIOD_BLOCKS:
        raise ConfigError(
            f"weights.mortal_period_blocks must be {SN39_MORTAL_PERIOD_BLOCKS}"
        )

    state_file = Path(_config_str(runtime, "state_file", "runtime.state_file"))
    if state_file.name != INDEPENDENT_STATE_FILE.name:
        raise ConfigError(
            f"runtime.state_file must be named {INDEPENDENT_STATE_FILE.name!r}; "
            "this lineage never shares another runtime's journal"
        )
    broadcast = _config_bool(runtime, "broadcast", "runtime.broadcast")
    if broadcast is not False:
        raise BroadcastDisabled(
            "runtime.broadcast = true, but this lineage has no chain writer"
        )

    return IndependentConfig(
        network=network_name,
        netuid=netuid,
        genesis_hash=FINNEY_GENESIS_HASH,
        wallet_name=_config_str(network, "wallet_name", "network.wallet_name"),
        validator_hotkey=validator_hotkey,
        lineage=lineage_name,
        policy_url=policy_url,
        burn_hotkey=burn_hotkey,
        version_key=version_key,
        mecid=mecid,
        tempo=tempo,
        commit_reveal_enabled=commit_reveal_enabled,
        min_allowed_weights=min_allowed_weights,
        max_weight_limit=float(raw_limit),
        mortal_period_blocks=mortal_period_blocks,
        state_file=state_file,
        broadcast=broadcast,
    )


def load_config(path: Path | str) -> IndependentConfig:
    """Read and validate an `independent_v1` configuration file."""
    target = Path(path)
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise ConfigError(f"configuration {target} could not be read: {exc}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(
            f"configuration {target} is {len(raw)} bytes, over the "
            f"{MAX_CONFIG_BYTES} byte bound"
        )
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"configuration {target} is not valid TOML: {exc}") from exc
    return parse_config(document)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cathedral-independent-validator",
        description=(
            "independent_v1 start-up gates: validate the operator configuration, "
            "the runtime identity, and the chain pin. Composes nothing and "
            "broadcasts nothing."
        ),
    )
    parser.add_argument(
        "--config", required=True, help="path to a validator-independent TOML profile"
    )
    parser.add_argument(
        "--hotkey-ss58",
        default=None,
        help="the resolved ss58 this runtime would sign as, checked against the "
        "refuse-list",
    )
    parser.add_argument(
        "--observed-genesis",
        default=None,
        help="the chain genesis hash this runtime observed, checked against the pin",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Validate start-up gates and print the resolved pins. Never broadcasts."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    for argument in arguments:
        if argument == "--broadcast" or argument.startswith("--broadcast="):
            print(
                "independent_v1 has no --broadcast flag: this lineage ships no "
                "chain writer",
                file=sys.stderr,
            )
            return 2
    parser = _build_parser()
    options = parser.parse_args(arguments)
    try:
        if options.hotkey_ss58 is not None:
            refuse_wallet(options.hotkey_ss58)
        config = load_config(options.config)
        if options.observed_genesis is not None:
            check_genesis_pin(options.observed_genesis)
    except IndependentValidatorError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(config.summary(), sort_keys=True, indent=2))
    return 0


__all__ = [
    "MAX_CONFIG_BYTES",
    "IndependentConfig",
    "check_genesis_pin",
    "load_config",
    "main",
    "parse_config",
    "refuse_wallet",
]
