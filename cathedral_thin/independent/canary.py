"""One-write canary: injected transport, dedicated hotkey, no chain client.

This module is the last gate in front of a mechanism-weight submission, not a
writer the package owns. There is no substrate client here, no default dialer,
and no path that acquires one. A caller that already holds a transport may ask
``submit_canary_once`` to invoke it exactly once, and only when every gate
below passes.

The gates, all fail-closed, all before the transport is touched:

* the identity is the dedicated canary hotkey, and is not refuse-listed;
* the compose result is ``COMPOSED``. ``DEGRADED`` is a legal burn-only vector
  and is not acceptance. ``BROADCAST_BLOCKED`` is not a write;
* the signed policy bundle carries a funded Compute row. A CyberGym-only mix,
  or Compute at allocation 0, is not this canary;
* the destination vector still includes burn and is not burn-only;
* the prepared kwargs match the composed dests and weights exactly, on the
  pinned netuid / mecid / version_key;
* the transport is injected;
* the one-write lock file does not yet exist.

A composition that is still ``BROADCAST_BLOCKED`` because Compute allocation
is 0 will never pass these gates. That is the remaining blocker, not a gap
in this module. The happy-path tests construct a synthetic ``COMPOSED`` result
so the gate can be proven without pretending a funded Compute row is payable.

The lock is claimed with ``O_EXCL`` before the transport runs. The file and
its parent directory are both fsynced before that call returns: fsyncing only
the file leaves the new directory entry in the page cache, and a crash then
looks like the slot was never spent. A crash after the claim, or a transport
that raises, spends the slot: retrying a maybe-sent extrinsic is the failure
this file exists to prevent.
"""

from __future__ import annotations

import errno
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

from .compose import STATUS_COMPOSED, ComposeResult
from .compute import COMPUTE_LANE
from .constants import (
    CANARY_HOTKEY,
    INDEPENDENT_CANARY_FILE,
    LINEAGE,
    NETUID,
)
from .errors import (
    CanaryIneligible,
    CanarySpent,
    CanaryStateError,
    CanaryTransportError,
    HamiltonError,
)
from .policy import PolicyBundle, funded_lanes
from .refuse import require_permitted_hotkey
from .submit import MECHANISM_WEIGHTS_CALL, build_mechanism_weights_kwargs

# Fields a canary record may never carry. This path still signs nothing; a
# receipt is an opaque id the transport returned, not an extrinsic.
REFUSED_CANARY_KEYS = frozenset({"signed_vector", "signature", "extrinsic"})

MAX_CANARY_BYTES = 65_536
MAX_RECEIPT_CHARS = 256

_CANARY_KIND = "canary"


@runtime_checkable
class CanaryTransport(Protocol):
    """Submits prepared mechanism-weight kwargs and returns an opaque receipt.

    Injected by the caller. There is no implementation in this package: writing
    one would put a chain client behind a function whose default is currently
    ineligible to fire.
    """

    def submit_mechanism_weights(self, kwargs: Mapping[str, Any]) -> str: ...


@dataclass(frozen=True)
class CanaryReceipt:
    """What the one-write canary recorded after a successful transport call."""

    hotkey: str
    call: str
    kwargs: Mapping[str, Any]
    receipt: str
    state_path: Path


def require_canary_hotkey(ss58: object) -> str:
    """Return ``ss58`` if it is the dedicated canary identity, else raise."""
    permitted = require_permitted_hotkey(ss58, label="canary hotkey")
    if permitted != CANARY_HOTKEY:
        raise CanaryIneligible(
            f"canary hotkey {permitted} is not the dedicated canary identity"
        )
    return permitted


def _require_canary_path(path: Path) -> Path:
    resolved = Path(path)
    if resolved.name != INDEPENDENT_CANARY_FILE.name:
        raise CanaryStateError(
            f"the one-write canary lock must be named "
            f"{INDEPENDENT_CANARY_FILE.name!r}, got {resolved.name!r}"
        )
    return resolved


def _require_transport(transport: object) -> CanaryTransport:
    if transport is None or not callable(
        getattr(transport, "submit_mechanism_weights", None)
    ):
        raise CanaryTransportError(
            "canary requires an injected CanaryTransport; this package ships "
            "no chain client"
        )
    return transport  # type: ignore[return-value]


def _require_funded_compute(bundle: object) -> None:
    if not isinstance(bundle, PolicyBundle):
        raise CanaryIneligible("canary requires the signed policy bundle")
    if bundle.economics.netuid != NETUID:
        raise CanaryIneligible(
            f"canary is pinned to netuid {NETUID}, got {bundle.economics.netuid}"
        )
    funded = [
        row
        for row in funded_lanes(bundle.economics)
        if row.lane_contract_id == COMPUTE_LANE
    ]
    if not funded:
        raise CanaryIneligible(
            "canary requires a funded Compute row; burn-only is not acceptance"
        )


def _require_composed(result: object) -> ComposeResult:
    if not isinstance(result, ComposeResult):
        raise CanaryIneligible("canary requires a ComposeResult")
    if result.status != STATUS_COMPOSED:
        raise CanaryIneligible(
            f"canary requires status {STATUS_COMPOSED}; {result.status} is not "
            "acceptance (burn-only DEGRADED is not a canary, and a blocked "
            "composition is not a write)"
        )
    if result.blocks:
        raise CanaryIneligible(
            "canary refuses a composition that still carries a blocked funded lane"
        )
    burn_uid = result.inclusion.burn_uid
    if burn_uid not in result.dests:
        raise CanaryIneligible("the canary vector dropped the burn destination")
    if result.dests == (burn_uid,):
        raise CanaryIneligible("burn-only is not a canary; DEGRADED is not acceptance")
    return result


def _require_u16_match(result: ComposeResult, kwargs: object) -> dict[str, Any]:
    if not isinstance(kwargs, Mapping):
        raise CanaryIneligible("prepared kwargs must be a mapping")
    try:
        expected = build_mechanism_weights_kwargs(
            dests=result.dests, weights=result.weights
        )
    except HamiltonError as exc:
        raise CanaryIneligible(
            f"the composed vector is not a legal u16 submission: {exc}"
        ) from exc
    prepared = dict(kwargs)
    if prepared != expected:
        raise CanaryIneligible("dry-run u16 does not match the prepared submission")
    return expected


def _require_receipt(receipt: object) -> str:
    if not isinstance(receipt, str) or not receipt:
        raise CanaryTransportError("the canary transport must return a receipt string")
    if len(receipt) > MAX_RECEIPT_CHARS:
        raise CanaryTransportError(
            f"the canary receipt is {len(receipt)} characters, over the "
            f"{MAX_RECEIPT_CHARS} character bound"
        )
    if any(ord(character) < 32 for character in receipt):
        raise CanaryTransportError("the canary receipt carries a control character")
    return receipt


def _serialise(record: Mapping[str, Any]) -> bytes:
    refused = sorted(REFUSED_CANARY_KEYS & set(record))
    if refused:
        raise CanaryStateError(
            f"the canary lock never records {', '.join(refused)}; "
            "this lineage has no chain writer"
        )
    if record.get("broadcast") is not False:
        raise CanaryStateError(
            "the canary lock must state broadcast = false; this lineage "
            "does not broadcast"
        )
    if record.get("lineage") != LINEAGE:
        raise CanaryStateError(f"the canary lock must carry lineage {LINEAGE!r}")
    try:
        serialised = json.dumps(record, sort_keys=True, allow_nan=False, indent=2)
    except (TypeError, ValueError) as exc:
        raise CanaryStateError(f"the canary lock is not serialisable: {exc}") from exc
    encoded = (serialised + "\n").encode("utf-8")
    if len(encoded) > MAX_CANARY_BYTES:
        raise CanaryStateError(
            f"the canary lock exceeds the {MAX_CANARY_BYTES} byte bound"
        )
    return encoded


def _fsync_directory(directory: Path) -> None:
    """Persist the directory entry. File fsync alone does not."""
    flags = os.O_RDONLY
    for name in ("O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW"):
        flags |= getattr(os, name, 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(str(directory), flags)
        os.fsync(descriptor)
    except OSError as exc:
        raise CanaryStateError(
            f"the canary directory could not be fsynced: {exc}"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _claim_lock(path: Path, record: Mapping[str, Any]) -> None:
    encoded = _serialise(record)
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CanaryStateError(f"the canary directory is unusable: {exc}") from exc
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    descriptor: int | None = None
    try:
        descriptor = os.open(str(path), flags, 0o600)
    except FileExistsError as exc:
        raise CanarySpent(f"the one-write canary at {path} is already spent") from exc
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise CanarySpent(
                f"the one-write canary at {path} is already spent"
            ) from exc
        raise CanaryStateError(f"the canary lock could not be claimed: {exc}") from exc
    try:
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            raise CanaryStateError("the canary lock write was short")
        os.fsync(descriptor)
    except OSError as exc:
        raise CanaryStateError(f"the canary lock could not be written: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    _fsync_directory(parent)


def _replace_lock(path: Path, record: Mapping[str, Any]) -> None:
    encoded = _serialise(record)
    handle = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
        )
        handle = os.fdopen(descriptor, "wb")
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        handle = None
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        temporary = None
        _fsync_directory(path.parent)
    except OSError as exc:
        raise CanaryStateError(f"the canary lock could not be updated: {exc}") from exc
    finally:
        if handle is not None:
            handle.close()
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def load_canary_state(path: Path | str = INDEPENDENT_CANARY_FILE) -> dict[str, Any]:
    """Read the one-write lock, refusing duplicate keys and oversize files."""
    target = _require_canary_path(Path(path))
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise CanaryStateError(f"the canary lock could not be read: {exc}") from exc
    if len(raw) > MAX_CANARY_BYTES:
        raise CanaryStateError(
            f"the canary lock is {len(raw)} bytes, over the {MAX_CANARY_BYTES} byte bound"
        )

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CanaryStateError(f"the canary lock has duplicate key {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanaryStateError(f"the canary lock is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise CanaryStateError("the canary lock is not a JSON object")
    refused = sorted(REFUSED_CANARY_KEYS & set(document))
    if refused:
        raise CanaryStateError(
            f"the canary lock on disk carries {', '.join(refused)}; refusing to trust it"
        )
    return document


def submit_canary_once(
    *,
    result: ComposeResult,
    kwargs: Mapping[str, Any],
    bundle: PolicyBundle,
    hotkey: str,
    transport: CanaryTransport,
    state_path: Path | str,
) -> CanaryReceipt:
    """Submit prepared kwargs exactly once, or raise. Sends nothing by default.

    ``state_path`` is required. A default that wrote the operator lock from a
    unit test is how a dry-run path becomes a live one.
    """
    if state_path is None:
        raise CanaryStateError(
            "canary requires an explicit lock path; refusing the operator default"
        )
    _require_transport(transport)
    identity = require_canary_hotkey(hotkey)
    _require_funded_compute(bundle)
    composed = _require_composed(result)
    expected = _require_u16_match(composed, kwargs)
    target = _require_canary_path(Path(state_path))

    pending = {
        "lineage": LINEAGE,
        "kind": _CANARY_KIND,
        "status": "pending",
        "hotkey": identity,
        "call": MECHANISM_WEIGHTS_CALL,
        "kwargs": expected,
        "broadcast": False,
        "receipt": None,
    }
    _claim_lock(target, pending)

    try:
        raw_receipt = transport.submit_mechanism_weights(expected)
        receipt = _require_receipt(raw_receipt)
    except CanaryTransportError:
        raise
    except Exception as exc:
        raise CanaryTransportError(
            f"the canary transport failed after the slot was claimed: {exc}"
        ) from exc

    completed = dict(pending)
    completed["status"] = "submitted"
    completed["receipt"] = receipt
    _replace_lock(target, completed)
    return CanaryReceipt(
        hotkey=identity,
        call=MECHANISM_WEIGHTS_CALL,
        kwargs=expected,
        receipt=receipt,
        state_path=target,
    )


__all__ = [
    "MAX_CANARY_BYTES",
    "MAX_RECEIPT_CHARS",
    "REFUSED_CANARY_KEYS",
    "CanaryReceipt",
    "CanaryTransport",
    "load_canary_state",
    "require_canary_hotkey",
    "submit_canary_once",
]
