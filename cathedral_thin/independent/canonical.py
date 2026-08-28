"""Canonical bytes and strict JSON parsing for the policy path.

This mirrors the shared receipt canonicalisation rule (sorted keys, ASCII, tight
separators, no floats) deliberately as a local implementation. The independent
composer's write path takes no dependency on an optional extra: a signature
check that cannot run because a package is missing is not a signature check.

Two properties beyond "it serialises":

* floats are refused recursively, so a policy amount can never arrive as
  ``1e12`` and round somewhere downstream;
* duplicate JSON keys are refused at parse time. ``{"amount":1,"amount":0}``
  hashes identically to ``{"amount":0}`` after any last-key-wins parse, so a
  document can otherwise carry one number for the signer and another for the
  reader.
"""

from __future__ import annotations

import json
import math
from typing import Any, Mapping

from .errors import PolicyBundleError

# Nesting cap for a policy document. The measurement and receipt-key registries
# are nested objects, so this is not 2; it is still bounded so a hostile
# document cannot drive recursion into the interpreter's own limit.
MAX_CANONICAL_DEPTH = 32
# Key-count cap per object, aggregate across the walk. Bounded work on a
# bounded body.
MAX_CANONICAL_NODES = 100_000


def canonical_bytes(document: Any) -> bytes:
    """Return the one canonical byte string for ``document``.

    Refuses anything that is not a JSON object/array/string/int/bool/null, and
    refuses non-string object keys, so two callers cannot disagree about what
    was signed.
    """
    _check_canonical(document)
    return json.dumps(
        document,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _check_canonical(
    node: Any, *, depth: int = 0, budget: list[int] | None = None
) -> None:
    if budget is None:
        budget = [MAX_CANONICAL_NODES]
    if depth > MAX_CANONICAL_DEPTH:
        raise PolicyBundleError(
            f"policy document nests deeper than {MAX_CANONICAL_DEPTH} levels"
        )
    budget[0] -= 1
    if budget[0] < 0:
        raise PolicyBundleError(
            f"policy document exceeds {MAX_CANONICAL_NODES} canonical nodes"
        )
    if node is None or isinstance(node, (bool, str)):
        return
    if isinstance(node, float):
        raise PolicyBundleError("policy document carries a float; integers only")
    if isinstance(node, int):
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                raise PolicyBundleError("policy document has a non-string object key")
            _check_canonical(value, depth=depth + 1, budget=budget)
        return
    if isinstance(node, (list, tuple)):
        for value in node:
            _check_canonical(value, depth=depth + 1, budget=budget)
        return
    raise PolicyBundleError(
        f"policy document carries an unserialisable {type(node).__name__}"
    )


def strict_int(value: Any, field: str, *, low: int, high: int) -> int:
    """Return ``value`` as an int, refusing ``bool`` and any out-of-range value.

    ``bool`` subclasses ``int`` in Python, so ``isinstance(value, int)`` accepts
    ``True`` as ``1``. An amount of ``true`` must never become one unit of mass.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyBundleError(
            f"{field} must be an integer, not {type(value).__name__}"
        )
    if not (low <= value <= high):
        raise PolicyBundleError(f"{field} is {value}, outside [{low}, {high}]")
    return value


def strict_bool(value: Any, field: str) -> bool:
    """Return ``value`` as a bool, refusing ints and truthy strings."""
    if not isinstance(value, bool):
        raise PolicyBundleError(
            f"{field} must be a JSON boolean, not {type(value).__name__}"
        )
    return value


def strict_str(value: Any, field: str, *, max_length: int = 256) -> str:
    """Return ``value`` as a non-empty bounded string."""
    if not isinstance(value, str):
        raise PolicyBundleError(f"{field} must be a string, not {type(value).__name__}")
    if not value or len(value) > max_length:
        raise PolicyBundleError(
            f"{field} must be 1..{max_length} characters, got {len(value)}"
        )
    return value


def strict_object(value: Any, field: str) -> dict[str, Any]:
    """Return ``value`` as a plain JSON object with string keys.

    A read-only mapping is accepted and copied: parsed bundles hand their
    document around as a ``MappingProxyType`` so a caller cannot mutate what was
    hashed, and that proxy is not a ``dict`` subclass.
    """
    if not isinstance(value, Mapping):
        raise PolicyBundleError(f"{field} must be a JSON object")
    for key in value:
        if not isinstance(key, str):
            raise PolicyBundleError(f"{field} has a non-string key")
    return dict(value)


def exact_keys(document: dict[str, Any], expected: frozenset[str], label: str) -> None:
    """Refuse unknown and missing keys.

    Unknown keys halt rather than being ignored: a document carrying a field
    this composer does not understand may be paying somewhere it cannot see.
    """
    present = set(document)
    unknown = sorted(present - expected)
    missing = sorted(expected - present)
    if unknown:
        raise PolicyBundleError(f"{label} has unknown keys: {', '.join(unknown)}")
    if missing:
        raise PolicyBundleError(f"{label} is missing keys: {', '.join(missing)}")


def parse_strict_json(raw: bytes, *, max_bytes: int | None = None) -> Any:
    """Parse ``raw`` refusing duplicate keys and non-finite numbers.

    Used by both the HTTPS fetch and any local file load, so the two paths
    cannot disagree about which bytes are acceptable.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise PolicyBundleError("policy document must be parsed from bytes")
    if max_bytes is not None and len(raw) > max_bytes:
        raise PolicyBundleError(
            f"policy document is {len(raw)} bytes, over the {max_bytes} byte bound"
        )

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PolicyBundleError(f"policy JSON has duplicate key {key!r}")
            result[key] = value
        return result

    def finite_float(text: str) -> float:
        value = float(text)
        if not math.isfinite(value):
            raise PolicyBundleError("policy JSON has non-finite numbers")
        # A finite float is still refused by the canonical walk and by every
        # amount parser; returning it keeps the failure in one place.
        return value

    def refuse_constant(name: str) -> Any:
        raise PolicyBundleError(f"policy JSON has the non-finite constant {name}")

    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyBundleError("policy document is not valid UTF-8") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=no_duplicates,
            parse_float=finite_float,
            parse_constant=refuse_constant,
        )
    except json.JSONDecodeError as exc:
        raise PolicyBundleError(f"policy document is not valid JSON: {exc}") from exc
    return document


__all__ = [
    "MAX_CANONICAL_DEPTH",
    "MAX_CANONICAL_NODES",
    "canonical_bytes",
    "exact_keys",
    "parse_strict_json",
    "strict_bool",
    "strict_int",
    "strict_object",
    "strict_str",
]
