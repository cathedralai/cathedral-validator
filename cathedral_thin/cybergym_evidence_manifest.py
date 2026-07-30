"""The canonical CyberGym evidence manifest: what `evidence_sha256` actually commits to.

Why this exists. The producer's report carries an `evidence_sha256`, but nothing tied
it to the work being paid for. The field is producer-chosen, so whoever holds the
shared secret can re-sign any 64-hex string, and an operator pin only anchors it to a
value a human typed. Neither proves the digest describes the receipts that earned.

This module defines the one thing it must commit to: a canonical manifest over the
FINAL verified and credited CyberGym receipts for one audience epoch. The producer
builds it from the receipts it scored; the validator REBUILDS it from the receipts it
admitted and requires exact equality before any epoch claim or consumption. A producer
that scored a different set, different amounts, or different receipts cannot produce a
matching digest, so the two sides either agree exactly or the lane burns.

Why these fields and no others:

  * `schema` is inside the digested body, so the hash is domain separated: a digest
    over some other structure cannot collide with one over this one by construction.
  * `network`, `netuid` and `source_epoch` bind it to one audience and one epoch, so a
    manifest cannot be lifted from another subnet or replayed from another epoch.
  * each entry is `{miner_hotkey, receipt_id, work_units}` and nothing more.
    `receipt_id` already commits to the signed batch, result and items_root, so
    including it transitively binds the underlying work without restating it.
    `work_units` is the exact quantity composed, as its canonical decimal STRING, so
    float formatting can never change the digest.
  * entries are sorted, so two honest implementations agree regardless of iteration
    order.

An empty funded epoch is a real state, not an error: the manifest has no entries and
its digest is deterministic, so "the producer scored nobody this epoch" is itself
attestable rather than indistinguishable from a missing manifest.

This file is duplicated byte-for-byte in Cathedral's `cybergym_contract` and in
cathedral-distill's producer builder, because no import spans the three repositories.
`test_cybergym_evidence_manifest.py` pins the schema string and the empty digest so
drift fails a test rather than silently failing to verify a real producer report.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping

SCHEMA = "cathedral_cybergym_evidence_manifest_v1"


class EvidenceManifestError(ValueError):
    """The manifest could not be built from the given entries."""


def _canonical_units(value: Any) -> str:
    """The exact quantity as a canonical decimal string.

    A string rather than a float: 12, 12.0 and "12.000" must all digest identically on
    both sides, and float repr is not a contract.
    """
    try:
        quantity = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise EvidenceManifestError(f"work_units {value!r} is not a decimal") from exc
    if not quantity.is_finite() or quantity < 0:
        raise EvidenceManifestError(
            f"work_units {value!r} is not a finite non-negative"
        )
    normalized = quantity.normalize()
    # normalize() renders integers in exponent form (1E+1); expand those back.
    if normalized == normalized.to_integral_value():
        normalized = normalized.quantize(Decimal(1))
    return format(normalized, "f")


def build_manifest(
    *,
    network: str,
    netuid: int,
    source_epoch: int,
    entries: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """The canonical manifest body. ``entries`` may be in any order."""
    rows = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        hotkey = str(entry["miner_hotkey"])
        receipt_id = str(entry["receipt_id"])
        key = (hotkey, receipt_id)
        if key in seen:
            raise EvidenceManifestError(f"duplicate entry for {hotkey} / {receipt_id}")
        seen.add(key)
        rows.append(
            {
                "miner_hotkey": hotkey,
                "receipt_id": receipt_id,
                "work_units": _canonical_units(entry["work_units"]),
            }
        )
    rows.sort(key=lambda row: (row["miner_hotkey"], row["receipt_id"]))
    return {
        "schema": SCHEMA,
        "network": str(network),
        "netuid": int(netuid),
        "source_epoch": int(source_epoch),
        "entries": rows,
    }


def canonical_bytes(manifest: Mapping[str, Any]) -> bytes:
    """sort_keys + compact separators + UTF-8, the same canonicalization as the report."""
    return json.dumps(
        dict(manifest), sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def manifest_digest(
    *,
    network: str,
    netuid: int,
    source_epoch: int,
    entries: Iterable[Mapping[str, Any]],
) -> str:
    """The 64 lowercase hex digest a report's ``evidence_sha256`` must equal."""
    manifest = build_manifest(
        network=network, netuid=netuid, source_epoch=source_epoch, entries=entries
    )
    return hashlib.sha256(canonical_bytes(manifest)).hexdigest()


def empty_digest(*, network: str, netuid: int, source_epoch: int) -> str:
    """The digest of a funded epoch in which the producer credited nobody."""
    return manifest_digest(
        network=network, netuid=netuid, source_epoch=source_epoch, entries=()
    )


__all__ = [
    "SCHEMA",
    "EvidenceManifestError",
    "build_manifest",
    "canonical_bytes",
    "manifest_digest",
    "empty_digest",
]
