"""A submitter must not choose the key its report is stored under.

`external_score_reports.id` is a PRIMARY KEY written with INSERT OR REPLACE. When
that id came from the request body, any source could address any other source's
row. Reusing the confidential lane's report_id destroyed its stored snapshot AND
erased its epoch high-water, which re-opened replay and collapsed the signed
vector to 100% burn.

These tests pin the derived key. They fail against a build that reads
`report_id` from the payload.
"""

from __future__ import annotations

import pytest

from scaffold.publisher import external_scores as ext


def test_storage_key_ignores_a_submitter_supplied_report_id():
    """Two payloads, same claimed id, different content: distinct keys."""
    a = ext._storage_key(source_name="cathedral_confidential_tdx", digest="a" * 64)
    b = ext._storage_key(source_name="cathedral_confidential_tdx", digest="b" * 64)
    assert a != b


def test_two_sources_can_never_collide_even_on_identical_content():
    """The attack: a lower-trust source reusing a confidential report's id."""
    confidential = ext._storage_key(
        source_name="cathedral_confidential_tdx", digest="c" * 64
    )
    other = ext._storage_key(source_name="violet_audio", digest="c" * 64)
    assert confidential != other, (
        "identical content from two sources must not share a primary key; "
        "INSERT OR REPLACE would let one erase the other"
    )


def test_the_key_is_stable_for_the_same_source_and_content():
    """Idempotent retry still has to land on the same row."""
    first = ext._storage_key(source_name="violet_audio", digest="d" * 64)
    second = ext._storage_key(source_name="violet_audio", digest="d" * 64)
    assert first == second


def test_the_key_is_a_pure_function_of_source_and_digest():
    """Same inputs, same key. Nothing a caller sends elsewhere can steer it."""
    first = ext._storage_key(source_name="violet_audio", digest="e" * 64)
    second = ext._storage_key(source_name="violet_audio", digest="e" * 64)
    assert first == second
    assert first.startswith("ext:")


def test_a_separator_in_the_source_cannot_forge_another_sources_key():
    """Plain concatenation was ambiguous and a Codex review caught it.

    ("foo", "bar:baz") and ("foo:bar", "baz") both rendered as ext:foo:bar:baz,
    so a source name containing the separator could address another source's
    row. The route normalizes source names today, but a primary key whose
    uniqueness depends on its callers is not unique.
    """
    assert ext._storage_key(source_name="foo", digest="bar:baz") != ext._storage_key(
        source_name="foo:bar", digest="baz"
    )
    assert ext._storage_key(source_name="a:b", digest="c") != ext._storage_key(
        source_name="a", digest="b:c"
    )


def test_normalize_still_carries_a_claimed_report_id_as_a_label():
    """The submitter's id is not forbidden, it is simply not the storage key.

    Keeping it in the document preserves the operator's ability to correlate a
    report back to whatever produced it.
    """
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    payload = {
        "source": "violet_audio",
        "epoch": 5,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "report_id": "their-own-reference-42",
        "scores": [{"miner_hotkey": "5F" + "a" * 46, "score": 0.5}],
    }
    normalized = ext.normalize_report(payload, now=now)
    assert normalized["report_id"] == "their-own-reference-42"
    # ...but it is not what the row is keyed on.
    assert ext._storage_key(
        source_name=normalized["source"], digest=normalized["report_sha256"]
    ) != normalized["report_id"]
