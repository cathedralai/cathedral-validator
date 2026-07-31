"""The derived-from SHA is recorded in three places; they must agree.

`MANIFEST.origin.tsv` carries the machine-checked copy: CI reads the SHA out of
its header, clones upstream at exactly that commit, and fails if one mirrored
byte differs. `README.md` and `BOUNDARY.md` carry human-written copies, and a
human has to remember to move them.

One did not get moved. Between the `5c38016` sync and the `ebc65f0` one, both
documents still claimed `dabf10b` while the manifest already said `5c38016` --
so a reader following the README would have cloned upstream at the wrong commit
to reproduce this tree, and nothing anywhere would have contradicted them. It
was found by hand, twice, and the second time it had been wrong across a merge.

Prose the manifest cannot contradict is prose that drifts. This makes the
documented SHA a checked claim: the manifest stays authoritative and the two
documents are compared against it, never the other way round.

Each document is read through one explicit anchor rather than by scanning for
hex, because not every SHA in these files is an upstream one -- `BOUNDARY.md`
also lists the `cathedral-compute` provenance pin and a table of superseded
derived-from values, and both are correct where they stand. If an anchor stops
matching, that is a real signal too: the sentence stating what this tree is
derived from was reworded or removed, and it needs a look.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

MANIFEST = REPO_ROOT / "MANIFEST.origin.tsv"

_UPSTREAM_HEADER = re.compile(r"^#\s*Upstream:\s*\S+\s*@\s*([0-9a-f]{40})\s*$")

# One anchor per place a human states the CURRENT derived-from commit. Written
# to survive reflowing and re-linking, not to survive the claim being deleted.
ANCHORS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "README.md",
        re.compile(
            r"extracted from.{0,200}?\b([0-9a-f]{40})\b",
            re.DOTALL | re.IGNORECASE,
        ),
        "the status banner's 'extracted from ... at commit <sha>'",
    ),
    (
        "BOUNDARY.md",
        re.compile(r"Current derived-from SHA.{0,120}?\b([0-9a-f]{40})\b", re.DOTALL),
        "the Derived-from table's 'Current derived-from SHA' row",
    ),
)


def _manifest_sha() -> str:
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        match = _UPSTREAM_HEADER.match(line)
        if match:
            return match.group(1)
    raise AssertionError(
        f"{MANIFEST.name} has no '# Upstream: <repo> @ <sha>' header. CI reads the "
        "derived-from SHA from that line to clone upstream, so without it the "
        "byte-identity check has nothing to check against."
    )


def test_manifest_declares_a_derived_from_sha() -> None:
    assert len(_manifest_sha()) == 40


@pytest.mark.parametrize(
    ("doc_name", "anchor", "where"),
    ANCHORS,
    ids=[name for name, _, _ in ANCHORS],
)
def test_documented_derived_from_sha_matches_the_manifest(
    doc_name: str, anchor: re.Pattern[str], where: str
) -> None:
    text = (REPO_ROOT / doc_name).read_text(encoding="utf-8")

    match = anchor.search(text)
    assert match is not None, (
        f"{doc_name} no longer states its derived-from commit where this test "
        f"looks for it ({where}). Either restore the statement or move this "
        "anchor -- do not delete the check; an unstated derived-from SHA is how "
        "the documented one silently went stale before."
    )

    documented, expected = match.group(1), _manifest_sha()
    assert documented == expected, (
        f"{doc_name} says this tree is derived from {documented[:7]}, but "
        f"{MANIFEST.name} -- which CI actually clones against -- records "
        f"{expected[:7]}. A re-sync moved the manifest and left the prose behind; "
        "see the re-sync checklist in BOUNDARY.md, step 6."
    )
