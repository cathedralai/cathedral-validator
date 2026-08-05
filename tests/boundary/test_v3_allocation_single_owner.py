"""Proof that the v3 CyberGym lane has exactly one owner of its wire shape.

The v3 allocation contract is written down twice by necessity: the publisher
composes `policy_metadata["cybergym_lane"]` and the validator admits it. That
split is deliberate — the validator must re-derive the lane's values instead of
trusting the process that produced them — but it means the lane's KEY SET is a
contract between two files that can drift apart while both still look correct
in review.

Drift there is not a soft failure. The validator admits the lane by exact-set
equality, so a field present on one side and absent on the other rejects every
vector for the whole epoch. And the same shape exists divergently outside this
repository: `cathedralai/cathedral`'s unmerged `feat/allocation-v3-70-30-0`
composes a six-field lane with no `uid_hotkeys`, which this validator refuses.
That branch is the fork hazard BOUNDARY.md rules out, and the last test here is
its regression: a lane shaped like that one must never be admitted.

These tests hold the single-owner claim to account rather than asserting it in
prose.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from scaffold import validator_thin, wire_vector
from scaffold.publisher import weights

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# The shape as of the v3 contract. Spelled out here, independently of the
# constant under test, so that changing the constant alone cannot make these
# tests vacuously agree with themselves.
EXPECTED_LANE_FIELDS = frozenset(
    {
        "fraction",
        "weights",
        "contributing_fraction",
        "forfeited_fraction",
        "burn_uid",
        "uid_hotkeys",
        "cybergym",
    }
)

# Where the shared constant is allowed to be defined and referenced. Any other
# site spelling the set out longhand is the duplication this file exists to
# prevent.
OWNER_MODULE = "scaffold/wire_vector.py"
CONSUMER_SITES = ("scaffold/validator_thin.py", "scaffold/publisher/weights.py")


def _tracked_python_files() -> list[pathlib.Path]:
    # `.claude` holds agent worktrees — whole second checkouts of this repo — so
    # every source file would otherwise appear twice and this scan would report
    # phantom duplicate definitions that CI (a fresh clone) never sees.
    skip_parts = {
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".venv",
        "venv",
        "env",
        ".tox",
        "site-packages",
        "build",
        "dist",
        ".claude",
    }
    return sorted(
        path
        for path in REPO_ROOT.rglob("*.py")
        if not skip_parts.intersection(path.relative_to(REPO_ROOT).parts)
    )


def _literal_field_sets(path: pathlib.Path) -> list[int]:
    """Line numbers of set/dict literals whose keys are exactly the lane fields.

    Matching on the full key set rather than on individual names keeps this from
    firing on unrelated code that happens to mention `weights` or `burn_uid`.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Set):
            names = {
                elt.value
                for elt in node.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            }
        elif isinstance(node, ast.Dict):
            names = {
                key.value
                for key in node.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
        else:
            continue
        if names == set(EXPECTED_LANE_FIELDS):
            hits.append(node.lineno)
    return hits


def test_the_constant_is_the_shape_the_contract_specifies() -> None:
    assert wire_vector.V3_CYBERGYM_LANE_FIELDS == EXPECTED_LANE_FIELDS


def test_the_constant_is_immutable() -> None:
    """A mutable set here could be edited by one importer for every other."""
    assert isinstance(wire_vector.V3_CYBERGYM_LANE_FIELDS, frozenset)


def test_both_sides_share_the_same_object() -> None:
    """Not merely equal values — the same object, so they cannot drift."""
    assert weights.V3_CYBERGYM_LANE_FIELDS is wire_vector.V3_CYBERGYM_LANE_FIELDS
    assert validator_thin.wire.V3_CYBERGYM_LANE_FIELDS is (
        wire_vector.V3_CYBERGYM_LANE_FIELDS
    )


def test_the_lane_shape_is_spelled_out_in_exactly_one_place() -> None:
    """No second longhand copy of the key set in shipped code.

    Two sites are legitimate: `wire_vector.py` defines the constant, and
    `weights.py` builds the dict that the constant describes — and that literal
    is checked against the constant before it returns.

    Test fixtures are excluded on purpose. A fixture that builds a stale lane
    cannot drift silently: the admission check under test compares the whole key
    set, so a fixture left behind fails immediately and loudly. Shipped code is
    where a second longhand copy would sit unnoticed until an epoch broke.
    """
    allowed = {OWNER_MODULE, "scaffold/publisher/weights.py"}
    offenders = []
    for path in _tracked_python_files():
        rel = str(path.relative_to(REPO_ROOT))
        if rel in allowed:
            continue
        if "tests" in path.relative_to(REPO_ROOT).parts or path.name.startswith(
            "test_"
        ):
            continue
        for lineno in _literal_field_sets(path):
            offenders.append(f"{rel}:{lineno}")
    assert not offenders, (
        "the v3 CyberGym lane key set is spelled out longhand outside "
        f"{OWNER_MODULE}; import wire_vector.V3_CYBERGYM_LANE_FIELDS instead:\n"
        + "\n".join(offenders)
    )


def test_the_scan_finds_files_at_all() -> None:
    """A skip list matching the repo's own path would prove nothing."""
    files = _tracked_python_files()
    assert len(files) > 100, (
        f"the tracked-file scan found only {len(files)} files; the skip list is "
        "almost certainly matching a component of the repo's own path"
    )
    assert any(p.name == "validator_thin.py" for p in files)


def test_the_scan_can_actually_detect_a_duplicate(tmp_path: pathlib.Path) -> None:
    """Negative control: the detector fires on a planted longhand copy.

    Without this, a detector that silently matched nothing would let every
    duplicate through while this file reported success.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(
        "expected = {\n"
        + "".join(f"    {name!r},\n" for name in sorted(EXPECTED_LANE_FIELDS))
        + "}\n",
        encoding="utf-8",
    )
    assert _literal_field_sets(planted) == [1]


def test_a_lane_without_uid_hotkeys_is_refused() -> None:
    """The cathedral-branch shape must not be admissible.

    `feat/allocation-v3-70-30-0` composes every field below and no
    `uid_hotkeys`. A validator that accepted it would credit the CyberGym lane
    by UID with nothing binding those UIDs to the hotkeys that earned them.
    """
    cathedral_branch_shape = EXPECTED_LANE_FIELDS - {"uid_hotkeys"}
    assert cathedral_branch_shape != wire_vector.V3_CYBERGYM_LANE_FIELDS
    assert "uid_hotkeys" in wire_vector.V3_CYBERGYM_LANE_FIELDS


def test_the_publisher_refuses_to_emit_a_lane_of_the_wrong_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The compose-time guard fires rather than shipping a rejected vector.

    Driving this through the real `_compose_cybergym_lane_v3` keeps the check
    honest: it proves the guard sits on the path that actually builds the lane,
    not on a copy of it. The bridge is stubbed to return a well-formed lane, and
    the shared constant is widened so the composed dict is the thing that no
    longer matches.
    """
    from scaffold.publisher import cybergym_bridge

    monkeypatch.setattr(cybergym_bridge, "mechanism_enabled", lambda: True)
    monkeypatch.setattr(
        cybergym_bridge, "weight_fraction", lambda: weights.V3_CYBERGYM_ALLOCATION
    )
    monkeypatch.setattr(
        cybergym_bridge,
        "cybergym_allocation",
        lambda store, *, now: {
            "status": "ok",
            "weights": {"250": weights.V3_CYBERGYM_ALLOCATION},
            "uid_hotkeys": {"250": "5FakeHotkeyForTheLaneShapeGuard"},
            "contributing_fraction": weights.V3_CYBERGYM_ALLOCATION,
            "forfeited_fraction": 0.0,
            "burn_uid": None,
            "cybergym": {},
        },
    )

    # Sanity: with the real contract the compose succeeds and matches the shape.
    lane = weights._compose_cybergym_lane_v3(object(), now=None)
    assert set(lane) == wire_vector.V3_CYBERGYM_LANE_FIELDS

    monkeypatch.setattr(
        weights,
        "V3_CYBERGYM_LANE_FIELDS",
        wire_vector.V3_CYBERGYM_LANE_FIELDS | {"a_field_the_validator_never_admits"},
    )
    with pytest.raises(weights.VectorError, match="does not match the wire contract"):
        weights._compose_cybergym_lane_v3(object(), now=None)


def test_boundary_doc_records_the_ownership() -> None:
    text = (REPO_ROOT / "BOUNDARY.md").read_text(encoding="utf-8")
    assert "V3_CYBERGYM_LANE_FIELDS" in text
    assert "not a v3 allocation source" in text
