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
That branch is the fork hazard BOUNDARY.md rules out.

The file has two halves, and the second is the one that matters most:

  * shape ownership — the constant is defined once, both sides import the same
    object, and no shipped module spells the key set out longhand again;
  * ADMISSION — the refusals the shape exists to produce, driven through
    `vector_to_uid_weights` against a real v3 vector and a real metagraph
    mapping. Asserting on the constant proves only that the constant says what
    it says; these tests fail if the code that reads it stops enforcing it.

Behind the shape check sits the reason the lane carries `uid_hotkeys` at all:
the validator re-derives every recipient by checking the signed UID->hotkey
binding against THIS tick's metagraph. Without that, the 30% lane pays whoever
holds the UID when weights are set, not the miner who earned it. Two admission
tests here — the missing-field refusal and the rebound-UID refusal — are the
regression for exactly that, and were written by mutating the validator to
break each one and confirming they went red.

These tests hold the single-owner claim to account rather than asserting it in
prose.
"""

from __future__ import annotations

import ast
import copy
import math
import pathlib
from typing import Any

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


# ---- admission: the refusals the shape exists to produce ---------------------
#
# Everything above reasons about the constant. Nothing above would notice if
# `_validated_supply_v3_to_uid_weights` stopped comparing against it, or stopped
# re-deriving recipients from the signed UID->hotkey bindings. These tests drive
# that function through the public entry point so that they do.

V3_PIN = validator_thin.REQUIRE_POLICY_VALIDATED_SUPPLY_V3
BURN_HOTKEY = "burn-hotkey"

# The metagraph as this tick reads it. Every refusal below is a disagreement
# between a signed vector and THIS mapping.
LIVE_METAGRAPH = {
    BURN_HOTKEY: 0,
    "tdx-a": 10,
    "tdx-b": 11,
    "cyber-a": 50,
    "cyber-b": 51,
}


def _well_formed_lane() -> dict[str, Any]:
    """A CyberGym lane that agrees with LIVE_METAGRAPH in every particular."""
    return {
        "fraction": 0.30,
        "weights": {"50": 0.18, "51": 0.12},
        "contributing_fraction": 0.30,
        "forfeited_fraction": 0.0,
        "burn_uid": None,
        "uid_hotkeys": {"50": "cyber-a", "51": "cyber-b"},
        "cybergym": {"reason": "ok"},
    }


def _v3_vector(lane: dict[str, Any] | None = None) -> dict[str, Any]:
    """A signed-shaped v3 vector: 70% Intel TDX, 30% CyberGym, 0% fixed burn."""
    return {
        "weights": [
            {
                "miner_hotkey": "tdx-a",
                "weight": 0.6,
                "base_component": 0.0,
                "external_component": 0.6,
            },
            {
                "miner_hotkey": "tdx-b",
                "weight": 0.4,
                "base_component": 0.0,
                "external_component": 0.4,
            },
        ],
        "burn_snapshot": {
            "burn_uid": None,
            "burn_hotkey": BURN_HOTKEY,
            "forced_burn_percentage": 0.0,
        },
        "policy_metadata": {
            "confidential_primary": {
                "contract_version": "v1",
                "mode": "confidential_primary",
                "source": "cathedral_confidential_tdx",
                "base_mass": 0.0,
                "confidential_mass": 1.0,
                "complete": True,
                "fresh": True,
                "confirmed": True,
            },
            "validated_supply": {
                "contract_version": "v3",
                "intel_tdx_allocation": 0.70,
                "cybergym_allocation": 0.30,
                "fixed_burn_allocation": 0.0,
                "burn_hotkey": BURN_HOTKEY,
            },
            "cybergym_lane": _well_formed_lane() if lane is None else lane,
        },
    }


def _admit(vector: dict[str, Any], metagraph: dict[str, int]) -> dict[int, float]:
    return validator_thin.vector_to_uid_weights(
        vector, metagraph, require_policy=V3_PIN
    )


def test_the_admitted_lane_is_the_shape_the_constant_describes() -> None:
    """Positive control for every refusal below.

    Without this, a fixture broken in some unrelated way would make the refusal
    tests pass for the wrong reason — they would be watching the validator
    reject a vector it was always going to reject. This pins the baseline: the
    fixture is admissible, it carries exactly the owned key set, and it pays the
    70/30 split to the miners the bindings name.
    """
    assert set(_well_formed_lane()) == wire_vector.V3_CYBERGYM_LANE_FIELDS

    out = _admit(_v3_vector(), LIVE_METAGRAPH)

    assert out[10] == pytest.approx(0.42)  # 0.6 of the 70% Intel TDX lane
    assert out[11] == pytest.approx(0.28)
    assert out[50] == pytest.approx(0.18)  # the 30% CyberGym lane
    assert out[51] == pytest.approx(0.12)
    assert 0 not in out  # nothing forfeited, so burn collects nothing
    assert math.isclose(math.fsum(out.values()), 1.0, abs_tol=1e-12)


def test_a_lane_without_uid_hotkeys_is_refused() -> None:
    """The cathedral-branch shape must not be admissible.

    `feat/allocation-v3-70-30-0` composes every other field and no
    `uid_hotkeys`. A validator that accepted it would credit the CyberGym lane
    by UID with nothing binding those UIDs to the hotkeys that earned them: the
    30% would go to whoever holds each UID at mapping time.

    This drives the real admission path. Asserting that the constant contains
    `uid_hotkeys` would prove only that the constant contains `uid_hotkeys`;
    relaxing the admission check to a subset test would leave that assertion
    green and the lane admitted.
    """
    lane = _well_formed_lane()
    del lane["uid_hotkeys"]
    assert set(lane) == EXPECTED_LANE_FIELDS - {"uid_hotkeys"}  # the fork's shape

    with pytest.raises(
        validator_thin.wire.VectorError, match="cybergym_lane fields mismatch"
    ):
        _admit(_v3_vector(lane), LIVE_METAGRAPH)


@pytest.mark.parametrize("field", sorted(EXPECTED_LANE_FIELDS))
def test_a_lane_missing_any_owned_field_is_refused(field: str) -> None:
    """The whole key set is load-bearing, not just `uid_hotkeys`.

    Exact-set equality is what makes the constant a contract rather than a
    suggestion. Parametrizing over the set welds it to the admission path: drop
    any single field the constant owns and the vector is refused.
    """
    lane = _well_formed_lane()
    del lane[field]

    with pytest.raises(
        validator_thin.wire.VectorError, match="cybergym_lane fields mismatch"
    ):
        _admit(_v3_vector(lane), LIVE_METAGRAPH)


def test_a_lane_carrying_an_unowned_field_is_refused() -> None:
    """The other direction of the equality: a superset is not admissible either.

    A publisher that grew a field this validator does not know about is a
    publisher this validator has not agreed with. Fail closed and let the
    coordinated re-pin admit it.
    """
    lane = _well_formed_lane()
    lane["a_field_the_validator_never_agreed_to"] = 1

    with pytest.raises(
        validator_thin.wire.VectorError, match="cybergym_lane fields mismatch"
    ):
        _admit(_v3_vector(lane), LIVE_METAGRAPH)


def test_a_lane_whose_uid_hotkeys_disagree_with_the_metagraph_is_refused() -> None:
    """A rebound UID must not collect the miner's share.

    The lane was composed when `cyber-a` held UID 50. By the time weights are
    set, `cyber-a` has moved to 52 and UID 50 belongs to `a-newcomer`. The
    signed weights still say 0.18 to UID 50. Paying that is paying the
    newcomer for work `cyber-a` did.

    This is the test that fails if the UID-rebinding loop is deleted: every
    other check in the lane still passes, because the lane is internally
    consistent — it is only wrong about the world.
    """
    moved = {**LIVE_METAGRAPH, "cyber-a": 52, "a-newcomer": 50}

    with pytest.raises(
        validator_thin.wire.VectorError,
        match="recipient UID does not match the current hotkey",
    ):
        _admit(_v3_vector(), moved)


def test_a_lane_naming_a_deregistered_hotkey_is_refused() -> None:
    """The same guard, for the case where the miner is simply gone.

    `cyber-b` deregistered between compose and admission, so the mapping has no
    UID for it at all. `hotkey_to_uid.get(...)` returning None must refuse, not
    quietly compare unequal-and-continue or pay UID 51 to its next holder.
    """
    deregistered = {k: v for k, v in LIVE_METAGRAPH.items() if k != "cyber-b"}

    with pytest.raises(
        validator_thin.wire.VectorError,
        match="recipient UID does not match the current hotkey",
    ):
        _admit(_v3_vector(), deregistered)


def test_the_forfeit_burn_uid_is_re_derived_from_the_burn_hotkey() -> None:
    """Forfeited mass follows the same rule as miner mass: re-derive, never trust.

    A lane that resolved its forfeited share to UID 7 when the burn hotkey held
    UID 7 must be refused once the burn hotkey is UID 0, rather than paying the
    forfeited 30% to whoever holds 7 now.
    """
    lane = _well_formed_lane()
    lane["weights"] = {"7": 0.30}
    lane["uid_hotkeys"] = {"7": BURN_HOTKEY}
    lane["contributing_fraction"] = 0.0
    lane["forfeited_fraction"] = 0.30
    lane["burn_uid"] = 7

    with pytest.raises(validator_thin.wire.VectorError, match="does not match"):
        _admit(_v3_vector(lane), LIVE_METAGRAPH)


def test_the_admission_path_reads_the_shared_constant_not_a_private_copy() -> None:
    """Widening the owned set widens what the validator admits — same object.

    If the validator ever compared against its own longhand copy, this would
    still refuse and the single-owner claim would be false while every other
    test here stayed green. Monkeypatching is confined to this test.
    """
    lane = _well_formed_lane()
    lane["an_experimental_field"] = 1

    with pytest.raises(
        validator_thin.wire.VectorError, match="cybergym_lane fields mismatch"
    ):
        _admit(_v3_vector(copy.deepcopy(lane)), LIVE_METAGRAPH)

    widened = wire_vector.V3_CYBERGYM_LANE_FIELDS | {"an_experimental_field"}
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(validator_thin.wire, "V3_CYBERGYM_LANE_FIELDS", widened)
        out = _admit(_v3_vector(copy.deepcopy(lane)), LIVE_METAGRAPH)
    assert out[50] == pytest.approx(0.18)


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
