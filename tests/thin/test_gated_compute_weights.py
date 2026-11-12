"""The gated weight split: approved compute lane, escape lane, burn.

Owner decision of 12 Nov 2026. Only hotkeys on the release's approved list
earn compute weight (10 percent of the vector), escape breakers share 10
percent, and everything else goes to the subnet owner hotkey, which the chain
burns. A lane with no recipient is burned, never redistributed.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import replace
from pathlib import Path

import pytest

import test_direct_commit_reveal as commit_reveal
import test_direct_validator as base
from cathedral_thin.independent.constants import NETUID, VERSION_KEY, W
from cathedral_thin.independent_runtime import approved_miners
from cathedral_thin.independent_runtime import direct_writer as writer_runtime
from cathedral_thin.independent_runtime.approved_miners import (
    PINNED_APPROVED_MINERS_SHA256,
    ApprovedMinersError,
    load_approved_miners,
)
from cathedral_thin.independent_runtime.direct_contract import (
    COMPUTE_LANE_SHARE,
    DIRECT_VERSION_KEY,
    ESCAPE_LANE_SHARE,
    PRIOR_DIRECT_VERSION_KEYS,
    SUBNET_OWNER_BURN_HOTKEYS,
    DirectValidatorError,
    FinalizedMetagraphSnapshot,
    gated_split_vector,
)
from cathedral_thin.independent_runtime.direct_validator import build_direct_plan
from cathedral_thin.independent_runtime.direct_writer import (
    STATUS_COMMITTED,
    STATUS_CONFIRMED,
    STATUS_RECOVERED,
    STATUS_REVEALED,
    DirectSubmissionAmbiguous,
    DirectSubmissionContradiction,
)
from cathedral_thin.independent_runtime.telemetry import (
    build_telemetry_snapshot,
    validate_public_telemetry_event,
)

REPO = Path(__file__).resolve().parents[2]
LANE = 6553  # 10 percent of 65535, floored
BURN_UID = base.BURN_UID


@pytest.fixture(autouse=True)
def approved_compute_hotkeys(monkeypatch):
    """Replace the suite-wide "approve everyone" list with the release list.

    Returns a setter, so each test names exactly who is approved.
    """

    def approve(*hotkeys: str) -> None:
        monkeypatch.setattr(
            approved_miners, "APPROVED_COMPUTE_HOTKEYS", frozenset(hotkeys)
        )

    approve(*approved_miners._pinned_approved_miners())
    return approve


def split(scores, hotkeys, *, approved=(), escape=(), escape_hotkeys=None):
    uids, weights = gated_split_vector(
        tuple(scores),
        hotkeys,
        approved_hotkeys=frozenset(approved),
        escape_units=tuple(escape),
        escape_uid_hotkeys=escape_hotkeys or {},
        burn_uid=BURN_UID,
    )
    assert sum(weights) == W
    return dict(zip(uids, weights, strict=True))


def verified_plan(*counts: tuple[base.ServingAxon, int]):
    """A direct plan in which each miner has ``count`` verified machines."""

    miners = tuple(miner for miner, _count in counts)
    rows = tuple(
        base.machine_row(str(index), uid=miner.uid, hotkey=miner.hotkey)
        for miner, count in counts
        for index in range(count)
    )
    return build_direct_plan(
        base.snapshot(miners=miners), base.round_result(*rows, miners=miners)
    )


# The list that ships in the release -----------------------------------------


def test_the_shares_and_the_burn_pin_are_what_the_owner_set() -> None:
    assert COMPUTE_LANE_SHARE * 10 == 1
    assert ESCAPE_LANE_SHARE * 10 == 1
    assert int(COMPUTE_LANE_SHARE * W) == int(ESCAPE_LANE_SHARE * W) == LANE
    assert (
        SUBNET_OWNER_BURN_HOTKEYS[NETUID]
        == "5FQsFkui1UvS7S7Sf3JAqN9FPCR7RmufSEZTGuVPPN5EDmsN"
    )


OWNER_MINER_HOTKEYS = frozenset(
    {
        "5Ci4hDP6Fc7CDMy5uxZUnjQF2QgdK2HYpLt1MrWmV2vi9ujw",
        "5FTS68kHHrG7c9XYDyiCzfVnuqNJBk1uWV1D9vN4YwkQ3Ztq",
        "5GejPbqLvfrLGdrjLzHN59TQ5c7KuWWDVajFAz8r7pSG2TKq",
    }
)


def test_the_release_list_is_the_reviewed_file_with_the_three_owner_hotkeys() -> None:
    from bittensor.utils import is_valid_ss58_address

    raw = (REPO / "config/compute/approved-miners.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PINNED_APPROVED_MINERS_SHA256
    listed = load_approved_miners(raw, expected_sha256=PINNED_APPROVED_MINERS_SHA256)
    assert listed == approved_miners._pinned_approved_miners() == OWNER_MINER_HOTKEYS
    assert all(is_valid_ss58_address(hotkey) for hotkey in listed)
    # Never the burn destination, and never the wallet's default hotkey.
    assert SUBNET_OWNER_BURN_HOTKEYS[NETUID] not in listed
    assert not any(hotkey.startswith("5FF6FtDU") for hotkey in listed)
    document = json.loads(raw)
    assert [miner["label"] for miner in document["miners"]] == [
        "sn94_mainnet_cherry48",
        "sn94_mainnet_cherry46",
        "sn94_mainnet_contabo",
    ]
    assert all(
        miner["note"].startswith("owner's own miner hotkey; not registered")
        for miner in document["miners"]
    )


def _list_bytes(*hotkeys: object) -> bytes:
    document = {
        "miners": [{"hotkey": hotkey, "label": "x", "note": "y"} for hotkey in hotkeys],
        "netuid": NETUID,
        "schema": approved_miners.APPROVED_MINERS_SCHEMA,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def test_an_edited_list_fails_its_pin_and_a_malformed_one_is_refused() -> None:
    first, second = sorted(OWNER_MINER_HOTKEYS)[:2]
    edited = _list_bytes(first)
    with pytest.raises(ApprovedMinersError, match="sha256 pin"):
        load_approved_miners(edited, expected_sha256=PINNED_APPROVED_MINERS_SHA256)
    assert load_approved_miners(
        edited, expected_sha256=hashlib.sha256(edited).hexdigest()
    ) == frozenset({first})
    for hotkeys in ([first, first], [second, first], ["5Short"], [first[:-1] + "0"]):
        bad = _list_bytes(*hotkeys)
        with pytest.raises(ApprovedMinersError, match="sorted unique SS58"):
            load_approved_miners(bad, expected_sha256=hashlib.sha256(bad).hexdigest())
    for bad in (
        _list_bytes(7),
        _list_bytes(first).replace(b'"label":"x"', b'"label":""'),
    ):
        with pytest.raises(ApprovedMinersError, match="entry is malformed"):
            load_approved_miners(bad, expected_sha256=hashlib.sha256(bad).hexdigest())


def test_a_listed_hotkey_that_is_not_registered_changes_nothing(
    approved_compute_hotkeys,
) -> None:
    # The release list names three hotkeys that are on no UID. The vector is
    # the one an empty list gives: nobody is paid for compute.
    with_release_list = verified_plan(
        (base.MINER_ONE_AXON, 3), (base.MINER_TWO_AXON, 1)
    )
    approved_compute_hotkeys()
    with_empty_list = verified_plan((base.MINER_ONE_AXON, 3), (base.MINER_TWO_AXON, 1))

    assert with_release_list.wire_uids == with_empty_list.wire_uids == (BURN_UID,)
    assert with_release_list.wire_weights == with_empty_list.wire_weights == (W,)
    assert with_release_list.identity() == with_empty_list.identity()


def test_the_compute_share_burns_while_no_listed_hotkey_has_a_verified_machine() -> (
    None
):
    # One listed hotkey is registered and serving but verified nothing; an
    # unlisted miner verified four machines. The compute share is burned.
    listed = base.ServingAxon(21, sorted(OWNER_MINER_HOTKEYS)[0], "8.8.4.4", 8081)

    planned = verified_plan((listed, 0), (base.MINER_ONE_AXON, 4))

    assert planned.raw_scores == ((19, 4), (21, 0))
    assert planned.approved_uids() == (21,)
    assert (planned.wire_uids, planned.wire_weights) == ((BURN_UID,), (W,))

    # Once it verifies a machine it is paid the whole lane, and only it.
    paid = verified_plan((listed, 1), (base.MINER_ONE_AXON, 4))
    assert (paid.wire_uids, paid.wire_weights) == ((BURN_UID, 21), (W - LANE, LANE))


# The split ------------------------------------------------------------------


def test_an_unlisted_verified_machine_gets_zero_compute_weight() -> None:
    planned = verified_plan((base.MINER_ONE_AXON, 3), (base.MINER_TWO_AXON, 1))

    assert planned.raw_scores == ((19, 3), (20, 1))
    assert (planned.wire_uids, planned.wire_weights) == ((BURN_UID,), (W,))
    assert planned.identity()["burn_weight"] == W
    assert planned.identity()["compute_lane"] == {"share": "1/10", "approved_uids": []}


def test_listed_hotkeys_share_exactly_the_compute_share(
    approved_compute_hotkeys,
) -> None:
    approved_compute_hotkeys(base.MINER_ONE, base.MINER_TWO)
    unlisted = base.ServingAxon(21, "5Unlisted", "8.8.4.4", 8081)

    planned = verified_plan(
        (base.MINER_ONE_AXON, 2), (base.MINER_TWO_AXON, 1), (unlisted, 5)
    )

    weights = dict(zip(planned.wire_uids, planned.wire_weights, strict=True))
    # 6553 split 2:1 by verified machine count; the unlisted five earn nothing.
    assert weights == {BURN_UID: W - LANE, 19: 4369, 20: 2184}
    assert weights[19] + weights[20] == LANE
    assert planned.identity()["compute_lane"]["approved_uids"] == [19, 20]


def test_escape_recipients_share_exactly_the_escape_share() -> None:
    weights = split(
        [(19, 4)],
        {19: "5Unlisted"},
        escape=[(30, 2), (31, 1)],
        escape_hotkeys={30: "5BreakerA", 31: "5BreakerB"},
    )

    assert weights == {BURN_UID: W - LANE, 30: 4369, 31: 2184}
    assert weights[30] + weights[31] == LANE


def test_with_no_approved_machine_the_compute_share_is_burned_not_moved() -> None:
    # The approved hotkey verified nothing; the unlisted one verified plenty.
    weights = split(
        [(19, 0), (20, 9)],
        {19: "5Approved", 20: "5Unlisted"},
        approved={"5Approved"},
        escape=[(30, 1)],
        escape_hotkeys={30: "5Breaker"},
    )

    # The escape lane keeps its own 10 percent and gains nothing.
    assert weights == {BURN_UID: W - LANE, 30: LANE}


def test_with_no_escape_recipient_the_escape_share_is_burned_not_moved() -> None:
    weights = split([(19, 1)], {19: "5Approved"}, approved={"5Approved"})

    # The compute lane keeps its own 10 percent and gains nothing.
    assert weights == {BURN_UID: W - LANE, 19: LANE}


def test_both_lanes_paid_burn_the_remaining_eighty_percent() -> None:
    weights = split(
        [(19, 1)],
        {19: "5Approved"},
        approved={"5Approved"},
        escape=[(19, 1)],
        escape_hotkeys={19: "5Approved"},
    )

    # An approved miner that also broke a room is paid from both lanes.
    assert weights == {BURN_UID: W - 2 * LANE, 19: 2 * LANE}
    assert 0.80 <= weights[BURN_UID] / W < 0.801


def test_the_burn_uid_is_never_paid_by_a_lane_and_is_never_dropped() -> None:
    with pytest.raises(DirectValidatorError, match="burn UID cannot be paid"):
        split([(BURN_UID, 1)], {BURN_UID: "5Approved"}, approved={"5Approved"})
    with pytest.raises(DirectValidatorError, match="burn UID cannot be paid"):
        split([], {}, escape=[(BURN_UID, 1)], escape_hotkeys={BURN_UID: "5Breaker"})
    assert split([], {}) == {BURN_UID: W}


def test_rounding_never_reaches_an_unlisted_hotkey() -> None:
    rng = random.Random(20261112)
    for _case in range(400):
        uids = rng.sample(range(10, 250), rng.randint(1, 40))
        hotkeys = {uid: f"5Miner{uid}" for uid in uids}
        scores = [(uid, rng.choice((0, 0, 1, 2, 3, 17, 40))) for uid in uids]
        approved = {hotkeys[uid] for uid in uids if rng.random() < 0.3}
        breakers = rng.sample(range(10, 250), rng.randint(0, 5))
        escape_hotkeys = {uid: hotkeys.get(uid, f"5Breaker{uid}") for uid in breakers}
        escape = [(uid, rng.randint(1, 4)) for uid in breakers]

        weights = split(
            scores,
            hotkeys,
            approved=approved,
            escape=escape,
            escape_hotkeys=escape_hotkeys,
        )

        compute_paid = {
            uid for uid, count in scores if count > 0 and hotkeys[uid] in approved
        }
        assert set(weights) == compute_paid | set(breakers) | {BURN_UID}
        paid = W - weights[BURN_UID]
        assert paid == LANE * (bool(compute_paid) + bool(breakers))
        assert weights[BURN_UID] >= W - 2 * LANE


def test_the_outside_operator_earns_nothing_and_the_vector_burns() -> None:
    # The case read from the chain on 12 Nov 2026: one operator with five big
    # hotkeys, plus ten small ones, none of them approved.
    big = [(uid, 40) for uid in (79, 80, 82, 83, 84)]
    small = [(uid, 1) for uid in range(100, 110)]
    hotkeys = {uid: f"5Outside{uid}" for uid, _count in (*big, *small)}

    assert split([*big, *small], hotkeys) == {BURN_UID: W}

    # With approved miners verified too, the outsiders still earn nothing.
    ours = [(240, 1), (241, 1), (242, 2)]
    hotkeys.update({uid: f"5Ours{uid}" for uid, _count in ours})
    weights = split(
        [*big, *small, *ours],
        hotkeys,
        approved={hotkeys[uid] for uid, _count in ours},
    )
    assert set(weights) == {BURN_UID, 240, 241, 242}
    assert 0.80 <= weights[BURN_UID] / W <= 1.0
    assert weights[240] + weights[241] + weights[242] == LANE


# The writer -----------------------------------------------------------------


def test_the_writer_signs_and_confirms_an_all_burn_vector(
    tmp_path: Path, monkeypatch
) -> None:
    planned = verified_plan((base.MINER_ONE_AXON, 1))
    assert (planned.wire_uids, planned.wire_weights) == ((BURN_UID,), (W,))
    instance, subtensor, _planned = base.writer(tmp_path, monkeypatch, planned=planned)

    receipt = base.submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_CONFIRMED
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    identity = state["last_attempt"]["identity"]
    assert identity["burn_uid"] == BURN_UID
    assert identity["burn_hotkey"] == base.BURN_HOTKEY
    assert identity["burn_weight"] == W
    assert state["last_attempt"]["intent"]["kwargs"] == {
        "netuid": NETUID,
        "mecid": 0,
        "dests": [BURN_UID],
        "weights": [W],
        "version_key": DIRECT_VERSION_KEY,
    }


def _refused(tmp_path, monkeypatch, tampered, *, subtensor_setup=None) -> str:
    """The writer refuses ``tampered`` before signing or journalling."""

    instance, subtensor, _planned = base.writer(tmp_path, monkeypatch, planned=tampered)
    if subtensor_setup is not None:
        subtensor_setup(subtensor)
    with pytest.raises(DirectValidatorError) as raised:
        base.submit_before_deadline(instance, tampered)
    assert not isinstance(raised.value, DirectSubmissionAmbiguous)
    assert subtensor.substrate.sign_calls == 0
    assert subtensor.substrate.submit_calls == 0
    assert not instance.state_path.exists()
    return str(raised.value)


def test_the_writer_refuses_a_vector_that_pays_an_unlisted_miner(
    tmp_path: Path, monkeypatch
) -> None:
    planned = verified_plan((base.MINER_ONE_AXON, 1))
    # The vector every earlier release signed: all of it to the verified miner.
    zero_burn = replace(planned, wire_uids=(19,), wire_weights=(W,))
    assert "UID identities are inconsistent" in _refused(
        tmp_path, monkeypatch, zero_burn
    )


def test_the_writer_refuses_a_listed_share_above_the_lane(
    tmp_path: Path, monkeypatch, approved_compute_hotkeys
) -> None:
    approved_compute_hotkeys(base.MINER_ONE)
    planned = verified_plan((base.MINER_ONE_AXON, 1))
    assert planned.wire_weights == (W - LANE, LANE)
    inflated = replace(planned, wire_weights=(W - 2 * LANE, 2 * LANE))
    assert "UID identities are inconsistent" in _refused(
        tmp_path, monkeypatch, inflated
    )


@pytest.mark.parametrize(
    "tamper",
    (
        lambda plan: replace(plan, burn_uid=None, burn_hotkey=""),
        lambda plan: replace(plan, burn_hotkey="5SomebodyElse"),
        lambda plan: replace(plan, burn_uid=19),
        lambda plan: replace(plan, burn_uid=True),
    ),
    ids=("no-burn", "another-hotkey", "a-miner-uid", "bool-uid"),
)
def test_the_writer_refuses_any_burn_destination_but_the_pinned_owner(
    tmp_path: Path, monkeypatch, tamper
) -> None:
    planned = verified_plan((base.MINER_ONE_AXON, 1))
    assert "burn destination is not the pinned subnet owner hotkey" in _refused(
        tmp_path, monkeypatch, tamper(planned)
    )


def test_the_writer_refuses_when_the_chain_names_another_subnet_owner(
    tmp_path: Path, monkeypatch
) -> None:
    def moved(subtensor) -> None:
        subtensor.substrate.subnet_owner_hotkey = "5NewOwner"

    planned = verified_plan((base.MINER_ONE_AXON, 1))
    assert "not the subnet owner hotkey at the sign head" in _refused(
        tmp_path, monkeypatch, planned, subtensor_setup=moved
    )


def test_the_writer_refuses_when_the_burn_uid_changed_hotkey(
    tmp_path: Path, monkeypatch
) -> None:
    def recycled(subtensor) -> None:
        original = subtensor.get_metagraph_info

        def info(netuid, mechid, *, block):
            document = original(netuid, mechid, block=block)
            document.hotkeys[BURN_UID] = "5NewHolder"
            return document

        subtensor.get_metagraph_info = info

    planned = verified_plan((base.MINER_ONE_AXON, 1))
    assert "not the subnet owner hotkey at the sign head" in _refused(
        tmp_path, monkeypatch, planned, subtensor_setup=recycled
    )


def test_a_plan_cannot_be_built_without_the_burn_hotkey_at_the_anchor() -> None:
    snapshot = replace(base.snapshot(), registered_hotkeys={base.VALIDATOR: 7})
    with pytest.raises(DirectValidatorError, match="burn hotkey is not registered"):
        build_direct_plan(snapshot, base.round_result(base.machine_row("1")))


# The validator that signs as the subnet owner hotkey -------------------------


def _owner_validator_plan(monkeypatch, *counts):
    """A plan built by a validator whose own hotkey is the burn destination."""

    monkeypatch.setitem(SUBNET_OWNER_BURN_HOTKEYS, NETUID, base.VALIDATOR)
    miners = tuple(miner for miner, _count in counts) or (base.MINER_ONE_AXON,)
    rows = tuple(
        base.machine_row(str(index), uid=miner.uid, hotkey=miner.hotkey)
        for miner, count in counts
        for index in range(count)
    )
    snapshot = replace(
        base.snapshot(miners=miners),
        registered_hotkeys={
            base.VALIDATOR: 7,
            **{miner.hotkey: miner.uid for miner in miners},
        },
    )
    return build_direct_plan(snapshot, base.round_result(*rows, miners=miners))


def _owner_validator_writer(tmp_path, monkeypatch, planned):
    instance, subtensor, _planned = base.writer(tmp_path, monkeypatch, planned=planned)
    subtensor.substrate.subnet_owner_hotkey = base.VALIDATOR
    return instance, subtensor


def test_the_owner_hotkey_validator_submits_the_same_vector_with_empty_lanes(
    tmp_path: Path, monkeypatch
) -> None:
    # The chain accepts a validator's weight on its own UID and keeps it for
    # the subnet owner UID, so this validator burns like every other one.
    planned = _owner_validator_plan(monkeypatch)
    assert (planned.wire_uids, planned.wire_weights) == ((7,), (W,))
    instance, subtensor = _owner_validator_writer(tmp_path, monkeypatch, planned)

    receipt = base.submit_before_deadline(instance, planned)

    assert receipt.status == STATUS_CONFIRMED
    assert subtensor.substrate.submit_calls == 1
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["last_attempt"]["intent"]["kwargs"]["dests"] == [7]
    assert state["last_attempt"]["identity"]["burn_uid"] == 7


def test_the_owner_hotkey_validator_pays_the_lanes_and_burns_on_its_own_uid(
    tmp_path: Path, monkeypatch, approved_compute_hotkeys
) -> None:
    approved_compute_hotkeys(base.MINER_ONE)
    planned = _owner_validator_plan(monkeypatch, (base.MINER_ONE_AXON, 1))
    assert (planned.wire_uids, planned.wire_weights) == ((7, 19), (W - LANE, LANE))
    instance, _subtensor = _owner_validator_writer(tmp_path, monkeypatch, planned)

    assert base.submit_before_deadline(instance, planned).status == STATUS_CONFIRMED


def test_only_the_owner_hotkey_validator_may_weight_its_own_uid(
    tmp_path: Path, monkeypatch
) -> None:
    # Any other validator whose plan names its own UID as the burn is refused.
    planned = verified_plan((base.MINER_ONE_AXON, 1))
    own_uid = replace(
        planned,
        burn_uid=7,
        wire_uids=(7,),
        snapshot=replace(
            planned.snapshot,
            registered_hotkeys={
                **planned.snapshot.registered_hotkeys,
                base.BURN_HOTKEY: 7,
            },
        ),
    )
    assert "burn destination is not the pinned subnet owner hotkey" in _refused(
        tmp_path, monkeypatch, own_uid
    )


# Upgrading with work in flight ------------------------------------------------


def _as_the_previous_release_journalled(entry: dict) -> None:
    """Rewrite one journal entry to the zero-burn form on the old version key."""

    identity, intent = entry["identity"], entry["intent"]
    for name in ("burn_hotkey", "compute_lane"):
        del identity[name]
    identity["burn_uid"] = None
    identity["burn_weight"] = 0
    kwargs = {**intent["kwargs"], "dests": [19], "weights": [W]}
    kwargs["version_key"] = VERSION_KEY
    identity["kwargs"] = intent["kwargs"] = kwargs
    entry["attempt_id"] = writer_runtime._attempt_id(identity, intent)
    if isinstance(entry.get("receipt"), dict):
        entry["receipt"]["attempt_id"] = entry["attempt_id"]


def test_the_version_key_is_raised_one_step_above_every_earlier_release() -> None:
    assert VERSION_KEY == 10005000
    assert DIRECT_VERSION_KEY == 10005001
    assert PRIOR_DIRECT_VERSION_KEYS == frozenset({VERSION_KEY})
    planned = verified_plan((base.MINER_ONE_AXON, 1))
    assert planned.kwargs()["version_key"] == DIRECT_VERSION_KEY


def test_a_pending_zero_burn_intent_on_the_old_key_recovers_after_the_upgrade(
    tmp_path: Path, monkeypatch
) -> None:
    # The previous release signed [miner: 65535] with version key 10005000 and
    # lost the response. The upgraded validator must confirm that exact call
    # from finalized history, without signing or broadcasting again.
    planned = verified_plan((base.MINER_ONE_AXON, 1))
    instance, subtensor, _planned = base.writer(tmp_path, monkeypatch, planned=planned)
    subtensor.substrate.raise_after_include = True
    with pytest.raises(DirectSubmissionAmbiguous, match="recover, never retry"):
        base.submit_before_deadline(instance, planned)
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    _as_the_previous_release_journalled(state["pending"])
    instance.state_path.write_text(json.dumps(state), encoding="ascii")
    subtensor.substrate.expected_uids = [19]
    subtensor.substrate.expected_weights = [W]
    subtensor.substrate.call_version_key = VERSION_KEY

    receipt = instance.recover()

    assert receipt is not None and receipt.status == STATUS_RECOVERED
    assert receipt.attempt_id == state["pending"]["attempt_id"]
    assert subtensor.substrate.sign_calls == subtensor.substrate.submit_calls == 1
    after = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert after["pending"] is None
    assert after["last_attempt"]["intent"]["kwargs"]["version_key"] == VERSION_KEY
    assert after["last_attempt"]["identity"]["burn_weight"] == 0


@pytest.mark.parametrize("version_key", (DIRECT_VERSION_KEY + 1, 0, True))
def test_a_pending_intent_on_an_unknown_version_key_is_a_contradiction(
    tmp_path: Path, monkeypatch, version_key
) -> None:
    planned = verified_plan((base.MINER_ONE_AXON, 1))
    instance, subtensor, _planned = base.writer(tmp_path, monkeypatch, planned=planned)
    subtensor.substrate.raise_after_include = True
    with pytest.raises(DirectSubmissionAmbiguous, match="recover, never retry"):
        base.submit_before_deadline(instance, planned)
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    pending = state["pending"]
    pending["identity"]["kwargs"]["version_key"] = version_key
    pending["intent"]["kwargs"]["version_key"] = version_key
    pending["attempt_id"] = writer_runtime._attempt_id(
        pending["identity"], pending["intent"]
    )
    instance.state_path.write_text(json.dumps(state), encoding="ascii")

    with pytest.raises(DirectSubmissionContradiction):
        instance.recover()
    assert subtensor.substrate.sign_calls == subtensor.substrate.submit_calls == 1


def test_a_commit_made_by_the_previous_release_is_proven_revealed_after_the_upgrade(
    tmp_path: Path, monkeypatch
) -> None:
    # SN94 has commit-reveal on, so an upgrade usually lands between a commit
    # and its reveal. The stored commit reveals the old zero-burn vector; the
    # upgraded validator must prove that reveal, not stop on it.
    instance, subtensor, _planned, _encryptor = commit_reveal.commit_once(
        tmp_path, monkeypatch
    )
    state = commit_reveal.journal(instance)
    assert state["last_attempt"]["status"] == STATUS_COMMITTED
    _as_the_previous_release_journalled(state["last_attempt"])
    instance.state_path.write_text(json.dumps(state), encoding="ascii")
    subtensor.substrate.expected_uids = [19]
    subtensor.substrate.expected_weights = [W]
    subtensor.substrate.chain.reveal_block = commit_reveal.REVEAL_BLOCK
    subtensor.substrate.finalized_number = commit_reveal.REVEAL_BLOCK + 30

    revealed = instance.recover()

    assert revealed is not None and revealed.status == STATUS_REVEALED
    last = commit_reveal.journal(instance)["last_attempt"]
    assert last["reveal"]["outcome"]["applied"] is True
    assert last["intent"]["kwargs"]["version_key"] == VERSION_KEY


@pytest.mark.parametrize(
    "corrupt",
    (
        lambda identity: identity.update(burn_weight=identity["burn_weight"] - 1),
        lambda identity: identity.update(burn_uid=19),
        lambda identity: identity.update(burn_hotkey=""),
        lambda identity: identity.pop("burn_hotkey"),
        lambda identity: identity.update(burn_uid=None),
    ),
    ids=("wrong-weight", "a-miner-uid", "empty-hotkey", "no-hotkey", "half-legacy"),
)
def test_recovery_refuses_a_journal_whose_burn_identity_is_not_what_was_signed(
    tmp_path: Path, monkeypatch, corrupt, approved_compute_hotkeys
) -> None:
    approved_compute_hotkeys(base.MINER_ONE)
    planned = verified_plan((base.MINER_ONE_AXON, 1))
    instance, subtensor, _planned = base.writer(tmp_path, monkeypatch, planned=planned)
    subtensor.substrate.raise_after_include = True
    with pytest.raises(DirectSubmissionAmbiguous, match="recover, never retry"):
        base.submit_before_deadline(instance, planned)
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    pending = state["pending"]
    corrupt(pending["identity"])
    pending["attempt_id"] = writer_runtime._attempt_id(
        pending["identity"], pending["intent"]
    )
    instance.state_path.write_text(json.dumps(state), encoding="ascii")

    with pytest.raises(DirectSubmissionContradiction):
        instance.recover()


# The published snapshot --------------------------------------------------------


def _telemetry_case(approved_compute_hotkeys):
    from bittensor_wallet import Keypair

    validator = Keypair.create_from_uri("//Alice")
    listed = base.ServingAxon(
        41, Keypair.create_from_uri("//Bob").ss58_address, "1.1.1.1", 8081
    )
    unlisted = base.ServingAxon(
        42, Keypair.create_from_uri("//Charlie").ss58_address, "8.8.8.8", 8081
    )
    idle = base.ServingAxon(
        43, Keypair.create_from_uri("//Dave").ss58_address, "8.8.4.4", 8081
    )
    approved_compute_hotkeys(listed.hotkey, idle.hotkey)
    miners = (listed, unlisted, idle)
    rows = tuple(
        {
            **base.machine_row("1", uid=miner.uid, hotkey=miner.hotkey),
            "tee_kind": "tdx",
            "phase_timings_ms": {"qvl": 10},
        }
        for miner in (listed, unlisted)
    )
    snapshot = FinalizedMetagraphSnapshot(
        block_number=123,
        block_hash="0x" + "a" * 64,
        validator_uid=30,
        validator_hotkey=validator.ss58_address,
        miners=miners,
        skipped_axons={},
        netuid=NETUID,
        registered_hotkeys={base.BURN_HOTKEY: BURN_UID},
    )
    planned = build_direct_plan(snapshot, base.round_result(*rows, miners=miners))
    receipt = base.DirectSubmissionReceipt(
        status="CONFIRMED",
        attempt_id="sha256:" + "c" * 64,
        extrinsic_hash="0x" + "d" * 64,
        block_hash="0x" + "e" * 64,
        block_number=124,
        recovered=False,
    )
    event = build_telemetry_snapshot(
        result_rows=rows, plan=planned, receipt=receipt, keypair=validator
    )
    return planned, event


def test_the_published_snapshot_tells_the_truth_about_the_burn(
    approved_compute_hotkeys,
) -> None:
    planned, event = _telemetry_case(approved_compute_hotkeys)

    assert event["burn_weight"] == planned.burn_weight() == W - LANE
    by_uid = {miner["uid"]: miner for miner in event["miners"]}
    assert BURN_UID not in by_uid
    assert (by_uid[41]["status"], by_uid[41]["weight_u16"]) == ("weighted", LANE)
    # Verified, but not on the approved list: zero weight, and it says why.
    assert by_uid[42]["distinct_verified_compute"] == 1
    assert (by_uid[42]["status"], by_uid[42]["weight_u16"]) == ("not_approved", 0)
    assert (by_uid[43]["status"], by_uid[43]["weight_u16"]) == ("not_verified", 0)
    assert validate_public_telemetry_event(event) == event


def test_a_snapshot_that_hides_the_burn_or_pays_an_unlisted_miner_is_refused(
    approved_compute_hotkeys,
) -> None:
    from cathedral_thin.independent_runtime.telemetry import TelemetryError

    _planned, event = _telemetry_case(approved_compute_hotkeys)
    for mutate in (
        lambda document: document.update(burn_weight=0),
        lambda document: document.update(burn_weight=W),
        lambda document: document.update(burn_weight=-1),
        lambda document: document["miners"][1].update(weight_u16=1),
        lambda document: document["miners"][1].update(status="not_verified"),
    ):
        document = json.loads(json.dumps(event))
        mutate(document)
        with pytest.raises(TelemetryError):
            validate_public_telemetry_event(document)
