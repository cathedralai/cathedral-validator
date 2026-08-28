"""The chain transport is not a writer. It signs only what is already claimed.

``SubstrateCanaryTransport`` used to be reachable with a canary keypair and
nothing else: no compose result, no policy bundle, no one-write lock, and no
re-check of the vector. A direct call landed on ``submit_extrinsic``.

Two fail-closed rules close that, and both are proven here against a fake
substrate. Nothing in this file holds key material or opens a socket.

1. The kwargs are rebuilt with ``build_mechanism_weights_kwargs`` and refused
   unless they are byte-identical to the canonical form. An empty vector, one
   that does not sum to 65535, one whose destinations are not strictly
   increasing, and one carrying an extra key are all refused before anything is
   signed.
2. The one-write canary lock must ALREADY exist, be ``pending``, name this
   hotkey, and carry these exact kwargs. The transport never claims that lock:
   claiming it here would give this module its own path to an extrinsic, which
   is what the one-write design exists to prevent. ``submit_canary_once`` claims
   it, and only then does the transport find a slot to spend.

A vector that dropped burn entirely is a LEGAL u16 vector, so rule 1 cannot see
it. Rule 2 does: the lock was claimed for the composed vector, and a miner
taking 100% is not that vector.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from _independent_fixtures import BOB, BURN_UID
from cathedral_thin.independent.canary import submit_canary_once
from cathedral_thin.independent.constants import (
    CANARY_HOTKEY,
    FINNEY_GENESIS_HASH,
    INDEPENDENT_CANARY_FILE,
    INDEPENDENT_STATE_FILE,
    LINEAGE,
    MECID,
    NETUID,
    VERSION_KEY,
)
from cathedral_thin.independent.errors import CanaryIneligible
from cathedral_thin.independent.submit import (
    MECHANISM_WEIGHTS_CALL,
    build_mechanism_weights_kwargs,
)
from cathedral_thin.independent_runtime.chain import SubstrateCanaryTransport
from cathedral_thin.independent_runtime.errors import ChainClientError
from test_independent_canary import (
    MINER_UID,
    PAYABLE_DESTS,
    PAYABLE_WEIGHTS,
    funded_compute_bundle,
    stamp_bundle_digest,
    synthetic_composed,
)

EXTRINSIC_HASH = "0x" + "cd" * 32
SIGN_TIME_BLOCK = 6_120_123
PAYABLE_KWARGS = build_mechanism_weights_kwargs(
    dests=PAYABLE_DESTS, weights=PAYABLE_WEIGHTS
)


class FakeKeypair:
    """An ss58 address and nothing else. There is no seed on this path."""

    def __init__(self, ss58: str = CANARY_HOTKEY) -> None:
        self.ss58_address = ss58


class FakeSubstrate:
    def __init__(self, genesis: str = FINNEY_GENESIS_HASH) -> None:
        self.genesis = genesis
        self.signed: list[dict] = []
        self.submitted: list[object] = []

    def get_block_hash(self, number: int) -> str:
        assert number == 0
        return self.genesis

    def get_block_header(self) -> dict:
        return {"header": {"number": SIGN_TIME_BLOCK}}

    def get_account_next_index(self, ss58: str) -> int:
        assert ss58 == CANARY_HOTKEY
        return 4

    def create_signed_extrinsic(self, *, call, keypair, nonce, era):
        self.signed.append(
            {"call": call, "keypair": keypair, "nonce": nonce, "era": era}
        )
        return _Signed()

    def submit_extrinsic(self, signed, *, wait_for_inclusion, wait_for_finalization):
        assert wait_for_inclusion is True
        assert wait_for_finalization is False
        self.submitted.append(signed)
        return _Signed()


class _Signed:
    extrinsic_hash = EXTRINSIC_HASH


class FakeSubtensor:
    def __init__(self, genesis: str = FINNEY_GENESIS_HASH) -> None:
        self.substrate = FakeSubstrate(genesis)
        self.composed: list[dict] = []

    def compose_call(self, *, call_module, call_function, call_params):
        self.composed.append(
            {
                "call_module": call_module,
                "call_function": call_function,
                "call_params": dict(call_params),
            }
        )
        return "composed-call"


def lock_path(tmp_path) -> Path:
    return tmp_path / INDEPENDENT_CANARY_FILE.name


def write_lock(tmp_path, **overrides) -> Path:
    record = {
        "lineage": LINEAGE,
        "kind": "canary",
        "status": "pending",
        "hotkey": CANARY_HOTKEY,
        "call": MECHANISM_WEIGHTS_CALL,
        "kwargs": dict(PAYABLE_KWARGS),
        "broadcast": False,
        "receipt": None,
    }
    record.update(overrides)
    target = lock_path(tmp_path)
    target.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return target


def transport_for(tmp_path, *, subtensor=None, keypair=None, state_path=None):
    return SubstrateCanaryTransport(
        subtensor if subtensor is not None else FakeSubtensor(),
        keypair if keypair is not None else FakeKeypair(),
        state_path=lock_path(tmp_path) if state_path is None else state_path,
    )


def test_the_transport_requires_a_lock_path(tmp_path):
    with pytest.raises(ChainClientError, match="one-write lock path"):
        SubstrateCanaryTransport(FakeSubtensor(), FakeKeypair(), state_path=None)


def test_a_non_canary_keypair_cannot_build_the_transport(tmp_path):
    with pytest.raises(CanaryIneligible, match="well-known Substrate"):
        transport_for(tmp_path, keypair=FakeKeypair(BOB))
    other = "5Eyj9kxQF5zimWrnt1mh3dDeATDiHZ6mQHeLGhNuyCN9agG3"
    with pytest.raises(CanaryIneligible, match="dedicated canary identity"):
        transport_for(tmp_path, keypair=FakeKeypair(other))


def test_a_missing_lock_refuses_and_never_reaches_the_pallet(tmp_path):
    subtensor = FakeSubtensor()
    transport = transport_for(tmp_path, subtensor=subtensor)
    with pytest.raises(ChainClientError, match="is not usable"):
        transport.submit_mechanism_weights(PAYABLE_KWARGS)
    assert subtensor.substrate.submitted == []
    assert subtensor.composed == []
    assert not lock_path(tmp_path).exists()


def test_a_pending_lock_is_the_only_path_to_submit_extrinsic(tmp_path):
    write_lock(tmp_path)
    subtensor = FakeSubtensor()
    transport = transport_for(tmp_path, subtensor=subtensor)
    receipt = transport.submit_mechanism_weights(PAYABLE_KWARGS)
    assert receipt == EXTRINSIC_HASH
    assert len(subtensor.substrate.submitted) == 1
    assert subtensor.composed == [
        {
            "call_module": "SubtensorModule",
            "call_function": "set_mechanism_weights",
            "call_params": {
                "netuid": NETUID,
                "mecid": MECID,
                "dests": [MINER_UID, BURN_UID],
                "weights": list(PAYABLE_WEIGHTS),
                "version_key": VERSION_KEY,
            },
        }
    ]
    era = subtensor.substrate.signed[0]["era"]
    assert era == {"period": 16, "current": SIGN_TIME_BLOCK}


@pytest.mark.parametrize("status", ["submitted", "", "PENDING", None])
def test_a_lock_that_is_not_pending_is_refused(tmp_path, status):
    write_lock(tmp_path, status=status)
    subtensor = FakeSubtensor()
    transport = transport_for(tmp_path, subtensor=subtensor)
    with pytest.raises(ChainClientError, match="not 'pending'"):
        transport.submit_mechanism_weights(PAYABLE_KWARGS)
    assert subtensor.substrate.submitted == []


def test_a_lock_claimed_for_another_hotkey_is_refused(tmp_path):
    write_lock(tmp_path, hotkey=BOB)
    subtensor = FakeSubtensor()
    transport = transport_for(tmp_path, subtensor=subtensor)
    with pytest.raises(ChainClientError, match="different hotkey"):
        transport.submit_mechanism_weights(PAYABLE_KWARGS)
    assert subtensor.substrate.submitted == []


def test_a_lock_for_another_vector_is_refused(tmp_path):
    """A miner taking 100% is a legal u16 vector. It is not the claimed one."""
    write_lock(tmp_path)
    subtensor = FakeSubtensor()
    transport = transport_for(tmp_path, subtensor=subtensor)
    burn_dropped = build_mechanism_weights_kwargs(dests=[MINER_UID], weights=[65535])
    with pytest.raises(ChainClientError, match="not the vector being signed"):
        transport.submit_mechanism_weights(burn_dropped)
    assert subtensor.substrate.submitted == []


def test_a_lock_from_another_lineage_is_refused(tmp_path):
    write_lock(tmp_path, lineage="thin_relay")
    with pytest.raises(ChainClientError, match="canary record"):
        transport_for(tmp_path).submit_mechanism_weights(PAYABLE_KWARGS)


def test_a_lock_that_claims_broadcast_is_refused(tmp_path):
    write_lock(tmp_path, broadcast=True)
    with pytest.raises(ChainClientError, match="broadcast = false"):
        transport_for(tmp_path).submit_mechanism_weights(PAYABLE_KWARGS)


def test_a_lock_naming_another_call_is_refused(tmp_path):
    write_lock(tmp_path, call="SubtensorModule.set_weights")
    with pytest.raises(ChainClientError, match="set_mechanism_weights"):
        transport_for(tmp_path).submit_mechanism_weights(PAYABLE_KWARGS)


def test_the_compose_journal_is_not_accepted_as_the_lock(tmp_path):
    subtensor = FakeSubtensor()
    transport = transport_for(
        tmp_path,
        subtensor=subtensor,
        state_path=tmp_path / INDEPENDENT_STATE_FILE.name,
    )
    with pytest.raises(ChainClientError, match="is not usable"):
        transport.submit_mechanism_weights(PAYABLE_KWARGS)
    assert subtensor.substrate.submitted == []


@pytest.mark.parametrize(
    ("dests", "weights"),
    [
        ((), ()),
        ((MINER_UID, BURN_UID), (1, 1)),
        ((BURN_UID, MINER_UID), (1, 65534)),
        ((MINER_UID, MINER_UID), (1, 65534)),
        ((MINER_UID, BURN_UID), (0, 65535)),
    ],
)
def test_an_illegal_vector_is_refused_before_the_lock_is_read(tmp_path, dests, weights):
    write_lock(tmp_path)
    subtensor = FakeSubtensor()
    transport = transport_for(tmp_path, subtensor=subtensor)
    with pytest.raises(ChainClientError, match="not a legal u16"):
        transport.submit_mechanism_weights(
            {
                "netuid": NETUID,
                "mecid": MECID,
                "dests": list(dests),
                "weights": list(weights),
                "version_key": VERSION_KEY,
            }
        )
    assert subtensor.substrate.submitted == []


def test_kwargs_carrying_an_extra_key_are_refused(tmp_path):
    write_lock(tmp_path)
    subtensor = FakeSubtensor()
    transport = transport_for(tmp_path, subtensor=subtensor)
    with pytest.raises(ChainClientError, match="canonical mechanism weight"):
        transport.submit_mechanism_weights({**PAYABLE_KWARGS, "hotkey": CANARY_HOTKEY})
    assert subtensor.substrate.submitted == []


@pytest.mark.parametrize("field", ["netuid", "mecid", "version_key"])
def test_an_unpinned_scalar_is_refused(tmp_path, field):
    write_lock(tmp_path)
    subtensor = FakeSubtensor()
    transport = transport_for(tmp_path, subtensor=subtensor)
    with pytest.raises(ChainClientError, match="pinned to"):
        transport.submit_mechanism_weights({**PAYABLE_KWARGS, field: 1})
    assert subtensor.substrate.submitted == []


@pytest.mark.parametrize("field", ["netuid", "mecid", "version_key"])
@pytest.mark.parametrize("value", ["39", None, 39.0, True])
def test_a_scalar_that_is_not_an_integer_is_refused(tmp_path, field, value):
    """``int("39")`` would have coerced a string into the pin."""
    write_lock(tmp_path)
    subtensor = FakeSubtensor()
    transport = transport_for(tmp_path, subtensor=subtensor)
    with pytest.raises(ChainClientError, match="pinned to"):
        transport.submit_mechanism_weights({**PAYABLE_KWARGS, field: value})
    assert subtensor.substrate.submitted == []


def test_a_non_mapping_is_refused(tmp_path):
    write_lock(tmp_path)
    with pytest.raises(ChainClientError, match="must be a mapping"):
        transport_for(tmp_path).submit_mechanism_weights([1, 2, 3])  # type: ignore[arg-type]


def test_a_foreign_genesis_is_still_refused_with_a_pending_lock(tmp_path):
    write_lock(tmp_path)
    subtensor = FakeSubtensor(genesis="0x" + "11" * 32)
    transport = transport_for(tmp_path, subtensor=subtensor)
    with pytest.raises(ChainClientError, match="pinned Finney genesis"):
        transport.submit_mechanism_weights(PAYABLE_KWARGS)
    assert subtensor.substrate.submitted == []


def test_submit_canary_once_claims_the_lock_the_transport_then_finds(tmp_path):
    """The only shipped path: the sealed package claims, the transport signs."""
    bundle, _registry = funded_compute_bundle()
    result = stamp_bundle_digest(synthetic_composed(), bundle)
    subtensor = FakeSubtensor()
    transport = transport_for(tmp_path, subtensor=subtensor)
    assert not lock_path(tmp_path).exists()
    receipt = submit_canary_once(
        result=result,
        kwargs=PAYABLE_KWARGS,
        bundle=bundle,
        hotkey=CANARY_HOTKEY,
        transport=transport,
        state_path=lock_path(tmp_path),
    )
    assert receipt.receipt == EXTRINSIC_HASH
    assert len(subtensor.substrate.submitted) == 1
    record = json.loads(lock_path(tmp_path).read_text(encoding="utf-8"))
    assert record["status"] == "submitted"
    assert record["receipt"] == EXTRINSIC_HASH

    # The slot is spent, so the same transport cannot be reused directly.
    with pytest.raises(ChainClientError, match="not 'pending'"):
        transport.submit_mechanism_weights(PAYABLE_KWARGS)
    assert len(subtensor.substrate.submitted) == 1
