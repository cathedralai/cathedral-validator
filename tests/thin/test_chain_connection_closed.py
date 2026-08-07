"""Every chain connection the tick opens must be closed.

bittensor's Subtensor opens a websocket in its constructor and does not close
it on garbage collection, so an un-closed instance strands a socket and an fd
for the life of the process. Measured on SN39 mainnet before the fix: +4
stranded descriptors per 25-minute tick, which reaches the default
RLIMIT_NOFILE ceiling of 1024 in about three days and then stops the validator
writing weights entirely.

These tests fail if any of the per-tick chain helpers goes back to building a
connection and dropping it on the floor.
"""

from __future__ import annotations

import sys
import types
from typing import ClassVar

import pytest

from scaffold import validator_thin as vt


class _FakeMetagraph:
    def __init__(self, block: int = 100):
        self.block = block
        self.hotkeys = ["hk-a", "hk-b"]
        self.uids = _FakeUids([0, 1])


class _FakeUids(list):
    def tolist(self):
        return list(self)


class _FakeSubtensor:
    """Records whether the caller closed it."""

    instances: ClassVar[list[_FakeSubtensor]] = []

    def __init__(self, network: str = ""):
        self.network = network
        self.closed = False
        _FakeSubtensor.instances.append(self)

    def close(self):
        self.closed = True

    # -- the surface the helpers under test actually touch ------------------
    def metagraph(self, netuid, block=None):
        return _FakeMetagraph(block if block is not None else 100)

    def get_block_hash(self, block):
        return f"0xhash{block}"

    def commit_reveal_enabled(self, netuid=None, block=None):
        return False


@pytest.fixture
def fake_bittensor(monkeypatch):
    """Install a fake `bittensor` module and reset the instance ledger."""
    _FakeSubtensor.instances = []
    module = types.ModuleType("bittensor")
    module.Subtensor = _FakeSubtensor
    monkeypatch.setitem(sys.modules, "bittensor", module)
    return module


def _only_instance() -> _FakeSubtensor:
    assert len(_FakeSubtensor.instances) == 1, (
        f"expected exactly one chain connection, got {len(_FakeSubtensor.instances)}"
    )
    return _FakeSubtensor.instances[0]


def test_chain_connection_closes_on_the_happy_path(fake_bittensor):
    with vt._chain_connection("finney") as subtensor:
        assert subtensor.closed is False
    assert _only_instance().closed is True


def test_chain_connection_closes_when_the_body_raises(fake_bittensor):
    """A failing tick must not strand the connection — this is the path the
    validator took for hours during the finney 429 incident."""
    with pytest.raises(RuntimeError), vt._chain_connection("finney"):
        raise RuntimeError("tick blew up")
    assert _only_instance().closed is True


def test_a_close_that_itself_fails_never_breaks_the_tick(fake_bittensor):
    class _AngryClose(_FakeSubtensor):
        def close(self):
            raise OSError("socket already gone")

    fake_bittensor.Subtensor = _AngryClose
    with vt._chain_connection("finney") as subtensor:
        assert subtensor is not None
    # No exception escaped: the caller's result is what matters.


def test_block_hash_lookup_closes_its_connection(fake_bittensor):
    lookup = vt._block_hash_lookup("finney")
    assert lookup(42) == "0xhash42"
    assert _only_instance().closed is True


def test_historical_metagraph_lookup_closes_its_connection(fake_bittensor):
    lookup = vt._historical_metagraph_lookup("finney", 39)
    lookup(100)
    assert _only_instance().closed is True


def test_metagraph_hotkey_to_uid_closes_its_connection(fake_bittensor):
    mapping = vt.metagraph_hotkey_to_uid(network="finney", netuid=39)
    assert mapping == {"hk-a": 0, "hk-b": 1}
    assert _only_instance().closed is True


def test_repeated_lookups_do_not_accumulate_open_connections(fake_bittensor):
    """The leak was cumulative: this is the shape of the actual outage."""
    lookup = vt._block_hash_lookup("finney")
    for block in range(25):
        lookup(block)
    still_open = [s for s in _FakeSubtensor.instances if not s.closed]
    assert still_open == [], f"{len(still_open)} connections left open"
