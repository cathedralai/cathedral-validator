from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest

from cathedral_thin import uid30_state
from cathedral_thin.independent.constants import FINNEY_GENESIS_HASH

BLOCK = 100
BLOCK_HASH = "0x" + "ab" * 32
OWNER = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"


class _Substrate:
    def get_chain_finalised_head(self):
        return BLOCK_HASH

    def get_block_number(self, block_hash):
        assert block_hash == BLOCK_HASH
        return BLOCK

    def get_block_hash(self, block):
        if block == 0:
            return FINNEY_GENESIS_HASH
        assert block == BLOCK
        return BLOCK_HASH

    def query(self, *, module, storage_function, params, block_hash):
        assert module == "SubtensorModule"
        assert block_hash == BLOCK_HASH
        if storage_function == "StakeThreshold":
            assert params == []
            return 100
        if storage_function == "WeightsVersionKey":
            assert params == [39]
            return 0
        raise AssertionError(storage_function)


class _Subtensor:
    def __init__(self, *, permit=np.bool_(True)):
        self.substrate = _Substrate()
        self.permit = permit
        self.hotkeys = [f"hotkey-{uid}" for uid in range(125)]
        self.hotkeys[uid30_state.UID30] = uid30_state.UID30_HOTKEY
        self.hotkeys[124] = uid30_state.MINER_HOTKEY

    def metagraph(self, netuid, *, block):
        assert (netuid, block) == (39, BLOCK)
        permits = [False] * len(self.hotkeys)
        permits[uid30_state.UID30] = self.permit
        return SimpleNamespace(
            block=BLOCK,
            uids=np.arange(len(self.hotkeys), dtype=np.int64),
            hotkeys=list(self.hotkeys),
            validator_permit=permits,
        )

    def get_metagraph_info(self, netuid, mecid, *, block):
        assert (netuid, mecid, block) == (39, 0, BLOCK)
        permits = [False] * len(self.hotkeys)
        permits[uid30_state.UID30] = self.permit
        stakes = [SimpleNamespace(rao=0) for _ in self.hotkeys]
        stakes[uid30_state.UID30] = SimpleNamespace(rao=200)
        axons = [
            {"ip_type": 4, "ip": 0, "port": 0, "protocol": 0} for _ in self.hotkeys
        ]
        axons[124] = {
            "ip_type": 4,
            "ip": int.from_bytes(bytes([1, 1, 1, 1]), "big"),
            "port": 8081,
            "protocol": 4,
        }
        last_update = [0] * len(self.hotkeys)
        last_update[uid30_state.UID30] = 50
        return SimpleNamespace(
            block=BLOCK,
            hotkeys=list(self.hotkeys),
            axons=axons,
            validator_permit=permits,
            total_stake=stakes,
            last_update=last_update,
        )

    def blocks_until_next_epoch(self, netuid, *, block):
        assert (netuid, block) == (39, BLOCK)
        return 100

    def get_next_epoch_start_block(self, netuid, *, block):
        assert (netuid, block) == (39, BLOCK)
        return 200

    def weights_rate_limit(self, netuid, *, block):
        assert (netuid, block) == (39, BLOCK)
        return 10

    def blocks_since_last_update(self, netuid, uid, *, block):
        assert (netuid, uid, block) == (39, uid30_state.UID30, BLOCK)
        return 50

    def commit_reveal_enabled(self, *, netuid, block):
        assert (netuid, block) == (39, BLOCK)
        return np.bool_(False)

    def min_allowed_weights(self, *, netuid, block):
        assert (netuid, block) == (39, BLOCK)
        return np.int64(1)

    def max_weight_limit(self, *, netuid, block):
        assert (netuid, block) == (39, BLOCK)
        return 1.0

    def get_subnet_owner_hotkey(self, netuid, *, block):
        assert (netuid, block) == (39, BLOCK)
        return OWNER

    def get_mechanism_count(self, netuid, *, block):
        assert (netuid, block) == (39, BLOCK)
        return np.int64(1)


def _install(monkeypatch, subtensor):
    keypair = SimpleNamespace(
        ss58_address=uid30_state.UID30_HOTKEY,
        sign=lambda _body: b"s" * 64,
    )
    monkeypatch.setattr(
        uid30_state,
        "make_wallet",
        lambda *_args, **_kwargs: SimpleNamespace(hotkey=keypair),
    )
    monkeypatch.setattr(
        uid30_state, "make_subtensor", lambda *_args, **_kwargs: subtensor
    )


def test_read_only_uid30_state_uses_one_finalized_head_and_no_write_authority(
    monkeypatch,
):
    _install(monkeypatch, _Subtensor())
    state = uid30_state.read_uid30_chain_state()
    assert state.block_number == BLOCK
    assert state.block_hash == BLOCK_HASH
    assert state.validator_uid == 30
    assert state.validator_permit is True
    assert state.miner_uid == 124
    assert state.serving_axon.ip == "1.1.1.1"
    assert state.uid_safety == {
        "status": "read_only_current_mapping_only",
        "mapping_block": BLOCK,
        "uid_hotkeys": [[124, uid30_state.MINER_HOTKEY]],
        "authorized_for_chain_write": False,
    }


def test_read_only_uid30_state_requires_strict_finalized_permit(monkeypatch):
    _install(monkeypatch, _Subtensor(permit="True"))
    with pytest.raises(uid30_state.UID30LaunchError, match="explicit boolean"):
        uid30_state.read_uid30_chain_state()
