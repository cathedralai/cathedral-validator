"""Legacy scaffold chain paths must never become a second SN94 writer."""

from __future__ import annotations

import pytest

from scaffold.chain import ChainClient, WeightVector


@pytest.mark.parametrize(
    "network",
    [
        "finney",
        "test",
        "wss://entrypoint-finney.opentensor.ai:443",
        "wss://self-hosted-finney.example",
    ],
)
def test_legacy_chain_client_refuses_sn94_before_importing_bittensor(
    network: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = ChainClient(netuid=94, network=network, broadcast=True)
    monkeypatch.setattr(
        client,
        "_bittensor",
        lambda: (_ for _ in ()).throw(
            AssertionError("SN94 refusal must happen before chain setup")
        ),
    )
    result = client.set_weights(WeightVector(by_uid={1: 1.0}))
    assert result["submitted"] is False
    assert "disabled on SN94" in result["reason"]
