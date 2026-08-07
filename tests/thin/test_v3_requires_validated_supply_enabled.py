"""A v3 contract without the enable flag must fail closed, not fall back.

`test_v3_full_compose_proof.py::test_missing_validated_supply_enabled_silently_falls_back`
pinned the old behaviour: with `CATHEDRAL_ALLOCATION_CONTRACT=v3` set but
`CATHEDRAL_VALIDATED_SUPPLY_ENABLED` unset, `validated_supply_metadata()`
returned None, the composer applied no contract, and the publisher emitted a
flat-recent vector with no v3 stamp and no CyberGym lane.

Nothing downstream can distinguish that from a deliberate v2 run, which is why
every live v3 cutover attempt failed this way unnoticed. Five of the six v3
settings present is the likeliest operator mistake and it was the silent one.

These tests hold the line on the three cases that matter: the half-applied
cutover raises, a genuine v2 run is untouched, and a fully-configured v3 run
still composes.
"""

from __future__ import annotations

import pytest

from scaffold.publisher import weights
from scaffold.wire_vector import VectorError

BURN = "5FBurnHotkeyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# The v3 settings an operator sets when they intend to cut over, minus the
# enable flag. This is the exact half-applied state that used to be silent.
V3_MINUS_ENABLE = {
    "CATHEDRAL_WEIGHT_POLICY_NETWORK": "finney",
    "CATHEDRAL_WEIGHT_POLICY_NETUID": "39",
    "CATHEDRAL_WEIGHT_POLICY_BURN_HOTKEY": BURN,
    "CATHEDRAL_WEIGHT_POLICY_BURN_UID": "",
    "CATHEDRAL_WEIGHT_POLICY_FORCED_BURN_PERCENTAGE_V2": "0",
    "CATHEDRAL_EXTERNAL_SCORES_ENABLED": "1",
    "CATHEDRAL_EXTERNAL_SCORES_SOURCE": "cathedral_confidential_tdx",
    "CATHEDRAL_EXTERNAL_SCORES_MODE": "confidential_primary",
    "CATHEDRAL_EXTERNAL_SCORES_PRIMARY_CONFIRM": "true",
    "CATHEDRAL_ALLOCATION_CONTRACT": "v3",
    "CATHEDRAL_CYBERGYM_MECHANISM_ENABLED": "1",
    "CATHEDRAL_CYBERGYM_WEIGHT_FRACTION": "0.30",
    "CATHEDRAL_CYBERGYM_PRODUCER_HOTKEY": "cathedral-cybergym-producer-sn39",
    "CATHEDRAL_CYBERGYM_SCORES_HMAC_SECRET": "test-cybergym-hmac-secret",
}


def _apply(monkeypatch, env: dict[str, str]) -> None:
    monkeypatch.delenv("CATHEDRAL_VALIDATED_SUPPLY_ENABLED", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def test_v3_without_the_enable_flag_raises(monkeypatch):
    _apply(monkeypatch, V3_MINUS_ENABLE)
    with pytest.raises(VectorError) as raised:
        weights.validated_supply_metadata()
    message = str(raised.value)
    # The error has to name the missing variable, or it cannot be acted on.
    assert "CATHEDRAL_VALIDATED_SUPPLY_ENABLED" in message
    assert "v3" in message


def test_a_plain_v2_run_is_untouched(monkeypatch):
    """Unset remains the legitimate default: v2 operators must not be broken."""
    env = dict(V3_MINUS_ENABLE)
    env["CATHEDRAL_ALLOCATION_CONTRACT"] = "v2"
    _apply(monkeypatch, env)
    assert weights.validated_supply_metadata() is None


def test_the_default_contract_is_untouched(monkeypatch):
    """No contract set at all is the most common deployment; still silent."""
    env = dict(V3_MINUS_ENABLE)
    env.pop("CATHEDRAL_ALLOCATION_CONTRACT")
    monkeypatch.delenv("CATHEDRAL_ALLOCATION_CONTRACT", raising=False)
    _apply(monkeypatch, env)
    assert weights.validated_supply_metadata() is None


def test_fully_configured_v3_still_composes(monkeypatch):
    """The guard must not break the case it is protecting."""
    _apply(monkeypatch, V3_MINUS_ENABLE)
    monkeypatch.setenv("CATHEDRAL_VALIDATED_SUPPLY_ENABLED", "1")
    supply = weights.validated_supply_metadata()
    assert supply is not None
    assert supply["contract_version"] == "v3"
