"""An explicitly empty --require-policy must be refused, not silently unpinned.

`--require-policy` is the allocation-contract pin: it names the ONE signed
contract this validator will apply, so a vector of any other shape fails closed.
main() validated it behind a truthiness test, which conflates "not supplied"
with "supplied empty". The flag's default is a real pin, so "not supplied" never
produces an empty value; only an explicit `--require-policy ''` (or an
equivalent config/unit-file line that resolves to empty) does, and that value
skipped validation entirely and reached the mapper as "unpinned".

Unpinned is not a harmless setting. It is the ambiguity the pin exists to
remove: the same binary then accepts v2 (90/10), v3 (70/30/0), a bare
confidential_primary vector and legacy flat vectors, choosing by whatever the
payload happens to carry. Refusing an unknown value while accepting the empty
one means the loudest possible misconfiguration is the one that goes unreported.
"""

from __future__ import annotations

import math

import pytest

from scaffold import cli, validator_thin as vt

V1_PIN = vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V1
V3_PIN = vt.REQUIRE_POLICY_VALIDATED_SUPPLY_V3


def _main_with(monkeypatch, argv: list[str]) -> tuple[int, list]:
    """Run main() with argv, stubbing run() so nothing touches chain or disk."""
    monkeypatch.delenv("CATHEDRAL_VALIDATOR_REQUIRE_POLICY", raising=False)
    monkeypatch.setattr(vt, "installed_recurring_context", lambda: True)
    monkeypatch.setattr("sys.argv", ["cathedral-validator", *argv])
    seen: list = []

    def _fake_run(args):
        seen.append(args)
        return 0

    monkeypatch.setattr(vt, "run", _fake_run)
    return vt.main(), seen


def test_explicitly_empty_require_policy_is_rejected(monkeypatch, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        _main_with(monkeypatch, ["--require-policy", ""])
    assert exc.value.code == 2
    assert "--require-policy" in capsys.readouterr().err


def test_unknown_require_policy_is_still_rejected(monkeypatch, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        _main_with(monkeypatch, ["--require-policy", "validated_supply_v9"])
    assert exc.value.code == 2
    assert "validated_supply_v9" in capsys.readouterr().err


def test_empty_env_pin_still_falls_back_to_the_default_contract(monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_VALIDATOR_REQUIRE_POLICY", "   ")
    monkeypatch.setattr(vt, "installed_recurring_context", lambda: True)
    monkeypatch.setattr("sys.argv", ["cathedral-validator"])
    seen: list = []
    monkeypatch.setattr(vt, "run", lambda args: seen.append(args) or 0)
    assert vt.main() == 0
    assert seen[0].require_policy == V1_PIN


def test_omitted_flag_keeps_the_launch_pin(monkeypatch) -> None:
    rc, seen = _main_with(monkeypatch, [])
    assert rc == 0
    assert seen[0].require_policy == V1_PIN


def test_every_named_choice_is_accepted(monkeypatch) -> None:
    for choice in vt.REQUIRE_POLICY_CHOICES:
        rc, seen = _main_with(monkeypatch, ["--require-policy", choice])
        assert rc == 0
        assert seen[0].require_policy == choice


# ---- the `serve` entry point carried the same skipped check ------------------


def _serve(monkeypatch, argv: list[str]) -> tuple[int, list]:
    monkeypatch.delenv("CATHEDRAL_VALIDATOR_REQUIRE_POLICY", raising=False)
    monkeypatch.setattr(vt, "installed_recurring_context", lambda: True)
    seen: list = []
    monkeypatch.setattr(vt, "_validate_runtime_contract", lambda _cfg: None)
    monkeypatch.setattr(vt, "run", lambda cfg: seen.append(cfg) or 0)
    base = [
        "serve",
        "--once",
        "--public-key-hex",
        vt.DEFAULT_PUBLIC_KEY_HEX,
    ]
    return cli.main([*base, *argv]), seen


def test_serve_rejects_an_explicitly_empty_require_policy(monkeypatch, capsys) -> None:
    rc, seen = _serve(monkeypatch, ["--require-policy", ""])
    assert rc == 2
    assert seen == []
    assert "require_policy" in capsys.readouterr().err


def test_serve_keeps_the_default_pin(monkeypatch) -> None:
    rc, seen = _serve(monkeypatch, [])
    assert rc == 0
    assert seen[0].require_policy == V1_PIN


# ---- why an unpinned validator is the defect, not a preference ---------------

BURN = "burn-hotkey"
H2U = {BURN: 0, "tdx-a": 10, "tdx-b": 11, "cyber-a": 50, "cyber-b": 51}


def _cp_block() -> dict:
    return {
        "contract_version": "v1",
        "mode": "confidential_primary",
        "source": "cathedral_confidential_tdx",
        "base_mass": 0.0,
        "confidential_mass": 1.0,
        "complete": True,
        "fresh": True,
        "confirmed": True,
    }


def _tdx_rows(rows: list[tuple[str, float]]) -> list[dict]:
    return [
        {
            "miner_hotkey": hk,
            "weight": w,
            "base_component": 0.0,
            "external_component": w,
        }
        for hk, w in rows
    ]


def _v2_payload() -> dict:
    """The launch contract: 90% Intel TDX, 10% unconditional burn."""
    return {
        "weights": _tdx_rows([("tdx-a", 1.0)]),
        "burn_snapshot": {
            "burn_uid": None,
            "burn_hotkey": BURN,
            "forced_burn_percentage": 10.0,
        },
        "policy_metadata": {
            "confidential_primary": _cp_block(),
            "validated_supply": {
                "contract_version": "v2",
                "intel_tdx_allocation": 0.90,
                "fixed_burn_allocation": 0.10,
                "burn_hotkey": BURN,
            },
        },
    }


def _v3_payload() -> dict:
    """The re-pin contract: 70% Intel TDX, 30% CyberGym, 0% fixed burn."""
    lane_weights = {50: 0.18, 51: 0.12}
    return {
        "weights": _tdx_rows([("tdx-a", 0.6), ("tdx-b", 0.4)]),
        "burn_snapshot": {
            "burn_uid": None,
            "burn_hotkey": BURN,
            "forced_burn_percentage": 0.0,
        },
        "policy_metadata": {
            "confidential_primary": _cp_block(),
            "validated_supply": {
                "contract_version": "v3",
                "intel_tdx_allocation": 0.70,
                "cybergym_allocation": 0.30,
                "fixed_burn_allocation": 0.0,
                "burn_hotkey": BURN,
            },
            "cybergym_lane": {
                "fraction": 0.30,
                "weights": {str(u): w for u, w in lane_weights.items()},
                "contributing_fraction": 0.30,
                "forfeited_fraction": 0.0,
                "burn_uid": None,
                "uid_hotkeys": {"50": "cyber-a", "51": "cyber-b"},
                "cybergym": {"reason": "ok"},
            },
        },
    }


def test_an_empty_pin_maps_two_different_allocations_from_one_binary() -> None:
    # This is what the skipped validation buys: no pin at all, so the payload
    # picks the economy. A real pin admits exactly one of these two and fails
    # closed on the other.
    v2 = vt.vector_to_uid_weights(_v2_payload(), H2U, require_policy="")
    v3 = vt.vector_to_uid_weights(_v3_payload(), H2U, require_policy="")
    assert v2 == {0: pytest.approx(0.10), 10: pytest.approx(0.90)}
    assert v3[10] == pytest.approx(0.42)
    assert v3[50] == pytest.approx(0.18)
    assert math.isclose(math.fsum(v3.values()), 1.0, abs_tol=1e-12)

    with pytest.raises(vt.wire.VectorError):
        vt.vector_to_uid_weights(_v3_payload(), H2U, require_policy=V1_PIN)
    with pytest.raises(vt.wire.VectorError):
        vt.vector_to_uid_weights(_v2_payload(), H2U, require_policy=V3_PIN)
