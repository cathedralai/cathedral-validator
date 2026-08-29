from __future__ import annotations

from pathlib import Path

import pytest

from cathedral_thin import uid30_launch
from cathedral_thin.independent.constants import (
    UID30_MINER_HOTKEY,
    UID30_VALIDATOR_HOTKEY,
    UID30_VALIDATOR_UID,
)
from cathedral_thin.independent_runtime import miner_axon
from cathedral_thin.independent_runtime import miner_axon_cli
from cathedral_thin.independent_runtime import second_miner_axon_cli
from cathedral_thin.independent_runtime import uid124_axon_generation2_cli


@pytest.mark.parametrize(
    "command",
    ("preview", "submit", "successor-preview", "successor-submit"),
)
def test_uid30_recovery_console_rejects_every_launch_command(command: str) -> None:
    with pytest.raises(SystemExit) as refusal:
        uid30_launch._parser().parse_args([command])
    assert refusal.value.code == 2


def test_uid30_recovery_console_exposes_only_read_only_modes() -> None:
    parser = uid30_launch._parser()
    commands = parser._subparsers._group_actions[0].choices
    assert set(commands) == {"recover", "successor-recover"}


def test_read_only_uid30_pins_match_historical_recovery_writer() -> None:
    writer = uid30_launch.canonical_validator
    assert UID30_VALIDATOR_UID == writer.SN39_UID30_LAUNCH_VALIDATOR_UID
    assert UID30_VALIDATOR_HOTKEY == writer.SN39_UID30_LAUNCH_VALIDATOR_HOTKEY
    assert UID30_MINER_HOTKEY == writer.SN39_UID30_LAUNCH_MINER_HOTKEY


@pytest.mark.parametrize(
    ("module", "argv"),
    (
        (
            miner_axon_cli,
            ["preview", "--ip", "1.1.1.1", "--qvl", "/reviewed/qvl"],
        ),
        (
            second_miner_axon_cli,
            ["announce", "--reviewed-sha256", "00" * 32, "--qvl", "/qvl"],
        ),
        (
            uid124_axon_generation2_cli,
            ["announce", "--reviewed-sha256", "00" * 32, "--qvl", "/qvl"],
        ),
    ),
)
def test_stale_axon_console_shims_reject_preview_and_announce(
    module, argv: list[str]
) -> None:
    with pytest.raises(SystemExit) as refusal:
        module.main(argv)
    assert refusal.value.code == 2


def test_axon_recovery_parser_has_no_announce_surface() -> None:
    parser = miner_axon_cli._parser(
        prog="cathedral-miner-axon-recover",
        contract=miner_axon.UID124_AXON_CONTRACT,
        recovery_only=True,
    )
    commands = parser._subparsers._group_actions[0].choices
    assert set(commands) == {"recover"}


def test_packaged_scripts_expose_recovery_and_fleet_preview_only() -> None:
    project = Path(__file__).parents[2] / "pyproject.toml"
    source = project.read_text(encoding="utf-8")
    for retired in (
        "cathedral-independent-miner-announce =",
        "cathedral-second-miner-announce =",
        "cathedral-second-miner-plan =",
        "cathedral-uid124-axon-generation2 =",
        "cathedral-uid30-launch =",
    ):
        assert retired not in source
    assert "cathedral-miner-axon-recover =" in source
    assert "cathedral-uid30-recover =" in source
    assert "cathedral-multicompute-preview =" in source
    assert "cathedral-uid30-fleet-preview =" in source
