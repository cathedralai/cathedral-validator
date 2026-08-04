"""The sanitized-status stream is a THREE file contract, and all three must agree.

The split BOUNDARY.md declares: the raw journal carries hotkeys, receipts and
caller-supplied fields and stays 0600 with no reader group; a sanitized allowlisted
projection is what the public status service reads, group-readable.

Three files have to agree for that to hold, and a re-sync broke it by changing only
one of them:

  1. config/validator-selfcompose-sn39.toml must set [logs].status_jsonl, or nothing
     ever writes the projection.
  2. deploy/sn39/cathedral-sn39-public-status.service names exactly that path in
     ConditionPathExists, so if (1) is missing the unit can never start and skips
     silently rather than failing loudly.
  3. deploy/sn39/cathedral-sn39-release-launcher.py builds the COMPLETE child
     environment for os.execve, so the service's own Environment= never reaches the
     child; the launcher must grant the reader group on the projection and never on
     the raw journal.

These tests read the shipped files, so a future sync that drops any one of the three
fails here instead of on the host.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re

try:  # tomllib is stdlib from 3.11
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CONFIG = _ROOT / "config" / "validator-selfcompose-sn39.toml"
_STATUS_UNIT = _ROOT / "deploy" / "sn39" / "cathedral-sn39-public-status.service"
_VALIDATOR_UNIT = _ROOT / "deploy" / "sn39" / "cathedral-validator-sn39.service"
_LAUNCHER = _ROOT / "deploy" / "sn39" / "cathedral-sn39-release-launcher.py"

_spec = importlib.util.spec_from_file_location("_sn39_launcher_contract", _LAUNCHER)
_launcher = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_launcher)


def _logs() -> dict:
    return tomllib.loads(_CONFIG.read_text(encoding="utf-8")).get("logs", {})


def test_the_config_writes_the_sanitized_projection():
    logs = _logs()
    assert logs.get("status_jsonl"), (
        "without [logs].status_jsonl nothing writes the projection, and the public "
        "status unit's ConditionPathExists can never be satisfied"
    )


def test_the_raw_journal_and_the_projection_are_different_files():
    logs = _logs()
    assert logs.get("jsonl") and logs.get("status_jsonl")
    assert logs["jsonl"] != logs["status_jsonl"]


def test_the_status_unit_waits_for_exactly_the_configured_projection():
    unit = _STATUS_UNIT.read_text(encoding="utf-8")
    condition = re.search(r"^ConditionPathExists=(.+)$", unit, re.M)
    assert condition, "the status unit is expected to gate on the projection existing"
    assert condition.group(1).strip() == _logs()["status_jsonl"], (
        "the unit waits for a file the config does not write"
    )


def test_the_launcher_grants_the_group_on_the_projection_only():
    for mode in ("continuous",):
        environment = _launcher._child_environment(mode)
        assert "CATHEDRAL_VALIDATOR_JSONL_GROUP" not in environment, (
            f"{mode}: the raw journal must not be group-readable"
        )
        assert (
            environment.get("CATHEDRAL_VALIDATOR_STATUS_GROUP")
            == "cathedral-validator-log"
        ), f"{mode}: the projection is what the reader needs"


def test_the_validator_unit_agrees_with_the_launcher():
    unit = _VALIDATOR_UNIT.read_text(encoding="utf-8")
    assert re.search(
        r"^Environment=CATHEDRAL_VALIDATOR_STATUS_GROUP=cathedral-validator-log$",
        unit,
        re.M,
    )
    assert not re.search(r"^Environment=CATHEDRAL_VALIDATOR_JSONL_GROUP=", unit, re.M)


def test_the_reader_account_can_reach_the_projection_group():
    unit = _STATUS_UNIT.read_text(encoding="utf-8")
    assert re.search(r"^SupplementaryGroups=.*cathedral-validator-log", unit, re.M), (
        "the status reader runs as another account and needs the projection group"
    )
