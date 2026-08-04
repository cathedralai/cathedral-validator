"""The launcher must group-read the SANITIZED projection, never the raw journal.

`04d6b3b` established the split and `deploy/sn39/cathedral-validator-sn39.service`
encodes it: the raw journal (hotkeys, receipts, caller-supplied fields) stays 0600,
and only the sanitized status projection is group-readable by the public status
service, which runs as a different account.

The launcher builds the COMPLETE environment for `os.execve`, so the unit's own
`Environment=` never reaches the child and whatever the launcher sets is the entire
access decision. It set `CATHEDRAL_VALIDATOR_JSONL_GROUP` and never set
`CATHEDRAL_VALIDATOR_STATUS_GROUP`, which is exactly inverted: the raw journal became
0640 group-readable while the projection stayed 0600 and unreadable by its reader.
`ProtectSystem=strict` does not compensate, because it makes /var/log read-only
rather than hidden, so the DAC mode is the whole decision.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re

import pytest

_LAUNCHER_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "deploy"
    / "sn39"
    / "cathedral-sn39-release-launcher.py"
)
_spec = importlib.util.spec_from_file_location("_sn39_release_launcher", _LAUNCHER_PATH)
_launcher = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_launcher)

_UNIT_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "deploy"
    / "sn39"
    / "cathedral-validator-sn39.service"
)

_CHILD_MODES = ("continuous",)


@pytest.mark.parametrize("mode", _CHILD_MODES)
def test_the_raw_journal_group_is_never_granted(mode):
    environment = _launcher._child_environment(mode)
    assert "CATHEDRAL_VALIDATOR_JSONL_GROUP" not in environment, (
        "the raw journal carries hotkeys, receipts and caller-supplied fields; "
        "granting it a reader group makes it 0640 to another account"
    )


@pytest.mark.parametrize("mode", _CHILD_MODES)
def test_the_sanitized_projection_group_is_granted(mode):
    environment = _launcher._child_environment(mode)
    assert (
        environment.get("CATHEDRAL_VALIDATOR_STATUS_GROUP") == "cathedral-validator-log"
    ), "the projection is what the public status service exists to read"


def test_the_status_mode_grants_neither():
    # The status reader is a separate unit and account; it writes no validator log.
    environment = _launcher._child_environment("status")
    assert "CATHEDRAL_VALIDATOR_JSONL_GROUP" not in environment
    assert "CATHEDRAL_VALIDATOR_STATUS_GROUP" not in environment


def test_the_launcher_agrees_with_the_unit_it_replaces():
    # The unit documents the same split. Since the launcher's environment wins for
    # a launcher-mediated start, the two must not disagree.
    unit = _UNIT_PATH.read_text(encoding="utf-8")
    assert re.search(
        r"^Environment=CATHEDRAL_VALIDATOR_STATUS_GROUP=cathedral-validator-log$",
        unit,
        re.M,
    ), "the unit is expected to grant the reader group on the projection"
    assert not re.search(
        r"^Environment=CATHEDRAL_VALIDATOR_JSONL_GROUP=", unit, re.M
    ), "the unit is expected to leave the raw journal ungrouped"
    environment = _launcher._child_environment("continuous")
    assert "CATHEDRAL_VALIDATOR_JSONL_GROUP" not in environment
    assert environment.get("CATHEDRAL_VALIDATOR_STATUS_GROUP") == (
        "cathedral-validator-log"
    )
