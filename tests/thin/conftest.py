"""Shared setup for the thin validator tests."""

from __future__ import annotations

import pytest

from cathedral_thin.independent_runtime import approved_miners


class _EveryHotkey(frozenset):
    """An approved list that admits any hotkey a test invents."""

    def __contains__(self, hotkey: object) -> bool:
        return True


@pytest.fixture(autouse=True)
def approved_compute_hotkeys(monkeypatch):
    """Approve every test miner, so the older tests still exercise paid UIDs.

    The release list is empty, and with it every vector is burn only. The
    gate itself is tested in test_gated_compute_weights.py, which overrides
    this fixture with exact lists.
    """

    monkeypatch.setattr(approved_miners, "APPROVED_COMPUTE_HOTKEYS", _EveryHotkey())


@pytest.fixture(autouse=True)
def escape_lane_opted_out(monkeypatch):
    """Run the older CLI tests with the escape lane off, as they were written.

    The release turns the lane on by default (AB#830), which would make every
    CLI test read the public feed over the network. The default itself is
    tested in test_escape_receipt_weights.py, which removes this variable.
    """

    monkeypatch.setenv("CATHEDRAL_ESCAPE_WEIGHT_FRACTION", "0")
