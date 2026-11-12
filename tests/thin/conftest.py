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
