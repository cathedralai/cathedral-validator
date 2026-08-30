"""The event journal's directory contract.

The journal is opened from the STARTUP event, before the first tick, so its
path is the first thing a new operator can get wrong. Two behaviours have to
hold together:

1. A missing parent directory is created, owner-only. Every shipped example
   logs under a per-operator directory that nothing else provisions, so
   refusing to create it turns a copied config into a traceback for no gain.
2. A parent directory this process cannot create — the shipped SN39 profiles
   log to ``/var/log/cathedral-validator``, which the service install owns —
   raises `EventLogPathError` naming the directory and both fixes. A raw
   ``FileNotFoundError`` from inside ``os.open`` names neither the setting
   that chose the path nor the command that repairs it.

The file's own owner/mode/symlink gates are unchanged and are covered by
tests/thin/test_status_sanitization.py; nothing here may relax them.
"""

from __future__ import annotations

import os
import stat

import pytest

from scaffold.events import EventLogger, EventLogPathError


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_missing_journal_directory_is_created_owner_only(tmp_path):
    journal = tmp_path / "cathedral" / "logs" / "validator-events.jsonl"

    logger = EventLogger(mode="thin", jsonl_path=str(journal))
    logger.event("STARTUP", stage="startup")
    logger.close()

    assert journal.exists()
    assert _mode(journal) == 0o600, "the journal itself stays private"
    assert _mode(journal.parent) == 0o700, (
        "a directory we create for a 0600 journal must be at least as private"
    )
    assert _mode(journal.parent.parent) == 0o700


def test_an_existing_directory_keeps_its_own_mode(tmp_path):
    """The live unit ships LogsDirectoryMode=0750; we must not restat it.

    Creating a missing directory is a convenience for previews. Re-permissioning
    one the service install already provisioned would be a deploy change wearing
    a convenience's clothes.
    """
    directory = tmp_path / "provisioned"
    directory.mkdir(mode=0o750)
    os.chmod(directory, 0o750)

    logger = EventLogger(mode="thin", jsonl_path=str(directory / "events.jsonl"))
    logger.close()

    assert _mode(directory) == 0o750


def test_an_uncreatable_directory_names_the_path_and_the_fix(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.mkdir(mode=0o500)
    os.chmod(blocked, 0o500)
    journal = blocked / "cathedral-validator" / "validator-events.jsonl"

    try:
        with pytest.raises(EventLogPathError) as caught:
            EventLogger(mode="thin", jsonl_path=str(journal))
    finally:
        os.chmod(blocked, 0o700)

    message = str(caught.value)
    assert str(journal.parent) in message, "the operator must be told which path"
    assert "install -d" in message, "and how to provision it"
    assert "--jsonl" in message, "and how to avoid needing to"
    assert "event log" in message, "and which of the two streams failed"


def test_the_status_stream_reports_its_own_label(tmp_path):
    """Both streams take the same path, so the message must say which one."""
    blocked = tmp_path / "blocked"
    blocked.mkdir(mode=0o500)
    os.chmod(blocked, 0o500)

    try:
        with pytest.raises(EventLogPathError) as caught:
            EventLogger(
                mode="thin",
                jsonl_path=str(tmp_path / "ok" / "events.jsonl"),
                status_path=str(blocked / "denied" / "status.jsonl"),
            )
    finally:
        os.chmod(blocked, 0o700)

    assert "status log" in str(caught.value)


def test_an_unopenable_journal_is_reported_not_raised_raw(tmp_path):
    """A present-but-unopenable path is the same class of operator mistake."""
    directory = tmp_path / "logs"
    directory.mkdir()
    journal = directory / "events.jsonl"
    journal.symlink_to(tmp_path / "elsewhere.jsonl")

    with pytest.raises(EventLogPathError) as caught:
        EventLogger(mode="thin", jsonl_path=str(journal))

    assert str(journal) in str(caught.value)


def test_the_cli_prints_the_fix_instead_of_a_traceback(tmp_path, monkeypatch, capsys):
    """`cathedral-validator serve` must exit 2 with one line, not a traceback.

    Non-zero, so a supervising unit still treats it as a failed start; the
    point is only that the operator gets the remediation rather than a stack.
    """
    from scaffold import cli
    from scaffold import validator_thin as vt

    monkeypatch.setattr(vt, "installed_recurring_context", lambda: True)

    blocked = tmp_path / "blocked"
    blocked.mkdir(mode=0o500)
    os.chmod(blocked, 0o500)
    config = tmp_path / "my-validator.toml"
    config.write_text(
        "[network]\n"
        'name = "finney"\n'
        "netuid = 39\n"
        "[weight_policy]\n"
        f'public_key_hex = "{"a" * 64}"\n'
        "[logs]\n"
        f'jsonl = "{blocked}/cathedral-validator/validator-events.jsonl"\n'
    )

    try:
        code = cli.main(["serve", "--config", str(config), "--once"])
    finally:
        os.chmod(blocked, 0o700)

    assert code == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("error: ")
    assert "Traceback" not in captured.err
