"""Relative provenance key-file pins must survive a foreign working directory.

The shipped profiles pin their trusted key bundles as
``config/provenance/*.json``, and `scaffold.provenance_audit._load_pubkeys`
reads them with ``Path(pin).read_bytes()`` — against the process CWD. That
resolves only because the SN39 release launcher chdirs into the release before
exec. Every other invocation shape (a copied config run from ``$HOME``, a unit
with a different WorkingDirectory, a packaged install) loses the shadow audit
to a ``FileNotFoundError``. The audit never blocks the write path, so nothing
fails loudly: the validator keeps broadcasting with its independent check
silently off.

`cli._anchor_config_paths` closes that without moving anything that currently
resolves. The CWD interpretation still wins when it exists — the live mainnet
writer's pins are untouched — and the config file's own directory is consulted
only as a fallback. The tests below pin both halves, because the fallback
alone would be a live-behaviour change dressed as a fix.
"""

from __future__ import annotations

import json
from pathlib import Path

from scaffold import cli

ROOT = Path(__file__).resolve().parents[2]

_KEY_PINS = (
    "provenance_registry_keys",
    "provenance_report_keys",
    "provenance_index_keys",
)


def _write_config(directory: Path, pin: str) -> Path:
    config = directory / "my-validator.toml"
    config.write_text(
        "[network]\n"
        'name = "finney"\n'
        "netuid = 39\n"
        "[provenance]\n"
        'mode = "shadow"\n'
        f'index_keys = "{pin}"\n'
    )
    return config


def _plant_keys(directory: Path, marker: str) -> Path:
    keys = directory / "config" / "provenance"
    keys.mkdir(parents=True, exist_ok=True)
    target = keys / "index-keys.json"
    target.write_text(json.dumps({marker: "A" * 43 + "="}))
    return target


def test_a_relative_pin_resolves_beside_its_config(tmp_path, monkeypatch):
    """The whole point: run from anywhere, still find the pinned bundle."""
    install = tmp_path / "install"
    install.mkdir()
    planted = _plant_keys(install, "beside-the-config")
    config = _write_config(install, "config/provenance/index-keys.json")

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    cfg = cli._load_config_file(str(config))

    assert Path(cfg["provenance_index_keys"]) == planted
    assert Path(cfg["provenance_index_keys"]).is_absolute()


def test_the_working_directory_still_wins_when_it_resolves(tmp_path, monkeypatch):
    """The live shape: the launcher chdirs into the release tree.

    The installed SN39 config lives in /etc/cathedral-validator while its key
    bundle lives in the release checkout, so anchoring unconditionally would
    point a live mainnet writer at a directory that does not hold its pins.
    """
    install = tmp_path / "etc"
    install.mkdir()
    _plant_keys(install, "beside-the-config")
    config = _write_config(install, "config/provenance/index-keys.json")

    release = tmp_path / "release"
    release.mkdir()
    _plant_keys(release, "in-the-release")
    monkeypatch.chdir(release)

    cfg = cli._load_config_file(str(config))

    # Unchanged: still the CWD-relative string the audit reads today.
    assert cfg["provenance_index_keys"] == "config/provenance/index-keys.json"


def test_an_absolute_pin_is_never_rewritten(tmp_path, monkeypatch):
    install = tmp_path / "install"
    install.mkdir()
    absolute = _plant_keys(tmp_path / "keys", "absolute")
    config = _write_config(install, str(absolute))
    monkeypatch.chdir(tmp_path)

    cfg = cli._load_config_file(str(config))

    assert cfg["provenance_index_keys"] == str(absolute)


def test_a_pin_that_resolves_nowhere_is_left_alone(tmp_path, monkeypatch):
    """No invented paths: a genuinely missing bundle must still report itself.

    Rewriting an unresolvable pin would only move which path the audit's own
    error names, and the operator pinned that string on purpose.
    """
    install = tmp_path / "install"
    install.mkdir()
    config = _write_config(install, "config/provenance/index-keys.json")
    monkeypatch.chdir(tmp_path)

    cfg = cli._load_config_file(str(config))

    assert cfg["provenance_index_keys"] == "config/provenance/index-keys.json"


def test_the_shipped_profile_resolves_in_place_from_a_foreign_directory(
    tmp_path, monkeypatch
):
    """`--config config/validator-thin-sn39-relay.toml` run from anywhere.

    The profile is still inside ``config/``, so its pins are written relative
    to the root that ``config/`` hangs off — one directory above the config
    file, not beside it.
    """
    monkeypatch.chdir(tmp_path)
    cfg = cli._load_config_file(str(ROOT / "config" / "validator-thin-sn39-relay.toml"))

    for pin in _KEY_PINS:
        resolved = Path(cfg[pin])
        assert resolved.is_absolute(), pin
        assert resolved.is_file(), pin


def test_a_relay_profile_copy_resolves_from_a_foreign_directory(tmp_path, monkeypatch):
    """A copied release profile still resolves its pinned key files.

    Copying the relay profile to the repository root puts the copy one level
    above ``config/``, so
    the pins resolve beside it.
    """
    checkout = tmp_path / "cathedral-validator"
    (checkout / "config" / "provenance").mkdir(parents=True)
    for name in ("registry-keys.json", "report-keys.json", "index-keys.json"):
        source = ROOT / "config" / "provenance" / name
        (checkout / "config" / "provenance" / name).write_bytes(source.read_bytes())
    copied = checkout / "my-validator.toml"
    copied.write_bytes(
        (ROOT / "config" / "validator-thin-sn39-relay.toml").read_bytes()
    )

    monkeypatch.chdir(tmp_path)
    cfg = cli._load_config_file(str(copied))

    for pin in _KEY_PINS:
        resolved = Path(cfg[pin])
        assert resolved.is_absolute(), pin
        assert resolved.parent == checkout / "config" / "provenance", pin
