"""The recurring operator surface has one fail-closed shadow relay runtime."""

from __future__ import annotations

import argparse
import contextlib
import inspect
import pathlib
import runpy
import sys
import tomllib
from types import SimpleNamespace

import pytest

from scaffold import cli
from scaffold import validator_thin as vt


ROOT = pathlib.Path(__file__).resolve().parents[2]


def _serve_namespace(*, config: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        config=config,
        dry_run=False,
        broadcast=False,
        once=False,
        offline=False,
    )


def test_only_the_relay_profile_ships_and_the_release_binds_it() -> None:
    assert not (ROOT / "config" / "validator-authority-sn39.toml").exists()
    assert not (ROOT / "config" / "validator-selfcompose-sn39.toml").exists()
    release_files = runpy.run_path(
        str(ROOT / "scripts" / "build_sn39_release_manifest.py")
    )["RELEASE_FILES"]
    assert "config/validator-thin-sn39-relay.toml" in release_files
    assert all(
        "authority" not in path and "selfcompose" not in path for path in release_files
    )


def test_every_shipped_validator_profile_selects_shadow() -> None:
    for path in sorted((ROOT / "config").glob("validator*.toml")):
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        assert "mode" not in document.get("provenance", {}), path.name
        cfg = cli._load_config_file(str(path))
        assert cfg.get("provenance", "shadow") == "shadow", path.name


@pytest.mark.parametrize("flag", ["--mode", "--provenance"])
def test_console_serve_does_not_expose_a_mode_switch(flag: str, capsys) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.main(["serve", flag, "authority"])
    assert caught.value.code == 2
    error = capsys.readouterr().err
    assert flag in error
    assert "unrecognized arguments" in error or "ambiguous option" in error


def test_direct_module_parser_does_not_expose_authority() -> None:
    parser = vt.build_parser()
    assert parser.parse_args([]).provenance == "shadow"
    with pytest.raises(SystemExit) as caught:
        parser.parse_args(["--provenance", "authority"])
    assert caught.value.code == 2


def test_direct_module_environment_override_is_explicitly_refused(
    monkeypatch, capsys
) -> None:
    monkeypatch.setenv("CATHEDRAL_VALIDATOR_PROVENANCE", "authority")
    monkeypatch.setattr(sys, "argv", ["validator_thin"])
    with pytest.raises(SystemExit) as caught:
        vt.main()
    assert caught.value.code == 2
    assert "authority/full was refused" in capsys.readouterr().err


def test_run_refuses_non_shadow_before_startup(monkeypatch) -> None:
    monkeypatch.setattr(
        vt,
        "_validate_runtime_contract",
        lambda _args: pytest.fail("non-shadow reached recurring startup validation"),
    )
    with pytest.raises(vt.wire.VectorError, match="only the shadow relay runtime"):
        vt.run(SimpleNamespace(provenance="authority"))


@pytest.mark.parametrize("mode", ["authority", "full", "thin", "off"])
def test_toml_mode_override_is_explicitly_refused(
    mode: str, tmp_path: pathlib.Path, capsys
) -> None:
    config = tmp_path / "validator.toml"
    config.write_text(f'[provenance]\nmode = "{mode}"\n', encoding="utf-8")
    assert cli._cmd_serve(_serve_namespace(config=str(config))) == 2
    error = capsys.readouterr().err
    assert "supports only the shadow relay runtime" in error
    assert "authority/full operator modes were removed" in error


def test_environment_mode_override_is_explicitly_refused(monkeypatch, capsys) -> None:
    monkeypatch.setenv("CATHEDRAL_VALIDATOR_PROVENANCE", "authority")
    assert cli._cmd_serve(_serve_namespace()) == 2
    assert "supports only the shadow relay runtime" in capsys.readouterr().err


def test_retired_feed_fallback_config_is_rejected(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "validator.toml"
    config.write_text(
        "[provenance]\nfeed_down_fallback = true\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="feed_down_fallback was removed"):
        cli._load_config_file(str(config))


def test_feed_fallback_has_no_runtime_plumbing() -> None:
    assert "feed_down_fallback" not in cli._DEFAULTS
    assert ("provenance", "feed_down_fallback") not in cli._CONFIG_MAP
    assert "feed_down_fallback" not in inspect.getsource(vt.tick)
    assert not hasattr(vt, "_authority_tick")


def test_a_dead_feed_never_dispatches_to_authority(monkeypatch) -> None:
    @contextlib.contextmanager
    def no_lock(_args):
        yield

    def unavailable(_args):
        raise vt._FeedUnavailableForThin("signed vector unavailable")

    monkeypatch.setattr(vt, "_prepare_tick_preflight", lambda _args: None)
    monkeypatch.setattr(vt, "_thin_tick_lock", no_lock)
    monkeypatch.setattr(vt, "_thin_tick_locked", unavailable)
    args = SimpleNamespace(
        provenance="shadow",
        publisher_url="https://example.invalid/vector.json",
        broadcast=False,
    )

    with pytest.raises(vt._FeedUnavailableForThin):
        vt.tick(args)
    assert args.provenance == "shadow"
