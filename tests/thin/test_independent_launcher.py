"""Start-up gates: who may run this, on which chain, journalling where.

The refuse-list is the sharpest of these. The independent composer pays a burn
destination, and one of the two refused hotkeys IS that destination: a runtime
holding it could pay itself every epoch. The other is the live relay identity,
which must never have a second runtime signing as it. Both are start-up
refusals, so the process does not exist rather than warning and continuing.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from cathedral_thin.independent.constants import (
    BURN_HOTKEY,
    FINNEY_GENESIS_HASH,
    INDEPENDENT_STATE_FILE,
    LINEAGE,
    REFUSE_HOTKEYS,
)
from cathedral_thin.independent.errors import (
    BroadcastDisabled,
    ConfigError,
    GenesisPinError,
    RefuseListError,
)
from cathedral_thin.independent.launcher import (
    check_genesis_pin,
    load_config,
    main,
    parse_config,
    refuse_wallet,
)
from cathedral_thin.independent.refuse import is_refused, require_permitted_hotkey

PROFILE = Path("config/validator-independent-sn39.toml")
RELAY_HOTKEY = "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"


def profile_document() -> dict:
    return tomllib.loads(PROFILE.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# refuse-list
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("ss58", sorted(REFUSE_HOTKEYS))
def test_a_refuse_listed_hotkey_will_not_start(ss58):
    assert is_refused(ss58)
    with pytest.raises(RefuseListError, match="refuse-list"):
        refuse_wallet(ss58)
    with pytest.raises(RefuseListError, match="refuse-list"):
        require_permitted_hotkey(ss58)


def test_the_refuse_list_is_exactly_the_relay_and_the_burn_destination():
    assert REFUSE_HOTKEYS == frozenset({RELAY_HOTKEY, BURN_HOTKEY})
    with pytest.raises(RefuseListError, match="burn destination"):
        refuse_wallet(BURN_HOTKEY)


def test_a_permitted_hotkey_passes_through():
    other = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
    assert refuse_wallet(other) == other
    assert not is_refused(other)


def test_an_empty_hotkey_is_refused():
    with pytest.raises(RefuseListError, match="non-empty ss58"):
        refuse_wallet("")


# --------------------------------------------------------------------------- #
# genesis pin
# --------------------------------------------------------------------------- #


def test_the_pinned_genesis_is_accepted_and_anything_else_halts():
    assert check_genesis_pin(FINNEY_GENESIS_HASH) == FINNEY_GENESIS_HASH
    assert check_genesis_pin(FINNEY_GENESIS_HASH.upper()) == FINNEY_GENESIS_HASH
    with pytest.raises(GenesisPinError, match="not the pinned Finney genesis"):
        check_genesis_pin("0x" + "00" * 32)
    with pytest.raises(GenesisPinError, match="no chain genesis"):
        check_genesis_pin(None)


# --------------------------------------------------------------------------- #
# the shipped profile
# --------------------------------------------------------------------------- #


def test_the_shipped_profile_loads_and_broadcasts_nothing():
    config = load_config(PROFILE)
    assert config.lineage == LINEAGE
    assert config.broadcast is False
    assert config.netuid == 39
    assert config.network == "finney"
    assert config.genesis_hash == FINNEY_GENESIS_HASH
    assert config.state_file == INDEPENDENT_STATE_FILE
    assert config.burn_hotkey == BURN_HOTKEY
    assert (config.version_key, config.mecid, config.tempo) == (10005000, 0, 360)
    assert config.commit_reveal_enabled is False
    assert config.min_allowed_weights == 1
    assert config.max_weight_limit == 1.0
    assert config.mortal_period_blocks == 16


def test_the_shipped_profile_names_no_thin_journal_and_no_relay_feed():
    text = PROFILE.read_text(encoding="utf-8")
    assert "thin-state.json" not in text
    assert "weights/next" not in text
    assert "api.cathedral.computer" not in text


def test_the_shipped_profile_never_tells_an_operator_to_broadcast():
    """The only mention of the flag is that it does not exist."""
    for line in PROFILE.read_text(encoding="utf-8").splitlines():
        if "--broadcast" in line:
            assert "no `--broadcast` flag" in line


def test_the_shipped_profile_documents_the_refuse_list():
    text = PROFILE.read_text(encoding="utf-8")
    for ss58 in REFUSE_HOTKEYS:
        assert ss58 in text


def test_the_profile_summary_hides_the_document_path():
    summary = load_config(PROFILE).summary()
    assert summary["policy_endpoint"] == "https://policy.example.invalid:443"
    assert "policy-bundle.json" not in json.dumps(summary)


# --------------------------------------------------------------------------- #
# configuration refusals
# --------------------------------------------------------------------------- #


def test_a_config_asking_for_broadcast_fails_to_load():
    document = profile_document()
    document["runtime"]["broadcast"] = True
    with pytest.raises(BroadcastDisabled, match="no chain writer"):
        parse_config(document)


def test_a_config_pointing_at_another_runtime_journal_is_refused():
    document = profile_document()
    document["runtime"]["state_file"] = "/var/lib/cathedral-validator/thin-state.json"
    with pytest.raises(ConfigError, match="must be named"):
        parse_config(document)


def test_a_config_on_the_wrong_chain_is_refused():
    document = profile_document()
    document["network"]["genesis_hash"] = "0x" + "11" * 32
    with pytest.raises(GenesisPinError, match="not the pinned"):
        parse_config(document)


def test_a_config_on_another_netuid_is_refused():
    document = profile_document()
    document["network"]["netuid"] = 1
    with pytest.raises(ConfigError, match="network.netuid must be 39"):
        parse_config(document)


def test_a_config_naming_a_refuse_listed_hotkey_is_refused():
    document = profile_document()
    document["network"]["validator_hotkey"] = BURN_HOTKEY
    with pytest.raises(RefuseListError, match="refuse-list"):
        parse_config(document)


def test_a_config_with_a_narrower_weight_cap_is_refused():
    """0.5 would make a legal burn-heavy vector overweight on chain."""
    document = profile_document()
    document["weights"]["max_weight_limit"] = 0.5
    with pytest.raises(ConfigError, match="max_weight_limit must be 1.0"):
        parse_config(document)


def test_a_config_enabling_commit_reveal_is_refused():
    document = profile_document()
    document["weights"]["commit_reveal_enabled"] = True
    with pytest.raises(ConfigError, match="commit_reveal_enabled must be false"):
        parse_config(document)


@pytest.mark.parametrize(
    "section,field,value",
    [
        ("weights", "version_key", 1),
        ("weights", "mecid", 1),
        ("weights", "tempo", 100),
        ("weights", "mortal_period_blocks", 128),
    ],
)
def test_a_config_deviating_from_a_chain_pin_is_refused(section, field, value):
    document = profile_document()
    document[section][field] = value
    with pytest.raises(ConfigError, match=field):
        parse_config(document)


@pytest.mark.parametrize(
    "url",
    [
        "http://policy.example.invalid/b.json",
        "https://user@policy.example.invalid/b.json",
        "https://policy.example.invalid/b.json?sig=1",
    ],
)
def test_a_config_with_an_unhardened_policy_url_is_refused(url):
    document = profile_document()
    document["policy"]["url"] = url
    with pytest.raises(Exception) as raised:
        parse_config(document)
    assert "policy URL" in str(raised.value)


def test_an_unknown_config_section_is_refused():
    document = profile_document()
    document["publisher"] = {"url": "https://api.example.invalid"}
    with pytest.raises(ConfigError, match="unknown sections: publisher"):
        parse_config(document)


def test_a_missing_config_file_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="could not be read"):
        load_config(tmp_path / "absent.toml")


# --------------------------------------------------------------------------- #
# the CLI
# --------------------------------------------------------------------------- #


def test_main_reports_the_resolved_pins(capsys):
    assert main(["--config", str(PROFILE)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["lineage"] == LINEAGE
    assert summary["broadcast"] is False


def test_main_refuses_a_refuse_listed_hotkey(capsys):
    code = main(["--config", str(PROFILE), "--hotkey-ss58", BURN_HOTKEY])
    assert code == 2
    assert "RefuseListError" in capsys.readouterr().err


def test_main_refuses_the_wrong_chain(capsys):
    code = main(["--config", str(PROFILE), "--observed-genesis", "0x" + "22" * 32])
    assert code == 2
    assert "GenesisPinError" in capsys.readouterr().err


def test_main_refuses_a_missing_config(capsys, tmp_path):
    assert main(["--config", str(tmp_path / "absent.toml")]) == 2
    assert "ConfigError" in capsys.readouterr().err


def test_the_cli_has_no_broadcast_flag(capsys):
    assert main(["--config", str(PROFILE), "--broadcast"]) == 2
    assert "no --broadcast flag" in capsys.readouterr().err


def test_the_cli_help_mentions_no_broadcast():
    proc = subprocess.run(
        [sys.executable, "-m", "cathedral_thin.independent", "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "--broadcast" not in proc.stdout
    assert "broadcasts nothing" in proc.stdout


def test_the_module_entry_point_refuses_the_relay_hotkey():
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "cathedral_thin.independent",
            "--config",
            str(PROFILE),
            "--hotkey-ss58",
            RELAY_HOTKEY,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "refuse-list" in proc.stderr
