"""The daily alarm that fails before signed release metadata or the bootstrap expires.

Every test reads fixture files. None touches the network.
"""

from __future__ import annotations

import hashlib
import json
import re
import runpy
from pathlib import Path
from typing import Any

import pytest

import cathedral_thin.independent_runtime.updater as updater

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_release_expiry.py"
NOW = 1_800_000_000
DAY = 86_400
BASE = (
    "https://github.com/cathedralai/cathedral-validator/releases/download/"
    "validator-bootstrap-production-s9-" + "e" * 64
)


def _check() -> dict[str, Any]:
    return runpy.run_path(str(SCRIPT))


def _metadata(
    channel: str, *, sequence: int, expires_in: int, lifetime: int = 7 * DAY
) -> bytes:
    expires = NOW + expires_in
    signed = {
        "schema": "cathedral_validator_release_v1",
        "channel": channel,
        "sequence": sequence,
        "issued_unix": expires - lifetime,
        "expires_unix": expires,
        "release": {},
    }
    # The alarm reads validity only; hosts verify signatures.
    return json.dumps({"signed": signed, "signature": "AAAA"}).encode("ascii")


def _manifest(*, sequence: int, expires_in: int, lifetime: int = 30 * DAY) -> bytes:
    expires = NOW + expires_in
    return json.dumps(
        {
            "schema": "cathedral_validator_updater_bootstrap_v3",
            "bootstrap_metadata": {
                "expires_unix": expires,
                "issued_unix": expires - lifetime,
                "sequence": sequence,
            },
            "bundle": {"sha256": "a" * 64, "size": 1},
        },
        sort_keys=True,
    ).encode("ascii")


def _install_script(manifest: bytes) -> str:
    digest = hashlib.sha256(manifest).hexdigest()
    return (
        "#!/usr/bin/env bash\n"
        f"BASE={BASE}\n"
        "printf '%s  %s\\n' \\\n"
        f"  '{'1' * 64}' \"$BOOTSTRAP_DIR/updater-bootstrap.tar.gz\" \\\n"
        f"  '{digest}' \"$BOOTSTRAP_DIR/updater-bootstrap.manifest.json\" \\\n"
        f"  '{'2' * 64}' \"$BOOTSTRAP_DIR/updater-bootstrap.manifest.sig\" \\\n"
        "  | sudo sha256sum --check --strict\n"
    )


def _fixtures(
    tmp_path: Path,
    *,
    stable: bytes | None = None,
    canary: bytes | None = None,
    manifest: bytes | None = None,
    pinned: bytes | None = None,
) -> list[str]:
    stable = stable or _metadata("stable", sequence=4, expires_in=13 * DAY)
    canary = canary or _metadata("canary", sequence=5, expires_in=13 * DAY)
    manifest = manifest or _manifest(sequence=3, expires_in=29 * DAY)
    paths = {
        "stable.json": stable,
        "canary.json": canary,
        "updater-bootstrap.manifest.json": manifest,
    }
    for name, body in paths.items():
        (tmp_path / name).write_bytes(body)
    (tmp_path / "update.env").write_text(
        "# fixture\n"
        "CATHEDRAL_VALIDATOR_CANARY_METADATA_URL=https://example.invalid/canary.json\n"
        "CATHEDRAL_VALIDATOR_STABLE_METADATA_URL=https://example.invalid/stable.json\n"
    )
    (tmp_path / "install.sh").write_text(_install_script(pinned or manifest))
    return [
        "--now-unix",
        str(NOW),
        "--update-env",
        str(tmp_path / "update.env"),
        "--install-script",
        str(tmp_path / "install.sh"),
        "--stable",
        str(tmp_path / "stable.json"),
        "--canary",
        str(tmp_path / "canary.json"),
        "--bootstrap-manifest",
        str(tmp_path / "updater-bootstrap.manifest.json"),
    ]


def _no_network(url: str, _maximum: int) -> bytes:
    raise AssertionError(f"fixture test fetched {url}")


def _run(check: dict[str, Any], argv: list[str], capsys) -> tuple[int, str, str]:
    code = check["main"](argv, fetcher=_no_network)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_all_valid_beyond_the_window_passes(tmp_path: Path, capsys) -> None:
    code, out, _err = _run(_check(), _fixtures(tmp_path), capsys)
    assert code == 0
    assert out.count("OK: ") == 3
    assert "stable release metadata sequence 4" in out
    assert "canary release metadata sequence 5" in out
    assert "updater bootstrap manifest sequence 3" in out


@pytest.mark.parametrize(
    ("artifact", "fixture", "expected"),
    (
        (
            "stable",
            {"stable": _metadata("stable", sequence=4, expires_in=5 * DAY)},
            "EXPIRES SOON: stable release metadata sequence 4 expires at "
            "2027-01-20T08:00:00Z, in 5.0 days",
        ),
        (
            "canary",
            {"canary": _metadata("canary", sequence=5, expires_in=-DAY)},
            "EXPIRED: canary release metadata sequence 5 expired at "
            "2027-01-14T08:00:00Z, 1.0 days ago",
        ),
        (
            "bootstrap",
            {"manifest": _manifest(sequence=3, expires_in=2 * DAY)},
            "EXPIRES SOON: updater bootstrap manifest sequence 3 expires at "
            "2027-01-17T08:00:00Z, in 2.0 days",
        ),
        (
            "bootstrap",
            {"manifest": _manifest(sequence=3, expires_in=0)},
            "EXPIRED: updater bootstrap manifest sequence 3 expired at "
            "2027-01-15T08:00:00Z",
        ),
    ),
)
def test_each_artifact_fails_within_five_days_naming_it_and_its_expiry(
    tmp_path: Path, capsys, artifact: str, fixture: dict[str, bytes], expected: str
) -> None:
    code, out, err = _run(_check(), _fixtures(tmp_path, **fixture), capsys)
    assert code == 1
    assert expected in out
    assert out.count("OK: ") == 2
    assert "FAILED for 1 of 3 artifacts" in err
    guide = "case (c)" if artifact == "bootstrap" else "case (a)"
    assert f"docs/RENEW_RELEASE_CHANNEL.md, {guide}" in out


def test_window_boundary_is_inclusive(tmp_path: Path, capsys) -> None:
    check = _check()
    outside = _fixtures(
        tmp_path,
        stable=_metadata("stable", sequence=4, expires_in=5 * DAY + 1),
    )
    assert _run(check, outside, capsys)[0] == 0
    inside = _fixtures(
        tmp_path,
        stable=_metadata("stable", sequence=4, expires_in=5 * DAY),
    )
    assert _run(check, inside, capsys)[0] == 1
    assert _run(check, [*inside, "--warn-days", "4"], capsys)[0] == 0


def test_the_published_state_on_the_handoff_date_fails(tmp_path: Path, capsys) -> None:
    """Stable 3 and canary 4 expired on 2026-09-15; the bootstrap on 2026-10-03."""

    handoff = 1_790_380_800  # 2026-09-26T00:00:00Z
    stable_expiry = 1_789_507_587  # 2026-09-15T21:26:27Z
    canary_expiry = 1_789_506_398  # 2026-09-15T21:06:38Z
    bootstrap_expiry = 1_790_985_604  # 2026-10-03T00:00:04Z
    argv = _fixtures(
        tmp_path,
        stable=_metadata("stable", sequence=3, expires_in=stable_expiry - NOW),
        canary=_metadata("canary", sequence=4, expires_in=canary_expiry - NOW),
        manifest=_manifest(sequence=2, expires_in=bootstrap_expiry - NOW),
    )
    argv[argv.index("--now-unix") + 1] = str(handoff)
    code, out, _err = _run(_check(), argv, capsys)
    assert code == 1
    assert "EXPIRED: stable release metadata sequence 3 expired at " in out
    assert "2026-09-15T21:26:27Z" in out
    assert "EXPIRED: canary release metadata sequence 4 expired at " in out
    assert "2026-09-15T21:06:38Z" in out
    assert "OK: updater bootstrap manifest sequence 2 expires at " in out

    # The alarm starts failing for the bootstrap at 2026-09-28T00:00:04Z.
    argv[argv.index("--now-unix") + 1] = str(bootstrap_expiry - 5 * DAY - 1)
    code, out, _err = _run(_check(), argv, capsys)
    assert "OK: updater bootstrap manifest sequence 2 expires at " in out
    argv[argv.index("--now-unix") + 1] = str(bootstrap_expiry - 5 * DAY)
    code, out, _err = _run(_check(), argv, capsys)
    assert "EXPIRES SOON: updater bootstrap manifest sequence 2 expires at " in out
    assert "2026-10-03T00:00:04Z" in out


def test_manifest_that_install_sh_does_not_pin_fails(tmp_path: Path, capsys) -> None:
    served = _manifest(sequence=3, expires_in=29 * DAY)
    pinned = _manifest(sequence=2, expires_in=29 * DAY)
    code, out, _err = _run(
        _check(), _fixtures(tmp_path, manifest=served, pinned=pinned), capsys
    )
    assert code == 1
    assert "UNREADABLE: updater bootstrap manifest" in out
    assert "but scripts/install.sh pins" in out


@pytest.mark.parametrize(
    ("body", "reason"),
    (
        (
            _metadata("canary", sequence=4, expires_in=13 * DAY),
            "stable release metadata is for channel 'canary'",
        ),
        (
            _metadata("stable", sequence=4, expires_in=13 * DAY, lifetime=15 * DAY),
            "validity window the updater refuses",
        ),
        (b'{"signed": {}, "signed": {}}', "repeats key 'signed'"),
        (b"not json", "is not strict JSON"),
    ),
)
def test_malformed_metadata_fails_closed(
    tmp_path: Path, capsys, body: bytes, reason: str
) -> None:
    code, out, _err = _run(_check(), _fixtures(tmp_path, stable=body), capsys)
    assert code == 1
    assert "UNREADABLE: " in out
    assert reason in out


def test_missing_source_fails_rather_than_passing(tmp_path: Path, capsys) -> None:
    argv = _fixtures(tmp_path)
    (tmp_path / "canary.json").unlink()
    code, out, _err = _run(_check(), argv, capsys)
    assert code == 1
    assert "UNREADABLE: cannot read" in out


def test_github_actions_gets_one_error_annotation_per_failure(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    argv = _fixtures(tmp_path, canary=_metadata("canary", sequence=5, expires_in=-DAY))
    code, out, _err = _run(_check(), argv, capsys)
    assert code == 1
    assert out.count("::error ") == 1
    assert "::error title=canary release metadata expiry::EXPIRED: canary" in out


def test_default_sources_are_what_hosts_and_the_installer_read(
    capsys,
) -> None:
    check = _check()
    urls = check["metadata_urls"](
        ROOT / "deploy" / "validator-update" / "update.env.example"
    )
    assert urls == {
        "stable": "https://raw.githubusercontent.com/cathedralai/"
        "cathedral-validator/validator-release-channel/validator/stable.json",
        "canary": "https://raw.githubusercontent.com/cathedralai/"
        "cathedral-validator/validator-release-channel/validator/canary.json",
    }
    manifest_url, pinned = check["bootstrap_location"](ROOT / "scripts" / "install.sh")
    install = (ROOT / "scripts" / "install.sh").read_text()
    base = re.search(r"^BASE=(\S+)$", install, re.MULTILINE)
    assert base is not None
    assert manifest_url == f"{base.group(1)}/updater-bootstrap.manifest.json"
    # The pinned manifest digest is the one the published tag names.
    assert base.group(1).endswith(f"-{pinned}")
    auto_update = (ROOT / "docs" / "AUTO_UPDATE.md").read_text()
    assert f"{manifest_url}`\n  (`{pinned}`)" in auto_update

    fetched: list[str] = []

    def fake_fetch(url: str, _maximum: int) -> bytes:
        fetched.append(url)
        raise check["CheckFailed"]("offline fixture")

    assert check["main"](["--now-unix", str(NOW)], fetcher=fake_fetch) == 1
    capsys.readouterr()
    assert fetched == [urls["stable"], urls["canary"], manifest_url]


def test_limits_match_the_updater_and_the_installer() -> None:
    check = _check()
    installer = runpy.run_path(
        str(ROOT / "deploy" / "validator-update" / "install_updater_bundle.py")
    )
    assert check["RELEASE_METADATA_SCHEMA"] == updater.METADATA_SCHEMA
    assert check["MAX_RELEASE_METADATA_BYTES"] == updater.MAX_METADATA_BYTES
    assert (
        check["MAX_RELEASE_METADATA_LIFETIME_SECONDS"]
        == updater.MAX_METADATA_LIFETIME_SECONDS
    )
    assert check["BOOTSTRAP_SCHEMA"] == installer["BUNDLE_SCHEMA"]
    assert check["MAX_BOOTSTRAP_MANIFEST_BYTES"] == installer["MAX_MANIFEST_BYTES"]
    assert (
        check["MAX_BOOTSTRAP_LIFETIME_SECONDS"]
        == installer["MAX_BOOTSTRAP_LIFETIME_SECONDS"]
    )


def test_daily_workflow_is_read_only_and_runs_the_five_day_check() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release-expiry.yml").read_text()
    assert '\non:\n  schedule:\n    - cron: "17 6 * * *"\n' in workflow
    assert "  workflow_dispatch:\n" in workflow
    assert "\npermissions:\n  contents: read\n\n" in workflow
    assert workflow.count("permissions:") == 1
    assert "write" not in workflow
    assert "secrets." not in workflow
    assert "persist-credentials: false" in workflow
    assert "run: python3 scripts/check_release_expiry.py --warn-days 5\n" in workflow
    assert "pull_request" not in workflow
