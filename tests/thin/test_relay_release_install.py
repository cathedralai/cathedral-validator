"""A third party must be able to BUILD the manifest the launcher demands.

The immutable-install manifest binds every reviewed byte the launcher re-checks
before exec. Until now it also pinned two things only Cathedral has: the
controlled-disclosure Intel TDX verifier binary (`EXPECTED_VERIFIER_BINARY`,
which is not in this repository and not on PyPI) and the producer-side status
publisher that runs as the producer's account. The builder therefore refused to
run anywhere else, which made the launcher's whole verification path — and so
the supported pinned install — Cathedral-only.

`--relay` builds the manifest the relay posture actually needs. It is not a
weaker manifest: it binds a SUPERSET of the reviewed source, the same
environment commitment, and the same bootstrap binding. What it omits are
EXTERNAL files a relay host does not install, because an `external_files` entry
naming an absent file is an unbuildable manifest rather than a stricter one. It
also binds one thing the Cathedral manifest does not: the shadow-audit mismatch
alert, which on a relay is the only health surface there is.

The relay profile is only sound because the relay's audit never needed the
verifier: `config/validator-thin-sn39-relay.toml` omits `controlled_dir` and
`verifier_binary`, `scaffold/provenance_audit.py` requires both only in
authority mode, and its full-assurance replay is reached only when
`controlled_dir` is set. Without them the audit is receipts-only and still
never delays or blocks the thin submission.

These tests run the builder end to end against a fixture release, so a change
that reintroduces a Cathedral-only requirement fails here rather than on a
third party's host. Two heavyweight preconditions are stood in for: the tree
ownership rule (`ROOT_UID`, monkeypatched to the test user exactly as
`test_release_manifest_venv_symlinks.py` does) and `verify_locked_environment`,
which needs the 55-distribution hash-locked venv that only a real install has.
Everything else — the pristine-checkout proof, the reviewed-vs-installed byte
comparison, the bootstrap interpreter binding, and the emitted document — is
the shipped code path.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_BUILDER_PATH = _ROOT / "scripts" / "build_sn39_release_manifest.py"
_LAUNCHER_PATH = _ROOT / "deploy" / "sn39" / "cathedral-sn39-release-launcher.py"
_ORIGIN_UNIT = _ROOT / "deploy" / "sn39" / "cathedral-validator-sn39.service"
_RELAY_UNIT = _ROOT / "deploy" / "sn39" / "cathedral-validator-sn39-relay.service"
_ORIGIN_TMPFILES = _ROOT / "deploy" / "sn39" / "cathedral-sn39-validator.tmpfiles"
_RELAY_TMPFILES = _ROOT / "deploy" / "sn39" / "cathedral-sn39-validator-relay.tmpfiles"

# The exact external files a Cathedral manifest has always bound. Pinned
# literally so that the relay work cannot quietly drop one from the origin
# posture: a relay manifest that could stand in for this set would let a host
# claim the origin posture without the verifier pin.
_CATHEDRAL_EXTERNAL = frozenset(
    {
        "continuous_config",
        "registry_keys",
        "report_keys",
        "index_keys",
        "verifier",
        "launcher",
        "continuous_unit",
        "status_unit",
        "status_timer",
        "sysusers",
        "tmpfiles",
    }
)
_MISMATCH_EXTERNAL = frozenset({"mismatch_check", "mismatch_unit", "mismatch_timer"})
# A relay drops the three Cathedral-only externals and gains the shadow-audit
# alert. The alert is bound because a relay has no other health surface: an
# alert script outside the manifest could be edited by the same compromised
# service account the whole immutable install exists to contain.
_RELAY_EXTERNAL = (
    _CATHEDRAL_EXTERNAL - {"verifier", "status_unit", "status_timer"}
) | _MISMATCH_EXTERNAL


def _load(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_builder = _load(_BUILDER_PATH, "_sn39_release_manifest_relay")
_launcher = _load(_LAUNCHER_PATH, "_sn39_release_launcher_relay")


def _git(repo: pathlib.Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", f"safe.directory={repo}", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(repo),
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        },
    )


def _release_checkout(base: pathlib.Path) -> tuple[pathlib.Path, str]:
    """A pristine, root-controlled-looking checkout of the reviewed files.

    Only the files a manifest binds are copied. Bytes are written rather than
    copied with their modes so that every regular file is 0644 and git records
    the same mode it finds on disk; otherwise the later `status --porcelain`
    pristine check reports a mode change and the builder refuses, which would
    make this fixture fail for a reason that has nothing to do with the relay.
    """
    release = base / "release"
    for relative in _builder.RELAY_RELEASE_FILES:
        target = release / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((_ROOT / relative).read_bytes())
    _git(release, "init", "--quiet", "--initial-branch=main")
    _git(release, "add", "--all")
    _git(release, "commit", "--quiet", "--message=fixture")
    for path in [release, *release.rglob("*")]:
        path.chmod(0o755 if path.is_dir() else 0o644)
    sha = subprocess.check_output(
        ["git", "-c", f"safe.directory={release}", "rev-parse", "HEAD"],
        cwd=release,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    ).strip()
    return release, sha


def _venv(base: pathlib.Path) -> pathlib.Path:
    venv = base / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("#!/bin/sh\n", encoding="utf-8")
    for path in [venv, *venv.rglob("*")]:
        path.chmod(0o755 if path.is_dir() else 0o644)
    return venv


@pytest.fixture
def install(tmp_path, monkeypatch):
    """Run the shipped builder against a fixture install and return its JSON."""
    monkeypatch.setattr(_builder, "ROOT_UID", os.getuid())
    monkeypatch.setattr(_builder, "verify_locked_environment", lambda *_args: None)
    release, sha = _release_checkout(tmp_path)
    venv = _venv(tmp_path)
    installed = tmp_path / "installed"
    installed.mkdir()

    def _install(relative: str, name: str) -> pathlib.Path:
        target = installed / name
        target.write_bytes((release / relative).read_bytes())
        target.chmod(0o644)
        return target

    external = {
        "continuous_config": _install(
            "config/validator-thin-sn39-relay.toml", "validator-thin-sn39-relay.toml"
        ),
        "registry_keys": _install(
            "config/provenance/registry-keys.json", "registry-keys.json"
        ),
        "report_keys": _install(
            "config/provenance/report-keys.json", "report-keys.json"
        ),
        "index_keys": _install("config/provenance/index-keys.json", "index-keys.json"),
        "launcher": _install(
            "deploy/sn39/cathedral-sn39-release-launcher.py", "cathedral-sn39-release"
        ),
        "status_unit": _install(
            "deploy/sn39/cathedral-sn39-public-status.service",
            "cathedral-sn39-public-status.service",
        ),
        "status_timer": _install(
            "deploy/sn39/cathedral-sn39-public-status.timer",
            "cathedral-sn39-public-status.timer",
        ),
        "sysusers": _install(
            "deploy/sn39/cathedral-sn39-validator.sysusers",
            "cathedral-sn39-validator.conf",
        ),
        "mismatch_check": _install(
            "deploy/sn39/cathedral-mismatch-check", "cathedral-mismatch-check"
        ),
        "mismatch_unit": _install(
            "deploy/sn39/cathedral-mismatch-alert.service",
            "cathedral-mismatch-alert.service",
        ),
        "mismatch_timer": _install(
            "deploy/sn39/cathedral-mismatch-alert.timer",
            "cathedral-mismatch-alert.timer",
        ),
    }

    def build(
        *,
        relay: bool,
        verifier: pathlib.Path | None = None,
        mismatch_check: pathlib.Path | None = None,
        **overrides,
    ):
        profile = _builder.install_profile(relay=relay)
        paths = dict(external)
        paths["continuous_unit"] = _install(
            profile.continuous_unit_source, f"{profile.name}-validator.service"
        )
        paths["tmpfiles"] = _install(
            profile.tmpfiles_source, f"{profile.name}-validator.tmpfiles"
        )
        paths.update(overrides)
        argv = [
            "--release",
            str(release),
            "--release-sha",
            sha,
            "--venv",
            str(venv),
            "--continuous-config",
            str(paths["continuous_config"]),
            "--registry-keys",
            str(paths["registry_keys"]),
            "--report-keys",
            str(paths["report_keys"]),
            "--index-keys",
            str(paths["index_keys"]),
            "--launcher",
            str(paths["launcher"]),
            "--continuous-unit",
            str(paths["continuous_unit"]),
            "--sysusers",
            str(paths["sysusers"]),
            "--tmpfiles",
            str(paths["tmpfiles"]),
        ]
        if relay:
            argv += [
                "--relay",
                "--mismatch-check",
                str(paths["mismatch_check"]),
                "--mismatch-unit",
                str(paths["mismatch_unit"]),
                "--mismatch-timer",
                str(paths["mismatch_timer"]),
            ]
        else:
            argv += [
                "--status-unit",
                str(paths["status_unit"]),
                "--status-timer",
                str(paths["status_timer"]),
            ]
        if verifier is not None:
            argv += ["--verifier", str(verifier)]
        # Named explicitly (rather than through `overrides`) so a test can pass
        # a relay-only path to the Cathedral posture and see it refused.
        if mismatch_check is not None:
            argv += ["--mismatch-check", str(mismatch_check)]
        monkeypatch.setattr("sys.argv", ["build_sn39_release_manifest.py", *argv])
        return _builder.main()

    build.release = release
    build.release_sha = sha
    build.paths = external
    build.tmp_path = tmp_path
    return build


def _document(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


def test_the_relay_manifest_builds_with_no_verifier_binary_on_the_host(install, capsys):
    """The whole point: no controlled binary exists here, and it still builds."""
    assert install(relay=True) == 0
    document = _document(capsys)
    assert document["schema"] == "cathedral_sn39_release_install_v3"
    assert document["release_sha"] == install.release_sha
    assert not any(
        "cathedral-tdx-verifier" in path for path in document["external_files"]
    )
    assert not any("public-status" in path for path in document["external_files"]), (
        "the status publisher runs as the producer and writes the producer's tree"
    )
    assert len(document["external_files"]) == len(_RELAY_EXTERNAL)


def test_the_relay_manifest_binds_the_relay_unit_and_its_tmpfiles(install, capsys):
    assert install(relay=True) == 0
    document = _document(capsys)
    bound = "\n".join(document["external_files"])
    assert "relay-validator.service" in bound
    assert "relay-validator.tmpfiles" in bound
    for relative in (
        "deploy/sn39/cathedral-validator-sn39-relay.service",
        "deploy/sn39/cathedral-sn39-validator-relay.tmpfiles",
    ):
        assert relative in document["release_files"]


def test_the_relay_manifest_binds_the_shadow_audit_mismatch_alert(install, capsys):
    """A relay's only health surface must be inside the tamper-evidence boundary.

    The failed `cathedral-mismatch-alert.service` unit IS the alert; there is
    no separate notification channel. An alert script the manifest does not
    bind could be edited or emptied by the same compromised service account the
    immutable install exists to contain, and the launcher would still exec.
    """
    assert install(relay=True) == 0
    document = _document(capsys)
    for key in ("mismatch_check", "mismatch_unit", "mismatch_timer"):
        assert str(install.paths[key]) in document["external_files"]
    for relative in (
        "deploy/sn39/cathedral-mismatch-check",
        "deploy/sn39/cathedral-mismatch-alert.service",
        "deploy/sn39/cathedral-mismatch-alert.timer",
    ):
        assert relative in document["release_files"]


def test_a_relay_manifest_cannot_be_built_without_the_alert_installed(
    install, tmp_path
):
    """Skipping the alert must fail at install time, not go unnoticed at run time."""
    with pytest.raises(SystemExit, match="required release file is unavailable"):
        install(relay=True, mismatch_check=tmp_path / "not-installed")


def test_the_cathedral_posture_refuses_the_relay_only_alert_paths(install):
    """Refused rather than ignored, exactly as the Cathedral-only paths are."""
    with pytest.raises(SystemExit, match="relay-only"):
        install(relay=False, mismatch_check=pathlib.Path("/nonexistent"))


def test_the_readme_relay_install_installs_and_enables_the_alert():
    """The alert must be IN the procedure README calls the supported install.

    An operator who follows README top to bottom and nothing else — which is
    what README tells them to do — otherwise finishes with a running validator
    and no monitoring at all, and nothing tells them anything is missing.
    """
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("## Supported systemd install (relay)")
    end = readme.index("## What it does", start)
    section = readme[start:end]
    for line in (
        '"$release/deploy/sn39/cathedral-mismatch-check"',
        "/usr/local/bin/cathedral-mismatch-check",
        '"$release/deploy/sn39/cathedral-mismatch-alert.service"',
        '"$release/deploy/sn39/cathedral-mismatch-alert.timer"',
        "systemctl enable --now cathedral-mismatch-alert.timer",
    ):
        assert line in section, line


def test_the_relay_manifest_binds_a_superset_of_the_reviewed_source(install, capsys):
    """A relay omits external files, never reviewed source."""
    assert install(relay=True) == 0
    relay_source = set(_document(capsys)["release_files"])
    assert relay_source >= set(_builder.RELEASE_FILES)


def test_the_launcher_would_accept_the_relay_manifest(install, capsys):
    """Every field the launcher's `_verify` reads, checked against its own code.

    `_verify` itself needs root-owned `/opt/cathedral-sn39` trees and a masked
    legacy unit, so it cannot run here. What can be checked is that the
    document satisfies each rule it applies: the exact field set, the schema
    string, a 40-hex release SHA, non-empty digest maps whose every value is a
    sha256, and the selected service config bound by `external_files`.
    """
    assert install(relay=True) == 0
    document = _document(capsys)
    assert set(document) == {
        "schema",
        "release_sha",
        "release_files",
        "external_files",
        "venv_tree_digest",
        "bootstrap_python",
    }
    assert _launcher.SHA_RE.fullmatch(document["release_sha"])
    assert _launcher.DIGEST_RE.fullmatch(document["venv_tree_digest"])
    assert set(document["bootstrap_python"]) == {
        "invoked_path",
        "resolved_path",
        "digest",
    }
    for name in ("release_files", "external_files"):
        assert document[name]
        for value in document[name].values():
            assert _launcher.DIGEST_RE.fullmatch(value)
    # `_verify` requires CONFIGS[mode] in external_files. The fixture installs
    # that config outside /etc, so the binding is checked against the path the
    # run was given and the shipped default is checked against the launcher's.
    assert str(install.paths["continuous_config"]) in document["external_files"]
    assert _launcher.CONFIGS["continuous"] == (
        _builder.INSTALL_ROOT / "validator-thin-sn39-relay.toml"
    )


def test_the_cathedral_manifest_still_pins_the_verifier_and_status_publisher(
    install, capsys, tmp_path, monkeypatch
):
    """The origin posture is unchanged, so a relay manifest cannot stand in."""
    verifier = tmp_path / "cathedral-tdx-verifier"
    verifier.write_bytes(b"fixture verifier bytes")
    verifier.chmod(0o644)
    monkeypatch.setattr(_builder, "EXPECTED_VERIFIER_BINARY", _builder.digest(verifier))
    assert install(relay=False, verifier=verifier) == 0
    document = _document(capsys)
    assert str(verifier) in document["external_files"]
    assert len(document["external_files"]) == len(_CATHEDRAL_EXTERNAL)
    assert set(document["release_files"]) == set(_builder.RELEASE_FILES)


def test_a_verifier_that_is_not_the_pin_is_still_refused(install, tmp_path):
    verifier = tmp_path / "cathedral-tdx-verifier"
    verifier.write_bytes(b"not the pinned verifier")
    verifier.chmod(0o644)
    with pytest.raises(SystemExit, match="differs from the launch pin"):
        install(relay=False, verifier=verifier)


def test_relay_is_refused_on_a_host_that_holds_launch_material(
    install, tmp_path, monkeypatch
):
    """`--relay` must not be usable to downgrade the one host that owes a launch.

    The paths are the same three `scaffold.validator_thin._sn39_launch_obligation`
    reads, so a host that the runtime would force through the launch and
    recurring-write authorization cannot build itself a manifest that pins no
    verifier.
    """
    material = tmp_path / "controlled-current"
    material.mkdir()
    monkeypatch.setattr(_builder, "LAUNCH_MATERIAL_PATHS", (material,))
    with pytest.raises(SystemExit, match="holds SN39 launch material"):
        install(relay=True)


def test_the_launch_material_paths_are_the_runtime_obligation_paths():
    """Restated constants drift; this is what keeps the two in agreement."""
    from scaffold import validator_thin

    assert set(_builder.LAUNCH_MATERIAL_PATHS) == {
        validator_thin.SN39_LAUNCH_CONTROLLED_DIR,
        validator_thin.SN39_LAUNCH_VERIFIER_BINARY,
        validator_thin.SN39_LAUNCH_APPROVAL_FILE,
    }


def test_relay_refuses_the_cathedral_only_paths_rather_than_ignoring_them(install):
    with pytest.raises(SystemExit, match="Cathedral-only path"):
        install(relay=True, verifier=pathlib.Path("/nonexistent"))


def test_the_relay_unit_drops_exactly_the_producer_only_requirements():
    relay = _RELAY_UNIT.read_text(encoding="utf-8")
    directives = [
        line
        for line in relay.splitlines()
        if line and not line.startswith("#") and not line.startswith("[")
    ]
    joined = "\n".join(directives)
    assert "ConditionPathExists=" not in joined, (
        "a third party cannot obtain the root-signed recurring-write "
        "authorization, and an unmet Condition= is reported as a successful start"
    )
    assert "SupplementaryGroups=" not in joined, (
        "cathedral-validator-evidence belongs to the producer and is "
        "deliberately not declared by the shipped sysusers file"
    )
    assert "cathedral-validator-controlled-sn39" not in joined
    assert "cathedral-tdx-verifier" not in joined, (
        "an unprefixed ReadOnlyPaths= on a missing path fails the mount "
        "namespace and takes the unit down before ExecStart"
    )


def test_the_relay_unit_keeps_every_gate_the_origin_unit_applies():
    origin = _ORIGIN_UNIT.read_text(encoding="utf-8")
    relay = _RELAY_UNIT.read_text(encoding="utf-8")
    for directive in (
        "User=cathedral-validator",
        "Group=cathedral-validator-log",
        "Environment=CATHEDRAL_VALIDATOR_STATUS_GROUP=cathedral-validator-log",
        "ExecStart=/usr/bin/python3.12 -I -E -s "
        "/usr/local/libexec/cathedral-sn39-release continuous",
        "StateDirectoryMode=0700",
        "LogsDirectoryMode=0750",
        "UMask=0077",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "RestrictSUIDSGID=true",
    ):
        assert directive in origin
        assert directive in relay
    directives = "\n".join(
        line for line in relay.splitlines() if not line.startswith("#")
    )
    assert "CATHEDRAL_VALIDATOR_JSONL_GROUP" not in directives, (
        "the raw journal carries hotkeys and receipts and stays 0600"
    )


def test_the_relay_unit_refuses_to_run_beside_any_other_sn39_writer():
    relay = _RELAY_UNIT.read_text(encoding="utf-8")
    conflicts = [line for line in relay.splitlines() if line.startswith("Conflicts=")]
    assert len(conflicts) == 1
    assert "cathedral-validator-sn39.service" in conflicts[0], (
        "one host must never run both postures against one hotkey"
    )
    guard = [line for line in relay.splitlines() if line.startswith("ExecStartPre=")]
    assert len(guard) == 1
    assert "cathedral-validator-sn39.service" in guard[0]


def test_the_relay_tmpfiles_creates_what_the_unit_conditions_on():
    """Otherwise the first start of a correct install is silently skipped."""
    relay = _RELAY_TMPFILES.read_text(encoding="utf-8")
    created = {
        line.split()[1]
        for line in relay.splitlines()
        if line.startswith("d ") and not line.startswith("#")
    }
    unit = _RELAY_UNIT.read_text(encoding="utf-8")
    conditioned = {
        line.split("=", 1)[1].strip()
        for line in unit.splitlines()
        if line.startswith("ConditionPathIsReadWrite=")
    }
    assert conditioned
    assert conditioned <= created
    assert "/var/log/cathedral-validator" in created


def test_the_relay_tmpfiles_declares_no_producer_identity_or_tree():
    relay = _RELAY_TMPFILES.read_text(encoding="utf-8")
    contracts = [line for line in relay.splitlines() if line.startswith("d ")]
    joined = "\n".join(contracts)
    assert "polaris" not in joined, "a relay host has no producer account to name"
    assert "cathedral-public-evidence" in _ORIGIN_TMPFILES.read_text(encoding="utf-8")
    assert "cathedral-public-evidence" not in joined
    for line in contracts:
        for field in line.split()[2:5]:
            assert field.startswith(":"), (
                "unprefixed fields are reapplied on every boot to an inode a "
                "running service already owns"
            )
