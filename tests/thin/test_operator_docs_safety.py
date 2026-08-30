"""The public validator has one short, runnable operator path."""

import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def _run_startup_stability_check(
    tmp_path: Path, mode: str
) -> subprocess.CompletedProcess[str]:
    source = (ROOT / "deploy" / "sn39" / "install-validator").read_text(
        encoding="utf-8"
    )
    start = source.index("wait_for_service_stability() {\n")
    end = source.index("\n}\n", start) + 3
    function = source[start:end]
    counter = tmp_path / "systemctl-calls"
    counter.write_text("0", encoding="utf-8")
    shell = f"""\
set -euo pipefail
SERVICE=cathedral-validator-sn39-relay.service
STARTUP_STABILITY_SECONDS=2
fail() {{ printf 'failed: %s\\n' "$*" >&2; exit 1; }}
sleep() {{ :; }}
systemctl() {{
  local calls
  calls="$(<"${{MOCK_COUNTER}}")"
  calls=$((calls + 1))
  printf '%s' "${{calls}}" >"${{MOCK_COUNTER}}"
  if [[ "${{MOCK_MODE}}" == restart && "${{calls}}" -ge 2 ]]; then
    printf '%s\\n' ActiveState=active SubState=running NRestarts=1 MainPID=456
  else
    printf '%s\\n' ActiveState=active SubState=running NRestarts=0 MainPID=123
  fi
}}
{function}
wait_for_service_stability
"""
    return subprocess.run(
        ["bash"],
        input=shell,
        text=True,
        capture_output=True,
        env={**os.environ, "MOCK_COUNTER": str(counter), "MOCK_MODE": mode},
        check=False,
    )


def test_false_launch_design_page_is_not_active() -> None:
    assert not (ROOT / "MINER_VALIDATOR.md").exists()
    assert not (ROOT / "VALIDATOR-ONBOARDING.md").exists()
    assert not (ROOT / "REVIEW.md").exists()
    assert not (ROOT / "docs" / "PROVENANCE_CATCHUP.md").exists()
    assert not (ROOT / "deploy" / "publisher" / "init-clean-journal.sh").exists()
    assert not (ROOT / "deploy" / "sn39" / "wallet-host-quickstart.sh").exists()
    assert not (ROOT / "deploy" / "sn39" / "docker").exists()


def test_readme_is_the_small_public_guide() -> None:
    guide = (ROOT / "README.md").read_text(encoding="utf-8")
    assert guide.count("## ") == 3
    assert '<div align="center">' in guide
    assert "<h1>⚡ Cathedral Validator</h1>" in guide
    assert "<strong>Bittensor SN39</strong>" in guide
    assert "## 1. What it does" in guide
    assert "## 2. What you need" in guide
    assert "## 3. Install, run, and know it is working" in guide
    assert "deploy/sn39/install-validator" in guide
    assert "WEIGHTS_SUBMITTED" in guide
    assert "Never provide your coldkey" in guide
    assert "not self-service" not in guide
    assert "authorized Cathedral operator" not in guide
    assert "Where to get help" not in guide
    assert "--dry-run" not in guide
    assert "--broadcast" not in guide
    assert "--offline" not in guide
    assert "cathedral-sandbox/blob/main/MINING.md" not in guide
    assert "cathedral-validator/blob/main/VALIDATOR.md" not in guide


def test_old_validator_page_is_only_a_compatibility_pointer() -> None:
    pointer = (ROOT / "VALIDATOR.md").read_text(encoding="utf-8")
    assert pointer == (
        "# Cathedral Validator\n\n"
        "The public installation and operating guide is on the "
        "[repository home page](README.md).\n"
    )


def test_public_installer_is_one_live_path() -> None:
    path = ROOT / "deploy" / "sn39" / "install-validator"
    source = path.read_text(encoding="utf-8")
    assert os.access(path, os.X_OK)
    subprocess.run(["bash", "-n", str(path)], check=True)
    assert "--hotkey" in source
    assert "--relay --release" in source
    assert "requirements/sn39-build.lock" in source
    assert "requirements/sn39-reproduction.lock" in source
    assert 'staged_venv="$(mktemp -d' in source
    assert '"${staged_venv}/bin/python" -m pip install' in source
    assert 'systemctl enable "${SERVICE}"' in source
    assert 'systemctl is-active --quiet "${SERVICE}"' in source
    assert "/.bittensor/wallets/validator/hotkeys/default" in source
    assert 'hotkey_source="$(realpath -e -- "${hotkey_source}")"' in source
    assert "*/wallets/*/hotkeys/*" in source
    assert source.index("cathedral-sn39-release verify") < source.rindex(
        'systemctl start "${SERVICE}"'
    )
    assert "restore_targets" in source
    backup = source.index('  "${LEGACY_UNIT_PATH}" \\\n')
    mutated = source.index("install_mutated=true", backup)
    remove = source.index('rm -f -- "${LEGACY_UNIT_PATH}"')
    mask = source.index('systemctl mask --now --force "${LEGACY_SERVICE}"')
    assert backup < mutated < remove < mask
    restore = source.index("    restore_targets\n")
    reload_systemd = source.index("systemctl daemon-reload", restore)
    restore_legacy_enabled = source.index(
        'systemctl enable "${LEGACY_SERVICE}"', reload_systemd
    )
    restore_legacy_active = source.index(
        'systemctl start "${LEGACY_SERVICE}"', restore_legacy_enabled
    )
    assert restore < reload_systemd < restore_legacy_enabled < restore_legacy_active
    assert '-f "${LEGACY_UNIT_PATH}" || -L "${LEGACY_UNIT_PATH}"' in source
    assert '-e "${LEGACY_UNIT_PATH}" && ! -L "${LEGACY_UNIT_PATH}"' in source
    assert 'systemctl mask --now --force "${LEGACY_SERVICE}"' in source
    assert "STARTUP_STABILITY_SECONDS=20" in source
    assert "--property=ActiveState" in source
    assert "--property=SubState" in source
    assert "--property=NRestarts" in source
    assert "--property=MainPID" in source
    reset = source.index('systemctl reset-failed "${SERVICE}"')
    start = source.rindex('systemctl start "${SERVICE}"')
    stable = source.rindex("wait_for_service_stability")
    committed = source.index("install_complete=true", stable)
    assert reset < start < stable < committed
    assert "--dry-run" not in source
    assert "--broadcast" not in source
    assert "--offline" not in source
    assert "cathedral-sn39-public-status.service" not in source
    assert 'cathedral-validator-sn39.service"' not in source


def test_installer_startup_check_accepts_one_stable_process(tmp_path: Path) -> None:
    result = _run_startup_stability_check(tmp_path, "stable")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "systemctl-calls").read_text(encoding="utf-8") == "3"


def test_installer_startup_check_rejects_a_restart_loop(tmp_path: Path) -> None:
    result = _run_startup_stability_check(tmp_path, "restart")
    assert result.returncode != 0
    assert "restarted during its startup check" in result.stderr


def test_tracked_documentation_has_no_removed_onboarding_anchors() -> None:
    markdown = [
        *ROOT.glob("*.md"),
        *(ROOT / "docs").rglob("*.md"),
        *(ROOT / "deploy").rglob("*.md"),
    ]
    for path in markdown:
        text = path.read_text(encoding="utf-8")
        assert "README.md#quickstart" not in text, path.relative_to(ROOT)
        assert "VALIDATOR.md#" not in text, path.relative_to(ROOT)
