"""A re-sync must never silently revert a DECLARED divergence.

This is the regression for a real, silent production break. A re-sync copied upstream
over `config/validator-mainnet-sn39.toml`, dropping `[logs].status_jsonl`. Nothing
then wrote the sanitized status projection, and
`cathedral-sn39-public-status.service` gates on exactly that path with
`ConditionPathExists`. systemd records an unmet condition as SKIPPED, not failed, so
the public status stream stopped with no error anywhere.

`tools/sync-from-upstream.sh` needs bash 4 for `mapfile` and therefore only executes
in CI (macOS ships bash 3.2), so these tests check the properties portably: that the
two lists which must agree do agree, and that the protection and its mandatory
refusal are actually present in the script. The end-to-end behaviour is proven by
`tools/sync-from-upstream.sh selftest`, which the manifest CI job now runs.
"""

from __future__ import annotations

import pathlib
import re
import subprocess

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SYNC = _ROOT / "tools" / "sync-from-upstream.sh"
_MANIFEST_SH = _ROOT / "tools" / "manifest.sh"
_CONFIG = _ROOT / "config" / "validator-mainnet-sn39.toml"


def _declared_from_manifest_sh() -> set[str]:
    text = _MANIFEST_SH.read_text(encoding="utf-8")
    match = re.search(r'ALLOWED_DIVERGENCE="(.*?)"', text, re.S)
    assert match, "manifest.sh must declare ALLOWED_DIVERGENCE"
    return set(match.group(1).replace("\\\n", " ").split())


def _declared_from_sync_parser() -> set[str]:
    """Run the script's own awk parser, so drift between the two is caught."""
    body = re.search(
        r"^declared_divergences\(\) \{.*?^\}",
        _SYNC.read_text(encoding="utf-8"),
        re.M | re.S,
    )
    assert body, "the sync script must parse the declared divergences"
    script = body.group(0) + '\ndeclared_divergences "$1"\n'
    out = subprocess.run(
        ["bash", "-c", script, "bash", str(_ROOT / "tools")],
        capture_output=True,
        text=True,
        check=True,
    )
    return {line.strip() for line in out.stdout.splitlines() if line.strip()}


def test_the_sync_and_the_manifest_agree_on_what_may_diverge():
    # Two lists that must not drift apart: the sync protects exactly what the manifest
    # permits to differ.
    assert _declared_from_sync_parser() == _declared_from_manifest_sh()


def test_the_status_config_is_declared_divergent():
    # It MUST differ from upstream: upstream has no sanitized-status split.
    assert "config/validator-mainnet-sn39.toml" in _declared_from_manifest_sh()


def test_the_status_projection_is_still_configured():
    # The exact value the re-sync dropped.
    assert "status_jsonl" in _CONFIG.read_text(encoding="utf-8")


def test_the_sync_refuses_to_report_success_with_an_outstanding_reconciliation():
    # Upstream changes to a divergent file still have to be READ; that is how the
    # #403-#408 hardening went missing. The refusal is what forces it.
    text = _SYNC.read_text(encoding="utf-8")
    assert "MUST RECONCILE" in text
    assert "exit 3" in text, "an outstanding reconciliation must not exit 0"
    assert "ALLOW_UNRECONCILED" in text, "the override must be explicit"


def test_the_sync_selftest_covers_the_divergence_case():
    # A sync tool with no gating coverage is how the revert landed unnoticed.
    text = _SYNC.read_text(encoding="utf-8")
    assert "declared divergence survived the sync" in text
    workflow = (_ROOT / ".github" / "workflows" / "tests.yml").read_text(
        encoding="utf-8"
    )
    assert "sync-from-upstream.sh selftest" in workflow, "the selftest must run in CI"
