#!/usr/bin/env python3
"""Readiness process for a live updater test with no chain or wallet path.

The signed validator PEX runs this script in interpreter mode.  The systemd
test override permits AF_UNIX only, so the process can notify systemd but
cannot create an IPv4 or IPv6 socket.  Target-specific marker files let the
controller hold or fail one archive without changing another archive.

This file is test infrastructure.  It is not a validator and must never be
used by the production service definition.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import stat
import time
from pathlib import Path

from cathedral_thin.independent_runtime import direct_validator, qvl, snp_production


INSTALL_ROOT = Path("/opt/cathedral-validator")
POLICY_PATH = Path("/etc/cathedral-validator/snp-policy.json")
CONTROL_ROOT = Path("/etc/cathedral-validator-live-test")
MAX_DELAY_SECONDS = 300


def refuse(message: str) -> None:
    raise SystemExit(f"TEST_NO_CHAIN_REFUSED: {message}")


def digest(path: Path) -> str:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
        refuse(f"unsafe release file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_pex_origin(module: object) -> None:
    module_file = getattr(module, "__file__", None)
    # PEX strips PEX_* variables before interpreter-mode user code runs. The
    # live controller preserves the reviewed root under this test-only name.
    raw_root = os.environ.get("CATHEDRAL_LIVE_TEST_PEX_ROOT")
    if not isinstance(module_file, str):
        refuse(f"{getattr(module, '__name__', module)!r} has no module file")
    if not raw_root:
        refuse("preserved live-test PEX root is unavailable")
    module_path = Path(module_file).resolve()
    pex_root = Path(raw_root).resolve()
    if not module_path.is_relative_to(pex_root):
        refuse(
            f"{getattr(module, '__name__', module)!r} did not load from the "
            "preserved live-test PEX root"
        )


def require_ip_denied() -> None:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            probe = socket.socket(family, socket.SOCK_STREAM)
        except OSError:
            continue
        probe.close()
        refuse(f"systemd permitted IP socket family {family}")


def active_release() -> tuple[Path, dict[str, object]]:
    current = INSTALL_ROOT / "current"
    if not current.is_symlink():
        refuse("active release is not a symlink")
    root = current.resolve(strict=True)
    if root.parent != INSTALL_ROOT / "releases" or len(root.name) != 64:
        refuse("active release target is not canonical")
    try:
        manifest = json.loads((root / "RELEASE.json").read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        refuse(f"active release manifest is unreadable: {exc}")
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != "cathedral_validator_bundle_v2"
    ):
        refuse("active release manifest has wrong schema")
    return root, manifest


def marker(kind: str, target: str) -> Path:
    return CONTROL_ROOT / f"{kind}.{target}"


def apply_target_control(target: str) -> None:
    fail = marker("fail-before-ready", target)
    if fail.exists():
        print(f"TEST_NO_CHAIN_TARGET_FAIL target={target}", flush=True)
        raise SystemExit(42)

    delay = marker("delay-before-ready", target)
    if not delay.exists():
        return
    try:
        seconds = int(delay.read_text(encoding="ascii").strip())
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        refuse(f"invalid target delay marker: {exc}")
    if not 1 <= seconds <= MAX_DELAY_SECONDS:
        refuse("target delay is outside the live-test bound")
    deadline = time.monotonic() + seconds
    print(f"TEST_NO_CHAIN_TARGET_DELAY target={target} seconds={seconds}", flush=True)
    while delay.exists() and time.monotonic() < deadline:
        time.sleep(0.25)
    if delay.exists():
        refuse("target delay marker was not released before its deadline")


def main() -> int:
    require_ip_denied()
    require_pex_origin(direct_validator)
    require_pex_origin(qvl)
    require_pex_origin(snp_production)
    root, manifest = active_release()
    validator = root / "bin" / "cathedral-validator"
    qvl_path = root / "bin" / "cathedral-tdx-verifier"
    snpguest_path = root / "bin" / "snpguest"
    if digest(validator) != manifest.get("pex_sha256"):
        refuse("active PEX digest differs from RELEASE.json")
    if manifest.get("qvl_path") != "bin/cathedral-tdx-verifier":
        refuse("active release has unexpected QVL path")
    if digest(qvl_path) != manifest.get("qvl_sha256"):
        refuse("active QVL digest differs from RELEASE.json")
    verifier = qvl.load_direct_validator_verifier(str(qvl_path))
    if verifier.digest != qvl.DIRECT_VALIDATOR_QVL_DIGEST:
        refuse("QVL did not satisfy direct-validator pin")
    if manifest.get("snpguest_path") != "bin/snpguest":
        refuse("active release has unexpected snpguest path")
    if digest(snpguest_path) != manifest.get("snpguest_sha256"):
        refuse("active snpguest digest differs from RELEASE.json")
    policy = snp_production.load_snp_policy(POLICY_PATH)
    snp = snp_production.SnpProductionVerifier(
        policy=policy, snpguest_path=snpguest_path
    )
    if not snp.digest.startswith("sha256:"):
        refuse("SNP verifier did not initialize")

    # The production verifier validates the pinned Compute distribution before
    # importing it.  Importing Compute earlier would correctly trip that
    # fail-closed provenance boundary.
    import cathedral

    require_pex_origin(cathedral)

    apply_target_control(root.name)
    direct_validator._notify_ready()
    print(f"TEST_NO_CHAIN_READY target={root.name} pid={os.getpid()}", flush=True)
    stopping = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        signal.pause()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
