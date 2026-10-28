#!/usr/bin/python3.12
"""Install the published signed updater bootstrap into a container image.

This is image-build code. It downloads the same artifacts ``scripts/install.sh``
pins, verifies them, installs the updater venv without systemd, and writes the
floor and expiry the supervisor reads on first install.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import urllib.request
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[2]
INSTALLER_PATH = ROOT / "deploy" / "validator-update" / "install_updater_bundle.py"

# Keep these identical to scripts/install.sh. tests/thin/test_container_supervisor.py
# refuses a drift.
BOOTSTRAP_BASE = (
    "https://github.com/cathedralai/cathedral-validator/releases/download/"
    "validator-bootstrap-production-s4-649e3a887d37bc220f16a80e58721c81188b30572d6319ebd9ba4dfa27f589e8"
)
BOOTSTRAP_FILES = {
    "updater-bootstrap.tar.gz": (
        "06635e7eb448acb037a505db5daccb702f7dd998d9c65d32c9ef20766b0b7f90"
    ),
    "updater-bootstrap.manifest.json": (
        "649e3a887d37bc220f16a80e58721c81188b30572d6319ebd9ba4dfa27f589e8"
    ),
    "updater-bootstrap.manifest.sig": (
        "262872ffc0273e69459763e2f8afc839f976a7e18cea0e1208232744d57aa46a"
    ),
    "bootstrap-signing-public-key.pem": (
        "390a10b2e18f1d9eeffd5146e166cc518cc13bb03c6f2784c101456d8042809e"
    ),
}
BOOTSTRAP_KEY_FINGERPRINT = (
    "sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013"
)
MINIMUM_BOOTSTRAP_SEQUENCE = 4
STABLE_METADATA_URL_PREFIX = "CATHEDRAL_VALIDATOR_STABLE_METADATA_URL="

# The signed installer refuses group-writable ancestors. Official Ubuntu
# rootfs often leaves /usr/local as 2775.
IMAGE_DESTINATION_ANCESTORS = (
    "usr/local",
    "usr/local/lib",
    "usr/local/sbin",
    "usr/local/share",
    "var/lib",
    "etc",
    "opt",
)

# Mutable state lives on the named volume. Bake absolute dest symlinks so a
# --read-only root can start without creating them at runtime.
VOLUME_LINKS = (
    ("var/lib/cathedral/releases", "opt/cathedral-validator"),
    ("var/lib/cathedral/update", "var/lib/cathedral-validator-update"),
    ("var/lib/cathedral/validator", "var/lib/cathedral-validator"),
)


class ImageBootstrapRefused(RuntimeError):
    """The published bootstrap cannot be installed into this image."""


def _load_installer():
    import importlib.util
    import sys
    from importlib.machinery import SourceFileLoader

    name = "cathedral_image_install_updater_bundle"
    spec = importlib.util.spec_from_file_location(
        name,
        INSTALLER_PATH,
        loader=SourceFileLoader(name, str(INSTALLER_PATH)),
    )
    if spec is None or spec.loader is None:
        raise ImageBootstrapRefused("updater installer is missing")
    module = importlib.util.module_from_spec(spec)
    # Dataclass looks the module up in sys.modules while the class body runs.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def prepare_image_destination_ancestors(root: Path) -> None:
    """Clear group/other write on ancestors the signed installer requires."""

    for relative in IMAGE_DESTINATION_ANCESTORS:
        path = root / relative
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            continue
        if metadata.st_uid != os.geteuid():
            continue
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            os.chmod(path, 0o755)


def install_volume_layout(root: Path) -> None:
    """Point host paths at the named volume so PID1 need not write the root FS."""

    for volume_relative, dest_relative in VOLUME_LINKS:
        volume_path = root / volume_relative
        dest = root / dest_relative
        volume_path.mkdir(parents=True, exist_ok=True)
        os.chmod(volume_path, 0o755)
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        elif dest.is_dir():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.symlink_to(volume_path)


def download_bootstrap(dest: Path, *, base: str = BOOTSTRAP_BASE) -> dict[str, Path]:
    dest.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for name, digest in BOOTSTRAP_FILES.items():
        path = dest / name
        url = f"{base}/{name}"
        request = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(request, timeout=120) as response:
            body = response.read()
        if hashlib.sha256(body).hexdigest() != digest:
            raise ImageBootstrapRefused(f"{name} digest does not match install.sh")
        path.write_bytes(body)
        paths[name] = path
    return paths


def _stable_metadata_url(example: bytes) -> str:
    lines = example.decode("ascii").splitlines()
    matches = [
        line[len(STABLE_METADATA_URL_PREFIX) :]
        for line in lines
        if line.startswith(STABLE_METADATA_URL_PREFIX)
    ]
    if len(matches) != 1 or not matches[0].startswith("https://"):
        raise ImageBootstrapRefused("signed update example has no stable metadata URL")
    return matches[0]


def write_image_bootstrap_metadata(bundle, dest: Path, *, runtime_key: Path) -> None:
    example = bundle.files["payload/examples/update.env.example"].body
    document = {
        "schema": "cathedral_validator_image_bootstrap_v1",
        "expires_unix": bundle.expires_unix,
        "bootstrap_sequence": bundle.bootstrap_sequence,
        "stable_metadata_url": _stable_metadata_url(example),
        "stable_minimum_sequence": bundle.stable_release_minimum_sequence,
        "stable_metadata_sha256": bundle.stable_release_metadata_sha256,
        "runtime_release_key": str(runtime_key),
        "runtime_release_key_fingerprint": bundle.runtime_release_key_fingerprint,
    }
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    os.chmod(dest, 0o444)


def install_published_bootstrap(
    *,
    root: Path,
    staging: Path,
    python_executable: Path,
    expected_owner: int,
) -> str:
    installer = _load_installer()
    prepare_image_destination_ancestors(root)
    paths = download_bootstrap(staging)
    bundle = installer.verify_bundle(
        bundle_path=paths["updater-bootstrap.tar.gz"],
        manifest_path=paths["updater-bootstrap.manifest.json"],
        signature_path=paths["updater-bootstrap.manifest.sig"],
        bootstrap_public_key_path=paths["bootstrap-signing-public-key.pem"],
        expected_bootstrap_fingerprint=BOOTSTRAP_KEY_FINGERPRINT,
        minimum_bootstrap_sequence=MINIMUM_BOOTSTRAP_SEQUENCE,
        expected_owner=expected_owner,
    )
    digest = installer.install_verified_bundle(
        bundle,
        root=root,
        expected_owner=expected_owner,
        python_executable=python_executable,
        host_activation=False,
    )
    share = root / "usr/local/share/cathedral-validator-updater/bootstrap"
    share.mkdir(parents=True, exist_ok=True)
    runtime_key = share / "runtime-release-public-key.pem"
    installed_key = root / "etc/cathedral-validator/runtime-release-public-key.pem"
    shutil.copy2(installed_key, runtime_key)
    os.chmod(runtime_key, 0o444)
    write_image_bootstrap_metadata(
        bundle, share / "image-bootstrap.json", runtime_key=runtime_key
    )
    install_volume_layout(root)
    return digest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install the signed updater bootstrap into a container image"
    )
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path("/usr/bin/python3.12"))
    options = parser.parse_args(argv)
    try:
        digest = install_published_bootstrap(
            root=options.root,
            staging=options.staging,
            python_executable=options.python,
            expected_owner=os.geteuid(),
        )
    except (ImageBootstrapRefused, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"image bootstrap refused: {exc}") from exc
    print(f"CATHEDRAL_VALIDATOR_IMAGE_BOOTSTRAP {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
