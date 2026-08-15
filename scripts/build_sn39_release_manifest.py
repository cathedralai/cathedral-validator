#!/usr/bin/env python3
"""Build the root-owned immutable-install manifest for one reviewed SN39 SHA.

Two postures install this release and each gets its own manifest. The default
is the Cathedral ORIGIN host: it pins the controlled-disclosure TDX verifier
binary and the producer-side status publisher. `--relay` builds the manifest a
THIRD PARTY can actually produce — same reviewed source, same environment
commitment, same bootstrap binding, minus the two external files a relay can
neither obtain nor install, plus the shadow-audit mismatch alert that is a
relay's only health surface. The relay manifest is refused outright on a host
holding SN39 launch material, so it cannot be used to weaken the origin host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, NamedTuple

SHA_RE = re.compile(r"[0-9a-f]{40}")
NAME_RE = re.compile(r"[-_.]+")
BOOTSTRAP_PYTHON = Path("/usr/bin/python3.12")
INSTALL_ROOT = Path("/etc/cathedral-validator")
PROVENANCE_INSTALL_ROOT = INSTALL_ROOT / "provenance"
ROOT_UID = 0
EXPECTED_VERIFIER_BINARY = (
    "sha256:35bb55f89f411d5dcf5f72be90488e999ee68c41dfc0429a0dcb8cc2b448b6bb"
)
# The exact Compute archive installed into the immutable validator environment.
# This revision reserves `cathedral-validator` for scaffold.cli and exposes its
# worker-side publisher as `cathedral-compute-validator`.
EXPECTED_CATHEDRAL_URL = (
    "https://github.com/cathedralai/cathedral-compute/archive/"
    "26ebdbb885746f1835ea67ff314e384b4838560f.tar.gz"
)
EXPECTED_CATHEDRAL_ARCHIVE_SHA256 = (
    "559dd8e347dcf635a76d4f930f251184fa09948ad3173ba36211a967c1f5d46e"
)
RELEASE_FILES = (
    "config/validator-selfcompose-sn39.toml",
    "config/validator-thin-sn39-relay.toml",
    "config/provenance/registry-keys.json",
    "config/provenance/report-keys.json",
    "config/provenance/index-keys.json",
    "config/provenance/release-attestation-keys.json",
    "requirements/sn39-reproduction.lock",
    "deploy/sn39/cathedral-sn39-release-launcher.py",
    "deploy/sn39/cathedral-validator-sn39.service",
    "requirements/sn39-build.in",
    "requirements/sn39-build.lock",
    "scaffold/sn39_continuous_authorization.py",
    "scripts/publish_sn39_validator_status.py",
    "scripts/finalize_sn39_public_release.py",
    "deploy/sn39/cathedral-sn39-public-status.service",
    "deploy/sn39/cathedral-sn39-public-status.timer",
    "deploy/sn39/cathedral-sn39-validator.sysusers",
    "deploy/sn39/cathedral-sn39-validator.tmpfiles",
    # Both postures log to /var/log/cathedral-validator, so both bind the
    # fragment that bounds it. Binding the reviewed SOURCE (rather than adding
    # an external_files entry for the installed /etc/logrotate.d copy) is
    # deliberate: logrotate is not in the exec path the launcher re-verifies,
    # and an external entry naming a file an existing host has not installed
    # yet would make the manifest unbuildable rather than stricter.
    "deploy/sn39/cathedral-validator.logrotate",
)
# The relay manifest binds a SUPERSET of the reviewed source above: every file
# the Cathedral manifest binds, plus the files only a relay host installs.
# Binding more source, not less, is the point — what a relay manifest omits is
# an EXTERNAL file (the controlled verifier binary), never reviewed source.
#
# The three shadow-audit alert files are here because README's relay install
# installs them and enables the timer: on a relay the failed
# `cathedral-mismatch-alert.service` unit is the ONLY health surface, so an
# alert script a compromised service account could edit would be no alert at
# all. Binding them puts the relay's whole monitoring path inside the same
# tamper-evidence boundary as the validator it watches.
RELAY_RELEASE_FILES = RELEASE_FILES + (
    "deploy/sn39/cathedral-validator-sn39-relay.service",
    "deploy/sn39/cathedral-sn39-validator-relay.tmpfiles",
    "deploy/sn39/cathedral-mismatch-check",
    "deploy/sn39/cathedral-mismatch-alert.service",
    "deploy/sn39/cathedral-mismatch-alert.timer",
)
# The release-pinned absolute paths that make a host owe SN39 its own launch.
# `scaffold.validator_thin._sn39_launch_obligation` reads exactly these three,
# and a runtime that holds any of them must present the root-signed launch and
# recurring-write authorization no matter what its config says. Restating them
# here is what keeps `--relay` from being usable as a downgrade: on the one
# host where the obligation is real, a relay manifest cannot be built at all.
LAUNCH_MATERIAL_PATHS = (
    Path("/var/lib/cathedral-validator-controlled-sn39/current"),
    Path("/opt/cathedral-sn39/bin/cathedral-tdx-verifier"),
    Path("/etc/cathedral-validator/sn39-launch-approval.json"),
)


class InstallProfile(NamedTuple):
    """Which reviewed files one manifest binds, and what it therefore claims.

    Two postures install this release. The ORIGIN host holds the
    controlled-disclosure TDX evidence package and the pinned verifier binary,
    so its manifest pins the verifier bytes and the producer-side status
    publisher. A third-party RELAY holds neither: the raw evidence package is
    Cathedral's, its shadow audit is receipts-only by design
    (`config/validator-thin-sn39-relay.toml` omits `controlled_dir` and
    `verifier_binary`, and `scaffold/provenance_audit.py` requires both only in
    authority mode), and the public status publisher writes the producer's
    evidence tree as the producer's account. Pinning files a relay cannot
    obtain made the manifest builder — and therefore the launcher's whole
    verification — buildable by Cathedral only.

    The difference is carried here rather than as `if relay:` branches at each
    use so that what each posture claims is one readable object, and so that
    the Cathedral profile stays byte-identical to what it has always emitted.

    A NamedTuple rather than a dataclass on purpose: this script is loaded by
    `runpy.run_path` and by a bare `spec.loader.exec_module` in the test suite,
    neither of which registers the module in `sys.modules`, and
    `@dataclass` needs that registration to resolve its own annotations.
    """

    name: str
    release_files: tuple[str, ...]
    continuous_unit_source: str
    continuous_unit_path: Path
    tmpfiles_source: str
    tmpfiles_path: Path
    # FALSE for a relay only. The verifier binary is controlled-disclosure, so
    # a relay can neither install it nor prove its digest; pinning it is what
    # an origin-host manifest asserts and a relay manifest must not.
    pins_verifier_binary: bool
    # The status publisher runs as the producer's account and writes the
    # producer's published evidence tree. A relay does not install it, and an
    # external_files entry for a file that is absent is an unbuildable
    # manifest, not a stricter one.
    binds_status_publisher: bool
    # TRUE for a relay only. The relay install enables the shadow-audit
    # mismatch timer and has no other health surface, so its manifest binds the
    # check script and both units. The Cathedral posture is left byte-identical
    # to what it has always emitted — the origin host's alerting is governed by
    # Cathedral's own release runbook, and changing what an origin manifest
    # requires is not a documentation gap this fixes.
    binds_mismatch_alert: bool


CATHEDRAL_PROFILE = InstallProfile(
    name="cathedral",
    release_files=RELEASE_FILES,
    continuous_unit_source="deploy/sn39/cathedral-validator-sn39.service",
    continuous_unit_path=Path("/etc/systemd/system/cathedral-validator-sn39.service"),
    tmpfiles_source="deploy/sn39/cathedral-sn39-validator.tmpfiles",
    tmpfiles_path=Path("/etc/tmpfiles.d/cathedral-sn39-validator.conf"),
    pins_verifier_binary=True,
    binds_status_publisher=True,
    binds_mismatch_alert=False,
)
RELAY_PROFILE = InstallProfile(
    name="relay",
    release_files=RELAY_RELEASE_FILES,
    continuous_unit_source="deploy/sn39/cathedral-validator-sn39-relay.service",
    continuous_unit_path=Path(
        "/etc/systemd/system/cathedral-validator-sn39-relay.service"
    ),
    tmpfiles_source="deploy/sn39/cathedral-sn39-validator-relay.tmpfiles",
    tmpfiles_path=Path("/etc/tmpfiles.d/cathedral-sn39-validator-relay.conf"),
    pins_verifier_binary=False,
    binds_status_publisher=False,
    binds_mismatch_alert=True,
)


def install_profile(*, relay: bool) -> InstallProfile:
    return RELAY_PROFILE if relay else CATHEDRAL_PROFILE


def require_no_launch_material() -> None:
    """Refuse to build a relay manifest on a host that owes SN39 a launch."""
    for path in LAUNCH_MATERIAL_PATHS:
        try:
            path.lstat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            # A host that cannot answer the question is treated as holding the
            # material. Refusing the relay manifest is the safe direction:
            # the worst case is that an origin host must build the manifest it
            # was always supposed to build.
            raise SystemExit(
                f"cannot determine whether this host holds launch material: {path}"
            ) from None
        raise SystemExit(
            "this host holds SN39 launch material at "
            f"{path}, so --relay is refused. A host that can originate weights "
            "builds the Cathedral manifest, which pins the verifier binary."
        )


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def record_digest(state: Any, *parts: str) -> None:
    for part in parts:
        encoded = part.encode("utf-8")
        state.update(len(encoded).to_bytes(8, "big"))
        state.update(encoded)


def immutable_tree_digest(root: Path) -> str:
    """Generate the byte-for-byte environment commitment checked at exec."""
    root_info = root.lstat()
    root_mode = stat.S_IMODE(root_info.st_mode)
    if (
        root.is_symlink()
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != ROOT_UID
        or root_mode & 0o022
        or root_mode & 0o005 != 0o005
    ):
        raise SystemExit(
            "immutable tree root must be root-controlled, readable, and "
            "searchable by the service account"
        )
    tree = hashlib.sha256()
    record_digest(tree, "root", f"{root_mode:04o}")
    for directory, names, files in os.walk(root, followlinks=False):
        names.sort()
        files.sort()
        base = Path(directory)
        for name in sorted([*names, *files]):
            path = base / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            mode = f"{stat.S_IMODE(info.st_mode):04o}"
            if stat.S_ISREG(info.st_mode):
                if (
                    info.st_uid != ROOT_UID
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) & 0o022
                    or stat.S_IMODE(info.st_mode) & 0o004 != 0o004
                ):
                    raise SystemExit(
                        "immutable tree file is not root-controlled, "
                        f"single-linked, and service-readable: {path}"
                    )
                record_digest(tree, "file", relative, mode, digest(path))
            elif stat.S_ISDIR(info.st_mode):
                if (
                    info.st_uid != ROOT_UID
                    or stat.S_IMODE(info.st_mode) & 0o022
                    or stat.S_IMODE(info.st_mode) & 0o005 != 0o005
                ):
                    raise SystemExit(
                        "immutable tree directory is not root-controlled, "
                        f"readable, and searchable by the service account: {path}"
                    )
                record_digest(tree, "directory", relative, mode)
            elif stat.S_ISLNK(info.st_mode):
                if info.st_uid != ROOT_UID:
                    raise SystemExit(
                        f"immutable tree symlink is not root-controlled: {path}"
                    )
                target = path.resolve(strict=True)
                target_info = target.stat()
                if stat.S_ISDIR(target_info.st_mode) and target.is_relative_to(root):
                    # Upstream accepts any in-root directory symlink. This repo
                    # narrows that to the single shape a stock venv creates
                    # (`python3 -m venv` makes lib64 -> lib on 64-bit Linux, and
                    # nothing else), because any other directory symlink inside an
                    # immutable tree is unexplained and a swapped target is exactly
                    # what the commitment exists to catch. Upstream's ownership and
                    # mode checks are kept on top of that, as is its digest label and
                    # root-relative target, so the commitment stays byte-identical to
                    # upstream's for the shapes both accept.
                    if relative != "lib64" or os.readlink(path) != "lib":
                        raise SystemExit(
                            "immutable tree directory symlink is unsupported "
                            f"(only a venv lib64 -> lib is allowed): {path}"
                        )
                    if (
                        target_info.st_uid != ROOT_UID
                        or stat.S_IMODE(target_info.st_mode) & 0o022
                        or stat.S_IMODE(target_info.st_mode) & 0o005 != 0o005
                    ):
                        raise SystemExit(
                            "immutable tree directory symlink target is not "
                            f"service-readable: {path}"
                        )
                    record_digest(
                        tree,
                        "directory-symlink",
                        relative,
                        os.readlink(path),
                        target.relative_to(root).as_posix(),
                        f"{stat.S_IMODE(target_info.st_mode):04o}",
                    )
                elif (
                    stat.S_ISREG(target_info.st_mode)
                    and target_info.st_uid == ROOT_UID
                    and target_info.st_nlink == 1
                    and not stat.S_IMODE(target_info.st_mode) & 0o022
                    and stat.S_IMODE(target_info.st_mode) & 0o004 == 0o004
                ):
                    record_digest(
                        tree,
                        "symlink",
                        relative,
                        os.readlink(path),
                        str(target),
                        f"{stat.S_IMODE(target_info.st_mode):04o}",
                        digest(target),
                    )
                else:
                    raise SystemExit(
                        f"versioned venv symlink target is unsupported: {path}"
                    )
            else:
                raise SystemExit(f"versioned venv has unsupported entry type: {path}")
    return "sha256:" + tree.hexdigest()


def canonical_name(value: str) -> str:
    return NAME_RE.sub("-", value).lower()


def locked_distributions(
    lock: Path,
    *,
    require_cathedral: bool,
) -> dict[str, str]:
    expected: dict[str, str] = {}
    for line in lock.read_text("utf-8").splitlines():
        if not line or line[0].isspace() or line.startswith("#"):
            continue
        direct = re.match(r"^([A-Za-z0-9_.-]+)\s+@\s+(\S+)\s+\\$", line)
        pinned = re.match(r"^([A-Za-z0-9_.-]+)==(\S+)\s+\\$", line)
        if direct:
            name, url = direct.groups()
            if canonical_name(name) != "cathedral" or url != EXPECTED_CATHEDRAL_URL:
                raise SystemExit(
                    "reproduction lock has an unexpected direct dependency"
                )
            expected["cathedral"] = "0.0.0"
        elif pinned:
            name, version = pinned.groups()
            normalized = canonical_name(name)
            if normalized in expected:
                raise SystemExit(f"reproduction lock duplicates {normalized}")
            expected[normalized] = version
        else:
            raise SystemExit(
                f"reproduction lock has an unsupported requirement: {line}"
            )
    if require_cathedral and (len(expected) != 55 or "cathedral" not in expected):
        raise SystemExit("reproduction lock distribution set is incomplete")
    if not require_cathedral and (
        set(expected)
        != {"hatchling", "packaging", "pathspec", "pluggy", "trove-classifiers"}
        or "cathedral" in expected
    ):
        raise SystemExit("build lock distribution set is incomplete")
    lock_text = lock.read_text("utf-8")
    if require_cathedral and (
        f"--hash=sha256:{EXPECTED_CATHEDRAL_ARCHIVE_SHA256}" not in lock_text
        or EXPECTED_CATHEDRAL_URL not in lock_text
    ):
        raise SystemExit("Cathedral archive bytes are not pinned in the lock")
    if not require_cathedral and (
        EXPECTED_CATHEDRAL_URL in lock_text or "hatchling==" not in lock_text
    ):
        raise SystemExit("build lock contains an unexpected source package")
    return expected


def expected_locked_distributions(
    reproduction_lock: Path,
    build_lock: Path,
) -> dict[str, str]:
    expected = locked_distributions(
        reproduction_lock,
        require_cathedral=True,
    )
    for name, version in locked_distributions(
        build_lock,
        require_cathedral=False,
    ).items():
        if name in expected and expected[name] != version:
            raise SystemExit(f"build and reproduction locks disagree on {name}")
        expected[name] = version
    return expected


def validate_installed_distributions(
    document: dict[str, Any],
    expected: dict[str, str],
) -> None:
    rows = document.get("installed")
    if not isinstance(rows, list):
        raise SystemExit("pip inspect returned no installed distribution list")
    installed: dict[str, tuple[str, dict[str, Any] | None]] = {}
    for row in rows:
        metadata = row.get("metadata") if isinstance(row, dict) else None
        if not isinstance(metadata, dict):
            raise SystemExit("pip inspect returned malformed package metadata")
        name = canonical_name(str(metadata.get("name") or ""))
        version = str(metadata.get("version") or "")
        if not name or not version or name in installed:
            raise SystemExit("pip inspect returned a duplicate or nameless package")
        direct_url = row.get("direct_url")
        installed[name] = (
            version,
            direct_url if isinstance(direct_url, dict) else None,
        )
    unexpected = set(installed) - set(expected) - {"pip"}
    missing = set(expected) - set(installed)
    mismatched = {
        name
        for name, version in expected.items()
        if name in installed and installed[name][0] != version
    }
    if unexpected or missing or mismatched:
        raise SystemExit(
            "installed venv differs from the hash lock "
            f"(unexpected={sorted(unexpected)}, missing={sorted(missing)}, "
            f"version_mismatch={sorted(mismatched)})"
        )
    cathedral_url = installed["cathedral"][1] or {}
    archive_info = cathedral_url.get("archive_info") or {}
    hashes = archive_info.get("hashes") or {}
    if (
        cathedral_url.get("url") != EXPECTED_CATHEDRAL_URL
        or hashes.get("sha256") != EXPECTED_CATHEDRAL_ARCHIVE_SHA256
    ):
        raise SystemExit(
            "installed Cathedral dependency is not the hash-locked commit archive"
        )


def validate_compute_console_scripts(names: list[str]) -> None:
    """The Compute dependency must never own the Validator command."""
    if any(not isinstance(name, str) for name in names):
        raise SystemExit("Compute console-script metadata is malformed")
    if "cathedral-validator" in names:
        raise SystemExit(
            "pinned Cathedral Compute dependency overwrites cathedral-validator"
        )


def validate_installed_release_files(pairs: tuple[tuple[Path, Path], ...]) -> None:
    """Require every external release file to match its reviewed source bytes."""
    for installed, reviewed in pairs:
        try:
            installed_bytes = installed.read_bytes()
            reviewed_bytes = reviewed.read_bytes()
        except OSError as exc:
            raise SystemExit(
                f"required release file is unavailable: {installed}"
            ) from exc
        if installed_bytes != reviewed_bytes:
            raise SystemExit(
                f"installed file differs from reviewed release: {installed}"
            )


def verify_locked_environment(
    venv: Path,
    reproduction_lock: Path,
    build_lock: Path,
) -> None:
    python = venv / "bin/python"
    try:
        raw = subprocess.check_output(
            [str(python), "-m", "pip", "inspect", "--local"],
            text=True,
            timeout=120,
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        document = json.loads(raw)
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as exc:
        raise SystemExit("cannot inspect the versioned venv") from exc
    validate_installed_distributions(
        document,
        expected_locked_distributions(reproduction_lock, build_lock),
    )
    try:
        entry_points_raw = subprocess.check_output(
            [
                str(python),
                "-I",
                "-E",
                "-s",
                "-c",
                (
                    "import importlib.metadata as m,json;"
                    "d=m.distribution('cathedral');"
                    "print(json.dumps(sorted(e.name for e in d.entry_points "
                    "if e.group=='console_scripts')))"
                ),
            ],
            text=True,
            timeout=30,
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        entry_points = json.loads(entry_points_raw)
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as exc:
        raise SystemExit("cannot inspect Cathedral Compute console scripts") from exc
    if not isinstance(entry_points, list):
        raise SystemExit("Compute console-script metadata is malformed")
    validate_compute_console_scripts(entry_points)


def git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["/usr/bin/git", "-c", f"safe.directory={root}", *args],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit("cannot verify reviewed release source") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--venv", type=Path)
    parser.add_argument(
        "--relay",
        action="store_true",
        help=(
            "build the third-party relay manifest: no controlled verifier "
            "binary pin, the relay unit and tmpfiles, the shadow-audit "
            "mismatch alert, and no producer-side status publisher"
        ),
    )
    parser.add_argument(
        "--continuous-config",
        type=Path,
        default=INSTALL_ROOT / "validator-thin-sn39-relay.toml",
    )
    parser.add_argument(
        "--registry-keys",
        type=Path,
        default=PROVENANCE_INSTALL_ROOT / "registry-keys.json",
    )
    parser.add_argument(
        "--report-keys",
        type=Path,
        default=PROVENANCE_INSTALL_ROOT / "report-keys.json",
    )
    parser.add_argument(
        "--index-keys",
        type=Path,
        default=PROVENANCE_INSTALL_ROOT / "index-keys.json",
    )
    # The four paths below default to None rather than to a literal because the
    # posture chooses them. Resolving the default after parsing keeps the
    # Cathedral invocation identical to what it has always produced while
    # letting --relay select the unit and tmpfiles a relay host installs.
    parser.add_argument("--verifier", type=Path)
    parser.add_argument(
        "--launcher",
        type=Path,
        default=Path("/usr/local/libexec/cathedral-sn39-release"),
    )
    parser.add_argument("--continuous-unit", type=Path)
    parser.add_argument("--status-unit", type=Path)
    parser.add_argument("--status-timer", type=Path)
    # Relay-only, and refused rather than ignored in the Cathedral posture for
    # the same reason the Cathedral-only paths are refused with --relay.
    parser.add_argument("--mismatch-check", type=Path)
    parser.add_argument("--mismatch-unit", type=Path)
    parser.add_argument("--mismatch-timer", type=Path)
    parser.add_argument(
        "--sysusers",
        type=Path,
        default=Path("/etc/sysusers.d/cathedral-sn39-validator.conf"),
    )
    parser.add_argument("--tmpfiles", type=Path)
    parser.add_argument(
        "--bootstrap-python",
        type=Path,
        default=BOOTSTRAP_PYTHON,
    )
    args = parser.parse_args()
    profile = install_profile(relay=args.relay)
    if args.relay:
        # Refused rather than ignored. Silently dropping a path the operator
        # named would produce a manifest that does not bind the file they
        # believe it binds, which is the failure mode this whole file exists
        # to prevent.
        for flag, value in (
            ("--verifier", args.verifier),
            ("--status-unit", args.status_unit),
            ("--status-timer", args.status_timer),
        ):
            if value is not None:
                raise SystemExit(
                    f"{flag} is a Cathedral-only path and is refused with --relay"
                )
        require_no_launch_material()
    else:
        for flag, value in (
            ("--mismatch-check", args.mismatch_check),
            ("--mismatch-unit", args.mismatch_unit),
            ("--mismatch-timer", args.mismatch_timer),
        ):
            if value is not None:
                raise SystemExit(f"{flag} is a relay-only path and needs --relay")
    verifier = args.verifier or Path("/opt/cathedral-sn39/bin/cathedral-tdx-verifier")
    continuous_unit = args.continuous_unit or profile.continuous_unit_path
    status_unit = args.status_unit or Path(
        "/etc/systemd/system/cathedral-sn39-public-status.service"
    )
    status_timer = args.status_timer or Path(
        "/etc/systemd/system/cathedral-sn39-public-status.timer"
    )
    mismatch_check = args.mismatch_check or Path(
        "/usr/local/bin/cathedral-mismatch-check"
    )
    mismatch_unit = args.mismatch_unit or Path(
        "/etc/systemd/system/cathedral-mismatch-alert.service"
    )
    mismatch_timer = args.mismatch_timer or Path(
        "/etc/systemd/system/cathedral-mismatch-alert.timer"
    )
    tmpfiles = args.tmpfiles or profile.tmpfiles_path
    root = args.release.resolve()
    venv = (
        args.venv.resolve()
        if args.venv is not None
        else Path("/opt/cathedral-sn39/venvs") / args.release_sha
    )
    immutable_tree_digest(root)
    if (
        SHA_RE.fullmatch(args.release_sha) is None
        or git(root, "rev-parse", "HEAD") != args.release_sha
        or git(
            root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        )
    ):
        raise SystemExit("release checkout is not the exact pristine requested SHA")
    config_pairs = (
        (args.continuous_config, root / "config/validator-thin-sn39-relay.toml"),
        (args.registry_keys, root / "config/provenance/registry-keys.json"),
        (args.report_keys, root / "config/provenance/report-keys.json"),
        (args.index_keys, root / "config/provenance/index-keys.json"),
        (
            args.launcher,
            root / "deploy/sn39/cathedral-sn39-release-launcher.py",
        ),
        (
            continuous_unit,
            root / profile.continuous_unit_source,
        ),
        *(
            (
                (
                    status_unit,
                    root / "deploy/sn39/cathedral-sn39-public-status.service",
                ),
                (
                    status_timer,
                    root / "deploy/sn39/cathedral-sn39-public-status.timer",
                ),
            )
            if profile.binds_status_publisher
            else ()
        ),
        *(
            (
                (mismatch_check, root / "deploy/sn39/cathedral-mismatch-check"),
                (
                    mismatch_unit,
                    root / "deploy/sn39/cathedral-mismatch-alert.service",
                ),
                (
                    mismatch_timer,
                    root / "deploy/sn39/cathedral-mismatch-alert.timer",
                ),
            )
            if profile.binds_mismatch_alert
            else ()
        ),
        (args.sysusers, root / "deploy/sn39/cathedral-sn39-validator.sysusers"),
        (tmpfiles, root / profile.tmpfiles_source),
    )
    validate_installed_release_files(config_pairs)
    if profile.pins_verifier_binary and digest(verifier) != EXPECTED_VERIFIER_BINARY:
        raise SystemExit("installed verifier binary differs from the launch pin")
    try:
        bootstrap_info = args.bootstrap_python.lstat()
        bootstrap_resolved = args.bootstrap_python.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SystemExit("bootstrap interpreter is unavailable") from exc
    if (
        bootstrap_info.st_uid != 0
        or stat.S_IMODE(bootstrap_info.st_mode) & 0o022
        or not bootstrap_resolved.is_file()
        or bootstrap_resolved.stat().st_uid != 0
        or stat.S_IMODE(bootstrap_resolved.stat().st_mode) & 0o022
    ):
        raise SystemExit("bootstrap interpreter is not root-controlled")
    verify_locked_environment(
        venv,
        root / "requirements/sn39-reproduction.lock",
        root / "requirements/sn39-build.lock",
    )
    release_files = {name: digest(root / name) for name in profile.release_files}
    external_files = {
        str(args.continuous_config): digest(args.continuous_config),
        str(args.registry_keys): digest(args.registry_keys),
        str(args.report_keys): digest(args.report_keys),
        str(args.index_keys): digest(args.index_keys),
        str(args.launcher): digest(args.launcher),
        str(continuous_unit): digest(continuous_unit),
        str(args.sysusers): digest(args.sysusers),
        str(tmpfiles): digest(tmpfiles),
    }
    if profile.pins_verifier_binary:
        external_files[str(verifier)] = digest(verifier)
    if profile.binds_status_publisher:
        external_files[str(status_unit)] = digest(status_unit)
        external_files[str(status_timer)] = digest(status_timer)
    if profile.binds_mismatch_alert:
        external_files[str(mismatch_check)] = digest(mismatch_check)
        external_files[str(mismatch_unit)] = digest(mismatch_unit)
        external_files[str(mismatch_timer)] = digest(mismatch_timer)
    print(
        json.dumps(
            {
                "schema": "cathedral_sn39_release_install_v3",
                "release_sha": args.release_sha,
                "release_files": release_files,
                "external_files": external_files,
                "venv_tree_digest": immutable_tree_digest(venv),
                "bootstrap_python": {
                    "invoked_path": str(args.bootstrap_python),
                    "resolved_path": str(bootstrap_resolved),
                    "digest": digest(bootstrap_resolved),
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
