#!/usr/bin/python3.12
"""PID1 for the Cathedral SN94 validator container.

The image is the signed bootstrap. This process replaces systemd: it copies
the mounted hotkey and SNP policy, runs boot reconcile, starts the validator,
reruns the signed updater on the hourly jittered schedule, and keeps exit
codes 2 and 3 stopped. It does no network I/O of its own. The updater child
talks back through a Unix socket instead of systemctl.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


VALIDATOR_USER = "cathedral-validator"
HOTKEY_SOURCE = Path("/run/secrets/hotkey")
HOTKEY_DEST = Path("/run/cathedral-validator-wallet/validator/hotkeys/default")
SNP_SOURCE = Path("/etc/cathedral/snp-policy.json")
SNP_DEST = Path("/etc/cathedral-validator/snp-policy.json")
TDX_SOURCE = Path("/etc/cathedral/tdx-measurement-policy.json")
TDX_DEST = Path("/etc/cathedral-validator/tdx-measurement-policy.json")
ETC = Path("/etc/cathedral-validator")
IDENTITY_FILE = ETC / "identity.env"
DIRECT_ENV = ETC / "direct.env"
UPDATE_ENV = ETC / "update.env"
RUNTIME_KEY = ETC / "runtime-release-public-key.pem"
IMAGE_BOOTSTRAP = Path(
    "/usr/local/share/cathedral-validator-updater/bootstrap/image-bootstrap.json"
)
INSTALL_ROOT = Path("/opt/cathedral-validator")
STATE_ROOT = Path("/var/lib/cathedral-validator-update")
VALIDATOR_HOME = Path("/var/lib/cathedral-validator")
VOLUME_ROOT = Path("/var/lib/cathedral")
CONTROL_SOCKET = Path("/run/cathedral/service.sock")
SUPERVISOR_STATE = Path("/run/cathedral/supervisor.json")
UPDATER_PYTHON = Path("/usr/local/lib/cathedral-validator-updater/bin/python3.12")
CONTAINER_UPDATE = Path("/usr/local/lib/cathedral-container/container_update.py")
SETPRIV = Path("/usr/bin/setpriv")
STOP_GRACE_SECONDS = 150
TERMINAL_EXIT_CODES = frozenset({2, 3})
UPDATE_FIRST_DELAY_SECONDS = 15 * 60
UPDATE_INTERVAL_SECONDS = 60 * 60
UPDATE_JITTER_SECONDS = 5 * 60
VALIDATOR_RESTART_DELAY_SECONDS = 15
DEFAULT_INTERVAL_SECONDS = "1500"
CONTROL_ACTIONS = frozenset({"restart", "stop"})


class SupervisorRefused(ValueError):
    """The container cannot start without breaking a local safety boundary."""


def is_first_install(state_root: Path) -> bool:
    return not (state_root / "state.json").is_file()


def check_bootstrap_expiry(
    *,
    expires_unix: int,
    now_unix: int,
    first_install: bool,
) -> None:
    """Refuse an expired bootstrap only on an empty state volume."""

    if not first_install:
        return
    if (
        isinstance(expires_unix, bool)
        or not isinstance(expires_unix, int)
        or expires_unix < 1
    ):
        raise SupervisorRefused("bootstrap expiry is invalid")
    if now_unix >= expires_unix:
        raise SupervisorRefused("bootstrap manifest has expired")


def load_image_bootstrap(path: Path = IMAGE_BOOTSTRAP) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupervisorRefused("image bootstrap metadata is unreadable") from exc
    required = (
        "expires_unix",
        "stable_metadata_url",
        "stable_minimum_sequence",
        "stable_metadata_sha256",
        "runtime_release_key",
    )
    if not isinstance(document, dict) or any(key not in document for key in required):
        raise SupervisorRefused("image bootstrap metadata is incomplete")
    return document


def copy_owned_file(
    source: Path,
    dest: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    """Copy a mounted file to a dest the destination uid can read.

    Used for the hotkey (0400, validator uid) and policy files (0644, root).
    """

    if not source.is_absolute() or source.is_symlink() or not source.is_file():
        raise SupervisorRefused(f"{source} must be an absolute regular file")
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        body = source.read_bytes()
    except OSError as exc:
        raise SupervisorRefused(f"{source} is unreadable") from exc
    if not body:
        raise SupervisorRefused(f"{source} is empty")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(dest, flags, mode)
    try:
        os.write(fd, body)
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
    finally:
        os.close(fd)


def require_mounted_snp_policy(path: Path = SNP_SOURCE) -> None:
    if path.is_file() and not path.is_symlink():
        return
    raise SupervisorRefused(
        "mount a reviewed SNP policy at /etc/cathedral/snp-policy.json; "
        "this image does not ship a default policy"
    )


def write_text_file(path: Path, body: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="ascii")
    os.chmod(path, mode)


def write_identity_env(path: Path, expected_hotkey: str) -> None:
    if not expected_hotkey or not expected_hotkey.isascii():
        raise SupervisorRefused(
            "CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY must be the public SS58 address"
        )
    write_text_file(path, f"CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY={expected_hotkey}\n")


def write_direct_env(path: Path, *, interval_seconds: str) -> None:
    write_text_file(
        path,
        (
            f"CATHEDRAL_SNP_POLICY={SNP_DEST}\n"
            f"CATHEDRAL_VALIDATOR_INTERVAL_SECONDS={interval_seconds}\n"
        ),
    )


def write_update_env(path: Path, *, metadata_url: str, minimum_sequence: int) -> None:
    write_text_file(
        path,
        (
            f"CATHEDRAL_VALIDATOR_STABLE_METADATA_URL={metadata_url}\n"
            f"CATHEDRAL_VALIDATOR_STABLE_MINIMUM_SEQUENCE={minimum_sequence}\n"
        ),
    )


def next_update_due(
    *, now: float, first: bool, jitter: Callable[[int], int] = secrets.randbelow
) -> float:
    delay = UPDATE_FIRST_DELAY_SECONDS if first else UPDATE_INTERVAL_SECONDS
    return now + delay + jitter(UPDATE_JITTER_SECONDS + 1)


def decode_control_action(raw: bytes) -> str:
    if not raw or len(raw) > 32:
        raise SupervisorRefused("container service control request is invalid")
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise SupervisorRefused("container service control request is invalid") from exc
    if text not in CONTROL_ACTIONS:
        raise SupervisorRefused("container service control request is not fixed")
    return text


def write_supervisor_state(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(document), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    os.chmod(path, 0o644)


def read_supervisor_state(path: Path = SUPERVISOR_STATE) -> dict[str, Any] | None:
    try:
        document = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def bind_volume_paths(*, volume_root: Path | None = None) -> None:
    """Put journal, releases, and updater state on the one named volume.

    The image bakes dest as a symlink so a --read-only root can start. This
    only creates missing dests when the parent is writable (tests, or a
    writable root).
    """

    if volume_root is None:
        volume_root = VOLUME_ROOT
    mapping = (
        (volume_root / "releases", INSTALL_ROOT),
        (volume_root / "update", STATE_ROOT),
        (volume_root / "validator", VALIDATOR_HOME),
    )
    for source, dest in mapping:
        source.mkdir(parents=True, exist_ok=True)
        wanted = 0o755 if dest == INSTALL_ROOT else 0o700
        try:
            os.chmod(source, wanted)
        except PermissionError as exc:
            raise SupervisorRefused(
                f"{source} must be root-owned so PID1 can set mode {wanted:o}"
            ) from exc
        if dest.exists() or dest.is_symlink():
            if dest.is_symlink() and dest.resolve() == source.resolve():
                continue
            if dest.is_dir() and not dest.is_symlink() and not any(dest.iterdir()):
                dest.rmdir()
            elif dest.resolve() != source.resolve():
                raise SupervisorRefused(f"{dest} is not the state volume path")
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.symlink_to(source)


def validator_command(*, expected_hotkey: str, interval_seconds: str) -> list[str]:
    current = INSTALL_ROOT / "current" / "bin"
    return [
        str(current / "cathedral-validator"),
        "--network=finney",
        "--wallet-name=validator",
        "--wallet-hotkey=default",
        "--wallet-path=/run/cathedral-validator-wallet",
        f"--expected-hotkey={expected_hotkey}",
        f"--qvl={current / 'cathedral-tdx-verifier'}",
        f"--snp-policy={SNP_DEST}",
        f"--snpguest={current / 'snpguest'}",
        f"--interval-seconds={interval_seconds}",
        "--confirm-direct-write",
    ]


def drop_validator_command(command: Sequence[str], *, uid: int, gid: int) -> list[str]:
    # setpriv treats --init-groups, --clear-groups, --keep-groups, and
    # --groups as alternatives. --clear-groups drops every supplementary
    # group after the uid/gid change.
    return [
        str(SETPRIV),
        f"--reuid={uid}",
        f"--regid={gid}",
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--",
        *command,
    ]


class Supervisor:
    """Own the validator and updater children inside one container."""

    def __init__(
        self,
        *,
        expected_hotkey: str,
        interval_seconds: str = DEFAULT_INTERVAL_SECONDS,
        now: Callable[[], float] = time.time,
        spawn: Callable[..., subprocess.Popen[Any]] = subprocess.Popen,
    ) -> None:
        self.expected_hotkey = expected_hotkey
        self.interval_seconds = interval_seconds
        self.now = now
        self.spawn = spawn
        self.validator: subprocess.Popen[Any] | None = None
        self.updater: subprocess.Popen[Any] | None = None
        self.validator_held_stop: int | None = None
        self.update_due = 0.0
        self.first_update_scheduled = False
        self.control: socket.socket | None = None
        self._stopping = False

    def validator_uid_gid(self) -> tuple[int, int]:
        try:
            account = pwd.getpwnam(VALIDATOR_USER)
        except KeyError as exc:
            raise SupervisorRefused(
                "cathedral-validator service account does not exist"
            ) from exc
        return account.pw_uid, account.pw_gid

    def prepare(self) -> None:
        require_mounted_snp_policy()
        if not HOTKEY_SOURCE.is_file():
            raise SupervisorRefused(
                "mount the unencrypted hotkey at /run/secrets/hotkey"
            )
        bind_volume_paths()
        ETC.mkdir(parents=True, exist_ok=True)
        os.chmod(ETC, 0o755)
        uid, gid = self.validator_uid_gid()
        copy_owned_file(HOTKEY_SOURCE, HOTKEY_DEST, uid=uid, gid=gid, mode=0o400)
        copy_owned_file(SNP_SOURCE, SNP_DEST, uid=0, gid=0, mode=0o644)
        if TDX_SOURCE.is_file():
            copy_owned_file(TDX_SOURCE, TDX_DEST, uid=0, gid=0, mode=0o644)
        baked = load_image_bootstrap()
        first_install = is_first_install(VOLUME_ROOT / "update")
        check_bootstrap_expiry(
            expires_unix=int(baked["expires_unix"]),
            now_unix=int(self.now()),
            first_install=first_install,
        )
        write_identity_env(IDENTITY_FILE, self.expected_hotkey)
        write_direct_env(DIRECT_ENV, interval_seconds=self.interval_seconds)
        write_update_env(
            UPDATE_ENV,
            metadata_url=str(baked["stable_metadata_url"]),
            minimum_sequence=int(baked["stable_minimum_sequence"]),
        )
        key_source = Path(str(baked["runtime_release_key"]))
        if key_source != RUNTIME_KEY:
            copy_owned_file(key_source, RUNTIME_KEY, uid=0, gid=0, mode=0o644)
        VALIDATOR_HOME.mkdir(parents=True, exist_ok=True)
        pex = VALIDATOR_HOME / "pex"
        pex.mkdir(parents=True, exist_ok=True)
        os.chmod(VALIDATOR_HOME, 0o700)
        os.chmod(pex, 0o700)
        os.chown(pex, uid, gid)
        os.chown(VALIDATOR_HOME, uid, gid)
        self._listen()
        self._run_updater(first_install=first_install, reconcile=not first_install)
        self.update_due = next_update_due(now=self.now(), first=True)
        self.first_update_scheduled = True
        self._persist_state()

    def _listen(self) -> None:
        CONTROL_SOCKET.parent.mkdir(parents=True, exist_ok=True)
        if CONTROL_SOCKET.exists():
            CONTROL_SOCKET.unlink()
        self.control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.control.bind(os.fspath(CONTROL_SOCKET))
        os.chmod(CONTROL_SOCKET, 0o600)
        self.control.listen(1)
        self.control.setblocking(False)

    def _updater_argv(self, *, first_install: bool, reconcile: bool) -> list[str]:
        baked = load_image_bootstrap()
        argv = [
            str(UPDATER_PYTHON),
            str(CONTAINER_UPDATE),
            f"--identity-file={IDENTITY_FILE}",
            f"--install-root={VOLUME_ROOT / 'releases'}",
            f"--state-root={VOLUME_ROOT / 'update'}",
            f"--container-service-control={CONTROL_SOCKET}",
        ]
        if reconcile:
            argv.append("--reconcile-boot")
            return argv
        argv.extend(
            [
                "--channel=stable",
                f"--metadata-url={baked['stable_metadata_url']}",
                f"--public-key={RUNTIME_KEY}",
                f"--minimum-sequence={baked['stable_minimum_sequence']}",
            ]
        )
        if first_install:
            argv.extend(
                [
                    "--bootstrap-first-install",
                    f"--first-install-metadata-sha256={baked['stable_metadata_sha256']}",
                ]
            )
        return argv

    def _run_updater(self, *, first_install: bool, reconcile: bool) -> None:
        command = self._updater_argv(first_install=first_install, reconcile=reconcile)
        print(
            "CATHEDRAL_VALIDATOR_SUPERVISOR_UPDATER "
            f"first_install={str(first_install).lower()} "
            f"reconcile={str(reconcile).lower()}",
            flush=True,
        )
        process = self.spawn(command, pass_fds=())
        self.updater = process
        while process.poll() is None:
            # The updater restarts the validator through the control socket.
            # Blocked wait() would deadlock that call.
            self.accept_control()
            time.sleep(0.05)
        self.updater = None
        if process.returncode != 0:
            raise SupervisorRefused(
                f"updater exited {process.returncode} during "
                f"{'first install' if first_install else 'reconcile' if reconcile else 'update'}"
            )

    def start_validator(self) -> None:
        if self.validator is not None and self.validator.poll() is None:
            self._persist_state()
            return
        if self.validator_held_stop is not None:
            print(
                f"CATHEDRAL_VALIDATOR_SUPERVISOR_HELD exit={self.validator_held_stop}",
                flush=True,
            )
            self._persist_state()
            return
        uid, gid = self.validator_uid_gid()
        command = drop_validator_command(
            validator_command(
                expected_hotkey=self.expected_hotkey,
                interval_seconds=self.interval_seconds,
            ),
            uid=uid,
            gid=gid,
        )
        env = os.environ.copy()
        env["HOME"] = str(VALIDATOR_HOME)
        env["PEX_ROOT"] = str(VALIDATOR_HOME / "pex")
        env["CATHEDRAL_VALIDATOR_FAILED_WRITE_EXIT_CODE"] = "3"
        env["CATHEDRAL_VALIDATOR_CONTAINER"] = "1"
        if TDX_DEST.is_file():
            env["CATHEDRAL_TDX_MEASUREMENT_POLICY"] = str(TDX_DEST)
        print("CATHEDRAL_VALIDATOR_SUPERVISOR_START", flush=True)
        self.validator = self.spawn(command, env=env)
        self._persist_state()

    def handle_validator_exit(self, code: int) -> None:
        self.validator = None
        if code in TERMINAL_EXIT_CODES:
            self.validator_held_stop = code
            print(
                "CATHEDRAL_VALIDATOR_SUPERVISOR_TERMINAL "
                f"exit={code}. The validator stays stopped. "
                "Inspect the journal, then run record-failed-write as "
                "cathedral-validator and docker restart this container.",
                flush=True,
            )
            self._persist_state()
            return
        print(
            f"CATHEDRAL_VALIDATOR_SUPERVISOR_EXIT status={code}",
            flush=True,
        )
        self._persist_state()
        if self._stopping:
            return
        time.sleep(VALIDATOR_RESTART_DELAY_SECONDS)
        self.start_validator()

    def handle_control(self, action: str) -> str:
        if action not in CONTROL_ACTIONS:
            return "error: validator service command is not fixed"
        if action == "stop":
            self._stop_validator(grace_seconds=STOP_GRACE_SECONDS)
            return "ok"
        self.validator_held_stop = None
        if self.validator is not None:
            self._stop_validator(grace_seconds=STOP_GRACE_SECONDS)
        self.start_validator()
        return "ok"

    def accept_control(self) -> None:
        if self.control is None:
            return
        try:
            conn, _addr = self.control.accept()
        except BlockingIOError:
            return
        with conn:
            conn.settimeout(30)
            try:
                raw = conn.recv(32)
                reply = self.handle_control(decode_control_action(raw))
            except (SupervisorRefused, OSError) as exc:
                reply = f"error: {exc}"
            conn.sendall(f"{reply}\n".encode("ascii"))

    def maybe_update(self) -> None:
        if self._stopping or self.now() < self.update_due:
            return
        try:
            self._run_updater(first_install=False, reconcile=False)
        except SupervisorRefused as exc:
            print(f"CATHEDRAL_VALIDATOR_SUPERVISOR_UPDATE_REFUSED: {exc}", flush=True)
        self.update_due = next_update_due(now=self.now(), first=False)
        self._persist_state()

    def _stop_validator(self, *, grace_seconds: int) -> None:
        process = self.validator
        if process is None or process.poll() is not None:
            self.validator = None
            return
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=30)
        self.validator = None

    def shutdown(self) -> None:
        self._stopping = True
        print("CATHEDRAL_VALIDATOR_SUPERVISOR_STOP", flush=True)
        self._stop_validator(grace_seconds=STOP_GRACE_SECONDS)
        self._persist_state()

    def _persist_state(self) -> None:
        write_supervisor_state(
            SUPERVISOR_STATE,
            {
                "schema": "cathedral_validator_container_supervisor_v1",
                "validator_running": (
                    self.validator is not None and self.validator.poll() is None
                ),
                "validator_pid": None if self.validator is None else self.validator.pid,
                "held_stop": self.validator_held_stop,
                "update_loop": not self._stopping,
                "update_due_unix": int(self.update_due),
            },
        )

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self._on_term)
        signal.signal(signal.SIGINT, self._on_term)
        self.prepare()
        self.start_validator()
        while not self._stopping:
            self.accept_control()
            if self.validator is not None:
                result = self.validator.poll()
                if result is not None:
                    self.handle_validator_exit(result)
            self.maybe_update()
            time.sleep(0.25)
        return 0

    def _on_term(self, _signum: int, _frame: Any) -> None:
        self.shutdown()


def _expected_hotkey_from_env(env: Mapping[str, str]) -> str:
    value = env.get("CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY", "").strip()
    if not value:
        raise SupervisorRefused(
            "set CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY to the public SS58 address"
        )
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PID1 for the Cathedral SN94 validator container"
    )
    parser.add_argument(
        "--expected-hotkey",
        default="",
        help="defaults to CATHEDRAL_VALIDATOR_EXPECTED_HOTKEY",
    )
    options = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise SupervisorRefused("supervisor must start as root")
        expected = options.expected_hotkey or _expected_hotkey_from_env(os.environ)
        interval = os.environ.get(
            "CATHEDRAL_VALIDATOR_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS
        )
        return Supervisor(expected_hotkey=expected, interval_seconds=interval).run()
    except SupervisorRefused as exc:
        print(f"CATHEDRAL_VALIDATOR_SUPERVISOR_REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
