#!/usr/bin/env python3
"""Executable preflight for the SN39 v3 cutover: is the flip safe to ATTEMPT?

``assert_live_v3_contract.py`` answers the question AFTER the publisher flips:
"does a v3-pinned validator accept the vector now being emitted?" This script
answers the question BEFORE anything is touched: "if we flip, will the publisher
be able to compose a v3 vector at all, and will there be anything in the lane to
fund?" The two are complementary and neither substitutes for the other.

Why it exists. Seven independent things must ALL be true before a v3 flip, and
the failure mode when one is not is silent and severe: the publisher keeps
composing v2 (or refuses to sign at all), a v3-pinned validator rejects every
vector, and the validator goes dark with no single check failing to explain why.
Each one below is checked separately, so the report names WHICH of the seven is
missing rather than reporting one undifferentiated "not ready".

  0. composer_identity   -- the process every publisher-side check below is
     about IS the one that composes this subnet's signed vector. A box can run
     several processes that all import scaffold.publisher.server, answer
     /v1/validator/weights/next, and look alike; only one of them writes the
     ``latest:<network>:<netuid>`` row the validator consumes. Probing a decoy
     and reporting ITS state as fact is how this preflight once declared a
     healthy composer broken. See resolve_composer() for how the real one is
     identified -- it is never assumed from a unit-name flag.
  1. composer_reachable  -- the RUNNING publisher process can reach
     ``_compose_cybergym_lane_v3``. Not "the file exists somewhere on disk":
     proven through the interpreter, cwd and environment that process is
     actually running under, and cross-checked against the process's start time
     so a tree updated after the last restart is reported as unreachable (it is
     -- the running interpreter still holds the old module).
  2. db_migration        -- the publisher database the process is configured
     against carries migration ``0048_cybergym_scores`` (and ``0049``, which the
     intake writer needs), so the cybergym tables exist.
  3. producer_identity   -- the configured CyberGym producer is a real key, not
     a Substrate development key. See the note on that check: one accepted epoch
     under a dev key permanently raises an audience-scoped floor that rotating
     the key does NOT reset.
  4. trust_profile       -- the RUNNING validator's own trust profile admits
     ``validated_supply_v3``, evaluated by calling that validator's
     ``_validate_runtime_contract`` against its own live config with the pin
     swapped to v3. A pass here is the startup gate the re-pinned validator runs.
  5. fundable_lane       -- at least one scoreable/admitted task exists, i.e.
     the lane could fund somebody. A v3 flip with an empty corpus forfeits the
     whole 30% to burn, which is WORSE than v2's 10%.
  6. validator_writing   -- the validator is healthy and writing right now: a
     recent WEIGHTS_SUBMITTED, and ``blocks_since_last_update`` within a sane
     multiple of ``weights_rate_limit``. Flipping a validator that is already
     mute converts a pre-existing outage into a v3 mystery.

Every check reports PASS, FAIL, or BLOCKED-ON-OTHER (it could not be evaluated
because a check it depends on failed -- the reason names which). Exit is 0 only
when all seven PASS. Anything else is non-zero, because "we could not tell" is
not "ready".

READ-ONLY BY CONSTRUCTION. This script must be safe to run against the live box
at any time, so:

  * the only systemd verb it ever runs is ``systemctl show`` (never start, stop,
    restart, or daemon-reload). Publisher processes are enumerated by reading
    ``/proc``, not by asking systemd, so a publisher that runs outside the
    system manager (a user unit, a bare process) is still seen rather than
    silently missed;
  * the advisory-lock observation only READS ``pg_locks``. It never calls
    ``pg_try_advisory_lock`` itself: taking that lock would make the real
    composer's next refresh find it held and skip a whole build cycle, which is
    a write-shaped side effect of a read-only preflight;
  * its probe never imports ``scaffold.publisher.server``. Building the app
    constructs a ``Store``, and ``Store.__init__`` calls ``migrate()`` -- which
    would run migrations against the live publisher database as a side effect of
    a preflight. It imports ``scaffold.publisher.weights`` only, which has no
    such side effect;
  * SQLite is opened ``file:...?mode=ro`` and Postgres with
    ``default_transaction_read_only=on``, so a write cannot be issued even by
    accident;
  * nothing is written to the box, and no secret is printed. The database DSN
    carries a password and is never echoed; the producer hotkey is a public ss58
    and is.

Usage:
    # from a workstation, through IAP (the live box)
    python scripts/assert_v3_cutover_ready.py \\
        --gcloud-instance polaris-tdx-7e93d5de --gcloud-zone us-central1-b
    # on the box itself
    sudo python3 scripts/assert_v3_cutover_ready.py
    # machine-readable, for a runbook step or a CI gate
    python scripts/assert_v3_cutover_ready.py --gcloud-instance ... --json
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

PASS = "PASS"
FAIL = "FAIL"
BLOCKED = "BLOCKED-ON-OTHER"

# Only ever consulted when /proc enumeration finds no publisher at all, or when
# an operator names a unit explicitly. It is NOT how the composer is normally
# identified -- see resolve_composer(). It is the SN39 composer's unit because,
# if this script is ever reduced to guessing, it should guess the right one:
# cathedral-publisher.service is a legacy process on the live box that writes
# its own unscoped `latest` row, which nothing consumes.
DEFAULT_PUBLISHER_UNIT = "cathedral-scorer-sn39.service"
# Every publisher-shaped process runs this ASGI app. Matching on it (rather than
# on a unit name) is what lets the identification below consider a decoy at all,
# which is what lets it REJECT one.
PUBLISHER_PROCESS_MARKER = "scaffold.publisher.server"
DEFAULT_VALIDATOR_UNIT = "cathedral-validator-passive.service"
DEFAULT_VALIDATOR_CONFIG = "/etc/cathedral-validator/validator-mainnet-sn39.toml"
DEFAULT_STATUS_LOG = "/var/log/cathedral-validator/validator-status.jsonl"
DEFAULT_STATE_FILE = "/var/lib/cathedral-validator/thin-state.json"
DEFAULT_NETWORK = "finney"
DEFAULT_NETUID = 39
# The publisher composes and signs roughly every 25 minutes and the validator
# ticks against it; 2100s is the same staleness ceiling the public status
# service applies to a validator event (scripts/publish_sn39_validator_status.py
# MAX_EVENT_AGE_SECONDS), so the two agree on what "recent" means.
DEFAULT_MAX_WEIGHTS_AGE_SECS = 2100
# blocks_since_last_update is EXPECTED to exceed weights_rate_limit -- that is
# what makes the next write permitted. What is not expected is for it to keep
# growing: a validator that never writes accumulates multiples of the window.
DEFAULT_MAX_COOLDOWN_MULTIPLE = 3.0
# The composer refuses any fraction other than this one (weights.py
# V3_CYBERGYM_ALLOCATION), so a mismatch here is a vector that never signs.
V3_CYBERGYM_ALLOCATION = 0.30
CYBERGYM_MIGRATIONS = ("0048_cybergym_scores", "0049_cybergym_authenticated_body")
# The composer takes this cluster lock for the duration of every rebuild
# (weights._refresh_lock_name / Store.advisory_lock), so only the process that
# actually composes this subnet's vector ever holds it. It is held for a few
# hundred milliseconds out of every refresh cycle, which is why observing it is
# a bounded poll and a corroboration rather than the primary identification.
DEFAULT_OBSERVE_LOCK_SECS = 75.0

# The well-known Substrate development keys, by ss58 address. //Alice is the one
# that was found configured live; the rest are here because a deployment that
# reached for one dev key can reach for its neighbour. Both crypto types are
# listed: a bittensor hotkey is sr25519 by default, but nothing stops an ed25519
# dev key from being pasted into the same variable.
#
# Verified by derivation (bittensor_wallet.Keypair.create_from_uri), not from
# memory. test_dev_key_addresses_are_the_derived_ones re-derives them when the
# library is available, so a typo here fails a test rather than admitting a dev
# key.
SUBSTRATE_DEV_KEYS = {
    "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY": "//Alice",
    "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty": "//Bob",
    "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y": "//Charlie",
    "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy": "//Dave",
    "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEZcCj68kUMaw": "//Eve",
    "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2DjL": "//Ferdie",
    "5GNJqTPyNqANBkUVMN1LPPrxXnFouWXoe2wNSmmEoLctxiZY": "//Alice//stash",
    "5HpG9w8EBLe5XCrbczpwq5TSXvedjrBGCwqxK1iQ7qUsSWFc": "//Bob//stash",
    "5Ck5SLSHYac6WFt5UZRSsdJjwmpSZq85fd5TRNAdZQVzEAPT": "//Charlie//stash",
    "5HKPmK9GYtE1PSLsS1qiYU9xQ9Si1NcEhdeCq9sw5bqu4ns8": "//Dave//stash",
    "5FCfAonRZgTFrTd9HREEyeJjDpT397KMzizE6T3DvebLFE7n": "//Eve//stash",
    "5CRmqmsiNFExV6VbdmPJViVxrWmkaXXvBrSX8oqBT8R9vmWk": "//Ferdie//stash",
    "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu": "//Alice (ed25519)",
    "5GoNkf6WdbxCFnPdAnYYQyCjAKPJgLNxXwPjwTh6DGg6gN3E": "//Bob (ed25519)",
    "5DbKjhNLpqX3zqZdNBc9BGb4fHU1cRBaDhJUskrvkwfraDi6": "//Charlie (ed25519)",
    "5ECTwv6cZ5nJQPk6tWfaTrEk8YH2L7X1VT4EL5Tx2ikfFwb7": "//Dave (ed25519)",
    "5Ck2miBfCe1JQ4cY3NDsXyBaD6EcsgiVmEFTWwqNSs25XDEq": "//Eve (ed25519)",
    "5E2BmpVFzYGd386XRCZ76cDePMB3sfbZp5ZKGUsrG1m6gomN": "//Ferdie (ed25519)",
}

PRODUCER_HOTKEY_ENV = "CATHEDRAL_CYBERGYM_PRODUCER_HOTKEY"
MECHANISM_ENABLED_ENV = "CATHEDRAL_CYBERGYM_MECHANISM_ENABLED"
WEIGHT_FRACTION_ENV = "CATHEDRAL_CYBERGYM_WEIGHT_FRACTION"
MAX_SCORE_AGE_SECS_ENV = "CATHEDRAL_CYBERGYM_MAX_SCORE_AGE_SECS"
DEFAULT_MAX_SCORE_AGE_SECS = 3600.0
NETWORK_ENV = "CATHEDRAL_WEIGHT_POLICY_NETWORK"
NETUID_ENV = "CATHEDRAL_WEIGHT_POLICY_NETUID"
ALLOCATION_CONTRACT_ENV = "CATHEDRAL_ALLOCATION_CONTRACT"


def persisted_vector_id(network: str, netuid: int) -> str:
    """The signed-vector row id a correctly scoped publisher writes.

    Mirrors scaffold/publisher/weights.py ``_persisted_vector_id()``. The
    pre-scope publisher had no such function and wrote an unscoped ``latest``
    row instead, which is exactly what makes "which row does this process
    write?" a decisive identity question rather than a cosmetic one.
    """
    return f"latest:{network}:{netuid}"


def refresh_lock_name(network: str, netuid: int) -> str:
    """The cluster advisory lock only this subnet's composer ever takes.

    Mirrors scaffold/publisher/weights.py ``_refresh_lock_name()``.
    """
    return f"cathedral:weights:refresh:{network}:{netuid}"


class ProbeError(RuntimeError):
    """The preflight itself could not gather a fact. Not a check verdict."""


@dataclass
class CheckResult:
    check_id: str
    title: str
    state: str
    reason: str
    action: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.check_id,
            "title": self.title,
            "state": self.state,
            "reason": self.reason,
            "action": self.action,
            "evidence": self.evidence,
        }


# --------------------------------------------------------------------------
# The read-only probe surface. Every check consumes THIS, never a subprocess,
# so the unit tests substitute a fake and drive each failure deliberately.
# --------------------------------------------------------------------------

# Runs on the box as root and answers one JSON request. Kept in one blob so
# there is a single place where privileged reads happen and a single place to
# audit for writes: it opens files for reading, reads /proc, runs
# `systemctl show`, and spawns the service's own interpreter. Nothing else.
REMOTE_HELPER = r'''
import json, os, pwd, subprocess, sys, time


def _environ(pid):
    env = {}
    with open("/proc/%d/environ" % pid, "rb") as fh:
        for chunk in fh.read().split(b"\0"):
            if b"=" in chunk:
                key, _, value = chunk.partition(b"=")
                env[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
    return env


def _start_epoch(pid):
    with open("/proc/%d/stat" % pid) as fh:
        raw = fh.read()
    fields = raw[raw.rindex(")") + 2:].split()
    ticks = int(fields[19])
    boot = 0
    with open("/proc/stat") as fh:
        for line in fh:
            if line.startswith("btime "):
                boot = int(line.split()[1])
                break
    return boot + ticks / os.sysconf("SC_CLK_TCK")


def op_unit(req):
    out = {"unit": req["unit"]}
    for prop in ("MainPID", "User", "ActiveState", "SubState"):
        res = subprocess.run(
            ["systemctl", "show", "-p", prop, "--value", req["unit"]],
            capture_output=True, text=True, timeout=30,
        )
        out[prop] = res.stdout.strip()
    return out


def op_process(req):
    pid = int(req["pid"])
    with open("/proc/%d/cmdline" % pid, "rb") as fh:
        argv = [a.decode("utf-8", "replace") for a in fh.read().split(b"\0") if a]
    return {
        "pid": pid,
        "argv": argv,
        "cwd": os.readlink("/proc/%d/cwd" % pid),
        "exe": os.path.realpath("/proc/%d/exe" % pid),
        "environ": _environ(pid),
        "start_epoch": _start_epoch(pid),
        "now": time.time(),
    }


def _unit_of(pid):
    """The systemd unit a pid belongs to, read from its cgroup.

    Deliberately NOT `systemctl status`: a publisher started as a user unit
    (or by hand) has no system-manager entry, and asking systemd would make it
    invisible to the identification below. The cgroup path names it either way.
    """
    try:
        with open("/proc/%d/cgroup" % pid) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return ""
    for line in lines:
        for segment in reversed(line.split("/")):
            if segment.endswith(".service") or segment.endswith(".scope"):
                return segment
    return ""


def _status_of(pid):
    out = {"ppid": 0, "uid": 0}
    with open("/proc/%d/status" % pid) as fh:
        for line in fh:
            if line.startswith("PPid:"):
                out["ppid"] = int(line.split()[1])
            elif line.startswith("Uid:"):
                out["uid"] = int(line.split()[1])
    return out


def op_publishers(req):
    marker = req["marker"]
    found = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open("/proc/%d/cmdline" % pid, "rb") as fh:
                argv = [a.decode("utf-8", "replace") for a in fh.read().split(b"\0") if a]
        except OSError:
            continue
        if not argv or not any(marker in arg for arg in argv):
            continue
        try:
            info = op_process({"pid": pid})
            status = _status_of(pid)
        except OSError:
            continue  # exited between listdir and the read; not a publisher we can probe
        info["unit"] = _unit_of(pid)
        info["ppid"] = status["ppid"]
        try:
            info["user"] = pwd.getpwuid(status["uid"]).pw_name
        except KeyError:
            info["user"] = str(status["uid"])
        found[pid] = info
    # `uvicorn --workers N` re-execs the same argv in each child. The parent is
    # the process that owns the listening socket and runs the refresh thread, so
    # a candidate whose parent is also a candidate is a worker, not a publisher.
    return {"publishers": [info for pid, info in sorted(found.items())
                           if info["ppid"] not in found]}


def op_pyprobe(req):
    proc = op_process(req)
    env = {k: v for k, v in proc["environ"].items() if k in req.get("env_keys", [])}
    env.update(req.get("env", {}))
    interpreter = req.get("interpreter") or proc["argv"][0]
    argv = []
    user = req.get("user") or ""
    if user and user != "root":
        argv += ["sudo", "-n", "-u", user]
    argv += ["env", "-i"] + ["%s=%s" % kv for kv in sorted(env.items())]
    argv += [interpreter, "-c", req["program"]]
    res = subprocess.run(
        argv, cwd=proc["cwd"], capture_output=True, text=True,
        timeout=float(req.get("timeout", 120)),
    )
    return {
        "rc": res.returncode,
        "stdout": res.stdout,
        "stderr": res.stderr[-4000:],
        "interpreter": interpreter,
        "cwd": proc["cwd"],
    }


def op_tail(req):
    path = req["path"]
    limit = int(req.get("max_bytes", 262144))
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        if size > limit:
            fh.seek(size - limit)
        data = fh.read()
    return {"path": path, "size": size, "text": data.decode("utf-8", "replace")}


def op_state(req):
    with open(req["path"]) as fh:
        doc = json.load(fh)
    identity = doc.get("thin_submission_identity") or {}
    if not isinstance(identity, dict):
        identity = {}
    # Deliberately narrow: the state file embeds whole signed vectors, and this
    # preflight needs four scalars from it.
    return {
        "validator_hotkey": identity.get("validator_hotkey"),
        "validator_uid": identity.get("validator_uid"),
        "network": identity.get("network"),
        "netuid": identity.get("netuid"),
        "block_number": doc.get("thin_submission_block_number"),
        "finalized_at": doc.get("thin_submission_finalized_at"),
    }


OPS = {"unit": op_unit, "process": op_process, "pyprobe": op_pyprobe,
       "tail": op_tail, "state": op_state, "publishers": op_publishers}
request = json.loads(sys.argv[1])
try:
    print(json.dumps({"ok": True, "result": OPS[request["op"]](request)}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}))
'''


@dataclass
class ProcessFacts:
    pid: int
    unit: str
    user: str
    argv: list[str]
    cwd: str
    exe: str
    environ: dict[str, str]
    start_epoch: float
    host_now: float

    @property
    def interpreter(self) -> str:
        """The interpreter this process is REALLY running.

        ``/proc/<pid>/exe`` resolves through the venv symlink to the base binary
        (``/usr/bin/python3.12``), which would import from the system
        site-packages instead of the service's virtualenv -- a probe run that
        way proves nothing about what the service can import. argv[0] is the
        path the service was launched with and keeps the venv.
        """
        if self.argv and "python" in self.argv[0].rsplit("/", 1)[-1]:
            return self.argv[0]
        venv = self.environ.get("VIRTUAL_ENV")
        if venv:
            return f"{venv}/bin/python"
        return self.exe


def process_facts(entry: dict[str, Any]) -> ProcessFacts:
    """Build ProcessFacts from one enumerated /proc record."""
    return ProcessFacts(
        pid=int(entry.get("pid") or 0),
        unit=str(entry.get("unit") or ""),
        user=str(entry.get("user") or "root"),
        argv=list(entry.get("argv") or []),
        cwd=str(entry.get("cwd") or ""),
        exe=str(entry.get("exe") or ""),
        environ=dict(entry.get("environ") or {}),
        start_epoch=float(entry.get("start_epoch") or 0.0),
        host_now=float(entry.get("now") or 0.0),
    )


class Host:
    """A read-only view of the machine the services run on."""

    def unit(self, unit: str) -> dict[str, Any]:
        raise NotImplementedError

    def process(self, pid: int) -> dict[str, Any]:
        raise NotImplementedError

    def publishers(self, marker: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def pyprobe(
        self,
        proc: ProcessFacts,
        program: str,
        *,
        env_keys: tuple[str, ...] = (),
        env: dict[str, str] | None = None,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def tail(self, path: str, *, max_bytes: int = 262144) -> dict[str, Any]:
        raise NotImplementedError

    def state(self, path: str) -> dict[str, Any]:
        raise NotImplementedError

    def now(self) -> float:
        return time.time()

    # -- shared, backend-independent ------------------------------------

    def service_process(self, unit: str) -> ProcessFacts:
        info = self.unit(unit)
        if (info.get("ActiveState") or "") != "active":
            raise ProbeError(
                f"{unit} is {info.get('ActiveState') or 'unknown'}, not active"
            )
        try:
            pid = int(info.get("MainPID") or 0)
        except (TypeError, ValueError):
            pid = 0
        if pid <= 0:
            raise ProbeError(f"{unit} reports no MainPID")
        proc = self.process(pid)
        return ProcessFacts(
            pid=pid,
            unit=unit,
            user=info.get("User") or "root",
            argv=list(proc.get("argv") or []),
            cwd=str(proc.get("cwd") or ""),
            exe=str(proc.get("exe") or ""),
            environ=dict(proc.get("environ") or {}),
            start_epoch=float(proc.get("start_epoch") or 0.0),
            host_now=float(proc.get("now") or 0.0),
        )

    def pyprobe_json(self, proc: ProcessFacts, program: str, **kwargs) -> dict[str, Any]:
        """Run *program* the way *proc* would run it and parse its JSON stdout."""
        result = self.pyprobe(proc, program, **kwargs)
        stdout = (result.get("stdout") or "").strip()
        if result.get("rc") != 0 or not stdout:
            detail = (result.get("stderr") or "").strip().splitlines()
            tail = detail[-1] if detail else "no output"
            raise ProbeError(
                f"probe in {proc.unit} exited {result.get('rc')}: {tail}"
            )
        try:
            return json.loads(stdout.splitlines()[-1])
        except ValueError as exc:
            raise ProbeError(f"probe in {proc.unit} did not return JSON: {exc}") from exc


class CommandHost(Host):
    """A ``Host`` backed by one command runner (local shell or gcloud SSH)."""

    def __init__(self, runner: Callable[[str, float], tuple[int, str, str]]):
        self._runner = runner

    def _call(self, request: dict[str, Any], timeout: float) -> dict[str, Any]:
        command = "sudo -n python3 -c {} {}".format(
            shlex.quote(REMOTE_HELPER), shlex.quote(json.dumps(request))
        )
        code, out, err = self._runner(command, timeout)
        line = ""
        for candidate in reversed(out.strip().splitlines()):
            if candidate.startswith("{"):
                line = candidate
                break
        if not line:
            detail = (err or out).strip().splitlines()
            raise ProbeError(
                "remote probe produced no JSON (exit {}): {}".format(
                    code, detail[-1] if detail else "no output"
                )
            )
        try:
            payload = json.loads(line)
        except ValueError as exc:
            raise ProbeError(f"remote probe returned malformed JSON: {exc}") from exc
        if not payload.get("ok"):
            raise ProbeError(str(payload.get("error") or "unknown probe error"))
        return payload["result"]

    def unit(self, unit: str) -> dict[str, Any]:
        return self._call({"op": "unit", "unit": unit}, 60.0)

    def process(self, pid: int) -> dict[str, Any]:
        return self._call({"op": "process", "pid": pid}, 60.0)

    def publishers(self, marker: str) -> list[dict[str, Any]]:
        result = self._call({"op": "publishers", "marker": marker}, 90.0)
        return list(result.get("publishers") or [])

    def pyprobe(
        self,
        proc: ProcessFacts,
        program: str,
        *,
        env_keys: tuple[str, ...] = (),
        env: dict[str, str] | None = None,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        return self._call(
            {
                "op": "pyprobe",
                "pid": proc.pid,
                "user": proc.user,
                "program": program,
                "env_keys": list(env_keys),
                "env": dict(env or {}),
                "timeout": timeout,
            },
            timeout + 30.0,
        )

    def tail(self, path: str, *, max_bytes: int = 262144) -> dict[str, Any]:
        return self._call({"op": "tail", "path": path, "max_bytes": max_bytes}, 60.0)

    def state(self, path: str) -> dict[str, Any]:
        return self._call({"op": "state", "path": path}, 60.0)


def local_runner(command: str, timeout: float) -> tuple[int, str, str]:
    res = subprocess.run(
        ["/bin/sh", "-c", command], capture_output=True, text=True, timeout=timeout
    )
    return res.returncode, res.stdout, res.stderr


def gcloud_runner(instance: str, zone: str) -> Callable[[str, float], tuple[int, str, str]]:
    def run(command: str, timeout: float) -> tuple[int, str, str]:
        argv = [
            "gcloud", "compute", "ssh", instance,
            "--zone", zone, "--tunnel-through-iap",
            "--command", command,
        ]
        res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 60)
        return res.returncode, res.stdout, res.stderr

    return run


# --------------------------------------------------------------------------
# Probe programs. Each runs inside a service's own interpreter/cwd/environment.
# --------------------------------------------------------------------------

# Asks ONE candidate publisher process, through its own interpreter, cwd and
# environment, the only question that distinguishes the real composer from a
# look-alike: which durable row do you write, and which cluster lock do you take
# to write it? Both answers come from the module the process actually imports,
# evaluated against the environment it actually runs under -- so a legacy tree
# whose weights.py has no _persisted_vector_id at all answers "attribute absent"
# (it writes the unscoped `latest` row nothing consumes), and a canary scoped to
# test/292 answers with test/292. Neither can be mistaken for finney/39.
#
# Like COMPOSER_PROBE it imports scaffold.publisher.weights and nothing that
# constructs a Store.
SCOPE_PROBE = r'''
import json, os, sys
out = {"cwd": os.getcwd(), "executable": sys.executable}
try:
    import scaffold.publisher.weights as weights
except Exception as exc:
    out["import_error"] = "%s: %s" % (type(exc).__name__, exc)
    print(json.dumps(out))
    raise SystemExit(0)
out["module_file"] = os.path.realpath(weights.__file__)
for label, attr in (("persisted_vector_id", "_persisted_vector_id"),
                    ("refresh_lock_name", "_refresh_lock_name")):
    fn = getattr(weights, attr, None)
    if fn is None:
        # A pre-scope tree. It writes one unscoped row for every subnet, so it
        # cannot be this subnet's composer no matter what its environment says.
        out[label] = None
        out[label + "_error"] = "%s is absent from this module" % attr
        continue
    try:
        out[label] = fn()
    except Exception as exc:
        out[label] = None
        out[label + "_error"] = "%s: %s" % (type(exc).__name__, exc)
out["legacy_vector_id"] = getattr(weights, "_LEGACY_PERSISTED_VECTOR_ID", None)
print(json.dumps(out))
'''

# Corroborates the identification above by WATCHING (never taking) the cluster
# advisory lock the composer holds while it rebuilds, and mapping the holder's
# Postgres client socket back to a local pid.
#
# It is a poll because the lock is held for a fraction of each refresh cycle, so
# a single sample almost always misses it. "Not observed in the window" is
# therefore neutral -- it is a sighting or nothing. A sighting that maps to a
# DIFFERENT candidate is the one outcome that is fatal: it means the durable row
# is being written by a process other than the one selected, and every
# publisher-side verdict below would be about the wrong process.
LOCK_OBSERVE_PROBE = r'''
import glob, hashlib, json, os, time

out = {"observed": False, "lock_name": os.environ["LOCK_NAME"]}
key = int.from_bytes(
    hashlib.sha256(out["lock_name"].encode("utf-8")).digest()[:8], "big"
) & ((1 << 63) - 1)
# Postgres splits a bigint advisory key across (classid, objid) with objsubid=1.
out["classid"] = key >> 32
out["objid"] = key & 0xFFFFFFFF
budget = float(os.environ.get("BUDGET_SECS") or "0")
candidates = [int(p) for p in json.loads(os.environ.get("CANDIDATE_PIDS") or "[]")]
dsn = os.environ.get("DATABASE_URL") or ""
if not (dsn.startswith("postgres://") or dsn.startswith("postgresql://")):
    out["skipped"] = "the composer is not configured against postgres, so there is no cluster advisory lock to observe"
    print(json.dumps(out))
    raise SystemExit(0)
if budget <= 0:
    out["skipped"] = "lock observation disabled (--observe-lock-secs 0)"
    print(json.dumps(out))
    raise SystemExit(0)


def _hex_v4(text):
    parts = text.split(".")
    if len(parts) != 4:
        return None
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    return "".join("%02X" % o for o in reversed(octets))


def _inode(addr_hex, port):
    """The socket inode of the holder's client connection, from /proc/net/tcp."""
    want = "%s:%04X" % (addr_hex, port)
    try:
        handle = open("/proc/net/tcp")
    except OSError:
        return None
    with handle:
        next(handle, None)
        for line in handle:
            fields = line.split()
            if len(fields) > 9 and fields[1] == want:
                return fields[9]
    return None


def _owner(inode, pids):
    """Which enumerated candidate holds that socket. Only its own user's
    processes are readable here, so an unreadable candidate yields None rather
    than a wrong answer."""
    target = "socket:[%s]" % inode
    for pid in pids:
        for fd in glob.glob("/proc/%d/fd/*" % pid):
            try:
                if os.readlink(fd) == target:
                    return pid
            except OSError:
                continue
    return None


try:
    import psycopg2
    conn = psycopg2.connect(dsn, options="-c default_transaction_read_only=on")
    conn.set_session(autocommit=True)
    cur = conn.cursor()
    deadline = time.time() + budget
    polls = 0
    while time.time() < deadline:
        cur.execute(
            "SELECT host(a.client_addr), a.client_port FROM pg_locks l "
            "JOIN pg_stat_activity a ON a.pid = l.pid "
            "WHERE l.locktype = 'advisory' AND l.classid = %s AND l.objid = %s "
            "AND l.objsubid = 1 AND l.granted",
            (out["classid"], out["objid"]),
        )
        rows = cur.fetchall()
        polls += 1
        if rows:
            out["observed"] = True
            addr, port = rows[0][0], int(rows[0][1] or 0)
            out["client"] = "%s:%s" % (addr, port)
            addr_hex = _hex_v4(str(addr or ""))
            if addr_hex is None or port <= 0:
                out["unmapped_reason"] = "the holder is not connected over IPv4 TCP"
            else:
                inode = _inode(addr_hex, port)
                if inode is None:
                    out["unmapped_reason"] = "the holder's client socket is already gone"
                else:
                    out["holder_pid"] = _owner(inode, candidates)
                    if out["holder_pid"] is None:
                        out["unmapped_reason"] = (
                            "the holder's socket belongs to no enumerated publisher "
                            "readable by this user"
                        )
            break
        time.sleep(0.05)
    out["polls"] = polls
    out["budget_secs"] = budget
except Exception as exc:
    # psycopg2 puts connection details in its messages; the DSN carries a
    # password and this output is printed verbatim into the report.
    out["error"] = ("%s: %s" % (type(exc).__name__, exc)).replace(dsn, "<postgres dsn>")
print(json.dumps(out))
'''

# Imports scaffold.publisher.weights and NOTHING that constructs a Store. See
# the module docstring: importing scaffold.publisher.server would migrate the
# live database as a side effect of a read-only preflight.
COMPOSER_PROBE = r'''
import hashlib, json, os, sys
out = {"executable": sys.executable, "prefix": sys.prefix,
       "exe_real": os.path.realpath(sys.executable), "cwd": os.getcwd()}
try:
    import scaffold.publisher.weights as weights
except Exception as exc:
    out["import_error"] = "%s: %s" % (type(exc).__name__, exc)
    print(json.dumps(out))
    raise SystemExit(0)
out["module_file"] = os.path.realpath(weights.__file__)
out["present"] = hasattr(weights, "_compose_cybergym_lane_v3")
# co_names of the LOADED code object, not a grep of the file: this is the call
# the imported build_signed_vector actually makes.
out["wired"] = "_compose_cybergym_lane_v3" in set(
    weights.build_signed_vector.__code__.co_names
)
out["v3_allocation"] = getattr(weights, "V3_CYBERGYM_ALLOCATION", None)
try:
    stat = os.stat(out["module_file"])
    out["module_mtime"] = stat.st_mtime
    out["module_sha256"] = hashlib.sha256(
        open(out["module_file"], "rb").read()
    ).hexdigest()
except OSError as exc:
    out["stat_error"] = str(exc)
print(json.dumps(out))
'''

# Opens the SAME database the publisher process is configured against, using the
# same precedence Store.__init__ applies (a postgres DATABASE_URL wins over
# CATHEDRAL_DB_PATH), and refuses to be able to write.
DATABASE_PROBE = r'''
import json, os, sys

out = {}
dsn = os.environ.get("DATABASE_URL") or ""
path = os.environ.get("CATHEDRAL_DB_PATH") or ""
is_pg = dsn.startswith("postgres://") or dsn.startswith("postgresql://")
out["backend"] = "postgres" if is_pg else "sqlite"
out["target"] = "<postgres dsn>" if is_pg else path

QUERIES = json.loads(os.environ["QUERIES"])


def run(cursor, sql, params=()):
    cursor.execute(sql, params)
    return cursor.fetchall()


try:
    if is_pg:
        import psycopg2
        conn = psycopg2.connect(dsn, options="-c default_transaction_read_only=on")
        cur = conn.cursor()
        placeholder = "%s"

        def exists(name):
            row = run(cur, "SELECT to_regclass(%s)::text", ("public." + name,))
            return row[0][0] is not None
    else:
        import sqlite3
        if not path:
            raise RuntimeError("neither DATABASE_URL nor CATHEDRAL_DB_PATH is set")
        conn = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        cur = conn.cursor()
        placeholder = "?"

        def exists(name):
            return bool(run(
                cur,
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (name,),
            ))
    out["migrations"] = [row[0] for row in run(cur, "SELECT id FROM schema_migrations")]
    out["tables"] = {
        name: exists(name)
        for name in (
            "cybergym_score_reports",
            "cybergym_scores",
            "cybergym_epoch_status",
            "metagraph_hotkeys",
        )
    }
    out["rows"] = {}
    for name, spec in QUERIES.items():
        if spec.get("requires") and not out["tables"].get(spec["requires"]):
            continue
        sql = spec["sql"].replace("?", placeholder)
        out["rows"][name] = [list(row) for row in run(cur, sql, tuple(spec.get("params", ())))]
except Exception as exc:
    out["error"] = "%s: %s" % (type(exc).__name__, exc)
print(json.dumps(out))
'''

# Asks the validator's own code, against the validator's own live config, the
# exact question a re-pin asks: would this validator start pinned to v3?
TRUST_PROFILE_PROBE = r'''
import argparse, json, os, sys
out = {"executable": sys.executable}
from scaffold import cli
from scaffold import validator_thin as vt
out["module_file"] = os.path.realpath(vt.__file__)
try:
    out["module_mtime"] = os.stat(out["module_file"]).st_mtime
except OSError as exc:
    out["stat_error"] = str(exc)
pinned = list(getattr(vt, "SN39_PINNED_REQUIRE_POLICIES", ()))
v3 = getattr(vt, "REQUIRE_POLICY_VALIDATED_SUPPLY_V3", "validated_supply_v3")
out["pinned_policies"] = pinned
out["admits_v3"] = v3 in pinned
config = os.environ.get("VALIDATOR_CONFIG") or ""
if config:
    try:
        ns = argparse.Namespace(config=config, dry_run=False, once=False, broadcast=True)
        cfg = cli._resolve_serve_config(ns)
        out["configured_require_policy"] = getattr(cfg, "require_policy", None)
        mode = (getattr(cfg, "provenance", "shadow") or "shadow").strip().lower()
        if mode != "shadow":
            raise RuntimeError("recurring validator config must use shadow relay mode")
        cfg.provenance = "shadow"
        out["provenance_mode"] = cfg.provenance
        # The re-pin, evaluated without performing it: same config, v3 pin.
        cfg.require_policy = v3
        vt._validate_runtime_contract(cfg)
        out["v3_startup_ok"] = True
    except Exception as exc:
        out["v3_startup_ok"] = False
        out["v3_startup_error"] = "%s: %s" % (type(exc).__name__, exc)
print(json.dumps(out))
'''

# One finalized-head sample of the two numbers the write schedule turns on,
# through the validator's own chain helpers.
CHAIN_PROBE = r'''
import json, os
out = {}
from scaffold import validator_thin as vt
from scaffold.chain import connection_target
network = os.environ["NETWORK"]
netuid = int(os.environ["NETUID"])
uid = int(os.environ["VALIDATOR_UID"])
with vt._isolated_argv():
    import bittensor as bt
    subtensor = vt._bt_subtensor(bt)(network=connection_target(network))
    block = int(subtensor.get_current_block())
    out["block"] = block
    out["weights_rate_limit"] = int(subtensor.weights_rate_limit(netuid, block=block))
    out["blocks_since_last_update"] = int(
        subtensor.blocks_since_last_update(netuid, uid, block=block)
    )
print(json.dumps(out))
'''


# --------------------------------------------------------------------------
# The checks. Each is a pure function of already-gathered facts, so a unit test
# drives any verdict by handing it a different Facts object.
# --------------------------------------------------------------------------


@dataclass
class ComposerResolution:
    """Which running process is this subnet's weight composer, and how we know.

    ``process`` is set whenever a candidate was selected -- including when the
    selection was later contradicted -- so the report can always name what it
    looked at. ``confirmed`` is the only thing the checks may act on.
    """

    expected_vector_id: str = ""
    expected_lock_name: str = ""
    method: str = ""
    process: ProcessFacts | None = None
    scope: dict[str, Any] = field(default_factory=dict)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    lock: dict[str, Any] = field(default_factory=dict)
    enumeration_error: str = ""
    error: str = ""

    @property
    def confirmed(self) -> bool:
        return self.process is not None and not self.error


@dataclass
class Facts:
    """Everything the checks are allowed to see."""

    composer_id: ComposerResolution = field(default_factory=ComposerResolution)
    publisher: ProcessFacts | None = None
    publisher_error: str = ""
    composer: dict[str, Any] = field(default_factory=dict)
    composer_error: str = ""
    database: dict[str, Any] = field(default_factory=dict)
    database_error: str = ""
    validator: ProcessFacts | None = None
    validator_error: str = ""
    trust: dict[str, Any] = field(default_factory=dict)
    trust_error: str = ""
    status_events: list[dict[str, Any]] = field(default_factory=list)
    status_error: str = ""
    state: dict[str, Any] = field(default_factory=dict)
    state_error: str = ""
    chain: dict[str, Any] = field(default_factory=dict)
    chain_error: str = ""
    now: float = 0.0
    max_weights_age_secs: float = DEFAULT_MAX_WEIGHTS_AGE_SECS
    max_cooldown_multiple: float = DEFAULT_MAX_COOLDOWN_MULTIPLE


def check_composer_identity(facts: Facts) -> CheckResult:
    """#0 -- is the process every check below is about actually the composer?

    This check exists because the preflight once resolved the publisher by a
    unit-name default, landed on a legacy process that writes its own unscoped
    ``latest`` row, and reported that decoy's state as fact: it declared the v3
    composer absent and the producer hotkey unset when the real composer had
    both. A wrong answer delivered confidently is worse than no answer, so the
    identification is proven here and every publisher-side check is blocked when
    it cannot be.
    """
    title = "the probed publisher IS this subnet's weight composer"
    ident = facts.composer_id
    evidence: dict[str, Any] = {
        "expected_persisted_vector_id": ident.expected_vector_id,
        "expected_refresh_lock_name": ident.expected_lock_name,
        "method": ident.method,
        "candidates": ident.candidates,
    }
    if ident.enumeration_error:
        evidence["enumeration_error"] = ident.enumeration_error
    if ident.lock:
        evidence["advisory_lock"] = ident.lock
    if ident.process is not None:
        proc = ident.process
        evidence["selected"] = {
            "unit": proc.unit or "(no unit)",
            "pid": proc.pid,
            "user": proc.user,
            "cwd": proc.cwd,
            "interpreter": proc.interpreter,
            "started_at": _iso(proc.start_epoch),
            "module_file": ident.scope.get("module_file"),
            "persisted_vector_id": ident.scope.get("persisted_vector_id"),
            "refresh_lock_name": ident.scope.get("refresh_lock_name"),
        }
    # No selection and no recorded reason means the resolution never ran. That
    # is still "we cannot tell which process this report is about", which is a
    # FAIL -- the one verdict this check must never soften.
    error = ident.error or (
        "" if ident.process is not None
        else "the composer was never resolved, so no publisher-side fact below "
             "can be attributed to a process"
    )
    if error:
        return CheckResult(
            "composer_identity", title, FAIL, error,
            "do NOT read the publisher-side verdicts below as facts about the "
            "composer -- they are blocked precisely because the process they "
            f"would describe is unproven. Confirm which process writes the "
            f"{ident.expected_vector_id} row (it is the one holding "
            f"{ident.expected_lock_name} during a rebuild), then re-run. If this "
            "box genuinely runs no composer for this subnet, there is nothing to "
            "flip.",
            evidence,
        )
    return CheckResult(
        "composer_identity", title, PASS,
        f"{evidence['selected']['unit']} (pid {ident.process.pid}, cwd "
        f"{ident.process.cwd}) composes {ident.expected_vector_id}; "
        f"{_lock_phrase(ident)}",
        evidence=evidence,
    )


def _lock_phrase(ident: ComposerResolution) -> str:
    """One clause describing what the advisory-lock observation added."""
    lock = ident.lock or {}
    if lock.get("error"):
        return f"the advisory-lock observation did not run ({lock['error']})"
    if lock.get("skipped"):
        return f"the advisory-lock observation was skipped ({lock['skipped']})"
    if not lock.get("observed"):
        return (
            f"{ident.expected_lock_name} was not seen held during the "
            f"{lock.get('budget_secs', 0)}s window (it is only held while a "
            "rebuild runs, so this neither confirms nor contradicts)"
        )
    if lock.get("holder_pid") is not None:
        return f"and it was seen holding {ident.expected_lock_name}"
    return (
        f"{ident.expected_lock_name} was seen held but not attributable to a pid "
        f"({lock.get('unmapped_reason') or 'unmapped'})"
    )


def check_composer_reachable(facts: Facts) -> CheckResult:
    """#1 -- can the RUNNING publisher process reach the v3 composer?"""
    title = "the running publisher can reach _compose_cybergym_lane_v3"
    if facts.publisher is None:
        # Never fall back to "probe whatever publisher-ish process we can find
        # and report its state". That silent substitution is the bug this check
        # pair exists to prevent.
        return CheckResult(
            "composer_reachable", title, BLOCKED,
            "composer_identity could not prove which process composes "
            f"{facts.composer_id.expected_vector_id}, so there is no process "
            "whose reachability could be reported as the composer's: "
            f"{facts.publisher_error}",
            "fix composer_identity first. Confirm the publisher runs as root-"
            "readable /proc (run this on the box with sudo, or pass "
            "--gcloud-instance), and that one process claims this subnet's scope.",
        )
    proc = facts.publisher
    evidence = {
        "pid": proc.pid,
        "interpreter": proc.interpreter,
        "cwd": proc.cwd,
        "started_at": _iso(proc.start_epoch),
        # Reported, never asserted: this preflight runs BEFORE the flip, so v2
        # here is the expected value. It is in the record so the operator can
        # see which contract the process is currently composing under.
        ALLOCATION_CONTRACT_ENV: proc.environ.get(ALLOCATION_CONTRACT_ENV, "v2"),
    }
    if facts.composer_error:
        return CheckResult(
            "composer_reachable", title, FAIL,
            f"the import probe did not run: {facts.composer_error}",
            "run the probe by hand in the publisher's environment: "
            f"cd {proc.cwd} && {proc.interpreter} -c "
            "'import scaffold.publisher.weights as w; print(w.__file__)'",
            evidence,
        )
    probe = facts.composer
    evidence.update(
        {
            "module_file": probe.get("module_file"),
            "module_sha256": probe.get("module_sha256"),
            "present": probe.get("present"),
            "wired": probe.get("wired"),
        }
    )
    if probe.get("import_error"):
        return CheckResult(
            "composer_reachable", title, FAIL,
            "the publisher's own interpreter cannot import "
            f"scaffold.publisher.weights: {probe['import_error']}",
            "the deployed tree is broken or incomplete; reinstall it before any "
            "flip. The publisher would fail to compose ANY vector, v2 or v3.",
            evidence,
        )
    if not probe.get("present"):
        return CheckResult(
            "composer_reachable", title, FAIL,
            "_compose_cybergym_lane_v3 is absent from the module this process "
            f"imports ({probe.get('module_file')})",
            "the deployed publisher predates the v3 composer. Deploy the reviewed "
            "revision that carries scaffold/publisher/weights.py "
            "_compose_cybergym_lane_v3 to that path, then restart the publisher "
            "IN the cutover window. Flipping CATHEDRAL_ALLOCATION_CONTRACT=v3 "
            "against this tree emits v2 forever and a v3-pinned validator "
            "rejects every vector.",
            evidence,
        )
    if not probe.get("wired"):
        return CheckResult(
            "composer_reachable", title, FAIL,
            "the composer exists but build_signed_vector does not call it",
            "the deployed tree is a partial cherry-pick: the function is present "
            "but nothing reaches it, so a v3 contract would sign a vector with no "
            "cybergym_lane. Deploy the full reviewed revision.",
            evidence,
        )
    allocation = probe.get("v3_allocation")
    if allocation is None or abs(float(allocation) - V3_CYBERGYM_ALLOCATION) > 1e-12:
        return CheckResult(
            "composer_reachable", title, FAIL,
            f"the imported module's V3_CYBERGYM_ALLOCATION is {allocation!r}, "
            f"not {V3_CYBERGYM_ALLOCATION}",
            "the deployed tree disagrees with the reviewed v3 contract; deploy the "
            "reviewed revision rather than editing the constant.",
            evidence,
        )
    # The probe ran in a NEW process. That proves the tree ON DISK is importable
    # and complete, but the long-lived publisher holds whatever it imported at
    # start: if the tree changed since, the running process still composes the
    # OLD code and no amount of on-disk correctness changes that.
    mtime = probe.get("module_mtime")
    if mtime is not None and float(mtime) > proc.start_epoch:
        evidence["module_mtime"] = _iso(float(mtime))
        return CheckResult(
            "composer_reachable", title, FAIL,
            "the module file was modified at "
            f"{_iso(float(mtime))}, after this process started at "
            f"{_iso(proc.start_epoch)} -- the RUNNING publisher still holds the "
            "pre-update module",
            f"restart {proc.unit} (a human, in the cutover window) and re-run this "
            "preflight; on-disk correctness is not reachability.",
            evidence,
        )
    return CheckResult(
        "composer_reachable", title, PASS,
        "the publisher's own interpreter imports the composer, "
        "build_signed_vector calls it, and the process is not older than the file",
        evidence=evidence,
    )


def check_db_migration(facts: Facts) -> CheckResult:
    """#2 -- is the publisher database at the cybergym migration?"""
    title = "the publisher database carries the cybergym tables"
    if facts.publisher is None:
        return CheckResult(
            "db_migration", title, BLOCKED,
            "composer_identity could not prove which process is the composer, so "
            "the database it is configured against is unknown",
            "fix composer_identity first.",
        )
    if facts.database_error:
        return CheckResult(
            "db_migration", title, FAIL,
            f"the database probe did not run: {facts.database_error}",
            "check that the publisher's DATABASE_URL / CATHEDRAL_DB_PATH is "
            "readable from the publisher's own environment. This preflight only "
            "ever opens it read-only.",
        )
    probe = facts.database
    if probe.get("error"):
        return CheckResult(
            "db_migration", title, FAIL,
            f"the database could not be read: {probe['error']}",
            "the publisher is configured against a database this preflight cannot "
            "open read-only; resolve that before the flip.",
            {"backend": probe.get("backend"), "target": probe.get("target")},
        )
    applied = set(probe.get("migrations") or [])
    tables = probe.get("tables") or {}
    missing = [name for name in CYBERGYM_MIGRATIONS if name not in applied]
    evidence = {
        "backend": probe.get("backend"),
        "applied_count": len(applied),
        "missing_migrations": missing,
        "tables": tables,
    }
    if missing:
        return CheckResult(
            "db_migration", title, FAIL,
            f"missing migration(s): {', '.join(missing)}",
            "the publisher applies migrations at Store construction, so this "
            "database is behind the deployed code OR the deployed code predates "
            "the migration. Deploy the revision carrying "
            f"{CYBERGYM_MIGRATIONS[0]} and restart the publisher in a maintenance "
            "window so it migrates on start. Do NOT hand-apply DDL to the live "
            "database.",
            evidence,
        )
    absent = [name for name in ("cybergym_score_reports", "cybergym_scores")
              if not tables.get(name)]
    if absent:
        return CheckResult(
            "db_migration", title, FAIL,
            f"the migration is recorded as applied but table(s) {', '.join(absent)} "
            "do not exist",
            "the schema_migrations row and the schema disagree; this database was "
            "restored or hand-edited. Reconcile it before the flip -- the intake "
            "will 500 and the lane will burn.",
            evidence,
        )
    return CheckResult(
        "db_migration", title, PASS,
        "both cybergym migrations are applied and the tables exist",
        evidence=evidence,
    )


def check_producer_identity(facts: Facts) -> CheckResult:
    """#3 -- is the configured producer a real key, or a Substrate dev key?

    The intake admits exactly ONE producer per audience and fences epochs by
    audience, not by producer (scaffold/publisher/cybergym_ingest.py). So a
    single accepted epoch under a dev key permanently raises the floor for that
    audience: rotating to the real key does not reset the counter, and the real
    producer's next post is refused as ``epoch_too_old`` until it climbs above
    whatever the dev key posted. That is why this check refuses the dev key
    BEFORE the flip, and why it also looks for evidence that one was already
    admitted.
    """
    title = "the configured CyberGym producer is not a development key"
    if facts.publisher is None:
        return CheckResult(
            "producer_identity", title, BLOCKED,
            "composer_identity could not prove which process is the composer, so "
            "the configured producer identity read here would be some other "
            "process's",
            "fix composer_identity first. A producer hotkey read off a decoy is "
            "the exact wrong answer this preflight used to give.",
        )
    configured = (facts.publisher.environ.get(PRODUCER_HOTKEY_ENV) or "").strip()
    evidence = {"env": PRODUCER_HOTKEY_ENV, "configured": configured or None}
    if not configured:
        return CheckResult(
            "producer_identity", title, FAIL,
            f"{PRODUCER_HOTKEY_ENV} is unset in the running publisher's environment",
            f"set {PRODUCER_HOTKEY_ENV} to the CyberGym producer's real ss58 hotkey "
            "and restart the publisher. Unset means the intake answers 503, no "
            "report is ever admitted, and the 30% lane burns in full.",
            evidence,
        )
    label = SUBSTRATE_DEV_KEYS.get(configured)
    if label:
        evidence["dev_key"] = label
        return CheckResult(
            "producer_identity", title, FAIL,
            f"the configured producer is the Substrate development key {label} "
            f"({configured})",
            f"set {PRODUCER_HOTKEY_ENV} to the producer's real hotkey and restart "
            "the publisher BEFORE any report is posted. The epoch fence is scoped "
            "to the audience, not the key: once an epoch is accepted under this "
            "key the floor is permanent and rotating the key cannot undo it.",
            evidence,
        )
    # A second, independent question: has one already been admitted? If the
    # tables do not exist yet, no report can have been stored, so the answer is
    # a proven no rather than an unknown.
    tables = (facts.database or {}).get("tables") or {}
    if facts.database_error or (facts.database or {}).get("error"):
        return CheckResult(
            "producer_identity", title, BLOCKED,
            "the configured identity is clean, but db_migration could not read the "
            "database, so an already-admitted dev-key epoch cannot be ruled out",
            "fix db_migration, then re-run: an accepted dev-key epoch is permanent "
            "and must be known about before the flip.",
            evidence,
        )
    if not tables.get("cybergym_score_reports"):
        evidence["stored_producers"] = []
        return CheckResult(
            "producer_identity", title, PASS,
            "the configured producer is not a development key, and no report can "
            "have been admitted yet (the cybergym tables do not exist)",
            evidence=evidence,
        )
    rows = ((facts.database or {}).get("rows") or {}).get("producers") or []
    stored = [(str(row[0]), int(row[1])) for row in rows]
    evidence["stored_producers"] = [
        {"producer_hotkey": hotkey, "max_source_epoch": epoch} for hotkey, epoch in stored
    ]
    poisoned = [(hotkey, epoch) for hotkey, epoch in stored if hotkey in SUBSTRATE_DEV_KEYS]
    if poisoned:
        hotkey, epoch = poisoned[0]
        return CheckResult(
            "producer_identity", title, FAIL,
            f"an epoch was already admitted under development key "
            f"{SUBSTRATE_DEV_KEYS[hotkey]} ({hotkey}), highest source_epoch {epoch}",
            "the audience-scoped epoch floor is already raised and rotating the key "
            "will not lower it. The real producer must post above "
            f"{epoch}, or the owner must decide to reset the fence in the database. "
            "Do not flip until the real producer's next post is proven acceptable.",
            evidence,
        )
    return CheckResult(
        "producer_identity", title, PASS,
        "the configured producer is a real key and no development key has ever "
        "been admitted for this audience",
        evidence=evidence,
    )


def check_trust_profile(facts: Facts) -> CheckResult:
    """#4 -- does the running validator's trust profile admit v3?"""
    title = "the validator's trust profile admits validated_supply_v3"
    if facts.validator is None:
        return CheckResult(
            "trust_profile", title, FAIL,
            f"the validator process could not be resolved: {facts.validator_error}",
            "confirm the validator unit is active and readable, or pass "
            "--validator-unit if this host runs a different one.",
        )
    proc = facts.validator
    evidence = {"pid": proc.pid, "interpreter": proc.interpreter,
                "started_at": _iso(proc.start_epoch)}
    if facts.trust_error:
        return CheckResult(
            "trust_profile", title, FAIL,
            f"the trust-profile probe did not run: {facts.trust_error}",
            "run it by hand in the validator's environment: "
            f"{proc.interpreter} -c 'from scaffold import validator_thin as vt; "
            "print(vt.SN39_PINNED_REQUIRE_POLICIES)'",
            evidence,
        )
    probe = facts.trust
    evidence.update(
        {
            "module_file": probe.get("module_file"),
            "pinned_policies": probe.get("pinned_policies"),
            "configured_require_policy": probe.get("configured_require_policy"),
            "provenance_mode": probe.get("provenance_mode"),
        }
    )
    if not probe.get("admits_v3"):
        return CheckResult(
            "trust_profile", title, FAIL,
            "SN39_PINNED_REQUIRE_POLICIES in the running validator's code does not "
            f"contain validated_supply_v3: {probe.get('pinned_policies')}",
            "this validator predates #74. Deploy the reviewed revision that widens "
            "the trust profile and restart it BEFORE re-pinning; a v3 pin against "
            "this code is refused at startup and the validator never writes.",
            evidence,
        )
    mtime = probe.get("module_mtime")
    if mtime is not None and float(mtime) > proc.start_epoch:
        evidence["module_mtime"] = _iso(float(mtime))
        return CheckResult(
            "trust_profile", title, FAIL,
            f"validator_thin.py was modified at {_iso(float(mtime))}, after the "
            f"validator started at {_iso(proc.start_epoch)} -- the RUNNING "
            "validator holds the pre-update module",
            f"restart {proc.unit} and re-run this preflight.",
            evidence,
        )
    if probe.get("v3_startup_ok") is False:
        return CheckResult(
            "trust_profile", title, FAIL,
            "the running validator's own startup contract refuses this host's "
            f"config under a v3 pin: {probe.get('v3_startup_error')}",
            "fix the named field in the validator config BEFORE re-pinning. A "
            "config that fails the trust profile means a validator that starts "
            "and never writes (or refuses to start at all).",
            evidence,
        )
    if probe.get("v3_startup_ok") is None:
        return CheckResult(
            "trust_profile", title, FAIL,
            "the trust profile admits v3, but this host's live config was not "
            "evaluated under a v3 pin",
            "pass --validator-config pointing at the config the unit actually "
            "loads, so the re-pin is proven against the file that will change.",
            evidence,
        )
    return CheckResult(
        "trust_profile", title, PASS,
        "the profile admits validated_supply_v3 and this host's live config "
        "passes the validator's own startup contract with the v3 pin applied",
        evidence=evidence,
    )


def check_fundable_lane(facts: Facts) -> CheckResult:
    """#5 -- could the v3 lane actually fund anybody?

    An empty corpus is not a neutral outcome. Under v3 the whole 30% CyberGym
    lane forfeits to burn, so flipping into an empty lane burns three times what
    v2 burns. Being ready to flip means somebody would actually be paid.
    """
    title = "the CyberGym lane could fund at least one admitted task"
    if facts.publisher is None:
        return CheckResult(
            "fundable_lane", title, BLOCKED,
            "composer_identity could not prove which process is the composer",
            "fix composer_identity first.",
        )
    env = facts.publisher.environ
    enabled = (env.get(MECHANISM_ENABLED_ENV) or "").strip().lower() in {
        "1", "true", "yes", "on"
    }
    raw_fraction = (env.get(WEIGHT_FRACTION_ENV) or "").strip()
    evidence = {
        MECHANISM_ENABLED_ENV: env.get(MECHANISM_ENABLED_ENV),
        WEIGHT_FRACTION_ENV: env.get(WEIGHT_FRACTION_ENV),
        "audience": [
            env.get(NETWORK_ENV) or DEFAULT_NETWORK,
            env.get(NETUID_ENV) or str(DEFAULT_NETUID),
        ],
    }
    if not enabled:
        return CheckResult(
            "fundable_lane", title, FAIL,
            f"{MECHANISM_ENABLED_ENV} is not enabled in the running publisher",
            f"set {MECHANISM_ENABLED_ENV}=1 and restart the publisher. Without it "
            "_compose_cybergym_lane_v3 raises and the ENTIRE v3 vector refuses to "
            "sign -- the publisher stops emitting altogether.",
            evidence,
        )
    try:
        fraction = float(raw_fraction) if raw_fraction else None
    except ValueError:
        fraction = None
    if fraction is None or abs(fraction - V3_CYBERGYM_ALLOCATION) > 1e-12:
        return CheckResult(
            "fundable_lane", title, FAIL,
            f"{WEIGHT_FRACTION_ENV} is {raw_fraction or 'unset'}, not "
            f"{V3_CYBERGYM_ALLOCATION}",
            f"set {WEIGHT_FRACTION_ENV}={V3_CYBERGYM_ALLOCATION} and restart the "
            "publisher; the composer refuses any other fraction and the whole v3 "
            "vector refuses to sign.",
            evidence,
        )
    if not env.get(NETWORK_ENV) or not env.get(NETUID_ENV):
        return CheckResult(
            "fundable_lane", title, FAIL,
            f"{NETWORK_ENV}/{NETUID_ENV} are not both set, so the intake cannot "
            "resolve its audience",
            f"set {NETWORK_ENV}={DEFAULT_NETWORK} and {NETUID_ENV}={DEFAULT_NETUID} "
            "and restart the publisher. cybergym_ingest.configured_audience() "
            "fails closed, so the intake answers 503 and no task can ever be "
            "admitted -- the composing side would silently read finney/39 defaults.",
            evidence,
        )
    if facts.database_error or (facts.database or {}).get("error"):
        return CheckResult(
            "fundable_lane", title, BLOCKED,
            "db_migration could not read the publisher database, so admitted tasks "
            "cannot be counted",
            "fix db_migration first.",
            evidence,
        )
    tables = (facts.database or {}).get("tables") or {}
    if not tables.get("cybergym_scores"):
        return CheckResult(
            "fundable_lane", title, BLOCKED,
            "the cybergym tables do not exist, so no admitted task can exist yet",
            "fix db_migration first, then wait for the producer to post a complete "
            "report before flipping.",
            evidence,
        )
    rows = ((facts.database or {}).get("rows") or {})
    reports = rows.get("latest_report") or []
    if not reports:
        return CheckResult(
            "fundable_lane", title, FAIL,
            "no complete CyberGym report has ever been admitted for this audience",
            "have the producer post a complete report to POST /v1/cybergym/scores "
            "and confirm it lands, BEFORE the flip. Flipping now forfeits the whole "
            f"{V3_CYBERGYM_ALLOCATION:.0%} lane to burn -- worse than v2's 10%.",
            evidence,
        )
    report_id, source_epoch, generated_at, score_count = (
        str(reports[0][0]), int(reports[0][1]), str(reports[0][2]), int(reports[0][3])
    )
    evidence.update(
        {
            "report_id": report_id,
            "source_epoch": source_epoch,
            "generated_at": generated_at,
            "score_count": score_count,
        }
    )
    max_age = _float_env(env.get(MAX_SCORE_AGE_SECS_ENV), DEFAULT_MAX_SCORE_AGE_SECS)
    age = _age_secs(generated_at, facts.now)
    evidence["age_secs"] = None if age is None else round(age, 1)
    evidence["max_score_age_secs"] = max_age
    epoch_states = {int(row[0]): str(row[1]) for row in (rows.get("epoch_state") or [])}
    state = epoch_states.get(source_epoch)
    if state is not None and state != "closed":
        evidence["epoch_state"] = state
        return CheckResult(
            "fundable_lane", title, FAIL,
            f"the newest report's epoch {source_epoch} is marked {state!r}, not closed",
            "wait for the producer to close the epoch. The adapter raises on a "
            "non-closed marker, which skips the mechanism rather than funding it.",
            evidence,
        )
    if age is not None and age > max_age:
        return CheckResult(
            "fundable_lane", title, FAIL,
            f"the newest admitted report is {age / 60:.0f} min old, past the "
            f"adapter's {max_age / 60:.0f} min freshness ceiling",
            "the producer has stopped posting (or its clock is wrong): a stale "
            "report is refused at compose time and the whole lane burns. Restore "
            "the producer, confirm a fresh report lands, then flip.",
            evidence,
        )
    scored = rows.get("scored_uids") or []
    positive = [(str(row[0]), float(row[1]), row[2]) for row in scored]
    mapped = [entry for entry in positive if entry[2] is not None]
    evidence["positive_scores"] = len(positive)
    evidence["positive_scores_with_uid"] = len(mapped)
    if not positive:
        return CheckResult(
            "fundable_lane", title, FAIL,
            f"the newest admitted report ({report_id}, epoch {source_epoch}) scores "
            "nobody above zero",
            "an empty report is a legal 'nobody solved this epoch', and under v3 it "
            "burns the full 30%. Do not flip until at least one miner is scored: "
            "confirm the corpus is admitting tasks and the verifier is crediting "
            "solves.",
            evidence,
        )
    if not mapped:
        return CheckResult(
            "fundable_lane", title, FAIL,
            f"{len(positive)} scored miner(s) exist, but none maps to a UID in the "
            "metagraph_hotkeys snapshot for this audience",
            "the scored hotkeys are unregistered or the snapshot is stale. The "
            "adapter drops unmapped hotkeys, so the lane would contribute nothing "
            "and burn. Refresh the snapshot and confirm the scored miners are "
            "registered on this subnet.",
            evidence,
        )
    return CheckResult(
        "fundable_lane", title, PASS,
        f"{len(mapped)} scored miner(s) in a fresh complete report (epoch "
        f"{source_epoch}) map to UIDs, so the lane funds real work",
        evidence=evidence,
    )


def check_validator_writing(facts: Facts) -> CheckResult:
    """#6 -- is the validator healthy and writing right now?"""
    title = "the validator is healthy and writing weights"
    evidence: dict[str, Any] = {}
    if facts.status_error:
        return CheckResult(
            "validator_writing", title, FAIL,
            f"the validator status log could not be read: {facts.status_error}",
            "pass --status-log with the path this host's validator writes "
            "(config [logs].status_jsonl), and make sure it is readable.",
        )
    submissions = [
        event for event in facts.status_events
        if event.get("event") == "WEIGHTS_SUBMITTED" and event.get("status") == "PASS"
    ]
    if not submissions:
        return CheckResult(
            "validator_writing", title, FAIL,
            "no successful WEIGHTS_SUBMITTED event in the tail of the status log",
            "the validator is not writing. Diagnose that FIRST -- re-pinning a mute "
            "validator turns an existing outage into a v3 mystery. Look for "
            "TICK_FAILED / VECTOR_REJECTED in the same log.",
            {"events_scanned": len(facts.status_events)},
        )
    last = submissions[-1]
    age = _age_secs(str(last.get("ts") or ""), facts.now)
    evidence["last_weights_submitted"] = last.get("ts")
    evidence["age_secs"] = None if age is None else round(age, 1)
    evidence["max_age_secs"] = facts.max_weights_age_secs
    if age is None:
        return CheckResult(
            "validator_writing", title, FAIL,
            f"the last WEIGHTS_SUBMITTED carries an unparseable timestamp "
            f"{last.get('ts')!r}",
            "inspect the status log; a malformed timestamp means the freshness of "
            "the write cannot be established.",
            evidence,
        )
    if age > facts.max_weights_age_secs:
        return CheckResult(
            "validator_writing", title, FAIL,
            f"the last successful weight write was {age / 60:.0f} min ago, over the "
            f"{facts.max_weights_age_secs / 60:.0f} min ceiling",
            "the validator has gone quiet. Fix that before the flip; a v3 re-pin on "
            "top of an existing outage hides the original cause.",
            evidence,
        )
    if facts.validator is None and not facts.chain:
        return CheckResult(
            "validator_writing", title, BLOCKED,
            "the write is recent, but trust_profile could not resolve the validator "
            "process, so the chain cooldown cannot be sampled through it",
            "fix trust_profile, or pass --chain-json with a sample of "
            '{"weights_rate_limit": .., "blocks_since_last_update": ..}.',
            evidence,
        )
    if facts.chain_error:
        return CheckResult(
            "validator_writing", title, FAIL,
            f"the write is recent, but the chain cooldown could not be sampled: "
            f"{facts.chain_error}",
            "re-run with the chain reachable, or pass --chain-json with a sample of "
            "{\"weights_rate_limit\": .., \"blocks_since_last_update\": ..}. "
            "Without it a validator that is fenced off the chain looks healthy.",
            evidence,
        )
    rate_limit = facts.chain.get("weights_rate_limit")
    since = facts.chain.get("blocks_since_last_update")
    evidence["weights_rate_limit"] = rate_limit
    evidence["blocks_since_last_update"] = since
    evidence["block"] = facts.chain.get("block")
    if not isinstance(rate_limit, int) or not isinstance(since, int) or rate_limit < 0:
        return CheckResult(
            "validator_writing", title, FAIL,
            "weights_rate_limit / blocks_since_last_update did not read back as two "
            "non-negative integers",
            "the same values the validator's own cooldown gate needs are "
            "unreadable; it will fail its ticks closed. Resolve the chain read "
            "before the flip.",
            evidence,
        )
    ceiling = max(1, rate_limit) * facts.max_cooldown_multiple
    evidence["cooldown_multiple"] = round(since / max(1, rate_limit), 2)
    if since > ceiling:
        return CheckResult(
            "validator_writing", title, FAIL,
            f"blocks_since_last_update is {since}, more than "
            f"{facts.max_cooldown_multiple:g}x weights_rate_limit ({rate_limit})",
            "the chain has not accepted a write for several whole rate-limit "
            "windows even though the log claims recent submissions. Reconcile the "
            "log with the chain before the flip -- this is the shape of a validator "
            "that thinks it is writing and is not.",
            evidence,
        )
    return CheckResult(
        "validator_writing", title, PASS,
        f"last weight write {age / 60:.0f} min ago; blocks_since_last_update "
        f"{since} against a rate limit of {rate_limit}",
        evidence=evidence,
    )


CHECKS: tuple[Callable[[Facts], CheckResult], ...] = (
    check_composer_identity,
    check_composer_reachable,
    check_db_migration,
    check_producer_identity,
    check_trust_profile,
    check_fundable_lane,
    check_validator_writing,
)


def run_checks(facts: Facts) -> list[CheckResult]:
    return [check(facts) for check in CHECKS]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _iso(epoch: float) -> str:
    if not epoch:
        return "unknown"
    moment = datetime.fromtimestamp(float(epoch), timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _age_secs(iso_text: str, now: float) -> float | None:
    try:
        moment = datetime.fromisoformat(str(iso_text).strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return now - moment.timestamp()


def _float_env(raw: str | None, default: float) -> float:
    try:
        value = float((raw or "").strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def parse_status_events(text: str) -> list[dict[str, Any]]:
    """Parse a status-log tail. The first line may be a byte-sliced fragment."""
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    return events


# The two read-only queries the fundable-lane and producer checks need. Kept
# beside each other so it is obvious that neither writes.
def database_queries(network: str, netuid: int) -> dict[str, Any]:
    return {
        "producers": {
            "requires": "cybergym_score_reports",
            "sql": "SELECT producer_hotkey, MAX(source_epoch) FROM cybergym_score_reports "
                   "GROUP BY producer_hotkey",
        },
        "latest_report": {
            "requires": "cybergym_score_reports",
            "sql": "SELECT id, source_epoch, generated_at_iso, score_count "
                   "FROM cybergym_score_reports WHERE network=? AND netuid=? AND complete=1 "
                   "ORDER BY source_epoch DESC LIMIT 1",
            "params": [network, netuid],
        },
        "epoch_state": {
            "requires": "cybergym_epoch_status",
            "sql": "SELECT epoch, state FROM cybergym_epoch_status",
        },
        # The adapter maps scored hotkeys through metagraph_hotkeys and drops
        # what it cannot map, so the join is the question: is anybody payable?
        "scored_uids": {
            "requires": "cybergym_scores",
            "sql": "SELECT s.miner_hotkey, s.score, m.uid FROM cybergym_scores s "
                   "LEFT JOIN metagraph_hotkeys m ON m.hotkey = s.miner_hotkey "
                   "AND m.network = ? AND m.netuid = ? "
                   "WHERE s.report_id = (SELECT id FROM cybergym_score_reports "
                   "WHERE network=? AND netuid=? AND complete=1 "
                   "ORDER BY source_epoch DESC LIMIT 1) AND s.score > 0",
            "params": [network, netuid, network, netuid],
        },
    }


SCOPE_ENV_KEYS = (
    "PATH", "PYTHONPATH", "VIRTUAL_ENV", "HOME", "LANG",
    # The scope is a function of these two, so they must reach the probe
    # exactly as the process has them -- including "absent".
    NETWORK_ENV, NETUID_ENV,
)


def resolve_composer(host: Host, args: argparse.Namespace) -> ComposerResolution:
    """Identify the process that composes ``latest:<network>:<netuid>``.

    Not by unit name. A box can run several processes that import the same ASGI
    app, answer the same paths, and differ only in which durable row they write;
    the live SN39 host runs four. What separates them is a fact each one will
    state about itself:

      * the row id its own imported ``weights`` module would write
        (``_persisted_vector_id()``), and
      * the cluster lock that module would take to write it
        (``_refresh_lock_name()``),

    both evaluated inside that process's interpreter, cwd and environment. A
    pre-scope tree has neither function and writes one unscoped ``latest`` row;
    a canary scoped to test/292 names test/292. Exactly one process may name
    this subnet, and if none or several do, that is a FAIL rather than a guess.

    The Postgres advisory lock is then WATCHED (never taken) to corroborate:
    only the true composer holds it, so a sighting attributable to a different
    candidate contradicts the selection and is fatal. It is held for a fraction
    of each refresh cycle, so not seeing it is neutral.

    ``--publisher-unit`` is a fallback, not the mechanism: it is consulted only
    when /proc enumeration finds nothing (or when an operator names a unit
    deliberately), and even then the named process must still prove its scope.
    """
    ident = ComposerResolution(
        expected_vector_id=persisted_vector_id(args.network, args.netuid),
        expected_lock_name=refresh_lock_name(args.network, args.netuid),
    )
    unit = getattr(args, "publisher_unit", None)
    procs: list[ProcessFacts] = []
    if unit:
        ident.method = f"named unit {unit}"
        try:
            procs = [host.service_process(unit)]
        except (ProbeError, OSError, ValueError) as exc:
            ident.error = f"--publisher-unit {unit} could not be resolved: {exc}"
            return ident
    else:
        ident.method = f"/proc scan for {PUBLISHER_PROCESS_MARKER}"
        try:
            procs = [process_facts(entry)
                     for entry in host.publishers(PUBLISHER_PROCESS_MARKER)]
        except (ProbeError, OSError, ValueError) as exc:
            ident.enumeration_error = str(exc)
        if not procs:
            ident.method = f"unit fallback to {DEFAULT_PUBLISHER_UNIT}"
            try:
                procs = [host.service_process(DEFAULT_PUBLISHER_UNIT)]
            except (ProbeError, OSError, ValueError) as exc:
                ident.error = (
                    "no running process imports "
                    f"{PUBLISHER_PROCESS_MARKER}"
                    + (f" ({ident.enumeration_error})" if ident.enumeration_error else "")
                    + f", and the fallback unit {DEFAULT_PUBLISHER_UNIT} could not "
                    f"be resolved either: {exc}"
                )
                return ident

    matches: list[tuple[ProcessFacts, dict[str, Any]]] = []
    for proc in procs:
        entry: dict[str, Any] = {
            "unit": proc.unit or "(no unit)",
            "pid": proc.pid,
            "cwd": proc.cwd,
            "interpreter": proc.interpreter,
        }
        try:
            scope = host.pyprobe_json(proc, SCOPE_PROBE, env_keys=SCOPE_ENV_KEYS)
        except (ProbeError, OSError, ValueError) as exc:
            entry["probe_error"] = str(exc)
            entry["is_composer"] = False
            ident.candidates.append(entry)
            continue
        entry["module_file"] = scope.get("module_file")
        entry["persisted_vector_id"] = scope.get("persisted_vector_id")
        entry["refresh_lock_name"] = scope.get("refresh_lock_name")
        for key in ("import_error", "persisted_vector_id_error", "refresh_lock_name_error"):
            if scope.get(key):
                entry[key] = scope[key]
        entry["is_composer"] = (
            scope.get("refresh_lock_name") == ident.expected_lock_name
            and scope.get("persisted_vector_id") == ident.expected_vector_id
        )
        ident.candidates.append(entry)
        if entry["is_composer"]:
            matches.append((proc, scope))

    if not matches:
        seen = ", ".join(
            f"{c['unit']} (pid {c['pid']}, {c.get('cwd')}) -> "
            f"{c.get('persisted_vector_id') or c.get('import_error') or c.get('probe_error') or 'unscoped `latest`'}"
            for c in ident.candidates
        ) or "nothing"
        ident.error = (
            f"no running publisher composes {ident.expected_vector_id}. Considered: "
            f"{seen}"
        )
        return ident
    if len(matches) > 1:
        ident.error = (
            f"{len(matches)} running processes each claim to compose "
            f"{ident.expected_vector_id} "
            f"({', '.join(f'{p.unit or p.pid}' for p, _ in matches)}); the durable "
            "row has one writer, so this box is misconfigured and probing either "
            "one would be a coin flip"
        )
        ident.process, ident.scope = matches[0]
        return ident

    ident.process, ident.scope = matches[0]

    try:
        ident.lock = host.pyprobe_json(
            ident.process,
            LOCK_OBSERVE_PROBE,
            env_keys=("PATH", "PYTHONPATH", "VIRTUAL_ENV", "HOME", "LANG", "DATABASE_URL"),
            env={
                "LOCK_NAME": ident.expected_lock_name,
                "BUDGET_SECS": str(args.observe_lock_secs),
                "CANDIDATE_PIDS": json.dumps([c["pid"] for c in ident.candidates]),
            },
            timeout=float(args.observe_lock_secs) + 60.0,
        )
    except (ProbeError, OSError, ValueError) as exc:
        ident.lock = {"error": str(exc)}

    holder = ident.lock.get("holder_pid")
    if ident.lock.get("observed") and holder is not None and int(holder) != ident.process.pid:
        other = next(
            (c for c in ident.candidates if c["pid"] == int(holder)), {"unit": "?"}
        )
        ident.error = (
            f"{ident.expected_lock_name} is held by pid {holder} "
            f"({other.get('unit')}), not by the process whose code claims that "
            f"scope ({ident.process.unit}, pid {ident.process.pid}). The durable "
            "row is being written by something other than the process this "
            "preflight would have described"
        )
    return ident


def gather(host: Host, args: argparse.Namespace) -> Facts:
    """Collect every fact once. Probe failures are recorded, never raised."""
    facts = Facts(
        now=host.now(),
        max_weights_age_secs=args.max_weights_age_secs,
        max_cooldown_multiple=args.max_cooldown_multiple,
    )

    facts.composer_id = resolve_composer(host, args)
    if facts.composer_id.confirmed:
        facts.publisher = facts.composer_id.process
    else:
        facts.publisher_error = facts.composer_id.error

    if facts.publisher is not None:
        try:
            facts.composer = host.pyprobe_json(
                facts.publisher,
                COMPOSER_PROBE,
                env_keys=("PATH", "PYTHONPATH", "VIRTUAL_ENV", "HOME", "LANG"),
            )
        except (ProbeError, OSError, ValueError) as exc:
            facts.composer_error = str(exc)
        network = facts.publisher.environ.get(NETWORK_ENV) or args.network
        try:
            netuid = int(facts.publisher.environ.get(NETUID_ENV) or args.netuid)
        except ValueError:
            netuid = args.netuid
        try:
            facts.database = host.pyprobe_json(
                facts.publisher,
                DATABASE_PROBE,
                env_keys=(
                    "PATH", "PYTHONPATH", "VIRTUAL_ENV", "HOME", "LANG",
                    "DATABASE_URL", "CATHEDRAL_DB_PATH",
                ),
                env={"QUERIES": json.dumps(database_queries(network, netuid))},
            )
        except (ProbeError, OSError, ValueError) as exc:
            facts.database_error = str(exc)

    try:
        facts.validator = host.service_process(args.validator_unit)
    except (ProbeError, OSError, ValueError) as exc:
        facts.validator_error = str(exc)

    if facts.validator is not None:
        try:
            facts.trust = host.pyprobe_json(
                facts.validator,
                TRUST_PROFILE_PROBE,
                env_keys=("PATH", "PYTHONPATH", "HOME", "LANG", "COLUMNS"),
                env={"VALIDATOR_CONFIG": args.validator_config},
            )
        except (ProbeError, OSError, ValueError) as exc:
            facts.trust_error = str(exc)

    try:
        facts.status_events = parse_status_events(host.tail(args.status_log)["text"])
    except (ProbeError, OSError, ValueError, KeyError) as exc:
        facts.status_error = str(exc)

    if args.chain_json:
        try:
            with open(args.chain_json) as handle:
                facts.chain = json.load(handle)
        except (OSError, ValueError) as exc:
            facts.chain_error = f"could not read {args.chain_json}: {exc}"
    elif facts.validator is not None:
        try:
            facts.state = host.state(args.state_file)
            uid = facts.state.get("validator_uid")
            if uid is None:
                raise ProbeError(
                    f"{args.state_file} carries no thin_submission_identity.validator_uid"
                )
            facts.chain = host.pyprobe_json(
                facts.validator,
                CHAIN_PROBE,
                env_keys=("PATH", "PYTHONPATH", "HOME", "LANG", "CATHEDRAL_CHAIN_ENDPOINT"),
                env={
                    "NETWORK": str(facts.state.get("network") or args.network),
                    "NETUID": str(facts.state.get("netuid") or args.netuid),
                    "VALIDATOR_UID": str(int(uid)),
                },
                timeout=180.0,
            )
        except (ProbeError, OSError, ValueError, KeyError) as exc:
            facts.chain_error = str(exc)
    else:
        facts.chain_error = "the validator process could not be resolved"

    return facts


def render(results: list[CheckResult], facts: Facts, as_json: bool) -> str:
    ready = all(result.state == PASS for result in results)
    if as_json:
        ident = facts.composer_id
        probed: dict[str, Any] | None = None
        if ident.process is not None:
            probed = {
                "unit": ident.process.unit,
                "pid": ident.process.pid,
                "cwd": ident.process.cwd,
                "module_file": ident.scope.get("module_file"),
                "persisted_vector_id": ident.scope.get("persisted_vector_id"),
                "confirmed": ident.confirmed,
            }
        return json.dumps(
            {
                "ready": ready,
                "checked_at": _iso(facts.now),
                "probed_publisher": probed,
                "identification_method": ident.method,
                "checks": [result.as_dict() for result in results],
            },
            sort_keys=True,
        )
    lines = []
    # The header names the process the publisher-side verdicts are ABOUT,
    # before any of them. A reader who cannot see which process was probed
    # cannot tell whether the report is about the right one -- and this report
    # has been about the wrong one before.
    ident = facts.composer_id
    proc = ident.process
    if proc is None:
        lines.append(
            f"probed publisher  NONE -- no process proven to compose "
            f"{ident.expected_vector_id or 'this subnet'}"
        )
    else:
        mark = "" if ident.confirmed else "  (UNCONFIRMED -- see composer_identity)"
        lines.append(
            f"probed publisher  {proc.unit or '(no unit)'} pid {proc.pid}{mark}"
        )
        lines.append(f"                  cwd      {proc.cwd}")
        lines.append(f"                  module   {ident.scope.get('module_file')}")
        lines.append(
            f"                  composes {ident.scope.get('persisted_vector_id')}"
        )
    lines.append(f"                  found by {ident.method}")
    lines.append("")
    for result in results:
        lines.append(f"{result.state:<17} {result.check_id:<20} {result.title}")
        lines.append(f"    why    {result.reason}")
        if result.state != PASS and result.action:
            lines.append(f"    do     {result.action}")
    lines.append("")
    if ready:
        lines.append(
            "READY. All seven independent conditions hold. Flip the publisher to "
            "CATHEDRAL_ALLOCATION_CONTRACT=v3 and re-pin the validators in ONE "
            "coordinated window, then confirm with scripts/assert_live_v3_contract.py "
            "that a v3-pinned validator accepts the emitted vector."
        )
    else:
        failed = [r.check_id for r in results if r.state == FAIL]
        blocked = [r.check_id for r in results if r.state == BLOCKED]
        lines.append("NOT READY. Do not flip.")
        if failed:
            lines.append(f"  failing: {', '.join(failed)}")
        if blocked:
            lines.append(f"  blocked: {', '.join(blocked)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None, host: Host | None = None) -> int:
    """*host* exists so the tests can drive the whole report from fake facts."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gcloud-instance", help="probe this instance over IAP SSH")
    parser.add_argument("--gcloud-zone", default="us-central1-b")
    parser.add_argument(
        "--publisher-unit",
        default=None,
        help="probe THIS unit's process instead of discovering the composer. "
        "Only ever narrows the search: the named process must still prove it "
        f"composes latest:<network>:<netuid>, or the run fails. Default: "
        f"discover by /proc scan, falling back to {DEFAULT_PUBLISHER_UNIT}.",
    )
    parser.add_argument(
        "--observe-lock-secs",
        type=float,
        default=DEFAULT_OBSERVE_LOCK_SECS,
        help="how long to watch pg_locks for the composer's refresh lock, as "
        "corroboration. The lock is held only while a rebuild runs (roughly "
        "once a minute), so this window is a little over one cycle. 0 skips it; "
        "not seeing the lock is never itself a failure.",
    )
    parser.add_argument("--validator-unit", default=DEFAULT_VALIDATOR_UNIT)
    parser.add_argument("--validator-config", default=DEFAULT_VALIDATOR_CONFIG)
    parser.add_argument("--status-log", default=DEFAULT_STATUS_LOG)
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    parser.add_argument("--network", default=DEFAULT_NETWORK)
    parser.add_argument("--netuid", type=int, default=DEFAULT_NETUID)
    parser.add_argument(
        "--max-weights-age-secs", type=float, default=DEFAULT_MAX_WEIGHTS_AGE_SECS
    )
    parser.add_argument(
        "--max-cooldown-multiple", type=float, default=DEFAULT_MAX_COOLDOWN_MULTIPLE
    )
    parser.add_argument(
        "--chain-json",
        help="read weights_rate_limit / blocks_since_last_update from this file "
        "instead of the chain (for a host with no RPC path)",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    if host is None:
        if args.gcloud_instance:
            host = CommandHost(gcloud_runner(args.gcloud_instance, args.gcloud_zone))
        else:
            host = CommandHost(local_runner)

    facts = gather(host, args)
    results = run_checks(facts)
    print(render(results, facts, args.as_json))
    return 0 if all(result.state == PASS for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
