"""The real differential behind the validator's `benchmark` seam.

:mod:`cybergym_round_eval` takes ``benchmark(task_id, poc, proof) -> bool``. This is that function
for a real deployment: it rebuilds the task from the SERVER-SUPPLIED proof and runs the PoC
against both builds under Docker, network-isolated.

**Solved means crash on the vulnerable build AND clean on the patched one.** One half alone proves
nothing: a PoC that crashes both is an input that breaks the target generally, not the specific
bug, and a PoC that crashes neither did nothing at all.

The crash test is deliberately strict, and mirrors ``cathedral_distill.cybergym_repro._is_crash``
(reproduced rather than imported, so the validator carries no optional cross-repo dependency on
the payout path). Two conditions must BOTH hold:

* a canonical sanitizer report — matched structurally on the ``==pid==ERROR|WARNING:
  <X>Sanitizer:`` banner, the colon being what separates a real report from a build log that
  merely mentions the sanitizer — and the sanitizer must be the one this task is known to
  produce; and
* the process actually died the way this task's committed rule says it dies (an expected exit
  code or terminating signal). A marker in output is not execution evidence: an input can echo
  ``AddressSanitizer: ...`` while the process exits 0.

That rule travels in the proof (``crash_evidence``), so every validator judges a task by the same
committed criterion instead of "any crash counts". A proof without one is refused: an unjudgeable
task is not a solve.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Callable

DOCKER_TIMEOUT = 300
#: No network, no privileges, bounded memory/pids: a PoC is hostile input from an unknown miner.
SANDBOX_FLAGS: tuple[str, ...] = (
    "--network=none",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--pids-limit=256",
    "--memory=4g",
    "--user=1000:1000",
)

_SANITIZERS = ("Address", "Memory", "Thread", "Leak", "UndefinedBehavior", "HWAddress")
_SANITIZER_REPORT = re.compile(
    r"(?m)^==\d+==(?:ERROR|WARNING): "
    r"(?P<sanitizer>" + "|".join(_SANITIZERS) + r")Sanitizer:"
)
#: The rule's sanitizer must be one the detector can actually recognise. A name outside this set
#: (a typo, a sanitizer nobody built for) would make the task unsolvable BY ANYONE — every PoC
#: would fail the report check and the whole task would silently score zero for the entire field.
#: Refusing the proof surfaces that as a broken task instead of a round of undeserved zeros.
KNOWN_SANITIZERS = frozenset(s + "Sanitizer" for s in _SANITIZERS)

Runner = Callable[..., Any]


class BenchmarkError(ValueError):
    """The proof cannot be judged. Fails closed — an unjudgeable task is never a solve."""


@dataclass(frozen=True)
class CrashRule:
    sanitizer: str
    exit_codes: frozenset[int]
    signals: frozenset[int]


@dataclass(frozen=True)
class TaskBuilds:
    """What the server's proof must carry for a validator to run the differential itself."""

    vulnerable_image: str
    fixed_image: str
    command: tuple[str, ...]
    rule: CrashRule


def parse_proof(proof: Mapping) -> TaskBuilds:
    """Read a server-supplied proof, refusing anything it cannot judge strictly."""
    if not isinstance(proof, Mapping):
        raise BenchmarkError("proof must be a mapping")
    vul = str(proof.get("vulnerable_image") or "")
    fix = str(proof.get("fixed_image") or "")
    if not vul or not fix:
        raise BenchmarkError("proof needs both a vulnerable_image and a fixed_image")
    if vul == fix:
        raise BenchmarkError(
            "vulnerable and fixed images are identical; no differential exists"
        )
    command = tuple(str(c) for c in (proof.get("command") or ("/bin/arvo",)))
    if not command:
        raise BenchmarkError("proof needs a reproduce command")
    ev = proof.get("crash_evidence")
    if not isinstance(ev, Mapping):
        raise BenchmarkError("proof carries no crash_evidence rule")
    sanitizer = ev.get("sanitizer")
    if not isinstance(sanitizer, str) or sanitizer not in KNOWN_SANITIZERS:
        raise BenchmarkError(
            f"crash_evidence sanitizer {sanitizer!r} is not one this validator can detect; "
            f"expected one of {sorted(KNOWN_SANITIZERS)}"
        )
    codes = _int_set(ev.get("exit_codes"), 1, 255, "exit_codes")
    signals = _int_set(ev.get("signals"), 1, 64, "signals")
    return TaskBuilds(vul, fix, command, CrashRule(sanitizer, codes, signals))


def _int_set(values, low: int, high: int, what: str) -> frozenset[int]:
    if (
        not isinstance(values, Sequence)
        or isinstance(values, (str, bytes))
        or not values
        or any(
            isinstance(v, bool) or not isinstance(v, int) or not low <= v <= high
            for v in values
        )
    ):
        raise BenchmarkError(f"crash_evidence has invalid {what}")
    return frozenset(int(v) for v in values)


def is_crash(output: str, returncode: int, rule: CrashRule) -> bool:
    """Sanitizer report for THIS task's sanitizer, plus a death the task is known to die."""
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        return False
    died = (
        (-returncode in rule.signals)
        if returncode < 0
        else (returncode in rule.exit_codes)
    )
    if not died:
        return False
    report = _SANITIZER_REPORT.search(output)
    return (
        report is not None and report.group("sanitizer") + "Sanitizer" == rule.sanitizer
    )


def run_once(
    image: str,
    command: Sequence[str],
    poc: bytes,
    rule: CrashRule,
    *,
    docker: str = "docker",
    timeout: int = DOCKER_TIMEOUT,
    _run: Runner = subprocess.run,
) -> bool:
    """True iff this build crashes on this PoC."""
    fd, path = tempfile.mkstemp(prefix="cgpoc-")
    name = "cgbench-" + os.path.basename(path)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(poc)
        os.chmod(
            path, 0o444
        )  # readable by the container's unprivileged uid, never writable
        try:
            r = _run(
                [
                    docker,
                    "run",
                    "--rm",
                    "--name",
                    name,
                    *SANDBOX_FLAGS,
                    "-v",
                    f"{path}:/tmp/poc:ro",
                    image,
                    *command,
                ],
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            # Under --rm the container survives the killed client, so force it down: a looping or
            # memory-bombing PoC must not linger on the validator host. A timeout is a CLEAN
            # result, never a solve.
            try:
                _run([docker, "rm", "-f", name], capture_output=True, timeout=30)
            except Exception:
                pass
            return False
        out = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace")
        return is_crash(out, r.returncode, rule)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def docker_benchmark(
    task_id: str,
    poc: bytes,
    proof: Mapping,
    *,
    docker: str = "docker",
    timeout: int = DOCKER_TIMEOUT,
    _run: Runner = subprocess.run,
) -> bool:
    """The `BenchmarkFn` for production: crash on vulnerable AND clean on patched.

    The vulnerable build runs first and a non-crash short-circuits: most PoCs fail there, and
    skipping the patched run halves the container work for every one of them — which is what
    keeps 200 miners x ~30 tasks inside the round.
    """
    if not poc:
        return False
    builds = parse_proof(proof)
    if not run_once(
        builds.vulnerable_image,
        builds.command,
        poc,
        builds.rule,
        docker=docker,
        timeout=timeout,
        _run=_run,
    ):
        return False
    return not run_once(
        builds.fixed_image,
        builds.command,
        poc,
        builds.rule,
        docker=docker,
        timeout=timeout,
        _run=_run,
    )


__all__ = [
    "BenchmarkError",
    "CrashRule",
    "TaskBuilds",
    "SANDBOX_FLAGS",
    "DOCKER_TIMEOUT",
    "KNOWN_SANITIZERS",
    "parse_proof",
    "is_crash",
    "run_once",
    "docker_benchmark",
]
