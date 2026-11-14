"""Offline receipt checks and result reuse for Speedrun results (AB#456).

A Speedrun result is a sealed run whose evidence bundle (AMD attestation, the
sealed guest's receipts, Cathedral's receipt chain) a validator can check with
no network. The checking itself is ``ctcli receipt verify --bundle ...
--approved-measurement ... --json`` (cathedral-pool, ``cli/evidence.py``). This
module does not re-implement that crypto; it runs ctcli, accepts a result only
on a consistent PASS, and keeps a local store so a result is never measured
twice.

Trust: the validator trusts the ctcli install it runs, as it trusts its own
code. The checks here on ctcli's output (exit code matches verdict, every row
names the attested measurement and binding, the measurement is on the
validator's own approved list, ``result_digest`` recomputes) are consistency
checks against a wrong or drifted verifier, not a defence against a hostile
one. ``expected_verifier_sha256`` pins the verifier version ctcli reports.

Reuse key: entry digest, model digest, harness version, room size and round
(``SpeedrunKey``). A key already recorded is reused. A rerun happens only on a
dispute or on a documented, reproducible sample (``sample_selected``). The key
fields are not inside any receipt today, so the caller supplies them from the
Speedrun entry; the store refuses to let one verified run (one
``result_digest``) count for two keys, and ``expected_command_sha256`` lets a
caller require the exact argv it launched.

The score stored with a result is the caller's; the store binds it to the
result digests it was computed from, nothing more.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from cathedral_thin.independent.canonical import canonical_bytes, parse_strict_json
from cathedral_thin.independent.errors import PolicyBundleError

RESULT_SCHEMA = "cathedral_verified_result_v1"
STORE_SCHEMA = "cathedral_speedrun_result_store_v1"
SAMPLE_DOMAIN = b"cathedral-speedrun-sample-v1\x00"
KEY_DOMAIN = "cathedral-speedrun-key-v1"
TIMEOUT_SECONDS = 120.0
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_STORE_BYTES = 32 * 1024 * 1024
# ctcli exit codes (cathedral-pool cli/evidence.py): PASS 0, FAIL 1, NOT PROVEN 3.
_VERDICT_EXIT = {"PASS": 0, "FAIL": 1, "NOT PROVEN": 3}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MEASUREMENT = re.compile(r"[0-9a-f]{96}")
_HARNESS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
_ROW_HASHES = (
    "binding_sha256",
    "guest_receipt_sha256",
    "command_sha256",
    "guest_result_sha256",
    "stdout_sha256",
)
_ROW_KEYS = frozenset((*_ROW_HASHES, "measurement", "exit_code", "result_digest"))

MEASURE = "measure"
REUSE = "reuse"
RERUN_DISPUTE = "rerun-dispute"
RERUN_SAMPLE = "rerun-sample"


class SpeedrunResultError(Exception):
    """A bundle, a ctcli answer or the result store failed closed.

    ``infra`` is True when the check could not run (ctcli missing, timed out,
    unreadable output): retry later. False means the evidence was refused.
    """

    def __init__(self, message: str, *, infra: bool = False) -> None:
        super().__init__(message)
        self.infra = infra


@dataclass(frozen=True)
class SpeedrunKey:
    entry_digest: str
    model_digest: str
    harness_version: str
    room_size: int
    round: int

    def __post_init__(self) -> None:
        for name in ("entry_digest", "model_digest"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise SpeedrunResultError(f"{name} must be 64 lowercase hex")
        if not isinstance(self.harness_version, str) or not _HARNESS.fullmatch(
            self.harness_version
        ):
            raise SpeedrunResultError("harness_version must be a short ASCII version")
        for name in ("room_size", "round"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SpeedrunResultError(f"{name} must be a positive integer")

    def fields(self) -> dict[str, Any]:
        return {
            "entry_digest": self.entry_digest,
            "model_digest": self.model_digest,
            "harness_version": self.harness_version,
            "room_size": self.room_size,
            "round": self.round,
        }

    @property
    def key_id(self) -> str:
        document = {"domain": KEY_DOMAIN, **self.fields()}
        return hashlib.sha256(canonical_bytes(document)).hexdigest()

    @classmethod
    def from_fields(cls, document: object) -> SpeedrunKey:
        if not isinstance(document, Mapping):
            raise SpeedrunResultError("speedrun key must be an object")
        expected = {
            "entry_digest",
            "model_digest",
            "harness_version",
            "room_size",
            "round",
        }
        if set(document) != expected:
            raise SpeedrunResultError("speedrun key has missing or unknown fields")
        return cls(**{name: document[name] for name in expected})


@dataclass(frozen=True)
class VerifiedBundle:
    """Rows ctcli verified, re-checked here. One row per argv exec."""

    measurement: str
    binding_sha256: str
    rows: tuple[dict[str, Any], ...]
    verifier_sha256: str | None

    @property
    def result_digests(self) -> tuple[str, ...]:
        return tuple(sorted(row["result_digest"] for row in self.rows))


def _measurements(values: Sequence[str]) -> frozenset[str]:
    approved = set()
    for value in values:
        text = str(value).strip().lower()
        if not _MEASUREMENT.fullmatch(text):
            raise SpeedrunResultError("approved measurement must be 96 hex characters")
        approved.add(text)
    if not approved:
        raise SpeedrunResultError("at least one approved measurement is required")
    return frozenset(approved)


def row_digest(row: Mapping[str, Any]) -> str:
    """The pool's result_digest: sha256 of the row's canonical identity fields."""

    identity = {name: row[name] for name in row if name != "result_digest"}
    try:
        return hashlib.sha256(canonical_bytes(identity)).hexdigest()
    except PolicyBundleError as exc:
        raise SpeedrunResultError("verified row is not canonical JSON") from exc


def _check_row(row: object, *, measurement: str, binding: str) -> dict[str, Any]:
    if not isinstance(row, dict) or set(row) != _ROW_KEYS:
        raise SpeedrunResultError("verified row has missing or unknown fields")
    for name in (*_ROW_HASHES, "result_digest"):
        if not isinstance(row[name], str) or not _SHA256.fullmatch(row[name]):
            raise SpeedrunResultError(f"verified row {name} is not a sha256")
    code = row["exit_code"]
    if isinstance(code, bool) or not isinstance(code, int):
        raise SpeedrunResultError("verified row exit_code is not an integer")
    if row["measurement"] != measurement or row["binding_sha256"] != binding:
        raise SpeedrunResultError("verified row does not name the attested guest")
    if row_digest(row) != row["result_digest"]:
        raise SpeedrunResultError("verified row result_digest does not recompute")
    return dict(row)


def parse_ctcli_report(
    stdout: bytes,
    returncode: int,
    *,
    approved_measurements: Sequence[str],
    expected_verifier_sha256: str | None = None,
    expected_command_sha256: str | None = None,
) -> VerifiedBundle:
    """Accept ctcli's ``--json`` answer only when it is a consistent PASS."""

    approved = _measurements(approved_measurements)
    try:
        report = parse_strict_json(stdout, max_bytes=MAX_OUTPUT_BYTES)
    except (PolicyBundleError, ValueError, RecursionError) as exc:
        raise SpeedrunResultError("ctcli output is not JSON", infra=True) from exc
    if not isinstance(report, dict) or "verdict" not in report:
        raise SpeedrunResultError("ctcli did not return a verdict", infra=True)
    verdict = report["verdict"]
    if _VERDICT_EXIT.get(verdict) != returncode:
        raise SpeedrunResultError("ctcli exit code does not match its verdict")
    if verdict != "PASS":
        failures = report.get("failures") or report.get("not_proven") or []
        first = (
            str(failures[0])[:200] if isinstance(failures, list) and failures else ""
        )
        raise SpeedrunResultError(f"bundle verdict is {verdict}: {first}".rstrip(": "))
    verifier = report.get("verifier")
    verifier_sha256 = verifier.get("sha256") if isinstance(verifier, dict) else None
    if (
        expected_verifier_sha256 is not None
        and verifier_sha256 != expected_verifier_sha256
    ):
        raise SpeedrunResultError("ctcli ran a verifier other than the pinned one")
    attestation = report.get("attestation")
    if not isinstance(attestation, dict):
        raise SpeedrunResultError("PASS without an attestation")
    measurement = str(attestation.get("measurement") or "").lower()
    binding = attestation.get("binding_sha256")
    if measurement not in approved:
        raise SpeedrunResultError("attested measurement is not on the approved list")
    if not isinstance(binding, str) or not _SHA256.fullmatch(binding):
        raise SpeedrunResultError("attestation has no binding_sha256")
    results = report.get("verified_results")
    if not isinstance(results, dict) or results.get("schema") != RESULT_SCHEMA:
        raise SpeedrunResultError(f"ctcli output has no {RESULT_SCHEMA} block")
    raw_rows = results.get("results")
    if not isinstance(raw_rows, list) or not raw_rows:
        reason = str(results.get("reason") or "no rows")[:200]
        raise SpeedrunResultError(f"no verified results: {reason}")
    rows = tuple(
        _check_row(r, measurement=measurement, binding=binding) for r in raw_rows
    )
    if len({row["result_digest"] for row in rows}) != len(rows):
        raise SpeedrunResultError("ctcli returned the same result twice")
    if expected_command_sha256 is not None and expected_command_sha256 not in {
        row["command_sha256"] for row in rows
    }:
        raise SpeedrunResultError("no verified result ran the expected command")
    return VerifiedBundle(
        measurement=measurement,
        binding_sha256=binding,
        rows=rows,
        verifier_sha256=verifier_sha256 if isinstance(verifier_sha256, str) else None,
    )


Runner = Callable[..., "subprocess.CompletedProcess[bytes]"]


def verify_bundle_offline(
    bundle: Path,
    *,
    trusted_keys_file: Path,
    approved_measurements: Sequence[str],
    ctcli: Sequence[str] = ("ctcli",),
    expected_verifier_sha256: str | None = None,
    expected_command_sha256: str | None = None,
    timeout: float = TIMEOUT_SECONDS,
    runner: Runner = subprocess.run,
) -> VerifiedBundle:
    """Run ctcli on one bundle with no network inputs and return its verified rows.

    Never passes ``--kds-cache``: ctcli then seeds AMD certificates from the
    bundle itself, and a partial cache would make it fetch from AMD.
    """

    approved = sorted(_measurements(approved_measurements))
    command = [
        *ctcli,
        "receipt",
        "verify",
        "--bundle",
        str(bundle),
        "--trusted-keys-file",
        str(trusted_keys_file),
        "--json",
    ]
    for measurement in approved:
        command += ["--approved-measurement", measurement]
    try:
        completed = runner(command, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SpeedrunResultError(
            f"ctcli could not run: {type(exc).__name__}", infra=True
        ) from exc
    if len(completed.stdout) > MAX_OUTPUT_BYTES:
        raise SpeedrunResultError("ctcli output is too large", infra=True)
    return parse_ctcli_report(
        completed.stdout,
        completed.returncode,
        approved_measurements=approved,
        expected_verifier_sha256=expected_verifier_sha256,
        expected_command_sha256=expected_command_sha256,
    )


def sample_selected(key: SpeedrunKey, *, seed: bytes, rate_ppm: int) -> bool:
    """Documented sampling: rerun when sha256(domain || seed || key_id) < rate.

    ``seed`` must be fixed after entries close (for example the round's closing
    block hash), so a miner cannot pick key fields that avoid the sample.
    ``rate_ppm`` is parts per million; 0 means no sampled reruns.
    """

    if isinstance(rate_ppm, bool) or not isinstance(rate_ppm, int):
        raise SpeedrunResultError("sample rate must be an integer ppm")
    if not 0 <= rate_ppm <= 1_000_000:
        raise SpeedrunResultError("sample rate must be 0..1000000 ppm")
    if not isinstance(seed, (bytes, bytearray)) or len(seed) < 16:
        raise SpeedrunResultError("sample seed must be at least 16 bytes")
    draw = hashlib.sha256(SAMPLE_DOMAIN + bytes(seed) + bytes.fromhex(key.key_id))
    return int.from_bytes(draw.digest(), "big") * 1_000_000 < rate_ppm * (1 << 256)


class ResultStore:
    """A validator-local JSON file: Speedrun key -> verified result and score.

    One writer at a time (an exclusive lock on a sibling ``.lock`` file); each
    write replaces the file atomically.
    """

    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise SpeedrunResultError("result store path must be absolute")
        self.path = path

    @contextlib.contextmanager
    def _locked(self) -> Iterator[dict[str, Any]]:
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        fd = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield self._read()
        finally:
            os.close(fd)

    def _read(self) -> dict[str, Any]:
        try:
            fd = os.open(
                self.path,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            )
        except FileNotFoundError:
            return {"schema": STORE_SCHEMA, "results": {}, "digests": {}}
        except OSError as exc:
            raise SpeedrunResultError(
                f"result store is unreadable: {type(exc).__name__}"
            ) from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & stat.S_IWOTH:
                raise SpeedrunResultError("result store must be a private regular file")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                raw = handle.read(MAX_STORE_BYTES + 1)
        finally:
            os.close(fd)
        try:
            document = parse_strict_json(raw, max_bytes=MAX_STORE_BYTES)
        except (PolicyBundleError, ValueError, RecursionError) as exc:
            raise SpeedrunResultError("result store is not valid JSON") from exc
        if (
            not isinstance(document, dict)
            or document.get("schema") != STORE_SCHEMA
            or not isinstance(document.get("results"), dict)
            or not isinstance(document.get("digests"), dict)
        ):
            raise SpeedrunResultError("result store has the wrong shape")
        return document

    def _write(self, document: Mapping[str, Any]) -> None:
        data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        if len(data) > MAX_STORE_BYTES:
            raise SpeedrunResultError("result store is too large to write")
        tmp = self.path.with_name(f".{self.path.name}.{secrets.token_hex(8)}.tmp")
        fd = os.open(
            tmp,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        directory = os.open(
            self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def lookup(self, key: SpeedrunKey) -> dict[str, Any] | None:
        record = self._read()["results"].get(key.key_id)
        return dict(record) if isinstance(record, dict) else None

    def record(
        self,
        key: SpeedrunKey,
        verified: VerifiedBundle,
        *,
        score: int,
        now: datetime | None = None,
        rerun: bool = False,
    ) -> str:
        """Record a measured result. Returns ``recorded``, ``reused``, ``disputed``
        or ``resolved``.

        * same key, same digests: ``reused``, nothing is measured or changed;
        * same key, other or partly overlapping digests: ``disputed``, the first
          record and its score stay until a rerun resolves it;
        * ``rerun=True`` on a key: the rerun's result replaces the record and
          closes any dispute (``resolved``);
        * a digest already counted for a different key: refused.
        """

        if isinstance(score, bool) or not isinstance(score, int):
            raise SpeedrunResultError("score must be an integer")
        digests = list(verified.result_digests)
        stamp = (now or datetime.now(timezone.utc)).isoformat()
        with self._locked() as document:
            owners = document["digests"]
            for digest in digests:
                owner = owners.get(digest)
                if owner is not None and owner != key.key_id:
                    raise SpeedrunResultError(
                        "this verified run is already counted for another Speedrun key"
                    )
            results = document["results"]
            existing = results.get(key.key_id)
            if isinstance(existing, dict) and not rerun:
                if existing.get("result_digests") == digests:
                    return "reused"
                disputes = existing.setdefault("disputes", [])
                if digests not in [d.get("result_digests") for d in disputes]:
                    disputes.append({"result_digests": digests, "seen_at": stamp})
                self._write(document)
                return "disputed"
            if isinstance(existing, dict):
                for digest in existing.get("result_digests", []):
                    if owners.get(digest) == key.key_id:
                        del owners[digest]
            results[key.key_id] = {
                "key": key.fields(),
                "result_digests": digests,
                "measurement": verified.measurement,
                "binding_sha256": verified.binding_sha256,
                "score": score,
                "recorded_at": stamp,
                "disputes": [],
            }
            for digest in digests:
                owners[digest] = key.key_id
            self._write(document)
        return "resolved" if isinstance(existing, dict) else "recorded"


def decide(
    store: ResultStore,
    key: SpeedrunKey,
    *,
    disputed: bool = False,
    sample_seed: bytes | None = None,
    sample_rate_ppm: int = 0,
) -> str:
    """Whether to measure, reuse or rerun one Speedrun key.

    A key never seen is measured. A key already recorded is reused unless it
    has an open dispute (recorded in the store or raised by the caller) or the
    documented sample selects it. There is no standing rerun.
    """

    record = store.lookup(key)
    if record is None:
        return MEASURE
    if disputed or record.get("disputes"):
        return RERUN_DISPUTE
    if sample_rate_ppm:
        if sample_seed is None:
            raise SpeedrunResultError("a sample rate needs a sample seed")
        if sample_selected(key, seed=sample_seed, rate_ppm=sample_rate_ppm):
            return RERUN_SAMPLE
    return REUSE


def _key_from_options(options: argparse.Namespace) -> SpeedrunKey:
    return SpeedrunKey(
        entry_digest=options.entry_digest,
        model_digest=options.model_digest,
        harness_version=options.harness_version,
        room_size=options.room_size,
        round=options.round,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m cathedral_thin.independent_runtime.speedrun_results",
        description="Check a Speedrun evidence bundle offline and decide reuse.",
    )
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--entry-digest", required=True)
    parser.add_argument("--model-digest", required=True)
    parser.add_argument("--harness-version", required=True)
    parser.add_argument("--room-size", type=int, required=True)
    parser.add_argument("--round", type=int, required=True)
    parser.add_argument("--disputed", action="store_true")
    parser.add_argument("--sample-seed-hex")
    parser.add_argument("--sample-rate-ppm", type=int, default=0)
    parser.add_argument("--bundle", type=Path, help="verify and record this bundle")
    parser.add_argument("--trusted-keys-file", type=Path)
    parser.add_argument("--approved-measurement", action="append", default=[])
    parser.add_argument("--ctcli", default="ctcli", help="ctcli executable")
    parser.add_argument("--score", type=int)
    parser.add_argument("--rerun", action="store_true")
    options = parser.parse_args(argv)
    try:
        key = _key_from_options(options)
        store = ResultStore(options.store.resolve())
        seed = (
            bytes.fromhex(options.sample_seed_hex) if options.sample_seed_hex else None
        )
        answer: dict[str, Any] = {
            "key_id": key.key_id,
            "decision": decide(
                store,
                key,
                disputed=options.disputed,
                sample_seed=seed,
                sample_rate_ppm=options.sample_rate_ppm,
            ),
        }
        if options.bundle is not None:
            if options.trusted_keys_file is None or options.score is None:
                raise SpeedrunResultError(
                    "--bundle needs --trusted-keys-file and --score"
                )
            verified = verify_bundle_offline(
                options.bundle,
                trusted_keys_file=options.trusted_keys_file,
                approved_measurements=options.approved_measurement,
                ctcli=(options.ctcli,),
            )
            answer["result_digests"] = list(verified.result_digests)
            answer["stored"] = store.record(
                key, verified, score=options.score, rerun=options.rerun
            )
    except (SpeedrunResultError, ValueError) as exc:
        print(f"speedrun results: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(answer, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
