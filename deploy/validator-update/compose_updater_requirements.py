#!/usr/bin/env python3
"""Bind reviewed updater dependencies to one reproducible local project wheel."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from packaging.utils import canonicalize_name, parse_wheel_filename


EXPECTED_THIRD_PARTY = {
    "cffi": "2.1.1",
    "cryptography": "50.0.1",
    "pycparser": "3.0",
}
PROJECT_NAME = "cathedral-scaffold"
_LOCKED_REQUIREMENT = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*) "
    r"--hash=sha256:(?P<digest>[0-9a-f]{64})"
)


class LockCompositionRefused(RuntimeError):
    """The retained updater inputs do not match the reviewed dependency lock."""


def _third_party_lock(path: Path) -> tuple[bytes, dict[str, tuple[str, str]]]:
    raw = path.read_bytes()
    if not raw or len(raw) > 65_536 or not raw.endswith(b"\n"):
        raise LockCompositionRefused(
            "third-party lock must be non-empty, bounded, and newline-terminated"
        )
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise LockCompositionRefused("third-party lock must be ASCII") from exc

    records: dict[str, tuple[str, str]] = {}
    for physical in text.splitlines():
        line = physical.strip()
        if not line or line.startswith("#"):
            continue
        match = _LOCKED_REQUIREMENT.fullmatch(line)
        if match is None:
            raise LockCompositionRefused(
                "third-party lock must contain exact pins and one SHA-256 per line"
            )
        name = canonicalize_name(match.group("name"))
        if name in records:
            raise LockCompositionRefused("third-party lock repeats a package")
        records[name] = (match.group("version"), match.group("digest"))

    actual = {name: version for name, (version, _digest) in records.items()}
    if actual != EXPECTED_THIRD_PARTY:
        raise LockCompositionRefused(
            "third-party lock does not contain the exact updater dependency closure"
        )
    return raw, records


def compose_lock(
    *,
    wheelhouse: Path,
    third_party_lock: Path,
    output: Path,
) -> bytes:
    """Verify the exact four-wheel closure and create its complete hash lock."""

    committed, reviewed = _third_party_lock(third_party_lock)
    wheels: dict[str, tuple[str, str]] = {}
    entries = sorted(wheelhouse.iterdir(), key=lambda item: item.name)
    if len(entries) != 4 or any(not item.is_file() for item in entries):
        raise LockCompositionRefused("updater wheelhouse must contain four files")
    for wheel in entries:
        if wheel.suffix != ".whl":
            raise LockCompositionRefused("updater wheelhouse must contain only wheels")
        try:
            name, version, _build, _tags = parse_wheel_filename(wheel.name)
        except ValueError as exc:
            raise LockCompositionRefused("updater wheel filename is invalid") from exc
        canonical_name = canonicalize_name(name)
        if canonical_name in wheels:
            raise LockCompositionRefused(
                "updater wheelhouse does not contain four unique wheels"
            )
        wheels[canonical_name] = (
            str(version),
            hashlib.sha256(wheel.read_bytes()).hexdigest(),
        )

    expected_names = set(EXPECTED_THIRD_PARTY) | {PROJECT_NAME}
    if set(wheels) != expected_names:
        raise LockCompositionRefused(
            "updater wheelhouse does not contain the exact updater dependency closure"
        )
    for name, expected in reviewed.items():
        if wheels[name] != expected:
            raise LockCompositionRefused(
                f"updater wheel for {name} differs from the committed lock"
            )

    project_version, project_digest = wheels[PROJECT_NAME]
    body = committed + (
        f"{PROJECT_NAME}=={project_version} --hash=sha256:{project_digest}\n"
    ).encode("ascii")
    try:
        with output.open("xb") as handle:
            handle.write(body)
    except FileExistsError as exc:
        raise LockCompositionRefused("output lock already exists") from exc
    return body


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compose a reviewed updater lock with the local project wheel"
    )
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--third-party-lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        compose_lock(
            wheelhouse=options.wheelhouse,
            third_party_lock=options.third_party_lock,
            output=options.output,
        )
    except (LockCompositionRefused, OSError) as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
