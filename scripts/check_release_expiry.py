#!/usr/bin/env python3
"""Fail before signed validator release metadata or the bootstrap expires.

Validators refuse expired signed metadata, and the installer refuses an
expired bootstrap manifest. Nothing re-signs either one automatically, so this
check reads what hosts and new installs actually read and fails loudly when
any of it expires within the warning window or has already expired:

- the stable and canary release metadata that the updater timers poll, at the
  URLs in deploy/validator-update/update.env.example
- the bootstrap manifest that scripts/install.sh downloads from its BASE
  release, which must match the digest that install.sh pins

This is an expiry alarm, not a trust decision. It does not verify signatures;
the updater and installer do that on the host. It reads only public data and
needs only the Python standard library.

Run from a checkout:

    python3 scripts/check_release_expiry.py

Exit 0 when everything stays valid for longer than the warning window. Exit 1
when anything expires within it, has expired, or cannot be read. The renewal
steps are in docs/RENEW_RELEASE_CHANNEL.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

# These mirror the host-side limits. The test suite asserts parity with the
# updater and the installer, so a limit change cannot silently drift here.
RELEASE_METADATA_SCHEMA = "cathedral_validator_release_v1"
MAX_RELEASE_METADATA_BYTES = 131_072
MAX_RELEASE_METADATA_LIFETIME_SECONDS = 14 * 24 * 60 * 60
BOOTSTRAP_SCHEMA = "cathedral_validator_updater_bootstrap_v3"
MAX_BOOTSTRAP_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_BOOTSTRAP_LIFETIME_SECONDS = 90 * 24 * 60 * 60

DEFAULT_WARN_DAYS = 5.0
RENEWAL_GUIDE = "docs/RENEW_RELEASE_CHANNEL.md"
MANIFEST_ASSET = "updater-bootstrap.manifest.json"
FETCH_ATTEMPTS = 3
FETCH_TIMEOUT_SECONDS = 30.0
_METADATA_URL_KEYS = {
    "stable": "CATHEDRAL_VALIDATOR_STABLE_METADATA_URL",
    "canary": "CATHEDRAL_VALIDATOR_CANARY_METADATA_URL",
}
_BASE_LINE = re.compile(r"^BASE=(https://\S+)$", re.MULTILINE)
_MANIFEST_PIN = re.compile(
    r"'([0-9a-f]{64})' \"\$BOOTSTRAP_DIR/" + re.escape(MANIFEST_ASSET) + r"\""
)


class CheckFailed(RuntimeError):
    """One artifact could not be read or does not have the expected shape."""


@dataclass(frozen=True)
class Expiry:
    artifact: str
    source: str
    sequence: int
    issued_unix: int
    expires_unix: int
    renewal: str


@dataclass(frozen=True)
class Finding:
    artifact: str
    ok: bool
    message: str


Fetcher = Callable[[str, int], bytes]


def _iso(unix: int) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _days(seconds: float) -> str:
    return f"{abs(seconds) / 86_400:.1f} days"


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise CheckFailed(f"{label} repeats key {key!r}")
            output[key] = value
        return output

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CheckFailed(f"{label} is not strict JSON") from exc
    if not isinstance(document, dict):
        raise CheckFailed(f"{label} is not a JSON object")
    return document


def _integer(value: object, *, label: str, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CheckFailed(f"{label} is not a positive integer")
    return value


def fetch_https(url: str, maximum: int) -> bytes:
    """Read one public HTTPS resource, bounded, with a few retries."""

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise CheckFailed(f"refusing a non-HTTPS source: {url}")
    request = urllib.request.Request(
        url, headers={"User-Agent": "cathedral-validator-release-expiry-check/1"}
    )
    last_error: Exception | None = None
    for attempt in range(FETCH_ATTEMPTS):
        try:
            with urllib.request.urlopen(
                request, timeout=FETCH_TIMEOUT_SECONDS
            ) as response:
                body = response.read(maximum + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt + 1 < FETCH_ATTEMPTS:
                time.sleep(2 * (attempt + 1))
            continue
        if len(body) > maximum:
            raise CheckFailed(f"{url} is larger than {maximum} bytes")
        return body
    raise CheckFailed(f"could not fetch {url}: {last_error}")


def read_source(source: str, maximum: int, *, fetcher: Fetcher = fetch_https) -> bytes:
    if source.startswith("https://"):
        return fetcher(source, maximum)
    path = Path(source)
    try:
        body = path.read_bytes()
    except OSError as exc:
        raise CheckFailed(f"cannot read {source}: {exc.strerror}") from exc
    if len(body) > maximum:
        raise CheckFailed(f"{source} is larger than {maximum} bytes")
    return body


def metadata_urls(update_env: Path) -> dict[str, str]:
    """Return the channel URLs installed updater timers poll."""

    values: dict[str, str] = {}
    for line in update_env.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    urls: dict[str, str] = {}
    for channel, key in _METADATA_URL_KEYS.items():
        url = values.get(key)
        if not url or not url.startswith("https://"):
            raise CheckFailed(f"{update_env} has no HTTPS {key}")
        urls[channel] = url
    return urls


def bootstrap_location(install_script: Path) -> tuple[str, str]:
    """Return the manifest URL install.sh downloads and the digest it pins."""

    text = install_script.read_text(encoding="utf-8")
    bases = _BASE_LINE.findall(text)
    pins = _MANIFEST_PIN.findall(text)
    if len(bases) != 1:
        raise CheckFailed(f"{install_script} does not have exactly one BASE= line")
    if len(pins) != 1:
        raise CheckFailed(
            f"{install_script} does not pin exactly one {MANIFEST_ASSET} digest"
        )
    return f"{bases[0]}/{MANIFEST_ASSET}", pins[0]


def release_expiry(raw: bytes, *, channel: str, source: str) -> Expiry:
    label = f"{channel} release metadata"
    if len(raw) > MAX_RELEASE_METADATA_BYTES:
        raise CheckFailed(f"{label} exceeds the updater's size limit")
    envelope = _strict_json(raw, label=label)
    signed = envelope.get("signed")
    if set(envelope) != {"signed", "signature"} or not isinstance(signed, dict):
        raise CheckFailed(f"{label} is not a signed envelope")
    if signed.get("schema") != RELEASE_METADATA_SCHEMA:
        raise CheckFailed(f"{label} has an unknown schema")
    if signed.get("channel") != channel:
        raise CheckFailed(f"{label} is for channel {signed.get('channel')!r}")
    sequence = _integer(signed.get("sequence"), label=f"{label} sequence")
    issued = _integer(signed.get("issued_unix"), label=f"{label} issue time")
    expires = _integer(signed.get("expires_unix"), label=f"{label} expiry")
    if expires <= issued or expires - issued > MAX_RELEASE_METADATA_LIFETIME_SECONDS:
        raise CheckFailed(
            f"{label} sequence {sequence} has a validity window the updater refuses"
        )
    return Expiry(
        artifact=label,
        source=source,
        sequence=sequence,
        issued_unix=issued,
        expires_unix=expires,
        renewal=f"re-sign it: {RENEWAL_GUIDE}, case (a)",
    )


def bootstrap_expiry(raw: bytes, *, source: str, pinned_sha256: str) -> Expiry:
    label = "updater bootstrap manifest"
    actual = hashlib.sha256(raw).hexdigest()
    if actual != pinned_sha256:
        raise CheckFailed(
            f"{label} at {source} has SHA-256 {actual}, but scripts/install.sh "
            f"pins {pinned_sha256}; every new install would fail"
        )
    if len(raw) > MAX_BOOTSTRAP_MANIFEST_BYTES:
        raise CheckFailed(f"{label} exceeds the installer's size limit")
    manifest = _strict_json(raw, label=label)
    if manifest.get("schema") != BOOTSTRAP_SCHEMA:
        raise CheckFailed(f"{label} has an unknown schema")
    metadata = manifest.get("bootstrap_metadata")
    if not isinstance(metadata, dict) or set(metadata) != {
        "expires_unix",
        "issued_unix",
        "sequence",
    }:
        raise CheckFailed(f"{label} has no bootstrap validity record")
    sequence = _integer(metadata["sequence"], label=f"{label} sequence")
    issued = _integer(metadata["issued_unix"], label=f"{label} issue time")
    expires = _integer(metadata["expires_unix"], label=f"{label} expiry")
    if expires <= issued or expires - issued > MAX_BOOTSTRAP_LIFETIME_SECONDS:
        raise CheckFailed(
            f"{label} sequence {sequence} has a validity window the installer refuses"
        )
    return Expiry(
        artifact=label,
        source=source,
        sequence=sequence,
        issued_unix=issued,
        expires_unix=expires,
        renewal=f"rebuild and re-sign it: {RENEWAL_GUIDE}, case (c)",
    )


def judge(expiry: Expiry, *, now_unix: int, warn_seconds: float) -> Finding:
    remaining = expiry.expires_unix - now_unix
    subject = f"{expiry.artifact} sequence {expiry.sequence}"
    when = _iso(expiry.expires_unix)
    if remaining <= 0:
        return Finding(
            expiry.artifact,
            False,
            f"EXPIRED: {subject} expired at {when}, {_days(remaining)} ago. "
            f"Hosts refuse it now; {expiry.renewal}.",
        )
    if remaining <= warn_seconds:
        return Finding(
            expiry.artifact,
            False,
            f"EXPIRES SOON: {subject} expires at {when}, in {_days(remaining)} "
            f"(alarm threshold {_days(warn_seconds)}); {expiry.renewal}.",
        )
    return Finding(
        expiry.artifact,
        True,
        f"OK: {subject} expires at {when}, in {_days(remaining)}.",
    )


def run_checks(
    *,
    stable: str,
    canary: str,
    bootstrap_manifest: str,
    pinned_manifest_sha256: str,
    now_unix: int,
    warn_seconds: float,
    fetcher: Fetcher = fetch_https,
) -> list[Finding]:
    findings: list[Finding] = []
    for channel, source in (("stable", stable), ("canary", canary)):
        artifact = f"{channel} release metadata"
        try:
            raw = read_source(source, MAX_RELEASE_METADATA_BYTES, fetcher=fetcher)
            expiry = release_expiry(raw, channel=channel, source=source)
        except CheckFailed as exc:
            findings.append(Finding(artifact, False, f"UNREADABLE: {exc}"))
            continue
        findings.append(judge(expiry, now_unix=now_unix, warn_seconds=warn_seconds))
    artifact = "updater bootstrap manifest"
    try:
        raw = read_source(
            bootstrap_manifest, MAX_BOOTSTRAP_MANIFEST_BYTES, fetcher=fetcher
        )
        expiry = bootstrap_expiry(
            raw, source=bootstrap_manifest, pinned_sha256=pinned_manifest_sha256
        )
    except CheckFailed as exc:
        findings.append(Finding(artifact, False, f"UNREADABLE: {exc}"))
    else:
        findings.append(judge(expiry, now_unix=now_unix, warn_seconds=warn_seconds))
    return findings


def _parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Fail when signed validator release metadata or the updater "
            "bootstrap expires soon"
        )
    )
    parser.add_argument(
        "--warn-days",
        type=float,
        default=DEFAULT_WARN_DAYS,
        help="fail when anything expires within this many days (default 5)",
    )
    parser.add_argument(
        "--update-env",
        type=Path,
        default=root / "deploy" / "validator-update" / "update.env.example",
        help="file naming the channel metadata URLs hosts poll",
    )
    parser.add_argument(
        "--install-script",
        type=Path,
        default=root / "scripts" / "install.sh",
        help="installer whose BASE release and manifest digest are checked",
    )
    parser.add_argument("--stable", help="stable metadata path or HTTPS URL")
    parser.add_argument("--canary", help="canary metadata path or HTTPS URL")
    parser.add_argument(
        "--bootstrap-manifest",
        help="bootstrap manifest path or HTTPS URL (default: from install.sh)",
    )
    parser.add_argument("--now-unix", type=int, help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None, *, fetcher: Fetcher = fetch_https) -> int:
    options = _parser().parse_args(argv)
    if not 0 <= options.warn_days <= 90:
        raise SystemExit("--warn-days must be between 0 and 90")
    try:
        urls = metadata_urls(options.update_env)
        manifest_url, pinned = bootstrap_location(options.install_script)
    except (CheckFailed, OSError) as exc:
        print(f"release expiry check could not start: {exc}", file=sys.stderr)
        return 1
    findings = run_checks(
        stable=options.stable or urls["stable"],
        canary=options.canary or urls["canary"],
        bootstrap_manifest=options.bootstrap_manifest or manifest_url,
        pinned_manifest_sha256=pinned,
        now_unix=int(time.time()) if options.now_unix is None else options.now_unix,
        warn_seconds=options.warn_days * 86_400,
        fetcher=fetcher,
    )
    annotate = os.environ.get("GITHUB_ACTIONS") == "true"
    for finding in findings:
        print(finding.message)
        if annotate and not finding.ok:
            title = f"{finding.artifact} expiry"
            print(f"::error title={title}::{finding.message}")
    failed = [finding for finding in findings if not finding.ok]
    if failed:
        print(
            f"release expiry check FAILED for {len(failed)} of {len(findings)} "
            f"artifacts; see {RENEWAL_GUIDE}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
