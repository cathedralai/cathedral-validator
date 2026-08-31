#!/usr/bin/env python3
"""Publish one already-signed validator release to the public GitHub channel.

The offline signer remains the authority.  This helper only enforces publication
ordering: immutable archive first, anonymous verification second, immutable
history third, and the mutable signed channel pointer last.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from cathedral_thin.independent_runtime.updater import (
    MAX_ARCHIVE_BYTES,
    UpdateRefused,
    load_pinned_public_key,
    parse_release_metadata,
)

DEFAULT_REPOSITORY = "cathedralai/cathedral-validator"
DEFAULT_CHANNEL_BRANCH = "validator-release-channel"
RELEASE_MANIFEST = "RELEASE.json"
RELEASE_BUNDLE_SCHEMA = "cathedral_validator_bundle_v2"
_REVISION = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class Publication:
    repository: str
    channel_branch: str
    channel: str
    sequence: int
    metadata: bytes
    metadata_sha256: str
    archive: bytes
    archive_sha256: str
    archive_url: str
    asset_name: str
    tag: str
    source_revision: str

    @property
    def history_path(self) -> str:
        return (
            f"validator/history/{self.channel}/"
            f"{self.sequence}-{self.metadata_sha256}.json"
        )

    @property
    def pointer_path(self) -> str:
        return f"validator/{self.channel}.json"


def _owner_file(path: Path, *, maximum: int, label: str) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise UpdateRefused(f"{label} path must be an absolute regular file")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise UpdateRefused(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not 1 <= metadata.st_size <= maximum
    ):
        raise UpdateRefused(f"{label} is not a bounded owner-controlled file")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise UpdateRefused(f"{label} is unreadable") from exc


def _release_manifest(archive: bytes) -> Mapping[str, Any]:
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            matches = [
                member
                for member in bundle.getmembers()
                if member.name == RELEASE_MANIFEST and member.isfile()
            ]
            if len(matches) != 1 or not 1 <= matches[0].size <= 65_536:
                raise UpdateRefused("release archive has no unique bounded manifest")
            extracted = bundle.extractfile(matches[0])
            if extracted is None:
                raise UpdateRefused("release archive manifest is unreadable")
            raw = extracted.read(65_537)
    except (OSError, EOFError, tarfile.TarError) as exc:
        raise UpdateRefused("release archive is unreadable") from exc
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateRefused("release archive manifest is invalid") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema") != RELEASE_BUNDLE_SCHEMA
    ):
        raise UpdateRefused("release archive manifest has the wrong schema")
    return document


def validate_publication(
    *,
    metadata_path: Path,
    archive_path: Path,
    public_key_path: Path,
    repository: str = DEFAULT_REPOSITORY,
    channel_branch: str = DEFAULT_CHANNEL_BRANCH,
    now_unix: int | None = None,
) -> Publication:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise UpdateRefused("GitHub repository is invalid")
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", channel_branch):
        raise UpdateRefused("release channel branch is invalid")
    try:
        metadata = _owner_file(
            metadata_path, maximum=1_048_576, label="release metadata"
        )
        archive = _owner_file(
            archive_path, maximum=MAX_ARCHIVE_BYTES, label="release archive"
        )
        envelope = json.loads(metadata.decode("ascii"))
        channel = envelope["signed"]["channel"]
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
    ) as exc:
        raise UpdateRefused("signed release inputs are unreadable") from exc
    if channel not in {"canary", "stable"}:
        raise UpdateRefused("signed release channel is invalid")
    release = parse_release_metadata(
        metadata,
        channel=channel,
        public_key=load_pinned_public_key(public_key_path, expected_uid=os.geteuid()),
        now_unix=int(time.time()) if now_unix is None else now_unix,
    )
    if not 1 <= len(archive) <= MAX_ARCHIVE_BYTES:
        raise UpdateRefused("release archive size is invalid")
    archive_sha256 = hashlib.sha256(archive).hexdigest()
    if archive_sha256 != release.archive_sha256:
        raise UpdateRefused("release archive does not match signed metadata")
    tag = f"validator-{archive_sha256}"
    asset_name = f"cathedral-validator-{archive_sha256}.tar.gz"
    expected_url = (
        f"https://github.com/{repository}/releases/download/{tag}/{asset_name}"
    )
    if release.archive_url != expected_url or archive_path.name != asset_name:
        raise UpdateRefused("release archive URL or filename is not content-addressed")
    manifest = _release_manifest(archive)
    source_revision = manifest.get("source_revision")
    if (
        not isinstance(source_revision, str)
        or _REVISION.fullmatch(source_revision) is None
    ):
        raise UpdateRefused("release source revision is invalid")
    return Publication(
        repository=repository,
        channel_branch=channel_branch,
        channel=channel,
        sequence=release.sequence,
        metadata=metadata,
        metadata_sha256=hashlib.sha256(metadata).hexdigest(),
        archive=archive,
        archive_sha256=archive_sha256,
        archive_url=expected_url,
        asset_name=asset_name,
        tag=tag,
        source_revision=source_revision,
    )


class GitHub:
    def __init__(self, repository: str) -> None:
        self.repository = repository

    def _run(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        allow_missing: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            ["gh", *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0 and not allow_missing:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise UpdateRefused(f"GitHub publication failed: {message[:500]}")
        return result

    def api(
        self,
        endpoint: str,
        *,
        method: str = "GET",
        payload: Mapping[str, Any] | None = None,
        allow_missing: bool = False,
    ) -> Mapping[str, Any] | None:
        arguments = ["api", f"repos/{self.repository}/{endpoint}"]
        if method != "GET":
            arguments.extend(["--method", method])
        body = None
        if payload is not None:
            arguments.extend(["--input", "-"])
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        result = self._run(arguments, input_bytes=body, allow_missing=allow_missing)
        if result.returncode != 0:
            return None
        try:
            decoded = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateRefused("GitHub returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise UpdateRefused("GitHub returned an unexpected response")
        return decoded

    def ensure_release(self, publication: Publication, archive_path: Path) -> None:
        existing = self.api(f"releases/tags/{publication.tag}", allow_missing=True)
        if existing is None:
            notes = (
                "Cathedral validator release candidate.\n\n"
                f"Source commit: `{publication.source_revision}`\n"
                f"Archive SHA-256: `{publication.archive_sha256}`\n"
                f"Channel sequence: `{publication.channel} {publication.sequence}`\n\n"
                "This release is available to the signed updater channel. It does "
                "not by itself prove a successful validator cycle or chain write.\n"
            ).encode("utf-8")
            self._run(
                [
                    "release",
                    "create",
                    publication.tag,
                    str(archive_path),
                    "--repo",
                    publication.repository,
                    "--target",
                    publication.source_revision,
                    "--title",
                    publication.tag,
                    "--notes-file",
                    "-",
                    "--prerelease",
                ],
                input_bytes=notes,
            )
            return
        assets = existing.get("assets")
        if not isinstance(assets, list):
            raise UpdateRefused("existing GitHub release has invalid assets")
        names = [asset.get("name") for asset in assets if isinstance(asset, dict)]
        if publication.asset_name not in names:
            self._run(
                [
                    "release",
                    "upload",
                    publication.tag,
                    str(archive_path),
                    "--repo",
                    publication.repository,
                ]
            )

    def ensure_branch(self, publication: Publication) -> None:
        encoded = urllib.parse.quote(publication.channel_branch, safe="")
        existing = self.api(f"git/ref/heads/{encoded}", allow_missing=True)
        if existing is not None:
            return
        self.api(
            "git/refs",
            method="POST",
            payload={
                "ref": f"refs/heads/{publication.channel_branch}",
                "sha": publication.source_revision,
            },
        )

    def read_content(self, path: str, branch: str) -> tuple[str, bytes] | None:
        encoded_path = urllib.parse.quote(path, safe="/")
        encoded_branch = urllib.parse.quote(branch, safe="")
        existing = self.api(
            f"contents/{encoded_path}?ref={encoded_branch}", allow_missing=True
        )
        if existing is None:
            return None
        sha = existing.get("sha")
        content = existing.get("content")
        encoding = existing.get("encoding")
        if (
            not isinstance(sha, str)
            or not isinstance(content, str)
            or encoding != "base64"
        ):
            raise UpdateRefused("GitHub channel object is invalid")
        try:
            return sha, base64.b64decode(content, validate=False)
        except ValueError as exc:
            raise UpdateRefused("GitHub channel object is not valid base64") from exc

    def write_content(
        self,
        *,
        path: str,
        branch: str,
        body: bytes,
        message: str,
        existing_sha: str | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(body).decode("ascii"),
            "branch": branch,
        }
        if existing_sha is not None:
            payload["sha"] = existing_sha
        self.api(
            f"contents/{urllib.parse.quote(path, safe='/')}",
            method="PUT",
            payload=payload,
        )


def _parse_existing_sequence(
    raw: bytes, *, channel: str, public_key_path: Path
) -> tuple[int, str]:
    try:
        envelope = json.loads(raw.decode("ascii"))
        issued = envelope["signed"]["issued_unix"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise UpdateRefused("existing channel pointer is invalid") from exc
    if isinstance(issued, bool) or not isinstance(issued, int):
        raise UpdateRefused("existing channel issue time is invalid")
    release = parse_release_metadata(
        raw,
        channel=channel,
        public_key=load_pinned_public_key(public_key_path, expected_uid=os.geteuid()),
        now_unix=issued,
    )
    return release.sequence, hashlib.sha256(raw).hexdigest()


def _anonymous_fetch(url: str, *, maximum: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cathedral-validator-release-publisher/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status != 200:
                raise UpdateRefused(
                    "anonymous release download did not return HTTP 200"
                )
            body = response.read(maximum + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise UpdateRefused("anonymous release download failed") from exc
    if len(body) > maximum:
        raise UpdateRefused("anonymous release download exceeds its bound")
    return body


def publish(
    publication: Publication,
    *,
    archive_path: Path,
    public_key_path: Path,
    github: GitHub,
) -> None:
    github.ensure_release(publication, archive_path)
    downloaded = _anonymous_fetch(publication.archive_url, maximum=MAX_ARCHIVE_BYTES)
    if hashlib.sha256(downloaded).hexdigest() != publication.archive_sha256:
        raise UpdateRefused("anonymous GitHub archive does not match the signed digest")
    github.ensure_branch(publication)

    pointer = github.read_content(publication.pointer_path, publication.channel_branch)
    pointer_sha = None
    pointer_identical = False
    if pointer is not None:
        pointer_sha, pointer_body = pointer
        if pointer_body == publication.metadata:
            pointer_identical = True
        else:
            old_sequence, old_digest = _parse_existing_sequence(
                pointer_body,
                channel=publication.channel,
                public_key_path=public_key_path,
            )
            if publication.sequence <= old_sequence:
                raise UpdateRefused(
                    "channel pointer does not advance its signed sequence "
                    f"(current {old_sequence} {old_digest})"
                )

    history = github.read_content(publication.history_path, publication.channel_branch)
    if history is None:
        github.write_content(
            path=publication.history_path,
            branch=publication.channel_branch,
            body=publication.metadata,
            message=(
                f"release({publication.channel}): retain sequence "
                f"{publication.sequence}"
            ),
        )
    elif history[1] != publication.metadata:
        raise UpdateRefused("immutable release history path already has other bytes")

    if not pointer_identical:
        github.write_content(
            path=publication.pointer_path,
            branch=publication.channel_branch,
            body=publication.metadata,
            message=(
                f"release({publication.channel}): point to sequence "
                f"{publication.sequence}"
            ),
            existing_sha=pointer_sha,
        )
    raw_url = (
        f"https://raw.githubusercontent.com/{publication.repository}/"
        f"{publication.channel_branch}/{publication.pointer_path}"
    )
    if _anonymous_fetch(raw_url, maximum=1_048_576) != publication.metadata:
        raise UpdateRefused(
            "anonymous channel pointer does not match published metadata"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Publish an offline-signed Cathedral validator release"
    )
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--channel-branch", default=DEFAULT_CHANNEL_BRANCH)
    parser.add_argument(
        "--publish",
        action="store_true",
        help="perform GitHub writes; omission validates and prints the exact plan",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        publication = validate_publication(
            metadata_path=options.metadata,
            archive_path=options.archive,
            public_key_path=options.public_key,
            repository=options.repository,
            channel_branch=options.channel_branch,
        )
        if options.publish:
            publish(
                publication,
                archive_path=options.archive,
                public_key_path=options.public_key,
                github=GitHub(publication.repository),
            )
            status = "PUBLISHED"
        else:
            status = "VALIDATED_NO_WRITE"
    except (OSError, UpdateRefused, ValueError) as exc:
        raise SystemExit(f"release publication refused: {exc}") from exc
    print(
        f"CATHEDRAL_VALIDATOR_RELEASE_{status} "
        f"channel={publication.channel} sequence={publication.sequence} "
        f"archive_sha256={publication.archive_sha256} "
        f"metadata_sha256={publication.metadata_sha256}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
