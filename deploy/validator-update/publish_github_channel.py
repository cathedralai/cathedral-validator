#!/usr/bin/env python3
"""Publish one already-signed validator release to the public GitHub channel.

The offline signer remains the authority.  This helper only enforces publication
ordering: immutable archive first, anonymous verification second, immutable
history third, and the mutable signed channel pointer last.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

# The maintainer guide invokes this file directly from a clean checkout. Bind
# imports to that exact checkout rather than an editable install or PYTHONPATH.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if not (_REPOSITORY_ROOT / "cathedral_thin" / "__init__.py").is_file():
    raise RuntimeError("Cathedral repository root is unavailable")
sys.path.insert(0, str(_REPOSITORY_ROOT))

from cathedral_thin.independent_runtime.updater import (  # noqa: E402
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
_NOT_FOUND = re.compile(r"(?:HTTP 404|404 Not Found)", re.IGNORECASE)
_RELEASE_PAGE_SIZE = 100
_RELEASE_MAX_PAGES = 10


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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise UpdateRefused(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 1 <= before.st_size <= maximum
        ):
            raise UpdateRefused(f"{label} is not a bounded owner-controlled file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(body) != before.st_size
            or len(body) > maximum
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise UpdateRefused(f"{label} changed while it was read")
        return body
    finally:
        os.close(descriptor)


def _safe_repository(repository: str) -> str:
    component = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?")
    parts = repository.split("/")
    if (
        len(parts) != 2
        or any(component.fullmatch(part) is None for part in parts)
        or any(part in {".", ".."} or part.endswith(".git") for part in parts)
    ):
        raise UpdateRefused("GitHub repository is invalid")
    return repository


def _safe_branch(branch: str) -> str:
    parts = branch.split("/")
    if (
        not 1 <= len(branch) <= 200
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", branch) is None
        or ".." in branch
        or "@{" in branch
        or branch.endswith((".", "/", ".lock"))
        or any(part in {"", ".", ".."} or part.startswith(".") for part in parts)
    ):
        raise UpdateRefused("release channel branch is invalid")
    return branch


def _safe_tag(tag: str) -> str:
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", tag) is None
        or ".." in tag
        or tag.endswith((".", ".lock"))
    ):
        raise UpdateRefused("GitHub release tag is invalid")
    return tag


def _write_staged(path: Path, body: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    try:
        os.fchmod(descriptor, 0o400)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


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
    repository = _safe_repository(repository)
    channel_branch = _safe_branch(channel_branch)
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
        self.repository = _safe_repository(repository)

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
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            if allow_missing and _NOT_FOUND.search(message):
                return result
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
        resource = f"repos/{self.repository}"
        if endpoint:
            resource = f"{resource}/{endpoint}"
        arguments = ["api", resource]
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

    def require_immutable_releases(self) -> None:
        repository = self.api("")
        if repository is None or repository.get("private") is not False:
            raise UpdateRefused("GitHub release repository is not public")
        setting = self.api("immutable-releases", allow_missing=True)
        if setting is None or setting.get("enabled") is not True:
            raise UpdateRefused("GitHub repository does not enforce immutable releases")

    def release_by_id(self, release_id: int) -> Mapping[str, Any]:
        if (
            isinstance(release_id, bool)
            or not isinstance(release_id, int)
            or not 1 <= release_id <= 2**63 - 1
        ):
            raise UpdateRefused("GitHub release identifier is invalid")
        release = self.api(f"releases/{release_id}")
        if release is None:
            raise UpdateRefused("GitHub release is unavailable")
        return release

    def release(self, tag: str) -> Mapping[str, Any] | None:
        tag = _safe_tag(tag)
        matches: list[int] = []
        exhausted = False
        for page in range(1, _RELEASE_MAX_PAGES + 1):
            result = self._run(
                [
                    "api",
                    f"repos/{self.repository}/releases"
                    f"?per_page={_RELEASE_PAGE_SIZE}&page={page}",
                ]
            )
            try:
                records = json.loads(result.stdout.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise UpdateRefused("GitHub returned an invalid release list") from exc
            if not isinstance(records, list):
                raise UpdateRefused("GitHub returned an unexpected release list")
            for record in records:
                if not isinstance(record, dict):
                    raise UpdateRefused(
                        "GitHub release list contains an invalid record"
                    )
                if record.get("tag_name") != tag:
                    continue
                release_id = record.get("id")
                if (
                    isinstance(release_id, bool)
                    or not isinstance(release_id, int)
                    or not 1 <= release_id <= 2**63 - 1
                ):
                    raise UpdateRefused("GitHub release identifier is invalid")
                matches.append(release_id)
            if len(records) < _RELEASE_PAGE_SIZE:
                exhausted = True
                break
        if not exhausted:
            raise UpdateRefused("GitHub release search exceeded its safe bound")
        if len(matches) > 1:
            raise UpdateRefused("GitHub has duplicate releases for the exact tag")
        if not matches:
            return None
        return self.release_by_id(matches[0])

    def tag_ref(
        self, tag: str, *, allow_missing: bool = False
    ) -> Mapping[str, Any] | None:
        tag = _safe_tag(tag)
        encoded = urllib.parse.quote(tag, safe="")
        return self.api(f"git/ref/tags/{encoded}", allow_missing=allow_missing)

    def create_release_draft(self, publication: Publication) -> Mapping[str, Any]:
        notes = (
            "Cathedral validator release candidate.\n\n"
            f"Source commit: `{publication.source_revision}`\n"
            f"Archive SHA-256: `{publication.archive_sha256}`\n"
            f"Channel sequence: `{publication.channel} {publication.sequence}`\n\n"
            "This release is available to the signed updater channel. It does "
            "not by itself prove a successful validator cycle or chain write.\n"
        )
        draft = self.api(
            "releases",
            method="POST",
            payload={
                "tag_name": publication.tag,
                "target_commitish": publication.source_revision,
                "name": publication.tag,
                "body": notes,
                "draft": True,
                "prerelease": True,
                "make_latest": "false",
            },
        )
        if draft is None:
            raise UpdateRefused("new GitHub release draft is unavailable")
        return draft

    def upload_release_asset(
        self, publication: Publication, archive_path: Path
    ) -> None:
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

    def publish_release(
        self, publication: Publication, release_id: int
    ) -> Mapping[str, Any]:
        published = self.api(
            f"releases/{release_id}",
            method="PATCH",
            payload={
                "draft": False,
                "prerelease": True,
                "make_latest": "false",
            },
        )
        if published is None:
            raise UpdateRefused("published GitHub release is unavailable")
        return published

    def ensure_release(self, publication: Publication) -> None:
        self.require_immutable_releases()
        existing = self.release(publication.tag)
        if existing is None:
            if self.tag_ref(publication.tag, allow_missing=True) is not None:
                raise UpdateRefused(
                    "GitHub release tag exists without the exact immutable release"
                )
            existing = self.create_release_draft(publication)
        if existing.get("draft") is True:
            release_id = _release_id(existing)
            records = existing.get("assets")
            if records == []:
                _verify_release_record(publication, existing, draft=True, asset=False)
                with tempfile.TemporaryDirectory(
                    prefix="cathedral-validator-release-"
                ) as raw:
                    root = Path(raw)
                    os.chmod(root, 0o700)
                    archive_path = root / publication.asset_name
                    _write_staged(archive_path, publication.archive)
                    self.upload_release_asset(publication, archive_path)
                existing = self.release_by_id(release_id)
            _verify_release_record(publication, existing, draft=True, asset=True)
            self.publish_release(publication, release_id)
            existing = self.release_by_id(release_id)
        _verify_release_record(publication, existing, draft=False, asset=True)
        ref = self.tag_ref(publication.tag)
        if ref is None:
            raise UpdateRefused("published GitHub release tag is unavailable")
        _verify_release_tag(publication, ref)

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
            if "\r" in content:
                raise ValueError("unsupported base64 line ending")
            return sha, base64.b64decode(content.replace("\n", ""), validate=True)
        except (ValueError, binascii.Error) as exc:
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


def _verify_release_record(
    publication: Publication,
    release: Mapping[str, Any],
    *,
    draft: bool,
    asset: bool,
) -> None:
    expected_immutable = not draft
    if (
        release.get("tag_name") != publication.tag
        or release.get("name") != publication.tag
        or release.get("target_commitish") != publication.source_revision
        or release.get("draft") is not draft
        or release.get("prerelease") is not True
        or release.get("immutable") is not expected_immutable
    ):
        raise UpdateRefused(
            "existing GitHub release differs from the exact publication plan"
        )
    records = release.get("assets")
    if not asset:
        if records != []:
            raise UpdateRefused("new GitHub release draft is not empty")
        return
    if not isinstance(records, list) or len(records) != 1:
        raise UpdateRefused("GitHub release does not contain the exact asset set")
    record = records[0]
    if not isinstance(record, dict):
        raise UpdateRefused("GitHub release asset is invalid")
    if (
        record.get("name") != publication.asset_name
        or record.get("state") != "uploaded"
        or record.get("size") != len(publication.archive)
        or record.get("digest") != f"sha256:{publication.archive_sha256}"
        or record.get("browser_download_url") != publication.archive_url
    ):
        raise UpdateRefused("GitHub release asset differs from the signed archive")


def _release_id(release: Mapping[str, Any]) -> int:
    release_id = release.get("id")
    if (
        isinstance(release_id, bool)
        or not isinstance(release_id, int)
        or not 1 <= release_id <= 2**63 - 1
    ):
        raise UpdateRefused("GitHub release identifier is invalid")
    return release_id


def _verify_release_tag(publication: Publication, ref: Mapping[str, Any]) -> None:
    tag_object = ref.get("object")
    if (
        not isinstance(tag_object, dict)
        or tag_object.get("type") != "commit"
        or tag_object.get("sha") != publication.source_revision
    ):
        raise UpdateRefused("GitHub release tag does not bind the source revision")


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
    public_key_path: Path,
    github: GitHub,
) -> None:
    github.ensure_release(publication)
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
    encoded_branch = urllib.parse.quote(publication.channel_branch, safe="")
    raw_url = (
        f"https://raw.githubusercontent.com/{publication.repository}/"
        f"{encoded_branch}/{publication.pointer_path}"
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
