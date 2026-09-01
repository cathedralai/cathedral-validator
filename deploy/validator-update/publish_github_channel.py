#!/usr/bin/env python3
"""Publish one already-signed validator release to the public GitHub channel.

The offline signer remains the authority. This helper enforces publication
ordering: immutable archive first, anonymous archive verification second,
atomic signed history and pointer commit third, and anonymous pointer
verification last.
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
from typing import Any, Callable, Mapping, Sequence

# The maintainer guide invokes this file directly from a clean checkout. Bind
# imports to that exact checkout rather than an editable install or PYTHONPATH.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if not (_REPOSITORY_ROOT / "cathedral_thin" / "__init__.py").is_file():
    raise RuntimeError("Cathedral repository root is unavailable")
sys.path.insert(0, str(_REPOSITORY_ROOT))

from cathedral_thin.independent_runtime.updater import (  # noqa: E402
    MAX_ARCHIVE_BYTES,
    MAX_METADATA_BYTES,
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
_DRAFT_ASSET_TOKEN = re.compile(r"untagged-[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
_RELEASE_PAGE_SIZE = 100
_RELEASE_MAX_PAGES = 10
_HISTORY_NAME = re.compile(r"([1-9][0-9]{0,18})-([0-9a-f]{64})\.json")
_MAX_HISTORY_RECORDS = 1_000
_RAW_POINTER_CACHE_MAX_AGE_SECONDS = 300.0
_RAW_POINTER_CACHE_SAFETY_MARGIN_SECONDS = 60.0
_MUTABLE_POINTER_MINIMUM_OBSERVATION_SECONDS = (
    _RAW_POINTER_CACHE_MAX_AGE_SECONDS + _RAW_POINTER_CACHE_SAFETY_MARGIN_SECONDS
)
_POINTER_VERIFY_RETRY_SECONDS = 5.0
_POINTER_VERIFY_REQUEST_SECONDS = 5.0
_POINTER_VERIFY_DEADLINE_SECONDS = (
    _MUTABLE_POINTER_MINIMUM_OBSERVATION_SECONDS
    + _POINTER_VERIFY_RETRY_SECONDS
    + _POINTER_VERIFY_REQUEST_SECONDS
)
_POINTER_VERIFY_ATTEMPTS = (
    int(_POINTER_VERIFY_DEADLINE_SECONDS / _POINTER_VERIFY_RETRY_SECONDS) + 1
)
_PINNED_POINTER_VERIFY_ATTEMPTS = 31
_PINNED_POINTER_VERIFY_DEADLINE_SECONDS = 60.0
_PINNED_POINTER_VERIFY_RETRY_SECONDS = 2.0
_POINTER_PUBLICATION_SAFETY_SECONDS = 30
_MIN_POINTER_VERIFICATION_REMAINING_SECONDS = int(
    _PINNED_POINTER_VERIFY_DEADLINE_SECONDS
    + _POINTER_VERIFY_DEADLINE_SECONDS
    + _POINTER_PUBLICATION_SAFETY_SECONDS
)
_PUBLICATION_OPERATION_SAFETY_SECONDS = 300
_MIN_PUBLICATION_REMAINING_SECONDS = int(
    _MIN_POINTER_VERIFICATION_REMAINING_SECONDS + _PUBLICATION_OPERATION_SAFETY_SECONDS
)


@dataclass(frozen=True)
class Publication:
    repository: str
    channel_branch: str
    channel: str
    sequence: int
    expires_unix: int
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
    def history_root(self) -> str:
        return f"validator/history/{self.channel}"

    @property
    def pointer_path(self) -> str:
        return f"validator/{self.channel}.json"


@dataclass(frozen=True)
class ChannelObject:
    path: str
    sha: str
    size: int


@dataclass(frozen=True)
class ChannelBranch:
    created: bool
    revision: str


@dataclass(frozen=True)
class RetainedHistory:
    sequence: int
    metadata_sha256: str


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
    observed_now = int(time.time()) if now_unix is None else now_unix
    release = parse_release_metadata(
        metadata,
        channel=channel,
        public_key=load_pinned_public_key(public_key_path, expected_uid=os.geteuid()),
        now_unix=observed_now,
    )
    if release.expires_unix - observed_now <= _MIN_PUBLICATION_REMAINING_SECONDS:
        remaining = release.expires_unix - observed_now
        raise UpdateRefused(
            "signed release lacks required publication headroom "
            f"(remaining_seconds={remaining}, "
            f"required_seconds>{_MIN_PUBLICATION_REMAINING_SECONDS})"
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
        expires_unix=release.expires_unix,
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

    def api_records(
        self, endpoint: str, *, allow_missing: bool = False
    ) -> tuple[Mapping[str, Any], ...] | None:
        result = self._run(
            ["api", f"repos/{self.repository}/{endpoint}"],
            allow_missing=allow_missing,
        )
        if result.returncode != 0:
            return None
        try:
            decoded = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateRefused("GitHub returned invalid JSON") from exc
        if not isinstance(decoded, list) or any(
            not isinstance(record, dict) for record in decoded
        ):
            raise UpdateRefused("GitHub returned an unexpected record list")
        return tuple(decoded)

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

    def ensure_branch(self, publication: Publication) -> ChannelBranch:
        encoded = urllib.parse.quote(publication.channel_branch, safe="")
        existing = self.api(f"git/ref/heads/{encoded}", allow_missing=True)
        if existing is not None:
            return ChannelBranch(created=False, revision=_branch_revision(existing))
        created = self.api(
            "git/refs",
            method="POST",
            payload={
                "ref": f"refs/heads/{publication.channel_branch}",
                "sha": publication.source_revision,
            },
        )
        if created is None:
            raise UpdateRefused("created GitHub channel branch is unavailable")
        revision = _branch_revision(created)
        if revision != publication.source_revision:
            raise UpdateRefused("created GitHub channel branch has the wrong revision")
        return ChannelBranch(created=True, revision=revision)

    def list_channel_objects(
        self, path: str, branch: str
    ) -> tuple[ChannelObject, ...] | None:
        encoded_path = urllib.parse.quote(path, safe="/")
        encoded_branch = urllib.parse.quote(_safe_branch(branch), safe="")
        records = self.api_records(
            f"contents/{encoded_path}?ref={encoded_branch}", allow_missing=True
        )
        if records is None:
            return None
        if len(records) >= _MAX_HISTORY_RECORDS:
            raise UpdateRefused("GitHub channel history exceeds its safe bound")
        objects: list[ChannelObject] = []
        observed: set[str] = set()
        for record in records:
            record_path = record.get("path")
            name = record.get("name")
            sha = record.get("sha")
            size = record.get("size")
            if (
                record.get("type") != "file"
                or not isinstance(record_path, str)
                or not isinstance(name, str)
                or not name
                or "/" in name
                or record_path != f"{path}/{name}"
                or record_path in observed
                or not isinstance(sha, str)
                or _REVISION.fullmatch(sha) is None
                or isinstance(size, bool)
                or not isinstance(size, int)
                or not 1 <= size <= MAX_METADATA_BYTES
            ):
                raise UpdateRefused("GitHub channel history record is invalid")
            observed.add(record_path)
            objects.append(ChannelObject(path=record_path, sha=sha, size=size))
        return tuple(sorted(objects, key=lambda item: item.path))

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

    def commit_channel(self, publication: Publication, *, base_revision: str) -> str:
        base = self.api(f"git/commits/{base_revision}")
        if base is None or _record_sha(base, label="base commit") != base_revision:
            raise UpdateRefused("GitHub channel base commit is unavailable")
        base_tree = base.get("tree")
        if not isinstance(base_tree, dict):
            raise UpdateRefused("GitHub channel base tree is unavailable")
        base_tree_sha = _record_sha(base_tree, label="base tree")

        blob = self.api(
            "git/blobs",
            method="POST",
            payload={
                "content": base64.b64encode(publication.metadata).decode("ascii"),
                "encoding": "base64",
            },
        )
        if blob is None:
            raise UpdateRefused("GitHub channel metadata blob is unavailable")
        blob_sha = _record_sha(blob, label="metadata blob")
        tree = self.api(
            "git/trees",
            method="POST",
            payload={
                "base_tree": base_tree_sha,
                "tree": [
                    {
                        "path": publication.history_path,
                        "mode": "100644",
                        "type": "blob",
                        "sha": blob_sha,
                    },
                    {
                        "path": publication.pointer_path,
                        "mode": "100644",
                        "type": "blob",
                        "sha": blob_sha,
                    },
                ],
            },
        )
        if tree is None:
            raise UpdateRefused("GitHub channel release tree is unavailable")
        tree_sha = _record_sha(tree, label="release tree")
        commit = self.api(
            "git/commits",
            method="POST",
            payload={
                "message": (
                    f"release({publication.channel}): retain and point to "
                    f"sequence {publication.sequence}"
                ),
                "tree": tree_sha,
                "parents": [base_revision],
            },
        )
        if commit is None:
            raise UpdateRefused("GitHub channel release commit is unavailable")
        commit_sha = _record_sha(commit, label="release commit")
        encoded = urllib.parse.quote(publication.channel_branch, safe="")
        updated = self.api(
            f"git/refs/heads/{encoded}",
            method="PATCH",
            payload={"sha": commit_sha, "force": False},
        )
        if updated is None or _branch_revision(updated) != commit_sha:
            raise UpdateRefused("GitHub channel branch update is unconfirmed")
        return commit_sha


def _branch_revision(ref: Mapping[str, Any]) -> str:
    target = ref.get("object")
    if (
        not isinstance(target, dict)
        or target.get("type") != "commit"
        or not isinstance(target.get("sha"), str)
        or _REVISION.fullmatch(target["sha"]) is None
    ):
        raise UpdateRefused("GitHub channel branch target is invalid")
    return target["sha"]


def _record_sha(record: Mapping[str, Any], *, label: str) -> str:
    sha = record.get("sha")
    if not isinstance(sha, str) or _REVISION.fullmatch(sha) is None:
        raise UpdateRefused(f"GitHub channel {label} is invalid")
    return sha


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
    ):
        raise UpdateRefused("GitHub release asset differs from the signed archive")
    url = record.get("browser_download_url")
    if draft:
        if not _safe_draft_asset_url(publication, url):
            raise UpdateRefused("GitHub release draft asset URL differs")
    elif url != publication.archive_url:
        raise UpdateRefused("GitHub release asset differs from the signed archive")


def _safe_draft_asset_url(publication: Publication, value: object) -> bool:
    """Accept GitHub's draft-only untagged asset identity, not a redirect."""
    if not isinstance(value, str):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or hostname != "github.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return False
    prefix = f"/{publication.repository}/releases/download/"
    if not parsed.path.startswith(prefix):
        return False
    token, separator, name = parsed.path[len(prefix) :].partition("/")
    return (
        separator == "/"
        and name == publication.asset_name
        and _DRAFT_ASSET_TOKEN.fullmatch(token) is not None
        and ".." not in token
    )


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
    raw: bytes, *, channel: str, public_key_path: Path, label: str = "pointer"
) -> tuple[int, str]:
    try:
        envelope = json.loads(raw.decode("ascii"))
        issued = envelope["signed"]["issued_unix"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise UpdateRefused(f"existing channel {label} is invalid") from exc
    if isinstance(issued, bool) or not isinstance(issued, int):
        raise UpdateRefused(f"existing channel {label} issue time is invalid")
    release = parse_release_metadata(
        raw,
        channel=channel,
        public_key=load_pinned_public_key(public_key_path, expected_uid=os.geteuid()),
        now_unix=issued,
    )
    return release.sequence, hashlib.sha256(raw).hexdigest()


def _retained_history_floor(
    publication: Publication,
    *,
    public_key_path: Path,
    github: GitHub,
    revision: str,
) -> RetainedHistory | None:
    records = github.list_channel_objects(publication.history_root, revision)
    if not records:
        return None
    sequences: dict[int, str] = {}
    for record in records:
        name = record.path.rsplit("/", 1)[-1]
        match = _HISTORY_NAME.fullmatch(name)
        if match is None:
            raise UpdateRefused("retained channel history filename is invalid")
        filename_sequence = int(match.group(1))
        filename_digest = match.group(2)
        current = github.read_content(record.path, revision)
        if current is None:
            raise UpdateRefused("retained channel history was deleted during review")
        object_sha, body = current
        if object_sha != record.sha or len(body) != record.size:
            raise UpdateRefused("retained channel history changed during review")
        sequence, digest = _parse_existing_sequence(
            body,
            channel=publication.channel,
            public_key_path=public_key_path,
            label="history",
        )
        if sequence != filename_sequence or digest != filename_digest:
            raise UpdateRefused("retained channel history name does not bind its bytes")
        if sequence in sequences:
            raise UpdateRefused("retained channel history repeats a signed sequence")
        sequences[sequence] = digest
    if github.list_channel_objects(publication.history_root, revision) != records:
        raise UpdateRefused("retained channel history changed during review")
    floor = max(sequences)
    return RetainedHistory(sequence=floor, metadata_sha256=sequences[floor])


def _anonymous_fetch(url: str, *, maximum: int, timeout_seconds: float = 60.0) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cathedral-validator-release-publisher/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
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


def _verify_anonymous_pointer(
    url: str,
    expected: bytes,
    *,
    label: str,
    attempts: int = _POINTER_VERIFY_ATTEMPTS,
    deadline_seconds: float = _POINTER_VERIFY_DEADLINE_SECONDS,
    retry_seconds: float = _POINTER_VERIFY_RETRY_SECONDS,
    request_seconds: float = _POINTER_VERIFY_REQUEST_SECONDS,
    minimum_success_elapsed_seconds: float = 0.0,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    started = clock()
    deadline = started + deadline_seconds
    success_not_before = started + minimum_success_elapsed_seconds
    last_error: UpdateRefused | None = None
    last_observed_sha256: str | None = None
    successful_fetches = 0
    transport_errors = 0
    post_threshold_attempted = False
    for attempt in range(attempts):
        now = clock()
        remaining = deadline - now
        if remaining <= 0:
            break
        if now >= success_not_before:
            post_threshold_attempted = True
        try:
            observed = _anonymous_fetch(
                url,
                maximum=MAX_METADATA_BYTES,
                timeout_seconds=min(request_seconds, remaining),
            )
        except UpdateRefused as exc:
            last_error = exc
            last_observed_sha256 = None
            transport_errors += 1
            matched = False
        else:
            successful_fetches += 1
            matched = observed == expected
            if matched and now >= success_not_before and clock() <= deadline:
                return
            last_observed_sha256 = hashlib.sha256(observed).hexdigest()
            last_error = None
        if attempt + 1 == attempts:
            break
        remaining = deadline - clock()
        if remaining <= 0:
            break
        current = clock()
        if not post_threshold_attempted and current >= success_not_before:
            delay = 0.0
        elif matched and not post_threshold_attempted:
            delay = max(0.0, success_not_before - current)
        else:
            delay = retry_seconds
        if delay > 0:
            sleeper(min(delay, remaining))
    diagnostic = (
        f"; last_observed_sha256={last_observed_sha256}"
        if last_observed_sha256 is not None
        else "; last_result=transport_error"
    )
    raise UpdateRefused(
        f"anonymous {label} did not converge to the exact published metadata "
        f"within its bounded retry window{diagnostic}; "
        f"successful_fetches={successful_fetches}; transport_errors={transport_errors}"
    ) from last_error


def _require_publication_lifetime(
    publication: Publication,
    *,
    wall_clock: Callable[[], float],
    minimum_remaining_seconds: int,
    stage: str,
) -> None:
    remaining = publication.expires_unix - int(wall_clock())
    if remaining <= minimum_remaining_seconds:
        raise UpdateRefused(
            f"signed release expires too soon {stage} "
            f"(remaining_seconds={remaining}, required_seconds>"
            f"{minimum_remaining_seconds})"
        )


def publish(
    publication: Publication,
    *,
    public_key_path: Path,
    github: GitHub,
    wall_clock: Callable[[], float] = time.time,
) -> str:
    _require_publication_lifetime(
        publication,
        wall_clock=wall_clock,
        minimum_remaining_seconds=_MIN_PUBLICATION_REMAINING_SECONDS,
        stage="before publication",
    )
    github.ensure_release(publication)
    downloaded = _anonymous_fetch(publication.archive_url, maximum=MAX_ARCHIVE_BYTES)
    if hashlib.sha256(downloaded).hexdigest() != publication.archive_sha256:
        raise UpdateRefused("anonymous GitHub archive does not match the signed digest")
    branch = github.ensure_branch(publication)

    pointer = github.read_content(publication.pointer_path, branch.revision)
    pointer_identical = False
    if pointer is None:
        history_floor = _retained_history_floor(
            publication,
            public_key_path=public_key_path,
            github=github,
            revision=branch.revision,
        )
        if history_floor is None:
            if branch.revision != publication.source_revision:
                raise UpdateRefused(
                    "channel pointer is missing without retained signed history "
                    "on the exact initial branch revision"
                )
        elif branch.created:
            raise UpdateRefused("new channel branch already contains retained history")
        elif publication.sequence < history_floor.sequence:
            raise UpdateRefused(
                "channel pointer is missing and the release does not advance "
                f"retained signed history sequence {history_floor.sequence}"
            )
        elif (
            publication.sequence == history_floor.sequence
            and publication.metadata_sha256 != history_floor.metadata_sha256
        ):
            raise UpdateRefused(
                "channel pointer is missing and the release differs from the "
                "retained signed history at the same sequence"
            )
    else:
        _pointer_sha, pointer_body = pointer
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

    history = github.read_content(publication.history_path, branch.revision)
    history_identical = history is not None
    if history is not None and history[1] != publication.metadata:
        raise UpdateRefused("immutable release history path already has other bytes")

    _require_publication_lifetime(
        publication,
        wall_clock=wall_clock,
        minimum_remaining_seconds=_MIN_POINTER_VERIFICATION_REMAINING_SECONDS,
        stage="before the channel update",
    )
    published_revision = branch.revision
    if not pointer_identical or not history_identical:
        published_revision = github.commit_channel(
            publication,
            base_revision=branch.revision,
        )
    encoded_revision = urllib.parse.quote(published_revision, safe="")
    encoded_branch = urllib.parse.quote(publication.channel_branch, safe="")
    pinned_url = (
        f"https://raw.githubusercontent.com/{publication.repository}/"
        f"{encoded_revision}/{publication.pointer_path}"
    )
    raw_url = (
        f"https://raw.githubusercontent.com/{publication.repository}/"
        f"{encoded_branch}/{publication.pointer_path}"
    )
    _verify_anonymous_pointer(
        pinned_url,
        publication.metadata,
        label="commit-pinned channel pointer",
        attempts=_PINNED_POINTER_VERIFY_ATTEMPTS,
        deadline_seconds=_PINNED_POINTER_VERIFY_DEADLINE_SECONDS,
        retry_seconds=_PINNED_POINTER_VERIFY_RETRY_SECONDS,
    )
    _verify_anonymous_pointer(
        raw_url,
        publication.metadata,
        label="mutable channel pointer",
        minimum_success_elapsed_seconds=(_MUTABLE_POINTER_MINIMUM_OBSERVATION_SECONDS),
    )
    _require_publication_lifetime(
        publication,
        wall_clock=wall_clock,
        minimum_remaining_seconds=0,
        stage="after pointer verification",
    )
    return published_revision


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
        published_revision: str | None = None
        if options.publish:
            published_revision = publish(
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
        + (
            f" channel_revision={published_revision}"
            if published_revision is not None
            else ""
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
