from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import runpy
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_thin.independent_runtime.preview_io import canonical_document_bytes
from cathedral_thin.independent_runtime.updater import METADATA_SCHEMA, UpdateRefused

NOW = 1_800_000_000
SOURCE_REVISION = "a" * 40


def _publisher() -> dict[str, object]:
    root = Path(__file__).resolve().parents[2]
    return runpy.run_path(
        str(root / "deploy" / "validator-update" / "publish_github_channel.py")
    )


def test_documented_publisher_runs_from_a_clean_checkout(tmp_path: Path) -> None:
    script = (
        Path(__file__).resolve().parents[2]
        / "deploy"
        / "validator-update"
        / "publish_github_channel.py"
    )
    result = subprocess.run(
        [sys.executable, "-E", str(script), "--help"],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Publish an offline-signed Cathedral validator release" in result.stdout
    imported = subprocess.run(
        [
            sys.executable,
            "-E",
            "-c",
            (
                "import runpy,sys; namespace=runpy.run_path(sys.argv[1]); "
                "print(namespace['parse_release_metadata'].__globals__['__file__'])"
            ),
            str(script),
        ],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert imported.returncode == 0, imported.stderr
    expected = (
        Path(__file__).resolve().parents[2]
        / "cathedral_thin"
        / "independent_runtime"
        / "updater.py"
    ).resolve()
    assert Path(imported.stdout.strip()).resolve() == expected


def _key(tmp_path: Path) -> tuple[Ed25519PrivateKey, Path]:
    private = Ed25519PrivateKey.generate()
    public_path = tmp_path / "update-public-key.pem"
    public_path.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    public_path.chmod(0o444)
    assert public_path.stat().st_uid == os.geteuid()
    return private, public_path


def _archive(*, schema: str = "cathedral_validator_bundle_v2") -> bytes:
    manifest = canonical_document_bytes(
        {
            "schema": schema,
            "source_revision": SOURCE_REVISION,
            "entry_point": ("cathedral_thin.independent_runtime.direct_validator:main"),
        }
    )
    executable = b"#!/bin/sh\nexit 0\n"
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        for name, body, mode in (
            ("RELEASE.json", manifest, 0o644),
            ("bin/cathedral-validator", executable, 0o755),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mode = mode
            bundle.addfile(info, io.BytesIO(body))
    return output.getvalue()


def _metadata(
    private: Ed25519PrivateKey,
    archive: bytes,
    *,
    sequence: int,
    repository: str = "cathedralai/cathedral-validator",
) -> bytes:
    digest = hashlib.sha256(archive).hexdigest()
    signed = {
        "schema": METADATA_SCHEMA,
        "channel": "canary",
        "sequence": sequence,
        "issued_unix": NOW,
        "expires_unix": NOW + 3600,
        "release": {
            "version": "4.0.0rc5",
            "archive_url": (
                f"https://github.com/{repository}/releases/download/"
                f"validator-{digest}/cathedral-validator-{digest}.tar.gz"
            ),
            "archive_sha256": digest,
            "tree_sha256": "b" * 64,
            "entrypoint": "bin/cathedral-validator",
        },
    }
    signature = private.sign(canonical_document_bytes(signed))
    return canonical_document_bytes(
        {
            "signed": signed,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    )


def _validated(
    tmp_path: Path,
    *,
    sequence: int = 1,
    channel_branch: str = "validator-release-channel",
):
    publisher = _publisher()
    private, public_path = _key(tmp_path)
    archive = _archive()
    digest = hashlib.sha256(archive).hexdigest()
    archive_path = tmp_path / f"cathedral-validator-{digest}.tar.gz"
    metadata_path = tmp_path / "canary.json"
    archive_path.write_bytes(archive)
    metadata_path.write_bytes(_metadata(private, archive, sequence=sequence))
    publication = publisher["validate_publication"](
        metadata_path=metadata_path,
        archive_path=archive_path,
        public_key_path=public_path,
        channel_branch=channel_branch,
        now_unix=NOW,
    )
    return publisher, private, public_path, archive_path, publication


def _release_record(publication, *, draft: bool, asset: bool):
    return {
        "id": 77,
        "tag_name": publication.tag,
        "name": publication.tag,
        "target_commitish": publication.source_revision,
        "draft": draft,
        "prerelease": True,
        "immutable": not draft,
        "assets": (
            [
                {
                    "name": publication.asset_name,
                    "state": "uploaded",
                    "size": len(publication.archive),
                    "digest": f"sha256:{publication.archive_sha256}",
                    "browser_download_url": publication.archive_url,
                }
            ]
            if asset
            else []
        ),
    }


def test_validate_publication_binds_archive_url_name_and_source(tmp_path: Path) -> None:
    _publisher_module, _private, _public, archive_path, publication = _validated(
        tmp_path
    )
    assert publication.archive_sha256 in archive_path.name
    assert publication.tag == f"validator-{publication.archive_sha256}"
    assert publication.source_revision == SOURCE_REVISION
    assert publication.history_path.endswith(f"1-{publication.metadata_sha256}.json")


def test_github_release_uses_explicit_draft_upload_publish_sequence(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, _public, archive_path, publication = _validated(tmp_path)
    github = publisher["GitHub"](publication.repository)
    api_calls: list[tuple[str, str, object]] = []
    command_calls: list[tuple[str, ...]] = []

    monkeypatch.setattr(
        github,
        "_run",
        lambda arguments, **_kwargs: command_calls.append(tuple(arguments)),
    )
    monkeypatch.setattr(
        github,
        "api",
        lambda endpoint, *, method="GET", payload=None, **_kwargs: (
            api_calls.append((endpoint, method, payload)),
            _release_record(
                publication, draft=method == "POST", asset=method == "PATCH"
            ),
        )[1],
    )

    github.create_release_draft(publication)
    github.upload_release_asset(publication, archive_path)
    github.publish_release(publication, 77)
    assert command_calls == [
        (
            "release",
            "upload",
            publication.tag,
            str(archive_path),
            "--repo",
            publication.repository,
        ),
    ]
    assert api_calls[0][0:2] == ("releases", "POST")
    create_payload = api_calls[0][2]
    assert create_payload["tag_name"] == publication.tag
    assert create_payload["target_commitish"] == publication.source_revision
    assert create_payload["draft"] is True
    assert create_payload["prerelease"] is True
    assert create_payload["make_latest"] == "false"
    assert api_calls[1] == (
        "releases/77",
        "PATCH",
        {"draft": False, "prerelease": True, "make_latest": "false"},
    )


def test_ensure_release_verifies_each_state_before_publishing(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, _public, archive_path, publication = _validated(tmp_path)
    archive_path.write_bytes(b"changed after publication validation")
    github = publisher["GitHub"](publication.repository)
    events: list[str] = []
    release_by_id = iter(
        (
            _release_record(publication, draft=True, asset=True),
            _release_record(publication, draft=False, asset=True),
        )
    )

    monkeypatch.setattr(
        github,
        "require_immutable_releases",
        lambda: events.append("immutable-setting"),
    )
    monkeypatch.setattr(
        github,
        "release",
        lambda *_args, **_kwargs: (events.append("release"), None)[1],
    )
    tag_records = iter(
        (
            None,
            {"object": {"type": "commit", "sha": publication.source_revision}},
        )
    )
    monkeypatch.setattr(
        github,
        "tag_ref",
        lambda *_args, **_kwargs: (events.append("tag"), next(tag_records))[1],
    )
    monkeypatch.setattr(
        github,
        "create_release_draft",
        lambda _publication: (
            events.append("create-draft"),
            _release_record(publication, draft=True, asset=False),
        )[1],
    )

    def upload(_publication, path: Path) -> None:
        assert path.read_bytes() == publication.archive
        assert path.stat().st_mode & 0o777 == 0o400
        events.append("upload")

    monkeypatch.setattr(github, "upload_release_asset", upload)
    monkeypatch.setattr(
        github,
        "release_by_id",
        lambda release_id: (
            events.append("release-id"),
            77 == release_id,
            next(release_by_id),
        )[2],
    )
    monkeypatch.setattr(
        github,
        "publish_release",
        lambda _publication, release_id: (
            events.append("publish-draft"),
            77 == release_id,
            _release_record(publication, draft=False, asset=True),
        )[2],
    )

    github.ensure_release(publication)

    assert events == [
        "immutable-setting",
        "release",
        "tag",
        "create-draft",
        "upload",
        "release-id",
        "publish-draft",
        "release-id",
        "tag",
    ]


@pytest.mark.parametrize("already_uploaded", (False, True))
def test_ensure_release_resumes_only_an_exact_same_plan_draft(
    tmp_path: Path, monkeypatch, already_uploaded: bool
) -> None:
    publisher, _private, _public, _archive_path, publication = _validated(tmp_path)
    github = publisher["GitHub"](publication.repository)
    existing = _release_record(publication, draft=True, asset=already_uploaded)
    events: list[str] = []
    after_publish = False

    monkeypatch.setattr(
        github,
        "require_immutable_releases",
        lambda: events.append("immutable-setting"),
    )
    monkeypatch.setattr(github, "release", lambda _tag: existing)

    def upload(_publication, path: Path) -> None:
        assert path.read_bytes() == publication.archive
        events.append("upload")

    monkeypatch.setattr(github, "upload_release_asset", upload)

    def release_by_id(release_id: int):
        assert release_id == 77
        events.append("release-id")
        return _release_record(
            publication,
            draft=not after_publish,
            asset=True,
        )

    monkeypatch.setattr(github, "release_by_id", release_by_id)

    def publish_release(_publication, release_id: int):
        nonlocal after_publish
        assert release_id == 77
        events.append("publish-draft")
        after_publish = True
        return _release_record(publication, draft=False, asset=True)

    monkeypatch.setattr(github, "publish_release", publish_release)
    monkeypatch.setattr(
        github,
        "tag_ref",
        lambda _tag: {"object": {"type": "commit", "sha": publication.source_revision}},
    )

    github.ensure_release(publication)

    expected = ["immutable-setting"]
    if not already_uploaded:
        expected.extend(["upload", "release-id"])
    expected.extend(["publish-draft", "release-id"])
    assert events == expected


def test_ensure_release_refuses_a_mismatched_draft_without_repair(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, _public, _archive_path, publication = _validated(tmp_path)
    github = publisher["GitHub"](publication.repository)
    partial = _release_record(publication, draft=True, asset=True)
    partial["assets"][0]["digest"] = "sha256:" + "0" * 64
    events: list[str] = []
    monkeypatch.setattr(github, "require_immutable_releases", lambda: None)
    monkeypatch.setattr(github, "release", lambda _tag: partial)
    monkeypatch.setattr(
        github,
        "upload_release_asset",
        lambda *_args: events.append("upload"),
    )
    monkeypatch.setattr(
        github,
        "publish_release",
        lambda *_args: events.append("publish"),
    )

    with pytest.raises(UpdateRefused, match="differs from the signed archive"):
        github.ensure_release(publication)
    assert events == []


def test_immutable_release_preflight_refuses_a_private_repository(monkeypatch) -> None:
    publisher = _publisher()
    github = publisher["GitHub"]("cathedralai/cathedral-validator")
    calls: list[str] = []

    def api(endpoint: str, **_kwargs):
        calls.append(endpoint)
        return {"private": True}

    monkeypatch.setattr(github, "api", api)
    with pytest.raises(UpdateRefused, match="not public"):
        github.require_immutable_releases()
    assert calls == [""]


def test_release_lookup_uses_draft_capable_paginated_rest_list(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, _public, _archive_path, publication = _validated(tmp_path)
    github = publisher["GitHub"](publication.repository)
    calls: list[tuple[str, ...]] = []
    expected = _release_record(publication, draft=True, asset=False)

    def run(arguments, **_kwargs):
        calls.append(tuple(arguments))
        return subprocess.CompletedProcess(
            arguments,
            0,
            json.dumps([{"id": 77, "tag_name": publication.tag}]).encode(),
            b"",
        )

    monkeypatch.setattr(github, "_run", run)
    monkeypatch.setattr(github, "release_by_id", lambda release_id: expected)

    assert github.release(publication.tag) == expected
    assert calls == [
        (
            "api",
            f"repos/{publication.repository}/releases?per_page=100&page=1",
        )
    ]


def test_release_lookup_refuses_an_unexhausted_bound(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, _public, _archive_path, publication = _validated(tmp_path)
    github = publisher["GitHub"](publication.repository)
    page = [{"id": index + 1, "tag_name": f"other-{index}"} for index in range(100)]
    calls = 0

    def run(arguments, **_kwargs):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(arguments, 0, json.dumps(page).encode(), b"")

    monkeypatch.setattr(github, "_run", run)
    with pytest.raises(UpdateRefused, match="safe bound"):
        github.release(publication.tag)
    assert calls == 10


def test_isolated_channel_branch_is_url_encoded_for_github_refs(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, _public, _archive_path, publication = _validated(
        tmp_path, channel_branch="validator-release-channel/fault"
    )
    github = publisher["GitHub"](publication.repository)
    calls: list[tuple[str, object]] = []

    def api(endpoint: str, **kwargs):
        calls.append((endpoint, kwargs.get("payload")))
        return None

    monkeypatch.setattr(github, "api", api)
    github.ensure_branch(publication)
    assert calls == [
        (
            "git/ref/heads/validator-release-channel%2Ffault",
            None,
        ),
        (
            "git/refs",
            {
                "ref": "refs/heads/validator-release-channel/fault",
                "sha": SOURCE_REVISION,
            },
        ),
    ]


@pytest.mark.parametrize(
    ("repository", "branch"),
    (
        ("../cathedral-validator", "validator-release-channel"),
        ("cathedralai/cathedral-validator.git", "validator-release-channel"),
        ("cathedralai/cathedral-validator", "../fault"),
        ("cathedralai/cathedral-validator", ".hidden"),
        ("cathedralai/cathedral-validator", "fault.lock"),
    ),
)
def test_validate_publication_rejects_unsafe_repository_and_branch(
    tmp_path: Path, repository: str, branch: str
) -> None:
    publisher = _publisher()
    with pytest.raises(UpdateRefused, match="invalid"):
        publisher["validate_publication"](
            metadata_path=tmp_path / "metadata",
            archive_path=tmp_path / "archive",
            public_key_path=tmp_path / "key",
            repository=repository,
            channel_branch=branch,
            now_unix=NOW,
        )


def test_github_missing_probe_refuses_auth_and_transport_errors(monkeypatch) -> None:
    publisher = _publisher()
    github = publisher["GitHub"]("cathedralai/cathedral-validator")
    subprocess_module = github._run.__globals__["subprocess"]

    monkeypatch.setattr(
        subprocess_module,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 1, b"", b"HTTP 404: Not Found"
        ),
    )
    assert github.api("releases/tags/missing", allow_missing=True) is None

    monkeypatch.setattr(
        subprocess_module,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 1, b"", b"HTTP 403: authentication required"
        ),
    )
    with pytest.raises(UpdateRefused, match="authentication required"):
        github.api("releases/tags/private", allow_missing=True)


def test_github_channel_content_requires_strict_base64(monkeypatch) -> None:
    publisher = _publisher()
    github = publisher["GitHub"]("cathedralai/cathedral-validator")
    monkeypatch.setattr(
        github,
        "api",
        lambda *_args, **_kwargs: {
            "sha": "a" * 40,
            "encoding": "base64",
            "content": "not base64!",
        },
    )
    with pytest.raises(UpdateRefused, match="valid base64"):
        github.read_content("validator/canary.json", "validator-release-channel")


def test_github_channel_content_accepts_github_line_wrapping(monkeypatch) -> None:
    publisher = _publisher()
    github = publisher["GitHub"]("cathedralai/cathedral-validator")
    expected = b"signed channel bytes\n"
    encoded = base64.b64encode(expected).decode("ascii")
    wrapped = "\n".join(
        encoded[index : index + 8] for index in range(0, len(encoded), 8)
    )
    monkeypatch.setattr(
        github,
        "api",
        lambda *_args, **_kwargs: {
            "sha": "a" * 40,
            "encoding": "base64",
            "content": wrapped + "\n",
        },
    )
    assert github.read_content(
        "validator/canary.json", "validator-release-channel"
    ) == ("a" * 40, expected)


def test_validate_publication_rejects_tamper_and_noncanonical_name(
    tmp_path: Path,
) -> None:
    publisher, _private, public_path, archive_path, publication = _validated(tmp_path)
    wrong_name = tmp_path / "validator.tar.gz"
    wrong_name.write_bytes(archive_path.read_bytes())
    metadata = tmp_path / "canary.json"
    metadata.write_bytes(publication.metadata)
    with pytest.raises(UpdateRefused, match="content-addressed"):
        publisher["validate_publication"](
            metadata_path=metadata,
            archive_path=wrong_name,
            public_key_path=public_path,
            now_unix=NOW,
        )

    archive_path.write_bytes(archive_path.read_bytes() + b"tampered")
    with pytest.raises(UpdateRefused, match="does not match signed metadata"):
        publisher["validate_publication"](
            metadata_path=metadata,
            archive_path=archive_path,
            public_key_path=public_path,
            now_unix=NOW,
        )


class _FakeGitHub:
    def __init__(self, *, pointer: bytes | None = None) -> None:
        self.pointer = pointer
        self.objects: dict[str, bytes] = {}
        self.events: list[str] = []

    def ensure_release(self, publication) -> None:
        assert publication.archive
        self.events.append("release")

    def ensure_branch(self, publication) -> None:
        self.events.append("branch")

    def read_content(self, path: str, branch: str):
        assert branch == "validator-release-channel"
        if path.endswith("canary.json") and self.pointer is not None:
            return "pointer-sha", self.pointer
        body = self.objects.get(path)
        return None if body is None else ("object-sha", body)

    def write_content(
        self,
        *,
        path: str,
        branch: str,
        body: bytes,
        message: str,
        existing_sha: str | None = None,
    ) -> None:
        assert branch == "validator-release-channel"
        assert message.startswith("release(canary):")
        if path.endswith("canary.json"):
            assert existing_sha in {None, "pointer-sha"}
            self.pointer = body
            self.events.append("pointer")
        else:
            assert existing_sha is None
            self.events.append("history")
        self.objects[path] = body


def test_publish_orders_archive_history_then_pointer(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, public_path, _archive_path, publication = _validated(tmp_path)
    github = _FakeGitHub()

    def anonymous(url: str, *, maximum: int) -> bytes:
        assert maximum > 0
        if "github.com/" in url:
            return publication.archive
        assert url.endswith("validator/canary.json")
        return github.pointer or b""

    monkeypatch.setitem(publisher["publish"].__globals__, "_anonymous_fetch", anonymous)
    publisher["publish"](
        publication,
        public_key_path=public_path,
        github=github,
    )
    assert github.events == ["release", "branch", "history", "pointer"]
    assert github.pointer == publication.metadata


def test_publish_rejects_pointer_rollback_before_channel_write(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, private, public_path, _archive_path, publication = _validated(
        tmp_path, sequence=2
    )
    old_pointer = _metadata(private, publication.archive, sequence=3)
    github = _FakeGitHub(pointer=old_pointer)
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        lambda _url, *, maximum: publication.archive,
    )
    with pytest.raises(UpdateRefused, match="does not advance"):
        publisher["publish"](
            publication,
            public_key_path=public_path,
            github=github,
        )
    assert github.events == ["release", "branch"]
    assert github.objects == {}


def test_publish_never_moves_channel_after_release_verification_failure(
    tmp_path: Path,
) -> None:
    publisher, _private, public_path, _archive_path, publication = _validated(tmp_path)

    class RefusingGitHub(_FakeGitHub):
        def ensure_release(self, publication) -> None:
            self.events.append("release")
            raise UpdateRefused("immutable release verification failed")

    github = RefusingGitHub()
    with pytest.raises(UpdateRefused, match="immutable release verification failed"):
        publisher["publish"](
            publication,
            public_key_path=public_path,
            github=github,
        )
    assert github.events == ["release"]
    assert github.objects == {}


def test_release_manifest_schema_is_enforced(tmp_path: Path) -> None:
    publisher = _publisher()
    private, public_path = _key(tmp_path)
    archive = _archive(schema="cathedral_validator_bundle_v1")
    digest = hashlib.sha256(archive).hexdigest()
    archive_path = tmp_path / f"cathedral-validator-{digest}.tar.gz"
    metadata_path = tmp_path / "canary.json"
    archive_path.write_bytes(archive)
    metadata_path.write_bytes(_metadata(private, archive, sequence=1))
    with pytest.raises(UpdateRefused, match="wrong schema"):
        publisher["validate_publication"](
            metadata_path=metadata_path,
            archive_path=archive_path,
            public_key_path=public_path,
            now_unix=NOW,
        )
