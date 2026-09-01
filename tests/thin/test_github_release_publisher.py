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
from dataclasses import dataclass
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
    # The production cache hold is tested with a deterministic clock below.
    # Other publisher tests must not spend six minutes waiting on wall time.
    publisher["publish"].__globals__["_MUTABLE_POINTER_MINIMUM_OBSERVATION_SECONDS"] = (
        0.0
    )
    publisher["publish"].__kwdefaults__["wall_clock"] = lambda: NOW
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
                    "browser_download_url": (
                        f"https://github.com/{publication.repository}/releases/download/"
                        f"untagged-30ab6836a380fb821857/{publication.asset_name}"
                        if draft
                        else publication.archive_url
                    ),
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


def test_draft_asset_accepts_github_untagged_identity(tmp_path: Path) -> None:
    publisher, _private, _public, _archive_path, publication = _validated(tmp_path)
    draft = _release_record(publication, draft=True, asset=True)

    publisher["_verify_release_record"](publication, draft, draft=True, asset=True)


@pytest.mark.parametrize(
    "replacement",
    (
        "https://github.com/cathedralai/other/releases/download/untagged-91/{}",
        "https://example.com/cathedralai/cathedral-validator/releases/download/untagged-91/{}",
        "https://github.com:443/cathedralai/cathedral-validator/releases/download/untagged-91/{}",
        "https://user@github.com/cathedralai/cathedral-validator/releases/download/untagged-91/{}",
        "https://github.com/cathedralai/cathedral-validator/releases/download/untagged-91/{}?token=secret",
        "https://github.com/cathedralai/cathedral-validator/releases/download/untagged-91/{}#fragment",
        "https://github.com/cathedralai/cathedral-validator/releases/download/untagged-token..token/{}",
        "https://github.com/cathedralai/cathedral-validator/releases/download/untagged-91/not-the-asset",
        "https://github.com/cathedralai/cathedral-validator/releases/download/untagged-91%2Fextra/{}",
    ),
)
def test_draft_asset_refuses_noncanonical_untagged_urls(
    tmp_path: Path, replacement: str
) -> None:
    publisher, _private, _public, _archive_path, publication = _validated(tmp_path)
    draft = _release_record(publication, draft=True, asset=True)
    draft["assets"][0]["browser_download_url"] = replacement.format(
        publication.asset_name
    )

    with pytest.raises(UpdateRefused, match="draft asset URL differs"):
        publisher["_verify_release_record"](publication, draft, draft=True, asset=True)


def test_published_asset_still_requires_final_tagged_url(tmp_path: Path) -> None:
    publisher, _private, _public, _archive_path, publication = _validated(tmp_path)
    published = _release_record(publication, draft=False, asset=True)
    published["assets"][0]["browser_download_url"] = (
        f"https://github.com/{publication.repository}/releases/download/"
        f"untagged-91/{publication.asset_name}"
    )

    with pytest.raises(UpdateRefused, match="differs from the signed archive"):
        publisher["_verify_release_record"](
            publication, published, draft=False, asset=True
        )


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
        if endpoint == "git/refs":
            return {
                "object": {
                    "type": "commit",
                    "sha": publication.source_revision,
                }
            }
        return None

    monkeypatch.setattr(github, "api", api)
    assert github.ensure_branch(publication) == publisher["ChannelBranch"](
        created=True,
        revision=publication.source_revision,
    )
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

    calls.clear()
    monkeypatch.setattr(
        github,
        "api",
        lambda endpoint, **kwargs: (
            calls.append((endpoint, kwargs.get("payload"))),
            {
                "object": {
                    "type": "commit",
                    "sha": publication.source_revision,
                }
            },
        )[1],
    )
    assert github.ensure_branch(publication) == publisher["ChannelBranch"](
        created=False,
        revision=publication.source_revision,
    )
    assert calls == [("git/ref/heads/validator-release-channel%2Ffault", None)]


def test_channel_history_listing_uses_bounded_strict_file_records(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, _public, _archive_path, publication = _validated(tmp_path)
    github = publisher["GitHub"](publication.repository)
    history_path = f"{publication.history_root}/1-{'b' * 64}.json"
    record = {
        "type": "file",
        "path": history_path,
        "name": history_path.rsplit("/", 1)[-1],
        "sha": "c" * 40,
        "size": 123,
    }
    calls = []

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(
            arguments,
            0,
            json.dumps([record]).encode("utf-8"),
            b"",
        )

    monkeypatch.setattr(github, "_run", run)
    assert github.list_channel_objects(
        publication.history_root, publication.channel_branch
    ) == (
        publisher["ChannelObject"](
            path=history_path,
            sha="c" * 40,
            size=123,
        ),
    )
    assert calls == [
        (
            [
                "api",
                f"repos/{publication.repository}/contents/"
                f"{publication.history_root}?ref={publication.channel_branch}",
            ],
            {"allow_missing": True},
        )
    ]

    invalid = dict(record, type="dir")
    monkeypatch.setattr(github, "api_records", lambda *_args, **_kwargs: (invalid,))
    with pytest.raises(UpdateRefused, match="history record is invalid"):
        github.list_channel_objects(
            publication.history_root, publication.channel_branch
        )

    monkeypatch.setattr(
        github,
        "api_records",
        lambda *_args, **_kwargs: tuple(record for _index in range(1_000)),
    )
    with pytest.raises(UpdateRefused, match="safe bound"):
        github.list_channel_objects(
            publication.history_root, publication.channel_branch
        )


def test_channel_commit_atomically_binds_history_pointer_and_branch_cas(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, _public, _archive_path, publication = _validated(tmp_path)
    github = publisher["GitHub"](publication.repository)
    base = "d" * 40
    calls: list[tuple[str, str, object]] = []
    results = {
        f"git/commits/{base}": {"sha": base, "tree": {"sha": "1" * 40}},
        "git/blobs": {"sha": "2" * 40},
        "git/trees": {"sha": "3" * 40},
        "git/commits": {"sha": "4" * 40},
        f"git/refs/heads/{publication.channel_branch}": {
            "object": {"type": "commit", "sha": "4" * 40}
        },
    }

    def api(endpoint: str, *, method="GET", payload=None, **_kwargs):
        calls.append((endpoint, method, payload))
        return results[endpoint]

    monkeypatch.setattr(github, "api", api)
    assert github.commit_channel(publication, base_revision=base) == "4" * 40
    blob_payload = calls[1][2]
    assert blob_payload == {
        "content": base64.b64encode(publication.metadata).decode("ascii"),
        "encoding": "base64",
    }
    tree_payload = calls[2][2]
    assert tree_payload == {
        "base_tree": "1" * 40,
        "tree": [
            {
                "path": publication.history_path,
                "mode": "100644",
                "type": "blob",
                "sha": "2" * 40,
            },
            {
                "path": publication.pointer_path,
                "mode": "100644",
                "type": "blob",
                "sha": "2" * 40,
            },
        ],
    }
    assert calls[3][2]["parents"] == [base]
    assert calls[4] == (
        f"git/refs/heads/{publication.channel_branch}",
        "PATCH",
        {"sha": "4" * 40, "force": False},
    )


def test_lower_sequence_loses_when_higher_sequence_wins_branch_cas(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, _public, _archive_path, publication = _validated(
        tmp_path, sequence=4
    )
    github = publisher["GitHub"](publication.repository)
    base = "d" * 40
    endpoints = {
        f"git/commits/{base}": {"sha": base, "tree": {"sha": "1" * 40}},
        "git/blobs": {"sha": "2" * 40},
        "git/trees": {"sha": "3" * 40},
        "git/commits": {"sha": "4" * 40},
    }
    ref_payloads = []

    def api(endpoint: str, *, method="GET", payload=None, **_kwargs):
        if endpoint.startswith("git/refs/heads/"):
            ref_payloads.append(payload)
            raise UpdateRefused(
                "non-fast-forward: signed sequence 5 advanced the reviewed head"
            )
        return endpoints[endpoint]

    monkeypatch.setattr(github, "api", api)
    with pytest.raises(UpdateRefused, match="sequence 5 advanced"):
        github.commit_channel(publication, base_revision=base)
    assert ref_payloads == [{"sha": "4" * 40, "force": False}]


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


def test_anonymous_pointer_verification_retries_stale_fixed_url_bytes(
    monkeypatch,
) -> None:
    publisher = _publisher()
    expected = b"exact signed pointer\n"
    responses = iter((b"stale pointer\n", b"stale pointer\n", expected))
    urls: list[str] = []
    now = [100.0]

    def fetch(url: str, *, maximum: int, timeout_seconds: float) -> bytes:
        urls.append(url)
        assert maximum == 131_072
        assert 0 < timeout_seconds <= 2.0
        now[0] += 0.25
        return next(responses)

    def sleep(seconds: float) -> None:
        now[0] += seconds

    monkeypatch.setitem(
        publisher["_verify_anonymous_pointer"].__globals__,
        "_anonymous_fetch",
        fetch,
    )
    publisher["_verify_anonymous_pointer"](
        "https://raw.githubusercontent.com/example/repo/channel/validator/canary.json",
        expected,
        label="mutable channel pointer",
        attempts=4,
        deadline_seconds=10.0,
        retry_seconds=0.5,
        request_seconds=2.0,
        clock=lambda: now[0],
        sleeper=sleep,
    )
    assert len(urls) == 3
    assert (
        urls
        == [
            "https://raw.githubusercontent.com/example/repo/channel/validator/canary.json"
        ]
        * 3
    )


def test_anonymous_pointer_verification_stops_at_its_deadline(monkeypatch) -> None:
    publisher = _publisher()
    expected = b"exact signed pointer\n"
    now = [0.0]
    calls = 0

    def fetch(_url: str, *, maximum: int, timeout_seconds: float) -> bytes:
        nonlocal calls
        calls += 1
        assert maximum == 131_072
        assert timeout_seconds <= 1.5
        now[0] += 0.75
        return b"stale pointer\n"

    def sleep(seconds: float) -> None:
        now[0] += seconds

    monkeypatch.setitem(
        publisher["_verify_anonymous_pointer"].__globals__,
        "_anonymous_fetch",
        fetch,
    )
    with pytest.raises(UpdateRefused, match="bounded retry window") as refused:
        publisher["_verify_anonymous_pointer"](
            "https://raw.githubusercontent.com/example/repo/channel/validator/canary.json",
            expected,
            label="mutable channel pointer",
            attempts=99,
            deadline_seconds=2.0,
            retry_seconds=0.5,
            request_seconds=1.5,
            clock=lambda: now[0],
            sleeper=sleep,
        )
    assert calls == 2
    assert now[0] == 2.0
    stale_digest = hashlib.sha256(b"stale pointer\n").hexdigest()
    assert f"last_observed_sha256={stale_digest}" in str(refused.value)
    assert "successful_fetches=2; transport_errors=0" in str(refused.value)


def test_anonymous_pointer_requires_a_fresh_match_after_cache_lifetime() -> None:
    publisher = _publisher()
    expected = b"exact signed pointer\n"
    now = [0.0]
    fetch_times: list[float] = []

    def fetch(_url: str, *, maximum: int, timeout_seconds: float) -> bytes:
        assert maximum > 0
        assert timeout_seconds > 0
        fetch_times.append(now[0])
        return expected

    def sleep(seconds: float) -> None:
        now[0] += seconds

    publisher["_verify_anonymous_pointer"].__globals__["_anonymous_fetch"] = fetch
    publisher["_verify_anonymous_pointer"](
        "https://raw.githubusercontent.com/example/repo/channel/validator/canary.json",
        expected,
        label="mutable channel pointer",
        attempts=publisher["_POINTER_VERIFY_ATTEMPTS"],
        deadline_seconds=publisher["_POINTER_VERIFY_DEADLINE_SECONDS"],
        retry_seconds=5.0,
        request_seconds=5.0,
        minimum_success_elapsed_seconds=360.0,
        clock=lambda: now[0],
        sleeper=sleep,
    )

    assert fetch_times[0] == 0.0
    assert fetch_times[-1] == 360.0
    assert now[0] == 360.0


def test_anonymous_pointer_slow_exact_fetch_starts_again_after_cache_lifetime() -> None:
    publisher = _publisher()
    expected = b"exact signed pointer\n"
    now = [0.0]
    fetch_start_times: list[float] = []

    def fetch(_url: str, *, maximum: int, timeout_seconds: float) -> bytes:
        assert maximum > 0
        assert timeout_seconds > 0
        fetch_start_times.append(now[0])
        now[0] += 4.9
        return expected

    def sleep(seconds: float) -> None:
        now[0] += seconds

    publisher["_verify_anonymous_pointer"].__globals__["_anonymous_fetch"] = fetch
    publisher["_verify_anonymous_pointer"](
        "https://raw.githubusercontent.com/example/repo/channel/validator/canary.json",
        expected,
        label="mutable channel pointer",
        attempts=publisher["_POINTER_VERIFY_ATTEMPTS"],
        deadline_seconds=publisher["_POINTER_VERIFY_DEADLINE_SECONDS"],
        retry_seconds=5.0,
        request_seconds=5.0,
        minimum_success_elapsed_seconds=360.0,
        clock=lambda: now[0],
        sleeper=sleep,
    )

    assert fetch_start_times == [0.0, 360.0]
    assert now[0] == pytest.approx(364.9)


def test_anonymous_pointer_slow_stale_fetch_still_gets_post_cache_attempt() -> None:
    publisher = _publisher()
    expected = b"exact signed pointer\n"
    now = [0.0]
    fetch_start_times: list[float] = []

    def fetch(_url: str, *, maximum: int, timeout_seconds: float) -> bytes:
        assert maximum > 0
        assert timeout_seconds > 0
        started = now[0]
        fetch_start_times.append(started)
        now[0] += 4.9
        return expected if started >= 360.0 else b"stale pointer\n"

    def sleep(seconds: float) -> None:
        now[0] += seconds

    publisher["_verify_anonymous_pointer"].__globals__["_anonymous_fetch"] = fetch
    publisher["_verify_anonymous_pointer"](
        "https://raw.githubusercontent.com/example/repo/channel/validator/canary.json",
        expected,
        label="mutable channel pointer",
        attempts=publisher["_POINTER_VERIFY_ATTEMPTS"],
        deadline_seconds=publisher["_POINTER_VERIFY_DEADLINE_SECONDS"],
        retry_seconds=5.0,
        request_seconds=5.0,
        minimum_success_elapsed_seconds=360.0,
        clock=lambda: now[0],
        sleeper=sleep,
    )

    assert fetch_start_times[-2] == pytest.approx(356.4)
    assert fetch_start_times[-1] == pytest.approx(361.3)
    assert now[0] == pytest.approx(366.2)


def test_anonymous_pointer_error_reports_last_outcome_without_stale_digest() -> None:
    publisher = _publisher()
    expected = b"exact signed pointer\n"
    responses: list[bytes | UpdateRefused] = [
        b"stale pointer\n",
        UpdateRefused("network unavailable"),
    ]
    now = [0.0]

    def fetch(_url: str, *, maximum: int, timeout_seconds: float) -> bytes:
        assert maximum > 0
        assert timeout_seconds > 0
        response = responses.pop(0)
        if isinstance(response, UpdateRefused):
            raise response
        return response

    def sleep(seconds: float) -> None:
        now[0] += seconds

    publisher["_verify_anonymous_pointer"].__globals__["_anonymous_fetch"] = fetch
    with pytest.raises(UpdateRefused, match="last_result=transport_error") as refused:
        publisher["_verify_anonymous_pointer"](
            "https://raw.githubusercontent.com/example/repo/channel/validator/canary.json",
            expected,
            label="mutable channel pointer",
            attempts=2,
            deadline_seconds=2.0,
            retry_seconds=1.0,
            request_seconds=1.0,
            clock=lambda: now[0],
            sleeper=sleep,
        )

    assert "last_observed_sha256" not in str(refused.value)
    assert "successful_fetches=1; transport_errors=1" in str(refused.value)


def test_mutable_pointer_verification_window_covers_raw_cache_ttl() -> None:
    publisher = _publisher()
    assert (
        publisher["_POINTER_VERIFY_DEADLINE_SECONDS"]
        >= publisher["_RAW_POINTER_CACHE_MAX_AGE_SECONDS"]
        + publisher["_RAW_POINTER_CACHE_SAFETY_MARGIN_SECONDS"]
        + publisher["_POINTER_VERIFY_RETRY_SECONDS"]
        + publisher["_POINTER_VERIFY_REQUEST_SECONDS"]
    )
    assert (publisher["_POINTER_VERIFY_ATTEMPTS"] - 2) * publisher[
        "_POINTER_VERIFY_RETRY_SECONDS"
    ] >= publisher["_MUTABLE_POINTER_MINIMUM_OBSERVATION_SECONDS"]


def test_pinned_pointer_verification_attempts_cover_its_deadline() -> None:
    publisher = _publisher()
    assert (publisher["_PINNED_POINTER_VERIFY_ATTEMPTS"] - 1) * publisher[
        "_PINNED_POINTER_VERIFY_RETRY_SECONDS"
    ] >= publisher["_PINNED_POINTER_VERIFY_DEADLINE_SECONDS"]


def test_publication_rejects_metadata_too_close_to_expiry(tmp_path: Path) -> None:
    publisher = _publisher()
    private, public_path = _key(tmp_path)
    archive = _archive()
    digest = hashlib.sha256(archive).hexdigest()
    archive_path = tmp_path / f"cathedral-validator-{digest}.tar.gz"
    metadata_path = tmp_path / "canary.json"
    archive_path.write_bytes(archive)
    metadata_path.write_bytes(_metadata(private, archive, sequence=1))
    minimum = publisher["_MIN_PUBLICATION_REMAINING_SECONDS"]

    with pytest.raises(UpdateRefused, match="lacks required publication headroom"):
        publisher["validate_publication"](
            metadata_path=metadata_path,
            archive_path=archive_path,
            public_key_path=public_path,
            now_unix=NOW + 3600 - minimum,
        )

    publisher["validate_publication"](
        metadata_path=metadata_path,
        archive_path=archive_path,
        public_key_path=public_path,
        now_unix=NOW + 3600 - minimum - 1,
    )


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


@dataclass(frozen=True)
class _ChannelObject:
    path: str
    sha: str
    size: int


@dataclass(frozen=True)
class _ChannelBranch:
    created: bool
    revision: str


class _FakeGitHub:
    def __init__(
        self,
        *,
        pointer: bytes | None = None,
        branch_created: bool | None = None,
        branch_revision: str | None = None,
        objects: dict[str, bytes] | None = None,
    ) -> None:
        self.pointer = pointer
        self.branch_created = (
            pointer is None if branch_created is None else branch_created
        )
        self.branch_revision = (
            SOURCE_REVISION
            if self.branch_created
            else ("d" * 40 if branch_revision is None else branch_revision)
        )
        self.objects = dict(objects or {})
        self.events: list[str] = []

    def ensure_release(self, publication) -> None:
        assert publication.archive
        self.events.append("release")

    def ensure_branch(self, publication) -> _ChannelBranch:
        self.events.append("branch")
        return _ChannelBranch(
            created=self.branch_created,
            revision=self.branch_revision,
        )

    def list_channel_objects(self, path: str, revision: str):
        assert revision == self.branch_revision
        self.events.append("history-list")
        return (
            tuple(
                _ChannelObject(
                    path=object_path,
                    sha="object-sha",
                    size=len(body),
                )
                for object_path, body in sorted(self.objects.items())
                if object_path.startswith(path + "/")
            )
            or None
        )

    def read_content(self, path: str, revision: str):
        assert revision == self.branch_revision
        if path.endswith("canary.json") and self.pointer is not None:
            return "pointer-sha", self.pointer
        body = self.objects.get(path)
        return None if body is None else ("object-sha", body)

    def commit_channel(self, publication, *, base_revision: str) -> str:
        assert base_revision == self.branch_revision
        self.pointer = publication.metadata
        self.objects[publication.history_path] = publication.metadata
        self.branch_revision = "e" * 40
        self.events.append("channel-commit")
        return self.branch_revision


def _history_object(publication, body: bytes, *, sequence: int) -> dict[str, bytes]:
    digest = hashlib.sha256(body).hexdigest()
    return {
        f"{publication.history_root}/{sequence}-{digest}.json": body,
    }


def _anonymous_publication_fetch(
    publication, github: _FakeGitHub, urls: list[str] | None = None
):
    def fetch(url: str, *, maximum: int, timeout_seconds: float = 60.0) -> bytes:
        if urls is not None:
            urls.append(url)
        assert maximum > 0
        assert timeout_seconds > 0
        if "github.com/" in url:
            return publication.archive
        assert url.endswith("/validator/canary.json")
        return github.pointer or b""

    return fetch


def test_publish_orders_archive_then_atomic_channel_commit(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, public_path, _archive_path, publication = _validated(tmp_path)
    github = _FakeGitHub()
    urls: list[str] = []

    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, github, urls),
    )
    publisher["publish"](
        publication,
        public_key_path=public_path,
        github=github,
    )
    assert github.events == [
        "release",
        "branch",
        "history-list",
        "channel-commit",
    ]
    assert github.pointer == publication.metadata
    assert urls == [
        publication.archive_url,
        (
            "https://raw.githubusercontent.com/cathedralai/cathedral-validator/"
            f"{'e' * 40}/validator/canary.json"
        ),
        (
            "https://raw.githubusercontent.com/cathedralai/cathedral-validator/"
            "validator-release-channel/validator/canary.json"
        ),
    ]


def test_publish_applies_the_full_cache_hold_to_the_mutable_pointer(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, public_path, _archive_path, publication = _validated(tmp_path)
    github = _FakeGitHub()
    production_hold = (
        publisher["_RAW_POINTER_CACHE_MAX_AGE_SECONDS"]
        + publisher["_RAW_POINTER_CACHE_SAFETY_MARGIN_SECONDS"]
    )
    publisher["publish"].__globals__["_MUTABLE_POINTER_MINIMUM_OBSERVATION_SECONDS"] = (
        production_hold
    )
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, github),
    )
    verification_calls: list[tuple[str, dict[str, object]]] = []

    def verify(_url: str, _expected: bytes, *, label: str, **kwargs) -> None:
        verification_calls.append((label, kwargs))

    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_verify_anonymous_pointer",
        verify,
    )

    publisher["publish"](
        publication,
        public_key_path=public_path,
        github=github,
    )

    assert verification_calls[0][0] == "commit-pinned channel pointer"
    assert verification_calls[0][1] == {
        "attempts": publisher["_PINNED_POINTER_VERIFY_ATTEMPTS"],
        "deadline_seconds": publisher["_PINNED_POINTER_VERIFY_DEADLINE_SECONDS"],
        "retry_seconds": publisher["_PINNED_POINTER_VERIFY_RETRY_SECONDS"],
    }
    assert verification_calls[1] == (
        "mutable channel pointer",
        {"minimum_success_elapsed_seconds": production_hold},
    )


def test_idempotent_publish_verifies_the_existing_exact_revision(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, public_path, _archive_path, publication = _validated(tmp_path)
    revision = "d" * 40
    github = _FakeGitHub(
        pointer=publication.metadata,
        branch_created=False,
        branch_revision=revision,
        objects={publication.history_path: publication.metadata},
    )
    urls: list[str] = []
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, github, urls),
    )

    publisher["publish"](
        publication,
        public_key_path=public_path,
        github=github,
    )

    assert github.events == ["release", "branch"]
    assert urls == [
        publication.archive_url,
        (
            "https://raw.githubusercontent.com/cathedralai/cathedral-validator/"
            f"{revision}/validator/canary.json"
        ),
        (
            "https://raw.githubusercontent.com/cathedralai/cathedral-validator/"
            "validator-release-channel/validator/canary.json"
        ),
    ]


def test_publish_retry_after_mutable_verification_failure_does_not_recommit(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, public_path, _archive_path, publication = _validated(tmp_path)
    github = _FakeGitHub()
    anonymous_fetch = _anonymous_publication_fetch(publication, github)
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        anonymous_fetch,
    )
    verify_calls: list[tuple[str, str]] = []
    refuse_mutable = [True]

    def verify(url: str, _expected: bytes, *, label: str, **_kwargs) -> None:
        verify_calls.append((label, url))
        if label == "mutable channel pointer" and refuse_mutable[0]:
            raise UpdateRefused("mutable pointer remained stale")

    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_verify_anonymous_pointer",
        verify,
    )

    with pytest.raises(UpdateRefused, match="remained stale"):
        publisher["publish"](
            publication,
            public_key_path=public_path,
            github=github,
        )

    committed_revision = "e" * 40
    assert github.branch_revision == committed_revision
    assert github.pointer == publication.metadata
    assert github.objects[publication.history_path] == publication.metadata
    assert github.events[-1] == "channel-commit"

    github.events.clear()
    verify_calls.clear()
    refuse_mutable[0] = False
    observed_revision = publisher["publish"](
        publication,
        public_key_path=public_path,
        github=github,
    )

    assert observed_revision == committed_revision
    assert github.events == ["release", "branch"]
    assert [label for label, _url in verify_calls] == [
        "commit-pinned channel pointer",
        "mutable channel pointer",
    ]
    assert committed_revision in verify_calls[0][1]


def test_publish_rechecks_expiry_before_channel_update(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, public_path, _archive_path, publication = _validated(tmp_path)
    now = [NOW]

    class SlowReleaseGitHub(_FakeGitHub):
        def ensure_release(self, publication) -> None:
            super().ensure_release(publication)
            now[0] = (
                publication.expires_unix
                - publisher["_MIN_POINTER_VERIFICATION_REMAINING_SECONDS"]
            )

    github = SlowReleaseGitHub()
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, github),
    )

    with pytest.raises(UpdateRefused, match="before the channel update"):
        publisher["publish"](
            publication,
            public_key_path=public_path,
            github=github,
            wall_clock=lambda: now[0],
        )

    assert "channel-commit" not in github.events
    assert github.pointer is None


def test_publish_refuses_success_if_metadata_expires_during_verification(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, public_path, _archive_path, publication = _validated(tmp_path)
    github = _FakeGitHub()
    now = [NOW]
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, github),
    )

    def verify(_url: str, _expected: bytes, *, label: str, **_kwargs) -> None:
        if label == "mutable channel pointer":
            now[0] = publication.expires_unix

    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_verify_anonymous_pointer",
        verify,
    )

    with pytest.raises(UpdateRefused, match="after pointer verification"):
        publisher["publish"](
            publication,
            public_key_path=public_path,
            github=github,
            wall_clock=lambda: now[0],
        )

    assert github.events[-1] == "channel-commit"
    assert github.pointer == publication.metadata


@pytest.mark.parametrize(
    ("sequence", "expected"),
    ((2, "does not advance retained"), (3, "differs from the retained")),
)
def test_missing_pointer_refuses_different_or_lower_retained_sequence(
    tmp_path: Path, monkeypatch, sequence: int, expected: str
) -> None:
    publisher, private, public_path, _archive_path, publication = _validated(
        tmp_path, sequence=sequence
    )
    retained_archive = publication.archive if sequence == 2 else b"different archive"
    retained = _metadata(private, retained_archive, sequence=3)
    objects = _history_object(publication, retained, sequence=3)
    github = _FakeGitHub(branch_created=False, objects=objects)
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, github),
    )

    with pytest.raises(UpdateRefused, match=expected):
        publisher["publish"](
            publication,
            public_key_path=public_path,
            github=github,
        )
    assert github.events == ["release", "branch", "history-list", "history-list"]
    assert github.objects == objects
    assert github.pointer is None


def test_missing_pointer_resumes_exact_staged_history(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, public_path, _archive_path, publication = _validated(
        tmp_path, sequence=3
    )
    github = _FakeGitHub(
        branch_created=False,
        objects=_history_object(publication, publication.metadata, sequence=3),
    )
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, github),
    )

    publisher["publish"](
        publication,
        public_key_path=public_path,
        github=github,
    )
    assert github.events == [
        "release",
        "branch",
        "history-list",
        "history-list",
        "channel-commit",
    ]
    assert github.pointer == publication.metadata


def test_missing_pointer_advances_stable_retained_history(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, private, public_path, _archive_path, publication = _validated(
        tmp_path, sequence=4
    )
    retained = _metadata(private, publication.archive, sequence=3)
    github = _FakeGitHub(
        branch_created=False,
        objects=_history_object(publication, retained, sequence=3),
    )
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, github),
    )

    publisher["publish"](
        publication,
        public_key_path=public_path,
        github=github,
    )
    assert github.events == [
        "release",
        "branch",
        "history-list",
        "history-list",
        "channel-commit",
    ]
    assert github.pointer == publication.metadata


def test_missing_pointer_refuses_existing_branch_without_retained_history(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, public_path, _archive_path, publication = _validated(tmp_path)
    github = _FakeGitHub(branch_created=False)
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, github),
    )

    with pytest.raises(UpdateRefused, match="without retained signed history"):
        publisher["publish"](
            publication,
            public_key_path=public_path,
            github=github,
        )
    assert github.events == ["release", "branch", "history-list"]
    assert github.objects == {}


def test_first_publication_resumes_an_empty_branch_at_the_exact_source(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, _private, public_path, _archive_path, publication = _validated(tmp_path)
    github = _FakeGitHub(
        branch_created=False,
        branch_revision=publication.source_revision,
    )
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, github),
    )

    publisher["publish"](
        publication,
        public_key_path=public_path,
        github=github,
    )
    assert github.events == [
        "release",
        "branch",
        "history-list",
        "channel-commit",
    ]
    assert github.pointer == publication.metadata


def test_first_publication_requires_an_empty_new_channel_branch(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, private, public_path, _archive_path, publication = _validated(
        tmp_path, sequence=2
    )
    retained = _metadata(private, publication.archive, sequence=1)
    github = _FakeGitHub(
        branch_created=True,
        objects=_history_object(publication, retained, sequence=1),
    )
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, github),
    )

    with pytest.raises(UpdateRefused, match="new channel branch already contains"):
        publisher["publish"](
            publication,
            public_key_path=public_path,
            github=github,
        )
    assert github.events == ["release", "branch", "history-list", "history-list"]
    assert github.pointer is None


def test_missing_pointer_refuses_ambiguous_or_deleted_history(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, private, public_path, _archive_path, publication = _validated(
        tmp_path, sequence=4
    )
    first = _metadata(private, publication.archive, sequence=3)
    second = _metadata(private, b"other retained archive", sequence=3)
    ambiguous_objects = {
        **_history_object(publication, first, sequence=3),
        **_history_object(publication, second, sequence=3),
    }
    ambiguous = _FakeGitHub(branch_created=False, objects=ambiguous_objects)
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, ambiguous),
    )
    with pytest.raises(UpdateRefused, match="repeats a signed sequence"):
        publisher["publish"](
            publication,
            public_key_path=public_path,
            github=ambiguous,
        )

    class DeletingHistory(_FakeGitHub):
        def read_content(self, path: str, branch: str):
            if path.startswith(publication.history_root + "/"):
                self.objects.pop(path, None)
                return None
            return super().read_content(path, branch)

    deleted = DeletingHistory(
        branch_created=False,
        objects=_history_object(publication, first, sequence=3),
    )
    monkeypatch.setitem(
        publisher["publish"].__globals__,
        "_anonymous_fetch",
        _anonymous_publication_fetch(publication, deleted),
    )
    with pytest.raises(UpdateRefused, match="deleted during review"):
        publisher["publish"](
            publication,
            public_key_path=public_path,
            github=deleted,
        )


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
