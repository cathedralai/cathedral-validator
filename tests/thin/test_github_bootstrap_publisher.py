from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy" / "validator-update"
NOW = 1_800_000_000
SOURCE_REVISION = "a" * 40


def _module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


builder = _module(
    "cathedral_test_bootstrap_publisher_builder",
    DEPLOY / "build_updater_bundle.py",
)
publisher = _module(
    "cathedral_test_bootstrap_publisher",
    DEPLOY / "publish_github_bootstrap.py",
)


def _keypair(root: Path, label: str) -> tuple[Path, Path, str]:
    root.mkdir(parents=True)
    private = Ed25519PrivateKey.generate()
    private_path = root / f"{label}-private.pem"
    public_path = root / f"{label}-public.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_path.write_bytes(public)
    public_path.chmod(0o644)
    der = private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_path, public_path, "sha256:" + hashlib.sha256(der).hexdigest()


def _wheelhouse(root: Path) -> tuple[Path, Path]:
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir()
    wheel_path = wheelhouse / "cathedral_scaffold-4.0.0-py3-none-any.whl"
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as wheel:
        records = {
            "cathedral_scaffold/__init__.py": b"__version__ = '4.0.0'\n",
            "cathedral_scaffold-4.0.0.dist-info/METADATA": (
                b"Metadata-Version: 2.1\nName: cathedral-scaffold\nVersion: 4.0.0\n"
            ),
            "cathedral_scaffold-4.0.0.dist-info/WHEEL": (
                b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            ),
        }
        for name, body in sorted(records.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            wheel.writestr(info, body)
    wheel_path.write_bytes(output.getvalue())
    wheel_path.chmod(0o644)
    requirements = root / "requirements.txt"
    requirements.write_text(
        "cathedral-scaffold==4.0.0 --hash=sha256:"
        + hashlib.sha256(output.getvalue()).hexdigest()
        + "\n",
        encoding="ascii",
    )
    requirements.chmod(0o644)
    return wheelhouse, requirements


def _assets(root: Path) -> Path:
    assets = root / "assets"
    assets.mkdir()
    for name in builder.REQUIRED_ASSETS:
        shutil.copyfile(DEPLOY / name, assets / name)
        (assets / name).chmod(0o644)
    return assets


def _stable_metadata(root: Path, private_path: Path) -> Path:
    private = serialization.load_pem_private_key(
        private_path.read_bytes(), password=None
    )
    assert isinstance(private, Ed25519PrivateKey)
    archive_digest = "a" * 64
    signed = {
        "schema": "cathedral_validator_release_v1",
        "channel": "stable",
        "sequence": 9,
        "issued_unix": NOW - 60,
        "expires_unix": NOW + 3600,
        "release": {
            "version": "4.0.0",
            "archive_url": "https://example.invalid/release.tar.gz",
            "archive_sha256": archive_digest,
            "tree_sha256": "b" * 64,
            "entrypoint": "bin/cathedral-validator",
            "promoted_canary": {
                "sequence": 9,
                "signed_sha256": "c" * 64,
                "metadata_sha256": "d" * 64,
                "archive_sha256": archive_digest,
            },
        },
    }
    payload = builder.canonical_json(signed)
    path = root / "stable.json"
    path.write_bytes(
        builder.canonical_json(
            {
                "signed": signed,
                "signature": base64.b64encode(private.sign(payload)).decode("ascii"),
            }
        )
    )
    path.chmod(0o644)
    return path


def _validated(tmp_path: Path, *, track: str = "test"):
    bootstrap_private, bootstrap_public, bootstrap_fingerprint = _keypair(
        tmp_path / "bootstrap", "bootstrap"
    )
    runtime_private, runtime_public, _runtime_fingerprint = _keypair(
        tmp_path / "runtime", "runtime"
    )
    wheelhouse, requirements = _wheelhouse(tmp_path)
    archive, manifest, signature, _, _ = builder.build_bundle(
        wheelhouse=wheelhouse,
        requirements=requirements,
        bootstrap_signing_private_key_path=bootstrap_private,
        bootstrap_signing_public_key_path=bootstrap_public,
        runtime_release_public_key_path=runtime_public,
        stable_release_metadata_path=_stable_metadata(tmp_path, runtime_private),
        assets_dir=_assets(tmp_path),
        sequence=7,
        issued_unix=NOW - 60,
        lifetime_seconds=3600,
    )
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    paths = {
        "bundle_path": artifact_root / "updater-bootstrap.tar.gz",
        "manifest_path": artifact_root / "updater-bootstrap.manifest.json",
        "signature_path": artifact_root / "updater-bootstrap.manifest.sig",
        "bootstrap_public_key_path": artifact_root / "bootstrap-public-key.pem",
    }
    bodies = (archive, manifest, signature, bootstrap_public.read_bytes())
    for path, body in zip(paths.values(), bodies, strict=True):
        path.write_bytes(body)
        path.chmod(0o644)
    publication = publisher.validate_publication(
        **paths,
        expected_bootstrap_fingerprint=bootstrap_fingerprint,
        minimum_bootstrap_sequence=7,
        repository="cathedralai/cathedral-validator",
        track=track,
        target_revision=SOURCE_REVISION,
        now_unix=NOW,
    )
    return publication, paths, bootstrap_fingerprint


def _release_record(
    publication, *, draft: bool = False, draft_token: str = "untagged-91", **changes
):
    record = {
        "id": 91,
        "tag_name": publication.tag,
        "name": publication.tag,
        "target_commitish": publication.target_revision,
        "draft": draft,
        "prerelease": publication.track == "test",
        "immutable": not draft,
        "assets": [
            {
                "name": asset.name,
                "state": "uploaded",
                "size": len(asset.body),
                "digest": f"sha256:{asset.sha256}",
                "browser_download_url": (
                    f"https://github.com/{publication.repository}/releases/download/"
                    f"{draft_token}/{asset.name}"
                    if draft
                    else publication.asset_url(asset)
                ),
            }
            for asset in publication.assets
        ],
    }
    record.update(changes)
    return record


def _tag_record(publication, *, sha: str | None = None):
    return {
        "object": {
            "type": "commit",
            "sha": publication.target_revision if sha is None else sha,
        }
    }


class _FakeGitHub:
    def __init__(
        self,
        publication,
        *,
        immutable_enabled: bool = True,
        existing=None,
        orphan_tag=None,
    ) -> None:
        self.publication = publication
        self.immutable_enabled = immutable_enabled
        self.existing = existing
        self.orphan_tag = orphan_tag
        self.created = False
        self.draft_ready = bool(existing and existing.get("draft") is True)
        self.uploaded = bool(
            self.draft_ready
            and existing.get("assets")
            == _release_record(publication, draft=True)["assets"]
        )
        self.published = False
        self.events: list[str] = []

    def require_immutable_releases(self) -> None:
        self.events.append("immutable-setting")
        if not self.immutable_enabled:
            raise publisher.BootstrapPublicationRefused("immutable releases")

    def release(self, tag: str):
        assert tag == self.publication.tag
        self.events.append("release")
        return self.existing

    def release_by_id(self, release_id: int):
        assert release_id == 91
        self.events.append("release-id")
        if self.published:
            return _release_record(self.publication)
        return _release_record(
            self.publication,
            draft=True,
            assets=_release_record(self.publication, draft=True)["assets"],
        )

    def tag_ref(self, tag: str, *, allow_not_found: bool = False):
        assert tag == self.publication.tag
        self.events.append("tag")
        if self.published or self.existing is not None:
            return _tag_record(self.publication)
        return self.orphan_tag

    def create_release_draft(self, publication):
        assert publication == self.publication
        self.events.append("create-draft")
        self.created = True
        return _release_record(
            self.publication,
            draft=True,
            immutable=False,
            assets=[],
        )

    def upload_release_assets(self, publication, asset_paths) -> None:
        assert publication == self.publication
        assert [path.name for path in asset_paths] == [
            asset.name for asset in publication.assets
        ]
        assert [path.read_bytes() for path in asset_paths] == [
            asset.body for asset in publication.assets
        ]
        assert all(path.stat().st_mode & 0o777 == 0o400 for path in asset_paths)
        self.events.append("upload")
        self.uploaded = True

    def publish_release(self, publication, release_id: int):
        assert publication == self.publication
        assert release_id == 91
        assert (self.created or self.draft_ready) and self.uploaded
        self.events.append("publish-draft")
        self.published = True
        return _release_record(self.publication)


def _anonymous_from(publication):
    by_url = {publication.asset_url(asset): asset.body for asset in publication.assets}

    def fetch(url: str, *, maximum: int) -> bytes:
        body = by_url[url]
        assert maximum == len(body)
        return body

    return fetch


def test_bootstrap_publisher_runs_from_a_clean_checkout(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-E", str(DEPLOY / "publish_github_bootstrap.py"), "--help"],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "authenticated immutable validator bootstrap" in result.stdout


def test_release_lookup_uses_draft_capable_paginated_rest_list(
    tmp_path: Path, monkeypatch
) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path)
    github = publisher.GitHub(publication.repository)
    calls: list[tuple[str, ...]] = []
    expected = _release_record(publication, draft=True, immutable=False, assets=[])

    def run(arguments, **_kwargs):
        calls.append(tuple(arguments))
        return subprocess.CompletedProcess(
            arguments,
            0,
            json.dumps([{"id": 91, "tag_name": publication.tag}]).encode(),
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
    publication, _paths, _fingerprint = _validated(tmp_path)
    github = publisher.GitHub(publication.repository)
    page = [{"id": index + 1, "tag_name": f"other-{index}"} for index in range(100)]
    calls = 0

    def run(arguments, **_kwargs):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(arguments, 0, json.dumps(page).encode(), b"")

    monkeypatch.setattr(github, "_run", run)
    with pytest.raises(publisher.BootstrapPublicationRefused, match="safe bound"):
        github.release(publication.tag)
    assert calls == 10


def test_validate_binds_signed_bootstrap_and_exact_asset_set(tmp_path: Path) -> None:
    publication, _paths, fingerprint = _validated(tmp_path)
    assert publication.sequence == 7
    assert publication.bootstrap_fingerprint == fingerprint
    assert publication.tag == (
        "validator-bootstrap-test-s7-" + publication.manifest_sha256
    )
    assert [asset.name for asset in publication.assets] == list(
        publisher.ASSET_NAMES.values()
    )
    assert publication.issued_unix == NOW - 60
    assert publication.expires_unix == NOW + 3540


def test_validate_refuses_public_key_with_appended_private_material(
    tmp_path: Path, monkeypatch
) -> None:
    _publication, paths, fingerprint = _validated(tmp_path)
    appended_private_key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_key_path = paths["bootstrap_public_key_path"]
    public_key_path.write_bytes(public_key_path.read_bytes() + appended_private_key)
    public_key_path.chmod(0o600)

    def github_call(*_args, **_kwargs):
        raise AssertionError("GitHub must not be called for a non-canonical public key")

    monkeypatch.setattr(publisher.subprocess, "run", github_call)
    with pytest.raises(publisher.BootstrapPublicationRefused, match="not canonical"):
        publisher.validate_publication(
            **paths,
            expected_bootstrap_fingerprint=fingerprint,
            minimum_bootstrap_sequence=7,
            repository="cathedralai/cathedral-validator",
            track="test",
            target_revision=SOURCE_REVISION,
            now_unix=NOW,
        )


def test_validate_requires_absolute_owner_controlled_inputs(tmp_path: Path) -> None:
    publication, paths, fingerprint = _validated(tmp_path)
    assert publication.sequence == 7

    relative = dict(paths)
    relative["bundle_path"] = Path("updater-bootstrap.tar.gz")
    with pytest.raises(publisher.BootstrapPublicationRefused, match="absolute"):
        publisher.validate_publication(
            **relative,
            expected_bootstrap_fingerprint=fingerprint,
            minimum_bootstrap_sequence=7,
            repository="cathedralai/cathedral-validator",
            track="test",
            target_revision=SOURCE_REVISION,
            now_unix=NOW,
        )

    paths["manifest_path"].chmod(0o666)
    with pytest.raises(publisher.BootstrapPublicationRefused, match="owner-controlled"):
        publisher.validate_publication(
            **paths,
            expected_bootstrap_fingerprint=fingerprint,
            minimum_bootstrap_sequence=7,
            repository="cathedralai/cathedral-validator",
            track="test",
            target_revision=SOURCE_REVISION,
            now_unix=NOW,
        )


def test_validate_refuses_wrong_pin_replay_and_unsafe_names(tmp_path: Path) -> None:
    _publication, paths, fingerprint = _validated(tmp_path)
    common = {
        **paths,
        "expected_bootstrap_fingerprint": fingerprint,
        "minimum_bootstrap_sequence": 7,
        "repository": "cathedralai/cathedral-validator",
        "track": "test",
        "target_revision": SOURCE_REVISION,
        "now_unix": NOW,
    }
    with pytest.raises(publisher.BootstrapPublicationRefused, match="fingerprint"):
        publisher.validate_publication(
            **{**common, "expected_bootstrap_fingerprint": "sha256:" + "0" * 64}
        )
    with pytest.raises(publisher.BootstrapPublicationRefused, match="checkpoint"):
        publisher.validate_publication(**{**common, "minimum_bootstrap_sequence": 8})
    with pytest.raises(publisher.BootstrapPublicationRefused, match="repository"):
        publisher.validate_publication(**{**common, "repository": "../repository"})
    with pytest.raises(publisher.BootstrapPublicationRefused, match="track"):
        publisher.validate_publication(**{**common, "track": "stable"})
    with pytest.raises(publisher.BootstrapPublicationRefused, match="revision"):
        publisher.validate_publication(**{**common, "target_revision": "main"})
    with pytest.raises(publisher.BootstrapPublicationRefused, match="tag"):
        publisher._safe_tag("refs/tags/unsafe")


def test_publish_creates_then_anonymously_verifies_exact_immutable_release(
    tmp_path: Path, monkeypatch
) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path)
    github = _FakeGitHub(publication)
    monkeypatch.setattr(publisher, "_anonymous_fetch", _anonymous_from(publication))

    publisher.publish(publication, github=github)

    assert github.events == [
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


def test_publish_is_idempotent_only_for_the_exact_existing_release(
    tmp_path: Path, monkeypatch
) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path, track="production")
    github = _FakeGitHub(publication, existing=_release_record(publication))
    monkeypatch.setattr(publisher, "_anonymous_fetch", _anonymous_from(publication))

    publisher.publish(publication, github=github)

    assert github.created is False
    assert github.events == ["immutable-setting", "release", "tag"]


@pytest.mark.parametrize("already_uploaded", (False, True))
def test_publish_resumes_only_an_exact_same_plan_draft(
    tmp_path: Path, monkeypatch, already_uploaded: bool
) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path)
    existing = _release_record(
        publication,
        draft=True,
        assets=(
            _release_record(publication, draft=True)["assets"]
            if already_uploaded
            else []
        ),
    )
    github = _FakeGitHub(publication, existing=existing)
    monkeypatch.setattr(publisher, "_anonymous_fetch", _anonymous_from(publication))

    publisher.publish(publication, github=github)

    expected = ["immutable-setting", "release"]
    if not already_uploaded:
        expected.extend(["upload", "release-id"])
    expected.extend(["publish-draft", "release-id", "tag"])
    assert github.events == expected
    assert github.created is False


def test_draft_assets_accept_github_untagged_identity(tmp_path: Path) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path)
    draft = _release_record(
        publication,
        draft=True,
        draft_token="untagged-1489237-55b9d805-07a8-4fd8-a18d-6f1ccbd78654",
    )

    publisher._verify_release_record(publication, draft, draft=True, assets=True)


@pytest.mark.parametrize(
    "replacement",
    (
        "https://github.com/cathedralai/other/releases/download/untagged-91/",
        "https://example.com/cathedralai/cathedral-validator/releases/download/untagged-91/",
        "https://github.com/cathedralai/cathedral-validator/releases/download/untagged-91/not-the-asset",
        "https://github.com/cathedralai/cathedral-validator/releases/download/untagged-91/{}?token=secret",
        "https://github.com/cathedralai/cathedral-validator/releases/download/untagged-token..token/",
    ),
)
def test_draft_assets_refuse_noncanonical_untagged_urls(
    tmp_path: Path, replacement: str
) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path)
    draft = _release_record(publication, draft=True)
    asset = publication.assets[0]
    suffix = asset.name if replacement.endswith("/") else ""
    draft["assets"][0]["browser_download_url"] = replacement.format(asset.name) + suffix

    with pytest.raises(
        publisher.BootstrapPublicationRefused, match="draft asset URL differs"
    ):
        publisher._verify_release_record(publication, draft, draft=True, assets=True)


def test_published_assets_still_require_final_tagged_url(tmp_path: Path) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path)
    published = _release_record(publication)
    published["assets"][0]["browser_download_url"] = (
        f"https://github.com/{publication.repository}/releases/download/"
        f"untagged-91/{publication.assets[0].name}"
    )

    with pytest.raises(
        publisher.BootstrapPublicationRefused,
        match="asset metadata differs",
    ):
        publisher._verify_release_record(
            publication, published, draft=False, assets=True
        )


def test_publish_refuses_partial_draft_without_repair(tmp_path: Path) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path)
    partial = _release_record(
        publication,
        draft=True,
        assets=_release_record(publication, draft=True)["assets"][:1],
    )
    github = _FakeGitHub(publication, existing=partial)

    with pytest.raises(publisher.BootstrapPublicationRefused, match="exact asset set"):
        publisher.publish(publication, github=github)
    assert github.events == ["immutable-setting", "release"]
    assert github.created is False


@pytest.mark.parametrize(
    "change",
    (
        {"immutable": False},
        {"target_commitish": "b" * 40},
        {"prerelease": False},
        {"assets": []},
    ),
)
def test_publish_refuses_existing_release_equivocation(
    tmp_path: Path, monkeypatch, change
) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path)
    github = _FakeGitHub(
        publication,
        existing=_release_record(publication, **change),
    )
    monkeypatch.setattr(
        publisher,
        "_anonymous_fetch",
        lambda *_args, **_kwargs: pytest.fail("equivocation was downloaded"),
    )
    with pytest.raises(publisher.BootstrapPublicationRefused):
        publisher.publish(publication, github=github)
    assert github.created is False


def test_publish_refuses_orphan_tag_and_disabled_immutability(tmp_path: Path) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path)
    orphan = _FakeGitHub(
        publication,
        orphan_tag=_tag_record(publication),
    )
    with pytest.raises(publisher.BootstrapPublicationRefused, match="tag exists"):
        publisher.publish(publication, github=orphan)
    assert orphan.created is False

    disabled = _FakeGitHub(publication, immutable_enabled=False)
    with pytest.raises(publisher.BootstrapPublicationRefused, match="immutable"):
        publisher.publish(publication, github=disabled)
    assert disabled.events == ["immutable-setting"]


def test_publish_refuses_tag_target_and_anonymous_byte_equivocation(
    tmp_path: Path, monkeypatch
) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path)
    github = _FakeGitHub(publication, existing=_release_record(publication))
    github.tag_ref = lambda *_args, **_kwargs: _tag_record(  # type: ignore[method-assign]
        publication, sha="b" * 40
    )
    with pytest.raises(publisher.BootstrapPublicationRefused, match="target revision"):
        publisher.publish(publication, github=github)

    exact = _FakeGitHub(publication, existing=_release_record(publication))
    monkeypatch.setattr(
        publisher,
        "_anonymous_fetch",
        lambda *_args, **_kwargs: b"different bytes",
    )
    with pytest.raises(publisher.BootstrapPublicationRefused, match="bytes differ"):
        publisher.publish(publication, github=exact)


def test_github_only_treats_real_404_as_missing(monkeypatch) -> None:
    github = publisher.GitHub("cathedralai/cathedral-validator")
    monkeypatch.setattr(
        publisher.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 1, b"", b"HTTP 404: Not Found"
        ),
    )
    assert github.api("releases/tags/missing", allow_not_found=True) is None

    monkeypatch.setattr(
        publisher.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 1, b"", b"HTTP 403: permission denied"
        ),
    )
    with pytest.raises(
        publisher.BootstrapPublicationRefused, match="permission denied"
    ):
        github.api("releases/tags/private", allow_not_found=True)


def test_immutable_release_preflight_refuses_a_private_repository(monkeypatch) -> None:
    github = publisher.GitHub("cathedralai/cathedral-validator")
    calls: list[str] = []

    def api(endpoint: str, **_kwargs):
        calls.append(endpoint)
        return {"private": True}

    monkeypatch.setattr(github, "api", api)
    with pytest.raises(publisher.BootstrapPublicationRefused, match="not public"):
        github.require_immutable_releases()
    assert calls == [""]


def test_create_upload_publish_use_exact_target_assets_and_classification(
    tmp_path: Path, monkeypatch
) -> None:
    publication, _paths, _fingerprint = _validated(tmp_path)
    github = publisher.GitHub(publication.repository)
    asset_paths = []
    for asset in publication.assets:
        path = tmp_path / asset.name
        path.write_bytes(asset.body)
        asset_paths.append(path)
    api_calls = []
    command_calls = []
    monkeypatch.setattr(
        github,
        "_run",
        lambda arguments, **kwargs: command_calls.append((arguments, kwargs)),
    )
    monkeypatch.setattr(
        github,
        "api",
        lambda endpoint, *, method="GET", payload=None, **_kwargs: (
            api_calls.append((endpoint, method, payload)),
            _release_record(
                publication,
                draft=method == "POST",
                immutable=method != "POST",
                assets=[],
            ),
        )[1],
    )

    github.create_release_draft(publication)
    github.upload_release_assets(publication, asset_paths)
    github.publish_release(publication, 91)

    assert len(command_calls) == 1
    upload, upload_kwargs = command_calls[0]
    assert upload[:3] == ["release", "upload", publication.tag]
    assert upload[3:7] == [str(path) for path in asset_paths]
    assert upload_kwargs == {}
    assert api_calls[0][0:2] == ("releases", "POST")
    create_payload = api_calls[0][2]
    assert create_payload["tag_name"] == publication.tag
    assert create_payload["target_commitish"] == SOURCE_REVISION
    assert create_payload["draft"] is True
    assert create_payload["prerelease"] is True
    assert create_payload["make_latest"] == "false"
    assert publication.bootstrap_fingerprint in create_payload["body"]
    assert api_calls[1] == (
        "releases/91",
        "PATCH",
        {"draft": False, "prerelease": True, "make_latest": "false"},
    )


def test_ci_lints_both_github_publication_boundaries() -> None:
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text()
    assert workflow.count("deploy/validator-update/publish_github_channel.py") == 2
    assert workflow.count("deploy/validator-update/publish_github_bootstrap.py") == 2
