from __future__ import annotations

import base64
import hashlib
import io
import os
import runpy
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


def _validated(tmp_path: Path, *, sequence: int = 1):
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
        now_unix=NOW,
    )
    return publisher, private, public_path, archive_path, publication


def test_validate_publication_binds_archive_url_name_and_source(tmp_path: Path) -> None:
    _publisher_module, _private, _public, archive_path, publication = _validated(
        tmp_path
    )
    assert publication.archive_sha256 in archive_path.name
    assert publication.tag == f"validator-{publication.archive_sha256}"
    assert publication.source_revision == SOURCE_REVISION
    assert publication.history_path.endswith(f"1-{publication.metadata_sha256}.json")


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

    def ensure_release(self, publication, archive_path: Path) -> None:
        assert archive_path.read_bytes() == publication.archive
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
    publisher, _private, public_path, archive_path, publication = _validated(tmp_path)
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
        archive_path=archive_path,
        public_key_path=public_path,
        github=github,
    )
    assert github.events == ["release", "branch", "history", "pointer"]
    assert github.pointer == publication.metadata


def test_publish_rejects_pointer_rollback_before_channel_write(
    tmp_path: Path, monkeypatch
) -> None:
    publisher, private, public_path, archive_path, publication = _validated(
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
            archive_path=archive_path,
            public_key_path=public_path,
            github=github,
        )
    assert github.events == ["release", "branch"]
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
