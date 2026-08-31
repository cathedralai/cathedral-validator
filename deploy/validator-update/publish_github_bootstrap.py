#!/usr/bin/env python3
"""Publish one authenticated updater bootstrap as an immutable GitHub release."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ASSET_NAMES = {
    "bundle": "updater-bootstrap.tar.gz",
    "manifest": "updater-bootstrap.manifest.json",
    "signature": "updater-bootstrap.manifest.sig",
    "public_key": "bootstrap-signing-public-key.pem",
}
MAX_BUNDLE_BYTES = 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 16_384
_REVISION = re.compile(r"[0-9a-f]{40}")
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
_NOT_FOUND = re.compile(r"(?:HTTP 404|404 Not Found)", re.IGNORECASE)
_RELEASE_PAGE_SIZE = 100
_RELEASE_MAX_PAGES = 10


class BootstrapPublicationRefused(RuntimeError):
    """The bootstrap publication is unsafe, unauthenticated, or equivocal."""


@dataclass(frozen=True)
class Asset:
    name: str
    body: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


@dataclass(frozen=True)
class BootstrapPublication:
    repository: str
    track: str
    target_revision: str
    sequence: int
    manifest_sha256: str
    bundle_sha256: str
    bootstrap_fingerprint: str
    runtime_fingerprint: str
    issued_unix: int
    expires_unix: int
    assets: tuple[Asset, ...]

    @property
    def tag(self) -> str:
        return (
            f"validator-bootstrap-{self.track}-s{self.sequence}-{self.manifest_sha256}"
        )

    def asset_url(self, asset: Asset) -> str:
        return (
            f"https://github.com/{self.repository}/releases/download/"
            f"{self.tag}/{asset.name}"
        )


def _safe_repository(repository: str) -> str:
    component = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?")
    parts = repository.split("/")
    if (
        len(parts) != 2
        or any(component.fullmatch(part) is None for part in parts)
        or any(part in {".", ".."} or part.endswith(".git") for part in parts)
    ):
        raise BootstrapPublicationRefused("GitHub repository is invalid")
    return repository


def _safe_tag(tag: str) -> str:
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", tag) is None
        or ".." in tag
        or tag.endswith((".", ".lock"))
    ):
        raise BootstrapPublicationRefused("GitHub bootstrap tag is invalid")
    return tag


def _controlled_file(path: Path, *, maximum: int, label: str) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise BootstrapPublicationRefused(
            f"{label} path must be an absolute non-symlink file"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BootstrapPublicationRefused(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 1 <= before.st_size <= maximum
        ):
            raise BootstrapPublicationRefused(
                f"{label} is not a bounded owner-controlled file"
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            body = os.read(descriptor, remaining)
            if not body:
                break
            chunks.append(body)
            remaining -= len(body)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or len(raw) > maximum
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise BootstrapPublicationRefused(f"{label} changed while it was read")
        return raw
    finally:
        os.close(descriptor)


def _installer_module() -> ModuleType:
    path = Path(__file__).resolve().with_name("install_updater_bundle.py")
    name = "cathedral_bootstrap_publication_installer_contract"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise BootstrapPublicationRefused("bootstrap installer contract is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _signature_verifier(manifest: bytes, signature: bytes, public_key: bytes) -> None:
    key = serialization.load_pem_public_key(public_key)
    if not isinstance(key, Ed25519PublicKey):
        raise BootstrapPublicationRefused("bootstrap public key is not Ed25519")
    key.verify(signature, manifest)


def _require_canonical_public_key(public_key: bytes) -> None:
    try:
        key = serialization.load_pem_public_key(public_key)
    except (TypeError, ValueError) as exc:
        raise BootstrapPublicationRefused("bootstrap public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise BootstrapPublicationRefused("bootstrap public key is not Ed25519")
    canonical = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if public_key != canonical:
        raise BootstrapPublicationRefused(
            "bootstrap public key is not canonical Ed25519 SPKI PEM"
        )


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


def validate_publication(
    *,
    bundle_path: Path,
    manifest_path: Path,
    signature_path: Path,
    bootstrap_public_key_path: Path,
    expected_bootstrap_fingerprint: str,
    minimum_bootstrap_sequence: int,
    repository: str,
    track: str,
    target_revision: str,
    now_unix: int | None = None,
) -> BootstrapPublication:
    repository = _safe_repository(repository)
    if track not in {"test", "production"}:
        raise BootstrapPublicationRefused("bootstrap publication track is invalid")
    if _REVISION.fullmatch(target_revision) is None:
        raise BootstrapPublicationRefused("bootstrap target revision is invalid")
    if _FINGERPRINT.fullmatch(expected_bootstrap_fingerprint) is None:
        raise BootstrapPublicationRefused("bootstrap fingerprint pin is invalid")

    bodies = {
        "bundle": _controlled_file(
            bundle_path, maximum=MAX_BUNDLE_BYTES, label="bootstrap bundle"
        ),
        "manifest": _controlled_file(
            manifest_path, maximum=MAX_MANIFEST_BYTES, label="bootstrap manifest"
        ),
        "signature": _controlled_file(
            signature_path, maximum=64, label="bootstrap signature"
        ),
        "public_key": _controlled_file(
            bootstrap_public_key_path,
            maximum=MAX_PUBLIC_KEY_BYTES,
            label="bootstrap public key",
        ),
    }
    _require_canonical_public_key(bodies["public_key"])
    installer = _installer_module()
    with tempfile.TemporaryDirectory(prefix="cathedral-bootstrap-verify-") as raw_root:
        root = Path(raw_root)
        os.chmod(root, 0o700)
        staged: dict[str, Path] = {}
        for label, body in bodies.items():
            path = root / ASSET_NAMES[label]
            _write_staged(path, body)
            staged[label] = path
        try:
            verified = installer.verify_bundle(
                bundle_path=staged["bundle"],
                manifest_path=staged["manifest"],
                signature_path=staged["signature"],
                bootstrap_public_key_path=staged["public_key"],
                expected_bootstrap_fingerprint=expected_bootstrap_fingerprint,
                minimum_bootstrap_sequence=minimum_bootstrap_sequence,
                expected_owner=os.geteuid(),
                now_unix=now_unix,
                signature_verifier=_signature_verifier,
            )
        except installer.InstallRefused as exc:
            raise BootstrapPublicationRefused(str(exc)) from exc

    assets = tuple(Asset(ASSET_NAMES[label], bodies[label]) for label in ASSET_NAMES)
    return BootstrapPublication(
        repository=repository,
        track=track,
        target_revision=target_revision,
        sequence=verified.bootstrap_sequence,
        manifest_sha256=verified.manifest_sha256,
        bundle_sha256=hashlib.sha256(bodies["bundle"]).hexdigest(),
        bootstrap_fingerprint=verified.bootstrap_signing_key_fingerprint,
        runtime_fingerprint=verified.runtime_release_key_fingerprint,
        issued_unix=verified.issued_unix,
        expires_unix=verified.expires_unix,
        assets=assets,
    )


class GitHub:
    def __init__(self, repository: str) -> None:
        self.repository = _safe_repository(repository)

    def _run(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        allow_not_found: bool = False,
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
            if allow_not_found and _NOT_FOUND.search(message):
                return result
            raise BootstrapPublicationRefused(
                f"GitHub bootstrap publication failed: {message[:500]}"
            )
        return result

    def api(
        self,
        endpoint: str,
        *,
        method: str = "GET",
        payload: Mapping[str, Any] | None = None,
        allow_not_found: bool = False,
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
        result = self._run(
            arguments,
            input_bytes=body,
            allow_not_found=allow_not_found,
        )
        if result.returncode != 0:
            return None
        try:
            decoded = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BootstrapPublicationRefused("GitHub returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise BootstrapPublicationRefused(
                "GitHub returned an unexpected bootstrap response"
            )
        return decoded

    def require_immutable_releases(self) -> None:
        repository = self.api("")
        if repository is None or repository.get("private") is not False:
            raise BootstrapPublicationRefused(
                "GitHub bootstrap release repository is not public"
            )
        setting = self.api("immutable-releases", allow_not_found=True)
        if setting is None or setting.get("enabled") is not True:
            raise BootstrapPublicationRefused(
                "GitHub repository does not enforce immutable releases"
            )

    def release_by_id(self, release_id: int) -> Mapping[str, Any]:
        if (
            isinstance(release_id, bool)
            or not isinstance(release_id, int)
            or not 1 <= release_id <= 2**63 - 1
        ):
            raise BootstrapPublicationRefused("GitHub release identifier is invalid")
        release = self.api(f"releases/{release_id}")
        if release is None:
            raise BootstrapPublicationRefused("GitHub bootstrap release is unavailable")
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
                raise BootstrapPublicationRefused(
                    "GitHub returned an invalid release list"
                ) from exc
            if not isinstance(records, list):
                raise BootstrapPublicationRefused(
                    "GitHub returned an unexpected release list"
                )
            for record in records:
                if not isinstance(record, dict):
                    raise BootstrapPublicationRefused(
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
                    raise BootstrapPublicationRefused(
                        "GitHub release identifier is invalid"
                    )
                matches.append(release_id)
            if len(records) < _RELEASE_PAGE_SIZE:
                exhausted = True
                break
        if not exhausted:
            raise BootstrapPublicationRefused(
                "GitHub release search exceeded its safe bound"
            )
        if len(matches) > 1:
            raise BootstrapPublicationRefused(
                "GitHub has duplicate releases for the exact bootstrap tag"
            )
        if not matches:
            return None
        return self.release_by_id(matches[0])

    def tag_ref(
        self, tag: str, *, allow_not_found: bool = False
    ) -> Mapping[str, Any] | None:
        tag = _safe_tag(tag)
        encoded = urllib.parse.quote(tag, safe="")
        ref = self.api(f"git/ref/tags/{encoded}", allow_not_found=allow_not_found)
        if ref is None and not allow_not_found:
            raise BootstrapPublicationRefused("GitHub bootstrap tag is unavailable")
        return ref

    def create_release_draft(
        self, publication: BootstrapPublication
    ) -> Mapping[str, Any]:
        _safe_tag(publication.tag)
        notes = (
            "Cathedral validator updater bootstrap.\n\n"
            f"Track: `{publication.track}`\n"
            f"Bootstrap sequence: `{publication.sequence}`\n"
            f"Manifest SHA-256: `{publication.manifest_sha256}`\n"
            f"Bundle SHA-256: `{publication.bundle_sha256}`\n"
            f"Bootstrap key: `{publication.bootstrap_fingerprint}`\n"
            f"Runtime release key: `{publication.runtime_fingerprint}`\n\n"
            "Operators must authenticate the bootstrap public-key fingerprint "
            "outside GitHub before installation.\n"
        )
        draft = self.api(
            "releases",
            method="POST",
            payload={
                "tag_name": publication.tag,
                "target_commitish": publication.target_revision,
                "name": publication.tag,
                "body": notes,
                "draft": True,
                "prerelease": publication.track == "test",
                "make_latest": "false",
            },
        )
        if draft is None:
            raise BootstrapPublicationRefused(
                "new GitHub bootstrap draft is unavailable"
            )
        return draft

    def upload_release_assets(
        self, publication: BootstrapPublication, asset_paths: Sequence[Path]
    ) -> None:
        self._run(
            [
                "release",
                "upload",
                publication.tag,
                *(str(path) for path in asset_paths),
                "--repo",
                publication.repository,
            ]
        )

    def publish_release(
        self, publication: BootstrapPublication, release_id: int
    ) -> Mapping[str, Any]:
        published = self.api(
            f"releases/{release_id}",
            method="PATCH",
            payload={
                "draft": False,
                "prerelease": publication.track == "test",
                "make_latest": "false",
            },
        )
        if published is None:
            raise BootstrapPublicationRefused(
                "published GitHub bootstrap release is unavailable"
            )
        return published


def _anonymous_fetch(url: str, *, maximum: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cathedral-validator-bootstrap-publisher/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status != 200:
                raise BootstrapPublicationRefused(
                    "anonymous bootstrap download did not return HTTP 200"
                )
            body = response.read(maximum + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise BootstrapPublicationRefused(
            "anonymous bootstrap download failed"
        ) from exc
    if len(body) > maximum:
        raise BootstrapPublicationRefused(
            "anonymous bootstrap download exceeds its bound"
        )
    return body


def _verify_release_record(
    publication: BootstrapPublication,
    release: Mapping[str, Any],
    *,
    draft: bool,
    assets: bool,
) -> None:
    expected_immutable = not draft
    if (
        release.get("tag_name") != publication.tag
        or release.get("name") != publication.tag
        or release.get("target_commitish") != publication.target_revision
        or release.get("draft") is not draft
        or release.get("prerelease") != (publication.track == "test")
        or release.get("immutable") is not expected_immutable
    ):
        raise BootstrapPublicationRefused(
            "existing GitHub bootstrap release differs from the exact plan"
        )

    records = release.get("assets")
    if not assets:
        if records != []:
            raise BootstrapPublicationRefused("new GitHub bootstrap draft is not empty")
        return
    if not isinstance(records, list) or len(records) != len(publication.assets):
        raise BootstrapPublicationRefused(
            "GitHub bootstrap release does not contain the exact asset set"
        )
    by_name: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            raise BootstrapPublicationRefused("GitHub bootstrap asset is invalid")
        name = record["name"]
        if name in by_name:
            raise BootstrapPublicationRefused(
                "GitHub bootstrap release repeats an asset"
            )
        by_name[name] = record
    if set(by_name) != {asset.name for asset in publication.assets}:
        raise BootstrapPublicationRefused(
            "GitHub bootstrap release does not contain the exact asset names"
        )
    for asset in publication.assets:
        record = by_name[asset.name]
        if (
            record.get("state") != "uploaded"
            or record.get("size") != len(asset.body)
            or record.get("digest") != f"sha256:{asset.sha256}"
            or record.get("browser_download_url") != publication.asset_url(asset)
        ):
            raise BootstrapPublicationRefused(
                f"GitHub bootstrap asset metadata differs for {asset.name}"
            )


def _verify_tag(publication: BootstrapPublication, tag_ref: Mapping[str, Any]) -> None:
    tag_object = tag_ref.get("object")
    if (
        not isinstance(tag_object, dict)
        or tag_object.get("type") != "commit"
        or tag_object.get("sha") != publication.target_revision
    ):
        raise BootstrapPublicationRefused(
            "GitHub bootstrap tag does not bind the exact target revision"
        )


def _release_id(release: Mapping[str, Any]) -> int:
    release_id = release.get("id")
    if (
        isinstance(release_id, bool)
        or not isinstance(release_id, int)
        or not 1 <= release_id <= 2**63 - 1
    ):
        raise BootstrapPublicationRefused("GitHub release identifier is invalid")
    return release_id


def publish(publication: BootstrapPublication, *, github: GitHub) -> None:
    github.require_immutable_releases()
    existing = github.release(publication.tag)
    if existing is None:
        if github.tag_ref(publication.tag, allow_not_found=True) is not None:
            raise BootstrapPublicationRefused(
                "GitHub bootstrap tag exists without the exact immutable release"
            )
        existing = github.create_release_draft(publication)
    if existing.get("draft") is True:
        release_id = _release_id(existing)
        records = existing.get("assets")
        if records == []:
            _verify_release_record(publication, existing, draft=True, assets=False)
            with tempfile.TemporaryDirectory(
                prefix="cathedral-bootstrap-publish-"
            ) as raw:
                root = Path(raw)
                os.chmod(root, 0o700)
                paths: list[Path] = []
                for asset in publication.assets:
                    path = root / asset.name
                    _write_staged(path, asset.body)
                    paths.append(path)
                github.upload_release_assets(publication, paths)
            existing = github.release_by_id(release_id)
        _verify_release_record(publication, existing, draft=True, assets=True)
        github.publish_release(publication, release_id)
        existing = github.release_by_id(release_id)
    tag_ref = github.tag_ref(publication.tag)
    if tag_ref is None:  # Defensive for alternate GitHub implementations.
        raise BootstrapPublicationRefused("GitHub bootstrap tag is unavailable")
    _verify_release_record(publication, existing, draft=False, assets=True)
    _verify_tag(publication, tag_ref)
    for asset in publication.assets:
        downloaded = _anonymous_fetch(
            publication.asset_url(asset), maximum=len(asset.body)
        )
        if downloaded != asset.body:
            raise BootstrapPublicationRefused(
                f"anonymous GitHub bytes differ for {asset.name}"
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Publish an authenticated immutable validator bootstrap"
    )
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--bootstrap-public-key", required=True, type=Path)
    parser.add_argument("--expected-bootstrap-key-fingerprint", required=True)
    parser.add_argument("--minimum-bootstrap-sequence", required=True, type=int)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--track", required=True, choices=("test", "production"))
    parser.add_argument("--target-revision", required=True)
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
            bundle_path=options.bundle,
            manifest_path=options.manifest,
            signature_path=options.signature,
            bootstrap_public_key_path=options.bootstrap_public_key,
            expected_bootstrap_fingerprint=(options.expected_bootstrap_key_fingerprint),
            minimum_bootstrap_sequence=options.minimum_bootstrap_sequence,
            repository=options.repository,
            track=options.track,
            target_revision=options.target_revision,
        )
        if options.publish:
            publish(publication, github=GitHub(publication.repository))
            status = "PUBLISHED"
        else:
            status = "VALIDATED_NO_WRITE"
    except (BootstrapPublicationRefused, OSError, ValueError) as exc:
        raise SystemExit(f"bootstrap publication refused: {exc}") from exc
    print(
        f"CATHEDRAL_VALIDATOR_BOOTSTRAP_{status} "
        f"track={publication.track} sequence={publication.sequence} "
        f"tag={publication.tag} manifest_sha256={publication.manifest_sha256} "
        f"bundle_sha256={publication.bundle_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
