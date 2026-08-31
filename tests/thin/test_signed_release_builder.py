from __future__ import annotations

import hashlib
import io
import json
import runpy
import stat
import time
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_thin.independent_runtime.preview_io import canonical_document_bytes
from cathedral_thin.independent_runtime.updater import (
    extract_release_archive,
    parse_release_metadata,
    release_tree_sha256,
)

NOW = int(time.time())
SOURCE_REVISION = "a" * 40
ARCHIVE_URL_TEMPLATE = (
    "https://github.com/cathedralai/cathedral-validator/releases/download/"
    "validator-{archive_sha256}/cathedral-validator-{archive_sha256}.tar.gz"
)


def _builder() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    return runpy.run_path(
        str(root / "deploy" / "validator-update" / "build_signed_release.py")
    )


def test_private_key_loader_supports_encrypted_ed25519_and_hides_passphrases(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    builder = _builder()
    private = Ed25519PrivateKey.generate()
    correct = "correct release custody passphrase"
    wrong = "wrong release custody passphrase"
    path = tmp_path / "encrypted-release-signing-key.pem"
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(correct.encode("utf-8")),
        )
    )
    path.chmod(0o600)
    prompts: list[str] = []
    monkeypatch.setattr(
        builder["getpass"],
        "getpass",
        lambda prompt: (prompts.append(prompt), correct)[1],
    )

    loaded = builder["_private_key"](path)
    assert (
        loaded.public_key().public_bytes_raw()
        == private.public_key().public_bytes_raw()
    )
    assert prompts == ["Release signing key password: "]
    output = capsys.readouterr()
    assert correct not in output.out + output.err

    monkeypatch.setattr(builder["getpass"], "getpass", lambda _prompt: wrong)
    with pytest.raises(builder["UpdateRefused"], match="decryption failed") as refused:
        builder["_private_key"](path)
    output = capsys.readouterr()
    combined = output.out + output.err + str(refused.value)
    assert correct not in combined
    assert wrong not in combined


def _validator_pex(path: Path) -> None:
    pex_info = canonical_document_bytes(
        {
            "distributions": {
                "bittensor-10.5.0-py3-none-any.whl": "1" * 64,
                "cathedral-0.0.0-py3-none-any.whl": "5" * 64,
                "cathedral_scaffold-1.2.3-py3-none-any.whl": "2" * 64,
                "cryptography-48.0.0-py3-none-any.whl": "3" * 64,
                "numpy-2.5.2-py3-none-any.whl": "4" * 64,
            },
            "entry_point": ("cathedral_thin.independent_runtime.direct_validator:main"),
            "inherit_path": "false",
            "inject_env": {},
            "interpreter_constraints": ["CPython==3.12.*"],
            "pex_path": "",
            "pex_paths": [],
            "requirements": [
                "cathedral-scaffold[snp-production] @ "
                "file:///reviewed/cathedral_scaffold-1.2.3-py3-none-any.whl",
                "cathedral@ git+https://github.com/cathedralai/"
                "cathedral-sandbox.git@8dde6eaca27116eed53386a1fa33ec70b74a01fb",
            ],
            "strip_pex_env": True,
        }
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        entries = {
            "PEX-INFO": pex_info,
            "__main__.py": b"raise SystemExit(0)\n",
            "cathedral_thin/__init__.py": b"",
            "cathedral_thin/independent_runtime/__init__.py": b"",
            "cathedral_thin/independent_runtime/direct_validator.py": b"",
            "cathedral_thin/independent_runtime/snp_production.py": b"",
            "cathedral_thin/independent_runtime/telemetry.py": b"",
            "cathedral_thin/independent_runtime/telemetry_exporter.py": b"",
        }
        for name, body in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            bundle.writestr(info, body)
    path.write_bytes(b"#!/usr/bin/python3.12\n" + output.getvalue())
    path.chmod(0o755)


def _executable(path: Path, body: bytes) -> None:
    path.write_bytes(body)
    path.chmod(0o755)


def _inputs(
    tmp_path: Path, *, marker: bytes = b"one"
) -> tuple[Path, Path, Path, Path, Path]:
    pex = tmp_path / f"validator-{marker.decode()}.pex"
    qvl = tmp_path / f"qvl-{marker.decode()}"
    snpguest = tmp_path / f"snpguest-{marker.decode()}"
    _validator_pex(pex)
    _executable(qvl, b"#!/bin/sh\n# qvl " + marker + b"\n")
    _executable(snpguest, b"#!/bin/sh\n# snpguest " + marker + b"\n")
    runtime_lock = (
        Path(__file__).resolve().parents[2]
        / "requirements"
        / "validator-release-cpython312-linux-x86_64.pex.lock"
    )
    raw = pex.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw), "r") as bundle:
        info = bundle.read("PEX-INFO")
    runtime_distributions = tmp_path / f"runtime-{marker.decode()}.json"
    runtime_distributions.write_bytes(
        canonical_document_bytes(
            {
                "schema": "cathedral_validator_pex_distributions_v1",
                "runtime_lock_sha256": hashlib.sha256(
                    runtime_lock.read_bytes()
                ).hexdigest(),
                "pex_sha256": hashlib.sha256(raw).hexdigest(),
                "pex_info_sha256": hashlib.sha256(info).hexdigest(),
                "distributions": json.loads(info)["distributions"],
            }
        )
    )
    runtime_distributions.chmod(0o644)
    return pex, qvl, snpguest, runtime_lock, runtime_distributions


def _build(
    builder: dict[str, Any],
    tmp_path: Path,
    private: Ed25519PrivateKey,
    *,
    name: str,
    sequence: int,
    source_revision: str = SOURCE_REVISION,
    issued_unix: int = NOW,
) -> tuple[Path, Path]:
    pex, qvl, snpguest, runtime_lock, runtime_distributions = _inputs(
        tmp_path, marker=name.encode()
    )
    metadata = tmp_path / f"{name}.json"
    archive = builder["build_canary"](
        pex=pex,
        qvl=qvl,
        snpguest=snpguest,
        runtime_lock=runtime_lock,
        runtime_distributions=runtime_distributions,
        source_revision=source_revision,
        archive_out_dir=tmp_path / f"{name}-archives",
        metadata_out=metadata,
        archive_url_template=ARCHIVE_URL_TEMPLATE,
        sequence=sequence,
        private_key=private,
        issued_unix=issued_unix,
        lifetime_seconds=3600,
    )
    return archive, metadata


def _release(metadata: Path, private: Ed25519PrivateKey, channel: str = "canary"):
    envelope = json.loads(metadata.read_text())
    return parse_release_metadata(
        metadata.read_bytes(),
        channel=channel,
        public_key=private.public_key(),
        now_unix=envelope["signed"]["issued_unix"],
    )


def test_self_contained_signer_parser_matches_installed_updater(
    tmp_path: Path,
) -> None:
    builder = _builder()
    private = Ed25519PrivateKey.generate()
    _archive, metadata = _build(
        builder, tmp_path, private, name="parser-parity", sequence=1
    )
    raw = metadata.read_bytes()
    now = json.loads(raw)["signed"]["issued_unix"]

    signer_release = builder["parse_release_metadata"](
        raw,
        channel="canary",
        public_key=private.public_key(),
        now_unix=now,
    )
    updater_release = parse_release_metadata(
        raw,
        channel="canary",
        public_key=private.public_key(),
        now_unix=now,
    )
    assert asdict(signer_release) == asdict(updater_release)

    for malformed, expected in (
        (b"{}", "release metadata fields are invalid"),
        (raw[:-2], "release metadata is not strict JSON"),
    ):
        for parser in (builder["parse_release_metadata"], parse_release_metadata):
            with pytest.raises(RuntimeError) as refused:
                parser(
                    malformed,
                    channel="canary",
                    public_key=private.public_key(),
                    now_unix=now,
                )
            assert str(refused.value) == expected


def test_strict_canary_binds_all_runtime_files_and_is_deterministic(
    tmp_path: Path,
) -> None:
    builder = _builder()
    private = Ed25519PrivateKey.generate()
    pex, qvl, snpguest, runtime_lock, runtime_distributions = _inputs(tmp_path)

    outputs: list[tuple[Path, Path]] = []
    for suffix in ("first", "second"):
        metadata = tmp_path / f"{suffix}.json"
        archive = builder["build_canary"](
            pex=pex,
            qvl=qvl,
            snpguest=snpguest,
            runtime_lock=runtime_lock,
            runtime_distributions=runtime_distributions,
            source_revision=SOURCE_REVISION,
            archive_out_dir=tmp_path / f"{suffix}-archives",
            metadata_out=metadata,
            archive_url_template=ARCHIVE_URL_TEMPLATE,
            sequence=4,
            private_key=private,
            issued_unix=NOW,
            lifetime_seconds=3600,
        )
        outputs.append((archive, metadata))

    assert outputs[0][0].read_bytes() == outputs[1][0].read_bytes()
    assert outputs[0][1].read_bytes() == outputs[1][1].read_bytes()
    release = _release(outputs[0][1], private)
    assert (
        release.archive_sha256 == hashlib.sha256(outputs[0][0].read_bytes()).hexdigest()
    )
    assert release.archive_url == (
        "https://github.com/cathedralai/cathedral-validator/releases/download/"
        f"validator-{release.archive_sha256}/"
        f"cathedral-validator-{release.archive_sha256}.tar.gz"
    )

    extracted = tmp_path / "extracted"
    extract_release_archive(outputs[0][0].read_bytes(), extracted)
    manifest = json.loads((extracted / "RELEASE.json").read_text())
    assert manifest == {
        "entry_point": "cathedral_thin.independent_runtime.direct_validator:main",
        "interpreter_constraints": ["CPython==3.12.*"],
        "pex_distributions": json.loads((runtime_distributions).read_text())[
            "distributions"
        ],
        "pex_info_sha256": manifest["pex_info_sha256"],
        "pex_sha256": hashlib.sha256(pex.read_bytes()).hexdigest(),
        "project_distribution": "cathedral_scaffold-1.2.3-py3-none-any.whl",
        "qvl_path": "bin/cathedral-tdx-verifier",
        "qvl_sha256": hashlib.sha256(qvl.read_bytes()).hexdigest(),
        "schema": "cathedral_validator_bundle_v2",
        "snpguest_path": "bin/snpguest",
        "snpguest_sha256": hashlib.sha256(snpguest.read_bytes()).hexdigest(),
        "source_revision": SOURCE_REVISION,
        "runtime_lock_sha256": hashlib.sha256(runtime_lock.read_bytes()).hexdigest(),
        "telemetry_module": ("cathedral_thin.independent_runtime.telemetry_exporter"),
    }
    assert (extracted / manifest["qvl_path"]).read_bytes() == qvl.read_bytes()
    assert (extracted / manifest["snpguest_path"]).read_bytes() == snpguest.read_bytes()
    for relative in (
        "bin/cathedral-validator",
        "bin/cathedral-tdx-verifier",
        "bin/snpguest",
    ):
        assert stat.S_IMODE((extracted / relative).stat().st_mode) == 0o555


def test_canary_refuses_a_different_valid_shape_runtime_lock(tmp_path: Path) -> None:
    builder = _builder()
    private = Ed25519PrivateKey.generate()
    pex, qvl, snpguest, _runtime_lock, runtime_distributions = _inputs(tmp_path)
    alternate_lock = tmp_path / "alternate-runtime.pex.lock"
    alternate_lock.write_bytes(
        canonical_document_bytes(
            {
                "style": "strict",
                "pex_version": "2.101.1",
                "locked_resolves": [
                    {"platform_tag": ["cp312", "cp312", "manylinux_2_17_x86_64"]}
                ],
            }
        )
    )
    alternate_lock.chmod(0o644)
    distributions = json.loads(runtime_distributions.read_text())
    distributions["runtime_lock_sha256"] = hashlib.sha256(
        alternate_lock.read_bytes()
    ).hexdigest()
    alternate_distributions = tmp_path / "alternate-runtime-distributions.json"
    alternate_distributions.write_bytes(canonical_document_bytes(distributions))
    alternate_distributions.chmod(0o644)

    with pytest.raises(builder["UpdateRefused"], match="reviewed lock digest"):
        builder["build_canary"](
            pex=pex,
            qvl=qvl,
            snpguest=snpguest,
            runtime_lock=alternate_lock,
            runtime_distributions=alternate_distributions,
            source_revision=SOURCE_REVISION,
            archive_out_dir=tmp_path / "alternate-archives",
            metadata_out=tmp_path / "alternate.json",
            archive_url_template=ARCHIVE_URL_TEMPLATE,
            sequence=1,
            private_key=private,
            issued_unix=NOW,
            lifetime_seconds=3600,
        )


@pytest.mark.parametrize(
    "revision",
    ("", "a" * 39, "a" * 41, "A" * 40, "g" * 40, True, None),
)
def test_source_revision_requires_exact_lowercase_commit(
    revision: object,
) -> None:
    builder = _builder()
    with pytest.raises(builder["UpdateRefused"], match="source revision"):
        builder["_source_revision"](revision)


def test_strict_canary_rejects_uncontrolled_verifiers(tmp_path: Path) -> None:
    builder = _builder()
    target = tmp_path / "target"
    _executable(target, b"reviewed")

    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(builder["UpdateRefused"], match="unavailable"):
        builder["_validated_executable"](link, label="QVL")

    target.chmod(0o775)
    with pytest.raises(builder["UpdateRefused"], match="owner-controlled executable"):
        builder["_validated_executable"](target, label="QVL")

    target.chmod(0o600)
    with pytest.raises(builder["UpdateRefused"], match="owner-controlled executable"):
        builder["_validated_executable"](target, label="QVL")

    with pytest.raises(builder["UpdateRefused"], match="path must be absolute"):
        builder["_validated_executable"](Path("relative-qvl"), label="QVL")


def test_canary_refuses_a_bundle_larger_than_the_updater_accepts(
    tmp_path: Path,
) -> None:
    builder = _builder()
    private = Ed25519PrivateKey.generate()
    pex, qvl, snpguest, runtime_lock, runtime_distributions = _inputs(tmp_path)
    builder["build_canary"].__globals__["MAX_TREE_BYTES"] = 1

    with pytest.raises(builder["UpdateRefused"], match="updater tree limit"):
        builder["build_canary"](
            pex=pex,
            qvl=qvl,
            snpguest=snpguest,
            runtime_lock=runtime_lock,
            runtime_distributions=runtime_distributions,
            source_revision=SOURCE_REVISION,
            archive_out_dir=tmp_path / "oversized-archives",
            metadata_out=tmp_path / "oversized.json",
            archive_url_template=ARCHIVE_URL_TEMPLATE,
            sequence=1,
            private_key=private,
            issued_unix=NOW,
            lifetime_seconds=3600,
        )


@pytest.mark.parametrize(
    "template",
    (
        "http://github.com/cathedralai/cathedral-validator/releases/download/"
        "validator-{archive_sha256}/cathedral-validator-{archive_sha256}.tar.gz",
        "https://example.com/cathedralai/cathedral-validator/releases/download/"
        "validator-{archive_sha256}/cathedral-validator-{archive_sha256}.tar.gz",
        "https://github.com/cathedralai/other/releases/download/"
        "validator-{archive_sha256}/cathedral-validator-{archive_sha256}.tar.gz",
        "https://github.com/cathedralai/cathedral-validator/releases/download/"
        "validator-latest/cathedral-validator-{archive_sha256}.tar.gz",
        "https://github.com/cathedralai/cathedral-validator/releases/download/"
        "validator-{archive_sha256}/cathedral-validator.tar.gz",
        "https://github.com/cathedralai/cathedral-validator/releases/download/"
        "validator-{archive_sha256}/cathedral-validator-{archive_sha256}.tar.gz?x=1",
        "https://github.com/cathedralai/cathedral-validator/releases/download/"
        "validator-{archive_sha256}/cathedral-validator-{unknown}.tar.gz",
    ),
)
def test_archive_url_template_is_exactly_content_addressed(template: str) -> None:
    builder = _builder()
    with pytest.raises(builder["UpdateRefused"], match="archive URL"):
        builder["_archive_url_from_template"](template, "a" * 64)


def test_canary_rollback_resigns_retained_bytes_then_promotes_exactly(
    tmp_path: Path,
) -> None:
    builder = _builder()
    private = Ed25519PrivateKey.generate()
    retained_archive, retained_metadata = _build(
        builder,
        tmp_path,
        private,
        name="retained",
        sequence=4,
        issued_unix=NOW - 100_000,
    )
    _current_archive, current_metadata = _build(
        builder,
        tmp_path,
        private,
        name="current",
        sequence=5,
        source_revision="b" * 40,
    )
    rollback_metadata = tmp_path / "rollback.json"

    builder["resign_canary"](
        current_canary_metadata=current_metadata,
        retained_metadata=retained_metadata,
        retained_archive=retained_archive,
        metadata_out=rollback_metadata,
        sequence=6,
        private_key=private,
        issued_unix=NOW,
        lifetime_seconds=3600,
    )

    retained_release = _release(retained_metadata, private)
    rollback_release = _release(rollback_metadata, private)
    assert rollback_release.sequence == 6
    assert (
        rollback_release.version,
        rollback_release.archive_url,
        rollback_release.archive_sha256,
        rollback_release.tree_sha256,
        rollback_release.entrypoint,
    ) == (
        retained_release.version,
        retained_release.archive_url,
        retained_release.archive_sha256,
        retained_release.tree_sha256,
        retained_release.entrypoint,
    )

    stable_metadata = tmp_path / "stable.json"
    builder["promote_stable"](
        canary_metadata=rollback_metadata,
        metadata_out=stable_metadata,
        sequence=7,
        private_key=private,
        issued_unix=NOW,
        lifetime_seconds=3600,
        enforce_content_addressed=True,
    )
    stable = _release(stable_metadata, private, channel="stable")
    assert stable.archive_sha256 == retained_release.archive_sha256
    assert stable.promoted_canary_sequence == 6
    assert stable.promoted_canary_metadata_sha256 == rollback_release.metadata_sha256


def test_promote_stable_refuses_a_symlinked_canary_metadata(tmp_path: Path) -> None:
    builder = _builder()
    private = Ed25519PrivateKey.generate()
    _archive, canary_metadata = _build(
        builder, tmp_path, private, name="canary", sequence=1
    )
    linked_metadata = tmp_path / "linked-canary.json"
    linked_metadata.symlink_to(canary_metadata)

    with pytest.raises(
        builder["UpdateRefused"], match="canary metadata is unavailable"
    ):
        builder["promote_stable"](
            canary_metadata=linked_metadata,
            metadata_out=tmp_path / "stable.json",
            sequence=1,
            private_key=private,
            issued_unix=NOW,
            lifetime_seconds=3600,
            enforce_content_addressed=True,
        )


def test_canary_rollback_refuses_replay_and_wrong_retained_bytes(
    tmp_path: Path,
) -> None:
    builder = _builder()
    private = Ed25519PrivateKey.generate()
    retained_archive, retained_metadata = _build(
        builder, tmp_path, private, name="retained", sequence=4
    )
    _current_archive, current_metadata = _build(
        builder, tmp_path, private, name="current", sequence=5
    )
    output = tmp_path / "rollback.json"
    arguments = {
        "current_canary_metadata": current_metadata,
        "retained_metadata": retained_metadata,
        "retained_archive": retained_archive,
        "metadata_out": output,
        "private_key": private,
        "issued_unix": NOW,
        "lifetime_seconds": 3600,
    }

    for sequence in (4, 5):
        with pytest.raises(builder["UpdateRefused"], match="must exceed"):
            builder["resign_canary"](sequence=sequence, **arguments)

    _future_archive, future_metadata = _build(
        builder, tmp_path, private, name="future", sequence=7
    )
    with pytest.raises(builder["UpdateRefused"], match="retained canary sequence"):
        builder["resign_canary"](
            sequence=6,
            **(arguments | {"retained_metadata": future_metadata}),
        )

    retained_archive.write_bytes(retained_archive.read_bytes() + b"tampered")
    with pytest.raises(
        builder["UpdateRefused"], match="does not match signed metadata"
    ):
        builder["resign_canary"](sequence=6, **arguments)


def test_canary_rollback_revalidates_inner_runtime_manifest(tmp_path: Path) -> None:
    builder = _builder()
    private = Ed25519PrivateKey.generate()
    retained_archive, retained_metadata = _build(
        builder, tmp_path, private, name="retained", sequence=4
    )
    _current_archive, current_metadata = _build(
        builder, tmp_path, private, name="current", sequence=5
    )
    tree = tmp_path / "tampered-tree"
    extract_release_archive(retained_archive.read_bytes(), tree)
    qvl = tree / "bin" / "cathedral-tdx-verifier"
    qvl.chmod(0o755)
    qvl.write_bytes(b"different QVL")
    qvl.chmod(0o755)
    tampered_archive = tmp_path / "tampered.tar.gz"
    tampered_archive.write_bytes(builder["deterministic_archive"](tree))
    tampered_digest = hashlib.sha256(tampered_archive.read_bytes()).hexdigest()

    signed = json.loads(retained_metadata.read_text())["signed"]
    signed["release"]["archive_sha256"] = tampered_digest
    signed["release"]["tree_sha256"] = release_tree_sha256(tree)
    signed["release"]["archive_url"] = ARCHIVE_URL_TEMPLATE.replace(
        "{archive_sha256}", tampered_digest
    )
    tampered_metadata = tmp_path / "tampered.json"
    tampered_metadata.write_bytes(builder["_signed_envelope"](signed, private))

    with pytest.raises(
        builder["UpdateRefused"], match="QVL does not match RELEASE.json"
    ):
        builder["resign_canary"](
            current_canary_metadata=current_metadata,
            retained_metadata=tampered_metadata,
            retained_archive=tampered_archive,
            metadata_out=tmp_path / "rollback.json",
            sequence=6,
            private_key=private,
            issued_unix=NOW,
            lifetime_seconds=3600,
        )


def test_direct_service_executes_only_verifiers_from_current_release() -> None:
    root = Path(__file__).resolve().parents[2]
    service = (
        root / "deploy" / "validator-update" / "cathedral-validator-direct.service"
    ).read_text()

    assert (
        "AssertFileIsExecutable=/opt/cathedral-validator/current/bin/"
        "cathedral-tdx-verifier"
    ) in service
    assert (
        "AssertFileIsExecutable=/opt/cathedral-validator/current/bin/snpguest"
    ) in service
    assert (
        "--qvl=/opt/cathedral-validator/current/bin/cathedral-tdx-verifier" in service
    )
    assert "--snpguest=/opt/cathedral-validator/current/bin/snpguest" in service
    assert "CATHEDRAL_VALIDATOR_QVL" not in service
    assert "CATHEDRAL_SNPGUEST" not in service
    assert "/usr/local/lib/cathedral-validator" not in service
