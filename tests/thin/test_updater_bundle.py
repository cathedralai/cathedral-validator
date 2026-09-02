from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
import zipfile
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral_thin.independent_runtime import updater as runtime_updater

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy" / "validator-update"


def _module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


builder = _module(
    "cathedral_test_updater_bundle_builder", DEPLOY / "build_updater_bundle.py"
)
installer = _module(
    "cathedral_test_updater_bundle_installer", DEPLOY / "install_updater_bundle.py"
)
composer = _module(
    "cathedral_test_updater_requirements_composer",
    DEPLOY / "compose_updater_requirements.py",
)


@pytest.mark.parametrize(
    "name",
    (
        "cathedral-validator-canary-update.timer",
        "cathedral-validator-update.timer",
    ),
)
def test_update_timer_schedules_from_activation_and_repeats(name: str) -> None:
    timer = (DEPLOY / name).read_text(encoding="utf-8").splitlines()

    assert not any(line.startswith("OnBootSec=") for line in timer)
    assert timer.count("OnActiveSec=15min") == 1
    assert timer.count("OnUnitActiveSec=1h") == 1
    assert timer.count("RandomizedDelaySec=5min") == 1
    assert "6h" not in timer
    assert "Persistent=true" not in timer


def test_bootstrap_private_key_loader_supports_encryption_and_hides_passphrases(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    private = Ed25519PrivateKey.generate()
    correct = "correct bootstrap custody passphrase"
    wrong = "wrong bootstrap custody passphrase"
    path = tmp_path / "encrypted-bootstrap-signing-key.pem"
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
        builder.getpass,
        "getpass",
        lambda prompt: (prompts.append(prompt), correct)[1],
    )

    loaded = builder._bootstrap_signing_private_key(path)
    assert (
        loaded.public_key().public_bytes_raw()
        == private.public_key().public_bytes_raw()
    )
    assert prompts == ["Bootstrap signing key password: "]
    output = capsys.readouterr()
    assert correct not in output.out + output.err

    monkeypatch.setattr(builder.getpass, "getpass", lambda _prompt: wrong)
    with pytest.raises(builder.BundleRefused, match="decryption failed") as refused:
        builder._bootstrap_signing_private_key(path)
    output = capsys.readouterr()
    combined = output.out + output.err + str(refused.value)
    assert correct not in combined
    assert wrong not in combined


def _keypair(
    root: Path,
    label: str,
) -> tuple[Ed25519PrivateKey, Path, Path, str]:
    root.mkdir(parents=True, exist_ok=True)
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
    fingerprint = installer.ed25519_public_key_fingerprint(public, label)
    return private, private_path, public_path, fingerprint


def _stable_metadata(
    root: Path,
    *,
    private: Ed25519PrivateKey,
    sequence: int,
    issued_unix: int,
) -> Path:
    archive_digest = "a" * 64
    signed = {
        "schema": "cathedral_validator_release_v1",
        "channel": "stable",
        "sequence": sequence,
        "issued_unix": issued_unix,
        "expires_unix": issued_unix + 3600,
        "release": {
            "version": "4.0.0",
            "archive_url": "https://example.invalid/release.tar.gz",
            "archive_sha256": archive_digest,
            "tree_sha256": "b" * 64,
            "entrypoint": "bin/cathedral-validator",
            "promoted_canary": {
                "sequence": sequence,
                "signed_sha256": "c" * 64,
                "metadata_sha256": "d" * 64,
                "archive_sha256": archive_digest,
            },
        },
    }
    payload = builder.canonical_json(signed)
    body = builder.canonical_json(
        {
            "signed": signed,
            "signature": base64.b64encode(private.sign(payload)).decode("ascii"),
        }
    )
    path = root / "stable.json"
    path.write_bytes(body)
    path.chmod(0o644)
    return path


def _resign_stable_metadata(
    values: dict[str, object],
    field_path: tuple[str, ...],
    value: object,
) -> bytes:
    path = values["stable_metadata"]
    document = json.loads(path.read_bytes())
    target = document["signed"]
    for field in field_path[:-1]:
        target = target[field]
    target[field_path[-1]] = value
    payload = builder.canonical_json(document["signed"])
    document["signature"] = base64.b64encode(
        values["runtime_private"].sign(payload)
    ).decode("ascii")
    raw = builder.canonical_json(document)
    path.write_bytes(raw)
    return raw


def _wheel(root: Path, *, private_marker: bool = False) -> tuple[Path, str]:
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(mode=0o755)
    path = wheelhouse / "cathedral_scaffold-4.0.0-py3-none-any.whl"
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as bundle:
        entries = {
            "cathedral_scaffold/__init__.py": b"__version__ = '4.0.0'\n",
            "cathedral_scaffold-4.0.0.dist-info/METADATA": (
                b"Metadata-Version: 2.1\nName: cathedral-scaffold\nVersion: 4.0.0\n"
            ),
            "cathedral_scaffold-4.0.0.dist-info/WHEEL": (
                b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            ),
            "cathedral_scaffold-4.0.0.dist-info/entry_points.txt": (
                b"[console_scripts]\ncathedral-validator-update = "
                b"cathedral_scaffold:update\n"
            ),
        }
        if private_marker:
            entries["cathedral_scaffold/test.key"] = (
                b"-----BEGIN " + b"PRIVATE KEY-----\nnot-allowed\n"
            )
        for name, body in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, body)
    path.write_bytes(output.getvalue())
    path.chmod(0o644)
    return wheelhouse, hashlib.sha256(output.getvalue()).hexdigest()


def _wheel_member(path: Path, name: str, body: bytes) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as bundle:
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        bundle.writestr(info, body)
    path.write_bytes(output.getvalue())


def test_private_key_scan_accepts_source_code_literal_inside_wheel(
    tmp_path: Path,
) -> None:
    path = tmp_path / "source-code-literal.whl"
    _wheel_member(
        path,
        "package/ssh.py",
        b'_SK_START = b"' + builder._PRIVATE_KEY_MARKERS[-1] + b'"\n',
    )
    builder._scan_wheel(path, path.read_bytes())


@pytest.mark.parametrize(
    "body",
    [
        builder._PRIVATE_KEY_MARKERS[0],
        builder._PRIVATE_KEY_MARKERS[0] + b"\n",
        b" \t" + builder._PRIVATE_KEY_MARKERS[2] + b"\t \r\n",
    ],
)
def test_private_key_scan_refuses_marker_on_logical_line(body: bytes) -> None:
    scanner = builder._PrivateKeyLineScanner("private-key fixture")
    with pytest.raises(builder.BundleRefused, match="contains private-key material"):
        scanner.feed(body)
        scanner.finish()


def test_control_file_scan_refuses_inline_private_key_marker() -> None:
    body = b"IDENTITY_KEY=" + builder._PRIVATE_KEY_MARKERS[0] + b"\n"
    with pytest.raises(builder.BundleRefused, match="contains private-key material"):
        builder._refuse_private_key(body, "reviewed environment")


def test_private_key_scan_refuses_marker_split_across_wheel_read_chunks(
    tmp_path: Path,
) -> None:
    path = tmp_path / "chunked-private-key.whl"
    prefix = b"-----BEGIN OPENSSH "
    _wheel_member(
        path,
        "package/test.key",
        b" " * (64 * 1024 - len(prefix)) + prefix + b"PRIVATE KEY-----\r\n",
    )
    with pytest.raises(builder.BundleRefused, match="contains private-key material"):
        builder._scan_wheel(path, path.read_bytes())


def test_private_key_scan_refuses_private_key_inside_wheel(tmp_path: Path) -> None:
    path = tmp_path / "private-key.whl"
    _wheel_member(
        path,
        "package/test.key",
        builder._PRIVATE_KEY_MARKERS[0] + b"\nsecret\n",
    )
    with pytest.raises(builder.BundleRefused, match="contains private-key material"):
        builder._scan_wheel(path, path.read_bytes())


def test_project_and_scaffold_versions_remain_identical() -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project_version = tomllib.load(handle)["project"]["version"]
    scaffold = (ROOT / "scaffold" / "__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{project_version}"' in scaffold


def _updater_dependency_wheelhouse(
    root: Path,
) -> tuple[Path, Path, dict[str, tuple[Path, str]]]:
    wheelhouse = root / "updater-wheelhouse"
    wheelhouse.mkdir(parents=True)
    files = {
        "cathedral-scaffold": "cathedral_scaffold-4.0.0-py3-none-any.whl",
        "cffi": (
            "cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl"
        ),
        "cryptography": ("cryptography-50.0.1-cp311-abi3-manylinux_2_34_x86_64.whl"),
        "pycparser": "pycparser-3.0-py3-none-any.whl",
    }
    records: dict[str, tuple[Path, str]] = {}
    for name, filename in files.items():
        wheel = wheelhouse / filename
        wheel.write_bytes(f"reviewed fixture for {name}\n".encode())
        records[name] = (wheel, hashlib.sha256(wheel.read_bytes()).hexdigest())
    lock = root / "updater-third-party.lock"
    lock.write_text(
        "# retained reviewed third-party lines\n"
        + "".join(
            f"{name}=={composer.EXPECTED_THIRD_PARTY[name]} "
            f"--hash=sha256:{records[name][1]}\n"
            for name in sorted(composer.EXPECTED_THIRD_PARTY)
        ),
        encoding="ascii",
    )
    return wheelhouse, lock, records


def _assets(root: Path) -> Path:
    assets = root / "assets"
    assets.mkdir(mode=0o755)
    for name in builder.REQUIRED_ASSETS:
        shutil.copyfile(DEPLOY / name, assets / name)
        (assets / name).chmod(0o644)
    return assets


def _inputs(tmp_path: Path) -> dict[str, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (
        bootstrap_private,
        bootstrap_private_path,
        bootstrap_public_path,
        bootstrap_fingerprint,
    ) = _keypair(tmp_path / "bootstrap-key", "bootstrap")
    (
        runtime_private,
        _,
        runtime_public_path,
        runtime_fingerprint,
    ) = _keypair(tmp_path / "runtime-key", "runtime")
    wheelhouse, digest = _wheel(tmp_path)
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        f"cathedral-scaffold==4.0.0 --hash=sha256:{digest}\n",
        encoding="utf-8",
    )
    requirements.chmod(0o644)
    issued_unix = int(time.time()) - 60
    stable_sequence = 7
    return {
        "bootstrap_private": bootstrap_private,
        "bootstrap_private_path": bootstrap_private_path,
        "bootstrap_public_path": bootstrap_public_path,
        "bootstrap_fingerprint": bootstrap_fingerprint,
        "runtime_public_path": runtime_public_path,
        "runtime_private": runtime_private,
        "runtime_fingerprint": runtime_fingerprint,
        "stable_sequence": stable_sequence,
        "stable_metadata": _stable_metadata(
            tmp_path,
            private=runtime_private,
            sequence=stable_sequence,
            issued_unix=issued_unix,
        ),
        "sequence": 1,
        "issued_unix": issued_unix,
        "lifetime_seconds": 24 * 60 * 60,
        "wheelhouse": wheelhouse,
        "requirements": requirements,
        "assets": _assets(tmp_path),
    }


def _build(
    values: dict[str, object],
) -> tuple[bytes, bytes, bytes, str, str]:
    return builder.build_bundle(
        wheelhouse=values["wheelhouse"],
        requirements=values["requirements"],
        bootstrap_signing_private_key_path=values["bootstrap_private_path"],
        bootstrap_signing_public_key_path=values["bootstrap_public_path"],
        runtime_release_public_key_path=values["runtime_public_path"],
        stable_release_metadata_path=values["stable_metadata"],
        assets_dir=values["assets"],
        sequence=values["sequence"],
        issued_unix=values["issued_unix"],
        lifetime_seconds=values["lifetime_seconds"],
    )


def _artifacts(
    root: Path,
    archive: bytes,
    manifest: bytes,
    signature: bytes,
    public_path: Path,
) -> tuple[Path, Path, Path, Path]:
    root.mkdir(parents=True, exist_ok=True)
    bundle_path = root / "updater-bootstrap.tar.gz"
    manifest_path = root / "updater-bootstrap.manifest.json"
    signature_path = root / "updater-bootstrap.manifest.sig"
    trusted_path = root / "bootstrap-public-key.pem"
    bundle_path.write_bytes(archive)
    manifest_path.write_bytes(manifest)
    signature_path.write_bytes(signature)
    trusted_path.write_bytes(public_path.read_bytes())
    for path in (bundle_path, manifest_path, signature_path, trusted_path):
        path.chmod(0o644)
    return bundle_path, manifest_path, signature_path, trusted_path


def _verifier(manifest: bytes, signature: bytes, public: bytes) -> None:
    key = serialization.load_pem_public_key(public)
    key.verify(signature, manifest)


def _verified(tmp_path: Path) -> tuple[object, dict[str, object], tuple[Path, ...]]:
    values = _inputs(tmp_path)
    verified, artifacts = _verify_values(tmp_path / "artifacts", values)
    return verified, values, artifacts


def _verify_values(
    artifact_root: Path,
    values: dict[str, object],
) -> tuple[object, tuple[Path, ...]]:
    archive, manifest, signature, _, _ = _build(values)
    artifacts = _artifacts(
        artifact_root,
        archive,
        manifest,
        signature,
        values["bootstrap_public_path"],
    )
    verified = installer.verify_bundle(
        bundle_path=artifacts[0],
        manifest_path=artifacts[1],
        signature_path=artifacts[2],
        bootstrap_public_key_path=artifacts[3],
        expected_bootstrap_fingerprint=values["bootstrap_fingerprint"],
        minimum_bootstrap_sequence=1,
        expected_owner=os.geteuid(),
        signature_verifier=_verifier,
    )
    return verified, artifacts


def _fake_runner(
    calls: list[list[str]],
    *,
    fail_pip: bool = False,
    interrupt_pip: bool = False,
    fail_preflight: bool = False,
    fail_daemon_reload: bool = False,
):
    def run(command, **kwargs):
        command = [str(value) for value in command]
        calls.append(command)
        if "import ensurepip, venv" in command[-1] and fail_preflight:
            raise subprocess.CalledProcessError(1, command)
        if command[1:4] == ["-m", "venv", command[-1]]:
            version = Path(command[-1])
            (version / "bin").mkdir(parents=True, exist_ok=True)
            python = version / "bin" / installer.VENV_INTERPRETER_NAME
            python.write_text("#!/bin/sh\nexit 0\n")
            python.chmod(0o755)
            (version / "bin" / "python").symlink_to(installer.VENV_INTERPRETER_NAME)
            updater = version / "bin" / "cathedral-validator-update"
            updater.write_text(f"#!{python}\nexit 0\n")
            updater.chmod(0o755)
        elif "install" in command and interrupt_pip:
            raise KeyboardInterrupt
        elif "install" in command and fail_pip:
            raise subprocess.CalledProcessError(1, command)
        elif command[-1] == "daemon-reload" and fail_daemon_reload:
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0, "", "")

    return run


def _resign_archive(
    values: dict[str, object],
    manifest: bytes,
    archive: bytes,
) -> tuple[bytes, bytes]:
    document = json.loads(manifest)
    document["bundle"] = {
        "sha256": hashlib.sha256(archive).hexdigest(),
        "size": len(archive),
    }
    new_manifest = builder.canonical_json(document)
    return new_manifest, values["bootstrap_private"].sign(new_manifest)


def test_builder_is_reproducible_and_contains_no_private_key(tmp_path):
    values = _inputs(tmp_path)
    first = _build(values)
    second = _build(values)
    assert first == second
    (
        archive,
        manifest,
        signature,
        bootstrap_fingerprint,
        runtime_fingerprint,
    ) = first
    assert len(signature) == 64
    assert bootstrap_fingerprint == values["bootstrap_fingerprint"]
    assert runtime_fingerprint == values["runtime_fingerprint"]
    assert bootstrap_fingerprint != runtime_fingerprint
    assert b"PRIVATE KEY" not in archive
    assert b"PRIVATE KEY" not in manifest
    document = json.loads(manifest)
    assert document["schema"] == "cathedral_validator_updater_bootstrap_v3"
    assert document["bootstrap_signing_key"] == {
        "algorithm": "Ed25519",
        "fingerprint": values["bootstrap_fingerprint"],
        "source": "operator-pinned-external",
    }
    assert document["bootstrap_metadata"] == {
        "expires_unix": values["issued_unix"] + values["lifetime_seconds"],
        "issued_unix": values["issued_unix"],
        "sequence": values["sequence"],
    }
    assert document["runtime_release_key"] == {
        "algorithm": "Ed25519",
        "fingerprint": values["runtime_fingerprint"],
        "path": "payload/runtime-release-public-key.pem",
    }
    assert document["stable_release_floor"] == {
        "metadata_sha256": hashlib.sha256(
            values["stable_metadata"].read_bytes()
        ).hexdigest(),
        "sequence": values["stable_sequence"],
    }
    assert "public_key" not in document
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        names = bundle.getnames()
        assert names == sorted(names)
        assert names.count("payload/installer/install_updater_bundle.py") == 1
        assert names.count("payload/runtime-release-public-key.pem") == 1
        assert all(member.uid == 0 and member.gid == 0 for member in bundle)
        assert all(member.mtime == 0 for member in bundle)
        runtime_member = bundle.extractfile("payload/runtime-release-public-key.pem")
        assert runtime_member is not None
        assert runtime_member.read() == values["runtime_public_path"].read_bytes()
        update_member = bundle.extractfile("payload/examples/update.env.example")
        assert update_member is not None
        update_body = update_member.read()
        assert (
            f"CATHEDRAL_VALIDATOR_STABLE_MINIMUM_SEQUENCE={values['stable_sequence']}\n".encode()
            in update_body
        )
        assert builder.STABLE_SEQUENCE_PLACEHOLDER not in update_body
        stable_digest = document["stable_release_floor"]["metadata_sha256"]
        assert (
            f"CATHEDRAL_VALIDATOR_STABLE_METADATA_SHA256={stable_digest}\n".encode()
            in update_body
        )
        assert builder.STABLE_METADATA_SHA256_PLACEHOLDER not in update_body
        assert installer._stable_floor_from_example(update_body) == (
            values["stable_sequence"],
            stable_digest,
        )


def test_builder_requires_matching_bootstrap_pair_and_distinct_runtime_key(tmp_path):
    values = _inputs(tmp_path / "mismatch")
    values["bootstrap_public_path"] = values["runtime_public_path"]
    with pytest.raises(builder.BundleRefused, match="does not match"):
        _build(values)


def test_builder_binds_floor_to_verified_stable_metadata(tmp_path):
    values = _inputs(tmp_path)
    metadata = json.loads(values["stable_metadata"].read_bytes())
    metadata["signed"]["sequence"] += 1
    values["stable_metadata"].write_bytes(builder.canonical_json(metadata))

    with pytest.raises(builder.BundleRefused, match="signature is invalid"):
        _build(values)

    values = _inputs(tmp_path / "same-key")
    values["runtime_public_path"] = values["bootstrap_public_path"]
    with pytest.raises(builder.BundleRefused, match="must be distinct"):
        _build(values)


def test_builder_stable_contract_matches_runtime_parser(tmp_path):
    values = _inputs(tmp_path)
    raw = values["stable_metadata"].read_bytes()
    public_key = values["runtime_private"].public_key()
    now_unix = values["issued_unix"] + 60

    release = runtime_updater.parse_release_metadata(
        raw,
        channel="stable",
        public_key=public_key,
        now_unix=now_unix,
    )
    sequence, metadata_sha256 = builder._stable_release_sequence(
        values["stable_metadata"],
        public_key=public_key,
        now_unix=now_unix,
    )

    assert sequence == release.sequence
    assert metadata_sha256 == release.metadata_sha256


@pytest.mark.parametrize(
    ("field_path", "value", "builder_error"),
    (
        (("release", "version"), "", "release version is invalid"),
        (
            ("release", "archive_url"),
            "http://example.invalid/release.tar.gz",
            "archive URL must be HTTPS",
        ),
        (
            ("release", "archive_sha256"),
            "A" * 64,
            "archive digest is not a lower-case SHA-256 digest",
        ),
        (
            ("release", "tree_sha256"),
            "b" * 63,
            "tree digest is not a lower-case SHA-256 digest",
        ),
        (
            ("release", "entrypoint"),
            "../bin/cathedral-validator",
            "release entrypoint escapes its release",
        ),
        (
            ("release", "promoted_canary", "sequence"),
            True,
            "promoted canary sequence is invalid",
        ),
        (
            ("release", "promoted_canary", "signed_sha256"),
            "C" * 64,
            "promoted canary signed digest is not a lower-case SHA-256 digest",
        ),
        (
            ("release", "promoted_canary", "metadata_sha256"),
            "d" * 63,
            "promoted canary metadata digest is not a lower-case SHA-256 digest",
        ),
        (
            ("release", "promoted_canary", "archive_sha256"),
            "e" * 64,
            "stable release is not the exact promoted canary archive",
        ),
    ),
)
def test_builder_rejects_every_runtime_stable_release_contract_violation(
    tmp_path, field_path, value, builder_error
):
    values = _inputs(tmp_path)
    raw = _resign_stable_metadata(values, field_path, value)
    public_key = values["runtime_private"].public_key()
    now_unix = values["issued_unix"] + 60

    with pytest.raises(runtime_updater.UpdateRefused):
        runtime_updater.parse_release_metadata(
            raw,
            channel="stable",
            public_key=public_key,
            now_unix=now_unix,
        )
    with pytest.raises(builder.BundleRefused, match=builder_error):
        builder._stable_release_sequence(
            values["stable_metadata"],
            public_key=public_key,
            now_unix=now_unix,
        )


def test_bootstrap_builder_keeps_the_offline_signer_import_boundary() -> None:
    source = (DEPLOY / "build_updater_bundle.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert not any(name.startswith("cathedral_thin") for name in imported_modules)
    assert "build_signed_release" not in imported_modules


def test_builder_cli_names_bootstrap_and_runtime_key_roles() -> None:
    options = {
        option
        for action in builder._parser()._actions
        for option in action.option_strings
    }
    assert "--bootstrap-signing-private-key" in options
    assert "--bootstrap-signing-public-key" in options
    assert "--runtime-release-public-key" in options
    assert "--stable-release-metadata" in options
    assert "--sequence" in options
    assert "--issued-unix" in options
    assert "--lifetime-seconds" in options
    assert "--private-key" not in options
    assert "--public-key" not in options


def test_builder_refuses_incomplete_hash_lock_and_private_key_in_wheel(tmp_path):
    values = _inputs(tmp_path)
    values["requirements"].write_text(
        "cathedral-scaffold==4.0.0 --hash=sha256:" + "0" * 64 + "\n"
    )
    with pytest.raises(builder.BundleRefused, match="match every wheel"):
        _build(values)

    second = tmp_path / "private-wheel"
    second.mkdir()
    values = _inputs(second)
    shutil.rmtree(values["wheelhouse"])
    wheelhouse, digest = _wheel(second, private_marker=True)
    values["wheelhouse"] = wheelhouse
    values["requirements"].write_text(
        f"cathedral-scaffold==4.0.0 --hash=sha256:{digest}\n"
    )
    with pytest.raises(builder.BundleRefused, match="private-key material"):
        _build(values)


def test_updater_lock_composer_preserves_reviewed_lines_and_binds_local_wheel(
    tmp_path,
):
    wheelhouse, third_party_lock, records = _updater_dependency_wheelhouse(tmp_path)
    output = tmp_path / "updater-requirements.lock"

    body = composer.compose_lock(
        wheelhouse=wheelhouse,
        third_party_lock=third_party_lock,
        output=output,
    )

    assert body == output.read_bytes()
    assert body.startswith(third_party_lock.read_bytes())
    assert body.endswith(
        (
            "cathedral-scaffold==4.0.0 "
            f"--hash=sha256:{records['cathedral-scaffold'][1]}\n"
        ).encode("ascii")
    )
    assert body.count(b"--hash=sha256:") == 4


def test_updater_lock_composer_refuses_substitution_and_extra_wheel(tmp_path):
    substituted = tmp_path / "substituted"
    wheelhouse, third_party_lock, records = _updater_dependency_wheelhouse(substituted)
    records["cffi"][0].write_bytes(b"substituted wheel bytes\n")
    with pytest.raises(composer.LockCompositionRefused, match="committed lock"):
        composer.compose_lock(
            wheelhouse=wheelhouse,
            third_party_lock=third_party_lock,
            output=substituted / "output.lock",
        )

    expanded = tmp_path / "expanded"
    wheelhouse, third_party_lock, _records = _updater_dependency_wheelhouse(expanded)
    (wheelhouse / "bittensor-10.5.0-py3-none-any.whl").write_bytes(b"not allowed\n")
    with pytest.raises(composer.LockCompositionRefused, match="four files"):
        composer.compose_lock(
            wheelhouse=wheelhouse,
            third_party_lock=third_party_lock,
            output=expanded / "output.lock",
        )


def test_updater_lock_composer_refuses_changed_reviewed_hash(tmp_path):
    wheelhouse, third_party_lock, _records = _updater_dependency_wheelhouse(tmp_path)
    text = third_party_lock.read_text(encoding="ascii")
    third_party_lock.write_text(
        text.replace(
            next(
                line.split("sha256:", 1)[1]
                for line in text.splitlines()
                if line.startswith("cryptography==")
            ),
            "0" * 64,
        ),
        encoding="ascii",
    )
    with pytest.raises(composer.LockCompositionRefused, match="committed lock"):
        composer.compose_lock(
            wheelhouse=wheelhouse,
            third_party_lock=third_party_lock,
            output=tmp_path / "output.lock",
        )


def test_builder_refuses_symlinked_asset_and_permissive_private_key(tmp_path):
    values = _inputs(tmp_path)
    asset = values["assets"] / "update.env.example"
    target = tmp_path / "outside.env"
    target.write_text("outside\n")
    asset.unlink()
    asset.symlink_to(target)
    with pytest.raises(builder.BundleRefused, match="non-symlink"):
        _build(values)

    second = tmp_path / "key-mode"
    second.mkdir()
    values = _inputs(second)
    values["bootstrap_private_path"].chmod(0o644)
    with pytest.raises(builder.BundleRefused, match="owner-controlled"):
        _build(values)


def test_output_writer_never_overwrites_an_existing_artifact(tmp_path):
    values = _inputs(tmp_path)
    archive, manifest, signature, _, _ = _build(values)
    output = tmp_path / "output"
    output.mkdir()
    bundle_path = output / "bundle.tar.gz"
    manifest_path = output / "manifest.json"
    signature_path = output / "manifest.sig"
    bundle_path.write_bytes(b"operator artifact\n")
    with pytest.raises(builder.BundleRefused, match="already exists"):
        builder.write_outputs(
            bundle_out=bundle_path,
            manifest_out=manifest_path,
            signature_out=signature_path,
            archive=archive,
            manifest=manifest,
            signature=signature,
        )
    assert bundle_path.read_bytes() == b"operator artifact\n"
    assert not manifest_path.exists()
    assert not signature_path.exists()


def test_verifier_rejects_wrong_pin_bad_signature_and_tampered_archive(tmp_path):
    verified, values, artifacts = _verified(tmp_path)
    assert verified.bootstrap_signing_key_fingerprint == values["bootstrap_fingerprint"]
    assert verified.runtime_release_key_fingerprint == values["runtime_fingerprint"]

    with pytest.raises(installer.InstallRefused, match="operator pin"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint="sha256:" + "0" * 64,
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )

    document = json.loads(artifacts[1].read_bytes())
    document["bundle"]["sha256"] = "1" * 64
    artifacts[1].write_bytes(builder.canonical_json(document))
    with pytest.raises(installer.InstallRefused, match="signature"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint=values["bootstrap_fingerprint"],
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )

    archive, manifest, signature, _, _ = _build(values)
    artifacts[0].write_bytes(archive[:-1] + bytes([archive[-1] ^ 1]))
    artifacts[1].write_bytes(manifest)
    artifacts[2].write_bytes(signature)
    with pytest.raises(installer.InstallRefused, match="bundle bytes"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint=values["bootstrap_fingerprint"],
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )


def test_verifier_binds_runtime_key_and_rejects_old_one_key_schema(tmp_path):
    values = _inputs(tmp_path)
    archive, manifest, _, _, _ = _build(values)
    document = json.loads(manifest)
    document["runtime_release_key"]["fingerprint"] = "sha256:" + "0" * 64
    mismatched_manifest = builder.canonical_json(document)
    mismatched_signature = values["bootstrap_private"].sign(mismatched_manifest)
    artifacts = _artifacts(
        tmp_path / "runtime-mismatch",
        archive,
        mismatched_manifest,
        mismatched_signature,
        values["bootstrap_public_path"],
    )
    with pytest.raises(
        installer.InstallRefused,
        match="runtime release key fingerprint differs",
    ):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint=values["bootstrap_fingerprint"],
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )

    old_document = json.loads(manifest)
    old_document["schema"] = "cathedral_validator_updater_bootstrap_v1"
    old_manifest = builder.canonical_json(old_document)
    old_signature = values["bootstrap_private"].sign(old_manifest)
    artifacts[1].write_bytes(old_manifest)
    artifacts[2].write_bytes(old_signature)
    with pytest.raises(installer.InstallRefused, match="schema is unsupported"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint=values["bootstrap_fingerprint"],
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )


def test_verifier_binds_update_example_to_the_stable_metadata_digest(tmp_path):
    values = _inputs(tmp_path)
    archive, manifest, _, _, _ = _build(values)
    document = json.loads(manifest)
    stable_digest = hashlib.sha256(values["stable_metadata"].read_bytes()).hexdigest()
    assert document["stable_release_floor"]["metadata_sha256"] == stable_digest

    document["stable_release_floor"]["metadata_sha256"] = "0" * 64
    mismatched_manifest = builder.canonical_json(document)
    mismatched_signature = values["bootstrap_private"].sign(mismatched_manifest)
    artifacts = _artifacts(
        tmp_path / "digest-mismatch",
        archive,
        mismatched_manifest,
        mismatched_signature,
        values["bootstrap_public_path"],
    )
    with pytest.raises(
        installer.InstallRefused,
        match="differs from the authenticated stable floor",
    ):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint=values["bootstrap_fingerprint"],
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )

    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        member = bundle.extractfile("payload/examples/update.env.example")
        assert member is not None
        body = member.read()
    digest_line = (
        f"CATHEDRAL_VALIDATOR_STABLE_METADATA_SHA256={stable_digest}\n".encode()
    )
    assert body.count(digest_line) == 1
    with pytest.raises(installer.InstallRefused, match="no exact stable metadata"):
        installer._stable_floor_from_example(body.replace(digest_line, b""))
    with pytest.raises(installer.InstallRefused, match="no exact stable metadata"):
        installer._stable_floor_from_example(body + digest_line)

    example_asset = values["assets"] / "update.env.example"
    example_asset.write_bytes(
        example_asset.read_bytes().replace(
            builder.STABLE_METADATA_SHA256_PLACEHOLDER, b"0" * 64
        )
    )
    with pytest.raises(builder.BundleRefused, match="metadata digest placeholder"):
        _build(values)


def test_bootstrap_sequence_checkpoint_and_validity_window_are_enforced(tmp_path):
    values = _inputs(tmp_path)
    archive, manifest, signature, _, _ = _build(values)
    artifacts = _artifacts(
        tmp_path / "artifacts",
        archive,
        manifest,
        signature,
        values["bootstrap_public_path"],
    )

    common = {
        "bundle_path": artifacts[0],
        "manifest_path": artifacts[1],
        "signature_path": artifacts[2],
        "bootstrap_public_key_path": artifacts[3],
        "expected_bootstrap_fingerprint": values["bootstrap_fingerprint"],
        "expected_owner": os.geteuid(),
        "signature_verifier": _verifier,
    }
    with pytest.raises(installer.InstallRefused, match="operator checkpoint"):
        installer.verify_bundle(
            **common,
            minimum_bootstrap_sequence=2,
        )
    with pytest.raises(installer.InstallRefused, match="not valid yet"):
        installer.verify_bundle(
            **common,
            minimum_bootstrap_sequence=1,
            now_unix=values["issued_unix"] - 301,
        )
    with pytest.raises(installer.InstallRefused, match="has expired"):
        installer.verify_bundle(
            **common,
            minimum_bootstrap_sequence=1,
            now_unix=values["issued_unix"] + values["lifetime_seconds"],
        )

    values["sequence"] = 0
    with pytest.raises(builder.BundleRefused, match="sequence is invalid"):
        _build(values)
    values["sequence"] = 1
    values["lifetime_seconds"] = 91 * 24 * 60 * 60
    with pytest.raises(builder.BundleRefused, match="outside"):
        _build(values)


def test_installer_cli_accepts_only_external_bootstrap_trust_anchor() -> None:
    options = {
        option
        for action in installer._parser()._actions
        for option in action.option_strings
    }
    assert "--bootstrap-public-key" in options
    assert "--expected-bootstrap-key-fingerprint" in options
    assert "--minimum-bootstrap-sequence" in options
    assert "--runtime-release-public-key" not in options
    assert "--trusted-public-key" not in options
    assert "--expected-public-key-fingerprint" not in options


def test_openssl3_verifies_ed25519_from_memory_without_temp_files():
    openssl = shutil.which("openssl")
    if not hasattr(os, "memfd_create") or openssl is None:
        pytest.skip("Linux memfd and OpenSSL are required")
    version = subprocess.run(
        [openssl, "version"], check=True, capture_output=True, text=True
    ).stdout
    if not version.startswith("OpenSSL 3."):
        pytest.skip("OpenSSL 3 is required")
    private = Ed25519PrivateKey.generate()
    manifest = b'{"schema":"test"}\n'
    signature = private.sign(manifest)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    installer._openssl_verify(manifest, signature, public, openssl=openssl)
    with pytest.raises(installer.InstallRefused, match="signature"):
        installer._openssl_verify(
            manifest + b"tampered", signature, public, openssl=openssl
        )


def test_verifier_rejects_self_signed_attacker_key_and_permissive_inputs(tmp_path):
    values = _inputs(tmp_path)
    archive, manifest, signature, _, _ = _build(values)
    artifact_root = tmp_path / "artifacts"
    artifacts = _artifacts(
        artifact_root,
        archive,
        manifest,
        signature,
        values["bootstrap_public_path"],
    )
    _, _, legitimate, legitimate_fingerprint = _keypair(
        tmp_path / "legitimate",
        "legitimate-bootstrap",
    )
    artifacts[3].write_bytes(legitimate.read_bytes())
    with pytest.raises(installer.InstallRefused, match="fingerprint differs"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint=legitimate_fingerprint,
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )

    artifacts[3].write_bytes(values["bootstrap_public_path"].read_bytes())
    artifacts[0].chmod(0o666)
    with pytest.raises(installer.InstallRefused, match="owner-controlled"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint=values["bootstrap_fingerprint"],
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )


def test_verifier_rejects_traversal_and_symlink_members(tmp_path):
    values = _inputs(tmp_path)
    archive, manifest, _, _, _ = _build(values)
    document = json.loads(manifest)
    document["files"][0]["path"] = "../escape"
    document["files"] = sorted(document["files"], key=lambda item: item["path"])
    malicious_manifest = builder.canonical_json(document)
    malicious_signature = values["bootstrap_private"].sign(malicious_manifest)
    artifacts = _artifacts(
        tmp_path / "traversal",
        archive,
        malicious_manifest,
        malicious_signature,
        values["bootstrap_public_path"],
    )
    with pytest.raises(installer.InstallRefused, match="unsafe archive path"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint=values["bootstrap_fingerprint"],
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )

    source = tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz")
    members = source.getmembers()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as target:
        for index, member in enumerate(members):
            if index == 0:
                link = tarfile.TarInfo(member.name)
                link.type = tarfile.SYMTYPE
                link.linkname = "../../escape"
                link.mode = member.mode
                link.uid = member.uid
                link.gid = member.gid
                link.uname = member.uname
                link.gname = member.gname
                link.mtime = member.mtime
                target.addfile(link)
            else:
                target.addfile(member, source.extractfile(member))
    source.close()
    link_archive = output.getvalue()
    link_manifest, link_signature = _resign_archive(values, manifest, link_archive)
    artifacts = _artifacts(
        tmp_path / "symlink",
        link_archive,
        link_manifest,
        link_signature,
        values["bootstrap_public_path"],
    )
    with pytest.raises(installer.InstallRefused, match="metadata differs"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint=values["bootstrap_fingerprint"],
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )


def test_verifier_rejects_tampered_or_missing_signed_installer(tmp_path):
    values = _inputs(tmp_path)
    archive, manifest, _, _, _ = _build(values)
    source = tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as target:
        for member in source.getmembers():
            handle = source.extractfile(member)
            assert handle is not None
            body = handle.read()
            if member.name == installer.INSTALLER_ARCHIVE_PATH:
                body = bytes([body[0] ^ 1]) + body[1:]
            target.addfile(member, io.BytesIO(body))
    source.close()
    tampered_archive = output.getvalue()
    tampered_manifest, tampered_signature = _resign_archive(
        values, manifest, tampered_archive
    )
    artifacts = _artifacts(
        tmp_path / "tampered-installer",
        tampered_archive,
        tampered_manifest,
        tampered_signature,
        values["bootstrap_public_path"],
    )
    with pytest.raises(installer.InstallRefused, match="content differs"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint=values["bootstrap_fingerprint"],
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )

    document = json.loads(manifest)
    document["files"] = [
        record
        for record in document["files"]
        if record["path"] != installer.INSTALLER_ARCHIVE_PATH
    ]
    missing_manifest = builder.canonical_json(document)
    missing_signature = values["bootstrap_private"].sign(missing_manifest)
    artifacts = _artifacts(
        tmp_path / "missing-installer",
        archive,
        missing_manifest,
        missing_signature,
        values["bootstrap_public_path"],
    )
    with pytest.raises(installer.InstallRefused, match="fixed bootstrap asset set"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            bootstrap_public_key_path=artifacts[3],
            expected_bootstrap_fingerprint=values["bootstrap_fingerprint"],
            minimum_bootstrap_sequence=1,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )


def test_running_installer_must_equal_the_signed_member(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    script = tmp_path / "install_updater_bundle.py"
    script.write_bytes(verified.files[installer.INSTALLER_ARCHIVE_PATH].body)
    script.chmod(0o644)
    installer.verify_running_installer(
        verified,
        script_path=script,
        expected_owner=os.geteuid(),
    )
    script.write_bytes(script.read_bytes() + b"# tampered\n")
    with pytest.raises(installer.InstallRefused, match="differs"):
        installer.verify_running_installer(
            verified,
            script_path=script,
            expected_owner=os.geteuid(),
        )


def test_install_is_idempotent_preserves_secrets_and_never_enables_units(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    secrets = {
        "etc/cathedral-validator/direct.env": b"operator-direct\n",
        "etc/cathedral-validator/identity.env": b"operator-identity\n",
        "etc/cathedral-validator/update.env": b"operator-update\n",
        "etc/cathedral-validator/validator-hotkey": b"secret-hotkey\n",
    }
    for relative, body in secrets.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o600)

    calls: list[list[str]] = []
    runner = _fake_runner(calls)
    digest = installer.install_verified_bundle(
        verified,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=runner,
    )
    assert digest == verified.manifest_sha256
    assert calls[0][1:3] == ["-I", "-c"]
    assert "import ensurepip, venv" in calls[0][3]
    assert [command[1:4] for command in calls[1:3]] == [
        ["-m", "venv", calls[1][-1]],
        ["-m", "pip", "install"],
    ]
    pip_command = calls[2]
    assert "--no-index" in pip_command
    assert "--no-deps" in pip_command
    assert "--require-hashes" in pip_command
    assert "--only-binary=:all:" in pip_command
    assert calls[3][1:3] == ["-I", "-c"]
    assert "import updater" in calls[3][3]
    assert "import cryptography" in calls[3][3]
    assert calls[4][-1] == "--help"
    assert not any(command[1:4] == ["-m", "pip", "check"] for command in calls)
    assert not any(
        action in command
        for command in calls
        for action in ("enable", "start", "restart")
    )
    for relative, body in secrets.items():
        assert (root / relative).read_bytes() == body
    fixed = root / "usr/local/lib/cathedral-validator-updater"
    assert fixed.is_symlink()
    assert fixed.readlink() == (
        Path(installer.UPDATER_RELEASES_DIRECTORY) / verified.manifest_sha256
    )
    assert (root / "etc/systemd/system/cathedral-validator-update.timer").is_file()
    assert (
        root / "etc/systemd/system/cathedral-validator-boot-reconcile.service"
    ).is_file()
    assert not (root / "etc/cathedral-validator/update.env.example").exists()
    assert (
        root / "usr/local/share/cathedral-validator-updater/examples/update.env.example"
    ).is_file()
    assert (
        root / "usr/local/share/cathedral-validator-updater/bootstrap/"
        "install_updater_bundle.py"
    ).read_bytes() == verified.files[installer.INSTALLER_ARCHIVE_PATH].body
    for command in installer.OPERATOR_ASSETS:
        installed = root / "usr/local/sbin" / command
        assert (
            installed.read_bytes() == verified.files[f"payload/operator/{command}"].body
        )
        assert stat.S_IMODE(installed.stat().st_mode) == 0o755
    version = (
        root
        / "usr/local/lib"
        / installer.UPDATER_RELEASES_DIRECTORY
        / verified.manifest_sha256
    )
    assert (version / "bin" / "cathedral-validator-update").read_text(
        encoding="utf-8"
    ).splitlines()[0] == f"#!{version}/bin/{installer.VENV_INTERPRETER_NAME}"

    before = {
        path.relative_to(root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    first_call_count = len(calls)
    installer.install_verified_bundle(
        verified,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=runner,
    )
    after = {
        path.relative_to(root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    assert after == before
    assert calls[first_call_count:] == [
        [
            "/usr/bin/python3.12",
            "-I",
            "-c",
            "import ensurepip, venv; assert callable(venv.create)",
        ],
        [
            "/usr/bin/systemd-sysusers",
            str(root / "etc/sysusers.d/cathedral-validator.conf"),
        ],
        ["/usr/bin/systemctl", "daemon-reload"],
    ]


def test_production_updater_release_path_has_distlib_shebang_headroom():
    digest = "0" * 64
    version = installer._updater_version_dir(Path("/"), digest)
    shebang = installer._updater_entrypoint_shebang(version)

    assert version == Path("/usr/local/lib/cathedral-updater-r") / digest
    assert len(shebang) + 1 == 117
    assert (
        installer.DISTLIB_MAX_SHEBANG_BYTES - (len(shebang) + 1)
        >= installer.DISTLIB_MIN_SHEBANG_HEADROOM_BYTES
    )
    installer._check_distlib_shebang_budget(version)


def test_distlib_shebang_budget_refuses_before_bootstrap_state_mutation(
    tmp_path, monkeypatch
):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    calls: list[list[str]] = []
    overlong = Path("/") / ("x" * installer.DISTLIB_MAX_SHEBANG_BYTES)
    monkeypatch.setattr(installer, "_updater_version_dir", lambda *_args: overlong)

    with pytest.raises(installer.InstallRefused, match="shebang safety budget"):
        installer.install_verified_bundle(
            verified,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner(calls),
        )

    assert len(calls) == 1
    assert list(root.iterdir()) == []


@pytest.mark.skipif(
    sys.platform != "linux" or sys.version_info[:2] != (3, 12),
    reason="requires the production Ubuntu Python 3.12 pip/distlib policy",
)
def test_pip_vendored_distlib_uses_direct_shebang_within_production_budget(tmp_path):
    from pip._vendor.distlib.scripts import ScriptMaker

    digest = "0" * 64
    direct = installer._updater_version_dir(Path("/"), digest)
    legacy = Path("/usr/local/lib/cathedral-validator-updater-releases") / digest

    def make_entrypoint(label: str, interpreter: Path) -> Path:
        maker = ScriptMaker(None, str(tmp_path / label))
        maker.executable = str(interpreter)
        maker.variants = {""}
        maker.clobber = True
        files = maker.make("cathedral-validator-update = tiny_updater:main")
        assert len(files) == 1
        return Path(files[0])

    direct_entrypoint = make_entrypoint(
        "direct", direct / "bin" / installer.VENV_INTERPRETER_NAME
    )
    legacy_entrypoint = make_entrypoint(
        "legacy", legacy / "bin" / installer.VENV_INTERPRETER_NAME
    )

    assert direct_entrypoint.read_bytes().splitlines()[
        0
    ] == installer._updater_entrypoint_shebang(direct)
    assert legacy_entrypoint.read_bytes().splitlines()[0] == b"#!/bin/sh"


def test_legacy_updater_active_link_is_refused(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    digest = "0" * 64
    legacy_parent = root / "usr/local/lib/cathedral-validator-updater-releases"
    legacy_release = legacy_parent / digest
    legacy_release.mkdir(parents=True, mode=0o755)
    fixed_link = root / "usr/local/lib/cathedral-validator-updater"
    fixed_link.symlink_to(Path("cathedral-validator-updater-releases") / digest)

    with pytest.raises(installer.InstallRefused, match="activation target is unsafe"):
        installer.install_verified_bundle(
            verified,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner([]),
        )

    assert (
        fixed_link.readlink() == Path("cathedral-validator-updater-releases") / digest
    )
    assert not (
        root
        / "usr/local/lib"
        / installer.UPDATER_RELEASES_DIRECTORY
        / verified.manifest_sha256
    ).exists()


def test_missing_python_venv_support_refuses_before_mutation(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    calls: list[list[str]] = []
    with pytest.raises(installer.InstallRefused, match="python3.12-venv"):
        installer.install_verified_bundle(
            verified,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner(calls, fail_preflight=True),
        )
    assert len(calls) == 1
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("interpreter_kind", ["non_versioned", "staging"])
def test_installed_updater_entry_point_requires_final_versioned_interpreter(
    tmp_path, interpreter_kind
):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    installer.install_verified_bundle(
        verified,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner([]),
    )
    version = (
        root
        / "usr/local/lib"
        / installer.UPDATER_RELEASES_DIRECTORY
        / verified.manifest_sha256
    )
    executable = version / "bin" / "cathedral-validator-update"
    if interpreter_kind == "non_versioned":
        interpreter = version / "bin" / "python"
    else:
        interpreter = (
            root
            / "usr/local/lib/cathedral-validator-updater-staging"
            / "abandoned"
            / "bin"
            / installer.VENV_INTERPRETER_NAME
        )
    executable.write_text(f"#!{interpreter}\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)

    with pytest.raises(installer.InstallRefused, match="wrong interpreter"):
        installer._validate_installed_venv(
            version,
            verified,
            expected_owner=os.geteuid(),
        )


def test_install_sets_traversable_service_paths_under_owner_only_umask(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    previous = os.umask(0o077)
    try:
        installer.install_verified_bundle(
            verified,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner([]),
        )
    finally:
        os.umask(previous)
    assert stat.S_IMODE((root / "etc/cathedral-validator").stat().st_mode) == 0o755
    assert (
        stat.S_IMODE(
            (root / "etc/cathedral-validator/runtime-release-public-key.pem")
            .stat()
            .st_mode
        )
        == 0o644
    )


def test_bootstrap_upgrade_is_monotonic_atomic_and_retains_prior_version(tmp_path):
    values = _inputs(tmp_path / "inputs")
    first, _ = _verify_values(tmp_path / "first-artifacts", values)
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    installer.install_verified_bundle(
        first,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner([]),
    )

    values["sequence"] = 2
    unit_asset = values["assets"] / "cathedral-validator-update.service"
    unit_asset.write_text(unit_asset.read_text() + "# signed bootstrap v2\n")
    second, _ = _verify_values(tmp_path / "second-artifacts", values)
    installer.install_verified_bundle(
        second,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner([]),
    )

    fixed = root / "usr/local/lib/cathedral-validator-updater"
    assert fixed.readlink() == (
        Path(installer.UPDATER_RELEASES_DIRECTORY) / second.manifest_sha256
    )
    releases = root / "usr/local/lib" / installer.UPDATER_RELEASES_DIRECTORY
    assert (releases / first.manifest_sha256).is_dir()
    assert (releases / second.manifest_sha256).is_dir()
    state_path = root / "var/lib/cathedral-validator-update/bootstrap-state.json"
    state = json.loads(state_path.read_bytes())
    assert state["sequence"] == 2
    assert state["manifest_sha256"] == second.manifest_sha256
    assert not (
        root / "var/lib/cathedral-validator-update/bootstrap-pending.json"
    ).exists()
    assert (
        root / "etc/systemd/system/cathedral-validator-update.service"
    ).read_bytes() == second.files[
        "payload/systemd/cathedral-validator-update.service"
    ].body

    with pytest.raises(installer.InstallRefused, match="bootstrap replay"):
        installer.install_verified_bundle(
            first,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner([]),
        )
    assert json.loads(state_path.read_bytes())["manifest_sha256"] == (
        second.manifest_sha256
    )


def test_bootstrap_upgrade_recovers_same_signed_target_after_interruption(tmp_path):
    values = _inputs(tmp_path / "inputs")
    first, _ = _verify_values(tmp_path / "first-artifacts", values)
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    installer.install_verified_bundle(
        first,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner([]),
    )

    values["sequence"] = 2
    values["assets"].joinpath("cathedral-validator-update.timer").write_text(
        values["assets"].joinpath("cathedral-validator-update.timer").read_text()
        + "# interrupted signed upgrade\n"
    )
    second, _ = _verify_values(tmp_path / "second-artifacts", values)
    with pytest.raises(subprocess.CalledProcessError):
        installer.install_verified_bundle(
            second,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner([], fail_daemon_reload=True),
        )
    state_root = root / "var/lib/cathedral-validator-update"
    assert (
        json.loads((state_root / "bootstrap-state.json").read_bytes())["sequence"] == 1
    )
    assert (
        json.loads((state_root / "bootstrap-pending.json").read_bytes())[
            "manifest_sha256"
        ]
        == second.manifest_sha256
    )

    installer.install_verified_bundle(
        second,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner([]),
    )
    assert (
        json.loads((state_root / "bootstrap-state.json").read_bytes())["sequence"] == 2
    )
    assert not (state_root / "bootstrap-pending.json").exists()


def test_same_bootstrap_sequence_with_different_manifest_is_refused(tmp_path):
    values = _inputs(tmp_path / "inputs")
    first, _ = _verify_values(tmp_path / "first-artifacts", values)
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    installer.install_verified_bundle(
        first,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner([]),
    )

    values["assets"].joinpath("direct.env.example").write_text(
        values["assets"].joinpath("direct.env.example").read_text()
        + "# signed but equivocal contents\n"
    )
    equivocal, _ = _verify_values(tmp_path / "equivocal-artifacts", values)
    with pytest.raises(installer.InstallRefused, match="equivocal"):
        installer.install_verified_bundle(
            equivocal,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner([]),
        )


def _rebind_stable_floor(
    values: dict[str, object], root: Path, *, sequence: int
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    values["stable_sequence"] = sequence
    values["stable_metadata"] = _stable_metadata(
        root,
        private=values["runtime_private"],
        sequence=sequence,
        issued_unix=values["issued_unix"],
    )


def _install(verified: object, root: Path, **runner_options: bool) -> str:
    return installer.install_verified_bundle(
        verified,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner([], **runner_options),
    )


def test_bootstrap_state_persists_stable_floor_and_refuses_lowering_it(tmp_path):
    """The bootstrap sequence and the stable floor are independent monotones.

    A bootstrap built later from an older still-valid stable record carries a
    higher bootstrap sequence and a lower stable floor. Installing it would
    hand a not-yet-set-up host a lower authenticated minimum, so the floor is
    persisted and enforced regardless of the bootstrap sequence.
    """

    values = _inputs(tmp_path / "inputs")
    first, _ = _verify_values(tmp_path / "first-artifacts", values)
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    _install(first, root)
    state_path = root / "var/lib/cathedral-validator-update/bootstrap-state.json"
    example = (
        root / "usr/local/share/cathedral-validator-updater/examples/update.env.example"
    )
    fixed = root / "usr/local/lib/cathedral-validator-updater"
    committed = json.loads(state_path.read_bytes())
    assert committed["schema"] == installer.BOOTSTRAP_STATE_SCHEMA
    assert committed["sequence"] == 1
    assert committed["stable_release_minimum_sequence"] == 7
    assert b"CATHEDRAL_VALIDATOR_STABLE_MINIMUM_SEQUENCE=7\n" in example.read_bytes()

    values["sequence"] = 2
    _rebind_stable_floor(values, tmp_path / "older-stable", sequence=5)
    lowered, _ = _verify_values(tmp_path / "lowered-artifacts", values)
    assert lowered.bootstrap_sequence == 2
    assert lowered.stable_release_minimum_sequence == 5
    with pytest.raises(
        installer.InstallRefused, match="lowers the committed stable release floor"
    ):
        _install(lowered, root)
    assert json.loads(state_path.read_bytes()) == committed
    assert b"CATHEDRAL_VALIDATOR_STABLE_MINIMUM_SEQUENCE=7\n" in example.read_bytes()
    assert fixed.readlink().name == first.manifest_sha256
    assert not (
        root / "var/lib/cathedral-validator-update/bootstrap-pending.json"
    ).exists()

    _rebind_stable_floor(values, tmp_path / "equal-stable", sequence=7)
    equal, _ = _verify_values(tmp_path / "equal-artifacts", values)
    _install(equal, root)
    after_equal = json.loads(state_path.read_bytes())
    assert after_equal["sequence"] == 2
    assert after_equal["stable_release_minimum_sequence"] == 7

    values["sequence"] = 3
    _rebind_stable_floor(values, tmp_path / "newer-stable", sequence=9)
    raised, _ = _verify_values(tmp_path / "raised-artifacts", values)
    _install(raised, root)
    after_raise = json.loads(state_path.read_bytes())
    assert after_raise["sequence"] == 3
    assert after_raise["stable_release_minimum_sequence"] == 9
    assert b"CATHEDRAL_VALIDATOR_STABLE_MINIMUM_SEQUENCE=9\n" in example.read_bytes()
    assert fixed.readlink().name == raised.manifest_sha256

    with pytest.raises(installer.InstallRefused, match="bootstrap replay"):
        _install(lowered, root)


def test_pending_stable_floor_blocks_a_lower_floor_until_recovery_completes(
    tmp_path,
):
    values = _inputs(tmp_path / "inputs")
    first, _ = _verify_values(tmp_path / "first-artifacts", values)
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    _install(first, root)
    state_root = root / "var/lib/cathedral-validator-update"

    values["sequence"] = 2
    _rebind_stable_floor(values, tmp_path / "floor-nine", sequence=9)
    interrupted, _ = _verify_values(tmp_path / "interrupted-artifacts", values)
    with pytest.raises(subprocess.CalledProcessError):
        _install(interrupted, root, fail_daemon_reload=True)
    committed = json.loads((state_root / "bootstrap-state.json").read_bytes())
    pending = json.loads((state_root / "bootstrap-pending.json").read_bytes())
    assert committed["stable_release_minimum_sequence"] == 7
    assert pending["schema"] == installer.BOOTSTRAP_PENDING_SCHEMA
    assert pending["stable_release_minimum_sequence"] == 9

    values["sequence"] = 3
    _rebind_stable_floor(values, tmp_path / "floor-eight", sequence=8)
    between, _ = _verify_values(tmp_path / "between-artifacts", values)
    with pytest.raises(
        installer.InstallRefused, match="lowers the pending stable release floor"
    ):
        _install(between, root)
    assert json.loads((state_root / "bootstrap-state.json").read_bytes()) == committed
    assert json.loads((state_root / "bootstrap-pending.json").read_bytes()) == pending

    _install(interrupted, root)
    recovered = json.loads((state_root / "bootstrap-state.json").read_bytes())
    assert recovered["sequence"] == 2
    assert recovered["stable_release_minimum_sequence"] == 9
    assert not (state_root / "bootstrap-pending.json").exists()
    with pytest.raises(
        installer.InstallRefused, match="lowers the committed stable release floor"
    ):
        _install(between, root)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda record: {
                **{
                    key: value
                    for key, value in record.items()
                    if key != "stable_release_minimum_sequence"
                },
                "schema": "cathedral_validator_bootstrap_state_v1",
            },
            "schema is unsupported",
        ),
        (
            lambda record: {
                key: value
                for key, value in record.items()
                if key != "stable_release_minimum_sequence"
            },
            "unsupported fields",
        ),
        (
            lambda record: {**record, "stable_release_minimum_sequence": 0},
            "fields are invalid",
        ),
        (
            lambda record: {**record, "stable_release_minimum_sequence": True},
            "fields are invalid",
        ),
        (
            lambda record: {**record, "stable_release_minimum_sequence": "7"},
            "fields are invalid",
        ),
        (
            lambda record: {**record, "stable_release_minimum_sequence": 2**63},
            "fields are invalid",
        ),
    ],
    ids=[
        "legacy-v1-schema",
        "missing-floor",
        "zero-floor",
        "bool-floor",
        "string-floor",
        "oversized-floor",
    ],
)
def test_bootstrap_state_without_a_valid_stable_floor_is_refused(
    tmp_path, mutation, message
):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    state_root = root / "var/lib/cathedral-validator-update"
    state_root.mkdir(parents=True, mode=0o700)
    state_root.chmod(0o700)
    record = json.loads(
        installer._bootstrap_record(verified, installer.BOOTSTRAP_STATE_SCHEMA)
    )
    state_path = state_root / "bootstrap-state.json"
    state_path.write_bytes(installer.canonical_json(mutation(record)))
    state_path.chmod(0o600)
    before = state_path.read_bytes()

    with pytest.raises(installer.InstallRefused, match=message):
        _install(verified, root)

    assert state_path.read_bytes() == before
    assert not (root / "usr/local/lib/cathedral-validator-updater").exists()
    assert not (root / "usr/local/lib" / installer.UPDATER_RELEASES_DIRECTORY).exists()
    assert not (state_root / "bootstrap-pending.json").exists()


def test_install_refuses_destination_symlink_before_persistent_mutation(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "etc").symlink_to(outside)
    calls: list[list[str]] = []
    with pytest.raises(installer.InstallRefused, match="unsafe destination ancestor"):
        installer.install_verified_bundle(
            verified,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner(calls),
        )
    assert len(calls) == 1
    assert "import ensurepip, venv" in calls[0][-1]
    assert list(outside.iterdir()) == []
    assert not (root / "var").exists()


def test_signed_bootstrap_replaces_a_safe_managed_unit(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    unit = root / "etc/systemd/system/cathedral-validator-update.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("operator unit\n")
    unit.chmod(0o644)
    calls: list[list[str]] = []
    installer.install_verified_bundle(
        verified,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner(calls),
    )
    assert (
        unit.read_bytes()
        == verified.files["payload/systemd/cathedral-validator-update.service"].body
    )
    assert (root / "usr/local/lib/cathedral-validator-updater").is_symlink()


def test_failed_offline_pip_install_leaves_no_active_or_partial_updater(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    calls: list[list[str]] = []
    with pytest.raises(subprocess.CalledProcessError):
        installer.install_verified_bundle(
            verified,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner(calls, fail_pip=True),
        )
    releases = root / "usr/local/lib" / installer.UPDATER_RELEASES_DIRECTORY
    assert releases.is_dir()
    assert list(releases.iterdir()) == []
    assert not (root / "usr/local/lib/cathedral-validator-updater").exists()
    assert not (root / "etc/systemd/system/cathedral-validator-update.timer").exists()


def test_interrupted_install_cleans_an_unreferenced_partial_release(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    with pytest.raises(KeyboardInterrupt):
        installer.install_verified_bundle(
            verified,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner([], interrupt_pip=True),
        )
    releases = root / "usr/local/lib" / installer.UPDATER_RELEASES_DIRECTORY
    assert releases.is_dir()
    assert list(releases.iterdir()) == []
    assert not (root / "usr/local/lib/cathedral-validator-updater").exists()


def test_sigkill_residue_without_completion_markers_is_rebuilt(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    releases = root / "usr/local/lib" / installer.UPDATER_RELEASES_DIRECTORY
    releases.mkdir(parents=True, mode=0o755)
    version = releases / verified.manifest_sha256
    version.mkdir(mode=0o755)
    residue = version / "pip-was-writing"
    residue.write_bytes(b"partial\n")
    residue.chmod(0o644)

    installer.install_verified_bundle(
        verified,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner([]),
    )

    assert not residue.exists()
    assert (version / ".bootstrap-manifest.json").read_bytes() == verified.manifest
    assert (version / ".bootstrap-manifest.sig").read_bytes() == verified.signature
    assert (root / "usr/local/lib/cathedral-validator-updater").is_symlink()


def test_unreferenced_complete_markers_do_not_preserve_crash_residue(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    releases = root / "usr/local/lib" / installer.UPDATER_RELEASES_DIRECTORY
    releases.mkdir(parents=True, mode=0o755)
    version = releases / verified.manifest_sha256
    bin_dir = version / "bin"
    bin_dir.mkdir(parents=True, mode=0o755)
    python = bin_dir / "python"
    python.write_bytes(b"#!/bin/sh\nexit 0\n")
    python.chmod(0o755)
    updater = bin_dir / "cathedral-validator-update"
    updater.write_bytes(f"#!{python}\nexit 0\n".encode())
    updater.chmod(0o755)
    manifest_marker = version / ".bootstrap-manifest.json"
    manifest_marker.write_bytes(verified.manifest)
    manifest_marker.chmod(0o444)
    signature_marker = version / ".bootstrap-manifest.sig"
    signature_marker.write_bytes(verified.signature)
    signature_marker.chmod(0o444)
    residue = version / "package-write-was-not-durable"
    residue.write_bytes(b"truncated\n")
    residue.chmod(0o644)

    installer.install_verified_bundle(
        verified,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner([]),
    )

    assert not residue.exists()
    assert manifest_marker.read_bytes() == verified.manifest
    assert signature_marker.read_bytes() == verified.signature


@pytest.mark.parametrize(
    ("reference", "schema"),
    [
        ("active link", None),
        ("committed state", installer.BOOTSTRAP_STATE_SCHEMA),
        ("pending state", installer.BOOTSTRAP_PENDING_SCHEMA),
    ],
)
def test_incomplete_release_is_never_removed_when_referenced(
    tmp_path,
    reference,
    schema,
):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    releases = root / "usr/local/lib" / installer.UPDATER_RELEASES_DIRECTORY
    releases.mkdir(parents=True, mode=0o755)
    version = releases / verified.manifest_sha256
    version.mkdir(mode=0o755)
    residue = version / "pip-was-writing"
    residue.write_bytes(b"partial\n")
    residue.chmod(0o644)

    if reference == "active link":
        (root / "usr/local/lib/cathedral-validator-updater").symlink_to(
            Path(installer.UPDATER_RELEASES_DIRECTORY) / verified.manifest_sha256
        )
    else:
        state_root = root / "var/lib/cathedral-validator-update"
        state_root.mkdir(parents=True, mode=0o700)
        state_root.chmod(0o700)
        filename = (
            "bootstrap-state.json"
            if schema == installer.BOOTSTRAP_STATE_SCHEMA
            else "bootstrap-pending.json"
        )
        record = state_root / filename
        record.write_bytes(installer._bootstrap_record(verified, schema))
        record.chmod(0o600)

    with pytest.raises(installer.InstallRefused, match=f"referenced by {reference}"):
        installer.install_verified_bundle(
            verified,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner([]),
        )
    assert residue.read_bytes() == b"partial\n"
    assert version.is_dir()


def test_referenced_complete_release_is_validated_and_never_removed(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    installer.install_verified_bundle(
        verified,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner([]),
    )
    version = (
        root
        / "usr/local/lib"
        / installer.UPDATER_RELEASES_DIRECTORY
        / verified.manifest_sha256
    )
    unsafe = version / "unsafe-package-file"
    unsafe.write_bytes(b"do not trust\n")
    unsafe.chmod(0o666)

    with pytest.raises(installer.InstallRefused, match="writable by another user"):
        installer.install_verified_bundle(
            verified,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner([]),
        )

    assert unsafe.read_bytes() == b"do not trust\n"
    assert version.is_dir()
    assert (root / "usr/local/lib/cathedral-validator-updater").is_symlink()


def test_release_tree_fsyncs_files_and_directories_without_following_symlinks(
    tmp_path,
    monkeypatch,
):
    release = tmp_path / "release"
    bin_dir = release / "bin"
    package_dir = release / "lib/python3.12/site-packages/example"
    bin_dir.mkdir(parents=True, mode=0o755)
    package_dir.mkdir(parents=True, mode=0o755)
    real_python = bin_dir / "python-real"
    real_python.write_bytes(b"#!/bin/sh\nexit 0\n")
    real_python.chmod(0o755)
    (bin_dir / installer.VENV_INTERPRETER_NAME).symlink_to("python-real")
    (bin_dir / "python").symlink_to(installer.VENV_INTERPRETER_NAME)
    module = package_dir / "module.py"
    module.write_bytes(b"VALUE = 1\n")
    module.chmod(0o644)

    regular_and_directories = [
        path
        for path in release.rglob("*")
        if not path.is_symlink() and (path.is_file() or path.is_dir())
    ] + [release]
    expected = {
        (path.lstat().st_dev, path.lstat().st_ino) for path in regular_and_directories
    }
    symlink_metadata = (bin_dir / "python").lstat()
    symlink_identity = (symlink_metadata.st_dev, symlink_metadata.st_ino)
    synced: set[tuple[int, int]] = set()
    real_fsync = installer.os.fsync

    def record_fsync(descriptor):
        metadata = os.fstat(descriptor)
        synced.add((metadata.st_dev, metadata.st_ino))
        return real_fsync(descriptor)

    monkeypatch.setattr(installer.os, "fsync", record_fsync)
    installer._validate_venv_interpreter(
        release,
        expected_owner=os.geteuid(),
    )
    installer._fsync_owned_tree(
        release,
        expected_owner=os.geteuid(),
    )

    assert expected <= synced
    assert symlink_identity not in synced


def test_release_tree_is_durable_before_state_or_activation(tmp_path, monkeypatch):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    events: list[str] = []
    releases = root / "usr/local/lib" / installer.UPDATER_RELEASES_DIRECTORY
    real_fsync_tree = installer._fsync_owned_tree
    real_fsync_directory = installer._fsync_directory
    real_install_managed_file = installer._install_managed_file
    real_activate = installer._activate_updater_link

    def record_tree(*args, **kwargs):
        result = real_fsync_tree(*args, **kwargs)
        events.append("release tree")
        return result

    def record_directory(path, **kwargs):
        result = real_fsync_directory(path, **kwargs)
        if path == releases:
            events.append("releases parent")
        return result

    def record_managed_file(root_path, path, body, **kwargs):
        if path.name == "bootstrap-pending.json":
            events.append("pending state")
        elif path.name == "bootstrap-state.json":
            events.append("committed state")
        return real_install_managed_file(root_path, path, body, **kwargs)

    def record_activate(*args, **kwargs):
        events.append("active link")
        return real_activate(*args, **kwargs)

    monkeypatch.setattr(installer, "_fsync_owned_tree", record_tree)
    monkeypatch.setattr(installer, "_fsync_directory", record_directory)
    monkeypatch.setattr(installer, "_install_managed_file", record_managed_file)
    monkeypatch.setattr(installer, "_activate_updater_link", record_activate)

    installer.install_verified_bundle(
        verified,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner([]),
    )

    assert events.index("release tree") < events.index("releases parent")
    assert events.index("releases parent") < events.index("pending state")
    assert events.index("pending state") < events.index("active link")
    assert events.index("active link") < events.index("committed state")


def test_runtime_guard_enforces_root_linux_python312_and_systemd(monkeypatch):
    monkeypatch.setattr(installer.os, "geteuid", lambda: 501)
    with pytest.raises(installer.InstallRefused, match="root"):
        installer._runtime_guard()

    monkeypatch.setattr(installer.os, "geteuid", lambda: 0)
    monkeypatch.setattr(installer.sys, "platform", "darwin")
    with pytest.raises(installer.InstallRefused, match="Linux"):
        installer._runtime_guard()

    monkeypatch.setattr(installer.sys, "platform", "linux")
    monkeypatch.setattr(installer.sys, "version_info", (3, 11, 9))
    with pytest.raises(installer.InstallRefused, match="3.12"):
        installer._runtime_guard()

    monkeypatch.setattr(installer.sys, "version_info", (3, 12, 9))
    monkeypatch.setattr(installer.sys, "executable", "/usr/bin/python3")
    with pytest.raises(installer.InstallRefused, match="/usr/bin/python3.12"):
        installer._runtime_guard()

    monkeypatch.setattr(installer.sys, "executable", "/usr/bin/python3.12")
    monkeypatch.setattr(installer.Path, "is_dir", lambda self: False)
    with pytest.raises(installer.InstallRefused, match="systemd"):
        installer._runtime_guard()


def test_installed_files_are_root_style_modes_and_manifest_is_immutable(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    calls: list[list[str]] = []
    installer.install_verified_bundle(
        verified,
        root=root,
        expected_owner=os.geteuid(),
        python_executable=Path("/usr/bin/python3.12"),
        runner=_fake_runner(calls),
    )
    release = (
        root
        / "usr/local/lib"
        / installer.UPDATER_RELEASES_DIRECTORY
        / verified.manifest_sha256
    )
    assert stat.S_IMODE((release / ".bootstrap-manifest.json").stat().st_mode) == 0o444
    assert (
        stat.S_IMODE(
            (root / "etc/cathedral-validator/runtime-release-public-key.pem")
            .stat()
            .st_mode
        )
        == 0o644
    )
    assert (
        root / "etc/cathedral-validator/runtime-release-public-key.pem"
    ).read_bytes() == verified.files[
        installer.RUNTIME_RELEASE_PUBLIC_KEY_ARCHIVE_PATH
    ].body
    for unit in installer.SYSTEMD_ASSETS:
        assert (
            stat.S_IMODE((root / "etc/systemd/system" / unit).stat().st_mode) == 0o644
        )
    for command in installer.OPERATOR_ASSETS:
        assert stat.S_IMODE((root / "usr/local/sbin" / command).stat().st_mode) == 0o755
