from __future__ import annotations

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
import zipfile
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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


def _keypair(root: Path) -> tuple[Ed25519PrivateKey, Path, Path, str]:
    root.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    private_path = root / "release-private.pem"
    public_path = root / "release-public.pem"
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
    fingerprint = installer.public_key_fingerprint(public)
    return private, private_path, public_path, fingerprint


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
                b"-----BEGIN PRIVATE KEY-----\nnot-allowed\n"
            )
        for name, body in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, body)
    path.write_bytes(output.getvalue())
    path.chmod(0o644)
    return wheelhouse, hashlib.sha256(output.getvalue()).hexdigest()


def _assets(root: Path) -> Path:
    assets = root / "assets"
    assets.mkdir(mode=0o755)
    for name in builder.REQUIRED_ASSETS:
        shutil.copyfile(DEPLOY / name, assets / name)
        (assets / name).chmod(0o644)
    return assets


def _inputs(tmp_path: Path) -> dict[str, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    private, private_path, public_path, fingerprint = _keypair(tmp_path)
    wheelhouse, digest = _wheel(tmp_path)
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        f"cathedral-scaffold==4.0.0 --hash=sha256:{digest}\n",
        encoding="utf-8",
    )
    requirements.chmod(0o644)
    return {
        "private": private,
        "private_path": private_path,
        "public_path": public_path,
        "fingerprint": fingerprint,
        "wheelhouse": wheelhouse,
        "requirements": requirements,
        "assets": _assets(tmp_path),
    }


def _build(values: dict[str, object]) -> tuple[bytes, bytes, bytes, str]:
    return builder.build_bundle(
        wheelhouse=values["wheelhouse"],
        requirements=values["requirements"],
        public_key_path=values["public_path"],
        private_key_path=values["private_path"],
        assets_dir=values["assets"],
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
    trusted_path = root / "trusted-public.pem"
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
    archive, manifest, signature, _ = _build(values)
    artifacts = _artifacts(
        tmp_path / "artifacts",
        archive,
        manifest,
        signature,
        values["public_path"],
    )
    verified = installer.verify_bundle(
        bundle_path=artifacts[0],
        manifest_path=artifacts[1],
        signature_path=artifacts[2],
        trusted_public_key_path=artifacts[3],
        expected_fingerprint=values["fingerprint"],
        expected_owner=os.geteuid(),
        signature_verifier=_verifier,
    )
    return verified, values, artifacts


def _fake_runner(calls: list[list[str]], *, fail_pip: bool = False):
    def run(command, **kwargs):
        command = [str(value) for value in command]
        calls.append(command)
        if command[1:4] == ["-m", "venv", command[-1]]:
            version = Path(command[-1])
            (version / "bin").mkdir(parents=True, exist_ok=True)
            python = version / "bin" / "python"
            python.write_text("#!/bin/sh\nexit 0\n")
            python.chmod(0o755)
            updater = version / "bin" / "cathedral-validator-update"
            updater.write_text(f"#!{python}\nexit 0\n")
            updater.chmod(0o755)
        elif "install" in command and fail_pip:
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
    return new_manifest, values["private"].sign(new_manifest)


def test_builder_is_reproducible_and_contains_no_private_key(tmp_path):
    values = _inputs(tmp_path)
    first = _build(values)
    second = _build(values)
    assert first == second
    archive, manifest, signature, fingerprint = first
    assert len(signature) == 64
    assert fingerprint == values["fingerprint"]
    assert b"PRIVATE KEY" not in archive
    assert b"PRIVATE KEY" not in manifest
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        names = bundle.getnames()
        assert names == sorted(names)
        assert names.count("payload/installer/install_updater_bundle.py") == 1
        assert names.count("payload/update-public-key.pem") == 1
        assert all(member.uid == 0 and member.gid == 0 for member in bundle)
        assert all(member.mtime == 0 for member in bundle)


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
    values["private_path"].chmod(0o644)
    with pytest.raises(builder.BundleRefused, match="owner-controlled"):
        _build(values)


def test_output_writer_never_overwrites_an_existing_artifact(tmp_path):
    values = _inputs(tmp_path)
    archive, manifest, signature, _ = _build(values)
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
    assert verified.public_key_fingerprint == values["fingerprint"]

    with pytest.raises(installer.InstallRefused, match="differs from the pin"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            trusted_public_key_path=artifacts[3],
            expected_fingerprint="sha256:" + "0" * 64,
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
            trusted_public_key_path=artifacts[3],
            expected_fingerprint=values["fingerprint"],
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )

    archive, manifest, signature, _ = _build(values)
    artifacts[0].write_bytes(archive[:-1] + bytes([archive[-1] ^ 1]))
    artifacts[1].write_bytes(manifest)
    artifacts[2].write_bytes(signature)
    with pytest.raises(installer.InstallRefused, match="bundle bytes"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            trusted_public_key_path=artifacts[3],
            expected_fingerprint=values["fingerprint"],
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )


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
    archive, manifest, signature, _ = _build(values)
    artifact_root = tmp_path / "artifacts"
    artifacts = _artifacts(
        artifact_root,
        archive,
        manifest,
        signature,
        values["public_path"],
    )
    _, _, legitimate, legitimate_fingerprint = _keypair(tmp_path / "legitimate")
    artifacts[3].write_bytes(legitimate.read_bytes())
    with pytest.raises(installer.InstallRefused, match="fingerprint differs"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            trusted_public_key_path=artifacts[3],
            expected_fingerprint=legitimate_fingerprint,
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )

    artifacts[3].write_bytes(values["public_path"].read_bytes())
    artifacts[0].chmod(0o666)
    with pytest.raises(installer.InstallRefused, match="owner-controlled"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            trusted_public_key_path=artifacts[3],
            expected_fingerprint=values["fingerprint"],
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )


def test_verifier_rejects_traversal_and_symlink_members(tmp_path):
    values = _inputs(tmp_path)
    archive, manifest, _, _ = _build(values)
    document = json.loads(manifest)
    document["files"][0]["path"] = "../escape"
    document["files"] = sorted(document["files"], key=lambda item: item["path"])
    malicious_manifest = builder.canonical_json(document)
    malicious_signature = values["private"].sign(malicious_manifest)
    artifacts = _artifacts(
        tmp_path / "traversal",
        archive,
        malicious_manifest,
        malicious_signature,
        values["public_path"],
    )
    with pytest.raises(installer.InstallRefused, match="unsafe archive path"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            trusted_public_key_path=artifacts[3],
            expected_fingerprint=values["fingerprint"],
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
        values["public_path"],
    )
    with pytest.raises(installer.InstallRefused, match="metadata differs"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            trusted_public_key_path=artifacts[3],
            expected_fingerprint=values["fingerprint"],
            expected_owner=os.geteuid(),
            signature_verifier=_verifier,
        )


def test_verifier_rejects_tampered_or_missing_signed_installer(tmp_path):
    values = _inputs(tmp_path)
    archive, manifest, _, _ = _build(values)
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
        values["public_path"],
    )
    with pytest.raises(installer.InstallRefused, match="content differs"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            trusted_public_key_path=artifacts[3],
            expected_fingerprint=values["fingerprint"],
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
    missing_signature = values["private"].sign(missing_manifest)
    artifacts = _artifacts(
        tmp_path / "missing-installer",
        archive,
        missing_manifest,
        missing_signature,
        values["public_path"],
    )
    with pytest.raises(installer.InstallRefused, match="fixed bootstrap asset set"):
        installer.verify_bundle(
            bundle_path=artifacts[0],
            manifest_path=artifacts[1],
            signature_path=artifacts[2],
            trusted_public_key_path=artifacts[3],
            expected_fingerprint=values["fingerprint"],
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
    assert [command[1:4] for command in calls[:2]] == [
        ["-m", "venv", calls[0][-1]],
        ["-m", "pip", "install"],
    ]
    pip_command = calls[1]
    assert "--no-index" in pip_command
    assert "--no-deps" in pip_command
    assert "--require-hashes" in pip_command
    assert "--only-binary=:all:" in pip_command
    assert calls[2][1:3] == ["-I", "-c"]
    assert "import updater" in calls[2][3]
    assert "import cryptography" in calls[2][3]
    assert calls[3][-1] == "--help"
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
        Path("cathedral-validator-updater-releases") / verified.manifest_sha256
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
            "/usr/bin/systemd-sysusers",
            str(root / "etc/sysusers.d/cathedral-validator.conf"),
        ],
        ["/usr/bin/systemctl", "daemon-reload"],
    ]


def test_install_refuses_destination_symlink_before_running_commands(tmp_path):
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
    assert calls == []
    assert list(outside.iterdir()) == []


def test_install_refuses_existing_different_unit_without_mutation(tmp_path):
    verified, _, _ = _verified(tmp_path / "source")
    root = tmp_path / "host"
    unit = root / "etc/systemd/system/cathedral-validator-update.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("operator unit\n")
    unit.chmod(0o644)
    calls: list[list[str]] = []
    with pytest.raises(installer.InstallRefused, match="differs from signed bundle"):
        installer.install_verified_bundle(
            verified,
            root=root,
            expected_owner=os.geteuid(),
            python_executable=Path("/usr/bin/python3.12"),
            runner=_fake_runner(calls),
        )
    assert unit.read_text() == "operator unit\n"
    assert calls == []
    assert not (root / "usr/local/lib/cathedral-validator-updater").exists()


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
    releases = root / "usr/local/lib/cathedral-validator-updater-releases"
    assert releases.is_dir()
    assert list(releases.iterdir()) == []
    assert not (root / "usr/local/lib/cathedral-validator-updater").exists()
    assert not (root / "etc/systemd/system/cathedral-validator-update.timer").exists()


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
        / "usr/local/lib/cathedral-validator-updater-releases"
        / verified.manifest_sha256
    )
    assert stat.S_IMODE((release / ".bootstrap-manifest.json").stat().st_mode) == 0o444
    assert (
        stat.S_IMODE(
            (root / "etc/cathedral-validator/update-public-key.pem").stat().st_mode
        )
        == 0o644
    )
    for unit in installer.SYSTEMD_ASSETS:
        assert (
            stat.S_IMODE((root / "etc/systemd/system" / unit).stat().st_mode) == 0o644
        )
