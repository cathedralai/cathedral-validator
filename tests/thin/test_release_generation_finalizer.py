"""Adversarial boundaries for versioned SN39 release publication."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest


_ROOT = Path(__file__).resolve().parents[2]


def _load_script(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, _ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_finalizer = _load_script(
    "_cathedral_release_generation_finalizer",
    "scripts/finalize_sn39_public_release.py",
)
_launcher = _load_script(
    "_cathedral_release_generation_launcher",
    "deploy/sn39/cathedral-sn39-release-launcher.py",
)


def _private_directory(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o750)
    return path


def _controlled_epoch(base: Path, name: str, payload: bytes) -> tuple[Path, str]:
    epoch = _private_directory(base / name)
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    envelope = epoch / f"{digest.split(':', 1)[1]}.json"
    envelope.write_bytes(payload)
    envelope.chmod(0o640)
    return epoch, digest


def _public_root(tmp_path: Path) -> Path:
    root = tmp_path / "public"
    for path in (
        root,
        root / "blobs",
        root / "blobs" / "sha256",
        root / "releases",
        root / "releases" / "sha256",
    ):
        path.mkdir()
        path.chmod(0o755)
    return root


def _tree_snapshot(root: Path) -> dict[str, tuple[str, bytes | str, int]]:
    snapshot: dict[str, tuple[str, bytes | str, int]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if path.is_symlink():
            snapshot[relative] = ("symlink", os.readlink(path), info.st_nlink)
        elif path.is_file():
            snapshot[relative] = ("file", path.read_bytes(), info.st_nlink)
        else:
            snapshot[relative] = ("directory", b"", info.st_nlink)
    return snapshot


def _index_snapshot(path: Path) -> tuple[bytes, tuple[int, ...]]:
    info = path.stat()
    return path.read_bytes(), (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def test_pristine_checks_do_not_refresh_the_git_index(tmp_path):
    release = tmp_path / ("a" * 40)
    release.mkdir()
    tracked = release / "tracked.txt"
    tracked.write_text("sealed bytes\n", encoding="utf-8")
    git_env = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(tmp_path),
    }
    for command in (
        ["/usr/bin/git", "init", "--quiet"],
        ["/usr/bin/git", "add", "tracked.txt"],
        [
            "/usr/bin/git",
            "-c",
            "user.name=Cathedral Test",
            "-c",
            "user.email=cathedral-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
    ):
        subprocess.run(command, cwd=release, env=git_env, check=True)

    tracked_info = tracked.stat()
    os.utime(
        tracked,
        ns=(tracked_info.st_atime_ns, tracked_info.st_mtime_ns + 2_000_000_000),
    )
    index = release / ".git" / "index"
    before = _index_snapshot(index)

    assert (
        _launcher._git_output(
            release,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        )
        == ""
    )
    assert _index_snapshot(index) == before
    assert (
        _finalizer.git(
            release,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        )
        == ""
    )
    assert _index_snapshot(index) == before


def test_current_symlink_is_bound_to_one_direct_epoch(tmp_path, monkeypatch):
    monkeypatch.setattr(_finalizer, "ROOT_UID", os.geteuid())
    base = _private_directory(tmp_path / "controlled")
    _epoch_a, digest = _controlled_epoch(base, "epoch-a", b"epoch-a")
    _epoch_b, _ = _controlled_epoch(base, "epoch-b", b"epoch-b")
    current = base / "current"
    current.symlink_to("epoch-a", target_is_directory=True)

    with _finalizer._open_controlled_directory(current) as descriptor:
        current.unlink()
        current.symlink_to("epoch-b", target_is_directory=True)
        assert _finalizer._read_controlled_envelope(descriptor, digest) == b"epoch-a"


@pytest.mark.parametrize(
    "target",
    ["../outside", "/tmp/outside", "current", "./epoch-a", "epoch-a/"],
)
def test_current_symlink_cannot_escape_its_controlled_parent(
    tmp_path,
    monkeypatch,
    target,
):
    monkeypatch.setattr(_finalizer, "ROOT_UID", os.geteuid())
    base = _private_directory(tmp_path / "controlled")
    current = base / "current"
    current.symlink_to(target, target_is_directory=True)
    with pytest.raises(_finalizer.ReleaseError, match="direct epoch"):
        with _finalizer._open_controlled_directory(current):
            pass


def test_controlled_path_rejects_a_symlinked_ancestor(tmp_path, monkeypatch):
    monkeypatch.setattr(_finalizer, "ROOT_UID", os.geteuid())
    base = _private_directory(tmp_path / "controlled")
    _controlled_epoch(base, "epoch-a", b"epoch-a")
    (base / "current").symlink_to("epoch-a", target_is_directory=True)
    alias = tmp_path / "controlled-alias"
    alias.symlink_to(base, target_is_directory=True)

    with pytest.raises(_finalizer.ReleaseError, match="contains a symlink"):
        with _finalizer._open_controlled_directory(alias / "current"):
            pass


def test_controlled_selector_rejects_a_symlinked_epoch_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(_finalizer, "ROOT_UID", os.geteuid())
    base = _private_directory(tmp_path / "controlled")
    _controlled_epoch(base, "epoch-a", b"epoch-a")
    (base / "epoch-alias").symlink_to("epoch-a", target_is_directory=True)
    current = base / "current"
    current.symlink_to("epoch-alias", target_is_directory=True)

    with pytest.raises(_finalizer.ReleaseError, match="is a symlink"):
        with _finalizer._open_controlled_directory(current):
            pass


def test_preflight_leaves_every_public_inode_unchanged(tmp_path):
    root = _public_root(tmp_path)
    release_bytes = b'{"generation":2}'
    signature_bytes = b'{"signature":"test"}\n'
    _, _, release_path, _, plan = _finalizer._release_publication_plan(
        public_root=root,
        release_bytes=release_bytes,
        signature_bytes=signature_bytes,
        replay_bytes=b"",
        checkpoint=None,
    )
    pending = release_path.parent / f".{release_path.name}.pending"
    pending.write_bytes(b"recoverable-stale-stage")
    pending.chmod(0o644)
    historical = root / "release.json"
    historical.write_bytes(b"historical-release")
    historical.chmod(0o644)
    before = _tree_snapshot(root)

    _finalizer._preflight_publication(plan, public_root=root)

    assert _tree_snapshot(root) == before
    assert not (root / ".sn39-publication.lock").exists()


def test_versioned_publication_preserves_the_historical_root_release(tmp_path):
    root = _public_root(tmp_path)
    historical = root / "release.json"
    historical_signature = root / "release.json.sig"
    historical.write_bytes(b"historical-release")
    historical_signature.write_bytes(b"historical-signature")
    historical.chmod(0o644)
    historical_signature.chmod(0o644)
    release_bytes = b'{"generation":2}'
    signature_bytes = b'{"signature":"test"}\n'
    release_digest, _, release_path, signature_path, plan = (
        _finalizer._release_publication_plan(
            public_root=root,
            release_bytes=release_bytes,
            signature_bytes=signature_bytes,
            replay_bytes=b"",
            checkpoint=None,
        )
    )

    _finalizer._publish_publication(plan, public_root=root)

    assert historical.read_bytes() == b"historical-release"
    assert historical_signature.read_bytes() == b"historical-signature"
    assert release_path.read_bytes() == release_bytes
    assert signature_path.read_bytes() == signature_bytes
    assert release_path.name == release_digest.split(":", 1)[1] + ".json"


def test_a_late_conflict_is_found_before_any_blob_or_release_write(tmp_path):
    root = _public_root(tmp_path)
    replay = b"replay"
    replay_digest = "sha256:" + hashlib.sha256(replay).hexdigest()
    checkpoint = {"replay_result": replay_digest}
    _, _, release_path, _, plan = _finalizer._release_publication_plan(
        public_root=root,
        release_bytes=b'{"generation":2}',
        signature_bytes=b'{"signature":"test"}\n',
        replay_bytes=replay,
        checkpoint=checkpoint,
    )
    release_path.write_bytes(b"hostile-conflict")
    release_path.chmod(0o644)
    blob_path = root / "blobs" / "sha256" / replay_digest.split(":", 1)[1]

    with pytest.raises(_finalizer.ReleaseError, match="different bytes"):
        _finalizer._publish_publication(plan, public_root=root)

    assert not blob_path.exists()
    assert release_path.read_bytes() == b"hostile-conflict"


def test_preflight_rejects_a_release_hardlink_alias(tmp_path):
    root = _public_root(tmp_path)
    release_bytes = b'{"generation":2}'
    _, _, release_path, _, plan = _finalizer._release_publication_plan(
        public_root=root,
        release_bytes=release_bytes,
        signature_bytes=b'{"signature":"test"}\n',
        replay_bytes=b"",
        checkpoint=None,
    )
    release_path.write_bytes(release_bytes)
    release_path.chmod(0o644)
    os.link(release_path, release_path.parent / "untrusted-alias")

    with pytest.raises(_finalizer.ReleaseError, match="hardlink alias"):
        _finalizer._preflight_publication(plan, public_root=root)


def test_versioned_reproducer_path_is_digest_bound():
    digest = "sha256:" + "a" * 64
    assert _finalizer.SHA256.fullmatch(digest)
    from scaffold import sn39_public_reproduction as reproduction

    assert reproduction._release_artifact_paths(None) == (
        "/release.json",
        "/release.json.sig",
    )
    assert reproduction._release_artifact_paths(digest) == (
        f"/releases/sha256/{'a' * 64}.json",
        f"/releases/sha256/{'a' * 64}.json.sig",
    )
    with pytest.raises(reproduction.ReproductionError, match="malformed"):
        reproduction._release_artifact_paths("sha256:../release.json")


class _ExecveCalled(RuntimeError):
    pass


def test_launcher_binds_preflight_context_and_adds_no_finalize_flag(
    tmp_path,
    monkeypatch,
):
    release = tmp_path / ("a" * 40)
    release.mkdir()
    python = tmp_path / "python"
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    journal = runtime / f"journal-{'b' * 64}.json"
    captured = {}
    monkeypatch.setattr(_launcher, "RUNTIME_ROOT", runtime)
    monkeypatch.setattr(
        _launcher,
        "_verify",
        lambda mode: (release, python, "sha256:" + "c" * 64),
    )
    monkeypatch.setattr(_launcher.os, "geteuid", lambda: 0)
    monkeypatch.setattr(_launcher.os, "chdir", lambda _path: None)

    def capture_execve(executable, command, environment):
        captured.update(
            executable=executable,
            command=command,
            environment=environment,
        )
        raise _ExecveCalled

    monkeypatch.setattr(_launcher.os, "execve", capture_execve)

    with pytest.raises(_ExecveCalled):
        _launcher.main(["preflight", str(journal)])

    assert captured["command"][-1] == "--preflight"
    expected = _launcher._finalizer_context_digest(
        operation="preflight",
        release_sha=release.name,
        journal=journal,
        manifest_digest="sha256:" + "c" * 64,
    )
    assert captured["environment"][_launcher.FINALIZER_CONTEXT_ENV] == expected


def test_preflight_context_cannot_authorize_finalize(tmp_path):
    journal = tmp_path / f"journal-{'b' * 64}.json"
    values = {
        operation: _launcher._finalizer_context_digest(
            operation=operation,
            release_sha="a" * 40,
            journal=journal,
            manifest_digest="sha256:" + "c" * 64,
        )
        for operation in ("preflight", "finalize")
    }
    assert values["preflight"] != values["finalize"]


@pytest.mark.parametrize("operation", ["preflight", "finalize"])
def test_launcher_and_finalizer_context_contracts_match(tmp_path, operation):
    journal = tmp_path / f"journal-{'b' * 64}.json"
    arguments = {
        "operation": operation,
        "release_sha": "a" * 40,
        "journal": journal,
        "manifest_digest": "sha256:" + "c" * 64,
    }
    assert _launcher._finalizer_context_digest(
        **arguments
    ) == _finalizer._launcher_context_digest(**arguments)


def test_tmpfiles_provisions_the_versioned_release_parents():
    tmpfiles = (_ROOT / "deploy/sn39/cathedral-sn39-validator.tmpfiles").read_text(
        "utf-8"
    )
    assert (
        "d /var/lib/cathedral-public-evidence/releases :0755 :root :root -" in tmpfiles
    )
    assert (
        "d /var/lib/cathedral-public-evidence/releases/sha256 "
        ":0755 :root :root -" in tmpfiles
    )


def test_preflight_main_never_enters_the_publication_primitive(
    tmp_path,
    monkeypatch,
):
    root = _public_root(tmp_path)
    historical = root / "release.json"
    historical.write_bytes(b"historical")
    historical.chmod(0o644)
    release = {
        "attested_submission": {
            "evidence_checkpoint": None,
            "extrinsic": {"hash": "0x" + "d" * 64},
        }
    }
    monkeypatch.setattr(_finalizer, "PUBLIC_ROOT", root)
    monkeypatch.setattr(_finalizer, "_require_launcher_context", lambda **_kw: None)
    monkeypatch.setattr(_finalizer, "verify_release_checkout", lambda *_a: None)
    monkeypatch.setattr(_finalizer, "read_launch_journal", lambda _path: {})
    monkeypatch.setattr(_finalizer, "_archive_subtensor", object)
    monkeypatch.setattr(
        _finalizer,
        "build_release",
        lambda *_a, **_kw: (release, b""),
    )
    monkeypatch.setattr(
        _finalizer,
        "verify_frozen_release_evidence",
        lambda *_a, **_kw: None,
    )
    monkeypatch.setattr(_finalizer, "_read_root_seed", lambda _path: b"seed")
    monkeypatch.setattr(
        _finalizer,
        "build_signature",
        lambda *_a, **_kw: b"signature\n",
    )
    monkeypatch.setattr(
        _finalizer,
        "_publish_publication",
        lambda *_a, **_kw: (_ for _ in ()).throw(
            AssertionError("preflight attempted publication")
        ),
    )
    journal = Path("/var/lib/cathedral-validator") / f"journal-{'b' * 64}.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(Path(_finalizer.__file__)),
            "--release",
            str(_ROOT),
            "--release-sha",
            "a" * 40,
            "--journal",
            str(journal),
            "--preflight",
        ],
    )
    before = _tree_snapshot(root)

    assert _finalizer.main() == 0

    assert _tree_snapshot(root) == before
    assert not (root / ".sn39-publication.lock").exists()
