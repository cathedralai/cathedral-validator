"""The venv tree commitment accepts the stock lib64 symlink and nothing else.

`python3 -m venv` creates `lib64 -> lib` on 64-bit Linux, so refusing every
directory symlink rejected every venv this project builds. The exception is exactly
that shape, root-owned and not group or other writable. File-symlink integrity is
unchanged.

**Why this is still a divergence after the `dabf10b` sync.** Upstream's #403-#406
hardening rewrote `immutable_tree_digest` and, in doing so, broadened directory
symlinks to accept *any* symlink resolving inside the tree. This repo keeps the
narrow rule — only `lib64 -> lib` — because any other directory symlink inside an
immutable tree is unexplained, and a swapped target is precisely what the commitment
exists to catch. Upstream's ownership and mode checks are kept on top, as are its
`directory-symlink` digest label and root-relative target, so the commitment stays
byte-identical to upstream's for the shapes both accept. Retiring the narrowing to
take upstream's version wholesale would have loosened a control, which is a decision
for the owner rather than a side effect of a sync.

Upstream's rewrite also requires the tree ROOT to be root-owned, readable and
searchable. That cannot hold for a `tmp_path` owned by the test user, so `ROOT_UID`
is monkeypatched to the current uid — the same pattern upstream's own
`test_sn39_rotation_bundle.py` uses. The ownership rule is then still exercised
against a *target* the fixture makes non-conforming, so the security-relevant half
runs everywhere rather than only as root.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib

import pytest

_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "scripts"
    / "build_sn39_release_manifest.py"
)
_spec = importlib.util.spec_from_file_location("_sn39_release_manifest", _MODULE_PATH)
_manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_manifest)

# The narrowing's own refusal, and upstream's target-ownership refusal.
UNSUPPORTED = "directory symlink is unsupported"
NOT_READABLE = "directory symlink target is not"


@pytest.fixture
def as_owner(monkeypatch):
    """Treat the test user as the tree owner.

    Upstream requires the immutable tree root to be root-owned; a pytest tmp_path
    never is. Upstream's own tests monkeypatch `ROOT_UID` for exactly this, so the
    rule under test stays the symlink rule rather than "are we root".
    """
    monkeypatch.setattr(_manifest, "ROOT_UID", os.getuid())
    return _manifest


def _venv(root: pathlib.Path) -> pathlib.Path:
    """A stock-shaped venv tree that satisfies upstream's mode requirements.

    Upstream's rewrite requires every directory to be non-group/other-writable and
    both readable and searchable by the service account (`mode & 0o005 == 0o005`).
    A pytest `tmp_path` is 0o700, which fails that before any symlink is examined,
    so the fixture sets 0755/0644 explicitly. That is also what the real deployed
    tree looks like, so the modes here are not a test-only fiction.
    """
    root.mkdir(parents=True)
    (root / "lib").mkdir()
    (root / "lib" / "payload.py").write_text("x = 1\n")
    (root / "bin").mkdir()
    (root / "bin" / "python3").write_text("#!/bin/sh\n")
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            continue
        path.chmod(0o755 if path.is_dir() else 0o644)
    return root


def test_a_directory_symlink_that_is_not_lib64_is_refused(tmp_path, as_owner):
    """Upstream would accept this; the narrowing is what refuses it."""
    root = _venv(tmp_path / "venv")
    os.symlink("lib", root / "lib-alias")
    with pytest.raises(SystemExit, match=UNSUPPORTED):
        as_owner.immutable_tree_digest(root)


def test_lib64_pointing_somewhere_other_than_lib_is_refused(tmp_path, as_owner):
    root = _venv(tmp_path / "venv")
    (root / "other").mkdir()
    os.symlink("other", root / "lib64")
    with pytest.raises(SystemExit, match=UNSUPPORTED):
        as_owner.immutable_tree_digest(root)


def test_a_group_writable_lib64_target_is_refused(tmp_path, as_owner):
    """The exception is scoped to a tree nobody else can rewrite.

    A group-writable target is what an attacker could stage, so it fails closed even
    though the name and link text are the permitted shape. Upstream's rewrite catches
    it at the *directory* check, before the symlink branch runs — a stricter path than
    the target check this used to rely on, so the message names the directory. What
    matters is that it refuses and says which path, not which check got there first.
    """
    root = _venv(tmp_path / "venv")
    os.symlink("lib", root / "lib64")
    (root / "lib").chmod(0o775)
    with pytest.raises(SystemExit) as caught:
        as_owner.immutable_tree_digest(root)
    message = str(caught.value)
    assert "lib" in message
    assert "not root-controlled" in message or NOT_READABLE in message


def test_file_symlink_to_a_non_regular_target_is_still_refused(tmp_path, as_owner):
    root = _venv(tmp_path / "venv")
    os.symlink("/dev/null", root / "bin" / "rogue")
    with pytest.raises(SystemExit, match="symlink"):
        as_owner.immutable_tree_digest(root)


def test_plain_tree_without_directory_symlinks_still_commits(tmp_path, as_owner):
    root = _venv(tmp_path / "venv")
    os.symlink("python3", root / "bin" / "python")
    assert as_owner.immutable_tree_digest(root).startswith("sha256:")


def test_stock_lib64_is_accepted_and_committed(tmp_path, as_owner):
    """The whole reason the exception exists: a stock venv must commit."""
    root = _venv(tmp_path / "venv")
    os.symlink("lib", root / "lib64")
    assert as_owner.immutable_tree_digest(root).startswith("sha256:")


def test_the_narrowing_is_what_differs_from_upstream(tmp_path, as_owner):
    """Documents the divergence so retiring it becomes a deliberate act.

    Upstream accepts any in-root directory symlink. If a future sync takes that
    version wholesale, `lib-alias` starts committing instead of being refused and
    this fails, rather than the loosening landing silently.
    """
    root = _venv(tmp_path / "venv")
    os.symlink("lib", root / "lib-alias")
    with pytest.raises(SystemExit, match=UNSUPPORTED):
        as_owner.immutable_tree_digest(root)
    source = _MODULE_PATH.read_text(encoding="utf-8")
    assert 'relative != "lib64"' in source, (
        "the lib64 narrowing is gone from build_sn39_release_manifest.py; upstream's "
        "broader rule accepts any in-root directory symlink, which is a loosening "
        "that needs an owner decision rather than a sync"
    )
