"""The venv tree commitment accepts the stock lib64 symlink and nothing else.

`python3 -m venv` creates `lib64 -> lib` on 64-bit Linux, so refusing every
directory symlink rejected every venv this project builds. The exception is
exactly that shape, root-owned and not group or other writable. File-symlink
integrity is unchanged.

The accept path requires a root-owned target, so it is asserted only when the
suite runs as root. The refusals below are the security-relevant half and run
everywhere.
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

UNSUPPORTED = "symlink target is unsupported"


def _venv(root: pathlib.Path) -> pathlib.Path:
    root.mkdir(parents=True)
    (root / "lib").mkdir()
    (root / "lib" / "payload.py").write_text("x = 1\n")
    (root / "bin").mkdir()
    (root / "bin" / "python3").write_text("#!/bin/sh\n")
    return root


def test_a_directory_symlink_that_is_not_lib64_is_refused(tmp_path):
    root = _venv(tmp_path / "venv")
    os.symlink("lib", root / "lib-alias")
    with pytest.raises(SystemExit, match=UNSUPPORTED):
        _manifest.immutable_tree_digest(root)


def test_lib64_pointing_somewhere_other_than_lib_is_refused(tmp_path):
    root = _venv(tmp_path / "venv")
    (root / "other").mkdir()
    os.symlink("other", root / "lib64")
    with pytest.raises(SystemExit, match=UNSUPPORTED):
        _manifest.immutable_tree_digest(root)


def test_lib64_whose_target_is_not_root_owned_is_refused(tmp_path):
    # The exception is scoped to a root-controlled venv. A user-owned tree is
    # exactly the case an attacker could stage, so it must still fail closed.
    if os.geteuid() == 0:
        pytest.skip("running as root; the non-root refusal cannot be constructed")
    root = _venv(tmp_path / "venv")
    os.symlink("lib", root / "lib64")
    with pytest.raises(SystemExit, match=UNSUPPORTED):
        _manifest.immutable_tree_digest(root)


def test_file_symlink_to_a_non_regular_target_is_still_refused(tmp_path):
    root = _venv(tmp_path / "venv")
    os.symlink("/dev/null", root / "bin" / "rogue")
    with pytest.raises(SystemExit, match=UNSUPPORTED):
        _manifest.immutable_tree_digest(root)


def test_plain_tree_without_directory_symlinks_still_commits(tmp_path):
    root = _venv(tmp_path / "venv")
    os.symlink("python3", root / "bin" / "python")
    assert _manifest.immutable_tree_digest(root).startswith("sha256:")


@pytest.mark.skipif(os.geteuid() != 0, reason="accept path needs a root-owned target")
def test_stock_lib64_is_accepted_and_committed_as_root(tmp_path):
    root = _venv(tmp_path / "venv")
    os.symlink("lib", root / "lib64")
    assert _manifest.immutable_tree_digest(root).startswith("sha256:")
