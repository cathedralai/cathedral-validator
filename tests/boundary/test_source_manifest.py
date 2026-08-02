from __future__ import annotations

import importlib.util
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE = ROOT / "tools" / "source_manifest.py"
SPEC = importlib.util.spec_from_file_location("source_manifest", MODULE)
assert SPEC is not None and SPEC.loader is not None
SOURCE_MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE_MANIFEST)


def test_source_manifest_matches_tracked_files() -> None:
    assert (ROOT / "MANIFEST.sha256").read_bytes() == SOURCE_MANIFEST.render()


def test_source_manifest_never_hashes_itself() -> None:
    assert pathlib.Path("MANIFEST.sha256") not in SOURCE_MANIFEST.tracked_files()
