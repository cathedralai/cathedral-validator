"""Owner-only, create-once JSON output for no-write preview commands."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

MAX_PREVIEW_BYTES = 1_048_576


class PreviewWriteError(Exception):
    """A local preview artifact could not be written safely."""


def canonical_document_bytes(document: Mapping[str, Any]) -> bytes:
    try:
        text = json.dumps(
            document,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise PreviewWriteError("preview is not canonical JSON data") from exc
    return (text + "\n").encode("ascii")


def write_owner_only_preview(
    document: Mapping[str, Any], output: Path
) -> tuple[Path, Path, str]:
    """Create an immutable owner-only JSON artifact and detached SHA-256."""

    if not output.is_absolute():
        raise PreviewWriteError("preview output path must be absolute")
    body = canonical_document_bytes(document)
    if len(body) > MAX_PREVIEW_BYTES:
        raise PreviewWriteError("preview exceeds its 1 MiB bound")
    digest = hashlib.sha256(body).hexdigest()
    digest_path = Path(str(output) + ".sha256")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = output.parent.stat()
    if (
        output.parent.is_symlink()
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise PreviewWriteError("preview parent is not owner-controlled")
    opened: list[Path] = []
    try:
        for target, payload in (
            (output, body),
            (digest_path, f"{digest}  {output.name}\n".encode()),
        ):
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target, flags, 0o600)
            opened.append(target)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("preview write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory = os.open(output.parent, directory_flags)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        for target in opened:
            try:
                target.unlink()
            except OSError:
                pass
        raise
    return output, digest_path, digest


__all__ = [
    "MAX_PREVIEW_BYTES",
    "PreviewWriteError",
    "canonical_document_bytes",
    "write_owner_only_preview",
]
