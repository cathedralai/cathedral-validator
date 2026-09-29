"""Read a small, owner-controlled local policy file safely.

Shared by the SNP production policy and the TDX measurement allowlist, so a
hardening lands in both. The file must be a regular file, owned by root or by
the process's effective user, not group or world writable, and at most
``max_bytes``. What each check covers, exactly:

* ``O_NOFOLLOW`` refuses a symlink as the final path component only; a
  symlinked parent directory still resolves;
* ``O_NONBLOCK`` keeps a FIFO (or other special file) at the path from blocking
  the open; it is then refused as not regular. It has no effect on reading a
  regular file;
* the size bound is checked on the open file and again while reading, so a
  file that grows is refused without reading more than ``max_bytes + 1``;
* the second ``fstat`` is on the same descriptor: it catches the file being
  rewritten in place while it is read, not the path being swapped afterwards
  (a swap after the open does not change what was read).

Every refusal raises ``error(message)``.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable


def read_owner_policy_file(
    path: Path,
    *,
    max_bytes: int,
    error: Callable[[str], Exception],
    unavailable: str,
    unreadable: str,
    unsafe: str,
    too_large: str,
    changed: str,
) -> bytes:
    """Return the file's bytes, or raise ``error`` with the matching message."""

    if not hasattr(os, "O_NOFOLLOW"):
        raise error(unavailable)
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise error(unreadable) from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 1 <= before.st_size <= max_bytes
        ):
            raise error(unsafe)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise error(too_large)
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or len(raw) != before.st_size:
            raise error(changed)
        return raw
    finally:
        os.close(fd)


__all__ = ["read_owner_policy_file"]
