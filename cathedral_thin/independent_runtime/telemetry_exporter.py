"""Export the latest sanitized validator snapshot to Cathedral's private collector."""

from __future__ import annotations

import argparse
import grp
import json
import os
import stat
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .telemetry import (
    MAX_TELEMETRY_EVENT_BYTES,
    TelemetryError,
    latest_telemetry_event,
)

MAX_TOKEN_BYTES = 4096
MAX_RESPONSE_BYTES = 16 * 1024
DEFAULT_TIMEOUT_SECONDS = 15.0


class TelemetryExportError(RuntimeError):
    """The independent exporter could not safely deliver a snapshot."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _https_endpoint(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise TelemetryExportError("collector endpoint is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise TelemetryExportError("collector endpoint must be a plain HTTPS URL")
    return value


def _secret(path: Path, *, label: str) -> str:
    if not path.is_absolute() or path.is_symlink():
        raise TelemetryExportError(f"{label} file is not an absolute regular file")
    try:
        metadata = path.stat()
        raw = path.read_bytes()
    except OSError as exc:
        raise TelemetryExportError(f"{label} file is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not raw
        or len(raw) > MAX_TOKEN_BYTES
    ):
        raise TelemetryExportError(f"{label} file must be owner-only and bounded")
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise TelemetryExportError(f"{label} is not ASCII") from exc
    if not value or any(character.isspace() for character in value):
        raise TelemetryExportError(f"{label} is malformed")
    return value


def _distinct_secret_files(
    ingest_token_file: Path,
    sites_authorization_file: Path,
    *,
    ingest_token: str,
    sites_authorization: str,
) -> None:
    """Require separate credentials for collector authentication and bypass."""

    try:
        same_file = os.path.samestat(
            ingest_token_file.stat(), sites_authorization_file.stat()
        )
    except OSError as exc:
        raise TelemetryExportError(
            "telemetry credential files are unavailable"
        ) from exc
    if same_file or ingest_token == sites_authorization:
        raise TelemetryExportError(
            "ingest and Sites authorization credentials must be distinct"
        )


def export_event(
    *,
    endpoint: str,
    event: Mapping[str, Any],
    ingest_token: str,
    sites_authorization: str,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    opener: Callable[..., Any] | None = None,
) -> None:
    """POST one already-sanitized event without following redirects."""

    target = _https_endpoint(endpoint)
    try:
        body = json.dumps(
            event,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise TelemetryExportError("telemetry event cannot be encoded") from exc
    if not body or len(body) > MAX_TELEMETRY_EVENT_BYTES:
        raise TelemetryExportError("telemetry event exceeds its transport bound")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "cathedral-validator-telemetry/1",
        "X-Cathedral-Ingest-Token": ingest_token,
    }
    headers["OAI-Sites-Authorization"] = f"Bearer {sites_authorization}"
    request = urllib.request.Request(target, data=body, headers=headers, method="POST")
    open_request = opener or urllib.request.build_opener(_NoRedirect()).open
    try:
        with open_request(request, timeout=timeout_seconds) as response:
            status = int(response.getcode())
            content_type = str(response.headers.get("Content-Type", ""))
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise TelemetryExportError(
            f"collector refused telemetry with HTTP {exc.code}"
        ) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise TelemetryExportError("collector is unavailable") from exc
    if status not in {200, 201}:
        raise TelemetryExportError(f"collector returned unexpected HTTP {status}")
    if len(response_body) > MAX_RESPONSE_BYTES:
        raise TelemetryExportError("collector response exceeds its bound")
    if "application/json" not in content_type.lower():
        raise TelemetryExportError("collector response is not JSON")
    try:
        acknowledgement = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelemetryExportError("collector response is invalid JSON") from exc
    if (
        not isinstance(acknowledgement, dict)
        or acknowledgement.get("accepted") is not True
        or acknowledgement.get("event_id") != event.get("event_id")
    ):
        raise TelemetryExportError("collector did not acknowledge the exact event")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cathedral-validator-telemetry-export")
    parser.add_argument("--spool", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--ingest-token-file", type=Path, required=True)
    parser.add_argument("--sites-authorization-file", type=Path, required=True)
    parser.add_argument("--reader-group", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        try:
            reader_gid = grp.getgrnam(options.reader_group).gr_gid
        except KeyError as exc:
            raise TelemetryExportError("telemetry reader group does not exist") from exc
        event = latest_telemetry_event(
            options.spool,
            expected_reader_gid=reader_gid,
        )
        ingest_token = _secret(options.ingest_token_file, label="ingest token")
        sites_authorization = _secret(
            options.sites_authorization_file,
            label="Sites authorization",
        )
        _distinct_secret_files(
            options.ingest_token_file,
            options.sites_authorization_file,
            ingest_token=ingest_token,
            sites_authorization=sites_authorization,
        )
        export_event(
            endpoint=options.endpoint,
            event=event,
            ingest_token=ingest_token,
            sites_authorization=sites_authorization,
        )
    except (TelemetryError, TelemetryExportError) as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {"status": "EXPORTED", "event_id": event["event_id"]}, sort_keys=True
        )
    )
    return 0


__all__ = ["TelemetryExportError", "export_event", "main"]
