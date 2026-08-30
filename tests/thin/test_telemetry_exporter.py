from __future__ import annotations

import json
import urllib.error
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cathedral_thin.independent_runtime.telemetry_exporter import (
    TelemetryExportError,
    _distinct_secret_files,
    _secret,
    export_event,
)


class _Response:
    def __init__(
        self,
        status: int = 201,
        body: bytes | None = None,
        content_type: str = "application/json",
    ) -> None:
        self.status = status
        self.body = (
            body
            or json.dumps({"accepted": True, "event_id": _event()["event_id"]}).encode()
        )
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def getcode(self) -> int:
        return self.status

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


def _event() -> dict[str, object]:
    return {
        "schema": "cathedral_validator_telemetry_v2",
        "observed_at": datetime(2026, 8, 30, tzinfo=UTC).isoformat(),
        "event_id": "sha256:" + "a" * 64,
        "signature": {"algorithm": "sr25519", "value_base64": "not-a-real-fixture"},
    }


def test_export_posts_only_json_and_private_auth_headers() -> None:
    seen = {}

    def open_request(request, *, timeout):
        seen["request"] = request
        seen["timeout"] = timeout
        return _Response()

    export_event(
        endpoint="https://collector.example/api/validator/ingest",
        event=_event(),
        ingest_token="ingest-secret",
        sites_authorization="sites-secret",
        opener=open_request,
    )

    request = seen["request"]
    assert request.full_url == "https://collector.example/api/validator/ingest"
    assert request.method == "POST"
    assert json.loads(request.data) == _event()
    headers = {key.lower(): value for key, value in request.header_items()}
    assert headers["x-cathedral-ingest-token"] == "ingest-secret"
    assert headers["oai-sites-authorization"] == "Bearer sites-secret"


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://collector.example/ingest",
        "https://user@collector.example/ingest",
        "https://collector.example:8443/ingest",
        "https://collector.example/ingest?token=bad",
        "https://collector.example/ingest#fragment",
    ],
)
def test_export_refuses_unsafe_endpoint(endpoint: str) -> None:
    with pytest.raises(TelemetryExportError, match="HTTPS"):
        export_event(
            endpoint=endpoint,
            event=_event(),
            ingest_token="secret",
            sites_authorization="sites-secret",
        )


def test_export_refuses_redirect() -> None:
    def redirect(_request, *, timeout):
        raise urllib.error.HTTPError(
            "https://collector.example/ingest", 302, "redirect", {}, None
        )

    with pytest.raises(TelemetryExportError, match="HTTP 302"):
        export_event(
            endpoint="https://collector.example/ingest",
            event=_event(),
            ingest_token="secret",
            sites_authorization="sites-secret",
            opener=redirect,
        )


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (_Response(status=204), "unexpected HTTP 204"),
        (_Response(body=b"not-json"), "invalid JSON"),
        (_Response(content_type="text/html"), "not JSON"),
        (
            _Response(
                body=json.dumps(
                    {"accepted": True, "event_id": "sha256:" + "b" * 64}
                ).encode()
            ),
            "exact event",
        ),
        (
            _Response(
                body=json.dumps(
                    {"accepted": False, "event_id": _event()["event_id"]}
                ).encode()
            ),
            "exact event",
        ),
    ],
)
def test_export_requires_exact_collector_acknowledgement(
    response: _Response,
    message: str,
) -> None:
    with pytest.raises(TelemetryExportError, match=message):
        export_event(
            endpoint="https://collector.example/ingest",
            event=_event(),
            ingest_token="secret",
            sites_authorization="sites-secret",
            opener=lambda _request, *, timeout: response,
        )


def test_secret_file_is_owner_only(tmp_path) -> None:
    path = tmp_path / "token"
    path.write_text("secret\n", encoding="ascii")
    path.chmod(0o600)
    assert _secret(path, label="token") == "secret"
    path.chmod(0o644)
    with pytest.raises(TelemetryExportError, match="owner-only"):
        _secret(path, label="token")


def test_exporter_requires_two_distinct_credential_files_and_values(tmp_path) -> None:
    ingest = tmp_path / "ingest"
    sites = tmp_path / "sites"
    for path, value in ((ingest, "ingest-secret"), (sites, "sites-secret")):
        path.write_text(value, encoding="ascii")
        path.chmod(0o600)

    _distinct_secret_files(
        ingest,
        sites,
        ingest_token="ingest-secret",
        sites_authorization="sites-secret",
    )

    with pytest.raises(TelemetryExportError, match="must be distinct"):
        _distinct_secret_files(
            ingest,
            ingest,
            ingest_token="ingest-secret",
            sites_authorization="ingest-secret",
        )


def test_deployment_files_share_one_isolated_identity_and_spool_contract() -> None:
    root = Path(__file__).resolve().parents[2]
    deploy = root / "deploy" / "validator-telemetry"
    service = (deploy / "cathedral-validator-telemetry.service").read_text()
    sysusers = (deploy / "cathedral-validator-telemetry.sysusers").read_text()
    tmpfiles = (deploy / "cathedral-validator-telemetry.tmpfiles").read_text()
    environment = (deploy / "telemetry-export.env.example").read_text()
    guide = (root / "docs" / "PRIVATE_TELEMETRY.md").read_text()

    assert "User=cathedral-telemetry" in service
    assert "Group=cathedral-telemetry" in service
    assert "Environment=PEX_INTERPRETER=1" in service
    assert "Environment=PEX_ROOT=/run/cathedral-validator-telemetry-pex" in service
    assert "RuntimeDirectory=cathedral-validator-telemetry-pex" in service
    assert "ConditionFileIsExecutable=/usr/bin/python3.12" in service
    assert (
        "ExecStart=/opt/cathedral-validator/current/bin/cathedral-validator "
        "-m cathedral_thin.independent_runtime.telemetry_exporter" in service
    )
    assert "/usr/local/bin/cathedral-validator-telemetry-export" not in service
    assert "InaccessiblePaths=/var/lib/cathedral-validator" in service
    assert "InaccessiblePaths=/etc/cathedral-validator" in service
    assert "EnvironmentFile=/etc/cathedral-validator-telemetry/export.env" in service
    assert (
        "ReadOnlyPaths=/opt/cathedral-validator/current "
        "/var/lib/cathedral-validator-telemetry "
        "/etc/cathedral-validator-telemetry" in service
    )
    assert "CapabilityBoundingSet=" in service
    assert "PrivateDevices=true" in service
    assert "--spool /var/lib/cathedral-validator-telemetry/events.jsonl" in service
    assert "--reader-group cathedral-telemetry" in service
    assert "g cathedral-telemetry -" in sysusers
    assert "u cathedral-telemetry -" in sysusers
    assert "m cathedral-validator cathedral-telemetry" in sysusers
    assert (
        "d /var/lib/cathedral-validator-telemetry 0750 "
        "cathedral-validator cathedral-telemetry -"
    ) in tmpfiles
    for path in (
        "/etc/cathedral-validator-telemetry/ingest.token",
        "/etc/cathedral-validator-telemetry/sites-authorization.token",
    ):
        assert path in environment
        assert path in guide
    assert (
        "--telemetry-spool /var/lib/cathedral-validator-telemetry/events.jsonl" in guide
    )
    assert "--telemetry-reader-group cathedral-telemetry" in guide
    assert "systemd-sysusers" in guide
    assert "systemd-tmpfiles --create" in guide
    assert "enable --now cathedral-validator-telemetry.timer" in guide
    assert (
        "bittensor"
        not in (
            root / "cathedral_thin" / "independent_runtime" / "telemetry_exporter.py"
        ).read_text()
    )
