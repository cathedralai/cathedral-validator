"""Cathedral Workers rental and listing client.

This is the customer API at ``https://cathedral.computer/v1``, not the SN39
miner protocol. A rented persistent Intel TDX Worker is how this runner lists
a machine. Serving ``POST /v1/evidence`` from inside that guest is a later
step; listing the Worker is this module.
"""

from __future__ import annotations

import json
import ssl
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .errors import WorkersApiError

DEFAULT_BASE_URL = "https://cathedral.computer"
DEFAULT_TIMEOUT = 30.0
MAX_BODY_BYTES = 1_048_576
USER_AGENT = "cathedral-independent-live/1.0"

READY_STATUSES = frozenset(
    {"ready", "running", "active", "available", "up", "workload_ready"}
)
PROVISIONING_STATUSES = frozenset(
    {"queued", "provisioning", "attesting", "starting", "pending", "created"}
)

HttpTransport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]


def _require_https(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.query or parsed.fragment:
        raise WorkersApiError(
            "Workers API URLs must be https with no query or fragment"
        )
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise WorkersApiError("Workers API URLs must be credential-free")


def _decode_json(raw: bytes, label: str) -> Any:
    if len(raw) > MAX_BODY_BYTES:
        raise WorkersApiError(f"{label} exceeds the {MAX_BODY_BYTES} byte bound")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkersApiError(f"{label} is not JSON: {exc}") from exc
    return document


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def default_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> tuple[int, bytes]:
    """One HTTPS request. Redirects are not followed."""
    _require_https(url)
    request = Request(url, data=body, method=method, headers=headers)
    context = ssl.create_default_context()
    opener = build_opener(HTTPSHandler(context=context), _RejectRedirects())
    try:
        with opener.open(request, timeout=DEFAULT_TIMEOUT) as response:
            return int(response.status), response.read(MAX_BODY_BYTES + 1)
    except Exception as exc:
        status = getattr(getattr(exc, "fp", None), "status", None) or getattr(
            exc, "code", None
        )
        raw = b""
        fp = getattr(exc, "fp", None)
        if fp is not None:
            try:
                raw = fp.read(MAX_BODY_BYTES + 1)
            except Exception:
                raw = b""
        if isinstance(status, int):
            return status, raw
        raise WorkersApiError(f"Workers API {method} {url} failed: {exc}") from exc


def fetch_public_json(path: str, *, base_url: str = DEFAULT_BASE_URL) -> Any:
    """GET a credential-free public Workers route such as ``/v1/profiles``."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise WorkersApiError("public Workers path must start with /")
    url = f"{base_url.rstrip('/')}{path}"
    status, raw = default_transport(
        "GET",
        url,
        {"Accept": "application/json", "User-Agent": USER_AGENT},
        None,
    )
    if status != 200:
        raise WorkersApiError(f"GET {path} returned {status}")
    return _decode_json(raw, f"GET {path}")


@dataclass(frozen=True)
class WorkerRecord:
    """One listed Worker, enough to decide whether it can become a miner."""

    worker_id: str
    status: str
    hardware_class: str
    name: str
    ip: str | None
    ssh_host: str | None
    raw: Mapping[str, Any]

    @property
    def ready(self) -> bool:
        return self.status.lower() in READY_STATUSES

    @property
    def is_tdx(self) -> bool:
        return self.hardware_class in {"tdx_cpu", "intel_tdx_cpu"}


def _optional_str(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _worker_from_document(document: Mapping[str, Any]) -> WorkerRecord:
    if not isinstance(document, Mapping):
        raise WorkersApiError("a Worker record must be a JSON object")
    worker_id = document.get("id") or document.get("worker_id")
    if not isinstance(worker_id, str) or not worker_id:
        raise WorkersApiError("a Worker record has no id")
    status = document.get("status")
    if not isinstance(status, str) or not status:
        raise WorkersApiError(f"worker {worker_id} has no status")
    resources = document.get("resources")
    hardware = ""
    if isinstance(resources, Mapping):
        raw_hardware = resources.get("hardware_class")
        if isinstance(raw_hardware, str):
            hardware = raw_hardware
    trust = document.get("trust")
    if not hardware and isinstance(trust, Mapping):
        raw_hardware = trust.get("hardware_class") or trust.get("execution_class")
        if isinstance(raw_hardware, str):
            hardware = raw_hardware
    if not hardware:
        execution = document.get("execution_class")
        if isinstance(execution, str):
            hardware = execution
    name = document.get("name")
    if not isinstance(name, str):
        name = ""
    connection = document.get("connection")
    ssh_host = _optional_str(document.get("ssh_host"))
    ip = _optional_str(document.get("ip"))
    if isinstance(connection, Mapping):
        ip = (
            ip
            or _optional_str(connection.get("ip"))
            or _optional_str(connection.get("public_ip"))
        )
        ssh = connection.get("ssh")
        if isinstance(ssh, Mapping):
            host = _optional_str(ssh.get("host"))
            if host:
                ssh_host = host
                if ip is None:
                    ip = host
    return WorkerRecord(
        worker_id=worker_id,
        status=status,
        hardware_class=hardware,
        name=name,
        ip=ip,
        ssh_host=ssh_host,
        raw=dict(document),
    )


class WorkersClient:
    """Account-scoped Cathedral Workers API."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        transport: HttpTransport | None = None,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.startswith("cat_sk_"):
            raise WorkersApiError("CATHEDRAL_API_KEY must be a cat_sk_* token")
        _require_https(base_url if base_url.endswith("/") else base_url + "/")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.transport = transport or default_transport

    def _headers(self, *, idempotency: str | None = None) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        if idempotency is not None:
            headers["Idempotency-Key"] = idempotency
            headers["Content-Type"] = "application/json"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        idempotency: str | None = None,
    ) -> tuple[int, Any]:
        url = f"{self.base_url}{path}"
        _require_https(url)
        encoded: bytes | None = None
        headers = self._headers(idempotency=idempotency)
        if body is not None:
            encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
            headers["Content-Type"] = "application/json"
        status, raw = self.transport(method, url, headers, encoded)
        if len(raw) > MAX_BODY_BYTES:
            raise WorkersApiError(
                f"{method} {path} exceeded the {MAX_BODY_BYTES} byte bound"
            )
        if not raw:
            return status, None
        return status, _decode_json(raw, f"{method} {path}")

    def credits(self) -> Any:
        status, document = self._request("GET", "/v1/credits")
        if status != 200:
            raise WorkersApiError(f"GET /v1/credits returned {status}: {document}")
        return document

    def profiles(self) -> Any:
        status, document = self._request("GET", "/v1/profiles")
        if status != 200:
            raise WorkersApiError(f"GET /v1/profiles returned {status}: {document}")
        return document

    def list_workers(self) -> tuple[WorkerRecord, ...]:
        status, document = self._request("GET", "/v1/workers")
        if status == 401:
            raise WorkersApiError("GET /v1/workers returned 401: API key was rejected")
        if status != 200:
            raise WorkersApiError(f"GET /v1/workers returned {status}: {document}")
        if isinstance(document, Mapping) and "workers" in document:
            rows = document["workers"]
        elif isinstance(document, list):
            rows = document
        else:
            raise WorkersApiError("GET /v1/workers did not return a worker list")
        if not isinstance(rows, list):
            raise WorkersApiError("GET /v1/workers workers field is not a list")
        return tuple(_worker_from_document(row) for row in rows)

    def get_worker(self, worker_id: str) -> WorkerRecord:
        if not isinstance(worker_id, str) or not worker_id:
            raise WorkersApiError("worker_id must be a non-empty string")
        status, document = self._request("GET", f"/v1/workers/{worker_id}")
        if status != 200:
            raise WorkersApiError(
                f"GET /v1/workers/{worker_id} returned {status}: {document}"
            )
        if not isinstance(document, Mapping):
            raise WorkersApiError("GET worker did not return an object")
        return _worker_from_document(document)

    def create_persistent_tdx(
        self,
        *,
        name: str,
        max_runtime_minutes: int = 120,
        max_spend_usd: float = 2.0,
        idempotency_key: str | None = None,
    ) -> WorkerRecord:
        """Rent a sealed Intel TDX Worker. Fast CPU is refused here.

        Cathedral's live catalog uses ``custom.v1`` + ``bounded_service`` for
        sealed TDX. ``lifetime.mode=persistent`` is the Fast CPU keep-warm
        path and is not confidential.
        """
        if not isinstance(name, str) or not name:
            raise WorkersApiError("a Worker name is required")
        if max_runtime_minutes <= 0:
            raise WorkersApiError("max_runtime_minutes must be positive")
        if max_spend_usd < 1.0:
            raise WorkersApiError("max_spend_usd must be at least 1.00")
        key = idempotency_key or str(uuid.uuid4())
        body = {
            "profile": "custom.v1",
            "name": name,
            "lifetime": {
                "mode": "bounded_service",
                "max_runtime_minutes": max_runtime_minutes,
                "reuse": "allowed",
            },
            "resources": {
                "hardware_class": "tdx_cpu",
                "cpu": 4,
                "memory_gib": 16,
                "region": "auto",
                "gpu": {"mode": "none"},
            },
            "workload": {
                "image": "python:3.12-slim",
                "command": ["python", "-m", "http.server", "8080"],
            },
            "network": {"egress": "default"},
            "budget": {"max_spend_usd": max_spend_usd, "auto_stop": True},
        }
        status, document = self._request(
            "POST", "/v1/workers", body=body, idempotency=key
        )
        if status not in {200, 201, 202}:
            raise WorkersApiError(f"POST /v1/workers returned {status}: {document}")
        if not isinstance(document, Mapping):
            raise WorkersApiError("POST /v1/workers did not return an object")
        return _worker_from_document(document)

    def run_command(
        self, worker_id: str, command: str, *, timeout_seconds: int = 60
    ) -> Any:
        if not isinstance(command, str) or not command:
            raise WorkersApiError("command must be a non-empty string")
        status, document = self._request(
            "POST",
            f"/v1/workers/{worker_id}/commands",
            body={
                "command": command,
                "cwd": ".",
                "timeout_seconds": timeout_seconds,
            },
            idempotency=str(uuid.uuid4()),
        )
        if status not in {200, 201, 202}:
            raise WorkersApiError(
                f"POST /v1/workers/{worker_id}/commands returned {status}: {document}"
            )
        return document

    def attest(self, worker_id: str, *, nonce: str) -> Any:
        if not isinstance(worker_id, str) or not worker_id:
            raise WorkersApiError("worker_id must be a non-empty string")
        if not isinstance(nonce, str) or not nonce:
            raise WorkersApiError("attest nonce must be a non-empty string")
        status, document = self._request(
            "POST",
            f"/v1/workers/{worker_id}/attest",
            body={"nonce": nonce, "include_gpu_record": False},
            idempotency=str(uuid.uuid4()),
        )
        if status != 200:
            raise WorkersApiError(
                f"POST /v1/workers/{worker_id}/attest returned {status}: {document}"
            )
        return document

    def wait_until_ready(
        self,
        worker_id: str,
        *,
        timeout_seconds: int = 600,
        interval_seconds: float = 5.0,
    ) -> WorkerRecord:
        deadline = time.monotonic() + timeout_seconds
        last = self.get_worker(worker_id)
        while time.monotonic() < deadline:
            if last.ready:
                return last
            if last.status.lower() not in PROVISIONING_STATUSES and not last.ready:
                raise WorkersApiError(
                    f"worker {worker_id} ended as {last.status} before ready"
                )
            time.sleep(interval_seconds)
            last = self.get_worker(worker_id)
        raise WorkersApiError(
            f"worker {worker_id} was still {last.status} after {timeout_seconds}s"
        )


def tdx_workers(records: tuple[WorkerRecord, ...]) -> tuple[WorkerRecord, ...]:
    """The listed machines that claim Intel TDX."""
    return tuple(record for record in records if record.is_tdx)
