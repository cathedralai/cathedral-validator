"""Ordinary-key sandbox observations. These never grant admission or weights."""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from typing import Any
from urllib import error, parse, request
import uuid


class ProbeError(ValueError):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProbeError("redirect_refused")


class Client:
    def __init__(self, url: str, key: str):
        parts = parse.urlsplit(url)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
            or not key
            or "\n" in key
            or "\r" in key
        ):
            raise ProbeError("probe_configuration_refused")
        self.url = url.rstrip("/")
        self.key = key
        self.opener = request.build_opener(NoRedirect())

    def call(self, method: str, path: str, body=None, idempotency_key=None):
        headers = {"Authorization": "Bearer " + self.key, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        req = request.Request(
            self.url + path,
            method=method,
            headers=headers,
            data=json.dumps(body).encode() if body is not None else None,
        )
        try:
            with self.opener.open(req, timeout=15) as response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise ProbeError("response_limit")
                value = json.loads(raw) if raw else {}
                if not isinstance(value, dict):
                    raise ProbeError("response_shape")
                return value
        except error.HTTPError as exc:
            # Response bodies and transport exceptions can contain customer data.
            raise ProbeError("http_" + str(exc.code)) from None
        except (error.URLError, TimeoutError, OSError, ValueError):
            raise ProbeError("request_outcome_unknown") from None


def probe(
    client: Any,
    *,
    image: str,
    hold_seconds: int,
    create_timeout: int,
    clock=time.monotonic,
    sleep=time.sleep,
) -> dict[str, Any]:
    probe_id = "probe-" + uuid.uuid4().hex
    result = {
        "schema": "cathedral_sn94_probe_v1",
        "probe_id": probe_id,
        "chain_write": False,
        "admission": "not_checked",
        "status": "NOT_PROVEN",
        "create_latency_ms": None,
        "exec_latency_ms": None,
        "lost_sandbox": None,
        "cleanup": "unknown",
    }
    sandbox_id = None
    started = clock()
    try:
        # One create submission only. A lost response never authorizes replay.
        created = client.call(
            "POST",
            "/v1/sandboxes",
            {
                "image": image,
                "resources": {"vcpu": 1, "memory_gib": 2, "disk_gib": 5},
                "ttl_seconds": create_timeout + hold_seconds + 60,
                "labels": {"owner": "sn94-validator-probe", "probe_id": probe_id},
            },
            idempotency_key=probe_id,
        )
        value = created.get("id")
        if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,128}", value
        ):
            raise ProbeError("create_identity_unknown")
        sandbox_id = value
        result["sandbox_id"] = value
        path = "/v1/sandboxes/" + sandbox_id
        state = created
        while state.get("state") != "running":
            if state.get("state") in {"failed", "deleted"}:
                raise ProbeError("create_failed")
            if clock() - started >= create_timeout:
                raise ProbeError("create_deadline")
            sleep(min(1, create_timeout - (clock() - started)))
            state = client.call("GET", path)
        result["create_latency_ms"] = round((clock() - started) * 1000, 3)
        executed = clock()
        command = client.call(
            "POST", path + "/exec", {"cmd": ["true"], "timeout_seconds": 5}
        )
        result["exec_latency_ms"] = round((clock() - executed) * 1000, 3)
        if command.get("exit_code") != 0 or command.get("timed_out") is not False:
            raise ProbeError("exec_failed")
        observed = clock()
        while clock() - observed < hold_seconds:
            sleep(min(1, hold_seconds - (clock() - observed)))
            state = client.call("GET", path)
            if state.get("state") != "running":
                if state.get("state") in {"failed", "deleted"}:
                    result["lost_sandbox"] = True
                    raise ProbeError("sandbox_lost")
                raise ProbeError("sandbox_state_unknown")
        result.update(
            status="OBSERVED", lost_sandbox=False, observed_seconds=hold_seconds
        )
    except ProbeError as exc:
        result["code"] = str(exc)
    finally:
        if sandbox_id is not None:
            try:
                client.call("DELETE", "/v1/sandboxes/" + sandbox_id)
                result["cleanup"] = "deleted"
            except ProbeError:
                result["cleanup"] = "ttl_backstop"
        else:
            result["cleanup"] = "ttl_backstop_if_created"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--hold-seconds", type=int, default=10)
    parser.add_argument("--create-timeout", type=int, default=60)
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.hold_seconds <= 300 or not 1 <= args.create_timeout <= 300:
            raise ProbeError("probe_configuration_refused")
        client = Client(args.api_url, os.environ.get("CATHEDRAL_API_KEY", ""))
    except ProbeError:
        print(json.dumps({"code": "probe_configuration_refused", "chain_write": False}))
        return 2
    result = probe(
        client,
        image=args.image,
        hold_seconds=args.hold_seconds,
        create_timeout=args.create_timeout,
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "OBSERVED" else 2
