from collections import deque
import pytest
from cathedral_thin.independent_runtime.delivery_probe import Client, ProbeError, probe


class Clock:
    value = 0.0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class FakeClient:
    def __init__(self, states=None, *, create_error=False, exec_error=False):
        self.calls = []
        self.states = deque(states or [{"state": "running"}])
        self.create_error = create_error
        self.exec_error = exec_error

    def call(self, method, path, body=None, idempotency_key=None):
        self.calls.append((method, path, body, idempotency_key))
        if method == "POST" and path == "/v1/sandboxes":
            if self.create_error:
                raise ProbeError("request_outcome_unknown")
            return {"id": "sb-1", "state": "creating"}
        if method == "GET":
            return self.states.popleft() if len(self.states) > 1 else self.states[0]
        if path.endswith("/exec"):
            if self.exec_error:
                raise ProbeError("request_outcome_unknown")
            return {"exit_code": 0, "timed_out": False}
        return {"state": "deleting"}


def run(client):
    clock = Clock()
    return probe(
        client,
        image="alpine:3.22",
        hold_seconds=2,
        create_timeout=5,
        max_spend_usd="0.01",
        clock=clock.now,
        sleep=clock.sleep,
    )


def test_probe_records_create_exec_lifetime_and_cleanup():
    client = FakeClient()
    result = run(client)
    assert result["status"] == "OBSERVED" and result["lost_sandbox"] is False
    assert result["create_latency_ms"] == 1000
    assert result["cleanup"] == "requested"
    assert client.calls[0][3] == result["probe_id"]
    assert client.calls[0][2]["max_spend_usd"] == "0.01"
    assert client.calls[-1][3] == result["probe_id"] + ":delete"
    assert (
        next(call for call in client.calls if call[1].endswith("/exec"))[3]
        == result["probe_id"] + ":exec"
    )
    assert client.calls[-1][:2] == ("DELETE", "/v1/sandboxes/sb-1")
    assert result["admission"] == "not_checked" and result["chain_write"] is False


def test_create_ambiguity_never_replays():
    client = FakeClient(create_error=True)
    result = run(client)
    assert result["status"] == "NOT_PROVEN" and result["lost_sandbox"] is None
    assert len(client.calls) == 1
    assert result["cleanup"] == "ttl_backstop_if_created"


def test_exec_ambiguity_never_reexecutes_and_deletes():
    client = FakeClient(exec_error=True)
    result = run(client)
    assert result["status"] == "NOT_PROVEN"
    assert len([call for call in client.calls if call[1].endswith("/exec")]) == 1
    assert result["cleanup"] == "requested"


def test_lost_running_sandbox_is_counted_separately():
    client = FakeClient(states=[{"state": "running"}, {"state": "failed"}])
    result = run(client)
    assert result["code"] == "sandbox_lost" and result["lost_sandbox"] is True


def test_create_failure_is_not_counted_as_midlife_loss():
    client = FakeClient(states=[{"state": "failed"}])
    result = run(client)
    assert result["code"] == "create_failed" and result["lost_sandbox"] is None


@pytest.mark.parametrize(
    "url",
    ["http://example.com", "https://key@example.com", "https://example.com?secret=1"],
)
def test_api_origin_requires_https_and_no_embedded_credentials(url):
    with pytest.raises(ProbeError):
        Client(url, "test-only-key")
