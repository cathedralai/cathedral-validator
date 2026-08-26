"""The policy fetch is a copy of the thin feed client's peer rules, not a call.

No test here opens a socket. The URL rules, the address rules, the status gate
and the body bound are all reachable without one, which is the point: the
refusals are what matter, and a test that needed a live endpoint would only
exercise the happy path.
"""

from __future__ import annotations

import pytest

from cathedral_thin.independent.constants import (
    MAX_POLICY_BUNDLE_BYTES,
    POLICY_USER_AGENT,
)
from cathedral_thin.independent.errors import PolicyFetchError
from cathedral_thin.independent.fetch_policy import (
    fetch_policy_bytes,
    read_bounded_response,
    validate_policy_url,
    validated_peer_ips,
)

GOOD = "https://policy.example.com/cathedral/sn39/policy-bundle.json"


@pytest.mark.parametrize(
    "url,reason",
    [
        ("http://policy.example.com/bundle.json", "must be https"),
        ("ftp://policy.example.com/bundle.json", "must be https"),
        ("policy.example.com/bundle.json", "must be https"),
        ("https://user:pass@policy.example.com/b.json", "credential-free"),
        ("https://user@policy.example.com/b.json", "credential-free"),
        ("https://policy.example.com/b.json?sig=abc", "no query or fragment"),
        ("https://policy.example.com/b.json#frag", "no query or fragment"),
        ("https://policy.example.com/b .json", "malformed"),
        ("https://policy.example.com\\b.json", "malformed"),
        ("https:///bundle.json", "no host"),
        ("https://policy.example.com:notaport/b.json", "malformed"),
        ("", "non-empty string"),
    ],
)
def test_rejected_policy_urls(url, reason):
    with pytest.raises(PolicyFetchError, match=reason):
        validate_policy_url(url)


def test_the_path_is_used_exactly_as_given():
    """Nothing is appended. The operator names the document, not a base URL."""
    endpoint = validate_policy_url(GOOD)
    assert endpoint.host == "policy.example.com"
    assert endpoint.port == 443
    assert endpoint.path == "/cathedral/sn39/policy-bundle.json"


def test_an_explicit_port_is_kept_and_the_label_hides_the_path():
    endpoint = validate_policy_url("https://policy.example.com:8443/b.json")
    assert (endpoint.port, endpoint.path) == (8443, "/b.json")
    assert endpoint.label == "https://policy.example.com:8443"
    assert "b.json" not in endpoint.label


def test_the_host_header_includes_a_non_default_port():
    default = validate_policy_url(GOOD)
    assert default.host_header == "policy.example.com"
    explicit = validate_policy_url("https://policy.example.com:8443/b.json")
    assert explicit.host_header == "policy.example.com:8443"


def test_ipv6_literals_are_bracketed_in_the_host_header_and_label():
    default = validate_policy_url("https://[2001:db8::1]/b.json")
    assert default.host == "2001:db8::1"
    assert default.host_header == "[2001:db8::1]"
    assert default.label == "https://[2001:db8::1]:443"
    explicit = validate_policy_url("https://[2001:db8::1]:8443/b.json")
    assert explicit.host_header == "[2001:db8::1]:8443"
    assert explicit.label == "https://[2001:db8::1]:8443"


def _info(address: str) -> tuple:
    return (2, 1, 6, "", (address, 443))


def test_every_resolved_address_must_be_globally_routable():
    assert validated_peer_ips([_info("93.184.216.34")]) == ["93.184.216.34"]
    for private in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "192.168.1.1"):
        with pytest.raises(PolicyFetchError, match="non-public address"):
            validated_peer_ips([_info(private)])


def test_a_private_address_anywhere_in_the_answer_refuses_the_whole_answer():
    """No per-address fallback: a hostile resolver cannot hide one behind a public one."""
    with pytest.raises(PolicyFetchError, match="non-public address"):
        validated_peer_ips([_info("93.184.216.34"), _info("127.0.0.1")])


def test_duplicate_addresses_are_collapsed_in_order():
    infos = [_info("93.184.216.34"), _info("8.8.8.8"), _info("93.184.216.34")]
    assert validated_peer_ips(infos) == ["93.184.216.34", "8.8.8.8"]


def test_an_empty_dns_answer_refuses():
    with pytest.raises(PolicyFetchError, match="does not resolve"):
        validated_peer_ips([])


def test_the_fetch_refuses_a_non_global_peer_through_the_injected_resolver():
    """The resolver is injectable so this rule is testable without a network."""

    def resolver(host, port, timeout):
        assert (host, port) == ("policy.example.com", 443)
        return [_info("127.0.0.1")]

    with pytest.raises(PolicyFetchError, match="non-public address"):
        fetch_policy_bytes(GOOD, resolver=resolver)


def test_the_fetch_refuses_a_non_positive_timeout():
    with pytest.raises(PolicyFetchError, match="timeout must be positive"):
        fetch_policy_bytes(GOOD, timeout=0)
    with pytest.raises(PolicyFetchError, match="timeout must be positive"):
        fetch_policy_bytes(GOOD, timeout=True)


def test_the_fetch_validates_the_url_before_resolving_anything():
    def resolver(host, port, timeout):  # pragma: no cover - must not be reached
        raise AssertionError("a malformed URL reached the resolver")

    with pytest.raises(PolicyFetchError, match="must be https"):
        fetch_policy_bytes("http://policy.example.com/b.json", resolver=resolver)


class _Response:
    """The narrow surface ``read_bounded_response`` uses."""

    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body
        self._offset = 0

    def read(self, amount: int) -> bytes:
        chunk = self._body[self._offset : self._offset + amount]
        self._offset += len(chunk)
        return chunk


def test_a_non_200_response_fails_and_redirects_are_never_followed():
    for status in (204, 301, 302, 307, 404, 500, 503):
        with pytest.raises(PolicyFetchError, match="redirects are never followed"):
            read_bounded_response(_Response(status, b"{}"), {"bytes": 1024})


def test_a_200_response_is_returned_whole():
    body = b'{"schema":"cathedral_policy_bundle_v1"}'
    assert read_bounded_response(_Response(200, body), {"bytes": 1024}) == body


def test_an_oversize_body_is_refused_at_the_bound():
    budget = {"bytes": 16}
    with pytest.raises(PolicyFetchError, match=str(MAX_POLICY_BUNDLE_BYTES)):
        read_bounded_response(_Response(200, b"x" * 17), budget)


def test_the_body_budget_is_aggregate_across_peer_attempts():
    """A peer that streams most of the cap then dies cannot reset it by failing over."""
    budget = {"bytes": 32}
    assert read_bounded_response(_Response(200, b"y" * 30), budget) == b"y" * 30
    assert budget["bytes"] == 2
    with pytest.raises(PolicyFetchError, match="byte bound"):
        read_bounded_response(_Response(200, b"y" * 30), budget)


def test_the_timeout_is_refreshed_before_every_chunk():
    """A trickle of chunks must not keep a stale per-read allowance forever."""

    class Chunked:
        status = 200

        def __init__(self) -> None:
            self._chunks = [b"abcd", b"efgh", b""]

        def read(self, amount: int) -> bytes:
            del amount
            return self._chunks.pop(0)

    calls: list[int] = []
    body = read_bounded_response(
        Chunked(), {"bytes": 1024}, refresh_timeout=lambda: calls.append(1)
    )
    assert body == b"abcdefgh"
    assert len(calls) == 3


def test_the_user_agent_names_this_lineage():
    assert POLICY_USER_AGENT == "cathedral-independent-validator/1.0"
