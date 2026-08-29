"""Hardened bounded fetch of the policy document (public HTTPS only).

The peer rules here are a deliberate COPY of the thin feed client's hardening,
not a call into it. That client appends its own feed path to whatever base URL
it is handed, and the policy document is not that resource: the operator config
names the document URL and the path is used exactly as given. Reusing the
function would silently rewrite the path; reimplementing the rules keeps the
independent path independent while keeping the same refusals.

What is enforced, all fail-closed:

* https only, no whitespace or backslash, no userinfo, no ``@`` in the netloc,
  no query, no fragment;
* EVERY resolved address must be globally routable, checked before any dial, so
  a split-horizon answer cannot walk this into a private network;
* the TCP connection is pinned to a validated peer address while TLS still
  verifies the certificate for the ORIGINAL hostname via SNI;
* ONE total deadline spans DNS, connect, TLS, request, and every body read;
* redirects are never followed -- any non-200 fails;
* the body is bounded, and the budget is aggregate across peer attempts so a
  peer that streams most of the cap and dies cannot reset it by failing over.
"""

from __future__ import annotations

import ipaddress
import queue
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from .canonical import parse_strict_json
from .constants import MAX_POLICY_BUNDLE_BYTES, POLICY_USER_AGENT
from .errors import PolicyFetchError

# Bound abandoned resolver threads process-wide. A slow resolver holds its slot
# only until it returns; a full pool fails promptly rather than piling up.
RESOLVER_SLOT_CAP = 8
_RESOLVER_SLOTS: threading.BoundedSemaphore | None = None
_RESOLVER_SLOTS_GUARD = threading.Lock()

DEFAULT_FETCH_TIMEOUT = 30.0
_READ_CHUNK = 65536

# Resolver signature: (host, port, timeout) -> getaddrinfo-shaped tuples.
Resolver = Callable[[str, int, float], Sequence[tuple[Any, ...]]]


_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.ip_network("64:ff9b:1::/48")
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")


def is_globally_routable_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Whether an address is public without an embedded IPv4 routing bypass.

    ``ipaddress.is_global`` alone is insufficient for IPv6 transition forms.
    Some Python releases classify NAT64 or IPv4-compatible literals as global
    even when their embedded IPv4 destination is loopback or private.  The
    validator never needs those transition encodings, so every such form is
    refused rather than trying to recursively reason about the route chosen by
    the host kernel.
    """

    if not isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return False
    if not address.is_global:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return True
    if (
        address.ipv4_mapped is not None
        or address.sixtofour is not None
        or address.teredo is not None
        or address in _NAT64_WELL_KNOWN
        or address in _NAT64_LOCAL_USE
        or address in _IPV4_COMPATIBLE
    ):
        return False
    return True


def _authority_host(host: str) -> str:
    """Host as it appears in a URL authority or Host header.

    ``urlsplit`` stores IPv6 literals without brackets. Putting that value
    back into a URL or a Host header without wrapping it produces an
    ambiguous authority (``https://2001:db8::1:8443/path`` has no parseable
    host/port split).
    """
    return f"[{host}]" if ":" in host else host


@dataclass(frozen=True)
class PolicyEndpoint:
    """A validated policy document endpoint."""

    host: str
    port: int
    path: str

    @property
    def label(self) -> str:
        """A log-safe identity: scheme, host, port. Never the raw URL."""
        return f"https://{_authority_host(self.host)}:{self.port}"

    @property
    def host_header(self) -> str:
        """RFC 9110 Host: omit the port only when it is the https default.

        IPv6 literals are bracketed, so reconstructing a URL from this value
        (the collect client does) remains a valid https authority.
        """
        host = _authority_host(self.host)
        if self.port == 443:
            return host
        return f"{host}:{self.port}"


def validate_policy_url(url: str) -> PolicyEndpoint:
    """Return the validated endpoint for ``url``, or raise.

    The path is taken AS GIVEN. Nothing is appended: the operator names the
    document, and a composer that rewrote the path would be fetching a
    different resource than the one the config was reviewed against.
    """
    if not isinstance(url, str) or not url:
        raise PolicyFetchError("policy URL must be a non-empty string")
    if any(character.isspace() or character == "\\" for character in url):
        raise PolicyFetchError("policy URL is malformed")
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise PolicyFetchError("policy URL must be https")
    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
    ):
        raise PolicyFetchError("policy URL must be credential-free")
    if parsed.query or parsed.fragment:
        raise PolicyFetchError("policy URL must carry no query or fragment")
    host = parsed.hostname
    if not host:
        raise PolicyFetchError("policy URL has no host")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise PolicyFetchError("policy URL port is malformed") from exc
    path = parsed.path or "/"
    if not path.startswith("/"):
        raise PolicyFetchError("policy URL path must be absolute")
    return PolicyEndpoint(host=host, port=port, path=path)


def _resolver_slots() -> threading.BoundedSemaphore:
    global _RESOLVER_SLOTS
    with _RESOLVER_SLOTS_GUARD:
        if _RESOLVER_SLOTS is None:
            _RESOLVER_SLOTS = threading.BoundedSemaphore(RESOLVER_SLOT_CAP)
    return _RESOLVER_SLOTS


def getaddrinfo_bounded(host: str, port: int, timeout: float) -> list[tuple[Any, ...]]:
    """Resolve on a daemon thread from a bounded slot pool, within ``timeout``.

    ``socket.getaddrinfo`` has no timeout of its own, so an unreachable
    resolver would otherwise blow through the one total deadline this fetch
    promises.
    """
    slots = _resolver_slots()
    if not slots.acquire(timeout=max(0.0, min(timeout, 5.0))):
        raise PolicyFetchError(
            f"DNS resolver capacity exhausted while resolving {host}: "
            f"{RESOLVER_SLOT_CAP} lookups are already in flight"
        )
    channel: queue.Queue = queue.Queue(maxsize=1)

    def _resolve() -> None:
        try:
            try:
                channel.put(
                    ("ok", socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP))
                )
            except OSError as exc:
                channel.put(("err", exc))
        finally:
            slots.release()

    try:
        threading.Thread(
            target=_resolve, name="cathedral-independent-dns", daemon=True
        ).start()
    except BaseException:
        slots.release()
        raise
    try:
        kind, value = channel.get(timeout=max(0.0, timeout))
    except queue.Empty:
        raise PolicyFetchError(
            f"DNS resolution for {host} exceeded the fetch deadline"
        ) from None
    if kind == "err":
        raise PolicyFetchError(f"policy host does not resolve: {host}") from value
    return list(value)


def validated_peer_ips(infos: Sequence[tuple[Any, ...]]) -> list[str]:
    """Return the ordered, de-duplicated public addresses, or raise.

    EVERY answer is validated up front and only this list may be dialed. A
    per-address check with a fallback would let a hostile resolver put a private
    address second and still be tried.
    """
    if not infos:
        raise PolicyFetchError("policy host does not resolve")
    peer_ips: list[str] = []
    for info in infos:
        try:
            raw = info[4][0]
        except (IndexError, TypeError) as exc:
            raise PolicyFetchError("policy DNS answer is malformed") from exc
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise PolicyFetchError(
                f"policy DNS answer {raw!r} is not an address"
            ) from exc
        if not is_globally_routable_address(address):
            raise PolicyFetchError(
                "policy host resolves to a non-public address; the policy "
                "document is served over public HTTPS"
            )
        if raw not in peer_ips:
            peer_ips.append(raw)
    return peer_ips


def read_bounded_response(
    response: Any,
    budget: dict[str, int],
    *,
    refresh_timeout: Callable[[], None] | None = None,
) -> bytes:
    """Read one response body under a shared byte budget, refusing non-200.

    ``budget`` is shared across every peer attempt on purpose; see the module
    docstring. Redirects are never followed, so any status other than 200 is a
    refusal rather than a hop.

    ``refresh_timeout`` runs before every ``read`` so a trickle of chunks cannot
    keep each idle wait under a stale allowance while the total deadline
    expires. The thin feed client resets its socket timeout the same way.
    """
    status = int(getattr(response, "status", 0))
    if status != 200:
        raise PolicyFetchError(
            f"policy fetch failed with status {status} (redirects are never followed)"
        )
    chunks: list[bytes] = []
    while True:
        if refresh_timeout is not None:
            refresh_timeout()
        chunk = response.read(min(_READ_CHUNK, budget["bytes"] + 1))
        if not chunk:
            break
        budget["bytes"] -= len(chunk)
        if budget["bytes"] < 0:
            raise PolicyFetchError(
                f"policy document exceeds the {MAX_POLICY_BUNDLE_BYTES} byte bound"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def fetch_policy_bytes(
    url: str,
    *,
    timeout: float = DEFAULT_FETCH_TIMEOUT,
    resolver: Resolver | None = None,
) -> bytes:
    """Fetch the policy document bytes under every rule in the module docstring.

    Returns raw bytes. Parsing is a separate step so the exact bytes that were
    hashed and checked against the on-chain commitment are the bytes that came
    off the wire.
    """
    # Imported here on purpose: `ssl` subclasses `socket.socket` at import time,
    # and importing this package must not load it. The import-graph test stubs
    # `socket.socket` before any module in this package is imported.
    import http.client
    import ssl

    endpoint = validate_policy_url(url)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
    ):
        raise PolicyFetchError("policy fetch timeout must be positive")
    deadline = time.monotonic() + float(timeout)

    def phase_timeout() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PolicyFetchError("policy fetch exceeded its total deadline")
        return remaining

    resolve = resolver or getaddrinfo_bounded
    peer_ips = validated_peer_ips(
        resolve(endpoint.host, endpoint.port, phase_timeout())
    )
    budget = {"bytes": MAX_POLICY_BUNDLE_BYTES}
    host = endpoint.host
    port = endpoint.port

    class _PinnedConnection(http.client.HTTPSConnection):
        peer_ip = ""

        def connect(self) -> None:
            raw = socket.create_connection((self.peer_ip, port), phase_timeout())
            # TLS must not inherit the connect phase's stale allowance, and SNI
            # plus certificate verification use the ORIGINAL hostname.
            raw.settimeout(phase_timeout())
            self.sock = self._context.wrap_socket(raw, server_hostname=host)

    def fetch_via(peer_ip: str) -> bytes:
        connection = _PinnedConnection(
            host, port, timeout=phase_timeout(), context=ssl.create_default_context()
        )
        connection.peer_ip = peer_ip
        try:
            connection.connect()
            connection.sock.settimeout(phase_timeout())
            connection.request(
                "GET",
                endpoint.path,
                headers={"Host": endpoint.host_header, "User-Agent": POLICY_USER_AGENT},
            )
            connection.sock.settimeout(phase_timeout())
            response = connection.getresponse()

            def refresh_timeout() -> None:
                connection.sock.settimeout(phase_timeout())

            return read_bounded_response(
                response, budget, refresh_timeout=refresh_timeout
            )
        finally:
            connection.close()

    data: bytes | None = None
    transport_failures: list[str] = []
    for candidate_ip in peer_ips:
        phase_timeout()
        try:
            data = fetch_via(candidate_ip)
            break
        except OSError as exc:
            transport_failures.append(f"{candidate_ip}: {type(exc).__name__}")
    if data is None:
        raise PolicyFetchError(
            "policy host unreachable on every validated address: "
            + "; ".join(transport_failures)
        )
    return data


def load_policy_document(raw: bytes) -> Any:
    """Parse fetched bytes with the same strict rules a local file load uses."""
    return parse_strict_json(raw, max_bytes=MAX_POLICY_BUNDLE_BYTES)


__all__ = [
    "DEFAULT_FETCH_TIMEOUT",
    "RESOLVER_SLOT_CAP",
    "PolicyEndpoint",
    "Resolver",
    "fetch_policy_bytes",
    "getaddrinfo_bounded",
    "load_policy_document",
    "read_bounded_response",
    "validate_policy_url",
    "validated_peer_ips",
]
