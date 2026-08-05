"""A wrong host clock must not read as "Cathedral's feed is broken".

`wire_vector.invariant_check` enforces a 120s future-skew bound and a bounded
vector lifetime against the HOST clock. A host whose clock is shifted therefore
fails every tick, forever, writing nothing — correctly. What it did not do was
say why: `generated_at is 286s in the future` and `vector expired at '...'`
both name the vector, so an operator reads them as a broken publisher and goes
looking in the wrong place while their validator stays silently muted.

`fetch_vector` already holds the HTTP response, and that response carries a
`Date:` header — the publisher's own clock, free, for the asking. These tests
pin that it is used to EXPLAIN a refusal and for nothing else:

  (a) both directions are named, with a magnitude and an NTP pointer;
  (b) every degraded case — no header, junk header, no fetch, a reading too old
      to trust — falls back to exactly today's message;
  (c) the header is never a time source: it can neither rescue a vector the
      host clock refused nor refuse one the host clock accepted;
  (d) the diagnosis survives the 200-char cap on the surface operators read.

Throughout, a shifted host clock is simulated by moving the publisher and the
vector relative to the (real, unshifted) process clock, which is exactly what
the checks see: a host 300s slow observes a `Date:` header 300s ahead of it.
"""

from __future__ import annotations

import base64
import http.client
import socket
import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scaffold import provenance_audit, validator_thin
from scaffold import wire_vector as wire
from scaffold.events import stable_error

NETWORK = "finney"
NETUID = 39
KEY_ID = "cathedral-weight-policy"
PUBLISHER_URL = "https://api.example.test"

# The host clock's reading. Everything else is expressed relative to it.
HOST_NOW = datetime(2026, 8, 5, 18, 38, 45, tzinfo=UTC)


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _http_date(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")


def _clock(
    *, host_offset_secs: float, header: str | None = None
) -> wire.PublisherClock:
    """One `Date:` observation for a host clock `host_offset_secs` off true.

    Negative is a slow host: it reads `HOST_NOW` while the publisher — whose
    clock is right — stamps a header that far ahead of it.
    """
    if header is None:
        header = _http_date(HOST_NOW - timedelta(seconds=host_offset_secs))
    return wire.PublisherClock(date_header=header, observed_at=HOST_NOW)


def _vector(*, generated_at: datetime, lifetime_secs: float = 1800.0) -> dict:
    """A structurally valid vector; only its freshness is ever in question."""
    return {
        "vector_id": "clock-skew-test",
        "policy_version": 42,
        "network": NETWORK,
        "netuid": NETUID,
        "generated_at": _iso(generated_at),
        "expires_at": _iso(generated_at + timedelta(seconds=lifetime_secs)),
        "burn_snapshot": {
            "burn_uid": 0,
            "burn_hotkey": "burn-hotkey",
            "forced_burn_percentage": 10.0,
        },
        "key_id": KEY_ID,
        "weights": [{"miner_hotkey": "miner-a", "weight": 1.0}],
    }


def _check(payload: dict, *, clock: wire.PublisherClock | None = None) -> None:
    wire.invariant_check(
        payload,
        network=NETWORK,
        netuid=NETUID,
        now_iso=_iso(HOST_NOW),
        publisher_clock=clock,
    )


# -- (a) both directions are named -------------------------------------------


def test_a_slow_host_clock_is_named_as_behind_with_a_magnitude() -> None:
    # Host is 300s slow, so a vector generated 14s ago looks 286s in the future.
    payload = _vector(generated_at=HOST_NOW + timedelta(seconds=286))
    with pytest.raises(wire.VectorError) as raised:
        _check(payload, clock=_clock(host_offset_secs=-300))
    message = str(raised.value)
    # The refusal itself is untouched, diagnosis appended.
    assert message.startswith(
        "generated_at is 286s in the future; maximum skew is 120s"
    )
    assert "your host clock is 300s BEHIND the publisher's" in message
    assert "NTP" in message
    assert "AHEAD" not in message


def test_a_fast_host_clock_is_named_as_ahead_with_a_magnitude() -> None:
    # Host is 2400s fast, so a vector issued 600s ago looks long expired.
    payload = _vector(generated_at=HOST_NOW - timedelta(seconds=2400))
    with pytest.raises(wire.VectorError) as raised:
        _check(payload, clock=_clock(host_offset_secs=2400))
    message = str(raised.value)
    assert message.startswith("vector expired at ")
    assert "your host clock is 2400s AHEAD OF the publisher's" in message
    assert "NTP" in message
    assert "BEHIND" not in message


def test_the_direction_words_are_distinct_because_the_fix_is_distinct() -> None:
    # "Behind" and "ahead" are different operator actions; a diagnosis that
    # collapsed them would be worse than none.
    behind = wire.clock_skew_hint(_clock(host_offset_secs=-600))
    ahead = wire.clock_skew_hint(_clock(host_offset_secs=600))
    assert "BEHIND" in behind and "AHEAD" not in behind
    assert "AHEAD" in ahead and "BEHIND" not in ahead
    assert "600s" in behind and "600s" in ahead


def test_a_clock_that_agrees_says_so_instead_of_inventing_a_number() -> None:
    # Below the noise floor there is no number worth printing: the header has
    # one-second granularity and absorbs the round trip. Say the clock is fine
    # so the operator stops suspecting it, and never print "0s BEHIND".
    payload = _vector(generated_at=HOST_NOW - timedelta(seconds=2400))
    with pytest.raises(wire.VectorError) as raised:
        _check(payload, clock=_clock(host_offset_secs=1))
    message = str(raised.value)
    assert "not host clock skew" in message
    assert "BEHIND" not in message
    assert "AHEAD" not in message
    assert "NTP" not in message


def test_the_noise_floor_is_where_a_number_starts_being_printed() -> None:
    assert wire.MIN_REPORTABLE_CLOCK_SKEW_SECONDS == 5.0
    below = wire.clock_skew_hint(_clock(host_offset_secs=-4))
    at = wire.clock_skew_hint(_clock(host_offset_secs=-5))
    assert "BEHIND" not in below
    assert "5s BEHIND" in at


# -- (b) every degraded case falls back to today's message -------------------


def _todays_future_message() -> str:
    payload = _vector(generated_at=HOST_NOW + timedelta(seconds=286))
    with pytest.raises(wire.VectorError) as raised:
        _check(payload, clock=None)
    return str(raised.value)


def test_no_fetch_at_all_leaves_the_message_exactly_as_it_is_today() -> None:
    # Offline runs, a cached vector, a stubbed fetch: no observation exists.
    assert (
        _todays_future_message()
        == "generated_at is 286s in the future; maximum skew is 120s"
    )


@pytest.mark.parametrize(
    "header",
    [
        "",
        "not-a-date",
        "Wed, 99 Zzz 2026 99:99:99 GMT",
        "0",
        "Wed, 05 Aug 2026 18:38:45 GMT" + "x" * 200,  # bounded, never parsed
        # Well-formed and short, but converting it to UTC leaves the range
        # datetime can represent. An explanation that raised here would turn a
        # clean refusal into a crash — a different exception and a different
        # exit path — which is the one thing diagnosis may never do.
        "Fri, 31 Dec 9999 23:59:59 -1400",
    ],
)
def test_an_unparseable_or_oversized_header_falls_back_cleanly(header: str) -> None:
    payload = _vector(generated_at=HOST_NOW + timedelta(seconds=286))
    with pytest.raises(wire.VectorError) as raised:
        _check(payload, clock=_clock(host_offset_secs=-300, header=header))
    assert str(raised.value) == _todays_future_message()


def test_a_missing_header_never_turns_a_refusal_into_an_acceptance() -> None:
    # The point of the fallback: losing the diagnosis must cost the operator a
    # sentence, never cost the chain a check.
    payload = _vector(generated_at=HOST_NOW + timedelta(seconds=286))
    for clock in (None, _clock(host_offset_secs=-300, header="not-a-date")):
        with pytest.raises(wire.VectorError):
            _check(payload, clock=clock)


def test_the_hint_helper_never_raises_on_anything_it_is_handed() -> None:
    naive = wire.PublisherClock(
        date_header=_http_date(HOST_NOW), observed_at=datetime(2026, 8, 5, 18, 38, 45)
    )
    assert wire.clock_skew_hint(naive) == ""
    assert wire.clock_skew_hint(None) == ""
    assert (
        wire.clock_skew_hint(
            wire.PublisherClock(date_header=None, observed_at=HOST_NOW)  # type: ignore[arg-type]
        )
        == ""
    )


# -- (c) the header is never a time source -----------------------------------


def test_a_date_header_cannot_rescue_a_vector_the_host_clock_refused() -> None:
    # The publisher says the vector is comfortably fresh. The host clock says
    # it expired. The host clock wins, every time — otherwise whoever answers
    # the HTTP request owns the freshness gate.
    payload = _vector(generated_at=HOST_NOW - timedelta(seconds=2400))
    excusing = wire.PublisherClock(
        date_header=_http_date(HOST_NOW - timedelta(seconds=2400)),
        observed_at=HOST_NOW,
    )
    with pytest.raises(wire.VectorError, match="vector expired at"):
        _check(payload, clock=excusing)


def test_a_date_header_cannot_refuse_a_vector_the_host_clock_accepted() -> None:
    # A publisher whose own clock is wrong by a day changes nothing: a vector
    # fresh by the host clock stays accepted, with or without an observation.
    payload = _vector(generated_at=HOST_NOW - timedelta(seconds=10))
    _check(payload, clock=None)
    _check(payload, clock=_clock(host_offset_secs=-86400))
    _check(payload, clock=_clock(host_offset_secs=86400))
    _check(payload, clock=_clock(host_offset_secs=-300, header="not-a-date"))


def test_the_bounds_themselves_are_untouched() -> None:
    assert wire.MAX_VECTOR_FUTURE_SKEW_SECONDS == 120.0
    assert wire.MAX_VECTOR_LIFETIME_SECONDS == 3600.0
    # Exactly at the bound still passes; one second past it still refuses —
    # with an observation present, so the diagnosis cannot have moved the line.
    clock = _clock(host_offset_secs=-300)
    _check(_vector(generated_at=HOST_NOW + timedelta(seconds=120)), clock=clock)
    with pytest.raises(wire.VectorError, match="in the future"):
        _check(_vector(generated_at=HOST_NOW + timedelta(seconds=121)), clock=clock)


def test_non_freshness_refusals_gain_no_clock_diagnosis() -> None:
    # A netuid mismatch is not a clock problem and must not be dressed as one.
    payload = _vector(generated_at=HOST_NOW - timedelta(seconds=10))
    payload["netuid"] = 1
    with pytest.raises(wire.VectorError) as raised:
        _check(payload, clock=_clock(host_offset_secs=-300))
    assert "host clock" not in str(raised.value)


# -- (d) the diagnosis reaches the operator ----------------------------------


@pytest.mark.parametrize("offset", [-300, 2400])
def test_the_diagnosis_survives_the_stable_error_truncation(offset: int) -> None:
    # `stable_error` caps the operator-facing line at 200 characters, and the
    # diagnosis is appended LAST — so a message that overran the cap would
    # deliver the blame and drop the explanation.
    if offset < 0:
        payload = _vector(generated_at=HOST_NOW + timedelta(seconds=286))
    else:
        payload = _vector(generated_at=HOST_NOW - timedelta(seconds=2400))
    with pytest.raises(wire.VectorError) as raised:
        _check(payload, clock=_clock(host_offset_secs=offset))
    rendered = stable_error(raised.value)
    assert rendered.startswith("VectorError: ")
    assert "check NTP/chrony" in rendered
    assert len(rendered) <= 200


def test_the_header_is_re_rendered_not_echoed() -> None:
    # The header is unvalidated network input. Only the PARSED instant is ever
    # interpolated, so no attacker-chosen bytes reach an operator's terminal.
    hostile = "Wed, 05 Aug 2026 18:43:45 GMT (\x1b[31m spoofed \x1b[0m)"
    hint = wire.clock_skew_hint(
        wire.PublisherClock(date_header=hostile, observed_at=HOST_NOW)
    )
    assert "spoofed" not in hint
    assert "\x1b" not in hint


# -- the reading comes off a real response, and ages out ---------------------


class _FakeSocket:
    def settimeout(self, _timeout) -> None:
        return None


class _FakeContext:
    def wrap_socket(self, _raw, server_hostname=None):
        return _FakeSocket()


class _FakeResponse:
    def __init__(self, headers: dict[str, str], body: bytes, status: int = 200) -> None:
        self.status = status
        self._headers = headers
        self._body = body
        self._drained = False

    def getheader(self, name: str, default=None):
        for key, value in self._headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def read(self, _amount=None) -> bytes:
        if self._drained:
            return b""
        self._drained = True
        return self._body


def _serve(monkeypatch, response: _FakeResponse) -> None:
    """Run `fetch_vector`'s real body against a canned HTTP response."""

    class _FakeHTTPSConnection:
        def __init__(self, host, port=None, timeout=None, context=None, **_kwargs):
            self.host = host
            self.port = port
            self._context = context
            self.sock = None

        def request(self, *_args, **_kwargs) -> None:
            return None

        def getresponse(self) -> _FakeResponse:
            return response

        def close(self) -> None:
            return None

    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeHTTPSConnection)
    monkeypatch.setattr(ssl, "create_default_context", _FakeContext)
    monkeypatch.setattr(
        socket, "create_connection", lambda *_a, **_k: _FakeSocket(), raising=True
    )
    # A genuinely global address: the fetch refuses anything reserved before it
    # ever dials, and that guard is not what these tests are relaxing.
    monkeypatch.setattr(
        provenance_audit,
        "_getaddrinfo_bounded",
        lambda *_a, **_k: [(2, 1, 6, "", ("1.1.1.1", 443))],
    )


@pytest.fixture(autouse=True)
def _forget_observations(monkeypatch):
    """No test inherits another's reading."""
    monkeypatch.setattr(validator_thin, "_PUBLISHER_CLOCK", None, raising=False)


def test_the_date_header_is_captured_off_the_real_fetch_path(monkeypatch) -> None:
    header = _http_date(HOST_NOW + timedelta(seconds=300))
    _serve(monkeypatch, _FakeResponse({"Date": header}, b'{"vector_id":"v"}'))
    assert validator_thin.fetch_vector(PUBLISHER_URL) == {"vector_id": "v"}
    observed = validator_thin._observed_publisher_clock()
    assert observed is not None
    assert observed.date_header == header
    assert "BEHIND" in wire.clock_skew_hint(
        wire.PublisherClock(date_header=header, observed_at=HOST_NOW)
    )


def test_a_response_without_a_date_header_clears_any_earlier_reading(
    monkeypatch,
) -> None:
    # An older, unrelated reading must never be reused to explain this fetch.
    validator_thin._record_publisher_clock(_http_date(HOST_NOW))
    assert validator_thin._observed_publisher_clock() is not None
    _serve(monkeypatch, _FakeResponse({"Server": "nginx"}, b'{"vector_id":"v"}'))
    validator_thin.fetch_vector(PUBLISHER_URL)
    assert validator_thin._observed_publisher_clock() is None


def test_a_reading_older_than_its_ttl_is_dropped(monkeypatch) -> None:
    # An operator who fixes NTP must stop being told about the old drift, and a
    # cached vector re-verified much later must not borrow a stale reading.
    ticks = iter([0.0, validator_thin.PUBLISHER_CLOCK_OBSERVATION_TTL_SECONDS + 1.0])
    monkeypatch.setattr(validator_thin.time, "monotonic", lambda: next(ticks))
    validator_thin._record_publisher_clock(_http_date(HOST_NOW))
    assert validator_thin._observed_publisher_clock() is None


def _refuse_through_accept_vector(monkeypatch, host_now: datetime) -> str:
    """Drive the tick's real acceptance path and return the refusal text."""
    private_key = Ed25519PrivateKey.generate()
    payload = _vector(generated_at=host_now + timedelta(seconds=286))
    payload["signature"] = base64.b64encode(
        private_key.sign(wire.canonical_bytes(payload))
    ).decode()
    monkeypatch.setattr(validator_thin, "_ms_iso_now", lambda: _iso(host_now))
    with pytest.raises(wire.VectorError) as raised:
        validator_thin.accept_vector(
            payload,
            public_key_hex=private_key.public_key().public_bytes_raw().hex(),
            key_id=KEY_ID,
            network=NETWORK,
            netuid=NETUID,
            fence_version=0,
        )
    return str(raised.value)


def _freeze_host_clock(monkeypatch) -> None:
    """Pin what `_record_publisher_clock` reads off the host clock."""

    class _Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return HOST_NOW if tz is None else HOST_NOW.astimezone(tz)

    monkeypatch.setattr(validator_thin, "datetime", _Frozen)


def test_accept_vector_feeds_the_observation_into_the_refusal(monkeypatch) -> None:
    """The end-to-end seam: a fetched header explains the tick's own refusal.

    The host is taken at its word — it reads `HOST_NOW`, and stamps the
    observation with it — while the publisher's header sits 300s ahead. That is
    exactly what a 300s-slow host sees on the wire.
    """
    _freeze_host_clock(monkeypatch)
    validator_thin._record_publisher_clock(
        _http_date(HOST_NOW + timedelta(seconds=300))
    )
    message = _refuse_through_accept_vector(monkeypatch, HOST_NOW)
    assert "generated_at is 286s in the future" in message
    assert "300s BEHIND the publisher's" in message
    assert "check NTP/chrony" in message


def test_accept_vector_without_an_observation_refuses_identically(monkeypatch) -> None:
    message = _refuse_through_accept_vector(monkeypatch, HOST_NOW)
    assert message == "generated_at is 286s in the future; maximum skew is 120s"
