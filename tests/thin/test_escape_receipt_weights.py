"""Escape contest receipts as an SN94 weight source (default off)."""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import replace
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_direct_validator as base
from cathedral_thin.independent.constants import W
from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import escape_receipts
from cathedral_thin.independent_runtime.direct_contract import DirectValidatorError
from cathedral_thin.independent_runtime.direct_writer import STATUS_CONFIRMED
from cathedral_thin.independent_runtime.escape_receipts import (
    CONTEST_SIGNER_SET_SCHEMA,
    DEFAULT_REWARD_WINDOW_SECONDS,
    MAX_FEED_BYTES,
    MAX_FEED_RECEIPTS,
    MAX_WEIGHT_FRACTION,
    EscapeReceiptConfig,
    EscapeReceiptError,
    authorizing_body,
    canonical_bytes,
    escape_config_from_environment,
    parse_contest_signers,
    score_escape_receipts,
    verify_escape_receipt,
)

REPO = Path(__file__).resolve().parents[2]
BREAKER = "5Breaker"
BREAKER_UID = 23
NOW = 1_800_000_000.0
TEST_KEY = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)


def receipt(
    *,
    key: Ed25519PrivateKey = TEST_KEY,
    window_id: str = "w-1",
    room_id: str = "room-1",
    hotkey: str | None = BREAKER,
    planted_at: float = NOW - 3600,
    commands: int = 1,
    key_id: str | None = None,
) -> dict[str, object]:
    nonce = hashlib.sha256(window_id.encode()).hexdigest()[:32]
    claim: dict[str, object] = {
        "schema": "escape_practice_claim_v0",
        "target": "host",
        "window_id": window_id,
        "room_id": room_id,
        "commands": [{"attested_room": room_id, "argv": ["id"]}] * commands,
        "proof_token": {"kind": "host_nonce", "window_id": window_id, "nonce": nonce},
    }
    if hotkey is not None:
        claim["breaker_hotkey"] = hotkey
    body = {
        "schema": "escape_stage_c_receipt_v0",
        "window_id": window_id,
        "room_id": room_id,
        "host_nonce": nonce,
        "nonce_origin": "control_plane",
        "planted_at": planted_at,
        "claim": claim,
    }
    signed = dict(body)
    signed["sig"] = base64.b64encode(key.sign(canonical_bytes(body))).decode("ascii")
    signed["signer"] = "control_plane"
    if key_id is not None:
        signed["key_id"] = key_id
    return signed


def _signer_set_for_key(
    key: Ed25519PrivateKey, *, key_id: str = "test"
) -> escape_receipts.ContestSignerSet:
    pubkey = key.public_key()
    b64 = base64.b64encode(pubkey.public_bytes_raw()).decode("ascii")
    return parse_contest_signers(
        {
            "schema": CONTEST_SIGNER_SET_SCHEMA,
            "keys": [{"id": key_id, "not_before": 0, "pubkey_b64": b64}],
        }
    )


@pytest.fixture
def test_signer(monkeypatch) -> None:
    """Stand the test key in for the pinned key (we do not hold its seed)."""

    pubkey = TEST_KEY.public_key()
    monkeypatch.setattr(escape_receipts, "PINNED_CONTEST_PUBKEY", pubkey)
    monkeypatch.setattr(
        escape_receipts, "PINNED_CONTEST_SIGNERS", _signer_set_for_key(TEST_KEY)
    )


def registered_snapshot(**kwargs):
    snap = base.snapshot(**kwargs)
    registered = {**snap.registered_hotkeys, BREAKER: BREAKER_UID}
    return replace(snap, registered_hotkeys=registered)


def machine_plan():
    return base.build_direct_plan(
        registered_snapshot(), base.round_result(base.machine_row("1"))
    )


def config(fraction: str = "1/10", window: int = DEFAULT_REWARD_WINDOW_SECONDS):
    return EscapeReceiptConfig(
        source="/unused", fraction=Fraction(fraction), window_seconds=window
    )


def score(receipts, *, now: float = NOW, window: int = DEFAULT_REWARD_WINDOW_SECONDS):
    return score_escape_receipts(
        receipts,
        registered={BREAKER: BREAKER_UID, base.VALIDATOR: 7},
        validator_uid=7,
        now=now,
        window_seconds=window,
    )


# --- pinned key ------------------------------------------------------------


def test_vendored_key_file_matches_the_pinned_constant_and_sha256() -> None:
    raw = (REPO / "config/escape/contest-signer.ed25519.pub").read_bytes()
    assert (
        hashlib.sha256(raw).hexdigest()
        == escape_receipts.PINNED_CONTEST_PUBKEY_FILE_SHA256
    )
    assert (
        raw.decode("ascii").splitlines()[0] == escape_receipts.PINNED_CONTEST_PUBKEY_B64
    )
    set_raw = (REPO / "config/escape/contest-signers.json").read_bytes()
    assert (
        hashlib.sha256(set_raw).hexdigest()
        == escape_receipts.PINNED_CONTEST_SIGNERS_SHA256
    )
    assert escape_receipts.PINNED_CONTEST_SIGNERS.keys[0].pubkey_b64 == (
        escape_receipts.PINNED_CONTEST_PUBKEY_B64
    )


def test_wrong_key_fails_against_the_pinned_key() -> None:
    forged = receipt(key=Ed25519PrivateKey.from_private_bytes(b"\x09" * 32))
    with pytest.raises(EscapeReceiptError, match="non-pinned key"):
        verify_escape_receipt(forged)
    assert score([forged]).units_by_uid == ()
    assert score([forged]).refused == {"invalid": 1}


def test_tampered_body_fails(test_signer) -> None:
    good = receipt()
    verify_escape_receipt(good)
    tampered = json.loads(json.dumps(good))
    tampered["claim"]["breaker_hotkey"] = "5Thief"
    with pytest.raises(EscapeReceiptError, match="non-pinned key"):
        verify_escape_receipt(tampered)


def test_signature_covers_exactly_the_upstream_authorizing_body(test_signer) -> None:
    good = receipt()
    good["extra_unsigned_field"] = "ignored"
    verified = verify_escape_receipt(good)
    expected = hashlib.sha256(canonical_bytes(authorizing_body(good))).hexdigest()
    assert verified.digest == "sha256:" + expected


def test_receipt_without_breaker_hotkey_is_refused(test_signer) -> None:
    with pytest.raises(EscapeReceiptError, match="breaker hotkey"):
        verify_escape_receipt(receipt(hotkey=None))
    assert score([receipt(hotkey=None)]).refused == {"no_breaker_hotkey": 1}


# --- scoring ---------------------------------------------------------------


def test_replay_is_counted_once(test_signer) -> None:
    one = receipt()
    result = score([one, json.loads(json.dumps(one)), one])
    assert result.units_by_uid == ((BREAKER_UID, 1),)
    assert result.refused == {"replay": 2}


def test_second_claim_for_the_same_room_and_window_is_counted_once(test_signer) -> None:
    result = score([receipt(commands=1), receipt(commands=2)])
    assert result.units_by_uid == ((BREAKER_UID, 1),)
    assert result.refused == {"duplicate_room": 1}


def test_distinct_rooms_each_count(test_signer) -> None:
    result = score(
        [receipt(room_id="a"), receipt(room_id="b"), receipt(window_id="w-2")]
    )
    assert result.units_by_uid == ((BREAKER_UID, 3),)


def test_expired_window_drops(test_signer) -> None:
    window = DEFAULT_REWARD_WINDOW_SECONDS
    fresh = receipt(room_id="fresh", planted_at=NOW - window)
    stale = receipt(room_id="stale", planted_at=NOW - window - 1)
    result = score([fresh, stale], window=window)
    assert result.units_by_uid == ((BREAKER_UID, 1),)
    assert result.refused == {"expired": 1}


def test_future_planted_at_is_refused(test_signer) -> None:
    assert score([receipt(planted_at=NOW + 3600)]).refused == {"future": 1}


def test_unregistered_hotkey_is_ignored_and_logged(test_signer) -> None:
    result = score([receipt(hotkey="5Nobody")])
    assert result.units_by_uid == ()
    assert result.refused == {"unregistered": 1}
    assert result.summary()["unregistered_hotkeys"] == ["5Nobody"]


def test_validator_cannot_pay_itself(test_signer) -> None:
    assert score([receipt(hotkey=base.VALIDATOR)]).refused == {"validator_self": 1}


def test_unregistered_receipt_does_not_consume_the_room(test_signer) -> None:
    result = score(
        [
            receipt(hotkey="5Nobody", planted_at=NOW - 10),
            receipt(hotkey=BREAKER, planted_at=NOW - 9),
        ]
    )
    assert result.units_by_uid == ((BREAKER_UID, 1),)
    assert result.refused == {"unregistered": 1}


def test_unregistered_receipt_does_not_hold_the_room_for_a_later_breaker(
    test_signer,
) -> None:
    """Pin current behavior: an unregistered claim does not reserve the room.

    Reviewer open question on PR #313: a later registered breaker for the
    same (window_id, room_id) is paid. This is unchanged; the test exists so
    a product decision to hold the room would fail here first.
    """

    later = "5LaterBreaker"
    later_uid = 31
    result = score_escape_receipts(
        [
            receipt(hotkey="5Nobody", planted_at=NOW - 10),
            receipt(hotkey=later, planted_at=NOW - 9),
        ],
        registered={BREAKER: BREAKER_UID, later: later_uid, base.VALIDATOR: 7},
        validator_uid=7,
        now=NOW,
        window_seconds=DEFAULT_REWARD_WINDOW_SECONDS,
    )
    assert result.units_by_uid == ((later_uid, 1),)
    assert result.refused == {"unregistered": 1}
    assert "duplicate_room" not in result.refused


def test_validator_self_receipt_does_not_consume_the_room(test_signer) -> None:
    result = score(
        [
            receipt(hotkey=base.VALIDATOR, planted_at=NOW - 10),
            receipt(hotkey=BREAKER, planted_at=NOW - 9),
        ]
    )
    assert result.units_by_uid == ((BREAKER_UID, 1),)
    assert result.refused == {"validator_self": 1}


def test_oversized_planted_at_is_refused_without_aborting(test_signer) -> None:
    bad = receipt()
    bad["planted_at"] = 10**400
    with pytest.raises(EscapeReceiptError, match="planted_at"):
        verify_escape_receipt(bad)
    result = score([bad, receipt(room_id="ok")])
    assert result.units_by_uid == ((BREAKER_UID, 1),)
    assert result.refused == {"invalid": 1}
    planned = machine_plan()
    blended, summary = runtime.apply_escape_receipts(
        planned, config(), now=NOW, load=lambda _source: [bad, receipt()]
    )
    assert summary["status"] == "APPLIED"
    assert summary["refused"] == {"invalid": 1}
    assert blended is not planned


def test_non_finite_planted_at_is_refused(test_signer) -> None:
    for value in (float("nan"), float("inf"), float("-inf"), 0, -1, True):
        bad = receipt()
        bad["planted_at"] = value
        with pytest.raises(EscapeReceiptError, match="planted_at"):
            verify_escape_receipt(bad)


# --- blending into the plan ------------------------------------------------


def test_valid_receipt_weights_the_breaker_uid(test_signer) -> None:
    planned = machine_plan()
    blended, summary = runtime.apply_escape_receipts(
        planned, config("1/10"), now=NOW, load=lambda _source: [receipt()]
    )
    assert summary["status"] == "APPLIED"
    assert summary["accepted"] == 1
    weights = dict(zip(blended.wire_uids, blended.wire_weights, strict=True))
    # Each lane is 6553 of 65535 (10 percent, floored); the rest is burned.
    assert weights == {base.BURN_UID: 52429, 19: 6553, BREAKER_UID: 6553}
    assert sum(weights.values()) == W
    assert blended.identity()["escape"] == {
        "fraction": "1/10",
        "units_by_uid": [[BREAKER_UID, 1]],
        "uid_hotkeys": [[BREAKER_UID, BREAKER]],
    }
    assert blended.evidence_digest != planned.evidence_digest
    assert blended.expected_vector() == (blended.wire_uids, blended.wire_weights)


def test_blend_splits_the_share_by_break_count(test_signer, monkeypatch) -> None:
    planned = machine_plan()
    second = "5SecondBreaker"
    snap = replace(
        planned.snapshot,
        registered_hotkeys={**planned.snapshot.registered_hotkeys, second: 31},
    )
    planned = replace(planned, snapshot=snap)
    receipts = [
        receipt(room_id="a"),
        receipt(room_id="b"),
        receipt(room_id="c", hotkey=second),
    ]
    # The configured fraction only switches the lane on: the share paid is the
    # owner-set 10 percent, split 2:1 by break count.
    blended, summary = runtime.apply_escape_receipts(
        planned, config("1/20"), now=NOW, load=lambda _source: receipts
    )
    assert summary["fraction"] == "1/10"
    weights = dict(zip(blended.wire_uids, blended.wire_weights, strict=True))
    assert weights == {base.BURN_UID: 52429, 19: 6553, BREAKER_UID: 4369, 31: 2184}


def test_no_breaks_or_unreadable_source_leave_the_plan_unchanged(test_signer) -> None:
    planned = machine_plan()
    same, summary = runtime.apply_escape_receipts(
        planned, config(), now=NOW, load=lambda _source: []
    )
    assert same is planned and summary["status"] == "NO_BREAKS"

    def broken(_source: str) -> list[object]:
        raise OSError("feed down")

    same, summary = runtime.apply_escape_receipts(
        planned, config(), now=NOW, load=broken
    )
    assert same is planned and summary["status"] == "SOURCE_UNAVAILABLE"


def test_off_by_default_changes_nothing(monkeypatch) -> None:
    for name in (
        escape_receipts.ESCAPE_RECEIPTS_SOURCE_ENV,
        escape_receipts.ESCAPE_WEIGHT_FRACTION_ENV,
        escape_receipts.ESCAPE_REWARD_WINDOW_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    assert escape_config_from_environment() is None
    # A source without a fraction, or a zero fraction, is still off.
    assert (
        escape_config_from_environment({"CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "/x"})
        is None
    )
    assert (
        escape_config_from_environment(
            {
                "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "/x",
                "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "0",
            }
        )
        is None
    )
    # The plan a validator builds today has no escape block and the same
    # identity as before this change.
    planned = base.plan()
    assert planned.escape_active is False
    assert "escape" not in planned.identity()
    assert planned.expected_vector() == (planned.wire_uids, planned.wire_weights)
    assert planned.snapshot.identity() == registered_snapshot().identity()


def test_malformed_config_refuses() -> None:
    with pytest.raises(EscapeReceiptError):
        escape_config_from_environment(
            {
                "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "/x",
                "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "1",
            }
        )
    with pytest.raises(EscapeReceiptError):
        escape_config_from_environment(
            {
                "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "http://insecure.example/feed",
                "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "0.1",
            }
        )
    with pytest.raises(EscapeReceiptError):
        escape_config_from_environment(
            {
                "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "https://api.example/escape/receipts?x=1",
                "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "0.05",
            }
        )
    with pytest.raises(EscapeReceiptError):
        escape_config_from_environment(
            {
                "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "https://api.example:999999/escape/receipts",
                "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "0.05",
            }
        )
    loaded = escape_config_from_environment(
        {
            "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "https://api.example/escape/receipts",
            "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "0.1",
            "CATHEDRAL_ESCAPE_REWARD_WINDOW_SECONDS": "86400",
        }
    )
    assert loaded == EscapeReceiptConfig(
        source="https://api.example/escape/receipts",
        fraction=Fraction(1, 10),
        window_seconds=86400,
    )


def test_weight_fraction_is_capped_at_one_tenth() -> None:
    with pytest.raises(EscapeReceiptError, match=r"\[0, 1/10\]"):
        escape_config_from_environment(
            {
                "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "https://api.example/escape/receipts",
                "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "0.11",
            }
        )
    with pytest.raises(EscapeReceiptError, match=r"\[0, 1/10\]"):
        escape_config_from_environment(
            {
                "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "https://api.example/escape/receipts",
                "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "1/2",
            }
        )
    loaded = escape_config_from_environment(
        {
            "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "https://api.example/escape/receipts",
            "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "1/10",
        }
    )
    assert loaded is not None
    assert loaded.fraction == MAX_WEIGHT_FRACTION == Fraction(1, 10)
    five_percent = escape_config_from_environment(
        {
            "CATHEDRAL_ESCAPE_RECEIPTS_SOURCE": "https://api.example/escape/receipts",
            "CATHEDRAL_ESCAPE_WEIGHT_FRACTION": "0.05",
        }
    )
    assert five_percent is not None
    assert five_percent.fraction == Fraction(1, 20)


def test_a_five_percent_setting_still_pays_the_owner_set_share(test_signer) -> None:
    # Hosts that followed the earlier rollout have 0.05 in direct.env. It
    # still starts and turns the lane on, and the lane pays 10 percent.
    planned = machine_plan()
    blended, summary = runtime.apply_escape_receipts(
        planned, config("1/20"), now=NOW, load=lambda _source: [receipt()]
    )
    assert summary["status"] == "APPLIED"
    assert blended.escape_fraction == "1/10"
    weights = dict(zip(blended.wire_uids, blended.wire_weights, strict=True))
    assert sum(weights.values()) == W
    assert weights[BREAKER_UID] == 6553


def test_http_404_leaves_the_plan_unchanged(test_signer) -> None:
    planned = machine_plan()

    def missing(_source: str) -> list[object]:
        raise EscapeReceiptError("escape receipt feed HTTP 404")

    same, summary = runtime.apply_escape_receipts(
        planned, config(), now=NOW, load=missing
    )
    assert same is planned
    assert summary["status"] == "SOURCE_UNAVAILABLE"
    assert summary["error"] == "escape receipt feed HTTP 404"


def test_cycle_deadline_skips_the_feed(test_signer) -> None:
    planned = machine_plan()
    called = {"n": 0}

    def load(_source: str) -> list[object]:
        called["n"] += 1
        return [receipt()]

    same, summary = runtime.apply_escape_receipts(
        planned,
        config(),
        now=NOW,
        load=load,
        deadline_monotonic=time.monotonic() - 1,
    )
    assert called["n"] == 0
    assert same is planned
    assert summary["status"] == "SOURCE_UNAVAILABLE"
    assert summary["error"] == "cycle deadline"


def test_scoring_failure_leaves_the_plan_unchanged(test_signer, monkeypatch) -> None:
    planned = machine_plan()

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(runtime, "score_escape_receipts", boom)
    same, summary = runtime.apply_escape_receipts(
        planned, config(), now=NOW, load=lambda _source: [receipt()]
    )
    assert same is planned
    assert summary["status"] == "SCORING_UNAVAILABLE"
    assert summary["error"] == "RuntimeError"


def test_feed_file_accepts_list_or_object(tmp_path: Path, test_signer) -> None:
    path = tmp_path / "feed.json"
    path.write_text(json.dumps({"receipts": [receipt()]}))
    assert len(escape_receipts.load_receipt_feed(str(path))) == 1
    path.write_text(json.dumps([receipt(), receipt(room_id="b")]))
    assert len(escape_receipts.load_receipt_feed(str(path))) == 2


def test_feed_directory_and_oversize_and_count_are_refused(
    tmp_path: Path, test_signer
) -> None:
    with pytest.raises(EscapeReceiptError, match="regular file"):
        escape_receipts.load_receipt_feed(str(tmp_path))
    huge = tmp_path / "huge.json"
    huge.write_bytes(b"x" * (MAX_FEED_BYTES + 2))
    with pytest.raises(EscapeReceiptError, match="too large"):
        escape_receipts.load_receipt_feed(str(huge))
    many = tmp_path / "many.json"
    many.write_text(json.dumps([{"n": i} for i in range(MAX_FEED_RECEIPTS + 1)]))
    with pytest.raises(EscapeReceiptError, match="too many receipts"):
        escape_receipts.load_receipt_feed(str(many))
    garbage = tmp_path / "garbage.json"
    garbage.write_text("not-json")
    with pytest.raises(EscapeReceiptError, match="not JSON"):
        escape_receipts.load_receipt_feed(str(garbage))


class _FeedResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        url: str = "https://api.example/escape/receipts",
    ) -> None:
        self._body = body
        self._offset = 0
        self._status = status
        self._url = url

    def getcode(self) -> int:
        return self._status

    def geturl(self) -> str:
        return self._url

    def read(self, size: int) -> bytes:
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def read1(self, size: int) -> bytes:
        return self.read(size)

    def __enter__(self) -> _FeedResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_https_fetch_maps_http_errors_and_rejects_non_https_final_url() -> None:
    def not_found(_request: object, *, timeout: float) -> None:
        raise urllib.error.HTTPError(
            "https://api.example/escape/receipts", 404, "Not Found", {}, None
        )

    with pytest.raises(EscapeReceiptError, match="HTTP 404"):
        escape_receipts._fetch_https(
            "https://api.example/escape/receipts", opener=not_found
        )

    def redirect(_request: object, *, timeout: float) -> None:
        raise urllib.error.HTTPError(
            "https://api.example/escape/receipts", 302, "Found", {}, None
        )

    with pytest.raises(EscapeReceiptError, match="HTTP 302"):
        escape_receipts._fetch_https(
            "https://api.example/escape/receipts", opener=redirect
        )

    def unexpected(_request: object, *, timeout: float) -> _FeedResponse:
        return _FeedResponse(b"[]", status=204)

    with pytest.raises(EscapeReceiptError, match="HTTP 204"):
        escape_receipts._fetch_https(
            "https://api.example/escape/receipts", opener=unexpected
        )

    def downgrade(_request: object, *, timeout: float) -> _FeedResponse:
        return _FeedResponse(b"[]", url="http://api.example/escape/receipts")

    with pytest.raises(EscapeReceiptError, match="off HTTPS"):
        escape_receipts._fetch_https(
            "https://api.example/escape/receipts", opener=downgrade
        )


def test_slow_drip_feed_aborts_within_the_total_timeout_and_keeps_machine_weights(
    test_signer,
) -> None:
    """A feed dripping 1 byte / 0.5s must abort inside the 1s total budget.

    urllib's timeout is per recv. On the previous branch this ran until the
    whole body arrived (~6s for a 12-byte payload). Abort is feed-down:
    SOURCE_UNAVAILABLE, machine plan unchanged.
    """

    payload = b"[" + b"0," * 20 + b"0]"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                for index in range(len(payload)):
                    self.wfile.write(payload[index : index + 1])
                    self.wfile.flush()
                    time.sleep(0.5)
            except OSError:
                return

        def log_message(self, _format: str, *args: object) -> None:
            del args

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 0.5
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/feed"
        planned = machine_plan()
        started = time.monotonic()

        def load(_source: str) -> list[object]:
            return escape_receipts.load_receipt_feed(
                "https://api.example/escape/receipts",
                fetch=lambda _ignored: escape_receipts._fetch_https(url, timeout=1.0),
                timeout=1.0,
            )

        same, summary = runtime.apply_escape_receipts(
            planned, config(), now=NOW, load=load
        )
        elapsed = time.monotonic() - started
        assert elapsed < 2.0
        assert same is planned
        assert summary["status"] == "SOURCE_UNAVAILABLE"
        assert summary["error"] == "escape receipt feed is unavailable"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_https_fetch_installs_no_redirect_handler(monkeypatch) -> None:
    seen: dict[str, object] = {}

    class DummyOpener:
        def open(self, request: object, timeout: float | None = None) -> None:
            raise urllib.error.HTTPError(
                getattr(request, "full_url", ""), 302, "Found", {}, None
            )

    def build_opener(*handlers: object) -> DummyOpener:
        seen["handlers"] = handlers
        return DummyOpener()

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)
    with pytest.raises(EscapeReceiptError, match="HTTP 302"):
        escape_receipts._fetch_https("https://api.example/escape/receipts")
    handlers = seen["handlers"]
    assert isinstance(handlers, tuple)
    assert any(isinstance(handler, escape_receipts._NoRedirect) for handler in handlers)


# --- writer ----------------------------------------------------------------


class BreakerSubtensor(base.WriterSubtensor):
    """Chain double where the breaker is registered but serves no axon."""

    breaker_hotkey = BREAKER

    def metagraph(self, netuid: int, *, block: int):
        graph = super().metagraph(netuid, block=block)
        graph.uids.append(BREAKER_UID)
        graph.hotkeys.append(self.breaker_hotkey)
        graph.validator_permit.append(False)
        graph.axons.append(base.Axon("0.0.0.0", 0, serving=False))
        graph.last_update.append(0)
        graph.total_stake.append(SimpleNamespace(rao=0))
        return graph


def breaker_writer(tmp_path: Path, monkeypatch, planned):
    instance, _subtensor, _ = base.writer(tmp_path, monkeypatch, planned=planned)
    subtensor = BreakerSubtensor(miners=planned.snapshot.miners)
    subtensor.substrate.expected_uids = list(planned.wire_uids)
    subtensor.substrate.expected_weights = list(planned.wire_weights)
    instance.subtensor = subtensor
    return instance, subtensor


def test_writer_signs_and_confirms_a_blended_vector(
    tmp_path, monkeypatch, test_signer
) -> None:
    blended, _summary = runtime.apply_escape_receipts(
        machine_plan(), config("1/10"), now=NOW, load=lambda _source: [receipt()]
    )
    instance, subtensor = breaker_writer(tmp_path, monkeypatch, blended)
    result = base.submit_before_deadline(instance, blended)
    assert result.status == STATUS_CONFIRMED
    state = json.loads(instance.state_path.read_text(encoding="ascii"))
    assert state["last_attempt"]["intent"]["kwargs"]["dests"] == sorted(
        [base.BURN_UID, 19, BREAKER_UID]
    )
    assert state["last_attempt"]["identity"]["escape"]["units_by_uid"] == [
        [BREAKER_UID, 1]
    ]
    assert subtensor.substrate.submit_calls == 1


def test_writer_refuses_a_recycled_breaker_uid(
    tmp_path, monkeypatch, test_signer
) -> None:
    blended, _summary = runtime.apply_escape_receipts(
        machine_plan(), config("1/10"), now=NOW, load=lambda _source: [receipt()]
    )
    instance, subtensor = breaker_writer(tmp_path, monkeypatch, blended)
    subtensor.breaker_hotkey = "5NewHolder"
    with pytest.raises(DirectValidatorError, match="escape receipt UID changed"):
        base.submit_before_deadline(instance, blended)
    assert subtensor.substrate.submit_calls == 0


def test_writer_refuses_a_vector_that_does_not_match_its_escape_inputs(
    tmp_path, monkeypatch, test_signer
) -> None:
    blended, _summary = runtime.apply_escape_receipts(
        machine_plan(), config("1/10"), now=NOW, load=lambda _source: [receipt()]
    )
    inflated = replace(blended, escape_fraction="1/2")
    instance, subtensor = breaker_writer(tmp_path, monkeypatch, inflated)
    with pytest.raises(DirectValidatorError):
        base.submit_before_deadline(instance, inflated)
    assert subtensor.substrate.submit_calls == 0


# AB#691: an HTTPS feed is read page by page, so one large receipt cannot push
# the whole feed over the per-document cap.

FEED_URL = "https://api.example/v1/escape/receipts/published"


def _query(url: str) -> dict[str, str]:
    parts = urllib.parse.urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == FEED_URL
    return dict(urllib.parse.parse_qsl(parts.query))


class _PagedFeed:
    """Serves ``pages`` keyed by the cursor the request carries."""

    def __init__(self, pages: dict[int | None, object]) -> None:
        self.pages = pages
        self.urls: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.urls.append(url)
        cursor = _query(url).get("cursor")
        page = self.pages[None if cursor is None else int(cursor)]
        return page if isinstance(page, bytes) else json.dumps(page).encode()


def _page(receipts: list[object], next_cursor: object) -> dict[str, object]:
    return {
        "schema": "escape_published_receipts_v0",
        "receipts": receipts,
        "count": len(receipts),
        "next_cursor": next_cursor,
    }


def test_https_feed_follows_next_cursor_and_scores_every_page(test_signer) -> None:
    first, second, third = (
        receipt(window_id="w-1", room_id="room-1"),
        receipt(window_id="w-2", room_id="room-2"),
        receipt(window_id="w-3", room_id="room-3"),
    )
    feed = _PagedFeed(
        {
            None: _page([first], 11),
            11: _page([second], 42),
            42: _page([third], None),
        }
    )
    loaded = escape_receipts.load_receipt_feed(
        FEED_URL, fetch=feed, window_seconds=DEFAULT_REWARD_WINDOW_SECONDS, now=NOW
    )
    assert loaded == [first, second, third]
    since = str(
        int(
            NOW
            - DEFAULT_REWARD_WINDOW_SECONDS
            - escape_receipts.MAX_FUTURE_SKEW_SECONDS
        )
    )
    limit = str(escape_receipts.FEED_PAGE_RECEIPTS)
    assert [_query(url) for url in feed.urls] == [
        {"limit": limit, "since": since},
        {"limit": limit, "since": since, "cursor": "11"},
        {"limit": limit, "since": since, "cursor": "42"},
    ]
    assert len(score(loaded).accepted_digests) == 3


@pytest.mark.parametrize(
    "body",
    [
        [{"n": 1}, {"n": 2}],
        {"receipts": [{"n": 1}, {"n": 2}]},
        {"receipts": [{"n": 1}, {"n": 2}], "next_cursor": None},
    ],
)
def test_server_that_does_not_page_is_read_in_one_request(body: object) -> None:
    feed = _PagedFeed({None: body})
    loaded = escape_receipts.load_receipt_feed(FEED_URL, fetch=feed)
    assert loaded == [{"n": 1}, {"n": 2}]
    assert len(feed.urls) == 1
    assert "since" not in _query(feed.urls[0])


@pytest.mark.parametrize("bad", [7, 3, True, "8", -1, 1.5])
def test_cursor_that_does_not_advance_is_refused(bad: object) -> None:
    feed = _PagedFeed({None: _page([{"n": 1}], 7), 7: _page([{"n": 2}], bad)})
    with pytest.raises(EscapeReceiptError, match="cursor did not advance"):
        escape_receipts.load_receipt_feed(FEED_URL, fetch=feed)


def test_first_page_cursor_must_be_a_non_negative_int() -> None:
    for bad in (-1, True, "0"):
        feed = _PagedFeed({None: _page([{"n": 1}], bad)})
        with pytest.raises(EscapeReceiptError, match="cursor did not advance"):
            escape_receipts.load_receipt_feed(FEED_URL, fetch=feed)


def test_empty_page_with_a_cursor_is_refused() -> None:
    feed = _PagedFeed({None: _page([], 5)})
    with pytest.raises(EscapeReceiptError, match="empty mid-feed"):
        escape_receipts.load_receipt_feed(FEED_URL, fetch=feed)


def test_oversized_page_fails_the_whole_read_and_keeps_the_plan(test_signer) -> None:
    feed = _PagedFeed(
        {None: _page([receipt()], 1), 1: b"[" + b" " * MAX_FEED_BYTES + b"]"}
    )
    planned = machine_plan()
    same, summary = runtime.apply_escape_receipts(
        planned,
        config(),
        now=NOW,
        load=lambda _source: escape_receipts.load_receipt_feed(FEED_URL, fetch=feed),
    )
    assert same is planned
    assert summary["status"] == "SOURCE_UNAVAILABLE"
    assert summary["error"] == "escape receipt feed is too large"


def test_failed_later_page_fails_the_whole_read(test_signer) -> None:
    def fetch(url: str) -> bytes:
        if "cursor" in _query(url):
            raise EscapeReceiptError("escape receipt feed HTTP 429")
        return json.dumps(_page([receipt()], 1)).encode()

    planned = machine_plan()
    same, summary = runtime.apply_escape_receipts(
        planned,
        config(),
        now=NOW,
        load=lambda source: escape_receipts.load_receipt_feed(FEED_URL, fetch=fetch),
    )
    assert same is planned
    assert summary["status"] == "SOURCE_UNAVAILABLE"
    assert summary["error"] == "escape receipt feed HTTP 429"


def test_a_full_page_at_the_largest_published_receipt_fits() -> None:
    # The control plane caps the published claim at 16 KiB; a receipt adds
    # about 1 KiB of envelope around it.
    big = {"claim": {"pad": "x" * (16 * 1024)}, "envelope": "y" * 1024}
    body = json.dumps(_page([big] * escape_receipts.FEED_PAGE_RECEIPTS, None))
    assert len(body.encode()) <= MAX_FEED_BYTES
    feed = _PagedFeed({None: body.encode()})
    loaded = escape_receipts.load_receipt_feed(FEED_URL, fetch=feed)
    assert len(loaded) == escape_receipts.FEED_PAGE_RECEIPTS


def test_paging_stops_at_the_page_ceiling_and_keeps_the_oldest() -> None:
    def fetch(url: str) -> bytes:
        cursor = int(_query(url).get("cursor", "0"))
        rows = [{"n": cursor * 10 + i} for i in range(10)]
        return json.dumps(_page(rows, cursor + 1)).encode()

    loaded = escape_receipts.load_receipt_feed(FEED_URL, fetch=fetch)
    assert len(loaded) == escape_receipts.MAX_FEED_PAGES * 10
    assert loaded[0] == {"n": 0}


def test_paging_stops_at_the_receipt_ceiling() -> None:
    def fetch(url: str) -> bytes:
        cursor = int(_query(url).get("cursor", "0"))
        rows = [{"n": cursor * 6000 + i} for i in range(6000)]
        return json.dumps(_page(rows, cursor + 1)).encode()

    loaded = escape_receipts.load_receipt_feed(FEED_URL, fetch=fetch)
    assert len(loaded) == MAX_FEED_RECEIPTS
    assert loaded[-1] == {"n": MAX_FEED_RECEIPTS - 1}


def test_since_is_clamped_at_zero() -> None:
    feed = _PagedFeed({None: []})
    escape_receipts.load_receipt_feed(FEED_URL, fetch=feed, window_seconds=600, now=10)
    assert _query(feed.urls[0])["since"] == "0"


def test_total_budget_spans_pages() -> None:
    def fetch(url: str) -> bytes:
        time.sleep(0.3)
        cursor = int(_query(url).get("cursor", "0"))
        return json.dumps(_page([{"n": cursor}], cursor + 1)).encode()

    started = time.monotonic()
    with pytest.raises(EscapeReceiptError, match="unavailable"):
        escape_receipts.load_receipt_feed(FEED_URL, fetch=fetch, timeout=1.0)
    assert time.monotonic() - started < 2.0


def test_direct_validator_reads_the_window_from_its_own_clock(
    test_signer, monkeypatch
) -> None:
    seen: list[tuple[str, float]] = []

    def fake_fetch(url: str, *, timeout: float, opener: object = None) -> bytes:
        seen.append((url, timeout))
        return json.dumps(_page([receipt()], None)).encode()

    monkeypatch.setattr(escape_receipts, "_fetch_https", fake_fetch)
    window = 3 * 24 * 3600
    https = replace(config(window=window), source=FEED_URL)
    planned = machine_plan()
    _same, summary = runtime.apply_escape_receipts(planned, https, now=NOW)
    assert summary["status"] == "APPLIED", summary
    [(url, timeout)] = seen
    assert _query(url)["since"] == str(
        int(NOW - window - escape_receipts.MAX_FUTURE_SKEW_SECONDS)
    )
    assert 0 < timeout <= escape_receipts.FEED_TIMEOUT_SECONDS
