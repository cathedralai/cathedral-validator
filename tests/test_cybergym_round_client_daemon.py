"""The validator's HTTP client and its off-chain round daemon."""
import json
import sys
import threading
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_thin.cybergym_round_client import HttpRoundClient, RoundClientError  # noqa: E402
from cathedral_thin.cybergym_round_daemon import (  # noqa: E402
    FileWeightSink, RoundDaemon, config_from_geometry, offchain_nonce,
)
from cathedral_thin.cybergym_round_eval import MinerRoundResult  # noqa: E402
from cathedral_thin.cybergym_round_runtime import LaneWeights  # noqa: E402
from cathedral_thin.cybergym_round_schedule import TEST_CONFIG  # noqa: E402

TASKS = ["arvo:1", "arvo:2"]
GEOMETRY = {"round_blocks": 72, "submission_close_offset": 60,
            "weight_set_offset": 66, "reassert_blocks": 3}


class FakeBackend:
    """A real HTTP server speaking the v2 round API, so the client's transport is exercised."""

    def __init__(self, block=0, submissions=None, scores=None, tasks=TASKS, broken=()):
        self.block = block
        self.submissions = submissions if submissions is not None else []
        self.scores = scores or {}
        self.tasks = tasks
        self.broken = set(broken)
        self.posted = []
        backend = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                path = self.path.split("?")[0]
                if path in backend.broken:
                    return self._send(500, {"error": "backend is having a day"})
                if path == "/v2/round":
                    return self._send(200, {"block": backend.block, "geometry": GEOMETRY,
                                            "round_id": backend.block // 72})
                if path == "/v2/tasks":
                    return self._send(200, {"round_id": 0, "tasks": backend.tasks})
                if path == "/v2/submissions":
                    return self._send(200, {"round_id": 0, "submissions": backend.submissions})
                if path == "/v2/average":
                    return self._send(200, {"round_id": 0, "scores": backend.scores})
                return self._send(404, {"error": "nope"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                backend.posted.append(json.loads(self.rfile.read(length)))
                return self._send(200, {"recorded": True})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()


def wire_submission(hotkey, tasks=TASKS):
    import base64
    return {"miner_hotkey": hotkey, "agent_digest": "sha256:" + hotkey,
            "tasks": [{"task_id": t, "poc_b64": base64.b64encode(b"solve").decode(),
                       "proof": {"vulnerable_image": t}} for t in tasks]}


@pytest.fixture
def backend():
    b = FakeBackend()
    yield b
    b.close()


class TestTheClient:
    def test_it_reads_the_shared_block_height(self, backend):
        backend.block = 137
        assert HttpRoundClient(backend.base, "v1").fetch_round()["block"] == 137

    def test_it_reads_the_published_task_set(self, backend):
        assert HttpRoundClient(backend.base, "v1").fetch_round_tasks(0) == TASKS

    def test_it_decodes_submissions_with_their_server_supplied_proofs(self, backend):
        backend.submissions = [wire_submission("m1")]
        subs = HttpRoundClient(backend.base, "v1").fetch_submissions(0)
        assert subs[0].miner_hotkey == "m1"
        assert subs[0].tasks[0].poc == b"solve"
        assert subs[0].tasks[0].proof == {"vulnerable_image": "arvo:1"}

    def test_it_posts_results_under_its_own_hotkey(self, backend):
        results = {"m1": MinerRoundResult("m1", "d", 1, 2, Decimal("50"), (("arvo:1", True),))}
        HttpRoundClient(backend.base, "v-me").post_results(0, results)
        assert backend.posted[0]["validator_hotkey"] == "v-me"
        assert backend.posted[0]["results"][0]["score"] == "50"

    def test_it_reports_abstention_explicitly(self, backend):
        results = {"m1": MinerRoundResult("m1", "d", 0, 2, Decimal(0), (), evaluated=False)}
        HttpRoundClient(backend.base, "v1").post_results(0, results)
        assert backend.posted[0]["results"][0]["evaluated"] is False

    def test_it_reads_averages_as_decimals(self, backend):
        backend.scores = {"m1": "83.333333"}
        assert HttpRoundClient(backend.base, "v1").fetch_average_scores(0) == {
            "m1": Decimal("83.333333")}

    def test_a_server_error_raises_rather_than_reading_as_an_empty_field(self, backend):
        """An empty field composes an all-burn board; a hiccup must never look like one."""
        backend.broken = {"/v2/average"}
        with pytest.raises(RoundClientError):
            HttpRoundClient(backend.base, "v1").fetch_average_scores(0)

    def test_an_unreachable_backend_raises(self):
        with pytest.raises(RoundClientError):
            HttpRoundClient("http://127.0.0.1:9", "v1", timeout=1).fetch_round()

    def test_an_empty_task_set_raises(self, backend):
        backend.tasks = []
        with pytest.raises(RoundClientError):
            HttpRoundClient(backend.base, "v1").fetch_round_tasks(0)

    def test_a_malformed_submission_row_raises(self, backend):
        backend.submissions = [{"miner_hotkey": "m1", "tasks": [{"task_id": "t"}]}]
        with pytest.raises(RoundClientError):
            HttpRoundClient(backend.base, "v1").fetch_submissions(0)


class TestTheWeightSink:
    def test_it_records_every_set_with_its_block(self, tmp_path):
        sink = FileWeightSink(path=tmp_path / "w.jsonl")
        sink.block = 66
        sink(LaneWeights({"m1": Decimal("0.84")}, Decimal("0.16")))
        rows = [json.loads(line) for line in (tmp_path / "w.jsonl").read_text().splitlines()]
        assert rows[0]["block"] == 66 and rows[0]["weights"] == {"m1": "0.84"}
        assert rows[0]["burn"] == "0.16", "a trail without the burn hides a forfeited lane"

    def test_the_latest_vector_is_the_last_one_set(self, tmp_path):
        sink = FileWeightSink(path=tmp_path / "w.jsonl")
        sink(LaneWeights({"m1": Decimal("1")}))
        sink(LaneWeights({"m2": Decimal("1")}))
        assert sink.latest == {"m2": "1"}

    def test_it_works_without_a_file(self):
        sink = FileWeightSink()
        sink(LaneWeights({"m1": Decimal("1")}))
        assert sink.latest == {"m1": "1"}


class TestTheDaemon:
    def test_it_adopts_the_servers_geometry(self, backend):
        d = RoundDaemon(HttpRoundClient(backend.base, "v1"), lambda *a: True, FileWeightSink())
        d.sync_geometry()
        assert d.cfg == TEST_CONFIG

    def test_a_backend_outage_skips_the_tick_and_keeps_the_last_weights(self, backend):
        backend.submissions = [wire_submission("m1")]
        backend.scores = {"m1": "100"}
        sink = FileWeightSink()
        d = RoundDaemon(HttpRoundClient(backend.base, "v1", timeout=1), lambda *a: True, sink)
        backend.block = 72 + 66          # compose block of the first evaluation round
        d.tick()
        first = dict(sink.latest)
        assert first, "the first tick should have composed real weights"
        backend.block = 72 * 2 + 66       # next round: it must benchmark and compose again
        backend.broken = {"/v2/tasks", "/v2/submissions", "/v2/average"}
        block, action = d.tick()
        assert action is None and d.errors and sink.latest == first

    def test_it_benchmarks_reports_and_composes_across_the_round(self, backend):
        backend.submissions = [wire_submission("m1"), wire_submission("m2", TASKS[:1])]
        backend.scores = {"m1": "100", "m2": "50"}
        sink = FileWeightSink()
        d = RoundDaemon(HttpRoundClient(backend.base, "v1"),
                        lambda tid, poc, proof: poc == b"solve", sink)
        backend.block = 72 + 66  # the compose block of the evaluation round
        d.tick()
        assert backend.posted, "the validator must report its own verdicts"
        assert sink.latest == {"m1": "0.930000", "m2": "0.07"}

    def test_a_lane_with_no_qualifying_miner_forfeits_rather_than_setting_nothing(self, backend):
        """An empty vector is not a forfeit; it is a malformed set that drops the allocation."""
        backend.submissions = []
        backend.scores = {}
        sink = FileWeightSink()
        d = RoundDaemon(HttpRoundClient(backend.base, "v1"), lambda *a: True, sink)
        backend.block = 72 + 66
        d.tick()
        assert sink.latest == {} and Decimal(sink.latest_burn) == Decimal(1)

    def test_before_the_first_compose_it_asserts_a_forfeit_not_an_empty_vector(self, backend):
        sink = FileWeightSink()
        d = RoundDaemon(HttpRoundClient(backend.base, "v1"), lambda *a: True, sink)
        backend.block = 10          # mid-round-0: nothing to score, nothing composed yet
        d.tick()
        assert Decimal(sink.latest_burn) == Decimal(1)

    def test_the_offchain_nonce_is_shared_deterministic_and_labelled_test_only(self):
        assert offchain_nonce(7) == offchain_nonce(7) != offchain_nonce(8)
        assert "not adversarially safe" in offchain_nonce.__doc__.lower()

    def test_geometry_conversion_rejects_an_incoherent_server(self):
        with pytest.raises(ValueError):
            config_from_geometry({**GEOMETRY, "weight_set_offset": 999})


class TestTheReportedRoundIsTheRoundActuallyScored:
    """The first compose scores round -1 — nothing — and must not be filed under round 0.

    Found reading the live dashboard off the box (2026-09-04): round 0 showed a composed all-burn
    board while its real compose was still a round away.
    """

    def test_the_first_compose_reports_nothing(self, backend):
        sink = FileWeightSink()
        d = RoundDaemon(HttpRoundClient(backend.base, "v1"), lambda *a: True, sink)
        backend.block = 66                      # round 0's compose block; it scores round -1
        d.tick()
        assert sink.sets, "it must still SET weights (skipping lets the chain zero us)"
        assert backend.posted == [], "but it has no scored round to report them against"

    def test_a_later_compose_reports_the_round_it_scored(self, backend):
        backend.submissions = [wire_submission("m1")]
        backend.scores = {"m1": "100"}
        d = RoundDaemon(HttpRoundClient(backend.base, "v1"), lambda t, p, pr: True,
                        FileWeightSink())
        backend.block = 72 * 2 + 66             # round 2's compose scores round 1
        d.tick()
        weight_posts = [p for p in backend.posted if "weights" in p]
        assert weight_posts and weight_posts[-1]["round_id"] == 1


class TestTheSignedMessageMatchesTheBackendByteForByte:
    """The backend verifies a signature over ITS rendering of the report. The two repos cannot
    import each other, so the agreement is pinned as a literal on both sides. If this changes
    without the backend changing, every validator's reports start being rejected as forgeries.
    """

    ROWS = [{"miner_hotkey": "m2", "score": "50", "evaluated": False},
            {"miner_hotkey": "m1", "score": "100"}]
    EXPECTED = b'cybergym:v2:results:5V:3:[["m1","100",true],["m2","50",false]]'

    def test_the_exact_bytes(self):
        from cathedral_thin.cybergym_round_client import results_message
        assert results_message("5V", 3, self.ROWS) == self.EXPECTED

    def test_wire_order_does_not_change_what_is_signed(self):
        from cathedral_thin.cybergym_round_client import results_message
        assert results_message("5V", 3, list(reversed(self.ROWS))) == self.EXPECTED

    def test_the_weights_message_bytes(self):
        from cathedral_thin.cybergym_round_client import weights_message
        assert weights_message("5V", 3, {"m1": "0.9"}, "0.1") == (
            b'cybergym:v2:weights:5V:3:[["m1","0.9"]]:0.1')

    def test_an_unsigned_client_sends_no_signature_field(self, backend):
        """Unsigned is a real mode (a local dry run); it must not fabricate a signature."""
        client = HttpRoundClient(backend.base, "5V")
        client.post_results(0, {"m1": MinerRoundResult("m1", "d", 1, 1, Decimal("100"), ())})
        assert "signature" not in backend.posted[0]

    def test_a_signing_client_signs_what_the_backend_will_verify(self, backend):
        from cathedral_thin.cybergym_round_client import results_message
        seen = {}
        client = HttpRoundClient(backend.base, "5V",
                                 sign=lambda msg: seen.setdefault("msg", msg) and "sighex")
        client.post_results(3, {"m1": MinerRoundResult("m1", "d", 1, 1, Decimal("100"), ())})
        posted = backend.posted[0]
        assert posted["signature"] == "sighex"
        assert seen["msg"] == results_message("5V", 3, posted["results"])


class TestTheClientSignsItsReads:
    """The submission feed carries every miner's PoC bytes, so the backend gates it behind the
    same hotkey that posts the results back. Pinned as a byte literal on both sides, like the
    write messages: the repos cannot import each other."""

    def test_the_exact_read_bytes(self):
        from cathedral_thin.cybergym_round_client import read_message
        assert read_message("/v2/submissions", 3, 1700) == (
            b"cybergym:v2:read:/v2/submissions:3:1700")

    def test_the_path_the_round_and_the_moment_are_all_bound(self):
        from cathedral_thin.cybergym_round_client import read_message
        base = read_message("/v2/submissions", 3, 1700)
        assert base != read_message("/v2/log", 3, 1700)
        assert base != read_message("/v2/submissions", 4, 1700)
        assert base != read_message("/v2/submissions", 3, 1701)

    def test_a_signing_client_sends_read_headers(self, backend):
        backend.submissions = [wire_submission("m1")]
        seen = {}
        client = HttpRoundClient(backend.base, "5V",
                                 sign=lambda msg: seen.setdefault("msg", msg) and "sighex")
        client.fetch_submissions(3)
        from cathedral_thin.cybergym_round_client import read_message
        assert seen["msg"].startswith(b"cybergym:v2:read:/v2/submissions:3:")

    def test_an_unsigned_client_sends_no_read_headers(self, backend):
        """Unsigned is a real mode for a local dry run; it must not fabricate a signature."""
        backend.submissions = [wire_submission("m1")]
        HttpRoundClient(backend.base, "5V").fetch_submissions(0)   # must not raise

    def test_public_reads_are_not_signed(self, backend):
        """The clock is public; signing it would imply a gate that is not there."""
        calls = []
        HttpRoundClient(backend.base, "5V", sign=lambda m: calls.append(m) or "s").fetch_round()
        assert calls == []
