"""Weekly per-hotkey readback (AB#322): telemetry aggregation and chain proof."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from fractions import Fraction
from pathlib import Path

import pytest
from bittensor_wallet import Keypair

from cathedral_thin.independent.constants import NETUID, W
from cathedral_thin.independent_runtime import direct_validator, weekly_report
from cathedral_thin.independent_runtime.axon import ServingAxon
from cathedral_thin.independent_runtime.direct_contract import (
    SUBNET_OWNER_BURN_HOTKEYS,
    DirectSubmissionReceipt,
    DirectWeightPlan,
    FinalizedMetagraphSnapshot,
)
from cathedral_thin.independent_runtime.direct_writer import (
    _subtensor_max_upscale_to_u16,
)
from cathedral_thin.independent_runtime.telemetry import build_telemetry_snapshot

VALIDATOR = Keypair.create_from_uri("//Alice")
OTHER_VALIDATOR = Keypair.create_from_uri("//Dave")
MINER_A = Keypair.create_from_uri("//Bob").ss58_address
MINER_B = Keypair.create_from_uri("//Charlie").ss58_address
BREAKER = Keypair.create_from_uri("//Eve").ss58_address
BURN_HOTKEY = SUBNET_OWNER_BURN_HOTKEYS[NETUID]
BURN_UID = 0
VALIDATOR_UID = 30
END = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
APPLIED_HASH = "0x" + "e" * 64
HEAD_HASH = "0x" + "f" * 64


def _row(uid: int, hotkey: str) -> dict[str, object]:
    return {
        "uid": uid,
        "hotkey": hotkey,
        "machine_id": f"machine-{uid}",
        "verdict": "PASS",
        "platform_identity_verified": True,
        "sat_units": 20,
        "counted_units": 20,
        "tee_kind": "tdx",
        "phase_timings_ms": {"binding": 5, "evidence": 5, "qvl": 5, "sat": 5},
    }


def _event(
    when: datetime,
    *,
    weights: dict[int, int],
    verified: set[int],
    burn: int,
    escape: dict[int, int] | None = None,
    block: int = 200,
    keypair: Keypair = VALIDATOR,
    hotkeys: dict[int, str] | None = None,
) -> dict[str, object]:
    """One signed spool event. ``weights`` maps UID 41/42 to their wire u16."""

    names = hotkeys or {41: MINER_A, 42: MINER_B}
    snapshot = FinalizedMetagraphSnapshot(
        block_number=block - 1,
        block_hash="0x" + "a" * 64,
        validator_uid=VALIDATOR_UID,
        validator_hotkey=keypair.ss58_address,
        miners=tuple(ServingAxon(uid, names[uid], "1.1.1.1", 8081) for uid in names),
        skipped_axons={},
        netuid=NETUID,
    )
    wire = {uid: weight for uid, weight in weights.items() if weight > 0}
    wire.update(escape or {})
    wire[BURN_UID] = burn
    plan = DirectWeightPlan(
        snapshot=snapshot,
        qvl_digest="4b6f" + "0" * 60,
        evidence_digest="sha256:" + "b" * 64,
        machine_ids_by_uid=tuple(
            (uid, (f"machine-{uid}",) if uid in verified else ()) for uid in names
        ),
        raw_scores=tuple((uid, 1 if uid in verified else 0) for uid in names),
        uid_hotkeys=tuple(names.items()),
        wire_uids=tuple(sorted(wire)),
        wire_weights=tuple(wire[uid] for uid in sorted(wire)),
        burn_uid=BURN_UID,
        burn_hotkey=BURN_HOTKEY,
    )
    receipt = DirectSubmissionReceipt(
        status="CONFIRMED",
        attempt_id="sha256:" + "c" * 64,
        extrinsic_hash="0x" + "d" * 64,
        block_hash=APPLIED_HASH,
        block_number=block,
        recovered=False,
    )
    return build_telemetry_snapshot(
        result_rows=tuple(_row(uid, names[uid]) for uid in sorted(verified)),
        plan=plan,
        receipt=receipt,
        keypair=keypair,
        observed_at=when,
    )


def _spool(tmp_path: Path, events: list[dict[str, object]], extra: bytes = b"") -> Path:
    path = tmp_path / "events.jsonl"
    body = b"".join(
        json.dumps(event, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        for event in events
    )
    path.write_bytes(body + extra)
    return path


def _week(tmp_path: Path) -> Path:
    """Two in-window cycles plus one before the window."""

    return _spool(
        tmp_path,
        [
            _event(
                END - timedelta(days=8),
                weights={41: 6553, 42: 0},
                verified={41},
                burn=W - 6553,
                block=100,
            ),
            _event(
                END - timedelta(days=2),
                weights={41: 6553, 42: 0},
                verified={41},
                burn=W - 6553,
                block=200,
            ),
            _event(
                END - timedelta(hours=1),
                weights={41: 3277, 42: 3276},
                verified={41, 42},
                burn=W - 6553,
                block=300,
            ),
        ],
    )


def _history(path: Path) -> weekly_report.TelemetryHistory:
    return weekly_report.load_telemetry_history(
        path, netuid=NETUID, expected_hotkey=VALIDATOR.ss58_address
    )


def _by_hotkey(report: dict[str, object]) -> dict[str, dict[str, object]]:
    return {row["hotkey"]: row for row in report["hotkeys"]}


def test_aggregates_applied_weight_and_pass_rate_over_the_window(tmp_path) -> None:
    report = weekly_report.build_weekly_report(
        _history(_week(tmp_path)), window_end=END
    )

    assert report["applied_cycles"] == 2
    assert report["window"]["coverage"] == "FULL_WINDOW"
    assert (report["first_applied_block"], report["last_applied_block"]) == (200, 300)
    rows = _by_hotkey(report)
    assert rows[MINER_A]["cycles_verified"] == 2
    assert rows[MINER_A]["verification_pass_rate"] == "1.0000"
    assert rows[MINER_A]["mean_weight_u16"] == "4915.0000"  # (6553 + 3277) / 2
    assert rows[MINER_A]["last_weight_u16"] == 3277
    assert rows[MINER_B]["cycles_present"] == 2
    assert rows[MINER_B]["cycles_verified"] == 1
    assert rows[MINER_B]["verification_pass_rate"] == "0.5000"
    assert rows[MINER_B]["mean_weight_u16"] == "1638.0000"
    assert rows[MINER_A]["uids"] == [41]


def test_fraction_is_zero_and_hours_and_uptime_are_never_invented(tmp_path) -> None:
    report = weekly_report.build_weekly_report(
        _history(_week(tmp_path)), window_end=END
    )

    assert report["open_season"] == {"fraction": "0", "status": "NOT_WIRED"}
    for row in report["hotkeys"]:
        assert row["delivered_hours"] is None
        assert row["delivered_hours_source"] == "NO_FEED"
        assert row["uptime"] is None
        assert row["uptime_source"] == "NO_FEED"
        assert row["chain_status"] == "NOT_READ"
        assert row["chain_stored_u16"] is None
    assert report["chain_readback"] == {"status": "NOT_READ"}


def test_feeds_fill_hours_and_uptime_and_add_hotkeys_with_no_weight(tmp_path) -> None:
    newcomer = Keypair.create_from_uri("//Ferdie").ss58_address
    report = weekly_report.build_weekly_report(
        _history(_week(tmp_path)),
        window_end=END,
        delivered_hours={MINER_A: Fraction(335, 2), newcomer: Fraction(4)},
        uptime={MINER_A: Fraction(99, 100)},
    )

    rows = _by_hotkey(report)
    assert rows[MINER_A]["delivered_hours"] == "167.50"
    assert rows[MINER_A]["uptime"] == "0.9900"
    assert rows[MINER_B]["delivered_hours"] is None
    assert rows[MINER_B]["delivered_hours_source"] == "FEED"
    assert rows[newcomer]["delivered_hours"] == "4.00"
    assert rows[newcomer]["cycles_present"] == 0
    assert rows[newcomer]["mean_weight_u16"] == "0.0000"


def test_partial_window_when_the_spool_starts_inside_it(tmp_path) -> None:
    path = _spool(
        tmp_path,
        [
            _event(
                END - timedelta(days=1),
                weights={41: 6553, 42: 0},
                verified={41},
                burn=W - 6553,
            )
        ],
    )
    report = weekly_report.build_weekly_report(_history(path), window_end=END)

    assert report["window"]["coverage"] == "PARTIAL_WINDOW"
    assert report["window"]["first_retained_event"] == "2026-11-12T12:00:00Z"


def test_empty_spool_reports_no_events(tmp_path) -> None:
    report = weekly_report.build_weekly_report(
        _history(_spool(tmp_path, [])), window_end=END
    )

    assert report["window"]["coverage"] == "NO_EVENTS"
    assert report["applied_cycles"] == 0
    assert report["hotkeys"] == []


def test_a_hotkey_that_moves_uid_stays_one_row(tmp_path) -> None:
    path = _spool(
        tmp_path,
        [
            _event(
                END - timedelta(days=3),
                weights={41: 6553, 42: 0},
                verified={41},
                burn=W - 6553,
            ),
            _event(
                END - timedelta(days=1),
                weights={43: 6553, 42: 0},
                verified={43},
                burn=W - 6553,
                hotkeys={43: MINER_A, 42: MINER_B},
            ),
        ],
    )
    rows = _by_hotkey(weekly_report.build_weekly_report(_history(path), window_end=END))

    assert rows[MINER_A]["uids"] == [41, 43]
    assert rows[MINER_A]["cycles_weighted"] == 2


def test_tampered_foreign_and_garbage_lines_are_rejected(tmp_path) -> None:
    good = _event(
        END - timedelta(days=1), weights={41: 6553, 42: 0}, verified={41}, burn=W - 6553
    )
    tampered = json.loads(json.dumps(good))
    tampered["miners"][0]["weight_u16"] = 6000
    tampered["burn_weight"] = W - 6000
    foreign = _event(
        END - timedelta(days=1),
        weights={41: 6553, 42: 0},
        verified={41},
        burn=W - 6553,
        keypair=OTHER_VALIDATOR,
    )
    path = _spool(tmp_path, [good, tampered, foreign], extra=b"not json\n\n")

    history = _history(path)

    assert len(history.events) == 1
    assert history.rejected == {"invalid": 2, "other_validator": 1}


def test_spool_must_be_a_regular_bounded_file(tmp_path) -> None:
    target = _week(tmp_path)
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    with pytest.raises(weekly_report.WeeklyReportError, match="symlink"):
        _history(link)
    with pytest.raises(weekly_report.WeeklyReportError, match="regular"):
        _history(tmp_path)


@pytest.mark.parametrize(
    ("document", "upper"),
    [
        ([], None),
        ({"bad key!": "1"}, None),
        ({MINER_A: 1}, None),
        ({MINER_A: "x"}, None),
        ({MINER_A: "NaN"}, None),
        ({MINER_A: "-1"}, None),
        ({MINER_A: "1.01"}, Fraction(1)),
    ],
)
def test_malformed_feeds_refuse(document, upper) -> None:
    with pytest.raises(weekly_report.WeeklyReportError):
        weekly_report.parse_feed(document, label="t", upper=upper)


# Chain readback -------------------------------------------------------------


class FakeSubstrate:
    """Weights and Keys storage per block hash; counts reads."""

    def __init__(self, blocks: dict[str, dict[str, object]], *, fail: bool = False):
        self.blocks = blocks
        self.fail = fail
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def query(self, *, module, storage_function, params, block_hash):
        assert module == "SubtensorModule"
        self.calls.append((storage_function, tuple(params)))
        if self.fail:
            raise ConnectionError("rpc down")
        block = self.blocks[block_hash]
        if storage_function == "Weights":
            return block["weights"]
        if storage_function == "Keys":
            return block["keys"].get(params[1])
        raise AssertionError(storage_function)

    def get_chain_finalised_head(self):
        return HEAD_HASH

    def get_block_number(self, block_hash):
        return 400

    def get_block_hash(self, number):
        return HEAD_HASH


class FakeSubtensor:
    def __init__(self, substrate: FakeSubstrate):
        self.substrate = substrate


KEYS = {
    VALIDATOR_UID: VALIDATOR.ss58_address,
    41: MINER_A,
    42: MINER_B,
    BURN_UID: BURN_HOTKEY,
    50: BREAKER,
}


def _stored(event_wire: dict[int, int]) -> list[list[int]]:
    uids = sorted(event_wire)
    return [
        [uid, weight]
        for uid, weight in zip(
            uids, _subtensor_max_upscale_to_u16(tuple(event_wire[u] for u in uids))
        )
        if weight > 0
    ]


def _latest_with_escape() -> dict[str, object]:
    return _event(
        END - timedelta(hours=1),
        weights={41: 3277, 42: 3276},
        verified={41, 42},
        burn=W - 6553 - 6553,
        escape={50: 6553},
        block=300,
    )


def _chain(applied: list[list[int]], head: list[list[int]] | None = None):
    return FakeSubtensor(
        FakeSubstrate(
            {
                APPLIED_HASH: {"weights": applied, "keys": KEYS},
                HEAD_HASH: {"weights": applied if head is None else head, "keys": KEYS},
            }
        )
    )


WIRE = {41: 3277, 42: 3276, 50: 6553, BURN_UID: W - 6553 - 6553}


def test_chain_readback_matches_the_applied_row_including_escape_and_burn() -> None:
    result = weekly_report.chain_readback(_chain(_stored(WIRE)), _latest_with_escape())

    assert result["status"] == "MATCHES_LAST_APPLIED"
    assert result["head"] == "SAME_AS_APPLIED"
    kinds = {entry["uid"]: entry["kind"] for entry in result["entries"]}
    assert kinds == {0: "burn", 41: "listed", 42: "listed", 50: "not_in_event"}
    assert result["entries"][0]["stored"] == W  # burn is the max, upscaled to W


def test_chain_readback_flags_a_changed_listed_weight() -> None:
    stored = _stored(WIRE)
    stored[1][1] -= 50  # UID 41
    result = weekly_report.chain_readback(_chain(stored), _latest_with_escape())

    assert result["status"] == "DIFFERS"
    entry = next(item for item in result["entries"] if item["uid"] == 41)
    assert entry["status"] == "DIFFERS"


def test_chain_readback_flags_a_missing_miner_and_an_inflated_unlisted_row() -> None:
    missing = [row for row in _stored(WIRE) if row[0] != 42]
    assert (
        weekly_report.chain_readback(_chain(missing), _latest_with_escape())["status"]
        == "DIFFERS"
    )
    inflated = [
        [uid, weight * 2 if uid == 50 else weight] for uid, weight in _stored(WIRE)
    ]
    assert (
        weekly_report.chain_readback(_chain(inflated), _latest_with_escape())["status"]
        == "DIFFERS"
    )


def test_chain_readback_reports_a_newer_row_at_the_head() -> None:
    head = _stored({41: 6553, BURN_UID: W - 6553})
    result = weekly_report.chain_readback(
        _chain(_stored(WIRE), head), _latest_with_escape()
    )

    assert result["status"] == "MATCHES_LAST_APPLIED"
    assert result["head"] == "CHANGED_SINCE_APPLIED"


def test_chain_readback_refuses_when_the_validator_uid_changed_hands() -> None:
    subtensor = _chain(_stored(WIRE))
    subtensor.substrate.blocks[APPLIED_HASH]["keys"] = {
        **KEYS,
        VALIDATOR_UID: OTHER_VALIDATOR.ss58_address,
    }
    result = weekly_report.chain_readback(subtensor, _latest_with_escape())

    assert result["status"] == "DIFFERS"
    assert "validator UID" in result["reason"]


def test_chain_read_failure_is_reported_not_raised() -> None:
    subtensor = FakeSubtensor(FakeSubstrate({}, fail=True))

    result = weekly_report.chain_readback(subtensor, _latest_with_escape())

    assert result == {"status": "UNAVAILABLE", "reason": "ConnectionError"}


def test_chain_readback_only_reads_storage() -> None:
    subtensor = _chain(_stored(WIRE))
    weekly_report.chain_readback(subtensor, _latest_with_escape())

    assert {name for name, _params in subtensor.substrate.calls} == {"Weights", "Keys"}


def test_legacy_event_with_unlisted_weight_is_unproven() -> None:
    event = _latest_with_escape()
    event = json.loads(json.dumps(event))
    event["burn_weight"] = 0
    result = weekly_report.compare_event_to_row(
        event, [(41, MINER_A, 100)], burn_hotkey=BURN_HOTKEY
    )

    assert result["status"] == "UNPROVEN"


def test_report_carries_chain_values_per_hotkey_and_lists_escape_breakers(
    tmp_path,
) -> None:
    path = _spool(tmp_path, [_latest_with_escape()])
    history = _history(path)
    chain = weekly_report.chain_readback(_chain(_stored(WIRE)), history.events[-1])

    report = weekly_report.build_weekly_report(history, window_end=END, chain=chain)

    rows = _by_hotkey(report)
    assert rows[MINER_A]["chain_status"] == "MATCH"
    assert rows[MINER_A]["chain_stored_u16"] == _stored(WIRE)[1][1]
    assert rows[BREAKER]["chain_status"] == "NOT_IN_EVENT"
    assert rows[BREAKER]["cycles_present"] == 0
    assert BURN_HOTKEY not in rows
    assert report["chain_readback"]["status"] == "MATCHES_LAST_APPLIED"


# CLI -------------------------------------------------------------------------


def _cli(tmp_path, capsys, *extra: str, subtensor=None) -> tuple[int, str]:
    path = _week(tmp_path)
    code = weekly_report.main(
        [
            "--expected-hotkey",
            VALIDATOR.ss58_address,
            "--telemetry",
            str(path),
            "--end",
            "2026-11-13T12:00:00Z",
            *extra,
        ],
        subtensor_factory=(lambda: subtensor) if subtensor is not None else None,
    )
    return code, capsys.readouterr().out


def test_cli_json_report(tmp_path, capsys) -> None:
    hours = tmp_path / "hours.json"
    hours.write_text(json.dumps({MINER_A: "12.5"}))
    code, out = _cli(
        tmp_path, capsys, "--format", "json", "--delivered-hours-json", str(hours)
    )

    assert code == 0
    report = json.loads(out)
    assert report["schema"] == weekly_report.WEEKLY_REPORT_SCHEMA
    assert _by_hotkey(report)[MINER_A]["delivered_hours"] == "12.50"


def test_cli_text_report_names_the_fraction_and_chain_state(tmp_path, capsys) -> None:
    code, out = _cli(tmp_path, capsys)

    assert code == 0
    assert "open-season fraction 0 (NOT_WIRED)" in out
    assert "chain readback NOT_READ" in out
    assert MINER_A in out


def test_cli_chain_readback_uses_the_latest_event_in_window(tmp_path, capsys) -> None:
    wire = {41: 3277, 42: 3276, BURN_UID: W - 6553}
    code, out = _cli(
        tmp_path,
        capsys,
        "--format",
        "json",
        "--chain-readback",
        subtensor=_chain(_stored(wire)),
    )

    assert code == 0
    assert json.loads(out)["chain_readback"]["status"] == "MATCHES_LAST_APPLIED"


def test_cli_refuses_a_bad_feed(tmp_path, capsys) -> None:
    uptime = tmp_path / "uptime.json"
    uptime.write_text(json.dumps({MINER_A: "2"}))
    code, out = _cli(tmp_path, capsys, "--uptime-json", str(uptime))

    assert code == 1
    assert out.startswith("WEEKLY_REPORT_REFUSED")


def test_validator_entrypoint_dispatches_without_loading_a_key(
    tmp_path, capsys, monkeypatch
) -> None:
    def no_wallet(*_args, **_kwargs):
        raise AssertionError("weekly-report must not load a wallet")

    monkeypatch.setattr(direct_validator, "make_wallet", no_wallet)
    path = _week(tmp_path)
    code = direct_validator.main(
        [
            direct_validator.WEEKLY_REPORT_COMMAND,
            "--expected-hotkey",
            VALIDATOR.ss58_address,
            "--telemetry",
            str(path),
            "--end",
            "2026-11-13T12:00:00Z",
        ]
    )

    assert code == 0
    assert "Weekly validator report" in capsys.readouterr().out
