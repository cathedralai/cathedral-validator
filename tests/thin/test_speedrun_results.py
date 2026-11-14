"""AB#456: offline receipt checks and Speedrun result reuse.

Fixtures in fixtures/speedrun_receipts_20261109 are a real signed sealed run
(cathedral-pool examples/sandbox/audit_trail/sample-run-20261109, nc-sealed-3,
AMD Genoa) and its tampered copy (Cathedral receipt 8 edited), plus the
``ctcli receipt verify --approved-measurement --json`` output for both, captured
from cathedral-pool main fe1d7aa. The real-ctcli tests at the bottom rerun ctcli
when CATHEDRAL_CTCLI names it (for example ``python3 -m cli`` with the pool on
PYTHONPATH) and are skipped otherwise.
"""

from __future__ import annotations

import copy
import json
import os
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cathedral_thin.independent_runtime import speedrun_results as sr

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures" / "speedrun_receipts_20261109"
MEASUREMENT = (FIXTURES / "pinned-measurement.txt").read_text().strip()
PASS_REPORT = json.loads((FIXTURES / "ctcli-verify-pass.json").read_text())
TAMPERED_REPORT = json.loads((FIXTURES / "ctcli-verify-tampered.json").read_text())
OTHER_MEASUREMENT = "ab" * 48
NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)
SEED = bytes.fromhex("11" * 32)


def _key(**overrides):
    fields = {
        "entry_digest": "aa" * 32,
        "model_digest": "bb" * 32,
        "harness_version": "speedrun-1.4.0",
        "room_size": 8,
        "round": 12,
    }
    fields.update(overrides)
    return sr.SpeedrunKey(**fields)


def _parse(report, code=0, **kwargs):
    kwargs.setdefault("approved_measurements", [MEASUREMENT])
    return sr.parse_ctcli_report(json.dumps(report).encode(), code, **kwargs)


def _verified(report=None):
    return _parse(report or PASS_REPORT)


def _with_rows(rows):
    report = copy.deepcopy(PASS_REPORT)
    report["verified_results"]["results"] = rows
    return report


# Offline verification -------------------------------------------------------


def test_real_pass_report_gives_four_rows():
    verified = _verified()
    assert verified.measurement == MEASUREMENT
    assert len(verified.rows) == 4
    assert verified.result_digests == tuple(
        sorted(r["result_digest"] for r in PASS_REPORT["verified_results"]["results"])
    )


def test_row_digest_matches_pool_formula():
    for row in PASS_REPORT["verified_results"]["results"]:
        assert sr.row_digest(row) == row["result_digest"]


def test_tampered_bundle_is_refused():
    with pytest.raises(sr.SpeedrunResultError, match="verdict is FAIL") as exc:
        _parse(TAMPERED_REPORT, code=1)
    assert exc.value.infra is False


def test_exit_code_must_match_verdict():
    with pytest.raises(sr.SpeedrunResultError, match="exit code"):
        _parse(PASS_REPORT, code=1)
    with pytest.raises(sr.SpeedrunResultError, match="exit code"):
        _parse(TAMPERED_REPORT, code=0)


def test_not_proven_is_refused():
    report = copy.deepcopy(PASS_REPORT)
    report["verdict"] = "NOT PROVEN"
    with pytest.raises(sr.SpeedrunResultError, match="NOT PROVEN"):
        _parse(report, code=3)


def test_validator_rechecks_approved_measurement():
    with pytest.raises(sr.SpeedrunResultError, match="approved list"):
        _parse(PASS_REPORT, approved_measurements=[OTHER_MEASUREMENT])


@pytest.mark.parametrize(
    "field,value",
    [
        ("guest_result_sha256", "00" * 32),
        ("stdout_sha256", "00" * 32),
        ("exit_code", 1),
        ("command_sha256", "00" * 32),
    ],
)
def test_edited_row_does_not_recompute(field, value):
    rows = copy.deepcopy(PASS_REPORT["verified_results"]["results"])
    rows[0][field] = value
    with pytest.raises(sr.SpeedrunResultError, match="does not recompute"):
        _parse(_with_rows(rows))


def test_row_for_another_guest_is_refused():
    rows = copy.deepcopy(PASS_REPORT["verified_results"]["results"])
    rows[0]["binding_sha256"] = "00" * 32
    rows[0]["result_digest"] = sr.row_digest(rows[0])
    with pytest.raises(sr.SpeedrunResultError, match="attested guest"):
        _parse(_with_rows(rows))


def test_extra_row_field_is_refused():
    rows = copy.deepcopy(PASS_REPORT["verified_results"]["results"])
    rows[0]["score"] = 99
    with pytest.raises(sr.SpeedrunResultError, match="unknown fields"):
        _parse(_with_rows(rows))


def test_duplicate_row_is_refused():
    rows = PASS_REPORT["verified_results"]["results"]
    with pytest.raises(sr.SpeedrunResultError, match="twice"):
        _parse(_with_rows([rows[0], rows[0]]))


def test_missing_or_empty_results_block_is_refused():
    report = copy.deepcopy(PASS_REPORT)
    del report["verified_results"]
    with pytest.raises(sr.SpeedrunResultError, match="cathedral_verified_result_v1"):
        _parse(report)
    with pytest.raises(sr.SpeedrunResultError, match="no verified results"):
        _parse(_with_rows([]))


def test_unreadable_output_is_infra():
    with pytest.raises(sr.SpeedrunResultError) as exc:
        sr.parse_ctcli_report(b"not json", 0, approved_measurements=[MEASUREMENT])
    assert exc.value.infra is True
    error = {"ok": False, "error": {"code": "x", "message": "y"}}
    with pytest.raises(sr.SpeedrunResultError) as exc:
        sr.parse_ctcli_report(
            json.dumps(error).encode(), 1, approved_measurements=[MEASUREMENT]
        )
    assert exc.value.infra is True


def test_verifier_pin():
    pinned = PASS_REPORT["verifier"]["sha256"]
    assert (
        _parse(PASS_REPORT, expected_verifier_sha256=pinned).verifier_sha256 == pinned
    )
    with pytest.raises(sr.SpeedrunResultError, match="pinned"):
        _parse(PASS_REPORT, expected_verifier_sha256="00" * 32)


def test_expected_command():
    command = PASS_REPORT["verified_results"]["results"][2]["command_sha256"]
    assert _parse(PASS_REPORT, expected_command_sha256=command)
    with pytest.raises(sr.SpeedrunResultError, match="expected command"):
        _parse(PASS_REPORT, expected_command_sha256="00" * 32)


def test_runner_gets_offline_command_and_failures_are_infra(tmp_path):
    seen = {}

    def runner(command, **kwargs):
        seen["command"] = command
        return subprocess.CompletedProcess(
            command, 0, json.dumps(PASS_REPORT).encode(), b""
        )

    verified = sr.verify_bundle_offline(
        tmp_path / "b.json",
        trusted_keys_file=tmp_path / "k.json",
        approved_measurements=[MEASUREMENT.upper()],
        runner=runner,
    )
    assert len(verified.rows) == 4
    assert "--kds-cache" not in seen["command"]
    assert seen["command"][-2:] == ["--approved-measurement", MEASUREMENT]

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 1)

    with pytest.raises(sr.SpeedrunResultError) as exc:
        sr.verify_bundle_offline(
            tmp_path / "b.json",
            trusted_keys_file=tmp_path / "k.json",
            approved_measurements=[MEASUREMENT],
            runner=timeout,
        )
    assert exc.value.infra is True


def test_bad_approved_list_is_refused():
    with pytest.raises(sr.SpeedrunResultError, match="at least one"):
        _parse(PASS_REPORT, approved_measurements=[])
    with pytest.raises(sr.SpeedrunResultError, match="96 hex"):
        _parse(PASS_REPORT, approved_measurements=["abc"])


# Key ------------------------------------------------------------------------


def test_key_validation_and_identity():
    assert _key().key_id == _key().key_id
    assert _key().key_id != _key(round=13).key_id
    assert _key().key_id != _key(room_size=4).key_id
    assert sr.SpeedrunKey.from_fields(_key().fields()) == _key()
    for bad in (
        {"entry_digest": "AA" * 32},
        {"model_digest": "bb"},
        {"harness_version": "bad version"},
        {"room_size": 0},
        {"round": True},
    ):
        with pytest.raises(sr.SpeedrunResultError):
            _key(**bad)
    with pytest.raises(sr.SpeedrunResultError):
        sr.SpeedrunKey.from_fields({**_key().fields(), "extra": 1})


# Store and reuse ------------------------------------------------------------


def _store(tmp_path):
    return sr.ResultStore(tmp_path / "speedrun-results.json")


def _other_run():
    """A second, different verified run of the same guest (one exec)."""

    rows = copy.deepcopy(PASS_REPORT["verified_results"]["results"][:1])
    rows[0]["guest_receipt_sha256"] = "cd" * 32
    rows[0]["result_digest"] = sr.row_digest(rows[0])
    return _parse(_with_rows(rows))


def test_measure_then_reuse(tmp_path):
    store = _store(tmp_path)
    key = _key()
    assert sr.decide(store, key) == sr.MEASURE
    assert store.record(key, _verified(), score=700, now=NOW) == "recorded"
    assert sr.decide(store, key) == sr.REUSE
    assert store.record(key, _verified(), score=1, now=NOW) == "reused"
    record = store.lookup(key)
    assert record["score"] == 700
    assert record["key"] == key.fields()
    assert record["result_digests"] == list(_verified().result_digests)
    assert os.stat(store.path).st_mode & 0o777 == 0o600


def test_store_survives_reopen(tmp_path):
    _store(tmp_path).record(_key(), _verified(), score=5, now=NOW)
    assert sr.decide(_store(tmp_path), _key()) == sr.REUSE


def test_one_run_cannot_count_for_two_keys(tmp_path):
    store = _store(tmp_path)
    store.record(_key(), _verified(), score=5, now=NOW)
    with pytest.raises(sr.SpeedrunResultError, match="another Speedrun key"):
        store.record(_key(round=13), _verified(), score=5, now=NOW)
    with pytest.raises(sr.SpeedrunResultError, match="another Speedrun key"):
        store.record(_key(entry_digest="cc" * 32), _verified(), score=5, now=NOW)


def test_second_different_run_is_a_dispute_then_rerun_resolves(tmp_path):
    store = _store(tmp_path)
    key = _key()
    store.record(key, _verified(), score=700, now=NOW)
    assert store.record(key, _other_run(), score=900, now=NOW) == "disputed"
    record = store.lookup(key)
    assert record["score"] == 700
    assert len(record["disputes"]) == 1
    assert sr.decide(store, key) == sr.RERUN_DISPUTE
    assert store.record(key, _other_run(), score=900, now=NOW, rerun=True) == "resolved"
    record = store.lookup(key)
    assert record["score"] == 900 and record["disputes"] == []
    assert sr.decide(store, key) == sr.REUSE
    # The replaced run's digests are released, so they are not stuck on this key.
    assert store.record(_key(round=13), _verified(), score=1, now=NOW) == "recorded"


def test_caller_dispute_forces_rerun(tmp_path):
    store = _store(tmp_path)
    store.record(_key(), _verified(), score=1, now=NOW)
    assert sr.decide(store, _key(), disputed=True) == sr.RERUN_DISPUTE


def test_sampling_is_documented_and_reproducible(tmp_path):
    store = _store(tmp_path)
    key = _key()
    store.record(key, _verified(), score=1, now=NOW)
    assert sr.decide(store, key, sample_seed=SEED, sample_rate_ppm=0) == sr.REUSE
    assert (
        sr.decide(store, key, sample_seed=SEED, sample_rate_ppm=1_000_000)
        == sr.RERUN_SAMPLE
    )
    keys = [_key(round=r) for r in range(1, 401)]
    picks = [sr.sample_selected(k, seed=SEED, rate_ppm=100_000) for k in keys]
    assert picks == [sr.sample_selected(k, seed=SEED, rate_ppm=100_000) for k in keys]
    assert 15 < sum(picks) < 70
    other = [sr.sample_selected(k, seed=b"\x22" * 32, rate_ppm=100_000) for k in keys]
    assert picks != other
    with pytest.raises(sr.SpeedrunResultError, match="seed"):
        sr.decide(store, key, sample_rate_ppm=10)
    with pytest.raises(sr.SpeedrunResultError):
        sr.sample_selected(key, seed=b"short", rate_ppm=10)


def test_corrupt_store_fails_closed(tmp_path):
    store = _store(tmp_path)
    store.path.write_text('{"schema":"x"}')
    store.path.chmod(0o600)
    with pytest.raises(sr.SpeedrunResultError, match="wrong shape"):
        store.lookup(_key())


def test_relative_store_path_is_refused():
    with pytest.raises(sr.SpeedrunResultError, match="absolute"):
        sr.ResultStore(Path("relative.json"))


# Real ctcli on the real signed bundle ----------------------------------------

CTCLI = os.environ.get("CATHEDRAL_CTCLI")
needs_ctcli = pytest.mark.skipif(not CTCLI, reason="CATHEDRAL_CTCLI is not set")


def _real(bundle):
    return sr.verify_bundle_offline(
        FIXTURES / bundle,
        trusted_keys_file=FIXTURES / "trusted-keys.json",
        approved_measurements=[MEASUREMENT],
        ctcli=tuple(shlex.split(CTCLI or "")),
    )


@needs_ctcli
def test_real_bundle_verifies_and_is_reused(tmp_path):
    store = _store(tmp_path)
    key = _key()
    first = _real("bundle.json")
    assert len(first.rows) == 4
    assert store.record(key, first, score=700) == "recorded"
    second = _real("bundle.json")
    assert second.result_digests == first.result_digests
    assert sr.decide(store, key) == sr.REUSE
    assert store.record(key, second, score=700) == "reused"


@needs_ctcli
def test_real_tampered_bundle_is_refused():
    with pytest.raises(sr.SpeedrunResultError, match="verdict is FAIL") as exc:
        _real("bundle-tampered.json")
    assert exc.value.infra is False
