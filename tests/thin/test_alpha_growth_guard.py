"""Alpha growth guard: earned versus sold per hotkey, owner decision gate (AB#351)."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from fractions import Fraction
from pathlib import Path

import pytest

from cathedral_thin.independent_runtime import alpha_growth
from cathedral_thin.independent_runtime.alpha_growth import (
    ALPHA_EVIDENCE_SCHEMA,
    DECISIONS_SCHEMA,
    EXIT_ATTENTION,
    EXIT_OK,
    EXIT_REFUSED,
    MAX_OPEN_SEASON_FRACTION,
    OWNER_DECISIONS,
    PINNED_DECISIONS_SHA256,
    STATUS_DECISION_REQUIRED,
    STATUS_DILUTING,
    STATUS_REPORT_ONLY,
    STATUS_WITHIN_GUARD,
    AlphaGuardError,
    evaluate,
    load_decisions,
    load_evidence,
)

REPO = Path(__file__).resolve().parents[2]
HK_A = "5" + "A" * 47
HK_B = "5" + "B" * 47
HK_C = "5" + "C" * 47


def _evidence_doc(rows=None, **overrides):
    doc = {
        "schema": ALPHA_EVIDENCE_SCHEMA,
        "source": "taostats",
        "source_endpoint": "https://api.taostats.io/api/example/v1",
        "netuid": 94,
        "window_start": "2026-12-01",
        "window_end": "2026-12-31",
        "observed_at": "2027-01-02",
        "rows": rows
        if rows is not None
        else [
            {"hotkey": HK_A, "alpha_earned": "100", "alpha_sold": "10"},
            {"hotkey": HK_B, "alpha_earned": "50.5", "alpha_sold": "0"},
        ],
    }
    doc.update(overrides)
    return doc


def _raw(doc) -> bytes:
    return json.dumps(doc).encode()


def _evidence(rows=None, **overrides):
    return load_evidence(_raw(_evidence_doc(rows, **overrides)))


def _decision(**overrides):
    entry = {
        "month": "2026-12",
        "decided_by": "Fred",
        "decided_on": "2026-11-30",
        "open_season_fraction": "1/20",
        "hold_days": 0,
        "max_sell_ratio": "1/2",
        "note": "test entry",
    }
    entry.update(overrides)
    return entry


def _ledger(*entries, **overrides) -> bytes:
    doc = {"decisions": list(entries), "netuid": 94, "schema": DECISIONS_SCHEMA}
    doc.update(overrides)
    return json.dumps(doc, sort_keys=True).encode()


def _decisions(*entries, **overrides):
    raw = _ledger(*entries, **overrides)
    return load_decisions(raw, expected_sha256=hashlib.sha256(raw).hexdigest())


# The shipped ledger


def test_shipped_ledger_is_empty_and_matches_its_pin():
    raw = (REPO / "config/open-season/alpha-growth-decisions.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PINNED_DECISIONS_SHA256
    assert load_decisions(raw, expected_sha256=PINNED_DECISIONS_SHA256) == ()
    assert OWNER_DECISIONS == ()
    assert raw == alpha_growth._canonical(alpha_growth.PINNED_DECISIONS_DOCUMENT)


def test_edited_ledger_is_refused_without_a_new_pin():
    edited = _ledger(_decision())
    with pytest.raises(AlphaGuardError, match="sha256 pin"):
        load_decisions(edited, expected_sha256=PINNED_DECISIONS_SHA256)


def test_ceiling_is_one_tenth():
    assert MAX_OPEN_SEASON_FRACTION == Fraction(1, 10)


# Default: no decision means nothing changes


def test_no_decision_requires_one_and_ledger_fraction_is_zero():
    report = evaluate(_evidence(), OWNER_DECISIONS)
    assert report.status == STATUS_DECISION_REQUIRED
    assert report.ledger_fraction == 0
    assert report.exit_code == EXIT_ATTENTION
    assert "stays 0" in report.recommendation


def test_decision_for_another_month_does_not_apply():
    decisions = _decisions(_decision(month="2026-11", decided_on="2026-10-31"))
    report = evaluate(_evidence(), decisions)
    assert report.status == STATUS_DECISION_REQUIRED
    assert report.ledger_fraction == 0


# Per-hotkey earned versus sold


def test_rows_report_earned_sold_retained_and_ratio_exactly():
    report = evaluate(_evidence(), _decisions(_decision(max_sell_ratio=None)))
    assert report.status == STATUS_REPORT_ONLY
    assert report.exit_code == EXIT_OK
    data = report.as_dict()
    assert data["rows"] == [
        {
            "hotkey": HK_A,
            "alpha_earned": "100",
            "alpha_sold": "10",
            "alpha_retained": "90",
            "sell_ratio": "1/10",
        },
        {
            "hotkey": HK_B,
            "alpha_earned": "50.5",
            "alpha_sold": "0",
            "alpha_retained": "50.5",
            "sell_ratio": "0/1",
        },
    ]
    assert data["totals"] == {
        "alpha_earned": "150.5",
        "alpha_sold": "10",
        "alpha_retained": "140.5",
        "sell_ratio": "20/301",
    }
    assert data["ledger_fraction"] == "1/20"
    assert data["decision"]["decided_by"] == "Fred"
    assert data["evidence"]["window_start"] == "2026-12-01"


def test_sub_unit_decimals_stay_exact():
    rows = [{"hotkey": HK_A, "alpha_earned": "0.1", "alpha_sold": "0.03"}]
    data = evaluate(_evidence(rows), ()).as_dict()
    assert data["rows"][0]["alpha_retained"] == "0.07"
    assert data["rows"][0]["sell_ratio"] == "3/10"


def test_report_carries_evidence_hash():
    raw = _raw(_evidence_doc())
    report = evaluate(load_evidence(raw), ())
    assert report.as_dict()["evidence"]["sha256"] == hashlib.sha256(raw).hexdigest()


# Dilution


def test_within_guard_at_exact_limit():
    rows = [{"hotkey": HK_A, "alpha_earned": "100", "alpha_sold": "50"}]
    report = evaluate(_evidence(rows), _decisions(_decision()))
    assert report.status == STATUS_WITHIN_GUARD
    assert report.exit_code == EXIT_OK
    assert report.recommendation == ""


def test_one_hotkey_over_limit_is_diluting_even_if_aggregate_is_not():
    rows = [
        {"hotkey": HK_A, "alpha_earned": "1000", "alpha_sold": "0"},
        {"hotkey": HK_B, "alpha_earned": "10", "alpha_sold": "10"},
    ]
    report = evaluate(_evidence(rows), _decisions(_decision()))
    assert report.status == STATUS_DILUTING
    assert report.over_hotkeys == (HK_B,)
    assert report.aggregate_over is False
    assert report.exit_code == EXIT_ATTENTION
    assert "hold period" in report.recommendation
    # The guard reports; it never changes the decided fraction.
    assert report.ledger_fraction == Fraction(1, 20)


def test_aggregate_over_limit_is_diluting():
    rows = [
        {"hotkey": HK_A, "alpha_earned": "100", "alpha_sold": "51"},
        {"hotkey": HK_B, "alpha_earned": "100", "alpha_sold": "51"},
    ]
    report = evaluate(_evidence(rows), _decisions(_decision()))
    assert report.status == STATUS_DILUTING
    assert report.aggregate_over is True
    assert report.over_hotkeys == (HK_A, HK_B)


def test_selling_without_earning_is_over_any_limit():
    rows = [
        {"hotkey": HK_A, "alpha_earned": "1000", "alpha_sold": "0"},
        {"hotkey": HK_C, "alpha_earned": "0", "alpha_sold": "1"},
    ]
    report = evaluate(_evidence(rows), _decisions(_decision(max_sell_ratio="1/1")))
    assert report.status == STATUS_DILUTING
    assert report.over_hotkeys == (HK_C,)
    assert report.as_dict()["rows"][1]["sell_ratio"] is None


def test_empty_rows_with_decision_is_within_guard():
    report = evaluate(_evidence([]), _decisions(_decision()))
    assert report.status == STATUS_WITHIN_GUARD
    assert report.as_dict()["totals"]["sell_ratio"] is None


# Evidence refusals


@pytest.mark.parametrize(
    "amount",
    ["1e3", "1_000", "+1", "-0", "-1", " 1", "1.", ".5", "01", "1/2", 5, 1.5, None],
)
def test_amount_must_be_plain_decimal_string(amount):
    rows = [{"hotkey": HK_A, "alpha_earned": amount, "alpha_sold": "0"}]
    with pytest.raises(AlphaGuardError):
        _evidence(rows)


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema": "other"},
        {"netuid": 39},
        {"netuid": True},
        {"source": ""},
        {"window_start": "2026-12-01T00:30:00+01:00"},
        {"window_start": "2026-12-32"},
        {"window_start": "2027-01-01"},
        {"observed_at": "2026-12-30"},
        {"window_start": "2026-11-15"},
    ],
)
def test_evidence_header_refusals(overrides):
    with pytest.raises(AlphaGuardError):
        _evidence(**overrides)


def test_duplicate_hotkey_refused():
    rows = [
        {"hotkey": HK_A, "alpha_earned": "1", "alpha_sold": "0"},
        {"hotkey": HK_A, "alpha_earned": "2", "alpha_sold": "0"},
    ]
    with pytest.raises(AlphaGuardError, match="twice"):
        _evidence(rows)


@pytest.mark.parametrize("hotkey", ["short", "5" + "0" * 47, 7])
def test_bad_hotkey_refused(hotkey):
    rows = [{"hotkey": hotkey, "alpha_earned": "1", "alpha_sold": "0"}]
    with pytest.raises(AlphaGuardError):
        _evidence(rows)


def test_extra_row_field_refused():
    rows = [{"hotkey": HK_A, "alpha_earned": "1", "alpha_sold": "0", "x": 1}]
    with pytest.raises(AlphaGuardError):
        _evidence(rows)


def test_duplicate_json_key_and_nan_refused():
    good = _raw(_evidence_doc())
    duplicated = good.replace(
        b'"source": "taostats"', b'"source": "x", "source": "taostats"'
    )
    with pytest.raises(AlphaGuardError, match="duplicate"):
        load_evidence(duplicated)
    with pytest.raises(AlphaGuardError, match="NaN"):
        load_evidence(good.replace(b'"netuid": 94', b'"netuid": NaN'))


def test_non_json_refused():
    with pytest.raises(AlphaGuardError):
        load_evidence(b"\xff not json")


# Decision refusals


@pytest.mark.parametrize(
    "overrides",
    [
        {"open_season_fraction": "11/100"},
        {"open_season_fraction": "1/2"},
        {"open_season_fraction": "0.05"},
        {"open_season_fraction": 0},
        {"decided_by": "someone"},
        {"decided_on": "2026-12-02"},
        {"month": "2026-13"},
        {"month": "2026-1"},
        {"hold_days": -1},
        {"hold_days": True},
        {"hold_days": 366},
        {"max_sell_ratio": "3/2"},
        {"max_sell_ratio": 0.5},
        {"note": ""},
    ],
)
def test_decision_refusals(overrides):
    with pytest.raises(AlphaGuardError):
        _decisions(_decision(**overrides))


def test_decision_on_the_first_day_of_its_month_is_allowed():
    (decision,) = _decisions(_decision(decided_on="2026-12-01"))
    assert decision.open_season_fraction == Fraction(1, 20)


def test_zero_and_ceiling_fractions_are_allowed():
    (zero,) = _decisions(_decision(open_season_fraction="0/1"))
    (ceiling,) = _decisions(_decision(open_season_fraction="1/10"))
    assert zero.open_season_fraction == 0
    assert ceiling.open_season_fraction == MAX_OPEN_SEASON_FRACTION


def test_duplicate_or_unsorted_months_refused():
    dec = _decision(month="2026-11", decided_on="2026-10-31")
    with pytest.raises(AlphaGuardError, match="sorted"):
        _decisions(dec, dec)
    with pytest.raises(AlphaGuardError, match="sorted"):
        _decisions(_decision(), dec)


def test_ledger_header_refusals():
    with pytest.raises(AlphaGuardError):
        _decisions(netuid=39)
    with pytest.raises(AlphaGuardError):
        _decisions(schema="other")


# CLI


def _write(tmp_path, doc) -> Path:
    path = tmp_path / "evidence.json"
    path.write_bytes(_raw(doc))
    return path


def test_cli_reports_decision_required_with_shipped_ledger(tmp_path, capsys):
    code = alpha_growth.main(["--evidence", str(_write(tmp_path, _evidence_doc()))])
    out = capsys.readouterr().out
    assert code == EXIT_ATTENTION
    assert "status: DECISION_REQUIRED" in out
    assert HK_A in out and "100  10  90  1/10" in out
    assert "ledger fraction: 0/1 (ceiling 1/10)" in out


def test_cli_json_and_diluting(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(alpha_growth, "OWNER_DECISIONS", _decisions(_decision()))
    rows = [{"hotkey": HK_A, "alpha_earned": "10", "alpha_sold": "9"}]
    path = _write(tmp_path, _evidence_doc(rows))
    code = alpha_growth.main(["--evidence", str(path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == EXIT_ATTENTION
    assert data["status"] == STATUS_DILUTING
    assert data["over_hotkeys"] == [HK_A]


def test_cli_refuses_bad_input(tmp_path, capsys):
    code = alpha_growth.main(["--evidence", str(_write(tmp_path, {"schema": "x"}))])
    assert code == EXIT_REFUSED
    assert "refused" in capsys.readouterr().err
    assert (
        alpha_growth.main(["--evidence", str(tmp_path / "missing.json")])
        == EXIT_REFUSED
    )


# Isolation


def test_module_loads_no_chain_or_network_client():
    code = (
        "import importlib, sys; "
        "importlib.import_module('cathedral_thin.independent_runtime.alpha_growth'); "
        "print(sorted({m.split('.')[0] for m in sys.modules} & "
        "{'scaffold', 'bittensor', 'substrateinterface', 'numpy', 'requests', "
        "'httpx', 'urllib3', 'socket'}))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert proc.stdout.strip() == "[]", proc.stdout
