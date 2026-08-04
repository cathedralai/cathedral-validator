"""The v3 pre-cutover gate must run the validator's ACCEPT stage, not just mapping.

A well-formed v3 payload with a missing/bad signature is refused by every
validator (`accept_vector` runs signature + freshness before mapping), so the
gate returning PASS for it would send an operator into the exact sink-to-burn
scenario the gate exists to prevent. These tests lock the accept stage in.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

from test_validated_supply_v3 import H2U, v3_payload

_GATE_PATH = (
    pathlib.Path(__file__).resolve().parents[3] / "scripts" / "assert_live_v3_contract.py"
)
_spec = importlib.util.spec_from_file_location("_v3_gate", _GATE_PATH)
_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gate)


def _write(tmp_path, doc):
    path = tmp_path / "vector.json"
    path.write_text(json.dumps(doc))
    return str(path)


def test_unsigned_v3_payload_fails_the_accept_stage(tmp_path, capsys):
    # Mapping-valid v3 vector, no signature, no embedded map: the gate must
    # refuse at the accept stage — before any metagraph/chain access.
    doc = v3_payload()
    rc = _gate.main(["--offline", _write(tmp_path, doc), "--json"])
    assert rc == 1
    err = capsys.readouterr().err
    detail = json.loads(err.splitlines()[0])
    assert detail["ok"] is False
    assert detail["stage"] == "accept"
    assert "DO NOT RE-PIN" in err


def test_bad_signature_fails_even_with_correct_key_id(tmp_path, capsys):
    doc = v3_payload()
    doc["key_id"] = "cathedral-weight-policy"
    doc["signature"] = "aW52YWxpZA=="  # valid base64, invalid signature
    rc = _gate.main(["--offline", _write(tmp_path, doc), "--json"])
    assert rc == 1
    assert json.loads(capsys.readouterr().err.splitlines()[0])["stage"] == "accept"


def test_hermetic_fixture_passes_mapping_but_reports_unchecked(tmp_path, capsys):
    doc = v3_payload()
    doc["_hotkey_to_uid"] = dict(H2U)
    rc = _gate.main(["--offline", _write(tmp_path, doc), "--json"])
    assert rc == 0
    result = json.loads(capsys.readouterr().out.strip())
    assert result["ok"] is True
    assert result["signature_checked"] is False
    assert result["weight_sum"] == pytest.approx(1.0)


def test_hermetic_human_output_carries_the_warning(tmp_path, capsys):
    doc = v3_payload()
    doc["_hotkey_to_uid"] = dict(H2U)
    rc = _gate.main(["--offline", _write(tmp_path, doc)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Never re-pin on this output" in out


def test_redirects_are_refused():
    handler = _gate._NoRedirect()

    class _Req:
        full_url = "https://api.cathedral.computer/v1/validator/weights/next"

    with pytest.raises(SystemExit, match="redirected"):
        handler.redirect_request(_Req(), None, 302, "Found", {}, "https://evil.example/")
