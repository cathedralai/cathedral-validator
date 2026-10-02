"""The owner TDX measurement allowlist (review finding A1).

The pinned verifier emits a measurement for every genuine quote, but the direct
validator used to pay any TD running any image. ``CATHEDRAL_TDX_MEASUREMENT_POLICY``
records the measurement (shadow) or pays only listed ones (enforce); without
CATHEDRAL_TDX_MEASUREMENT_POLICY nothing changes.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import threading
import time
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

import test_fleet_deadline as fd
from cathedral_thin.independent.compute import (
    ComputeAdapter,
    QuoteIdentityVerdict,
    QuoteVerdict,
    tdx_measurement_or_none,
)
from cathedral_thin.independent_runtime import (
    direct_validator,
    fleet_score,
    snp_production,
    tdx_measurement,
)
from cathedral_thin.independent_runtime.direct_contract import DirectValidatorError
from cathedral_thin.independent_runtime.direct_writer import STATUS_CONFIRMED
from cathedral_thin.independent_runtime.qvl import (
    DIRECT_VALIDATOR_QVL_DIGEST,
    SubprocessQuoteVerifier,
)
from cathedral_thin.independent_runtime.tdx_measurement import (
    MEASUREMENT_CONTRACT_QVL_DIGEST,
    POLICY_SCHEMA,
    TDX_MEASUREMENT_POLICY_ENV,
    TdxMeasurementPolicyError,
    load_tdx_measurement_policy,
    reference_image_measurement,
    reference_measurement,
)

INTEL_COLLATERAL = "https://api.trustedservices.intel.com/sgx/certification/v4/"
GOOD = "tdx-measurement-sha256:" + "1" * 64
BAD = "tdx-measurement-sha256:" + "2" * 64


def _policy_file(tmp_path, document, *, mode=0o644, name="tdx-policy.json"):
    path = tmp_path / name
    path.write_text(document if isinstance(document, str) else json.dumps(document))
    path.chmod(mode)
    return path


def _policy(tmp_path, mode, allowed=(GOOD,)):
    return load_tdx_measurement_policy(
        _policy_file(
            tmp_path,
            {
                "schema": POLICY_SCHEMA,
                "mode": mode,
                "allowed_measurements": sorted(allowed),
            },
            name=f"{mode}.json",
        )
    )


# -- the policy file ---------------------------------------------------------


def test_a_valid_policy_loads_with_its_digest(tmp_path):
    policy = _policy(tmp_path, "enforce", (BAD, GOOD))
    assert policy.enforced and policy.admits(GOOD) and policy.admits(BAD)
    assert not policy.admits(None) and not policy.admits(
        "tdx-measurement-sha256:" + "3" * 64
    )
    assert policy.digest.startswith("sha256:") and len(policy.digest) == 71
    shadow = _policy(tmp_path, "shadow", ())
    assert not shadow.enforced and not shadow.admits(GOOD)


@pytest.mark.parametrize(
    "document",
    [
        {"schema": "other", "mode": "shadow", "allowed_measurements": []},
        {"schema": POLICY_SCHEMA, "mode": "warn", "allowed_measurements": []},
        {"schema": POLICY_SCHEMA, "mode": "enforce", "allowed_measurements": []},
        {
            "schema": POLICY_SCHEMA,
            "mode": "shadow",
            "allowed_measurements": [BAD, GOOD],
        },
        {
            "schema": POLICY_SCHEMA,
            "mode": "shadow",
            "allowed_measurements": [GOOD, GOOD],
        },
        {"schema": POLICY_SCHEMA, "mode": "shadow", "allowed_measurements": ["1" * 64]},
        {
            "schema": POLICY_SCHEMA,
            "mode": "shadow",
            "allowed_measurements": [GOOD.upper()],
        },
        {"schema": POLICY_SCHEMA, "mode": "shadow", "allowed_measurements": GOOD},
        {
            "schema": POLICY_SCHEMA,
            "mode": "shadow",
            "allowed_measurements": [],
            "extra": 1,
        },
        {"schema": POLICY_SCHEMA, "mode": "shadow"},
        {"schema": POLICY_SCHEMA, "mode": "shadow", "allowed_measurements": [GOOD, 1]},
        # fullmatch, not match: trailing characters after a valid entry
        {
            "schema": POLICY_SCHEMA,
            "mode": "shadow",
            "allowed_measurements": [GOOD + "junk"],
        },
        {
            "schema": POLICY_SCHEMA,
            "mode": "shadow",
            "allowed_measurements": [GOOD + "\n"],
        },
        '{"schema": "x", "schema": "y"}',
        "not json",
    ],
)
def test_a_malformed_policy_is_refused(tmp_path, document):
    with pytest.raises(TdxMeasurementPolicyError):
        load_tdx_measurement_policy(_policy_file(tmp_path, document))


def test_a_writable_or_linked_policy_is_refused(tmp_path):
    ok = {"schema": POLICY_SCHEMA, "mode": "shadow", "allowed_measurements": [GOOD]}
    with pytest.raises(TdxMeasurementPolicyError, match="writable"):
        load_tdx_measurement_policy(_policy_file(tmp_path, ok, mode=0o664))
    target = _policy_file(tmp_path, ok, name="real.json")
    link = tmp_path / "link.json"
    os.symlink(target, link)
    with pytest.raises(TdxMeasurementPolicyError, match="readable regular file"):
        load_tdx_measurement_policy(link)
    with pytest.raises(TdxMeasurementPolicyError):
        load_tdx_measurement_policy(tmp_path / "missing.json")


def test_a_policy_owned_by_another_user_is_refused(tmp_path, monkeypatch):
    ok = {"schema": POLICY_SCHEMA, "mode": "shadow", "allowed_measurements": [GOOD]}
    path = _policy_file(tmp_path, ok)
    owner = path.stat().st_uid
    if owner == 0:
        pytest.skip("a root-owned file is always an allowed owner")
    assert load_tdx_measurement_policy(path).admits(GOOD)
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
    with pytest.raises(TdxMeasurementPolicyError, match="root or operator owned"):
        load_tdx_measurement_policy(path)


@pytest.mark.parametrize(
    ("load", "error"),
    [
        (load_tdx_measurement_policy, TdxMeasurementPolicyError),
        (snp_production.load_snp_policy, snp_production.SnpProductionError),
    ],
)
def test_a_fifo_at_the_policy_path_is_refused_without_blocking(tmp_path, load, error):
    # Round-3 review: without O_NONBLOCK the open blocked until TimeoutStartSec.
    fifo = tmp_path / "policy.json"
    os.mkfifo(fifo, 0o600)
    outcome: list[BaseException] = []
    worker = threading.Thread(
        target=lambda: outcome.append(pytest.raises(error, load, fifo).value),
        daemon=True,
    )
    worker.start()
    worker.join(5)
    if worker.is_alive():
        # Unblock the stuck open so the test process can exit.
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail("loading a FIFO policy blocked")
    assert len(outcome) == 1 and isinstance(outcome[0], error)


# -- the measurement reaches the scorer -----------------------------------------


def test_the_pinned_verifier_output_carries_the_measurement(tmp_path):
    stable = "tdx-platform-sha256:" + "a" * 64
    claims = {
        "intel_verified": True,
        "report_data_match": True,
        "stable_platform_id": stable,
        "platform_id": stable,
        "platform_identity_kind": "stable",
        "platform_identity_verified": True,
        "claims_bound_to_quote": True,
        "measurement": GOOD,
    }
    verifier = SubprocessQuoteVerifier(fd_verifier_script(tmp_path, claims))
    result = verifier.verify_with_identity(b"quote", expected_report_data=b"r" * 64)
    assert result.measurement == GOOD and result.platform_identity_verified

    prefix = "tdx-measurement-sha256:"
    for junk in (
        "sha256:" + "1" * 64,
        GOOD.upper(),
        prefix + "A" * 64,
        prefix + "1" * 63,
        prefix + "1" * 65,
        GOOD + "\x00",
        GOOD + "\n",
        " " + GOOD,
        prefix + "\u0661" * 64,  # Arabic-Indic digits
        prefix + "\uff41" * 64,  # fullwidth letters
        7,
        None,
        [GOOD],
    ):
        claims["measurement"] = junk
        verifier = SubprocessQuoteVerifier(fd_verifier_script(tmp_path, claims))
        result = verifier.verify_with_identity(b"quote", expected_report_data=b"r" * 64)
        assert result.verdict is QuoteVerdict.PASS and result.measurement is None


def fd_verifier_script(tmp_path, claims):
    path = tmp_path / "qvl-fixture"
    path.write_text(
        "#!/usr/bin/env python3\nimport json\n"
        f"print(json.dumps({claims!r}, sort_keys=True))\n",
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def test_the_adapter_keeps_the_measurement():
    class Verifier:
        def verify(self, quote, *, expected_report_data):
            return QuoteVerdict.PASS

        def verify_with_identity(
            self, quote, *, expected_report_data, deadline_monotonic=None
        ):
            return QuoteIdentityVerdict(
                QuoteVerdict.PASS, "tdx-platform-sha256:" + "b" * 64, True, GOOD
            )

    adapter = ComputeAdapter(
        Verifier(), collateral_base_url=INTEL_COLLATERAL, qvl_digest="a" * 64
    )
    result = adapter.verify_quote_with_identity(
        b"q" * 64, expected_report_data=b"r" * 64
    )
    assert result.measurement == GOOD and tdx_measurement_or_none(BAD) == BAD


# -- who gets paid ----------------------------------------------------------------

FLEET = fd.BOB_FLEET[:2]  # marker 1 runs an allowed image, marker 2 does not


class _MeasuringVerifier(fd._Verifier):
    def verify_with_identity(
        self, quote, *, expected_report_data, deadline_monotonic=None
    ):
        marker = quote[-1]
        return QuoteIdentityVerdict(
            QuoteVerdict.PASS,
            "tdx-platform-sha256:" + f"{marker:064x}",
            True,
            {1: GOOD, 3: None}.get(marker, BAD),  # 3: a PASS with no measurement
        )


def _round(monkeypatch, tdx_policy, markers=(1, 2)):
    fd._install_miners(
        monkeypatch,
        fleets={fd.BOB: FLEET},
        markers=dict(zip(FLEET, markers)),
        evidence_cost=lambda _endpoint: None,
        fleet_cost=lambda: None,
    )
    adapter = ComputeAdapter(
        _MeasuringVerifier(lambda _marker: None),
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest="a" * 64,
    )
    result = fleet_score.score_multicompute_round(
        axons=(fd.BOB_AXON,),
        keypair=fd._keypair(),
        anchor_hash=fd.WINDOW,
        verifier_adapter=adapter,
        snp_verifier=None,
        tdx_policy=tdx_policy,
        cycle_deadline_monotonic=time.monotonic() + 60.0,
        netuid=fd.NETUID,
    )
    snapshot = fd.FinalizedMetagraphSnapshot(
        block_number=100,
        block_hash=fd.WINDOW,
        validator_uid=7,
        validator_hotkey=fd.CANARY_HOTKEY,
        miners=(fd.BOB_AXON,),
        skipped_axons={},
        netuid=fd.NETUID,
    )
    plan = direct_validator.build_direct_plan(snapshot, result, tdx_policy=tdx_policy)
    return fd._rows_by_endpoint(result), plan, result


def test_without_a_policy_every_genuine_td_is_paid_and_rows_are_unchanged(monkeypatch):
    rows, plan, _result = _round(monkeypatch, None)
    assert plan.raw_scores == ((fd.BOB_AXON.uid, 2),)
    assert all("measurement" not in rows[endpoint] for endpoint in FLEET)


def test_shadow_records_measurements_and_pays_as_before(monkeypatch, tmp_path):
    policy = _policy(tmp_path, "shadow")
    rows, plan, _result = _round(monkeypatch, policy)
    assert plan.raw_scores == ((fd.BOB_AXON.uid, 2),)
    assert (rows[FLEET[0]]["measurement"], rows[FLEET[0]]["measurement_allowed"]) == (
        GOOD,
        True,
    )
    assert (rows[FLEET[1]]["measurement"], rows[FLEET[1]]["measurement_allowed"]) == (
        BAD,
        False,
    )
    assert rows[FLEET[1]]["verdict"] == QuoteVerdict.PASS.value
    assert {rows[e]["measurement_policy_mode"] for e in FLEET} == {"shadow"}
    assert {rows[e]["measurement_policy_digest"] for e in FLEET} == {policy.digest}


def test_enforce_pays_only_listed_measurements(monkeypatch, tmp_path):
    rows, plan, _result = _round(monkeypatch, _policy(tmp_path, "enforce"))
    assert plan.raw_scores == ((fd.BOB_AXON.uid, 1),)
    assert plan.machine_ids_by_uid == (
        (fd.BOB_AXON.uid, (rows[FLEET[0]]["machine_id"],)),
    )
    unlisted = rows[FLEET[1]]
    assert unlisted["verdict"] == QuoteVerdict.FAIL.value
    assert unlisted["identity_error"] == "tdx_measurement_not_allowed"
    assert "machine_id" not in unlisted


def test_the_policy_comes_from_the_environment_not_a_flag(monkeypatch, tmp_path):
    required = [
        "--expected-hotkey",
        "5x",
        "--qvl",
        "q",
        "--snp-policy",
        "p",
        "--snpguest",
        "g",
    ]
    with pytest.raises(SystemExit):
        # An unknown flag is what an older runtime would exit on after a rollback.
        direct_validator._parser().parse_args(
            [*required, "--tdx-measurement-policy", "x"]
        )

    monkeypatch.delenv(TDX_MEASUREMENT_POLICY_ENV, raising=False)
    assert direct_validator._tdx_measurement_policy_from_environment() is None
    monkeypatch.setenv(TDX_MEASUREMENT_POLICY_ENV, "  ")
    assert direct_validator._tdx_measurement_policy_from_environment() is None

    path = _policy_file(
        tmp_path,
        {"schema": POLICY_SCHEMA, "mode": "shadow", "allowed_measurements": [GOOD]},
    )
    monkeypatch.setenv(TDX_MEASUREMENT_POLICY_ENV, str(path))
    policy = direct_validator._tdx_measurement_policy_from_environment()
    assert policy is not None and policy.mode == "shadow" and policy.admits(GOOD)

    monkeypatch.setenv(TDX_MEASUREMENT_POLICY_ENV, str(tmp_path / "missing.json"))
    with pytest.raises(SystemExit, match="TDX measurement policy refused"):
        direct_validator._tdx_measurement_policy_from_environment()


def test_enforce_fails_a_pass_without_a_measurement(monkeypatch, tmp_path):
    rows, plan, result = _round(
        monkeypatch, _policy(tmp_path, "enforce"), markers=(1, 3)
    )
    assert plan.raw_scores == ((fd.BOB_AXON.uid, 1),)
    assert rows[FLEET[1]]["measurement"] is None
    assert rows[FLEET[1]]["identity_error"] == "tdx_measurement_not_allowed"
    # A refused image is a plain FAIL: it neither counts as QVL INFRA nor aborts the cycle.
    assert result.qvl_infra_count == 0 and result.pass_count == 1


def test_enforce_excludes_the_fleet_an_unlisted_primary_vouches_for(
    monkeypatch, tmp_path
):
    # The primary serves the fleet list; an unadmitted image does not vouch for others.
    # With nobody verified the direct plan refuses, so this cycle writes nothing.
    with pytest.raises(DirectValidatorError, match="no miner has a verified machine"):
        _round(monkeypatch, _policy(tmp_path, "enforce"), markers=(2, 1))
    fd._install_miners(
        monkeypatch,
        fleets={fd.BOB: FLEET},
        markers=dict(zip(FLEET, (2, 1))),
        evidence_cost=lambda _endpoint: None,
        fleet_cost=lambda: None,
    )
    result = fleet_score.score_multicompute_round(
        axons=(fd.BOB_AXON,),
        keypair=fd._keypair(),
        anchor_hash=fd.WINDOW,
        verifier_adapter=ComputeAdapter(
            _MeasuringVerifier(lambda _marker: None),
            collateral_base_url=INTEL_COLLATERAL,
            qvl_digest="a" * 64,
        ),
        snp_verifier=None,
        tdx_policy=_policy(tmp_path, "enforce"),
        cycle_deadline_monotonic=time.monotonic() + 60.0,
        netuid=fd.NETUID,
    )
    rows = fd._rows_by_endpoint(result)
    assert rows[FLEET[0]]["identity_error"] == "tdx_measurement_not_allowed"
    assert result.verified_units == {} and result.qvl_infra_count == 0


# -- what the operator sees, and what the evidence binds ----------------------


def test_startup_says_which_policy_applies(monkeypatch, tmp_path, capsys):
    env_file = tmp_path / "direct-tdx-measurement.env"
    monkeypatch.setattr(tdx_measurement, "TDX_MEASUREMENT_ENV_FILE", env_file)
    monkeypatch.delenv(TDX_MEASUREMENT_POLICY_ENV, raising=False)
    assert direct_validator._tdx_measurement_policy_from_environment() is None
    assert capsys.readouterr().out == ""  # no policy, no env file: nothing new

    # The env file is installed but the unit (an older bootstrap's) does not
    # read it: say so, since no policy applies.
    env_file.write_text(f"{TDX_MEASUREMENT_POLICY_ENV}=/etc/x.json\n")
    assert direct_validator._tdx_measurement_policy_from_environment() is None
    event = json.loads(capsys.readouterr().out)["tdx_measurement_policy"]
    assert event["status"] == "NOT_LOADED" and str(env_file) in event["warning"]

    # The unit does read the file, and the file sets the variable to empty: a
    # deliberate "no policy", not a unit that misses the file.
    monkeypatch.setenv(TDX_MEASUREMENT_POLICY_ENV, "")
    assert direct_validator._tdx_measurement_policy_from_environment() is None
    assert capsys.readouterr().out == ""

    policy_path = _policy_file(
        tmp_path,
        {"schema": POLICY_SCHEMA, "mode": "shadow", "allowed_measurements": [GOOD]},
    )
    monkeypatch.setenv(TDX_MEASUREMENT_POLICY_ENV, str(policy_path))
    policy = direct_validator._tdx_measurement_policy_from_environment()
    assert json.loads(capsys.readouterr().out) == {
        "tdx_measurement_policy": {
            "status": "LOADED",
            "mode": "shadow",
            "digest": policy.digest,
            "allowed_measurements": 1,
            "source": "unrecorded",  # no .source.json beside it
            "registry_release": None,
            "registry_digest": None,
            "registry_valid_until": None,
        }
    }


# -- the signed list release it mirrors (<policy>.source.json) -----------------

REGISTRY_DIGEST = "sha256:" + "ab" * 32


def _exported(tmp_path, *, valid_until="2099-01-01T00:00:00Z", release=7, **changes):
    """A policy file and its record, as cathedral-sandbox #249's
    ``policy-registry export-measurement-policy`` writes them."""

    document = {
        "schema": POLICY_SCHEMA,
        "mode": "shadow",
        "allowed_measurements": [GOOD],
    }
    raw = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("ascii")
    policy_path = tmp_path / "tdx-measurement-policy.json"
    policy_path.write_bytes(raw)
    policy_path.chmod(0o644)
    source = {
        "schema": tdx_measurement.MIRROR_SOURCE_SCHEMA,
        "kind": "tdx",
        "mode": "shadow",
        "scope": "box",
        "policy_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "registry_release": release,
        "registry_digest": REGISTRY_DIGEST,
        "registry_signing_key_id": "owner-2026",
        "registry_generated_at": "2026-09-29T11:00:00Z",
        "registry_valid_until": valid_until,
        **changes,
    }
    source_path = tmp_path / "tdx-measurement-policy.json.source.json"
    source_path.write_text(json.dumps(source, indent=2, sort_keys=True) + "\n")
    source_path.chmod(0o644)
    return policy_path, source_path


def _loaded(monkeypatch, capsys, policy_path):
    monkeypatch.setenv(TDX_MEASUREMENT_POLICY_ENV, str(policy_path))
    policy = direct_validator._tdx_measurement_policy_from_environment()
    event = json.loads(capsys.readouterr().out)["tdx_measurement_policy"]
    assert event["status"] == "LOADED"
    return policy, event


def test_loaded_names_the_signed_release_the_policy_mirrors(
    monkeypatch, tmp_path, capsys
):
    policy_path, _source = _exported(tmp_path)
    policy, event = _loaded(monkeypatch, capsys, policy_path)
    assert event == {
        "status": "LOADED",
        "mode": "shadow",
        "digest": policy.digest,
        "allowed_measurements": 1,
        "source": "recorded",
        "registry_release": 7,
        "registry_digest": REGISTRY_DIGEST,
        "registry_valid_until": "2099-01-01T00:00:00Z",
    }
    assert policy.registry_release == 7


def test_a_record_for_another_policy_file_warns(monkeypatch, tmp_path, capsys):
    policy_path, _source = _exported(tmp_path, policy_digest="sha256:" + "cd" * 32)
    policy, event = _loaded(monkeypatch, capsys, policy_path)
    assert event["source"] == "recorded" and event["registry_release"] == 7
    assert "policy_digest" in event["warning"] and policy.digest in event["warning"]
    assert "export-measurement-policy" in event["warning"]
    # The release does not describe this file, so the cycle summary omits it.
    assert policy.registry_release is None


def test_an_expired_release_warns(monkeypatch, tmp_path, capsys):
    policy_path, _source = _exported(tmp_path, valid_until="2026-01-01T00:00:00Z")
    policy, event = _loaded(monkeypatch, capsys, policy_path)
    assert event["source"] == "recorded" and event["registry_release"] == 7
    assert "expired at 2026-01-01T00:00:00Z" in event["warning"]
    assert "policy_digest" not in event["warning"]
    assert policy.registry_release == 7  # still the release this file came from
    fresh = tdx_measurement.read_policy_source(
        policy_path, policy, now=datetime(2025, 12, 31, tzinfo=UTC)
    )
    assert fresh.warnings == () and fresh.matches
    # It expires at valid_until itself, not a second later.
    for now, expired in (
        (datetime(2025, 12, 31, 23, 59, 59, tzinfo=UTC), False),
        (datetime(2026, 1, 1, tzinfo=UTC), True),
    ):
        edge = tdx_measurement.read_policy_source(policy_path, policy, now=now)
        assert bool(edge.warnings) is expired


def _oversized(source_path):
    source_path.write_bytes(b" " * (tdx_measurement.MAX_SOURCE_BYTES + 1))


def _fifo(source_path):
    source_path.unlink()
    os.mkfifo(source_path, 0o644)


def _symlink(source_path):
    target = source_path.with_name("elsewhere.json")
    source_path.rename(target)
    source_path.symlink_to(target)


@pytest.mark.parametrize(
    "spoil",
    [
        lambda path: path.write_text("{not json"),
        lambda path: path.write_text('{"schema": "x", "schema": "x"}'),
        lambda path: path.write_text("[]"),
        lambda path: path.write_text(json.dumps({"schema": "another_record_v1"})),
        lambda path: path.write_text(
            path.read_text().replace('"registry_release": 7', '"registry_release": "7"')
        ),
        lambda path: path.write_text(
            path.read_text().replace(
                '"registry_release": 7', '"registry_release": true'
            )
        ),
        lambda path: path.write_text(
            path.read_text().replace(REGISTRY_DIGEST, "sha256:short")
        ),
        lambda path: path.write_text(
            path.read_text().replace("2099-01-01T00:00:00Z", "2099-13-01T00:00:00Z")
        ),
        lambda path: path.write_text(
            path.read_text().replace('"registry_release": 7', '"registry_release": -1')
        ),
        lambda path: path.write_text(
            path.read_text().replace(
                '"registry_release": 7', '"registry_release": ' + "9" * 5000
            )
        ),
        lambda path: path.write_bytes(b"\xff\xfe"),
        lambda path: path.write_bytes(b"[" * tdx_measurement.MAX_SOURCE_BYTES),
        lambda path: path.write_bytes(b""),
        _oversized,
        lambda path: path.chmod(0o666),
        _fifo,
        _symlink,
    ],
    ids=[
        "not-json",
        "repeated-key",
        "not-object",
        "schema",
        "release-text",
        "release-bool",
        "release-negative",
        "release-too-many-digits",
        "digest",
        "valid-until",
        "not-utf8",
        "deeply-nested",
        "empty",
        "oversized",
        "world-writable",
        "fifo",
        "symlink",
    ],
)
def test_a_broken_record_is_ignored_with_a_warning(
    monkeypatch, tmp_path, capsys, spoil
):
    policy_path, source_path = _exported(tmp_path)
    spoil(source_path)
    outcome: list = []
    worker = threading.Thread(
        target=lambda: outcome.append(_loaded(monkeypatch, capsys, policy_path)),
        daemon=True,
    )
    worker.start()
    worker.join(5)
    if worker.is_alive():
        os.close(os.open(source_path, os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail("reading the source record blocked")
    policy, event = outcome[0]
    assert event["source"] == "unreadable"
    assert event["registry_release"] is None and event["registry_digest"] is None
    assert str(source_path) in event["warning"] and "ignored" in event["warning"]
    assert policy.mode == "shadow" and policy.registry_release is None


def test_the_record_does_not_change_the_policy(tmp_path):
    policy_path, source_path = _exported(tmp_path)
    with_record = load_tdx_measurement_policy(policy_path)
    source_path.write_text("{not json")
    broken = load_tdx_measurement_policy(policy_path)
    source_path.unlink()
    without = load_tdx_measurement_policy(policy_path)
    assert with_record == broken == without
    assert with_record.digest == without.digest
    assert with_record.registry_release is None  # only startup attaches it
    # The loader stays strict: the record's keys cannot go in the policy file.
    document = json.loads(policy_path.read_text())
    document["registry_release"] = 7
    policy_path.write_text(json.dumps(document))
    with pytest.raises(TdxMeasurementPolicyError, match="exactly"):
        load_tdx_measurement_policy(policy_path)


def test_the_release_reaches_the_summary_but_not_the_evidence(monkeypatch, tmp_path):
    documents = _evidence_documents(monkeypatch)
    policy = _policy(tmp_path, "shadow")
    _rows, plan, result = _round(monkeypatch, policy)
    mirrored = dataclasses.replace(policy, registry_release=7)
    _rows, mirrored_plan, mirrored_result = _round(monkeypatch, mirrored)
    assert documents[-1] == documents[-2]
    assert mirrored_plan.evidence_digest == plan.evidence_digest
    summary = direct_validator._evidence_cycle_summary(
        SimpleNamespace(skipped_axons={}), result, plan, tdx_policy=policy
    )["tdx_measurement"]
    assert "registry_release" not in summary  # unrecorded: exactly as before
    mirrored_summary = direct_validator._evidence_cycle_summary(
        SimpleNamespace(skipped_axons={}),
        mirrored_result,
        mirrored_plan,
        tdx_policy=mirrored,
    )["tdx_measurement"]
    assert mirrored_summary == {**summary, "registry_release": 7}


def _evidence_documents(monkeypatch):
    documents: list[dict] = []
    real = direct_validator.canonical_document_bytes

    def capture(document):
        if document.get("schema") == "cathedral_direct_validator_evidence_v1":
            documents.append(document)
        return real(document)

    monkeypatch.setattr(direct_validator, "canonical_document_bytes", capture)
    return documents


def test_the_evidence_document_binds_the_policy_only_when_one_is_set(
    monkeypatch, tmp_path
):
    documents = _evidence_documents(monkeypatch)
    _round(monkeypatch, None)
    assert "tdx_measurement_policy" not in documents[-1]
    policy = _policy(tmp_path, "enforce", (BAD, GOOD))
    _round(monkeypatch, policy)
    assert documents[-1]["tdx_measurement_policy"] == {
        "mode": "enforce",
        "digest": policy.digest,
    }


def test_the_cycle_event_lists_what_the_policy_saw(monkeypatch, tmp_path):
    # Review of #256: shadow mode must show the unlisted measurement to the
    # operator, in the event run_direct_cycle prints.
    policy = _policy(tmp_path, "shadow")
    snapshot = fd.FinalizedMetagraphSnapshot(
        block_number=100,
        block_hash=fd.WINDOW,
        validator_uid=7,
        validator_hotkey=fd.CANARY_HOTKEY,
        miners=(fd.BOB_AXON,),
        skipped_axons={},
        netuid=fd.NETUID,
    )
    fd._install_miners(
        monkeypatch,
        fleets={fd.BOB: FLEET},
        markers=dict(zip(FLEET, (1, 2))),
        evidence_cost=lambda _endpoint: None,
        fleet_cost=lambda: None,
    )
    adapter = ComputeAdapter(
        _MeasuringVerifier(lambda _marker: None),
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest="a" * 64,
    )
    real_score = fleet_score.score_multicompute_round
    seen: dict = {}

    def score(**kwargs):
        seen.update(kwargs)
        return real_score(**{**kwargs, "verifier_adapter": adapter})

    monkeypatch.setattr(
        direct_validator, "finalized_serving_miners_snapshot", lambda *_a: snapshot
    )
    monkeypatch.setattr(direct_validator, "score_multicompute_round", score)
    receipt = SimpleNamespace(
        status=STATUS_CONFIRMED, as_document=lambda: {"status": STATUS_CONFIRMED}
    )
    event = direct_validator.run_direct_cycle(
        subtensor=object(),
        keypair=fd._keypair(),
        verifier_adapter=SimpleNamespace(qvl_digest=DIRECT_VALIDATOR_QVL_DIGEST),
        writer=SimpleNamespace(recover=lambda: None, submit=lambda *_a, **_k: receipt),
        report_recovery=lambda _event: None,
        tdx_policy=policy,
        netuid=fd.NETUID,
    )
    assert seen["tdx_policy"] is policy
    assert event["raw_scores"] == [[fd.BOB_AXON.uid, 2]]  # shadow pays as before
    assert json.loads(json.dumps(event["evidence_summary"]["tdx_measurement"])) == {
        "mode": "shadow",
        "policy_digest": policy.digest,
        "machines": 2,
        "allowed_machines": 1,
        "missing_measurement": 0,
        "observed": {
            BAD: {"allowed": False, "machines": 1},
            GOOD: {"allowed": True, "machines": 1},
        },
        "observed_omitted": 0,
    }


def test_the_summary_counts_refused_and_missing_and_stays_bounded(
    monkeypatch, tmp_path
):
    policy = _policy(tmp_path, "enforce")
    _rows, plan, result = _round(monkeypatch, policy, markers=(1, 3))
    summary = direct_validator._evidence_cycle_summary(
        SimpleNamespace(skipped_axons={}), result, plan, tdx_policy=policy
    )["tdx_measurement"]
    assert summary["machines"] == 2 and summary["missing_measurement"] == 1
    assert summary["observed"] == {GOOD: {"allowed": True, "machines": 1}}
    _rows, plan, result = _round(monkeypatch, policy, markers=(1, 2))
    refused = direct_validator._evidence_cycle_summary(
        SimpleNamespace(skipped_axons={}), result, plan, tdx_policy=policy
    )["tdx_measurement"]
    assert refused["observed"][BAD] == {"allowed": False, "machines": 1}

    many = [
        {
            "measurement_policy_digest": policy.digest,
            "measurement": f"tdx-measurement-sha256:{index:064x}",
            "measurement_allowed": False,
        }
        for index in range(direct_validator.MAX_REPORTED_TDX_MEASUREMENTS + 5)
    ]
    many += [dict(many[0]), {"measurement_policy_digest": "sha256:other"}]
    bounded = direct_validator._tdx_measurement_summary(
        SimpleNamespace(rows=many), policy
    )
    assert len(bounded["observed"]) == direct_validator.MAX_REPORTED_TDX_MEASUREMENTS
    assert bounded["observed_omitted"] == 5
    assert bounded["machines"] == direct_validator.MAX_REPORTED_TDX_MEASUREMENTS + 6
    # the most common is kept first
    assert bounded["observed"][many[0]["measurement"]]["machines"] == 2


def test_without_a_policy_the_summary_is_unchanged(monkeypatch):
    _rows, plan, result = _round(monkeypatch, None)
    summary = direct_validator._evidence_cycle_summary(
        SimpleNamespace(skipped_axons={}), result, plan
    )
    assert set(summary) == {"phase_timings_ms", "exclusions"}


# -- the verifier's formula -----------------------------------------------------


def test_the_measurement_formula_matches_the_verifiers_contract_vector():
    # cathedral-sandbox cmd/cathedral-tdx-verifier/main_test.go,
    # TestMeasurementMatchesPythonContractVector.
    fields = (
        b"T" * 8,
        b"X" * 8,
        b"M" * 48,
        b"C" * 48,
        b"O" * 48,
        b"o" * 48,
        b"0" * 48,
        b"1" * 48,
        b"2" * 48,
        b"3" * 48,
    )
    assert reference_measurement(fields) == (
        "tdx-measurement-sha256:"
        "b3cf84af07e6fb79dce23c46eef78eb627b39989814fcf1b6ea42fd93fea1585"
    )
    with pytest.raises(ValueError):
        reference_measurement(fields[:-1])


def test_moving_the_verifier_pin_requires_rechecking_the_measurement():
    # Every allowlist entry depends on the pinned verifier computing the same
    # measurement. A new pin (for example with cathedral-sandbox#238) must be
    # checked against the contract vector or a known quote, then
    # MEASUREMENT_CONTRACT_QVL_DIGEST moved with it.
    assert MEASUREMENT_CONTRACT_QVL_DIGEST == DIRECT_VALIDATOR_QVL_DIGEST


# -- the v2 image identity (cathedral-sandbox #265) ----------------------------

IMAGE = "tdx-image-sha256:" + "3" * 64
OTHER_IMAGE = "tdx-image-sha256:" + "4" * 64


def test_a_policy_may_list_image_identities(tmp_path):
    policy = _policy(tmp_path, "enforce", (IMAGE, GOOD))
    assert policy.allowed_measurements == frozenset({IMAGE, GOOD})
    # v1 or v2 admits; neither does not.
    assert policy.admits(GOOD) and policy.admits(BAD, IMAGE)
    assert policy.admits(None, IMAGE)
    assert not policy.admits(BAD, OTHER_IMAGE) and not policy.admits(None, None)
    for junk in (IMAGE.upper(), IMAGE + "0", "tdx-image-sha256:" + "3" * 63):
        with pytest.raises(TdxMeasurementPolicyError):
            load_tdx_measurement_policy(
                _policy_file(
                    tmp_path,
                    {"schema": POLICY_SCHEMA, "mode": "shadow", "allowed_measurements": [junk]},
                )
            )


def test_the_pinned_verifier_output_carries_the_image_identity(tmp_path):
    stable = "tdx-platform-sha256:" + "a" * 64
    claims = {
        "intel_verified": True,
        "report_data_match": True,
        "stable_platform_id": stable,
        "platform_id": stable,
        "platform_identity_kind": "stable",
        "platform_identity_verified": True,
        "claims_bound_to_quote": True,
        "measurement": GOOD,
        "image_measurement": IMAGE,
    }
    verifier = SubprocessQuoteVerifier(fd_verifier_script(tmp_path, claims))
    result = verifier.verify_with_identity(b"quote", expected_report_data=b"r" * 64)
    assert (result.measurement, result.image_measurement) == (GOOD, IMAGE)
    # A verifier from before the v2 identity, or a malformed value: None.
    for junk in (None, IMAGE.upper(), GOOD, IMAGE + "\n", 7):
        if junk is None:
            claims.pop("image_measurement", None)
        else:
            claims["image_measurement"] = junk
        verifier = SubprocessQuoteVerifier(fd_verifier_script(tmp_path, claims))
        result = verifier.verify_with_identity(b"quote", expected_report_data=b"r" * 64)
        assert result.verdict is QuoteVerdict.PASS and result.image_measurement is None
        assert result.measurement == GOOD


def test_the_adapter_keeps_the_image_identity():
    class Verifier:
        def verify(self, quote, *, expected_report_data):
            return QuoteVerdict.PASS

        def verify_with_identity(
            self, quote, *, expected_report_data, deadline_monotonic=None
        ):
            return QuoteIdentityVerdict(
                QuoteVerdict.PASS, "tdx-platform-sha256:" + "b" * 64, True, GOOD, IMAGE
            )

    adapter = ComputeAdapter(
        Verifier(), collateral_base_url=INTEL_COLLATERAL, qvl_digest="a" * 64
    )
    result = adapter.verify_quote_with_identity(
        b"q" * 64, expected_report_data=b"r" * 64
    )
    assert (result.measurement, result.image_measurement) == (GOOD, IMAGE)


class _ImageVerifier(fd._Verifier):
    """Two VMs from one image: GCP sets MROWNER per VM, so their v1 values
    differ (neither listed) while their v2 image identity is the same."""

    def verify_with_identity(
        self, quote, *, expected_report_data, deadline_monotonic=None
    ):
        marker = quote[-1]
        return QuoteIdentityVerdict(
            QuoteVerdict.PASS,
            "tdx-platform-sha256:" + f"{marker:064x}",
            True,
            "tdx-measurement-sha256:" + f"{marker + 16:064x}",
            {1: IMAGE, 2: IMAGE}.get(marker, OTHER_IMAGE),
        )


def test_enforce_pays_every_vm_of_a_listed_image(monkeypatch, tmp_path):
    monkeypatch.setattr(
        _MeasuringVerifier, "verify_with_identity", _ImageVerifier.verify_with_identity
    )
    policy = _policy(tmp_path, "enforce", (IMAGE,))
    rows, plan, result = _round(monkeypatch, policy)
    assert plan.raw_scores == ((fd.BOB_AXON.uid, 2),)
    for endpoint in FLEET:
        assert rows[endpoint]["measurement_allowed"] is True
        assert rows[endpoint]["image_measurement"] == IMAGE
        assert rows[endpoint]["verdict"] == QuoteVerdict.PASS.value
    summary = direct_validator._tdx_measurement_summary(result, policy)
    assert summary["observed_images"] == {IMAGE: {"allowed": True, "machines": 2}}
    assert all(entry["allowed"] for entry in summary["observed"].values())


def test_enforce_refuses_an_unlisted_image(monkeypatch, tmp_path):
    monkeypatch.setattr(
        _MeasuringVerifier, "verify_with_identity", _ImageVerifier.verify_with_identity
    )
    # Marker 1 is listed by its v1 value; marker 2 has only its image, unlisted.
    first_v1 = "tdx-measurement-sha256:" + f"{1 + 16:064x}"
    rows, plan, _result = _round(
        monkeypatch, _policy(tmp_path, "enforce", (first_v1, OTHER_IMAGE))
    )
    assert plan.raw_scores == ((fd.BOB_AXON.uid, 1),)
    assert rows[FLEET[0]]["measurement_allowed"] is True
    assert rows[FLEET[1]]["verdict"] == QuoteVerdict.FAIL.value
    assert rows[FLEET[1]]["identity_error"] == "tdx_measurement_not_allowed"


def test_rows_have_no_image_identity_when_the_verifier_emits_none(monkeypatch, tmp_path):
    rows, _plan, result = _round(monkeypatch, _policy(tmp_path, "shadow"))
    assert all("image_measurement" not in rows[e] for e in FLEET)
    summary = direct_validator._tdx_measurement_summary(result, _policy(tmp_path, "shadow"))
    assert "observed_images" not in summary


def test_the_image_formula_matches_the_verifiers_contract_vector():
    # cathedral-sandbox cmd/cathedral-tdx-verifier/image_identity_test.go,
    # TestImageMeasurementMatchesPythonContractVector.
    fields = (b"T" * 8, b"X" * 8, b"M" * 48, b"0" * 48, b"1" * 48, b"2" * 48, b"3" * 48)
    assert reference_image_measurement(fields) == (
        "tdx-image-sha256:"
        "5c1e249b50fa545864ca0f4e3f58c7c40114fb4afa7e59ac79714f9c5bb3856c"
    )
    with pytest.raises(ValueError):
        reference_image_measurement(fields[:-1])
