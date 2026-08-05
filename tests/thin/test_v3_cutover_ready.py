"""Every v3-cutover check must FAIL when the thing it names is not true.

A preflight that cannot fail is worse than no preflight: it converts "we think
it is ready" into "it says it is ready" while proving nothing. So these tests
drive each of the seven checks to its failure verdict with injected facts, and
they pay particular attention to the three that were mis-stated in the field:

  * the composer-IDENTITY check, because the preflight once resolved the
    publisher from a unit-name default, landed on a legacy process that writes
    its own unscoped `latest` row, and reported that decoy's state as fact --
    declaring the v3 composer absent and the producer hotkey unset when the
    real composer had both. Silently probing the wrong process and presenting
    its state confidently is the worst failure mode this script has;

  * the dev-key check, because //Alice was found configured on the live
    publisher, and the intake's audience-scoped epoch fence makes a single
    accepted epoch under it permanent; and

  * the composer-reachability check, because "the file is on disk" is NOT
    "the running process can reach it" -- the deployed publisher tree was
    missing `_compose_cybergym_lane_v3` entirely, and a tree updated after the
    last restart is equally unreachable to the process still holding the old
    module.

They live in tests/thin (which gates in CI) rather than beside the publisher
fixtures (which are advisory): this script is what stands between an operator
and a dark subnet.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
from types import SimpleNamespace

import pytest

_SCRIPT = (
    pathlib.Path(__file__).resolve().parents[2]
    / "scripts"
    / "assert_v3_cutover_ready.py"
)
_spec = importlib.util.spec_from_file_location("_v3_cutover_ready", _SCRIPT)
gate = importlib.util.module_from_spec(_spec)
# Registered before execution: @dataclass resolves its own module through
# sys.modules, and a script loaded by path is not there by default.
sys.modules[_spec.name] = gate
_spec.loader.exec_module(gate)

NOW = 1_785_916_800.0  # 2026-08-05T08:00:00Z
REAL_PRODUCER = "5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK"
ALICE = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"

# The three shapes the live SN39 box actually runs, because the decoys are not
# hypothetical: cathedral-publisher.service (a pre-scope tree writing an
# unscoped `latest` nothing consumes) and cathedral-scorer-canary.service
# (scoped to test/292) both answer /v1/validator/weights/next with a real
# signed vector, and one of them is the process this preflight used to probe.
COMPOSER_PID = 673997
LEGACY_PID = 135145
CANARY_PID = 134825
EXPECTED_VECTOR_ID = "latest:finney:39"
EXPECTED_LOCK_NAME = "cathedral:weights:refresh:finney:39"


def _iso(offset_secs: float) -> str:
    return gate._iso(NOW - offset_secs)


def publisher_process(**over) -> gate.ProcessFacts:
    environ = {
        "PATH": "/usr/bin",
        "DATABASE_URL": "postgresql://user:secret@127.0.0.1:5432/cathedral",
        gate.PRODUCER_HOTKEY_ENV: REAL_PRODUCER,
        gate.MECHANISM_ENABLED_ENV: "1",
        gate.WEIGHT_FRACTION_ENV: "0.30",
        gate.NETWORK_ENV: "finney",
        gate.NETUID_ENV: "39",
    }
    environ.update(over.pop("environ", {}))
    base = {
        "pid": COMPOSER_PID,
        "unit": gate.DEFAULT_PUBLISHER_UNIT,
        "user": "polaris",
        "argv": ["/srv/app/.venv/bin/python3", "-m", "uvicorn"],
        "cwd": "/srv/app",
        "exe": "/usr/bin/python3.12",
        "environ": environ,
        "start_epoch": NOW - 86_400,
        "host_now": NOW,
    }
    base.update(over)
    return gate.ProcessFacts(**base)


def legacy_process(**over) -> gate.ProcessFacts:
    """The pre-scope tree: no producer key, no cybergym env, unscoped row."""
    base = {
        "pid": LEGACY_PID,
        "unit": "cathedral-publisher.service",
        "user": "polaris",
        "argv": ["/home/polaris/cathedral/.venv/bin/python3", "-m", "uvicorn"],
        "cwd": "/home/polaris/cathedral",
        "exe": "/usr/bin/python3.12",
        "environ": {
            "PATH": "/usr/bin",
            "DATABASE_URL": "postgresql://user:secret@127.0.0.1:5432/cathedral",
        },
        "start_epoch": NOW - 900_000,
        "host_now": NOW,
    }
    base.update(over)
    return gate.ProcessFacts(**base)


def canary_process(**over) -> gate.ProcessFacts:
    """Scoped, current code -- but to test/292, not finney/39."""
    base = {
        "pid": CANARY_PID,
        "unit": "cathedral-scorer-canary.service",
        "user": "polaris",
        "argv": ["/home/polaris/cathedral-scorer/.venv/bin/python3", "-m", "uvicorn"],
        "cwd": "/home/polaris/cathedral-scorer",
        "exe": "/usr/bin/python3.12",
        "environ": {
            "PATH": "/usr/bin",
            "DATABASE_URL": "postgresql://user:secret@127.0.0.1:5432/cathedral",
            gate.NETWORK_ENV: "test",
            gate.NETUID_ENV: "292",
        },
        "start_epoch": NOW - 900_000,
        "host_now": NOW,
    }
    base.update(over)
    return gate.ProcessFacts(**base)


def scope_probe(**over) -> dict:
    """What a correctly scoped publisher says about itself."""
    base = {
        "cwd": "/srv/app",
        "executable": "/srv/app/.venv/bin/python3",
        "module_file": "/srv/app/scaffold/publisher/weights.py",
        "persisted_vector_id": EXPECTED_VECTOR_ID,
        "refresh_lock_name": EXPECTED_LOCK_NAME,
        "legacy_vector_id": "latest",
    }
    base.update(over)
    return base


def legacy_scope_probe() -> dict:
    """A pre-scope tree cannot answer the question at all: no such function."""
    return {
        "cwd": "/home/polaris/cathedral",
        "executable": "/home/polaris/cathedral/.venv/bin/python3",
        "module_file": "/home/polaris/cathedral/scaffold/publisher/weights.py",
        "persisted_vector_id": None,
        "persisted_vector_id_error": "_persisted_vector_id is absent from this module",
        "refresh_lock_name": None,
        "refresh_lock_name_error": "_refresh_lock_name is absent from this module",
        "legacy_vector_id": None,
    }


def canary_scope_probe() -> dict:
    return scope_probe(
        cwd="/home/polaris/cathedral-scorer",
        module_file="/home/polaris/cathedral-scorer/scaffold/publisher/weights.py",
        persisted_vector_id="latest:test:292",
        refresh_lock_name="cathedral:weights:refresh:test:292",
    )


def candidate_entry(proc: gate.ProcessFacts, scope: dict, *, is_composer: bool) -> dict:
    entry = {
        "unit": proc.unit or "(no unit)",
        "pid": proc.pid,
        "cwd": proc.cwd,
        "interpreter": proc.interpreter,
        "module_file": scope.get("module_file"),
        "persisted_vector_id": scope.get("persisted_vector_id"),
        "refresh_lock_name": scope.get("refresh_lock_name"),
        "is_composer": is_composer,
    }
    for key in ("import_error", "persisted_vector_id_error", "refresh_lock_name_error"):
        if scope.get(key):
            entry[key] = scope[key]
    return entry


def composer_identity(**over) -> gate.ComposerResolution:
    """A resolution that positively identified the composer."""
    proc = over.pop("process", publisher_process())
    scope = over.pop("scope", scope_probe())
    base = {
        "expected_vector_id": EXPECTED_VECTOR_ID,
        "expected_lock_name": EXPECTED_LOCK_NAME,
        "method": f"/proc scan for {gate.PUBLISHER_PROCESS_MARKER}",
        "process": proc,
        "scope": scope,
        "candidates": [candidate_entry(proc, scope, is_composer=True)],
        "lock": {
            "observed": True,
            "holder_pid": proc.pid if proc is not None else None,
            "polls": 91,
            "budget_secs": gate.DEFAULT_OBSERVE_LOCK_SECS,
            "lock_name": EXPECTED_LOCK_NAME,
        },
    }
    base.update(over)
    return gate.ComposerResolution(**base)


def validator_process(**over) -> gate.ProcessFacts:
    base = {
        "pid": 505121,
        "unit": gate.DEFAULT_VALIDATOR_UNIT,
        "user": "cathedral-validator",
        "argv": ["/opt/sn39/current-venv/bin/python", "-m", "scaffold.cli"],
        "cwd": "/opt/validator",
        "exe": "/usr/bin/python3.12",
        "environ": {"PATH": "/usr/bin", "PYTHONPATH": "/opt/validator"},
        "start_epoch": NOW - 3_600,
        "host_now": NOW,
    }
    base.update(over)
    return gate.ProcessFacts(**base)


def composer_probe(**over) -> dict:
    base = {
        "executable": "/srv/app/.venv/bin/python3",
        "module_file": "/srv/app/scaffold/publisher/weights.py",
        "present": True,
        "wired": True,
        "v3_allocation": 0.30,
        "module_mtime": NOW - 172_800,
        "module_sha256": "a" * 64,
    }
    base.update(over)
    return base


def database_probe(**over) -> dict:
    base = {
        "backend": "postgres",
        "target": "<postgres dsn>",
        "migrations": list(gate.CYBERGYM_MIGRATIONS) + ["0047_external_score_audience"],
        "tables": {
            "cybergym_score_reports": True,
            "cybergym_scores": True,
            "cybergym_epoch_status": True,
            "metagraph_hotkeys": True,
        },
        "rows": {
            "producers": [[REAL_PRODUCER, 41]],
            "latest_report": [["report-1", 41, _iso(600), 2]],
            "epoch_state": [[41, "closed"]],
            "scored_uids": [[REAL_PRODUCER, 3.5, 163]],
        },
    }
    base.update(over)
    return base


def trust_probe(**over) -> dict:
    base = {
        "module_file": "/opt/validator/scaffold/validator_thin.py",
        "module_mtime": NOW - 7_200,
        "pinned_policies": ["validated_supply_v1", "validated_supply_v3"],
        "admits_v3": True,
        "configured_require_policy": "validated_supply_v1",
        "provenance_mode": "shadow",
        "v3_startup_ok": True,
    }
    base.update(over)
    return base


def status_events(age_secs: float = 120.0) -> list[dict]:
    return [
        {"ts": _iso(age_secs + 60), "event": "VECTOR_ACCEPTED", "status": "PASS"},
        {"ts": _iso(age_secs), "event": "WEIGHTS_SUBMITTED", "status": "PASS"},
    ]


def healthy_facts(**over) -> gate.Facts:
    base = {
        "composer_id": composer_identity(),
        "publisher": publisher_process(),
        "composer": composer_probe(),
        "database": database_probe(),
        "validator": validator_process(),
        "trust": trust_probe(),
        "status_events": status_events(),
        "chain": {
            "block": 8_776_743,
            "weights_rate_limit": 100,
            "blocks_since_last_update": 117,
        },
        "now": NOW,
    }
    base.update(over)
    return gate.Facts(**base)


def result(facts: gate.Facts, check_id: str) -> gate.CheckResult:
    for candidate in gate.run_checks(facts):
        if candidate.check_id == check_id:
            return candidate
    raise AssertionError(f"no check named {check_id}")


# --------------------------------------------------------------------------
# the baseline: a ready host passes, and nothing else in this file can pass
# by accident
# --------------------------------------------------------------------------


def test_a_ready_host_passes_all_seven_checks():
    results = gate.run_checks(healthy_facts())
    assert [r.check_id for r in results] == [
        "composer_identity",
        "composer_reachable",
        "db_migration",
        "producer_identity",
        "trust_profile",
        "fundable_lane",
        "validator_writing",
    ]
    assert [r.state for r in results] == [gate.PASS] * 7


def test_every_non_pass_verdict_names_an_action():
    """A failure that does not say what to do is a failure this script owns."""
    facts = gate.Facts(now=NOW)  # nothing resolved: maximally broken host
    for candidate in gate.run_checks(facts):
        assert candidate.state != gate.PASS
        assert candidate.action.strip(), candidate.check_id


# --------------------------------------------------------------------------
# 0. composer identity -- the decoy trap
#
# The live SN39 box runs four publisher-shaped processes writing three
# different durable rows. The one this preflight originally probed by default
# was a legacy tree writing an unscoped `latest` row nothing consumes, so the
# report confidently described the wrong process. These tests hold the line at
# three properties: a decoy is never accepted, an unidentifiable process fails
# rather than passing, and the real composer is found without anyone passing a
# flag.
# --------------------------------------------------------------------------


def test_the_composer_is_found_among_the_decoys_without_a_unit_flag():
    host = live_box_host()
    ident = gate.resolve_composer(host, _args())
    assert ident.confirmed
    assert ident.process.pid == COMPOSER_PID
    assert ident.process.unit == gate.DEFAULT_PUBLISHER_UNIT
    assert ident.scope["persisted_vector_id"] == EXPECTED_VECTOR_ID
    # all three were considered, and exactly one was selected
    assert {c["pid"] for c in ident.candidates} == {
        LEGACY_PID,
        CANARY_PID,
        COMPOSER_PID,
    }
    assert [c["pid"] for c in ident.candidates if c["is_composer"]] == [COMPOSER_PID]


def test_the_legacy_unscoped_tree_is_never_accepted_as_the_composer():
    """Its weights.py has no _persisted_vector_id at all: it writes one
    unscoped `latest` row for every subnet, so it cannot be finney/39's."""
    host = FakeHost(
        processes=[legacy_process()], scopes={LEGACY_PID: legacy_scope_probe()}
    )
    ident = gate.resolve_composer(host, _args())
    assert not ident.confirmed
    assert ident.process is None
    assert EXPECTED_VECTOR_ID in ident.error
    assert "cathedral-publisher.service" in ident.error


def test_a_canary_scoped_to_another_subnet_is_never_accepted_as_the_composer():
    """Current code, correct shape, wrong audience: it writes latest:test:292."""
    host = FakeHost(
        processes=[canary_process()], scopes={CANARY_PID: canary_scope_probe()}
    )
    ident = gate.resolve_composer(host, _args())
    assert not ident.confirmed
    assert "latest:test:292" in ident.error


def test_a_decoy_is_rejected_even_when_it_is_the_only_process_named_by_the_flag():
    """Naming a unit narrows the search; it never substitutes for the proof.

    This is the exact shape of the original bug -- the flag (its default) chose
    the process, and nothing checked that the choice was right.
    """
    host = FakeHost(
        processes=[legacy_process()],
        scopes={LEGACY_PID: legacy_scope_probe()},
        units={
            "cathedral-publisher.service": {
                "MainPID": str(LEGACY_PID),
                "User": "polaris",
                "ActiveState": "active",
            }
        },
    )
    ident = gate.resolve_composer(
        host, _args(publisher_unit="cathedral-publisher.service")
    )
    assert not ident.confirmed
    assert EXPECTED_VECTOR_ID in ident.error


def test_a_process_that_cannot_be_identified_fails_rather_than_passing():
    """The probe did not run at all. Unknown is not clean."""
    host = FakeHost(
        processes=[publisher_process()],
        scopes={},  # no answer for this pid
    )
    host._scopes = {}

    def _raise(proc, program, **kwargs):
        if program is gate.SCOPE_PROBE:
            raise gate.ProbeError("probe exited 1: ImportError")
        return {"rc": 0, "stdout": json.dumps({}), "stderr": ""}

    host.pyprobe = _raise
    ident = gate.resolve_composer(host, _args())
    assert not ident.confirmed
    assert "ImportError" in ident.candidates[0]["probe_error"]
    verdict = result(
        healthy_facts(composer_id=ident, publisher=None), "composer_identity"
    )
    assert verdict.state == gate.FAIL


def test_two_processes_claiming_the_same_scope_is_a_failure_not_a_coin_flip():
    twin = publisher_process(pid=999001, unit="cathedral-scorer-twin.service")
    host = FakeHost(
        processes=[publisher_process(), twin],
        scopes={COMPOSER_PID: scope_probe(), 999001: scope_probe()},
    )
    ident = gate.resolve_composer(host, _args())
    assert not ident.confirmed
    assert "2 running processes" in ident.error


def test_the_advisory_lock_holder_overrides_a_scope_claim_it_contradicts():
    """Only the real composer holds the refresh lock. If it is held by some
    other candidate, the code-derived selection is wrong and saying nothing
    would be worse than saying so."""
    host = live_box_host(
        lock={
            "observed": True,
            "holder_pid": LEGACY_PID,
            "polls": 4,
            "budget_secs": 75.0,
            "lock_name": EXPECTED_LOCK_NAME,
        }
    )
    ident = gate.resolve_composer(host, _args())
    assert not ident.confirmed
    assert EXPECTED_LOCK_NAME in ident.error
    assert str(LEGACY_PID) in ident.error
    # still named, so the report can say what it looked at
    assert ident.process.pid == COMPOSER_PID


def test_an_unobserved_lock_is_neutral_because_it_is_held_only_while_building():
    host = live_box_host(
        lock={
            "observed": False,
            "polls": 1400,
            "budget_secs": 75.0,
            "lock_name": EXPECTED_LOCK_NAME,
        }
    )
    ident = gate.resolve_composer(host, _args())
    assert ident.confirmed
    verdict = result(healthy_facts(composer_id=ident), "composer_identity")
    assert verdict.state == gate.PASS
    assert "not seen held" in verdict.reason


def test_a_confirmed_identity_names_the_process_it_probed():
    verdict = result(healthy_facts(), "composer_identity")
    assert verdict.state == gate.PASS
    selected = verdict.evidence["selected"]
    assert selected["unit"] == gate.DEFAULT_PUBLISHER_UNIT
    assert selected["pid"] == COMPOSER_PID
    assert selected["cwd"] == "/srv/app"
    assert selected["module_file"] == "/srv/app/scaffold/publisher/weights.py"
    assert selected["persisted_vector_id"] == EXPECTED_VECTOR_ID


def test_the_default_publisher_unit_is_the_sn39_composer_not_the_legacy_one():
    """The fallback should still land on the right process if it is ever used."""
    assert gate.DEFAULT_PUBLISHER_UNIT == "cathedral-scorer-sn39.service"


def test_enumeration_falls_back_to_the_named_unit_but_keeps_the_proof():
    host = FakeHost(enumeration_error="remote probe produced no JSON")
    ident = gate.resolve_composer(host, _args())
    assert ident.confirmed
    assert ident.process.pid == COMPOSER_PID
    assert gate.DEFAULT_PUBLISHER_UNIT in ident.method
    assert ident.enumeration_error


def test_no_publisher_anywhere_is_a_failure_with_a_reason():
    host = FakeHost(processes=[], units={})
    ident = gate.resolve_composer(host, _args())
    assert not ident.confirmed
    assert gate.PUBLISHER_PROCESS_MARKER in ident.error


def test_the_scope_names_match_the_publishers_own_derivation():
    """These two strings are the whole identification. If weights.py ever
    changes how it scopes the durable row, this preflight must change with it."""
    weights = (
        pathlib.Path(__file__).resolve().parents[2]
        / "scaffold"
        / "publisher"
        / "weights.py"
    ).read_text()
    assert 'f"latest:{network}:{netuid}"' in weights
    assert 'f"cathedral:weights:refresh:{network}:{netuid}"' in weights
    assert gate.persisted_vector_id("finney", 39) == "latest:finney:39"
    assert gate.refresh_lock_name("finney", 39) == "cathedral:weights:refresh:finney:39"


def test_the_scope_probe_never_imports_the_server_module():
    """Same constraint as COMPOSER_PROBE: importing scaffold.publisher.server
    constructs a Store, and Store.__init__ migrates the LIVE database."""
    assert "publisher.weights" in gate.SCOPE_PROBE
    assert "publisher.server" not in gate.SCOPE_PROBE
    assert "Store(" not in gate.SCOPE_PROBE


def test_the_lock_probe_only_reads_pg_locks_and_never_takes_the_lock():
    """pg_try_advisory_lock here would make the real composer's next refresh
    find the lock held and skip a build -- a write-shaped side effect."""
    assert "pg_locks" in gate.LOCK_OBSERVE_PROBE
    assert "pg_try_advisory_lock" not in gate.LOCK_OBSERVE_PROBE
    assert "pg_advisory_lock" not in gate.LOCK_OBSERVE_PROBE
    assert "default_transaction_read_only=on" in gate.LOCK_OBSERVE_PROBE


def test_publisher_enumeration_reads_proc_and_drops_uvicorn_workers():
    """A `--workers N` child re-execs the same argv; only the parent composes."""
    assert "op_publishers" in gate.REMOTE_HELPER
    assert 'info["ppid"] not in found' in gate.REMOTE_HELPER
    for forbidden in ("systemctl start", "systemctl restart", "daemon-reload"):
        assert forbidden not in gate.REMOTE_HELPER


# --------------------------------------------------------------------------
# 1. composer reachability -- the "it is on disk" trap
# --------------------------------------------------------------------------


def test_composer_absent_from_the_module_the_process_imports_fails():
    facts = healthy_facts(composer=composer_probe(present=False, wired=False))
    verdict = result(facts, "composer_reachable")
    assert verdict.state == gate.FAIL
    assert "_compose_cybergym_lane_v3 is absent" in verdict.reason
    assert "restart the publisher" in verdict.action


def test_composer_defined_but_not_called_by_build_signed_vector_fails():
    """A partial cherry-pick: the function exists and nothing reaches it."""
    facts = healthy_facts(composer=composer_probe(wired=False))
    verdict = result(facts, "composer_reachable")
    assert verdict.state == gate.FAIL
    assert "does not call it" in verdict.reason


def test_module_updated_after_the_process_started_is_not_reachable():
    """The file on disk is correct; the RUNNING interpreter holds the old one."""
    proc = publisher_process(start_epoch=NOW - 86_400)
    facts = healthy_facts(
        publisher=proc, composer=composer_probe(module_mtime=NOW - 60)
    )
    verdict = result(facts, "composer_reachable")
    assert verdict.state == gate.FAIL
    assert "after this process started" in verdict.reason
    assert "restart" in verdict.action


def test_module_older_than_the_process_is_reachable():
    facts = healthy_facts(composer=composer_probe(module_mtime=NOW - 86_401))
    assert result(facts, "composer_reachable").state == gate.PASS


def test_unimportable_publisher_tree_fails():
    facts = healthy_facts(
        composer=composer_probe(import_error="ModuleNotFoundError: no scaffold")
    )
    verdict = result(facts, "composer_reachable")
    assert verdict.state == gate.FAIL
    assert "cannot import" in verdict.reason


def test_wrong_v3_allocation_constant_fails():
    facts = healthy_facts(composer=composer_probe(v3_allocation=0.25))
    verdict = result(facts, "composer_reachable")
    assert verdict.state == gate.FAIL
    assert "V3_CYBERGYM_ALLOCATION" in verdict.reason


def test_unresolvable_publisher_blocks_every_publisher_side_check():
    facts = gate.Facts(
        composer_id=gate.ComposerResolution(
            expected_vector_id=EXPECTED_VECTOR_ID,
            expected_lock_name=EXPECTED_LOCK_NAME,
            error="cathedral-scorer-sn39.service is inactive",
        ),
        publisher_error="cathedral-scorer-sn39.service is inactive",
        now=NOW,
    )
    verdicts = {r.check_id: r for r in gate.run_checks(facts)}
    assert verdicts["composer_identity"].state == gate.FAIL
    for dependent in (
        "composer_reachable",
        "db_migration",
        "producer_identity",
        "fundable_lane",
    ):
        assert verdicts[dependent].state == gate.BLOCKED
        assert "composer_identity" in verdicts[dependent].reason


def test_the_probe_interpreter_is_the_venv_the_service_runs_not_proc_exe():
    """`/proc/<pid>/exe` resolves through the venv symlink to the base binary.

    Probing with that interpreter would import the SYSTEM site-packages and
    prove nothing about what the service can reach, which is the whole point of
    this check.
    """
    proc = publisher_process()
    assert proc.interpreter == "/srv/app/.venv/bin/python3"
    assert proc.interpreter != proc.exe
    fallback = publisher_process(
        argv=["/srv/app/.venv/bin/uvicorn"],
        environ={"VIRTUAL_ENV": "/srv/app/.venv"},
    )
    assert fallback.interpreter == "/srv/app/.venv/bin/python"


def test_the_composer_probe_never_imports_the_server_module():
    """Importing scaffold.publisher.server builds the app, which constructs a
    Store, which runs migrate() -- a WRITE against the live database from a
    read-only preflight."""
    assert "publisher.weights" in gate.COMPOSER_PROBE
    assert "publisher.server" not in gate.COMPOSER_PROBE
    assert "Store(" not in gate.COMPOSER_PROBE


# --------------------------------------------------------------------------
# 2. the migration that provides the cybergym tables
# --------------------------------------------------------------------------


@pytest.mark.parametrize("missing", gate.CYBERGYM_MIGRATIONS)
def test_a_missing_cybergym_migration_fails(missing):
    applied = [m for m in gate.CYBERGYM_MIGRATIONS if m != missing]
    facts = healthy_facts(database=database_probe(migrations=applied))
    verdict = result(facts, "db_migration")
    assert verdict.state == gate.FAIL
    assert missing in verdict.reason
    assert "Do NOT hand-apply DDL" in verdict.action


def test_a_database_at_0047_fails_exactly_as_the_live_one_did():
    facts = healthy_facts(
        database=database_probe(
            migrations=["0046_v2_cnf_artifacts", "0047_external_score_audience"],
            tables={
                "cybergym_score_reports": False,
                "cybergym_scores": False,
                "cybergym_epoch_status": False,
                "metagraph_hotkeys": True,
            },
        )
    )
    assert result(facts, "db_migration").state == gate.FAIL


def test_migration_recorded_but_table_missing_fails():
    facts = healthy_facts(
        database=database_probe(
            tables={
                "cybergym_score_reports": False,
                "cybergym_scores": True,
                "cybergym_epoch_status": True,
                "metagraph_hotkeys": True,
            }
        )
    )
    verdict = result(facts, "db_migration")
    assert verdict.state == gate.FAIL
    assert "do not exist" in verdict.reason


def test_an_unreadable_database_fails_rather_than_passing_quietly():
    facts = healthy_facts(database={}, database_error="sudo: a password is required")
    verdict = result(facts, "db_migration")
    assert verdict.state == gate.FAIL
    assert "read-only" in verdict.action


def test_no_database_query_can_write():
    """Read-only by construction, asserted rather than assumed."""
    forbidden = ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE")
    for spec in gate.database_queries("finney", 39).values():
        upper = spec["sql"].upper()
        for verb in forbidden:
            assert verb not in upper, spec["sql"]
    assert "mode=ro" in gate.DATABASE_PROBE
    assert "default_transaction_read_only=on" in gate.DATABASE_PROBE


def test_the_remote_helper_only_ever_reads_systemd():
    """`systemctl show` is the single systemd verb this preflight may use."""
    for verb in (
        "systemctl start",
        "systemctl stop",
        "systemctl restart",
        "daemon-reload",
        '"start"',
        '"restart"',
    ):
        assert verb not in gate.REMOTE_HELPER
    assert '"show"' in gate.REMOTE_HELPER


# --------------------------------------------------------------------------
# 3. the producer identity -- the misconfiguration that was found live
# --------------------------------------------------------------------------


@pytest.mark.parametrize("address,label", sorted(gate.SUBSTRATE_DEV_KEYS.items()))
def test_every_substrate_dev_key_is_refused(address, label):
    facts = healthy_facts(
        publisher=publisher_process(environ={gate.PRODUCER_HOTKEY_ENV: address})
    )
    verdict = result(facts, "producer_identity")
    assert verdict.state == gate.FAIL
    assert label in verdict.reason
    assert "cannot undo it" in verdict.action


def test_alice_is_refused_by_her_exact_published_address():
    """The address in the task, byte for byte: a typo here admits a dev key."""
    assert gate.SUBSTRATE_DEV_KEYS[ALICE] == "//Alice"
    facts = healthy_facts(
        publisher=publisher_process(environ={gate.PRODUCER_HOTKEY_ENV: ALICE})
    )
    assert result(facts, "producer_identity").state == gate.FAIL


def test_an_unset_producer_fails():
    facts = healthy_facts(
        publisher=publisher_process(environ={gate.PRODUCER_HOTKEY_ENV: ""})
    )
    verdict = result(facts, "producer_identity")
    assert verdict.state == gate.FAIL
    assert "unset" in verdict.reason


def test_a_dev_key_already_admitted_fails_even_after_rotation():
    """The fence is audience-scoped: rotating to a real key does not clear it."""
    facts = healthy_facts(
        publisher=publisher_process(environ={gate.PRODUCER_HOTKEY_ENV: REAL_PRODUCER}),
        database=database_probe(
            rows=dict(
                database_probe()["rows"],
                producers=[[ALICE, 9_000], [REAL_PRODUCER, 41]],
            )
        ),
    )
    verdict = result(facts, "producer_identity")
    assert verdict.state == gate.FAIL
    assert "9000" in verdict.reason.replace(",", "")
    assert "//Alice" in verdict.reason
    assert "will not lower it" in verdict.action


def test_a_clean_key_with_no_tables_yet_passes_because_nothing_can_be_admitted():
    facts = healthy_facts(
        database=database_probe(
            tables={
                "cybergym_score_reports": False,
                "cybergym_scores": False,
                "cybergym_epoch_status": False,
                "metagraph_hotkeys": True,
            }
        )
    )
    verdict = result(facts, "producer_identity")
    assert verdict.state == gate.PASS


def test_an_unreadable_database_blocks_rather_than_passing_the_identity_check():
    facts = healthy_facts(database={}, database_error="connection refused")
    verdict = result(facts, "producer_identity")
    assert verdict.state == gate.BLOCKED
    assert "db_migration" in verdict.reason


def test_dev_key_addresses_are_the_derived_ones():
    """Re-derive the table rather than trusting it was typed correctly."""
    keypair = pytest.importorskip("bittensor_wallet").Keypair
    expected = {}
    for name in ("Alice", "Bob", "Charlie", "Dave", "Eve", "Ferdie"):
        expected[keypair.create_from_uri(f"//{name}").ss58_address] = f"//{name}"
        expected[keypair.create_from_uri(f"//{name}//stash").ss58_address] = (
            f"//{name}//stash"
        )
    for address, label in expected.items():
        assert gate.SUBSTRATE_DEV_KEYS.get(address) == label


# --------------------------------------------------------------------------
# 4. the validator trust profile
# --------------------------------------------------------------------------


def test_a_validator_predating_the_widened_profile_fails():
    facts = healthy_facts(
        trust=trust_probe(admits_v3=False, pinned_policies=["validated_supply_v1"])
    )
    verdict = result(facts, "trust_profile")
    assert verdict.state == gate.FAIL
    assert "does not contain validated_supply_v3" in verdict.reason


def test_a_config_the_v3_startup_contract_refuses_fails():
    """The v3-pin + provenance=authority combination is the silent-death one."""
    facts = healthy_facts(
        trust=trust_probe(
            v3_startup_ok=False,
            v3_startup_error=(
                "VectorError: require_policy=validated_supply_v3 is incompatible "
                "with provenance=authority"
            ),
            provenance_mode="authority",
        )
    )
    verdict = result(facts, "trust_profile")
    assert verdict.state == gate.FAIL
    assert "provenance=authority" in verdict.reason


def test_a_validator_running_older_code_than_its_tree_fails():
    facts = healthy_facts(trust=trust_probe(module_mtime=NOW - 60))
    verdict = result(facts, "trust_profile")
    assert verdict.state == gate.FAIL
    assert "after the validator started" in verdict.reason


def test_an_unevaluated_live_config_is_not_a_pass():
    facts = healthy_facts(trust=trust_probe(v3_startup_ok=None))
    verdict = result(facts, "trust_profile")
    assert verdict.state == gate.FAIL
    assert "--validator-config" in verdict.action


def test_an_unresolvable_validator_fails_the_trust_check():
    facts = healthy_facts(validator=None, validator_error="unit not found", trust={})
    assert result(facts, "trust_profile").state == gate.FAIL


# --------------------------------------------------------------------------
# 5. the lane must be able to fund something
# --------------------------------------------------------------------------


def test_a_disabled_mechanism_fails():
    facts = healthy_facts(
        publisher=publisher_process(environ={gate.MECHANISM_ENABLED_ENV: "0"})
    )
    verdict = result(facts, "fundable_lane")
    assert verdict.state == gate.FAIL
    assert "refuses to sign" in verdict.action


@pytest.mark.parametrize("fraction", ["", "0.1", "0.3000001", "not-a-number"])
def test_a_wrong_weight_fraction_fails(fraction):
    facts = healthy_facts(
        publisher=publisher_process(environ={gate.WEIGHT_FRACTION_ENV: fraction})
    )
    assert result(facts, "fundable_lane").state == gate.FAIL


def test_an_unconfigured_audience_fails_because_the_intake_answers_503():
    facts = healthy_facts(publisher=publisher_process(environ={gate.NETUID_ENV: ""}))
    verdict = result(facts, "fundable_lane")
    assert verdict.state == gate.FAIL
    assert "fails closed" in verdict.action


def test_missing_cybergym_tables_block_the_lane_check_on_the_migration():
    facts = healthy_facts(
        database=database_probe(
            tables={
                "cybergym_score_reports": False,
                "cybergym_scores": False,
                "cybergym_epoch_status": False,
                "metagraph_hotkeys": True,
            }
        )
    )
    verdict = result(facts, "fundable_lane")
    assert verdict.state == gate.BLOCKED
    assert "db_migration" in verdict.action


def test_no_admitted_report_fails_because_the_whole_lane_would_burn():
    rows = dict(database_probe()["rows"], latest_report=[], scored_uids=[])
    facts = healthy_facts(database=database_probe(rows=rows))
    verdict = result(facts, "fundable_lane")
    assert verdict.state == gate.FAIL
    assert "worse than v2's 10%" in verdict.action


def test_a_stale_report_fails():
    rows = dict(
        database_probe()["rows"], latest_report=[["report-1", 41, _iso(7_200), 2]]
    )
    facts = healthy_facts(database=database_probe(rows=rows))
    verdict = result(facts, "fundable_lane")
    assert verdict.state == gate.FAIL
    assert "freshness ceiling" in verdict.reason


def test_an_open_epoch_fails():
    rows = dict(database_probe()["rows"], epoch_state=[[41, "open"]])
    facts = healthy_facts(database=database_probe(rows=rows))
    verdict = result(facts, "fundable_lane")
    assert verdict.state == gate.FAIL
    assert "not closed" in verdict.reason


def test_a_complete_report_that_scores_nobody_fails():
    """'Nobody solved this epoch' is legal, and under v3 it burns 30%."""
    rows = dict(database_probe()["rows"], scored_uids=[])
    facts = healthy_facts(database=database_probe(rows=rows))
    verdict = result(facts, "fundable_lane")
    assert verdict.state == gate.FAIL
    assert "scores nobody above zero" in verdict.reason


def test_scored_miners_that_map_to_no_uid_fail():
    rows = dict(database_probe()["rows"], scored_uids=[["5Unregistered", 2.0, None]])
    facts = healthy_facts(database=database_probe(rows=rows))
    verdict = result(facts, "fundable_lane")
    assert verdict.state == gate.FAIL
    assert "none maps to a UID" in verdict.reason


# --------------------------------------------------------------------------
# 6. the validator has to be writing NOW
# --------------------------------------------------------------------------


def test_no_weights_submitted_event_fails():
    facts = healthy_facts(status_events=[{"ts": _iso(60), "event": "TICK_FAILED"}])
    verdict = result(facts, "validator_writing")
    assert verdict.state == gate.FAIL
    assert "not writing" in verdict.action


def test_a_failed_weights_submitted_event_does_not_count_as_a_write():
    facts = healthy_facts(
        status_events=[{"ts": _iso(60), "event": "WEIGHTS_SUBMITTED", "status": "FAIL"}]
    )
    assert result(facts, "validator_writing").state == gate.FAIL


def test_a_stale_weight_write_fails():
    facts = healthy_facts(status_events=status_events(age_secs=4_000))
    verdict = result(facts, "validator_writing")
    assert verdict.state == gate.FAIL
    assert "gone quiet" in verdict.action


def test_an_unsampled_chain_cooldown_fails_rather_than_assuming_health():
    facts = healthy_facts(chain={}, chain_error="websocket timeout")
    verdict = result(facts, "validator_writing")
    assert verdict.state == gate.FAIL
    assert "--chain-json" in verdict.action


def test_a_cooldown_stuck_at_many_rate_limit_windows_fails():
    """Recent WEIGHTS_SUBMITTED lines plus a chain that has accepted nothing."""
    facts = healthy_facts(
        chain={
            "block": 8_776_743,
            "weights_rate_limit": 100,
            "blocks_since_last_update": 1_200,
        }
    )
    verdict = result(facts, "validator_writing")
    assert verdict.state == gate.FAIL
    assert "thinks it is writing and is not" in verdict.action


def test_a_cooldown_just_past_the_rate_limit_is_healthy():
    facts = healthy_facts(
        chain={
            "block": 8_776_743,
            "weights_rate_limit": 100,
            "blocks_since_last_update": 117,
        }
    )
    assert result(facts, "validator_writing").state == gate.PASS


def test_non_integer_chain_values_fail():
    facts = healthy_facts(
        chain={"weights_rate_limit": None, "blocks_since_last_update": 117}
    )
    assert result(facts, "validator_writing").state == gate.FAIL


def test_an_unresolvable_validator_blocks_the_health_check_on_the_trust_check():
    facts = healthy_facts(validator=None, validator_error="unit not found", chain={})
    verdict = result(facts, "validator_writing")
    assert verdict.state == gate.BLOCKED
    assert "trust_profile" in verdict.reason


# --------------------------------------------------------------------------
# the report itself
# --------------------------------------------------------------------------


def _proc_entry(proc: gate.ProcessFacts) -> dict:
    return {
        "pid": proc.pid,
        "unit": proc.unit,
        "user": proc.user,
        "argv": proc.argv,
        "cwd": proc.cwd,
        "exe": proc.exe,
        "environ": proc.environ,
        "start_epoch": proc.start_epoch,
        "now": NOW,
        "ppid": 1,
    }


class FakeHost(gate.Host):
    """A host whose every read is canned. Nothing here touches a real machine.

    ``processes`` is the whole publisher population: by default just the real
    composer, but tests hand it the live box's actual mix of decoys.
    """

    def __init__(
        self,
        *,
        composer=None,
        units=None,
        processes=None,
        scopes=None,
        lock=None,
        enumeration_error=None,
    ):
        self.calls = []
        self._composer = composer if composer is not None else composer_probe()
        self._processes = list(
            processes if processes is not None else [publisher_process()]
        )
        self._scopes = dict(scopes or {COMPOSER_PID: scope_probe()})
        self._lock = (
            lock
            if lock is not None
            else {
                "observed": True,
                "holder_pid": COMPOSER_PID,
                "polls": 91,
                "budget_secs": gate.DEFAULT_OBSERVE_LOCK_SECS,
                "lock_name": EXPECTED_LOCK_NAME,
            }
        )
        self._enumeration_error = enumeration_error
        # `units={}` means "this host has no units", not "use the defaults".
        self._units = (
            units
            if units is not None
            else {
                gate.DEFAULT_PUBLISHER_UNIT: {
                    "MainPID": str(COMPOSER_PID),
                    "User": "polaris",
                    "ActiveState": "active",
                },
                gate.DEFAULT_VALIDATOR_UNIT: {
                    "MainPID": "505121",
                    "User": "cathedral-validator",
                    "ActiveState": "active",
                },
            }
        )

    def unit(self, unit):
        try:
            return dict(self._units[unit])
        except KeyError:
            raise gate.ProbeError(f"Unit {unit} could not be found.") from None

    def publishers(self, marker):
        if self._enumeration_error is not None:
            raise gate.ProbeError(self._enumeration_error)
        return [_proc_entry(proc) for proc in self._processes]

    def process(self, pid):
        for proc in self._processes:
            if proc.pid == pid:
                break
        else:
            proc = validator_process()
        return {
            "argv": proc.argv,
            "cwd": proc.cwd,
            "exe": proc.exe,
            "environ": proc.environ,
            "start_epoch": proc.start_epoch,
            "now": NOW,
        }

    def pyprobe(self, proc, program, *, env_keys=(), env=None, timeout=120.0):
        self.calls.append((proc.unit, proc.interpreter, program, dict(env or {})))
        if program is gate.SCOPE_PROBE:
            payload = self._scopes.get(proc.pid, legacy_scope_probe())
        elif program is gate.LOCK_OBSERVE_PROBE:
            payload = self._lock
        elif program is gate.COMPOSER_PROBE:
            payload = self._composer
        elif program is gate.DATABASE_PROBE:
            payload = database_probe()
        elif program is gate.TRUST_PROFILE_PROBE:
            payload = trust_probe()
        else:
            payload = {
                "block": 1,
                "weights_rate_limit": 100,
                "blocks_since_last_update": 117,
            }
        return {"rc": 0, "stdout": json.dumps(payload), "stderr": ""}

    def tail(self, path, *, max_bytes=262144):
        return {"text": "\n".join(json.dumps(e) for e in status_events())}

    def state(self, path):
        return {"validator_uid": 30, "network": "finney", "netuid": 39}

    def now(self):
        return NOW


def live_box_host(**over) -> FakeHost:
    """The population the live SN39 box actually runs: one composer, two decoys."""
    base = {
        "processes": [legacy_process(), canary_process(), publisher_process()],
        "scopes": {
            LEGACY_PID: legacy_scope_probe(),
            CANARY_PID: canary_scope_probe(),
            COMPOSER_PID: scope_probe(),
        },
    }
    base.update(over)
    return FakeHost(**base)


def _args(**over):
    base = {
        "publisher_unit": None,
        "observe_lock_secs": gate.DEFAULT_OBSERVE_LOCK_SECS,
        "validator_unit": gate.DEFAULT_VALIDATOR_UNIT,
        "validator_config": gate.DEFAULT_VALIDATOR_CONFIG,
        "status_log": gate.DEFAULT_STATUS_LOG,
        "state_file": gate.DEFAULT_STATE_FILE,
        "network": "finney",
        "netuid": 39,
        "chain_json": None,
        "max_weights_age_secs": gate.DEFAULT_MAX_WEIGHTS_AGE_SECS,
        "max_cooldown_multiple": gate.DEFAULT_MAX_COOLDOWN_MULTIPLE,
    }
    base.update(over)
    return SimpleNamespace(**base)


def test_gather_runs_each_probe_in_its_own_services_interpreter():
    host = FakeHost()
    facts = gate.gather(host, _args())
    by_unit = {unit: interpreter for unit, interpreter, _, _ in host.calls}
    assert by_unit[gate.DEFAULT_PUBLISHER_UNIT] == "/srv/app/.venv/bin/python3"
    assert by_unit[gate.DEFAULT_VALIDATOR_UNIT] == "/opt/sn39/current-venv/bin/python"
    assert facts.composer["present"] is True
    assert [r.state for r in gate.run_checks(facts)] == [gate.PASS] * 7


def test_the_exit_code_is_non_zero_when_any_check_fails(capsys):
    host = FakeHost(composer=composer_probe(present=False, wired=False))
    assert gate.main(["--json"], host=host) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is False
    states = {check["check"]: check["state"] for check in report["checks"]}
    assert states["composer_reachable"] == gate.FAIL
    assert states["trust_profile"] == gate.PASS


def test_a_ready_host_exits_zero_and_says_what_to_do_next(capsys):
    assert gate.main([], host=FakeHost()) == 0
    out = capsys.readouterr().out
    assert "READY" in out
    assert "assert_live_v3_contract.py" in out


def test_the_human_report_never_prints_the_database_dsn(capsys):
    gate.main([], host=FakeHost())
    assert "secret@127.0.0.1" not in capsys.readouterr().out


def test_the_json_report_never_prints_the_database_dsn(capsys):
    gate.main(["--json"], host=FakeHost())
    assert "secret@127.0.0.1" not in capsys.readouterr().out


def test_the_live_box_shape_probes_the_composer_and_not_a_decoy(capsys):
    """End to end, through main(), against the population the live box runs.

    The publisher-side verdicts must be about cathedral-scorer-sn39.service --
    the process that composes latest:finney:39 -- and the report must say so
    where a reader will see it.
    """
    host = live_box_host()
    assert gate.main([], host=host) == 0
    out = capsys.readouterr().out
    assert f"probed publisher  {gate.DEFAULT_PUBLISHER_UNIT} pid {COMPOSER_PID}" in out
    assert f"composes {EXPECTED_VECTOR_ID}" in out
    assert "cathedral-publisher.service" not in out
    # every publisher-side probe went to the composer, none to a decoy
    probed = {
        unit
        for unit, _, program, _ in host.calls
        if program in (gate.COMPOSER_PROBE, gate.DATABASE_PROBE)
    }
    assert probed == {gate.DEFAULT_PUBLISHER_UNIT}


def test_a_box_whose_composer_cannot_be_identified_never_reports_a_decoys_state(capsys):
    """The regression itself: only decoys running, so there is no composer.

    The old script probed one of them and reported "the v3 composer is absent"
    and "the producer hotkey is unset" as facts about the composer. Neither was
    true of the composer; both were true of the decoy. Now every publisher-side
    verdict is BLOCKED and the reason names why.
    """
    host = FakeHost(
        processes=[legacy_process(), canary_process()],
        scopes={LEGACY_PID: legacy_scope_probe(), CANARY_PID: canary_scope_probe()},
        units={},
    )
    assert gate.main(["--json"], host=host) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is False
    assert report["probed_publisher"] is None
    states = {check["check"]: check["state"] for check in report["checks"]}
    assert states["composer_identity"] == gate.FAIL
    for dependent in (
        "composer_reachable",
        "db_migration",
        "producer_identity",
        "fundable_lane",
    ):
        assert states[dependent] == gate.BLOCKED
    identity = next(c for c in report["checks"] if c["check"] == "composer_identity")
    # the reason must name what it looked at and what each one writes instead
    assert "cathedral-publisher.service" in identity["reason"]
    assert "latest:test:292" in identity["reason"]
    # and nothing anywhere claims a fact about "the composer" from a decoy
    reachable = next(c for c in report["checks"] if c["check"] == "composer_reachable")
    assert "absent" not in reachable["reason"]
    producer = next(c for c in report["checks"] if c["check"] == "producer_identity")
    assert "is unset" not in producer["reason"]


def test_the_json_report_names_the_process_every_publisher_verdict_is_about(capsys):
    gate.main(["--json"], host=live_box_host())
    probed = json.loads(capsys.readouterr().out)["probed_publisher"]
    assert probed == {
        "unit": gate.DEFAULT_PUBLISHER_UNIT,
        "pid": COMPOSER_PID,
        "cwd": "/srv/app",
        "module_file": "/srv/app/scaffold/publisher/weights.py",
        "persisted_vector_id": EXPECTED_VECTOR_ID,
        "confirmed": True,
    }


def test_the_status_log_tail_survives_a_sliced_first_line():
    text = '3-c46f-4"}\n{"ts":"2026-08-05T07:49:36.630Z","event":"WEIGHTS_SUBMITTED"}'
    events = gate.parse_status_events(text)
    assert [e["event"] for e in events] == ["WEIGHTS_SUBMITTED"]
