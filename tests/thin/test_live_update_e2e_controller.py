import importlib.abc
import importlib.util
import re
import runpy
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


def _live_readiness_namespace(monkeypatch):
    package = ModuleType("cathedral_thin")
    runtime = ModuleType("cathedral_thin.independent_runtime")
    for name in ("direct_validator", "qvl", "snp_production"):
        setattr(runtime, name, ModuleType(f"{runtime.__name__}.{name}"))
    package.independent_runtime = runtime
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, runtime.__name__, runtime)
    root = Path(__file__).resolve().parents[2]
    return runpy.run_path(str(root / "tests/live/cathedral_no_chain_readiness.py"))


def _live_readiness_guard(monkeypatch):
    return _live_readiness_namespace(monkeypatch)["require_pex_origin"]


def test_live_controller_isolates_the_unselected_timer_without_masking_units():
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    configure_host = script.split("configure_host() {", 1)[1].split(
        'record_step "first install A', 1
    )[0]

    assert "systemctl mask" not in configure_host
    assert "systemctl disable --now '$other_timer'" in configure_host
    condition = (
        "ConditionPathExists=/run/cathedral-live-${RUN_ID}-permit-${other_timer}"
    )
    assert condition in configure_host
    assert "systemctl start '$other_timer'" in configure_host
    for timer in ("$timer", "$other_timer"):
        assert f"systemctl show '{timer}' -p UnitFileState --value" in configure_host
    assert "systemctl show '$timer' -p ActiveState --value" in configure_host
    assert configure_host.count("= disabled") == 2
    assert "systemctl cat '$other_timer'" in configure_host
    assert "other_timer_state=" in configure_host
    assert "-p ActiveState -p SubState -p ConditionResult" in configure_host
    assert "ActiveState=inactive" in configure_host
    assert "SubState=dead" in configure_host
    assert "! sudo systemctl is-active --quiet '$other_timer'" in configure_host
    assert "ConditionResult=no" not in configure_host
    assert "CATHEDRAL_LIVE_TEST_PEX_ROOT=/run/cathedral-validator-pex" in configure_host


def test_live_controller_records_both_timer_states_in_host_evidence():
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    capture_host = script.split("capture_host() {", 1)[1].split(
        "configure_host() {", 1
    )[0]

    assert (
        "systemctl show cathedral-validator-canary-update.timer "
        "cathedral-validator-update.timer -p Id -p UnitFileState "
        "-p ActiveState -p SubState -p ConditionResult "
        "-p NextElapseUSecMonotonic -p LastTriggerUSec "
        "-p LastTriggerUSecMonotonic -p DropInPaths"
    ) in capture_host


def test_live_controller_captures_first_install_failures_before_teardown():
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()

    assert script.index("capture_host() {") < script.index("configure_host() {")
    configure_host = script.split("configure_host() {", 1)[1].split(
        'record_step "first install A', 1
    )[0]
    assert (
        configure_host.count(
            'capture_host_with_retries "first-install-failure-${channel}" '
            '"$host" || true'
        )
        == 2
    )
    assert (
        'capture_host_with_retries "first-readiness-failure-${channel}" '
        '"$host" || true' in configure_host
    )
    assert (
        configure_host.count('tee "$EVIDENCE_DIR/first-install-command-${host}.log"')
        == 2
    )
    assert 'tee "$EVIDENCE_DIR/first-readiness-command-${host}.log"' in configure_host
    assert configure_host.count("failure_status=$?") == 3
    assert configure_host.count('return "$failure_status"') == 3
    assert "return 1" not in configure_host


def test_live_controller_retries_failure_capture_before_teardown(tmp_path):
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    retry_capture = script.split("capture_host_with_retries() {", 1)[1].split(
        "configure_host() {", 1
    )[0]

    assert "readonly CAPTURE_RETRY_ATTEMPTS=6" in script
    assert "readonly CAPTURE_RETRY_INTERVAL_SECONDS=5" in script
    assert 'attempt_label="${label}-capture-attempt-${attempt}"' in retry_capture
    assert 'capture_host "$attempt_label" "$host" "$transient_unit"' in retry_capture
    assert (
        'cp "$EVIDENCE_DIR/${attempt_label}.txt" "$EVIDENCE_DIR/${label}.txt"'
        in retry_capture
    )
    assert '>>"$EVIDENCE_DIR/${label}-capture-retries.log"' in retry_capture
    assert "attempt < CAPTURE_RETRY_ATTEMPTS" in retry_capture
    assert 'sleep "$CAPTURE_RETRY_INTERVAL_SECONDS"' in retry_capture
    assert 'return "$capture_status"' in retry_capture

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    dynamic_check = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "CAPTURE_RETRY_ATTEMPTS=6\n"
            "CAPTURE_RETRY_INTERVAL_SECONDS=5\n"
            f"EVIDENCE_DIR={evidence!s}\n"
            "capture_attempts=0\n"
            "capture_host() { capture_attempts=$((capture_attempts + 1)); "
            "printf 'attempt-%s\\n' \"$capture_attempts\" "
            '>"$EVIDENCE_DIR/$1.txt"; (( capture_attempts >= 3 )); }\n'
            "sleep() { :; }\n"
            "capture_host_with_retries() {" + retry_capture + "\n"
            "capture_host_with_retries transient-host vm-a\n"
            'test "$capture_attempts" -eq 3\n'
            'test "$(wc -l < "$EVIDENCE_DIR/transient-host-capture-retries.log")" '
            "-eq 3\n"
            "grep -Fx 'attempt=3 status=0' "
            '"$EVIDENCE_DIR/transient-host-capture-retries.log"\n'
            "grep -Fx 'attempt-1' "
            '"$EVIDENCE_DIR/transient-host-capture-attempt-1.txt"\n'
            "grep -Fx 'attempt-2' "
            '"$EVIDENCE_DIR/transient-host-capture-attempt-2.txt"\n'
            "grep -Fx 'attempt-3' "
            '"$EVIDENCE_DIR/transient-host.txt"',
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert dynamic_check.returncode == 0, dynamic_check.stderr

    exhausted = tmp_path / "exhausted"
    exhausted.mkdir()
    exhausted_check = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "CAPTURE_RETRY_ATTEMPTS=6\n"
            "CAPTURE_RETRY_INTERVAL_SECONDS=5\n"
            f"EVIDENCE_DIR={exhausted!s}\n"
            "capture_attempts=0\n"
            "capture_host() { capture_attempts=$((capture_attempts + 1)); "
            "if (( capture_attempts == 1 )); then printf 'useful-partial\\n' "
            '>"$EVIDENCE_DIR/$1.txt"; else : >"$EVIDENCE_DIR/$1.txt"; fi; '
            "return 255; }\n"
            "sleep() { :; }\n"
            "capture_host_with_retries() {" + retry_capture + "\n"
            "! capture_host_with_retries exhausted-host vm-b\n"
            'test "$(wc -l < "$EVIDENCE_DIR/exhausted-host-capture-retries.log")" '
            "-eq 6\n"
            "grep -Fx 'useful-partial' "
            '"$EVIDENCE_DIR/exhausted-host-capture-attempt-1.txt"\n'
            'test ! -e "$EVIDENCE_DIR/exhausted-host.txt"',
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert exhausted_check.returncode == 0, exhausted_check.stderr


def test_live_controller_failure_evidence_includes_runtime_gate_and_timers():
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    capture_host = script.split("capture_host() {", 1)[1].split(
        "configure_host() {", 1
    )[0]

    for unit in (
        "cathedral-validator-direct.service",
        "cathedral-validator-boot-reconcile.service",
    ):
        assert f"systemctl show {unit}" in capture_host
        assert f"systemctl status {unit} --full --no-pager" in capture_host
        assert f"systemctl cat {unit}" in capture_host
        assert f"-u {unit}" in capture_host
    for unit in (
        "cathedral-validator-canary-update.service",
        "cathedral-validator-update.service",
    ):
        assert unit in capture_host
        assert f"-u {unit}" in capture_host
    assert (
        "systemctl status cathedral-validator-canary-update.service "
        "cathedral-validator-update.service --full --no-pager"
    ) in capture_host
    assert (
        "systemctl cat cathedral-validator-canary-update.service "
        "cathedral-validator-update.service"
    ) in capture_host
    for field in (
        "Result",
        "ExecMainCode",
        "ExecMainStatus",
        "ActiveState",
        "SubState",
        "FragmentPath",
        "DropInPaths",
    ):
        assert f"-p {field}" in capture_host
    assert "systemctl cat cathedral-validator-canary-update.timer" in capture_host
    assert "cathedral-validator-update.timer" in capture_host
    assert "-b -n 250 --no-pager" in capture_host
    assert '>"$EVIDENCE_DIR/${label}.txt" 2>&1' in capture_host
    assert "unsafe transient systemd unit for evidence capture" in capture_host
    assert "systemctl show '${transient_unit}.service'" in capture_host
    assert (
        "systemctl status '${transient_unit}.service' --full --no-pager" in capture_host
    )
    assert (
        "journalctl -u '${transient_unit}.service' -b -n 250 --no-pager" in capture_host
    )
    assert '>>"$EVIDENCE_DIR/${label}.txt" 2>&1' in capture_host
    assert script.count('capture_host "$attempt_label" "$host" "$transient_unit"') == 1
    assert script.count("\ncapture_host ") == 0


def test_live_controller_capture_preserves_both_ssh_failure_statuses(tmp_path):
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    capture_host = (
        "capture_host() {"
        + script.split("capture_host() {", 1)[1].split(
            "capture_host_with_retries() {", 1
        )[0]
    )
    evidence = tmp_path / "host-evidence"
    evidence.mkdir()

    dynamic_check = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            'EVIDENCE_DIR="$1"\n'
            "remote_calls=0\n"
            "generic_result=0\n"
            "transient_result=0\n"
            "remote() {\n"
            "  remote_calls=$((remote_calls + 1))\n"
            "  printf 'remote-%s\\n' \"$remote_calls\"\n"
            '  if (( remote_calls == 1 )); then return "$generic_result"; fi\n'
            '  return "$transient_result"\n'
            "}\n" + capture_host + "\n"
            "capture_host both-ok vm-a transient-a\n"
            "grep -Fx 'remote-1' \"$EVIDENCE_DIR/both-ok.txt\"\n"
            "grep -Fx 'remote-2' \"$EVIDENCE_DIR/both-ok.txt\"\n"
            "remote_calls=0\n"
            "generic_result=255\n"
            "transient_result=0\n"
            "if capture_host generic-fails vm-a transient-a; then exit 10; "
            "else status=$?; fi\n"
            'test "$status" -eq 255\n'
            "remote_calls=0\n"
            "generic_result=0\n"
            "transient_result=254\n"
            "if capture_host transient-fails vm-a transient-a; then exit 11; "
            "else status=$?; fi\n"
            'test "$status" -eq 254\n'
            "remote_calls=0\n"
            "if capture_host unsafe-unit vm-a 'bad/unit'; then exit 12; "
            "else status=$?; fi\n"
            'test "$status" -eq 2\n'
            'test "$remote_calls" -eq 0',
            "capture-host-test",
            str(evidence),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert dynamic_check.returncode == 0, dynamic_check.stderr


def test_live_controller_observes_update_then_proves_timer_rearmed(tmp_path):
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    start_timer = script.split("start_update_timer() {", 1)[1].split(
        "timer_state_is_rearmed() {", 1
    )[0]
    wait_sequence = script.split("wait_sequence() {", 1)[1].split(
        "start_update_timer() {", 1
    )[0]
    timer_state_check = (
        "timer_state_is_rearmed() {"
        + script.split("timer_state_is_rearmed() {", 1)[1].split(
            "wait_timer_rearmed() {", 1
        )[0]
    )
    rearm_timer = script.split("wait_timer_rearmed() {", 1)[1].split(
        "observe_timer_update() {", 1
    )[0]
    observe_timer = script.split("observe_timer_update() {", 1)[1].split(
        "run_update() {", 1
    )[0]

    assert "systemctl enable --now '$timer'" in start_timer
    assert "systemctl restart" not in start_timer
    assert "systemctl is-enabled --quiet '$timer'" in start_timer
    assert "systemctl is-active --quiet '$timer'" in start_timer
    assert "systemctl show '$timer'" in start_timer
    assert "systemctl list-timers --all --no-pager '$timer'" in start_timer
    assert "NextElapseUSecMonotonic" in start_timer
    assert "NextElapseUSecRealtime" not in start_timer
    assert "timer_status=\\$?" in start_timer
    assert "exit \\$timer_status" in start_timer
    assert "grep -Eq" not in start_timer
    assert ".sequence == $sequence and .pending == null" in wait_sequence
    assert '2>>"$EVIDENCE_DIR/${label}-sequence-snapshot-ssh.stderr"' in wait_sequence
    assert (
        'capture_host_with_retries "${label}-sequence-wait-failure" '
        '"$host" || true' in wait_sequence
    )
    assert "sleep 5" in wait_sequence
    assert "systemctl show '$timer'" in rearm_timer
    assert "-p ActiveState -p SubState -p NextElapseUSecMonotonic" in rearm_timer
    assert 'timer_state_is_rearmed "$active" "$substate" "$next"' in rearm_timer
    assert 'local timer_state=""' in rearm_timer
    assert "SECONDS + 120" in rearm_timer
    healthy_rearm = subprocess.run(
        [
            "/bin/bash",
            "-c",
            timer_state_check
            + "\ntimer_state_is_rearmed active waiting '22min 43.306514s'",
        ],
        check=False,
    )
    assert healthy_rearm.returncode == 0
    for unavailable in ("", "0", "infinity", "n/a"):
        unhealthy_rearm = subprocess.run(
            [
                "/bin/bash",
                "-c",
                timer_state_check + '\ntimer_state_is_rearmed active waiting "$1"',
                "timer-rearm-test",
                unavailable,
            ],
            check=False,
        )
        assert unhealthy_rearm.returncode != 0

    rearm_evidence = tmp_path / "rearm-evidence"
    rearm_evidence.mkdir()
    rearm_calls = tmp_path / "rearm-calls"
    dynamic_rearm = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            'EVIDENCE_DIR="$1"\n'
            'CALLS="$2"\n'
            ': >"$CALLS"\n'
            "remote() {\n"
            '  count="$(wc -l <"$CALLS")"\n'
            "  printf 'call\\n' >>\"$CALLS\"\n"
            "  if (( count == 0 )); then printf 'first-ssh-failure\\n' >&2; "
            "return 255; fi\n"
            "  if (( count == 1 )); then printf '%s\\n' "
            "'ActiveState=active' 'SubState=running' "
            "'NextElapseUSecMonotonic=0'; return 0; fi\n"
            "  printf '%s\\n' 'ActiveState=active' 'SubState=waiting' "
            "'NextElapseUSecMonotonic=22min 43.306514s'\n"
            "}\n"
            "sleep() { :; }\n"
            + timer_state_check
            + "\nwait_timer_rearmed() {"
            + rearm_timer
            + "\nwait_timer_rearmed rearm vm-a timer-a\n"
            'test "$(wc -l <"$CALLS")" -eq 3\n'
            "grep -Fx 'first-ssh-failure' "
            '"$EVIDENCE_DIR/rearm-timer-rearm-ssh.stderr"',
            "timer-rearm-retry-test",
            str(rearm_evidence),
            str(rearm_calls),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert dynamic_rearm.returncode == 0, dynamic_rearm.stderr
    for phase in ("start", "wait", "current", "rearm"):
        assert f"${{label}}-timer-{phase}-command.log" in observe_timer
        assert (
            f'capture_host_with_retries "${{label}}-timer-{phase}-failure" '
            '"$host" || true' in observe_timer
        )
    assert script.count('observe_timer_update canary-timer-a-to-b "$CANARY_VM"') == 1
    assert script.count('observe_timer_update stable-exact-promotion "$STABLE_VM"') == 1
    assert (
        script.count('observe_timer_update canary-same-archive-renewal "$CANARY_VM"')
        == 1
    )


def test_live_controller_polls_pending_state_with_short_ssh_snapshots(tmp_path):
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    wait_pending = script.split("wait_pending() {", 1)[1].split(
        "launch_background_update() {", 1
    )[0]

    assert "--pending-target" not in wait_pending
    assert "local deadline=$((SECONDS + CRASH_PENDING_WAIT_SECONDS))" in wait_pending
    assert 'local started_at="$5"' in wait_pending
    assert "started_at + TRANSIENT_UPDATE_TIMEOUT_SECONDS" in wait_pending
    assert "CRASH_POST_PENDING_RESERVE_SECONDS" in wait_pending
    assert "RESET_MINIMUM_HEADROOM_SECONDS" in wait_pending
    assert "absolute_deadline < deadline" in wait_pending
    assert 'snapshot_state "$host" stable' in wait_pending
    assert '2>>"$EVIDENCE_DIR/${label}-pending-snapshot-ssh.stderr"' in wait_pending
    assert (
        '.pending.stage == "may_have_run" and '
        ".pending.target_current == $target" in wait_pending
    )
    assert "sleep 2" in wait_pending
    assert "capture_host_with_retries \\" in wait_pending
    assert (
        '"${label}-pending-wait-failure" "$host" "$transient_unit" || true'
        in wait_pending
    )
    assert 'local transient_unit="$4"' in wait_pending
    assert script.count('wait_pending stable-reset "$STABLE_VM" "$ARCHIVE_A_SHA"') == 1
    assert '"cathedral-live-reset-${RUN_ID}"' in script
    assert script.count('wait_pending stable-rescue "$STABLE_VM" "$ARCHIVE_B_SHA"') == 1
    assert '"cathedral-live-rescue-${RUN_ID}"' in script
    assert 'capture_host_with_retries stable-before-reset "$STABLE_VM"' not in script
    assert 'capture_host_with_retries stable-before-rescue "$STABLE_VM"' not in script
    assert 'capture_host_with_retries stable-after-reset "$STABLE_VM"' in script
    assert 'capture_host_with_retries stable-after-rescue-crash "$STABLE_VM"' in script

    evidence = tmp_path / "pending-evidence"
    evidence.mkdir()
    calls = tmp_path / "snapshot-calls"
    captures = tmp_path / "capture-calls"
    dynamic_check = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            "CRASH_PENDING_WAIT_SECONDS=120\n"
            "TRANSIENT_UPDATE_TIMEOUT_SECONDS=240\n"
            "CRASH_POST_PENDING_RESERVE_SECONDS=60\n"
            "RESET_MINIMUM_HEADROOM_SECONDS=60\n"
            'EVIDENCE_DIR="$1"\n'
            'CALLS="$2"\n'
            'CAPTURES="$3"\n'
            "printf '0\\n' >\"$CALLS\"\n"
            ': >"$CAPTURES"\n'
            "snapshot_state() {\n"
            '  call="$(cat "$CALLS")"\n'
            "  call=$((call + 1))\n"
            '  printf \'%s\\n\' "$call" >"$CALLS"\n'
            '  case "$call" in\n'
            "    1) printf 'transient transport failure\\n' >&2; return 255 ;;\n"
            "    2) printf '%s\\n' "
            '\'{"pending":{"stage":"not_yet",'
            '"target_current":"releases/exact"}}\' ;;\n'
            "    3) printf '%s\\n' "
            '\'{"pending":{"stage":"may_have_run",'
            '"target_current":"releases/wrong"}}\' ;;\n'
            "    *) printf '%s\\n' "
            '\'{"pending":{"stage":"may_have_run",'
            '"target_current":"releases/exact"}}\' ;;\n'
            "  esac\n"
            "}\n"
            "capture_host_with_retries() { "
            'printf \'%s %s %s\\n\' "$1" "$2" "$3" >>"$CAPTURES"; }\n'
            "sleep() { :; }\n"
            "wait_pending() {" + wait_pending + "\n"
            "started_at=$SECONDS\n"
            'wait_pending pending-sequence vm-a exact transient-success "$started_at"\n'
            'test "$(cat "$CALLS")" -eq 4\n'
            'test ! -s "$CAPTURES"\n'
            "grep -Fx 'transient transport failure' "
            '"$EVIDENCE_DIR/pending-sequence-pending-snapshot-ssh.stderr"\n'
            "printf '0\\n' >\"$CALLS\"\n"
            ': >"$CAPTURES"\n'
            "snapshot_state() {\n"
            '  call="$(cat "$CALLS")"\n'
            "  call=$((call + 1))\n"
            '  printf \'%s\\n\' "$call" >"$CALLS"\n'
            "  printf 'snapshot still wrong\\n' >&2\n"
            "  printf '%s\\n' "
            '\'{"pending":{"stage":"may_have_run",'
            '"target_current":"releases/wrong"}}\'\n'
            "}\n"
            "sleep() { SECONDS=$((SECONDS + 121)); }\n"
            "started_at=$SECONDS\n"
            '! wait_pending timeout-sequence vm-b exact transient-timeout "$started_at"\n'
            'test "$(cat "$CALLS")" -eq 1\n'
            "grep -Fx 'timeout-sequence-pending-wait-failure vm-b transient-timeout' "
            '"$CAPTURES"\n'
            "grep -Fx 'snapshot still wrong' "
            '"$EVIDENCE_DIR/timeout-sequence-pending-snapshot-ssh.stderr"\n'
            "printf '0\\n' >\"$CALLS\"\n"
            ': >"$CAPTURES"\n'
            "SECONDS=1000\n"
            "started_at=879\n"
            '! wait_pending absolute-timeout vm-c exact transient-expired "$started_at"\n'
            'test "$(cat "$CALLS")" -eq 0\n'
            "grep -Fx 'absolute-timeout-pending-wait-failure vm-c transient-expired' "
            '"$CAPTURES"\n'
            "grep -F 'absolute_deadline=999 selected_deadline=999' "
            '"$EVIDENCE_DIR/absolute-timeout-pending-deadline.txt"\n'
            "printf '0\\n' >\"$CALLS\"\n"
            ': >"$CAPTURES"\n'
            "CRASH_PENDING_WAIT_SECONDS=1\n"
            "TRANSIENT_UPDATE_TIMEOUT_SECONDS=240\n"
            "SECONDS=1100\n"
            "snapshot_state() {\n"
            '  call="$(cat "$CALLS")"\n'
            "  call=$((call + 1))\n"
            '  printf \'%s\\n\' "$call" >"$CALLS"\n'
            "  /bin/sleep 2\n"
            "  printf '%s\\n' "
            '\'{"pending":{"stage":"may_have_run",'
            '"target_current":"releases/exact"}}\'\n'
            "}\n"
            "started_at=$SECONDS\n"
            "if wait_pending late-snapshot vm-d exact transient-late "
            '"$started_at" 2>"$EVIDENCE_DIR/late-snapshot.stderr"; then exit 19; fi\n'
            'test "$(cat "$CALLS")" -eq 1\n'
            "grep -Fx 'late-snapshot-pending-wait-failure vm-d transient-late' "
            '"$CAPTURES"\n'
            "grep -F 'exact pending state arrived after the reserved action deadline' "
            '"$EVIDENCE_DIR/late-snapshot.stderr"',
            "pending-test",
            str(evidence),
            str(calls),
            str(captures),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert dynamic_check.returncode == 0, dynamic_check.stderr


def test_live_controller_revalidates_crash_boundary_after_capture(
    tmp_path, monkeypatch
):
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    pre_action = (
        "assert_pending_pre_action() {"
        + script.split("assert_pending_pre_action() {", 1)[1].split(
            "launch_background_update() {", 1
        )[0]
    )
    rescue_crash = (
        "crash_pending_transient_for_rescue() {"
        + script.split("crash_pending_transient_for_rescue() {", 1)[1].split(
            'record_step "reset at durable may_have_run', 1
        )[0]
    )
    boot_wait = (
        "wait_boot_id_changed() {"
        + script.split("wait_boot_id_changed() {", 1)[1].split(
            'wait_ssh "$CANARY_VM"', 1
        )[0]
    )
    boot_read = (
        "canonical_boot_id() {"
        + script.split("canonical_boot_id() {", 1)[1].split("wait_ssh() {", 1)[0]
    )
    reset_transition = script.split('record_step "reset at durable may_have_run', 1)[
        1
    ].split('record_step "leave B crash-uncertain', 1)[0]
    rescue_transition = script.split('record_step "leave B crash-uncertain', 1)[
        1
    ].split("assert_project_metadata_unchanged final", 1)[0]

    assert '.current == $target and .pending.stage == "may_have_run"' in pre_action
    assert ".pending.target_current == $target" in pre_action
    assert "ActiveState=active" in pre_action
    assert "SubState=running" in pre_action
    assert "^MainPID=[1-9][0-9]*$" in pre_action
    assert "TRANSIENT_UPDATE_TIMEOUT_SECONDS - elapsed" in pre_action
    assert "remaining >= RESET_MINIMUM_HEADROOM_SECONDS" in pre_action
    assert "PRE_ACTION_READ_ATTEMPTS" in pre_action
    assert "PRE_ACTION_RETRY_INTERVAL_SECONDS" in pre_action
    assert "source=state" in pre_action
    assert "source=unit" in pre_action
    assert "transient updater journal before action" in pre_action
    assert "journalctl -u '${transient_unit}.service' -b -n 80" in pre_action
    assert "BootID=%s" in pre_action
    assert "host rebooted during pending crash preparation" in pre_action
    assert "pre-action state could not be read after transport retries" in pre_action

    def shell_constant(name):
        match = re.search(rf"^readonly {name}=([0-9]+)$", script, re.M)
        assert match is not None
        return int(match.group(1))

    transient_timeout = shell_constant("TRANSIENT_UPDATE_TIMEOUT_SECONDS")
    transient_systemd_timeout = shell_constant("TRANSIENT_SYSTEMD_TIMEOUT_SECONDS")
    timer_systemd_margin = shell_constant("TIMER_SYSTEMD_MARGIN_SECONDS")
    reset_headroom = shell_constant("RESET_MINIMUM_HEADROOM_SECONDS")
    pending_wait = shell_constant("CRASH_PENDING_WAIT_SECONDS")
    post_pending_reserve = shell_constant("CRASH_POST_PENDING_RESERVE_SECONDS")
    service_control_timeout = shell_constant(
        "VALIDATOR_SERVICE_CONTROL_TIMEOUT_SECONDS"
    )
    direct_timeout = shell_constant("DIRECT_START_TIMEOUT_SECONDS")
    readiness_delay = shell_constant("READINESS_DELAY_MAX_SECONDS")
    updater_source = (
        root / "cathedral_thin/independent_runtime/updater.py"
    ).read_text()
    updater_service_timeout = re.search(
        r"^DEFAULT_SERVICE_CONTROL_TIMEOUT_SECONDS = ([0-9_]+(?:\.[0-9]+)?)$",
        updater_source,
        re.M,
    )
    assert updater_service_timeout is not None
    assert service_control_timeout == int(
        float(updater_service_timeout.group(1).replace("_", ""))
    )
    live_readiness = _live_readiness_namespace(monkeypatch)
    assert transient_timeout == 240
    assert reset_headroom == 60
    assert transient_timeout >= pending_wait + post_pending_reserve + reset_headroom
    assert transient_systemd_timeout >= transient_timeout + timer_systemd_margin
    assert direct_timeout >= transient_timeout + reset_headroom
    assert readiness_delay >= transient_timeout + reset_headroom
    assert direct_timeout <= service_control_timeout
    assert readiness_delay <= service_control_timeout
    assert live_readiness["MAX_DELAY_SECONDS"] == readiness_delay
    assert "TimeoutStartSec=${DIRECT_START_TIMEOUT_SECONDS}s" in script
    assert script.count("'$READINESS_DELAY_MAX_SECONDS'") == 2
    assert "--operation-timeout-seconds='$TRANSIENT_UPDATE_TIMEOUT_SECONDS'" in script
    assert "--property=RuntimeMaxSec='${TRANSIENT_SYSTEMD_TIMEOUT_SECONDS}s'" in script
    assert "cat /proc/sys/kernel/random/boot_id" in boot_read
    assert "canonical_boot_id" in boot_read
    assert "read_boot_id" in boot_read
    assert '"$observed" != "$before"' in boot_wait
    assert "reboot was not proven by a changed boot ID" in boot_wait
    assert (
        reset_transition.index("require_host_value stable-reset-boot-id-before")
        < reset_transition.index("reset_started_at=$SECONDS")
        < reset_transition.index("launch_background_update")
        < reset_transition.index("wait_pending stable-reset")
        < (reset_transition.index("assert_pending_pre_action stable-reset-pre-action"))
        < reset_transition.index("require_host_proof stable-reset-request")
        < reset_transition.index("require_host_proof stable-reset-reboot-observed")
        < reset_transition.index("require_host_proof stable-reset-direct-restart")
        < reset_transition.index("capture_host_with_retries stable-after-reset")
    )
    assert 'read_boot_id "$STABLE_VM"' in reset_transition
    assert '"$reset_started_at" \\\n  "$reset_boot_id"' in reset_transition
    assert (
        rescue_transition.index("rescue_started_at=$SECONDS")
        < rescue_transition.index("launch_background_update")
        < rescue_transition.index("assert_pending_pre_action stable-rescue-pre-action")
        < rescue_transition.index(
            "crash_pending_transient_for_rescue stable-rescue-crash"
        )
        < rescue_transition.index("capture_host_with_retries stable-after-rescue-crash")
        < rescue_transition.index("rescue_url=")
    )
    kill = "sudo systemctl kill --kill-whom=main --signal=KILL"
    assert rescue_crash.count('if remote "$host"') == 1
    assert rescue_crash.index('test \\"\\$current\\"') < rescue_crash.index(kill)
    assert rescue_crash.index(".pending.stage") < rescue_crash.index(kill)
    assert rescue_crash.index("ActiveState=active") < rescue_crash.index(kill)
    assert rescue_crash.index("SubState=running") < rescue_crash.index(kill)
    assert rescue_crash.index("sudo kill -0") < rescue_crash.index(kill)
    kill_fragment = rescue_crash.split(kill, 1)[1].split(";", 1)[0]
    assert "|| true" not in kill_fragment

    boot_evidence = tmp_path / "boot-evidence"
    boot_evidence.mkdir()
    boot_calls = tmp_path / "boot-calls"
    boot_check = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            'EVIDENCE_DIR="$1"\n'
            'CALLS="$2"\n'
            ': >"$CALLS"\n'
            "remote() {\n"
            '  count="$(wc -l <"$CALLS")"\n'
            "  printf 'call\\n' >>\"$CALLS\"\n"
            "  if (( count == 0 )); then return 255; fi\n"
            "  if (( count == 1 )); then printf '%s\\n' "
            "11111111-1111-1111-1111-111111111111; return 0; fi\n"
            "  printf '%s\\n' 22222222-2222-2222-2222-222222222222\n"
            "}\n"
            "sleep() { :; }\n" + boot_read + "\n" + boot_wait + "\n"
            "wait_boot_id_changed reboot vm-a "
            "11111111-1111-1111-1111-111111111111\n"
            'test "$(wc -l <"$CALLS")" -eq 3\n'
            "grep -Fx 'before=11111111-1111-1111-1111-111111111111 "
            "observed=22222222-2222-2222-2222-222222222222' "
            '"$EVIDENCE_DIR/reboot-boot-id-observations.log"',
            "boot-id-test",
            str(boot_evidence),
            str(boot_calls),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert boot_check.returncode == 0, boot_check.stderr

    boot_precheck_actions = tmp_path / "boot-precheck-actions"
    boot_precheck = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            'ACTIONS="$1"\n'
            ': >"$ACTIONS"\n'
            "mode=crlf\n"
            "remote() {\n"
            "  if [[ \"$mode\" == crlf ]]; then printf '%s\\r\\n' "
            "11111111-1111-1111-1111-111111111111; else "
            "printf 'malformed\\r\\n'; fi\n"
            "}\n" + boot_read + "\n"
            'normalized="$(read_boot_id vm-a)"\n'
            'test "$normalized" = 11111111-1111-1111-1111-111111111111\n'
            "mode=invalid\n"
            'if reset_boot_id="$(read_boot_id vm-a)"; then '
            "printf 'reset-issued\\n' >\"$ACTIONS\"; exit 18; "
            "else status=$?; fi\n"
            'test "$status" -eq 2\n'
            'test ! -s "$ACTIONS"',
            "boot-precheck-test",
            str(boot_precheck_actions),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert boot_precheck.returncode == 0, boot_precheck.stderr

    evidence = tmp_path / "pre-action-evidence"
    evidence.mkdir()
    actions = tmp_path / "actions"
    captures = tmp_path / "captures"
    remote_calls = tmp_path / "remote-calls"
    stale_check = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            "TRANSIENT_UPDATE_TIMEOUT_SECONDS=240\n"
            "RESET_MINIMUM_HEADROOM_SECONDS=60\n"
            "PRE_ACTION_READ_ATTEMPTS=3\n"
            "PRE_ACTION_RETRY_INTERVAL_SECONDS=0\n"
            'EVIDENCE_DIR="$1"\n'
            'ACTIONS="$2"\n'
            'CAPTURES="$3"\n'
            'REMOTE_CALLS="$4"\n'
            ': >"$ACTIONS"\n'
            ': >"$CAPTURES"\n'
            ': >"$REMOTE_CALLS"\n'
            "state_mode=exact\n"
            "snapshot_state() {\n"
            '  if [[ "$state_mode" == exact ]]; then\n'
            "    printf '%s\\n' "
            '\'{"current":"releases/exact","pending":{'
            '"stage":"may_have_run",'
            '"target_current":"releases/exact"}}\'\n'
            "  else\n"
            "    printf '%s\\n' "
            '\'{"current":"releases/old","pending":{'
            '"stage":"may_have_run",'
            '"target_current":"releases/exact"}}\'\n'
            "  fi\n"
            "}\n"
            "remote() { "
            "printf 'called\\n' >>\"$REMOTE_CALLS\"; "
            "printf '%s\\n' 'ActiveState=active' 'SubState=running' "
            "'MainPID=42' 'BootID=11111111-1111-1111-1111-111111111111'; }\n"
            "capture_host_with_retries() {\n"
            '  if [[ "$1" == simulate-capture ]]; then '
            "state_mode=stale; SECONDS=$((SECONDS + 181)); return 0; fi\n"
            '  printf \'%s %s %s\\n\' "$1" "$2" "$3" >>"$CAPTURES"\n'
            "}\n" + boot_read + "\n" + pre_action + "\n"
            "capture_host_with_retries simulate-capture vm-a transient-a\n"
            "assert_pending_pre_action pre-action vm-a exact transient-a 0\n"
            "printf 'reset-issued\\n' >>\"$ACTIONS\"",
            "pre-action-stale-test",
            str(evidence),
            str(actions),
            str(captures),
            str(remote_calls),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert stale_check.returncode != 0
    assert actions.read_text() == ""
    assert remote_calls.read_text() == ""
    assert captures.read_text() == "pre-action-state-failure vm-a transient-a\n"
    assert (evidence / "pre-action-state.json").exists()

    success = tmp_path / "success"
    success.mkdir()
    success_actions = tmp_path / "success-actions"
    success_captures = tmp_path / "success-captures"
    success_check = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            "TRANSIENT_UPDATE_TIMEOUT_SECONDS=240\n"
            "RESET_MINIMUM_HEADROOM_SECONDS=60\n"
            "PRE_ACTION_READ_ATTEMPTS=3\n"
            "PRE_ACTION_RETRY_INTERVAL_SECONDS=0\n"
            'EVIDENCE_DIR="$1"\n'
            'ACTIONS="$2"\n'
            'CAPTURES="$3"\n'
            ': >"$CAPTURES"\n'
            "snapshot_state() { printf '%s\\n' "
            '\'{"current":"releases/exact","pending":{'
            '"stage":"may_have_run",'
            '"target_current":"releases/exact"}}\'; }\n'
            "remote() { printf '%s\\n' 'ActiveState=active' 'SubState=running' "
            "'MainPID=42' 'BootID=11111111-1111-1111-1111-111111111111'; }\n"
            "capture_host_with_retries() { "
            'printf \'%s %s %s\\n\' "$1" "$2" "$3" >>"$CAPTURES"; }\n'
            + boot_read
            + "\n"
            + pre_action
            + "\n"
            "started_at=$SECONDS\n"
            'assert_pending_pre_action pre-action vm-a exact transient-a "$started_at"\n'
            "printf 'action-issued\\n' >\"$ACTIONS\"\n"
            "SECONDS=$((started_at + 181))\n"
            "if assert_pending_pre_action no-headroom vm-a exact transient-a "
            '"$started_at"; then exit 14; else status=$?; fi\n'
            'test "$status" -eq 1',
            "pre-action-success-test",
            str(success),
            str(success_actions),
            str(success_captures),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert success_check.returncode == 0, success_check.stderr
    assert success_actions.read_text() == "action-issued\n"
    assert (
        success_captures.read_text()
        == "no-headroom-headroom-failure vm-a transient-a\n"
    )

    retry_evidence = tmp_path / "retry-evidence"
    retry_evidence.mkdir()
    retry_actions = tmp_path / "retry-actions"
    retry_captures = tmp_path / "retry-captures"
    retry_remote_calls = tmp_path / "retry-remote-calls"
    retry_check = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            "TRANSIENT_UPDATE_TIMEOUT_SECONDS=240\n"
            "RESET_MINIMUM_HEADROOM_SECONDS=60\n"
            "PRE_ACTION_READ_ATTEMPTS=3\n"
            "PRE_ACTION_RETRY_INTERVAL_SECONDS=0\n"
            'EVIDENCE_DIR="$1"\n'
            'ACTIONS="$2"\n'
            'CAPTURES="$3"\n'
            'REMOTE_CALLS="$4"\n'
            ': >"$ACTIONS"\n'
            ': >"$CAPTURES"\n'
            ': >"$REMOTE_CALLS"\n'
            "snapshot_state() { printf '%s\\n' "
            '\'{"current":"releases/exact","pending":{'
            '"stage":"may_have_run",'
            '"target_current":"releases/exact"}}\'; }\n'
            "remote() {\n"
            '  count="$(wc -l <"$REMOTE_CALLS")"\n'
            "  printf 'call\\n' >>\"$REMOTE_CALLS\"\n"
            "  if (( count == 0 )); then printf 'transient-ssh\\n' >&2; "
            "return 255; fi\n"
            "  printf '%s\\n' 'ActiveState=active' 'SubState=running' "
            "'MainPID=42' 'BootID=11111111-1111-1111-1111-111111111111'\n"
            "}\n"
            "sleep() { :; }\n"
            "capture_host_with_retries() { "
            'printf \'%s %s %s\\n\' "$1" "$2" "$3" >>"$CAPTURES"; }\n'
            + boot_read
            + "\n"
            + pre_action
            + "\n"
            "started_at=$SECONDS\n"
            'assert_pending_pre_action retry vm-a exact transient-a "$started_at"\n'
            "printf 'action-issued\\n' >\"$ACTIONS\"\n"
            'test "$(wc -l <"$REMOTE_CALLS")" -eq 2\n'
            'test ! -s "$CAPTURES"\n'
            "grep -Fx 'attempt=1 source=unit status=255' "
            '"$EVIDENCE_DIR/retry-read-retries.log"\n'
            "grep -Fx 'transient-ssh' "
            '"$EVIDENCE_DIR/retry-unit-ssh.stderr"',
            "pre-action-retry-test",
            str(retry_evidence),
            str(retry_actions),
            str(retry_captures),
            str(retry_remote_calls),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert retry_check.returncode == 0, retry_check.stderr
    assert retry_actions.read_text() == "action-issued\n"


def test_live_controller_captures_terminal_recovery_proofs(tmp_path):
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    require_proof = (
        "require_host_proof() {"
        + script.split("require_host_proof() {", 1)[1].split(
            "require_host_value() {", 1
        )[0]
    )
    require_value = (
        "require_host_value() {"
        + script.split("require_host_value() {", 1)[1].split("snapshot_state() {", 1)[0]
    )
    assert_current = (
        "assert_current() {"
        + script.split("assert_current() {", 1)[1].split(
            'record_step "prove both first installs', 1
        )[0]
    )
    reset_transition = script.split('record_step "reset at durable may_have_run', 1)[
        1
    ].split('record_step "leave B crash-uncertain', 1)[0]
    rescue_transition = script.split('record_step "leave B crash-uncertain', 1)[
        1
    ].split("assert_project_metadata_unchanged final", 1)[0]

    assert '2>&1 | tee "$EVIDENCE_DIR/${label}-command.log"' in require_proof
    assert 'capture_host_with_retries "${label}-failure" "$host" || true' in (
        require_proof
    )
    assert '2>"$EVIDENCE_DIR/${label}-value-command.stderr"' in require_value
    assert '| tee "$EVIDENCE_DIR/${label}-value.txt"' in require_value
    assert 'capture_host_with_retries "${label}-failure" "$host" || true' in (
        require_value
    )
    assert '2>>"$EVIDENCE_DIR/${label}-current-ssh.stderr"' in assert_current
    assert '"$EVIDENCE_DIR/${label}-current-proof.txt"' in assert_current
    assert 'capture_host_with_retries "${label}-current-read-failure"' in (
        assert_current
    )
    assert 'capture_host_with_retries "${label}-current-mismatch"' in assert_current
    for label in (
        "stable-reset-request",
        "stable-reset-reboot-observed",
        "stable-reset-direct-restart",
        "stable-reset-reconcile-proof",
    ):
        assert f"require_host_proof {label}" in reset_transition
    for label in (
        "higher-sequence-rescue-update",
        "stable-rescue-marker-clear",
        "higher-sequence-rescue-activation",
        "higher-sequence-rescue-service",
    ):
        assert f"require_host_proof {label}" in rescue_transition
    assert "higher-sequence-rescue-update-command.log" in rescue_transition
    assert 'run_update "$STABLE_VM" stable "$rescue_url" | tee' not in script
    for label in (
        "same-archive-pid-before",
        "same-archive-pid-after",
        "pause-before",
        "pause-after",
        "stable-reset-boot-id-before",
    ):
        assert f"require_host_value {label}" in script
    assert 'pid_before="$(main_pid' not in script
    assert 'pid_after="$(main_pid' not in script
    assert 'pause_before="$(snapshot_state' not in script
    assert 'pause_after="$(snapshot_state' not in script

    evidence = tmp_path / "proof-evidence"
    evidence.mkdir()
    captures = tmp_path / "proof-captures"
    dynamic_proof = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            'EVIDENCE_DIR="$1"\n'
            'CAPTURES="$2"\n'
            ': >"$CAPTURES"\n'
            "capture_host_with_retries() { "
            'printf \'%s %s\\n\' "$1" "$2" >>"$CAPTURES"; }\n'
            "failing_proof() { printf 'partial-stdout\\n'; "
            "printf 'exact-stderr\\n' >&2; return 42; }\n" + require_proof + "\n"
            "if require_host_proof terminal vm-a failing_proof; then exit 14; "
            "else status=$?; fi\n"
            'test "$status" -eq 42\n'
            "grep -Fx 'partial-stdout' "
            '"$EVIDENCE_DIR/terminal-command.log"\n'
            "grep -Fx 'exact-stderr' "
            '"$EVIDENCE_DIR/terminal-command.log"\n'
            "grep -Fx 'terminal-failure vm-a' "
            '"$CAPTURES"',
            "terminal-proof-test",
            str(evidence),
            str(captures),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert dynamic_proof.returncode == 0, dynamic_proof.stderr

    value_evidence = tmp_path / "value-evidence"
    value_evidence.mkdir()
    value_captures = tmp_path / "value-captures"
    dynamic_value = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            'EVIDENCE_DIR="$1"\n'
            'CAPTURES="$2"\n'
            ': >"$CAPTURES"\n'
            "capture_host_with_retries() { "
            'printf \'%s %s\\n\' "$1" "$2" >>"$CAPTURES"; }\n'
            "good_value() { printf 'clean-value\\n'; "
            "printf 'success-stderr\\n' >&2; }\n"
            "bad_value() { printf 'partial-value\\n'; "
            "printf 'failure-stderr\\n' >&2; return 43; }\n" + require_value + "\n"
            'value="$(require_host_value good vm-a good_value)"\n'
            'test "$value" = clean-value\n'
            'if value="$(require_host_value bad vm-a bad_value)"; '
            "then exit 17; else status=$?; fi\n"
            'test "$status" -eq 43\n'
            "grep -Fx 'clean-value' "
            '"$EVIDENCE_DIR/good-value.txt"\n'
            "grep -Fx 'success-stderr' "
            '"$EVIDENCE_DIR/good-value-command.stderr"\n'
            "grep -Fx 'partial-value' "
            '"$EVIDENCE_DIR/bad-value.txt"\n'
            "grep -Fx 'failure-stderr' "
            '"$EVIDENCE_DIR/bad-value-command.stderr"\n'
            "grep -Fx 'bad-failure vm-a' "
            '"$CAPTURES"',
            "terminal-value-test",
            str(value_evidence),
            str(value_captures),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert dynamic_value.returncode == 0, dynamic_value.stderr

    current_evidence = tmp_path / "current-evidence"
    current_evidence.mkdir()
    current_captures = tmp_path / "current-captures"
    dynamic_current = subprocess.run(
        [
            "/bin/bash",
            "-c",
            "set -Eeuo pipefail\n"
            'EVIDENCE_DIR="$1"\n'
            'CAPTURES="$2"\n'
            ': >"$CAPTURES"\n'
            "capture_host_with_retries() { "
            'printf \'%s %s\\n\' "$1" "$2" >>"$CAPTURES"; }\n' + assert_current + "\n"
            "current_digest() { return 255; }\n"
            "if assert_current vm-a exact read-failure; then exit 15; "
            "else status=$?; fi\n"
            'test "$status" -eq 255\n'
            "current_digest() { printf 'wrong\\n'; }\n"
            "if assert_current vm-a exact mismatch; then exit 16; "
            "else status=$?; fi\n"
            'test "$status" -eq 1\n'
            "current_digest() { printf 'exact\\n'; }\n"
            "assert_current vm-a exact success\n"
            "grep -Fx 'read-failure-current-read-failure vm-a' "
            '"$CAPTURES"\n'
            "grep -Fx 'mismatch-current-mismatch vm-a' "
            '"$CAPTURES"\n'
            "grep -Fx 'expected=exact observed=exact' "
            '"$EVIDENCE_DIR/success-current-proof.txt"',
            "current-proof-test",
            str(current_evidence),
            str(current_captures),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert dynamic_current.returncode == 0, dynamic_current.stderr


def test_live_controller_timer_wait_covers_service_deadline_and_waiter_cap():
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    waiter = root / "tests" / "live" / "wait_updater_state.py"
    updater = (
        root / "cathedral_thin" / "independent_runtime" / "updater.py"
    ).read_text()

    assert "readonly FIXED_CHANNEL_CACHE_MAX_SECONDS=300" in script
    assert "readonly UPDATE_TIMER_INTERVAL_SECONDS=60" in script
    assert "readonly TIMER_OPERATION_TIMEOUT_SECONDS=1200" in script
    assert "readonly TIMER_SYSTEMD_MARGIN_SECONDS=120" in script
    assert "readonly FIXED_CHANNEL_WAIT_MARGIN_SECONDS=180" in script
    assert "readonly FIXED_CHANNEL_WAIT_SECONDS=1860" in script
    assert "FIXED_CHANNEL_WAIT_SECONDS < FIXED_CHANNEL_CACHE_MAX_SECONDS" in script
    assert "ServerAliveInterval=15" in script
    assert "ServerAliveCountMax=2" in script
    assert "MAX_WAIT_SECONDS = 600" in waiter.read_text()
    assert "wait_sequence() {" in script
    assert script.count('wait_sequence canary-first-install "$CANARY_VM" canary 1') == 1
    assert script.count('wait_sequence stable-first-install "$STABLE_VM" stable 1') == 1
    assert (
        script.count('wait_sequence stable-reset-reconcile "$STABLE_VM" stable 3') == 1
    )
    assert (
        script.count(
            'wait_sequence stable-higher-sequence-rescue "$STABLE_VM" stable 5'
        )
        == 1
    )

    def numeric_constant(source, name):
        match = re.search(rf"^{name} = ([0-9_]+(?:\.[0-9]+)?)$", source, re.M)
        assert match is not None
        return int(float(match.group(1).replace("_", "")))

    operation_timeout = numeric_constant(updater, "DEFAULT_OPERATION_TIMEOUT_SECONDS")
    systemd_margin = numeric_constant(updater, "SYSTEMD_TIMEOUT_MARGIN_SECONDS")

    def shell_numeric(name):
        match = re.search(rf"^readonly {name}=([0-9]+)$", script, re.M)
        assert match is not None
        return int(match.group(1))

    shell_timeout = shell_numeric("TIMER_OPERATION_TIMEOUT_SECONDS")
    shell_systemd_margin = shell_numeric("TIMER_SYSTEMD_MARGIN_SECONDS")
    assert shell_timeout == operation_timeout
    assert shell_systemd_margin == systemd_margin
    assert shell_numeric("FIXED_CHANNEL_WAIT_SECONDS") == (
        shell_numeric("FIXED_CHANNEL_CACHE_MAX_SECONDS")
        + shell_numeric("UPDATE_TIMER_INTERVAL_SECONDS")
        + shell_timeout
        + shell_systemd_margin
        + shell_numeric("FIXED_CHANNEL_WAIT_MARGIN_SECONDS")
    )
    for service in (
        "cathedral-validator-canary-update.service",
        "cathedral-validator-update.service",
    ):
        unit = (root / "deploy" / "validator-update" / service).read_text()
        assert f"TimeoutStartSec={operation_timeout + systemd_margin}s" in unit


def test_live_readiness_preserves_the_expected_pex_root(tmp_path, monkeypatch):
    require_pex_origin = _live_readiness_guard(monkeypatch)
    pex_root = tmp_path / "pex-root"
    module_path = pex_root / "installed_wheels/project/module.py"
    module_path.parent.mkdir(parents=True)
    module_path.touch()
    module = SimpleNamespace(__name__="packaged.module", __file__=str(module_path))

    monkeypatch.setenv("CATHEDRAL_LIVE_TEST_PEX_ROOT", str(pex_root))
    monkeypatch.setenv("PEX_ROOT", str(tmp_path / "stripped-pex-variable"))
    require_pex_origin(module)


def test_live_readiness_verifies_compute_before_importing_it(tmp_path, monkeypatch):
    namespace = _live_readiness_namespace(monkeypatch)
    main = namespace["main"]
    globals_map = main.__globals__
    events: list[str] = []

    for name in tuple(sys.modules):
        if name == "cathedral" or name.startswith("cathedral."):
            monkeypatch.delitem(sys.modules, name)

    compute_source = (
        tmp_path / "pex-root/installed_wheels/compute/cathedral/__init__.py"
    )
    compute_source.parent.mkdir(parents=True)
    compute_source.touch()

    class ComputeLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
        def find_spec(self, fullname, _path=None, _target=None):
            if fullname != "cathedral":
                return None
            events.append("compute_import")
            return importlib.util.spec_from_loader(
                fullname, self, origin=str(compute_source)
            )

        def create_module(self, _spec):
            return None

        def exec_module(self, module):
            module.__file__ = str(compute_source)

    monkeypatch.setattr(sys, "meta_path", [ComputeLoader(), *sys.meta_path])

    release = tmp_path / "releases" / ("a" * 64)
    (release / "bin").mkdir(parents=True)
    manifest = {
        "pex_sha256": "pex",
        "qvl_path": "bin/cathedral-tdx-verifier",
        "qvl_sha256": "qvl",
        "snpguest_path": "bin/snpguest",
        "snpguest_sha256": "snpguest",
    }
    globals_map["require_ip_denied"] = lambda: None
    globals_map["require_pex_origin"] = lambda module: events.append(
        f"origin:{module.__name__}"
    )
    globals_map["active_release"] = lambda: (release, manifest)
    globals_map["digest"] = lambda path: {
        "cathedral-validator": "pex",
        "cathedral-tdx-verifier": "qvl",
        "snpguest": "snpguest",
    }[path.name]
    globals_map["apply_target_control"] = lambda _target: None

    direct_validator = globals_map["direct_validator"]
    direct_validator._notify_ready = lambda: events.append("ready")
    qvl = globals_map["qvl"]
    qvl.DIRECT_VALIDATOR_QVL_DIGEST = "qvl-digest"
    qvl.load_direct_validator_verifier = lambda _path: SimpleNamespace(
        digest="qvl-digest"
    )
    snp_production = globals_map["snp_production"]
    snp_production.load_snp_policy = lambda _path: object()

    class FakeSnpVerifier:
        digest = "sha256:verified"

        def __init__(self, **_kwargs):
            assert not any(
                name == "cathedral" or name.startswith("cathedral.")
                for name in sys.modules
            )
            events.append("snp_verifier_initialized")

    snp_production.SnpProductionVerifier = FakeSnpVerifier
    handlers = {}
    monkeypatch.setattr(
        globals_map["signal"],
        "signal",
        lambda signum, handler: handlers.__setitem__(signum, handler),
    )
    monkeypatch.setattr(
        globals_map["signal"],
        "pause",
        lambda: handlers[globals_map["signal"].SIGTERM](None, None),
    )

    try:
        result = main()
    finally:
        # The import hook inserts its synthetic package directly. Remove it
        # without adding another monkeypatch undo entry, so the fixture can
        # restore only modules that existed before this test.
        for name in tuple(sys.modules):
            if name == "cathedral" or name.startswith("cathedral."):
                sys.modules.pop(name, None)

    assert result == 0
    assert not any(
        name == "cathedral" or name.startswith("cathedral.") for name in sys.modules
    )
    assert events.index("snp_verifier_initialized") < events.index("compute_import")
    assert events.index("compute_import") < events.index("origin:cathedral")
    assert events.index("origin:cathedral") < events.index("ready")


def test_live_readiness_refuses_missing_or_outside_preserved_pex_root(
    tmp_path, monkeypatch
):
    require_pex_origin = _live_readiness_guard(monkeypatch)
    pex_root = tmp_path / "pex-root"
    pex_root.mkdir()
    outside = tmp_path / "checkout/module.py"
    outside.parent.mkdir()
    outside.touch()
    module = SimpleNamespace(__name__="unpackaged.module", __file__=str(outside))

    monkeypatch.delenv("CATHEDRAL_LIVE_TEST_PEX_ROOT", raising=False)
    monkeypatch.setenv("PEX_ROOT", str(pex_root))
    with pytest.raises(SystemExit, match="preserved live-test PEX root is unavailable"):
        require_pex_origin(module)

    monkeypatch.setenv("CATHEDRAL_LIVE_TEST_PEX_ROOT", str(pex_root))
    without_file = SimpleNamespace(__name__="packaged.without_file", __file__=None)
    with pytest.raises(SystemExit, match="has no module file"):
        require_pex_origin(without_file)

    with pytest.raises(SystemExit, match="did not load from the preserved live-test"):
        require_pex_origin(module)
