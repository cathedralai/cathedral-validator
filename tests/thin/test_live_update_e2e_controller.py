from pathlib import Path


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


def test_live_controller_records_both_timer_states_in_host_evidence():
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    capture_host = script.split("capture_host() {", 1)[1].split(
        "current_digest() {", 1
    )[0]

    assert (
        "systemctl show cathedral-validator-canary-update.timer "
        "cathedral-validator-update.timer -p Id -p UnitFileState "
        "-p ActiveState -p SubState -p ConditionResult -p DropInPaths"
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
            'capture_host "first-install-failure-${channel}" "$host" || true'
        )
        == 2
    )
    assert (
        'capture_host "first-readiness-failure-${channel}" "$host" || true'
        in configure_host
    )
    assert (
        configure_host.count('tee "$EVIDENCE_DIR/first-install-command-${host}.log"')
        == 2
    )
    assert 'tee "$EVIDENCE_DIR/first-readiness-command-${host}.log"' in configure_host
    assert configure_host.count("return 1") == 3


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


def test_live_controller_accepts_healthy_selected_timer_dispatch_states():
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()
    start_timer = script.split("start_update_timer() {", 1)[1].split(
        "run_update() {", 1
    )[0]

    assert "-p ActiveState -p SubState -p ConditionResult" in start_timer
    assert "ActiveState=active" in start_timer
    assert "ConditionResult=yes" in start_timer
    assert "^SubState=(waiting|running)$" in start_timer
    assert (
        script.count(
            'start_update_timer "$CANARY_VM" cathedral-validator-canary-update.timer'
        )
        == 2
    )
    assert (
        script.count('start_update_timer "$STABLE_VM" cathedral-validator-update.timer')
        == 1
    )
