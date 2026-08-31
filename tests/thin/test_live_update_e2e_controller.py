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
        assert f"systemctl show '{timer}' -p ActiveState --value" in configure_host
    assert configure_host.count("= disabled") == 2
    assert configure_host.count("= inactive") == 2
    assert "systemctl show '$other_timer' -p SubState --value" in configure_host
    assert "systemctl show '$other_timer' -p ConditionResult --value" in configure_host
    assert "= dead" in configure_host
    assert "= no" in configure_host


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


def test_live_controller_requires_selected_timers_to_be_waiting():
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "live_validator_update_e2e.sh").read_text()

    for timer in (
        "cathedral-validator-canary-update.timer",
        "cathedral-validator-update.timer",
    ):
        assert f"systemctl show {timer} -p ActiveState --value" in script
        assert f"systemctl show {timer} -p SubState --value" in script
        assert f"systemctl show {timer} -p ConditionResult --value" in script
