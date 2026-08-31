import importlib.abc
import importlib.util
import runpy
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
    assert configure_host.count("failure_status=$?") == 3
    assert configure_host.count('return "$failure_status"') == 3
    assert "return 1" not in configure_host


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
