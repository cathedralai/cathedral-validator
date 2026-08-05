"""Proof that the validator tree stands alone without the SAT lane's game/ package.

This repo copies scaffold/publisher/app.py byte-identically from upstream, and
that file contains two `from game.arena import ...` statements (:3764 and
:4211). Both are function-local and sit behind an environment-variable feature
gate, so they never execute on the validator paths this repo ships. These tests
hold that claim to account rather than asserting it in prose.

If a future upstream sync makes either import module-level, or adds a new
game.* edge anywhere in the tree, the static tests below fail and the
back-edge decision recorded in BOUNDARY.md has to be revisited.
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Top-level packages that live in the work repo / SAT lane and must not be
# reachable from anything this repo ships.
FOREIGN_ROOTS = {"game", "hunt_board"}


def _tracked_python_files() -> list[pathlib.Path]:
    skip_parts = {
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".venv",
        "venv",
        "env",
        ".tox",
        "site-packages",
        "build",
        "dist",
        # Agent/tool worktrees are whole second checkouts nested inside this
        # one, so every source file appears twice and this boundary reports a
        # phantom import site with a `.claude/worktrees/...` path. CI never
        # sees it (a fresh clone has none), which is exactly what makes it
        # corrosive: the suite is red only on the machine doing the work.
        ".claude",
    }
    # Match against the path RELATIVE to the repo, never the absolute one. A
    # checkout can itself live under a directory named like one of these — an
    # agent worktree literally lives under `.claude/`, and someone's clone can
    # sit under `venv/` or `build/`. Testing absolute parts then skips every
    # file in the tree and this boundary silently proves nothing: it reports an
    # EMPTY import set, which reads as "the code changed" rather than "the scan
    # found nothing", and the fix looks like updating the expected set.
    return sorted(
        path
        for path in REPO_ROOT.rglob("*.py")
        if not skip_parts.intersection(path.relative_to(REPO_ROOT).parts)
    )


def _imports(path: pathlib.Path) -> list[tuple[str, int, bool]]:
    """Return (module, lineno, is_module_level) for every import in a file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[str, int, bool]] = []

    def walk(node: ast.AST, lazy: bool) -> None:
        for child in ast.iter_child_nodes(node):
            child_lazy = lazy or isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef)
            )
            if isinstance(child, ast.Import):
                for alias in child.names:
                    found.append((alias.name, child.lineno, not lazy))
            elif isinstance(child, ast.ImportFrom) and child.module:
                found.append((child.module, child.lineno, not lazy))
            walk(child, child_lazy)

    walk(tree, False)
    return found


def test_game_package_is_absent_from_the_tree():
    for root in FOREIGN_ROOTS:
        assert not (REPO_ROOT / root).exists(), f"{root}/ must not be vendored here"


def test_game_is_not_importable():
    assert importlib.util.find_spec("game") is None, (
        "the SAT lane's game package is importable in this environment; these "
        "tests cannot prove independence from it"
    )


def test_no_module_level_import_of_the_sat_lane():
    """The only tolerated game.* edges are function-local imports."""
    offenders = []
    for path in _tracked_python_files():
        for module, lineno, module_level in _imports(path):
            if module.split(".")[0] in FOREIGN_ROOTS and module_level:
                rel = path.relative_to(REPO_ROOT)
                offenders.append(f"{rel}:{lineno} imports {module}")
    assert not offenders, "module-level SAT-lane imports found:\n" + "\n".join(
        offenders
    )


def test_the_only_lazy_game_edges_are_the_two_known_publisher_call_sites():
    """Pin the back-edge to exactly the sites BOUNDARY.md documents."""
    edges = set()
    for path in _tracked_python_files():
        for module, lineno, _ in _imports(path):
            if module.split(".")[0] in FOREIGN_ROOTS:
                edges.add((str(path.relative_to(REPO_ROOT)), lineno, module))

    # Line numbers move whenever app.py is re-mirrored from upstream; the invariant is
    # the SET: exactly these two lazy call sites, both game.arena, both inside
    # scaffold/publisher/app.py. Updated for the 5c38016 mirror (3764 -> 3775,
    # 4211 -> 4222); the count and the identity are unchanged, which is what this test
    # exists to protect.
    assert edges == {
        ("scaffold/publisher/app.py", 3775, "game.arena"),
        ("scaffold/publisher/app.py", 4222, "game.arena"),
    }, f"the set of SAT-lane import sites changed: {sorted(edges)}"


def test_no_shipped_test_imports_the_sat_lane():
    offenders = []
    for path in _tracked_python_files():
        if "tests" not in path.parts and not path.name.startswith("test_"):
            continue
        for module, lineno, _ in _imports(path):
            if module.split(".")[0] in FOREIGN_ROOTS:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno} -> {module}")
    assert not offenders, "shipped tests reach into the SAT lane:\n" + "\n".join(
        offenders
    )


def test_validator_entry_points_import_clean():
    """Every console-script target imports with game/ absent."""
    for module in (
        "scaffold.cli",
        "scaffold.snapshot_candidates",
        "scaffold.provenance_audit",
        "scaffold.validator_thin",
        "cathedral_thin.validator",
        "cathedral_thin.e2e",
        "cathedral_thin.preflight",
        "cathedral_thin.report_cli",
        "cathedral_thin.policy_cli",
    ):
        __import__(module)


# The runtime half of the proof needs the publisher extra.
pytest.importorskip("fastapi", reason="publisher extra not installed")

import json  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import textwrap  # noqa: E402

AUDIT_SCANNER_ROUTES = (
    "/v1/audit-scanner/families",
    "/v1/audit-scanner/catalog",
    "/v1/audit-scanner/leaderboard",
    "/v1/audit-scanner/benchmark",
    "/v1/audit-scanner/differential",
    "/v1/audit-scanner/submissions",
)

# The publisher keeps process-global state (rate limiter counters, warm caches,
# the v2 per-miner env pin). Running the runtime probes in a fresh interpreter
# keeps this proof about the boundary instead of about whichever tests happened
# to run first: a 429 from a leaked rate limiter would otherwise masquerade as
# a boundary failure.
_PROBE_PRELUDE = """
import json
from fastapi.testclient import TestClient
from scaffold.publisher.app import build_app

EVAL_KEY_HEX = "11" * 32
"""


def _probe(body: str) -> dict:
    """Run a snippet in a clean interpreter and return the JSON it prints."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "CATHEDRAL_CNF_TOKEN_SECRET": "test-cnf-token-secret",
    }
    completed = subprocess.run(
        [sys.executable, "-c", _PROBE_PRELUDE + textwrap.dedent(body)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, (
        f"probe exited {completed.returncode}\n"
        f"--- stdout ---\n{completed.stdout}\n--- stderr ---\n{completed.stderr}"
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_publisher_app_builds_without_the_sat_lane():
    result = _probe(
        """
        app = build_app(database_path=":memory:", signing_key_hex=EVAL_KEY_HEX)
        print(json.dumps({"built": app is not None}))
        """
    )
    assert result["built"] is True


def test_audit_scanner_routes_refuse_before_reaching_the_sat_lane():
    """The feature gate 404s ahead of the lazy import, so game/ is never needed."""
    result = _probe(
        f"""
        routes = {list(AUDIT_SCANNER_ROUTES)!r}
        app = build_app(database_path=":memory:", signing_key_hex=EVAL_KEY_HEX)
        statuses = {{}}
        with TestClient(app) as client:
            for route in routes:
                statuses[route] = client.get(route).status_code
        print(json.dumps(statuses))
        """
    )
    assert result == {route: 404 for route in AUDIT_SCANNER_ROUTES}, (
        "every audit-scanner route must 404 on the default configuration, "
        f"before the game.arena import is reached; got {result}"
    )


def test_enabling_the_audit_scanner_is_what_would_need_the_sat_lane():
    """Negative control: the gate, not luck, is what keeps the lane out.

    With the feature flag on and game/ absent, the route must fail, and it must
    fail *because* the game package is missing. Asserting only that it fails
    would also pass if the route were broken for some unrelated reason, which
    would leave the back-edge claim unproven.
    """
    result = _probe(
        """
        import os
        os.environ["CATHEDRAL_AUDIT_SCANNER_ENABLED"] = "1"
        app = build_app(database_path=":memory:", signing_key_hex=EVAL_KEY_HEX)

        outcome = {}
        # raise_server_exceptions=True so the handler's exception propagates
        # here instead of being flattened into an opaque 500. The identity of
        # that exception is the whole point of this test.
        with TestClient(app) as client:
            try:
                response = client.get("/v1/audit-scanner/differential")
                outcome["status"] = response.status_code
                outcome["raised"] = None
            except ModuleNotFoundError as exc:
                outcome["status"] = None
                outcome["raised"] = "ModuleNotFoundError"
                outcome["missing_module"] = exc.name
            except BaseException as exc:  # noqa: BLE001
                outcome["status"] = None
                outcome["raised"] = type(exc).__name__
                outcome["detail"] = str(exc)[:200]

        try:
            import game  # noqa: F401
            outcome["game_importable"] = True
        except ModuleNotFoundError as exc:
            outcome["game_importable"] = False
            outcome["missing"] = exc.name
        print(json.dumps(outcome))
        """
    )
    assert result["game_importable"] is False
    assert result["missing"] == "game"

    # The route must not have served a result.
    assert result["status"] != 200, (
        "the audit-scanner differential route served a result without game/ "
        "present; the back-edge analysis in BOUNDARY.md is wrong"
    )

    # And the reason must be the absent SAT lane, not some unrelated breakage.
    assert result["raised"] == "ModuleNotFoundError", (
        "expected the enabled route to raise ModuleNotFoundError for the "
        f"missing SAT lane; got {result.get('raised')} "
        f"{result.get('detail', '')} status={result.get('status')}"
    )
    assert result["missing_module"] == "game", (
        "the enabled route failed for a reason other than the absent game "
        f"package: missing module was {result.get('missing_module')!r}"
    )


def test_the_scan_finds_files_at_all():
    """A skip list that matches the repo's own location proves nothing.

    The exclusions are matched against repo-relative paths precisely because a
    checkout can live under a directory named like one of them — an agent
    worktree sits under `.claude/`. Matched against absolute paths instead,
    every file is skipped and the import-site assertion above compares an EMPTY
    set, which reads as a code change rather than a broken scan.
    """
    files = _tracked_python_files()
    assert len(files) > 100, (
        f"the tracked-file scan found only {len(files)} files; the skip list is "
        "almost certainly matching a component of the repo's own path"
    )
    assert any(p.name == "validator_thin.py" for p in files)
