"""The independent composer has no path to a chain writer. Proven, not asserted.

Three independent claims, each narrow on purpose:

1. structural, at runtime: a fresh interpreter that imports every module in the
   package loads no ``scaffold``, ``bittensor`` or substrate module at all, so
   there is no import path from this lineage to any writer in this repo;
2. structural, by AST: no module in the package imports or binds a name from the
   banned set, so a writer cannot arrive through a future refactor without
   failing here;
3. textual: no module names the thin feed path, the thin journal, or the burn
   environment variables that default to a stale owner UID.

What is NOT claimed: that nothing in the process can write weights. A caller
supplies the metagraph views and may import anything it likes. The guarantee is
about this package.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
import re
import subprocess
import sys
from pathlib import Path

import pytest

import cathedral_thin.independent as independent
from cathedral_thin.independent.constants import INDEPENDENT_STATE_FILE

PACKAGE_DIR = Path(independent.__file__).resolve().parent

# Every entry point that composes or submits a vector somewhere else in this
# repo (or in the shared contract), plus the helpers whose semantics this
# lineage deliberately does not inherit.
BANNED_NAMES = frozenset(
    {
        "fetch_vector",
        "set_weights_on_chain",
        "_submit_exact_sn39_extrinsic",
        "_authorize_sn39_chain_submission",
        "_reverify_reserved_signed_vector",
        "compose_integrated",
        "compose_vector",
        "coldkey_collapsed_weights",
        "_drop_unprovable_targets",
        "convert_and_normalize_weights_and_uids",
        "SatLane",
    }
)

BANNED_TEXT = (
    "weights/next",
    "thin-state.json",
    "CATHEDRAL_WEIGHT_POLICY_BURN",
    "api.cathedral.computer",
    "neuron.validator",
    "SatLane",
)

# ``numpy`` is banned alongside the writers: the u16 apportionment must be exact
# integer arithmetic, and the SDK's normalisation helper is a float path.
BANNED_ROOTS = frozenset(
    {"scaffold", "bittensor", "substrateinterface", "cathedral_distill", "numpy"}
)

MODULES = tuple(
    f"cathedral_thin.independent.{info.name}"
    for info in pkgutil.iter_modules([str(PACKAGE_DIR)])
    if info.name != "__main__"
) + ("cathedral_thin.independent",)


def sources() -> dict[Path, str]:
    return {
        path: path.read_text(encoding="utf-8")
        for path in sorted(PACKAGE_DIR.glob("*.py"))
    }


def test_the_module_inventory_is_not_empty():
    assert len(MODULES) >= 10, MODULES
    assert len(sources()) >= 10


@pytest.mark.parametrize("module", MODULES)
def test_a_fresh_interpreter_loads_no_writer(module):
    code = (
        "import importlib, sys; importlib.import_module(%r); "
        "print(sorted({m.split('.')[0] for m in sys.modules} & "
        "{'scaffold', 'bittensor', 'substrateinterface', 'cathedral_distill', "
        "'numpy'}))" % module
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert proc.stdout.strip() == "[]", proc.stdout


def test_importing_the_package_binds_no_banned_name():
    for module_name in MODULES:
        module = importlib.import_module(module_name)
        bound = BANNED_NAMES & set(vars(module))
        assert not bound, f"{module_name} binds {sorted(bound)}"


def test_no_module_imports_a_writer_or_a_composer():
    for path, text in sources().items():
        tree = ast.parse(text, filename=str(path))
        imported: set[str] = set()
        roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name)
                    roots.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module)
                    if node.level == 0:
                        roots.add(node.module.split(".")[0])
                imported.update(alias.name for alias in node.names)
        assert not (imported & BANNED_NAMES), f"{path.name} imports a banned name"
        assert not (roots & BANNED_ROOTS), f"{path.name} imports {sorted(roots)}"


def test_no_module_calls_a_banned_name():
    """An attribute call would evade the import check; the AST catches it too."""
    for path, text in sources().items():
        tree = ast.parse(text, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in BANNED_NAMES, f"{path.name} touches {node.attr}"
            elif isinstance(node, ast.Name):
                assert node.id not in BANNED_NAMES, f"{path.name} names {node.id}"


@pytest.mark.parametrize("needle", BANNED_TEXT)
def test_no_module_names_a_banned_path_or_environment_variable(needle):
    for path, text in sources().items():
        assert needle not in text, f"{path.name} contains {needle!r}"


def test_the_journal_is_not_the_thin_validator_journal():
    assert INDEPENDENT_STATE_FILE != Path(
        "/var/lib/cathedral-validator/thin-state.json"
    )
    assert INDEPENDENT_STATE_FILE.name == "independent-state.json"


def test_the_burn_uid_is_never_hardcoded():
    """The owner hotkey has moved UIDs; only the hotkey is pinned."""
    stale = re.compile(r"\b204\b")
    for path, text in sources().items():
        assert not stale.search(text), f"{path.name} hardcodes a burn uid"


def test_the_package_has_no_import_time_side_effects():
    """Importing opens no socket, reads no file, and touches no environment."""
    code = (
        "import builtins, os, socket, sys\n"
        "def deny(*a, **k):\n"
        "    raise AssertionError('import-time side effect')\n"
        "socket.socket = deny\n"
        "socket.create_connection = deny\n"
        "os.environ = {}\n"
        "builtins.open = deny\n"
        "import importlib\n"
        "importlib.import_module('cathedral_thin.independent')\n"
        "print('clean')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "clean"
