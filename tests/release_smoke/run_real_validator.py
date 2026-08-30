"""Run the real packaged validator startup with only external effects doubled."""

from __future__ import annotations

import os
import socket
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

from cathedral_thin.independent_runtime import direct_validator as runtime
from cathedral_thin.independent_runtime import direct_writer as writer_runtime
from cathedral_thin.independent_runtime import qvl as qvl_runtime
from cathedral_thin.independent_runtime import snp_production


COMPUTE_COMMIT = "8dde6eaca27116eed53386a1fa33ec70b74a01fb"


class _Hotkey:
    ss58_address = "5ReleaseSmokeValidator"

    @staticmethod
    def sign(_payload: bytes) -> bytes:
        return b"release-smoke-signature"


class _Writer:
    @contextmanager
    def process_locked(self):
        yield

    @staticmethod
    def recover():
        return None


def _require_ephemeral_pex_import(module: ModuleType) -> None:
    module_file = getattr(module, "__file__", None)
    pex_root_raw = os.environ.get("CATHEDRAL_RELEASE_SMOKE_PEX_ROOT")
    if not isinstance(module_file, str) or not pex_root_raw:
        raise SystemExit(f"{module.__name__} has no packaged PEX origin")
    module_path = Path(module_file).resolve()
    pex_root = Path(pex_root_raw).resolve()
    checkout = Path(__file__).resolve().parents[2]
    if not module_path.is_relative_to(pex_root):
        raise SystemExit(
            f"{module.__name__} resolved outside ephemeral PEX_ROOT: {module_path}"
        )
    if module_path.is_relative_to(checkout):
        raise SystemExit(f"{module.__name__} resolved from the source checkout")


def main() -> int:
    _require_ephemeral_pex_import(runtime)
    _require_ephemeral_pex_import(snp_production)
    contract = snp_production.load_compute_contract()
    if contract.commit != COMPUTE_COMMIT:
        raise SystemExit("real PEX loaded the wrong production Compute contract")
    import cathedral

    _require_ephemeral_pex_import(cathedral)
    if snp_production.SANDBOX_CONTRACT_COMMIT != COMPUTE_COMMIT:
        raise SystemExit("real PEX has the wrong production Compute contract")
    with tempfile.TemporaryDirectory(prefix="cv-release-smoke-") as directory:
        root = Path(directory)
        qvl = root / "qvl"
        policy = root / "snp-policy.json"
        snpguest = root / "snpguest"
        qvl.write_bytes(b"release smoke qvl")
        policy.write_text("{}", encoding="utf-8")
        snpguest.write_bytes(b"release smoke snpguest")
        snpguest.chmod(0o500)

        runtime.load_direct_validator_verifier = lambda _path: SimpleNamespace(
            digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        )
        runtime.ComputeAdapter = lambda *_args, **_kwargs: SimpleNamespace(
            qvl_digest=qvl_runtime.DIRECT_VALIDATOR_QVL_DIGEST
        )
        runtime.load_snp_policy = lambda path: (
            SimpleNamespace(path=path) if path == str(policy) else None
        )
        runtime.SnpProductionVerifier = lambda *, policy, snpguest_path: (
            SimpleNamespace(policy=policy, snpguest_path=snpguest_path)
        )
        runtime.make_wallet = lambda *_args, **_kwargs: SimpleNamespace(
            hotkey=_Hotkey()
        )
        runtime.make_subtensor = lambda *_args, **_kwargs: object()
        writer_runtime.DirectWeightWriter = lambda **_kwargs: _Writer()
        runtime.run_direct_cycle = lambda **_kwargs: {
            "status": writer_runtime.STATUS_CONFIRMED
        }

        notify_path = root / "notify.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
            server.bind(str(notify_path))
            server.settimeout(3.0)
            os.environ["NOTIFY_SOCKET"] = str(notify_path)
            result = runtime.main(
                [
                    "--qvl",
                    str(qvl),
                    "--snp-policy",
                    str(policy),
                    "--snpguest",
                    str(snpguest),
                    "--expected-hotkey",
                    _Hotkey.ss58_address,
                    "--once",
                    "--confirm-direct-write",
                ]
            )
            ready = server.recv(512)
    if result != 0:
        raise SystemExit(f"real validator entry point exited {result}")
    expected = b"READY=1\nSTATUS=initialized; waiting for the next direct cycle"
    if ready != expected:
        raise SystemExit(f"real validator emitted the wrong readiness: {ready!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
