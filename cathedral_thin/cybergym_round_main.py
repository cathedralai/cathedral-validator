"""Entrypoint: run one validator's v2 round loop against a backend.

Environment:

===============================  ===========================================================
``CYBERGYM_BACKEND``             backend base URL (default http://127.0.0.1:8700)
``CYBERGYM_VALIDATOR_HOTKEY``    this validator's hotkey — required, it signs nothing yet but
                                 the backend averages per validator and needs to tell them apart
``CYBERGYM_WEIGHTS_FILE``        where the weight trail is written (default ./cybergym-weights.jsonl)
``CYBERGYM_POLL_SECONDS``        how often to step the loop (default 2)
``CYBERGYM_DOCKER``              docker binary (default ``docker``)
``CYBERGYM_ALLOW_OFFCHAIN``      ``1`` to acknowledge weights are RECORDED, not set on chain
===============================  ===========================================================

**Off-chain is opt-in.** Without ``CYBERGYM_ALLOW_OFFCHAIN=1`` this refuses to start, because a
validator that silently records weights instead of setting them looks healthy while the chain
zeroes it. Wiring the substrate ``set_weights`` extrinsic in place of the file sink is the only
change going on-chain requires.
"""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

from cathedral_thin.cybergym_round_benchmark import docker_benchmark
from cathedral_thin.cybergym_round_client import HttpRoundClient
from cathedral_thin.cybergym_round_daemon import FileWeightSink, RoundDaemon


def main() -> int:
    hotkey = os.environ.get("CYBERGYM_VALIDATOR_HOTKEY", "").strip()
    if not hotkey:
        raise SystemExit("CYBERGYM_VALIDATOR_HOTKEY is required")
    if os.environ.get("CYBERGYM_ALLOW_OFFCHAIN") != "1":
        raise SystemExit(
            "this daemon RECORDS weights to a file, it does not set them on chain. "
            "Set CYBERGYM_ALLOW_OFFCHAIN=1 to run it knowingly."
        )
    base = os.environ.get("CYBERGYM_BACKEND", "http://127.0.0.1:8700")
    docker = os.environ.get("CYBERGYM_DOCKER", "docker")
    sink = FileWeightSink(
        path=Path(os.environ.get("CYBERGYM_WEIGHTS_FILE", "cybergym-weights.jsonl"))
    )
    daemon = RoundDaemon(
        client=HttpRoundClient(
            base, hotkey, timeout=float(os.environ.get("CYBERGYM_HTTP_TIMEOUT", "60"))
        ),
        benchmark=lambda tid, poc, proof: docker_benchmark(
            tid, poc, proof, docker=docker
        ),
        sink=sink,
        poll_seconds=float(os.environ.get("CYBERGYM_POLL_SECONDS", "2")),
    )
    block = daemon.sync_geometry()
    print(
        f"validator {hotkey} -> {base} | block={block} geometry={daemon.cfg} "
        f"| weights RECORDED to {sink.path}",
        flush=True,
    )

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: daemon.stop())
    daemon.run()
    print(
        f"stopped after {len(sink.sets)} weight sets; last = {sink.latest}", flush=True
    )
    if daemon.errors:
        print(
            f"{len(daemon.errors)} errored ticks, last: {daemon.errors[-1]}", flush=True
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
