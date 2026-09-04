"""The validator's round daemon: poll the block, step the loop, record the weights.

This is the deployable wrapper around :func:`cybergym_round_runtime.step`. It supplies the four
things the pure loop refuses to invent — a block height, an HTTP client, a differential, and a
weight sink — and does nothing else.

**Off-chain deployment.** With no chain to read, the backend is the block authority and this
daemon reads the height from ``/v2/round``; the round geometry comes from the same response, so
the validator cannot drift onto a different schedule than the server it is evaluating for. The
weight sink is a local recorder rather than a substrate extrinsic: the whole pipeline runs,
composes real weights, and writes them where an operator can read them, without touching a chain.
Swapping :class:`FileWeightSink` for the substrate call is the only change on-chain requires.

**The nonce is the honest gap.** The KING tie-break is keyed by a chain-anchored nonce so nobody
can grind a tie in their favour. Off-chain there is no such anchor, so :func:`offchain_nonce`
derives one deterministically from the round id and is clearly marked as a TEST stand-in: it makes
every validator agree, which is what a dry run needs, and it is not adversarially safe, which is
why production must pass a real block-hash nonce instead.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Callable

from cathedral_thin.cybergym_round_client import HttpRoundClient, RoundClientError
from cathedral_thin.cybergym_round_eval import BenchmarkFn
from cathedral_thin.cybergym_round_runtime import (
    Action,
    LaneWeights,
    RuntimeState,
    step,
)
from cathedral_thin.cybergym_round_schedule import (
    RoundConfig,
    submission_round_being_scored,
)


def offchain_nonce(round_id: int) -> bytes:
    """TEST-ONLY tie-break nonce. Deterministic, shared, and NOT adversarially safe.

    Production must pass a nonce anchored to a block hash the round cannot predict; this one is
    derivable by anyone, so a miner could grind a tie in its favour. It exists so an off-chain
    run has ONE tie-break every validator agrees on.
    """
    return sha256(f"cybergym-round-{round_id}".encode("ascii")).digest()


@dataclass
class FileWeightSink:
    """Records every weight set to a JSONL trail and keeps the latest vector.

    A recorder, not a chain call: an off-chain run still has to prove it composed the right
    weights at the right block, and the trail is that proof.
    """

    path: Path | None = None
    sets: list[dict] = field(default_factory=list)
    block: int = 0

    def __call__(self, weights: LaneWeights) -> None:
        row = {
            "block": self.block,
            "at": time.time(),
            "weights": {hk: str(w) for hk, w in weights.miners.items()},
            # Recorded explicitly: the forfeited share is the sandbox lane's, and a trail that
            # showed only the miner shares would make a full forfeit look like an empty set.
            "burn": str(weights.burn),
        }
        self.sets.append(row)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")

    @property
    def latest(self) -> dict[str, str]:
        return self.sets[-1]["weights"] if self.sets else {}

    @property
    def latest_burn(self) -> str:
        return self.sets[-1]["burn"] if self.sets else "1"


def config_from_geometry(geometry: Mapping) -> RoundConfig:
    """Adopt the server's round geometry, so both sides run one schedule."""
    return RoundConfig(
        round_blocks=int(geometry["round_blocks"]),
        weight_set_offset=int(geometry["weight_set_offset"]),
        reassert_blocks=int(geometry["reassert_blocks"]),
        submission_close_offset=int(geometry["submission_close_offset"]),
    )


@dataclass
class RoundDaemon:
    """One validator, running the v2 loop against a live backend."""

    client: HttpRoundClient
    benchmark: BenchmarkFn
    sink: FileWeightSink
    cfg: RoundConfig | None = None
    poll_seconds: float = 1.0
    state: RuntimeState = field(default_factory=RuntimeState)
    nonce_for: Callable[[int], bytes] = offchain_nonce
    actions: list[tuple[int, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    _stop: threading.Event = field(default_factory=threading.Event)

    def sync_geometry(self) -> int:
        """Read the block height, adopting the server's geometry the first time."""
        info = self.client.fetch_round()
        if self.cfg is None:
            self.cfg = config_from_geometry(info["geometry"])
        return int(info["block"])

    def tick(self) -> tuple[int, Action | None]:
        """One pass: read the block, step the loop, record what happened."""
        block = self.sync_geometry()
        self.sink.block = block

        # Past the compose block this validator has run out of round: `step` reports the miners it
        # never reached as UNEVALUATED, which the backend excludes from the average rather than
        # averaging in a zero.
        def past_deadline() -> bool:
            return block % self.cfg.round_blocks >= self.cfg.weight_set_offset

        try:
            self.state, action = step(
                block,
                self.state,
                client=self.client,
                benchmark=self.benchmark,
                set_weights=self.sink,
                nonce_for=self.nonce_for,
                deadline=past_deadline,
                cfg=self.cfg,
            )
        except (RoundClientError, Exception) as exc:
            # A transport failure must not compose weights from an empty field — that would burn
            # the lane's emission on a hiccup. Skip the tick and keep the last weights.
            self.errors.append(f"block {block}: {exc}")
            return block, None
        if action is not Action.WAIT:
            self.actions.append((block, action.value))
        if action is Action.COMPOSE_AND_SET:
            # Best-effort, after the weights are already set: the operator dashboard shows whether
            # the validators agreed, and a failure to report must never affect what we set.
            #
            # Report against the round we actually SCORED, using the same function the runtime
            # composes from. Clamping a negative to 0 (as this first did) files the very first
            # compose — which scores round -1, i.e. nothing — under round 0, so the dashboard
            # shows round 0 already composed as an all-burn board while its real compose is still
            # a round away. Display-only, but wrong exactly where an operator looks.
            scored = submission_round_being_scored(block, self.cfg)
            if scored >= 0:
                self.client.report_weights(
                    scored, self.state.weights().miners, self.state.weights().burn
                )
        return block, action

    def run(
        self, *, until_block: int | None = None, max_seconds: float | None = None
    ) -> None:
        started = time.time()
        while not self._stop.is_set():
            block, _ = self.tick()
            if until_block is not None and block >= until_block:
                return
            if max_seconds is not None and time.time() - started >= max_seconds:
                return
            self._stop.wait(self.poll_seconds)

    def start(self, **kwargs) -> threading.Thread:
        t = threading.Thread(
            target=self.run,
            kwargs=kwargs,
            daemon=True,
            name=f"validator-{self.client.validator_hotkey}",
        )
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()


__all__ = ["offchain_nonce", "FileWeightSink", "config_from_geometry", "RoundDaemon"]
