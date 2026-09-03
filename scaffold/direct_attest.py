"""Obtain attestation from the miner that produced the work, not from an operator.

Today every validator fetches one signed weight vector from Cathedral's endpoint and
checks its signature. That makes Cathedral the only party able to verify anything, and
makes its uptime a dependency for everyone else: the endpoint returned 502 for several
hours on 2026-08-12 and every following validator stalled with nothing to write.

Nothing about the miner protocol requires that. `MinerClient.collect_evidence(nonce)`
already exists in cathedral-compute and its docstring already calls it "the validator's
miner protocol". Miners have always been able to answer a validator directly. Only
Cathedral's epoch loop ever asked.

This module lets any validator ask. It discovers miners from their on-chain axons,
issues a nonce nobody else can predict or reuse, collects evidence over the miner's own
TLS channel, and hands it to the verification path that already exists. Cathedral is not
in the path, so Cathedral being down is not an outage.

Scope: collection and discovery only. Nothing here writes weights or scores anything.
See issue #120 for the wiring.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

NONCE_BYTES = 32
# A miner that cannot answer inside this budget scores zero for the epoch. It is not a
# reason to fall back to somebody else's numbers, which is the behaviour this module
# exists to remove.
DEFAULT_TIMEOUT_SECS = 20.0


class DirectAttestError(RuntimeError):
    """A miner could not be reached, or answered with evidence we will not accept."""


@dataclass(frozen=True, slots=True)
class MinerEndpoint:
    """Where a miner says it can be reached, according to the chain."""

    uid: int
    hotkey: str
    ip: str
    port: int

    @property
    def url(self) -> str:
        return f"https://{self.ip}:{self.port}"


class Metagraph(Protocol):
    """The subset of a bittensor metagraph this module reads."""

    hotkeys: list[str]
    axons: list[Any]


def discover(metagraph: Metagraph) -> list[MinerEndpoint]:
    """Miners that have published somewhere to reach them, from chain state alone.

    Discovery deliberately reads the chain rather than a Cathedral registry. An
    operator-held address book would reintroduce exactly the dependency this module
    removes: whoever serves the list decides who gets verified, and therefore who earns.

    A miner with no axon is simply not discoverable and earns nothing. That is a
    miner-side action (publish an axon, the standard Bittensor mechanism), not a
    permission Cathedral grants.
    """
    found: list[MinerEndpoint] = []
    for uid, hotkey in enumerate(metagraph.hotkeys):
        axon = metagraph.axons[uid]
        ip = getattr(axon, "ip", "") or ""
        port = int(getattr(axon, "port", 0) or 0)
        # 0.0.0.0 is what the chain holds for a neuron that never served an axon.
        if not ip or ip == "0.0.0.0" or port <= 0:
            continue
        found.append(MinerEndpoint(uid=uid, hotkey=hotkey, ip=ip, port=port))
    return found


def nonce_for(*, validator_hotkey: str, miner_hotkey: str, epoch: int) -> bytes:
    """The challenge this validator issues to this miner for this epoch.

    Three properties, each load-bearing:

    Unique per validator. Two validators challenging the same miner in the same epoch
    issue different nonces, so a miner cannot answer one validator with the proof it
    gave another. This is the same reason Targon derives its nonce from the validator's
    own hotkey rather than from shared state.

    Unpredictable before the epoch. Derived from the epoch number, so a miner cannot
    precompute answers for epochs it has not reached.

    Reproducible by anyone. All three inputs are public, so a third party can recompute
    the exact challenge a validator was obliged to issue and check it did. Verification
    work becomes auditable rather than asserted.
    """
    if not validator_hotkey or not miner_hotkey:
        raise DirectAttestError("nonce needs both hotkeys")
    material = b"\0".join(
        (
            b"cathedral-direct-attest-v1",
            validator_hotkey.encode("utf-8"),
            miner_hotkey.encode("utf-8"),
            str(int(epoch)).encode("ascii"),
        )
    )
    return hashlib.sha256(material).digest()[:NONCE_BYTES]


def collect(
    endpoint: MinerEndpoint,
    *,
    validator_hotkey: str,
    epoch: int,
    client_factory: Any,
    timeout_secs: float = DEFAULT_TIMEOUT_SECS,
) -> Any:
    """Ask one miner to attest itself, and return what it produced.

    `client_factory` builds something satisfying cathedral-compute's `MinerClient`
    protocol, normally `cathedral.remote.RemoteMiner`. It is injected rather than
    imported so this module stays testable without a live miner, and so the transport
    can change without touching the challenge logic.

    This returns evidence; it does not decide anything. Whether the quote is genuine,
    whether the measurement is approved, and what the miner earned are all decided by
    the verification path that already exists.
    """
    nonce = nonce_for(
        validator_hotkey=validator_hotkey,
        miner_hotkey=endpoint.hotkey,
        epoch=epoch,
    )
    try:
        client = client_factory(
            endpoint=endpoint.url,
            hotkey=endpoint.hotkey,
            timeout_secs=timeout_secs,
        )
        evidence = client.collect_evidence(nonce)
    except Exception as exc:  # noqa: BLE001 - any miner-side failure is the same verdict
        # Deliberately broad, and deliberately fatal for this miner only. A miner that
        # is unreachable, slow, or hostile earns nothing this epoch. It must never
        # degrade into reading somebody else's answer, because that is the behaviour
        # that made one endpoint's outage everybody's outage.
        raise DirectAttestError(
            f"uid {endpoint.uid} ({endpoint.hotkey[:8]}...) did not attest: {exc}"
        ) from exc

    if evidence is None:
        raise DirectAttestError(f"uid {endpoint.uid} returned no evidence")
    return evidence


def collect_all(
    endpoints: list[MinerEndpoint],
    *,
    validator_hotkey: str,
    epoch: int,
    client_factory: Any,
    timeout_secs: float = DEFAULT_TIMEOUT_SECS,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Attest every discoverable miner. Returns (evidence by hotkey, failures by hotkey).

    Failures are returned rather than raised. One unreachable miner is not an epoch
    failure, it is that miner earning nothing, and an operator needs to see which is
    which. Returning both halves is what lets the caller distinguish "nobody answered"
    (a validator-side problem worth alarming on) from "this miner is down" (routine).
    """
    evidence: dict[str, Any] = {}
    failures: dict[str, str] = {}
    for endpoint in endpoints:
        try:
            evidence[endpoint.hotkey] = collect(
                endpoint,
                validator_hotkey=validator_hotkey,
                epoch=epoch,
                client_factory=client_factory,
                timeout_secs=timeout_secs,
            )
        except DirectAttestError as exc:
            failures[endpoint.hotkey] = str(exc)
    return evidence, failures
