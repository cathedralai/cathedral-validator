"""Direct miner attestation: discovery, challenges, and failing closed.

The property under test throughout is that no code path here can produce a score from
anything except a miner's own answer to this validator's own challenge. Falling back to
another party's numbers is the behaviour being removed, so every failure mode must end
in "this miner earns nothing", never in "use something else".
"""

from __future__ import annotations

import pytest

from scaffold import direct_attest as da


VALIDATOR = "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"
MINER_A = "5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK"
MINER_B = "5G3qVaXzKMPDm5AJ3dpzbpUC27kpccBvDwzSWXrq8M6qMmbC"


class _Axon:
    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port


class _Metagraph:
    def __init__(self, entries):
        self.hotkeys = [hotkey for hotkey, _, _ in entries]
        self.axons = [_Axon(ip, port) for _, ip, port in entries]


# -- discovery --------------------------------------------------------------


def test_a_miner_without_an_axon_is_not_discoverable():
    """0.0.0.0 is what the chain holds for a neuron that never served an axon."""
    graph = _Metagraph(
        [
            (MINER_A, "1.2.3.4", 8443),
            (MINER_B, "0.0.0.0", 0),
        ]
    )
    found = da.discover(graph)
    assert [e.hotkey for e in found] == [MINER_A]


def test_discovery_reads_the_chain_and_nothing_else():
    """No registry, no allowlist, no operator endpoint in the signature.

    If discovery ever took an address book, whoever served it would decide who gets
    verified and therefore who earns, which is the dependency this module removes.
    """
    import inspect

    params = set(inspect.signature(da.discover).parameters)
    assert params == {"metagraph"}


def test_a_discovered_endpoint_addresses_the_miner_over_tls():
    graph = _Metagraph([(MINER_A, "35.223.202.14", 8443)])
    assert da.discover(graph)[0].url == "https://35.223.202.14:8443"


# -- the challenge ----------------------------------------------------------


def test_two_validators_issue_different_challenges_to_the_same_miner():
    """The property that stops a miner reusing one validator's proof on another."""
    mine = da.nonce_for(validator_hotkey=VALIDATOR, miner_hotkey=MINER_A, epoch=100)
    theirs = da.nonce_for(validator_hotkey=MINER_B, miner_hotkey=MINER_A, epoch=100)
    assert mine != theirs


def test_the_challenge_changes_every_epoch():
    """So a miner cannot precompute answers for epochs it has not reached."""
    now = da.nonce_for(validator_hotkey=VALIDATOR, miner_hotkey=MINER_A, epoch=100)
    later = da.nonce_for(validator_hotkey=VALIDATOR, miner_hotkey=MINER_A, epoch=101)
    assert now != later


def test_the_challenge_is_reproducible_by_a_third_party():
    """All three inputs are public, so anyone can check a validator issued the
    challenge it was obliged to issue. Verification work becomes auditable."""
    first = da.nonce_for(validator_hotkey=VALIDATOR, miner_hotkey=MINER_A, epoch=100)
    second = da.nonce_for(validator_hotkey=VALIDATOR, miner_hotkey=MINER_A, epoch=100)
    assert first == second


def test_the_challenge_is_the_length_the_miner_protocol_requires():
    """cathedral-compute's fetch_evidence_bundle rejects anything but 32 bytes."""
    nonce = da.nonce_for(validator_hotkey=VALIDATOR, miner_hotkey=MINER_A, epoch=1)
    assert isinstance(nonce, bytes)
    assert len(nonce) == da.NONCE_BYTES == 32


# -- failing closed ---------------------------------------------------------


def _endpoint(hotkey: str = MINER_A) -> da.MinerEndpoint:
    return da.MinerEndpoint(uid=163, hotkey=hotkey, ip="1.2.3.4", port=8443)


def test_an_unreachable_miner_raises_rather_than_returning_nothing():
    def refuses(**_kwargs):
        raise ConnectionError("connection refused")

    with pytest.raises(da.DirectAttestError, match="did not attest"):
        da.collect(
            _endpoint(), validator_hotkey=VALIDATOR, epoch=1, client_factory=refuses
        )


def test_a_miner_answering_with_nothing_is_a_failure_not_an_empty_pass():
    class _Empty:
        def collect_evidence(self, nonce):
            return None

    with pytest.raises(da.DirectAttestError, match="no evidence"):
        da.collect(
            _endpoint(),
            validator_hotkey=VALIDATOR,
            epoch=1,
            client_factory=lambda **_k: _Empty(),
        )


def test_the_miner_receives_this_validators_challenge_verbatim():
    """The whole point: the miner answers OUR challenge, not one it chose."""
    seen = {}

    class _Recorder:
        def collect_evidence(self, nonce):
            seen["nonce"] = nonce
            return {"quote": "..."}

    da.collect(
        _endpoint(),
        validator_hotkey=VALIDATOR,
        epoch=42,
        client_factory=lambda **_k: _Recorder(),
    )

    assert seen["nonce"] == da.nonce_for(
        validator_hotkey=VALIDATOR, miner_hotkey=MINER_A, epoch=42
    )


def test_one_dead_miner_does_not_stop_the_others_being_attested():
    """A failure is that miner earning nothing, not an epoch-wide failure."""
    alive, dead = _endpoint(MINER_A), _endpoint(MINER_B)

    class _Ok:
        def collect_evidence(self, nonce):
            return {"quote": "genuine"}

    def factory(*, endpoint, hotkey, timeout_secs):
        if hotkey == MINER_B:
            raise TimeoutError("no route to host")
        return _Ok()

    evidence, failures = da.collect_all(
        [alive, dead], validator_hotkey=VALIDATOR, epoch=7, client_factory=factory
    )

    assert set(evidence) == {MINER_A}
    assert set(failures) == {MINER_B}
    assert "no route to host" in failures[MINER_B]


def test_nothing_in_this_module_can_reach_a_signed_feed():
    """The regression that would undo the whole change.

    If a fallback to somebody else's numbers ever appears here, an outage at one
    endpoint becomes an outage for every validator again, which is precisely the
    2026-08-12 failure this module exists to make impossible.
    """
    source = (da.__file__ and open(da.__file__, encoding="utf-8").read()) or ""
    for forbidden in (
        "weights/next",
        "publisher_url",
        "signed vector",
        "api.cathedral",
    ):
        assert forbidden not in source, f"direct attestation must not reach {forbidden}"
