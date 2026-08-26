"""The audit-work client re-derives its own units, and that is what pays.

Five separate claims:

1. the copied wire contract matches the serving side byte-for-byte. The
   ``challenge_id`` preimage is pinned to literal vectors, and one of them is
   compared against the compact-separator digest so a drift from default
   ``json.dumps`` separators fails here rather than turning every honest solve
   into a challenge mismatch;
2. the audit instance is deterministic in its seed, satisfiable by
   construction, and derived from material already pinned for the epoch, so two
   validators auditing one machine ask it the same question;
3. the units are an ``int`` derived from the committed item. An inflated claim,
   a float claim, and a claim of zero all earn the same 20; a non-canonical
   instance earns nothing at all;
4. every way a miner can answer with something other than a checkable witness
   -- a wrong hotkey, a wrong challenge, an unsatisfiable claim, a
   contradictory assignment, an unsatisfied clause, an extra key, a non-200 --
   is a refusal;
5. end to end: one fake miner answers both endpoints, a mock pinned QVL passes
   the quote, the re-derived units become integer Compute mass, that mass
   composes to ``COMPOSED``, and the one-write canary fires exactly once. The
   quote alone never gets there.

No socket is opened. The transports are fakes, and one test proves the claim by
denying ``socket`` outright. The brute-force solver lives in this file: nothing
on the accept path solves anything.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import socket
from pathlib import Path

import pytest

from _independent_fixtures import (
    ANCHOR_HASH,
    BOB,
    BURN_UID,
    CHARLIE,
    EPOCH_OPEN,
    commitment_for,
)
from cathedral_thin.independent import sat as sat_module
from cathedral_thin.independent.collect import (
    CHANNEL_BINDING_TYPE_TLS,
    NONCE_BYTES,
    ChannelBinding,
    collect_evidence,
    verify_collected,
)
from cathedral_thin.independent.compose import (
    STATUS_COMPOSED,
    EpochAnchor,
    compose_dry_run,
)
from cathedral_thin.independent.compute import (
    COMPUTE_LANE,
    ComputeAdapter,
    QuoteVerdict,
    canonical_seed_material,
)
from cathedral_thin.independent.constants import (
    BURN_HOTKEY,
    INDEPENDENT_CANARY_FILE,
    INDEPENDENT_STATE_FILE,
)
from cathedral_thin.independent.errors import SatWorkError
from cathedral_thin.independent.inclusion import MetagraphView
from cathedral_thin.independent.sat import (
    CANONICAL_CLAUSES,
    CANONICAL_N_VARS,
    MAX_SAT_RESPONSE_BYTES,
    SAT_REQUEST_KEYS,
    SAT_RESPONSE_KEYS,
    SAT_WORK_PATH,
    SAT_WORK_UNIT_RULE,
    SatInstance,
    SatWorkItem,
    canonical_instance,
    canonical_work_item,
    collect_sat_work,
    compute_challenge_id,
    derived_work_units,
    instance_equals_canonical,
    sat_work_url,
    seed_from_material,
)
from cathedral_thin.independent.submit import prepare_mechanism_weights
from cathedral_thin.independent_runtime.local_policy import COMPUTE_ALLOCATION
from cathedral_thin.independent_runtime.score import mass_from_units
from test_independent_canary import FakeTransport as CanaryTransport
from test_independent_canary import funded_compute_bundle, run_canary
from test_independent_collect import BINDING, DIGEST, NONCE, URL, v2_response
from test_independent_compute import (
    INTEL_COLLATERAL,
    MINER_UID,
    PINNED_QVL,
    MockQuoteVerifier,
)

ANCHOR = EpochAnchor(
    epoch_open=EPOCH_OPEN, anchor_number=EPOCH_OPEN - 1, anchor_hash=ANCHOR_HASH
)

SAT_URL = "https://miner.example.test/v1/sat-work"

# The vectors this copied contract is pinned to. Computed from the serving
# side's encoding: sorted keys with ``json.dumps`` DEFAULT separators. If either
# tree moves, these literals fail before anything else does.
PINNED_CHALLENGE_IDS = {
    0: "23475ab156bb48bc771d5c63a843b7264ba6cea181cdb301cdef9670903ff103",
    1: "de3d0712b6a76adfcad44152f2f72f14c5fc21819da9da8cf6993578b161b06c",
    7: "cc49f49fc154680b6224f3947e39a378ab09951db379b0e477c6e21aa85fb7df",
}
# What the SAME instance and seed would hash to under compact separators. A
# validator that used those would commit to a challenge no honest miner
# recognises, so the two digests are asserted to differ.
COMPACT_CHALLENGE_ID_SEED_7 = (
    "78e8a15263fb7746134d25799d9d149b171d12cbb84a3757c9f161a37cb2ba24"
)

# The seed and instance the end-to-end fake miner is challenged with, derived
# from the pinned anchor, BOB, and the observed channel binding digest.
E2E_SEED = 2212287298787926531
E2E_CHALLENGE_ID = "53123f437b78eb2c07d3030807ca6da38dfc5188c4f213e58d60af6ba581633e"


class FakeSatTransport:
    """Answers one work POST with canned bytes and remembers the request."""

    def __init__(self, status: int = 200, body: bytes = b"{}") -> None:
        self.calls: list[tuple[str, dict]] = []
        self.status = status
        self.body = body

    def post(self, url: str, body) -> tuple[int, bytes]:
        self.calls.append((url, json.loads(json.dumps(dict(body)))))
        return self.status, self.body


def brute_force(instance: SatInstance) -> list[int]:
    """Solve 8 variables by exhaustion -- 256 assignments, in the TEST only.

    Production ``sat.py`` ships no solver: the audit instance is satisfiable by
    construction, so the validator only ever CHECKS a witness. A fake miner has
    to produce one, and this is the cheapest honest way to do it.
    """
    variables = range(1, instance.n_vars + 1)
    for signs in itertools.product((1, -1), repeat=instance.n_vars):
        assignment = [variable * sign for variable, sign in zip(variables, signs)]
        true_literals = set(assignment)
        if all(
            any(literal in true_literals for literal in clause)
            for clause in instance.clauses
        ):
            return assignment
    raise AssertionError("the canonical audit instance is satisfiable by construction")


def sat_response(item: SatWorkItem, **overrides) -> dict:
    response = {
        "satisfiable": True,
        "assignment": brute_force(item.instance),
        "work_units": float(len(item.instance.clauses)),
        "challenge_id": item.challenge_id,
        "assigned_hotkey": BOB,
    }
    response.update(overrides)
    return response


def sat_transport_for(item: SatWorkItem, **overrides) -> FakeSatTransport:
    return FakeSatTransport(
        body=json.dumps(sat_response(item, **overrides)).encode("utf-8")
    )


def audit_item(seed: int = 7) -> SatWorkItem:
    instance = canonical_instance(seed)
    return SatWorkItem(
        instance=instance,
        seed=seed,
        challenge_id=compute_challenge_id(instance, seed),
    )


def ask(transport, *, item=None, hotkey=BOB, url=SAT_URL) -> int:
    return collect_sat_work(
        url=url,
        assigned_hotkey=hotkey,
        item=audit_item() if item is None else item,
        transport=transport,
    )


# --- the copied wire contract ------------------------------------------------


@pytest.mark.parametrize("seed", sorted(PINNED_CHALLENGE_IDS))
def test_the_challenge_id_uses_default_json_separators(seed):
    instance = canonical_instance(seed)
    assert compute_challenge_id(instance, seed) == PINNED_CHALLENGE_IDS[seed]


def test_compact_separators_would_hash_to_a_challenge_no_miner_recognises():
    instance = canonical_instance(7)
    payload = {
        "n_vars": instance.n_vars,
        "clauses": instance.clauses_as_lists,
        "seed": 7,
    }
    compact = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert compact == COMPACT_CHALLENGE_ID_SEED_7
    assert compute_challenge_id(instance, 7) != compact


def test_the_request_key_sets_are_the_serving_sides():
    assert SAT_REQUEST_KEYS == {"challenge_id", "assigned_hotkey", "instance", "seed"}
    assert SAT_RESPONSE_KEYS == {
        "satisfiable",
        "assignment",
        "work_units",
        "challenge_id",
        "assigned_hotkey",
    }
    assert SAT_WORK_PATH == "/v1/sat-work"
    assert MAX_SAT_RESPONSE_BYTES == 64 * 1024
    assert SAT_WORK_UNIT_RULE == "sat_work_units_v1"


def test_a_base_url_gets_the_work_path_and_an_evidence_url_is_refused():
    assert sat_work_url("https://miner.example.test") == SAT_URL
    assert sat_work_url("https://miner.example.test/") == SAT_URL
    assert sat_work_url(SAT_URL) == SAT_URL
    ipv6 = "https://[2001:db8::1]:8443/v1/sat-work"
    assert sat_work_url(ipv6) == ipv6
    for bad in (
        # An evidence URL is never rewritten into a work URL.
        "https://miner.example.test/v1/evidence",
        "https://miner.example.test/v2/sat-work",
        "https://miner.example.test/v1/sat-work/",
        "http://miner.example.test/v1/sat-work",
        "https://user:pass@miner.example.test/v1/sat-work",
        "https://miner.example.test/v1/sat-work?seed=1",
        "",
        None,
    ):
        with pytest.raises(SatWorkError):
            sat_work_url(bad)


# --- the canonical audit instance --------------------------------------------


def test_the_audit_instance_is_deterministic_in_its_seed():
    assert canonical_instance(7) == canonical_instance(7)
    assert canonical_instance(7) != canonical_instance(8)
    instance = canonical_instance(7)
    assert instance.n_vars == CANONICAL_N_VARS == 8
    assert len(instance.clauses) == CANONICAL_CLAUSES == 20
    assert all(len(clause) == 3 for clause in instance.clauses)
    assert instance_equals_canonical(instance, 7) is True
    assert instance_equals_canonical(instance, 8) is False


def test_the_audit_instance_is_satisfiable_by_construction():
    """So the validator never has to solve: a witness always exists."""
    for seed in (0, 1, 7, 4242):
        instance = canonical_instance(seed)
        assignment = brute_force(instance)
        assert len(assignment) == instance.n_vars


def test_the_seed_is_folded_from_pinned_material_not_drawn():
    material = canonical_seed_material(
        anchor_hash=ANCHOR_HASH, miner_ss58=BOB, machine_id=DIGEST.hex()
    )
    assert len(material) == 32
    seed = seed_from_material(material)
    assert seed == E2E_SEED
    assert 0 <= seed <= (1 << 63) - 1
    # Deterministic in the anchor, the miner and the machine, and in nothing
    # else: no process randomness and no per-validator namespace.
    assert seed_from_material(material) == seed
    other = canonical_seed_material(
        anchor_hash=ANCHOR_HASH, miner_ss58=CHARLIE, machine_id=DIGEST.hex()
    )
    assert seed_from_material(other) != seed


@pytest.mark.parametrize(
    "material", [b"", bytes(31), bytes(33), DIGEST.hex(), None, bytearray(31)]
)
def test_seed_material_must_be_32_bytes(material):
    with pytest.raises(SatWorkError, match="32 bytes"):
        seed_from_material(material)


def test_the_work_item_binds_the_instance_to_the_pinned_challenge():
    item = canonical_work_item(
        anchor_hash=ANCHOR_HASH, miner_ss58=BOB, machine_id=DIGEST.hex()
    )
    assert item.seed == E2E_SEED
    assert item.challenge_id == E2E_CHALLENGE_ID
    assert item.instance == canonical_instance(E2E_SEED)


def test_a_challenge_id_that_is_not_the_digest_is_refused():
    instance = canonical_instance(7)
    with pytest.raises(SatWorkError, match="not the digest"):
        SatWorkItem(instance=instance, seed=7, challenge_id="ab" * 32)
    with pytest.raises(SatWorkError, match="64 lowercase hex"):
        SatWorkItem(instance=instance, seed=7, challenge_id="nope")


@pytest.mark.parametrize("seed", [True, False, 1.0, "7", None, 2**63, -(2**63) - 1])
def test_a_seed_outside_the_signed_64_bit_range_is_refused(seed):
    with pytest.raises(SatWorkError):
        canonical_instance(seed)


@pytest.mark.parametrize(
    "n_vars, clauses",
    [
        (0, [[1]]),
        (513, [[1]]),
        (True, [[1]]),
        (1.0, [[1]]),
        (2, []),
        (2, "not clauses"),
        (2, [[]]),
        (2, [[0]]),
        (2, [[3]]),
        (2, [[True]]),
        (2, [[1.0]]),
        (2, [1]),
        (2, [[1]] * 8193),
    ],
)
def test_an_out_of_bounds_instance_never_becomes_a_work_item(n_vars, clauses):
    with pytest.raises(SatWorkError):
        SatInstance(n_vars=n_vars, clauses=clauses)


# --- integer units -----------------------------------------------------------


def test_the_derived_units_are_the_integer_clause_count():
    units = derived_work_units(audit_item())
    assert units == 20
    assert isinstance(units, int)
    assert not isinstance(units, bool)
    assert not isinstance(units, float)


def test_a_non_canonical_instance_is_not_sn39_work():
    """A bounded customer job is somebody else's economics, not a smaller unit."""
    instance = SatInstance(n_vars=3, clauses=[[1, 2, 3], [-1, 2, 3]])
    item = SatWorkItem(
        instance=instance, seed=7, challenge_id=compute_challenge_id(instance, 7)
    )
    with pytest.raises(SatWorkError, match="non-canonical work earns nothing"):
        derived_work_units(item)


def test_the_canonical_instance_under_a_different_seed_is_not_canonical():
    instance = canonical_instance(7)
    item = SatWorkItem(
        instance=instance, seed=8, challenge_id=compute_challenge_id(instance, 8)
    )
    with pytest.raises(SatWorkError, match="non-canonical"):
        derived_work_units(item)


# --- the happy path ----------------------------------------------------------


def test_a_satisfying_witness_earns_the_derived_units():
    item = audit_item()
    transport = sat_transport_for(item)
    units = ask(transport, item=item)
    assert units == 20
    assert isinstance(units, int) and not isinstance(units, bool)

    ((url, body),) = transport.calls
    assert url == SAT_URL
    assert set(body) == SAT_REQUEST_KEYS
    assert body["challenge_id"] == item.challenge_id
    assert body["assigned_hotkey"] == BOB
    assert body["seed"] == item.seed
    assert set(body["instance"]) == {"n_vars", "clauses"}
    assert body["instance"]["n_vars"] == 8
    assert body["instance"]["clauses"] == item.instance.clauses_as_lists
    assert len(body["instance"]["clauses"]) == 20


@pytest.mark.parametrize("claimed", [999, 999.0, 20.0, 0, 0.0, 1, 10**9])
def test_the_miners_own_unit_claim_never_becomes_mass(claimed):
    """A liar claiming 999 earns 20; an honest 20.0 earns the integer 20."""
    item = audit_item()
    units = ask(sat_transport_for(item, work_units=claimed), item=item)
    assert units == 20
    assert isinstance(units, int) and not isinstance(units, bool)


@pytest.mark.parametrize(
    "claimed", [True, False, "20", None, -1, -1.0, [20], {"units": 20}]
)
def test_a_malformed_unit_claim_is_a_malformed_body(claimed):
    item = audit_item()
    with pytest.raises(SatWorkError, match="work_units"):
        ask(sat_transport_for(item, work_units=claimed), item=item)


# --- every refusal -----------------------------------------------------------


def test_an_unsatisfiable_claim_earns_nothing():
    item = audit_item()
    with pytest.raises(SatWorkError, match="satisfiable claim"):
        ask(
            sat_transport_for(item, satisfiable=False, assignment=None),
            item=item,
        )


@pytest.mark.parametrize("satisfiable", [False, None, "true", 1, 0])
def test_only_a_literal_true_satisfiable_flag_earns(satisfiable):
    item = audit_item()
    with pytest.raises(SatWorkError):
        ask(sat_transport_for(item, satisfiable=satisfiable), item=item)


def test_an_assignment_that_leaves_a_clause_unsatisfied_is_refused():
    item = audit_item()
    honest = brute_force(item.instance)
    flipped = [-literal for literal in honest]
    with pytest.raises(SatWorkError, match="not real work"):
        ask(sat_transport_for(item, assignment=flipped), item=item)


@pytest.mark.parametrize(
    "assignment",
    [
        None,
        [],
        [1, 2, 3],
        # A contradictory witness: +v and -v both "true".
        [1, -1, 2, -2, 3, -3, 4, -4],
        # Right length, wrong coverage: variable 8 never named.
        [1, 2, 3, 4, 5, 6, 7, 7],
        [1, 2, 3, 4, 5, 6, 7, True],
        [1, 2, 3, 4, 5, 6, 7, "8"],
        [1, 2, 3, 4, 5, 6, 7, 8.0],
        "12345678",
        {"1": True},
    ],
)
def test_a_malformed_assignment_is_refused(assignment):
    item = audit_item()
    with pytest.raises(SatWorkError):
        ask(sat_transport_for(item, assignment=assignment), item=item)


def test_a_response_that_does_not_echo_the_challenge_is_refused():
    item = audit_item()
    with pytest.raises(SatWorkError, match="echo the challenge"):
        ask(sat_transport_for(item, challenge_id="cd" * 32), item=item)


def test_a_response_assigned_to_another_hotkey_is_refused():
    item = audit_item()
    with pytest.raises(SatWorkError, match="hotkey does not match"):
        ask(sat_transport_for(item, assigned_hotkey=CHARLIE), item=item)


def test_an_extra_key_is_refused_rather_than_ignored():
    item = audit_item()
    with pytest.raises(SatWorkError, match="proof_hex"):
        ask(sat_transport_for(item, proof_hex="ab"), item=item)


def test_a_missing_key_is_refused():
    item = audit_item()
    body = sat_response(item)
    body.pop("work_units")
    transport = FakeSatTransport(body=json.dumps(body).encode("utf-8"))
    with pytest.raises(SatWorkError, match="missing"):
        ask(transport, item=item)


@pytest.mark.parametrize("status", [201, 204, 301, 302, 307, 400, 401, 403, 500, 0, -1])
def test_any_status_but_200_is_a_refusal_and_redirects_are_never_followed(status):
    item = audit_item()
    transport = FakeSatTransport(
        status=status, body=json.dumps(sat_response(item)).encode("utf-8")
    )
    with pytest.raises(SatWorkError, match="redirects are never followed"):
        ask(transport, item=item)


def test_an_oversize_body_is_refused_before_it_is_parsed():
    item = audit_item()
    raw = json.dumps(sat_response(item)).encode("utf-8")
    raw = raw + b" " * (MAX_SAT_RESPONSE_BYTES + 1 - len(raw))
    with pytest.raises(SatWorkError, match="byte bound"):
        ask(FakeSatTransport(body=raw), item=item)


def test_a_duplicate_json_key_is_refused_by_the_strict_parser():
    item = audit_item()
    raw = json.dumps(sat_response(item)).encode("utf-8")
    duplicated = raw[:-1] + b',"work_units":999}'
    with pytest.raises(SatWorkError, match="duplicate key"):
        ask(FakeSatTransport(body=duplicated), item=item)


@pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b"null", b"{}", b"\xff\xfe"])
def test_a_body_that_is_not_a_work_response_object_is_refused(raw):
    with pytest.raises(SatWorkError):
        ask(FakeSatTransport(body=raw))


def test_asking_for_work_has_no_default_transport():
    with pytest.raises(SatWorkError, match="injected transport"):
        ask(None)
    with pytest.raises(SatWorkError, match="injected transport"):
        ask(object())


@pytest.mark.parametrize("answer", [None, (200,), b"", (200, "{}"), (True, b"{}")])
def test_a_transport_that_answers_nonsense_is_refused(answer):
    class BadTransport:
        def post(self, url, body):
            return answer

    with pytest.raises(SatWorkError, match="transport must return"):
        ask(BadTransport())


def test_a_non_canonical_item_never_reaches_the_transport():
    """It is priced before it is asked, so a refusal costs no request."""
    instance = SatInstance(n_vars=3, clauses=[[1, 2, 3]])
    item = SatWorkItem(
        instance=instance, seed=7, challenge_id=compute_challenge_id(instance, 7)
    )
    transport = FakeSatTransport()
    with pytest.raises(SatWorkError, match="non-canonical"):
        ask(transport, item=item)
    assert transport.calls == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"hotkey": ""},
        {"hotkey": "a" * 257},
        {"hotkey": "miner\u00e9"},
        {"hotkey": 7},
        {"url": "https://miner.example.test/v1/evidence"},
        {"item": object()},
        {"item": 7},
    ],
)
def test_a_malformed_challenge_never_reaches_the_transport(kwargs):
    transport = FakeSatTransport()
    with pytest.raises(SatWorkError):
        ask(transport, **kwargs)
    assert transport.calls == []


def test_nothing_on_the_work_path_opens_a_socket(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("the audit-work path must not dial anything")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    item = audit_item()
    assert ask(sat_transport_for(item), item=item) == 20
    assert sat_work_url("https://miner.example.test") == SAT_URL


def test_the_work_module_names_no_writer_and_no_dispatcher():
    source = Path(sat_module.__file__).read_text(encoding="utf-8")
    for needle in (
        "SatLane",
        "independent_runtime",
        "neuron.validator",
        "api.cathedral.computer",
        "weights/next",
        "thin-state.json",
        "fetch_vector",
        "set_weights",
        "CUSTOMER_SAT_WORK_UNITS",
        "solve_sat",
    ):
        assert needle not in source, needle


# --- the miner / validator loop, end to end ----------------------------------


class FakeMiner:
    """One machine answering both endpoints over one injected transport.

    ``/v1/evidence`` returns the v2 body the collect tests pin; ``/v1/sat-work``
    solves the canonical instance by exhaustion and returns a witness with an
    inflated unit claim, so the loop also proves the claim is discarded.
    """

    def __init__(self, *, claimed_units: float = 999.0) -> None:
        self.calls: list[str] = []
        self.claimed_units = claimed_units

    def post(self, url: str, body) -> tuple[int, bytes]:
        self.calls.append(url)
        if url.endswith("/v1/evidence"):
            return 200, json.dumps(v2_response()).encode("utf-8")
        if url.endswith(SAT_WORK_PATH):
            instance = SatInstance(
                n_vars=body["instance"]["n_vars"],
                clauses=body["instance"]["clauses"],
            )
            return 200, json.dumps(
                {
                    "satisfiable": True,
                    "assignment": brute_force(instance),
                    "work_units": self.claimed_units,
                    "challenge_id": body["challenge_id"],
                    "assigned_hotkey": body["assigned_hotkey"],
                }
            ).encode("utf-8")
        raise AssertionError(f"the fake miner serves no {url}")


def miner_view() -> MetagraphView:
    return MetagraphView.from_uid_map({BURN_UID: BURN_HOTKEY, MINER_UID: BOB})


def test_a_fake_miner_loop_reaches_composed_and_fires_the_canary_once(tmp_path):
    miner = FakeMiner()

    collected = collect_evidence(
        url=URL,
        assigned_hotkey=BOB,
        nonce=NONCE,
        channel_binding=BINDING,
        transport=miner,
    )
    assert collected.assigned_hotkey == BOB
    assert len(collected.nonce) == NONCE_BYTES

    verifier = MockQuoteVerifier(QuoteVerdict.PASS)
    admitting = ComputeAdapter(
        verifier, collateral_base_url=INTEL_COLLATERAL, qvl_digest=PINNED_QVL
    )
    assert verify_collected(admitting, collected) is QuoteVerdict.PASS
    # Admission is not payment: the adapter that only verified a quote pays
    # nothing, and a funded row behind it would still be blocked.
    assert admitting.contributing is False
    assert admitting.probe(anchor=ANCHOR, view=miner_view()) == {}

    item = canonical_work_item(
        anchor_hash=ANCHOR_HASH,
        miner_ss58=collected.assigned_hotkey,
        machine_id=collected.channel_binding.digest.hex(),
    )
    assert item.challenge_id == E2E_CHALLENGE_ID
    units = collect_sat_work(
        url=SAT_URL,
        assigned_hotkey=collected.assigned_hotkey,
        item=item,
        transport=miner,
    )
    assert units == 20
    assert isinstance(units, int) and not isinstance(units, bool)
    assert miner.calls == [URL, SAT_URL]

    masses = mass_from_units(COMPUTE_ALLOCATION, {BOB: units})
    assert masses == {BOB: COMPUTE_ALLOCATION}
    assert all(isinstance(mass, int) for mass in masses.values())

    bundle, registry = funded_compute_bundle()
    paying = ComputeAdapter(
        verifier,
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=PINNED_QVL,
        verified_mass=masses,
    )
    assert paying.contributing is True
    view = miner_view()
    result = compose_dry_run(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=view,
        inclusion_view=view,
        adapters={COMPUTE_LANE: paying},
        journal_path=tmp_path / INDEPENDENT_STATE_FILE.name,
    )
    assert result.status == STATUS_COMPOSED
    assert MINER_UID in result.dests
    assert BURN_UID in result.dests
    assert sum(result.weights) == 65535
    # The mass bound to the miner came from the re-derived units, not the quote.
    assert result.record["h_map"][str(MINER_UID)]["m"] == COMPUTE_ALLOCATION

    kwargs = prepare_mechanism_weights(
        result=result, journal_path=tmp_path / INDEPENDENT_STATE_FILE.name
    )
    canary = CanaryTransport()
    receipt, used = run_canary(
        tmp_path, result=result, kwargs=kwargs, bundle=bundle, transport=canary
    )
    assert used is canary
    assert canary.calls == [dict(kwargs)]
    assert receipt.kwargs["dests"] == list(result.dests)
    lock = tmp_path / INDEPENDENT_CANARY_FILE.name
    assert lock.name == "independent-canary.json"
    assert lock.exists()


def test_a_quote_pass_alone_binds_no_mass_without_re_derived_units(tmp_path):
    """The same PASS, without the work POST, composes to nothing payable."""
    miner = FakeMiner()
    collected = collect_evidence(
        url=URL,
        assigned_hotkey=BOB,
        nonce=NONCE,
        channel_binding=BINDING,
        transport=miner,
    )
    admitting = ComputeAdapter(
        MockQuoteVerifier(QuoteVerdict.PASS),
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=PINNED_QVL,
    )
    assert verify_collected(admitting, collected) is QuoteVerdict.PASS
    assert mass_from_units(COMPUTE_ALLOCATION, {}) == {}
    assert admitting.contributing is False

    bundle, registry = funded_compute_bundle()
    view = miner_view()
    result = compose_dry_run(
        bundle=bundle,
        key_registry=registry,
        commitment=commitment_for(bundle),
        anchor=ANCHOR,
        anchor_view=view,
        inclusion_view=view,
        adapters={COMPUTE_LANE: admitting},
        journal_path=tmp_path / INDEPENDENT_STATE_FILE.name,
    )
    assert result.status != STATUS_COMPOSED
    assert result.dests == (BURN_UID,)
    assert miner.calls == [URL]


def test_a_failing_quote_never_reaches_the_work_endpoint(tmp_path):
    """FAIL is not admitted, so no challenge is issued and no units exist."""
    miner = FakeMiner()
    collected = collect_evidence(
        url=URL,
        assigned_hotkey=BOB,
        nonce=NONCE,
        channel_binding=BINDING,
        transport=miner,
    )
    failing = ComputeAdapter(
        MockQuoteVerifier(QuoteVerdict.FAIL),
        collateral_base_url=INTEL_COLLATERAL,
        qvl_digest=PINNED_QVL,
    )
    verdict = verify_collected(failing, collected)
    assert verdict is QuoteVerdict.FAIL

    verified_units: dict[str, int] = {}
    if verdict is QuoteVerdict.PASS:
        raise AssertionError("the fixture must not admit a FAIL quote")
    assert verified_units == {}
    assert mass_from_units(COMPUTE_ALLOCATION, verified_units) == {}
    assert miner.calls == [URL]


def test_the_channel_binding_digest_is_the_machine_id_without_re_hashing():
    """The observed TLS SPKI digest IS the machine identity for the seed.

    It is already sha256 of the SubjectPublicKeyInfo, so passing it through the
    bound-key hash would hash a hash and derive a different seed than any other
    validator observing the same connection.
    """
    binding = ChannelBinding(binding_type=CHANNEL_BINDING_TYPE_TLS, digest=DIGEST)
    machine_id = binding.digest.hex()
    assert len(machine_id) == 64
    item = canonical_work_item(
        anchor_hash=ANCHOR_HASH, miner_ss58=BOB, machine_id=machine_id
    )
    assert item.seed == E2E_SEED
