"""Independently re-derived audit work over ``POST /v1/sat-work``.

Attestation is admission. A verified quote proves *where* a machine is; it says
nothing about *what* that machine did, so a PASS verdict must never bind mass on
its own. This module is the other half: it commits to an audit instance derived
from material already pinned for the epoch, asks one miner to solve it, checks
the returned witness clause by clause, and returns the integer work units THIS
validator derived from the item it committed to.

The miner's wire contract is COPIED here, not imported, for the same reason
``collect`` copies the evidence contract: the package that serves this endpoint
also carries a work dispatcher, a scoring path and a chain writer, and depending
on it would drag all of that into a lineage whose whole claim is that it has
none. Four things have to agree byte-for-byte and are pinned by test vectors:
the request key set, the response key set, the instance encoding, and the
``challenge_id`` preimage -- which uses ``json.dumps`` DEFAULT separators
(``", "`` / ``": "``) with sorted keys. Compact separators would hash to
something no honest miner recognises, and every solve would be refused as a
challenge mismatch.

What earns, and what does not:

* only a ``satisfiable: true`` answer with an assignment that covers every
  variable exactly once, with a single sign, and satisfies every clause;
* only the units re-derived from the committed item. The miner's ``work_units``
  field is shape-checked so a malformed body is refused, and then discarded. A
  miner claiming 999 earns the clause count or nothing;
* only canonical audit work. This lineage pays for the instance it generated
  itself; a customer job arriving on this path is not SN39 work and is refused
  rather than priced.

The validator does NOT solve. Deriving the instance from a planted assignment
makes it satisfiable by construction, so a checkable witness always exists, and
checking one is a single scan over the literals. No solver ships here: a solver
on the accept path is a way to spend unbounded time on attacker-chosen input.

The transport is INJECTED and has no default, exactly as in ``collect``: a
default that dialed would make "ask a miner for work" reachable from a unit test
and from a misconfigured operator run.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .canonical import parse_strict_json
from .collect import MAX_HOTKEY_BYTES, EvidenceTransport
from .compute import canonical_seed_material
from .errors import PolicyBundleError, PolicyFetchError, SatWorkError
from .fetch_policy import validate_policy_url

# The versioned unit rule. The derivation is part of the contract, so any change
# to it MUST introduce a new rule id rather than quietly repricing past epochs.
SAT_WORK_UNIT_RULE = "sat_work_units_v1"

SAT_WORK_PATH = "/v1/sat-work"

# The miner serves the solve under this bound; a body over it is refused rather
# than truncated and parsed.
MAX_SAT_RESPONSE_BYTES = 64 * 1024

SAT_REQUEST_KEYS = frozenset({"challenge_id", "assigned_hotkey", "instance", "seed"})
SAT_INSTANCE_KEYS = frozenset({"n_vars", "clauses"})
SAT_RESPONSE_KEYS = frozenset(
    {"satisfiable", "assignment", "work_units", "challenge_id", "assigned_hotkey"}
)

# The serving side's bounds, restated. They are the same numbers on both ends
# because a request one side considers legal and the other refuses is an
# unforced zero for an honest miner.
MAX_N_VARS = 512
MAX_CLAUSES = 8192
MAX_LITERALS = 65_536
MAX_LITERALS_PER_CLAUSE = 1024

# The seed travels as a JSON number inside the challenge preimage, so it lives
# in the signed 64-bit range the serving side accepts.
MIN_SEED = -(2**63)
MAX_SEED = 2**63 - 1
MAX_NONNEGATIVE_SIGNED_I64 = (1 << 63) - 1

# The canonical audit generator's shape. Small on purpose: the point is a cheap,
# unforgeable certificate, not a benchmark.
CANONICAL_N_VARS = 8
CANONICAL_CLAUSES = 20
CANONICAL_CLAUSE_LENGTH = 3

_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class SatInstance:
    """A CNF instance in DIMACS form, bounded and normalised at construction.

    Variables are ``1..n_vars``; a literal is a non-zero int where ``+v`` means
    "v is true". Clauses are held as tuples so an instance cannot be mutated
    after the ``challenge_id`` has been computed over it; ``clauses_as_lists``
    is the wire and preimage form.
    """

    n_vars: int
    clauses: tuple[tuple[int, ...], ...]

    def __post_init__(self) -> None:
        n_vars = self.n_vars
        if (
            isinstance(n_vars, bool)
            or not isinstance(n_vars, int)
            or not 1 <= n_vars <= MAX_N_VARS
        ):
            raise SatWorkError(f"n_vars must be an integer in 1..{MAX_N_VARS}")
        raw = self.clauses
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
            raise SatWorkError("clauses must be a sequence of clauses")
        # A zero-clause instance is satisfied by any assignment, so it is not
        # work; the serving side refuses it at the same bound.
        if not raw or len(raw) > MAX_CLAUSES:
            raise SatWorkError(f"clauses must be 1..{MAX_CLAUSES} entries")
        literal_count = 0
        normalised: list[tuple[int, ...]] = []
        for clause in raw:
            if not isinstance(clause, Sequence) or isinstance(clause, (str, bytes)):
                raise SatWorkError("each clause must be a sequence of literals")
            if not clause or len(clause) > MAX_LITERALS_PER_CLAUSE:
                raise SatWorkError(
                    f"each clause must carry 1..{MAX_LITERALS_PER_CLAUSE} literals"
                )
            literal_count += len(clause)
            if literal_count > MAX_LITERALS:
                raise SatWorkError(
                    f"the instance carries more than {MAX_LITERALS} literals"
                )
            for literal in clause:
                if (
                    isinstance(literal, bool)
                    or not isinstance(literal, int)
                    or literal == 0
                    or abs(literal) > n_vars
                ):
                    raise SatWorkError(
                        "a literal must be a non-zero integer within 1..n_vars"
                    )
            normalised.append(tuple(int(literal) for literal in clause))
        object.__setattr__(self, "clauses", tuple(normalised))

    @property
    def clauses_as_lists(self) -> list[list[int]]:
        """The wire and preimage form: a JSON array of arrays."""
        return [list(clause) for clause in self.clauses]


@dataclass(frozen=True)
class SatWorkItem:
    """One audit challenge: the instance, the seed it came from, and its id.

    The seed makes the item reproducible, so a second validator auditing the
    same machine in the same epoch asks it the same question. The
    ``challenge_id`` binds instance and seed together, so a miner cannot answer
    a cheaper instance under this challenge.
    """

    instance: SatInstance
    seed: int
    challenge_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.instance, SatInstance):
            raise SatWorkError("a work item carries a validated SatInstance")
        require_seed(self.seed)
        challenge_id = self.challenge_id
        if (
            not isinstance(challenge_id, str)
            or len(challenge_id) != 64
            or any(character not in _HEX for character in challenge_id)
        ):
            raise SatWorkError("challenge_id must be 64 lowercase hex characters")
        if compute_challenge_id(self.instance, self.seed) != challenge_id:
            raise SatWorkError(
                "challenge_id is not the digest of this instance and seed"
            )


def require_seed(seed: Any) -> int:
    """Return ``seed`` if it is a signed 64-bit integer. ``bool`` is not one."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise SatWorkError("a seed must be an integer")
    if not MIN_SEED <= seed <= MAX_SEED:
        raise SatWorkError(f"a seed must be within [{MIN_SEED}, {MAX_SEED}]")
    return seed


def compute_challenge_id(instance: SatInstance, seed: int) -> str:
    """The serving side's challenge digest, byte-for-byte.

    ``json.dumps`` is called with its DEFAULT separators and sorted keys. That
    is not a stylistic detail: compact separators produce a different preimage,
    and an honest miner recomputing the id would reject every challenge.
    """
    if not isinstance(instance, SatInstance):
        raise SatWorkError("a challenge id is computed over a validated SatInstance")
    payload = {
        "n_vars": instance.n_vars,
        "clauses": instance.clauses_as_lists,
        "seed": require_seed(seed),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def canonical_instance(seed: int) -> SatInstance:
    """The audit instance for ``seed``, satisfiable by construction.

    A planted assignment is drawn from a local ``random.Random(seed)`` -- never
    from process randomness -- and every clause is emitted with at least one
    literal true under it. So a certificate always exists, the validator never
    has to solve anything, and two validators deriving the same seed derive the
    same instance.
    """
    rng = random.Random(require_seed(seed))
    planted = {
        variable: rng.choice([True, False])
        for variable in range(1, CANONICAL_N_VARS + 1)
    }
    clauses: list[list[int]] = []
    for _ in range(CANONICAL_CLAUSES):
        vars_in_clause = rng.sample(
            range(1, CANONICAL_N_VARS + 1), CANONICAL_CLAUSE_LENGTH
        )
        true_var = rng.choice(vars_in_clause)
        clause: list[int] = []
        for variable in vars_in_clause:
            if variable == true_var:
                literal = variable if planted[variable] else -variable
            else:
                literal = variable if rng.choice([True, False]) else -variable
            clause.append(literal)
        clauses.append(clause)
    return SatInstance(n_vars=CANONICAL_N_VARS, clauses=tuple(clauses))


def instance_equals_canonical(instance: SatInstance, seed: int) -> bool:
    """Whether ``instance`` is EXACTLY the audit derivation from ``seed``."""
    if not isinstance(instance, SatInstance):
        raise SatWorkError("only a validated SatInstance can be compared")
    return instance == canonical_instance(seed)


def seed_from_material(material: bytes) -> int:
    """Fold 32 bytes of pinned seed material into a nonnegative signed i64.

    The high bits are kept rather than truncated to 31: collapsing the seed
    space would raise the chance that two epochs, or two machines, are audited
    with the same challenge id.
    """
    if not isinstance(material, (bytes, bytearray)) or len(material) != 32:
        raise SatWorkError("seed material must be 32 bytes")
    return int.from_bytes(bytes(material)[:8], "big") & MAX_NONNEGATIVE_SIGNED_I64


def canonical_work_item(
    *, anchor_hash: str, miner_ss58: str, machine_id: str
) -> SatWorkItem:
    """The audit item for one machine at one anchor.

    Derived from material already pinned for the epoch -- the frozen anchor, the
    miner hotkey, the machine identity -- and from nothing else. There is no
    per-validator namespace and no process randomness, so this challenge is one
    any third party can regenerate and re-check.
    """
    material = canonical_seed_material(
        anchor_hash=anchor_hash, miner_ss58=miner_ss58, machine_id=machine_id
    )
    seed = seed_from_material(material)
    instance = canonical_instance(seed)
    return SatWorkItem(
        instance=instance,
        seed=seed,
        challenge_id=compute_challenge_id(instance, seed),
    )


def derived_work_units(item: SatWorkItem) -> int:
    """``sat_work_units_v1``: the integer units ``item`` is worth.

    Computed from the committed item alone -- never from a miner's claim, never
    from a signer's assertion, and never as a float, because mass apportionment
    is exact integer arithmetic. Canonical audit work is worth its clause count.

    A non-canonical instance is not repriced, it is refused: this lineage pays
    for work it generated itself, and a bounded customer job that arrived on
    this path is somebody else's economics.
    """
    if not isinstance(item, SatWorkItem):
        raise SatWorkError("work units are derived from a validated SatWorkItem")
    if not instance_equals_canonical(item.instance, item.seed):
        raise SatWorkError(
            "the instance is not the audit derivation from its own seed; "
            "non-canonical work earns nothing on this lineage"
        )
    return len(item.instance.clauses)


def sat_work_url(url: str) -> str:
    """Return the validated ``/v1/sat-work`` URL to POST, or raise.

    The transport rules are the policy fetch's rules. The path must then BE the
    work path: an operator naming a base URL gets it appended, and anything else
    -- an evidence endpoint included -- is a refusal rather than a rewrite of a
    reviewed config into a different resource.
    """
    try:
        endpoint = validate_policy_url(url)
    except PolicyFetchError as exc:
        raise SatWorkError(
            f"the miner work URL is not a hardened public HTTPS URL: {exc}"
        ) from exc
    if endpoint.path not in ("/", SAT_WORK_PATH):
        raise SatWorkError(
            f"the miner work URL path must be {SAT_WORK_PATH!r} or empty, "
            f"not {endpoint.path!r}"
        )
    return f"https://{endpoint.host_header}{SAT_WORK_PATH}"


def _require_exact_keys(
    document: Mapping[str, Any], expected: frozenset[str], label: str
) -> None:
    present = set(document)
    unknown = sorted(present - expected)
    missing = sorted(expected - present)
    if unknown or missing:
        raise SatWorkError(
            f"{label} has unknown keys {unknown} and is missing {missing}; "
            f"the work contract accepts exactly {sorted(expected)}"
        )


def _require_assigned_hotkey(assigned_hotkey: str) -> str:
    if (
        not isinstance(assigned_hotkey, str)
        or not assigned_hotkey
        or not assigned_hotkey.isascii()
    ):
        raise SatWorkError("assigned_hotkey must be a non-empty ASCII string")
    if len(assigned_hotkey) > MAX_HOTKEY_BYTES:
        raise SatWorkError(
            f"assigned_hotkey is {len(assigned_hotkey)} characters, over the "
            f"{MAX_HOTKEY_BYTES} bound"
        )
    return assigned_hotkey


def _post(
    transport: EvidenceTransport, url: str, body: Mapping[str, object]
) -> tuple[int, bytes]:
    if transport is None or not callable(getattr(transport, "post", None)):
        raise SatWorkError(
            "asking a miner for work requires an injected transport; this "
            "package ships no dialer, because no discovery has validated that "
            "a URL is a miner"
        )
    answer = transport.post(url, body)
    if not isinstance(answer, tuple) or len(answer) != 2:
        raise SatWorkError("the work transport must return (status, body)")
    status, raw = answer
    if isinstance(status, bool) or not isinstance(status, int):
        raise SatWorkError("the work transport must return an integer status")
    if not isinstance(raw, (bytes, bytearray)):
        raise SatWorkError("the work transport must return a raw byte body")
    return status, bytes(raw)


def _check_claimed_units(claimed: Any) -> None:
    """Shape-check the miner's own number, then forget it.

    A malformed field means a malformed body, so it is refused. The value is
    never compared against the derivation and never becomes mass: a valid
    witness earns the derived integer whether the claim said ``20.0`` or 999.
    """
    if isinstance(claimed, bool) or not isinstance(claimed, (int, float)):
        raise SatWorkError("the work_units field must be a JSON number")
    if not math.isfinite(claimed):
        raise SatWorkError("the work_units field must be finite")
    if claimed < 0:
        raise SatWorkError("the work_units field must not be negative")


def _check_witness(assignment: Any, instance: SatInstance) -> None:
    """Re-check a claimed satisfying assignment against every clause."""
    if not isinstance(assignment, list) or len(assignment) != instance.n_vars:
        raise SatWorkError(
            f"an assignment must be a JSON array of exactly {instance.n_vars} literals"
        )
    for literal in assignment:
        if isinstance(literal, bool) or not isinstance(literal, int):
            raise SatWorkError("an assignment literal must be an integer, not a bool")
    # Exactly-once coverage with a single sign. Without it a contradictory
    # assignment carrying both ``+v`` and ``-v`` could "satisfy" clauses no
    # Boolean assignment can.
    if {abs(literal) for literal in assignment} != set(range(1, instance.n_vars + 1)):
        raise SatWorkError(
            "an assignment must name every variable exactly once with one sign"
        )
    true_literals = set(assignment)
    for clause in instance.clauses:
        if not any(literal in true_literals for literal in clause):
            raise SatWorkError(
                "the assignment leaves a clause unsatisfied; the claimed solve "
                "is not real work"
            )


def collect_sat_work(
    *,
    url: str,
    assigned_hotkey: str,
    item: SatWorkItem,
    transport: EvidenceTransport,
) -> int:
    """POST one audit challenge and return the integer units it earned.

    The units come from ``derived_work_units`` on the item THIS validator
    committed to, and the item is priced before the request is sent, so a miner
    cannot influence the number by anything it answers. Everything the miner
    controls is either checked (the witness) or discarded (its unit claim).

    Raises ``SatWorkError`` for every refusal, including an unsatisfiable claim:
    a negative answer carries no bounded certificate in this contract, so it is
    zero rather than an unverified payout.
    """
    target = sat_work_url(url)
    hotkey = _require_assigned_hotkey(assigned_hotkey)
    if not isinstance(item, SatWorkItem):
        raise SatWorkError("asking for work requires a validated SatWorkItem")
    units = derived_work_units(item)

    instance_body: dict[str, object] = {
        "n_vars": item.instance.n_vars,
        "clauses": item.instance.clauses_as_lists,
    }
    request: dict[str, object] = {
        "challenge_id": item.challenge_id,
        "assigned_hotkey": hotkey,
        "instance": instance_body,
        "seed": item.seed,
    }
    _require_exact_keys(request, SAT_REQUEST_KEYS, "the work request")
    _require_exact_keys(instance_body, SAT_INSTANCE_KEYS, "the work request instance")

    status, raw = _post(transport, target, request)
    if status != 200:
        raise SatWorkError(
            f"the miner work POST answered {status}; only 200 is accepted and "
            "redirects are never followed"
        )
    if len(raw) > MAX_SAT_RESPONSE_BYTES:
        raise SatWorkError(
            f"the work response is {len(raw)} bytes, over the "
            f"{MAX_SAT_RESPONSE_BYTES} byte bound"
        )
    try:
        response = parse_strict_json(raw, max_bytes=MAX_SAT_RESPONSE_BYTES)
    except PolicyBundleError as exc:
        raise SatWorkError(f"the work response is not strict JSON: {exc}") from exc
    if not isinstance(response, dict):
        raise SatWorkError("the work response must be a JSON object")
    _require_exact_keys(response, SAT_RESPONSE_KEYS, "the work response")

    if response["challenge_id"] != item.challenge_id:
        raise SatWorkError("the work response does not echo the challenge id")
    if response["assigned_hotkey"] != hotkey:
        raise SatWorkError("the work response hotkey does not match the request")
    if response["satisfiable"] is not True:
        raise SatWorkError(
            "only a satisfiable claim with a checkable witness earns; this "
            "contract carries no bounded certificate for a negative answer"
        )
    _check_claimed_units(response["work_units"])
    _check_witness(response["assignment"], item.instance)
    return units


__all__ = [
    "CANONICAL_CLAUSES",
    "CANONICAL_CLAUSE_LENGTH",
    "CANONICAL_N_VARS",
    "MAX_CLAUSES",
    "MAX_LITERALS",
    "MAX_LITERALS_PER_CLAUSE",
    "MAX_NONNEGATIVE_SIGNED_I64",
    "MAX_N_VARS",
    "MAX_SAT_RESPONSE_BYTES",
    "MAX_SEED",
    "MIN_SEED",
    "SAT_INSTANCE_KEYS",
    "SAT_REQUEST_KEYS",
    "SAT_RESPONSE_KEYS",
    "SAT_WORK_PATH",
    "SAT_WORK_UNIT_RULE",
    "SatInstance",
    "SatWorkError",
    "SatWorkItem",
    "canonical_instance",
    "canonical_work_item",
    "collect_sat_work",
    "compute_challenge_id",
    "derived_work_units",
    "instance_equals_canonical",
    "require_seed",
    "sat_work_url",
    "seed_from_material",
]
