"""A failure that names only its symptom costs hours; these pin the causes.

Three surfaces used to report a fenced write with one sentence apiece, and
none of the three sentences said anything an operator could act on:

1. `_recover_pending_launch_receipt` wrapped EVERY exception from the chain
   preflight into "chain preflight is temporarily unavailable". An
   unregistered hotkey, a missing validator permit, a lite node that cannot
   serve `MinNonImmuneUids`, a commit-reveal subnet, a wrong runtime root and
   an actually-flaky endpoint all printed the same line, once per restart.
2. `_classify_finalized_receipt` funnelled twenty-odd distinct exits into
   three return values and dropped the exception behind its broad `except`.
   When a long-running process starts failing one archive call that a freshly
   restarted process makes fine, that exception IS the diagnosis.
3. The surfaced remediations asserted durable facts — "the exact signed
   attempt remains fenced", "a write may have finalized" — on paths where no
   attempt had been journaled and no chain call had been made.

What these tests must NOT allow is a fix that made anything more permissive.
Every verdict, fence and exit is asserted alongside the new wording: a
transient read still returns NOT_PROVEN and still refuses a replacement, and
a positive mismatch is still FAIL.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from scaffold import validator_thin as vt
from scaffold.events import EventLogger, sanitized_status_record

HOTKEY = "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"
EXTRINSIC_HASH = "0x" + "ab" * 32
BLOCK_HASH = "0x" + "cd" * 32
FINALIZED_HASH = "0x" + "ef" * 32
BLOCK_NUMBER = 1000
FINALIZED_NUMBER = 1004
VERSION_KEY = 7
WIRE_UIDS = [3, 11]
WIRE_WEIGHTS = [40000, 25535]


# --------------------------------------------------------------------------
# Chain doubles. Small enough to read, complete enough that the healthy shape
# genuinely reaches PASS, so every mutation below isolates exactly one exit.
# --------------------------------------------------------------------------


class _Value:
    def __init__(self, value):
        self.value = value


def _weights_call() -> dict:
    return {
        "call_module": "SubtensorModule",
        "call_function": "set_mechanism_weights",
        "call_args": [
            {"name": "netuid", "value": 39},
            {"name": "mecid", "value": 0},
            {"name": "version_key", "value": VERSION_KEY},
            {"name": "dests", "value": WIRE_UIDS},
            {"name": "weights", "value": WIRE_WEIGHTS},
        ],
    }


def _extrinsic(extrinsic_hash: str = EXTRINSIC_HASH) -> _Value:
    return _Value(
        {
            "extrinsic_hash": extrinsic_hash,
            "address": HOTKEY,
            "call": _weights_call(),
        }
    )


class _Execution:
    def __init__(self, *, is_success=True, extrinsic_idx=0, error_message=None):
        self.is_success = is_success
        self.extrinsic_idx = extrinsic_idx
        self.error_message = error_message


class _Substrate:
    """A finalized chain that answers every read the classifier makes."""

    def __init__(self, *, block=None, execution=..., raises=None):
        self.block = (
            {"extrinsics": [_extrinsic()]} if block is ... or block is None else block
        )
        self.execution = _Execution() if execution is ... else execution
        self.raises = raises or {}

    def _maybe_raise(self, name: str) -> None:
        if name in self.raises:
            raise self.raises[name]

    def get_chain_finalised_head(self):
        self._maybe_raise("get_chain_finalised_head")
        return FINALIZED_HASH

    def get_block_number(self, _block_hash):
        self._maybe_raise("get_block_number")
        return FINALIZED_NUMBER

    def get_block_hash(self, number):
        self._maybe_raise("get_block_hash")
        return FINALIZED_HASH if number == FINALIZED_NUMBER else BLOCK_HASH

    def get_block(self, *, block_hash):
        self._maybe_raise("get_block")
        return self.block

    def retrieve_extrinsic_by_hash(self, _block_hash, _extrinsic_hash):
        self._maybe_raise("retrieve_extrinsic_by_hash")
        return self.execution


class _Subtensor:
    def __init__(self, substrate):
        self.substrate = substrate


def _classify(subtensor, **overrides):
    """Run the classifier on the minimal healthy contract, plus overrides."""
    reason: list[str] = []
    kwargs = {
        "receipt": None,
        "extrinsic_hash": EXTRINSIC_HASH,
        "block_hash": BLOCK_HASH,
        "block_number": BLOCK_NUMBER,
        "validator_hotkey": HOTKEY,
        "netuid": 39,
        "version_key": VERSION_KEY,
        "wire_uids": WIRE_UIDS,
        "wire_weights": WIRE_WEIGHTS,
        "require_receipt": False,
        "reason_out": reason,
    }
    kwargs.update(overrides)
    status = vt._classify_finalized_receipt(subtensor, **kwargs)
    return status, (reason[-1] if reason else "")


# --------------------------------------------------------------------------
# The healthy baseline. If this ever stops proving, every case below is
# testing the wrong exit.
# --------------------------------------------------------------------------


def test_the_healthy_contract_still_proves_the_exact_call():
    status, reason = _classify(_Subtensor(_Substrate()))
    assert status == vt.PASS
    assert reason == "the exact finalized call is proven"


# --------------------------------------------------------------------------
# C. Every NOT_PROVEN exit is distinguishable, and no verdict moved.
# --------------------------------------------------------------------------


def test_a_transient_archive_read_still_fences_and_names_the_failing_call():
    """The property that must never regress, plus the one that was missing.

    A read that raises is not evidence of a mismatch, so it stays NOT_PROVEN
    — anything else would let an RPC blip authorize a second write over an
    irreversible one. What changes is that the operator can now see WHICH of
    the eight sequential calls failed and why, which is the only way to tell a
    rate-limited endpoint from a node that never had the state.
    """
    substrate = _Substrate(
        raises={"retrieve_extrinsic_by_hash": TimeoutError("read timed out")}
    )
    status, reason = _classify(_Subtensor(substrate))
    assert status == vt.NOT_PROVEN
    assert "substrate.retrieve_extrinsic_by_hash" in reason
    assert "TimeoutError" in reason or "ETIMEDOUT" in reason


@pytest.mark.parametrize(
    "failing_call, expected_step",
    [
        ("get_chain_finalised_head", "substrate.get_chain_finalised_head"),
        ("get_block_number", "substrate.get_block_number(finalized head)"),
        ("get_block", "substrate.get_block(receipt block hash)"),
        (
            "retrieve_extrinsic_by_hash",
            "substrate.retrieve_extrinsic_by_hash(receipt block)",
        ),
    ],
)
def test_each_failing_chain_read_names_itself(failing_call, expected_step):
    substrate = _Substrate(raises={failing_call: ConnectionResetError("reset by peer")})
    status, reason = _classify(_Subtensor(substrate))
    assert status == vt.NOT_PROVEN
    assert reason.startswith(f"chain read failed at {expected_step}: ")


def test_a_missing_substrate_interface_is_distinguishable():
    status, reason = _classify(_Subtensor(None))
    assert status == vt.NOT_PROVEN
    assert reason == "the subtensor client exposes no substrate interface"


def test_a_receipt_without_a_boolean_success_is_distinguishable():
    status, reason = _classify(
        _Subtensor(_Substrate()),
        receipt=SimpleNamespace(is_success="yes"),
        require_receipt=True,
    )
    assert status == vt.NOT_PROVEN
    assert reason == "the submit receipt exposes no boolean is_success"


def test_a_block_that_is_not_a_dict_is_distinguishable():
    status, reason = _classify(_Subtensor(_Substrate(block=["not", "a", "dict"])))
    assert status == vt.NOT_PROVEN
    assert reason == "the named block did not decode to a dict"


def test_a_block_without_an_extrinsics_list_is_distinguishable():
    status, reason = _classify(_Subtensor(_Substrate(block={"extrinsics": None})))
    assert status == vt.NOT_PROVEN
    assert reason == "the named block carries no extrinsics list"


def test_a_block_missing_the_signed_hash_is_distinguishable():
    substrate = _Substrate(block={"extrinsics": [_extrinsic("0x" + "11" * 32)]})
    status, reason = _classify(_Subtensor(substrate))
    assert status == vt.NOT_PROVEN
    assert reason == "no extrinsic in the named block carries the signed hash"


def test_a_missing_execution_record_is_distinguishable():
    status, reason = _classify(_Subtensor(_Substrate(execution=None)))
    assert status == vt.NOT_PROVEN
    assert reason == "the archive returned no execution record for the signed hash"


def test_a_bad_inclusion_timestamp_is_distinguishable():
    """The timestamp exit lives inside the try, so it must not read as a raise."""

    class _TimestampSubtensor(_Subtensor):
        def metagraph(self, *_args, **_kwargs):  # pragma: no cover - not reached
            raise AssertionError("uid_hotkeys is None; no metagraph read is owed")

        def commit_reveal_enabled(self, **_kwargs):
            return False

    substrate = _Substrate()
    substrate.query = lambda **_kwargs: _Value(0)
    policy = vt.InclusionPolicy(
        valid_from_block=BLOCK_NUMBER - 1,
        valid_until_block=BLOCK_NUMBER + 4,
        valid_from_time=datetime.fromtimestamp(0, UTC),
        valid_until_time=datetime.fromtimestamp(1 << 34, UTC),
        expected_next_epoch_start_block=None,
    )
    status, reason = _classify(
        _TimestampSubtensor(substrate),
        inclusion_policy=policy,
    )
    assert status == vt.NOT_PROVEN
    assert reason == "the inclusion block timestamp is not a positive integer"


def test_a_duplicated_signed_hash_is_still_a_positive_mismatch():
    """The one duplicate case that is FAIL, not NOT_PROVEN. It stays FAIL."""
    substrate = _Substrate(block={"extrinsics": [_extrinsic(), _extrinsic()]})
    status, reason = _classify(_Subtensor(substrate))
    assert status == vt.FAIL
    assert reason == "the named block carries the signed hash more than once"


def test_a_contradicted_call_stays_a_mismatch_and_names_the_clause():
    substrate = _Substrate()
    status, reason = _classify(_Subtensor(substrate), wire_weights=[1, 2])
    assert status == vt.FAIL
    assert reason == "the finalized call contradicts weights"


def test_the_reason_collector_is_optional():
    """Callers that only need a verdict — and tests that stub this out — are
    unaffected, which is why the collector is a keyword with a None default."""
    assert (
        vt._classify_finalized_receipt(
            _Subtensor(_Substrate()),
            receipt=None,
            extrinsic_hash=EXTRINSIC_HASH,
            block_hash=BLOCK_HASH,
            block_number=BLOCK_NUMBER,
            validator_hotkey=HOTKEY,
            netuid=39,
            version_key=VERSION_KEY,
            wire_uids=WIRE_UIDS,
            wire_weights=WIRE_WEIGHTS,
            require_receipt=False,
        )
        == vt.PASS
    )
    assert vt._receipt_reason_suffix([]) == ""


# --------------------------------------------------------------------------
# A. Preflight causes reach the operator instead of one generic sentence.
# --------------------------------------------------------------------------


def _recovery_args(tmp_path):
    return SimpleNamespace(
        broadcast=True,
        offline=False,
        network="finney",
        netuid=39,
        wallet_name="validator",
        wallet_hotkey="default",
        state_file=str(tmp_path / "state.json"),
        runtime_root=str(tmp_path),
    )


DIAGNOSTIC_PREFLIGHT_CAUSES = [
    "validator hotkey is not registered on this subnet",
    "validator hotkey lacks validator permit",
    "metagraph did not resolve at the finalized chain head",
    "subnet registration and immunity policy is unavailable at finalized head",
    "chain preflight exceeded its 180s wall-clock deadline",
    "Finney SN39 broadcast requires commit-reveal disabled",
    "Finney SN39 broadcast requires the pinned burn hotkey to remain the live "
    "subnet owner",
    "SN39 broadcast is supported only on the pinned Finney genesis",
]


@pytest.mark.parametrize("cause", DIAGNOSTIC_PREFLIGHT_CAUSES)
def test_a_diagnostic_preflight_refusal_surfaces_its_own_wording(
    monkeypatch, tmp_path, cause
):
    """Each of these already knew exactly what was wrong. Say it.

    These are the nine shapes a `chain_preflight` refusal actually takes on
    SN39, and every one of them names a condition an operator owns. The old
    wrapper replaced all nine with "temporarily unavailable", which is both
    unactionable and, for most of them, false: an unregistered hotkey does not
    become registered by waiting.
    """

    def _refuse(_args):
        raise vt.wire.VectorError(cause)

    monkeypatch.setattr(vt, "_prepare_tick_preflight", _refuse)
    monkeypatch.setattr(
        vt,
        "_pending_recovery_tick_lock",
        lambda _args: pytest.fail("preflight must fail before any lock is taken"),
    )

    with pytest.raises(vt._PendingReceiptNotProven) as raised:
        vt._recover_pending_launch_receipt(_recovery_args(tmp_path))

    message = str(raised.value)
    assert cause in message
    assert "temporarily unavailable" not in message
    # Nothing was journaled, so nothing may claim to be fenced.
    assert raised.value.fenced_attempt is False
    # The exit path is unchanged: same exception type, so the same event code
    # and the same nonzero return as before.
    assert isinstance(raised.value, vt.wire.VectorError)
    assert raised.value.__cause__ is not None


def test_a_transient_preflight_failure_keeps_its_framing_and_gains_its_cause(
    monkeypatch, tmp_path
):
    """A closed socket really is transient, so "unavailable" stays — but it is
    no longer the entire message."""

    def _drop(_args):
        raise ConnectionResetError("connection reset by peer")

    monkeypatch.setattr(vt, "_prepare_tick_preflight", _drop)

    with pytest.raises(vt._PendingReceiptNotProven) as raised:
        vt._recover_pending_launch_receipt(_recovery_args(tmp_path))

    message = str(raised.value)
    assert "temporarily unavailable" in message
    assert "ConnectionResetError" in message
    assert raised.value.fenced_attempt is False


def test_an_errno_bearing_transient_failure_collapses_to_its_errno(
    monkeypatch, tmp_path
):
    """`stable_error` is deliberately lossy for OSError: the errno names the
    condition without carrying the path or host that produced it."""

    def _drop(_args):
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(vt, "_prepare_tick_preflight", _drop)
    with pytest.raises(vt._PendingReceiptNotProven) as raised:
        vt._recover_pending_launch_receipt(_recovery_args(tmp_path))
    assert "ECONNREFUSED" in str(raised.value)


def test_a_preflight_refusal_carrying_a_path_is_redacted_not_dropped(
    monkeypatch, tmp_path
):
    """The runtime-root refusal names an absolute path; the operator still
    learns which check spoke, and the path itself never reaches the journal."""

    def _refuse(_args):
        raise vt.wire.VectorError(
            "Finney SN39 broadcast requires the canonical owner-only runtime "
            "root /var/lib/cathedral-validator"
        )

    monkeypatch.setattr(vt, "_prepare_tick_preflight", _refuse)
    with pytest.raises(vt._PendingReceiptNotProven) as raised:
        vt._recover_pending_launch_receipt(_recovery_args(tmp_path))
    message = str(raised.value)
    assert "requires the canonical owner-only runtime root" in message
    assert "/var/lib/cathedral-validator" not in message
    assert "<path>" in message


def test_an_already_classified_receipt_failure_is_never_re_wrapped(
    monkeypatch, tmp_path
):
    """`_prepare_tick_preflight` can itself raise the two fenced types. Those
    carry their own durable meaning and must pass through untouched."""
    original = vt._PostSignedSubmissionMismatch("a positive contradiction")

    def _raise(_args):
        raise original

    monkeypatch.setattr(vt, "_prepare_tick_preflight", _raise)
    with pytest.raises(vt._PostSignedSubmissionMismatch) as raised:
        vt._recover_pending_launch_receipt(_recovery_args(tmp_path))
    assert raised.value is original


def test_recovery_still_declines_without_broadcast(tmp_path):
    """The gate that decides whether recovery runs at all is untouched."""
    args = _recovery_args(tmp_path)
    args.broadcast = False
    assert vt._recover_pending_launch_receipt(args) is None
    args.broadcast = True
    args.offline = True
    assert vt._recover_pending_launch_receipt(args) is None


# --------------------------------------------------------------------------
# B and D. Remediation stops asserting durable facts it cannot know.
# --------------------------------------------------------------------------


def _events(records: list[dict]) -> EventLogger:
    stream = io.StringIO()

    class _Capturing(EventLogger):
        def event(self, code, **kwargs):
            record = super().event(code, **kwargs)
            records.append(record)
            return record

    return _Capturing(mode="thin", jsonl=stream, tty=None)


def _run_args(tmp_path, records) -> SimpleNamespace:
    return SimpleNamespace(
        broadcast=True,
        offline=False,
        once=True,
        interval_secs=0,
        network="finney",
        netuid=39,
        wallet_name="validator",
        wallet_hotkey="default",
        publisher_url="https://api.cathedral.computer",
        public_key_hex="ab" * 32,
        key_id="k1",
        require_policy="validated_supply_v3",
        provenance="shadow",
        max_submissions=1,
        state_file=str(tmp_path / "state.json"),
        runtime_root=str(tmp_path),
        _events=_events(records),
    )


def _emitted(records: list[dict], code: str) -> dict:
    matches = [record for record in records if record["event"] == code]
    assert len(matches) == 1, f"expected exactly one {code}, got {len(matches)}"
    return matches[0]


def test_no_fenced_attempt_claim_when_the_journal_was_never_opened(
    monkeypatch, tmp_path
):
    """The claim that costs the most when it is wrong.

    "The exact signed attempt remains fenced" tells an operator a transaction
    exists and must never be replaced. On the preflight path the journal has
    not been opened, so there may be no attempt at all, and the sentence sends
    them hunting for a hash nobody signed.
    """
    records: list[dict] = []
    args = _run_args(tmp_path, records)
    monkeypatch.setattr(vt, "_validate_runtime_contract", lambda _args: None)
    monkeypatch.setattr(
        vt,
        "_recover_pending_launch_receipt",
        lambda _args: (_ for _ in ()).throw(
            vt._PendingReceiptNotProven(
                "pending receipt recovery chain preflight refused: VectorError: "
                "validator hotkey lacks validator permit",
                fenced_attempt=False,
            )
        ),
    )

    assert vt.run(args) == 1  # the exit code is unchanged
    event = _emitted(records, "PENDING_RECEIPT_NOT_PROVEN")
    assert event["status"] == vt.NOT_PROVEN
    assert "validator hotkey lacks validator permit" in event["detail"]
    assert "remains fenced" not in event["remediation"]
    assert "No signed attempt was recorded" in event["remediation"]


def test_the_fenced_attempt_claim_survives_where_it_is_true(monkeypatch, tmp_path):
    records: list[dict] = []
    args = _run_args(tmp_path, records)
    monkeypatch.setattr(vt, "_validate_runtime_contract", lambda _args: None)
    monkeypatch.setattr(
        vt,
        "_recover_pending_launch_receipt",
        lambda _args: (_ for _ in ()).throw(
            vt._PendingReceiptNotProven(
                "pending receipt is still not provable from the archive; no "
                "second chain write was attempted (cause: chain read failed at "
                "substrate.get_block(receipt block hash): TimeoutError: slow)"
            )
        ),
    )

    assert vt.run(args) == 1
    event = _emitted(records, "PENDING_RECEIPT_NOT_PROVEN")
    assert "The exact signed attempt remains fenced" in event["remediation"]
    assert "never submit a replacement" in event["remediation"]
    assert "substrate.get_block(receipt block hash)" in event["detail"]


def test_a_tick_that_never_reached_the_chain_is_not_reported_as_ambiguous(
    monkeypatch, tmp_path
):
    """A dry run and a refused gate sign nothing; say so."""
    records: list[dict] = []
    args = _run_args(tmp_path, records)
    monkeypatch.setattr(vt, "_validate_runtime_contract", lambda _args: None)
    monkeypatch.setattr(vt, "_recover_pending_launch_receipt", lambda _args: None)
    monkeypatch.setattr(vt, "_drain_shadow_audit_once", lambda _args: True)
    monkeypatch.setattr(
        vt,
        "tick",
        lambda _args: (_ for _ in ()).throw(
            vt.wire.VectorError("thin dry run refused: policy pin is not satisfied")
        ),
    )

    assert vt.run(args) == 1
    event = _emitted(records, "TICK_FAILED")
    assert event["status"] == vt.FAIL
    assert "may have finalized" not in event["remediation"]
    assert "before any chain call" in event["remediation"]


def test_a_tick_that_reached_the_chain_call_still_warns_about_the_write(
    monkeypatch, tmp_path
):
    records: list[dict] = []
    args = _run_args(tmp_path, records)
    monkeypatch.setattr(vt, "_validate_runtime_contract", lambda _args: None)
    monkeypatch.setattr(vt, "_recover_pending_launch_receipt", lambda _args: None)
    monkeypatch.setattr(vt, "_drain_shadow_audit_once", lambda _args: True)

    def _fail_after_the_call(runtime):
        vt._mark_tick_reached_chain_call(runtime)
        raise vt.wire.VectorError("post-write telemetry could not be persisted")

    monkeypatch.setattr(vt, "tick", _fail_after_the_call)

    assert vt.run(args) == 1
    event = _emitted(records, "TICK_FAILED")
    assert "a write may have finalized" in event["remediation"]
    assert "named extrinsic" in event["remediation"]


def test_a_dry_run_never_marks_the_tick_as_having_reached_the_chain(tmp_path):
    """Proven against the real submission path, not a stand-in for it."""
    args = _run_args(tmp_path, [])
    args._tick_chain_call_started = False
    submission = vt.set_weights_on_chain(
        {3: 0.6, 11: 0.4},
        network="finney",
        netuid=39,
        wallet_name="validator",
        wallet_hotkey="default",
        broadcast=False,
        runtime_contract=args,
    )
    assert submission.success is True
    assert args._tick_chain_call_started is False
    assert vt._tick_failure_remediation(args).startswith(
        "The tick failed closed before any chain call"
    )


def test_the_marker_is_reporting_only_and_tolerates_no_runtime_contract():
    vt._mark_tick_reached_chain_call(None)  # non-SN39 callers pass none
    holder = SimpleNamespace()
    vt._mark_tick_reached_chain_call(holder)
    assert holder._tick_chain_call_started is True


def test_the_status_projection_still_carries_the_new_remediation(tmp_path):
    """The publisher-visible surface is an allowlist; remediation is on it."""
    records: list[dict] = []
    logger = _events(records)
    logger.event(
        "PENDING_RECEIPT_NOT_PROVEN",
        stage="result",
        status=vt.NOT_PROVEN,
        detail="pending receipt recovery chain preflight refused",
        remediation=vt._pending_receipt_not_proven_remediation(
            vt._PendingReceiptNotProven("x", fenced_attempt=False)
        ),
    )
    projected = sanitized_status_record(records[0])
    assert "No signed attempt was recorded" in projected["remediation"]
