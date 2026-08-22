from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scaffold import render, validator_thin, wire_vector
from scaffold.events import _neutralize


@pytest.fixture(autouse=True)
def _isolated_submission_runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(
        validator_thin, "_VALIDATOR_RUNTIME_ROOT", tmp_path / "submission-runtime"
    )


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _signed_vector(policy_version: int = 42) -> tuple[dict, str]:
    now = datetime.now(UTC)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw().hex()
    payload = {
        "vector_id": "12345678-lifecycle-test",
        "policy_version": policy_version,
        "network": "finney",
        "netuid": 39,
        "generated_at": _iso(now),
        "expires_at": _iso(now + timedelta(minutes=5)),
        "burn_snapshot": {
            "burn_uid": None,
            "burn_hotkey": "burn-hotkey",
            "forced_burn_percentage": 10.0,
        },
        "policy_metadata": {
            "confidential_primary": {
                "contract_version": "v1",
                "mode": "confidential_primary",
                "source": "cathedral_confidential_tdx",
                "base_mass": 0.0,
                "confidential_mass": 0.0,
                "complete": False,
                "fresh": False,
                "confirmed": False,
            },
            "validated_supply": {
                "contract_version": "v2",
                "intel_tdx_allocation": 0.90,
                "fixed_burn_allocation": 0.10,
                "burn_hotkey": "burn-hotkey",
            },
        },
        "policy_hash": "sha256:test",
        "key_id": "cathedral-weight-policy",
        "weights": [],
    }
    payload["signature"] = base64.b64encode(
        private_key.sign(wire_vector.canonical_bytes(payload))
    ).decode()
    return payload, public_key


def test_feed_label_never_logs_credentials_query_or_fragment():
    assert (
        validator_thin._feed_label(
            "https://user:secret@api.cathedral.computer:8443/path?token=secret#fragment"
        )
        == "https://api.cathedral.computer:8443"
    )


def test_event_redaction_drops_every_url_query_and_fragment() -> None:
    rendered = _neutralize(
        "probe https://alice:p@ss@example.invalid/path"
        "?apikey=SENSITIVE&X-Amz-Signature=ALSO-SENSITIVE#fragment"
    )
    assert rendered == "probe <redacted-url>"
    assert "SENSITIVE" not in rendered
    assert "fragment" not in rendered


def test_startup_never_serializes_malformed_or_protocol_relative_endpoints(
    tmp_path, monkeypatch
) -> None:
    events = tmp_path / "events.jsonl"
    args = SimpleNamespace(
        publisher_url="https://alice:p ass@example.invalid/path?sig=SECRET",
        evidence_url="//bob:token@example.invalid/v1/evidence?key=ALSO_SECRET",
        state_file=str(tmp_path / "state.json"),
        public_key_hex="00" * 32,
        key_id="test-key",
        network="finney",
        netuid=39,
        offline=True,
        broadcast=False,
        wallet_name="validator",
        wallet_hotkey="default",
        require_policy=None,
        # 'off' was deleted in 062d2fd as a mode no config could select and the
        # SN39 trust profile already rejected. 'shadow' is the mode this fixture
        # always meant: audit alongside, submission authority unchanged.
        provenance="shadow",
        once=True,
        interval_secs=1,
        jsonl=str(events),
    )
    monkeypatch.setattr(validator_thin, "tick", lambda _args: True)

    assert validator_thin.run(args) == 0
    serialized = events.read_text()
    assert "SECRET" not in serialized
    assert "alice" not in serialized
    assert "bob" not in serialized
    startup = json.loads(serialized)
    assert startup["publisher_url"] == "<invalid-endpoint>"
    assert startup["provenance_evidence_url"] == "<invalid-endpoint>"


def test_attempted_policy_is_a_durable_rollback_high_water(tmp_path) -> None:
    state_file = tmp_path / "fence.json"
    validator_thin.save_fence(state_file, 8, "vector-8")
    validator_thin._write_state_fenced(
        state_file,
        {
            "highest_attempted_policy_version": 10,
            "thin_submission_attempt_id": "sha256:" + "a" * 64,
            "thin_submission_attempt_status": "pending",
            "thin_submission_identity": {"policy_version": 10},
        },
    )
    assert validator_thin.load_fence(state_file) == 10

    payload, public_key = _signed_vector(policy_version=9)
    with pytest.raises(wire_vector.VectorError, match="rollback/replay"):
        validator_thin.accept_vector(
            payload,
            public_key_hex=public_key,
            key_id="cathedral-weight-policy",
            network="finney",
            netuid=39,
            fence_version=validator_thin.load_fence(state_file),
        )


def test_vector_freshness_uses_canonical_utc_and_bounded_lifetime() -> None:
    now = datetime(2026, 7, 25, 2, 0, tzinfo=UTC)
    payload, _public_key = _signed_vector()
    payload["generated_at"] = _iso(now)
    payload["expires_at"] = _iso(now + timedelta(minutes=30))
    wire_vector.invariant_check(
        payload,
        network="finney",
        netuid=39,
        now_iso=_iso(now),
    )

    malformed = dict(payload, generated_at="2026-07-25T02:00:00+00:00")
    with pytest.raises(wire_vector.VectorError, match="canonical UTC"):
        wire_vector.invariant_check(
            malformed,
            network="finney",
            netuid=39,
            now_iso=_iso(now),
        )

    future = dict(payload, generated_at=_iso(now + timedelta(minutes=3)))
    future["expires_at"] = _iso(now + timedelta(minutes=33))
    with pytest.raises(wire_vector.VectorError, match="in the future"):
        wire_vector.invariant_check(
            future,
            network="finney",
            netuid=39,
            now_iso=_iso(now),
        )

    long_lived = dict(payload, expires_at=_iso(now + timedelta(hours=2)))
    with pytest.raises(wire_vector.VectorError, match="lifetime"):
        wire_vector.invariant_check(
            long_lived,
            network="finney",
            netuid=39,
            now_iso=_iso(now),
        )


def test_tick_emits_sanitized_verdict_and_mapping_lifecycle(
    tmp_path, monkeypatch, capsys
):
    payload, public_key = _signed_vector()
    monkeypatch.setattr(validator_thin, "fetch_vector", lambda _url: payload)
    monkeypatch.setattr(
        validator_thin,
        "chain_preflight",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("offline tick must not initialize a chain client")
        ),
    )
    args = SimpleNamespace(
        publisher_url="https://user:secret@api.cathedral.computer?token=secret",  # pragma: allowlist secret
        state_file=str(tmp_path / "fence.json"),
        public_key_hex=public_key,
        key_id="cathedral-weight-policy",
        network="finney",
        netuid=39,
        offline=True,
        broadcast=False,
        wallet_name="unused",
        wallet_hotkey="unused",
        require_policy=None,
    )

    # `_lifecycle` documents the flat "<EVENT>" + "key=value" call site as the
    # stable contract and hands presentation to `render.py`, which now draws an
    # operator stream instead of echoing the raw pair. Assert the contract, not
    # the drawing -- but keep rendering for real so the leak check below reads
    # what an operator's terminal actually receives.
    emitted: list[tuple[str, str]] = []
    real_lifecycle = render.lifecycle

    def _record(event: str, detail: str, timestamp: str) -> None:
        emitted.append((event, detail))
        real_lifecycle(event, detail, timestamp)

    monkeypatch.setattr(render, "lifecycle", _record)

    assert validator_thin.tick(args)

    stages = dict(emitted)
    assert stages["FEED fetch"] == "source=https://api.cathedral.computer"
    assert stages["FEED fetched"] == "id=12345678 policy_version=42"
    assert stages["SIGNATURE valid"] == "key_id=cathedral-weight-policy"
    assert stages["FRESHNESS valid"].startswith("network=finney netuid=39")
    assert stages["ROLLBACK valid"] == "policy_version=42 prior_fence=-1"
    assert (
        stages["MAP complete"]
        == "uids=1 burn_uid=0 burn_share=1.000000 vector=0:1.000000"
    )
    assert "WEIGHTS dry-run" in stages
    # Order is part of the contract: nothing is mapped before it is verified,
    # and nothing is written before it is mapped.
    names = [event for event, _detail in emitted]
    assert names.index("SIGNATURE valid") < names.index("MAP complete")
    assert names.index("ROLLBACK valid") < names.index("MAP complete")
    assert names.index("MAP complete") < names.index("WEIGHTS dry-run")

    # The point of the whole test: neither the structured detail nor the drawn
    # terminal output may carry the credential or the query token.
    assert "secret" not in "".join(f"{e} {d}" for e, d in emitted)
    assert "secret" not in capsys.readouterr().out


def test_finalized_submission_fence_precedes_fallible_telemetry(tmp_path, monkeypatch):
    payload, public_key = _signed_vector()
    submissions = {"count": 0}

    monkeypatch.setattr(validator_thin, "fetch_vector", lambda _url: payload)
    monkeypatch.setattr(
        validator_thin,
        "chain_preflight",
        lambda **_kwargs: SimpleNamespace(
            hotkey_to_uid={"burn-hotkey": 204},
            subnet_owner_hotkey="burn-hotkey",
            blocks_until_next_epoch=100,
            next_epoch_start_block=223,
            weights_rate_limit=0,
            validator_blocks_since_last_update=1,
            uid_mapping_stable_until_block=127,
            replacement_safe_hotkeys=frozenset({"burn-hotkey"}),
            block=123,
            validator_uid=30,
            validator_hotkey="validator-hotkey",
            genesis_hash=validator_thin.FINNEY_GENESIS_HASH,
            commit_reveal_enabled=False,
            min_allowed_weights=1,
            max_weight_limit=1.0,
        ),
    )
    monkeypatch.setattr(
        validator_thin,
        "_require_continuous_launch_transition",
        lambda _args: None,
    )
    monkeypatch.setattr(
        validator_thin,
        "_require_uid_mapping_stability",
        lambda *_args, **_kwargs: {"schema": "fixture_uid_safety_v1"},
    )

    def submit(uid_weights, **kwargs):
        submissions["count"] += 1
        runtime = kwargs["runtime_contract"]
        ordered = sorted(uid_weights.items())
        wire_uids, wire_weights = validator_thin._wire_weights(
            [uid for uid, _weight in ordered],
            [weight for _uid, weight in ordered],
        )
        attempt_id = validator_thin._read_state(
            validator_thin._submission_state_path(runtime)
        )["submission_pending_id"]
        validator_thin._record_pending_broadcast_intent(
            runtime,
            attempt_id=attempt_id,
            extrinsic_hash="0x" + "a" * 64,
            nonce=17,
            era_reference_block=runtime._tick_preflight.block,
            mortal_period_blocks=validator_thin.SN39_MORTAL_PERIOD_BLOCKS,
            version_key=validator_thin._weight_version_key(),
            wire_uids=wire_uids,
            wire_weights=wire_weights,
        )
        return validator_thin.ChainSubmission(
            success=True,
            extrinsic_hash="0x" + "a" * 64,
            block_hash="0x" + "d" * 64,
            block_number=124,
            finalized=True,
        )

    class _FailAfterFinalization:
        def event(self, name, **_fields):
            if name == "WEIGHTS_SUBMITTED":
                raise OSError("simulated log flush failure")

    monkeypatch.setattr(validator_thin, "set_weights_on_chain", submit)
    monkeypatch.setattr(
        validator_thin,
        "_get_events",
        lambda _args: _FailAfterFinalization(),
    )
    state_file = tmp_path / "fence.json"
    args = SimpleNamespace(
        publisher_url="https://api.cathedral.computer",
        state_file=str(state_file),
        public_key_hex=public_key,
        key_id="cathedral-weight-policy",
        network="finney",
        netuid=39,
        offline=False,
        broadcast=True,
        wallet_name="validator",
        wallet_hotkey="default",
        require_policy="validated_supply_v1",
        provenance="shadow",
        provenance_burn_hotkey="burn-hotkey",
        runtime_root=str(validator_thin._VALIDATOR_RUNTIME_ROOT),
        # This fixture is a plain relay: it owes SN39 no launch of its own, so
        # it declares the stance a third-party config declares. The reservation
        # now reads the completed-launch requirement from
        # `_continuous_transition_required` alone, so an undeclared stance falls
        # back to the policy pin and demands an authorization this fence test
        # is not about.
        require_completed_launch_for_broadcast=False,
    )

    with pytest.raises(OSError, match="log flush"):
        validator_thin.tick(args)
    assert validator_thin.load_fence(state_file) == 42
    assert submissions["count"] == 1

    # The already-applied vector cannot be submitted again even though the
    # first tick's telemetry failed after finalization.
    with pytest.raises(wire_vector.VectorError, match="rollback/replay"):
        validator_thin.tick(args)
    assert submissions["count"] == 1


def test_pending_thin_attempt_blocks_retry_when_final_state_write_fails(
    tmp_path, monkeypatch
):
    payload, public_key = _signed_vector()
    submissions = {"count": 0}
    mapping_block = {"value": 123}

    monkeypatch.setattr(validator_thin, "fetch_vector", lambda _url: payload)
    monkeypatch.setattr(
        validator_thin,
        "chain_preflight",
        lambda **_kwargs: SimpleNamespace(
            hotkey_to_uid={"burn-hotkey": 204},
            subnet_owner_hotkey="burn-hotkey",
            blocks_until_next_epoch=100,
            next_epoch_start_block=mapping_block["value"] + 100,
            weights_rate_limit=0,
            validator_blocks_since_last_update=1,
            uid_mapping_stable_until_block=mapping_block["value"] + 4,
            replacement_safe_hotkeys=frozenset({"burn-hotkey"}),
            block=mapping_block["value"],
            validator_uid=30,
            validator_hotkey="validator-hotkey",
            genesis_hash=validator_thin.FINNEY_GENESIS_HASH,
            commit_reveal_enabled=False,
            min_allowed_weights=1,
            max_weight_limit=1.0,
        ),
    )
    monkeypatch.setattr(
        validator_thin,
        "_require_continuous_launch_transition",
        lambda _args: None,
    )
    monkeypatch.setattr(
        validator_thin,
        "_require_uid_mapping_stability",
        lambda *_args, **_kwargs: {"schema": "fixture_uid_safety_v1"},
    )

    def submit(uid_weights, **kwargs):
        submissions["count"] += 1
        runtime = kwargs["runtime_contract"]
        ordered = sorted(uid_weights.items())
        wire_uids, wire_weights = validator_thin._wire_weights(
            [uid for uid, _weight in ordered],
            [weight for _uid, weight in ordered],
        )
        attempt_id = validator_thin._read_state(
            validator_thin._submission_state_path(runtime)
        )["submission_pending_id"]
        validator_thin._record_pending_broadcast_intent(
            runtime,
            attempt_id=attempt_id,
            extrinsic_hash="0x" + "a" * 64,
            nonce=17,
            era_reference_block=runtime._tick_preflight.block,
            mortal_period_blocks=validator_thin.SN39_MORTAL_PERIOD_BLOCKS,
            version_key=validator_thin._weight_version_key(),
            wire_uids=wire_uids,
            wire_weights=wire_weights,
        )
        return validator_thin.ChainSubmission(
            success=True,
            extrinsic_hash="0x" + "a" * 64,
            block_hash="0x" + "d" * 64,
            block_number=124,
            finalized=True,
        )

    monkeypatch.setattr(validator_thin, "set_weights_on_chain", submit)
    real_write_state_fenced = validator_thin._write_state_fenced

    def fail_finalization(path, updates):
        if (
            Path(path) == state_file
            and updates.get("thin_submission_attempt_status") == "finalized"
        ):
            raise OSError("simulated final state fsync failure")
        return real_write_state_fenced(path, updates)

    state_file = tmp_path / "fence.json"
    monkeypatch.setattr(validator_thin, "_write_state_fenced", fail_finalization)
    args = SimpleNamespace(
        publisher_url="https://api.cathedral.computer",
        state_file=str(state_file),
        public_key_hex=public_key,
        key_id="cathedral-weight-policy",
        network="finney",
        netuid=39,
        offline=False,
        broadcast=True,
        wallet_name="validator",
        wallet_hotkey="default",
        require_policy="validated_supply_v1",
        provenance="shadow",
        provenance_burn_hotkey="burn-hotkey",
        runtime_root=str(validator_thin._VALIDATOR_RUNTIME_ROOT),
        # This fixture is a plain relay: it owes SN39 no launch of its own, so
        # it declares the stance a third-party config declares. The reservation
        # now reads the completed-launch requirement from
        # `_continuous_transition_required` alone, so an undeclared stance falls
        # back to the policy pin and demands an authorization this fence test
        # is not about.
        require_completed_launch_for_broadcast=False,
    )

    with pytest.raises(OSError, match="state fsync"):
        validator_thin.tick(args)
    assert submissions["count"] == 1
    assert validator_thin.load_fence(state_file) == -1
    common = validator_thin._read_state(validator_thin._submission_state_path(args))
    assert common["submission_pending_id"] is None
    assert common["submission_finalized_id"] in common["submission_attempt_ids"]
    assert common["submission_pending_identity"]["policy_version"] == 42

    mapping_block["value"] = 124
    with pytest.raises(
        wire_vector.VectorError,
        match="common thin policy rollback",
    ):
        validator_thin.tick(args)
    assert submissions["count"] == 1


def _run_loop_args(*, once: bool, interval_secs: int = 60) -> SimpleNamespace:
    return SimpleNamespace(
        publisher_url="https://api.cathedral.computer",
        evidence_url="https://api.cathedral.computer/v2/receipts/latest",
        state_file="/tmp/test-validator-state.json",
        public_key_hex="00" * 32,
        key_id="test-key",
        network="finney",
        netuid=39,
        offline=False,
        broadcast=True,
        wallet_name="validator",
        wallet_hotkey="default",
        require_policy=None,
        provenance="shadow",
        once=once,
        interval_secs=interval_secs,
        max_submissions=2,
        require_full_provenance_for_broadcast=False,
    )


class _RunEventRecorder:
    def __init__(self) -> None:
        self.rows: list[tuple[str, dict[str, object]]] = []

    def event(self, name: str, **fields: object) -> None:
        self.rows.append((name, fields))


def test_recurring_loop_exits_on_post_signed_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _run_loop_args(once=False)
    events = _RunEventRecorder()
    monkeypatch.setattr(
        validator_thin, "_validate_runtime_contract", lambda _args: None
    )
    monkeypatch.setattr(
        validator_thin,
        "_recover_pending_launch_receipt",
        lambda _args: None,
    )
    monkeypatch.setattr(validator_thin, "_get_events", lambda _args: events)
    monkeypatch.setattr(
        validator_thin,
        "tick",
        lambda _args: (_ for _ in ()).throw(
            validator_thin._PostSignedSubmissionMismatch(
                "historical execution contradicted the signed intent"
            )
        ),
    )
    monkeypatch.setattr(
        validator_thin.time,
        "sleep",
        lambda _seconds: (_ for _ in ()).throw(
            AssertionError("a post-signed contradiction must terminate")
        ),
    )

    assert validator_thin.run(args) == validator_thin.STAY_STOPPED_EXIT
    names = [name for name, _fields in events.rows]
    assert names.count("PENDING_RECEIPT_CONTRADICTION") == 1
    assert "TICK_FAILED" not in names


def test_safe_pre_sign_head_drift_retries_whole_tick_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _run_loop_args(once=True)
    events = _RunEventRecorder()
    tick_calls: list[int] = []

    def tick(_args: SimpleNamespace) -> bool:
        tick_calls.append(len(tick_calls) + 1)
        if len(tick_calls) == 1:
            raise validator_thin._RetryablePreSignHeadDrift(
                "finalized head advanced before signing"
            )
        return True

    monkeypatch.setattr(
        validator_thin, "_validate_runtime_contract", lambda _args: None
    )
    monkeypatch.setattr(
        validator_thin,
        "_recover_pending_launch_receipt",
        lambda _args: None,
    )
    monkeypatch.setattr(validator_thin, "_get_events", lambda _args: events)
    monkeypatch.setattr(validator_thin, "tick", tick)

    assert validator_thin.run(args) == 0
    assert tick_calls == [1, 2]
    retry_events = [
        fields for name, fields in events.rows if name == "PRE_SIGN_HEAD_DRIFT_RETRY"
    ]
    assert retry_events == [
        {
            "stage": "submit",
            "status": validator_thin.NOT_PROVEN,
            "detail": "finalized head advanced before signing",
            "retry": 1,
            "retry_limit": validator_thin.SN39_PRE_SIGN_HEAD_DRIFT_RETRIES,
            "remediation": (
                "The unsigned reservation was safely released. Rebuilding the "
                "complete tick from a fresh finalized head now."
            ),
        }
    ]


class _LoopStopped(Exception):
    """Break the unbounded serve loop after a bounded number of sleeps."""


def _run_recurring_loop(
    monkeypatch: pytest.MonkeyPatch,
    *,
    tick,
    events: "_RunEventRecorder",
    max_sleeps: int,
    interval_secs: int = 1500,
) -> list[float]:
    """Drive validator_thin.run()'s recurring loop and record every sleep.

    The head-drift phase offset is pinned to zero here. These tests are about
    re-arm CADENCE (short delay versus a whole write interval, and the cap that
    falls back to it), and a random offset would make every expected duration
    approximate for a reason none of them are testing. The offset's own
    behaviour is covered in tests/thin/test_head_drift_phase_offset.py.
    """
    args = _run_loop_args(once=False, interval_secs=interval_secs)
    sleeps: list[float] = []
    monkeypatch.setattr(
        validator_thin, "_head_drift_phase_offset", lambda _width: 0.0
    )

    def _sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) >= max_sleeps:
            raise _LoopStopped

    monkeypatch.setattr(
        validator_thin, "_validate_runtime_contract", lambda _args: None
    )
    monkeypatch.setattr(
        validator_thin, "_recover_pending_launch_receipt", lambda _args: None
    )
    monkeypatch.setattr(validator_thin, "_get_events", lambda _args: events)
    monkeypatch.setattr(validator_thin, "tick", tick)
    monkeypatch.setattr(validator_thin.time, "sleep", _sleep)

    with pytest.raises(_LoopStopped):
        validator_thin.run(args)
    return sleeps


def _always_drifts(_args: SimpleNamespace) -> bool:
    raise validator_thin._RetryablePreSignHeadDrift(
        "finalized head advanced before signing"
    )


def test_head_drift_exhaustion_rearms_without_losing_the_write_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exhausting the drift budget reserves and signs nothing, so the tick is
    re-armed on the short delay rather than costing a whole write cycle."""
    events = _RunEventRecorder()
    sleeps = _run_recurring_loop(
        monkeypatch, tick=_always_drifts, events=events, max_sleeps=1
    )

    assert sleeps == [validator_thin.SN39_PRE_SIGN_HEAD_DRIFT_REARM_SECS]
    assert sleeps[0] < 1500
    names = [name for name, _fields in events.rows]
    assert names.count("PRE_SIGN_HEAD_DRIFT_RETRY_EXHAUSTED") == 1
    # The retry budget itself is unchanged: exactly one exhaustion per tick,
    # after exactly SN39_PRE_SIGN_HEAD_DRIFT_RETRIES retries.
    assert (
        names.count("PRE_SIGN_HEAD_DRIFT_RETRY")
        == validator_thin.SN39_PRE_SIGN_HEAD_DRIFT_RETRIES
    )


def test_head_drift_rearm_is_bounded_and_falls_back_to_the_write_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A chain that keeps losing the race must fall back to the daemon's own
    cadence instead of retrying forever at the short interval."""
    events = _RunEventRecorder()
    cap = validator_thin.SN39_PRE_SIGN_HEAD_DRIFT_REARM_MAX_CONSECUTIVE
    sleeps = _run_recurring_loop(
        monkeypatch, tick=_always_drifts, events=events, max_sleeps=cap + 1
    )

    assert sleeps == [validator_thin.SN39_PRE_SIGN_HEAD_DRIFT_REARM_SECS] * cap + [1500]


def test_head_drift_rearm_never_lengthens_a_short_write_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The re-arm is a ceiling on lost time, never a floor on cadence."""
    events = _RunEventRecorder()
    sleeps = _run_recurring_loop(
        monkeypatch,
        tick=_always_drifts,
        events=events,
        max_sleeps=1,
        interval_secs=5,
    )

    assert sleeps == [5]


def test_successful_tick_keeps_the_configured_write_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only a drift exhaustion re-arms early; a normal tick keeps the cadence."""
    events = _RunEventRecorder()
    sleeps = _run_recurring_loop(
        monkeypatch, tick=lambda _args: True, events=events, max_sleeps=2
    )

    assert sleeps == [1500, 1500]


def test_head_drift_rearm_resets_after_a_tick_that_does_not_exhaust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recovered tick clears the consecutive-re-arm budget, so a later
    unlucky tick still gets the short re-arm."""
    events = _RunEventRecorder()
    calls: list[int] = []

    def tick(_args: SimpleNamespace) -> bool:
        calls.append(1)
        # Tick 1 exhausts (9 raises), then one clean tick, then exhaust again.
        if len(calls) <= validator_thin.SN39_PRE_SIGN_HEAD_DRIFT_RETRIES + 1:
            raise validator_thin._RetryablePreSignHeadDrift("head advanced")
        if len(calls) == validator_thin.SN39_PRE_SIGN_HEAD_DRIFT_RETRIES + 2:
            return True
        raise validator_thin._RetryablePreSignHeadDrift("head advanced")

    sleeps = _run_recurring_loop(monkeypatch, tick=tick, events=events, max_sleeps=3)

    rearm = validator_thin.SN39_PRE_SIGN_HEAD_DRIFT_REARM_SECS
    assert sleeps == [rearm, 1500, rearm]


def _cooldown_preflight(
    *,
    block: int,
    weights_rate_limit: int,
    blocks_since_last_update: int | None,
) -> SimpleNamespace:
    """A minimal broadcast-grade preflight parameterized on the cooldown."""
    return SimpleNamespace(
        hotkey_to_uid={"burn-hotkey": 204},
        subnet_owner_hotkey="burn-hotkey",
        blocks_until_next_epoch=100,
        next_epoch_start_block=block + 100,
        weights_rate_limit=weights_rate_limit,
        validator_blocks_since_last_update=blocks_since_last_update,
        uid_mapping_stable_until_block=block + 4,
        replacement_safe_hotkeys=frozenset({"burn-hotkey"}),
        block=block,
        validator_uid=30,
        validator_hotkey="validator-hotkey",
        genesis_hash=validator_thin.FINNEY_GENESIS_HASH,
        commit_reveal_enabled=False,
        min_allowed_weights=1,
        max_weight_limit=1.0,
    )


def _cooldown_broadcast_args(state_file: Path, public_key: str) -> SimpleNamespace:
    return SimpleNamespace(
        publisher_url="https://api.cathedral.computer",
        state_file=str(state_file),
        public_key_hex=public_key,
        key_id="cathedral-weight-policy",
        network="finney",
        netuid=39,
        offline=False,
        broadcast=True,
        wallet_name="validator",
        wallet_hotkey="default",
        require_policy="validated_supply_v1",
        provenance="shadow",
        provenance_burn_hotkey="burn-hotkey",
        runtime_root=str(validator_thin._VALIDATOR_RUNTIME_ROOT),
        # A plain relay, as in the fence fixtures above: it owes SN39 no launch
        # of its own, so the recurring authorization is not what these tests
        # are about.
        require_completed_launch_for_broadcast=False,
    )


def _install_cooldown_tick_fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    payload: dict,
    preflight: SimpleNamespace,
) -> tuple[list[dict[int, float]], _RunEventRecorder]:
    submitted: list[dict[int, float]] = []
    events = _RunEventRecorder()
    monkeypatch.setattr(validator_thin, "_get_events", lambda _args: events)
    monkeypatch.setattr(validator_thin, "fetch_vector", lambda _url: payload)
    monkeypatch.setattr(validator_thin, "chain_preflight", lambda **_kwargs: preflight)
    monkeypatch.setattr(
        validator_thin,
        "_require_continuous_launch_transition",
        lambda _args: None,
    )
    monkeypatch.setattr(
        validator_thin,
        "_require_uid_mapping_stability",
        lambda *_args, **_kwargs: {"schema": "fixture_uid_safety_v1"},
    )

    def submit(uid_weights, **kwargs):
        submitted.append(dict(uid_weights))
        runtime = kwargs["runtime_contract"]
        ordered = sorted(uid_weights.items())
        wire_uids, wire_weights = validator_thin._wire_weights(
            [uid for uid, _weight in ordered],
            [weight for _uid, weight in ordered],
        )
        validator_thin._record_pending_broadcast_intent(
            runtime,
            attempt_id=validator_thin._read_state(
                validator_thin._submission_state_path(runtime)
            )["submission_pending_id"],
            extrinsic_hash="0x" + "a" * 64,
            nonce=17,
            era_reference_block=runtime._tick_preflight.block,
            mortal_period_blocks=validator_thin.SN39_MORTAL_PERIOD_BLOCKS,
            version_key=validator_thin._weight_version_key(),
            wire_uids=wire_uids,
            wire_weights=wire_weights,
        )
        return validator_thin.ChainSubmission(
            success=True,
            extrinsic_hash="0x" + "a" * 64,
            block_hash="0x" + "d" * 64,
            block_number=preflight.block + 1,
            finalized=True,
        )

    monkeypatch.setattr(validator_thin, "set_weights_on_chain", submit)
    return submitted, events


def test_tick_skips_the_write_while_the_chain_weight_cooldown_is_unelapsed(
    tmp_path, monkeypatch
):
    payload, public_key = _signed_vector()
    # blocks_since_last_update == weights_rate_limit is the exact boundary the
    # submission gate refuses, so the chain still owes one more block.
    preflight = _cooldown_preflight(
        block=8680424, weights_rate_limit=100, blocks_since_last_update=100
    )
    submitted, events = _install_cooldown_tick_fixture(
        monkeypatch, payload=payload, preflight=preflight
    )
    state_file = tmp_path / "fence.json"
    args = _cooldown_broadcast_args(state_file, public_key)

    with pytest.raises(validator_thin._ChainWeightCooldownActive) as raised:
        validator_thin.tick(args)

    detail = str(raised.value)
    assert "1 block(s) left" in detail
    assert "next write becomes possible at block 8680425" in detail
    # No chain call, and no durable attempt fence to recover from either.
    assert submitted == []
    common = validator_thin._read_state(validator_thin._submission_state_path(args))
    assert common.get("submission_pending_id") is None
    lane_state = validator_thin._read_state(state_file)
    assert lane_state.get("thin_submission_attempt_id") is None
    # The rollback fence is untouched, so the identical vector stays eligible
    # on the first tick the chain is willing to accept.
    assert validator_thin.load_fence(state_file) == -1
    # Verification still ran in full; only the write was skipped.
    names = [name for name, _fields in events.rows]
    assert names == ["VECTOR_ACCEPTED"]


def test_tick_submits_normally_on_the_first_block_past_the_cooldown(
    tmp_path, monkeypatch
):
    payload, public_key = _signed_vector()
    preflight = _cooldown_preflight(
        block=8680425, weights_rate_limit=100, blocks_since_last_update=101
    )
    submitted, events = _install_cooldown_tick_fixture(
        monkeypatch, payload=payload, preflight=preflight
    )
    state_file = tmp_path / "fence.json"
    args = _cooldown_broadcast_args(state_file, public_key)

    assert validator_thin.tick(args) is True
    assert submitted == [{204: 1.0}]
    assert validator_thin.load_fence(state_file) == 42
    names = [name for name, _fields in events.rows]
    assert names == ["VECTOR_ACCEPTED", "WEIGHTS_SUBMITTED"]


def test_cooldown_precheck_stands_down_when_the_cooldown_stops_clearing():
    """A cooldown that never elapses is a fault, not a schedule, and stays loud."""
    args = SimpleNamespace(broadcast=True, offline=False)
    with pytest.raises(validator_thin._ChainWeightCooldownActive):
        validator_thin._require_chain_weight_write_permitted(
            args,
            _cooldown_preflight(
                block=8680424, weights_rate_limit=100, blocks_since_last_update=0
            ),
        )
    # Still within one rate-limit window of head advance: routine.
    with pytest.raises(validator_thin._ChainWeightCooldownActive):
        validator_thin._require_chain_weight_write_permitted(
            args,
            _cooldown_preflight(
                block=8680524, weights_rate_limit=100, blocks_since_last_update=0
            ),
        )
    # A whole rate-limit window has now passed with no progress, so the
    # pre-check defers and the strict submission gate fails the tick closed.
    validator_thin._require_chain_weight_write_permitted(
        args,
        _cooldown_preflight(
            block=8680525, weights_rate_limit=100, blocks_since_last_update=0
        ),
    )


def test_cooldown_precheck_defers_when_the_cooldown_cannot_be_proven():
    """An unreadable cooldown is never a routine skip."""
    validator_thin._require_chain_weight_write_permitted(
        SimpleNamespace(broadcast=True, offline=False),
        _cooldown_preflight(
            block=8680424, weights_rate_limit=100, blocks_since_last_update=None
        ),
    )


class _FakeClock:
    """A monotonic clock the test moves by hand."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _frozen_head_preflight() -> SimpleNamespace:
    """A head that never moves, inside a cooldown that therefore never clears."""
    return _cooldown_preflight(
        block=8680424, weights_rate_limit=100, blocks_since_last_update=0
    )


def test_cooldown_precheck_stands_down_when_the_finalized_head_freezes():
    """A frozen finalized head cannot hold the skip open forever.

    The block-delta stand-down is purely a function of the head ADVANCING, so
    the one case it cannot see is an endpoint that freezes its finalized head
    while the cooldown still refuses. Wall-clock time is the only bound left.
    """
    clock = _FakeClock()
    args = SimpleNamespace(broadcast=True, offline=False)
    frozen = _frozen_head_preflight()
    bound = validator_thin._chain_weight_cooldown_standdown_seconds(frozen)

    # Routine for as long as the cooldown could honestly still be running.
    with pytest.raises(validator_thin._ChainWeightCooldownActive):
        validator_thin._require_chain_weight_write_permitted(
            args, frozen, monotonic=clock
        )
    clock.advance(bound)
    with pytest.raises(validator_thin._ChainWeightCooldownActive):
        validator_thin._require_chain_weight_write_permitted(
            args, frozen, monotonic=clock
        )

    # Past the bound with the head unmoved: a fault, handed to the strict gate.
    clock.advance(1.0)
    validator_thin._require_chain_weight_write_permitted(args, frozen, monotonic=clock)


def test_a_frozen_head_cannot_hold_the_skip_open_over_a_long_run():
    """The reproduction: 200 consecutive ticks against a head that never moves."""
    clock = _FakeClock()
    args = SimpleNamespace(broadcast=True, offline=False)
    frozen = _frozen_head_preflight()

    skips = 0
    stood_down = False
    for _tick in range(200):
        try:
            validator_thin._require_chain_weight_write_permitted(
                args, frozen, monotonic=clock
            )
        except validator_thin._ChainWeightCooldownActive:
            skips += 1
            clock.advance(60.0)
            continue
        stood_down = True
        break

    assert stood_down, "a frozen head skipped all 200 ticks and never stood down"
    assert skips < 200
    # 100 blocks of cooldown at 12s a block is ~20 minutes; two windows of that
    # is ~40, so a minute-cadence loop gives up in the low tens of ticks.
    assert skips == 41


def test_wall_clock_backstop_does_not_pre_empt_a_live_chain():
    """With the head advancing, #76's block-delta bound is still what fires.

    The backstop must only ever catch a dead chain. On a chain advancing at the
    nominal block rate the stand-down still lands at +101 blocks, exactly where
    #76 put it.
    """
    clock = _FakeClock()
    args = SimpleNamespace(broadcast=True, offline=False)
    first_block = 8680424

    stood_down_at = None
    for step in range(400):
        preflight = _cooldown_preflight(
            block=first_block + step,
            weights_rate_limit=100,
            blocks_since_last_update=0,
        )
        try:
            validator_thin._require_chain_weight_write_permitted(
                args, preflight, monotonic=clock
            )
        except validator_thin._ChainWeightCooldownActive:
            clock.advance(validator_thin.CHAIN_BLOCK_SECONDS)
            continue
        stood_down_at = step
        break

    assert stood_down_at == 101


def test_a_cleared_cooldown_starts_the_next_episode_with_a_fresh_clock():
    """Both anchors reset together, so old waiting is never charged to a new one.

    A validator that has been up for hours has spent plenty of wall-clock time
    inside earlier, perfectly routine cooldowns. If the clock anchor survived
    those, the next legitimate cooldown would stand down instantly.
    """
    clock = _FakeClock()
    args = SimpleNamespace(broadcast=True, offline=False)
    frozen = _frozen_head_preflight()

    with pytest.raises(validator_thin._ChainWeightCooldownActive):
        validator_thin._require_chain_weight_write_permitted(
            args, frozen, monotonic=clock
        )
    clock.advance(10_000.0)

    # The cooldown clears: the episode is over and both anchors drop.
    validator_thin._require_chain_weight_write_permitted(
        args,
        _cooldown_preflight(
            block=8680524, weights_rate_limit=100, blocks_since_last_update=101
        ),
        monotonic=clock,
    )
    assert args._chain_weight_cooldown_anchor_block is None
    assert args._chain_weight_cooldown_anchor_monotonic is None

    # A brand-new cooldown is routine again, not instantly a fault.
    with pytest.raises(validator_thin._ChainWeightCooldownActive):
        validator_thin._require_chain_weight_write_permitted(
            args,
            _cooldown_preflight(
                block=8680525, weights_rate_limit=100, blocks_since_last_update=0
            ),
            monotonic=clock,
        )


def test_recurring_loop_reports_a_chain_cooldown_as_a_skip_not_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _run_loop_args(once=True)
    events = _RunEventRecorder()
    detail = (
        "chain weight-update cooldown has 4 block(s) left; the next write "
        "becomes possible at block 8680428"
    )
    monkeypatch.setattr(
        validator_thin, "_validate_runtime_contract", lambda _args: None
    )
    monkeypatch.setattr(
        validator_thin,
        "_recover_pending_launch_receipt",
        lambda _args: None,
    )
    monkeypatch.setattr(validator_thin, "_get_events", lambda _args: events)
    monkeypatch.setattr(validator_thin, "_drain_shadow_audit_once", lambda _args: True)
    monkeypatch.setattr(
        validator_thin,
        "tick",
        lambda _args: (_ for _ in ()).throw(
            validator_thin._ChainWeightCooldownActive(detail)
        ),
    )

    assert validator_thin.run(args) == 0
    names = [name for name, _fields in events.rows]
    assert "TICK_FAILED" not in names
    assert [
        fields for name, fields in events.rows if name == "WEIGHT_COOLDOWN_SKIPPED"
    ] == [{"stage": "submit", "status": validator_thin.INFO, "detail": detail}]


def test_recurring_loop_still_fails_a_genuine_tick_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _run_loop_args(once=True)
    events = _RunEventRecorder()
    monkeypatch.setattr(
        validator_thin, "_validate_runtime_contract", lambda _args: None
    )
    monkeypatch.setattr(
        validator_thin,
        "_recover_pending_launch_receipt",
        lambda _args: None,
    )
    monkeypatch.setattr(validator_thin, "_get_events", lambda _args: events)
    monkeypatch.setattr(validator_thin, "_drain_shadow_audit_once", lambda _args: True)
    monkeypatch.setattr(
        validator_thin,
        "tick",
        lambda _args: (_ for _ in ()).throw(
            wire_vector.VectorError("signed vector burn destination is not the pin")
        ),
    )

    assert validator_thin.run(args) == 1
    names = [name for name, _fields in events.rows]
    assert "WEIGHT_COOLDOWN_SKIPPED" not in names
    assert [fields for name, fields in events.rows if name == "TICK_FAILED"] == [
        {
            "stage": "result",
            "status": validator_thin.FAIL,
            "detail": "signed vector burn destination is not the pin",
            # #80 split this one sentence in two on `_tick_chain_call_started`.
            # This fixture throws from `tick` before any chain call, so the
            # honest remediation is the no-write branch: telling an operator to
            # go inspect a durable attempt and a named extrinsic would describe
            # a transaction that does not exist.
            "remediation": (
                "The tick failed closed before any chain call, so nothing was "
                "signed, submitted, or finalized and there is no ambiguous "
                "write to inspect. The detail above names the cause; the next "
                "tick rebuilds every proof from a fresh finalized head."
            ),
        }
    ]


def _throwing_loop_args(
    monkeypatch: pytest.MonkeyPatch, events: object, exc: Exception
):
    """A one-shot `run` whose tick raises `exc` and nothing else."""
    args = _run_loop_args(once=True)
    monkeypatch.setattr(
        validator_thin, "_validate_runtime_contract", lambda _args: None
    )
    monkeypatch.setattr(
        validator_thin,
        "_recover_pending_launch_receipt",
        lambda _args: None,
    )
    monkeypatch.setattr(validator_thin, "_get_events", lambda _args: events)
    monkeypatch.setattr(validator_thin, "_drain_shadow_audit_once", lambda _args: True)
    monkeypatch.setattr(
        validator_thin,
        "tick",
        lambda _args: (_ for _ in ()).throw(exc),
    )
    return args


def test_recurring_loop_reports_epoch_room_as_its_own_routine_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A self-clearing epoch-boundary wait must not look like a page.

    The refusal names the block at which it clears, so an operator has nothing
    to do. Sharing `TICK_FAILED`/`FAIL` with the launch lock below is what made
    an alert on that pair worth muting.
    """
    events = _RunEventRecorder()
    detail = (
        "only 32 block(s) remain in this epoch; a submission needs 48 "
        "(16 mortal + 32 finality margin) to prove mortal inclusion and "
        "finalized verification. This clears itself at block 8680428"
    )
    args = _throwing_loop_args(
        monkeypatch, events, validator_thin._EpochRoomUnavailable(detail)
    )

    # Still a tick that wrote nothing, so the process exit is unchanged: a
    # `--once` canary must never report success for a skipped write.
    assert validator_thin.run(args) == 1
    names = [name for name, _fields in events.rows]
    assert "TICK_FAILED" not in names
    rows = [fields for name, fields in events.rows if name == "EPOCH_ROOM_SKIPPED"]
    assert len(rows) == 1
    assert rows[0]["stage"] == "submit"
    assert rows[0]["status"] == validator_thin.NOT_PROVEN
    assert rows[0]["detail"] == detail
    assert "No action" in str(rows[0]["remediation"])


def test_recurring_loop_names_the_continuous_launch_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one refusal that never clears itself gets a code of its own.

    A validator that is up, ticking, and writing nothing until a human runs one
    named command is the single most important thing this loop can report, and
    it used to be indistinguishable from the epoch-boundary wait above.
    """
    events = _RunEventRecorder()
    detail = (
        "continuous broadcast is locked until `cathedral-validator "
        "reconcile-launch` independently verifies the finalized "
        "rewarded-set-gated launch"
    )
    args = _throwing_loop_args(
        monkeypatch, events, validator_thin._ContinuousLaunchLocked(detail)
    )

    assert validator_thin.run(args) == 1
    names = [name for name, _fields in events.rows]
    assert "TICK_FAILED" not in names
    assert "EPOCH_ROOM_SKIPPED" not in names
    rows = [
        fields for name, fields in events.rows if name == "CONTINUOUS_LAUNCH_LOCKED"
    ]
    assert len(rows) == 1
    assert rows[0]["status"] == validator_thin.FAIL
    assert "reconcile-launch" in str(rows[0]["remediation"])


def test_recurring_loop_names_an_attempt_fence_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _RunEventRecorder()
    detail = (
        "thin submission attempt fence refused before chain write: "
        "OSError: read-only file system"
    )
    args = _throwing_loop_args(
        monkeypatch, events, validator_thin._SubmissionFenceRefused(detail)
    )

    assert validator_thin.run(args) == 1
    names = [name for name, _fields in events.rows]
    assert "TICK_FAILED" not in names
    rows = [
        fields for name, fields in events.rows if name == "SUBMISSION_FENCE_REFUSED"
    ]
    assert len(rows) == 1
    assert rows[0]["status"] == validator_thin.FAIL
    # The reservation is taken immediately before the chain call precisely so
    # that a refusal here cannot have left an ambiguous write.
    assert "before any chain call" in str(rows[0]["remediation"])


def test_every_new_code_is_still_a_vector_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The split is reporting-only: existing handlers must be unaffected.

    Callers all the way up the stack catch `wire.VectorError`. If any of these
    stopped being one, a refusal would escape a handler that has caught it for
    every release so far.
    """
    for cls in (
        validator_thin._EpochRoomUnavailable,
        validator_thin._ContinuousLaunchLocked,
        validator_thin._SubmissionFenceRefused,
    ):
        assert issubclass(cls, wire_vector.VectorError)
