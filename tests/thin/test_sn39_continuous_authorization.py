"""Pin what the recurring-write authorization gate REFUSES.

Every recurring SN39 mainnet weight write passes through
`scaffold/sn39_continuous_authorization.py`. The module exists to say no, so
these tests assert refusals, not line execution: signer mismatch, wrong chain,
stale release, journal contradiction, wrong lane, time outside the window,
unfinalized block, attempt allowance exceeded, and nonce-interval rollback.

Two seams make the real code reachable off the production host without
weakening what is tested:

* `expected_uid` is threaded through `read_root_controlled`, so the root
  ownership rule is exercised against the test user rather than skipped.
* `public_key_base64` is threaded through `verify_authorization`, so the
  Ed25519 verification runs for real against an ephemeral test key. The
  compiled pin is asserted separately by `signature_document`.

Nothing here imports bittensor; the module's only bittensor-bound path
(`verify_journal_public_release`) is reached with injected fakes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import scaffold
from scaffold import sn39_continuous_authorization as auth

HOTKEY = "5" + "C" * 47
OTHER_HOTKEY = "5" + "D" * 47
LAUNCH_ATTEMPT_ID = "sha256:" + "a" * 64
RELEASE_SHA256 = "sha256:" + "b" * 64
REPRODUCER_REVISION = "c" * 40
NOW = datetime(2026, 8, 13, 12, 0, 0, 0, tzinfo=UTC)
FINALIZED_BLOCK = 1_000_000


def _journal_path(hotkey: str = HOTKEY, genesis: str | None = None) -> Path:
    """The canonical journal filename for one chain and signer identity."""
    identity = {
        "genesis_hash": (genesis or auth.FINNEY_GENESIS_HASH).lower(),
        "netuid": 39,
        "validator_hotkey": hotkey,
    }
    digest = hashlib.sha256(auth.canonical_json(identity)).hexdigest()
    return Path(auth.RUNTIME_ROOT) / f"journal-{digest}.json"


def _document(**overrides) -> dict:
    document = {
        "schema": auth.SCHEMA,
        "purpose": auth.PURPOSE,
        "network": "finney",
        "genesis_hash": auth.FINNEY_GENESIS_HASH,
        "netuid": 39,
        "validator_hotkey": HOTKEY,
        "runtime_root": auth.RUNTIME_ROOT,
        "state_file": auth.STATE_FILE,
        "submission_journal": str(_journal_path()),
        "mechanism": auth.MECHANISM,
        "call_module": "SubtensorModule",
        "call_function": "set_mechanism_weights",
        "mecid": 0,
        "lanes": ["thin"],
        "launch_attempt_id": LAUNCH_ATTEMPT_ID,
        "release_sha256": RELEASE_SHA256,
        "reproducer_revision": REPRODUCER_REVISION,
        "issued_at": auth.canonical_time(NOW - timedelta(minutes=5)),
        "valid_from_time": auth.canonical_time(NOW - timedelta(minutes=5)),
        "valid_until_time": auth.canonical_time(NOW + timedelta(hours=6)),
        "valid_from_block": FINALIZED_BLOCK - 100,
        "valid_until_block": FINALIZED_BLOCK + 600,
        "valid_from_nonce": 40,
        "valid_until_nonce_exclusive": 48,
        "max_attempts": 8,
    }
    document.update(overrides)
    return document


def _expected(**overrides) -> dict:
    expected = {
        "submission_journal": str(_journal_path()),
        "genesis_hash": auth.FINNEY_GENESIS_HASH,
        "validator_hotkey": HOTKEY,
        "launch_attempt_id": LAUNCH_ATTEMPT_ID,
        "release_sha256": RELEASE_SHA256,
        "reproducer_revision": REPRODUCER_REVISION,
        "not_before_time": auth.canonical_time(NOW - timedelta(days=1)),
    }
    expected.update(overrides)
    return expected


def _validate(document=None, **kwargs):
    parameters = {
        "expected": _expected(),
        "lane": "thin",
        "finalized_block": FINALIZED_BLOCK,
        "now": NOW,
        "authorization_sha256": "sha256:" + "0" * 64,
    }
    parameters.update(kwargs)
    return auth.validate_document(document or _document(), **parameters)


def _verified(**overrides) -> auth.VerifiedAuthorization:
    return _validate(_document(**overrides))


# --------------------------------------------------------------------------
# Byte-level intake: strict, canonical, bounded, root-controlled.
# --------------------------------------------------------------------------


def test_strict_json_refuses_duplicate_keys() -> None:
    payload = b'{"a":1,"a":2}\n'
    with pytest.raises(auth.AuthorizationError, match="duplicate keys"):
        auth.strict_json(payload, label="doc", require_canonical=False)


def test_strict_json_refuses_non_canonical_bytes() -> None:
    payload = json.dumps({"b": 1, "a": 2}, indent=2).encode("utf-8")
    with pytest.raises(auth.AuthorizationError, match="byte-canonical"):
        auth.strict_json(payload, label="doc")


def test_strict_json_refuses_non_finite_numbers() -> None:
    with pytest.raises(auth.AuthorizationError, match="non-finite"):
        auth.strict_json(b'{"a":NaN}', label="doc", require_canonical=False)
    with pytest.raises(auth.AuthorizationError, match="non-finite"):
        auth.strict_json(b'{"a":1e400}', label="doc", require_canonical=False)


def test_strict_json_refuses_bad_encoding_and_non_objects() -> None:
    with pytest.raises(auth.AuthorizationError, match="strict UTF-8 JSON"):
        auth.strict_json(b"\xff\xfe", label="doc", require_canonical=False)
    with pytest.raises(auth.AuthorizationError, match="strict UTF-8 JSON"):
        auth.strict_json(b"{", label="doc", require_canonical=False)
    with pytest.raises(auth.AuthorizationError, match="must be a JSON object"):
        auth.strict_json(b"[1,2]", label="doc", require_canonical=False)


def test_canonical_time_refuses_naive_datetimes() -> None:
    with pytest.raises(auth.AuthorizationError, match="timezone-aware"):
        auth.canonical_time(datetime(2026, 8, 13, 12, 0, 0))


def test_parse_time_refuses_non_canonical_strings() -> None:
    for value in (None, 17, "2026-08-13T12:00:00Z", "not a time"):
        with pytest.raises(auth.AuthorizationError, match="canonical UTC"):
            auth.parse_time(value, field="issued_at")
    # Microsecond precision parses but is not the millisecond canonical form.
    with pytest.raises(auth.AuthorizationError, match="millisecond canonical"):
        auth.parse_time("2026-08-13T12:00:00.123456Z", field="issued_at")


def _root_controlled(directory: Path, name: str, payload: bytes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    target = directory / name
    target.write_bytes(payload)
    target.chmod(0o644)
    return target


def test_read_root_controlled_refuses_relative_paths() -> None:
    with pytest.raises(auth.AuthorizationError, match="must be absolute"):
        auth.read_root_controlled(Path("relative.json"), label="doc")


def test_read_root_controlled_refuses_missing_directory_and_file(
    tmp_path: Path,
) -> None:
    with pytest.raises(auth.AuthorizationError, match="directory is unavailable"):
        auth.read_root_controlled(
            tmp_path / "absent" / "doc.json",
            label="doc",
            expected_uid=os.getuid(),
        )
    (tmp_path / "present").mkdir()
    (tmp_path / "present").chmod(0o755)
    with pytest.raises(auth.AuthorizationError, match="doc is unavailable"):
        auth.read_root_controlled(
            tmp_path / "present" / "doc.json",
            label="doc",
            expected_uid=os.getuid(),
        )


def test_read_root_controlled_refuses_foreign_owner(tmp_path: Path) -> None:
    target = _root_controlled(tmp_path / "d", "doc.json", b"{}\n")
    with pytest.raises(auth.AuthorizationError, match="not root-controlled"):
        auth.read_root_controlled(
            target,
            label="doc",
            expected_uid=os.getuid() + 1,
        )


def test_read_root_controlled_refuses_group_writable_directory(
    tmp_path: Path,
) -> None:
    target = _root_controlled(tmp_path / "d", "doc.json", b"{}\n")
    target.parent.chmod(0o775)
    with pytest.raises(auth.AuthorizationError, match="not root-controlled"):
        auth.read_root_controlled(
            target,
            label="doc",
            expected_uid=os.getuid(),
        )


def test_read_root_controlled_refuses_writable_file(tmp_path: Path) -> None:
    target = _root_controlled(tmp_path / "d", "doc.json", b"{}\n")
    target.chmod(0o666)
    with pytest.raises(auth.AuthorizationError, match="immutable root-controlled"):
        auth.read_root_controlled(
            target,
            label="doc",
            expected_uid=os.getuid(),
        )


def test_read_root_controlled_refuses_hardlinked_file(tmp_path: Path) -> None:
    target = _root_controlled(tmp_path / "d", "doc.json", b"{}\n")
    os.link(target, target.parent / "second-name.json")
    with pytest.raises(auth.AuthorizationError, match="immutable root-controlled"):
        auth.read_root_controlled(
            target,
            label="doc",
            expected_uid=os.getuid(),
        )


def test_read_root_controlled_refuses_symlink(tmp_path: Path) -> None:
    real = _root_controlled(tmp_path / "d", "real.json", b"{}\n")
    link = real.parent / "link.json"
    link.symlink_to(real)
    with pytest.raises(auth.AuthorizationError, match="doc is unavailable"):
        auth.read_root_controlled(
            link,
            label="doc",
            expected_uid=os.getuid(),
        )


def test_read_root_controlled_refuses_oversized_artifact(tmp_path: Path) -> None:
    target = _root_controlled(
        tmp_path / "d",
        "doc.json",
        b"x" * (auth.MAX_ARTIFACT_BYTES + 1),
    )
    with pytest.raises(auth.AuthorizationError, match="immutable root-controlled"):
        auth.read_root_controlled(
            target,
            label="doc",
            expected_uid=os.getuid(),
        )


def test_read_root_controlled_refuses_a_group_readable_private_artifact(
    tmp_path: Path,
) -> None:
    """The release signing seed is read under the private-mode rule."""
    target = _root_controlled(tmp_path / "d", "seed.key", b"c2VlZA==\n")
    target.chmod(0o640)
    with pytest.raises(auth.AuthorizationError, match="immutable root-controlled"):
        auth.read_root_controlled(
            target,
            label="release signing seed",
            expected_uid=os.getuid(),
            require_private_mode=True,
            expected_mode=0o600,
        )


def test_read_root_controlled_refuses_a_mode_other_than_the_expected_one(
    tmp_path: Path,
) -> None:
    target = _root_controlled(tmp_path / "d", "seed.key", b"c2VlZA==\n")
    target.chmod(0o400)
    with pytest.raises(auth.AuthorizationError, match="immutable root-controlled"):
        auth.read_root_controlled(
            target,
            label="release signing seed",
            expected_uid=os.getuid(),
            require_private_mode=True,
            expected_mode=0o600,
        )


@pytest.mark.skipif(os.geteuid() == 0, reason="asserts the non-root refusal")
def test_read_seed_refuses_a_seed_this_user_controls(tmp_path: Path) -> None:
    """The private release key is root-only; `_read_seed` pins no other owner."""
    seed = _root_controlled(
        tmp_path / "d", "seed.key", base64.b64encode(os.urandom(32)) + b"\n"
    )
    seed.chmod(0o600)
    with pytest.raises(auth.AuthorizationError, match="not root-controlled"):
        auth._read_seed(seed)


def test_read_root_controlled_accepts_a_bounded_root_file(tmp_path: Path) -> None:
    target = _root_controlled(tmp_path / "d", "doc.json", b'{"a":1}\n')
    assert (
        auth.read_root_controlled(target, label="doc", expected_uid=os.getuid())
        == b'{"a":1}\n'
    )


# --------------------------------------------------------------------------
# Ed25519 envelope: only the pinned release key, over these exact bytes.
# --------------------------------------------------------------------------


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _public_base64(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _signature(
    authorization_bytes: bytes,
    private: Ed25519PrivateKey,
    **overrides,
) -> bytes:
    envelope = {
        "schema": auth.SIGNATURE_SCHEMA,
        "algorithm": "Ed25519",
        "key_id": auth.RELEASE_KEY_ID,
        "payload": "sn39-recurring-write-authorization.json exact bytes",
        "payload_sha256": "sha256:" + hashlib.sha256(authorization_bytes).hexdigest(),
        "signature": base64.b64encode(private.sign(authorization_bytes)).decode(
            "ascii"
        ),
    }
    envelope.update(overrides)
    for key in [key for key, value in overrides.items() if value is None]:
        envelope.pop(key)
    return auth.canonical_json(envelope) + b"\n"


def test_signature_refuses_a_tampered_payload(signing_key) -> None:
    signed = auth.canonical_json(_document()) + b"\n"
    signature = _signature(signed, signing_key)
    tampered = auth.canonical_json(_document(max_attempts=96)) + b"\n"
    with pytest.raises(auth.AuthorizationError, match="envelope differs"):
        auth._verify_signature(
            tampered,
            signature,
            public_key_base64=_public_base64(signing_key),
        )


def test_signature_refuses_a_foreign_signer(signing_key) -> None:
    signed = auth.canonical_json(_document()) + b"\n"
    signature = _signature(signed, Ed25519PrivateKey.generate())
    with pytest.raises(auth.AuthorizationError, match="signature is invalid"):
        auth._verify_signature(
            signed,
            signature,
            public_key_base64=_public_base64(signing_key),
        )


@pytest.mark.parametrize(
    "override",
    [
        {"key_id": "some-other-key"},
        {"schema": "other_schema"},
        {"algorithm": "Ed448"},
        {"payload": "something else"},
        {"payload_sha256": "sha256:" + "e" * 64},
        {"extra": "field"},
        {"key_id": None},
    ],
)
def test_signature_refuses_envelope_drift(signing_key, override) -> None:
    signed = auth.canonical_json(_document()) + b"\n"
    signature = _signature(signed, signing_key, **override)
    with pytest.raises(auth.AuthorizationError, match="envelope differs"):
        auth._verify_signature(
            signed,
            signature,
            public_key_base64=_public_base64(signing_key),
        )


def test_signature_refuses_malformed_encodings(signing_key) -> None:
    signed = auth.canonical_json(_document()) + b"\n"
    with pytest.raises(auth.AuthorizationError, match="encoding is invalid"):
        auth._verify_signature(
            signed,
            _signature(signed, signing_key, signature="not base64!"),
            public_key_base64=_public_base64(signing_key),
        )
    with pytest.raises(auth.AuthorizationError, match="encoding is invalid"):
        auth._verify_signature(
            signed,
            _signature(signed, signing_key),
            public_key_base64=base64.b64encode(b"short").decode("ascii"),
        )


def test_signature_document_refuses_any_key_but_the_compiled_pin() -> None:
    with pytest.raises(auth.AuthorizationError, match="exactly 32 bytes"):
        auth.signature_document(b"payload", seed=b"too short")
    with pytest.raises(auth.AuthorizationError, match="differs from the compiled pin"):
        auth.signature_document(b"payload", seed=os.urandom(32))


# --------------------------------------------------------------------------
# Scope: signer, chain, release, journal, lane.
# --------------------------------------------------------------------------


def test_validate_document_accepts_the_in_scope_authorization() -> None:
    verified = _validate()
    assert verified.validator_hotkey == HOTKEY
    assert verified.genesis_hash == auth.FINNEY_GENESIS_HASH
    assert verified.lanes == ("thin",)
    assert verified.max_attempts == 8
    assert verified.valid_from_nonce == 40
    assert verified.valid_until_nonce_exclusive == 48


def test_refuses_unknown_or_missing_fields() -> None:
    document = _document()
    document["surprise"] = 1
    with pytest.raises(auth.AuthorizationError, match="fields differ"):
        _validate(document)
    document = _document()
    del document["mecid"]
    with pytest.raises(auth.AuthorizationError, match="fields differ"):
        _validate(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "cathedral_sn39_something_else_v1"),
        ("purpose", "authorize anything at all"),
        ("network", "test"),
        ("netuid", 40),
        ("runtime_root", "/tmp"),
        ("state_file", "/tmp/thin-state.json"),
        ("mechanism", "other_mechanism_v1"),
        ("call_module", "Balances"),
        ("call_function", "set_weights"),
        ("mecid", 1),
    ],
)
def test_refuses_drift_in_the_fixed_call_scope(field, value) -> None:
    with pytest.raises(auth.AuthorizationError, match=f"authorization {field} differs"):
        _validate(_document(**{field: value}))


def test_refuses_a_signer_mismatch() -> None:
    """A hotkey the operator did not review must never be authorized."""
    with pytest.raises(
        auth.AuthorizationError, match="authorization validator_hotkey differs"
    ):
        _validate(_document(validator_hotkey=OTHER_HOTKEY))


def test_refuses_a_wrong_chain() -> None:
    """Only the pinned Finney genesis; any other chain is out of scope."""
    other_chain = "0x" + "1" * 64
    with pytest.raises(
        auth.AuthorizationError, match="authorization genesis_hash differs"
    ):
        _validate(_document(genesis_hash=other_chain))
    # Even when the expectation itself is moved, the compiled pin still holds.
    with pytest.raises(auth.AuthorizationError, match="identity is malformed"):
        _validate(
            _document(genesis_hash=other_chain),
            expected=_expected(genesis_hash=other_chain),
        )


def test_refuses_a_stale_release() -> None:
    """A release or reproducer other than the reviewed one is refused."""
    with pytest.raises(
        auth.AuthorizationError, match="authorization release_sha256 differs"
    ):
        _validate(_document(release_sha256="sha256:" + "f" * 64))
    with pytest.raises(
        auth.AuthorizationError, match="authorization reproducer_revision differs"
    ):
        _validate(_document(reproducer_revision="d" * 40))


def test_refuses_a_journal_contradiction() -> None:
    """The authorization must name the exact journal the operator reviewed."""
    with pytest.raises(
        auth.AuthorizationError, match="authorization submission_journal differs"
    ):
        _validate(_document(submission_journal=str(_journal_path(OTHER_HOTKEY))))
    with pytest.raises(
        auth.AuthorizationError, match="authorization launch_attempt_id differs"
    ):
        _validate(_document(launch_attempt_id="sha256:" + "9" * 64))


@pytest.mark.parametrize(
    "override",
    [
        {"submission_journal": "/tmp/journal-" + "a" * 64 + ".json"},
        {"submission_journal": auth.RUNTIME_ROOT + "/journal.json"},
        {"validator_hotkey": "0O" * 24},
        {"launch_attempt_id": "a" * 64},
        {"release_sha256": "sha256:" + "z" * 64},
        {"reproducer_revision": "c" * 39},
    ],
)
def test_refuses_a_malformed_identity(override) -> None:
    with pytest.raises(auth.AuthorizationError, match="identity is malformed"):
        _validate(_document(**override), expected=_expected(**override))


@pytest.mark.parametrize(
    "lanes,lane",
    [
        (["thin"], "authority"),
        (["authority"], "thin"),
        (["thin", "authority"], "thin"),
        (["thin", "thin"], "thin"),
        ([], "thin"),
        (["thin", "shadow"], "thin"),
        ("thin", "thin"),
    ],
)
def test_refuses_a_lane_outside_the_approval(lanes, lane) -> None:
    """An unsorted, duplicated, unknown or unlisted lane is not approved."""
    with pytest.raises(auth.AuthorizationError, match="lane is not approved"):
        _validate(_document(lanes=lanes), lane=lane)


def test_accepts_both_lanes_only_when_both_were_authorized() -> None:
    document = _document(lanes=["authority", "thin"])
    assert _validate(document, lane="thin").lanes == ("authority", "thin")
    assert _validate(document, lane="authority").lanes == ("authority", "thin")


# --------------------------------------------------------------------------
# Bounds: attempt allowance, nonce interval, block window, time window.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("max_attempts", [0, -1, auth.MAX_ATTEMPTS + 1, True, "8", 8.0])
def test_refuses_an_invalid_attempt_allowance(max_attempts) -> None:
    document = _document(max_attempts=max_attempts, valid_until_nonce_exclusive=48)
    with pytest.raises(auth.AuthorizationError, match="attempt allowance is invalid"):
        _validate(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("valid_from_nonce", -1),
        ("valid_from_nonce", True),
        ("valid_from_nonce", "40"),
        ("valid_until_nonce_exclusive", -1),
        ("valid_until_nonce_exclusive", 3.5),
    ],
)
def test_refuses_a_malformed_nonce_bound(field, value) -> None:
    with pytest.raises(auth.AuthorizationError, match=f"{field} is invalid"):
        _validate(_document(**{field: value}))


@pytest.mark.parametrize(
    "from_nonce,until_nonce",
    [
        (40, 40),  # empty interval
        (40, 39),  # inverted interval
        (40, 49),  # wider than the attempt allowance
        (40, 47),  # narrower than the attempt allowance
    ],
)
def test_refuses_a_nonce_window_that_differs_from_the_allowance(
    from_nonce, until_nonce
) -> None:
    """max_attempts is only a real ceiling if it equals the nonce interval."""
    document = _document(
        valid_from_nonce=from_nonce,
        valid_until_nonce_exclusive=until_nonce,
        max_attempts=8,
    )
    with pytest.raises(auth.AuthorizationError, match="nonce window differs"):
        _validate(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("valid_from_block", 0),
        ("valid_from_block", -1),
        ("valid_from_block", True),
        ("valid_from_block", "100"),
        ("valid_until_block", 0),
        ("valid_until_block", 1.5),
    ],
)
def test_refuses_a_malformed_block_bound(field, value) -> None:
    with pytest.raises(auth.AuthorizationError, match=f"{field} is invalid"):
        _validate(_document(**{field: value}))


@pytest.mark.parametrize(
    "from_block,until_block,finalized",
    [
        # Finalized block below the authorized window.
        (FINALIZED_BLOCK + 10, FINALIZED_BLOCK + 600, FINALIZED_BLOCK),
        # Finalized block at or past the end of the window.
        (FINALIZED_BLOCK - 600, FINALIZED_BLOCK, FINALIZED_BLOCK),
        # Too little headroom left to land the extrinsic.
        (
            FINALIZED_BLOCK - 600,
            FINALIZED_BLOCK + auth.MIN_REMAINING_BLOCKS - 1,
            FINALIZED_BLOCK,
        ),
        # Inverted window.
        (FINALIZED_BLOCK + 10, FINALIZED_BLOCK + 5, FINALIZED_BLOCK),
        # Wider than the compiled ceiling.
        (
            FINALIZED_BLOCK - 1,
            FINALIZED_BLOCK + auth.MAX_VALIDITY_BLOCKS + 1,
            FINALIZED_BLOCK,
        ),
    ],
)
def test_refuses_an_unfinalized_or_expired_block_window(
    from_block, until_block, finalized
) -> None:
    document = _document(
        valid_from_block=from_block,
        valid_until_block=until_block,
    )
    with pytest.raises(auth.AuthorizationError, match="block window is invalid"):
        _validate(document, finalized_block=finalized)


def test_refuses_a_verification_clock_without_a_timezone() -> None:
    with pytest.raises(auth.AuthorizationError, match="clock is naive"):
        _validate(now=datetime(2026, 8, 13, 12, 0, 0))


@pytest.mark.parametrize(
    "not_before",
    [None, 17, datetime(2026, 8, 12, 12, 0, 0)],
)
def test_refuses_a_missing_or_naive_continuous_enabled_time(not_before) -> None:
    match = "naive" if isinstance(not_before, datetime) else "missing"
    with pytest.raises(
        auth.AuthorizationError, match=f"continuous enabled time is {match}"
    ):
        _validate(expected=_expected(not_before_time=not_before))


def test_accepts_an_aware_datetime_for_the_continuous_enabled_time() -> None:
    verified = _validate(
        expected=_expected(not_before_time=NOW - timedelta(days=1)),
    )
    assert verified.launch_attempt_id == LAUNCH_ATTEMPT_ID


@pytest.mark.parametrize(
    "overrides,reason",
    [
        # Issued before the operator enabled recurring writes at all.
        (
            {
                "issued_at": auth.canonical_time(NOW - timedelta(days=2)),
                "valid_from_time": auth.canonical_time(NOW - timedelta(days=2)),
            },
            "issued before enablement",
        ),
        # Validity starts before the document was issued.
        (
            {"valid_from_time": auth.canonical_time(NOW - timedelta(hours=9))},
            "backdated start",
        ),
        # Inverted time window.
        (
            {"valid_until_time": auth.canonical_time(NOW - timedelta(hours=1))},
            "inverted",
        ),
        # Not yet in force.
        (
            {
                "valid_from_time": auth.canonical_time(NOW + timedelta(minutes=1)),
                "valid_until_time": auth.canonical_time(NOW + timedelta(hours=2)),
            },
            "not yet valid",
        ),
        # Already expired.
        (
            {
                "issued_at": auth.canonical_time(NOW - timedelta(hours=5)),
                "valid_from_time": auth.canonical_time(NOW - timedelta(hours=5)),
                "valid_until_time": auth.canonical_time(NOW - timedelta(minutes=1)),
            },
            "expired",
        ),
        # Too little time left to land the write.
        (
            {
                "valid_until_time": auth.canonical_time(
                    NOW + timedelta(seconds=auth.MIN_REMAINING_SECONDS - 1)
                )
            },
            "no headroom",
        ),
        # Longer-lived than the compiled ceiling.
        (
            {
                "valid_until_time": auth.canonical_time(
                    NOW
                    + timedelta(seconds=auth.MAX_VALIDITY_SECONDS)
                    + timedelta(minutes=6)
                )
            },
            "over the validity ceiling",
        ),
    ],
)
def test_refuses_a_time_window_outside_the_authorization(overrides, reason) -> None:
    with pytest.raises(auth.AuthorizationError, match="time window is invalid"):
        _validate(_document(**overrides))


@pytest.mark.parametrize("field", ["issued_at", "valid_from_time", "valid_until_time"])
def test_refuses_non_canonical_times_in_the_document(field) -> None:
    with pytest.raises(auth.AuthorizationError, match=f"{field} must be canonical"):
        _validate(_document(**{field: "2026-08-13T12:00:00Z"}))


# --------------------------------------------------------------------------
# verify_authorization: the whole gate, over real bytes on disk.
# --------------------------------------------------------------------------


@pytest.fixture
def on_disk(tmp_path: Path, signing_key):
    """Write a signed authorization pair the way the launcher would."""

    def write(document=None, *, corrupt_signature: bool = False):
        directory = tmp_path / "etc"
        payload = auth.canonical_json(document or _document()) + b"\n"
        signed_over = (
            auth.canonical_json(_document(max_attempts=96)) + b"\n"
            if corrupt_signature
            else payload
        )
        authorization_path = _root_controlled(
            directory, "sn39-recurring-write-authorization.json", payload
        )
        signature_path = _root_controlled(
            directory,
            "sn39-recurring-write-authorization.json.sig",
            _signature(signed_over, signing_key),
        )
        return authorization_path, signature_path

    return write


def _verify(paths, **kwargs):
    authorization_path, signature_path = paths
    parameters = {
        "expected": _expected(),
        "lane": "thin",
        "finalized_block": FINALIZED_BLOCK,
        "now": NOW,
        "authorization_path": authorization_path,
        "signature_path": signature_path,
        "expected_uid": os.getuid(),
    }
    parameters.update(kwargs)
    return auth.verify_authorization(**parameters)


def test_verify_authorization_accepts_a_signed_in_scope_pair(
    on_disk, signing_key
) -> None:
    verified = _verify(
        on_disk(),
        public_key_base64=_public_base64(signing_key),
    )
    assert verified.validator_hotkey == HOTKEY
    assert verified.authorization_sha256.startswith("sha256:")
    assert verified.submission_journal == str(_journal_path())


@pytest.mark.parametrize("finalized_block", [0, -1, True, None, "1000"])
def test_verify_authorization_refuses_without_a_finalized_block(
    on_disk, signing_key, finalized_block
) -> None:
    """An unfinalized head is not a block this authorization can be bound to."""
    with pytest.raises(auth.AuthorizationError, match="needs a finalized block"):
        _verify(
            on_disk(),
            finalized_block=finalized_block,
            public_key_base64=_public_base64(signing_key),
        )


def test_verify_authorization_refuses_a_signature_over_other_bytes(
    on_disk, signing_key
) -> None:
    with pytest.raises(auth.AuthorizationError, match="envelope differs"):
        _verify(
            on_disk(corrupt_signature=True),
            public_key_base64=_public_base64(signing_key),
        )


def test_verify_authorization_refuses_a_foreign_release_key(on_disk) -> None:
    with pytest.raises(auth.AuthorizationError, match="signature is invalid"):
        _verify(
            on_disk(),
            public_key_base64=_public_base64(Ed25519PrivateKey.generate()),
        )


def test_verify_authorization_refuses_a_writable_authorization(
    on_disk, signing_key
) -> None:
    paths = on_disk()
    paths[0].chmod(0o666)
    with pytest.raises(auth.AuthorizationError, match="immutable root-controlled"):
        _verify(paths, public_key_base64=_public_base64(signing_key))


def test_verify_authorization_refuses_the_compiled_key_against_a_test_signature(
    on_disk,
) -> None:
    """The default public key is the compiled pin, not whatever signed the file."""
    with pytest.raises(auth.AuthorizationError, match="signature is invalid"):
        _verify(on_disk())


def test_verify_authorization_refuses_an_out_of_scope_lane_end_to_end(
    on_disk, signing_key
) -> None:
    with pytest.raises(auth.AuthorizationError, match="lane is not approved"):
        _verify(
            on_disk(),
            lane="authority",
            public_key_base64=_public_base64(signing_key),
        )


# --------------------------------------------------------------------------
# Re-checks at the chain boundary: still ready, and nonce still in interval.
# --------------------------------------------------------------------------


def test_assert_still_ready_accepts_an_unexpired_authorization() -> None:
    auth.assert_still_ready(
        _verified(), lane="thin", finalized_block=FINALIZED_BLOCK, now=NOW
    )


def test_assert_still_ready_refuses_a_clock_without_a_timezone() -> None:
    with pytest.raises(auth.AuthorizationError, match="clock is naive"):
        auth.assert_still_ready(
            _verified(),
            lane="thin",
            finalized_block=FINALIZED_BLOCK,
            now=datetime(2026, 8, 13, 12, 0, 0),
        )


@pytest.mark.parametrize(
    "lane,finalized,now",
    [
        # Lane switched between verification and the chain boundary.
        ("authority", FINALIZED_BLOCK, NOW),
        # Chain moved past the authorized block window.
        ("thin", FINALIZED_BLOCK + 600, NOW),
        # Chain is behind the authorized start.
        ("thin", FINALIZED_BLOCK - 200, NOW),
        # Too few blocks of headroom remain.
        ("thin", FINALIZED_BLOCK + 600 - auth.MIN_REMAINING_BLOCKS + 1, NOW),
        # Time ran out between verification and submission.
        ("thin", FINALIZED_BLOCK, NOW + timedelta(hours=7)),
        # Clock moved back before the window opened.
        ("thin", FINALIZED_BLOCK, NOW - timedelta(hours=1)),
        # Inside the window but under the landing headroom.
        (
            "thin",
            FINALIZED_BLOCK,
            NOW
            + timedelta(hours=6)
            - timedelta(seconds=auth.MIN_REMAINING_SECONDS - 1),
        ),
    ],
)
def test_assert_still_ready_refuses_after_the_window_moves(
    lane, finalized, now
) -> None:
    with pytest.raises(auth.AuthorizationError, match="expired before the chain"):
        auth.assert_still_ready(
            _verified(), lane=lane, finalized_block=finalized, now=now
        )


def test_assert_nonce_ready_accepts_the_interval_it_authorized() -> None:
    verified = _verified()
    for nonce in (
        verified.valid_from_nonce,
        verified.valid_until_nonce_exclusive - 1,
    ):
        auth.assert_nonce_ready(verified, account_nonce=nonce)


@pytest.mark.parametrize("account_nonce", [0, 39, 48, 49, True, None, 40.0, "40"])
def test_assert_nonce_ready_refuses_a_nonce_outside_the_allowance(
    account_nonce,
) -> None:
    """A restored journal cannot replay writes; the account nonce cannot roll back.

    A nonce below `valid_from_nonce` is exactly the rollback signature: local
    state was restored from a snapshot taken before the authorized writes.
    """
    with pytest.raises(auth.AuthorizationError, match="outside the recurring-write"):
        auth.assert_nonce_ready(_verified(), account_nonce=account_nonce)


def test_assert_nonce_ready_caps_accepted_writes_at_max_attempts() -> None:
    verified = _verified(
        max_attempts=1, valid_from_nonce=100, valid_until_nonce_exclusive=101
    )
    auth.assert_nonce_ready(verified, account_nonce=100)
    with pytest.raises(auth.AuthorizationError, match="outside the recurring-write"):
        auth.assert_nonce_ready(verified, account_nonce=101)


# --------------------------------------------------------------------------
# Journal intake and document construction (operator side).
# --------------------------------------------------------------------------


def _state(**overrides) -> dict:
    state = {
        "submission_continuous_enabled": True,
        "submission_launch_status": "finalized",
        "submission_launch_attempt_id": LAUNCH_ATTEMPT_ID,
        "submission_continuous_launch_attempt_id": LAUNCH_ATTEMPT_ID,
        "submission_validator_hotkey": HOTKEY,
        "submission_genesis_hash": auth.FINNEY_GENESIS_HASH,
        "submission_continuous_release_sha256": RELEASE_SHA256,
        "submission_continuous_reproducer_revision": REPRODUCER_REVISION,
        "submission_continuous_enabled_at": auth.canonical_time(
            NOW - timedelta(days=1)
        ),
    }
    state.update(overrides)
    return state


def _build(state=None, **kwargs):
    parameters = {
        "journal_path": _journal_path(),
        "expected_validator_hotkey": HOTKEY,
        "reviewed_finalized_block": FINALIZED_BLOCK,
        "reviewed_validator_nonce": 40,
        "max_attempts": 8,
        "valid_for_blocks": 600,
        "valid_for_seconds": 3600,
        "allow_authority_lane": False,
        "now": NOW,
    }
    parameters.update(kwargs)
    return auth.build_from_journal(state or _state(), **parameters)


def test_build_from_journal_produces_a_document_its_own_gate_accepts() -> None:
    document = _build()
    assert document["lanes"] == ["thin"]
    verified = _validate(
        document,
        expected=_expected(
            not_before_time=_state()["submission_continuous_enabled_at"]
        ),
    )
    assert verified.max_attempts == 8
    assert verified.valid_until_nonce_exclusive - verified.valid_from_nonce == 8


def test_build_from_journal_opts_into_the_authority_lane_explicitly() -> None:
    assert _build(allow_authority_lane=True)["lanes"] == ["authority", "thin"]


@pytest.mark.parametrize(
    "journal_path",
    [
        Path("/tmp/journal-" + "a" * 64 + ".json"),
        Path(auth.RUNTIME_ROOT) / "journal.json",
        Path("journal-" + "a" * 64 + ".json"),
    ],
)
def test_build_from_journal_refuses_a_journal_outside_the_runtime_root(
    journal_path,
) -> None:
    with pytest.raises(auth.AuthorizationError, match="outside the fixed runtime root"):
        _build(journal_path=journal_path)


@pytest.mark.parametrize(
    "override",
    [
        {"submission_continuous_enabled": False},
        {"submission_continuous_enabled": "true"},
        {"submission_launch_status": "submitted"},
        {"submission_continuous_launch_attempt_id": "sha256:" + "9" * 64},
    ],
)
def test_build_from_journal_refuses_an_unreconciled_launch(override) -> None:
    with pytest.raises(auth.AuthorizationError, match="no independently reconciled"):
        _build(_state(**override))


def test_build_from_journal_refuses_a_reviewed_hotkey_the_journal_does_not_name() -> (
    None
):
    with pytest.raises(auth.AuthorizationError, match="reviewed validator hotkey"):
        _build(_state(submission_validator_hotkey=OTHER_HOTKEY))
    with pytest.raises(auth.AuthorizationError, match="reviewed validator hotkey"):
        _build(
            _state(submission_validator_hotkey="not-a-hotkey"),
            expected_validator_hotkey="not-a-hotkey",
        )


def test_build_from_journal_refuses_a_journal_name_that_is_not_its_identity() -> None:
    """The filename commits to chain and signer; a mismatch is a contradiction."""
    with pytest.raises(auth.AuthorizationError, match="journal filename differs"):
        _build(journal_path=_journal_path(OTHER_HOTKEY))
    with pytest.raises(auth.AuthorizationError, match="journal filename differs"):
        _build(
            _state(submission_genesis_hash="0x" + "1" * 64),
            journal_path=_journal_path(),
        )


@pytest.mark.parametrize(
    "override",
    [
        {"reviewed_finalized_block": 0},
        {"reviewed_finalized_block": True},
        {"reviewed_finalized_block": "1000"},
        {"max_attempts": 0},
        {"max_attempts": auth.MAX_ATTEMPTS + 1},
        {"max_attempts": True},
        {"reviewed_validator_nonce": -1},
        {"reviewed_validator_nonce": True},
        {"valid_for_blocks": auth.MIN_REMAINING_BLOCKS - 1},
        {"valid_for_blocks": auth.MAX_VALIDITY_BLOCKS + 1},
        {"valid_for_blocks": True},
        {"valid_for_seconds": auth.MIN_REMAINING_SECONDS - 1},
        {"valid_for_seconds": auth.MAX_VALIDITY_SECONDS + 1},
        {"valid_for_seconds": True},
    ],
)
def test_build_from_journal_refuses_out_of_range_bounds(override) -> None:
    with pytest.raises(auth.AuthorizationError, match="bounds are invalid"):
        _build(**override)


def test_read_journal_refuses_a_path_outside_the_runtime_root() -> None:
    for path in (
        Path("/tmp/journal-" + "a" * 64 + ".json"),
        Path(auth.RUNTIME_ROOT) / "state.json",
        Path("journal-" + "a" * 64 + ".json"),
    ):
        with pytest.raises(
            auth.AuthorizationError, match="outside the fixed runtime root"
        ):
            auth._read_journal(path)


@pytest.fixture
def runtime_root(tmp_path, monkeypatch):
    """Relocate the fixed runtime root so journal intake is reachable."""
    root = tmp_path / "runtime"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(auth, "RUNTIME_ROOT", str(root))
    return root


def _journal_name() -> str:
    return _journal_path().name


def test_read_journal_reads_an_owner_controlled_journal(runtime_root) -> None:
    target = runtime_root / _journal_name()
    target.write_bytes(json.dumps({"submission_launch_status": "finalized"}).encode())
    target.chmod(0o600)
    assert auth._read_journal(target) == {"submission_launch_status": "finalized"}


def test_read_journal_refuses_a_group_readable_journal(runtime_root) -> None:
    target = runtime_root / _journal_name()
    target.write_bytes(b"{}")
    target.chmod(0o644)
    with pytest.raises(auth.AuthorizationError, match="not safely controlled"):
        auth._read_journal(target)


def test_read_journal_refuses_a_group_readable_directory(runtime_root) -> None:
    target = runtime_root / _journal_name()
    target.write_bytes(b"{}")
    target.chmod(0o600)
    runtime_root.chmod(0o750)
    with pytest.raises(auth.AuthorizationError, match="not owner-controlled"):
        auth._read_journal(target)


def test_read_journal_refuses_a_missing_journal(runtime_root) -> None:
    with pytest.raises(auth.AuthorizationError, match="journal is unavailable"):
        auth._read_journal(runtime_root / _journal_name())


def test_read_journal_refuses_a_missing_runtime_root(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(auth, "RUNTIME_ROOT", str(tmp_path / "absent"))
    with pytest.raises(auth.AuthorizationError, match="directory is unavailable"):
        auth._read_journal(Path(auth.RUNTIME_ROOT) / _journal_name())


# --------------------------------------------------------------------------
# Launcher context, public-release binding, and the CLI refusals.
# --------------------------------------------------------------------------


def test_authorizer_context_digest_binds_release_manifest_and_arguments() -> None:
    base = auth.authorizer_context_digest(
        release_sha="a" * 40, manifest_digest="sha256:" + "b" * 64, arguments=["--x"]
    )
    assert base.startswith("sha256:")
    assert base != auth.authorizer_context_digest(
        release_sha="a" * 40,
        manifest_digest="sha256:" + "b" * 64,
        arguments=["--x", "--y"],
    )
    assert base != auth.authorizer_context_digest(
        release_sha="d" * 40, manifest_digest="sha256:" + "b" * 64, arguments=["--x"]
    )


@pytest.fixture
def manifest(tmp_path):
    return _root_controlled(
        tmp_path / "release", "sn39-release-manifest.json", b'{"files":[]}\n'
    )


def test_require_launcher_context_refuses_a_missing_release_identity(
    manifest, monkeypatch
) -> None:
    monkeypatch.delenv(auth.RELEASE_SHA_ENV, raising=False)
    monkeypatch.setenv(auth.AUTHORIZER_CONTEXT_ENV, "sha256:" + "0" * 64)
    with pytest.raises(auth.AuthorizationError, match="launcher identity is missing"):
        auth.require_launcher_context(
            ["--x"], manifest_path=manifest, expected_uid=os.getuid()
        )


def test_require_launcher_context_refuses_a_forged_context(
    manifest, monkeypatch
) -> None:
    monkeypatch.setenv(auth.RELEASE_SHA_ENV, "a" * 40)
    monkeypatch.setenv(auth.AUTHORIZER_CONTEXT_ENV, "sha256:" + "0" * 64)
    with pytest.raises(auth.AuthorizationError, match="not entered through"):
        auth.require_launcher_context(
            ["--x"], manifest_path=manifest, expected_uid=os.getuid()
        )


def test_require_launcher_context_refuses_arguments_the_launcher_did_not_sign(
    manifest, monkeypatch
) -> None:
    """The digest covers argv, so a smuggled flag breaks the launcher binding."""
    digest = auth.authorizer_context_digest(
        release_sha="a" * 40,
        manifest_digest="sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest(),
        arguments=["--x"],
    )
    monkeypatch.setenv(auth.RELEASE_SHA_ENV, "a" * 40)
    monkeypatch.setenv(auth.AUTHORIZER_CONTEXT_ENV, digest)
    with pytest.raises(auth.AuthorizationError, match="not entered through"):
        auth.require_launcher_context(
            ["--x", "--smuggled"], manifest_path=manifest, expected_uid=os.getuid()
        )


def test_require_launcher_context_accepts_the_immutable_launcher(
    manifest, monkeypatch
) -> None:
    digest = auth.authorizer_context_digest(
        release_sha="a" * 40,
        manifest_digest="sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest(),
        arguments=["--x"],
    )
    monkeypatch.setenv(auth.RELEASE_SHA_ENV, "a" * 40)
    monkeypatch.setenv(auth.AUTHORIZER_CONTEXT_ENV, digest)
    auth.require_launcher_context(
        ["--x"], manifest_path=manifest, expected_uid=os.getuid()
    )
    # The launcher secret is consumed, so a second entry cannot reuse it.
    assert auth.AUTHORIZER_CONTEXT_ENV not in os.environ
    assert auth.RELEASE_SHA_ENV not in os.environ


@pytest.fixture
def public_release(monkeypatch):
    """Inject the two bittensor-bound modules the release binding imports."""

    def install(*, seal=None, raises=None):
        reproduction = types.ModuleType("scaffold.sn39_public_reproduction")
        reproduction.verify_public_release = lambda: {"status": "PASS"}
        thin = types.ModuleType("scaffold.validator_thin")

        def match(*, public_result, state, identity):
            if raises is not None:
                raise raises
            return seal

        thin._match_signed_public_release_to_launch = match
        monkeypatch.setattr(
            scaffold, "sn39_public_reproduction", reproduction, raising=False
        )
        monkeypatch.setattr(scaffold, "validator_thin", thin, raising=False)
        monkeypatch.setitem(
            sys.modules, "scaffold.sn39_public_reproduction", reproduction
        )
        monkeypatch.setitem(sys.modules, "scaffold.validator_thin", thin)

    return install


def _release_state(**overrides) -> dict:
    return _state(
        submission_launch_identity={"attempt_id": LAUNCH_ATTEMPT_ID}, **overrides
    )


def test_verify_journal_public_release_refuses_a_journal_without_an_identity(
    public_release,
) -> None:
    public_release(seal={})
    for identity in (None, "sha256:x", []):
        with pytest.raises(auth.AuthorizationError, match="exact finalized launch"):
            auth.verify_journal_public_release(
                _state(submission_launch_identity=identity)
            )


def test_verify_journal_public_release_refuses_when_reproduction_fails(
    public_release,
) -> None:
    public_release(raises=RuntimeError("reproduction mismatch"))
    with pytest.raises(auth.AuthorizationError, match="does not reproduce"):
        auth.verify_journal_public_release(_release_state())


def test_verify_journal_public_release_preserves_an_inner_refusal(
    public_release,
) -> None:
    public_release(raises=auth.AuthorizationError("inner refusal"))
    with pytest.raises(auth.AuthorizationError, match="inner refusal"):
        auth.verify_journal_public_release(_release_state())


@pytest.mark.parametrize(
    "seal",
    [
        {
            "release_sha256": "sha256:" + "f" * 64,
            "reproducer_revision": REPRODUCER_REVISION,
        },
        {"release_sha256": RELEASE_SHA256, "reproducer_revision": "d" * 40},
        {},
    ],
)
def test_verify_journal_public_release_refuses_a_seal_naming_another_release(
    public_release, seal
) -> None:
    public_release(seal=seal)
    with pytest.raises(auth.AuthorizationError, match="differs from the signed public"):
        auth.verify_journal_public_release(_release_state())


def test_verify_journal_public_release_accepts_the_matching_seal(
    public_release,
) -> None:
    seal = {
        "release_sha256": RELEASE_SHA256,
        "reproducer_revision": REPRODUCER_REVISION,
    }
    public_release(seal=seal)
    assert auth.verify_journal_public_release(_release_state()) == seal


def test_atomic_write_refuses_an_output_directory_that_is_not_the_pinned_one(
    tmp_path,
) -> None:
    with pytest.raises(auth.AuthorizationError, match="output directory differs"):
        auth._atomic_write(tmp_path / "authorization.json", b"{}\n", replace=True)


@pytest.mark.skipif(os.geteuid() == 0, reason="asserts the non-root refusal")
def test_atomic_write_refuses_a_directory_this_user_controls(
    tmp_path, monkeypatch
) -> None:
    """Only a root-owned directory may hold the authorization pair."""
    directory = tmp_path / "etc"
    directory.mkdir()
    directory.chmod(0o755)
    monkeypatch.setattr(
        auth,
        "AUTHORIZATION_PATH",
        directory / "sn39-recurring-write-authorization.json",
    )
    with pytest.raises(
        auth.AuthorizationError, match="output directory is not root-controlled"
    ):
        auth._atomic_write(auth.AUTHORIZATION_PATH, b"{}\n", replace=True)


CLI_ARGUMENTS = [
    "--journal",
    str(_journal_path()),
    "--expected-validator-hotkey",
    HOTKEY,
    "--reviewed-finalized-block",
    str(FINALIZED_BLOCK),
    "--reviewed-validator-nonce",
    "40",
    "--max-attempts",
    "8",
    "--valid-for-blocks",
    "600",
    "--valid-for-seconds",
    "3600",
]


def test_build_parser_requires_every_reviewed_bound() -> None:
    parser = auth.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--journal", str(_journal_path())])
    args = parser.parse_args(CLI_ARGUMENTS)
    assert args.max_attempts == 8
    assert args.allow_full_authority_writes is False
    assert args.replace_existing is False
    assert args.i_authorize_recurring_mainnet_writes is False


@pytest.mark.skipif(os.geteuid() == 0, reason="asserts the non-root refusal")
def test_main_refuses_a_non_root_operator(capsys) -> None:
    assert auth.main(CLI_ARGUMENTS) == 1
    assert "must be created by root" in capsys.readouterr().err


def test_main_refuses_without_the_explicit_acknowledgement(monkeypatch, capsys) -> None:
    monkeypatch.setattr(auth.os, "geteuid", lambda: auth.ROOT_UID)
    assert auth.main(CLI_ARGUMENTS) == 2
    assert (
        "--i-authorize-recurring-mainnet-writes is required" in capsys.readouterr().err
    )


def test_main_refuses_entry_outside_the_immutable_launcher(monkeypatch, capsys) -> None:
    monkeypatch.setattr(auth.os, "geteuid", lambda: auth.ROOT_UID)
    monkeypatch.delenv(auth.RELEASE_SHA_ENV, raising=False)
    monkeypatch.delenv(auth.AUTHORIZER_CONTEXT_ENV, raising=False)
    assert auth.main(CLI_ARGUMENTS + ["--i-authorize-recurring-mainnet-writes"]) == 1
    captured = capsys.readouterr()
    assert "recurring authorization refused" in captured.err
    assert "launcher identity is missing" in captured.err
