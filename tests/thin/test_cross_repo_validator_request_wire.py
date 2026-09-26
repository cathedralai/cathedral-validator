"""A request the validator signs must be accepted by the miner's authorizer, once.

Each repo tests its own half of the ``cathedral_validator_request_v1`` wire.
This repo proves `build_validator_request_header` signs the fields it claims to
sign; cathedral-sandbox proves `ValidatorRequestAuthorizer` refuses what it
should. Until this module, nothing handed one side's output to the other, so
the two halves could drift apart (a renamed field, a different canonical
encoding, a different subnet binding) with both suites green and every
validator request refused in production.

Here the validator builds the header and the miner's authorizer, from the exact
sandbox revision the validator pins, verifies it. No chain, no network, and only
local deterministic test keys. The subnet is random per run, so no real netuid
is written down and the subnet binding is not exercised only on a default value.

The module skips where `cathedral.validator_access` is absent. The default
tests job installs the older provenance `cathedral` distribution, which predates
that module, so it skips there. The snp-production job installs the pinned
sandbox revision and runs this module explicitly, which is where it gates.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import UTC, datetime, timedelta

import pytest

_NEEDS_SANDBOX = (
    "needs the pinned cathedral-sandbox contract: pip install -e '.[snp-production]'. "
    "The snp-production CI job runs this module; the default tests job skips it."
)

pytest.importorskip("cathedral.validator_access", reason=_NEEDS_SANDBOX)

from bittensor_wallet import Keypair  # noqa: E402
from cathedral.common import ChannelBinding as MinerChannelBinding  # noqa: E402
from cathedral.common import ChannelBindingType  # noqa: E402
from cathedral.validator_access import (  # noqa: E402
    VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
    ValidatorAccessState,
    ValidatorRequestAuthorizer,
    load_sr25519_verifier,
    preflight_sr25519_verifier,
    sign_validator_access_snapshot,
    verify_validator_access_snapshot,
)
from cathedral.validator_access import VALIDATOR_REQUEST_HEADER as MINER_HEADER  # noqa: E402
from cathedral.validator_access import VALIDATOR_REQUEST_SCHEMA as MINER_SCHEMA  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from cathedral_thin.independent.collect import (  # noqa: E402
    CHANNEL_BINDING_TYPE_TLS,
    ChannelBinding,
)
from cathedral_thin.independent_runtime.https import canonical_post_body  # noqa: E402
from cathedral_thin.independent_runtime.validator_request import (  # noqa: E402
    FLEET_PATH,
    VALIDATOR_REQUEST_HEADER,
    VALIDATOR_REQUEST_SCHEMA,
    build_validator_request_header,
)

# Random, never a literal: no real subnet number is written into this test.
TEST_NETUID = secrets.randbelow(60000) + 1
NETWORK = "finney"
NOW = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
SNAPSHOT_KEY_ID = "cathedral-validator-access"
SNAPSHOT_SEED = b"s" * 32
WORKER_SPKI = hashlib.sha256(b"worker-tls-spki").digest()
EVIDENCE_PATH = "/v1/evidence"


def validator() -> Keypair:
    return Keypair.create_from_uri("//Alice")


def worker() -> Keypair:
    return Keypair.create_from_uri("//Bob")


def _utc(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def authorizer(tmp_path) -> ValidatorRequestAuthorizer:
    """The miner's authorizer, holding a verified snapshot that qualifies Alice."""

    unsigned = {
        "schema": VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
        "network": NETWORK,
        "netuid": TEST_NETUID,
        "block": 1000,
        "block_hash": "0x" + "a" * 64,
        "block_is_finalized": True,
        "generated_at": _utc(NOW - timedelta(seconds=5)),
        "expires_at": _utc(NOW + timedelta(minutes=10)),
        "minimum_stake_rao": 1,
        "signing_key_id": SNAPSHOT_KEY_ID,
        "validators": [
            {
                "hotkey": validator().ss58_address,
                "uid": 3,
                "validator_permit": True,
                "stake_rao": 5,
            }
        ],
    }
    signed = sign_validator_access_snapshot(unsigned, SNAPSHOT_SEED)
    public_key = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    snapshot = verify_validator_access_snapshot(
        json.dumps(signed).encode(),
        {SNAPSHOT_KEY_ID: public_key},
        network=NETWORK,
        netuid=TEST_NETUID,
        required_minimum_stake_rao=1,
        now=NOW,
    )
    verifier = load_sr25519_verifier()
    preflight_sr25519_verifier(verifier)
    return ValidatorRequestAuthorizer(
        snapshot,
        worker_hotkey=worker().ss58_address,
        channel_binding=MinerChannelBinding(
            ChannelBindingType.TLS_SPKI_SHA256, WORKER_SPKI
        ),
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=verifier,
    )


def signed_header(
    body: bytes, *, path: str = FLEET_PATH, netuid: int = TEST_NETUID
) -> str:
    """What the validator puts on the wire, with a fresh nonce each call."""

    return build_validator_request_header(
        keypair=validator(),
        worker_hotkey=worker().ss58_address,
        method="POST",
        path=path,
        body=body,
        channel_binding=ChannelBinding(CHANNEL_BINDING_TYPE_TLS, WORKER_SPKI),
        nonce=os.urandom(32),
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=120),
        network=NETWORK,
        netuid=netuid,
    )


def authorize(
    authorizer: ValidatorRequestAuthorizer,
    header: str,
    *,
    body: bytes,
    path: str = FLEET_PATH,
) -> str | None:
    return authorizer.authorize_caller(
        header, method="POST", path=path, body=body, now=NOW
    )


def test_both_sides_name_the_same_header_and_schema():
    # The cases below hand the header value straight to the authorizer; the
    # miner's HTTP handler finds it by this name first.
    assert VALIDATOR_REQUEST_HEADER == MINER_HEADER
    assert VALIDATOR_REQUEST_SCHEMA == MINER_SCHEMA


def test_a_validator_signed_request_is_accepted_as_that_validator(authorizer):
    body = canonical_post_body({})

    caller = authorize(authorizer, signed_header(body), body=body)

    assert caller == validator().ss58_address


def test_the_same_request_is_refused_when_replayed(authorizer):
    body = canonical_post_body({})
    header = signed_header(body)

    assert authorize(authorizer, header, body=body) == validator().ss58_address
    assert authorize(authorizer, header, body=body) is None


def test_a_body_other_than_the_signed_one_is_refused(authorizer):
    signed_body = canonical_post_body({})
    sent_body = canonical_post_body({"x": 1})

    assert authorize(authorizer, signed_header(signed_body), body=sent_body) is None
    # Control: the same body is accepted when it is the one signed.
    assert (
        authorize(authorizer, signed_header(sent_body), body=sent_body)
        == validator().ss58_address
    )


def test_a_path_other_than_the_signed_one_is_refused(authorizer):
    body = canonical_post_body({})

    assert (
        authorize(authorizer, signed_header(body), body=body, path=EVIDENCE_PATH)
        is None
    )
    # Control: the miner serves that path when it is the one signed.
    assert (
        authorize(
            authorizer,
            signed_header(body, path=EVIDENCE_PATH),
            body=body,
            path=EVIDENCE_PATH,
        )
        == validator().ss58_address
    )


def test_a_request_signed_for_another_subnet_is_refused(authorizer):
    body = canonical_post_body({})
    other_netuid = TEST_NETUID + 1

    assert (
        authorize(authorizer, signed_header(body, netuid=other_netuid), body=body)
        is None
    )
    # Control: the same request signed for the miner's subnet is accepted.
    caller = authorize(authorizer, signed_header(body), body=body)
    assert caller == validator().ss58_address
