"""The policy document contract: one atomic set, 2-of-3, one on-chain digest.

The properties under test are the ones that decide whether a composer is paying
from numbers somebody actually signed:

* an amount cannot arrive as a bool or a float;
* a duplicate JSON key cannot show the signer one number and the reader another;
* one signature is not enough, and a duplicate or unknown key id does not make
  a second;
* the commitment is exactly 50 bytes and names the epoch it was committed at.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from _independent_fixtures import (
    COMPUTE_LANE,
    EPOCH_OPEN,
    bundle_document,
    commitment_for,
    economics_document,
    economics_keys,
    lane_row,
    sign_document,
    signed_bundle,
    signed_bundle_bytes,
)
from cathedral_thin.independent.canonical import (
    canonical_bytes,
    parse_strict_json,
)
from cathedral_thin.independent.constants import (
    BURN_HOTKEY,
    COMMITMENT_LENGTH,
    COMMITMENT_MAGIC,
    GENESIS_PREVIOUS_DIGEST,
    H,
    MAX_POLICY_BUNDLE_BYTES,
    NETUID,
)
from cathedral_thin.independent.errors import CommitmentError, PolicyBundleError
from cathedral_thin.independent.policy import (
    bundle_digest,
    decode_commitment,
    encode_commitment,
    is_genesis,
    load_policy_bundle,
    parse_economics_set,
    parse_policy_bundle,
    require_commitment,
    signing_payload,
    successor_lineage_fields,
    verify_signatures,
)


# --------------------------------------------------------------------------- #
# canonical bytes and strict parsing
# --------------------------------------------------------------------------- #


def test_canonical_bytes_is_sorted_ascii_and_tight():
    assert canonical_bytes({"b": 1, "a": [2, {"d": None, "c": True}]}) == (
        b'{"a":[2,{"c":true,"d":null}],"b":1}'
    )


def test_canonical_bytes_refuses_a_float_anywhere():
    with pytest.raises(PolicyBundleError, match="carries a float"):
        canonical_bytes({"economics": {"burn": {"amount": 1e12}}})


def test_strict_json_refuses_duplicate_keys():
    raw = b'{"schema":"x","schema":"y"}'
    with pytest.raises(PolicyBundleError, match="duplicate key 'schema'"):
        parse_strict_json(raw)


def test_strict_json_refuses_duplicate_amount_keys_inside_the_burn_object():
    """The attack this exists for: the signer sums one number, the reader another."""
    raw = json.dumps(bundle_document(), separators=(",", ":")).encode("utf-8")
    tampered = raw.replace(
        b'"amount":1000000000000', b'"amount":1000000000000,"amount":0'
    )
    assert tampered != raw
    with pytest.raises(PolicyBundleError, match="duplicate key 'amount'"):
        parse_strict_json(tampered)


def test_strict_json_refuses_non_finite_constants():
    with pytest.raises(PolicyBundleError, match="non-finite"):
        parse_strict_json(b'{"amount": NaN}')


def test_strict_json_refuses_an_oversize_body():
    with pytest.raises(PolicyBundleError, match="over the"):
        parse_strict_json(b'{"a":1}', max_bytes=3)


def test_the_policy_body_bound_is_one_mebibyte():
    assert MAX_POLICY_BUNDLE_BYTES == 1_048_576


# --------------------------------------------------------------------------- #
# EconomicsSet
# --------------------------------------------------------------------------- #


def test_the_genesis_economics_set_parses():
    economics = parse_economics_set(economics_document())
    assert economics.version == 1
    assert economics.previous_digest == GENESIS_PREVIOUS_DIGEST
    assert economics.previous_digest == hashlib.sha256(b"").hexdigest()
    assert economics.netuid == NETUID
    assert economics.burn.amount == H
    assert economics.explicit_burn_only is True
    assert economics.burn_only is True
    assert is_genesis(economics)


def test_a_bool_burn_amount_is_refused():
    """``bool`` subclasses ``int``: ``True`` must never become one unit of mass."""
    document = economics_document()
    document["burn"]["amount"] = True
    with pytest.raises(PolicyBundleError, match="burn.amount must be an integer"):
        parse_economics_set(document)


def test_a_bool_allocation_amount_is_refused():
    document = economics_document(
        burn_amount=H, allocations=[lane_row(COMPUTE_LANE, True)]
    )
    with pytest.raises(PolicyBundleError, match=r"allocations\[0\].amount"):
        parse_economics_set(document)


def test_a_bool_version_is_refused():
    document = economics_document()
    document["version"] = True
    with pytest.raises(PolicyBundleError, match="economics.version must be an integer"):
        parse_economics_set(document)


def test_a_float_amount_is_refused():
    document = economics_document()
    document["burn"]["amount"] = 1.0
    with pytest.raises(PolicyBundleError, match="burn.amount must be an integer"):
        parse_economics_set(document)


def test_a_decimal_string_amount_is_refused():
    document = economics_document()
    document["burn"]["amount"] = "1000000000000"
    with pytest.raises(PolicyBundleError, match="burn.amount must be an integer"):
        parse_economics_set(document)


def test_amounts_must_partition_h():
    document = economics_document(
        burn_amount=H, allocations=[lane_row(COMPUTE_LANE, 1)]
    )
    with pytest.raises(PolicyBundleError, match="not H="):
        parse_economics_set(document)


def test_disabled_rows_do_not_fold_into_the_partition():
    """A disabled row is not part of the signed sum, and is not re-homed either."""
    economics = parse_economics_set(
        economics_document(
            burn_amount=H,
            allocations=[lane_row(COMPUTE_LANE, 400_000_000_000, enabled=False)],
        )
    )
    assert economics.burn.amount == H
    assert economics.allocations[0].enabled is False
    assert economics.allocations[0].funded is False


def test_burn_equal_to_h_requires_the_explicit_flag():
    document = economics_document(burn_amount=H)
    document["explicit_burn_only"] = False
    with pytest.raises(PolicyBundleError, match="requires explicit_burn_only"):
        parse_economics_set(document)


def test_a_partial_burn_must_not_claim_explicit_burn_only():
    document = economics_document(
        burn_amount=H - 10**11, allocations=[lane_row(COMPUTE_LANE, 10**11)]
    )
    document["explicit_burn_only"] = True
    with pytest.raises(PolicyBundleError, match="but burn.amount is not H"):
        parse_economics_set(document)


def test_a_foreign_burn_hotkey_is_refused():
    document = economics_document()
    document["burn"]["burn_hotkey"] = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
    with pytest.raises(PolicyBundleError, match="not the pinned burn hotkey"):
        parse_economics_set(document)


def test_a_foreign_netuid_is_refused():
    with pytest.raises(PolicyBundleError, match="economics.netuid must be 39"):
        parse_economics_set(economics_document(netuid=1))


def test_an_unknown_economics_key_halts():
    document = economics_document()
    document["burn_uid"] = 204
    with pytest.raises(PolicyBundleError, match="unknown keys: burn_uid"):
        parse_economics_set(document)


def test_a_lane_named_twice_is_refused():
    with pytest.raises(PolicyBundleError, match="twice"):
        parse_economics_set(
            economics_document(
                burn_amount=H,
                allocations=[lane_row(COMPUTE_LANE, 0), lane_row(COMPUTE_LANE, 0)],
            )
        )


def test_the_lane_contract_id_is_schema_and_platform_only():
    economics = parse_economics_set(economics_document())
    lane = economics.allocations[0].lane_contract_id
    assert lane.as_dict() == COMPUTE_LANE
    with pytest.raises(PolicyBundleError, match="unknown keys: lane"):
        parse_economics_set(
            economics_document(
                burn_amount=H,
                allocations=[
                    {
                        "lane_contract_id": {**COMPUTE_LANE, "lane": "compute"},
                        "amount": 0,
                        "enabled": True,
                    }
                ],
            )
        )


# --------------------------------------------------------------------------- #
# 2-of-3 Ed25519
# --------------------------------------------------------------------------- #


def test_two_of_three_signatures_verify():
    bundle, registry = signed_bundle()
    assert verify_signatures(bundle, registry) == frozenset(
        {"economics-a", "economics-b"}
    )


def test_the_signature_covers_the_registries_too():
    """The digest is over the whole bundle, so a registry cannot be swapped."""
    private, registry = economics_keys()
    document = sign_document(bundle_document(), private, ("economics-a", "economics-b"))
    tampered = dict(document)
    tampered["measurement_registry"] = {"tdx": "0" * 96}
    bundle = parse_policy_bundle(tampered)
    with pytest.raises(PolicyBundleError, match="does not verify"):
        verify_signatures(bundle, registry)


def test_one_signature_is_not_enough():
    bundle, registry = signed_bundle(key_ids=("economics-a",))
    with pytest.raises(PolicyBundleError, match="has 1 distinct pinned signatures"):
        verify_signatures(bundle, registry)


def test_a_duplicate_key_id_does_not_count_twice():
    bundle, registry = signed_bundle(key_ids=("economics-a", "economics-a"))
    with pytest.raises(PolicyBundleError, match="has 1 distinct pinned signatures"):
        verify_signatures(bundle, registry)


def test_an_unknown_key_id_does_not_count():
    private, registry = economics_keys()
    document = sign_document(bundle_document(), private, ("economics-a",))
    document["signatures"].append(
        {"key_id": "economics-d", "sig": document["signatures"][0]["sig"]}
    )
    bundle = parse_policy_bundle(document)
    with pytest.raises(PolicyBundleError, match="has 1 distinct pinned signatures"):
        verify_signatures(bundle, registry)


def test_an_invalid_signature_from_a_pinned_key_halts():
    """Tampering is not merely "under-signed"; it does not fall back to last-good."""
    private, registry = economics_keys()
    document = sign_document(bundle_document(), private, ("economics-a", "economics-b"))
    document["signatures"][1]["sig"] = "00" * 64
    bundle = parse_policy_bundle(document)
    with pytest.raises(PolicyBundleError, match="economics-b does not verify"):
        verify_signatures(bundle, registry)


def test_signatures_are_verified_over_the_document_without_the_signatures_key():
    bundle, _registry = signed_bundle()
    payload = signing_payload(bundle.document)
    assert b"signatures" not in payload
    assert payload == canonical_bytes(
        {key: value for key, value in bundle.document.items() if key != "signatures"}
    )


def test_an_unsigned_bundle_is_refused_at_parse():
    with pytest.raises(PolicyBundleError, match="signatures is empty"):
        parse_policy_bundle(bundle_document())


def test_load_policy_bundle_parses_and_verifies_bytes():
    raw, registry = signed_bundle_bytes()
    bundle, signers = load_policy_bundle(raw, registry)
    assert signers == frozenset({"economics-a", "economics-b"})
    assert bundle.economics.burn.burn_hotkey == BURN_HOTKEY


def test_a_successor_bundle_chains_to_its_predecessor():
    bundle, _registry = signed_bundle()
    fields = successor_lineage_fields(bundle.document)
    assert fields == {
        "version": 2,
        "previous_digest": bundle_digest(bundle.document).hex(),
    }


# --------------------------------------------------------------------------- #
# On-chain commitment
# --------------------------------------------------------------------------- #


def test_the_commitment_is_fifty_bytes_of_magic_netuid_epoch_and_digest():
    bundle, _registry = signed_bundle()
    raw = commitment_for(bundle)
    assert len(raw) == 50 == COMMITMENT_LENGTH
    assert raw[:8] == COMMITMENT_MAGIC == b"CATHPOL1"
    assert raw[8:10] == (39).to_bytes(2, "big")
    assert raw[10:18] == EPOCH_OPEN.to_bytes(8, "big")
    assert raw[18:] == bundle.digest() == bundle_digest(bundle.document)
    assert decode_commitment(raw) == (39, EPOCH_OPEN, bundle.digest())


def test_the_commitment_digest_is_sha256_of_the_canonical_bundle():
    bundle, _registry = signed_bundle()
    assert bundle.digest() == hashlib.sha256(signing_payload(bundle.document)).digest()


def test_a_truncated_commitment_is_refused():
    bundle, _registry = signed_bundle()
    with pytest.raises(CommitmentError, match="expected 50"):
        decode_commitment(commitment_for(bundle)[:-1])


def test_a_commitment_without_the_magic_is_refused():
    bundle, _registry = signed_bundle()
    raw = b"NOTPOL1_" + commitment_for(bundle)[8:]
    with pytest.raises(CommitmentError, match="policy magic"):
        decode_commitment(raw)


def test_require_commitment_refuses_a_digest_for_another_document():
    bundle, _registry = signed_bundle()
    other, _ = signed_bundle(
        economics=economics_document(version=2, previous_digest="ab" * 32)
    )
    raw = commitment_for(other)
    with pytest.raises(CommitmentError, match="does not match the fetched"):
        require_commitment(raw, netuid=39, epoch=EPOCH_OPEN, document=bundle.document)


def test_require_commitment_refuses_another_epoch():
    bundle, _registry = signed_bundle()
    raw = commitment_for(bundle, epoch=EPOCH_OPEN - 360)
    with pytest.raises(CommitmentError, match="names epoch"):
        require_commitment(raw, netuid=39, epoch=EPOCH_OPEN, document=bundle.document)


def test_encode_commitment_refuses_a_bool_epoch():
    bundle, _registry = signed_bundle()
    with pytest.raises(CommitmentError, match="epoch must be an integer"):
        encode_commitment(39, True, bundle.digest())
