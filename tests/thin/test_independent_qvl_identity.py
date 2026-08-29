from __future__ import annotations

import pytest

from cathedral_thin.independent.compute import QuoteVerdict
from cathedral_thin.independent_runtime.qvl import SubprocessQuoteVerifier


def verifier_script(tmp_path, claims: dict):
    path = tmp_path / "qvl-fixture"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        f"print(json.dumps({claims!r}, sort_keys=True))\n",
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def test_pinned_qvl_json_shape_extracts_verified_stable_platform_id(tmp_path):
    stable = "tdx-platform-sha256:" + "a" * 64
    verifier = SubprocessQuoteVerifier(
        verifier_script(
            tmp_path,
            {
                "intel_verified": True,
                "report_data_match": True,
                "stable_platform_id": stable,
                "platform_id": stable,
                "platform_identity_kind": "stable",
                "platform_identity_verified": True,
                "claims_bound_to_quote": True,
            },
        )
    )
    result = verifier.verify_with_identity(b"quote", expected_report_data=b"r" * 64)
    assert result.verdict is QuoteVerdict.PASS
    assert result.stable_platform_id == stable
    assert result.platform_identity_verified is True
    assert (
        verifier.verify(b"quote", expected_report_data=b"r" * 64) is QuoteVerdict.PASS
    )


def test_legacy_qvl_pass_without_platform_identity_cannot_enable_fleet(tmp_path):
    verifier = SubprocessQuoteVerifier(
        verifier_script(
            tmp_path,
            {"intel_verified": True, "report_data_match": True},
        )
    )
    result = verifier.verify_with_identity(b"quote", expected_report_data=b"r" * 64)
    assert result.verdict is QuoteVerdict.PASS
    assert result.stable_platform_id is None
    assert result.platform_identity_verified is False


def test_qvl_platform_identity_fields_must_agree_exactly(tmp_path):
    stable = "tdx-platform-sha256:" + "a" * 64
    verifier = SubprocessQuoteVerifier(
        verifier_script(
            tmp_path,
            {
                "intel_verified": True,
                "report_data_match": True,
                "stable_platform_id": stable,
                "platform_id": "tdx-platform-sha256:" + "b" * 64,
                "platform_identity_kind": "stable",
                "platform_identity_verified": True,
                "claims_bound_to_quote": True,
            },
        )
    )
    result = verifier.verify_with_identity(b"quote", expected_report_data=b"r" * 64)
    assert result.verdict is QuoteVerdict.PASS
    assert result.stable_platform_id is None
    assert result.platform_identity_verified is False


@pytest.mark.parametrize(
    "changes",
    [
        {"platform_identity_kind": "ephemeral"},
        {"platform_identity_verified": False},
        {"claims_bound_to_quote": False},
        {"claims_bound_to_quote": "true"},
    ],
)
def test_qvl_identity_requires_stable_quote_bound_verified_claims(tmp_path, changes):
    stable = "tdx-platform-sha256:" + "c" * 64
    document = {
        "intel_verified": True,
        "report_data_match": True,
        "stable_platform_id": stable,
        "platform_id": stable,
        "platform_identity_kind": "stable",
        "platform_identity_verified": True,
        "claims_bound_to_quote": True,
    }
    document.update(changes)
    verifier = SubprocessQuoteVerifier(verifier_script(tmp_path, document))
    result = verifier.verify_with_identity(b"quote", expected_report_data=b"r" * 64)
    assert result.verdict is QuoteVerdict.PASS
    assert result.stable_platform_id is None
    assert result.platform_identity_verified is False
