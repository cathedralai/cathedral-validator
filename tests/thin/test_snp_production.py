"""Focused no-network tests for direct-validator AMD SEV-SNP admission."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from cathedral_thin.independent.collect import ChannelBinding, CollectedEvidence
from cathedral_thin.independent.compute import QuoteVerdict
from cathedral_thin.independent_runtime import fleet_score
from cathedral_thin.independent_runtime import direct_validator
from cathedral_thin.independent_runtime.snp_production import (
    AMD_GUEST_POLICY_DEBUG,
    POLICY_SCHEMA,
    SnpProductionError,
    SnpGenerationPolicy,
    SnpPolicy,
    SnpProductionVerifier,
    SnpVerificationResult,
    _machine_id,
    _tcb_meets_minimum,
    load_snp_policy,
)


def _policy() -> dict[str, object]:
    return {
        "schema": POLICY_SCHEMA,
        "generations": {
            "genoa": {
                "allowed_measurements": ["a" * 96],
                "minimum_tcb": "0x0000000000000001",
            }
        },
    }


def test_snp_policy_requires_a_narrow_generation_measurement_and_tcb(tmp_path):
    path = tmp_path / "snp-policy.json"
    path.write_text(json.dumps(_policy()))
    path.chmod(0o600)
    policy = load_snp_policy(path)
    assert policy.generations["genoa"].allowed_measurements == {"a" * 96}
    assert policy.digest.startswith("sha256:")

    path.write_text(json.dumps({"schema": POLICY_SCHEMA, "generations": {}}))
    with pytest.raises(SnpProductionError, match="no admitted"):
        load_snp_policy(path)


def test_production_cli_requires_both_snp_policy_and_verifier() -> None:
    parser = direct_validator._parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--qvl", "/reviewed/qvl"])
    options = parser.parse_args(
        [
            "--qvl",
            "/reviewed/qvl",
            "--snp-policy",
            "/reviewed/snp-policy.json",
            "--snpguest",
            "/reviewed/snpguest",
        ]
    )
    assert options.snp_policy == "/reviewed/snp-policy.json"
    assert options.snpguest == "/reviewed/snpguest"


def test_snp_machine_identity_is_domain_separated_and_stable():
    chip = bytes(range(64))
    assert _machine_id("genoa", chip) == _machine_id("genoa", chip)
    assert _machine_id("genoa", chip) != _machine_id("milan", chip)
    assert _machine_id("genoa", chip) != _machine_id("genoa", bytes(reversed(chip)))


def test_snp_policy_uses_the_abi_debug_bit_and_allows_componentwise_tcb_checks():
    assert AMD_GUEST_POLICY_DEBUG == 1 << 19
    minimum = int.from_bytes(bytes([2, 0, 0, 0, 0, 0, 5, 10]), "little")
    newer = int.from_bytes(bytes([3, 0, 0, 0, 0, 0, 6, 11]), "little")
    older_snp = int.from_bytes(bytes([3, 0, 0, 0, 0, 0, 4, 11]), "little")
    assert _tcb_meets_minimum(newer, minimum, "genoa") is True
    assert _tcb_meets_minimum(older_snp, minimum, "genoa") is False
    assert _tcb_meets_minimum(None, minimum, "genoa") is False


class _SnpPass:
    digest = "sha256:" + "b" * 64
    policy_digest = "sha256:" + "c" * 64

    def verify(self, collected, *, deadline_monotonic=None):
        del collected, deadline_monotonic
        return SnpVerificationResult(
            QuoteVerdict.PASS,
            "a" * 64,
            self.digest,
            self.policy_digest,
        )


class _SnpInfra(_SnpPass):
    def verify(self, collected, *, deadline_monotonic=None):
        del collected, deadline_monotonic
        return SnpVerificationResult(
            QuoteVerdict.INFRA,
            None,
            self.digest,
            self.policy_digest,
            "snp_verifier_infrastructure_unavailable",
        )


class _NeverQvl:
    qvl_digest = "d" * 64

    def verify_quote_with_identity(self, *_args, **_kwargs):
        raise AssertionError("SNP evidence must never fall back to QVL")


def _snp_collected() -> CollectedEvidence:
    binding = ChannelBinding("tls_spki_sha256", b"z" * 32)
    return CollectedEvidence(
        kind="sev_snp",
        quote=b"snp-report",
        nonce=b"n" * 32,
        assigned_hotkey="miner-hotkey",
        cert_chain=(),
        channel_binding=binding,
        report_data=b"r" * 64,
    )


def test_direct_scorer_dispatches_snp_without_qvl_fallback(monkeypatch):
    collected = _snp_collected()
    monkeypatch.setattr(
        fleet_score,
        "_try_collect",
        lambda **_kwargs: {
            "ok": True,
            "sat_url": "https://1.1.1.1:8081/v1/sat-work",
            "collected": collected,
            "phase_timings_ms": fleet_score._empty_phase_timings(),
        },
    )
    row, observation, returned, passed = fleet_score._collect_candidate(
        candidate=fleet_score.FleetCandidate(
            19, "miner-hotkey", "https://1.1.1.1:8081"
        ),
        keypair=object(),
        validator_ss58="validator-hotkey",
        anchor_hash="0x" + "1" * 64,
        verifier_adapter=_NeverQvl(),
        snp_verifier=_SnpPass(),
    )
    assert passed is True
    assert returned is collected
    assert observation.hardware_verified is True
    assert row["tee_kind"] == "sev_snp"
    assert row["machine_id"] == "a" * 64
    assert row["policy_digest"] == "sha256:" + "c" * 64
    assert row["phase_timings_ms"]["qvl"] is None
    assert row["phase_timings_ms"]["snp"] is not None


def test_snp_verifier_infrastructure_is_distinct_from_a_failed_quote(monkeypatch):
    collected = _snp_collected()
    monkeypatch.setattr(
        fleet_score,
        "_try_collect",
        lambda **_kwargs: {
            "ok": True,
            "sat_url": "https://1.1.1.1:8081/v1/sat-work",
            "collected": collected,
            "phase_timings_ms": fleet_score._empty_phase_timings(),
        },
    )
    row, observation, _returned, passed = fleet_score._collect_candidate(
        candidate=fleet_score.FleetCandidate(
            19, "miner-hotkey", "https://1.1.1.1:8081"
        ),
        keypair=object(),
        validator_ss58="validator-hotkey",
        anchor_hash="0x" + "1" * 64,
        verifier_adapter=_NeverQvl(),
        snp_verifier=_SnpInfra(),
    )
    assert passed is False
    assert observation.hardware_verified is False
    assert row["verdict"] == "INFRA"
    assert row["identity_error"] == "snp_verifier_infrastructure_unavailable"


def test_unconfigured_snp_verifier_is_infrastructure_not_a_zero_score(monkeypatch):
    collected = _snp_collected()
    monkeypatch.setattr(
        fleet_score,
        "_try_collect",
        lambda **_kwargs: {
            "ok": True,
            "sat_url": "https://1.1.1.1:8081/v1/sat-work",
            "collected": collected,
            "phase_timings_ms": fleet_score._empty_phase_timings(),
        },
    )
    row, observation, _returned, passed = fleet_score._collect_candidate(
        candidate=fleet_score.FleetCandidate(
            19, "miner-hotkey", "https://1.1.1.1:8081"
        ),
        keypair=object(),
        validator_ss58="validator-hotkey",
        anchor_hash="0x" + "1" * 64,
        verifier_adapter=_NeverQvl(),
        snp_verifier=None,
    )
    assert passed is False
    assert observation.hardware_verified is False
    assert row["verdict"] == "INFRA"


def test_late_snp_response_is_a_miner_deadline_miss_not_infrastructure(monkeypatch):
    collected = _snp_collected()
    verifier = _SnpPass()
    called = False
    original_verify = verifier.verify

    def verify(*_args, **_kwargs):
        nonlocal called
        called = True
        return original_verify(*_args, **_kwargs)

    verifier.verify = verify
    monkeypatch.setattr(
        fleet_score,
        "_try_collect",
        lambda **_kwargs: {
            "ok": True,
            "sat_url": "https://1.1.1.1:8081/v1/sat-work",
            "collected": collected,
            "phase_timings_ms": fleet_score._empty_phase_timings(),
        },
    )
    now = time.monotonic()
    row, observation, _returned, passed = fleet_score._collect_candidate(
        candidate=fleet_score.FleetCandidate(
            19, "miner-hotkey", "https://1.1.1.1:8081"
        ),
        keypair=object(),
        validator_ss58="validator-hotkey",
        anchor_hash="0x" + "1" * 64,
        verifier_adapter=_NeverQvl(),
        snp_verifier=verifier,
        deadline_monotonic=now + fleet_score.SNP_VERIFIER_RESERVED_SECONDS,
    )

    assert called is False
    assert passed is False
    assert observation.hardware_verified is False
    assert row["verdict"] == "FAIL"
    assert row["identity_error"] == (
        "snp_response_left_insufficient_verification_budget"
    )


def test_production_verifier_builds_the_real_compute_evidence_shape():
    evidence_kind = object()
    binding_kind = object()
    tier = object()

    @dataclass(frozen=True)
    class ContractBinding:
        binding_type: object
        digest: bytes

    @dataclass(frozen=True)
    class ContractEvidence:
        kind: object
        quote: bytes
        nonce: bytes
        miner_hotkey: str
        cert_chain: list[bytes]
        report_data_version: int
        channel_binding: ContractBinding

    minimum = 1
    parsed = SimpleNamespace(
        guest_policy=1 << 20,
        vmpl=0,
        chip_id="11" * 64,
        tcb=SimpleNamespace(
            current=minimum,
            reported=minimum,
            committed=minimum,
            launch=minimum,
        ),
    )
    seen: dict[str, object] = {}

    def evidence_report_data(evidence, nonce):
        assert isinstance(evidence, ContractEvidence)
        assert isinstance(evidence.channel_binding, ContractBinding)
        assert evidence.miner_hotkey == "miner-hotkey"
        assert evidence.cert_chain == [b"amd-chain"]
        assert nonce == b"n" * 32
        seen["evidence"] = evidence
        return b"r" * 64

    def verify_snp(evidence, nonce, policy, **kwargs):
        assert seen["evidence"] is evidence
        assert nonce == b"n" * 32
        assert policy.min_tcb == minimum
        assert kwargs["raise_on_verifier_unavailable"] is True
        assert kwargs["deadline_monotonic"] < deadline
        return SimpleNamespace(
            tier=tier,
            chain_verified=True,
            verification_status="VERIFIED",
            chip_id="11" * 64,
        )

    contract = SimpleNamespace(
        Evidence=ContractEvidence,
        ChannelBinding=ContractBinding,
        EvidenceKind=SimpleNamespace(SEV_SNP=evidence_kind),
        ChannelBindingType=SimpleNamespace(TLS_SPKI_SHA256=binding_kind),
        Tier=SimpleNamespace(CC_CPU_SNP=tier),
        Policy=lambda *, allowed_measurements, min_tcb: SimpleNamespace(
            allowed_measurements=allowed_measurements,
            min_tcb=min_tcb,
        ),
        parse_snp_report=lambda _quote: parsed,
        snp_generation=lambda _parsed: "genoa",
        evidence_report_data=evidence_report_data,
        verify_snp=verify_snp,
        SnpVerifierUnavailable=RuntimeError,
    )
    verifier = object.__new__(SnpProductionVerifier)
    verifier._contract = contract
    verifier._policy = SnpPolicy(
        generations={"genoa": SnpGenerationPolicy(frozenset({"a" * 96}), minimum)},
        digest="sha256:" + "c" * 64,
    )
    verifier._snpguest_path = "/pinned/snpguest"
    verifier._snpguest_digest = "d" * 64
    verifier.digest = "sha256:" + "e" * 64
    collected = CollectedEvidence(
        kind="sev_snp",
        quote=b"snp-report",
        nonce=b"n" * 32,
        assigned_hotkey="miner-hotkey",
        cert_chain=(b"amd-chain",),
        channel_binding=ChannelBinding("tls_spki_sha256", b"z" * 32),
        report_data=b"r" * 64,
    )

    deadline = time.monotonic() + 20
    result = verifier.verify(collected, deadline_monotonic=deadline)

    assert result.verdict is QuoteVerdict.PASS
    assert result.machine_id is not None


def test_unexpected_miner_triggered_contract_error_scores_only_that_miner_zero():
    verifier = object.__new__(SnpProductionVerifier)
    verifier._contract = SimpleNamespace(
        parse_snp_report=lambda _quote: (_ for _ in ()).throw(
            TypeError("contract drift")
        ),
        SnpVerifierUnavailable=OSError,
    )
    verifier._policy = SnpPolicy(
        generations={"genoa": SnpGenerationPolicy(frozenset({"a" * 96}), 1)},
        digest="sha256:" + "c" * 64,
    )
    verifier._snpguest_path = "/pinned/snpguest"
    verifier._snpguest_digest = "d" * 64
    verifier.digest = "sha256:" + "e" * 64

    result = verifier.verify(_snp_collected())

    assert result.verdict is QuoteVerdict.FAIL
    assert result.reason == "snp_verification_failed"
