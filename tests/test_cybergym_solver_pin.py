"""Checking WHICH program produced a PoC, instead of trusting the backend that ran it.

The backend runs every miner's agent itself, so "we only credited the approved solver" is a claim
it makes about itself. Our corpus is public bugs with published reference PoCs, so an enclave run
of a lookup table is as genuinely attested as an enclave run of an agent that derived the crash —
the measurement is the only thing that separates them, and a validator that does not check it is
trusting the party it exists to check.
"""
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
from cathedral_thin.cybergym_round_eval import (
    Submission, TaskProof, evaluate_round, solver_refusal,
)
from cathedral_thin.cybergym_round_runtime import (
    RoundRuntimeError, approved_workload_for, benchmark_and_report,
)

PIN = "d1" + "6" * 62
OTHER = "ff" + "0" * 62


def _att(**over):
    doc = {"receipt_id": "r1", "worker_id": "w1", "workload_sha256": PIN,
           "result_sha256": "b" * 64, "intel_verified": True,
           "report_data_match": True, "payload_bound": True}
    doc.update(over)
    return doc


def _sub(hk="5A", tasks=("t1", "t2"), attestation="approved"):
    return Submission(
        miner_hotkey=hk, agent_digest="sha256:" + hk,
        tasks=tuple(TaskProof(t, b"poc-" + t.encode(), {"img": t}) for t in tasks),
        attestation=_att() if attestation == "approved" else attestation,
    )


def _solves_everything(task_id, poc, proof):
    return True


class TestWhatFailsThePin:
    def test_the_approved_solver_passes(self):
        assert solver_refusal(_sub(), PIN) is None

    def test_no_receipt_at_all(self):
        assert "no attestation" in solver_refusal(_sub(attestation=None), PIN)

    def test_a_different_measurement(self):
        """The one that matters: a real enclave run of a program we did not approve."""
        why = solver_refusal(_sub(attestation=_att(workload_sha256=OTHER)), PIN)
        assert "not the approved solver" in why

    def test_a_receipt_with_no_measurement(self):
        att = _att()
        del att["workload_sha256"]
        assert "no workload_sha256" in solver_refusal(_sub(attestation=att), PIN)

    def test_a_quote_that_did_not_verify(self):
        assert "hardware quote" in solver_refusal(_sub(attestation=_att(intel_verified=False)), PIN)

    def test_a_receipt_that_does_not_bind_this_dispatch(self):
        why = solver_refusal(_sub(attestation=_att(report_data_match=False)), PIN)
        assert "does not bind" in why

    def test_an_enclave_that_did_not_read_the_payload(self):
        why = solver_refusal(_sub(attestation=_att(payload_bound=False)), PIN)
        assert "did not read the payload" in why

    def test_an_older_backend_that_omits_the_payload_field_is_not_punished_for_it(self):
        """Refusing every miner over a field the backend does not implement would be this
        validator's fault, not theirs. Present-and-false is refused; absent is not."""
        att = _att()
        del att["payload_bound"]
        assert solver_refusal(_sub(attestation=att), PIN) is None

    def test_the_comparison_is_case_insensitive(self):
        assert solver_refusal(_sub(attestation=_att(workload_sha256=PIN.upper())), PIN) is None


class TestWhatRefusalDoesToTheScore:
    def test_a_refused_submission_scores_zero_even_though_its_pocs_work(self):
        """The PoCs may well crash the target. A crash nobody can attribute to the approved solver
        is exactly what this lane refuses to pay for."""
        results = evaluate_round(
            [_sub("5A"), _sub("5B", attestation=_att(workload_sha256=OTHER))],
            _solves_everything, task_ids=["t1", "t2"], approved_workload=PIN,
        )
        assert results["5A"].score == Decimal("100")
        assert results["5B"].score == Decimal(0) and results["5B"].solved == 0

    def test_a_refusal_is_a_verdict_not_an_abstention(self):
        """`evaluated=False` means "I could not judge this" and the backend EXCLUDES it from the
        average. A refusal is the opposite: it was judged, and it must count."""
        results = evaluate_round(
            [_sub("5B", attestation=None)], _solves_everything,
            task_ids=["t1", "t2"], approved_workload=PIN,
        )
        assert results["5B"].evaluated is True
        assert results["5B"].per_task == (("t1", False), ("t2", False))

    def test_a_refused_submission_is_never_benchmarked(self):
        """Not just a scoring decision — running a rejected miner's PoCs costs a corpus rebuild
        this validator has no reason to spend."""
        ran = []

        def bench(task_id, poc, proof):
            ran.append(task_id)
            return True

        evaluate_round([_sub("5B", attestation=None)], bench,
                       task_ids=["t1", "t2"], approved_workload=PIN)
        assert ran == []

    def test_without_a_pin_nothing_changes(self):
        """Off by default: an operator who has not opted in gets today's behaviour exactly."""
        results = evaluate_round([_sub("5B", attestation=None)], _solves_everything,
                                 task_ids=["t1", "t2"])
        assert results["5B"].score == Decimal("100")


class _Client:
    def __init__(self, solver, submissions=()):
        self._solver = solver
        self._subs = list(submissions)
        self.posted = None

    def fetch_solver(self):
        return dict(self._solver)

    def fetch_round_tasks(self, round_id):
        return ["t1", "t2"]

    def fetch_submissions(self, round_id):
        return list(self._subs)

    def post_results(self, round_id, results):
        self.posted = results

    def fetch_average_scores(self, round_id):
        return {}


class TestResolvingThePinFromTheBackend:
    def test_the_published_pin_is_used(self):
        client = _Client({"enforced": True, "approved_workload_sha256": PIN})
        assert approved_workload_for(client, require=True) == PIN

    def test_not_requiring_it_does_not_even_ask(self):
        class Boom:
            def fetch_solver(self):
                raise AssertionError("must not be called")

        assert approved_workload_for(Boom(), require=False) is None

    def test_demanding_a_pin_the_backend_does_not_publish_raises(self):
        """Returning None here would leave the validator believing it enforces something it does
        not. It must also not zero the field: the caller records the failure and retries, which
        is an abstention — a backend that publishes nothing is not the miners' fault."""
        client = _Client({"enforced": False, "approved_workload_sha256": None})
        with pytest.raises(RoundRuntimeError, match="publishes none"):
            approved_workload_for(client, require=True)

    def test_a_malformed_published_pin_is_refused(self):
        client = _Client({"enforced": True, "approved_workload_sha256": "sha256:" + PIN})
        with pytest.raises(RoundRuntimeError):
            approved_workload_for(client, require=True)

    def test_the_daemon_path_reports_nothing_when_the_pin_is_missing(self):
        client = _Client({"enforced": False}, [_sub("5A")])
        with pytest.raises(RoundRuntimeError):
            benchmark_and_report(0, client=client, benchmark=_solves_everything,
                                 require_approved_solver=True)
        assert client.posted is None, "no verdicts may be reported on an unchecked field"

    def test_the_daemon_path_enforces_the_published_pin_end_to_end(self):
        client = _Client(
            {"enforced": True, "approved_workload_sha256": PIN},
            [_sub("5A"), _sub("5B", attestation=_att(workload_sha256=OTHER))],
        )
        results = benchmark_and_report(0, client=client, benchmark=_solves_everything,
                                       require_approved_solver=True)
        assert results["5A"].score == Decimal("100")
        assert results["5B"].score == Decimal(0)
        assert client.posted is results
