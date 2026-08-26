"""Fail-closed exception types for the independent composer.

Every refusal in this package raises. There is no "degrade quietly and carry
on" path: a composer that cannot prove the policy it is paying from, or cannot
prove the destination it is paying to, produces nothing.

`DEGRADED` is not an exception. It is a legal composed vector (burn-only) that
is explicitly NOT an acceptance signal, and it is reported as a status on the
compose result and in the journal.
"""

from __future__ import annotations


class IndependentValidatorError(Exception):
    """Base class for every refusal on the independent composer path."""


class PolicyBundleError(IndependentValidatorError):
    """The policy document is malformed, unsigned, or internally inconsistent."""


class PolicyLineageError(PolicyBundleError):
    """The economics version or previous_digest cannot follow genesis or last-good."""


class CommitmentError(IndependentValidatorError):
    """The on-chain commitment is malformed or does not match the document."""


class PolicyFetchError(IndependentValidatorError):
    """The policy document could not be fetched under the hardened rules."""


class HamiltonError(IndependentValidatorError):
    """The integer mass map cannot be apportioned to a legal u16 vector."""


class InclusionHalt(IndependentValidatorError):
    """The inclusion-time metagraph invalidates the composed destinations."""


class BroadcastBlocked(IndependentValidatorError):
    """A funded lane cannot be substantiated, so no vector may be broadcast."""


class BroadcastDisabled(IndependentValidatorError):
    """Broadcast was requested. This lineage has no chain writer."""


class RefuseListError(IndependentValidatorError):
    """The configured hotkey is on the refuse-list; the process must not start."""


class GenesisPinError(IndependentValidatorError):
    """The observed chain genesis hash is not the pinned Finney genesis."""


class JournalError(IndependentValidatorError):
    """The independent journal could not be written, or was refused on load."""


class ConfigError(IndependentValidatorError):
    """The operator configuration is missing, malformed, or unsafe."""


class AdapterUnavailable(IndependentValidatorError):
    """A lane adapter cannot be constructed under this lineage's evidence rules.

    Raised at construction rather than at use. An adapter that could be built
    without its verifier would leave a code path that reaches a quote nobody
    checked, and that path is what "attestation optional" actually means.
    """


class CollateralSourceError(IndependentValidatorError):
    """Attestation collateral would be fetched from somewhere other than its pin."""


class ComputeEvidenceError(IndependentValidatorError):
    """Compute-lane evidence is malformed, unbounded, or not bytes."""


class CollectError(IndependentValidatorError):
    """The miner evidence POST failed under the hardened collect rules."""


class SatWorkError(IndependentValidatorError):
    """The audit work unit could not be independently re-derived.

    Raised for every refusal on the work-unit path: a non-canonical instance, a
    miner answer that is not a checkable witness, or a claimed number this
    validator did not derive itself. It means zero mass, never a smaller one.
    """


class CanaryIneligible(IndependentValidatorError):
    """The one-write canary was asked to submit a vector it must not send."""


class CanarySpent(IndependentValidatorError):
    """The one-write canary slot is already claimed; a second write is refused."""


class CanaryTransportError(IndependentValidatorError):
    """The canary transport is missing, returned a bad receipt, or failed."""


class CanaryStateError(IndependentValidatorError):
    """The one-write canary lock file could not be claimed or was refused."""


class MachineIdentityConflict(ComputeEvidenceError):
    """One machine identity is claimed by two miner hotkeys.

    Both claimants are ``NOT_PROVEN`` for the epoch: the machine cannot be two
    miners' machines, and a validator that guessed which one to believe would be
    paying a sybil half the time.
    """


__all__ = [
    "AdapterUnavailable",
    "BroadcastBlocked",
    "BroadcastDisabled",
    "CanaryIneligible",
    "CanarySpent",
    "CanaryStateError",
    "CanaryTransportError",
    "CollateralSourceError",
    "CollectError",
    "CommitmentError",
    "ComputeEvidenceError",
    "ConfigError",
    "GenesisPinError",
    "HamiltonError",
    "IndependentValidatorError",
    "InclusionHalt",
    "JournalError",
    "MachineIdentityConflict",
    "PolicyBundleError",
    "PolicyFetchError",
    "PolicyLineageError",
    "RefuseListError",
    "SatWorkError",
]
