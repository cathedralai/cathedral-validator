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


__all__ = [
    "BroadcastBlocked",
    "BroadcastDisabled",
    "CommitmentError",
    "ConfigError",
    "GenesisPinError",
    "HamiltonError",
    "IndependentValidatorError",
    "InclusionHalt",
    "JournalError",
    "PolicyBundleError",
    "PolicyFetchError",
    "RefuseListError",
]
