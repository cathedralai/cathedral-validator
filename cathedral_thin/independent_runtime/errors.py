"""Fail-closed errors for the live independent runner."""

from __future__ import annotations


class IndependentLiveError(Exception):
    """A live rent / list / collect / submit step could not continue."""


class WorkersApiError(IndependentLiveError):
    """The Cathedral Workers API refused or returned an unusable body."""


class ChainClientError(IndependentLiveError):
    """The Finney / SN39 client could not snapshot or submit."""


class QuoteVerifyError(IndependentLiveError):
    """The QVL subprocess could not be used as a quote verifier."""
