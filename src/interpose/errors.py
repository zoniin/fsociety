"""Exception hierarchy.

The split between :class:`HarnessError` and :class:`ExpectationViolation` is
load-bearing: it is what lets CI tell "the policy failed" (a *result*) apart
from "the lab broke" (a *bug*). Collapsing them turns a regression suite into
noise. See the exit-code table in ``docs/METRICS.md``.
"""

from __future__ import annotations


class InterposeError(Exception):
    """Base class for everything this package raises deliberately."""


class HarnessError(InterposeError):
    """The harness itself malfunctioned. Exit code 2."""


class UsageError(InterposeError):
    """The invocation or configuration was wrong. Exit code 3."""


class ScenarioError(UsageError):
    """A scenario could not be loaded or validated."""


class PolicyLoadError(UsageError):
    """A policy adapter could not be resolved or does not satisfy the protocol."""


class ContainmentViolation(HarnessError):
    """The harness attempted something its containment guarantees forbid.

    Raised by the guards in :mod:`interpose.guards`. This is always a bug in
    interpose, never a finding about the scenario under test.
    """
