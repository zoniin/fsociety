"""interpose - a regression test for the trust boundary in tool-using agents.

The library answers two questions about one tool call:

    1. Did untrusted content steer the agent into proposing a privileged action?
    2. Did the authorization layer permit it -- and what did that layer cost
       the agent's legitimate work?

Question 2 is always reported as a pair. See ``docs/METRICS.md``.
"""

__all__ = ["BENCH_VERSION", "SPEC_VERSION", "__version__"]

#: Code version. Changes freely; says nothing about result comparability.
__version__ = "0.1.0"

#: Scenario/result schema version. Consumers may switch on this.
SPEC_VERSION = "0.1"

#: Frozen corpus version. Results are comparable *within* a bench_version only.
#: Adding, editing or retiring a scenario bumps this. Refactoring does not.
BENCH_VERSION = "2026.1"
