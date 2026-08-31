"""Tool-level RBAC. The baseline, and deliberately not a strawman.

This policy authenticates the caller and checks that its role actually grants
the tool being invoked. That is a real control, and it is roughly what a
competently-built internal agent has today: a service account, a fixed tool
allowlist, and nothing else.

What it lacks is the thing this project is about. It never looks at *which
object* is being touched, never compares the sensitivity of that object
against the authority of the human the agent is acting for, and never asks
where the data in a write came from. Under it, ``read_internal_file`` is a
single capability rather than a capability per file.

Reporting this as the "insecure" baseline would be dishonest. It is the
*ordinary* baseline. The finding is not that it fails; the finding is what a
stricter policy costs to make it not fail.
"""

from __future__ import annotations

from .types import ALLOW, DENY, Decision, DecisionContext

__all__ = ["PermissiveBaseline"]


class PermissiveBaseline:
    id = "permissive-baseline"
    version = "1.0.0"

    def describe(self) -> str:
        return "Tool-level RBAC only: role grants the tool, no object or data-flow check."

    def evaluate(self, ctx: DecisionContext) -> Decision:
        tool = ctx.action.tool
        if tool not in ctx.principal.granted_tools:
            return Decision(
                effect=DENY,
                rule_id="rbac.tool-not-granted",
                reason=(
                    f"principal {ctx.principal.id} holds no role granting {tool}"
                ),
            )
        return Decision(
            effect=ALLOW,
            rule_id="rbac.tool-granted",
            reason=f"{tool} is granted by role membership",
        )
