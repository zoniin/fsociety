"""Cedar as a per-request PDP, with no information about where data came from.

This is the control arm of the provenance ablation, and it is written to be
the **strongest** action-level policy the evidence supports, not a foil. It is
the reference policy's R1 and R2 in full -- deny by default at the tool
boundary, object-level read authorization on both the allowlist branch and the
clearance-lattice branch, and the delegation ceiling -- expressed natively in
Cedar and enforced by Cedar. It is strictly stronger than
``permissive-baseline``, and it denies the reads ``path-prefix-v1`` denies
without denying the legitimate ones, because it reasons about objects rather
than about their names.

It is given more than it uses. The call's arguments arrive as
``context.argumentText``, the destination queue arrives with its full
readership and an ``hasExternalReader`` flag, and the resolved resource arrives
with its path. It writes a rule over none of them, and
:mod:`~interpose.policy.cedar_common` records why: Cedar's ``like`` cannot
express a pattern, only a fixed keyword list, and a keyword list chosen to
catch this corpus would be selection on the answer key.

What it is not given is any statement connecting the bytes in an argument to
the objects they were read from. That single omission is the independent
variable of the ablation, and the reason the two arms share one policy text.

The design principle, stated so it can be disagreed with: an authorization
gateway is a stateless per-request decision point. It sees identity, action,
arguments and whatever static metadata the resolved target carries. It sees no
history and no data flow. Everything in ``DecisionContext`` except
``provenance`` and ``history`` is fair game; those two are not.
"""

from __future__ import annotations

from .cedar_common import CEDAR_POLICIES, STRICT_EXTERNAL_SINK_RULE, _CedarAdapter
from .types import Decision, DecisionContext

__all__ = ["CedarActionOnly", "CedarActionOnlyStrict"]


class CedarActionOnly(_CedarAdapter):
    """One Cedar authorization request per tool call. Exactly one, always."""

    id = "cedar-action-only"
    version = "0.1.0"
    _policy_text = CEDAR_POLICIES

    def describe(self) -> str:
        return (
            "Cedar PDP: deny-by-default tool grant, object-level read authorization, "
            "delegation ceiling. No provenance. Needs interpose[cedar]."
        )

    def evaluate(self, ctx: DecisionContext) -> Decision:
        entities = self._entities(ctx)
        answer = self._ask(self._invoke_request(ctx), entities, self._schema(ctx))
        if answer.fail_closed:
            return self._fail_closed(answer, "invocation")
        if answer.allowed:
            return self._allow(answer)
        return self._deny(ctx, answer)


class CedarActionOnlyStrict(CedarActionOnly):
    """``cedar-action-only`` plus the blanket external-sink ban.

    Deliberately **not** registered in ``BUILTIN_POLICIES``. It exists so that
    "the action-level arm was a strawman" is a claim with a measured answer
    rather than a matter of opinion: this is the rule a gateway operator would
    reach for on the write side, it is expressible in Cedar without provenance,
    and the ablation reports what it contains and what it costs. Load it by
    dotted path::

        interpose run confidential-egress \\
            --policy interpose.policy.cedar_action_only:CedarActionOnlyStrict

    It is not part of the five-policy ablation because it answers a different
    question -- what an action-level ceiling costs -- rather than the
    ablation's question of what provenance buys.
    """

    id = "cedar-action-only-strict"
    version = "0.1.0"
    _policy_text = CEDAR_POLICIES + STRICT_EXTERNAL_SINK_RULE

    def describe(self) -> str:
        return (
            "cedar-action-only plus a blanket ban on writes to externally-readable "
            "sinks. Unregistered; contains without provenance, and over-blocks."
        )
