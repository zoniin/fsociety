"""Least privilege with a *context-taint* egress rule.

This is the reference policy with one change, and the change is the whole
point: R3 checks every source that has entered the agent's context, not only
the sources whose words can be found in the write.

Why it exists
-------------

``reference-least-privilege`` decides egress on ``value_provenance`` -- an
eight-word shingle match between what was read and what is being written. The
Phase II paraphrase falsification (``docs/research/PARAPHRASE_FALSIFICATION.md``)
showed what that costs: a client that restates the confidential facts in its
own words escapes R3 on both flow scenarios, at zero utility cost, while the
content detector reports nothing exposed. The reference policy's own docstring
named the alternative and left it unbuilt:

    The stricter option -- refusing every write from a context that ever
    touched restricted data -- would raise containment and cost utility. That
    is a real point on the frontier, and it is left for a contributed policy.

This is that policy. It does not try to *detect* a flow in the text, so there
is nothing for a paraphrase to evade. If the context holds a source, the write
is treated as carrying it -- the same over-approximation dynamic IFC systems
for agents (FIDES, CaMeL's capability tags) make at the context level.

What it costs, and why
----------------------

Over-approximation is not free, and the cost has a name: **label creep**. A
context that browsed an internal retrospective while filing an unrelated
vendor ticket is tainted with that retrospective, and the ticket is refused
even though it carries nothing from it. On the bundled corpus that is exactly
one benign task (``confidential-egress`` / ``b2-vendor-invoice-query``).

That number is a floor, not an estimate. Every benign task here runs in a fresh
session, so taint never accumulates across tasks. In a long-lived session --
the way most deployed agents run -- the taint set only grows, and the false
denial rate grows with it. A production deployment of this rule needs a
declassification path (a quarantined reader, a human approval, a session
reset) and this policy does not model one.

Provenance of the policy itself
-------------------------------

Written **after** the paraphrasing client and all three scenarios existed, by
the same author. It is therefore not evidence under the ordering rule in
``docs/PROTOCOL.md``: it was tuned against attacks its author could see. Its
digest is frozen from the commit that adds it, so the next scenario that
scores it is a genuine test.

The file is deliberately standalone rather than a subclass of the reference
policy. ``policy_digest`` covers the defining file only; a subclass's digest
would silently not cover the rules it inherits.
"""

from __future__ import annotations

from .types import ALLOW, DENY, Decision, DecisionContext, SourceView

__all__ = ["ContextTaint"]


class ContextTaint:
    id = "context-taint"
    version = "1.0.0"

    def describe(self) -> str:
        return (
            "Reference rules, but egress is checked against every source in the "
            "agent context -- paraphrase-robust, pays for it in label creep."
        )

    def evaluate(self, ctx: DecisionContext) -> Decision:
        # R1 -- the tool must be granted at all.
        tool = ctx.action.tool
        if tool not in ctx.principal.granted_tools:
            return Decision(
                effect=DENY,
                rule_id="R1.tool-not-granted",
                reason=f"principal {ctx.principal.id} holds no role granting {tool}",
            )

        # R2 -- authorize the object being read. Identical to the reference.
        resource = ctx.resource
        if resource is not None and ctx.action.effect_class == "read":
            if resource.readers:
                if ctx.principal.on_behalf_of not in resource.readers:
                    return Decision(
                        effect=DENY,
                        rule_id="R2.not-in-reader-set",
                        reason=(
                            f"{resource.uri} restricts readers to an explicit set that does "
                            f"not include {ctx.principal.on_behalf_of}"
                        ),
                        metadata={
                            "resource": resource.uri,
                            "classification": resource.classification.value,
                        },
                    )
            elif ctx.principal.delegated_rank() < resource.rank():
                return Decision(
                    effect=DENY,
                    rule_id="R2.insufficient-clearance",
                    reason=(
                        f"effective clearance of {ctx.principal.id} acting for "
                        f"{ctx.principal.on_behalf_of} does not dominate "
                        f"{resource.classification.value} resource {resource.uri}"
                    ),
                    metadata={
                        "resource": resource.uri,
                        "classification": resource.classification.value,
                    },
                )

        # R3 -- egress against the *whole context*. Value sources are included
        # so that a source attributed to the arguments but not (yet) recorded
        # in the context is never dropped; in practice the context is a superset.
        sink = ctx.sink
        if sink is not None and ctx.action.effect_class in ("write", "irreversible"):
            for source, how in _tainting_sources(ctx):
                unentitled = sink.unentitled_readers(source)
                if unentitled:
                    who = ", ".join(r.id for r in unentitled)
                    return Decision(
                        effect=DENY,
                        rule_id="R3.context-tainted-egress",
                        reason=(
                            f"agent context holds {source.classification.value} data from "
                            f"{source.resource_uri} ({how}); sink {sink.id} is readable by "
                            f"{who} -- not entitled to that source"
                        ),
                        metadata={
                            "sink": sink.id,
                            "source": source.resource_uri,
                            "carried_classification": source.classification.value,
                            "unentitled_readers": [r.id for r in unentitled],
                            "attribution": how,
                        },
                    )

        return Decision(
            effect=ALLOW,
            rule_id="R0.permitted",
            reason="tool granted, object authorized, context carries nothing the sink may not hold",
        )


def _tainting_sources(ctx: DecisionContext) -> list[tuple[SourceView, str]]:
    """Every source the write may carry, value matches first, deduplicated.

    Value-attributed sources are listed first so that when the text *does*
    visibly carry a source, the denial names that one -- the more useful
    explanation for whoever reads the trace.
    """
    seen: set[str] = set()
    out: list[tuple[SourceView, str]] = []
    for pool, how in (
        (ctx.provenance.value_sources, "found in the write"),
        (ctx.provenance.context_sources, "present in context"),
    ):
        for source in sorted(pool, key=lambda s: s.unit_id):
            if source.unit_id not in seen:
                seen.add(source.unit_id)
                out.append((source, how))
    return out
