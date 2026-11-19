"""Context taint, with reads scoped to the egress the user asked for.

``context-taint`` closes paraphrase by treating a write as carrying everything
in the agent context. Its price is label creep: an agent that browses an
internal document while doing an unrelated vendor task taints the vendor
ticket, and the ticket is refused.

This policy moves the decision earlier. When the *trusted user's* request
names a sink -- "file a ticket in queue vendor-support" -- the user has
declared where this task's output is going. A read that would put into context
something that sink's readers are not entitled to cannot contribute to that
output legitimately, so it is refused **at read time**. The context stays
clean, and the write the user asked for goes through. Nothing in this depends
on matching text, so it is as paraphrase-robust as context-taint: R3 is kept
unchanged as the backstop.

It is declassification by construction rather than by exception. No tainted
write is ever let through; the policy only refuses to taint the context in the
first place.

Rules, in order:

R1  the tool must be granted (as the reference).
R2  the object must be authorized for the delegating human (as the reference).
R4  **read scoping.** If the user task names one or more sinks, a read is
    refused when any reader of any named sink is not entitled to the resource.
    No named sink, no scoping.
R3  egress against every source in context (as ``context-taint``).

Known limits, stated because this is the policy a reader might copy:

* The declared sinks come from sink ids appearing verbatim in the user task.
  A request that names its destination indirectly ("send it to the vendor")
  gets no scoping and falls back to context-taint's cost. A deployment would
  declare destinations structurally, not by string match.
* When the user names several sinks, a read must be holdable by *every* named
  sink's readers. A task whose outputs legitimately differ in sensitivity --
  "post the figures to finance and tell the vendor it is done" -- is refused
  reads it needs. That is the next point on this frontier.
* It cannot undo taint carried in from earlier tasks in a long session
  (``--session long``). A refused read keeps the *current* task clean; it does
  not declassify what is already there. Cross-task creep is a session-scoping
  decision, not one a per-call policy can make safely: forgetting labels at a
  task boundary is exactly how a two-task exfiltration would be laundered.
* A refused read is a false denial when the document was harmless to the task,
  and it is reported as one.

Provenance: written after every bundled attack was visible, like
``context-taint``. Frozen in the commit that adds it.

Standalone rather than a subclass for the reason given in ``context_taint.py``:
``policy_digest`` covers the defining file only.
"""

from __future__ import annotations

import re

from ..provenance import CLASSIFICATION_ORDER, Classification
from .types import ALLOW, DENY, Decision, DecisionContext, ReaderView, SinkView, SourceView

__all__ = ["SinkScopedTaint"]


class SinkScopedTaint:
    id = "sink-scoped-taint"
    version = "1.0.0"

    def describe(self) -> str:
        return (
            "Context taint, but reads are refused up front when the sink the user "
            "named could not hold them -- trades label creep for read denials."
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

        resource = ctx.resource
        if resource is not None and ctx.action.effect_class == "read":
            # R2 -- authorize the object for the delegating human.
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

            # R4 -- read scoping against the sinks the user named.
            for declared in declared_sinks(ctx.user_task, ctx.sinks):
                outsiders = [
                    r.id for r in declared.readers
                    if not _entitled(r, resource.classification, resource.readers)
                ]
                if outsiders:
                    return Decision(
                        effect=DENY,
                        rule_id="R4.read-outside-declared-egress",
                        reason=(
                            f"the task sends its output to {declared.id}, readable by "
                            f"{', '.join(outsiders)}, who may not read "
                            f"{resource.classification.value} resource {resource.uri}; "
                            "reading it would taint that output"
                        ),
                        metadata={
                            "resource": resource.uri,
                            "declared_sink": declared.id,
                            "unentitled_readers": outsiders,
                        },
                    )

        # R3 -- egress against the whole context. The backstop: anything the
        # read scoping did not prevent (no sink named, or taint carried in from
        # an earlier task) is still caught here, paraphrased or not.
        sink = ctx.sink
        if sink is not None and ctx.action.effect_class in ("write", "irreversible"):
            for source in _tainting_sources(ctx):
                unentitled = sink.unentitled_readers(source)
                if unentitled:
                    who = ", ".join(r.id for r in unentitled)
                    return Decision(
                        effect=DENY,
                        rule_id="R3.context-tainted-egress",
                        reason=(
                            f"agent context holds {source.classification.value} data from "
                            f"{source.resource_uri}; sink {sink.id} is readable by "
                            f"{who} -- not entitled to that source"
                        ),
                        metadata={
                            "sink": sink.id,
                            "source": source.resource_uri,
                            "unentitled_readers": [r.id for r in unentitled],
                        },
                    )

        return Decision(
            effect=ALLOW,
            rule_id="R0.permitted",
            reason="tool granted, object authorized, read within declared egress, context clean",
        )


def declared_sinks(user_task: str, sinks: tuple[SinkView, ...]) -> list[SinkView]:
    """Sinks whose id appears in the trusted user task as a whole token.

    Only the user task is consulted. Tool output, including the injected
    document, never declares a sink: letting untrusted content widen or choose
    the egress scope would hand the attacker the declassification decision.
    """
    out = []
    for sink in sinks:
        if re.search(rf"(?<![\w-]){re.escape(sink.id)}(?![\w-])", user_task):
            out.append(sink)
    return out


def _entitled(reader: ReaderView, classification: Classification, readers: tuple[str, ...]) -> bool:
    """The same relation as ``ReaderView.entitled_to``, for a resource not yet read."""
    if readers:
        return reader.id in readers
    return CLASSIFICATION_ORDER[reader.clearance] >= CLASSIFICATION_ORDER[classification]


def _tainting_sources(ctx: DecisionContext) -> list[SourceView]:
    seen: set[str] = set()
    out: list[SourceView] = []
    for pool in (ctx.provenance.value_sources, ctx.provenance.context_sources):
        for source in sorted(pool, key=lambda s: s.unit_id):
            if source.unit_id not in seen:
                seen.add(source.unit_id)
                out.append(source)
    return out
