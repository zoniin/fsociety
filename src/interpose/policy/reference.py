"""Object-level authorization with a data-flow egress rule.

Three rules, applied in order. Each corresponds to a control that exists in
production systems, and each is written to be copied rather than admired.

**R1 -- deny by default at the tool boundary.** Nothing runs that a role does
not grant. Saltzer and Schroeder, fail-safe defaults.

**R2 -- authorize the object, not the verb.** A read is permitted when the
*effective* authority of the request dominates the sensitivity of the
resource. Effective authority is the minimum of the agent service principal
clearance and the clearance of the human it is acting for -- delegation may
narrow authority, never widen it. An explicit reader allowlist on the resource
overrides the lattice comparison, which is how real systems express
need-to-know.

This is the rule that distinguishes this policy from a path deny-list. It
permits the quarterly headcount file and refuses the payroll export *for
reasons about the objects*, not about their names, so the benign task survives.

**R3 -- egress against provenance.** A write is refused when any reader of the
destination could not have read a source the written data derives from. This
is the rule that catches the second half of an exfiltration, and it is the one
that matters most: the interesting case is not reading a file you may not read,
it is reading a file you *may* read and then posting it somewhere you may not
post it. R2 cannot see that case at all.

The comparison is per reader and per source, deliberately. Aggregating over
either side loses the answer: comparing against the readership's strongest
clearance lets an insider cover for an outsider, and comparing against bulk
clearances alone refuses writes whose readers hold explicit need-to-know
grants. Both of those shipped before review.

Known limits, because this policy is published and someone will deploy it:

* R3 uses ``value_provenance``, which under-approximates. An agent that
  paraphrases rather than quotes escapes it (SIMPL-0002, bias optimistic). The
  stricter option -- refusing every write from a context that ever touched
  restricted data -- would raise containment and cost utility. That is a real
  point on the frontier, and it is left for a contributed policy rather than
  chosen here by fiat.
* It assumes every object carries a correct classification. In production the
  most common reason object-level authorization fails is that objects are
  unclassified, misclassified, or stale (SIMPL-0008).

Calibration statement, which is what a reader deploying this actually needs:
this policy is calibrated against one scenario, one threat model, and one
five-tool surface. It contains the attack in that scenario at zero measured
false denials on that scenario benign suite. It has not been evaluated against
anything else.
"""

from __future__ import annotations

from .types import ALLOW, DENY, Decision, DecisionContext

__all__ = ["ReferenceLeastPrivilege"]


class ReferenceLeastPrivilege:
    id = "reference-least-privilege"
    version = "1.0.0"

    def describe(self) -> str:
        return "Deny-by-default, object-level clearance check, provenance-based egress rule."

    def evaluate(self, ctx: DecisionContext) -> Decision:
        # R1 -- the tool must be granted at all.
        tool = ctx.action.tool
        if tool not in ctx.principal.granted_tools:
            return Decision(
                effect=DENY,
                rule_id="R1.tool-not-granted",
                reason=f"principal {ctx.principal.id} holds no role granting {tool}",
            )

        # R2 -- authorize the object being read.
        resource = ctx.resource
        if resource is not None and ctx.action.effect_class == "read":
            if resource.readers:
                entitled = ctx.principal.on_behalf_of in resource.readers
                if not entitled:
                    return Decision(
                        effect=DENY,
                        rule_id="R2.not-in-reader-set",
                        reason=(
                            f"{resource.uri} restricts readers to an explicit set that does "
                            f"not include {ctx.principal.on_behalf_of}"
                        ),
                        metadata={"resource": resource.uri, "classification": resource.classification.value},
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
                    metadata={"resource": resource.uri, "classification": resource.classification.value},
                )

        # R3 -- egress: every reader of the sink must be entitled to every
        # source the written data derives from.
        sink = ctx.sink
        if sink is not None and ctx.action.effect_class in ("write", "irreversible"):
            for source in ctx.provenance.value_sources:
                unentitled = sink.unentitled_readers(source)
                if unentitled:
                    who = ", ".join(r.id for r in unentitled)
                    return Decision(
                        effect=DENY,
                        rule_id="R3.egress-to-unentitled-reader",
                        reason=(
                            f"write carries {source.classification.value} data from "
                            f"{source.resource_uri} into sink {sink.id}, which is readable "
                            f"by {who} -- not entitled to that source"
                        ),
                        metadata={
                            "sink": sink.id,
                            "source": source.resource_uri,
                            "carried_classification": source.classification.value,
                            "unentitled_readers": [r.id for r in unentitled],
                        },
                    )

        return Decision(
            effect=ALLOW,
            rule_id="R0.permitted",
            reason="tool granted, object authorized, no egress violation",
        )
