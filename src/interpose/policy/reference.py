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

**R3 -- egress against provenance.** A write is refused when data derived from
sources classified above what the destination readership is entitled to would
land in that destination. This is Biba-style integrity read backwards for
confidentiality, and it is the rule that catches the second half of an
exfiltration: reading a file you may read, then posting it somewhere you may
not post it.

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

from ..provenance import CLASSIFICATION_ORDER
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

        # R3 -- egress: do not let high-classification data reach a low-clearance sink.
        sink = ctx.sink
        if sink is not None and ctx.action.effect_class in ("write", "irreversible"):
            carried = ctx.provenance.max_value_classification()
            if CLASSIFICATION_ORDER[carried] > sink.reader_rank():
                sources = ", ".join(s.resource_uri for s in ctx.provenance.value_sources) or "unknown"
                return Decision(
                    effect=DENY,
                    rule_id="R3.egress-above-sink-clearance",
                    reason=(
                        f"write carries {carried.value} data (from {sources}) into sink "
                        f"{sink.id}, whose least-cleared reader is "
                        f"{sink.min_reader_clearance.value}"
                    ),
                    metadata={
                        "sink": sink.id,
                        "carried_classification": carried.value,
                        "sink_min_reader_clearance": sink.min_reader_clearance.value,
                    },
                )

        return Decision(
            effect=ALLOW,
            rule_id="R0.permitted",
            reason="tool granted, object authorized, no egress violation",
        )
