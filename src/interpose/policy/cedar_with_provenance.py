"""The same Cedar policy text, with provenance supplied as context facts.

This is the treatment arm. It loads :data:`~interpose.policy.cedar_common.CEDAR_POLICIES`
unchanged -- the identical bytes ``cedar-action-only`` loads -- and differs in
exactly one respect: on a write, it asks Cedar a second kind of question.

The decomposition, published here because a reader comparing two rows needs to
know the enforcement point is doing more work in one of them
-------------------------------------------------------------------------------

The reference policy's egress rule is

    for every tainted source *s*, for every reader *r* of the destination:
        *r* must be entitled to read *s*

Two nested universal quantifiers over two request-scoped sets. Cedar has no
iteration construct of any kind -- not a lambda, not a comprehension, not an
``any``/``all`` method -- so neither quantifier can be written in the policy
language. What Cedar *can* do is decide the inner predicate, because
``entitled(r, s)`` is literally an ordinary read authorization: is principal
*r* allowed to read object *s*? That is R2, and R2 is already in the policy
text, unchanged, serving ordinary reads.

So the enforcement point unrolls the two quantifiers into |sources| x |readers|
``probeRead`` requests -- reader as principal, source as resource -- and
conjoins the answers. It supplies pairs. It never decides an entitlement, does
no lattice arithmetic, and compares no clearances; every one of those is
Cedar reading ``source.readers``, ``source.classification`` and
``reader.clearance`` from its own entity store and applying the same three
``forbid`` rules that govern a direct read.

Measured cost on the bundled corpus: at most 2 pairs per write. A run of
``confidential-egress`` issues one authorization request per decision plus the
pairs; the ablation artifact records the exact totals per cell.

Why the pairs are checked *by Cedar* and not merely enumerated
--------------------------------------------------------------

An enforcement point that unrolls a quantifier is trusted to unroll it
completely. A buggy or dishonest one could probe a subset and report no
violation. So the provenance is not only used to build the pairs, it is
*declared* to Cedar in every probe: ``context.taintedSources`` carries every
source the write derives from and ``context.sinkReaders`` carries every reader
of the destination, and ``R3.probe-integrity`` forbids any probe whose resource
is not in the declared taint set or whose principal is not in the declared
readership. Cedar checks the enforcement point's arithmetic against the
enforcement point's own declaration.

That is also what makes the fail-closed requirement bite. A ``forbid`` whose
condition errors is skipped, so a typo in either key would silently disable the
integrity rule; the schema in :mod:`~interpose.policy.cedar_common` turns that
into ``NoDecision`` and :meth:`_CedarAdapter._ask` turns ``NoDecision`` into
deny.

What this row is a result about
-------------------------------

Not Cedar alone. Cedar decides every entitlement question here and derives
none of the provenance. The taint set is computed upstream by
:mod:`interpose.provenance` and :class:`interpose.engine.runner.Runner`: which
content units entered the agent's context, which of them a given argument
derives from, and what the destination's readership is. Cedar has no state, no
history and no data-flow primitive, and could not compute any of it. Any
containment number from this policy is a result about
``interpose.provenance`` **plus** Cedar, and naming only one half of that is an
overclaim.
"""

from __future__ import annotations

from typing import Any

from .cedar_common import CEDAR_POLICIES, _Answer, _CedarAdapter, _ref, _uid
from .types import ALLOW, DENY, Decision, DecisionContext

__all__ = ["CedarWithProvenance"]

#: The rule the enforcement point conjoins its probe answers into. Named in the
#: reference policy's vocabulary so the two can be compared on rule identity.
_EGRESS_RULE = "R3.egress-to-unentitled-reader"


class CedarWithProvenance(_CedarAdapter):
    """Cedar deciding R1, R2 and the R3 entitlement predicate."""

    id = "cedar-with-provenance"
    version = "0.1.0"
    _policy_text = CEDAR_POLICIES

    def describe(self) -> str:
        return (
            "Cedar PDP; egress decomposed into one Cedar read-entitlement query per "
            "(tainted source, sink reader) pair. Needs interpose[cedar]."
        )

    def evaluate(self, ctx: DecisionContext) -> Decision:
        schema = self._schema(ctx)
        entities = self._entities(ctx)
        answer = self._ask(self._invoke_request(ctx), entities, schema)
        if answer.fail_closed:
            return self._fail_closed(answer, "invocation")
        if not answer.allowed:
            return self._deny(ctx, answer)

        sink = ctx.sink
        if sink is None or ctx.action.effect_class not in ("write", "irreversible"):
            return self._allow(answer)

        sources = ctx.provenance.value_sources
        if not sources or not sink.readers:
            return self._allow(answer)

        seen = {(e["uid"]["type"], e["uid"]["id"]) for e in entities}
        for source in sources:
            entity = self.source_entity(source)
            key = (entity["uid"]["type"], entity["uid"]["id"])
            if key not in seen:
                entities.append(entity)
                seen.add(key)

        declared: dict[str, Any] = {
            "taintedSources": [_ref("Resource", s.resource_uri) for s in sources],
            "sinkReaders": [_ref("Principal", r.id) for r in sink.readers],
        }

        for source in sources:
            for reader in sink.readers:
                probe = self._probe_request(reader.id, source.resource_uri, declared)
                verdict = self._ask(probe, entities, schema)
                if verdict.fail_closed:
                    return self._fail_closed(verdict, "entitlement probe")
                if verdict.allowed:
                    continue
                if verdict.cedar_rule == "R3.probe-integrity":
                    return self._probe_integrity_failure(source.resource_uri, reader.id, verdict)
                return Decision(
                    effect=DENY,
                    rule_id=_EGRESS_RULE,
                    reason=(
                        f"write carries {source.classification.value} data from "
                        f"{source.resource_uri} into sink {sink.id}, which is readable "
                        f"by {reader.id} -- Cedar denies that read"
                    ),
                    metadata={
                        "sink": sink.id,
                        "source": source.resource_uri,
                        "carried_classification": source.classification.value,
                        "unentitled_readers": [reader.id],
                        "cedar_rule": verdict.cedar_rule,
                    },
                )

        return Decision(
            effect=ALLOW,
            rule_id="R0.permitted",
            reason="tool granted, object authorized, every (source, reader) pair permitted",
            metadata={"probe_pairs": len(sources) * len(sink.readers)},
        )

    def _probe_request(
        self, reader_id: str, source_uri: str, declared: dict[str, Any]
    ) -> dict[str, Any]:
        """One entitlement question: may this reader read this source?

        ``effective`` and ``onBehalfOf`` are both the reader: a reader of the
        destination acts for nobody, so there is no delegation ceiling to apply
        and the two clearance rules collapse onto the same principal.
        """
        return {
            "principal": _uid("Principal", reader_id),
            "action": _uid("Action", "probeRead"),
            "resource": _uid("Resource", source_uri),
            "context": {
                "effective": _ref("Principal", reader_id),
                "onBehalfOf": _ref("Principal", reader_id),
                "effectClass": "read",
                **declared,
            },
        }

    @staticmethod
    def _probe_integrity_failure(source_uri: str, reader_id: str, verdict: _Answer) -> Decision:
        """The enforcement point asked about a pair it had not declared.

        Reported as a fail-closed deny rather than as an egress denial, because
        it means this adapter is wrong, not that the write is unsafe.
        """
        return Decision(
            effect=DENY,
            rule_id="cedar.fail-closed",
            reason=(
                "the enforcement point probed a (source, reader) pair outside the "
                "provenance it declared to Cedar; denying rather than trusting it"
            ),
            metadata={
                "source": source_uri,
                "reader": reader_id,
                "cedar_rule": verdict.cedar_rule,
                "stage": "probe integrity",
            },
        )
