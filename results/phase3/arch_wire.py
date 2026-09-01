"""The candidate policy-worker wire format, and the only two functions that
may cross an architecture boundary.

This module is the *specification* of what a policy worker is allowed to be
told and allowed to answer. It is deliberately separate from the driver so
that both the parent and the worker import the same bytes, and so that the
"does the boundary leak the answer key" test has a single object to inspect.

Two rules, both enforced by code below rather than by prose:

1. **Field-by-field, never ``asdict``.** ``dataclasses.asdict`` on
   ``DecisionContext`` would faithfully carry across whatever a future field
   happens to hold, which is exactly how ``task_kind`` or an attack reference
   arrives by accident. The same discipline ``report/result.py`` applies to
   the artifact is applied here to the boundary.

2. **The key set is closed and asserted.** ``WIRE_CONTEXT_KEYS`` is checked
   against the live dataclass on import. Adding a field to
   ``DecisionContext`` without deciding whether it crosses the boundary is a
   hard error, not a silent widening.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from interpose.policy.types import (
    ActionView,
    Decision,
    DecisionContext,
    Effect,
    PrincipalView,
    PriorDecision,
    ProvenanceView,
    ReaderView,
    ResourceView,
    SinkView,
    SourceView,
)
from interpose.provenance import Classification, TrustClass

__all__ = [
    "WIRE_CONTEXT_KEYS",
    "FORBIDDEN_WIRE_SUBSTRINGS",
    "context_from_wire",
    "context_to_wire",
    "decision_from_wire",
    "decision_to_wire",
    "assert_wire_is_closed",
]

#: Exactly the fields of ``DecisionContext``. Nothing else may travel.
WIRE_CONTEXT_KEYS = frozenset(
    {"step", "principal", "action", "provenance", "resource", "sink", "history", "user_task"}
)

#: Substrings that must never appear in a wire key at any depth. Same list the
#: shipped fairness test applies to the dataclass; applied here to the
#: serialised payload, which is the new surface a worker introduces.
FORBIDDEN_WIRE_SUBSTRINGS = (
    "attack",
    "objective",
    "adversary",
    "is_attack",
    "task_kind",
    "injection",
    "malicious",
    "seed",
    "scorer",
    "expected",
    "benign",
    "verdict",
    "outcome",
    "exposure",
    "canary",
    "detector",
)


def assert_wire_is_closed() -> None:
    """The boundary may not widen without someone deciding that it should."""
    live = {f.name for f in dataclasses.fields(DecisionContext)}
    if live != set(WIRE_CONTEXT_KEYS):
        raise AssertionError(
            "DecisionContext fields changed; the worker wire format must be "
            f"re-reviewed. added={sorted(live - WIRE_CONTEXT_KEYS)} "
            f"removed={sorted(WIRE_CONTEXT_KEYS - live)}"
        )


assert_wire_is_closed()


# -- context -> wire -------------------------------------------------------


def _source_to_wire(s: SourceView) -> dict[str, Any]:
    return {
        "unit_id": s.unit_id,
        "resource_uri": s.resource_uri,
        "trust": s.trust.value,
        "classification": s.classification.value,
        "readers": list(s.readers),
    }


def _principal_to_wire(p: PrincipalView) -> dict[str, Any]:
    return {
        "id": p.id,
        "kind": p.kind,
        "clearance": p.clearance.value,
        "roles": list(p.roles),
        # frozenset has no JSON form. Sorted, so the payload is canonical; the
        # reader below must restore the *type*, not just the members.
        "granted_tools": sorted(p.granted_tools),
        "on_behalf_of": p.on_behalf_of,
        "on_behalf_of_clearance": p.on_behalf_of_clearance.value,
    }


def _resource_to_wire(r: ResourceView | None) -> dict[str, Any] | None:
    if r is None:
        return None
    return {
        "uri": r.uri,
        "kind": r.kind,
        "classification": r.classification.value,
        "owner_principal_id": r.owner_principal_id,
        "readers": list(r.readers),
        "path": r.path,
    }


def _sink_to_wire(s: SinkView | None) -> dict[str, Any] | None:
    if s is None:
        return None
    return {
        "id": s.id,
        "readers": [{"id": r.id, "clearance": r.clearance.value} for r in s.readers],
    }


def context_to_wire(ctx: DecisionContext) -> dict[str, Any]:
    return {
        "step": ctx.step,
        "principal": _principal_to_wire(ctx.principal),
        "action": {
            "tool": ctx.action.tool,
            # Model-authored free text and numbers. JSON-native by assumption;
            # ``canonical_json(allow_nan=False)`` in the driver is what turns
            # that assumption into a check.
            "arguments": dict(ctx.action.arguments),
            "effect_class": ctx.action.effect_class,
        },
        "provenance": {
            "value_sources": [_source_to_wire(s) for s in ctx.provenance.value_sources],
            "context_sources": [_source_to_wire(s) for s in ctx.provenance.context_sources],
        },
        "resource": _resource_to_wire(ctx.resource),
        "sink": _sink_to_wire(ctx.sink),
        "history": [
            {"step": h.step, "tool": h.tool, "effect": h.effect.value, "rule_id": h.rule_id}
            for h in ctx.history
        ],
        "user_task": ctx.user_task,
    }


# -- wire -> context -------------------------------------------------------


def _source_from_wire(d: dict[str, Any]) -> SourceView:
    return SourceView(
        unit_id=d["unit_id"],
        resource_uri=d["resource_uri"],
        trust=TrustClass(d["trust"]),
        classification=Classification(d["classification"]),
        readers=tuple(d["readers"]),
    )


def context_from_wire(d: dict[str, Any]) -> DecisionContext:
    extra = set(d) - set(WIRE_CONTEXT_KEYS)
    if extra:
        raise ValueError(f"wire payload carries fields the policy may not see: {sorted(extra)}")
    p = d["principal"]
    r = d["resource"]
    s = d["sink"]
    return DecisionContext(
        step=d["step"],
        principal=PrincipalView(
            id=p["id"],
            kind=p["kind"],
            clearance=Classification(p["clearance"]),
            roles=tuple(p["roles"]),
            granted_tools=frozenset(p["granted_tools"]),
            on_behalf_of=p["on_behalf_of"],
            on_behalf_of_clearance=Classification(p["on_behalf_of_clearance"]),
        ),
        action=ActionView(
            tool=d["action"]["tool"],
            arguments=dict(d["action"]["arguments"]),
            effect_class=d["action"]["effect_class"],
        ),
        provenance=ProvenanceView(
            value_sources=tuple(_source_from_wire(x) for x in d["provenance"]["value_sources"]),
            context_sources=tuple(
                _source_from_wire(x) for x in d["provenance"]["context_sources"]
            ),
        ),
        resource=None
        if r is None
        else ResourceView(
            uri=r["uri"],
            kind=r["kind"],
            classification=Classification(r["classification"]),
            owner_principal_id=r["owner_principal_id"],
            readers=tuple(r["readers"]),
            path=r["path"],
        ),
        sink=None
        if s is None
        else SinkView(
            id=s["id"],
            readers=tuple(
                ReaderView(id=x["id"], clearance=Classification(x["clearance"]))
                for x in s["readers"]
            ),
        ),
        history=tuple(
            PriorDecision(
                step=h["step"], tool=h["tool"], effect=Effect(h["effect"]), rule_id=h["rule_id"]
            )
            for h in d["history"]
        ),
        user_task=d["user_task"],
    )


# -- decision --------------------------------------------------------------


def decision_to_wire(dec: Decision) -> dict[str, Any]:
    return {
        "effect": dec.effect.value,
        "rule_id": dec.rule_id,
        "reason": dec.reason,
        "metadata": dict(dec.metadata),
    }


def decision_from_wire(d: dict[str, Any]) -> Decision:
    return Decision(
        effect=Effect(d["effect"]),
        rule_id=d["rule_id"],
        reason=d["reason"],
        metadata=dict(d["metadata"]),
    )
