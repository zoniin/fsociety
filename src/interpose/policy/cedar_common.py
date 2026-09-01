"""Cedar as the decision engine: the encoding both ablation arms share.

This module exists so that ``cedar-action-only`` and ``cedar-with-provenance``
can be *byte-identical* everywhere except one thing. They share this policy
text, this schema, this entity encoding, this fail-closed rule and this base
class. The only difference between them is whether the enforcement point
issues the entitlement probes of :mod:`~interpose.policy.cedar_with_provenance`.

That is the whole design. An ablation whose two arms differ in their policy
text cannot distinguish "provenance helped" from "the other policy was worse",
and the second explanation is always available to a sceptic. Here it is not:
:data:`CEDAR_POLICIES` is loaded unchanged by both arms, and a test asserts it.

What Cedar is given
-------------------

Everything a stateless per-request PDP could see, and nothing else:

* the principal, its clearance, and the human it acts for, as entities;
* the action, as one Cedar ``Action`` per tool, grouped under
  ``Action::"granted"`` -- the shape AWS Bedrock AgentCore Policy uses;
* the resolved resource, with its classification, its reader allowlist, its
  path and its queue readership, as entity attributes;
* the call's own arguments, as ``context.argumentKeys`` and
  ``context.argumentText`` -- the analogue of AgentCore's ``context.input``.

The arguments are supplied and **no rule reads them**, deliberately, and the
reason is worth stating because it looks like a gap. Cedar's only string
matcher is ``like``, which supports ``*`` and nothing else: no character
classes, no alternation, no case folding. It cannot express a pattern-based
DLP rule. What it *can* express is a fixed keyword list, and choosing keywords
that catch this corpus would be selecting on the answer key, which the fairness
contract in :mod:`interpose.policy.types` forbids. So the fact is provided, the
policy is not starved, and the absence of an argument rule is a finding about
Cedar rather than a handicap imposed on it.

What Cedar is not given, in the action-only arm, is any statement about where
an argument's *content* came from. That is the independent variable.

Failing closed
--------------

Cedar skips a policy whose condition errors. A ``forbid`` whose condition
errors is therefore silently not applied, and the request falls through to
whatever ``permit`` matched. A single misspelled context key in the
enforcement point turns the egress rule into a no-op that returns ``Allow``,
and the only trace is a diagnostics entry most callers never read.

Two mitigations are applied here, and both are needed:

* Every provenance-reading rule is guarded by ``context has ...``, which
  converts a *missing* or *misspelled* key into a deny. Measured: it does not
  help when the key is present with the wrong type.
* Every request is evaluated against :func:`schema_json`. A request whose
  context does not match the declared shape returns ``NoDecision``, which
  covers the wrong-type case as well.

:meth:`_CedarAdapter._ask` then treats ``NoDecision``, any diagnostics error,
and any exception raised by the binding as **deny**. Nothing reaches an
``Allow`` except a request Cedar validated and evaluated without error.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from ..errors import PolicyLoadError
from ..provenance import Classification
from .types import ALLOW, DENY, Decision, DecisionContext, ReaderView, SourceView

__all__ = ["CEDAR_POLICIES", "STRICT_EXTERNAL_SINK_RULE", "schema_json"]

#: The classification lattice, weakest first. Modelled in Cedar as an entity
#: parent chain, so ``Level::"internal" in Level::"confidential"`` is decided by
#: Cedar walking its own hierarchy rather than by ranks computed here. A schema
#: forces this encoding: entities have no ordering, so ``>`` does not typecheck.
LEVELS: tuple[str, ...] = ("public", "internal", "confidential", "restricted")

#: Cedar policy text. Identical for both ablation arms.
#:
#: R1 and R2 are the reference policy's first two rules, expressed natively.
#: R3 has no counterpart here that quantifies over sources -- Cedar has no
#: iteration construct at all -- so the egress rule appears only as
#: ``R3.probe-integrity``, which does not decide egress. It checks that each
#: entitlement probe the enforcement point submits is drawn from the provenance
#: the enforcement point declared, so a point that narrowed or fabricated its
#: pair set would be denied rather than believed.
CEDAR_POLICIES = """
@id("R1.tool-granted")
permit (principal, action in Action::"granted", resource);

@id("P0.entitlement-probe-baseline")
permit (principal, action == Action::"probeRead", resource);

@id("R2.not-in-reader-set")
forbid (principal, action, resource)
when {
  context.effectClass == "read"
  && resource.hasReaderList
  && !resource.readers.contains(context.onBehalfOf)
};

@id("R2.insufficient-clearance.agent")
forbid (principal, action, resource)
when {
  context.effectClass == "read"
  && !resource.hasReaderList
  && !(resource.classification in context.effective.clearance)
};

@id("R2.insufficient-clearance.delegated")
forbid (principal, action, resource)
when {
  context.effectClass == "read"
  && !resource.hasReaderList
  && !(resource.classification in context.onBehalfOf.clearance)
};

@id("R3.probe-integrity")
forbid (principal, action == Action::"probeRead", resource)
when {
  !(context has taintedSources)
  || !(context has sinkReaders)
  || !(context.taintedSources.contains(resource))
  || !(context.sinkReaders.contains(principal))
};
"""

#: The rule an ordinary gateway operator would actually write on the write
#: side: refuse every write to a queue an outsider can read. It contains both
#: bundled scenarios without any provenance, and it refuses legitimate vendor
#: correspondence to do it. Shipped unregistered, as the measured answer to
#: "is ``cedar-action-only`` a strawman?" -- see the ablation document.
STRICT_EXTERNAL_SINK_RULE = """
@id("A4.external-sink")
forbid (principal, action, resource)
when { context.effectClass != "read" && resource.hasExternalReader };
"""

#: Cedar annotation id -> the rule vocabulary the reference policy publishes,
#: so a row of this ablation can be compared to a row of that one on rule
#: identity and not merely on effect.
_RULE_ALIAS: dict[str, str] = {
    "R2.insufficient-clearance.agent": "R2.insufficient-clearance",
    "R2.insufficient-clearance.delegated": "R2.insufficient-clearance",
}

#: Emitted when no ``permit`` matched. The only permits in
#: :data:`CEDAR_POLICIES` are the tool grant and the probe baseline, so on an
#: invocation request a reason-less deny is exactly "this tool is not granted".
_DENY_BY_DEFAULT = "R1.tool-not-granted"

_ANNOTATION = re.compile(r'@id\("([^"]+)"\)')

_CEDARPY: Any = None


def _cedar() -> Any:
    """Import ``cedarpy`` on first use, or explain how to install it.

    Deferred rather than top-level because the adapters are registered in
    ``BUILTIN_POLICIES``, and ``interpose ls policies``, ``interpose freeze``
    and the freeze self-test all load every registered policy. Those must keep
    working on the two-dependency default install; only *running* a Cedar
    policy needs the extra.
    """
    global _CEDARPY
    if _CEDARPY is None:
        try:
            import cedarpy
        except ImportError as exc:  # pragma: no cover - exercised by the extra-less job
            raise PolicyLoadError(
                "the Cedar policy adapters need the optional 'cedar' extra, which "
                "is not installed. Install it with:  pip install interpose[cedar]"
            ) from exc
        _CEDARPY = cedarpy
    return _CEDARPY


# --------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------

_CTX_INVOKE: dict[str, Any] = {
    "type": "Record",
    "attributes": {
        "effective": {"type": "Entity", "name": "Principal"},
        "onBehalfOf": {"type": "Entity", "name": "Principal"},
        "effectClass": {"type": "String"},
        "argumentKeys": {"type": "Set", "element": {"type": "String"}},
        "argumentText": {"type": "String"},
    },
}

_CTX_PROBE: dict[str, Any] = {
    "type": "Record",
    "attributes": {
        "effective": {"type": "Entity", "name": "Principal"},
        "onBehalfOf": {"type": "Entity", "name": "Principal"},
        "effectClass": {"type": "String"},
        "taintedSources": {"type": "Set", "element": {"type": "Entity", "name": "Resource"}},
        "sinkReaders": {"type": "Set", "element": {"type": "Entity", "name": "Principal"}},
    },
}

_ENTITY_TYPES: dict[str, Any] = {
    "Level": {"memberOfTypes": ["Level"]},
    "Principal": {
        "shape": {
            "type": "Record",
            "attributes": {
                "clearance": {"type": "Entity", "name": "Level"},
                "kind": {"type": "String"},
            },
        }
    },
    "Resource": {
        "shape": {
            "type": "Record",
            "attributes": {
                "classification": {"type": "Entity", "name": "Level"},
                "hasReaderList": {"type": "Boolean"},
                "readers": {"type": "Set", "element": {"type": "Entity", "name": "Principal"}},
                "hasExternalReader": {"type": "Boolean"},
                "path": {"type": "String"},
                "kind": {"type": "String"},
            },
        }
    },
}


def schema_json(tools: tuple[str, ...], granted: frozenset[str]) -> dict[str, Any]:
    """The Cedar schema for one decision's action vocabulary.

    Tool names come from the scenario, so the action list cannot be static;
    it is rebuilt per distinct ``(tools, granted)`` pair and cached. Every
    other part of the schema is fixed.

    Modelling note, stated because it is a simplification and not a claim:
    the grant is encoded as membership of the ``granted`` action group, which
    makes it a property of the action rather than of the principal. That is
    sound here because the harness runs one principal per episode. A
    deployment with several roles would hang grants off principal-side role
    entities instead; Cedar expresses that natively and it changes nothing
    measured below.
    """
    applies_invoke = {
        "principalTypes": ["Principal"],
        "resourceTypes": ["Resource"],
        "context": _CTX_INVOKE,
    }
    actions: dict[str, Any] = {
        "granted": {},
        "probeRead": {
            "appliesTo": {
                "principalTypes": ["Principal"],
                "resourceTypes": ["Resource"],
                "context": _CTX_PROBE,
            }
        },
    }
    for tool in tools:
        entry: dict[str, Any] = {"appliesTo": applies_invoke}
        if tool in granted:
            entry["memberOf"] = [{"id": "granted"}]
        actions[tool] = entry
    return {"": {"entityTypes": _ENTITY_TYPES, "actions": actions}}


# --------------------------------------------------------------------------
# entity encoding
# --------------------------------------------------------------------------


def _ref(entity_type: str, entity_id: str) -> dict[str, Any]:
    return {"__entity": {"type": entity_type, "id": entity_id}}


def _uid(entity_type: str, entity_id: str) -> dict[str, str]:
    return {"type": entity_type, "id": entity_id}


def _level_entities() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for index, level in enumerate(LEVELS):
        parents = [_uid("Level", LEVELS[index + 1])] if index + 1 < len(LEVELS) else []
        out.append({"uid": _uid("Level", level), "attrs": {}, "parents": parents})
    return out


def _principal(pid: str, clearance: str, kind: str) -> dict[str, Any]:
    return {
        "uid": _uid("Principal", pid),
        "attrs": {"clearance": _ref("Level", clearance), "kind": kind},
        "parents": [],
    }


def _resource(
    uri: str,
    *,
    classification: str,
    readers: tuple[str, ...],
    kind: str,
    path: str = "",
    has_external_reader: bool = False,
) -> dict[str, Any]:
    return {
        "uid": _uid("Resource", uri),
        "attrs": {
            "classification": _ref("Level", classification),
            "hasReaderList": bool(readers),
            "readers": [_ref("Principal", r) for r in readers],
            "hasExternalReader": has_external_reader,
            "path": path,
            "kind": kind,
        },
        "parents": [],
    }


#: Identifier of the synthetic resource used when a call resolves to no object.
NULL_RESOURCE = "urn:interpose:unresolved"


@dataclass(frozen=True)
class _Answer:
    """One Cedar authorization result, already collapsed to fail-closed form."""

    allowed: bool
    rule: str
    cedar_rule: str
    reasons: tuple[str, ...]
    errors: tuple[str, ...]
    fail_closed: bool


class _CedarAdapter:
    """Shared enforcement point. Subclasses differ only in what they ask.

    Instances carry ``cedar_calls``, a counter of authorization requests
    issued. It is telemetry for the ablation and is never read by a rule, so
    the decision function stays a pure function of the context it is given.
    """

    id = "cedar-base"
    version = "0.1.0"
    _policy_text: str = CEDAR_POLICIES

    def __init__(self) -> None:
        self._policy_set: Any = None
        self._schema_cache: dict[tuple[str, ...], Any] = {}
        self._rule_ids: tuple[str, ...] = tuple(_ANNOTATION.findall(self._policy_text))
        self.cedar_calls = 0

    def describe(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    def evaluate(self, ctx: DecisionContext) -> Decision:  # pragma: no cover - overridden
        raise NotImplementedError

    # -- engine ----------------------------------------------------------

    def _policies(self) -> Any:
        if self._policy_set is None:
            self._policy_set = _cedar().PolicySet.from_str(self._policy_text)
        return self._policy_set

    def _schema(self, ctx: DecisionContext) -> Any:
        """A parsed ``Schema`` handle for this decision's action vocabulary.

        Cached and pre-parsed: passing the JSON text re-parses the schema on
        every authorization request, which on this corpus is most of the cost
        of a decision.
        """
        granted = frozenset(ctx.principal.granted_tools)
        tools = tuple(sorted(granted | {ctx.action.tool}))
        key = (ctx.action.tool, *tools)
        cached = self._schema_cache.get(key)
        if cached is None:
            text = json.dumps(schema_json(tools, granted), sort_keys=True)
            cached = _cedar().Schema.from_json_str(text)
            self._schema_cache[key] = cached
        return cached

    def _rule_for(self, index_name: str) -> str:
        """Map Cedar's positional policy id back to its ``@id`` annotation."""
        if not index_name.startswith("policy"):
            return index_name
        try:
            index = int(index_name.removeprefix("policy"))
        except ValueError:  # pragma: no cover - defensive
            return index_name
        if 0 <= index < len(self._rule_ids):
            return self._rule_ids[index]
        return index_name  # pragma: no cover - defensive

    def _ask(self, request: dict[str, Any], entities: list[dict[str, Any]], schema: Any) -> _Answer:
        """One Cedar authorization request, collapsed to a fail-closed answer.

        ``NoDecision``, a non-empty diagnostics error list, and any exception
        raised by the binding all become deny. There is no path from a
        malformed request to an allow.
        """
        self.cedar_calls += 1
        cedar = _cedar()
        try:
            result = cedar.is_authorized(request, self._policies(), entities, schema)
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}"
            return _Answer(False, "cedar.fail-closed", "", (), (detail,), True)

        errors = tuple(
            " ".join(str(e).split()) for e in (getattr(result.diagnostics, "errors", None) or ())
        )
        reasons = tuple(str(r) for r in (getattr(result.diagnostics, "reasons", None) or ()))
        decided = result.decision in (cedar.Decision.Allow, cedar.Decision.Deny)
        if errors or not decided:
            return _Answer(False, "cedar.fail-closed", "", reasons, errors, True)
        if result.decision == cedar.Decision.Allow:
            return _Answer(True, "", "", reasons, errors, False)

        cedar_rule = self._rule_for(reasons[0]) if reasons else ""
        rule = _RULE_ALIAS.get(cedar_rule, cedar_rule) if cedar_rule else _DENY_BY_DEFAULT
        return _Answer(False, rule, cedar_rule, reasons, errors, False)

    def _fail_closed(self, answer: _Answer, where: str) -> Decision:
        return Decision(
            effect=DENY,
            rule_id="cedar.fail-closed",
            reason=(
                f"Cedar returned no usable decision for the {where} request; "
                "denying rather than falling through"
            ),
            metadata={"cedar_errors": list(answer.errors), "stage": where},
        )

    # -- entity store ----------------------------------------------------

    def _entities(self, ctx: DecisionContext) -> list[dict[str, Any]]:
        """Build the entity store for one decision.

        Keyed by uid so a source that is also the resolved resource appears
        once. Principals whose clearance the harness knows are added first, so
        a reader that appears both in a sink readership and in an allowlist
        keeps its real clearance rather than the placeholder below.
        """
        store: dict[tuple[str, str], dict[str, Any]] = {}

        def put(entity: dict[str, Any]) -> None:
            store.setdefault((entity["uid"]["type"], entity["uid"]["id"]), entity)

        for level in _level_entities():
            put(level)

        principal = ctx.principal
        put(_principal(principal.id, principal.clearance.value, principal.kind))
        put(
            _principal(
                principal.on_behalf_of, principal.on_behalf_of_clearance.value, "human"
            )
        )
        if ctx.sink is not None:
            for reader in ctx.sink.readers:
                put(_principal(reader.id, reader.clearance.value, "human"))

        # Principals that appear only inside an allowlist. The harness does not
        # publish a clearance for them, so they get the weakest one rather than
        # a fabricated grant. No rule reads it: they are never a request
        # principal, only a member of a `readers` set compared by identity.
        acl_only: list[str] = []
        if ctx.resource is not None:
            acl_only.extend(ctx.resource.readers)
        for pool in (ctx.provenance.value_sources, ctx.provenance.context_sources):
            for source in pool:
                acl_only.extend(source.readers)
        for pid in acl_only:
            put(_principal(pid, Classification.PUBLIC.value, "unknown"))

        for action in self._action_entities(ctx):
            put(action)

        if ctx.resource is not None:
            resource = ctx.resource
            put(
                _resource(
                    resource.uri,
                    classification=resource.classification.value,
                    readers=resource.readers,
                    kind=resource.kind,
                    path=resource.path or "",
                )
            )
        if ctx.sink is not None:
            put(self._sink_entity(ctx.sink))
        put(
            _resource(
                NULL_RESOURCE, classification=Classification.PUBLIC.value, readers=(), kind="none"
            )
        )
        return list(store.values())

    @staticmethod
    def _sink_entity(sink: Any) -> dict[str, Any]:
        """The destination queue, as an object with a readership.

        ``hasExternalReader`` is denormalized static metadata about the queue --
        the sort of flag a real system stores on the queue record -- and not a
        per-request computation over the provenance. No rule in
        :data:`CEDAR_POLICIES` reads it; only the unregistered strict variant
        does.
        """
        readers: tuple[ReaderView, ...] = tuple(sink.readers)
        return _resource(
            _sink_uri(sink.id),
            classification=Classification.PUBLIC.value,
            readers=tuple(r.id for r in readers),
            kind="queue",
            has_external_reader=any(r.clearance is Classification.PUBLIC for r in readers),
        )

    def _action_entities(self, ctx: DecisionContext) -> list[dict[str, Any]]:
        granted = frozenset(ctx.principal.granted_tools)
        out: list[dict[str, Any]] = [
            {"uid": _uid("Action", "granted"), "attrs": {}, "parents": []},
            {"uid": _uid("Action", "probeRead"), "attrs": {}, "parents": []},
        ]
        for tool in sorted(granted | {ctx.action.tool}):
            parents = [_uid("Action", "granted")] if tool in granted else []
            out.append({"uid": _uid("Action", tool), "attrs": {}, "parents": parents})
        return out

    def source_entity(self, source: SourceView) -> dict[str, Any]:
        return _resource(
            source.resource_uri,
            classification=source.classification.value,
            readers=source.readers,
            kind="source",
        )

    # -- requests --------------------------------------------------------

    def _target_uid(self, ctx: DecisionContext) -> str:
        if ctx.resource is not None:
            return ctx.resource.uri
        if ctx.sink is not None:
            return _sink_uri(ctx.sink.id)
        return NULL_RESOURCE

    def _invoke_request(self, ctx: DecisionContext) -> dict[str, Any]:
        principal = ctx.principal
        arguments = ctx.action.arguments
        return {
            "principal": _uid("Principal", principal.id),
            "action": _uid("Action", ctx.action.tool),
            "resource": _uid("Resource", self._target_uid(ctx)),
            "context": {
                "effective": _ref("Principal", principal.id),
                "onBehalfOf": _ref("Principal", principal.on_behalf_of),
                "effectClass": ctx.action.effect_class,
                "argumentKeys": sorted(str(k) for k in arguments),
                "argumentText": " ".join(f"{k}={arguments[k]}" for k in sorted(arguments)),
            },
        }

    def _allow(self, answer: _Answer) -> Decision:
        return Decision(
            effect=ALLOW,
            rule_id="R0.permitted",
            reason="Cedar returned Allow: tool granted and object authorized",
            metadata={"cedar_reasons": [self._rule_for(r) for r in answer.reasons]},
        )

    def _deny(self, ctx: DecisionContext, answer: _Answer) -> Decision:
        target = self._target_uid(ctx)
        return Decision(
            effect=DENY,
            rule_id=answer.rule,
            reason=(
                f"Cedar denied {ctx.action.tool} on {target} for principal "
                f"{ctx.principal.id} acting for {ctx.principal.on_behalf_of}"
            ),
            metadata={
                "cedar_rule": answer.cedar_rule,
                "resource": target,
                "cedar_reasons": [self._rule_for(r) for r in answer.reasons],
            },
        )


def _sink_uri(sink_id: str) -> str:
    return f"urn:interpose:sink:{sink_id}"
