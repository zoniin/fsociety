"""Cedar-backed SecurityPolicy adapters for Interpose. Research prototype.

Read-only with respect to the interpose package: nothing here is imported by it.
"""
from __future__ import annotations

import hashlib

from cedarpy import Decision as CedarDecision
from cedarpy import PolicySet, is_authorized

from interpose.policy.types import ALLOW, DENY, Decision, DecisionContext, SourceView

LEVELS = ["public", "internal", "confidential", "restricted"]

READ_TOOLS = {
    "search_documents",
    "read_document",
    "get_employee_profile",
    "read_internal_file",
}


def _ref(t, i):
    return {"__entity": {"type": t, "id": i}}


def _level_entities():
    out = []
    for i, lvl in enumerate(LEVELS):
        parents = [{"type": "Level", "id": LEVELS[i + 1]}] if i + 1 < len(LEVELS) else []
        out.append({"uid": {"type": "Level", "id": lvl}, "attrs": {}, "parents": parents})
    return out


def _principal_entity(pid, clearance, kind="unknown"):
    return {
        "uid": {"type": "Principal", "id": pid},
        "attrs": {"clearance": _ref("Level", clearance), "kind": kind},
        "parents": [],
    }


CORE_POLICIES = """
@id("R1.tool-granted")
permit (principal, action in Action::"granted", resource);

@id("P0.entitlement-probe-baseline")
permit (principal, action == Action::"probeRead", resource);

@id("R2.not-in-reader-set")
forbid (principal, action in Action::"anyRead", resource)
when { resource.hasReaderList && !resource.readers.contains(context.onBehalfOf) };

@id("R2.insufficient-clearance.agent")
forbid (principal, action in Action::"anyRead", resource)
when { !resource.hasReaderList && !(resource.classification in context.effective.clearance) };

@id("R2.insufficient-clearance.delegated")
forbid (principal, action in Action::"anyRead", resource)
when { !resource.hasReaderList && !(resource.classification in context.onBehalfOf.clearance) };
"""

STRICT_EXTRA = """
@id("A4.external-sink")
forbid (principal, action in Action::"anyWrite", resource)
when { resource.hasExternalReader };
"""

SESSION_TAINT_EXTRA = """
@id("A5.session-taint")
forbid (principal, action in Action::"anyWrite", resource)
when { resource.hasExternalReader && context.sessionReadPrivileged };
"""

DOC_ATTEMPT2 = """
@id("R1.tool-granted")
permit (principal, action in Action::"granted", resource);

@id("R3.doc-attempt2")
forbid (principal, action in Action::"anyWrite", resource)
when { !context.source.readers.containsAll(resource.readers) };
"""


class _CedarBase:
    _policy_text = CORE_POLICIES

    def __init__(self):
        self._pset = PolicySet.from_str(self._policy_text)
        self.cedar_calls = 0

    def digest(self):
        h = hashlib.sha256()
        h.update(type(self).__name__.encode())
        h.update(self._policy_text.encode())
        return h.hexdigest()

    def _base_entities(self, ctx: DecisionContext):
        ents = _level_entities()
        p = ctx.principal
        ents.append(_principal_entity(p.id, p.clearance.value, p.kind))
        seen = {p.id}
        if p.on_behalf_of not in seen:
            ents.append(_principal_entity(p.on_behalf_of, p.on_behalf_of_clearance.value, "human"))
            seen.add(p.on_behalf_of)
        if ctx.sink is not None:
            for r in ctx.sink.readers:
                if r.id not in seen:
                    ents.append(_principal_entity(r.id, r.clearance.value))
                    seen.add(r.id)
        pools = [ctx.provenance.value_sources, ctx.provenance.context_sources]
        for coll in pools:
            for s in coll:
                for rid in s.readers:
                    if rid not in seen:
                        ents.append(_principal_entity(rid, "restricted"))
                        seen.add(rid)
        if ctx.resource is not None:
            for rid in ctx.resource.readers:
                if rid not in seen:
                    ents.append(_principal_entity(rid, "restricted"))
                    seen.add(rid)
        ents.append({"uid": {"type": "Action", "id": "anyRead"}, "attrs": {}, "parents": []})
        ents.append({"uid": {"type": "Action", "id": "anyWrite"}, "attrs": {}, "parents": []})
        ents.append({"uid": {"type": "Action", "id": "granted"}, "attrs": {}, "parents": []})
        ents.append({"uid": {"type": "Action", "id": "probeRead"}, "attrs": {},
                     "parents": [{"type": "Action", "id": "anyRead"}]})
        tools = set(p.granted_tools) | {ctx.action.tool}
        for t in sorted(tools):
            parents = []
            if t in p.granted_tools:
                parents.append({"type": "Action", "id": "granted"})
            if t in READ_TOOLS:
                parents.append({"type": "Action", "id": "anyRead"})
            else:
                parents.append({"type": "Action", "id": "anyWrite"})
            ents.append({"uid": {"type": "Action", "id": t}, "attrs": {}, "parents": parents})
        return ents

    def _resource_entity(self, ctx: DecisionContext):
        r = ctx.resource
        if r is None:
            return []
        return [{
            "uid": {"type": "Resource", "id": r.uri},
            "attrs": {
                "classification": _ref("Level", r.classification.value),
                "hasReaderList": bool(r.readers),
                "readers": [_ref("Principal", x) for x in r.readers],
                "hasExternalReader": False,
                "minReaderClearance": _ref("Level", "public"),
                "path": r.path or "",
                "kind": r.kind,
            },
            "parents": [],
        }]

    def _sink_entity(self, ctx: DecisionContext):
        s = ctx.sink
        if s is None:
            return []
        min_lvl = s.min_reader_clearance.value if s.readers else "restricted"
        return [{
            "uid": {"type": "Resource", "id": "sink:" + s.id},
            "attrs": {
                "readers": [_ref("Principal", r.id) for r in s.readers],
                "hasReaderList": True,
                "classification": _ref("Level", "public"),
                "minReaderClearance": _ref("Level", min_lvl),
                "hasExternalReader": any(r.clearance.value == "public" for r in s.readers),
                "path": "",
                "kind": "queue",
            },
            "parents": [],
        }]

    def _null_resource(self):
        return {
            "uid": {"type": "Resource", "id": "none"},
            "attrs": {
                "classification": _ref("Level", "public"),
                "hasReaderList": False,
                "readers": [],
                "hasExternalReader": False,
                "minReaderClearance": _ref("Level", "public"),
                "path": "",
                "kind": "none",
            },
            "parents": [],
        }

    def _source_entity(self, src: SourceView):
        return {
            "uid": {"type": "Resource", "id": src.resource_uri},
            "attrs": {
                "classification": _ref("Level", src.classification.value),
                "hasReaderList": bool(src.readers),
                "readers": [_ref("Principal", x) for x in src.readers],
                "hasExternalReader": False,
                "minReaderClearance": _ref("Level", "public"),
                "path": "",
                "kind": "source",
            },
            "parents": [],
        }

    def _ask(self, req, ents):
        self.cedar_calls += 1
        res = is_authorized(req, self._pset, ents)
        errs = [" ".join(e.split()) for e in (getattr(res.diagnostics, "errors", []) or [])]
        if errs:
            raise RuntimeError("cedar evaluation error: " + "; ".join(errs))
        reasons = list(getattr(res.diagnostics, "reasons", []) or [])
        return res.decision == CedarDecision.Allow, reasons

    def _target(self, ctx: DecisionContext, ents):
        if ctx.resource is not None:
            return ctx.resource.uri
        if ctx.sink is not None:
            return "sink:" + ctx.sink.id
        ents.append(self._null_resource())
        return "none"

    def _invoke_request(self, ctx: DecisionContext, uid, extra=None):
        p = ctx.principal
        context = {
            "effective": _ref("Principal", p.id),
            "onBehalfOf": _ref("Principal", p.on_behalf_of),
        }
        if extra:
            context.update(extra)
        return {
            "principal": {"type": "Principal", "id": p.id},
            "action": {"type": "Action", "id": ctx.action.tool},
            "resource": {"type": "Resource", "id": uid},
            "context": context,
        }


class CedarActionOnly(_CedarBase):
    id = "cedar-action-only"
    version = "0.1.0"
    _policy_text = CORE_POLICIES

    def describe(self):
        return ("Cedar PDP: tool grant, object-level read authorization, "
                "delegation ceiling. No provenance.")

    def _extra_context(self, ctx):
        return None

    def evaluate(self, ctx: DecisionContext) -> Decision:
        ents = self._base_entities(ctx) + self._resource_entity(ctx) + self._sink_entity(ctx)
        uid = self._target(ctx, ents)
        ok, reasons = self._ask(self._invoke_request(ctx, uid, self._extra_context(ctx)), ents)
        if ok:
            return Decision(ALLOW, "cedar.permit", "Cedar Allow " + ",".join(reasons))
        return Decision(DENY, "cedar.deny",
                        "Cedar Deny on " + ctx.action.tool + " -> " + uid,
                        metadata={"cedar_reasons": reasons})


class CedarActionOnlyStrict(CedarActionOnly):
    id = "cedar-action-only-strict"
    version = "0.1.0"
    _policy_text = CORE_POLICIES + STRICT_EXTRA

    def describe(self):
        return "cedar-action-only plus a blanket ban on writes to externally-readable sinks."


class CedarSessionTaint(CedarActionOnly):
    """One-bit session taint from ctx.history. NOT provenance: resource-blind."""

    id = "cedar-session-taint"
    version = "0.1.0"
    _policy_text = CORE_POLICIES + SESSION_TAINT_EXTRA

    def describe(self):
        return ("cedar-action-only plus a one-bit session flag: any prior permitted "
                "privileged read blocks later writes to externally-readable sinks.")

    def _extra_context(self, ctx):
        flag = any(d.tool in ("read_internal_file", "read_document") and d.effect is ALLOW
                   for d in ctx.history)
        return {"sessionReadPrivileged": flag}


class CedarWithProvenance(_CedarBase):
    id = "cedar-with-provenance"
    version = "0.1.0"
    _policy_text = CORE_POLICIES

    def describe(self):
        return ("Cedar PDP; egress decomposed into one Cedar read-entitlement query "
                "per (tainted source, sink reader) pair.")

    def evaluate(self, ctx: DecisionContext) -> Decision:
        base = self._base_entities(ctx) + self._resource_entity(ctx) + self._sink_entity(ctx)
        uid = self._target(ctx, base)
        ok, reasons = self._ask(self._invoke_request(ctx, uid), base)
        if not ok:
            return Decision(DENY, "cedar.deny",
                            "Cedar Deny on " + ctx.action.tool + " -> " + uid,
                            metadata={"cedar_reasons": reasons})

        if ctx.sink is None or ctx.action.effect_class not in ("write", "irreversible"):
            return Decision(ALLOW, "cedar.permit", "Cedar Allow " + ",".join(reasons))

        for src in ctx.provenance.value_sources:
            ents = base + [self._source_entity(src)]
            for rdr in ctx.sink.readers:
                req = {
                    "principal": {"type": "Principal", "id": rdr.id},
                    "action": {"type": "Action", "id": "probeRead"},
                    "resource": {"type": "Resource", "id": src.resource_uri},
                    "context": {"effective": _ref("Principal", rdr.id),
                                "onBehalfOf": _ref("Principal", rdr.id)},
                }
                allowed, why = self._ask(req, ents)
                if not allowed:
                    return Decision(
                        DENY, "R3.egress-to-unentitled-reader",
                        ("write carries " + src.classification.value + " data from "
                         + src.resource_uri + " into sink " + ctx.sink.id
                         + ", readable by " + rdr.id + " -- Cedar denies that read"),
                        metadata={"sink": ctx.sink.id, "source": src.resource_uri,
                                  "unentitled_readers": [rdr.id], "cedar_reasons": why},
                    )
        return Decision(ALLOW, "cedar.permit",
                        "tool granted, object authorized, no egress violation")


class CedarDocAttempt2(_CedarBase):
    """Reproduction of docs/CEDAR-AND-ISOLATION.md attempt 2."""

    id = "cedar-doc-attempt2"
    version = "0.1.0"
    _policy_text = DOC_ATTEMPT2

    def describe(self):
        return "docs/CEDAR-AND-ISOLATION.md attempt 2: one forbid, one tainted source per request."

    _R1_ONLY = PolicySet.from_str(
        '@id("R1.tool-granted")\npermit (principal, action in Action::"granted", resource);'
    )

    def evaluate(self, ctx: DecisionContext) -> Decision:
        base = self._base_entities(ctx) + self._resource_entity(ctx) + self._sink_entity(ctx)
        uid = self._target(ctx, base)
        # R1 alone, with the R3 rule out of the policy set, so the wrapper does
        # not contaminate the reproduction.
        self.cedar_calls += 1
        r1 = is_authorized(self._invoke_request(ctx, uid), self._R1_ONLY, base)
        if r1.decision != CedarDecision.Allow:
            return Decision(DENY, "cedar.deny", "R1: " + ctx.action.tool + " not granted")
        if ctx.sink is None or ctx.action.effect_class not in ("write", "irreversible"):
            return Decision(ALLOW, "cedar.permit", "R1 only; attempt 2 has no read rule")
        for src in ctx.provenance.value_sources:
            extra = {"source": {"readers": [_ref("Principal", x) for x in src.readers]}}
            ok, reasons = self._ask(self._invoke_request(ctx, uid, extra), base)
            if not ok:
                return Decision(DENY, "R3.doc-attempt2",
                                "attempt-2 forbid fired for source " + src.resource_uri,
                                metadata={"source": src.resource_uri,
                                          "source_readers": list(src.readers),
                                          "sink": ctx.sink.id})
        return Decision(ALLOW, "cedar.permit", "no attempt-2 forbid fired")
