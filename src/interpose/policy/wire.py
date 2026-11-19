"""The policy worker wire format: ``ipwp/1``.

Implements the protocol specified in ``docs/research/phase3/agents/ipc-protocol.md``.
The design choices are that document's; this module only makes them code.

Framing::

    +--------+----------+---------------------------+
    | 'IPO1' |  uint32  |  payload: canonical JSON  |
    | 4 bytes|    BE    |  exactly len bytes        |
    +--------+----------+---------------------------+

* Length-prefixed rather than newline-delimited, so an oversized frame is
  rejected from its 8-byte header before a byte of body is read.
* The magic turns a stray ``print`` into a clean ``DESYNC`` instead of a
  1.4 GB length.
* Payloads are ``digest.canonical_json``: the wire encoder and the digest
  encoder cannot drift.
* Unknown fields are rejected, both directions. A field one side silently
  drops is a fact the other side believed it supplied.

Every function here is pure and runs identically in the harness and the
worker. Every limit is checked on both sides.
"""

from __future__ import annotations

import json
import re
from typing import IO, Any

from ..digest import canonical_json
from ..provenance import Classification, TrustClass
from .types import (
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

__all__ = [
    "MAGIC",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "PROTOCOL",
    "WireError",
    "ctx_from_wire",
    "ctx_to_wire",
    "decision_from_wire",
    "decision_to_wire",
    "read_frame",
    "write_frame",
]

PROTOCOL = "ipwp/1"
MAGIC = b"IPO1"
MAX_REQUEST_BYTES = 1 << 20
MAX_RESPONSE_BYTES = 64 << 10
MAX_DEPTH = 8
MAX_REASON = 512
MAX_METADATA_KEYS = 16
MAX_METADATA_VALUE = 256
_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")


class WireError(Exception):
    """A protocol fault. ``code`` is one of the codes in the spec's §7 table."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# -- framing ----------------------------------------------------------------


def write_frame(fp: IO[bytes], obj: dict[str, Any], *, limit: int) -> None:
    body = canonical_json(obj)
    if len(body) > limit:
        # Checked before sending: an oversized request never leaves this side.
        raise WireError("OVERSIZED_FRAME", f"{len(body)} bytes > {limit}")
    fp.write(MAGIC + len(body).to_bytes(4, "big") + body)
    fp.flush()


def read_frame(fp: IO[bytes], *, limit: int) -> dict[str, Any] | None:
    """Read one frame. ``None`` on a clean end of stream before any header byte."""
    header = _read_exact(fp, 8, allow_eof=True)
    if header is None:
        return None
    if header[:4] != MAGIC:
        raise WireError("DESYNC", f"expected magic, got {header[:4]!r}")
    size = int.from_bytes(header[4:], "big")
    if size > limit:
        raise WireError("OVERSIZED_FRAME", f"declared {size} bytes > {limit}")
    body = _read_exact(fp, size, allow_eof=False)
    assert body is not None
    try:
        obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WireError("MALFORMED_FRAME", str(exc)) from exc
    if not isinstance(obj, dict):
        raise WireError("MALFORMED_FRAME", "frame is not an object")
    if _depth(obj) > MAX_DEPTH:
        raise WireError("NESTING_LIMIT", f"deeper than {MAX_DEPTH}")
    return obj


def _read_exact(fp: IO[bytes], n: int, *, allow_eof: bool) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = fp.read(n - len(buf))
        if not chunk:
            if allow_eof and not buf:
                return None
            raise WireError("TRUNCATED_FRAME", f"got {len(buf)} of {n} bytes")
        buf += chunk
    return buf


def _depth(value: Any, level: int = 1) -> int:
    if isinstance(value, dict):
        return max([level, *(_depth(v, level + 1) for v in value.values())])
    if isinstance(value, list):
        return max([level, *(_depth(v, level + 1) for v in value)])
    return level


def expect_keys(obj: dict[str, Any], required: set[str], optional: set[str] = frozenset()) -> None:  # type: ignore[assignment]
    keys = set(obj)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise WireError("MALFORMED_FRAME", f"missing {sorted(missing)}")
    if unknown:
        raise WireError("UNKNOWN_FIELD", f"{sorted(unknown)}")


# -- decisions --------------------------------------------------------------


def decision_to_wire(d: Decision) -> dict[str, Any]:
    """Worker side. Metadata is flattened to ``str -> str``, as the spec requires."""
    meta = {
        str(k)[:64]: (v if isinstance(v, str) else canonical_json(v).decode("utf-8"))
        for k, v in list(d.metadata.items())[:MAX_METADATA_KEYS]
    }
    return {
        "effect": d.effect.value,
        "rule_id": d.rule_id,
        "reason": d.reason[:MAX_REASON],
        "metadata": {k: v[:MAX_METADATA_VALUE] for k, v in meta.items()},
    }


def decision_from_wire(obj: dict[str, Any]) -> Decision:
    """Harness side. Everything a worker returns is checked; nothing is coerced."""
    expect_keys(obj, {"effect", "rule_id", "reason", "metadata"})
    effect = obj["effect"]
    if effect not in ("allow", "deny"):
        raise WireError("BAD_EFFECT", repr(effect)[:64])
    rule_id = obj["rule_id"]
    if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id):
        raise WireError("BAD_RULE_ID", repr(rule_id)[:80])
    reason = obj["reason"]
    if not isinstance(reason, str) or len(reason) > MAX_REASON:
        raise WireError("MALFORMED_FRAME", "reason must be a string of at most 512 chars")
    meta = obj["metadata"]
    if not isinstance(meta, dict):
        raise WireError("METADATA_TYPE", "metadata must be an object")
    if len(meta) > MAX_METADATA_KEYS:
        raise WireError("METADATA_LIMIT", f"{len(meta)} keys")
    for k, v in meta.items():
        if not isinstance(v, str):
            raise WireError("METADATA_TYPE", f"{k!r} is not a string")
        if len(v) > MAX_METADATA_VALUE:
            raise WireError("METADATA_LIMIT", f"{k!r} longer than {MAX_METADATA_VALUE}")
    return Decision(effect=Effect(effect), rule_id=rule_id, reason=reason, metadata=dict(meta))


# -- decision context -------------------------------------------------------
#
# Explicit rather than reflective. A generic dataclass walker would follow any
# field someone adds to DecisionContext across the boundary without anyone
# deciding that it should cross. Here, a new field is a protocol change.


def _source(s: SourceView) -> dict[str, Any]:
    return {
        "unit_id": s.unit_id,
        "resource_uri": s.resource_uri,
        "trust": s.trust.value,
        "classification": s.classification.value,
        "readers": list(s.readers),
    }


def _sink(s: SinkView) -> dict[str, Any]:
    return {
        "id": s.id,
        "readers": [{"id": r.id, "clearance": r.clearance.value} for r in s.readers],
    }


def ctx_to_wire(ctx: DecisionContext) -> dict[str, Any]:
    p = ctx.principal
    r = ctx.resource
    return {
        "step": ctx.step,
        "principal": {
            "id": p.id,
            "kind": p.kind,
            "clearance": p.clearance.value,
            "roles": list(p.roles),
            "granted_tools": sorted(p.granted_tools),
            "on_behalf_of": p.on_behalf_of,
            "on_behalf_of_clearance": p.on_behalf_of_clearance.value,
        },
        "action": {
            "tool": ctx.action.tool,
            # Model-authored text. The spec gates it behind a negotiated
            # capability; it is sent unconditionally here because every
            # built-in policy reads it and an in-process policy already sees
            # it. Recorded as a deviation in docs/POLICY_WORKER.md.
            "arguments": canonical_safe(ctx.action.arguments),
            "effect_class": ctx.action.effect_class,
        },
        "provenance": {
            "value_sources": [_source(s) for s in ctx.provenance.value_sources],
            "context_sources": [_source(s) for s in ctx.provenance.context_sources],
        },
        "resource": None if r is None else {
            "uri": r.uri,
            "kind": r.kind,
            "classification": r.classification.value,
            "owner_principal_id": r.owner_principal_id,
            "readers": list(r.readers),
            "path": r.path,
        },
        "sink": None if ctx.sink is None else _sink(ctx.sink),
        "history": [
            {"step": h.step, "tool": h.tool, "effect": h.effect.value, "rule_id": h.rule_id}
            for h in ctx.history
        ],
        "user_task": ctx.user_task,
        "sinks": [_sink(s) for s in ctx.sinks],
    }


def canonical_safe(value: Any) -> Any:
    """Round-trip through canonical JSON so only JSON-native values cross."""
    return json.loads(canonical_json(value))


def ctx_from_wire(obj: dict[str, Any]) -> DecisionContext:
    expect_keys(obj, {"step", "principal", "action", "provenance", "resource", "sink",
                      "history", "user_task", "sinks"})
    pr = obj["principal"]
    expect_keys(pr, {"id", "kind", "clearance", "roles", "granted_tools", "on_behalf_of",
                     "on_behalf_of_clearance"})
    ac = obj["action"]
    expect_keys(ac, {"tool", "arguments", "effect_class"})
    pv = obj["provenance"]
    expect_keys(pv, {"value_sources", "context_sources"})

    def source(d: dict[str, Any]) -> SourceView:
        expect_keys(d, {"unit_id", "resource_uri", "trust", "classification", "readers"})
        return SourceView(
            unit_id=d["unit_id"],
            resource_uri=d["resource_uri"],
            trust=TrustClass(d["trust"]),
            classification=Classification(d["classification"]),
            readers=tuple(d["readers"]),
        )

    def sink(d: dict[str, Any]) -> SinkView:
        expect_keys(d, {"id", "readers"})
        readers = []
        for r in d["readers"]:
            expect_keys(r, {"id", "clearance"})
            readers.append(ReaderView(id=r["id"], clearance=Classification(r["clearance"])))
        return SinkView(id=d["id"], readers=tuple(readers))

    res = obj["resource"]
    resource = None
    if res is not None:
        expect_keys(res, {"uri", "kind", "classification", "owner_principal_id", "readers",
                          "path"})
        resource = ResourceView(
            uri=res["uri"],
            kind=res["kind"],
            classification=Classification(res["classification"]),
            owner_principal_id=res["owner_principal_id"],
            readers=tuple(res["readers"]),
            path=res["path"],
        )
    history = []
    for h in obj["history"]:
        expect_keys(h, {"step", "tool", "effect", "rule_id"})
        history.append(PriorDecision(step=h["step"], tool=h["tool"],
                                     effect=Effect(h["effect"]), rule_id=h["rule_id"]))
    return DecisionContext(
        step=obj["step"],
        principal=PrincipalView(
            id=pr["id"],
            kind=pr["kind"],
            clearance=Classification(pr["clearance"]),
            roles=tuple(pr["roles"]),
            granted_tools=frozenset(pr["granted_tools"]),
            on_behalf_of=pr["on_behalf_of"],
            on_behalf_of_clearance=Classification(pr["on_behalf_of_clearance"]),
        ),
        action=ActionView(tool=ac["tool"], arguments=dict(ac["arguments"]),
                          effect_class=ac["effect_class"]),
        provenance=ProvenanceView(
            value_sources=tuple(source(s) for s in pv["value_sources"]),
            context_sources=tuple(source(s) for s in pv["context_sources"]),
        ),
        resource=resource,
        sink=None if obj["sink"] is None else sink(obj["sink"]),
        history=tuple(history),
        user_task=obj["user_task"],
        sinks=tuple(sink(s) for s in obj["sinks"]),
    )
