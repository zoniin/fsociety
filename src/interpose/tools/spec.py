"""Tool contracts.

Every tool declares three things beyond its signature, and each exists so the
policy enforcement point can do its job without knowing what any individual
tool means:

``effect_class``
    ``read``, ``write``, or ``irreversible``. Authorization decisions turn on
    what an action *does*, not on what it is named. A policy that reasons over
    verbs cannot generalize to a tool it has not seen.
``resolve``
    Maps arguments to the resource and sink the call would touch, *before* the
    call runs. This is what makes object-level authorization possible at all:
    the enforcement point needs to know which object is at stake while it can
    still say no.
``execute``
    Runs against the in-memory world. Tools are executed, never emulated by a
    language model. Emulated tools produce hallucinated state transitions, and
    every number in this project is a claim about state.

A tool never checks permissions. Authorization happens once, at the
enforcement point, for every tool. Scattering checks into tool bodies is how
real systems end up with an incomplete mediation surface -- one tool that
forgot -- and it would also make the policy layer unmeasurable, since the
harness could no longer attribute a block to the policy.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..policy.types import EffectClass
from ..provenance import Source, Tagged
from ..world.models import World

__all__ = ["Resolution", "ToolError", "ToolOutcome", "ToolRegistry", "ToolSpec"]


class ToolError(Exception):
    """A tool could not complete. Returned to the agent, never fatal."""


@dataclass(frozen=True)
class Resolution:
    """What a call would touch, computed before it is allowed to happen."""

    resource_uri: str | None = None
    sink_id: str | None = None
    note: str = ""


@dataclass
class ToolOutcome:
    """What a call produced."""

    result: Tagged[str]
    #: Objects whose **content** this call returned. Feeds
    #: ``unauthorized_asset_read``.
    resource_uris: list[str] = field(default_factory=list)
    #: Objects this call merely *listed* -- uri, classification, title -- without
    #: returning their content. Enumeration is a real information leak and is
    #: recorded, but conflating it with disclosure let a challenger forge
    #: ``unauthorized_asset_read`` from a search that returned no content at
    #: all. Kept separate for that reason.
    enumerated_uris: list[str] = field(default_factory=list)
    #: Resources created or modified. Drives the state-diff assertions.
    written_uris: list[str] = field(default_factory=list)


class ExecuteFn(Protocol):
    def __call__(
        self,
        world: World,
        principal_id: str,
        on_behalf_of: str,
        arguments: dict[str, Any],
    ) -> ToolOutcome: ...


class ResolveFn(Protocol):
    def __call__(self, world: World, arguments: dict[str, Any]) -> Resolution: ...


@dataclass(frozen=True)
class ToolSpec:  # SIMPL-0010: a dict, not a wire protocol
    name: str
    description: str
    #: JSON-schema-shaped parameter declaration, handed to model providers.
    parameters: dict[str, Any]
    effect_class: EffectClass
    resolve: ResolveFn
    execute: ExecuteFn

    def to_provider_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


class ToolRegistry:
    """The fixed tool surface.

    Deliberately not extensible from scenario content. A new tool is a change
    to this repository, reviewed as code, because a tool is a capability and
    capabilities should grow on purpose.
    """

    def __init__(self, specs: list[ToolSpec]) -> None:
        self._by_name = {s.name: s for s in specs}

    def __contains__(self, name: object) -> bool:
        return name in self._by_name

    def get(self, name: str) -> ToolSpec:
        if name not in self._by_name:
            raise ToolError(f"no such tool: {name}")
        return self._by_name[name]

    def names(self) -> list[str]:
        return sorted(self._by_name)

    def subset(self, names: list[str]) -> list[ToolSpec]:
        return [self._by_name[n] for n in sorted(names) if n in self._by_name]


def source_of(world: World, uri: str, unit_id: str) -> Source:
    """Build the provenance label for content read out of ``uri``."""
    res = world.resource(uri)
    if res is None:
        raise ToolError(f"unknown resource: {uri}")
    return Source(
        unit_id=unit_id,
        resource_uri=res.uri,
        trust=res.trust,
        classification=res.classification,
    )


#: Convenience alias used by the library module.
Executor = Callable[..., ToolOutcome]
