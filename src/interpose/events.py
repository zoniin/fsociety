"""The causal event schema.

A run emits an ordered JSONL stream. The stream is the deliverable: formats
get adopted, harnesses get replaced. It is designed so that one grep answers
the question that motivates the project --

    which untrusted byte reached which privileged call, and what did the
    authorization layer decide about it?

Design rules, each learned from a specific failure mode:

* **Stable envelope, typed payload.** Every event carries the same six
  envelope fields; ``type`` discriminates the payload. Consumers can filter on
  the envelope without understanding any payload.
* **``seq`` and ``t_ms`` are deterministic**, from a seeded counter and a fake
  clock. Wall-clock time appears once per run, in ``result.json``, and is
  excluded from digests.
* **No free-form ``details`` bag.** Artifacts are built field-by-field from
  declared schemas. Nothing is serialized by dumping the ``__dict__`` of an
  object, because that is how ``os.environ`` ends up in a file someone pastes
  into a GitHub issue.
* **Append-only by convention, not construction.** The log is not hash-chained
  and control characters are stripped rather than structurally rejected; a
  tool result containing a newline plus forged JSON is a real gap. Recorded as
  SIMPL-0004; bias: invalidating.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .digest import canonical_json, sha256_bytes

__all__ = [
    "EVENT_SCHEMA_VERSION",
    "AgentMessage",
    "AnyEvent",
    "ContentIngested",
    "DetectorTriggered",
    "Event",
    "EventLog",
    "OutcomeEvaluated",
    "PolicyEvaluated",
    "RunFinished",
    "RunStarted",
    "ShadowEvaluated",
    "TaskAssigned",
    "ToolBlocked",
    "ToolExecuted",
    "ToolProposed",
    "WorldInitialized",
    "scrub",
]

EVENT_SCHEMA_VERSION = "0.1"

_CONTROL: dict[int, None] = {c: None for c in range(0x20) if c not in (0x09, 0x0A)}
_CONTROL[0x7F] = None


def scrub(text: str) -> str:
    """Strip control characters from model-authored or scenario-authored text.

    Model output and scenario fixtures are attacker-shaped by construction.
    Anything reaching a terminal or a log passes through here first, so an
    ANSI escape sequence in a document body cannot repaint the report that
    describes it.
    """
    return text.translate(_CONTROL)


class Event(BaseModel):
    """Envelope shared by every event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = EVENT_SCHEMA_VERSION
    run_id: str
    seq: int
    t_ms: int
    type: str

    def to_json_line(self) -> str:
        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )


class RunStarted(Event):
    type: Literal["run.started"] = "run.started"
    scenario_id: str
    scenario_version: str
    scenario_digest: str
    policy_id: str
    policy_digest: str
    provider_id: str
    bench_version: str
    harness_version: str
    deterministic: bool


class WorldInitialized(Event):
    type: Literal["world.initialized"] = "world.initialized"
    world_digest: str
    principal_count: int
    resource_count: int


class TaskAssigned(Event):
    type: Literal["task.assigned"] = "task.assigned"
    #: Identity the agent runs *as*.
    actor: str
    #: Identity the agent acts *for*. The confused-deputy axis lives here.
    on_behalf_of: str
    task_kind: Literal["benign", "under_attack"]
    task_id: str
    prompt: str


class ContentIngested(Event):
    """Content crossed into the agent context and acquired a label."""

    type: Literal["content.ingested"] = "content.ingested"
    unit_id: str
    resource_uri: str
    trust: str
    classification: str
    content_digest: str
    byte_length: int


class AgentMessage(Event):
    type: Literal["agent.message"] = "agent.message"
    turn: int
    text: str


class ToolProposed(Event):
    """The agent asked for an action. Nothing has happened yet.

    ``matches_adversary_objective`` is computed by the harness against the
    scenario declaration and is never visible to a policy. It is the only
    honest way to say "the model was steered" -- what is observable is a
    proposal matching a declared action signature, not a mental state.
    """

    type: Literal["tool.proposed"] = "tool.proposed"
    turn: int
    call_id: str
    tool: str
    arguments: dict[str, Any]
    arguments_digest: str
    #: Sources whose content is detectably present in the arguments.
    value_provenance: list[str]
    #: Every source in context at proposal time (over-approximation).
    context_provenance: list[str]
    matches_adversary_objective: bool


class PolicyEvaluated(Event):
    type: Literal["policy.evaluated"] = "policy.evaluated"
    turn: int
    call_id: str
    tool: str
    effect: Literal["allow", "deny"]
    rule_id: str
    reason: str
    policy_id: str


class ToolExecuted(Event):
    type: Literal["tool.executed"] = "tool.executed"
    turn: int
    call_id: str
    tool: str
    resource_uris: list[str]
    effect_class: Literal["read", "write", "irreversible"]
    result_digest: str
    result_provenance: list[str]
    world_digest_after: str


class ToolBlocked(Event):
    type: Literal["tool.blocked"] = "tool.blocked"
    turn: int
    call_id: str
    tool: str
    rule_id: str
    reason: str


class DetectorTriggered(Event):
    """A ground-truth state assertion fired. Never an LLM judgement.

    An LLM judge is a contamination vector: it makes the measurement depend on
    a second model whose behaviour is not pinned. Exposure here is exact
    string presence of a canary in a resource readable outside the
    confidentiality boundary.
    """

    type: Literal["detector.triggered"] = "detector.triggered"
    detector: str
    canary: str
    from_resource: str
    to_resource: str
    readable_by: list[str]


class ShadowEvaluated(Event):
    """A counterfactual decision. Logged, never committed.

    Answers "would the policy have permitted this had the agent asked?" for
    runs where the agent never asked. See :mod:`interpose.engine.probe`.
    """

    type: Literal["probe.shadow_evaluated"] = "probe.shadow_evaluated"
    step: int
    tool: str
    arguments: dict[str, Any]
    effect: Literal["allow", "deny"]
    rule_id: str
    reason: str


class OutcomeEvaluated(Event):
    type: Literal["outcome.evaluated"] = "outcome.evaluated"
    check: str
    value: bool
    detail: str


class RunFinished(Event):
    type: Literal["run.finished"] = "run.finished"
    verdict: str
    turns: int
    world_digest_final: str
    #: True when the loop stopped because it ran out of turns rather than
    #: because the agent finished. Every verdict from such a run is suspect --
    #: the attack may simply not have happened yet -- so this is recorded
    #: rather than left to be inferred from a turn count.
    turn_limit_reached: bool = False


AnyEvent = Annotated[
    RunStarted
    | WorldInitialized
    | TaskAssigned
    | ContentIngested
    | AgentMessage
    | ToolProposed
    | PolicyEvaluated
    | ToolExecuted
    | ToolBlocked
    | DetectorTriggered
    | ShadowEvaluated
    | OutcomeEvaluated
    | RunFinished,
    Field(discriminator="type"),
]


class EventLog:  # SIMPL-0004: append-only by convention, not construction
    """An append-only event list with a stable digest.

    Held in memory during a run and written once at the end. Writing
    incrementally would let a crashed run leave a half-file that looks like a
    result.
    """

    def __init__(self, run_id: str, clock_tick_ms: int = 1) -> None:
        self.run_id = run_id
        self._events: list[Event] = []
        self._seq = 0
        self._t = 0
        self._tick = clock_tick_ms

    def emit(self, factory: type[Event], **fields: Any) -> Event:
        self._seq += 1
        self._t += self._tick
        event = factory(run_id=self.run_id, seq=self._seq, t_ms=self._t, **fields)
        self._events.append(event)
        return event

    @property
    def events(self) -> list[Event]:
        return list(self._events)

    def of_type(self, *types: str) -> list[Event]:
        return [e for e in self._events if e.type in types]

    def to_jsonl(self) -> str:
        return "\n".join(e.to_json_line() for e in self._events) + "\n"

    def digest(self) -> str:
        """Digest over every event, envelope included.

        ``t_ms`` is deterministic so it is safe to hash; wall-clock time is
        not in the log at all.
        """
        return sha256_bytes(canonical_json([e.model_dump(mode="json") for e in self._events]))

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_jsonl(), encoding="utf-8", newline="\n")
