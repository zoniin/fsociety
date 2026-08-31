"""The model boundary.

This is intentionally the smallest interface in the project. interpose is not
an agent framework and must not become one: it measures the boundary *below*
the agent, so it needs to know only what the agent proposes, never how the
agent decided.

A provider receives the transcript so far and the tool schemas, and returns
one turn: some text, and zero or more proposed calls. The harness owns the
loop, the message list, tool execution, and every decision. Anything richer
would start reimplementing LangGraph badly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

from ..tools.spec import ToolSpec

__all__ = ["AgentProvider", "AgentTurn", "Message", "ProposedCall", "Role"]

Role = Literal["system", "user", "assistant", "tool"]


@dataclass(frozen=True)
class Message:
    role: Role
    content: str
    #: Set on ``tool`` messages to tie a result back to its call.
    call_id: str | None = None
    #: Set on ``tool`` messages so a provider can see what produced the text.
    tool_name: str | None = None
    #: True when this result is a policy refusal rather than tool output. A
    #: provider must be able to tell "refused" from "returned this text", or
    #: it treats a denial string as data -- which is exactly what happened
    #: before review: the compliant client posted the refusal message into the
    #: attacker's queue.
    blocked: bool = False
    #: Trust class of the content, when the harness could label it.
    #:
    #: Carried out-of-band rather than spliced into the text. Prefixing tool
    #: results with a visible ``[untrusted]`` banner would be *spotlighting* --
    #: a real prompt-injection defense -- and switching it on for every run
    #: would silently confound the thing being measured. Providers that model
    #: a system with no such defense simply ignore this field.
    trust: str | None = None


@dataclass(frozen=True)
class ProposedCall:
    """A request. Nothing has happened yet -- that is the entire point.

    Every interesting question in this project lives in the gap between a
    proposal and a commit.
    """

    tool: str
    arguments: dict[str, Any]


@dataclass
class AgentTurn:
    text: str = ""
    calls: list[ProposedCall] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)

    @property
    def is_final(self) -> bool:
        return not self.calls


@runtime_checkable
class AgentProvider(Protocol):
    # Declared read-only so that an implementation may supply either a plain
    # attribute or a computed property. The scripted provider derives its id
    # from its behaviour class; requiring a settable attribute would have
    # forced it to duplicate that.
    @property
    def id(self) -> str: ...

    @property
    def deterministic(self) -> bool:
        """True only when repeated runs are byte-identical.

        An artifact produced with this false may never claim
        byte-reproducibility, and no single run of any kind may be described
        with a rate.
        """
        ...

    def describe(self) -> str: ...

    def respond(self, transcript: list[Message], tools: list[ToolSpec]) -> AgentTurn: ...
