"""What a policy is told, and what it may answer.

The unit of control is the **action**: a single tool call, with its caller
identity and input parameters, evaluated at the moment of invocation. That
framing is borrowed deliberately rather than invented -- it is the shape AWS
AgentCore Policy, Cedar, and the out-of-band defense literature already use.
A novel abstraction here would be simultaneously un-adoptable and
pedagogically misleading.

Two failure modes bound the design of :class:`DecisionContext`.

**Starve the policy and you benchmark a strawman.** Information-flow defenses
need labels; evaluating them without provenance is rigged against them. So the
context carries principal identity, delegation, resource classification, sink
readership, both provenance views, and the decision history of the episode.

**Over-feed it and you measure nothing.** The bright line:

    A policy may receive anything the harness could compute at runtime in a
    real deployment without knowing the answer key, and nothing derived from
    the scenario definition.

Concretely, a policy is **never** given: the adversary objective, the target
action signature, the outcome predicate, the seed, the scorer, any flag that a
content unit "is the injection" (provenance says *untrusted_external*, never
*malicious*), or -- most important -- whether this trial is the benign task or
the attack. That last exclusion is what makes the benign suite a real control
rather than a formality, and it is enforced structurally: this module imports
nothing from :mod:`interpose.scenario`, and a test asserts it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

from ..provenance import CLASSIFICATION_ORDER, Classification, TrustClass

__all__ = [
    "ALLOW",
    "DENY",
    "ActionView",
    "Decision",
    "DecisionContext",
    "Effect",
    "EffectClass",
    "PrincipalView",
    "PriorDecision",
    "ProvenanceView",
    "ResourceView",
    "SinkView",
    "SourceView",
]

EffectClass = Literal["read", "write", "irreversible"]


class Effect(StrEnum):
    """The V0 decision alphabet.

    Real defenses also redact, downscope, quarantine and escalate. Those need
    a scorer that can grade them and a consumer that can act on them, and V0
    has neither, so shipping them would be interface theatre. The wire format
    below is versioned and additive, so ``allow_with_transform`` and
    ``escalate`` can arrive without breaking a published result.
    """

    ALLOW = "allow"
    DENY = "deny"


ALLOW = Effect.ALLOW
DENY = Effect.DENY


@dataclass(frozen=True)
class SourceView:
    """One labelled content unit, as a policy sees it."""

    unit_id: str
    resource_uri: str
    trust: TrustClass
    classification: Classification


@dataclass(frozen=True)
class PrincipalView:
    """Who is asking, and on whose behalf.

    ``id`` is the agent service principal; ``on_behalf_of`` is the human whose
    authority it is borrowing. The gap between the two is where the confused
    deputy lives, and a policy that ignores ``on_behalf_of`` will pass the
    attack scenario and fail the cross-principal one.
    """

    id: str
    kind: str
    clearance: Classification
    roles: tuple[str, ...]
    granted_tools: frozenset[str]
    on_behalf_of: str
    on_behalf_of_clearance: Classification

    def clearance_rank(self) -> int:
        return CLASSIFICATION_ORDER[self.clearance]

    def delegated_rank(self) -> int:
        """The ceiling a well-behaved delegation should respect."""
        return min(
            CLASSIFICATION_ORDER[self.clearance],
            CLASSIFICATION_ORDER[self.on_behalf_of_clearance],
        )


@dataclass(frozen=True)
class ActionView:
    tool: str
    arguments: dict[str, Any]
    effect_class: EffectClass


@dataclass(frozen=True)
class ResourceView:
    """The resource the action targets, when the harness could resolve one."""

    uri: str
    kind: str
    classification: Classification
    owner_principal_id: str
    readers: tuple[str, ...]
    path: str | None = None

    def rank(self) -> int:
        return CLASSIFICATION_ORDER[self.classification]


@dataclass(frozen=True)
class SinkView:
    """Where a write lands, and who can read it afterwards.

    Both extremes are given, because they answer different questions and
    picking the wrong one silently disables an egress rule.

    ``min_reader_clearance`` is the *least* cleared principal who can read the
    sink, and it is the one confidentiality needs: a queue is only as
    confidential as its weakest reader. Comparing against the maximum instead
    lets data flow into a queue that one insider and one outsider can both
    read, because the insider covers for the outsider. That inversion shipped
    in the first draft and disabled R3 entirely; see docs/V0_REVIEW.md.
    """

    id: str
    reader_principal_ids: tuple[str, ...]
    max_reader_clearance: Classification
    min_reader_clearance: Classification

    def reader_rank(self) -> int:
        """The rank an egress rule compares against: the weakest reader."""
        return CLASSIFICATION_ORDER[self.min_reader_clearance]

    def strongest_reader_rank(self) -> int:
        return CLASSIFICATION_ORDER[self.max_reader_clearance]


@dataclass(frozen=True)
class ProvenanceView:
    """Both provenance views, bracketing the truth.

    ``value_sources`` under-approximates (a paraphrase escapes it);
    ``context_sources`` over-approximates (reading a document taints
    everything after). A policy picks its point on that tradeoff and the
    choice shows up in its false-deny rate, which is exactly the property
    worth measuring.
    """

    value_sources: tuple[SourceView, ...] = ()
    context_sources: tuple[SourceView, ...] = ()

    def max_value_classification(self) -> Classification:
        if not self.value_sources:
            return Classification.PUBLIC
        return max(
            (s.classification for s in self.value_sources),
            key=lambda c: CLASSIFICATION_ORDER[c],
        )

    def has_untrusted_context(self) -> bool:
        return any(s.trust is TrustClass.UNTRUSTED_EXTERNAL for s in self.context_sources)

    def has_untrusted_value(self) -> bool:
        return any(s.trust is TrustClass.UNTRUSTED_EXTERNAL for s in self.value_sources)


@dataclass(frozen=True)
class PriorDecision:
    step: int
    tool: str
    effect: Effect
    rule_id: str


@dataclass(frozen=True)
class DecisionContext:
    """Everything a policy is allowed to know at the moment of invocation."""

    step: int
    principal: PrincipalView
    action: ActionView
    provenance: ProvenanceView
    resource: ResourceView | None = None
    sink: SinkView | None = None
    history: tuple[PriorDecision, ...] = ()
    #: The task the human asked for, verbatim. Trusted-user content.
    user_task: str = ""


@dataclass(frozen=True)
class Decision:
    """A policy answer.

    ``rule_id`` is not decoration. A deny with no rule identity is
    unauditable: it tells an incident responder that something was blocked
    without telling them which control blocked it or why. Every decision in
    this project names its rule.
    """

    effect: Effect
    rule_id: str
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    def as_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }
