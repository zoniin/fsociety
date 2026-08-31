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
    "ReaderView",
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
    """One labelled content unit, as a policy sees it.

    ``readers`` is the source resource's explicit need-to-know allowlist, empty
    when access is governed by clearance alone. An egress rule needs it: a
    principal may be entitled to a specific confidential object by grant while
    its clearance says otherwise, and a rule that only compares clearances will
    refuse writes that are perfectly legitimate.
    """

    unit_id: str
    resource_uri: str
    trust: TrustClass
    classification: Classification
    readers: tuple[str, ...] = ()


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
class ReaderView:
    """One principal who can read a sink after a write lands there."""

    id: str
    clearance: Classification

    def entitled_to(self, source: SourceView) -> bool:
        """Would this reader be permitted to read ``source`` directly?

        The question an egress rule actually has to answer. Comparing bulk
        clearances is not the same thing: an explicit grant can entitle a
        reader whose clearance does not dominate, and a rule that ignores
        grants refuses legitimate work.
        """
        if source.readers:
            return self.id in source.readers
        return CLASSIFICATION_ORDER[self.clearance] >= CLASSIFICATION_ORDER[source.classification]


@dataclass(frozen=True)
class SinkView:
    """Where a write lands, and who can read it afterwards.

    Carries the full readership rather than a summary statistic. Two earlier
    versions of this type each hid a bug behind an aggregate: taking the
    *maximum* clearance let an insider on the readership cover for an
    outsider, and taking the minimum then over-refused writes whose readers
    held explicit grants. Neither could be expressed correctly without the
    individual readers. See docs/V0_REVIEW.md.
    """

    id: str
    readers: tuple[ReaderView, ...] = ()

    @property
    def reader_principal_ids(self) -> tuple[str, ...]:
        return tuple(r.id for r in self.readers)

    @property
    def min_reader_clearance(self) -> Classification:
        """The weakest reader. A queue is only as confidential as this."""
        if not self.readers:
            return Classification.PUBLIC
        return min(
            ((CLASSIFICATION_ORDER[r.clearance], r.clearance) for r in self.readers),
        )[1]

    @property
    def max_reader_clearance(self) -> Classification:
        if not self.readers:
            return Classification.PUBLIC
        return max(
            ((CLASSIFICATION_ORDER[r.clearance], r.clearance) for r in self.readers),
        )[1]

    def unentitled_readers(self, source: SourceView) -> tuple[ReaderView, ...]:
        """Readers of this sink who could not read ``source`` directly."""
        return tuple(r for r in self.readers if not r.entitled_to(source))


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
