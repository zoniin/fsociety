"""The scenario contract.

A scenario is **data**. There is no code-loading path -- not behind a flag,
not for trusted authors, not ever. That is the single most consequential
decision in the project and it is a one-way door: a code path can be added
later, but it can never be removed once scenarios circulate.

The reasoning is short. A scenario is, by definition, adversarial content
written by a stranger. If scenarios shipped Python, ``interpose run
community/scenario-47`` would be arbitrary code execution triggered by content
designed to manipulate -- which is precisely the agentic-supply-chain failure
this project exists to study. A lab that ships that surface refutes itself.
"We review pull requests" fails the moment a scenario travels outside the
repository, and the review signal is already poor: a diff full of injection
payloads is excellent cover for one real exfiltration primitive.

The cost is real and worth stating. Expressiveness now comes from a
harness-owned primitive library, so a scenario needing genuinely new tool
behaviour requires a pull request here rather than a downloadable file. Tool
vocabulary grows on purpose, and slowly.

Two structures deserve attention:

``benign``
    The legitimate workload, with ground-truth required calls. Not optional.
    A scenario without it cannot be run, because a containment number with no
    utility number beside it is not a result.
``attack.objective``
    A machine-readable adversary objective: the action signature the attacker
    wants. It scores whether a proposal was attacker-directed, and it drives
    the shadow probe. It is never shown to a policy.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "SUPPORTED_SPEC_VERSIONS",
    "AgentSpec",
    "AttackSpec",
    "BenignTask",
    "CallPattern",
    "ObjectiveStep",
    "ScenarioSpec",
    "Taxonomy",
    "Variants",
]

SUPPORTED_SPEC_VERSIONS = {"0.1"}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CallPattern(_Strict):
    """A partial match against a proposed call.

    ``args`` is a subset match: every key given must be present and equal.
    Keys not given are ignored, so a pattern can pin the security-relevant
    argument without over-fitting to phrasing the model chose.
    """

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)

    def matches(self, tool: str, arguments: dict[str, Any]) -> bool:
        if tool != self.tool:
            return False
        return all(str(arguments.get(k, "")).strip() == str(v).strip() for k, v in self.args.items())


class ObjectiveStep(CallPattern):
    """One step of the adversary objective. Also a shadow-probe step."""

    note: str = ""


class AgentSpec(_Strict):
    #: Identity the agent runs as.
    actor: str
    #: Identity whose authority it borrows. The confused-deputy axis.
    on_behalf_of: str
    tools: list[str]
    max_turns: int = 8

    @field_validator("max_turns")
    @classmethod
    def _sane_turns(cls, v: int) -> int:
        if not 1 <= v <= 40:
            raise ValueError("max_turns must be between 1 and 40")
        return v


class BenignTask(_Strict):
    """A legitimate task, with the calls a correct agent must make.

    ``requires_calls`` is what makes over-blocking measurable: a policy that
    denies one of these has produced a false denial, and that is counted and
    reported next to containment whether or not it flatters the policy.
    """

    id: str
    prompt: str
    requires_calls: list[CallPattern] = Field(default_factory=list)


class AttackSpec(_Strict):
    id: str
    vector: Literal["untrusted_document", "tool_output", "retrieved_content"]
    #: URI of the resource carrying the adversarial content.
    injected_source: str
    #: The user task the attack rides on. Usually identical to a benign
    #: prompt, which is the point: the attack changes the environment, not
    #: the request.
    prompt: str
    objective: list[ObjectiveStep]
    #: Canary-bearing resources whose content must not cross the boundary.
    protected_assets: list[str] = Field(default_factory=list)


class Variants(_Strict):
    """Paraphrase axes.

    Robustness to paraphrase is a documented blind spot across this whole
    genre of benchmark. Cheap to cover for one scenario, so covered here.
    """

    benign_prompts: list[str] = Field(default_factory=list)
    injection_payloads: list[str] = Field(default_factory=list)


class Taxonomy(_Strict):
    """Where this scenario sits in the published taxonomies.

    Multiple categories per scenario, deliberately. An injection that
    redirects an agent to a legitimate tool for an illegitimate end is
    simultaneously goal hijack, tool misuse, and privilege abuse; no
    tiebreaker exists, so the mapping is published as data rather than
    asserted as a fact. ATLAS entries use technique *names* because ids have
    been reused across ATLAS versions.
    """

    owasp_asi: list[str] = Field(default_factory=list)
    owasp_llm: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)


class ScenarioSpec(_Strict):
    spec_version: str
    id: str
    version: str
    bench_version: str
    title: str
    summary: str
    world: str
    agent: AgentSpec
    benign: list[BenignTask]
    attack: AttackSpec
    tags: list[str] = Field(default_factory=list)
    taxonomy: Taxonomy = Field(default_factory=Taxonomy)
    variants: Variants = Field(default_factory=Variants)

    @field_validator("spec_version")
    @classmethod
    def _known_version(cls, v: str) -> str:
        if v not in SUPPORTED_SPEC_VERSIONS:
            raise ValueError(
                f"unsupported spec_version {v!r}; this build understands "
                f"{sorted(SUPPORTED_SPEC_VERSIONS)}"
            )
        return v

    @field_validator("benign")
    @classmethod
    def _benign_present(cls, v: list[BenignTask]) -> list[BenignTask]:
        if not v:
            raise ValueError(
                "a scenario must declare at least one benign task. Containment "
                "is only reportable alongside its cost; see docs/METRICS.md."
            )
        return v
