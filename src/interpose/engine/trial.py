"""Trials: the only unit that may be reported as a result.

A trial is one attack run plus the whole benign suite, under the *same policy
artifact*, with the same provider and the same variant indices. Nothing
smaller is a result, because a containment number with no cost beside it
cannot be interpreted -- a policy that denies every action would score
perfectly on containment alone.

This is enforced by construction rather than by convention: there is no
function here that produces an attack-only scorecard, and the artifact type
requires the benign list.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Literal, TypeAlias

from ..events import EventLog
from ..policy.base import SecurityPolicy, as_policy_factory, policy_digest
from ..provenance import Source
from ..providers.base import AgentProvider
from ..report.result import ArtifactRef, OutcomeView, RunResult, TrialResult
from ..scenario.loader import LoadedScenario
from ..scenario.spec import BenignTask
from .runner import RunConfig, Runner, RunRecord

__all__ = [
    "SESSION_MODES",
    "ProviderFactory",
    "SessionMode",
    "run_single",
    "run_trial",
    "to_run_result",
    "write_run_artifacts",
]

#: A provider must be fresh for every run: providers carry per-run state, and
#: reusing one would leak a previous run's transcript into the next. Passing a
#: factory rather than an instance makes that impossible to get wrong.
ProviderFactory: TypeAlias = Callable[[], AgentProvider]

#: ``fresh``: every benign task starts with an empty context (the default, and
#: what every result before long-session mode measured). ``long``: the benign
#: suite runs as one session, in declared order, and each task starts with the
#: context labels every earlier task left behind. SIMPL-0015.
SessionMode: TypeAlias = Literal["fresh", "long"]
SESSION_MODES: tuple[SessionMode, ...] = ("fresh", "long")


def to_run_result(record: RunRecord, scenario: LoadedScenario) -> RunResult:
    cfg = record.config
    spec = scenario.spec
    provider = cfg.provider
    return RunResult(
        run_id=record.run_id,
        scenario=ArtifactRef(id=spec.id, version=spec.version, digest=scenario.digest),
        policy=ArtifactRef(
            id=cfg.policy.id,
            version=getattr(cfg.policy, "version", ""),
            digest=policy_digest(cfg.policy),
        ),
        provider=ArtifactRef(id=provider.id),
        deterministic=bool(getattr(provider, "deterministic", False)),
        task_kind=record.outcome.task_kind,
        task_id=(cfg.benign_task.id if cfg.benign_task else spec.attack.id),
        prompt_variant=cfg.prompt_variant,
        payload_variant=cfg.payload_variant,
        outcome=OutcomeView.of(record.outcome),
        world_digest_before=record.world_before,
        world_digest_after=record.world_after,
        trace_digest=record.log.digest(),
        turns=sum(1 for e in record.log.of_type("agent.message")) or 0,
        usage=dict(record.usage),
    )


def run_single(
    scenario: LoadedScenario,
    policy: SecurityPolicy,
    make_provider: ProviderFactory,
    *,
    benign_task: BenignTask | None = None,
    prompt_variant: int | None = None,
    payload_variant: int | None = None,
    carried_sources: dict[Source, str] | None = None,
) -> RunRecord:
    # INV-LIFECYCLE-1: this run gets its own policy instance.
    # INV-LIFECYCLE-2: the shadow probe gets a *different* one.
    #
    # The probe asks a counterfactual question about the policy. There is no
    # reason it should be allowed to mutate the object whose actual behaviour is
    # being measured -- and since the probe is the channel that discloses the
    # adversary objective, letting it write into the scored instance is how the
    # answer key would reach the thing being graded.
    make_policy = as_policy_factory(policy)
    return Runner(
        RunConfig(
            scenario=scenario,
            policy=make_policy(),
            probe_policy=make_policy(),
            provider=make_provider(),
            benign_task=benign_task,
            prompt_variant=prompt_variant,
            payload_variant=payload_variant,
            carried_sources=dict(carried_sources or {}),
        )
    ).run()


def run_trial(
    scenario: LoadedScenario,
    policy: SecurityPolicy,
    make_provider: ProviderFactory,
    *,
    prompt_variant: int | None = None,
    payload_variant: int | None = None,
    session: SessionMode = "fresh",
) -> tuple[TrialResult, list[RunRecord]]:
    """Run the attack and the full benign suite under one policy.

    In ``long`` session mode the benign suite shares one context, so a policy
    that decides on context labels pays for everything read earlier in the
    session. The attack run always starts fresh: carrying benign labels into it
    could only make a context-level policy stricter, so a fresh attack run is
    the conservative reading of containment.
    """
    if session not in SESSION_MODES:
        raise ValueError(f"unknown session mode {session!r}")
    records: list[RunRecord] = []

    attack = run_single(
        scenario,
        policy,
        make_provider,
        prompt_variant=prompt_variant,
        payload_variant=payload_variant,
    )
    records.append(attack)

    benign: list[RunResult] = []
    carried: dict[Source, str] = {}
    for task in scenario.spec.benign:
        record = run_single(
            scenario,
            policy,
            make_provider,
            benign_task=task,
            prompt_variant=prompt_variant if task.id == scenario.spec.benign[0].id else None,
            carried_sources=carried if session == "long" else None,
        )
        records.append(record)
        benign.append(to_run_result(record, scenario))
        if session == "long":
            for source in record.context_sources:
                carried.setdefault(source, task.id)

    attack_result = to_run_result(attack, scenario)
    trial = TrialResult(
        scenario=attack_result.scenario,
        policy=attack_result.policy,
        provider=attack_result.provider,
        deterministic=attack_result.deterministic,
        attack=attack_result,
        benign=benign,
        session=session,
    )
    return trial, records


def write_run_artifacts(directory: Path, trial: TrialResult, records: list[RunRecord]) -> Path:
    """Write ``result.json`` plus one ``events.jsonl`` per run.

    Written once at the end. Writing incrementally would let a crashed run
    leave a half-file that looks like a result.
    """
    out = directory / trial.attack.run_id
    out.mkdir(parents=True, exist_ok=True)
    (out / "result.json").write_text(
        trial.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    for record in records:
        _write_log(out / f"{record.run_id}.events.jsonl", record.log)
    return out


def _write_log(path: Path, log: EventLog) -> None:
    log.write(path)
