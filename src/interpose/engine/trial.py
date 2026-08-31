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
from typing import TypeAlias

from ..events import EventLog
from ..policy.base import SecurityPolicy, policy_digest
from ..providers.base import AgentProvider
from ..report.result import ArtifactRef, OutcomeView, RunResult, TrialResult
from ..scenario.loader import LoadedScenario
from ..scenario.spec import BenignTask
from .runner import RunConfig, Runner, RunRecord

__all__ = ["ProviderFactory", "run_single", "run_trial", "to_run_result", "write_run_artifacts"]

#: A provider must be fresh for every run: providers carry per-run state, and
#: reusing one would leak a previous run's transcript into the next. Passing a
#: factory rather than an instance makes that impossible to get wrong.
ProviderFactory: TypeAlias = Callable[[], AgentProvider]


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
) -> RunRecord:
    return Runner(
        RunConfig(
            scenario=scenario,
            policy=policy,
            provider=make_provider(),
            benign_task=benign_task,
            prompt_variant=prompt_variant,
            payload_variant=payload_variant,
        )
    ).run()


def run_trial(
    scenario: LoadedScenario,
    policy: SecurityPolicy,
    make_provider: ProviderFactory,
    *,
    prompt_variant: int | None = None,
    payload_variant: int | None = None,
) -> tuple[TrialResult, list[RunRecord]]:
    """Run the attack and the full benign suite under one policy."""
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
    for task in scenario.spec.benign:
        record = run_single(
            scenario,
            policy,
            make_provider,
            benign_task=task,
            prompt_variant=prompt_variant if task.id == scenario.spec.benign[0].id else None,
        )
        records.append(record)
        benign.append(to_run_result(record, scenario))

    attack_result = to_run_result(attack, scenario)
    trial = TrialResult(
        scenario=attack_result.scenario,
        policy=attack_result.policy,
        provider=attack_result.provider,
        deterministic=attack_result.deterministic,
        attack=attack_result,
        benign=benign,
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
