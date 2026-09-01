"""Run the Cedar provenance ablation and write ``cedar-ablation.json``.

Five policies x three bundled scenarios x two scripted behaviour classes, plus a
supplementary pair of rows for the unregistered strict variant, plus a replay
that measures per-decision agreement with ``reference-least-privilege`` over
the decision contexts the reference policy itself produced.

Usage, from the repository root, with the ``cedar`` extra installed::

    .venv/Scripts/python.exe results/phase2/cedar_ablation.py

Every number in the artifact is a count or a duration. There are no rates and
no percentages: a single deterministic run of a three-scenario corpus does not
license one.
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from interpose import BENCH_VERSION, __version__  # noqa: E402
from interpose.engine.trial import run_trial  # noqa: E402
from interpose.policy.base import load_policy, policy_digest  # noqa: E402
from interpose.policy.types import Decision, DecisionContext  # noqa: E402
from interpose.providers.scripted import ScriptedProvider  # noqa: E402
from interpose.scenario.loader import load_scenario  # noqa: E402

SCENARIOS = ("indirect-document-injection", "confidential-egress", "compartment-egress")
BEHAVIORS = ("compliant", "paraphrasing")
ABLATION_POLICIES = (
    "permissive",
    "path-prefix",
    "reference",
    "cedar-action-only",
    "cedar-with-provenance",
)
#: Not part of the ablation. Reported separately as the measured answer to
#: "was the action-only arm a strawman?".
SUPPLEMENTARY_POLICIES = (
    "interpose.policy.cedar_action_only:CedarActionOnlyStrict",
)


class TimedPolicy:
    """Delegating wrapper that times every decision.

    Applied uniformly to all five policies so the latency column compares like
    with like, and kept outside the adapters so no policy is measured through
    instrumentation another policy does not carry. ``digest`` delegates, so the
    artifact still names the wrapped policy's bytes.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.id = inner.id
        self.version = getattr(inner, "version", "")
        self.seconds: list[float] = []

    def describe(self) -> str:
        return str(self._inner.describe())

    def digest(self) -> str:
        return policy_digest(self._inner)

    def evaluate(self, ctx: DecisionContext) -> Decision:
        started = time.perf_counter()
        decision = self._inner.evaluate(ctx)
        self.seconds.append(time.perf_counter() - started)
        return decision


class RecordingPolicy(TimedPolicy):
    """Also keeps every decision context, for the agreement replay."""

    def __init__(self, inner: Any) -> None:
        super().__init__(inner)
        self.contexts: list[DecisionContext] = []
        self.decisions: list[Decision] = []

    def evaluate(self, ctx: DecisionContext) -> Decision:
        decision = super().evaluate(ctx)
        self.contexts.append(ctx)
        self.decisions.append(decision)
        return decision


def _latency(seconds: list[float]) -> dict[str, Any]:
    if not seconds:
        return {"decisions": 0, "mean_ms": None, "max_ms": None}
    return {
        "decisions": len(seconds),
        "mean_ms": round(statistics.fmean(seconds) * 1000, 4),
        "max_ms": round(max(seconds) * 1000, 4),
    }


def _cell(policy_ref: str, scenario_id: str, behavior: str) -> dict[str, Any]:
    scenario = load_scenario(scenario_id)
    policy = TimedPolicy(load_policy(policy_ref))
    trial, _ = run_trial(scenario, policy, lambda: ScriptedProvider(behavior=behavior))
    attack = trial.attack.outcome
    inner = policy._inner
    return {
        "policy": trial.policy.id,
        "policy_digest": trial.policy.digest,
        "scenario": scenario_id,
        "provider": f"scripted:{behavior}",
        "verdict": attack.verdict,
        "sensitive_data_exposed": attack.sensitive_data_exposed,
        "possible_exposure": attack.possible_exposure,
        "enforcement_escape": attack.enforcement_escape,
        "authorization_gap_open": attack.authorization_gap_open,
        # The shadow probe's own numbers, which explain the gap column: the
        # probe asks whether the policy would permit the attack objective's
        # literal steps, not whether the episode actually leaked.
        "objective_steps_total": attack.objective_steps_total,
        "objective_steps_matched": attack.objective_steps_matched,
        "objective_steps_permitted": attack.objective_steps_permitted,
        "probe_detail": attack.probe_detail,
        "benign_passed": trial.benign_passed,
        "benign_total": trial.benign_total,
        "false_denials": trial.false_denials,
        "false_denied_calls": trial.false_denied_calls,
        "attack_denials": attack.denials,
        "benign_denials": sum(r.outcome.denials for r in trial.benign),
        "truncated_runs": trial.truncated_runs,
        "policy_blocked_tasks": trial.policy_blocked_tasks,
        "client_incomplete_tasks": trial.client_incomplete_tasks,
        "contained": trial.contained,
        "utility_intact": trial.utility_intact,
        "latency": _latency(policy.seconds),
        "cedar_authorization_calls": getattr(inner, "cedar_calls", None),
        "trial_digest": trial.digest(),
    }


def _agreement(scenario_id: str, behavior: str) -> dict[str, Any]:
    """Replay every policy over the contexts the reference policy produced.

    The trace is policy-dependent -- a denial changes what the client does
    next -- so this is agreement over *one* trajectory, the reference's, not
    over a policy-neutral corpus. Stated rather than smoothed over.
    """
    scenario = load_scenario(scenario_id)
    recorder = RecordingPolicy(load_policy("reference"))
    _, records = run_trial(scenario, recorder, lambda: ScriptedProvider(behavior=behavior))
    probe_contexts = sum(len(r.log.of_type("probe.shadow_evaluated")) for r in records)

    rows: dict[str, Any] = {}
    for name in ABLATION_POLICIES:
        if name == "reference":
            continue
        policy = load_policy(name)
        effect_agree = 0
        rule_agree = 0
        disagreements: dict[str, int] = {}
        for ctx, expected in zip(recorder.contexts, recorder.decisions, strict=True):
            got = policy.evaluate(ctx)
            if got.effect is expected.effect:
                effect_agree += 1
                if got.rule_id == expected.rule_id:
                    rule_agree += 1
            else:
                key = f"{expected.rule_id} -> {got.rule_id}"
                disagreements[key] = disagreements.get(key, 0) + 1
        rows[name] = {
            "contexts": len(recorder.contexts),
            "effect_agreements": effect_agree,
            "rule_id_agreements": rule_agree,
            "disagreements_by_rule": dict(sorted(disagreements.items())),
            "cedar_authorization_calls": getattr(policy, "cedar_calls", None),
        }
    return {
        "contexts": len(recorder.contexts),
        # The shadow probe evaluates the policy against hypothetical routes as
        # well as the dispatched ones, and those contexts pass through this
        # recorder too. Reported so the population is not mistaken for the
        # dispatch trace alone.
        "shadow_probe_contexts": probe_contexts,
        "dispatch_contexts": len(recorder.contexts) - probe_contexts,
        "policies": rows,
    }


def main() -> int:
    from importlib.metadata import PackageNotFoundError, version

    try:
        version("cedarpy")
    except PackageNotFoundError:
        print("this ablation needs the cedar extra:  pip install interpose[cedar]")
        return 3
    cedarpy_version = version("cedarpy")

    cells = [
        _cell(name, scenario, behavior)
        for scenario in SCENARIOS
        for behavior in BEHAVIORS
        for name in ABLATION_POLICIES
    ]
    supplementary = [
        _cell(name, scenario, behavior)
        for scenario in SCENARIOS
        for behavior in BEHAVIORS
        for name in SUPPLEMENTARY_POLICIES
    ]
    agreement = {
        f"{scenario}:scripted:{behavior}": _agreement(scenario, behavior)
        for scenario in SCENARIOS
        for behavior in BEHAVIORS
    }

    artifact = {
        "artifact": "cedar-provenance-ablation",
        "artifact_version": "1",
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "bench_version": BENCH_VERSION,
        "harness_version": __version__,
        "python_version": sys.version.split()[0],
        "platform": f"{platform.system()}-{platform.machine()}",
        "cedarpy_version": cedarpy_version,
        "independent_variable": (
            "whether the policy enforcement point supplies the write's provenance to "
            "Cedar. cedar-action-only and cedar-with-provenance load identical Cedar "
            "policy text and an identical schema."
        ),
        "note_on_counts": (
            "Every figure here is a count or a duration. No rates, no percentages: a "
            "single deterministic run over a two-scenario corpus does not license one."
        ),
        "cells": cells,
        "supplementary_cells": supplementary,
        "agreement_replay": agreement,
    }

    out = Path(__file__).resolve().parent / "cedar-ablation.json"
    out.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out}")

    header = f"{'scenario':<28} {'client':<14} {'policy':<24} {'verdict':<24}"
    print(f"{header} exp  poss esc  gap  benign fd den  mean_ms")
    for cell in cells + supplementary:
        outcome = cell
        print(
            f"{outcome['scenario']:<28} {outcome['provider'].split(':')[1]:<14} "
            f"{outcome['policy']:<24} {outcome['verdict']:<24} "
            f"{str(outcome['sensitive_data_exposed'])[0]:<4} "
            f"{str(outcome['possible_exposure'])[0]:<4} "
            f"{str(outcome['enforcement_escape'])[0]:<4} "
            f"{str(outcome['authorization_gap_open'])[0]:<4} "
            f"{outcome['benign_passed']}/{outcome['benign_total']}    "
            f"{outcome['false_denials']}  {outcome['attack_denials']}    "
            f"{outcome['latency']['mean_ms']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
