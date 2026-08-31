"""Failures that used to be silent.

A benchmark that reports a wrong number without saying so is worse than one
that crashes: the crash gets fixed, the number gets quoted. Each test here
pins a failure mode that previously changed a published figure with nothing in
the output to indicate it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from interpose.engine.trial import run_trial
from interpose.errors import ScenarioError
from interpose.policy.base import load_policy
from interpose.providers.scripted import ScriptedProvider
from interpose.report.result import exit_code_for
from interpose.scenario.loader import load_scenario


def _copy(scenario, tmp_path: Path, mutate) -> Path:
    """Copy the bundled scenario, apply ``mutate`` to its manifest, return the dir."""
    target = tmp_path / "case"
    shutil.copytree(scenario.root, target)
    manifest = target / "scenario.yaml"
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    mutate(data)
    manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return target


# -- turn-budget truncation ------------------------------------------------


def test_a_truncated_run_is_reported_and_fails(scenario, tmp_path: Path) -> None:
    """Running out of turns must not look like a verdict.

    The permissive attack run used to fit the budget with one turn to spare.
    One more document in the corpus and COMPROMISED would silently become
    NOT_ATTEMPTED -- a headline result flipped by an unrelated edit, with
    nothing in the output saying why.
    """
    root = _copy(scenario, tmp_path, lambda d: d["agent"].__setitem__("max_turns", 3))
    loaded = load_scenario(str(root))

    trial, _ = run_trial(
        loaded, load_policy("permissive"), lambda: ScriptedProvider("compliant")
    )

    assert trial.attack.outcome.turn_limit_reached is True
    assert trial.truncated_runs >= 1
    # A truncated scorecard is not a result, whatever the verdict says.
    assert exit_code_for(trial) == 1


def test_an_untruncated_run_is_not_flagged(scenario) -> None:
    trial, _ = run_trial(
        scenario, load_policy("reference"), lambda: ScriptedProvider("compliant")
    )
    assert trial.truncated_runs == 0
    assert trial.attack.outcome.turn_limit_reached is False


def test_the_bundled_scenarios_have_turn_headroom() -> None:
    """Every shipped scenario must finish with room to spare.

    Sitting exactly on the budget is how the previous version shipped, and it
    made the headline verdict one corpus document away from flipping.
    """
    from interpose.scenario.loader import discover_scenarios

    for sid in discover_scenarios():
        loaded = load_scenario(sid)
        for policy in ("permissive", "reference"):
            trial, _ = run_trial(
                loaded, load_policy(policy), lambda: ScriptedProvider("compliant")
            )
            assert trial.truncated_runs == 0, f"{sid} under {policy} hit the turn budget"


# -- unresolvable declared calls -------------------------------------------


def test_a_required_call_naming_an_unknown_tool_is_refused(scenario, tmp_path: Path) -> None:
    def mutate(d: dict) -> None:
        d["benign"][0]["requires_calls"][0]["tool"] = "send_email"

    root = _copy(scenario, tmp_path, mutate)
    with pytest.raises(ScenarioError, match="no such tool 'send_email'"):
        load_scenario(str(root))


def test_a_required_call_naming_a_missing_resource_is_refused(
    scenario, tmp_path: Path
) -> None:
    def mutate(d: dict) -> None:
        d["benign"][3]["requires_calls"][0]["args"]["uri"] = "res://docs/internal/nope"

    root = _copy(scenario, tmp_path, mutate)
    with pytest.raises(ScenarioError, match="no resource 'res://docs/internal/nope'"):
        load_scenario(str(root))


def test_a_required_call_naming_a_missing_path_is_refused(scenario, tmp_path: Path) -> None:
    def mutate(d: dict) -> None:
        d["benign"][0]["requires_calls"][0]["args"]["path"] = "/hr/nope.csv"

    root = _copy(scenario, tmp_path, mutate)
    with pytest.raises(ScenarioError, match=r"no file resource at path '/hr/nope.csv'"):
        load_scenario(str(root))


def test_a_required_call_naming_a_missing_queue_is_refused(scenario, tmp_path: Path) -> None:
    def mutate(d: dict) -> None:
        d["benign"][0]["requires_calls"][1]["args"]["queue"] = "nowhere"

    root = _copy(scenario, tmp_path, mutate)
    with pytest.raises(ScenarioError, match="no queue 'nowhere'"):
        load_scenario(str(root))


def test_a_call_using_a_tool_the_agent_lacks_is_refused(scenario, tmp_path: Path) -> None:
    """Granted-but-unusable is the subtle case.

    The tool exists, so a name check passes; the agent was never given it, so
    the task is unsatisfiable anyway.
    """

    def mutate(d: dict) -> None:
        d["agent"]["tools"] = [t for t in d["agent"]["tools"] if t != "read_internal_file"]

    root = _copy(scenario, tmp_path, mutate)
    with pytest.raises(ScenarioError, match=r"not in agent\.tools"):
        load_scenario(str(root))


def test_an_attack_objective_naming_a_missing_asset_is_refused(
    scenario, tmp_path: Path
) -> None:
    def mutate(d: dict) -> None:
        d["attack"]["protected_assets"] = ["res://files/hr/imaginary.csv"]

    root = _copy(scenario, tmp_path, mutate)
    with pytest.raises(ScenarioError, match="protected_assets"):
        load_scenario(str(root))


def test_both_bundled_scenarios_validate() -> None:
    from interpose.scenario.loader import discover_scenarios

    ids = list(discover_scenarios())
    assert len(ids) >= 2, ids
    for sid in ids:
        load_scenario(sid)
