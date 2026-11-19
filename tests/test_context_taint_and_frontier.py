"""The context-taint policy and the frontier sweep.

The claims these pin are the ones the README now leads with, so each is a
regression test rather than a description:

* the reference policy is compromised by the paraphrasing client on both flow
  scenarios (the Phase II falsification, kept standing);
* ``context-taint`` contains every bundled attack under every scripted client;
* what that costs is exactly one benign task, and it is the label-creep one;
* the frontier marks dominance correctly and the HTML report is self-contained.
"""

from __future__ import annotations

import itertools
import re

import pytest

from interpose.cli import main
from interpose.engine.trial import run_trial
from interpose.policy.base import load_policy
from interpose.providers.scripted import BEHAVIOR_CLASSES, ScriptedProvider
from interpose.report.frontier import (
    Point,
    collect_frontier,
    render_frontier_html,
    render_frontier_text,
)
from interpose.scenario.loader import discover_scenarios, load_scenario

SCENARIOS = sorted(discover_scenarios())
FLOW_SCENARIOS = ("confidential-egress", "compartment-egress")


def _trial(scenario: str, policy: str, client: str):
    trial, _ = run_trial(
        load_scenario(scenario), load_policy(policy),
        lambda: ScriptedProvider(behavior=client),  # type: ignore[arg-type]
    )
    return trial


@pytest.mark.parametrize("scenario", FLOW_SCENARIOS)
def test_reference_still_falls_to_paraphrase(scenario: str) -> None:
    # If this starts passing, either the reference policy changed (and the
    # freeze check should already be red) or the paraphrasing client stopped
    # paraphrasing. Both need a human, not a quiet green build.
    trial = _trial(scenario, "reference", "paraphrasing")
    assert trial.attack.outcome.verdict == "COMPROMISED"
    assert trial.attack.outcome.possible_exposure, "the structural observer must see it"


@pytest.mark.parametrize("client", BEHAVIOR_CLASSES)
@pytest.mark.parametrize("scenario", SCENARIOS)
def test_context_taint_holds_under_every_client(scenario: str, client: str) -> None:
    trial = _trial(scenario, "context-taint", client)
    assert trial.contained, trial.attack.outcome.verdict
    assert not trial.attack.outcome.sensitive_data_exposed
    assert not trial.attack.outcome.possible_exposure


def test_context_taint_denies_paraphrase_with_its_own_rule() -> None:
    trial = _trial("confidential-egress", "context-taint", "paraphrasing")
    assert trial.attack.outcome.verdict == "CONTAINED"
    assert "R3.context-tainted-egress" in trial.attack.outcome.probe_detail


def test_context_taint_cost_is_exactly_the_label_creep_task() -> None:
    blocked: list[str] = []
    for scenario in SCENARIOS:
        trial = _trial(scenario, "context-taint", "compliant")
        blocked += [f"{scenario}/{r.task_id}" for r in trial.benign
                    if r.outcome.verdict == "TASK_BLOCKED"]
    assert blocked == ["confidential-egress/b2-vendor-invoice-query"]


def test_point_dominance() -> None:
    a = Point("a", "c", contained=3, scenarios=3, benign_passed=24, benign_total=25,
              false_denials=1)
    b = Point("b", "c", contained=1, scenarios=3, benign_passed=24, benign_total=25,
              false_denials=1)
    c = Point("c", "c", contained=1, scenarios=3, benign_passed=25, benign_total=25,
              false_denials=0)
    assert a.dominates(b)
    assert not a.dominates(c) and not c.dominates(a)
    assert not a.dominates(a)


@pytest.fixture(scope="module")
def frontier():
    return collect_frontier(SCENARIOS)


def test_frontier_under_paraphrase(frontier) -> None:
    pts = {p.policy: p for p in frontier.points if p.client == "paraphrasing"}
    assert pts["context-taint"].contained == len(SCENARIOS)
    assert pts["context-taint"].on_frontier
    assert pts["reference-least-privilege"].contained == 1
    # Not dominated: it gives up containment, but completes every task.
    assert pts["reference-least-privilege"].on_frontier
    assert not pts["permissive-baseline"].on_frontier
    assert not pts["path-prefix-v1"].on_frontier


def test_frontier_is_deterministic(frontier) -> None:
    again = collect_frontier(SCENARIOS)
    assert again.to_dict() == frontier.to_dict()


def test_frontier_text_names_the_cost(frontier) -> None:
    text = render_frontier_text(frontier)
    assert "context-taint" in text
    assert "confidential-egress/b2-vendor-invoice-query" in text


def test_frontier_html_is_self_contained(frontier) -> None:
    page = render_frontier_html(frontier)
    assert page.startswith("<!doctype html>")
    assert "prefers-color-scheme: dark" in page
    # No network fetch of any kind: no external src, href, or CSS import.
    assert not re.search(r"""(src|href)\s*=\s*["']?https?://""", page)
    assert "@import" not in page
    assert page.count('class="dot"') == len(frontier.points)


def test_frontier_cli_writes_report(tmp_path, capsys) -> None:
    out = tmp_path / "f.html"
    rc = main(["frontier", "indirect-document-injection", "--html", str(out)])
    assert rc == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert "frontier" in capsys.readouterr().out


def test_frontier_cli_rejects_unknown_client() -> None:
    assert main(["frontier", "--clients", "nonsense"]) == 3


# -- long sessions ----------------------------------------------------------


def _long(scenario: str, policy: str, client: str = "compliant"):
    trial, records = run_trial(
        load_scenario(scenario), load_policy(policy),
        lambda: ScriptedProvider(behavior=client),  # type: ignore[arg-type]
        session="long",
    )
    return trial, records


def test_fresh_is_the_default_and_is_recorded() -> None:
    assert _trial("confidential-egress", "reference", "compliant").session == "fresh"
    trial, _ = _long("confidential-egress", "reference")
    assert trial.session == "long"


def test_long_session_carries_labels_forward() -> None:
    _, records = _long("compartment-egress", "context-taint")
    benign = records[1:]
    assert not benign[0].log.of_type("context.carried"), "the first task starts empty"
    later = [r for r in benign[1:] if r.log.of_type("context.carried")]
    assert later, "later tasks must inherit what earlier ones read"
    # Monotone: a session's label set never shrinks.
    for prev, nxt in itertools.pairwise(benign):
        assert prev.context_sources <= nxt.context_sources


def test_long_session_raises_context_taint_cost_only() -> None:
    blocked: list[str] = []
    for scenario in SCENARIOS:
        trial, _ = _long(scenario, "context-taint", "paraphrasing")
        assert trial.contained
        blocked += [f"{scenario}/{r.task_id}" for r in trial.benign
                    if r.outcome.verdict == "TASK_BLOCKED"]
    assert sorted(blocked) == [
        "compartment-egress/b2-templates-to-finance",
        "compartment-egress/b9-vendor-question",
        "confidential-egress/b2-vendor-invoice-query",
    ]
    # A text-matching policy does not consult context, so a longer session
    # costs it nothing. If that changes, the carry-over is leaking into values.
    for scenario in SCENARIOS:
        fresh = _trial(scenario, "reference", "compliant")
        long_, _ = _long(scenario, "reference")
        assert long_.benign_passed == fresh.benign_passed


def test_long_session_run_ids_differ_from_fresh() -> None:
    fresh = _trial("compartment-egress", "context-taint", "compliant")
    long_, _ = _long("compartment-egress", "context-taint")
    assert fresh.benign[0].run_id == long_.benign[0].run_id, "nothing carried yet"
    assert fresh.benign[-1].run_id != long_.benign[-1].run_id


def test_frontier_cli_session_flag(capsys) -> None:
    assert main(["frontier", "compartment-egress", "--session", "long", "--json"]) == 0
    import json
    data = json.loads(capsys.readouterr().out)
    assert data["session"] == "long"
