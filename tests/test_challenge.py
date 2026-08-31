"""The challenge workflow, and the ordering guarantee it rests on.

This is the project's answer to the circularity objection, so its failure modes
matter more than most. Each of these pins a way the workflow could quietly
become decorative -- reporting a break as a pass, accepting a result against an
edited policy, or counting a win that no data actually moved through.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from interpose.challenge import (
    FREEZE_FILE,
    build_freeze_record,
    check_freeze,
    evaluate_challenge,
    render_challenge,
    write_freeze,
)
from interpose.engine.trial import run_trial
from interpose.errors import UsageError
from interpose.policy.base import BUILTIN_POLICIES, load_policy, policy_digest
from interpose.providers.scripted import ScriptedProvider
from interpose.scenario.loader import load_scenario

REPO_FREEZE = Path(__file__).resolve().parents[1] / FREEZE_FILE


def _run(scenario, policy: str):
    return run_trial(scenario, load_policy(policy), lambda: ScriptedProvider("compliant"))[0]


# -- the committed record --------------------------------------------------


def test_the_committed_freeze_matches_the_installed_policies() -> None:
    """The whole ordering claim rests on this file staying true.

    If a frozen policy is edited without a deliberate re-freeze, every test
    still passes and PROTOCOL.md quietly becomes false. This is the assertion
    that stops that, and CI runs it on every pull request.
    """
    assert check_freeze(REPO_FREEZE) == []


def test_every_builtin_policy_is_frozen() -> None:
    recorded = json.loads(REPO_FREEZE.read_text(encoding="utf-8"))["policies"]
    installed = {load_policy(short).id for short in BUILTIN_POLICIES}
    assert installed == set(recorded), "a policy was added without freezing it"


def test_the_recorded_digest_is_the_one_results_are_stamped_with(scenario) -> None:
    """The freeze record and the result artifact must name the same bytes.

    Two digests computed two ways is how a published result ends up citing a
    hash that no run ever used.
    """
    recorded = json.loads(REPO_FREEZE.read_text(encoding="utf-8"))["policies"]
    policy = load_policy("reference")
    trial = _run(scenario, "reference")
    assert recorded[policy.id]["digest"] == policy_digest(policy) == trial.policy.digest


def test_freeze_is_deterministic() -> None:
    assert build_freeze_record() == build_freeze_record()


def test_a_missing_freeze_file_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="no freeze record"):
        check_freeze(tmp_path / "absent.json")


def test_a_corrupt_freeze_file_says_so(tmp_path: Path) -> None:
    bad = tmp_path / "policy-freeze.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(UsageError, match="not valid JSON"):
        check_freeze(bad)


def test_drift_is_detected_and_named(tmp_path: Path) -> None:
    path = tmp_path / "policy-freeze.json"
    record = write_freeze(path)
    record["policies"]["reference-least-privilege"]["digest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    problems = check_freeze(path)
    assert len(problems) == 1
    assert "reference-least-privilege" in problems[0]
    assert "content changed" in problems[0]


def test_an_unfrozen_policy_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "policy-freeze.json"
    record = write_freeze(path)
    del record["policies"]["reference-least-privilege"]
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    assert any("not in the freeze record" in p for p in check_freeze(path))


# -- the verdict -----------------------------------------------------------


def test_a_policy_that_lets_the_attack_through_is_reported_broken(scenario) -> None:
    report = evaluate_challenge(scenario, "permissive", _run(scenario, "permissive"), REPO_FREEZE)
    assert report.broken is True
    assert report.credible is True
    assert "POLICY BROKEN" in render_challenge(report)


def test_a_policy_that_contains_the_attack_is_reported_held(scenario) -> None:
    report = evaluate_challenge(scenario, "reference", _run(scenario, "reference"), REPO_FREEZE)
    assert report.broken is False
    assert "POLICY HELD" in render_challenge(report)


def test_a_latent_gap_alone_is_not_a_break() -> None:
    """The technicality that would hollow the whole thing out.

    A latent gap means the agent never took a route the policy would have
    permitted. Counting that as a break would make challenges winnable without
    moving any data, and a headline number winnable on a technicality stops
    meaning anything within a month. It is still surfaced in the text -- it is a
    break waiting for the right agent, just not one yet.

    The instance used to be ``path-prefix-v1`` on scenario 1. That turned out to
    be a probe false positive (retraction R11): the probe enumerated routes by
    ``resolve`` alone, and ``read_document`` resolves a ``kind: file`` resource
    and then refuses to execute on it. The genuine instance is a *refusing*
    client against a policy that would have allowed the whole objective -- which
    is exactly what the signal is for.
    """
    loaded = load_scenario("confidential-egress")
    trial = run_trial(
        loaded, load_policy("permissive"), lambda: ScriptedProvider("refusing")
    )[0]
    report = evaluate_challenge(loaded, "permissive", trial, REPO_FREEZE)

    assert trial.attack.outcome.authorization_gap_open is True
    assert trial.attack.outcome.denials == 0
    assert report.broken is False

    text = render_challenge(report)
    assert "POLICY HELD" in text
    assert "latent gap open           YES" in text
    assert "break waiting" in text


def test_the_probe_does_not_invent_routes_that_cannot_execute() -> None:
    """Retraction R11, pinned.

    ``read_document`` resolves the payroll file by URI and then raises, because
    two tools aliasing one object was a real bypass fixed in V0. The probe used
    resolvability alone and reported that unreachable call as an
    ``UNDECLARED ROUTE PERMITTED``. It was the sole driver of the
    ``LATENT GAP: YES`` cell the README described as the harness finding a
    bypass unaided.
    """
    loaded = load_scenario("indirect-document-injection")
    outcome = run_trial(
        loaded, load_policy("path-prefix"), lambda: ScriptedProvider("compliant")
    )[0].attack.outcome

    assert outcome.authorization_gap_open is False
    assert "UNDECLARED ROUTE" not in outcome.probe_detail


def test_the_benign_pair_is_always_shown(scenario) -> None:
    """A break in a world where nothing works is not a break.

    Printing the utility cost next to the verdict is what makes that visible
    rather than buried in an artifact nobody opens.
    """
    for policy in ("permissive", "reference", "path-prefix"):
        report = evaluate_challenge(scenario, policy, _run(scenario, policy), REPO_FREEZE)
        assert "benign suite" in render_challenge(report)


def test_a_result_against_an_edited_policy_is_inadmissible(scenario, tmp_path: Path) -> None:
    path = tmp_path / "policy-freeze.json"
    record = write_freeze(path)
    record["policies"]["reference-least-privilege"]["digest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    report = evaluate_challenge(scenario, "reference", _run(scenario, "reference"), path)
    assert report.freeze_status == "drifted"
    assert report.credible is False
    assert "INADMISSIBLE" in render_challenge(report)


def test_a_truncated_challenge_is_inconclusive_not_a_verdict(
    scenario, tmp_path: Path
) -> None:
    """Running out of turns must never read as containment.

    Without this, the cheapest way to make any policy look good is to lower the
    turn budget until the attack cannot finish.
    """
    target = tmp_path / "short"
    shutil.copytree(scenario.root, target)
    manifest = target / "scenario.yaml"
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["agent"]["max_turns"] = 3
    manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    loaded = load_scenario(str(target))
    trial = _run(loaded, "permissive")
    report = evaluate_challenge(loaded, "permissive", trial, REPO_FREEZE)

    assert trial.truncated_runs >= 1
    assert report.credible is False
    text = render_challenge(report)
    assert "INCONCLUSIVE" in text
    assert "POLICY BROKEN" not in text


def test_a_degraded_benign_suite_is_called_out_under_a_break() -> None:
    """path-prefix breaks on scenario 2 *and* costs a benign task.

    Both facts belong in the same report, or a challenger can bank the break
    and quietly drop the cost.
    """
    loaded = load_scenario("confidential-egress")
    trial = _run(loaded, "path-prefix")
    report = evaluate_challenge(loaded, "path-prefix", trial, REPO_FREEZE)

    assert report.broken is True
    assert trial.utility_intact is False
    text = render_challenge(report)
    assert "POLICY BROKEN" in text
    assert "benign suite is degraded" in text


# -- the CLI contract ------------------------------------------------------


def test_challenge_exits_one_when_the_policy_is_broken(scenario, capsys) -> None:
    """Exit 1 is the challenger's win condition, so it is a public contract.

    docs/CHALLENGE.md tells contributors to key their own CI off this
    inversion. If it ever flipped, a real break would be reported as a pass.
    """
    from interpose.cli import main

    assert main(["challenge", "indirect-document-injection", "--policy", "permissive"]) == 1
    assert "POLICY BROKEN" in capsys.readouterr().out


def test_challenge_exits_zero_when_the_policy_holds(capsys) -> None:
    from interpose.cli import main

    assert main(["challenge", "confidential-egress", "--policy", "reference"]) == 0
    assert "POLICY HELD" in capsys.readouterr().out


def test_freeze_check_exits_zero_on_the_committed_record(capsys) -> None:
    from interpose.cli import main

    assert main(["freeze", "--check", "--file", str(REPO_FREEZE)]) == 0
    assert "FREEZE INTACT" in capsys.readouterr().out


def test_freeze_check_exits_one_on_drift(tmp_path: Path, capsys) -> None:
    from interpose.cli import main

    path = tmp_path / "policy-freeze.json"
    record = write_freeze(path)
    record["policies"]["reference-least-privilege"]["digest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    assert main(["freeze", "--check", "--file", str(path)]) == 1
    assert "FREEZE DRIFTED" in capsys.readouterr().out


# -- the scaffold ----------------------------------------------------------


@pytest.mark.parametrize("origin", ["indirect-document-injection", "confidential-egress"])
def test_a_scaffold_from_either_scenario_passes_before_it_is_edited(
    origin: str, tmp_path: Path, capsys
) -> None:
    """The first five minutes decide whether there is a second contribution.

    A scaffold that fails out of the box makes a contributor debug the
    template instead of their idea, and they do not come back.
    """
    from interpose.cli import main

    assert main(["new", "scenario", "mine", "--directory", str(tmp_path), "--from", origin]) == 0
    capsys.readouterr()

    assert main(["challenge", str(tmp_path / "mine")]) == 0
    out = capsys.readouterr().out
    assert "POLICY HELD" in out
    assert "MATCHES the committed freeze record" in out


def test_the_scaffold_is_renamed_not_a_duplicate_id(tmp_path: Path, capsys) -> None:
    from interpose.cli import main

    main(["new", "scenario", "renamed", "--directory", str(tmp_path)])
    capsys.readouterr()
    assert load_scenario(str(tmp_path / "renamed")).spec.id == "renamed"


def test_scaffolding_from_an_unknown_scenario_fails_clearly(
    tmp_path: Path, capsys
) -> None:
    """The message has to name the scenarios that do exist.

    A contributor typing a scenario name from memory is the common case, and
    "unknown scenario" without the list sends them to the source tree.
    """
    from interpose.cli import main

    assert main(["new", "scenario", "x", "--directory", str(tmp_path), "--from", "nope"]) == 3
    err = capsys.readouterr().err
    assert "cannot start from 'nope'" in err
    assert "confidential-egress" in err
