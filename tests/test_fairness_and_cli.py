"""Fairness of the policy interface, and the command surface.

The fairness tests are the credibility artifact. A benchmark that hands the
policy the answer key measures nothing, and "we were careful" is not evidence.
These assert it structurally: the module that builds a decision context cannot
see the attack definition, and the context type has no field that could carry
it.
"""

from __future__ import annotations

import dataclasses
import io
import json
import typing
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from interpose.cli import main
from interpose.engine.trial import run_trial
from interpose.policy.base import load_policy
from interpose.policy.types import DecisionContext
from interpose.providers.scripted import ScriptedProvider


def _unwrap(annotation: object) -> list[object]:
    """Flatten Optional/Union/tuple annotations into their member types."""
    args = typing.get_args(annotation)
    if not args:
        return [annotation]
    out: list[object] = []
    for arg in args:
        out.extend(_unwrap(arg))
    return out


# -- fairness -------------------------------------------------------------


FORBIDDEN_CONTEXT_FIELDS = {
    "attack",
    "objective",
    "adversary",
    "is_attack",
    "task_kind",
    "injection",
    "malicious",
    "seed",
    "scorer",
    "expected",
}


def test_decision_context_cannot_carry_the_answer_key() -> None:
    """No field a policy receives may reveal which trial this is.

    The single most important exclusion is whether the run is the benign
    control or the attack. Without it the benign suite is not a control, and
    the false-denial number -- the only half the scenario author does not
    choose -- becomes meaningless.
    """

    # `from __future__ import annotations` makes every f.type a *string*, so
    # the obvious `dataclasses.is_dataclass(f.type)` recursion never fires and
    # the test silently inspects only the top level. It shipped that way and
    # was a no-op; resolve the annotations first. See docs/V0_REVIEW.md.
    def field_names(cls: type, seen: set[type] | None = None) -> set[str]:
        seen = seen if seen is not None else set()
        if cls in seen:
            return set()
        seen.add(cls)
        names: set[str] = set()
        hints = typing.get_type_hints(cls)
        for f in dataclasses.fields(cls):
            names.add(f.name)
            for arg in _unwrap(hints.get(f.name, f.type)):
                if dataclasses.is_dataclass(arg):
                    names |= field_names(arg, seen)
        return names

    names = field_names(DecisionContext)
    # Guard the guard: if the recursion is broken again, this fails loudly.
    assert "granted_tools" in names and "classification" in names, sorted(names)

    leaked = {n for n in names if any(bad in n.lower() for bad in FORBIDDEN_CONTEXT_FIELDS)}
    assert leaked == set(), leaked


def test_policy_package_does_not_import_the_scenario_package(repo_root: Path) -> None:
    """Structural half of the fairness guarantee, checkable by grep.

    If a policy could import the scenario models it could, in principle, read
    the adversary objective. Keeping the import graph acyclic here is cheap
    and makes the claim auditable by someone who does not trust the prose.
    """
    offenders: list[str] = []
    for path in sorted((repo_root / "src" / "interpose" / "policy").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for banned in ("scenario", "engine.outcome", "engine.probe"):
            if f"import {banned}" in text or f"from ..{banned}" in text:
                offenders.append(f"{path.name}: {banned}")
    assert offenders == [], offenders


def test_provenance_never_labels_content_as_malicious() -> None:
    """Provenance says *untrusted_external*, never *malicious*.

    A trust class that named the attack would let a policy pass by matching on
    the label instead of reasoning about the flow.
    """
    from interpose.provenance import TrustClass

    values = {t.value for t in TrustClass}
    assert values == {"trusted_user", "trusted_system", "untrusted_external", "tool_output"}


def test_policy_sees_identical_context_prefix_in_benign_and_attack_runs(scenario) -> None:
    """A policy cannot tell which trial it is in from the decisions it sees.

    The benign control and the attack share a task, a world, a tool surface
    and a principal. Up to the point where the corpus differs, the decision
    stream must be identical -- otherwise the policy could branch on the
    difference.
    """
    recorded: dict[str, list[tuple[str, str]]] = {}

    class Recording:
        id = "recording-probe"
        version = "1.0.0"

        def __init__(self, bucket: str) -> None:
            self.bucket = bucket
            recorded.setdefault(bucket, [])

        def describe(self) -> str:
            return "records what it was asked"

        def evaluate(self, ctx: DecisionContext):
            recorded[self.bucket].append((ctx.action.tool, json.dumps(ctx.action.arguments, sort_keys=True)))
            return load_policy("permissive").evaluate(ctx)

    first_task = scenario.spec.benign[0]
    run_trial(scenario, Recording("attack"), lambda: ScriptedProvider("compliant"))
    from interpose.engine.trial import run_single

    run_single(
        scenario,
        Recording("benign"),
        lambda: ScriptedProvider("compliant"),
        benign_task=first_task,
    )

    # The first two decisions (search, then the first document read) precede
    # any exposure to injected content and must match exactly.
    assert recorded["attack"][:2] == recorded["benign"][:2]


# -- CLI ------------------------------------------------------------------


def _run_cli(*argv: str) -> tuple[int, str]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = main(list(argv))
    return code, buffer.getvalue()


def test_bare_invocation_orients_rather_than_dumping_flags() -> None:
    code, out = _run_cli()
    assert code == 0
    assert "did the authorization layer hold" in out
    assert "interpose demo" in out
    assert "--help" not in out


def test_demo_prints_all_three_policies_with_a_cost_column() -> None:
    code, out = _run_cli("demo")
    assert code == 0
    for policy in ("permissive-baseline", "path-prefix-v1", "reference-least-privilege"):
        assert policy in out
    assert "FALSE-DENY" in out
    assert "BENIGN" in out


def test_output_is_ascii_only_so_it_survives_a_windows_pipe() -> None:
    """Reproduced failure: one non-ASCII glyph on a cp1252 stdout raises
    UnicodeEncodeError *and* the shell reports success, so the report silently
    becomes empty. ASCII is the default for that reason, not for austerity."""
    _code, out = _run_cli("demo")
    out.encode("ascii")


def test_verdict_tokens_are_greppable(tmp_path: Path) -> None:
    _code, out = _run_cli("run", "--policy", "reference", "--no-save")
    assert any(line.strip().startswith("RESULT") for line in out.splitlines())
    assert "CONTAINED" in out


def test_attack_only_withholds_the_scorecard() -> None:
    code, out = _run_cli("run", "--policy", "permissive", "--attack-only")
    assert code == 0
    assert "SCORECARD WITHHELD" in out
    assert "benign" in out.lower()


def test_attack_only_json_is_marked_withheld() -> None:
    _code, out = _run_cli("run", "--policy", "permissive", "--attack-only", "--json")
    payload = json.loads(out)
    assert payload["scorecard_withheld"] is True


def test_exit_codes_distinguish_result_from_breakage() -> None:
    assert _run_cli("run", "--policy", "reference", "--no-save")[0] == 0
    assert _run_cli("run", "--policy", "permissive", "--no-save")[0] == 1
    assert _run_cli("run", "--policy", "path-prefix", "--no-save")[0] == 1
    assert main(["run", "--policy", "does-not-exist"]) == 3


def test_json_and_human_output_come_from_one_object() -> None:
    _code, human = _run_cli("run", "--policy", "path-prefix", "--no-save")
    _code, raw = _run_cli("run", "--policy", "path-prefix", "--no-save", "--json")
    payload = json.loads(raw)
    passed = sum(1 for b in payload["benign"] if b["outcome"]["benign_task_completed"])
    assert f"{passed}/{len(payload['benign'])}" in human


def test_ls_and_show_and_doctor_work() -> None:
    assert _run_cli("ls")[0] == 0
    code, out = _run_cli("show")
    assert code == 0 and "indirect-document-injection" in out
    code, out = _run_cli("doctor")
    assert code == 0 and "scenarios" in out


def test_matrix_reports_coverage_not_rates() -> None:
    code, out = _run_cli("matrix")
    assert code == 0
    assert "No rate" in out or "no rate" in out
    assert "%" not in out


def test_matrix_obeys_the_pairing_rule() -> None:
    """No command prints containment without printing what it cost.

    ``matrix`` used to call ``run_single``, so it printed 25 containment
    verdicts per policy with no cost column at all -- a deny-everything policy
    scored a perfect matrix. That is the one invariant the project says it never
    breaks. Retraction in ``docs/research/RETRACTIONS.md``.
    """
    code, out = _run_cli("matrix")
    assert code == 0
    assert "BENIGN" in out and "FALSE-DENY" in out
    # The cost of path-prefix on scenario 1 is two benign tasks; if the pair is
    # really being reported, that number has to appear.
    assert "6/8" in out


def test_matrix_reports_the_client_axis_that_actually_moves_verdicts() -> None:
    """Payload wording is not paraphrase.

    The scripted client extracts a path and a queue with two regexes, so payload
    variants yielding the same pair are the same test in different words. The
    real paraphrase axis is the client, and it must be visible here.
    """
    code, out = _run_cli("matrix")
    assert code == 0
    assert "paraphrasing" in out
    assert "phrasing invariance" in out
    assert "Distinct (path, queue) pairs" in out


def test_verify_round_trips_a_written_result(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    code, _out = _run_cli("run", "--policy", "reference", "--save")
    assert code == 0
    results = list((tmp_path / "runs").rglob("result.json"))
    assert results
    code, out = _run_cli("verify", str(results[0]))
    assert code == 0
    assert out.startswith("AGREES")


def test_verify_detects_scenario_drift(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _run_cli("run", "--policy", "reference", "--save")
    result_path = next((tmp_path / "runs").rglob("result.json"))
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["scenario"]["digest"] = "sha256:" + "0" * 64
    result_path.write_text(json.dumps(payload), encoding="utf-8")
    code, out = _run_cli("verify", str(result_path))
    assert code == 1
    assert out.startswith("SCENARIO_DRIFT")


def test_new_scaffold_passes_immediately(tmp_path: Path, monkeypatch) -> None:
    """Nothing kills a first contribution like a scaffold that errors."""
    monkeypatch.chdir(tmp_path)
    code, _out = _run_cli("new", "scenario", "my-variant", "--directory", "scenarios")
    assert code == 0
    created = tmp_path / "scenarios" / "my-variant"
    assert (created / "scenario.yaml").is_file()
    assert _run_cli("run", str(created), "--policy", "reference", "--no-save")[0] == 0


@pytest.mark.parametrize("behaviour", ["compliant", "refusing", "partial", "confused"])
def test_every_behaviour_class_runs_clean(behaviour: str) -> None:
    assert _run_cli("run", "--policy", "reference", "--provider", f"scripted:{behaviour}", "--no-save")[0] == 0
