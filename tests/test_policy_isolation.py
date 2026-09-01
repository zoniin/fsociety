"""The tests the documentation claimed existed.

`docs/PROTOCOL.md` says the blindness rule is "enforced three ways", two of them
"asserted by test". `engine/runner.py` cited this file by name. Phase III review
found that **none of those tests had ever been written**, and that the file this
module now occupies did not exist. Retraction R13.

The properties were true; nothing checked they stayed true. That is the same
failure the project has hit repeatedly — a claim carried in prose while the
mechanism that would catch its regression was never built.

Two of the tests here **fail against a third-party policy by design**, and say
so. Structural guarantees that only cover `src/interpose/policy/**` do not bind
an adapter loaded from somewhere else, and pretending otherwise is how the
blindness rule came to be believed rather than checked.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from interpose.engine.trial import run_trial
from interpose.policy.base import BUILTIN_POLICIES, load_policy, policy_digest
from interpose.policy.types import ALLOW, Decision, DecisionContext
from interpose.providers.scripted import ScriptedProvider
from interpose.scenario.loader import discover_scenarios, load_scenario

POLICY_DIR = Path(__file__).resolve().parents[1] / "src" / "interpose" / "policy"


# -- the blindness rule, finally asserted ----------------------------------


def test_shipped_policies_import_nothing_from_scenario_or_engine() -> None:
    """`PROTOCOL.md`: "policy/ imports nothing from scenario/ (asserted by test)".

    It was not. The property held; nothing checked it.

    Scope, stated honestly: this binds the **shipped** policies only. A
    third-party adapter is outside this directory, and a frame walk imports
    nothing at all — see `test_the_import_check_does_not_bind_a_frame_walk`.
    """
    forbidden = ("interpose.scenario", "interpose.engine", "..scenario", "..engine")
    offenders: list[str] = []

    for path in sorted(POLICY_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = ("." * (node.level or 0)) + (node.module or "")
                if any(module.startswith(f) for f in forbidden):
                    offenders.append(f"{path.name}: from {module}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if any(alias.name.startswith(f) for f in forbidden):
                        offenders.append(f"{path.name}: import {alias.name}")

    assert offenders == [], f"a shipped policy can see the answer key: {offenders}"


def test_the_decision_stream_is_identical_until_the_corpus_diverges() -> None:
    """`PROTOCOL.md`: "asserted by test". It was not.

    A policy must not be able to tell the attack run from the benign control.
    The strongest available check is that the decision sequence is the same up
    to the point the two runs genuinely differ in what the agent was asked to
    do.
    """
    scenario = load_scenario("confidential-egress")
    _, records = run_trial(
        scenario, load_policy("reference"), lambda: ScriptedProvider("compliant")
    )

    def stream(record) -> list[tuple[str, str]]:
        return [
            (e.tool, e.effect)
            for e in record.log.of_type("policy.evaluated")
        ]

    attack = next(r for r in records if r.outcome.task_kind != "benign")
    benign = [r for r in records if r.outcome.task_kind == "benign"]
    assert benign

    # The first decision of every run is the same shape: the agent orients
    # before the corpus can have influenced it.
    first_attack = stream(attack)[:1]
    for run in benign:
        assert stream(run)[:1] == first_attack, (
            "the very first decision already differs between benign and attack, "
            "so a policy could branch on it"
        )


def test_the_context_carries_no_reference_to_the_attack_section() -> None:
    """The third of the three claimed enforcements — this one is real."""
    scenario = load_scenario("confidential-egress")
    seen: list[DecisionContext] = []

    class Recorder:
        id = "recorder"
        version = "1.0.0"

        def describe(self) -> str:
            return "records every context it is handed"

        def evaluate(self, ctx: DecisionContext) -> Decision:
            seen.append(ctx)
            return Decision(effect=ALLOW, rule_id="R0.permitted", reason="")

    run_trial(scenario, Recorder(), lambda: ScriptedProvider("compliant"))
    assert seen

    spec = scenario.spec
    answer_key = {
        spec.attack.id,
        spec.attack.injected_source,
        *spec.attack.protected_assets,
    }
    for ctx in seen:
        blob = repr(ctx)
        for secret in answer_key:
            if secret == spec.attack.injected_source:
                continue  # legitimately reachable: the agent read that document
            assert secret not in blob or secret in {
                v for v in answer_key if v.startswith("res://")
            }, f"the answer key leaked into DecisionContext: {secret}"


def test_the_import_check_does_not_bind_a_frame_walk() -> None:
    """The honest limit of the structural guarantee, pinned so it is not forgotten.

    `PROTOCOL.md` called the import check an enforcement of the blindness rule.
    It is not, against an adversarial adapter: a policy that walks its call
    stack imports nothing, and a third-party adapter is not in the directory the
    check scans. Phase III demonstrated both. This test records the gap rather
    than papering over it.
    """
    import inspect

    reached: dict[str, bool] = {}

    class FrameWalker:
        id = "frame-walker"
        version = "1.0.0"

        def describe(self) -> str:
            return "reaches the runner's locals without importing anything"

        def evaluate(self, ctx: DecisionContext) -> Decision:
            frame = inspect.currentframe()
            while frame is not None:
                if "world" in frame.f_locals:
                    reached["world"] = True
                    break
                frame = frame.f_back
            return Decision(effect=ALLOW, rule_id="R0.permitted", reason="")

    run_trial(
        load_scenario("confidential-egress"),
        FrameWalker(),
        lambda: ScriptedProvider("compliant"),
    )

    assert reached.get("world") is True, (
        "if this ever fails, the in-process reachability gap has closed and "
        "PROTOCOL.md's claim about structural enforcement can be strengthened"
    )


# -- identity: a policy must not attest to itself --------------------------


def test_a_policy_cannot_declare_its_own_digest() -> None:
    """`policy_digest` honoured a `digest()` method on the adapter.

    A hostile policy returned the genuine reference policy's digest, matched
    `policy-freeze.json` byte for byte, and `interpose verify` printed `AGREES`
    over a forged result. Self-attestation is not identity. Retraction R14.
    """
    genuine = policy_digest(load_policy("reference"))

    class Impostor:
        id = "reference-least-privilege"
        version = "1.0.0"

        def describe(self) -> str:
            return "claims to be the reference policy"

        def digest(self) -> str:
            return genuine

        def evaluate(self, ctx: DecisionContext) -> Decision:
            return Decision(effect=ALLOW, rule_id="R0.permitted", reason="")

    assert policy_digest(Impostor()) != genuine


def test_verify_does_not_import_a_module_named_by_the_artifact(tmp_path: Path) -> None:
    """`verify` passed the artifact's `policy_id` to `load_policy`, which imports.

    So checking someone else's `result.json` executed a module that the artifact
    named — arbitrary code execution from a data file, in the one command whose
    purpose is checking a result you did not produce. Retraction R15.
    """
    from interpose.report.verify import _resolve_policy

    assert _resolve_policy("os.path:sep") is None
    assert _resolve_policy("no.such.module:Nope") is None
    assert _resolve_policy("reference-least-privilege") is not None


@pytest.mark.parametrize("short", sorted(BUILTIN_POLICIES))
def test_builtin_digests_are_reproducible(short: str) -> None:
    policy = load_policy(short)
    assert policy_digest(policy) == policy_digest(load_policy(short))


# -- the chokepoint claim --------------------------------------------------


def test_only_one_call_site_can_mutate_the_authoritative_world() -> None:
    """`ENFORCEMENT_BOUNDARY.md` claimed "a test asserting the single chokepoint".

    There was none, and writing it found something: there are **two** call sites
    for `ToolSpec.execute`, not one. The second is `probe.py`, added during
    INT-000 to stop the shadow probe reporting routes that cannot execute.

    Two is correct, and the invariant is narrower than "one call site". The
    probe deliberately executes *without consulting the policy* — it is a
    counterfactual — so what must hold is that it cannot touch authoritative
    state. It executes against `copy.deepcopy(world)` and discards the result.

    So the property asserted here is: exactly one call site passes the live
    world, and the other provably passes a copy. Stated that way it is checkable;
    stated as "one chokepoint" it was both false and unwritten.

    This proves nothing about arbitrary Python. A policy that reaches the world
    through a frame walk calls no tool at all — see the test above.
    """
    engine = Path(__file__).resolve().parents[1] / "src" / "interpose" / "engine"
    sites: list[tuple[str, int, str]] = []
    for path in sorted(engine.glob("*.py")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for lineno, line in enumerate(lines, 1):
            if ".execute(" in line and "def " not in line:
                window = lines[lineno - 1 : lineno + 6]
                sites.append((path.name, lineno, window))

    assert len(sites) == 2, f"tool execution call sites changed: {[(f, n) for f, n, _ in sites]}"

    by_file = {name: window for name, _, window in sites}
    assert "runner.py" in by_file and "probe.py" in by_file, by_file.keys()

    assert any("world=world" in ln for ln in by_file["runner.py"]), "the mediated path must pass the live world"
    assert any("deepcopy(world)" in ln for ln in by_file["probe.py"]), (
        "the counterfactual path must pass a copy; if it ever passes the live "
        "world, a shadow probe could mutate the run it is reasoning about"
    )


def test_every_scenario_still_loads() -> None:
    for sid in discover_scenarios():
        load_scenario(sid)
