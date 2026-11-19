"""The out-of-process policy worker (``--isolate-policy``).

What these pin, in the order the Phase III objections were raised:

* the in-process tampering attacks stop working, rather than being detected;
* a dead, hung or malformed worker never yields a scored verdict;
* policy state still does not cross runs;
* the digest is the harness's, never the worker's;
* and, for an honest policy, isolation changes nothing but its identity.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

import interpose.engine.runner as runner_mod
from interpose.engine.trial import run_single, run_trial
from interpose.policy.base import load_policy, policy_digest
from interpose.policy.isolated import IsolatedPolicy, harness_digest
from interpose.providers.scripted import ScriptedProvider
from interpose.report.result import exit_code_for
from interpose.scenario.loader import discover_scenarios, load_scenario

FIXTURES = Path(__file__).parent / "worker_fixtures"
SCENARIO = "confidential-egress"


@pytest.fixture(autouse=True)
def _worker_path(monkeypatch) -> None:
    # Workers inherit the environment; this is how they find the fixtures.
    monkeypatch.setenv("PYTHONPATH", str(FIXTURES))


def _hostile(name: str, **kw) -> IsolatedPolicy:
    return IsolatedPolicy(f"hostile_policies:{name}", **kw)


def _run(policy, scenario: str = SCENARIO):
    return run_single(load_scenario(scenario), policy, lambda: ScriptedProvider("compliant"))


def _trial(policy, scenario: str = SCENARIO):
    return run_trial(load_scenario(scenario), policy, lambda: ScriptedProvider("compliant"))[0]


# -- the attacks stop working --------------------------------------------------


def test_verdict_forger_cannot_reach_the_scorer() -> None:
    before = runner_mod.evaluate_outcome
    record = _run(_hostile("VerdictForger"))
    assert runner_mod.evaluate_outcome is before, "the harness scorer was rebound"
    # Not caught after the fact as APPARATUS_TAMPERED: simply honest.
    assert record.outcome.verdict == "COMPROMISED"
    assert not record.outcome.apparatus_tampered


def test_world_hunter_finds_no_world() -> None:
    record = _run(_hostile("WorldHunter"))
    reasons = [getattr(e, "reason", "") for e in record.log.of_type("policy.evaluated")]
    assert reasons and all(r == "worlds=0" for r in reasons)
    assert record.outcome.verdict == "COMPROMISED"  # the leak it permitted is still seen


# -- faults are terminal, never scores ------------------------------------------


def test_crashed_worker_invalidates_the_run() -> None:
    trial = _trial(_hostile("Crasher"))
    assert trial.attack.outcome.verdict == "POLICY_ERROR"
    assert "WORKER_CRASH" in trial.attack.outcome.policy_error
    assert not trial.contained
    assert exit_code_for(trial) == 7
    # The connection is dead for every later run too: no "recovered" scores.
    assert all(r.outcome.verdict == "POLICY_ERROR" for r in trial.benign)


def test_hung_worker_times_out_into_policy_error() -> None:
    record = _run(_hostile("Sleeper", decision_timeout=0.5))
    assert record.outcome.verdict == "POLICY_ERROR"
    assert "TIMEOUT" in record.outcome.policy_error


def test_malformed_rule_id_is_a_fault_not_a_decision() -> None:
    record = _run(_hostile("BadRuleId"))
    assert record.outcome.verdict == "POLICY_ERROR"
    assert "BAD_RULE_ID" in record.outcome.policy_error


def test_a_policy_that_prints_corrupts_nothing() -> None:
    record = _run(_hostile("Printer"))
    assert record.outcome.verdict == "CONTAINED"
    assert not record.outcome.policy_error


def test_missing_module_fails_to_load_cleanly() -> None:
    from interpose.errors import PolicyLoadError

    with pytest.raises(PolicyLoadError):
        load_policy("no_such_module_anywhere:Nope", isolate=True)


# -- lifecycle ------------------------------------------------------------------


def test_every_run_gets_a_fresh_instance_in_the_worker() -> None:
    trial_policy = _hostile("Counter")
    _, records = run_trial(load_scenario(SCENARIO), trial_policy,
                           lambda: ScriptedProvider("compliant"))
    for record in records:
        first = record.log.of_type("policy.evaluated")[0]
        assert first.rule_id == "R0.call-1", "state leaked from an earlier run"


def test_deepcopy_shares_the_worker_but_not_the_instance() -> None:
    a = _hostile("Counter")
    b = copy.deepcopy(a)
    assert b._conn is a._conn and b._instance != a._instance


# -- identity ---------------------------------------------------------------------


def test_digest_is_the_harness_s_and_differs_from_in_process() -> None:
    iso = load_policy("reference", isolate=True)
    assert policy_digest(iso) == harness_digest("interpose.policy.reference:ReferenceLeastPrivilege")
    assert policy_digest(iso) != policy_digest(load_policy("reference"))
    assert policy_digest(load_policy("reference", isolate=True)) == policy_digest(iso)


def test_external_digest_is_computed_without_importing(tmp_path, monkeypatch) -> None:
    marker = tmp_path / "imported.txt"
    (tmp_path / "sideeffect_policy.py").write_text(
        f"open({str(marker)!r}, 'w').write('ran')\nclass P: pass\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    d1 = harness_digest("sideeffect_policy:P")
    assert not marker.exists(), "digesting executed the policy module"
    (tmp_path / "sideeffect_policy.py").write_text("class P: pass  # edited\n", encoding="utf-8")
    assert harness_digest("sideeffect_policy:P") != d1


def test_an_imitation_proxy_does_not_get_to_choose_its_digest() -> None:
    class Imitation:
        id = "reference-least-privilege"
        version = "1.0.0"
        harness_digest = policy_digest(load_policy("reference"))

        def describe(self) -> str:
            return ""

        def evaluate(self, ctx):  # pragma: no cover
            raise AssertionError

    assert policy_digest(Imitation()) != Imitation.harness_digest  # type: ignore[arg-type]


# -- equivalence ----------------------------------------------------------------


def _comparable(record) -> list[dict]:
    out = []
    for event in record.log.events:
        d = event.model_dump(mode="json")
        d.pop("run_id", None)
        d.pop("policy_digest", None)
        if d.get("type") == "run.started":
            d.pop("policy_id", None)
        out.append(d)
    return out


@pytest.mark.parametrize("scenario", sorted(discover_scenarios()))
@pytest.mark.parametrize("policy", ["reference", "context-taint", "sink-scoped"])
def test_isolation_changes_nothing_but_identity(scenario: str, policy: str) -> None:
    sc = load_scenario(scenario)
    _, inproc = run_trial(sc, load_policy(policy), lambda: ScriptedProvider("paraphrasing"))
    _, iso = run_trial(sc, load_policy(policy, isolate=True),
                       lambda: ScriptedProvider("paraphrasing"))
    assert len(inproc) == len(iso)
    for a, b in zip(inproc, iso, strict=True):
        assert _comparable(a) == _comparable(b)


# -- the freeze is append-only (found while building this) -------------------


def _freeze_with(tmp_path, mutate):
    import json

    from interpose.challenge import build_freeze_record

    path = tmp_path / "freeze.json"
    record = build_freeze_record()
    mutate(record["policies"])
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def test_freeze_refuses_to_move_a_changed_digest(tmp_path) -> None:
    from interpose.challenge import write_freeze
    from interpose.errors import UsageError

    def stale(p):
        p["reference-least-privilege"]["digest"] = "sha256:old"

    path = _freeze_with(tmp_path, stale)
    with pytest.raises(UsageError, match="reference-least-privilege"):
        write_freeze(path)
    with pytest.raises(UsageError, match="--reason"):
        write_freeze(path, refreeze=frozenset({"reference-least-privilege"}))
    record = write_freeze(path, refreeze=frozenset({"reference-least-privilege"}),
                          reason="test", today="2026-01-01")
    entry = record["refreezes"][-1]
    assert entry["policies"]["reference-least-privilege"]["from"] == "sha256:old"
    assert entry["reason"] == "test" and entry["date"] == "2026-01-01"


def test_freeze_adds_new_policies_without_touching_others(tmp_path) -> None:
    import json

    from interpose.challenge import write_freeze

    path = _freeze_with(tmp_path, lambda p: p.pop("sink-scoped-taint"))
    before = json.loads(path.read_text(encoding="utf-8"))["policies"]
    record = write_freeze(path)
    assert "sink-scoped-taint" in record["policies"]
    assert "refreezes" not in record
    for pid, entry in before.items():
        assert record["policies"][pid] == entry
