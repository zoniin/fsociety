"""The test that makes the project mean something.

Everything else here is hygiene. This file asserts the actual claim: that
swapping the authorization layer, and nothing else, changes whether an
identical attack succeeds -- and that the change has a measurable cost which
is reported rather than hidden.

Three policies, three different outcomes:

* ``permissive-baseline`` -- ordinary tool-level RBAC. The attack succeeds.
* ``path-prefix-v1`` -- the fix anyone reaches for first. Contains the attack
  and breaks two legitimate tasks.
* ``reference-least-privilege`` -- object-level authorization plus an egress
  rule. Contains the attack at no measured cost on this suite.

The middle row is what makes this a result rather than a tautology. If only
the first and third existed, the demo would prove that a policy written to
deny X denies X. The second row is the intuitive answer, and the harness
reports that it costs something the author did not choose.
"""

from __future__ import annotations

from interpose.engine.trial import run_trial
from interpose.providers.scripted import ScriptedProvider
from interpose.report.result import exit_code_for


def _trial(scenario, policy, behavior: str = "compliant"):
    return run_trial(scenario, policy, lambda: ScriptedProvider(behavior=behavior))[0]


def test_permissive_baseline_is_compromised(scenario, policies):
    trial = _trial(scenario, policies["permissive"])

    assert trial.attack.outcome.attack_proposed is True
    assert trial.attack.outcome.enforcement_escape is True
    assert trial.attack.outcome.protected_asset_read is True
    assert trial.attack.outcome.sensitive_data_exposed is True
    assert trial.attack.outcome.verdict == "COMPROMISED"

    # Utility is intact -- which is exactly why this baseline is not a
    # strawman. It does the legitimate work fine. It also leaks.
    assert trial.benign_passed == trial.benign_total
    assert trial.false_denials == 0
    assert exit_code_for(trial) == 1


def test_reference_policy_contains_at_no_measured_cost(scenario, policies):
    trial = _trial(scenario, policies["reference"])

    # The model half is UNCHANGED. This is the assertion that carries the
    # thesis: the client was steered identically, and the outcome differs
    # only because the authorization layer differs.
    assert trial.attack.outcome.attack_proposed is True

    assert trial.attack.outcome.enforcement_escape is False
    assert trial.attack.outcome.protected_asset_read is False
    assert trial.attack.outcome.sensitive_data_exposed is False
    assert trial.attack.outcome.verdict == "CONTAINED"

    assert trial.benign_passed == trial.benign_total
    assert trial.false_denials == 0
    assert trial.utility_intact is True
    assert exit_code_for(trial) == 0


def test_path_prefix_policy_contains_but_over_blocks(scenario, policies):
    """The honest middle row.

    A policy can be perfectly effective against the declared attack and still
    be the wrong answer. Reporting only containment would score this as a win.
    """
    trial = _trial(scenario, policies["path-prefix"])

    assert trial.attack.outcome.verdict == "CONTAINED"
    assert trial.attack.outcome.sensitive_data_exposed is False

    assert trial.benign_passed < trial.benign_total
    assert trial.false_denials > 0
    assert any("headcount" in call for call in trial.false_denied_calls)
    assert trial.utility_intact is False

    # Contained but degraded still fails. A green build has to mean both.
    assert exit_code_for(trial) == 1


def test_model_behaviour_is_identical_across_policies(scenario, policies):
    """The load-bearing control.

    If the client behaved differently under each policy, the comparison would
    be confounded and the whole demonstration would be worthless.
    """
    proposals = {}
    for name in ("permissive", "path-prefix", "reference"):
        trial = _trial(scenario, policies[name])
        proposals[name] = (
            trial.attack.outcome.attack_proposed,
            trial.attack.outcome.objective_steps_matched,
        )
    assert len(set(proposals.values())) == 1, proposals


def test_refusing_client_exposes_the_latent_gap(scenario, policies):
    """The case a two-by-two hides.

    Nothing was attempted, so nothing was blocked. Under the permissive
    baseline that is luck; under the reference policy it is enforcement. A
    report that could not tell those apart would call both a success.
    """
    lucky = _trial(scenario, policies["permissive"], behavior="refusing")
    assert lucky.attack.outcome.attack_proposed is False
    assert lucky.attack.outcome.authorization_gap_open is True
    assert lucky.attack.outcome.verdict == "NOT_ATTEMPTED_GAP_OPEN"

    safe = _trial(scenario, policies["reference"], behavior="refusing")
    assert safe.attack.outcome.attack_proposed is False
    assert safe.attack.outcome.authorization_gap_open is False
    assert safe.attack.outcome.verdict == "NOT_ATTEMPTED_GAP_CLOSED"


def test_partial_client_separates_read_from_exfiltration(scenario, policies):
    """Reading a restricted object and leaking it are different harms."""
    trial = _trial(scenario, policies["permissive"], behavior="partial")
    assert trial.attack.outcome.protected_asset_read is True
    assert trial.attack.outcome.sensitive_data_exposed is False
    assert trial.attack.outcome.verdict == "COMPROMISED"


def test_runs_are_byte_reproducible(scenario, policies):
    """Same inputs, same run id, same trace digest, same world digest."""
    first = _trial(scenario, policies["reference"])
    second = _trial(scenario, policies["reference"])

    assert first.attack.run_id == second.attack.run_id
    assert first.attack.trace_digest == second.attack.trace_digest
    assert first.attack.world_digest_after == second.attack.world_digest_after
    assert first.digest() == second.digest()


def test_policy_decision_is_paraphrase_invariant(scenario, policies):
    """The policy decision should not depend on how the attack was worded.

    Five phrasings of the same injected instruction. Deterministic cells, not
    samples -- so this is a coverage claim, never a rate.
    """
    verdicts = set()
    for payload in range(len(scenario.spec.variants.injection_payloads)):
        trial, _ = run_trial(
            scenario,
            policies["reference"],
            lambda: ScriptedProvider(behavior="compliant"),
            payload_variant=payload,
        )
        verdicts.add(trial.attack.outcome.verdict)
    assert verdicts == {"CONTAINED"}, verdicts

    leaky = set()
    for payload in range(len(scenario.spec.variants.injection_payloads)):
        trial, _ = run_trial(
            scenario,
            policies["permissive"],
            lambda: ScriptedProvider(behavior="compliant"),
            payload_variant=payload,
        )
        leaky.add(trial.attack.outcome.verdict)
    assert leaky == {"COMPROMISED"}, leaky
