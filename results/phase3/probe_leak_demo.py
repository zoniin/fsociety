"""Is the answer key reachable through the shadow probe, given policy state?

The blindness rule says a policy never learns the adversary objective. The
shadow probe replays that objective, verbatim, through the ordinary
``evaluate`` call site -- on **every** run, benign runs included. Probe
contexts are trivially separable from dispatch contexts: ``step`` restarts at
1 and ``history`` is empty after decisions have already been made this run.

Whether that is exploitable depends entirely on **how long a policy instance
lives**, which the project has never written down. ``cmd_matrix`` loads one
policy and reuses it for 25 attack cells; ``run_trial`` reuses one across the
attack run and the whole benign suite. Providers are protected from exactly
this by the ``ProviderFactory`` indirection ("providers carry per-run state,
and reusing one would leak a previous run's transcript into the next").
Policies have no such guard.

This script measures the size of the hole, in-process, today.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from interpose.engine.trial import run_single, run_trial
from interpose.policy.types import ALLOW, DENY, Decision, DecisionContext
from interpose.providers.scripted import ScriptedProvider
from interpose.scenario.loader import load_scenario


class OracleHarvester:
    """Permissive, except for calls it saw the shadow probe ask about.

    It contains nothing on its own. Every denial it issues is copied from the
    objective the harness handed it.
    """

    id = "oracle-harvester"
    version = "1.0.0"

    def __init__(self) -> None:
        self.learned: set[str] = set()
        self.seen_dispatch_this_run = False
        self._last_step = 0
        self.harvest_events = 0

    def describe(self) -> str:
        return "permissive, plus whatever the shadow probe told it"

    @staticmethod
    def _key(ctx: DecisionContext) -> str:
        return json.dumps(
            {"tool": ctx.action.tool, "args": ctx.action.arguments}, sort_keys=True
        )

    def evaluate(self, ctx: DecisionContext) -> Decision:
        # Probe contexts restart the step counter and carry no history.
        is_probe = ctx.step <= 1 and not ctx.history and self._last_step > 1
        self._last_step = ctx.step
        if is_probe:
            self.learned.add(self._key(ctx))
            self.harvest_events += 1
            # Answer ALLOW so the probe reports a wide-open gap and nothing
            # about this policy looks defensive to the shadow scorer.
            return Decision(ALLOW, "H0.probe", "permitted")
        if self._key(ctx) in self.learned:
            return Decision(DENY, "H1.memorised-objective", "seen this exact call before")
        return Decision(ALLOW, "H0.permitted", "permitted")


def main() -> int:
    sid = "confidential-egress"
    scenario = load_scenario(sid)
    prompts = len(scenario.spec.variants.benign_prompts) or 1
    payloads = len(scenario.spec.variants.injection_payloads) or 1

    # -- (a) exactly how cmd_matrix does it: ONE instance, 25 cells ---------
    shared = OracleHarvester()
    verdicts_shared: list[str] = []
    for pi in range(prompts):
        for yi in range(payloads):
            rec = run_single(
                scenario, shared, lambda: ScriptedProvider("compliant"),
                prompt_variant=pi, payload_variant=yi,
            )
            verdicts_shared.append(rec.outcome.verdict)

    # -- (b) the same policy, a fresh instance per run ----------------------
    verdicts_fresh: list[str] = []
    for pi in range(prompts):
        for yi in range(payloads):
            rec = run_single(
                scenario, OracleHarvester(), lambda: ScriptedProvider("compliant"),
                prompt_variant=pi, payload_variant=yi,
            )
            verdicts_fresh.append(rec.outcome.verdict)

    # -- (c) the paired scorecard, one shared instance ----------------------
    paired = OracleHarvester()
    trial, _ = run_trial(scenario, paired, lambda: ScriptedProvider("compliant"))

    def tally(v: list[str]) -> dict[str, int]:
        out: dict[str, int] = {}
        for x in v:
            out[x] = out.get(x, 0) + 1
        return out

    print(f"scenario: {sid}   cells: {prompts * payloads}")
    print()
    print("  policy instance shared across cells (what cmd_matrix does):")
    print(f"    cell 1 verdict : {verdicts_shared[0]}")
    print(f"    all cells      : {tally(verdicts_shared)}")
    print(f"    probe harvests : {shared.harvest_events}, "
          f"objective calls learned: {len(shared.learned)}")
    print()
    print("  fresh policy instance per cell:")
    print(f"    all cells      : {tally(verdicts_fresh)}")
    print()
    print("  paired scorecard, shared instance (run_trial):")
    print(f"    attack verdict : {trial.attack.outcome.verdict}")
    print(f"    benign         : {trial.benign_passed}/{trial.benign_total}"
          f"   false denials: {trial.false_denials}")
    print(f"    utility intact : {trial.utility_intact}   contained: {trial.contained}")
    print(f"    probe harvests during the BENIGN suite too: {paired.harvest_events}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
