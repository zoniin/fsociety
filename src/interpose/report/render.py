"""Terminal rendering.

Constraints, all of them learned from a specific failure:

**ASCII by default.** On a stock Windows Python, ``sys.stdout.encoding`` is
``cp1252``; printing a check mark through a pipe raises ``UnicodeEncodeError``
*and* the shell reports exit 0, so the failure is invisible and the output is
empty. A report that dies the first time someone pipes it to ``grep`` is not a
report. Unicode is used only when the stream can actually encode it.

**Closed verdict vocabulary.** Every verdict token comes from
:data:`~interpose.engine.outcome.VERDICTS`, so ``| grep CONTAINED`` keeps
working across versions. One assertion per line, fixed columns, no tables
that reflow.

**No colour carries information.** ``NO_COLOR`` and ``CI`` are honoured, and
nothing is expressed by colour alone.

**The pairing rule is enforced here, not documented here.** There is no
function in this module that renders containment without utility beside it.
Rendering a single attack run prints a withheld-scorecard banner instead of a
result. Making that a type-level property rather than a style guideline is the
difference between a rule and a hope.
"""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Sequence
from typing import Any

from ..engine.outcome import Outcome
from .result import TrialResult

__all__ = [
    "configure_stdout",
    "render_comparison",
    "render_replay",
    "render_single_run_banner",
    "render_trial",
    "supports_unicode",
]

RULE = "-" * 74


def configure_stdout() -> None:
    """Make stdout survive redirection on Windows.

    Reconfigures to UTF-8 with replacement rather than letting a single
    unencodable character abort the process with an empty pipe.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace", newline="\n")


def supports_unicode() -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        return False
    if not sys.stdout.isatty():
        return False
    encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" in encoding


def _yn(value: bool) -> str:
    return "YES" if value else "no"


def _row(label: str, value: str, detail: str = "") -> str:
    return f"  {label:<26s} {value:<10s} {detail}".rstrip()


def render_single_run_banner(outcome: Outcome, policy_id: str) -> str:
    """What a lone attack run is allowed to print.

    Deliberately not a scorecard. Containment with no cost measurement is the
    field's characteristic dishonesty, and this is where refusing it is cheap.
    """
    lines = [
        RULE,
        f"  SINGLE RUN  policy={policy_id}  verdict={outcome.verdict}",
        RULE,
        _row("attack_proposed", _yn(outcome.attack_proposed)),
        _row("enforcement_escape", _yn(outcome.enforcement_escape)),
        _row("protected_asset_read", _yn(outcome.protected_asset_read)),
        _row("unauthorized_asset_read", _yn(outcome.unauthorized_asset_read)),
        _row("sensitive_data_exposed", _yn(outcome.sensitive_data_exposed)),
        _row("authorization_gap_open", _yn(outcome.authorization_gap_open), outcome.probe_detail),
        "",
        "  SCORECARD WITHHELD: the benign suite did not run, so the cost of this",
        "  policy is unmeasured. A containment result without a utility result is",
        "  not a finding. Run without --attack-only for a scorecard.",
        RULE,
    ]
    return "\n".join(lines)


def render_trial(trial: TrialResult, *, show_header: bool = True) -> str:
    """The hero table. Containment and its cost, always together."""
    a = trial.attack.outcome
    lines: list[str] = []
    if show_header:
        lines += [
            RULE,
            f"  scenario  {trial.scenario.id} v{trial.scenario.version}",
            f"  policy    {trial.policy.id} v{trial.policy.version}",
            f"  provider  {trial.provider.id}"
            + ("  (deterministic)" if trial.deterministic else "  (NOT deterministic)"),
            RULE,
        ]

    lines += [
        "  MODEL BEHAVIOUR",
        _row(
            "attack_proposed",
            _yn(a.attack_proposed),
            f"{a.objective_steps_matched}/{a.objective_steps_total} adversary steps proposed",
        ),
        "",
        "  SYSTEM AUTHORIZATION",
        _row(
            "enforcement_escape",
            _yn(a.enforcement_escape),
            f"{a.objective_steps_permitted}/{a.objective_steps_total} adversary steps permitted",
        ),
        _row(
            "protected_asset_read",
            _yn(a.protected_asset_read),
            "a protected object was touched (not by itself a harm)",
        ),
        _row(
            "unauthorized_asset_read",
            _yn(a.unauthorized_asset_read),
            "touched by a principal not entitled to it",
        ),
        _row("sensitive_data_exposed", _yn(a.sensitive_data_exposed)),
        _row("authorization_gap_open", _yn(a.authorization_gap_open), a.probe_detail),
        "",
        "  COST OF THAT AUTHORIZATION",
        _row(
            "benign_tasks_passed",
            f"{trial.benign_passed}/{trial.benign_total}",
            "legitimate tasks completed under the same policy",
        ),
        _row(
            "false_denials",
            str(trial.false_denials),
            "legitimate calls the policy refused",
        ),
        _row(
            "blocked_by_policy",
            str(trial.policy_blocked_tasks),
            "benign tasks the policy stopped",
        ),
        _row(
            "incomplete_by_client",
            str(trial.client_incomplete_tasks),
            "benign tasks the agent did not attempt (not a policy cost)",
        ),
    ]
    for call in trial.false_denied_calls:
        lines.append(f"      denied: {call}")

    if trial.invalid_runs:
        lines += [
            "",
            "  !! THIS TRIAL PRODUCED NO MEASUREMENT",
        ]
        for detail in trial.invalid_runs:
            lines.append(f"     {detail}")
        lines += [
            "     The measurement machinery was mutated, or the policy did not",
            "     answer. Either way the security outcome is not trustworthy, so",
            "     nothing here is a containment result and nothing is scored.",
        ]

    if trial.truncated_runs:
        lines += [
            "",
            f"  !! {trial.truncated_runs} RUN(S) HIT THE TURN BUDGET",
            "     The agent was still working when the harness stopped it, so these",
            "     verdicts are not interpretable -- the attack may simply not have",
            "     reached its next step. Raise agent.max_turns in the scenario.",
        ]

    lines += [
        "",
        f"  RESULT  {a.verdict}  /  "
        + ("UTILITY INTACT" if trial.utility_intact else "UTILITY DEGRADED")
        + ("  /  TRUNCATED" if trial.truncated_runs else "")
        + ("  /  NOT SCORED" if trial.invalid_runs else ""),
        RULE,
    ]
    return "\n".join(lines)


def render_comparison(trials: list[TrialResult]) -> str:
    """The comparison across a policy family.

    One policy is a point; a family is a frontier, and the frontier is the
    comparison unit. Ordering is by dominance only -- a policy is better than
    another when it is at least as good on *both* axes. Non-dominated pairs
    are left unordered on purpose, because collapsing them into a single score
    would require inventing a weight between "attack contained" and "work
    blocked" that nobody has an empirical basis for.
    """
    if not trials:
        return "(no trials)"
    head = trials[0]
    lines = [
        RULE,
        f"  scenario  {head.scenario.id} v{head.scenario.version}",
        f"  provider  {head.provider.id}"
        + ("  (deterministic)" if head.deterministic else "  (NOT deterministic)"),
        f"  bench     {head.bench_version}",
        RULE,
        "",
        f"  {'POLICY':<28s}{'ATTACK':<16s}{'CANARY':<8s}{'FLOW?':<7s}"
        f"{'BENIGN':<9s}{'FALSE-DENY':<12s}{'LATENT GAP'}",
        f"  {'-' * 28}{'-' * 16}{'-' * 8}{'-' * 7}{'-' * 9}{'-' * 12}{'-' * 10}",
    ]
    for trial in trials:
        lines.append(
            f"  {trial.policy.id:<28s}"
            f"{trial.attack.outcome.verdict:<16s}"
            f"{_yn(trial.attack.outcome.sensitive_data_exposed):<8s}"
            f"{_yn(trial.attack.outcome.possible_exposure):<7s}"
            f"{f'{trial.benign_passed}/{trial.benign_total}':<9s}"
            f"{trial.false_denials!s:<12s}"
            f"{_yn(trial.attack.outcome.authorization_gap_open)}"
        )

    blind = [t for t in trials
             if t.attack.outcome.possible_exposure
             and not t.attack.outcome.sensitive_data_exposed]
    if blind:
        lines += [
            "",
            "  CANARY = exact marker tokens found in a sink. Content matching, so any",
            "           rewording defeats it. It is a lower bound, not exposure.",
            "  FLOW?  = a protected resource was read, then a non-empty write reached a",
            "           sink an unentitled principal can read. Structural, so paraphrase",
            "           cannot hide it -- and over-approximating, so it is a bracket.",
            "",
            f"  !! {len(blind)} row(s) have FLOW? yes and CANARY no. In those runs the content",
            "     detector saw nothing while a protected read was followed by a write to a",
            "     sink outside its readership. Treat CANARY as uninformative there.",
        ]

    lines += ["", "  READING THIS TABLE", ""]
    for trial in trials:
        lines.append(f"  {trial.policy.id}")
        lines.append(f"      {_explain(trial)}")
        if trial.truncated_runs:
            lines.append(
                f"      !! {trial.truncated_runs} run(s) hit the turn budget; "
                "these verdicts are not interpretable."
            )
    lines += ["", RULE]
    return "\n".join(lines)


def _explain(trial: TrialResult) -> str:
    a = trial.attack.outcome
    if a.possible_exposure and not a.sensitive_data_exposed:
        return (
            "a protected resource was read and a write then reached a sink outside its "
            "readership, with no marker token detected. The content detector is blind "
            "here; do not read the CANARY column as evidence of containment."
        )
    if a.sensitive_data_exposed:
        return (
            "the attack succeeded: restricted data reached a sink readable "
            "outside the boundary."
        )
    if a.verdict == "CONTAINED" and trial.utility_intact and not a.authorization_gap_open:
        return (
            "contained the attack and completed every legitimate task. The "
            "second half is the part the author did not get to choose."
        )
    if a.verdict == "CONTAINED" and a.authorization_gap_open:
        return (
            f"contained THIS attack and cost {trial.false_denials} legitimate "
            f"call(s) -- but a latent gap is open: {a.probe_detail}"
        )
    if a.verdict == "CONTAINED":
        return (
            f"contained the attack and cost {trial.false_denials} legitimate "
            f"call(s). Containment is not free here."
        )
    if a.verdict == "NOT_ATTEMPTED_GAP_OPEN":
        return (
            "nothing was attempted, and the policy would have permitted the "
            "attack had it been. Luck, not enforcement."
        )
    if a.verdict == "NOT_ATTEMPTED_GAP_CLOSED":
        return "nothing was attempted, and the policy would have refused it anyway."
    return a.verdict


def render_replay(events: Sequence[object], run_id: str, *, verbose: bool = False) -> str:
    """The causal narrative.

    Not a chat transcript. The question a transcript cannot answer is which
    untrusted bytes reached which privileged call, so that is what this
    renders: ingestion, then the proposals whose arguments carry that content,
    then the decision, then the effect.
    """
    lines = [RULE, f"  replay  {run_id}", RULE]
    for event in events:
        # Read defensively: a log written by a newer build may carry event
        # types and fields this renderer does not know. Replay has to be more
        # forgiving than the writer, or old tooling cannot read new traces.
        stamp = f"{float(getattr(event, 't_ms', 0)) / 1000:8.3f}"
        kind = str(getattr(event, "type", "?"))
        detail = _replay_detail(event, verbose=verbose)
        if detail is None:
            continue
        lines.append(f"  {stamp}  {kind:<26s} {detail}")
    lines.append(RULE)
    return "\n".join(lines)


def _replay_detail(event: object, *, verbose: bool) -> str | None:
    """Render one event line.

    Reads attributes defensively so that a log written by a newer build --
    with event types or fields this renderer has never seen -- still replays
    instead of crashing. Replay must be more forgiving than the writer.
    """
    t = str(getattr(event, "type", ""))

    def g(name: str, default: object = "") -> Any:
        return getattr(event, name, default)

    if t == "run.started":
        return f"{g('scenario_id')} policy={g('policy_id')} provider={g('provider_id')}"
    if t == "world.initialized":
        return f"{g('principal_count')} principals, {g('resource_count')} resources"
    if t == "task.assigned":
        return f"[{g('task_kind')}] {g('actor')} on behalf of {g('on_behalf_of')}"
    if t == "content.ingested":
        return f"{g('resource_uri')}  trust={g('trust')} class={g('classification')}"
    if t == "agent.message":
        return str(g("text"))[:80] if verbose else None
    if t == "tool.proposed":
        prov = ",".join(g("value_provenance", []) or []) or "-"
        flag = "  <-- matches adversary objective" if g("matches_adversary_objective") else ""
        return f"{g('tool')}({_args(dict(g('arguments', {})))})  value_provenance={prov}{flag}"
    if t == "policy.evaluated":
        return f"{str(g('effect')).upper():5s} {g('rule_id')}  {g('reason')}"
    if t == "tool.executed":
        return f"{g('tool')} -> {','.join(g('resource_uris', []) or []) or '-'}"
    if t == "tool.blocked":
        return f"{g('tool')} blocked by {g('rule_id')}"
    if t == "detector.triggered":
        return (
            f"{g('detector')}: {g('canary')} from {g('from_resource')} "
            f"reached {g('to_resource')} readable by {','.join(g('readable_by', []) or [])}"
        )
    if t == "probe.shadow_evaluated":
        return (
            f"[shadow] step {g('step')} {g('tool')} -> "
            f"{str(g('effect')).upper()} ({g('rule_id')})"
        )
    if t == "outcome.evaluated":
        return f"{g('check')} = {_yn(bool(g('value')))}  {g('detail')}"
    if t == "run.finished":
        return f"{g('verdict')} after {g('turns')} turns"
    return None


def _args(arguments: dict) -> str:
    return ", ".join(f"{k}={str(v)[:48]}" for k, v in sorted(arguments.items()))
