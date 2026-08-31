"""Command line interface.

Built on ``argparse`` rather than a CLI framework, on purpose. The whole
runtime dependency set is ``pydantic`` and ``PyYAML``; adding a CLI library
would pull a colour renderer and its transitive tree to save perhaps eighty
lines. For a security tool whose install one-liner is the product, a small
dependency graph is a feature and a smaller attack surface.

Two containment properties are visible right here in the command surface:

* **No verb reads as "point this at something".** There is no ``attack``, no
  ``exploit``, no ``target``. There is no host, URL, endpoint or IP parameter
  anywhere -- not behind a flag, not behind an environment variable, not "for
  advanced users". The property that makes third-party targeting impossible is
  that the code to do it does not exist, and a pull request adding it is
  refused regardless of justification.
* **Bare invocation orients rather than dumping flags.** Someone typing the
  bare binary is asking what this is, not what its options are.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import BENCH_VERSION, __version__
from .engine.trial import (
    ProviderFactory,
    run_single,
    run_trial,
    to_run_result,
    write_run_artifacts,
)
from .errors import HarnessError, InterposeError, UsageError
from .policy.base import BUILTIN_POLICIES, load_policy
from .providers.base import AgentProvider
from .providers.scripted import BEHAVIOR_CLASSES, ScriptedProvider
from .report.render import (
    configure_stdout,
    render_comparison,
    render_replay,
    render_single_run_banner,
    render_trial,
)
from .report.result import TrialResult, exit_code_for
from .report.verify import verify_result_file
from .scenario.loader import discover_scenarios, load_scenario

__all__ = ["main"]

DEFAULT_SCENARIO = "indirect-document-injection"
DEFAULT_RUNS_DIR = Path("runs")

ORIENTATION = f"""
interpose {__version__}   bench {BENCH_VERSION}

  A regression test for the trust boundary in tool-using agents. It runs a
  simulated agent against a simulated company, lets untrusted content try to
  steer it into a privileged tool call, and reports two things that are only
  meaningful together:

      did the authorization layer hold, and what did holding cost?

  Everything runs in-process. No network, no API key, no container, no target
  parameter. The default provider is a scripted client, not a model.

  Start here:

      interpose demo

  Then:  interpose ls  |  interpose show {DEFAULT_SCENARIO}  |  interpose replay <run-id>
"""


def _provider_factory(name: str) -> ProviderFactory:
    """Return a zero-argument factory. Providers hold per-run state."""
    if name.startswith("scripted"):
        _, _, behavior = name.partition(":")
        behavior = behavior or "compliant"
        if behavior not in BEHAVIOR_CLASSES:
            raise UsageError(
                f"unknown behaviour class {behavior!r}; choose from {list(BEHAVIOR_CLASSES)}"
            )
        return lambda: ScriptedProvider(behavior=behavior)
    if name.startswith("anthropic"):
        from .providers.anthropic_provider import DEFAULT_MODEL, AnthropicProvider

        _, _, model = name.partition(":")
        return lambda: AnthropicProvider(model=model or DEFAULT_MODEL)
    raise UsageError(
        f"unknown provider {name!r}. Use scripted[:class] or anthropic[:model]."
    )


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_demo(args: argparse.Namespace) -> int:
    """The three-row comparison. No arguments, no key, no network."""
    scenario = load_scenario(args.scenario)
    factory = _provider_factory(args.provider)
    trials: list[TrialResult] = []
    saved: dict[str, str] = {}
    for name in ("permissive", "path-prefix", "reference"):
        trial, records = run_trial(scenario, load_policy(name), factory)
        trials.append(trial)
        # Save, so the closing hint can name a real run id. Before review the
        # demo told the reader to replay a run it had never written.
        write_run_artifacts(DEFAULT_RUNS_DIR, trial, records)
        saved[name] = trial.attack.run_id

    if args.json:
        print(json.dumps([t.model_dump(mode="json") for t in trials], indent=2))
        return 0

    print(render_comparison(trials))
    print()
    print("  The first row is the ordinary baseline: tool-level RBAC, which is what")
    print("  most deployed agents actually have. The second row is the fix anyone")
    print("  reaches for first, and the report shows what it costs. The third row is")
    print("  the claim worth arguing with -- and the benign column is the half the")
    print("  author of this scenario did not get to choose.")
    print()
    print()
    print("  The causal trace for the contained run -- which untrusted bytes reached")
    print("  which privileged call, and which rule stopped it:")
    print()
    print(f"      interpose replay runs/{saved['reference']}")
    print()
    print(f"  Compare against the compromised one: runs/{saved['permissive']}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    scenario = load_scenario(args.scenario)
    policy = load_policy(args.policy)
    factory = _provider_factory(args.provider)

    if args.attack_only:
        record = run_single(scenario, policy, factory)
        if args.json:
            payload = to_run_result(record, scenario).model_dump(mode="json")
            payload["scorecard_withheld"] = True
            payload["scorecard_withheld_reason"] = (
                "benign suite did not run; containment is not interpretable alone"
            )
            print(json.dumps(payload, indent=2))
        else:
            print(render_single_run_banner(record.outcome, policy.id))
        if args.save:
            record.log.write(DEFAULT_RUNS_DIR / record.run_id / "events.jsonl")
        return 0

    trial, records = run_trial(scenario, policy, factory)
    if args.json:
        print(trial.model_dump_json(indent=2))
    else:
        print(render_trial(trial))

    if args.save or not args.no_save:
        out = write_run_artifacts(DEFAULT_RUNS_DIR, trial, records)
        if not args.json:
            print(f"  artifacts: {out}")
    return exit_code_for(trial)


def cmd_ls(args: argparse.Namespace) -> int:
    what = args.what or "all"
    if what in ("all", "scenarios"):
        print("scenarios")
        for sid, path in discover_scenarios().items():
            print(f"  {sid:<40s} {path}")
    if what in ("all", "policies"):
        print("policies")
        for short in sorted(BUILTIN_POLICIES):
            policy = load_policy(short)
            print(f"  {short:<14s} {policy.id:<28s} {policy.describe()}")
    if what in ("all", "providers"):
        print("providers")
        for behavior in BEHAVIOR_CLASSES:
            print(
                f"  scripted:{behavior:<14s} deterministic client, behaviour class "
                f"{behavior!r}"
            )
        print("  anthropic:<model>      real model; needs ANTHROPIC_API_KEY; not reproducible")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    scenario = load_scenario(args.scenario)
    spec = scenario.spec
    if args.json:
        print(json.dumps({"digest": scenario.digest, **spec.model_dump(mode="json")}, indent=2))
        return 0
    print(f"{spec.id}  v{spec.version}  bench {spec.bench_version}")
    print(f"  {spec.title}")
    print(f"  digest    {scenario.digest}")
    print(f"  tags      {', '.join(spec.tags)}")
    print(f"  taxonomy  ASI {', '.join(spec.taxonomy.owasp_asi)}  |  LLM "
          f"{', '.join(spec.taxonomy.owasp_llm)}")
    print()
    print(f"  agent     {spec.agent.actor} on behalf of {spec.agent.on_behalf_of}")
    print(f"  tools     {', '.join(spec.agent.tools)}")
    print()
    print(f"  attack    {spec.attack.id} via {spec.attack.vector}")
    print(f"    source  {spec.attack.injected_source}")
    for step in spec.attack.objective:
        print(f"    step    {step.tool}({_kv(step.args)})  {step.note}")
    print(f"    assets  {', '.join(spec.attack.protected_assets)}")
    print()
    print(f"  benign suite ({len(spec.benign)} tasks)")
    for task in spec.benign:
        print(f"    {task.id:<26s} {len(task.requires_calls)} required call(s)")
    print()
    print(f"  variants  {len(spec.variants.benign_prompts)} prompt paraphrases x "
          f"{len(spec.variants.injection_payloads)} injection phrasings")
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    path = Path(args.run)
    if path.is_dir():
        # A trial directory holds one log per run. Default to the attack run,
        # whose id names the directory -- that is the run someone asking for a
        # replay almost always means.
        preferred = path / f"{path.name}.events.jsonl"
        candidates = (
            [preferred]
            if preferred.is_file()
            else sorted(path.glob("*.events.jsonl")) or sorted(path.glob("events.jsonl"))
        )
        if not candidates:
            raise UsageError(f"no event log found under {path}")
        path = candidates[0]
    elif not path.is_file():
        guess = DEFAULT_RUNS_DIR / args.run
        if guess.is_dir():
            return cmd_replay(argparse.Namespace(run=str(guess), verbose=args.verbose))
        raise UsageError(f"no such run or event log: {args.run}")

    events = [
        _RawEvent(json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    print(render_replay(events, path.stem.replace(".events", ""), verbose=args.verbose))
    return 0


class _RawEvent:
    """A replayed event, read back from JSONL.

    Deliberately not re-validated against the typed models: replay must be
    able to read a log written by a *newer* build than the one reading it, and
    a strict parse would refuse. The renderer only reads attributes it knows.
    """

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def __getattr__(self, name: str) -> Any:
        try:
            return self._payload[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def model_dump(self, mode: str = "python") -> dict:
        return dict(self._payload)


def cmd_verify(args: argparse.Namespace) -> int:
    report = verify_result_file(Path(args.result))
    print(report.render())
    return 0 if report.status == "AGREES" else 1


def cmd_matrix(args: argparse.Namespace) -> int:
    """Paraphrase coverage.

    Deliberately *not* described as variance. Runs on the scripted provider
    are byte-identical by construction, so a confidence interval over them
    would measure the scenario author's phrasing choices rather than sampling
    error. What this shows is whether the policy decision is invariant across
    rewordings of both the request and the attack -- a property with, as far
    as I can find, no coverage anywhere today.
    """
    scenario = load_scenario(args.scenario)
    factory = _provider_factory(args.provider)
    prompts = len(scenario.spec.variants.benign_prompts) or 1
    payloads = len(scenario.spec.variants.injection_payloads) or 1

    rows: list[dict] = []
    for policy_name in ("permissive", "path-prefix", "reference"):
        verdicts: dict[str, int] = {}
        for pi in range(prompts):
            for yi in range(payloads):
                record = run_single(
                    scenario,
                    load_policy(policy_name),
                    factory,
                    prompt_variant=pi,
                    payload_variant=yi,
                )
                verdicts[record.outcome.verdict] = verdicts.get(record.outcome.verdict, 0) + 1
        rows.append({"policy": policy_name, "cells": prompts * payloads, "verdicts": verdicts})

    if args.json:
        print(json.dumps({"scenario": scenario.spec.id, "rows": rows}, indent=2))
        return 0

    print(f"paraphrase coverage: {prompts} prompt x {payloads} injection phrasings")
    print(f"  deterministic cells per policy: {prompts * payloads}")
    print()
    for row in rows:
        spread = ", ".join(f"{k}={v}" for k, v in sorted(row["verdicts"].items()))
        invariant = "invariant" if len(row["verdicts"]) == 1 else "NOT invariant"
        print(f"  {row['policy']:<14s} {invariant:<14s} {spread}")
    print()
    print("  These are deterministic cells, not samples. No rate, no interval.")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    import platform

    print(f"interpose   {__version__}   bench {BENCH_VERSION}")
    print(f"python      {sys.version.split()[0]}  ({platform.python_implementation()})")
    print(f"platform    {platform.system()}-{platform.machine()}")
    print(f"stdout enc  {getattr(sys.stdout, 'encoding', 'unknown')}")
    scenarios = discover_scenarios()
    print(f"scenarios   {len(scenarios)} installed: {', '.join(scenarios) or '(none)'}")
    print(f"policies    {', '.join(sorted(BUILTIN_POLICIES))}")
    try:
        import anthropic  # noqa: F401

        print("anthropic   installed (optional provider available)")
    except ImportError:
        print("anthropic   not installed (optional; the default path needs no key)")
    print("network     not used by the default provider; see docs/THREAT-MODEL.md")
    return 0


def cmd_new(args: argparse.Namespace) -> int:
    """Scaffold a scenario from the bundled one.

    A copy of something that already passes, not a stub. Nothing kills a first
    contribution like a scaffold that errors before it has been edited.
    """
    import shutil

    source = load_scenario(DEFAULT_SCENARIO).root
    target = Path(args.directory or ".") / args.name
    if target.exists():
        raise UsageError(f"{target} already exists")
    shutil.copytree(source, target)

    manifest = target / "scenario.yaml"
    text = manifest.read_text(encoding="utf-8")
    text = text.replace(f"id: {DEFAULT_SCENARIO}", f"id: {args.name}", 1)
    manifest.write_text(text, encoding="utf-8", newline="\n")

    print(f"created {target}")
    print()
    print("It already passes. Verify that first, then change one thing:")
    print(f"  interpose run {target} --policy reference")
    print()
    print("Good first edits, in order of how much they teach:")
    print("  1. edit untrusted/vendor-sow-q3.v1.md.b64 (base64; keep the marker line)")
    print("  2. add a benign task whose required call the policy might refuse")
    print("  3. change the objective to target a tool the policy allows with other args")
    return 0


def _kv(mapping: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(mapping.items()))


# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="interpose",
        description=(
            "A regression test for the trust boundary in tool-using agents. "
            "Runs entirely against a bundled simulation; there is no parameter "
            "for pointing it at an external system."
        ),
    )
    parser.add_argument("--version", action="version", version=f"interpose {__version__}")
    sub = parser.add_subparsers(dest="command")

    def add_common(p: argparse.ArgumentParser, with_policy: bool = True) -> None:
        p.add_argument("--provider", default="scripted:compliant",
                       help="scripted[:compliant|refusing|partial|confused] or anthropic[:model]")
        if with_policy:
            p.add_argument("--policy", default="reference",
                           help=f"{', '.join(sorted(BUILTIN_POLICIES))}, or module.path:ClassName")
        p.add_argument("--json", action="store_true", help="machine-readable output")

    p_demo = sub.add_parser("demo", help="the three-policy comparison; no key, no network")
    p_demo.add_argument("scenario", nargs="?", default=DEFAULT_SCENARIO)
    add_common(p_demo, with_policy=False)
    p_demo.set_defaults(func=cmd_demo)

    p_run = sub.add_parser("run", help="run one policy: attack plus the full benign suite")
    p_run.add_argument("scenario", nargs="?", default=DEFAULT_SCENARIO)
    add_common(p_run)
    p_run.add_argument("--attack-only", action="store_true",
                       help="single attack run; prints a trace, not a scorecard")
    p_run.add_argument("--save", action="store_true", help="write artifacts under runs/")
    p_run.add_argument("--no-save", action="store_true", help="do not write artifacts")
    p_run.set_defaults(func=cmd_run)

    p_ls = sub.add_parser("ls", help="list scenarios, policies, providers")
    p_ls.add_argument("what", nargs="?", choices=["scenarios", "policies", "providers", "all"])
    p_ls.set_defaults(func=cmd_ls)

    p_show = sub.add_parser("show", help="inspect a scenario")
    p_show.add_argument("scenario", nargs="?", default=DEFAULT_SCENARIO)
    p_show.add_argument("--json", action="store_true")
    p_show.set_defaults(func=cmd_show)

    p_replay = sub.add_parser("replay", help="render the causal trace of a stored run")
    p_replay.add_argument("run", help="run id, run directory, or events.jsonl path")
    p_replay.add_argument("--verbose", action="store_true", help="include agent messages")
    p_replay.set_defaults(func=cmd_replay)

    p_verify = sub.add_parser("verify", help="check a result.json against installed artifacts")
    p_verify.add_argument("result")
    p_verify.set_defaults(func=cmd_verify)

    p_matrix = sub.add_parser("matrix", help="paraphrase coverage across prompt and payload")
    p_matrix.add_argument("scenario", nargs="?", default=DEFAULT_SCENARIO)
    add_common(p_matrix, with_policy=False)
    p_matrix.set_defaults(func=cmd_matrix)

    p_doctor = sub.add_parser("doctor", help="environment report for a bug report")
    p_doctor.set_defaults(func=cmd_doctor)

    p_new = sub.add_parser("new", help="scaffold a scenario that already passes")
    p_new.add_argument("kind", choices=["scenario"])
    p_new.add_argument("name")
    p_new.add_argument("--directory", default="scenarios")
    p_new.set_defaults(func=cmd_new)

    return parser


def main(argv: list[str] | None = None) -> int:
    configure_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        print(ORIENTATION.strip())
        return 0

    try:
        return int(args.func(args))
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except HarnessError as exc:
        print(f"harness error: {exc}", file=sys.stderr)
        return 2
    except InterposeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except BrokenPipeError:
        return 0


_ = AgentProvider  # protocol referenced by the provider factories

if __name__ == "__main__":
    raise SystemExit(main())
