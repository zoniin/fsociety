"""Saved benchmarks: a frontier sweep written down so it can be run again.

A benchmark is a YAML file under ``benchmarks/`` naming the scenarios,
policies, clients, samples and session mode of one sweep, plus what it is
expected to cost. ``interpose bench run <name>`` executes it and writes a
self-describing result directory::

    results/<name>/<UTC timestamp>/
        benchmark.yaml   the spec exactly as run
        manifest.json    harness, scenario and policy versions and digests, usage, cost
        frontier.json    every cell, as `interpose frontier --json` prints it
        report.html      the self-contained frontier report
        runs/            every trial's result.json and event logs, written as it completes

Real models cost money, so a benchmark with any non-deterministic client
prints its plan and an estimate and stops, unless ``--yes`` is given. The
estimate comes from tokens measured on earlier runs, recorded in the spec.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import BENCH_VERSION, __version__
from .engine.trial import write_run_artifacts
from .errors import UsageError
from .policy.base import load_policy, policy_digest
from .providers.registry import is_deterministic_spec, provider_factory
from .report.frontier import Frontier, collect_frontier, render_frontier_html
from .report.result import TrialResult
from .scenario.loader import discover_scenarios, load_scenario

__all__ = ["BenchmarkSpec", "Plan", "discover_benchmarks", "load_benchmark", "plan", "run_benchmark"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TokensPerScorecard(_Strict):
    input: int = Field(ge=0)
    output: int = Field(ge=0)


class PricePerMTok(_Strict):
    input: float = Field(ge=0)
    output: float = Field(ge=0)


class CostModel(_Strict):
    #: Measured on earlier runs of a comparable sweep: one attack run plus the
    #: benign suite. An estimate, recorded with where it came from.
    measured_tokens_per_scorecard: TokensPerScorecard
    price_per_mtok: PricePerMTok
    source: str = ""


class BenchmarkSpec(_Strict):
    name: str
    description: str
    scenarios: list[str] = Field(min_length=1)
    policies: list[str] = Field(min_length=1)
    clients: list[str] = Field(min_length=1)
    repeat: int = Field(default=1, ge=1)
    session: Literal["fresh", "long"] = "fresh"
    isolate_policy: bool = False
    cost: CostModel | None = None
    notes: str = ""

    @field_validator("description", "notes")
    @classmethod
    def _strip(cls, value: str) -> str:
        return " ".join(value.split())


def benchmarks_root() -> Path:
    packaged = Path(__file__).resolve().parent / "_bundled" / "benchmarks"
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[2] / "benchmarks"


def discover_benchmarks() -> dict[str, Path]:
    root = benchmarks_root()
    if not root.is_dir():
        return {}
    return {p.stem: p for p in sorted(root.glob("*.yaml"))}


def load_benchmark(ref: str) -> tuple[BenchmarkSpec, Path]:
    path = Path(ref)
    if not path.is_file():
        found = discover_benchmarks()
        if ref not in found:
            raise UsageError(f"no benchmark {ref!r}. Saved benchmarks: {sorted(found) or 'none'}")
        path = found[ref]
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        spec = BenchmarkSpec.model_validate(data)
    except (yaml.YAMLError, ValueError) as exc:
        raise UsageError(f"{path} is not a valid benchmark: {exc}") from exc
    known = discover_scenarios()
    missing = [s for s in spec.scenarios if s not in known]
    if missing:
        raise UsageError(f"benchmark {spec.name!r} names unknown scenarios: {missing}")
    for client in spec.clients:
        provider_factory(client)  # validates the name
    for policy in spec.policies:
        load_policy(policy)  # validates the name
    return spec, path


class Plan(BaseModel):
    trials: int
    paid_trials: int
    deterministic: bool
    estimated_input_tokens: int = 0
    estimated_output_tokens: int = 0
    estimated_usd: float | None = None

    def describe(self, spec: BenchmarkSpec) -> str:
        lines = [
            f"benchmark  {spec.name}",
            f"  {spec.description}",
            f"  {len(spec.scenarios)} scenario(s) x {len(spec.policies)} policies x "
            f"{len(spec.clients)} client(s), repeat {spec.repeat}, {spec.session} sessions"
            + (", isolated policy" if spec.isolate_policy else ""),
            f"  {self.trials} scorecard(s), {self.paid_trials} against a non-deterministic client",
        ]
        if self.paid_trials:
            if self.estimated_usd is not None:
                lines.append(
                    f"  estimate: ~{self.estimated_input_tokens:,} input + "
                    f"~{self.estimated_output_tokens:,} output tokens, about "
                    f"${self.estimated_usd:.2f} at list price"
                )
            else:
                lines.append("  estimate: none (the spec records no cost model)")
        return "\n".join(lines)


def plan(spec: BenchmarkSpec) -> Plan:
    per_client = len(spec.scenarios) * len(spec.policies)
    paid = sum(per_client * spec.repeat for c in spec.clients if not is_deterministic_spec(c))
    total = sum(per_client * (1 if is_deterministic_spec(c) else spec.repeat)
                for c in spec.clients)
    p = Plan(trials=total, paid_trials=paid, deterministic=paid == 0)
    if paid and spec.cost is not None:
        t = spec.cost.measured_tokens_per_scorecard
        price = spec.cost.price_per_mtok
        p.estimated_input_tokens = t.input * paid
        p.estimated_output_tokens = t.output * paid
        p.estimated_usd = round(
            (p.estimated_input_tokens * price.input + p.estimated_output_tokens * price.output)
            / 1_000_000, 2,
        )
    return p


def run_benchmark(
    spec: BenchmarkSpec,
    spec_path: Path,
    *,
    out_root: Path = Path("results"),
    progress: Any = None,
    now: datetime | None = None,
) -> Path:
    """Run the sweep, saving every trial as it completes. Returns the result directory."""
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    out = out_root / spec.name / stamp
    (out / "runs").mkdir(parents=True, exist_ok=False)
    shutil.copyfile(spec_path, out / "benchmark.yaml")

    usage = {"trials": 0, "input_tokens": 0, "output_tokens": 0}

    def on_trial(trial: TrialResult, records: list[object]) -> None:
        write_run_artifacts(out / "runs", trial, records)  # type: ignore[arg-type]
        usage["trials"] += 1
        for r in [trial.attack, *trial.benign]:
            usage["input_tokens"] += int(r.usage.get("input_tokens", 0))
            usage["output_tokens"] += int(r.usage.get("output_tokens", 0))
        if progress is not None:
            progress(
                f"  [{usage['trials']}] {trial.scenario.id} {trial.policy.id} "
                f"{trial.provider.id}: {trial.attack.outcome.verdict}, benign "
                f"{trial.benign_passed}/{trial.benign_total}; tokens in="
                f"{usage['input_tokens']:,} out={usage['output_tokens']:,}"
            )

    frontier = collect_frontier(
        spec.scenarios, spec.policies, spec.clients, session=spec.session,
        repeat=spec.repeat, isolate=spec.isolate_policy, on_trial=on_trial,
    )
    write_result(out, spec, frontier, started=stamp)
    return out


def write_result(out: Path, spec: BenchmarkSpec, frontier: Frontier, *, started: str) -> None:
    """Write manifest, frontier.json and report.html for a finished sweep."""
    totals = frontier.usage()
    actual_usd = None
    if spec.cost is not None and totals.get("input_tokens"):
        price = spec.cost.price_per_mtok
        actual_usd = round(
            (totals.get("input_tokens", 0) * price.input
             + totals.get("output_tokens", 0) * price.output) / 1_000_000, 4,
        )
    manifest = {
        "benchmark": spec.name,
        "started": started,
        "harness_version": __version__,
        "bench_version": BENCH_VERSION,
        "scenarios": {
            sid: {"version": sc.spec.version, "digest": sc.digest}
            for sid, sc in ((s, load_scenario(s)) for s in spec.scenarios)
        },
        "policies": {
            name: {"id": pol.id, "version": pol.version,
                   "digest": _digest(name, pol, spec.isolate_policy)}
            for name, pol in ((n, load_policy(n)) for n in spec.policies)
        },
        "clients": spec.clients,
        "deterministic": frontier.deterministic,
        "usage": totals,
        "usd_at_list_price": actual_usd,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (out / "frontier.json").write_text(
        json.dumps(frontier.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    (out / "report.html").write_text(
        render_frontier_html(
            frontier, title=f"{spec.name} benchmark", heading=spec.name,
            lede=spec.description, footnote=spec.notes,
        ),
        encoding="utf-8",
    )


def _digest(name: str, policy: Any, isolated: bool) -> str:
    """The digest the trials were scored under, isolated or not."""
    if not isolated:
        return policy_digest(policy)
    from .policy.base import BUILTIN_POLICIES
    from .policy.isolated import harness_digest

    return harness_digest(BUILTIN_POLICIES.get(name, name))
