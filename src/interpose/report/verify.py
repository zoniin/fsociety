"""Verification: does this artifact still describe reality?

The whole citability story is about two hundred lines, and this is them.
Vendor self-reported agent-security numbers are currently reproducible by
nobody; the difference between a number and a claim is whether a third party
can check what produced it.

Three answers, deliberately only three:

``AGREES``
    The scenario and policy content this result names still hash to what it
    recorded. The result describes the artifacts present here.
``SCENARIO_DRIFT``
    Something it names has changed. The result is not wrong -- it is not
    comparable to anything you would produce now, which is different and
    worth its own word.
``UNVERIFIABLE``
    The named artifacts are not resolvable here at all.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..errors import ScenarioError, UsageError
from ..policy.base import SecurityPolicy, load_policy, policy_digest
from ..scenario.loader import load_scenario

__all__ = ["VerifyReport", "verify_result_file"]


def _resolve_policy(policy_id: str) -> SecurityPolicy | None:
    """Resolve a policy by its recorded id.

    A result records the policy's own ``id``, which is not always the short
    name used on the command line, so both are tried.
    """
    try:
        return load_policy(policy_id)
    except UsageError:
        pass
    for short in ("permissive", "path-prefix", "reference"):
        candidate = load_policy(short)
        if candidate.id == policy_id:
            return candidate
    return None


@dataclass(frozen=True)
class VerifyReport:
    status: str
    detail: list[str]

    def render(self) -> str:
        lines = [self.status] + [f"  {d}" for d in self.detail]
        return "\n".join(lines)


def verify_result_file(path: Path) -> VerifyReport:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UsageError(f"cannot read result file {path}: {exc}") from exc

    detail: list[str] = []
    scenario_ref = payload.get("scenario", {})
    policy_ref = payload.get("policy", {})

    try:
        scenario = load_scenario(str(scenario_ref.get("id", "")))
    except ScenarioError:
        return VerifyReport(
            "UNVERIFIABLE",
            [f"scenario {scenario_ref.get('id')!r} is not installed here"],
        )

    drift = False
    if scenario.digest != scenario_ref.get("digest"):
        drift = True
        detail.append(
            f"scenario content differs: recorded {scenario_ref.get('digest')}, "
            f"present {scenario.digest}"
        )
    else:
        detail.append(f"scenario {scenario.spec.id} content matches")

    policy = _resolve_policy(str(policy_ref.get("id", "")))
    if policy is None:
        return VerifyReport(
            "UNVERIFIABLE",
            [*detail, f"policy {policy_ref.get('id')!r} is not installed here"],
        )

    current = policy_digest(policy)
    if current != policy_ref.get("digest"):
        drift = True
        detail.append(
            f"policy content differs: recorded {policy_ref.get('digest')}, present {current}"
        )
    else:
        detail.append(f"policy {policy.id} content matches")

    recorded_bench = payload.get("bench_version")
    if recorded_bench != scenario.spec.bench_version:
        drift = True
        detail.append(
            f"bench_version differs: recorded {recorded_bench}, "
            f"present {scenario.spec.bench_version}"
        )

    if not payload.get("deterministic", False):
        detail.append(
            "result was produced with a non-deterministic provider; digests "
            "establish inputs, not that a re-run reproduces the outcome"
        )

    return VerifyReport("SCENARIO_DRIFT" if drift else "AGREES", detail)
