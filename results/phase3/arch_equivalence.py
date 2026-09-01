"""Before/after equivalence protocol for an Interpose execution-architecture change.

Run this **before** a migration to record a baseline, and **after** it to
decide whether the migration preserved semantics. It answers one question and
refuses to answer any other:

    Did changing where the policy runs change what the instrument measured?

Method. The same grid -- every scenario x every policy x every scripted
behaviour class -- is executed once per *architecture arm*. An arm differs
from the baseline only in how ``SecurityPolicy.evaluate`` is reached. Four
arms ship:

  ``raw``        the policy object, called directly. Neutrality control: this
                 arm carries no instrumentation at all, and its trial digests
                 must equal ``proxy``'s or the measurement apparatus is
                 itself perturbing the measurement.
  ``proxy``      an identity delegating wrapper that records and times every
                 decision. The other arms are this wrapper plus a transport,
                 so the wrapper cancels out of every arm-to-arm comparison.
  ``roundtrip``  the wrapper plus a full serialise/deserialise of the context
                 and the decision through ``arch_wire``. No process boundary.
                 This isolates *wire fidelity* from *process mechanics*, and
                 it is runnable today, against current code, with nothing
                 migrated.
  ``worker``     the wrapper plus a real subprocess speaking the same wire
                 format over stdio. One worker per trial, matching the
                 in-process policy lifetime.

Comparison is exact. There is no tolerance on any semantic field, because
``METRICS.md`` promises the scripted path is bit-reproducible; a tolerance
here would quietly buy a nondeterminism budget the project has refused to
take. Three artifact fields may legitimately differ (``created_at``,
``python_version``, ``platform``) and they are already excluded from
``TrialResult.digest()``. Latency is measured, reported, and never compared
for equality -- see the note in the artifact.

Usage, from the repository root::

    set PYTHONIOENCODING=utf-8
    .venv\\Scripts\\python.exe <this file> --arms raw,proxy,roundtrip,worker

Writes ``arch-equivalence.json`` beside itself and prints a verdict table.
Exit 0 EQUIVALENT, 1 DIVERGENT, 3 usage.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(HERE))

from arch_wire import (  # noqa: E402
    FORBIDDEN_WIRE_SUBSTRINGS,
    context_from_wire,
    context_to_wire,
    decision_from_wire,
    decision_to_wire,
)
from interpose import BENCH_VERSION, __version__  # noqa: E402
from interpose.digest import canonical_json  # noqa: E402
from interpose.engine.trial import run_single, run_trial, to_run_result  # noqa: E402
from interpose.policy.base import load_policy, policy_digest  # noqa: E402
from interpose.policy.types import Decision, DecisionContext  # noqa: E402
from interpose.providers.scripted import ScriptedProvider  # noqa: E402
from interpose.report.result import exit_code_for  # noqa: E402
from interpose.scenario.loader import load_scenario  # noqa: E402

SCENARIOS = ("indirect-document-injection", "confidential-egress", "compartment-egress")
BEHAVIORS = ("compliant", "paraphrasing")
POLICIES = (
    "permissive",
    "path-prefix",
    "reference",
    "cedar-action-only",
    "cedar-with-provenance",
)

#: The only fields of ``result.json`` that may differ between architectures.
#: All three are already excluded from ``TrialResult.digest()``; listing them
#: again here is the point -- the exclusion list must be written down and
#: reviewed, not inherited by accident from whatever the digest happens to skip.
MAY_DIFFER = ("created_at", "python_version", "platform")


# =========================================================================
# arms
# =========================================================================


class Recorder:
    """Identity delegating wrapper: records every context and decision, times it.

    Applied to every arm including the baseline, so no arm is measured through
    instrumentation another arm does not carry. ``digest`` delegates, so the
    artifact still names the wrapped policy's bytes.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.id = inner.id
        self.version = getattr(inner, "version", "")
        self.contexts: list[dict[str, Any]] = []
        self.decisions: list[dict[str, Any]] = []
        self.seconds: list[float] = []

    def describe(self) -> str:
        return str(self._inner.describe())

    def digest(self) -> str:
        return policy_digest(self._inner)

    def _call(self, ctx: DecisionContext) -> Decision:
        return self._inner.evaluate(ctx)

    def evaluate(self, ctx: DecisionContext) -> Decision:
        wire = context_to_wire(ctx)
        started = time.perf_counter()
        decision = self._call(ctx)
        self.seconds.append(time.perf_counter() - started)
        self.contexts.append(wire)
        self.decisions.append(decision_to_wire(decision))
        return decision

    def close(self) -> None:
        pass


class RoundTripPolicy(Recorder):
    """Serialise the context out and the decision back, in this process.

    Every fidelity failure a worker can have -- a ``frozenset`` arriving as a
    list, a tuple arriving as a list, an enum arriving as a bare string, an
    argument's int becoming a float -- happens here too, and happens without
    needing anything to have been migrated yet.
    """

    def _call(self, ctx: DecisionContext) -> Decision:
        payload = json.loads(canonical_json(context_to_wire(ctx)).decode("utf-8"))
        restored = context_from_wire(payload)
        decision = self._inner.evaluate(restored)
        return decision_from_wire(
            json.loads(canonical_json(decision_to_wire(decision)).decode("utf-8"))
        )


class NaiveRoundTripPolicy(Recorder):
    """**Negative control.** A plausible worker that gets the types slightly wrong.

    It does the three things a competent engineer does when JSON will not carry
    a Python type: leaves the ``StrEnum`` members as bare strings, leaves
    ``granted_tools`` as a list, and leaves the tuples as lists. Nothing here
    looks like a bug. Every one of these survives ``mypy`` at the boundary
    because the boundary is ``dict[str, Any]``.

    Its purpose is to prove the protocol above can *fail*. An equivalence
    protocol that has never been shown to reject anything is decoration.
    """

    mode = "types"

    def _call(self, ctx: DecisionContext) -> Decision:
        payload = json.loads(canonical_json(context_to_wire(ctx)).decode("utf-8"))
        restored = _naive_context(payload) if self.mode == "types" else _lossy_context(payload)
        decision = self._inner.evaluate(restored)
        return decision_from_wire(
            json.loads(canonical_json(decision_to_wire(decision)).decode("utf-8"))
        )


class LossyReadersPolicy(NaiveRoundTripPolicy):
    """**Negative control 2.** A worker that drops ``SourceView.readers``.

    A plausible payload-size optimisation -- the sink already carries its
    readers, so the source's need-to-know allowlist looks redundant. It is not.
    Dropping it silently converts ``ReaderView.entitled_to`` from an allowlist
    check into a bulk-clearance comparison, which is precisely the bug
    ``SinkView``'s own docstring records as having been fixed twice. Nothing
    raises. The policy keeps returning ``Decision`` objects.
    """

    mode = "lossy"


def _lossy_context(d: dict[str, Any]) -> DecisionContext:
    stripped = json.loads(json.dumps(d))
    for bucket in ("value_sources", "context_sources"):
        for s in stripped["provenance"][bucket]:
            s["readers"] = []
    return context_from_wire(stripped)


def _naive_context(d: dict[str, Any]) -> DecisionContext:
    from interpose.policy.types import (
        ActionView as _A,
    )
    from interpose.policy.types import (
        PrincipalView as _P,
    )
    from interpose.policy.types import (
        PriorDecision as _PD,
    )
    from interpose.policy.types import (
        ProvenanceView as _PV,
    )
    from interpose.policy.types import (
        ReaderView as _RV,
    )
    from interpose.policy.types import (
        ResourceView as _R,
    )
    from interpose.policy.types import (
        SinkView as _S,
    )
    from interpose.policy.types import (
        SourceView as _SV,
    )

    def src(x: dict) -> Any:
        # trust and classification left as plain strings
        return _SV(x["unit_id"], x["resource_uri"], x["trust"], x["classification"], x["readers"])

    p, r, s = d["principal"], d["resource"], d["sink"]
    return DecisionContext(
        step=d["step"],
        principal=_P(
            p["id"], p["kind"], p["clearance"], p["roles"], p["granted_tools"],
            p["on_behalf_of"], p["on_behalf_of_clearance"],
        ),
        action=_A(d["action"]["tool"], d["action"]["arguments"], d["action"]["effect_class"]),
        provenance=_PV(
            value_sources=[src(x) for x in d["provenance"]["value_sources"]],
            context_sources=[src(x) for x in d["provenance"]["context_sources"]],
        ),
        resource=None
        if r is None
        else _R(r["uri"], r["kind"], r["classification"], r["owner_principal_id"],
                r["readers"], r["path"]),
        sink=None
        if s is None
        else _S(s["id"], [_RV(x["id"], x["clearance"]) for x in s["readers"]]),
        history=[_PD(h["step"], h["tool"], h["effect"], h["rule_id"]) for h in d["history"]],
        user_task=d["user_task"],
    )


class WorkerPolicy(Recorder):
    """A real subprocess, one per trial, speaking the wire format over stdio."""

    def __init__(self, policy_ref: str) -> None:
        self._ref = policy_ref
        self.proc = subprocess.Popen(
            [str(REPO / ".venv" / "Scripts" / "python.exe"), str(HERE / "policy_worker.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self.spawn_seconds = 0.0
        started = time.perf_counter()
        hello = self._rpc({"op": "hello", "policy": policy_ref})
        self.spawn_seconds = time.perf_counter() - started
        if not hello.get("ok"):
            raise RuntimeError(f"worker refused to load {policy_ref}: {hello}")
        self.worker_digest = hello["digest"]
        self.worker_modules = hello["loaded_interpose_modules"]
        # The parent still loads the policy, because ``policy_digest`` and the
        # artifact's ``policy`` ref are parent-side facts. Whether the two
        # processes agree on the digest is one of the things under test.
        inner = load_policy(policy_ref)
        super().__init__(inner)
        self.__class__ = _transparent(type(self), inner)
        self.parent_digest = policy_digest(inner)

    def _rpc(self, msg: dict[str, Any]) -> dict[str, Any]:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"worker died: {err[:2000]}")
        return dict(json.loads(line))

    def _call(self, ctx: DecisionContext) -> Decision:
        reply = self._rpc({"op": "evaluate", "ctx": context_to_wire(ctx)})
        if not reply.get("ok"):
            raise RuntimeError(f"worker error: {reply.get('error')}")
        return decision_from_wire(reply["decision"])

    def close(self) -> None:
        try:
            self._rpc({"op": "bye"})
        except Exception:  # noqa: BLE001
            pass
        try:
            self.proc.terminate()
        except Exception:  # noqa: BLE001
            pass


def _transparent(wrapper_cls: type, inner: Any) -> type:
    """Make a wrapper digest as the policy it delegates to.

    ``policy_digest`` walks the first-party import closure of
    ``type(policy).__module__``. A wrapper therefore digests as *itself*, which
    is why substituting the policy object silently changes ``policy.digest``,
    ``run_id`` and ``trace_digest`` (§1.8 of the methodology note).

    R14 correctly removed the ``digest()`` override, because a third-party
    adapter must not choose its own hash. This is not that: the subclass cannot
    name an arbitrary digest, only the module it delegates into, and the hash is
    still computed from that module's source. It is a **stopgap for harness-side
    instrumentation only**.

    The real fix belongs in ``src``: apply timing and transport at the single
    ``policy.base.evaluate`` call site instead of substituting the policy
    object. ``results/phase2/cedar_ablation.py`` needs the same fix -- its
    ``TimedPolicy`` wraps the same way, so the published ``cedar-ablation.json``
    no longer regenerates its own ``policy_digest`` values.
    """
    return type(
        wrapper_cls.__name__, (wrapper_cls,), {"__module__": type(inner).__module__}
    )


def make_arm(arm: str, policy_ref: str) -> Any:
    if arm == "raw":
        return load_policy(policy_ref)
    if arm == "worker":
        return WorkerPolicy(policy_ref)
    cls = {
        "proxy": Recorder,
        "roundtrip": RoundTripPolicy,
        "naive": NaiveRoundTripPolicy,
        "lossy-readers": LossyReadersPolicy,
    }.get(arm)
    if cls is None:
        raise SystemExit(f"unknown arm {arm!r}")
    inner = load_policy(policy_ref)
    return _transparent(cls, inner)(inner)


# =========================================================================
# comparison
# =========================================================================


def diff(a: Any, b: Any, path: str = "") -> list[str]:
    """Dotted-path differences between two JSON-native values."""
    if type(a) is not type(b) and not (
        isinstance(a, int | float) and isinstance(b, int | float)
    ):
        return [f"{path or '<root>'}: type {type(a).__name__} != {type(b).__name__}"]
    if isinstance(a, dict):
        out: list[str] = []
        for key in sorted(set(a) | set(b)):
            if key not in a:
                out.append(f"{path}.{key}: missing in A")
            elif key not in b:
                out.append(f"{path}.{key}: missing in B")
            else:
                out.extend(diff(a[key], b[key], f"{path}.{key}"))
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            return [f"{path}: length {len(a)} != {len(b)}"]
        out = []
        for i, (x, y) in enumerate(zip(a, b, strict=True)):
            out.extend(diff(x, y, f"{path}[{i}]"))
        return out
    return [] if a == b else [f"{path}: {a!r} != {b!r}"]


def strip_volatile(result: dict[str, Any]) -> dict[str, Any]:
    out = dict(result)
    for key in MAY_DIFFER:
        out.pop(key, None)
    return out


def first_stream_divergence(a: list[dict], b: list[dict]) -> dict[str, Any] | None:
    """Index and field of the first difference between two decision streams."""
    for i in range(min(len(a), len(b))):
        d = diff(a[i], b[i], f"[{i}]")
        if d:
            return {"index": i, "fields": d[:6], "total_field_diffs": len(d)}
    if len(a) != len(b):
        return {"index": min(len(a), len(b)), "fields": ["stream length differs"],
                "total_field_diffs": abs(len(a) - len(b))}
    return None


def scan_for_answer_key(payloads: list[dict[str, Any]]) -> list[str]:
    """Any wire key at any depth whose name could name the trial."""
    hits: set[str] = set()

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                low = str(k).lower()
                for bad in FORBIDDEN_WIRE_SUBSTRINGS:
                    if bad in low:
                        hits.add(f"{path}.{k}")
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    for p in payloads:
        walk(p, "ctx")
    return sorted(hits)


# =========================================================================
# grid
# =========================================================================


def cell(arm: str, scenario_id: str, policy_ref: str, behavior: str) -> dict[str, Any]:
    scenario = load_scenario(scenario_id)
    policy = make_arm(arm, policy_ref)
    started = time.perf_counter()
    trial, _records = run_trial(scenario, policy, lambda: ScriptedProvider(behavior=behavior))
    wall = time.perf_counter() - started
    seconds = list(getattr(policy, "seconds", []))
    row: dict[str, Any] = {
        "arm": arm,
        "scenario": scenario_id,
        "policy": trial.policy.id,
        "provider": f"scripted:{behavior}",
        # -- the primary equivalence key -------------------------------
        "trial_digest": trial.digest(),
        "exit_code": exit_code_for(trial),
        # -- the full artifact, volatile fields removed ----------------
        "result": strip_volatile(json.loads(trial.model_dump_json())),
        # -- decision stream, for trajectory comparison ----------------
        "contexts": list(getattr(policy, "contexts", [])),
        "decisions": list(getattr(policy, "decisions", [])),
        # -- reported, never compared ----------------------------------
        "latency": {
            "decisions": len(seconds),
            "mean_ms": round(statistics.fmean(seconds) * 1000, 4) if seconds else None,
            "max_ms": round(max(seconds) * 1000, 4) if seconds else None,
            "policy_seconds_total": round(sum(seconds), 4),
        },
        "wall_seconds": round(wall, 3),
        "worker_digest_agrees": None,
        "worker_spawn_seconds": None,
    }
    if isinstance(policy, WorkerPolicy):
        row["worker_digest_agrees"] = policy.worker_digest == policy.parent_digest
        row["worker_digest"] = policy.worker_digest
        row["parent_digest"] = policy.parent_digest
        row["worker_spawn_seconds"] = round(policy.spawn_seconds, 3)
        row["worker_module_count"] = len(policy.worker_modules)
    close = getattr(policy, "close", None)
    if callable(close):
        close()
    return row


def blindness_probe(arm: str, scenario_id: str, policy_ref: str) -> dict[str, Any]:
    """Compare the attack run's context stream with its matched benign control.

    The shipped fairness test compares ``(tool, arguments)`` for the first two
    decisions. This compares **every field of every context**, so a boundary
    that quietly widens what the policy is told fails here even when the two
    action streams still agree.
    """
    scenario = load_scenario(scenario_id)
    b1 = scenario.spec.benign[0]

    attack_policy = make_arm(arm if arm != "raw" else "proxy", policy_ref)
    run_single(scenario, attack_policy, lambda: ScriptedProvider("compliant"))
    a_ctx = list(attack_policy.contexts)
    getattr(attack_policy, "close", lambda: None)()

    benign_policy = make_arm(arm if arm != "raw" else "proxy", policy_ref)
    run_single(scenario, benign_policy, lambda: ScriptedProvider("compliant"), benign_task=b1)
    b_ctx = list(benign_policy.contexts)
    getattr(benign_policy, "close", lambda: None)()

    div = first_stream_divergence(a_ctx, b_ctx)
    return {
        "arm": arm,
        "scenario": scenario_id,
        "policy": policy_ref,
        "attack_contexts": len(a_ctx),
        "benign_contexts": len(b_ctx),
        "identical_prefix_len": (div or {}).get("index", min(len(a_ctx), len(b_ctx))),
        "first_divergence": div,
        "user_task_identical": bool(a_ctx and b_ctx and a_ctx[0]["user_task"] == b_ctx[0]["user_task"]),
        "answer_key_keys_present": scan_for_answer_key(a_ctx),
    }


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=REPO, capture_output=True, text=True, timeout=15
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def wrapper_transparency(policy_ref: str = "reference") -> dict[str, Any]:
    """Can this protocol measure anything at all on this commit?

    Every arm but ``raw`` reaches the policy through a delegating object, so
    the protocol is only valid if substituting that object leaves
    ``policy_digest`` unchanged. ``policy_digest`` hashes ``type(policy)``'s
    first-party import closure, so a wrapper changes it unless the wrapper's
    ``digest`` method is honoured as an override.

    That override was removed at the working tree of 2026-09-01 -- correctly,
    because a hostile adapter used it to self-attest the genuine reference
    policy's hash. The correct consequence is **not** to restore it. It is that
    instrumentation and transport must be applied at the single
    ``policy.base.evaluate`` call site, not by substituting the policy object,
    so that ``policy.digest`` keeps naming the bytes that actually decided.

    Until that seam exists, this protocol reports itself unusable rather than
    printing thirty divergences whose only cause is its own wrapper.
    """
    inner = load_policy(policy_ref)
    direct = policy_digest(inner)
    wrapped = policy_digest(_transparent(Recorder, inner)(inner))
    return {
        "transparent": direct == wrapped,
        "digest_direct": direct,
        "digest_through_wrapper": wrapped,
        "consequence": (
            "usable"
            if direct == wrapped
            else "UNUSABLE: substituting the policy object changes policy.digest, "
            "hence run_id and trace_digest. Instrument at policy.base.evaluate "
            "instead of wrapping the policy. Note results/phase2/cedar_ablation.py "
            "wraps the same way and its published artifact no longer reproduces."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--arms", default="raw,proxy,roundtrip,worker")
    ap.add_argument("--baseline", default="proxy")
    ap.add_argument("--scenarios", default=",".join(SCENARIOS))
    ap.add_argument("--policies", default=",".join(POLICIES))
    ap.add_argument("--behaviors", default=",".join(BEHAVIORS))
    ap.add_argument("--out", default=str(HERE / "arch-equivalence.json"))
    args = ap.parse_args(argv)

    arms = [a for a in args.arms.split(",") if a]
    scenarios = [s for s in args.scenarios.split(",") if s]
    policies = [p for p in args.policies.split(",") if p]
    behaviors = [b for b in args.behaviors.split(",") if b]
    if args.baseline not in arms:
        print(f"baseline arm {args.baseline!r} not in --arms")
        return 3

    transparency = wrapper_transparency()
    if not transparency["transparent"]:
        print("PROTOCOL UNUSABLE ON THIS COMMIT")
        print(f"  policy_digest direct        : {transparency['digest_direct']}")
        print(f"  policy_digest via wrapper   : {transparency['digest_through_wrapper']}")
        print(f"  {transparency['consequence']}")
        Path(args.out).write_text(
            json.dumps(
                {
                    "artifact": "architecture-equivalence",
                    "verdict": "UNUSABLE",
                    "wrapper_transparency": transparency,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return 2

    t0 = time.perf_counter()
    cells: dict[str, dict[str, dict[str, Any]]] = {a: {} for a in arms}
    for arm in arms:
        for scenario in scenarios:
            for behavior in behaviors:
                for policy_ref in policies:
                    key = f"{scenario}|{policy_ref}|{behavior}"
                    cells[arm][key] = cell(arm, scenario, policy_ref, behavior)
                    print(f"  ran {arm:<10} {key}", flush=True)

    # -- comparison -----------------------------------------------------
    base = cells[args.baseline]
    comparisons: list[dict[str, Any]] = []
    divergent = 0
    for arm in arms:
        if arm == args.baseline:
            continue
        for key, row in cells[arm].items():
            ref = base[key]
            digest_match = row["trial_digest"] == ref["trial_digest"]
            artifact_diff = diff(ref["result"], row["result"], "result")
            exit_match = row["exit_code"] == ref["exit_code"]
            stream_div = None
            if ref["contexts"] and row["contexts"]:
                stream_div = first_stream_divergence(ref["contexts"], row["contexts"])
            dec_div = None
            if ref["decisions"] and row["decisions"]:
                dec_div = first_stream_divergence(ref["decisions"], row["decisions"])
            ok = digest_match and not artifact_diff and exit_match and not stream_div and not dec_div
            if not ok:
                divergent += 1
            comparisons.append(
                {
                    "arm": arm,
                    "baseline": args.baseline,
                    "cell": key,
                    "equivalent": ok,
                    "trial_digest_match": digest_match,
                    "exit_code_match": exit_match,
                    "artifact_diff": artifact_diff[:10],
                    "artifact_diff_count": len(artifact_diff),
                    "context_stream_divergence": stream_div,
                    "decision_stream_divergence": dec_div,
                    "latency_baseline_mean_ms": ref["latency"]["mean_ms"],
                    "latency_arm_mean_ms": row["latency"]["mean_ms"],
                }
            )

    blindness = [
        blindness_probe(arm, scenario, "reference")
        for arm in arms
        for scenario in scenarios
    ]
    blindness_bad = [
        b for b in blindness if b["answer_key_keys_present"] or not b["user_task_identical"]
    ]

    worker_digest_disagreements = [
        {"cell": k, "worker": r.get("worker_digest"), "parent": r.get("parent_digest")}
        for arm in arms
        for k, r in cells[arm].items()
        if r.get("worker_digest_agrees") is False
    ]

    elapsed = time.perf_counter() - t0
    artifact = {
        "artifact": "architecture-equivalence",
        "artifact_version": "1",
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "bench_version": BENCH_VERSION,
        "harness_version": __version__,
        "python_version": sys.version.split()[0],
        "platform": f"{platform.system()}-{platform.machine()}",
        # A before/after protocol whose two halves cannot be shown to describe
        # the same source is not a before/after protocol. HEAD moved under this
        # analysis once already, and a sibling's uncommitted edit made the
        # protocol unusable, so both the commit and the tree state are recorded.
        "git_sha": _git("rev-parse", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "wrapper_transparency": transparency,
        "baseline_arm": args.baseline,
        "arms": arms,
        "grid": {
            "scenarios": scenarios,
            "policies": policies,
            "behaviors": behaviors,
            "cells_per_arm": len(scenarios) * len(policies) * len(behaviors),
        },
        "may_differ_fields": list(MAY_DIFFER),
        "tolerance": (
            "none. Every semantic field is compared for exact equality. The "
            "scripted path is promised bit-reproducible in METRICS.md, so a "
            "tolerance here would purchase a nondeterminism budget the project "
            "has refused to take."
        ),
        "note_on_latency": (
            "Latency is reported per arm and never compared for equality. It is "
            "the one quantity an architecture change is *expected* to move, and "
            "it is also the one quantity already published in a cross-policy "
            "table (CEDAR_PROVENANCE_ABLATION.md), so a migration must re-baseline "
            "that table rather than let old and new numbers sit in one column."
        ),
        "verdict": "EQUIVALENT" if divergent == 0 and not blindness_bad else "DIVERGENT",
        "divergent_cells": divergent,
        "comparisons": comparisons,
        "blindness": blindness,
        "worker_digest_disagreements": worker_digest_disagreements,
        "cells": {arm: {k: {kk: vv for kk, vv in v.items() if kk not in ("contexts", "decisions", "result")}
                        for k, v in rows.items()} for arm, rows in cells.items()},
        "elapsed_seconds": round(elapsed, 1),
    }
    Path(args.out).write_text(
        json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )

    print()
    print(f"{'arm':<11} {'cells':<6} {'equiv':<6} {'digest':<7} {'stream':<7} mean_ms")
    for arm in arms:
        rows = [c for c in comparisons if c["arm"] == arm]
        if not rows:
            lat = [r["latency"]["mean_ms"] for r in cells[arm].values() if r["latency"]["mean_ms"]]
            print(f"{arm:<11} {len(cells[arm]):<6} {'BASE':<6} {'-':<7} {'-':<7} "
                  f"{round(statistics.fmean(lat), 4) if lat else '-'}")
            continue
        eq = sum(1 for r in rows if r["equivalent"])
        dg = sum(1 for r in rows if r["trial_digest_match"])
        st = sum(1 for r in rows if not r["context_stream_divergence"])
        lat = [r["latency_arm_mean_ms"] for r in rows if r["latency_arm_mean_ms"]]
        print(f"{arm:<11} {len(rows):<6} {eq:<6} {dg:<7} {st:<7} "
              f"{round(statistics.fmean(lat), 4) if lat else '-'}")
    print()
    for c in comparisons:
        if not c["equivalent"]:
            print(f"  DIVERGENT {c['arm']} {c['cell']}")
            for d in c["artifact_diff"]:
                print(f"      {d}")
            if c["context_stream_divergence"]:
                print(f"      ctx: {c['context_stream_divergence']}")
    for b in blindness:
        print(
            f"  blindness {b['arm']:<10} {b['scenario']:<30} "
            f"attack={b['attack_contexts']} benign={b['benign_contexts']} "
            f"identical_prefix={b['identical_prefix_len']} "
            f"user_task_identical={b['user_task_identical']} "
            f"answer_key_keys={b['answer_key_keys_present']}"
        )
    if worker_digest_disagreements:
        print(f"  POLICY DIGEST DISAGREES ACROSS PROCESSES: {worker_digest_disagreements}")
    print()
    print(f"verdict: {artifact['verdict']}   wrote {args.out}   {elapsed:.1f}s")
    return 0 if artifact["verdict"] == "EQUIVALENT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
