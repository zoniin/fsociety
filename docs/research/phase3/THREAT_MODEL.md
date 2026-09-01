# Phase III threat model

Written before implementation. Its purpose is to name the adversaries precisely
enough that a process boundary can be justified against one of them, or not
built at all.

The Phase III brief originally assumed the agent could bypass the enforcement
point. Repository evidence contradicts that, and the brief was amended. This
document records what was measured.

---

## The adversaries

| | Adversary | In scope for Phase III? |
|---|---|---|
| **T1** | Manipulated model behaviour — adversarial input causes the model to propose an unauthorized tool action | Modelled by the entire corpus. **Already mediated** — see §2. |
| **T2** | Compromised orchestration logic — the application code around the model is malicious | Not exercised by any shipped scenario. Research question. |
| **T3** | Arbitrary code execution in the client process | Stronger than anything the corpus models. Research question. |
| **P1** | **Untrusted, buggy, or malicious policy adapter** | **First-class. The live executable extension boundary.** |
| **H1** | Host compromise — malicious OS user, debugger, same-user malware, kernel | **Out of scope.** A subprocess is not a defence against it, and saying otherwise would be theatre. |

## 2. T1 is already mediated — the measurement

The claim: *for the adversary the corpus actually models, there is no path from
model output to protected state that skips the enforcement point.*

This rests on model output being **data, never code**. `provider.respond()`
returns an `AgentTurn` — text plus a list of `ProposedCall(tool: str, arguments:
dict)`. Verified structurally:

**No dynamic-execution construct exists in the package.**

```
grep -rnE "\b(eval|exec|compile|__import__)\(" src/interpose/   ->  no matches
```

The only `importlib` call in the package is `policy/base.py::load_policy`.

**No model-supplied string selects an attribute.** Every `getattr` in the
package is the defensive two-argument form with a **literal** attribute name
(`getattr(p, "tool", "")`, `getattr(e, "call_id", None)`) applied to internal
event objects. None takes a model-supplied string as the attribute name.

**A model-supplied tool name reaches only a dict lookup.**

```python
def get(self, name: str) -> ToolSpec:
    if name not in self._by_name:
        raise ToolError(f"no such tool: {name}")
    return self._by_name[name]
```

No dynamic dispatch, no attribute traversal, no import.

**Arguments are inert.** They flow to `tool.resolve(world, arguments)` and
`tool.execute(...)`, both of which treat them as data — dict lookups and string
comparisons against world contents.

### What may and may not be concluded

**May:** *Against the current model-output adversary, all modeled tool execution
is already mediated by the runner. Interpose has no code path from an
`AgentTurn` field to a dynamic construct.*

**May not:** that this is a proven universal reference-monitor property. It is a
property of *this* provider interface over *this* tool registry, established by
inspection and a structural test, not a proof over arbitrary Python. A provider
implementation is ordinary Python and can do anything; the claim is about the
model's output, not about the code that fetches it.

**Consequence for Phase III:** process-separating the *agent* would add no
property that any shipped scenario can exercise. That motivation is withdrawn.

## 3. P1 is the live boundary

The same audit that clears T1 indicts P1, and by the same evidence.

The one dynamic import in the package is the policy loader:

```python
module = importlib.import_module(module_name)   # policy/base.py
```

Its argument comes from `--policy`, from `challenge`, and from `verify` — never
from model output. So it is not reachable by T1. But it means **loading a
third-party policy adapter is arbitrary code execution in the harness process,
at import time, before `evaluate` is ever called.**

That process holds the authoritative `World`, the event log, the outcome
evaluator, the tool registry, the provenance index, and the scenario corpus that
is supposed to be *scoring the policy*.

`DecisionContext` is well built — frozen views, no `World` handle — so a
well-behaved policy already cannot reach anything. The question Phase III must
answer empirically is whether that holds **by construction or merely by
convention**, and it is being tested rather than assumed.

The governing principle, restated from the amendment:

> No component being evaluated by Interpose should possess unnecessary authority
> over the measurement apparatus that evaluates it.

For model output this already holds. For executable policy adapters it appears
not to.

## 4. What a policy worker process would and would not establish

Stated in advance so the result cannot be inflated afterwards.

**Would**, if it works: prevent policy adapters from receiving direct Python
object authority over Interpose's in-memory measurement apparatus.

**Would not**: make untrusted policy code safe. A worker running arbitrary
Python under the same OS user can still read the parent's files, exhaust memory,
spawn processes, and reach the network. That is **H1**, and it is out of scope.
Any claim beyond the narrow property above is unsupported.

The wording matters, and the phase is bound to it:

- **Supported:** "process-separated policy evaluation prevents policy adapters
  from receiving direct Python object authority over the in-memory apparatus."
- **Not supported:** "untrusted policy code is sandboxed."

## 5. The three extension mechanisms are not equally trusted

A distinction the project has not previously drawn.

| Extension | Executes code? | Whose? | Process | Current trust |
|---|---|---|---|---|
| **Scenarios** | No — YAML plus fixtures; the loader refuses `!!python/` tags and path escapes | contributor | n/a | **data** — can be run automatically |
| **Providers** | Yes | fixed set (`scripted`, `anthropic`); not loadable from an arbitrary string | harness | code, but not contributor-supplied |
| **Policies** | **Yes, via `importlib` on an arbitrary module path** | **contributor** | **harness** | **code, contributor-supplied, fully trusted** |

Only the third is both contributor-supplied and executable, and it is the one
the project actively solicits in `CHALLENGE.md`. That asymmetry is the finding
that reframed this phase.

Detail belongs in `EXTENSION_TRUST_MODEL.md`, which is written after the
empirical P1 results land.

## 6. Falsification conditions, recorded in advance

Phase III should be judged a success if uncertainty decreases, including in
these directions:

- **A malicious policy turns out to be unable to reach anything meaningful
  in-process.** Then architecture B is unnecessary and the honest output is a
  documented negative result.
- **A policy worker turns out not to prevent the attacks that matter**, because
  same-user process authority dominates. Then the answer is architecture E — a
  constrained declarative adapter — or nothing.
- **The P1 adversary turns out to be hypothetical.** The project has no external
  contributors and no policy adapter has ever been submitted. If the honest
  reading is that a policy adapter is a trusted dependency like any `pip install`
  and the correct control is human review, that should be said plainly rather
  than engineered around.
