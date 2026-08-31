# What the enforcement boundary actually guarantees

`SIMPL-0001` says the policy decision point is not a reference monitor. That is
true, but it is imprecise in both directions, and the imprecision matters
because it points remediation at the wrong thing. This document traces the
actual architecture and says exactly what can tamper with what.

Written before implementing anything. The conclusion is that the change
`SIMPL-0001` proposes would not fix the problem `SIMPL-0001` describes, and
that the sharper risk is somewhere else entirely.

---

## 1. The architecture as it exists

Everything below happens in **one CPython process**. There is no second
process anywhere in the default path.

```
                        ┌─────────────────────────────────────────────┐
                        │  ONE PYTHON PROCESS                         │
                        │                                             │
   remote model  ◀─────▶│  provider.respond(transcript, tools)        │
   (anthropic only,     │      returns AgentTurn: text + tool_calls   │
    optional)           │      ── this is DATA, not control ──        │
                        │                    │                        │
                        │                    ▼                        │
                        │  Runner.run()  loop, turn < max_turns       │
                        │                    │                        │
                        │                    ▼                        │
                        │  Runner._dispatch(tool_name, arguments)     │
                        │      1. registry.get(tool)      ─┐          │
                        │      2. tool in self.tools?      │ PEP      │
                        │      3. tool.resolve(world,args) │          │
                        │      4. provenance.attribute_args│          │
                        │      5. evaluate(policy, ctx)   ─┼─▶ PDP    │
                        │      6. if DENY: return         ─┘          │
                        │      7. tool.execute(world, ...) ──▶ WORLD  │
                        │                                             │
                        │  World: in-memory object graph              │
                        │      resources, principals, queues, tickets │
                        └─────────────────────────────────────────────┘
```

Precise component list:

| Component | What it is | Trust |
|---|---|---|
| the model | remote, or `ScriptedProvider`'s table | **untrusted** — this is the thing being mediated |
| provider object | in-process Python, `respond()` | trusted code, fixed set (`scripted`, `anthropic`) |
| `Runner.run()` | the turn loop | trusted |
| `Runner._dispatch` | **the PEP.** Sole path to `tool.execute` | trusted |
| policy adapter | in-process Python, `evaluate(ctx)` | **trusted by assumption — see §4** |
| `ToolSpec.execute` | in-process Python closure | trusted |
| `World` | mutable in-memory graph | the resource |

## 2. What can tamper with what

### The model cannot bypass the PEP — and this is stronger than SIMPL-0001 says

`SIMPL-0001` states the decision point "is a function call the agent's process
could in principle skip." That framing borrows from a threat model that does not
apply here. **The agent has no process.** `provider.respond()` returns an
`AgentTurn` — a dataclass of text and requested tool calls. The model's entire
influence on the system is that return value. Data cannot skip a function call.

So for the actual adversary the benchmark is about — a model induced by injected
content to request a privileged action — **mediation is complete**, and there is
a test asserting the single chokepoint. On this axis Interpose is stronger than
its own documentation claims, and the documentation should be corrected rather
than the code changed.

### The policy adapter can reach everything

This is the real exposure, and it runs the opposite way from the one documented.

`DecisionContext` is well designed: it carries **frozen views only** —
`PrincipalView`, `ActionView`, `ProvenanceView`, `ResourceView`, `SinkView` —
and holds **no reference to `World`**. A policy that only reads its argument
cannot touch anything.

But a policy is arbitrary Python running in the harness process. It does not
have to only read its argument. In CPython, an object with no reference to the
world is one `gc.get_referrers` or `sys._getframe(1).f_locals` away from having
one. Nothing prevents a policy adapter from mutating the world, rewriting the
event log, or monkey-patching `_dispatch` for subsequent calls.

And `load_policy` (`policy/base.py`) accepts `module.path:ClassName` and calls
`importlib.import_module` on it. **Loading a third-party policy adapter is
arbitrary code execution, at import time, before `evaluate` is ever called.**

That is a legitimate design choice — adapters are the extension point, and an
adapter is a dependency you chose, like any other. But it has one hard
consequence the project must honour:

> The challenge workflow must never load a contributor-supplied policy adapter
> in upstream CI. Scenario contributions are data; adapter contributions are
> code, and they are reviewed by a human before they run anywhere trusted.

`docs/CHALLENGE.md` currently invites both kinds of contribution without
distinguishing them on this axis. That is a gap to close in INT-002.

### Answering the four questions directly

**Can the agent reach the resource without the PEP?** No. Its only channel is
the `AgentTurn` return value, and every tool call in it goes through
`_dispatch`. Complete mediation holds *with respect to the model*.

**Can the policy reach the resource without the PEP?** Yes, trivially, via
ordinary Python introspection. Complete mediation does **not** hold with respect
to policy code.

**Can a tool reach a resource the PEP did not authorise?** Yes in principle —
`execute` receives the live `World` and could touch anything. In practice the
five bundled tools do not, and the tool registry is not contributor-extensible
today. This becomes live the moment a scenario can contribute a tool.

**Which reference-monitor properties are absent?** Using Anderson (1972):
*complete mediation* — **present** against the model, absent against policy and
tool code. *Tamper-proofness* — **absent**; same address space, no memory
protection, no capability discipline. *Verifiability* — **absent**; there is no
independent artefact to verify, only tests the same author wrote.

## 3. What moving only the PDP out of process would fix

| | in-process today | PDP in a subprocess |
|---|---|---|
| model bypasses PEP | already impossible | still impossible (no change) |
| policy mutates world | possible | **prevented** |
| policy patches `_dispatch` | possible | **prevented** |
| policy crash attribution | ambiguous | **clean** |
| policy depends on harness internals | possible, and it will drift | **structurally prevented** by serialization |
| tool reaches unauthorised resource | possible | unchanged |
| enforcement point tamper-proof | no | **still no** |
| verifiability | no | **still no** |

So subprocess isolation of the PDP buys exactly one real security property —
*the policy can no longer tamper with the harness* — plus one significant
engineering property, which is arguably worth more: **serialization as the
interface**. Forcing the policy contract through JSON makes it structurally
impossible for an adapter to depend on harness internals, which is the drift
that turns a clean plugin boundary into a private API within two years. It would
also have caught the tool-aliasing bug the V0 review found by hand.

What it does **not** buy is anything `SIMPL-0001` claims to be about. The
enforcement point stays where it is.

### The cost, corrected

`docs/CEDAR-AND-ISOLATION.md` priced this against a "~20 s" demo. The demo is
**2.35 s** (see `PHASE2_BASELINE.md`). Corrected:

| | cost | as % of the 2.35 s demo |
|---|---|---|
| persistent server (159 ms spawn + 360 × 0.076 ms) | 0.19 s | **8%** |
| spawn per run (18 × 159 ms + round trips) | 2.89 s | **123%** |

Still affordable for the persistent case; the per-run case would more than
double the demo. The earlier document's arithmetic was wrong in the direction
that flattered isolation.

## 4. The architecture that would actually improve complete mediation

Not proposed for Phase II. Recorded so the eventual design is not invented under
deadline.

```
┌──────────────────────────┐        ┌──────────────────────────────────┐
│ UNTRUSTED AGENT PROCESS  │        │ INTERPOSE MEDIATION PROCESS      │
│                          │        │                                  │
│  model client            │  IPC   │  resolve object                  │
│  tool stubs (no impl) ───┼───────▶│  attach provenance               │
│  no World reference      │ action │  consult PDP                     │
│  no tool implementations │ request│  execute authorised tool  ──┐    │
│                          │◀───────┤  emit event                 │    │
└──────────────────────────┘ result └─────────────────────────────┼────┘
                                                                  ▼
                                                              RESOURCE
```

The load-bearing property is that the agent side holds **no tool
implementation and no world handle** — only stubs that marshal a request. Then
"the agent could skip the check" becomes false by construction rather than by
convention, and it stays false for a hostile agent, not merely a compliant one.

**Two reasons not to build it in Phase II.** First, against the current scripted
provider it would measure nothing: the deterministic client does not attack the
harness, so every number would be identical before and after. It becomes worth
building when there is an adversarial *client* to point at it — which is a
different research programme from the one Phase II is running. Second, it is a
large change to the thing every other experiment is measured against, and
changing the instrument while running experiments on it is how a benchmark
loses its history.

## 5. What to change now, without new architecture

1. **Correct `SIMPL-0001`.** It overstates the model's ability to bypass the PEP
   and omits the policy adapter's ability to do so. As written it points a
   reader at the wrong remediation.
2. **State the adapter trust rule in `CHALLENGE.md` and `SECURITY.md`.** Scenario
   contributions are data and can be run automatically; policy adapters are code
   and must never be executed by upstream CI on an unreviewed PR.
3. **Do not ship subprocess isolation as a security claim.** If it ships at all,
   it ships as an interface-hygiene feature with the security delta stated
   exactly as in the table above.
