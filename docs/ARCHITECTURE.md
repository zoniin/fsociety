# Architecture

Seven concepts. Everything else is allowed to change.

```
Scenario ── declares ──> World ──┐
                                 │
   AgentProvider ──proposes──> Runner (the enforcement point) ──asks──> SecurityPolicy
                                 │                                            │
                                 │<─────────── ALLOW / DENY ───────────────────┘
                                 │
                          Tool.execute ──> World state change
                                 │
                                 └──> Event ──> Outcome ──> Result
```

The ordering inside the runner is the whole design:

```
propose -> resolve -> label -> decide -> (execute | block) -> record
```

Deciding before resolving would authorize a *name* instead of an *object*.
Executing before deciding would make the decision an audit note. Recording
after the fact would lose the causal chain that makes the trace worth having.

## The seven

| Concept | Module | Why it is a boundary |
|---|---|---|
| **Scenario** | `scenario/spec.py` | The contributor-facing contract. Data only. |
| **World** | `world/models.py` | Deterministic state; the thing outcomes assert over. |
| **Tool** | `tools/spec.py` | Declares `effect_class` and how arguments resolve to objects. |
| **Policy** | `policy/types.py` | The unit under test. What a vendor would implement. |
| **Provider** | `providers/base.py` | The model boundary. One method. |
| **Event** | `events.py` | The durable artifact. Formats outlive harnesses. |
| **Outcome** | `engine/outcome.py` | Facts, then a verdict — never a score. |

Nothing else is future-proofed. There is no plugin registry (a dict covers
three policies), no event bus, no repository abstraction over storage, no
network topology, and no scenario language with control flow.

## Decisions worth arguing with

### The enforcement point is a single chokepoint

Every tool call goes through `Runner._dispatch`, and no tool receives a world
handle it did not get from there. A tool never checks permissions.

Scattering authorization into tool bodies is how real systems acquire an
incomplete mediation surface — one tool that forgot. It would also make the
policy layer unmeasurable, because a block could no longer be attributed to
the policy rather than to the tool.

This is a policy enforcement point (PEP) with the decision point (PDP) split
out, in the XACML sense. It is **not** a reference monitor: same address space,
not tamper-proof, not independently verifiable. SIMPL-0001.

### Authorization is over the action, not the verb

`decide(principal, action, resource, sink, provenance, history) -> Decision`

The unit of control is a single tool call with its caller identity and input
parameters, evaluated at invocation. That shape is borrowed rather than
invented — it is what AWS AgentCore Policy, Cedar, and the out-of-band defense
literature already use. A novel abstraction here would be simultaneously
un-adoptable and pedagogically misleading: you would learn our invention
instead of the industry model.

Tools therefore declare `effect_class` (`read` / `write` / `irreversible`) and
a `resolve` function that maps arguments to the object and sink a call *would*
touch, **before** it runs. That pre-resolution is what makes object-level
authorization possible at all.

### The policy interface is synchronous

A batch regression harness has no concurrency requirement, and a network-bound
adapter can block. Adding `async` to every call site to serve a need that does
not exist buys complexity and no capability. There is exactly one call site
(`policy.base.evaluate`), so if a future adapter needs concurrency, that is the
only thing that changes.

### `ALLOW` and `DENY` only

Real defenses also redact, downscope, quarantine and escalate. Shipping
`ALLOW_WITH_TRANSFORM` and `ESCALATE` in V0 would be interface theatre: there
is no consumer for them and no scorer that could grade them. The `Decision`
wire format is versioned and additive, so they arrive later without breaking a
published result.

### Scenarios are data; policy adapters are code

The asymmetry is deliberate and it is the central trust decision.

Scenario content **circulates** — obtained from strangers, designed to
manipulate, shipped as fixtures. It is data, with no code path, ever. A policy
adapter is a **dependency you chose**, installed like any package and named on
the command line. Running one is running its author's code, with exactly the
trust that implies. Collapsing those into one rule is how a benchmark becomes a
malware distribution channel with a security-research veneer.

Full reasoning in [`THREAT_MODEL.md`](THREAT_MODEL.md).

### The policy never learns which trial it is in

The bright line: *a policy may receive anything the harness could compute at
runtime in a real deployment without knowing the answer key, and nothing
derived from the scenario definition.*

It is given identity, delegation, resource classification, sink readership,
both provenance views, and the episode's decision history — because starving it
would rig the comparison against sophisticated defenses that need labels.

It is never given the adversary objective, the outcome predicate, the seed, the
scorer, any flag that content "is the injection" (the trust class says
`untrusted_external`, never `malicious`), or **whether this run is the benign
control or the attack**.

Enforced structurally: `_context()` holds no reference to the attack section,
`policy/` imports nothing from `scenario/`, and
`tests/test_fairness_and_cli.py` asserts both — plus that the decision stream
is identical between benign and attack runs up to the point the corpus differs.

### Two provenance views, bracketing the truth

Tool *results* carry real labels that join on combination. Tool *arguments* are
free text the model wrote, so provenance is reconstructed by matching.

`value_provenance` under-approximates (paraphrase escapes it).
`context_provenance` over-approximates (reading a document taints everything
after). A policy picks its point on that tradeoff, and the choice shows up in
its false-deny rate — which is exactly the property worth measuring. SIMPL-0002.

### Determinism, and what breaks it first

Ranked by how fast each bites:

1. **The model.** Hence a first-class scripted provider.
2. **Iteration order.** Explicit sort keys with URI tie-breaks everywhere;
   never dict order.
3. **Time.** No `datetime.now()` in any run path. `t_ms` is a fake clock, one
   tick per event. Wall clock appears once, in `result.json`, excluded from
   every digest.
4. **Identifiers.** No `uuid4`. Seeded counters; the run id is a hash of the
   run's inputs, so equal inputs give an equal id.
5. **Floats.** Integer keyword scoring in search; no float relevance drift.
6. **Text and paths.** POSIX-style URIs, explicit UTF-8, newlines normalised on
   ingest, and digests computed over normalised bytes so a Windows checkout and
   a Linux runner agree.

### Reset is rebuild

`build_world(fixtures)` is pure and constructs ~30 objects in microseconds.
Copy-on-write and snapshot layers would be unjustified machinery at this size.
`world.digest()` is asserted before and after every run; the diff between the
two is the security-relevant state change.

## Toolchain

Runtime dependencies are `pydantic` and `PyYAML`. That is the whole list.

- **argparse, not a CLI framework.** A CLI library would pull a colour renderer
  and its transitive tree to save perhaps eighty lines. For a security tool
  whose install one-liner is the product, a small dependency graph is a feature
  and a smaller attack surface.
- **pydantic** for the artifact and scenario schemas, because strict validation
  with `extra="forbid"` at the serialization boundary is load-bearing here.
- **ruff** and **mypy** in CI. `hatchling` to build. `pytest`, no `make` and no
  `tox` — one documented command, and `make` is a tax on a Windows maintainer's
  own machine.

## Where a second scenario would strain this

Named honestly, because the data-only format is only proven by having a second
user:

- **New tool behaviour is a core pull request.** By design, but it is also the
  maintainer bottleneck.
- **The scripted provider is generic but shallow.** It searches, reads what it
  finds, optionally reads a path the task names, and optionally files a ticket.
  A scenario whose legitimate task has a different *shape* needs a new
  behaviour class — which is core code.
- **`ScenarioSpec.attack` is singular.** A scenario with two attack paths, or
  an attack spanning episodes, needs a schema change and a `spec_version` bump.
