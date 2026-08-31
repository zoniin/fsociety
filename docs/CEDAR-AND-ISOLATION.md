# Two explorations: Cedar, and out-of-process enforcement

> **CORRECTION NOTICE — Phase II, 2026-08-31.** Four claims below are wrong and
> are left in place rather than deleted, per the project's own rule about not
> shrinking a findings list by editing. See
> [`research/agents/authorization.md`](research/agents/authorization.md) and
> [`research/PHASE2_BASELINE.md`](research/PHASE2_BASELINE.md).
>
> 1. **§1 "attempt 2" is wrong, not merely partial.**
>    `!context.source.readers.containsAll(resource.readers)` denies every write
>    carrying a source that has *no* explicit reader allowlist — which is 26 of
>    29 objects across both worlds, including a public document into a public
>    queue. It is wrong on 3 of 6 real cases. The five cases shown below all
>    happen to have explicit reader sets, which is why the error is invisible
>    here. The corpus does not catch it either: 0 of 40 evaluated pairs involve
>    an empty allowlist.
> 2. **"The gap is arity" is the wrong framing.** Cedar *can* universally
>    quantify over one collection when it sits on the resource or principal side
>    of a `containsAll`. What it cannot do is iterate a **request-scoped** set,
>    at any arity. A correct one-request-per-source form exists that handles both
>    branches of `entitled_to` by modelling the classification lattice as an
>    entity hierarchy.
> 3. **Omitted: Cedar fails open.** A `forbid` whose condition errors is
>    silently skipped. Misspell or omit the provenance key and the egress rule
>    becomes a no-op returning `Allow`. A `has` guard covers some cases; a Cedar
>    **schema** covers all of them by returning `NoDecision`. Any adapter
>    contract must require the schema.
> 4. **§2's cost figures are scaled against a wrong number.** The demo is
>    **2.35 s**, not the "~20 s" stated — that figure was the pytest suite time
>    used as a proxy. A persistent out-of-process PDP costs **8%** of the demo,
>    not 1%; spawn-per-run would **more than double** it.
>
> The document's *recommendation* — Cedar before isolation — survives all four,
> and is strengthened by the first three.

Neither of these is built. Both are the next two roadmap items, and both had an
open question that made estimating them impossible. This document answers those
questions with measurements rather than reasoning, and ends with a
recommendation about order.

Everything below was run on Windows 11 / CPython 3.13 against `cedarpy` 4.8.7.
The probes are reproducible by copy-paste; nothing here depends on a service.

---

## 1. Cedar

### The question the roadmap said had to be answered first

> Cedar has no taint or information-flow primitive, so it may not be able to
> express the R3 egress rule at all. If it cannot, that is itself a publishable
> finding about the gap between deployed authorization engines and what agent
> security needs.

The short answer: **it can, but not the way R3 is written, and the shape of the
gap is more interesting than a yes or no.**

### Installability — no build step survives

`uv pip install cedarpy` pulls a prebuilt wheel. No Rust toolchain, no compiler,
no `cargo`. This matters more than it sounds: "two runtime deps, `pip install
-e .`, works in CI in twelve seconds" is currently the project's strongest
adoption property, and an adapter that required a toolchain would cost it.

Verified on Windows. CI would have to confirm the Linux and macOS wheels, which
is a five-minute check, not a risk.

The adapter would still be an extra — `pip install interpose[cedar]` — because
the default path must stay at two dependencies.

### R1 and R2 map directly

Cedar is a natural fit for the two rules that are ordinary authorization:

```cedar
permit(principal, action == Action::"read", resource)
when { resource.readers.contains(principal) };
```

```text
R2  entitled reader reads confidential file      Allow
R2  unentitled reader reads the same file        Deny
```

Nothing surprising. This is what Cedar is for.

### R3, attempt 1: say it directly — Cedar refuses

R3 is a nested quantification: *for every tainted source, for every reader of
the sink, that reader must be entitled to that source.* Written as it reads:

```cedar
forbid(principal, action == Action::"write", resource)
when {
  context.tainted.any(src ||
    resource.readers.any(rdr || !src.readers.contains(rdr)))
};
```

```text
policy parse errors:
invalid variable: rdr
```

Cedar has no lambda and no general quantifier. That is a deliberate design
choice — it is what keeps Cedar decidable and amenable to the symbolic analysis
that is arguably its main selling point — but it means an information-flow rule
cannot be stated in one policy.

### R3, attempt 2: one source per request — works

Flatten the outer quantifier out of the policy and into the caller. Cedar
handles the inner one with an ordinary set operation:

```cedar
forbid(principal, action == Action::"write", resource)
when { !context.source.readers.containsAll(resource.readers) };
```

The PEP issues one authorization request per tainted source and denies if any
denies. All five cases behave correctly, including the empty case:

```text
sources=['prices']         sink=vendor   allow=True   want=True    ok
sources=['pm']             sink=vendor   allow=False  want=False   ok
sources=['prices', 'pm']   sink=vendor   allow=False  want=False   ok
sources=['prices', 'pm']   sink=ops      allow=True   want=True    ok
sources=[]                 sink=vendor   allow=True   want=True    ok

per-decision latency: 0.432 ms
```

At 0.43 ms and roughly 20 decisions per run, a Cedar adapter adds well under a
second to a full `demo`. Latency is not a constraint.

### R3, attempt 3: let the PEP precompute — the line not to cross

```cedar
forbid(principal, action == Action::"write", resource)
when { context.unentitled != [] };
```

This works, and it is worthless. The harness computed `unentitled_readers` and
Cedar rendered an opinion about whether a list was empty. Any adapter can be
made to "support" any rule this way, so an adapter that does this is measuring
the harness, not the engine.

The distinction is easy to state and worth stating in the adapter contract:
**the PEP may decompose a question; it may not answer one.** Attempt 2
decomposes — Cedar still decides each entitlement comparison against entity
attributes it reads itself. Attempt 3 answers.

### The finding

The gap between Cedar and information flow is not expressiveness. It is
**arity**.

Cedar can decide *"may data from this one source reach this sink?"* It cannot
decide *"may data from this set of sources reach this sink?"* in a single
request, because that requires quantifying over a set, and quantification is
what Cedar gave up to get analyzability.

The consequence is where this stops being a Cedar trivia note. Decomposition
means the caller must hold the taint set and iterate. So in any Cedar-based
authorization gateway — AWS AgentCore Policy is the deployed instance of exactly
this shape — **the policy engine is authorizing actions, and something upstream
of it is authorizing flows.** If nothing upstream computes provenance, the
gateway is not doing information-flow control at all, however the rules are
written. That is a checkable claim about a shipping product category, and it is
the kind of finding this project exists to produce.

There is also a quiet piece of good news: expressing this needed **no change to
the `SecurityPolicy` interface**. `evaluate(ctx) -> Decision` already hands the
adapter the full provenance view, and the adapter loops internally. The
interface survived first contact with a real external engine — which is the
claim the "policy adapters" milestone was supposed to test, and it now has some
evidence before the work starts rather than after.

### What a Cedar adapter should and should not claim

- **Can claim:** a real, externally-maintained engine sits on the frontier and
  is measured by the same benign suite as everything else.
- **Cannot claim:** that Cedar "supports information flow". It supports the
  decomposed per-source question. Say which.
- **Must publish:** the decomposition, in the adapter's docstring, because a
  reader comparing Cedar's row to the reference row needs to know the PEP is
  doing more work in one than the other.

---

## 2. Out-of-process enforcement

### What it costs

A JSON-over-pipe policy server, benchmarked on this machine:

```text
cold start (spawn + first decision) :   159.2 ms   [once per server]
steady-state round trip            :     0.076 ms  [per decision]

a full `interpose demo` ~= 360 decisions across 18 runs
  persistent server, one spawn     :   0.19 s added
  spawn per run (clean isolation)  :   2.89 s added
  current demo wall clock          : ~20 s
```

A persistent server is free — 1% on the demo. Spawning per run, which is the
version that gives each run a clean policy process, costs 15%. Both are
affordable. **Latency is not the reason this has not been built.**

### What it buys

- **Memory isolation.** A policy adapter cannot reach into the runner, patch
  `_dispatch`, or mutate the world. Today it could; nothing stops it but
  convention.
- **Crash containment.** A policy that segfaults or hangs becomes a harness
  error with a clear attribution, instead of an ambiguous failure.
- **Serialization as the interface.** This is the underrated one. Forcing the
  policy contract through JSON makes it structurally impossible for an adapter
  to depend on harness internals, which is exactly the drift that turns a clean
  plugin interface into a private API over two years. It would also have caught
  the tool-aliasing bug the V0 review found.

### What it does not buy

It does not fix SIMPL-0001, and that is the important part.

SIMPL-0001 says the decision point "lives in the same address space as the thing
it mediates". The thing it mediates is the **agent**, and the enforcement point
is `Runner._dispatch` — which stays in the harness process no matter where the
*decision* is made. Moving the PDP out separates the policy from the runner. It
does not separate the runner from the agent.

So an honest changelog entry for subprocess isolation would read: *the policy
can no longer tamper with the harness.* It would not read: *the enforcement
point is now tamper-proof.* Anderson's second property still fails, and the
containment numbers stay optimistic by the same unmeasured amount.

Getting the *other* separation — the one SIMPL-0001 is actually about — means
the agent runs as the subprocess and the tools live in the parent. That is the
"out-of-process mediation" milestone, it is a much larger change, and against
the current scripted provider it would measure nothing, because the scripted
client does not attack the harness. It becomes worth building when there is an
adversarial client to point at it.

### What real isolation would cost

Beyond a process boundary, restricting what the policy process can *do* needs
OS-specific code:

| Platform | Mechanism | Stdlib support |
|---|---|---|
| Linux | seccomp-bpf via `prctl` | none — `ctypes` |
| Linux | user namespaces / `unshare` | none |
| Windows | Job Objects, AppContainer | none |
| macOS | `sandbox_init` | none, and deprecated |

Every row is either a new dependency or a `ctypes` binding to maintain across
three platforms, and any of them breaks "clone, `pip install -e .`, run". A
container gets all of it for free and breaks the same property harder.

The proportionate version is: **subprocess isolation as an opt-in flag**
(`--policy-isolation subprocess`), persistent server, default off, no OS-specific
code, and no claim that it makes anything a reference monitor.

---

## 3. Recommendation

**Cedar first. Then subprocess isolation, narrowly scoped. Then reassess.**

Three reasons, in order of weight:

1. **Cedar produces a finding; isolation produces a property.** The arity result
   above is a statement about a category of shipping product, and it gets
   sharper with a working adapter and a frontier row. Subprocess isolation
   produces a real but modest engineering improvement that does not move any
   published number and does not fix the simplification it appears to.

2. **Sequencing.** Cedar tells us whether the adapter interface survives contact
   with an external engine. The probes above say it does, but a working adapter
   is the real test. Building process isolation *around* an interface, and then
   discovering the interface has to change, is the expensive order.

3. **Isolation's value is mostly latent.** Its best property — serialization as
   the trust boundary — only pays off once there are third-party adapters to
   keep honest. Cedar would be the first one. That is another argument for the
   same order.

The one thing worth doing immediately, because it is cheap and it is the actual
bug risk today: the adapter contract should say in writing that a PEP may
decompose a question but may not answer one. That rule is what stops the next
adapter from being attempt 3 with better marketing.

### Not doing yet, deliberately

Simulated mail servers, SIEMs, Windows domains, adversarial bot fleets. Every
one of them adds surface without adding a measurement, and the corpus is two
scenarios deep. The binding constraint on this project is scenarios that
discriminate between policies and a third party willing to attack the frozen
one — not more world.

---

## Reproducing

```bash
uv pip install cedarpy    # 4.8.7, prebuilt wheel, no toolchain
```

Then the three attempts, in order, from §1. The full probe is short enough to
retype; the numbers above came from 2000-iteration loops for Cedar latency and
3000 for the pipe round trip. `cedarpy` is deliberately **not** a project
dependency and is not installed by `pip install -e ".[dev]"` — the exploration
used it transiently and the environment was restored afterwards.
