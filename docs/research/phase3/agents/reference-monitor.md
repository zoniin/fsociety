# Reference-monitor evaluation of Phase III

**Agent B — reference monitor and classical security principles.**
Against HEAD `55721a2`, post-INT-000, 168 tests, clean tree.

The amendment changes who is being mediated, so it changes almost every
verdict. Two claims run in opposite directions and both need to be said in the
same document: **the project has been under-claiming on the model axis and
over-claiming on the policy axis.** Correcting only one of those is worse than
correcting neither, because it converts an honest caveat into a marketing
sentence.

Nothing below awards a property for a change of PID.

---

## 0. What was measured, not reasoned

One probe, because the whole policy axis turns on it. A `SecurityPolicy` whose
`evaluate` walks its own call stack:

```text
REACHABLE_VIA_FRAMES {"runner_frame": 1, "log_frame": 1, "world_frame": 1}
```

Frame depth 1 above `interpose.policy.base.evaluate` is `Runner._dispatch`,
whose locals are `self` (the `Runner`), `world` (the live `World`), and `log`
(the `EventLog`). One `sys._getframe` hop from adapter code to every object the
harness owns. That is not an inference about CPython; it is this repository, on
this commit, in a run that completed and printed a verdict.

Everything in the "policy code" column below follows from that measurement plus
`load_policy` (`src/interpose/policy/base.py:85-107`), which calls
`importlib.import_module` on a user-supplied dotted path — arbitrary code
execution at *import*, before `evaluate` is ever reached.

---

## 1. The property table

Three subjects.

- **V0** — the shipped in-process design as it stood at `docs/V0_REVIEW.md`.
- **CURRENT** — HEAD `55721a2`, post-INT-000.
- **PROPOSED** — PDP in a worker process, JSON over a pipe, persistent server,
  `Runner._dispatch` / `World` / tools all remaining in the harness parent.

Where the answer depends on which subject is being mediated, the cell says so.
Anderson (1972) supplies rows 1–5 and 13; Saltzer & Schroeder (1975) supply
6–12.

| # | Property | V0 | CURRENT (post-INT-000) | PROPOSED (policy worker) |
|---|---|---|---|---|
| 1 | Complete mediation — **model** | **yes** — `provider.respond()` returns an `AgentTurn` dataclass (`providers/base.py:62-70`); every `ProposedCall` reaches `tool.execute` only via `_dispatch` | **yes** — unchanged, and now `resolve` precedes `evaluate` (`runner.py:310`, `343`), so the object is authorized rather than the name | **yes, no delta** — the worker moves the decision, not the enforcement point |
| 2 | Complete mediation — **policy code** | **no** — adapter is in-process Python with ambient authority | **no** — measured above: `world`, `Runner`, `EventLog` one frame up; and `build_registry().get(t).execute(world=…)` runs a tool with no decision, no `ToolProposed`, no `ToolExecuted` | **yes for harness objects** — `World` never crosses the pipe, so the frame walk has nothing to find. **No for the host**: same UID, inherited env, filesystem, sockets |
| 3 | Complete mediation — **tool code** | **no** — `ExecuteFn` receives the live `World` (`tools/spec.py:72-79`) and may touch any object the decision did not name | **no** — unchanged. Held closed by the fixed five-tool registry and `ToolRegistry` being non-extensible from scenario content (`tools/spec.py:104-127`). That is convention, not construction | **no, untouched** — this is the axis a policy worker does not reach at all |
| 4 | Mediator isolated | **model: yes, vacuously** — the model has no execution domain in this process. **policy: no** | **model: yes, vacuously. policy: no** — nothing in INT-000 changed address-space structure | **model: unchanged. policy: partial** — an OS process boundary, *not* a sandbox: same user, no seccomp / Job Object / AppContainer, all of which `CEDAR-AND-ISOLATION.md` §2 prices at the cost of the no-build-step install |
| 5 | Mediator tamper-resistant | **no** — `_dispatch` is a patchable class attribute, `policy.base.evaluate` a module global, `EventLog._events` a plain list (SIMPL-0004) | **no** — unchanged, and compounded: the *record* of mediation is as mutable as the mediation. A hostile adapter can pop `ToolExecuted` and `DetectorTriggered` rows before the artifact is written | **partial** — the adapter can no longer patch `_dispatch` or rewrite the log. The mediator is still not tamper-proof against anything else in the harness process (T2, tool code), and the parent accepts the child's verdict with no attestation |
| 6 | Resource bypass prevented | **model: yes. policy: no. tool: no** | **model: yes. policy: no. tool: no** | **model: yes. policy: yes. tool: no** |
| 7 | Decision fail-closed | **partial** — executes only on `decision.allowed`; a raising policy takes the run down rather than denying | **yes at the harness boundary** — `evaluate()` type-checks the return and refuses anything that is not a `Decision` (`policy/base.py:78-82`), so junk cannot be misread as ALLOW; `_dispatch` executes only on `allowed`. **But** an adapter can still fail open *beneath* it: a Cedar `forbid` whose condition errors is silently skipped (`CEDAR-AND-ISOLATION.md` correction #3) | **regression risk — the hardest thing in the design.** A worker adds five failure modes a function call does not have: crash, hang, EOF, unparseable frame, unknown `effect`. Each needs an explicit default and the default must be DENY. A worker that reads "no response" as anything but deny is *strictly worse* than the call it replaced |
| 8 | Economy of mechanism | **yes** — one `_dispatch`, holdable in one reading | **yes, weakening** — `_dispatch` is ~115 of `runner.py`'s 685 lines and carries six responsibilities (resolve, label, decide, execute, ingest, record). The harder thing to reason about is now `outcome.py::_verdict`, which has accreted retraction-driven special cases (R8, R9) | **no** — adds a process lifecycle, a wire schema, its versioning, a marshal/unmarshal pair, and five error-path semantics, to buy one property. This is the S&S tax, paid knowingly |
| 9 | Least privilege — policy adapters | **no** — ambient authority over the whole process | **partial, and the *design* is right while the *effect* is not.** `DecisionContext` is a well-formed capability: frozen views, no `World` handle, structurally unable to carry the answer key (`policy/types.py` imports nothing from `interpose.scenario`, asserted by test). That is the nominal authority. The effective authority is the whole process, because nothing revokes ambient authority — Miller's exact point: handing a capability does not subtract authority in a language that grants it by default | **partial → yes for harness state; no for the host by default.** The JSON boundary makes `DecisionContext` the *effective* authority over harness objects for the first time. The child still inherits `ANTHROPIC_API_KEY`, cwd, `~/.ssh`, and network. **The worker spawn must scrub the environment** — cheap, portable, no OS-specific code, and the single change that makes the worker more than interface hygiene |
| 10 | Least common mechanism | **no** — one heap, one `sys.modules`, one GC graph | **no** — and note the sharp case: `policy_digest`'s `_import_closure_sources` (`policy/base.py:132-170`) walks `sys.modules` to compute an integrity value. The anti-drift mechanism is itself built on the shared namespace it exists to police, and any adapter can bypass it by defining `digest()` (SIMPL-0007) | **yes — and this row, not tamper-proofness, is what the worker actually buys.** Separate interpreter, separate module table, separate heap. "Serialization as the interface" is least common mechanism enforced structurally instead of by convention |
| 11 | Separation of privilege | **no** — one policy decides; the grader and the policy shared both the entitlement relation (R5) and the content-matching failure mode (R1/R2) | **partial — a real CURRENT-only gain the project under-claims.** Containment now needs three semi-independent concurrences: a policy denial (`outcome.py:352` — `CONTAINED` requires `denials > 0`, R8), the canary detector, and `_observe_possible_exposure` (`runner.py:566-623`), which never reads content and so cannot fail the same way. That is separation of privilege in the *grading* path. It is absent from the *authorization* path: still one decider, and R5 (`readable_by` / `entitled_to` agree 116/116) means detection independence was fixed while entitlement independence was not | **unchanged** — a worker adds no second decider. The variant that would earn this row is *n*-of-*m* adapters concurring, which the worker protocol makes nearly free and which nobody has proposed |
| 12 | Psychological acceptability | **yes** — two runtime deps, `pip install -e .`, no build step | **yes** — explicitly the project's strongest adoption property | **partial** — 8% of the 2.35 s demo persistent, 123% spawning per run. Survivable as an opt-in flag, default off. Any *actual* sandboxing breaks the no-build-step install on all three platforms |
| 13 | Verifiability | **no** — the digest hashed one file, so gutting R3 via `types.py` left `freeze --check` printing FREEZE INTACT (R6) | **partial — under-claimed.** The digest now covers the transitive first-party import closure, closing R6; `freeze --check` runs in CI; `verify` reproduces an artifact and prints AGREES; run ids bind scenario + policy + digest. **Reproducible by anyone: yes. Verifiable in Anderson's sense: no** — everything is attested by the party the mechanism constrains (SIMPL-0014), the digest is source not behaviour and the adapter may override it (SIMPL-0007), and no third party has run a challenge | **no change to the property, one enabling gain.** If the wire format is the interface, the `(DecisionContext → Decision)` stream becomes an independently checkable artifact replayable against a different adapter build without the harness. That is the second-best reason to build it |

### The table's verdict in one line

Of thirteen rows the worker moves three — 2 (policy axis), 6 (policy axis), and
10 — improves 4, 5, 9 and 13 to *partial*, degrades 8 and 12, and puts row 7 at
risk. It does not touch rows 1, 3 or 11. **The honest headline is least common
mechanism, not tamper-proofness.**

---

## 2. Splitting SIMPL-0001

`SIMPL-0001` is imprecise in both directions. Four sub-items, and the disposal
of each is different. The proposed shape is kept and sharpened.

### SIMPL-0001A — agent/model and enforcement share an address space

**Verdict: false as stated. Retire it; do not re-scope it.**

Is it "even true in the sense that matters"? No, and not in any weaker sense
either. The model has no address space in this system. `provider.respond()`
returns an `AgentTurn`; `providers/base.py` gives a provider no `World` handle
and no tool implementations; `_dispatch` is the sole path to `tool.execute`.
Data cannot skip a function call, so complete mediation w.r.t. the model is not
merely tested — it is structural.

This is **the sub-item that is already closed and mis-documented.** The register
currently claims a weakness the architecture does not have, and — worse for a
document whose job is to bias-correct — claims it as *optimistic*, when the
error on this axis is pessimistic.

There is an honest residue, but it is a different item and deserves a different
id:

> **SIMPL-0001A′ (replacement).** Complete mediation w.r.t. the model holds
> because every shipped provider is first-party. `cli.py::_provider_factory`
> (lines 90-107) hard-codes an allowlist of `scripted` and `anthropic` and
> raises on anything else — there is **no** `load_provider("dotted.path")`. So
> the door that would open T3 is closed by code. It is **not pinned by a test**,
> unlike the "no target parameter" invariant. Adding a dotted-path provider
> loader would convert row 1 from structural to conventional in a single commit,
> and should be treated as a one-way door in the same class as
> scenarios-as-code.

### SIMPL-0001B — policy adapter code and enforcement share an address space

**Verdict: true, live, and the only sub-item a policy worker closes.**

Two distinct exposures, and remediations differ:

- *Import time.* `load_policy` imports an arbitrary module. Code runs before
  `evaluate` is called, before any `DecisionContext` exists, with no audit hook
  installed anywhere in the default path.
- *Evaluate time.* The frame walk measured in §0.

A worker closes B **for harness state** (`World`, `EventLog`, `Runner`) and
**does not** close it for host state. State it that way in the changelog or the
entry becomes the dishonest green check.

### SIMPL-0001C — no OS-level anti-tamper guarantee; same OS user throughout

**Verdict: true, and a policy worker does not close it.** A child process under
the same UID with an inherited environment is not a protection domain against
an adapter whose goal is `ANTHROPIC_API_KEY` or `~/.ssh` — the two assets
`THREAT_MODEL.md` ranks first. `CEDAR-AND-ISOLATION.md` §2 already prices the
real mechanisms (seccomp-bpf, user namespaces, Job Objects, `sandbox_init`) and
shows every row is either a new dependency or a `ctypes` binding across three
platforms.

C must stay open, and must be named explicitly in the worker's own
documentation. **Never call the worker a sandbox.** Environment scrubbing at
spawn narrows C measurably without touching the install story, and is the
recommended partial mitigation.

### SIMPL-0001D — complete mediation is tested over modeled tools, not proven over arbitrary Python

**Verdict: true, and a policy worker does not close it — it only shrinks its
scope.** Once the adapter cannot reach the `World`, D reduces to the tool-code
axis (row 3), which is untouched by anything proposed. `ExecuteFn` receives the
live `World`; only the fixed registry keeps that honest. `THREAT_MODEL.md`'s own
container trigger #1 — a tool that executes code — is the moment convention
stops being enough, and it is the correct trigger for D rather than a worker.

### Disposal map

| Sub-item | Status | Closed by a policy worker? |
|---|---|---|
| **A** | already closed, mis-documented — **retract** | n/a (nothing to close) |
| **A′** | closed by code, unpinned by test — **document + pin** | no |
| **B** | **live** | **yes, for harness state only** |
| **C** | open | **no** — partially narrowed by env scrubbing |
| **D** | open | **no** — scope shrinks, nothing is proven |

---

## 3. The nine amendment questions

**1. Is process-separating the agent materially useful against T1?**
No. T1 is already fully mediated and there is nothing to separate: the agent is
a remote service plus a dataclass. Against a hostile *provider* (T3) it would
matter, but that extension point does not exist (A′).

**2. What exact property would it add?**
Exactly one, conditionally: complete mediation w.r.t. the model would hold *by
construction* rather than by the type of `AgentTurn` plus an allowlist in
`_provider_factory`. It adds no tamper-proofness and no verifiability. It is
worth precisely the price of the extension point it protects, and that
extension point is currently closed.

**3. Is it relevant to any shipped scenario?**
No. All three scenarios run under `ScriptedProvider` behaviour classes or
`AnthropicProvider`; none attacks the harness, and SIMPL-0011 says the scripted
client "is not a model and resembles none." Every number would be byte-identical
before and after. A change that cannot move a measurement is not a Phase III
finding — and it rewrites the path every published number crosses, which is how
a benchmark loses its history.

**4. Does policy loading create a more immediate problem?**
Yes, and it is the only live one — but the sharp edge is not where the docs put
it. The user-facing story ("an adapter is a dependency you chose, named on a
command line") is sound. It is silently wrong in exactly one place: **the
challenge workflow**, the project's only mechanism for producing evidence it did
not manufacture. `cmd_challenge` (`cli.py:447`) passes `args.policy` straight
into `load_policy`, so `interpose challenge --policy stranger.module:Evil` is
arbitrary code execution on whoever runs it. Three remediations, none
architectural, all cheap:

- (a) `CHALLENGE.md` must separate data contributions from code contributions on
  this axis. `ENFORCEMENT_BOUNDARY.md` §2 already says so; it is unclosed.
- (b) Upstream CI must never load a contributor adapter. Today `ci.yml` names
  only builtin shorts, but nothing enforces it — pin it with a test asserting
  every `--policy` argument in the workflow is a key of `BUILTIN_POLICIES`.
- (c) **`challenge` should refuse a non-builtin `--policy`.** The challenge
  target is by definition a frozen first-party policy; a non-builtin already
  yields `freeze_status = "unfrozen"`, so the result is meaningless anyway.
  Refusing it costs nothing and removes an ACE vector from the one command the
  project asks strangers to run.

**5. First boundary: agent↔broker, harness↔policy worker, or both?**
**Harness ↔ policy worker, and only that.** Ranked by (property gained ×
liveness of the threat) ÷ (cost + risk to the instrument): the agent broker
scores a property against a threat with no shipped instance while rewriting the
measured path; the policy worker gains least common mechanism plus a real
least-privilege win on the one live threat, across a boundary no published
number crosses — the decision is the same decision on either side of the pipe.

**6. Can third-party policies be evaluated without importing their code?**
Not in-process; that is what "adapter" means in Python. But the useful question
is *without importing it into the harness process*, and there are three answers:

1. **Worker process.** Arbitrary Python preserved, but a stranger's code still
   runs as the user. A boundary against the harness, not against the host.
2. **Recorded-context replay — the one the project should notice.** A policy is
   a function from `DecisionContext` to `Decision`, and a function can be
   submitted as its *graph over a corpus*. The corpus already exists: the Cedar
   ablation compared 227 recorded decision contexts. A challenger runs their
   adapter in *their* process against a published context stream and submits a
   `(context_digest → Decision)` mapping; the harness verifies the mapping and
   re-derives every outcome having executed nothing. **This makes the challenge
   workflow safe with no new architecture and no new process.** Its limit is
   statefulness — a history-dependent adapter needs the stream in order, which
   is the same snapshot/restore problem as SIMPL-0005.
3. **Declarative adapter** (architecture E): no import at all.

**7. Which facts must a policy receive?**
Exactly what `DecisionContext` carries today. The set is well chosen and I would
change nothing but its serializability: step index; principal (id, kind,
clearance, roles, granted tools, and `on_behalf_of` plus its clearance — the
confused-deputy axis, Hardy 1988, which `PrincipalView` names explicitly and
which a policy ignoring it will pass the shipped scenarios while failing the
unbuilt cross-principal one); action (tool, arguments, `effect_class`);
provenance as both bracketing views with each source's trust, classification and
readers; the resolved resource when one exists; the sink with its **full
individual readership**, never an aggregate — two earlier aggregate designs each
hid a bug, per `SinkView`'s docstring; decision history; and the user task
verbatim. Every item satisfies the stated bright line: computable at runtime in
a real deployment without the answer key.

**8. Which must it never be authoritative for?**
Three tiers, and only the first is currently enforced.

- *Never received* (fairness — **enforced**): adversary objective, target action
  signature, outcome predicate, seed, scorer, any "this is the injection" flag,
  and above all whether the trial is benign or attack. Structural
  (`policy/types.py` imports nothing from `interpose.scenario`) and tested.
- *Never authoritative for* (integrity — **not enforced**): the outcome. A
  policy must not write the event log, set a verdict, mutate the `World`, alter
  provenance labels, or influence the grader. It can currently do all five. Under
  a worker it can do none — *provided* the parent treats the returned `Decision`
  as untrusted data: parse `effect` against the closed alphabet, map anything
  unknown to DENY, and treat adapter-authored strings as hostile. Concretely:
  **`decision.reason` and `decision.rule_id` are emitted unscrubbed**
  (`runner.py:344-353`, `366-371`) and `reason` is printed verbatim to a terminal
  at `report/render.py:343`. `events.py::scrub` is applied to model- and
  scenario-authored text and *not* to policy-authored text, on the assumption
  the policy is trusted — the assumption the amendment retires. That is CWE-117
  and an ANSI-repaint vector, and it is a two-line fix independent of any
  architecture.
- *Never authoritative for* (semantics — **not enforced, and no worker fixes
  it**): entitlement ground truth. `Resource.readable_by` is the oracle,
  `ReaderView.entitled_to` the policy's copy, and they agree 116/116 (R5).

**9. What can a malicious policy currently do?**
Principled derivation from the §0 measurement — flagged for the agent doing this
empirically, so a reasoned claim and a demonstrated one stay distinguishable.

*Derivable:*

- **Falsify the result.** Empty `Runner.context_sources` and
  `_observe_possible_exposure` never fires; delete canary-bearing tickets and
  `_run_detectors` finds nothing. One adapter defeats **both** observers — so the
  separation-of-privilege gain in row 11 is void against a hostile adapter, which
  is worth saying out loud next to the gain.
- **Rewrite history.** `EventLog._events` is a plain list (SIMPL-0004) and the
  artifact is written from it. Pop or forge rows at will.
- **Bypass enforcement literally.**
  `build_registry().get("create_ticket").execute(world=world, …)` from inside
  `evaluate` — world state changes with no `ToolProposed`, no decision, no
  `ToolExecuted`.
- **Persist across runs.** `run_trial` executes many runs in one process, so
  monkey-patching `Runner._dispatch` or `policy.base.evaluate` lets the attack
  run poison the benign suite that is supposed to be its control.
- **Forge its own integrity.** Define `digest()` returning the frozen hash
  (`policy/base.py:123-125`, SIMPL-0007) and both `freeze --check` and
  `evaluate_challenge` report intact/MATCHES for code that is not the frozen
  code. **The freeze protocol is enforced by a method the adapter implements.**
- **Reach the host**, at import and at evaluate: environment, `~/.ssh`,
  `~/.aws`, sockets. No audit hook exists in the default path.

*What I want tested empirically, in priority order:*

1. `digest()` override → does `freeze --check` print FREEZE INTACT and
   `challenge` print MATCHES? (Highest value: it invalidates the anti-circularity
   argument, not just a number.)
2. Log mutation surviving into `write_run_artifacts`, then `verify` printing
   AGREES on the forged artifact.
3. Tool execution from inside `evaluate`: world changed, no `tool.executed` event
   — does anything notice?
4. Cross-run persistence inside one `run_trial`.
5. `reason`/`rule_id` injection into JSONL and into the rendered report (CWE-117
   / ANSI).
6. Fail-closed behaviour for an adapter that raises, hangs, or returns a
   non-`Decision`.
7. Import-time egress from an adapter module.

---

## 4. Architecture scores

Scored on property gained against the *amended* threat set, cost to the
instrument, effort, and honesty risk — how easily the change gets over-claimed.

| | Architecture | Property gained | Cost to instrument | Honesty risk | Score |
|---|---|---|---|---|---|
| **A** | no new boundary | none | none | **high** — leaves SIMPL-0001 mis-stated in both directions and `challenge --policy` an ACE vector | **conditionally acceptable** |
| **B** | policies only | rows 2, 6, 10; partial 4, 5, 9, 13 | 8% of demo, persistent, opt-in; economy of mechanism | medium — "isolated" will be read as "sandboxed" | **recommended** |
| **C** | agent/tool broker only | row 1 becomes structural instead of conventional | rewrites the measured path; measures nothing today | low | **reject** |
| **D** | both | B's gains + C's non-gain | all of C's | medium | **reject** |
| **E** | constrained declarative adapter | rows 2, 3(policy-side), 6, 9, 10, 13 — by construction | forecloses network-calling, stateful and model-based defenses | low | **adopt as a second tier, not a replacement** |

**A** is not "do nothing" — it is only acceptable as **A+governance**: the
`CHALLENGE.md` code/data split, the CI policy-allowlist test, and the
`challenge --policy` restriction. Those three are the highest
value-per-line changes available and none of them is architecture.

**B** has the best ratio. Scope it narrowly: persistent server, opt-in flag,
default off, **environment scrubbed at spawn**, deny-on-{timeout, EOF, non-zero
exit, unparseable frame, unknown effect}, and a changelog entry that says *the
policy adapter can no longer tamper with the harness* and does not say
*the enforcement point is now tamper-proof*.

**E** is the strongest security answer and the project already half-holds it:
the Cedar adapters are a constrained declarative policy expressed as a
decomposed per-source question, digestible by content, with no host reach. But
`SecurityPolicy` is described as "the one interface a security product
implements to be measured here," and a DSL cannot host a stateful,
network-calling, model-based defense. Making E the *only* path would truncate
the frontier the benchmark exists to measure. Adopt it as a preferred **low-trust
tier**: a declarative adapter needs no trust decision and no worker; an
imperative one needs both.

---

## 5. Recommendation

1. **Ship the governance items first** (A+). Retract SIMPL-0001A, publish A′/B/C/D
   as separate register entries, split code from data in `CHALLENGE.md`, pin the
   CI policy allowlist, and restrict `challenge --policy` to builtins.
2. **Scrub `decision.reason` and `decision.rule_id`.** Two lines, independent of
   everything else, and the amended premise makes it a real gap rather than a
   theoretical one.
3. **Then build B**, narrowly, with the fail-closed protocol specified before the
   transport, and with the environment scrubbed at spawn.
4. **Adopt recorded-context replay for the challenge workflow.** It makes
   third-party policy evaluation safe without importing anyone's module, and it
   is the only proposal here that improves both the security property and the
   evidence the project is short of.
5. **Do not build C or D in Phase III.**

Row 1 is already green and should be reported that way. Rows 4, 5 and 13 are
amber and must not be reported as green because a process boundary appeared.
That distinction is the whole deliverable.
