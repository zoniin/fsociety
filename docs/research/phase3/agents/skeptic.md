# Agent G — the Skeptic

**Brief:** kill Phase III. Argue seriously that the policy worker process should
not be built, then say what survives.

**Verdict, up front.** Do not build the process boundary in Phase III. Not
architecture B, not C, not D. The boundary is *not* imaginary — I demonstrated
the tamper capability it would remove, and it is real — but it is the wrong size
for every adversary the project actually has, it damages the one integrity
mechanism the project already relies on, and it is not the binding constraint on
anything this benchmark publishes. **One narrow property survives, it is a
measurement-integrity property rather than a security one, and two changes worth
about twenty lines capture most of it.** Stated in §8.

All measurements below were taken on this machine at HEAD `55721a2`,
`src`/`tests`/`scenarios` untouched by me, `interpose freeze --check` →
`FREEZE INTACT`.

> **Concurrency note.** Partway through this review another Phase III agent
> edited `src/interpose/policy/base.py` (test count moved 168 → 171). It removed
> the `digest()` override — a separate and worse defect, where a hostile adapter
> returned the *genuine* reference digest and `verify` printed `AGREES` over a
> forged result — and documented the third-party weakness in the docstring.
> **I re-ran my §5 probe against the edited file; the finding survives
> unchanged.** Citations below are to the current file. Where the two interact,
> §5 says so.

---

## 1. The project has already written most of my argument, and should get credit for it

A skeptic who pretends to discover what the target documented is worthless. The
strongest statements against Phase III are already in the repository, written by
its author:

- `docs/research/ENFORCEMENT_BOUNDARY.md:203-205` — "**Do not ship subprocess
  isolation as a security claim.** If it ships at all, it ships as an
  interface-hygiene feature with the security delta stated exactly as in the
  table above."
- `docs/research/PHASE2_THESIS.md:252-254` lists subprocess isolation under
  *what must not be built*, because it "would not fix the property it appears to
  and would measure nothing against a non-adversarial client."
- `docs/SIMPLIFICATIONS.md:47-53` (SIMPL-0001) — "The reason it is unbuilt is
  that it would not close this entry."
- `docs/THREAT_MODEL.md:110-116` — the trust ruling on adapters, quoted in §4.

So the honest framing of my task is not "does the author see the objection." He
does, in more detail than most reviewers would. The question is whether Phase III
has produced a *new* reason to overturn a decision the project made deliberately
three times. My finding is that it has not, and that the new premise (P1) is
weaker than the one it replaced.

I also confirmed the project's cost arithmetic rather than disputing it, and
found it honest — see §7, where my numbers are slightly *worse* for isolation
than the project's own.

---

## 2. Model compromise and host compromise are being conflated

This is the central confusion, and everything downstream inherits it.

**Interpose measures model compromise.** Every published number — `CONTAINED`,
`sensitive_data_exposed`, `false_denials`, the Cedar ablation table, the
227/227 agreement — is about an agent induced by injected content to request a
privileged action. The threat is a *manipulated principal*, and the control is
authorization.

**Phase III proposes to defend against host compromise.** P1's adversary ships
arbitrary Python that runs as the user. That is not a manipulated principal; it
is code execution on a developer workstation. Different adversary, different
assets, different correct control.

These have almost nothing to do with each other, and the repository already says
so. `ENFORCEMENT_BOUNDARY.md:60-72` establishes that the model **cannot** bypass
the PEP at all: `provider.respond()` returns an `AgentTurn`, a frozen dataclass
of text and requested calls (`src/interpose/providers/base.py:62-70`), and "data
cannot skip a function call." I verified the shape: `ProposedCall` carries only
`tool: str` and `arguments: dict` (`providers/base.py:50-59`), and every call
reaches the world only through `Runner._dispatch`
(`src/interpose/engine/runner.py:287-395`).

So T1 is closed. Phase III's brief concedes this. But the conclusion drawn from
the concession is the wrong one. The correct inference from *"the threat we built
this to study is fully mediated"* is **not** *"find another threat to justify the
architecture we wanted." * It is *"the architecture is finished; go measure
something."*

What actually happened is visible in the report itself
(`INT000_FINAL_REPORT.md:145-153`): the P1 threat was discovered by reading
`importlib.import_module` in the project's own `load_policy`. It was not
discovered by an incident, a user, a scanner, a dependency audit, or an attack.
That is the signature of a solution looking for a problem, and the project's own
complexity rule — "**complexity must be earned.** A subsystem gets built when a
claim requires it" (`docs/ROADMAP.md`, *Wild future*) — is the rule that should
decide this.

---

## 3. The boundary is the wrong size — measured, not asserted

The core of the security-theatre argument. A subprocess under the same OS user is
not a security boundary against the assets the project itself says matter.

`docs/THREAT_MODEL.md` §Assets names them: model-provider API keys, developer
machine credentials (`~/.ssh`, `~/.aws`, `~/.config/gh`), source repositories on
the same machine, CI runner identity, the release channel.

I spawned a worker with the **best environment scrubbing a pure-Python parent can
do** (`env=` reduced to `SYSTEMROOT` and `PATH`) and probed what it still
reaches. Existence and open-permission checks only; nothing was read or
exfiltrated:

```
=== worker with SCRUBBED env (best case a pure-Python parent can do) ===
  env has fake key   : False
  C:/Users/Owner  : exists=True  readable=True
  repo            : exists=True  readable=True
  ~/.gitconfig    : exists=True  readable=True
  ~/.claude       : exists=True  readable=True
  socket() usable    : True
  can spawn child    : True
```

With the *default* inherited environment the same probe read
`INTERPOSE_FAKE_KEY` straight out of `os.environ`.

So the delta a policy worker buys against the project's own asset list is: **the
environment block, and only if the parent explicitly scrubs it** — and even then
the API key is recoverable from any dotfile on disk, the repository is readable,
sockets open, and the worker can spawn further processes. Against a P1 adversary
defined as "can ship arbitrary Python," a subprocess is a speed bump.

Closing that gap needs OS-level confinement, and `docs/CEDAR-AND-ISOLATION.md`
(§*What real isolation would cost*) already priced it: seccomp-bpf via `ctypes`,
user namespaces, Windows Job Objects, deprecated `sandbox_init` on macOS — "every
row is either a new dependency or a `ctypes` binding to maintain across three
platforms, and any of them breaks *clone, `pip install -e .`, run*."

Which leaves the boundary stranded between two coherent positions:

- **Too little for an untrusted adapter.** Real containment is a container. The
  project has an explicit, well-drafted container-trigger list
  (`THREAT_MODEL.md` §*Containers: the trigger*) — arbitrary code execution
  tools, egress-control enforcement, a policy engine shipping as a server, wire
  protocols. **A third-party policy adapter is not on it**, and "it would feel
  more real is not a trigger."
- **Too much for a trusted dependency.** If the adapter is chosen and reviewed,
  the boundary defends against a threat you already accepted.

A control that is too weak for the hostile case and unnecessary for the friendly
one is occupying a gap where no adversary lives. That is the definition of
security theatre, and it is the strongest form of the brief's argument.

---

## 4. The P1 adversary does not exist, and the project already ruled on him

Four independent lines of evidence.

**(a) The project already decided this, deliberately.**
`docs/THREAT_MODEL.md:110-116`:

> **Policy adapters are different, deliberately.** They are ordinary Python
> modules loaded by explicit dotted path, never referenced from scenario YAML,
> never auto-downloaded, never resolved from a registry. Running one is running
> its author's code with exactly the trust that implies — the same trust you
> extend to any dependency you install and name on a command line. Scenario
> content *circulates*; a policy adapter is *chosen*. Collapsing those two into
> one rule is the mistake.

The same ruling appears in `src/interpose/policy/base.py:3-14` and
`docs/ARCHITECTURE.md:91-101`. Phase III's premise does not refute this
reasoning; it simply proceeds as though it had not been written. **The honest
answer to "is a policy adapter a trusted dependency?" is the one the project
already gave: yes.** The correct control for a trusted dependency is human
review, and the project has already specified it
(`ENFORCEMENT_BOUNDARY.md:96-98`): "Scenario contributions are data; adapter
contributions are code, and they are reviewed by a human before they run
anywhere trusted."

**(b) The contribution funnel does not ask for adapters.** `docs/CHALLENGE.md`
opens: "**The most valuable thing you can contribute here is a scenario the
reference policy fails.**" The entire twenty-minute onboarding is
`interpose new scenario` → edit `untrusted/*.b64` → `interpose challenge`. It
asks strangers for **data**, which is already the most locked-down artifact in
the project. Phase III proposes to contain the artifact the project does not
solicit.

**(c) There are no third parties at all.**

```
$ git log --format='%an <%ae>' | sort | uniq -c
     21 zoniin <jarrettbungo@gmail.com>
$ git tag        # (empty)
$ git branch -a  # main, remotes/origin/main
```

Twenty-one commits, one author, no tags, no releases, no branches. `ROADMAP.md`
§1.0 says it plainly: "right now nothing has been used by anyone but its
author." The count of hostile third-party policy adapters is zero, and the count
of *any* third-party policy adapters is also zero.

**(d) The stated adversary is unmotivated.** The reward for compromising a
solo-maintained research benchmark with no users is one developer's workstation
— reachable far more cheaply through any of the project's actual dependencies.
A malicious adapter author must first persuade someone to `pip install` their
package and name it on a command line, at which point they own the process
regardless of where `evaluate()` runs.

**Conclusion of §4:** P1 is a hypothetical threat to a benchmark with no external
contributors, contradicting a considered ruling the project made three times, in
service of an artifact its own contribution funnel does not request.

---

## 5. New finding — the boundary breaks the integrity mechanism it claims to protect

This is the argument I did not expect to find, and it is the one I would lead
with if the maintainer reads only one section.

`policy_digest` is load-bearing. It is the project's answer to the circularity
objection — `policy-freeze.json`, `interpose freeze --check` in CI, and
`interpose verify` all rest on it (`docs/CHALLENGE.md`, `docs/PROTOCOL.md`).

**It is already blind to exactly the adapter class Phase III is about.**
`_import_closure_sources` filters the walk to first-party modules
(`src/interpose/policy/base.py:161`):

```python
if not name or name in seen or not name.startswith("interpose"):
    continue
```

The walk *starts* at the policy's own module (`base.py:157`). For any adapter
whose module is not named `interpose*` — i.e. every third-party adapter — the
first iteration `continue`s, `files` stays empty, and the function falls through
to `sha256_text(f"{policy.id}:{policy.version}")` (`base.py:138`). Verified
twice, before and after the concurrent edit described above:

```
third-party adapter digest : sha256:b0570ff52f9c5af529768d44d243c147780c80a5b5cb0e70d8fe8d2949fedbe7
sha256('hostile-probe:0.0.1'): sha256:b0570ff52f9c5af529768d44d243c147780c80a5b5cb0e70d8fe8d2949fedbe7
-> digest is the ID+VERSION STRING, not the source: True
```

A third-party adapter's "content digest" is a hash of two strings **it chooses
itself**, invariant under arbitrary rewriting of its own source. Today this is
latent — `build_freeze_record` iterates only `BUILTIN_POLICIES`
(`src/interpose/challenge.py:67-69`) — but it activates precisely at the
project's own 1.0 condition: "at least one policy adapter for an engine this
project did not write."

The concurrent edit now documents the weakness honestly (`base.py:127-133`:
"weak for third-party code … two adapters with opposite behaviour can digest
alike"). Two observations stand regardless:

- **Documenting it is not fixing it.** The filter at `base.py:161` is unchanged
  and the probe above still returns an id+version digest.
- **The docstring's stated mitigation is not in the code I can see.**
  `base.py:132-133` says this is "the reason `interpose challenge` now refuses
  non-built-in targets," but `challenge.py` has no such refusal:
  `build_report` calls `load_policy(policy_short)` unconditionally
  (`challenge.py:184`) and an unrecognised policy simply takes the
  `status = "unfrozen"` branch (`challenge.py:188-190`) and proceeds. This may
  be an in-flight edit by the other agent rather than a settled state — but it
  is the exact failure class INT-000 §5 recorded against itself ("two of my own
  fixes were silently ineffective … both passed the full suite"), and it is
  worth a check before the phase closes.

**Now the part that indicts the process boundary.** `_import_closure_sources`
reads `sys.modules.get(name)` (`base.py:155`) — it can only hash modules that
have **already been imported in this process**. If the adapter is moved to a
worker, the parent has three options and all are bad:

1. Import the adapter in the parent to digest it — which is the arbitrary code
   execution the boundary exists to prevent. Self-defeating.
2. Have the worker compute and report its own digest — **the untrusted party
   attests its own identity.** SIMPL-0014 already calls the freeze a
   self-attestation; this makes it an *adversary*-attestation.
3. Resolve and read the source textually in the parent without importing — which
   the transitive `sys.modules` closure walk cannot do, so it is a rewrite of the
   digest, not a port of it.

So for the exact adversary Phase III invokes, the process boundary converts a
first-party-verified digest into one the adversary supplies. **The boundary makes
the project's core integrity mechanism worse.** And the underlying defect — one
line at `base.py:152` — is fixable inside architecture A for a fraction of the
cost.

---

## 6. The RPC creates the first parser that attacker-controlled bytes must cross

T1 is closed today *because there is no parser*. `AgentTurn` is a dataclass; the
model's influence is a return value. An RPC boundary introduces a codec that
model-controlled data must traverse — a regression on the one axis the project is
currently strong on.

Three concrete problems.

**(a) `DecisionContext` is not serialisable.** The claim that serialization is
nearly free does not survive contact:

```
asdict+json.dumps FAILS: Object of type frozenset is not JSON serializable
```

`PrincipalView.granted_tools` is a `frozenset[str]` (`policy/types.py:110`), and
`Classification`/`TrustClass` are enums. A hand-written codec is required for
eight view types — new code, new bugs, a new versioned schema, in the one module
the project deliberately keeps free of dependencies
(`policy/types.py:27-29`: "this module imports nothing from
`interpose.scenario`, and a test asserts it").

**(b) The codec must carry untruncated attacker content.** `_dispatch` passes the
**raw** `arguments` dict into the context (`runner.py:334-341`). `_safe_args` —
which truncates at 240 chars — is used only for the *log*
(`runner.py:648-662`), and its docstring says why: "Tool arguments can carry an
entire exfiltrated file." So every decision would serialise the full exfiltrated
body, including `INTERPOSE-CANARY-*` markers, onto a pipe.

That collides with the threat model's first control: "**Allowlist serialization
is the control.** Artifacts are built field-by-field from declared schemas.
Nothing is written by dumping an object, a dict, or an exception's `__dict__`."
And it collides worst with the benefit most often cited for the boundary —
*clean crash attribution*. Attributing a worker crash means recording the
request that caused it, and that request is the exfiltrated document. The
canary test (`tests/test_containment.py:201-215`) asserts a secret appears in no
artifact; a crash-attribution log is a new artifact class that would carry the
scenario's canaries by construction.

**(c) The payload cost is real.** Round trips scale with body size, and the
project's 0.076 ms figure was measured on a trivial payload:

```
round trip tiny (logged/truncated)   : median 0.043 ms  p99 0.109 ms  (json   125 B)
round trip real max ingested body    : median 0.044 ms  p99 0.107 ms  (json  1353 B)
round trip 4 KB exfil body           : median 0.071 ms  p99 0.142 ms  (json  4075 B)
round trip 64 KB document            : median 0.647 ms  p99 1.744 ms  (json 64075 B)
```

Still affordable at current corpus sizes. Worth knowing it is 15× at 64 KB, and
that the corpus is supposed to grow.

---

## 7. Cost: the project's arithmetic is honest, and slightly optimistic

I re-measured rather than argued. The project's figures hold up well:

| | project's figure | mine (this box) |
|---|---|---|
| spawn + first decision | 159 ms | **132.4 ms** median, n=15 |
| steady-state round trip | 0.076 ms | **0.043 ms** median, n=2000 |
| demo wall clock | 3.4 s | **3.60 s** median, n=3 |

One correction, and it runs *against* isolation. Both benchmarks measured a
worker that imports nothing. A real policy worker must import the policy:

```
bare python -c pass               : median   110.9 ms
+ import json                     : median   143.5 ms
+ import interpose.policy.base    : median   241.9 ms
+ load reference policy           : median   239.0 ms
+ load cedar-with-provenance      : median   231.7 ms
```

**Realistic worker cold start is ~240 ms, not 159 ms** — the import closure the
digest walks is the same closure the worker must load. So spawn-per-run across
an 18-run demo is ≈ 4.3 s against a 3.60 s demo: **~120%, more than doubling
it.** A persistent server remains cheap (~0.26 s, ~7%).

Latency is genuinely not the objection, and I will not pretend otherwise. But
note what a *persistent* server costs conceptually: one worker shared across
runs is a policy process that outlives the run boundary, which reintroduces
cross-run state into an instrument whose whole value is per-run determinism.
The cheap option is the one that weakens reproducibility; the clean option is
the one that doubles the demo.

---

## 8. Being fair: the tamper capability is real

I tried to falsify the premise and could not. I wrote a hostile adapter, placed
it **outside the repository**, and loaded it by dotted path exactly as
`load_policy` permits:

```
loaded: hostile-probe | type: HostilePolicy
load_policy accepted an arbitrary module outside the repo: YES
```

Then I ran a real trial with it
(`interpose run scenarios/confidential-egress --policy hostile_policy:HostilePolicy`):

```
--- HOSTILE ADAPTER REACHABILITY ---
  world   : REACHED World
  runner  : REACHED Runner
  log     : REACHED EventLog
  world mutable attrs: ['create_ticket', 'digest', 'org_name', 'principal', 'principals',
                        'queue_readers', 'queues', 'resource', 'resource_by_path', ...]
  event log events attr: list len=46 append=YES
------------------------------------
```

A single `sys._getframe(1)` walk from inside `evaluate()` reaches the `World`
(with mutators), the `Runner`, and an `EventLog` whose backing store is a plain
`list` with `append` — SIMPL-0004's "append-only by convention, not
construction," confirmed at runtime and rated *invalidating* rather than merely
optimistic. `ENFORCEMENT_BOUNDARY.md:80-90` is accurate: this is not theoretical.

A parallel Phase III agent found something sharper still, and it is the single
strongest argument *for* the boundary: a hostile adapter could return the
genuine reference policy's `digest()`, match `policy-freeze.json` byte for byte,
and make `interpose verify` print `AGREES` over a forged result in which the
adapter performed the exfiltration itself (`base.py:118-125`). That is not
tampering at the margin — it is **full forgery of a published result**, which is
the worst thing that can happen to a benchmark.

I take it seriously, and it does not change my verdict — because of *how it was
fixed*. It was fixed by deleting three lines inside architecture A: stop
honouring a caller-supplied `digest()`. No process boundary, no codec, no
worker, no phase. That is the thesis of this review in miniature: **the real
attacks on this system have been found by reading the code, and closed by
changing the code.** A subprocess would not have prevented that forgery either,
since a worker computing its own digest is precisely the self-attestation the
fix removed (§5).

**So the property Phase III would buy is real. My argument is not that it is
fake; it is that it is a measurement property mis-filed as a security property,
with no consumer yet, obtainable more cheaply.**

---

## 9. Opportunity cost — this is not the binding constraint

Measured across every run artifact on disk (192 runs, 21 trial directories):

```
policy.evaluated totals: {'allow': 809, 'deny': 19}
deny rule_ids: {'prefix.blocked-namespace': 13, 'R3.egress-to-unentitled-reader': 3,
                'R2.not-in-reader-set': 3}
  reference-least-privilege: {'allow': 268, 'deny': 6}
```

The reference policy discriminates on **6 denials in 274 decisions (2.2%)**,
across exactly two rules. **`R1` never fires** — zero occurrences, confirming
`PHASE2_THESIS.md:48` (O5) empirically rather than by citation. The entire
published thesis rests on 3 R3 denials and 3 R2 denials.

Against that, the outstanding list from `INT000_FINAL_REPORT.md` §6:

- **R5** — oracle and policy still share an entitlement relation; the reference
  policy cannot be scored wrong on a read it permits.
- **The flow detector cannot survive paraphrase**, and `scripted:paraphrasing`
  drives both egress scenarios to COMPROMISED at zero denials.
- **No third party has ever run a challenge.** The mechanism built to answer the
  project's central epistemic objection has produced zero evidence.
- **SIMPL-0008** — perfect metadata, which `ROADMAP.md` itself calls "now the
  highest-value scenario, because it attacks the reference policy's foundation
  rather than its rules."
- **SIMPL-0013** — flat reader lists; the roadmap notes this pairs naturally with
  SIMPL-0008 and is "probably the same pull request."

`docs/CEDAR-AND-ISOLATION.md` §*Not doing yet* names the binding constraint
outright: "scenarios that discriminate between policies and a third party
willing to attack the frozen one — not more world." A policy worker is more
world. It changes no published number — by the project's own analysis it *cannot*
change one — while consuming the phase that could produce the scenario the
roadmap already ranks highest.

There is also a sequencing hazard the project has already articulated
(`ENFORCEMENT_BOUNDARY.md` §4): "changing the instrument while running
experiments on it is how a benchmark loses its history." There is now history to
lose — a frozen policy record, a 227-context agreement replay, a published
baseline.

---

## 10. Does an RPC help real agent systems, or hurt integration?

It hurts, for a reason specific to this codebase: **policy-relevant semantics
live in methods, not data.**

`ReaderView.entitled_to` (`policy/types.py:154-164`),
`SinkView.unentitled_readers` (`:203-205`), `PrincipalView.delegated_rank`
(`:117-122`) are not conveniences — R6 exists because "R3's entitlement logic
lives in `types.py`, not `reference.py`" (`base.py:135-139`). Over JSON there
are two options:

1. **Ship a client SDK** that reconstructs the dataclasses. The coupling the
   boundary was meant to eliminate returns unchanged, now with a version-skew
   failure mode between parent and worker.
2. **Ship raw JSON.** Every third-party adapter re-derives `entitled_to`. A
   re-derivation bug then appears in results as a *defense* difference. For a
   benchmark whose entire output is cross-policy comparison, that is
   measurement contamination — and it is worse given R5, where the oracle and
   the policy already share this relation.

Either way, an RPC converts a mypy-checked shared invariant into a protocol
invariant checked by nothing. For the third-party integrators the project keeps
saying it wants, `pip install`, write a class with `evaluate(ctx) -> Decision`,
name it on the command line is a *better* integration story than provision a
worker, implement a wire schema, re-derive entitlement, keep in version lockstep.
And `docs/PRACTICALITY.md:112` already flags the real adoption gap: "No adapter
has been written for LangChain, LangGraph, the …" — a gap an RPC widens.

---

## 11. Is `interpose[cedar]` evidence that architecture E is the right answer?

**Partly, and in a way that is fatal to E as a replacement.**

What E gets right: a constrained declarative language reproduced the reference
policy on **227/227 decision contexts, matching on effect *and* rule id**
(`CEDAR_PROVENANCE_ABLATION.md:170-189`), needing **no change to the
`SecurityPolicy` interface**.

What E gets wrong, measured:

- **The declarative half is small.** ~458 executable Python lines across the
  three Cedar modules against ~36 non-blank lines of Cedar text — roughly 12:1.
- **The Cedar text is not data.** It is a triple-quoted Python string constant
  (`cedar_common.py:91`), and the freeze digest works *because* of that
  (`CEDAR_PROVENANCE_ABLATION.md:510-514`). A real declarative format needs its
  own provenance story that does not exist.
- **It still imports arbitrary third-party Python.** `_cedar()` imports `cedarpy`
  (`cedar_common.py:161-180`), which the digest does not cover. E moves the
  arbitrary code from the adapter author to the engine binding; it does not
  remove it.
- **Cedar fails open** — a `forbid` whose condition errors is silently skipped,
  and the `NoDecision → DENY` collapse that fixes it is a **Python** decision
  (`cedar_common.py:402-429`).
- **Decisively: R3 is not in the Cedar text at all.** I verified this directly.
  `cedar_common.py:85-90` — "R3 has no counterpart here that quantifies over
  sources." The egress denial is authored in Python:
  `_EGRESS_RULE = "R3.egress-to-unentitled-reader"`
  (`cedar_with_provenance.py:80`), constructed as a Python `Decision` at
  `cedar_with_provenance.py:136-151`. Cedar decides per-pair entitlement; Python
  decides that egress is denied and names the rule.

So: **E is strongest exactly where the project's thesis is weakest (ordinary
object authorization, scenario 1, which INT-000 found "draws no support for the
thesis at all") and absent exactly where the thesis lives (flow control,
scenarios 2 and 3).** A general declarative adapter format would have to specify
schema construction, entity stores, quantifier unrolling and the fail-open
collapse — that is a policy DSL, and `ROADMAP.md` §*Things that will not be
built* lists "A novel policy DSL" explicitly.

E therefore does not make the subprocess unnecessary by being a better answer.
It makes it unnecessary by being *the same answer already reached*: the adapter
is a chosen dependency either way.

---

## 12. What survives

One property. Stated to be testable:

> **A policy adapter cannot alter any field of a published run artifact except
> through the `Decision` values it returns.**

Falsifiable today, and it **fails**: my hostile adapter reached the `World`, the
`Runner`, and a mutable `EventLog` (§8). The test is concrete — run a scenario
twice with two adapters that emit an identical decision sequence, one benign and
one hostile, and assert `result.json` and the event log are byte-identical.

Three things to be precise about:

1. **It is measurement integrity, not security.** It protects the *scoreboard*,
   not the host. §3 measured what the boundary does not protect.
2. **It has no consumer.** Its value begins the first time a number is published
   from an adapter the maintainer did not write. That has never happened and is
   a 1.0 precondition (`ROADMAP.md` §1.0).
3. **It is not the cheapest route to itself.** Two changes inside architecture A
   capture most of it:
   - **Fix `policy_digest` for third-party adapters** (`base.py:161`) so an
     adapter's own module source is hashed even when it is not named
     `interpose*`. Roughly one line plus a test. This closes the live defect in
     §5 — which the process boundary would have made *worse*.
   - **Actually make `verify` and `challenge` refuse non-builtin adapters**
     unless a human recorded the digest. This is the control
     `ENFORCEMENT_BOUNDARY.md:96-98` already prescribes, `CHALLENGE.md` does not
     state, and `base.py:132-133` currently claims as done while
     `challenge.py:184-190` still accepts them.

Those two land the trust rule the project already decided on, cost about twenty
lines, change no published number, and leave the boundary available later
without spending a phase on it.

---

## 13. Architecture scores

Criteria: does it address an adversary that exists · does it change a published
number · cost against the 3.60 s demo · effect on integration · reversibility.

| | Architecture | Score | Verdict |
|---|---|---|---|
| **A** | No new boundary | **8 / 10** | **Correct default.** Costs nothing, preserves history, and every live defect I found (§5) is fixable inside it. Its one real weakness — the tamper capability of §8 — has no consumer yet. |
| **B** | Policies only | **4 / 10** | The honest option, and the only one whose stated benefit I could confirm. But it is premature (no adapter to contain), it degrades `policy_digest` into adversary self-attestation (§5), it requires a hand-written codec carrying attacker payloads (§6), and it changes no number. Revisit at 1.0. |
| **C** | Agent/tool broker only | **1 / 10** | Refuted by the project's own analysis: against a scripted provider "every number would be identical before and after" (`ENFORCEMENT_BOUNDARY.md` §4). It is also the *only* architecture that would close SIMPL-0001 — which makes the roadmap's "out-of-process mediation" milestone a promise Phase III's brief does not keep, since the brief proposes B while the roadmap named C. Pure cost until there is an adversarial client. |
| **D** | Both | **2 / 10** | B's cost plus C's zero, on the instrument every result is measured against. The worst available use of the phase. |
| **E** | Constrained declarative adapter, no arbitrary imports | **5 / 10** | The only architecture that actually removes arbitrary import, and the right long-run direction for adapter *containment*. But §11 shows the general version is a policy DSL the project has forbidden, and the flow rule that carries the thesis is not expressible in it. Worth a narrow spike — accept `.cedar` text as data for the Cedar adapter, with its own digest — not a phase. |

---

## 14. Recommendation

**Do not build the process boundary in Phase III.**

1. Fix `policy_digest` for third-party adapters (`base.py:161`). This is a live
   defect on the path to 1.0, and the boundary would have entrenched it.
2. State the adapter trust rule in `CHALLENGE.md` and `SECURITY.md`, and make
   `verify`/`challenge` refuse unreviewed non-builtin adapters *in code*.
   Prescribed at `ENFORCEMENT_BOUNDARY.md:96-98`, asserted at `base.py:132-133`,
   and — at the time of this review — absent from `challenge.py`.
3. Record the §12 property as a named simplification with its failing test, so
   it is on the register rather than in a phase brief.
4. Spend the phase on the roadmap's own highest-value item: the
   misclassified-metadata scenario (SIMPL-0008) paired with group indirection
   (SIMPL-0013). That attacks the reference policy's foundation, moves published
   numbers, and addresses the fact that the corpus discriminates on 6 denials in
   274 decisions.

If the boundary is built anyway, `ENFORCEMENT_BOUNDARY.md:203-205` already wrote
the changelog entry it is allowed to have: an interface-hygiene feature, not a
security claim. I would add one line to it — *and the policy's digest is now
self-reported.*
