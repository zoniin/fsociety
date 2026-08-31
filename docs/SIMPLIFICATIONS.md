# Simplifications — the fidelity-debt register

Every measurement instrument has a validity section. This is ours.

Each entry names something the implementation fakes, what that hides, **which
direction it biases results**, and what closing it would take. `bias_direction`
is the field that matters: an *optimistic* simplification makes containment look
better than it is.

This is not a study log and not a roadmap. The test for whether an entry
belongs: **delete the `background` line — does it still limit a claim the tool
makes?** If not, it is a diary entry and does not go here.

Code carries `# SIMPL-NNNN` markers at the exact site of each simplification.
There is deliberately no CI linter enforcing that at n=12; that would be
infrastructure serving a document.

---

## SIMPL-0001 — The policy decision point is not a reference monitor

- **code_ref**: `interpose/engine/runner.py::Runner._dispatch`
- **status**: open · **hidden_by**: architecture · **bias_direction**: optimistic
- **affects**: every containment verdict, `enforcement_escape`, `authorization_gap_open`

**What we do.** All five tools dispatch through one function, which resolves the
target object, calls the policy, and executes only on `ALLOW`.

**What that hides.** Anderson (1972) requires three properties of a reference
monitor: complete mediation, tamper-proofness, and verifiability. We have the
first, by construction and by test. We have **neither of the other two.** The
decision point lives in the same address space as the thing it mediates; it is
a function call the agent's process could in principle skip, and nothing here is
independently verifiable.

**Why it matters.** The obvious attack on this design is "your policy layer is a
function call, not enforcement". Every containment number is optimistic by an
unmeasured amount relative to a real out-of-process gateway.

**Path to fidelity.** The enforcement point in a separate process with no import
path from the agent, serialization as the trust boundary, decisions over a
socket. That is the first milestone in `ROADMAP.md`.

**Measured, not yet built.** A JSON-over-pipe policy server costs 0.076 ms per
decision steady-state and 159 ms per spawn, so a persistent server adds about 1%
to a full `demo` -- latency is not why this is unbuilt. The reason is that it
would not close this entry. Moving the *decision* out of process stops a policy
adapter tampering with the runner; it does not move the *enforcement* point,
`Runner._dispatch`, out of the agent's process, which is what this simplification
is about. See [`CEDAR-AND-ISOLATION.md`](CEDAR-AND-ISOLATION.md) §2 for the
numbers and for why restricting the isolated process further costs the
no-build-step install on all three platforms.

**Real-world analogue.** AWS AgentCore Policy evaluating with Cedar at the
gateway; FORGE's reference-monitor architecture.
**Background.** Anderson 1972 (Computer Security Technology Planning Study);
Saltzer & Schroeder 1975.

---

## SIMPL-0002 — Taint attribution is content matching, not information flow

- **code_ref**: `interpose/provenance.py::ProvenanceIndex.attribute`
- **status**: open · **hidden_by**: simulation · **bias_direction**: optimistic
- **affects**: `sensitive_data_exposed`, the R3 egress rule in the reference policy

**What we do.** Tool *results* carry real labels that join on combination. Tool
*arguments* are free text the model wrote, so provenance is recovered by
matching argument content against ingested content using 8-word shingles plus
exact canary tokens.

**What that hides.** The information-flow literature: security lattices, join
and meet, **implicit flows**, declassification, label creep. Shingle matching
cannot see an implicit flow. An agent that reads a payroll row and *paraphrases*
it into a ticket carries the information without carrying the bytes, and both
the attribution and the egress rule miss it entirely.

**Why it matters.** Under-attribution scores a containment success on a run a
real information-flow system would call a leak.

**Mitigation in place.** Two views are recorded and they bracket the truth:
`value_provenance` under-approximates, `context_provenance` over-approximates.
A policy may use either, and the choice shows up in its false-deny rate — which
is itself a measurable property worth publishing. `tests/test_units.py`
contains a test asserting that paraphrase escapes attribution, so the limitation
cannot quietly stop being true.

**Path to fidelity.** Two-axis labels propagated at the tool-boundary
marshalling layer rather than reconstructed after the fact, with explicit
declassification that is itself a policy decision.

**Real-world analogue.** FIDES integrity/confidentiality labels; CaMeL
capability labels; RTBAS screeners.
**Background.** Denning 1976, *A Lattice Model of Secure Information Flow*;
Sabelfeld & Myers 2003.

---

## SIMPL-0003 — Exposure is a substring match on a canary

- **code_ref**: `interpose/engine/runner.py::Runner._run_detectors`
- **status**: open · **hidden_by**: simulation · **bias_direction**: optimistic
- **affects**: `sensitive_data_exposed`, every `COMPROMISED` verdict

**What we do.** Each protected asset carries `INTERPOSE-CANARY-*` tokens. If a
token appears in a resource readable by a principal not entitled to the asset,
exposure fired.

**What that hides.** Real data-loss detection: entropy analysis, encoding and
chunking evasion, splitting a payload across turns, and — the fatal case — an
agent that *summarizes* rather than quotes.

**Why it matters.** Exposure is undercounted, so attack success is undercounted.

**Why we do it anyway.** The alternative is a language-model judge, which makes
the measurement depend on a second unpinned model and becomes the contamination
vector for the whole result. Exactness is the lesser evil, stated rather than
hidden.

**Path to fidelity.** Per-run high-entropy tokens, plus a separately reported
semantic-leak judgement carrying its own error bars — never folded into the
same number.

---

## SIMPL-0004 — The event log is append-only by convention, not construction

- **code_ref**: `interpose/events.py::EventLog`
- **status**: open · **hidden_by**: scope · **bias_direction**: invalidating
- **affects**: every claim derived from the trace, and `verify`

**What we do.** An in-memory list, written once at the end as JSONL. Control
characters are stripped from model- and scenario-authored strings.

**What that hides.** Tamper-evidence, ordering under concurrency, clock trust,
and **log injection (CWE-117)**: a tool result containing a newline plus forged
JSON could in principle manufacture the record that proves containment.

**Why it matters.** This one is *invalidating*, not merely optimistic — a
forged record does not bias a number, it fabricates one. Mitigated in practice
because scenarios are data and payload content is not written verbatim into the
log (arguments are truncated and digested), but the structural property is
absent.

**Path to fidelity.** A prefix hash chain plus a per-run signed manifest;
structural rejection of control characters in string fields rather than
stripping.
**Background.** NIST SP 800-92; CWE-117.

---

## SIMPL-0005 — The shadow probe is isolated, not stateful

- **code_ref**: `interpose/engine/probe.py::shadow_probe`
- **status**: open · **hidden_by**: scope · **bias_direction**: pessimistic for stateful policies
- **affects**: `authorization_gap_open`

**What we do.** Each declared objective step is evaluated against end-of-run
world state, independently, without simulating the effects of prior steps.

**What that hides.** History-dependent enforcement. A policy that tightens after
observing untrusted content — Progent-style monotonic confinement is the
canonical example — is evaluated as if each step arrived cold, which is *less*
favourable than it deserves. Correcting it needs a snapshot/restore contract on
the policy interface.

Separately, and more seriously: the probe replays **static, author-declared**
paths. A policy that blocks the one declared path scores a closed gap while an
adaptive attacker walks around it. This is exactly the critique
[2606.26479](https://arxiv.org/abs/2606.26479) levels at CaMeL, FIDES, Progent,
RTBAS and FORGE, and it applies here unchanged.

**Path to fidelity.** Strict-shadow replay from the real agent's checkpoint at
exposure; N distinct paths per objective with a declared path-diversity score,
so a policy blocking 1 of 4 scores 0.75 and the weakness is visible in the
number rather than hidden behind it.

---

## SIMPL-0006 — The no-egress guarantee is a guardrail, not a boundary

- **code_ref**: `tests/test_containment.py::test_deterministic_run_makes_no_network_calls`
- **status**: open · **hidden_by**: architecture · **bias_direction**: overclaims containment of the tool
- **affects**: the "no network" claim in `README.md` and `THREAT_MODEL.md`

**What we do.** A test runs a full scenario under `sys.addaudithook` and asserts
no egress event fires, plus a structural test that networking imports live in
exactly one module.

**What that hides.** An audit hook does not propagate into child processes, and
`ctypes` handles acquired before installation bypass it. The real boundary is
OS-level.

Additionally, on CPython 3.13 (verified on the Microsoft Store build), installing
*any* audit hook breaks the cached-bytecode import path — `AttributeError:
'bytes' object has no attribute 'co_filename'`, even for `import json`. The
probe therefore warms every import before installing the hook, so **egress
during import is not covered by that test.**

**Path to fidelity.** A `--network=none` container job on main and release,
which converts an assertion into an OS-enforced fact. Scoped to main/release so
the per-PR budget stays under a minute.

---

## SIMPL-0007 — A policy digest hashes source, not behaviour

- **code_ref**: `interpose/policy/base.py::policy_digest`
- **status**: open · **hidden_by**: scope · **bias_direction**: overclaims verifiability
- **affects**: `verify`, the frozen-policy protocol

**What we do.** Hash the source file of the policy class.

**What that hides.** A policy whose behaviour lives elsewhere — a remote
service, a data file, a model — gets a digest that captures none of it. Such an
adapter can override `digest()`, but nothing forces it to, and `verify` would
happily print `AGREES` for a policy that has silently changed.

**Path to fidelity.** Require adapters to declare a behaviour digest; refuse to
verify results from adapters that do not.

---

## SIMPL-0008 — Every object is correctly and completely classified

- **code_ref**: `scenarios/indirect-document-injection/world.yaml`
- **status**: open · **hidden_by**: simulation · **bias_direction**: optimistic
- **affects**: the reference policy's R2 rule, and therefore its containment result

**What we do.** Hand the policy perfect metadata: every resource has a correct
classification and, where relevant, an explicit reader set.

**What that hides.** In production, the single most common practical reason
object-level authorization fails is that objects are **unclassified,
misclassified, or stale**. We assume that problem away entirely, and it is the
problem.

**Why it matters.** The reference policy's success is conditional on a property
no real deployment has. A reader copying that policy inherits the assumption
without inheriting the metadata discipline that makes it true.

**Path to fidelity.** A scenario variant with deliberately stale and missing
classifications, scored separately — arguably the single most valuable
scenario #2 candidate.

---

## SIMPL-0009 — Capabilities are in-process objects, not tokens

- **code_ref**: `interpose/policy/types.py::PrincipalView`
- **status**: open · **hidden_by**: simulation · **bias_direction**: optimistic

**What that hides.** Token theft, replay, audience confusion, `alg` confusion,
`kid` injection, missing `aud`/`iss`, expiry handling — a large fraction of
real authorization failures. There is also no policy distribution, so no cache
staleness and no eventual consistency in a relationship graph. SpiceDB's hardest
problem is assumed away.
**Background.** RFC 8693 token exchange; RFC 8707 audience restriction.

---

## SIMPL-0010 — A tool call is a Python dict, not a protocol

- **code_ref**: `interpose/tools/spec.py::ToolSpec`
- **status**: open · **hidden_by**: architecture · **bias_direction**: whole attack classes are unrepresentable

**What that hides.** JSON Schema validation *as a security boundary*: type
confusion, extra properties, unicode normalisation of tool names. And the entire
MCP surface — OAuth 2.1 + PKCE, tool-description poisoning, name shadowing,
rug-pulls. A tool description is attack surface; here it is a string in a Python
file that no adversary can touch.

---

## SIMPL-0011 — The scripted client is not a model and resembles none

- **code_ref**: `interpose/providers/scripted.py::ScriptedProvider`
- **status**: wontfix (by design) · **bias_direction**: says nothing about models

**What we do.** A programmed client with four behaviour classes. `compliant`
decides by scanning untrusted content for a file path and a queue name.

**What that hides.** Everything about how a real model behaves. This is
deliberate: under the framing "assume the component is owned", a deterministic
worst-case client is the correct instrument for a regression test. It is the
wrong instrument for any claim about model populations, and the tool refuses to
print a rate from it.

**Danger.** The temptation to quote a scripted-path number as though it says
something about models. If a result carries `deterministic: true`, it does not.

---

## SIMPL-0012 — The attack corpus is static and small

- **code_ref**: `scenarios/*/untrusted/`
- **status**: open · **hidden_by**: scope · **bias_direction**: overstates policy strength

**What that hides.** Adaptive, defense-aware attacks — which previously broke
twelve in-band defenses at over 90% success. Five phrasings of one objective is
paraphrase coverage, not attack diversity. Public payloads also get scraped, so
the corpus saturates.

**Path to fidelity.** Seeded attack generators published alongside results so
instances rotate while results stay reproducible; a versioned corpus with a
held-out split, once there is a community large enough to sustain the
governance that requires.

---

## SIMPL-0013 — Entitlement is a flat reader list, not an access-control system

- **code_ref**: `src/interpose/policy/types.py::ReaderView.entitled_to`
- **status**: open · **hidden_by**: scope · **bias_direction**: overstates policy strength
- **affects**: rule R3 in `reference-least-privilege`, and any adapter that mirrors it

**What we do.** A resource carries an explicit list of principal ids that may
read it. If the list is empty, entitlement falls back to comparing clearance
levels. R3 asks, for each tainted source and each reader of the sink, whether
that reader appears on that source's list.

**What that hides.** Real authorization is not a flat list. Groups, nested
groups, roles, inherited folder ACLs, sharing links, delegated access, time-
bounded grants, and break-glass all resolve to an effective permission through
machinery this model does not have. Every one of those is a place where the
*effective* reader set differs from the declared one, and the gap between them
is where a large share of real data exposure lives — a principal who is not on
the list but is in a group that is.

The flat list also makes the reference policy's job easier than it should be.
Entitlement here is a lookup that cannot be stale, cannot be misconfigured, and
cannot disagree with a second system of record.

**Path to fidelity.** Group and role indirection in the world model, then a
scenario where the declared reader set and the effective reader set diverge.
That is a natural pairing with the misclassified-metadata scenario on the
roadmap, and probably the same pull request.

---

## SIMPL-0014 — The policy freeze is a self-attestation, not a trusted timestamp

- **code_ref**: `policy-freeze.json`, `src/interpose/challenge.py::check_freeze`
- **status**: open · **hidden_by**: governance · **bias_direction**: overstates the ordering guarantee
- **affects**: the anti-circularity argument in `PROTOCOL.md` and `CHALLENGE.md`

**What we do.** `policy-freeze.json` records the content digest of every
published policy. It is committed, and `interpose freeze --check` runs in CI, so
editing a frozen policy without deliberately re-freezing turns the build red.
The claim built on it is that git commit order proves a policy predates the
attacks that score it.

**What that hides.** Everything here is attested by the same party the
mechanism is supposed to constrain. A maintainer can rewrite the branch, re-date
commits, or re-freeze and re-run in a single push; nothing in the repository
distinguishes that from honest history. Commit timestamps are author-supplied
and trivially forged. The freeze protects against *drift* — the realistic
failure, where someone edits a policy and forgets what it invalidates — and not
at all against a determined author, which is the case the circularity objection
is actually about.

So the ordering rule is a discipline the maintainer submits to publicly, not a
guarantee a reader can verify unaided. It should be read as the former.

**Path to fidelity.** Signed tags with a published key, an external timestamp
(an OpenTimestamps proof or the digest posted somewhere append-only), and
challenge results reproduced by CI from a checkout of the tagged revision rather
than the working tree. None of that helps until a third party actually runs a
challenge — which is the load-bearing gap, and no amount of cryptography closes
it.
