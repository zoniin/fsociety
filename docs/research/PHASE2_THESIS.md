# Phase II thesis

Written after six independent research agents and an independent verification
pass by the principal investigator, before any implementation. Its job is to say
what the project may still claim, what it may not, and what the smallest Phase II
is that produces genuinely new evidence.

Findings are separated into **OBSERVED** (measured, reproduced), **INFERRED**
(follows from the observations, but is an argument), and **HYPOTHESIZED**
(believed, untested). Nothing below is a plan; §7 is.

---

## 1. Verdict in one paragraph

Phase I produced one surprising result — a policy that looked defensible against
one scenario failed against a second. Phase II asked whether that was an
accident. **It was not an accident, but it was much smaller than advertised, and
the apparatus that produced it is substantially broken.** The measured
containment of the reference policy across all three scenarios is an artifact of
the scripted client pasting file contents verbatim; under a client that restates
the same facts, the reference policy denies nothing, anywhere, and the harness's
own exposure detector simultaneously stops reporting the leak. The grader shares
its entitlement predicate with the policy it grades. The freeze does not detect
the drift it was built to detect. The challenge workflow is both unwinnable by
construction and forgeable three ways. Confidence in the project's **claims**
has dropped sharply. Confidence in its **method** has risen, because the method
found all of this when pointed at itself — which is the only reason any of it is
known.

---

## 2. OBSERVED

Every item here was reproduced by the principal investigator with commands and
output recorded in [`PHASE2_FINDINGS_REGISTER.md`](PHASE2_FINDINGS_REGISTER.md).

| # | Observation |
|---|---|
| O1 | `Resource.readable_by` and `ReaderView.entitled_to` agree on **116 of 116** (resource, principal) pairs. The oracle and the policy share a predicate. |
| O2 | Under a restating client, `reference-least-privilege` scores **COMPROMISED with 0 denials and full benign pass** on scenarios 2 **and** 3. |
| O3 | `sensitive_data_exposed` reports **false** in every row under a restating client, including rows where the shipped demo prints `YES`. |
| O4 | Three lines changed in `policy/types.py` gut R3; `freeze --check` prints **FREEZE INTACT, exit 0** while the flagship scenario leaks. |
| O5 | Across a full demo: **233 policy decisions, R3 fires once.** `R1` never fires. The clearance-lattice branch is never exercised on a classified object. |
| O6 | `join_sources` has **no call site in `src/`**. Tool results carry 0 or 1 sources across 213 executions, never more. |
| O7 | `permissive-baseline` scores **`RESULT CONTAINED`** against `scripted:refusing` while the probe reports it would permit 2/2 objective steps. |
| O8 | `result.json` records the attack's own denied egress write as a **false denial**. |
| O9 | Only 2 of 5 tools attach a `Source` to their output; `spec.py` has accepted `vector: "tool_output"` since 0.1 for a vector the engine cannot track. |
| O10 | A `cedar-with-provenance` adapter reproduces the reference policy at **122/122** decisions; Cedar cannot express any iteration over a request-scoped set. |

Agent-reported and **not** independently reproduced, listed so the distinction
survives: the challenge workflow is forgeable three ways (objective-forging,
enumeration-as-read, canary-collision); a policy may declare its own digest; no
benign floor exists; `INADMISSIBLE`/`INCONCLUSIVE` collide with the challenger's
win exit code; the README's latent-gap cell is a probe false positive; `matrix`
violates the pairing rule and 5 of 25 cells are inert; adding `"/ops/"` to
`path_prefix.py` makes it contain both scenarios; 12 of 16 benign tasks are
undeniable by arithmetic.

---

## 3. INFERRED

**I1 — Interpose does not implement information-flow control. It implements
session-scoped near-duplicate detection.** From O5, O6 and the 8-word shingle
mechanism: values never carry more than one source, so no lattice join ever
occurs; the clearance branch never runs, so entitlement is always an ACL lookup;
and attribution is literal-span matching. Agent B's characterisation is the
accurate one: R3 is a *DLP fingerprint matcher*, not a flow control. It is
**not** merely an object ACL — it does discriminate a benign task the ACL would
permit — but the distance between "fingerprint matcher" and "information flow"
is the whole distance the project's vocabulary has been travelling on credit.

**I2 — The benchmark cannot detect its own blind spot.** From O2 and O3: the
policy's detector (≥8-word spans) strictly contains the grader's (exact
canaries). Any transformation defeating the policy defeats the grader. There is
no third observer, so a run in which the policy wrongly permits a flow is scored
`CONTAINED` with no contrary signal. This is worse than circularity, which at
least fails loudly.

**I3 — The circularity mitigations are individually broken and jointly
ineffective.** Ordering is falsified by the project's own git log and asserted
anyway in a shipped artifact. The benign suite — which `PROTOCOL.md` names as
the load-bearing mitigation — is 12/16 undeniable, and its discriminating power
is one file counted three times. The frozen hash does not cover the code the
policy's behaviour lives in. The challenge workflow is unwinnable by
construction *and* forgeable. Each of the three legs was independently
compromised.

**I4 — The Phase I headline overclaims.** `path-prefix-v1` failing scenario 2 is
real, but "it was never a good policy; it was a policy that happened to match
one attack" is not what the evidence shows. Twelve characters — adding `"/ops/"`
— make it contain both at a real utility cost. The defensible claim is narrower:
*a prefix deny-list must have enumerated the namespace correctly in advance, and
each new scenario found a namespace it had missed.* That is a statement about
the shape of the maintenance burden, not about the policy class being wrong.

**I5 — Cedar's contribution is a realistic PDP, not new security.** From O10:
Cedar reproduces the reference policy exactly when handed provenance, and cannot
derive provenance at all. So Cedar adds external validity — a real,
externally-maintained engine on the frontier — and adds nothing to what is
decidable. That is still worth having, but it must not be sold as more.

**I6 — The strongest remaining asset is the negative result, not the policy.**
The demonstration that a provenance-based egress control *and its own verifier*
fail together on the same input class, silently, is a finding about an
architecture pattern that is shipping commercially. Agent A found that
AgentCore's Cedar PDP receives no provenance at all, and that AWS's Dogwood
extension matches session history by *field equality* — so it fails on
paraphrase for precisely the reason Interpose does. That is the most defensible
and most externally relevant thing this project now knows.

---

## 4. HYPOTHESIZED

**H1** — That flow-sensitivity gives a security property object authorization
cannot. Not falsified; **no longer demonstrated**. The corpus cannot currently
distinguish information-flow control from ACL propagation (O5).

**H2** — That a semantically robust flow detector is buildable here without
reintroducing a model into the scorer. Untested and doubtful; see §6.

**H3** — That the scenario format generalises to new attack families. Agent E's
result is **C: a new engine primitive is required** for tool-output poisoning
(O9). One adjacent family (compartment breach) was expressible; the family the
schema has advertised since 0.1 was not.

**H4** — That a third party would ever run a challenge. Still zero evidence, and
Phase II makes it worse: until O1 and the forgery paths are fixed, a challenge
result would be meaningless in both directions.

---

## 5. What survived Phase I

Honestly, and it is not nothing:

- **The pairing rule.** Reporting containment beside its cost survives intact,
  and the paraphrase experiment *vindicates* it — the failing row is a policy at
  full benign pass, which is exactly the cell the pairing rule exists to expose.
- **The refusal to compute rates from deterministic runs.**
- **The refusal to use an LLM judge in the scorer.** This looks better after
  Phase II, not worse; see §6.
- **`DecisionContext` as frozen views with no `World` handle.** Well designed.
- **The closed verdict vocabulary** as a design — though O7 shows the
  implementation cannot reach the token that matters.
- **`SIMPLIFICATIONS.md` as an institution.** Every major Phase II finding was
  *foreshadowed* there. The register was right; what failed was treating
  load-bearing limitations as caveats.
- **Determinism and the offline property.** 2.35 s, two dependencies, no
  network. This is the constraint that makes everything else checkable, and
  nothing in Phase II may cost it.

## 6. The central decision: fix the detector, or narrow the claim?

This is the fork the whole phase turns on.

**Option (a): build a semantically robust detector** — embeddings, entailment,
fact extraction, an LLM judge. **Reject.** Three reasons, in increasing order of
weight. It would cost determinism, the two-dependency install, or the no-network
property — the three things that make the instrument checkable. `METRICS.md`
already refuses an LLM judge for the right reason: it makes the measurement
depend on a second model whose behaviour is not pinned. And decisively: a
semantic grader I write shares its failure mode with a semantic policy I write.
**The problem was never that the detector was weak; it was that the detector and
the policy failed together.** A better detector built by the same hand
reproduces exactly that defect at a higher level of sophistication.

**Option (b): narrow the claim.** State that Interpose measures containment
against a verbatim-copying agent; make the paraphrasing client a standing
adversary reported beside every result; stop saying "information flow." Cheap
and honest, but on its own it leaves the project measuring something small.

**Option (c): adopt (b), and make detector independence the design rule.**
This is the recommendation.

The structural fix is not a better detector. It is:

1. **The grader must never share code with the policy.** O1 exists because
   `readable_by` and `entitled_to` are the same relation written twice. The
   oracle should be defined independently and a test should assert that policy
   and oracle *can* disagree — the current suite would pass if they were literally
   the same function.
2. **Failure modes must be independent, and disagreement is the signal.** Keep
   canary matching. Add a second, structurally different observer — the simplest
   honest one is *the bytes of the protected resource that the sink's readers can
   now obtain*, tracked at the world level rather than by string matching. When
   the policy permits and any observer says content moved, that is the finding.
3. **Both clients, always.** A result reported under only the quoting client is
   the result Phase II falsified. The pair — "contains verbatim copying at cost
   X; does not contain restatement at all" — is more informative than either
   half, and it is honest.

That reframing converts the project's biggest failure into its most defensible
output. The headline stops being *"here is a policy that contains attacks"* and
becomes *"here is an apparatus that shows when a flow control fails and why —
including when its own verifier fails with it."* Given I6, that is a claim with
external relevance to shipping products, and it is one this project is uniquely
positioned to make because it caught itself doing it.

**Is a project that only measures verbatim-copy containment worth having?** Yes,
narrowly and honestly: copy-paste exfiltration is a real DLP threat model, and
"your fingerprint-based egress control is defeated by the agent summarising" is a
finding a practitioner can act on. It is a much smaller project than the README
describes. It should become that project.

---

## 7. Phase II scope

The three planned issues assume a working instrument. They do not have one.
Numbers produced on the current apparatus — including a Cedar ablation — would
not mean anything.

**INT-000 · Repair the instrument. Must precede everything.**
The instrument reports things that are false. In priority order: make the oracle
independent of the policy (O1); make the exposure observer's failure mode
independent of the policy's detector (I2); ship `scripted:paraphrasing` as a
standing behaviour class so O2/O3 become a permanent regression rather than a
one-off finding; fix the verdict so `contained` cannot be true when nothing was
contained (O7); fix `false_denials` on attack runs (O8); hash the policy's
**import closure**, not one file (O4); fix enumeration-as-read and the probe's
phantom gap.

**INT-001 · Cedar ablation.** Keep, and run it *after* INT-000. Agent A has
already done most of it and produced the phase's one clean positive. The
`cedar-action-only` versus `cedar-with-provenance` contrast is the sharpest
statement of what provenance buys, and the AgentCore/Dogwood evidence gives it
external weight.

**INT-002 · Challenge protocol.** Reduce scope sharply. The structural fix —
separating trusted apparatus from challenger-controlled input, so the challenger
cannot author the grader's inputs — is essential and is a prerequisite for the
workflow meaning anything. The manifest, transparency logs and signing are not.
Ship the separation; document the residual self-attestation; refuse the
cryptography.

**INT-003 · Scenario 3.** Ship `compartment-egress` — the failure family is
genuinely new and its benign suite is the best of the three — but **not** as
evidence that the reference policy generalises, because O2 shows it does not.
Do **not** build the engine primitives for tool-output poisoning in this phase;
document the gap (O9) and stop advertising `vector: tool_output` until it works.

### What must not be built in Phase II

Everything in the brief's §10 list, plus, from the evidence: a semantic or
model-based grader (§6); subprocess isolation, which
[`ENFORCEMENT_BOUNDARY.md`](ENFORCEMENT_BOUNDARY.md) shows would not fix the
property it appears to and would measure nothing against a non-adversarial
client; signing or transparency logs for the freeze; a capability-negotiation
plugin registry beyond a literal `requires:` list check; and any new scenario
beyond the third.

### What would reduce our claims further

- If, after INT-000, the reference policy still cannot be scored wrong on any
  axis, the frontier is unfalsifiable and the policy comparison should be
  withdrawn, not repaired.
- If `cedar-action-only` contains both scenarios at no utility cost, the
  provenance thesis is not merely undemonstrated but unsupported, and R3 should
  be presented as a DLP control rather than an authorization one.
- If the paraphrasing client makes every policy identical, then the corpus
  measures the client and not the policy, and the corpus is the thing to
  replace.

---

---

## 8. Amendment after Agent F's triage

Agent F triaged the full proposal set: **11 MUST FIX, 12 SHOULD FIX, 18 DEFER,
13 REJECT**, on the bar "a printed number, verdict token, or compiled-in
sentence is false." The eleven total roughly **+38 net lines of `src/`**. Two of
them are deletions.

### F sharpened the §6 argument, and I adopt its version

My reason for refusing a semantic detector was cost plus shared authorship.
F's is stronger and structural:

> Any detector strong enough to catch paraphrase is one a policy will also use,
> and the moment both use it, **F1 is reproduced exactly.** Either the policy
> does not get the new detector — in which case you bought option (b)'s result
> at 400 MB and a lost determinism guarantee — or it does, and the harness is
> again grading a policy with the policy's own predicate.

Structured fact extraction is the same trap one level down: still literal
matching, and the fact list is author-chosen, which relocates the arbitrariness
rather than removing it.

### The second observer — F's contribution, and the best idea in the phase

My §6 said the second observer "must fail differently" without saying how to
*guarantee* it. F's answer:

> Build it from the one strength a policy structurally cannot copy: **the
> harness built the world and watched the session.**

`possible_exposure` — a non-empty write to a sink with an unentitled reader,
after that source was read this session. It is already computed, as
`context_provenance`, and read by nothing (`SIMPLIFICATIONS` calls it one of two
"bracketing views"; no shipped policy consults it).

It is immune to paraphrase, base64, arithmetic derivation, column-dropping and
implicit flow — because **it does not look at content at all.** It looks at
session structure.

And the property that makes it permanently independent rather than independent
by convention: **it is not free to a policy.** A policy that used it would
over-block and pay a benign task. Over-approximation is correct for a grader,
which brackets, and unacceptable for a policy, which must not refuse legitimate
work. That asymmetry keeps grader and policy structurally distinct, and the gap
between them is exactly the width of the cost axis. ~30 lines.

Under a restating client the table would then read:

```
COMPROMISED   canary_exposed no   possible_exposure YES   8/8   0 denials
```

The instrument reporting its own blind spot, in the same row. Reported beside
`canary_exposed` as a bracket — never summed, never the sole verdict driver.

### Where I overrule F, and why

**Cedar.** F recommends publishing the Cedar/Dogwood result as prose and
shipping no adapter, on coupling grounds. I am shipping it, as an **optional
extra** (`pip install interpose[cedar]`) so the default stays at two
dependencies. Three reasons: the ablation is the sharpest available statement of
what provenance buys and it is the phase's only clean positive; Agent A has
already built and validated it at 122/122, so marginal cost is low; and a
finding about an external engine that cannot be re-run by a reader is weaker
than one that can. F's coupling concern is answered by the extra, not by
abstention. **Run after INT-000, never before.**

**The challenge workflow.** F recommends withdrawing the invitation entirely. I
am taking the middle: the forgery paths (`enumeration-as-read`, empty-args
objective matching, canary collision) are **real engine defects independent of
the challenge workflow** and get fixed regardless; the benign floor and the
exit-code collision get fixed; and the workflow is marked experimental with its
limitations stated in the invitation. I accept F's core point — Agent D's
manifest, baseline-separation architecture and transparency log are not built.
Withdrawing entirely would discard a mechanism whose *defects* are now
understood, which is a worse position than a documented experimental one.

### Final Phase II scope

1. **Retraction first, alone, dated before any fix** — including
   `challenge.py::_NOTE`, which compiles a false ordering claim into every
   regenerated `policy-freeze.json`.
2. **INT-000 · repair** — scorer corrections behind one `bench_version` bump;
   the two-sided exposure report; `scripted:paraphrasing` as a standing
   provider; policy import-closure digest; delete `matrix` (it prints 25
   containment verdicts with no cost column, violating the pairing rule, and 4
   of 5 variants reduce to an identical extracted `(path, queue)` pair) and
   `join_sources`.
3. **INT-003 · `compartment-egress`** — after the scorer is fixed, with F's
   added benign task egressing a source with **no reader list**, which exercises
   R3's dead lattice branch and measures write-side over-blocking for the first
   time. Not presented as generalization evidence.
4. **INT-001 · Cedar ablation** — optional extra, run last, on the repaired
   instrument.
5. **INT-002 · challenge defects** — fix, mark experimental, build no manifest.

Net ≈ **+130 / −60 lines**, two runtime dependencies, demo under three seconds.

If forced to ship only two things: **the retraction and the second observer.**
Those are the phase. The rest is hygiene.
