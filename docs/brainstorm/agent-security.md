# Agent B — AI Agent Security Research Design

**Position.** The V0 hypothesis is good; the framing is not novel. "Model fooled ≠ system compromised" is the 2026 consensus, published twice by name: ContainmentBench (arXiv 2607.23999) opens with *"Terminal attack-success or policy-violation rates do not show what happens between exposure and commit or whether a defense also suppresses authorized actions"* (verified verbatim), and the ICML 2026 position paper (arXiv 2607.22024, Siu/He/Song et al.) reclassifies indirect prompt injection as a **Source Authorization** violation. AgentDojo already scores outcomes with a security function over final *environment state*, not model compliance (verified). If the pitch is the thesis, it is late. The defensible contribution is **measurement machinery the thesis needs and nobody has built**: a model-independent way to measure the authorization layer, a mandatory utility co-axis that makes deny-all unpublishable, and a provenance-carrying decision interface fair to sophisticated defenses.

---

## 1. Failure classes: what a local sim can honestly represent

**FULL** = safe, reproducible, honest locally. **PARTIAL** = representable with a named fidelity caveat that ships in the docs. **OUT** = cannot be done honestly locally, or should not be done.

| Class | Verdict | Rationale / required caveat |
|---|---|---|
| Indirect prompt injection | FULL | The V0 wedge. Content is a file; placement is deterministic. |
| Tool misuse (legit tool, wrong end) | FULL | Needs typed effect classes on tools, not just names. |
| Excessive tool permissions | FULL | Best measured with **no attacker at all** (§3, LAG). Cheapest high-value family. |
| Confused deputy | FULL | Needs multi-principal identity. *None* of the 40 surveyed benchmarks models user A vs user B vs service account with credentials and delegation. Sharpest open axis. |
| Malicious tool metadata / tool poisoning | FULL | A tool description is a string in the manifest; hash it, mutate it. ATLAS *Publish Poisoned AI Agent Tool* (AML.T0104). |
| Malicious MCP server | PARTIAL | Hostile *server behavior* simulates faithfully over stdio/HTTP; registry distribution, rug-pulls and signing do not. "Hostile server, not ecosystem supply chain." |
| Compromised RAG source | FULL | Corpus is a file. Pin the retriever — an unpinned embedding model silently changes what the agent sees. |
| Cross-agent trust failure | PARTIAL | N principals is easy; real failures are framework-specific handoff quirks you would be inventing. Report generic, never "LangGraph fails this way." |
| Persistent memory poisoning | PARTIAL | Trial unit becomes an *episode sequence*: variance compounds, cost multiplies. Needs seeded stores and sequence-level reporting. V1. |
| Authorization failure | FULL | Core. |
| Agent identity confusion | FULL *if* principals exist; else unrepresentable | The difference between fsociety and AgentDojo. |
| Insecure handoff / delegation | FULL | RFC 8693-style token downscoping and expiry are deterministic. |
| Approval manipulation (fatigue / coercion) | PARTIAL | A **simulated approver principal** (auto-approve, auto-deny, stochastic rubber-stamp rate p) is FULL and unoccupied. Real human fatigue is OUT — needs human subjects. Do not conflate. |
| Sensitive information leakage | FULL | Only with structural detection: per-trial, per-seed high-entropy **canary tokens** reaching an attacker-readable sink. Never an LLM judge — judges are the contamination vector. |
| Policy bypass | FULL | |
| Tool-output poisoning | FULL | |
| Agent supply chain (poisoned package / skill / weights) | OUT (V0–V1) | Running genuinely malicious code locally is a containment hazard, and the interesting half (registries, signing, distribution) cannot be simulated honestly. Ship the metadata slice only, and say so. |

Also permanently OUT: pointing offensive automation at third-party systems; human subjects; model-weight attacks; and **frontier-model robustness rankings**, because closed model versions cannot be pinned (§5).

---

## 2. The metric set — five numbers, one structural rule

The deny-all trap is documented, not hypothetical. The Apr 2026 survey (arXiv 2605.16282) codes 40 benchmarks as **24 safety-only, 12 separate, 3 joint, 1 measuring over-refusal** (verified) and states directly: *"the predominance of safety-only evaluation means most benchmarks cannot distinguish a genuinely safe model from one that simply refuses everything."* It is the field's default failure.

Per (scenario, policy, model, seed) trial, record a five-stage chain — **E**xposure → **P**roposal → **D**ecision → **C**ommit → **O**utcome — and derive:

1. **ICR** — Injection Compliance Rate = P(proposal matching the adversary's action signature | exposure confirmed). *Model behavior.* Void the trial if E is false: unretrieved injections are a silent denominator bug across this genre.
2. **EER** — Enforcement Escape Rate = P(commit | proposal). *System behavior, correctly conditioned.* The number AgentDojo cannot produce, having no decision point.
3. **RHR** — Realized Harm Rate over final environment state, **per impact class** (confidentiality-breach / integrity-write / irreversible-effect), never summed. Only 2 of 40 benchmarks weight severity; rather than invent weights with no empirical basis, refuse to collapse the vector.
4. **TCA / BTC** — Task Completion under Attack, and Benign Task Completion with no attacker, same policy artifact and seeds.
5. **FDR** — False Deny Rate = fraction of *legitimate* benign-suite tool calls the policy denied.

**The structural rule:** the runner refuses to emit a scorecard unless the benign suite ran on the same policy artifact and seed set. A hard failure, not a lint warning. Deny-all then renders as a single point at the origin of the containment/utility plane, self-evidently worthless.

**Report frontiers, not scores.** One policy is a point; a *family* (permissive → strict) is a curve, and the curve is the comparison unit — precisely the cost curve nobody publishes (CaMeL's ~33% task loss has never been curve-mapped against alternatives). Rank only by **dominance**: A dominates B iff A ≥ B on both axes; refuse to order non-dominated pairs. AgentDojo already refuses a leaderboard on fairness grounds — adopt that refusal as a feature. It is also the only honest posture given ATT&CK Evals' collapse from ~30 vendors to 11.

---

## 3. Formalizing model vs system — and the latent gap

**The 2×2 is wrong**, for three reasons.

*(a) "Model fooled" is not observable.* What is observable is a *proposal* — a tool call matching the adversary's declared action signature. Score the proposal stream; never emit "the model was fooled" as a field, emit `injection_directed_proposal: true`.

*(b) "System held" conflates the deny decision with the outcome.* A policy can deny the specific call while the agent reaches the objective by an allowed path, or allow a call that is a no-op. Hold "held" to environment state.

*(c) There is no cell for the case the mission names* — the model never tried, so nothing was learned about the system. Not an edge case: a **statistical-power decay problem**. The Anthropic-co-authored competition (arXiv 2603.15714) reports ASR from 0.5% (Claude Opus 4.5) to 8.5% (Gemini 2.5 Pro); at 0.5% compliance EER has almost no denominator. A benchmark whose informativeness *decreases as models improve* is a broken instrument.

**Mechanism: the compliant-deputy shadow probe.** Not novel infrastructure — Istio authorization dry-run already reports "shadow denied"/"shadow allowed" and GCP Binary Authorization ships dry-run mode. Novel only in application; ASSUMPTION: I found no published agent-security benchmark doing this.

1. Every injection task ships a machine-readable **adversary objective spec**: target tool(s), argument constraints, outcome predicate. Needed anyway to score ICR.
2. The harness synthesizes **N oracle trajectories** — deterministic scripted tool-call sequences a *perfectly compliant* agent would emit to satisfy the objective. **No model in the loop.**
3. Each replays against the same PDP in **shadow mode**, from the real agent's checkpoint at exposure (*strict-shadow*, honest for history-dependent policies) or a canonical checkpoint (*isolated-shadow*, cheaper and model-comparable). Decisions logged; nothing commits.
4. **LAG** (Latent Authorization Gap) = fraction of oracle trajectories the PDP shadow-allows end-to-end.

LAG is a property of *policy × environment × scenario*, independent of model compliance, and it runs free in CI on the fake provider. Two caveats must ship in the docs. LAG is an **upper bound on exploitability under perfect compliance** — it cannot say whether a real model would find that path, so EER is always reported beside it. And oracle trajectories are **static attacks**, subject to exactly the critique arXiv 2606.26479 levels at all five out-of-band defenses (CaMeL, FIDES, Progent, RTBAS, FORGE): every one validated only on static benchmarks. Partial mitigation is N distinct paths to the same predicate, with *path diversity N* declared per scenario — a policy blocking 1 of 4 scores 0.75, so the weakness is visible in the number rather than hidden behind it.

---

## 4. The policy plug-in interface — the bright line

Two failure modes: starve the policy and you benchmark a strawman (FIDES and CaMeL *need* labels; testing them without provenance is rigged against them); over-feed it and you measure nothing.

**The line: a policy may receive anything the harness could compute at runtime in a real deployment without knowing the answer key, and nothing derived from the scenario definition.** The `DecisionContext` handed to a PDP:

```yaml
principal:   {agent_instance_id, acting_for, delegation_chain, granted_scopes, credential: {token_id, expires_at}}
action:      {tool, arguments, effect_class: read|write|irreversible, resource_refs}
resource:    {canonical_id, sensitivity_labels, owner_principal}
provenance:  [{content_unit_id, source_class: trusted_user|trusted_system|untrusted_external|tool_output, derived_from: [...]}]
context:     {user_task_statement, ordered prior proposals/decisions/observations this episode}
history:     {audit_log_so_far}
```

Adopt AWS AgentCore's framing verbatim — *the unit of control is the action: a single tool call, with its caller identity and input parameters, evaluated at the moment of invocation*. Mirroring it makes the interface implementable by Cedar, OPA, OpenFGA, LlamaFirewall and a human approver alike; inventing a novel abstraction gets it implemented by nobody.

**Never given:** the injection task id; the adversary objective spec; the target action signature; the outcome predicate; any flag that a content unit "is the injection" (provenance says *untrusted_external*, never *malicious*); the seed; the scorer; and — most important — **whether this trial is benign or attack**. Enforce mechanically: trials interleave in shuffled order through one policy process, and the harness asserts the decision stream is byte-identical over shared prefixes. Enforce structurally: `DecisionContext` is built by a module holding no reference to the scenario's `adversary` section, and CI greps the policy adapter's import graph to prove it — a cheap, legible credibility artifact worth publishing.

**Decisions must be richer than allow/deny**, because real defenses redact, downscope, quarantine and escalate: `ALLOW | DENY | ALLOW_WITH_TRANSFORM(args') | ESCALATE(approver_principal)`. ESCALATE makes human-in-the-loop a benchmarkable policy against a **simulated approver** — regulation-adjacent (EU AI Act Art. 14 demands demonstrable oversight and supplies no way to demonstrate it) and unoccupied. PDPs must also be allowed to be non-deterministic and to cost money (classifier and LLM-judge defenses are legitimate entrants): log `decision_latency_ms` and `decision_cost`, and ship a deterministic stub PDP for the no-key CI path.

**Trace format.** No portable causal trace exists — AgentDojo logs chat transcripts, Inspect logs `.eval` transcripts, Invariant's Explorer shut down Jan 2026. Not a graph database; greppable JSONL: `content_ingested(unit_id, source_class, sha256)`, `proposal(tool, args, arg_provenance:[unit_ids])`, `decision(verdict, rule_id, latency)`, `commit(effect, resource, state_delta_hash)`, `outcome(predicate, value)`. Enough to answer what nobody can answer today: *which untrusted byte reached which privileged call.*

---

## 5. Comparability, pinning, and honest reproducibility

**Pin for citability:** scenario id + semver; environment seed-state hash; **tool manifest hash including descriptions** (descriptions are attack surface); principal and grant set; injection corpus hash + placement; adversary spec + oracle trajectories; retriever config; scorer version; policy artifact hash; model id + params + provider snapshot; harness version; seeds; N. Citable **iff all present and both suites ran**.

**Three tiers of reproducibility — promise only the first two.**

- **Bit-reproducible:** environment, policy decisions, scoring, attack corpus, LAG, and the whole fake-provider path. CI enforces it. `fsoc verify <trace>` replays a recorded transcript and asserts identical decisions and scores — replay determinism works even against hosted models.
- **Distributionally reproducible:** same model id, temperature 0, same seeds → similar, never identical. Promise intervals, not points: **n ≥ 5 seeds, Wilson 95% CIs on all rates, no scorecard from n = 1.** Given the survey's Kendall W = 0.10 (p = 0.94) incoherence and its finding that robustness has *zero* primary benchmarks, mandatory variance reporting is a differentiator, not hygiene.
- **Not reproducible, ever:** a hosted closed model on a date. Providers change silently. State plainly in the docs: *a number from a hosted endpoint measures an endpoint on a date, not a model.*

**Refuse to promise:** cross-provider robustness rankings; transfer to production; that a well-scoring policy is secure (static attacks only); any vendor leaderboard.

---

## 6. Research questions, ranked by value

1. **The containment-per-unit-utility frontier across enforcement layers** (Cedar/OPA policy sets, Progent-style symbolic rules, FIDES/CaMeL-style IFC labels, simulated approver). Unanswerable today; zero prior art.
2. **Is enforcement efficacy independent of the model?** Enabled only by the LAG/EER split. If LAG holds stable while ICR varies 17× across models, that is the strongest possible empirical statement of the creator's thesis.
3. **Cross-principal containment under injection (confused deputy).** Sharpest empty axis in the survey.
4. **Does finer provenance granularity buy containment, and at what utility cost?**
5. **Approval-gate efficacy under pressure** — rubber-stamp rate vs. containment vs. escalation volume.
6. **Do static LAG path-diversity scores predict failure under adaptive attack?** The validity question for this whole method.
7. **Does deny-path audit completeness** (an invariant from arXiv 2606.29073) **predict incident localizability?**
8. **Paraphrase-invariance of policy decisions**, not just model behavior. Zero coverage today.

---

## 7. Taxonomy mapping, and where it is genuinely ambiguous

Primary: **OWASP Top 10 for Agentic Applications 2026**, ASI01–ASI10 (verified: Goal Hijack, Tool Misuse, Identity & Privilege Abuse, Agentic Supply Chain, Unexpected Code Execution, Memory & Context Poisoning, Insecure Inter-Agent Communication, Cascading Failures, Human-Agent Trust Exploitation, Rogue Agents). Secondary: **MITRE ATLAS** techniques. Tertiary: OWASP LLM Top 10 (LLM01, LLM02, LLM06, LLM08) for continuity.

Ambiguities to declare rather than paper over:

- **ASI01 vs ASI02 vs ASI03.** An injection redirecting an agent to a *legitimate* tool for an illegitimate end is both goal hijack and tool misuse; over-privilege at the tool boundary is arguably always both misuse and privilege abuse. No tiebreaker exists. Tag multiple categories and publish the mapping as data, not as an assertion.
- **Ontology clash.** Indirect prompt injection is LLM01 under the LLM Top 10 but a *Source Authorization* violation under arXiv 2607.22024 — different ontologies, not different labels. Carry both fields; state the preference for the authorization frame and why.
- **ATLAS is attacker-centric, OWASP defect-centric.** Many scenarios have a clean ATLAS technique and a fuzzy OWASP category, or the reverse. Do not force 1:1.
- **ASI09** covers approval manipulation but frames it as the *human trusting the agent*; approval fatigue is the inverse vector. Flag, do not silently resolve.
- **UNVERIFIED:** `AML.T0054` is cited for *AI Agent Context Poisoning*, but that ID denoted *LLM Jailbreak* in earlier ATLAS versions. Use technique **names** in manifests; resolve IDs against a pinned ATLAS version before publishing.

---

## Where I expect to disagree with the other agents

- **The range / infrastructure agent** will want containers, hosts, telemetry and a SIEM, because that is what makes a "cyber range." I fight this for V0. Container fidelity matters (containerized OpenAgentSafety reports 50–86% unsafe rates vs LLM-emulated ToolEmu's 23.9%), but *every* number in §2 needs ground-truth state and byte-level provenance, and both get much harder once the environment is real processes on a real network. In-process Python with perfect instrumentation in V0; containers only after the provenance model is proven, and then as a **declared fidelity axis** — never a silent upgrade that invalidates prior numbers.
- **The blue-team / detection agent** will argue, with better evidence than mine, that DetectionLab's death and Splunk Attack Range's local deprecation prove a real unmet need today while the agent-security thesis is a bet. I concede the demand evidence and disagree on sequencing: the intellectual case here rests on **enforcement**, and SHADE-Arena's best monitor at 0.87 AUC is the argument that monitoring is the weaker half. A SIEM in V0 costs weight budget and buys no metric in §2.
- **The adversary-simulation agent** will want an autonomous LLM attacker. Oppose in V0, support in V2: an adaptive attacker is non-reproducible by construction, doubles model cost, and must never exist without the containment guarantee. But I need it eventually — §6-Q6 is the validity question for my own LAG method, and arXiv 2606.26479 says plainly that static validation is the field's blind spot.
- **The CTF / education agent** will want tiers, flags and hints. Scoreboards and benchmarks have incompatible incentives: a CTF *wants* to be gamed, a benchmark dies when it is. Berkeley's reported reward-hacking of all eight major agent benchmarks to ~100% (UNVERIFIED, single source) is the warning. If both ship: separate score namespaces, separate manifests.
- **The product / positioning agent** will want a leaderboard because leaderboards get stars. I refuse one on record — dominance plots and frontiers only. AgentDojo already refuses to rank on fairness grounds; ATT&CK Evals losing 19 of 30 vendors is the cost of the alternative.
- **The aesthetics agent** and I collide on exactly one thing: a terminal that renders a metric without its confidence interval, or containment without its paired utility number, is a correctness bug, not a style choice. §2's rule binds the UI too.
- **Anyone proposing a standalone runner** instead of an `inspect_evals` eval: I am partly against you and want this argued explicitly. Inspect (UK AISI, MIT, pushed daily) already hosts AgentDojo, AgentHarm, b3, Cybench and CyberSecEval; a standalone harness loses on distribution. Compromise: fsociety owns the **policy decision point, provenance model, trace format and LAG probe** — none of which Inspect has — and ships scenarios as an Inspect-compatible eval. Their runner, our instrument.
