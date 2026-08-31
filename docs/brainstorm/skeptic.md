# Agent E — Adversarial Skeptic

**Verdict: the vision should not be built. A small, unglamorous fraction of it should, and it is not a cyber range, not a persistent organization, and not a leaderboard. The proposed V0 money-shot demo is, as currently specified, circular — and I can show you the paper that already ran it and got a degenerate result.**

I verified the load-bearing claims below against source rather than trusting the recon digest. Two digest claims turned out to be wrong or overstated; I flag both.

---

## 1. The tautology problem. This is the real one.

The V0 demo: a scenario declares `payroll.csv` protected. Policy A permits `read_internal_file(*)`. Policy B denies it for that path. Run 1 exfiltrates, run 2 blocks. Applause.

**Steelmanned at full strength:** the scenario author chose the asset, the tool, the attack path, and both policies. Policy B is written *with knowledge of the exact attack it will face*. The demo therefore has the epistemic content of `assert deny(payroll) == DENY`. It is not a security finding, it is an integration test proving the harness wired its own policy decision point correctly. Worse, it is a test whose expected value is fixed at authoring time, so it can never surprise anyone — and a measurement that cannot surprise you is not a measurement.

This is not a hypothetical. **ContainmentBench (arXiv 2607.23999, Lan et al., July 2026 — verified) ran exactly this experiment across 7 policy conditions and reports that _no committed policy violations occurred under the tested defenses_.** The terminal containment metric saturated at zero. Their entire contribution had to relocate into intermediate trace behavior because the endpoint number was uninformative by construction. Someone already ran fsociety's money shot and the money shot paid nothing.

**Is it fatal?** The demo is fatal. The project is survivable, but only with a specific design change, and only by measuring the quantity that is *not* fixed at authoring time.

What the author's pen controls: whether Policy B blocks the attack. That is determined. What the author's pen does **not** control:

1. **How much of the benign workload Policy B destroys.** The author picks the rule; the false-deny rate that rule inflicts across N legitimate tasks is an empirical property they did not choose and usually cannot predict. The 40-benchmark survey (arXiv 2605.16282 — verified, W = 0.10, p = 0.94) found only **1 of 40** benchmarks measures over-refusal at all. This is the non-tautological half and it is nearly virgin ground.
2. **Attacks the policy author did not imagine.** The circularity dissolves the moment the attack corpus is authored *after* the policy is frozen, by someone else, against a held-out split.
3. **Whether two engines agree.** Same declared intent in Cedar vs OPA vs a Python predicate — do they render the same decisions? Differential testing between authorization engines is genuinely open (verified gap: no authorization engine has any adversarial benchmark).

**Required design change, stated precisely.** The policy must be published and content-hashed *before* the attack set that scores it exists, with a held-out attack split; and **the primary reported result must always be the ordered pair (containment, benign false-deny). The harness must refuse to emit containment alone.** If you cannot commit to that protocol, you are shipping an assertion with a terminal aesthetic.

There is a cleaner way to say what is wrong. The demo proves a *conditional*: **if** a protection is expressible as a policy predicate, **then** enforcement holds regardless of whether the model was fooled. Nobody disputes the consequent. The open question is the **antecedent** — can real protections be expressed as predicates without destroying utility? That is where CaMeL's ~33% task loss lives, uncurve-mapped by anyone. **The project is currently designed to dramatize the consequent when the only unsolved part is the antecedent.**

Note the commercial consequence: the compelling demo is the circular one, and the honest measurement is a boring two-column table. That tension will pull this project toward dishonesty every single week.

---

## 2. Fake differentiation. The objection is roughly 80% correct.

"Untrusted input must not escalate privilege" is Anderson's reference monitor (1972), Saltzer & Schroeder's least privilege and complete mediation (1975), and Biba integrity (1977). This is not my framing — **arXiv 2606.26479 (verified) explicitly describes the five out-of-band defenses (CaMeL, FIDES, Progent, RTBAS, FORGE) as implementations of "classical integrity protection (Biba), reference monitoring, and least privilege."** The field already knows it is doing 1970s security theory.

It has also shipped. AWS Bedrock AgentCore Policy went GA 3 March 2026 with Cedar evaluating every tool call in the gateway, deny-by-default. Microsoft's FIDES ships in `agent_framework.security`. Auth0 ships RFC 8693 downscoping. OWASP already assigned it a number (ASI03, Agent Identity & Privilege Abuse). And the "model behavior vs system authorization" distinction is published twice by name: ContainmentBench, and **Siu/He/Montgomery/Wang/Wang/Song, "Agent Security Needs Redefinition through a Holistic Framework" (arXiv 2607.22024 — verified, Dawn Song group), which defines Source Authorization / Task Alignment / Action Alignment / Data Isolation and states snapshot benchmarks are "structurally incapable of evaluating Data Isolation," naming AgentDojo and WASP.**

Now the part the digest got wrong, which matters because it is the project's best remaining claim to novelty. **I checked AgentDojo's source directly.** `task_suite.py` computes security via `task.security(output_text, pre_environment, task_environment)` — a security function over pre- and post- environment state, with a `security_from_traces` variant taking the function-call stack trace. **AgentDojo already scores "the system got compromised," not "the model complied."** So the sentence "existing benchmarks only measure whether the model got fooled" is false for the single most-cited benchmark in the space, and anyone senior will know it. Do not write it.

What *does* survive verification: `DEFENSES = ["tool_filter", "transformers_pi_detector", "spotlighting_with_delimiting", "repeat_user_prompt"]` — confirmed verbatim. Four defenses, none an authorization layer. **The real gap is not conceptual and not metric. It is that no harness ships an authorization layer as a first-class swappable defense with a false-deny measurement.** That is a plumbing gap worth a few hundred lines, not a philosophy worth a movement.

---

## 3. The deterministic provider makes the AI framing collapse.

A scripted agent that always follows the injection tells you nothing about any model. The honest claim is narrow and I think it is actually the right one: *"Under a worst-case agent fully controlled by the attacker, the authorization layer contained the attack."* That is a legitimate lower bound and it matches how security engineers reason — assume the component is owned.

But follow it through. **If you assume the agent is 100% attacker-controlled, you no longer need an LLM in the loop at all.** What you have built is a test suite that exercises an authorization layer with a hostile client. That is a normal, respectable, unremarkable security test — and the entire "AI agent security benchmark" positioning evaporates. This is the honest consequence and the project should either accept it or drop the fake provider as the headline path.

Overclaims to ban in writing, permanently: any ASR number, any sentence beginning "LLMs are vulnerable to," any leaderboard, and any implication that the fake provider's compliance rate resembles a real model's.

---

## 4. Architecture astronautics: eight products, one person.

The stated ambition is cyber range + adversary simulator + agent security benchmark + IR laboratory + security observability + educational playground + CTF framework + autonomous-agent research environment. Every one has a funded incumbent, and the graveyard is the argument: **DetectionLab is dead since 2023-01-01 with ~5,000 stars and no successor. Splunk deprecated local Attack Range. KYPO ended development. Invariant Labs was acquired by Snyk and hosted Explorer shut down January 2026** — and Invariant is the one team that had *both* a policy DSL and a trace format, i.e. precisely this bundle. Institutions and funded teams could not sustain these. A solo founder will not.

**"Persistent" is the single worst word in the pitch, and it contradicts "reproducible."** A benchmark requires pinned, deterministic, resettable state. A persistent simulated organization accumulates state and drifts. These are opposite requirements and no amount of engineering reconciles them. Pick one, now, in writing.

Weight budget, unproven and load-bearing: GOAD needs 24GB+; TheAgentCompany wants 30GB+ disk and was baselined on a t3.2xlarge. Nobody has shown a credible enterprise under 16GB. "Locally runnable persistent organization" is a hypothesis, not a plan.

**Zero-utility feature, cut it:** the "slightly unsettling, information-dense" terminal aesthetic. A benchmark's output artifact is a JSON file and a CI exit code. A bespoke TUI is a permanent maintenance tax, an accessibility problem, and it actively repels the two audiences you need — lab researchers and enterprise security engineers.

---

## 5. Legal, safety, and the disqualifying conflict of interest

Publishing intentionally vulnerable material is fine and well-trodden (Juice Shop, DVWA); that is not the risk. The real ones:

- **ContainmentBench is CC BY-NC-ND 4.0 (verified).** Their trace schema and scenario specs are no-derivatives. Do not "take inspiration from" that 12-field summary format. This is a real trap.
- **A published "reference authorization policy" is a security recommendation.** If anyone deploys it and it fails, that is on you. Label every policy illustrative, non-production, explicitly non-warranted.
- **The vendor-neutrality claim is not credible and cannot be made credible.** The creator runs an AI-security company. MITRE — two decades of institutional standing, owner of ATT&CK — watched participation collapse from ~30 vendors to 11, losing Microsoft, SentinelOne and Palo Alto. A solo founder with a commercial position in the category has *less* standing than MITRE, not more. **The head-to-head vendor-scoring ambition is dead on arrival. Kill it now, position as a testbed, and the conflict becomes survivable.**

---

## 6. Why they close the tab

**A lab researcher:** not in `inspect_evals`, so it will not be run. No model numbers, so nothing citable. Thesis already published twice (2607.23999, 2607.22024), so the related-work section ends the review. It is the 41st benchmark in a field the survey shows has *no ranking concordance*.

**A security engineer:** "we already put authz outside the model." No Cedar or OPA adapter, so it does not map to production. Simulated Python tools, not their stack. And the name — **verified: `pip install fsociety` today installs "A Modular Penetration Testing Framework," v3.2.9, and Manisso/fsociety has ~12.3k stars.** The PyPI namespace is taken, the GitHub SEO is unwinnable, and the Mr. Robot reference reads as 2017 script-kiddie branding to the exact buyers you need. This is a free, five-minute fix that becomes impossible after launch.

---

## 7. What narrow version survives

Not "none." Something real survives, but it is a library, not a world.

**A differential over-blocking harness for tool-call authorization policies.**

- `pytest`-shaped, not a range, not a leaderboard, not persistent. Python, small deps, as specified.
- Fix the tool surface at the five tools already listed. Never grow it.
- Ship **N benign user tasks with ground-truth required tool calls**, plus a held-out attack corpus.
- The unit under test is a **policy**, behind a deliberately boring interface — mirror AWS's framing rather than inventing an abstraction nobody will implement:
  `decide(principal, action, resource, args, provenance) -> Allow | Deny`
- **Always report the pair.** `(containment_on_heldout_attacks, false_deny_rate_on_benign_tasks)`. The CLI must refuse to print containment alone. This is the anti-tautology mechanism and it is also the genuine white space — 1 of 40 benchmarks measures over-refusal.
- **Frozen-policy protocol:** policies published and content-hashed before the attack set that scores them exists. Without this you have an assertion.
- Ship **Cedar and OPA adapters**. Both open source and embeddable. This is the verified empty slot — no authorization engine has ever been adversarially benchmarked — and adapters make it immediately useful to people who already run those engines.
- Deterministic provider is the default, labeled honestly as "worst-case fully-compromised agent." Real models optional, off by default, never in CI.
- Distribution: ship as an `inspect_evals`-compatible eval. Building a competing runner is the fastest route to being ignored.

Everything else is cut: persistence, the TUI, CTF, IR, observability, adversary simulation, containers, multi-host, the enterprise. Scope: one person, a few weeks.

**Do the frozen-policy + paired-metric protocol document before writing any code.** If that protocol cannot be committed to, the project is an assertion with good typography and should not exist.

And rename it. `fsociety` is taken on PyPI and on GitHub, in this exact vertical.

---

## Where I expect to disagree with the other agents

I have not read the other memos; role attributions below are ASSUMPTIONS from the brief.

- **The visionary/maximalist agent (likely A):** will defend the persistent organization and the multi-phase roadmap. My direct conflict: *persistent* and *reproducible* are mutually exclusive requirements, and I claim the roadmap is eight dead products stacked (DetectionLab, KYPO, Splunk local, Invariant/Explorer all died doing less). They will call this failure of nerve. I call it the DetectionLab README.
- **The benchmark/research agent (likely B):** will want scenario count, model coverage, and a leaderboard. I claim the leaderboard is unbuildable by this author (MITRE 30→11) and that a 41st benchmark worsens a field with W = 0.10 concordance. We will also disagree factually: if they assert existing benchmarks only measure "the model got fooled," I have AgentDojo's `security(output, pre_env, post_env)` signature saying otherwise.
- **The architect agent (likely C):** will propose principals, credentials, delegation, provenance tracking, and a causal trace format. I claim every one of those is already published (FORGE's reference-monitor/Datalog architecture; HCP's principal binding and deny-path audit) and that provenance-tracking is where a solo project dies. Fight me on scope, not on whether it would be nice.
- **The security/threat-model agent (likely D):** likely my closest ally on containment and dangerous defaults, but I expect conflict on the reference policy — I want it labeled non-production and non-warranted; a security purist will want it to be *good*, which invites deployment and liability.
- **The educator/community agent (likely F):** will want the CTF framework, the aesthetic, and the Mr. Robot identity. Head-on collision: I want the TUI cut entirely and the name changed before launch. The aesthetic is negative-value for the only two audiences that matter.
- **The product/DX agent (likely G):** will want the dramatic before/after demo as the README hero. That demo is the circular one. We will disagree about whether the honest two-column table can carry a launch. My position: if it cannot, that is information about the project, not about the table.
