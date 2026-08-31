# Curriculum design — Agent G

**Status note:** the repo is empty (no commits as of writing). This is designed against the *proposed* V0, not shipped code.

**Thesis.** A learning agenda that exists as a parallel artifact — a syllabus, a topic roadmap, a "seasons" arc — is visible to practitioners and discounts the project. The only mechanism that survives a hostile senior reader is one where the learning artifact is *load-bearing for the project's scientific claims*. Build the thing that forces the concept; record the concept you hid; make that record the document that limits what the benchmark may claim. Then the study log is not a study log — it is the validity section, and every real measurement instrument has one.

Three arguments, made hard: (1) V0 teaches far less "cybersecurity" than the creator likely thinks, and admitting that is what makes the rest honest; (2) the domains that *do* get forced are forced by exactly the features that make the product defensible — which is the test that the curriculum isn't fake; (3) assembly, C memory corruption, and reverse engineering have **no honest home here**.

---

## 1. The rule, and what it excludes

A topic earns a place only when a concrete capability is blocked without it. Applied strictly, that kills roughly a third of the stated domain list *inside this project*. That is the correct outcome. A range that grows a binary-exploitation track to justify learning `gdb` has stopped being a measurement instrument.

## 2. What V0 honestly teaches

- **The reference monitor as an object.** Anderson's 1972 properties — complete mediation, tamper-proofness, verifiability — become concrete once you must decide whether the check sits on *every* path to the tool. V0 will fail two of the three (SIMPL-0001); discovering that yourself is the lesson.
- **Authorization over arguments, not names.** The gap between AgentDojo's `tool_filter` (pre-selecting tool *names*) and Progent-style rules over `(tool, arguments, context)` is the most transferable idea in the wedge. Saltzer & Schroeder's fail-safe defaults and least privilege stop being slogans when you write a `deny` default and watch benign tasks break.
- **The confused deputy, by name.** Indirect prompt injection *is* Hardy's 1988 confused deputy: a privileged component acting on an unprivileged party's intent.
- **Evaluation methodology.** Seeds, fixtures, deterministic providers, separating "the model complied" from "the environment changed." Honestly the *largest* skill V0 imparts — and it is a science skill, not a security skill. The fake provider is the best teaching object in the repo: writing fixed adversarial completions forces you to state in code exactly what model behaviour you assume, which is where benchmark dishonesty usually hides.
- **Audit-record design.** Which fields make an event forensically useful; why a decision record needs rule identity and reason, not just allow/deny.
- **Threat modelling** — but only if `docs/THREAT_MODEL.md` is written. Otherwise V0 teaches scenario authoring, which is not the same thing.

What V0 does **not** teach: nothing about Linux, processes, syscalls, or namespaces (the sandbox is a Python dict); nothing about TCP/IP, DNS, or HTTP (no wire exists); nothing about databases; no cryptography; no OS internals; no memory, C, assembly, or RE — zero, not "a little"; no real identity protocols. And critically: **writing detections against a log schema you designed teaches log design, not detection engineering.**

## 3. The progression — feature forces concept

| Stage | Capability needed | Why it's blocked without the concepts | Concepts forced |
|---|---|---|---|
| **0 — V0** | Scenario, policy decision point, JSONL trace, canary asset, fake provider | The wedge itself | Reference monitor, deny-by-default, subject/action/resource/context, taint labels, canary tokens, audit records, determinism, threat modelling |
| **1 — Out-of-process mediation** | PDP must not live in the agent's address space | The obvious attack on V0: "your policy layer is a function call the agent could skip — nothing is *enforced*, you chose not to call it." Claiming containment rather than convention requires a real boundary | Processes, fds, uid/gid, file permissions, unix sockets/IPC, serialization as trust boundary, rlimits, `shell=True`, seccomp basics |
| **2 — Tools become real services** | Fidelity | Containerized OpenAgentSafety reports 50–86% unsafe rates vs LLM-emulated ToolEmu's 23.9%; Li et al. (2605.16282) find 34/40 benchmarks sandboxed and call the effect "security by incompetence." Numbers from mocks aren't defensible | HTTP semantics, API design, SQL + parameterized queries, row-level security, TLS, container images/namespaces/cgroups, `--privileged` as game over, compose networking, DNS |
| **3 — Egress boundary** | Prove data *did not leave* | Containment of exfiltration is unclaimable without controlling and observing a network boundary. DNS exfiltration is the canonical case, and the reason DNS gets learned properly rather than skimmed | Egress proxying, allow-listed destinations, DNS records/tunnelling, TLS-interception tradeoffs, covert channels |
| **4 — Multi-principal identity** | The sharpest open axis in the recon: no benchmark instantiates user A vs user B vs service account vs agent-as-principal with credentials, delegation, scoping, expiry | Cross-principal containment is unmeasurable without real principals. This is also the best differentiator — richest learning coinciding with widest white space is evidence the curriculum is honest | authn vs authz, OAuth 2.1 + PKCE, token exchange (RFC 8693), audience restriction (RFC 8707), JWT failure modes (alg confusion, `kid` injection, missing `aud`/`iss`), SPIFFE, RBAC/ABAC/ReBAC, Zanzibar, Cedar |
| **5 — Telemetry you did not design** | Make "was it detected?" non-circular | Detections against a self-authored schema grade their own homework. Real signal needs container stdout, HTTP access logs, DB audit logs, DNS query logs, syscall events | Log parsing/normalization, clock skew, cross-source correlation, Sigma/detection-as-code, TP/FP rates and alert fatigue, ATT&CK + ATLAS mapping, IR process, forensic timelines |
| **6 — Tamper-evident artifacts** | A third party must verify *what was run* | Signed corpora, hash-chained logs and content-addressed manifests make results citable; log injection (CWE-117) into JSONL can forge the record that proves containment | Hash properties, HMAC vs signature and why a bare hash fails, Merkle chains, key management, log replay/rollback, ordering vs timestamps |

Stage 6 teaches **applied crypto engineering only** — not cryptanalysis, not number theory. Do not claim otherwise.

## 4. Topics with no honest home

- **Assembly, C memory corruption, binary RE.** No feature of an agent-authorization range is blocked without them. The nearest hooks are weak and I'll name them rather than pretend: a `run_code` tool puts container escape in scope, but that is Linux security, not assembly; shipping a native vulnerable daemon would justify pwn, but that is a *different product* — an offense-capability range, territory AgentCyberRange (2606.14295) already occupies. **Learn these outside the repo**, and never use "reverse engineering" for interpreting model behaviour.
- **Windows internals, kernel drivers, malware analysis.** Nothing pulls them in.
- **Cloud.** Earned only at concept level (IAM policy evaluation, least privilege, metadata-SSRF confused deputy) as threat-model exemplars. Real cloud mastery needs a real account and real bills — external.
- **OS internals** is earned partially (processes, namespaces, cgroups, seccomp at Stages 1–2). Scheduler and VM internals are not.

## 5. LEARNING_BACKLOG — mechanism

Ship it as `docs/SIMPLIFICATIONS.md`, a **fidelity-debt register**, not a study list. Two decisions make it engineering rather than journaling:

1. **It is linted.** Code carries `# SIMPL-0004` markers at the exact simplification site; CI asserts every marker resolves to an entry and every `code_ref` resolves to a real symbol. Dead entries fail the build.
2. **It is referenced by `docs/CLAIMS.md`.** Every published claim lists the SIMPL ids limiting it and the direction of bias. The register becomes what stops the benchmark overclaiming — which is why a hostile reader reads it as rigour.

Acceptance test: **delete the `background:` field — does the entry still earn its place as a limitation of the artifact?** If not, it's a diary entry; move it to private notes.

```yaml
- id: SIMPL-0002
  title: Taint is a boolean threaded by hand, not an information-flow lattice
  code_ref: fsociety/env/provenance.py::ToolResult.tainted
  status: open              # open | mitigated | closed | wontfix
  hidden_by: simulation     # library | architecture | scope | simulation
  what_we_do: >
    Documents from the untrusted corpus are flagged tainted; the flag is copied
    onto any tool result whose inputs included a tainted value.
  what_is_hidden: >
    The IFC literature: security lattices, join/meet, implicit flows,
    declassification, label creep. Manual propagation cannot see an implicit
    flow — the agent reads a tainted document, paraphrases it into an untainted
    string, and passes that to a privileged call.
  why_it_matters: >
    Under-tainting scores a containment SUCCESS on a run a real IFC system
    would call a leak.
  affects_claims: [containment_rate, exfiltration_detected]
  bias_direction: optimistic
  real_world_analogue: FIDES integrity/confidentiality labels; CaMeL capability labels; RTBAS screeners
  path_to_fidelity: >
    Two-axis labels propagated at the tool-boundary marshalling layer rather
    than in scenario code; explicit declassification that is itself a policy decision.
  background:
    - "Denning 1976, A Lattice Model of Secure Information Flow"
    - "Sabelfeld & Myers 2003, Language-Based Information-Flow Security"
    - "arXiv 2505.23643 (FIDES); 2502.08966 (RTBAS); 2503.18813 (CaMeL)"
```

Five more seeds, compressed:

- **SIMPL-0001 — In-process PDP is not a reference monitor.** Hides complete mediation and tamper-proofness (2 of Anderson's 3). Bias **optimistic**. Analogue: gateway-side evaluation (AWS AgentCore Policy + Cedar, GA 2026-03-03; FORGE 2602.16708). Path: PEP in a separate process with no import path from the agent. Background: Anderson 1972; Saltzer & Schroeder 1975.
- **SIMPL-0003 — "Sensitive data exposed" = substring match on a canary.** Hides real DLP: entropy detection, encoding/chunking evasion, splitting across turns — and the fatal case, a model that *summarizes* payroll rather than quoting it defeats the canary entirely. Bias **optimistic**; ASR undercounted. Path: per-run high-entropy tokens plus a separately reported semantic-leak judgment with its own error bars. Background: canarytokens.org design notes; AD honey-account practice.
- **SIMPL-0004 — The event log is append-only by convention, not construction.** Hides tamper-evidence, ordering under concurrency, clock trust, and **log injection (CWE-117)**: a tool result containing a newline plus forged JSON can manufacture the record that proves containment. Bias **invalidating**, not merely optimistic. Path: prefix hash chain + per-run signed manifest; reject control characters in string fields. Background: NIST SP 800-92; "Proof of Execution" (2607.05397).
- **SIMPL-0005 — Deterministic replay reproduces a transcript, not a system.** Hides what reproducibility costs: pinned dependency graph and container digests, controlled clock/RNG/iteration order (`PYTHONHASHSEED`), controlled filesystem state, and the fact that a hosted model is nondeterministic even at temperature 0. Bias: **overclaims reproducibility** — a third party rerunning in a year gets different numbers. Path: run manifest hashing scenario + policy + fixtures + commit, and `replay --verify` failing on drift. Background: reproducible-builds.org; `rr`; deterministic simulation testing (FoundationDB).
- **SIMPL-0006 — The tool call is a Python dict, not a protocol.** Hides JSON Schema validation *as a security boundary* (type confusion, extra properties, unicode normalization of tool names), MCP's auth model (OAuth 2.1 + PKCE, RFC 9728, RFC 8707), and tool-description poisoning / name shadowing / rug pulls. Bias: **whole attack classes are structurally unrepresentable.** Background: MCP authorization spec; 2606.29073's "metadata non-authority" invariant; mcp-scan.

A seventh worth opening early: **the restricted asset is a dict key**, so no OS, DB, or network control exists to fail — which flatters the policy engine by making it the only control.

## 6. What fsociety cannot teach you

Two structural limits: **you cannot learn adversarial creativity by building the defence** — attack skill comes from attacking things you did not design; and **you cannot learn detection engineering from your own logs.**

Specific external path: Kerrisk *The Linux Programming Interface* plus `man 7 capabilities` / `man 2 seccomp`; Kurose & Ross and Sanders' *Practical Packet Analysis* with Wireshark pointed at your own range; **PortSwigger Web Security Academy** (free, the best resource in the field with no close second); the Zanzibar paper (2019), Richer & Sanso *OAuth 2 in Action* (UNVERIFIED whether a 2.1 edition exists), Aaron Parecki's OAuth material, Hardy 1988; Liz Rice *Container Security* plus Trail of Bits container-escape writeups; Bejtlich *The Practice of Network Security Monitoring*, Palantir's ADS framework, the Sigma repo, and OTRF Security-Datasets or Splunk BOTS for logs you did not write; **Cryptopals** (do it, don't read about it) and Aumasson *Serious Cryptography*. The explicitly non-fsociety track: Bryant & O'Hallaron *CSAPP*, **pwn.college**, ROP Emporium, Sikorski & Honig *Practical Malware Analysis*, Andriesse *Practical Binary Analysis*. For agent security read primaries not summaries: AgentDojo (NeurIPS 2024), CaMeL 2503.18813, Progent 2504.11703, FIDES 2505.23643, FORGE 2602.16708, the ICML 2026 position paper 2607.22024, ContainmentBench 2607.23999, survey 2605.16282, plus OWASP ASI01–ASI10 and MITRE ATLAS.

Certifications: OSCP teaches offense under time pressure and will **not** make you better at this problem; Security+ teaches vocabulary. Neither is aligned. Say so rather than collecting one.

## 7. Editorial rules against bootcamp signal

1. The repo **never addresses the reader as a learner**: no "Lesson", "Module", "You will learn", no difficulty stars, no emoji checkmarks. Docs address a competent user and a competent contributor.
2. **No progress artifacts** — no `PROGRESS.md`, no completed-topics checklist, no roadmap that is secretly a syllabus. Every roadmap item must be defensible to someone with zero interest in your education.
3. **The fidelity register is the only in-repo learning artifact**, and it passes the delete-the-`background:` test.
4. **Never explain what the audience knows.** Cite primary sources instead of paraphrasing them: a bibliography reads as scholarship, a tutorial reads as homework.
5. **Commit messages describe changes, never learning.**
6. **Link direction is one-way.** Blog posts link *to* the repo; the repo never links to your blog, your certificates, or you.
7. **Every claim carries its limitation inline.** "Measures X, specifically does not measure Y, here is why" reads senior; "comprehensive AI security platform" reads junior.
8. **Difficulty is not a product attribute.** Tag scenarios by threat model and required capability — same information, no school framing.
9. Private notes live in a **separate private repo with an unrelated name**. No cross-links, ever.
10. Fix the name. `Manisso/fsociety` has ~12.1k stars in the same vertical; the Mr. Robot reference reads as 2017-era script-kiddie branding to exactly the practitioners you need. It is the cheapest item on this list to fix.

## 8. Seasons: reject, and the replacement

**Reject.** "Seasons" imports a consumer-content metaphor into a measurement instrument whose value is stability over time; it signals churn and reads as CTF branding to authorization vendors and detection engineers. It is also the wrong fix for a real problem — corpus saturation and contamination, documented as unsolved in "Measuring Security Without Fooling Ourselves" (May 2026).

Three replacements:

- **Milestones named by the claim they unlock**, not numbered: `in-process mediation` → `out-of-process mediation` → `multi-principal identity` → `network-observable exfiltration`. Each release headline is what can now be honestly claimed; the notes state what still cannot. Same episodic motivation, opposite credibility signal.
- **Versioned corpus with a held-out split.** `corpus/2026.11/public/` plus a `holdout/` whose hashes are published and contents released on a schedule. A solo project cannot run a Gandalf-scale data-generating game, so the realistic mitigation is *seeded attack generators* published alongside results: instances rotate, results stay reproducible.
- **An assurance argument** (`docs/CLAIMS.md`): claim → evidence → limitation → SIMPL ids. This is the capstone forcing function. Publishing a claims document and inviting people to break it produces more real learning per month than any build task, and it is the most senior-looking artifact in the repo.

The "seasons" *feeling* belongs in private notes as a six-week capability cycle — one milestone plus one external track (cycle 2 = out-of-process mediation + TLPI process/credential chapters + 20 PortSwigger auth labs). It never appears in the repo.

---

## Where I expect to disagree with the other agents

ASSUMPTION: I have not seen the other six briefs and infer their roles from the constraint list; the roles are my guess.

- **The prior-art / positioning agent** will argue fsociety should be an `inspect_evals` eval or an AgentDojo defense plug-in, since standalone loses on adoption. I concede distribution and reject it for Stage 1: contributing an eval to someone else's runner teaches you *their* abstractions, never the boundary. Building the PEP/PDP once yourself is the highest-yield act in the project. Compromise: build standalone, export in Inspect's log format, upstream the scenario later. I will also fight them on cutting Stage 1 as "already published by FORGE/AgentCore" — publication is not possession, and the gap between claiming containment and having it is the whole point.
- **The V0 scope-minimalist** and I agree V0 must not grow. We collide on `SIMPLIFICATIONS.md`, `THREAT_MODEL.md` and `CLAIMS.md`, which they will call non-essential documentation. They cost less than the test suite and are the only reason the numbers are publishable. Non-negotiable from my side.
- **The architecture agent** will want an elegant novel policy abstraction. I oppose it: mirror the AgentCore/Cedar shape — the unit of control is the *action*, a tool call with caller identity and parameters evaluated at invocation. A novel abstraction is simultaneously un-adoptable and pedagogically misleading; you would learn your own invention instead of the industry model.
- **The threat-model / adversary agent** will want an adaptive or LLM-driven attacker early. That destroys determinism, V0's entire differentiator, and teaches nothing the creator can currently evaluate. Attacker sophistication belongs at Stage 3+ as a seeded generator, never as an autonomous agent — which also keeps the containment constraint intact.
- **The aesthetic / narrative agent** is my sharpest conflict. I oppose lore, in-universe character names in the codebase, ASCII theatrics, and seasons. The aesthetic budget is real but must buy information density and legibility — a genuinely good trace viewer, a well-designed event schema, a readable allow→deny diff. Fiction implying the tool is a game costs exactly the audience the project needs, and that includes the project name.
- **The governance / community agent** will want early institutional cover (OWASP GenAI, AISI, CNCF) and vendor participation. Necessary *eventually*, corrosive *now*: chasing it converts a learning vehicle into a standards-committee job, and MITRE ATT&CK Evals losing 30→11 participants shows an unknown project cannot solve the governance problem anyway. I will also name the conflict they may soften — the creator runs an AI-security company, and soliciting vendor benchmark participation while doing so is something the vendor-neutrality constraint cannot survive.
