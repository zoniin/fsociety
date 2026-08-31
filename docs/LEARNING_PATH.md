# Learning path

A map of which security concepts building this project actually forces, and —
more usefully — which it does not.

**The rule:** a topic earns a place here only when a concrete capability is
blocked without it. Applied strictly, that excludes about a third of the
domains people expect to see on a list like this. That exclusion is the point.
A project that grows a binary-exploitation track to justify learning `gdb` has
stopped being a measurement instrument.

**Where the backlog lives.** The register of hidden complexity is
[`SIMPLIFICATIONS.md`](SIMPLIFICATIONS.md), not a separate learning file. That
is deliberate: each entry names something the code fakes, what it hides, and
**which direction it biases results**, so it is simultaneously a study list and
the document that limits what the tool may claim. A study log that does not
constrain a claim is a diary; a fidelity-debt register is engineering. Same
content, and only one of the two survives a hostile reader.

## What V0 honestly teaches

Someone reading this codebase learns, concretely:

- **The reference monitor as an object.** Anderson's 1972 properties — complete
  mediation, tamper-proofness, verifiability — stop being slogans once you must
  decide whether the check sits on *every* path to a tool. This implementation
  has one of the three, and discovering that yourself is the lesson
  (SIMPL-0001).
- **Authorization over arguments, not names.** The gap between a tool allowlist
  and a rule over `(tool, arguments, context)` is the most transferable idea
  here. `path_prefix.py` teaches it by failing: it authorizes a *string prefix*
  over a namespace never designed to be a security boundary.
- **Fail-safe defaults and least privilege**, from Saltzer & Schroeder — which
  become concrete the moment you write a deny-by-default rule and watch benign
  tasks break.
- **The confused deputy, by name.** Indirect prompt injection *is* Hardy's 1988
  confused deputy: a privileged component acting on an unprivileged party's
  intent. The `on_behalf_of` field is where it lives.
- **Information-flow labels, in their simplest useful form.** Join, lattice
  order, and — most instructively — why manual propagation cannot see an
  implicit flow (SIMPL-0002).
- **Canary tokens and honeytokens** as a detection primitive, including why
  exact matching is chosen over a language-model judge, and what that costs.
- **Audit record design.** Which fields make an event forensically useful; why
  a decision needs rule identity and a reason, not just allow/deny.
- **Evaluation methodology** — seeds, fixtures, deterministic providers,
  separating "the client complied" from "the environment changed", and why a
  containment number without a cost number is not a result. Honestly the
  largest skill this imparts, and it is a science skill more than a security
  one.

## What V0 does not teach — say this out loud

Nothing about Linux, processes, syscalls, or namespaces: the sandbox is a
Python dictionary. Nothing about TCP/IP, DNS, or HTTP: no wire exists. Nothing
about databases. No cryptography. No OS internals. No memory, C, assembly, or
reverse engineering — zero, not "a little". No real identity protocols: tokens
are in-process objects, so no theft, replay, or `alg` confusion.

And critically: **writing detections against a log schema you designed yourself
teaches log design, not detection engineering.** That is why `DETECTED` is not
a verdict token in this tool.

## The progression — capability forces concept

Each stage is justified by something the project cannot claim without it.

| Stage | Capability needed | Why it is blocked without the concepts | Concepts forced |
|---|---|---|---|
| **0 — now** | Enforcement point, policy, taint, trace, canary | The wedge itself | Reference monitor, deny-by-default, subject/action/resource/context, lattice labels, canary tokens, audit records, determinism, threat modelling |
| **1 — out-of-process mediation** | The decision point must not live in the agent's address space | The obvious attack on V0: "your policy layer is a function call the agent could skip." Claiming containment rather than convention needs a real boundary | Processes, file descriptors, uid/gid, unix sockets and IPC, serialization as a trust boundary, rlimits, seccomp basics |
| **2 — tools as real services** | Fidelity | Numbers from mocked tools are contestable in a way numbers from executed ones are not | HTTP semantics, API design, SQL and parameterized queries, row-level security, TLS, container images, namespaces, cgroups, `--privileged` as game over |
| **3 — egress boundary** | Proving data *did not leave* | Containment of exfiltration is unclaimable without controlling and observing a network boundary. DNS exfiltration is the canonical case, and the reason DNS gets learned properly rather than skimmed | Egress proxying, allow-listed destinations, DNS records and tunnelling, TLS interception tradeoffs, covert channels |
| **4 — multi-principal identity** | Cross-principal containment | Unmeasurable without real principals, credentials, delegation, scoping and expiry. Richest learning coinciding with the widest white space, which is evidence this progression is honest rather than invented | authn vs authz, OAuth 2.1 + PKCE, RFC 8693 token exchange, RFC 8707 audience restriction, JWT failure modes, SPIFFE, RBAC/ABAC/ReBAC, Zanzibar, Cedar |
| **5 — telemetry you did not design** | Making "was it detected?" non-circular | Detections against a self-authored schema grade their own homework | Log parsing and normalisation, clock skew, cross-source correlation, detection-as-code, TP/FP rates and alert fatigue, ATT&CK and ATLAS mapping, incident response, forensic timelines |
| **6 — tamper-evident artifacts** | A third party verifying *what was run* | Signed corpora and hash-chained logs make results citable; log injection can forge the record that proves containment (SIMPL-0004) | Hash properties, HMAC vs signature and why a bare hash fails, Merkle chains, key management, replay and rollback, ordering vs timestamps |

Stage 6 teaches **applied crypto engineering only** — not cryptanalysis, not
number theory. Do not claim otherwise.

## Topics with no honest home here

- **Assembly, C memory corruption, binary reverse engineering.** No feature of
  an agent-authorization harness is blocked without them. The nearest hook is
  weak and worth naming rather than dressing up: a `run_code` tool would put
  container escape in scope, but that is Linux security, not assembly. Shipping
  a native vulnerable daemon would justify exploitation work — and would be a
  different product.
- **Windows internals, kernel drivers, malware analysis.** Nothing pulls them
  in.
- **Cloud**, beyond concept level (IAM policy evaluation, least privilege,
  metadata-SSRF as a confused deputy exemplar). Real cloud competence needs a
  real account and real bills.

Learn these outside this repository. And never use "reverse engineering" to
describe interpreting model behaviour.

## What this project cannot teach at all

Two structural limits:

- **You cannot learn adversarial creativity by building the defence.** Attack
  skill comes from attacking things you did not design.
- **You cannot learn detection engineering from your own logs.**

External paths, named specifically rather than gestured at:

- **Linux and processes:** Kerrisk, *The Linux Programming Interface*; then
  `man 7 capabilities` and `man 2 seccomp`.
- **Networking:** Kurose & Ross; Sanders, *Practical Packet Analysis*, with
  Wireshark pointed at your own traffic.
- **Web security:** PortSwigger Web Security Academy — free, and the best
  resource in the field with no close second.
- **Authorization:** the Zanzibar paper (2019); Hardy 1988 on the confused
  deputy; Aaron Parecki's OAuth material; Cedar and OpenFGA documentation.
- **Containers:** Liz Rice, *Container Security*; Trail of Bits container-escape
  writeups.
- **Detection and IR:** Bejtlich, *The Practice of Network Security Monitoring*;
  the Sigma rule repository; OTRF Security-Datasets for logs you did not write.
- **Cryptography:** Cryptopals — do it, do not read about it. Then Aumasson,
  *Serious Cryptography*.
- **Systems, explicitly not via this project:** Bryant & O'Hallaron, *CSAPP*;
  pwn.college; Andriesse, *Practical Binary Analysis*.
- **Agent security — read primaries, not summaries:** AgentDojo (NeurIPS 2024);
  CaMeL ([2503.18813](https://arxiv.org/abs/2503.18813)); Progent
  ([2504.11703](https://arxiv.org/abs/2504.11703)); FIDES
  ([2505.23643](https://arxiv.org/abs/2505.23643)); the ICML 2026 position
  paper ([2607.22024](https://arxiv.org/abs/2607.22024)); ContainmentBench
  ([2607.23999](https://arxiv.org/abs/2607.23999)); the survey
  ([2605.16282](https://arxiv.org/abs/2605.16282)); OWASP ASI01–ASI10; MITRE
  ATLAS.

On certifications: OSCP teaches offense under time pressure and will not make
you better at this problem. Security+ teaches vocabulary. Neither is aligned
with this work, and saying so is more useful than collecting one.

## Editorial rules

These exist because a repository that reads as a learning exercise loses the
practitioners it needs — and that is a real, one-way reputational cost.

1. The repository never addresses the reader as a learner. No "lesson", no
   "you will learn", no difficulty stars.
2. No progress artifacts. No completed-topics checklist, no roadmap that is
   secretly a syllabus. Every roadmap item is defensible to someone with zero
   interest in anyone's education.
3. The fidelity register is the only in-repo learning artifact, and it earns its
   place by limiting claims.
4. Never explain what the audience already knows. Cite primary sources instead
   of paraphrasing them.
5. Commit messages describe changes, never learning.
6. Links point one way: writing links *to* the repository; the repository links
   to neither a blog nor a person.
7. Every claim carries its limitation inline. "Measures X, specifically does not
   measure Y, here is why" reads senior. "Comprehensive AI security platform"
   does not.
