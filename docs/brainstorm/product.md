# fsociety — Product Strategy Memo (Agent A)

My prior: most open-source security projects get 40 stars and die. Looking for evidence this
one escapes that, I found a distribution pattern in the prior art more decisive than any of
the technical gaps.

## The star-mass pattern nobody in the digest named

Sort the surveyed prior art by adoption and a clean split appears.

**Things a practitioner runs against their own system:** promptfoo 24,685 · Atomic Red Team
~10,000 · garak 9,080 · CALDERA ~7,100 · DetectionLab ~5,000 (dead since 2023 and *still*
5,000) · PyRIT 4,382 · Manisso/fsociety 12,300 (a Python 2 script aggregator).

**Things a researcher cites:** AgentDojo 782 · inspect_evals 653 · Cybench 317 · ASB 292 ·
DoomArena 62 · **PIArena 46** · ST-WebAgentBench 26.

**PIArena** (ACL 2026, `sleeepeer/PIArena`, MIT) — *not in the recon digest* — is literally
"a unified and extensible platform for prompt injection evaluation" with four pluggable
modules (benchmark, attack, defense, evaluator), nine attacks, nine defenses, and it already
wraps AgentDojo, InjecAgent and AgentDyn as sub-benchmarks. It has 46 stars. DoomArena built
the same architecture and has 62 and no commit since 2025-09-12.

That is the finding. **The "unified pluggable evaluation platform" slot has been claimed at
least three times by well-credentialed teams and every claimant landed under 100 stars.**
AgentDojo is the exception that proves it: its 782 stars come from being the *citable
benchmark in a NeurIPS paper*, not from being a platform.

So the strategic question is not "is there a technical gap" — the digest establishes several
real ones. It is which artifact shape survives contact with humans. A benchmark without a
paper and institutional cover is structurally a 50-star repo. A tool a developer runs
against their own thing is where the mass is.

## Ranked archetypes

**1. AI red teamer / security consultant who has to *show* someone.**
Senior Security Engineer on an internal AI red team at a 2,000–20,000 person company, or a
consultant at NCC/Bishop Fox/Trail of Bits. Tuesday: assessing a business unit's new
Confluence-connected assistant, readout to a VP Thursday. Currently: a Google Doc of nasty
strings, a garak run, and a slide saying "prompt injection is a risk." What they cannot
produce is *a live thing that visibly fails and then visibly holds*. The money-shot demo is
not a benchmark result for this person — it is a sales artifact and a training aid.

**2. Platform engineer who just wired an internal agent to real tools.**
Staff/Platform Engineer, "AI Platform" team, 200–5,000 person fintech/healthtech/B2B SaaS.
Tuesday: the assistant reads Confluence, Jira and an internal HR API over MCP; AppSec asked
"what if someone puts instructions in a Confluence page?" and they have no answer. Currently
they paste a hostile string in by hand and eyeball it, or nothing. They don't want a score.
They want **a pattern to copy and a test proving theirs works** — and an answer to "will
this policy break my agent?", which nobody publishes. Highest value per user; see the fatal
objection below.

**3. Educator / conference speaker / workshop author.**
Runs an internal AI-security training module, or has a DEF CON AI Village or BSides talk.
Tuesday: needs a demo that runs offline in a hotel conference room with no API key, no cloud
account, and no risk of pointing offensive tooling at a third party. Currently builds it
badly themselves, or uses Damn Vulnerable LLM Agent (a toy). Low value per user, **very high
distribution leverage** — blogs, tweets, curricula. The V0 constraint set (deterministic,
offline, no paid keys, small deps) is tailored to this person almost by accident.

**4. Authorization-engine maintainer or challenger vendor.**
Maintainer of Cerbos/Casbin/Permify, or a PM at Permit.io. Tuesday: writing "authorization
for AI agents" marketing with zero supporting evidence — OpenFGA already ships an
"Authorization for Agents" docs page with no adversarial validation behind it. They want a
third-party test they can pass and cite. Real pull, but per MITRE ATT&CK Evals (30 vendors →
11, Microsoft/SentinelOne/Palo Alto all withdrawing) they participate only while they win.

**5. Defense researcher needing a baseline.** Uses AgentDojo, won't switch without a paper.
The archetype whose approval produces a 46-star repo. Serve them; don't optimize for them.

**Not users in V0, despite real pain:** detection engineers (DetectionLab's corpse is the
clearest unmet need in the survey — and V0 builds nothing for them); compliance owners
chasing EU AI Act Art. 14 evidence (they buy, they don't clone).

## Star vs. clone vs. cite — three different acts

- **Star:** a legible terminal GIF in a tweet or HN post showing the two-run diff. A star is
  a bookmark for "good argument, might need it." The asset that earns it is the README hero
  recording, not the code. Optimize it like a product surface.
- **Clone-and-run:** a deadline — a readout, a talk, or an assessment this week. Conversion
  requires no API key, no Docker, under 5 minutes to first output, and output legible
  *without reading docs*. Every minute past five halves conversion.
- **Cite** (the act nobody plans for, and the one producing durable users): an arXiv number,
  or being vendored into someone else's docs. This is why the arXiv writeup below is a
  distribution decision, not a vanity one.

## The wedge

Not the range. Not the scenario. Not the policy engine.

**The wedge is the diff artifact: run one seeded scenario twice under two policies and emit
a byte-stable, human-legible trace that shows which untrusted bytes reached which privileged
call, which decision changed, and what the policy cost you on the benign task.**

If `diff run-permissive.json run-reference.json` tells the entire story to someone who has
never read the docs, the project works. If it needs explanation, it dies. Everything else in
V0 is scaffolding for that artifact.

Two properties make this defensible rather than cosmetic. First, **byte-stable
determinism**: AgentDojo's docs run on TogetherAI and GPT-4o throughout, and PIArena needs a
HuggingFace token plus optionally an OpenAI key. A first-class deterministic fake provider is
*embarrassing* under benchmark framing and *the entire point* under tool framing. Second,
**the over-block number.** The digest's gap list says nobody publishes the cost curve of a
policy layer, and Li et al. found 1 of 40 benchmarks measures over-refusal at all. Everyone
reports ASR. Reporting "the attack was contained AND the benign task still completed" is
both the honest open gap and exactly what archetype #2 cares about. Make it the headline
metric.

## Per-competitor: why pick this

- **AgentDojo** — owns "measure injection ASR on tool-calling agents." Do not fight it. I
  verified its `ToolsExecutionLoop` accepts a `BasePipelineElement` before tool execution, so
  an authorization layer *fits*, and its docs admit "we are still working on providing a
  better way to... register their own pipelines." Its four shipped defenses contain no authz
  layer. Pick fsociety when you need to know *why* it blocked and *what it cost*, and when it
  must run free in CI. **Complement, not replacement: ship the authz defense INTO AgentDojo.**
- **promptfoo** — 24.7k stars, in everyone's CI, already ships RBAC/BOLA/BFLA plugins. But it
  probes from *outside* by prompting and LLM-judging the response. It tells you the app
  leaked; it cannot tell you the policy engine's decision, because it isn't in the system.
  fsociety is inside the boundary and has ground truth. That is the whole pitch.
- **garak / PyRIT** — scanners and attack orchestrators against endpoints; no agent
  execution, no tool invocation, no state (CSA says this of PyRIT explicitly). They are the
  attacker, fsociety is the target. Don't position against them.
- **Inspect / inspect_evals** — not a competitor, **the distribution channel**. Verified: as
  of May 2026 you submit an issue with an arXiv URL and a source link, and evals register in
  `/register/` **pointing at external repos**. No rewrite into their runner required. The
  arXiv number is required.
- **CyberBattleSim** — dormant; Microsoft states the abstraction exists specifically to
  prevent real-world applicability. Cite as the abstraction trap to avoid.
- **CALDERA / HTB / hand-rolled Docker lab** — CALDERA needs hosts you supply. HTB is hosted,
  paid, unforkable, and trains humans; you lose on content depth, don't enter. **The
  hand-rolled lab is the real competitor.** The status quo is a competent engineer spending
  an afternoon wiring a fake tool and a hostile document. That sets the bar exactly: beat an
  afternoon within five minutes, and deliver what the afternoon cannot — the deterministic
  diff and the over-block number.

## Positioning: pick one

**A regression-testing tool for the trust boundary in tool-using agents.**

README headline shape: *"Prove your agent's tool-call authorization actually holds when the
model gets fooled. Deterministic, offline, runs in CI."*

Against the alternatives: **cyber range** collides with AgentCyberRange (June 2026), invites
GOAD/HTB comparisons V0 loses, and depends on the unsolved weight budget — no surveyed
project fits a credible enterprise under ~16GB. **Benchmark** is structurally the 50-star
slot, and the field's own survey recommends consolidating into 8–10 anchors, not a 41st
entry. **CTF framework** — CTFd owns scoring, and CTF framing recruits players, not buyers.
**Security simulator** is too vague to be a headline.

Regression-test framing is the only one where every V0 constraint becomes a feature: the
fake provider is determinism, small deps are CI-friendliness, one scenario is focus, and
containment-by-design is a selling point rather than a limitation. It also sidesteps
governance entirely — a test you run on yourself needs no vendor consent and no leaderboard.
The artifact people copy is **a reference implementation of the boundary**; the test is what
proves it. Ship both, lead with the test.

## Cut list

**Cut:** the leaderboard or any ranked scoreboard (MITRE lost two-thirds of its vendors;
AgentDojo refuses to rank on fairness grounds — do not walk into this). The multi-model
matrix. Containers (the weight budget is unproven; that argument belongs to phase 2). The
simulated *organization* — employees, org chart, email, chat — this is the aesthetic hook
and the single biggest time sink; keep only the entities the authorization decision needs.
**A novel policy DSL** — FORGE, Progent, Cedar and the HCP invariant paper already published
this vocabulary; invent nothing, ship boring YAML over `(principal, tool, argument
predicate)` and say in the README that the policy language is deliberately not a
contribution. Adaptive/agentic attackers. Any TUI, web dashboard, or SIEM.

**Essential:** deterministic seeded execution with byte-stable output. Taint provenance from
untrusted source ID to privileged call. A real policy decision point with a **deny-path
audit record**. The two-policy diff. The over-block measurement on the benign task. And —
non-negotiable for converting archetype #2 — **a documented adapter seam** showing how a
reader's own tools would plug in. Design the seam, ship exactly one implementation. No stub
adapters, and no seam-less monolith either.

## Distribution: the first 50

1. **PR an authorization-layer defense into AgentDojo** as a `BasePipelineElement` in the
   `ToolsExecutionLoop`. Highest-leverage single act available: the core idea in front of
   the exact 782-star audience, filling a gap they acknowledge in their own docs.
2. **arXiv writeup, then inspect_evals `/register/` submission.** Verified path: issue +
   arXiv URL + source link, registered as an external repo. The paper is the cite trigger,
   the register entry is durable distribution. Treat writing it as engineering work.
3. **OWASP GenAI Agentic Security Initiative, ASI03 (Agent Identity & Privilege Abuse).**
   ASI06 already has a reference implementation (Agent Memory Guard). **ASI03 does not.** A
   named, empty slot with institutional cover attached, cheap to claim. Probably the
   highest-value governance move on the board.
4. **Black Hat Arsenal** — a *runnable-tool demo* track; the money-shot demo is literally an
   Arsenal demo, and it beats any paper track on ROI. Then DEF CON AI Village and BSidesLV
   CFPs, OWASP Global AppSec as backup.
5. **PRs into adjacent authz repos:** OpenFGA's "Authorization for Agents" docs page (a
   worked adversarial example is a natural contribution), Cedar examples, and the challengers
   (Cerbos, Casbin, Permify) who want an agent story and have no evidence. Also PIArena —
   MIT, already integrates three benchmarks, wants integrations.
6. **Show HN with the terminal diff GIF**, r/netsec (substance only, no marketing voice),
   r/LocalLLaMA (rewards "no API key, runs offline").

## The single most likely reason this is ignored

**It reads as a 41st benchmark, and nobody can point it at their own agent.**

The failure loop is specific: a platform engineer reads the README, thinks "neat demo," and
closes the tab — because at no point does *their* system get tested. A synthetic scenario
proves only a fact about itself. Every archetype except the researcher eventually needs the
artifact to touch their own stack, and if the path from "your demo" to "my agent" isn't
visible on the README's first screen, the star never becomes a clone.

To avoid it: the adapter seam must be real, documented, and the README's *second* example
must be the same test run against a tool the reader defines in ~20 lines of config. Not
necessarily shipped in V0 — but visible, credible, and honest about its status.

A distant second: **the name.** Manisso/fsociety is 12.3k stars and 2.1k forks, same Mr.
Robot reference, same vertical, plus a Python-3 successor org. It will own GitHub search,
SEO and PyPI indefinitely, and it signals 2017 script-kiddie to exactly the platform
engineers and authz maintainers this project must recruit. Cheap now, impossible later.

**One strategic flag I am not authorized to decide.** GitInject (arXiv 2606.09935, not in
the recon digest) tested AI code-review agents in real GitHub Actions across four providers:
all vulnerable in default configuration, eleven named attacks including credential
exfiltration, framework released publicly. That threat model — untrusted PR content reaching
an agent holding elevated repo credentials — is the same trust boundary as the proposed V0,
but *present-tense, in production, right now*, with an obvious buyer. The synthetic
employee-assistant has no incumbent pain behind it. I recommend keeping the proposed V0
scenario for its clean pedagogy, but "CI agent with repo credentials" is the higher-pain
variant of the identical demo and deserves an explicit decision, not a default.

## Where I expect to disagree with the other agents

- **Whichever agent owns architecture/harness design:** they will want a pluggable
  attack/defense/environment platform with clean extension points. That architecture is a
  *demonstrated* 50-star outcome — DoomArena 62, PIArena 46, both strong teams with papers.
  One scenario and one seam, not a framework. We disagree on whether generality is a feature
  or the failure mode.
- **Whichever agent owns the simulated organization / aesthetics:** employees, org chart,
  internal comms and the "slightly unsettling terminal" are the creator's emotional core and
  my largest cut. They will argue the atmosphere *is* the differentiator; I argue it is why
  V0 slips two months and ships as a vibe with no metric.
- **Whichever agent owns benchmark rigor:** they will push for scenario count, model
  coverage, a leaderboard, statistical treatment. I cut the leaderboard on governance grounds
  and the model matrix on cost. Sharpest split is the arXiv paper — I want it written as a
  *distribution artifact* for the inspect_evals register; they want it to survive peer
  review. Different documents, different timelines.
- **Whichever agent owns threat modeling / red team:** they will want adaptive attackers,
  more injection variants, ATT&CK/OWASP coverage. I want static injections and the effort
  spent on the over-block metric. They will correctly note a static corpus saturates within a
  year; I note a corpus with no users saturates immediately.
- **Whichever agent owns roadmap/scope:** they will sequence toward the cyber-range and
  detection-engineering phases. The DetectionLab gap is the most *provable* unmet need in the
  survey — and V0 still must not chase it: different product, different user, and it drags
  containers and the unsolved weight budget into month one.
- **Anyone arguing fsociety should compete with AgentDojo:** I'll argue the opposite as hard
  as the evidence allows. Contribute a defense into it, cite it, and win on the artifact it
  does not produce.
