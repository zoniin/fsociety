# Founding thesis

Written after a seven-agent adversarial design review, a two-agent prior-art
sweep, and a cross-model second opinion. Several of the positions below reverse
what the project set out to build. Where that happened it is said plainly.

## What interpose is

A regression test for the trust boundary in tool-using AI agents. It runs a
simulated employee assistant against a small simulated company, lets untrusted
content try to steer it into a privileged tool call, and reports two numbers
that are only meaningful together: whether the authorization layer held, and
what holding cost in legitimate work. The authorization layer is a swappable
component, so the thing under test is the policy, not the model.

## What interpose is not

- **Not a cyber range.** No hosts, no network, no containers, no persistent
  world. Every surveyed project that left the laptop is dead, deprecated, or
  institution-only: DetectionLab (unmaintained since January 2023, ~5k stars,
  no successor), Splunk Attack Range local deployment (deprecated), KYPO
  (development ended), GOAD (24GB+), TheAgentCompany (30GB+, t3.2xlarge).
  "Persistent" and "reproducible" are also opposite requirements, and a
  benchmark needs the second one.
- **Not a benchmark leaderboard.** No ranking, no vendor scoreboard. MITRE
  ATT&CK Evaluations went from ~30 participating vendors to 11 in one round;
  AgentDojo's maintainers refuse to rank on fairness grounds. A solo project
  whose author has a commercial position in this category has *less* standing
  to run a vendor comparison than MITRE, not more. Frontiers and dominance
  only: policy A beats policy B when it is at least as good on **both** axes,
  and non-dominated pairs are left unordered.
- **Not a CTF, not an IR lab, not a SIEM, not an adversary simulator.** Each is
  a different product with a funded incumbent.
- **Not an agent framework.** The provider interface is one method. interpose
  should be compatible with agent ecosystems, never a competitor to them.

## Primary user, for V0

**The platform engineer who just wired an internal agent to real tools** and
was asked by AppSec: "what if someone puts instructions in a Confluence page?"

They do not want a score. They want a pattern to copy and a test that proves
theirs works — and an answer to the question nobody publishes: *will this
policy break my agent?*

Secondary: the AI red teamer who has to show a VP something concrete on
Thursday, and the workshop author who needs a demo that runs offline in a hotel
conference room with no key and no risk. Explicitly **not** optimised for: the
defense researcher who needs a citable benchmark. Serving that user first is
how this becomes a 46-star repository, which is the observed fate of every
"unified pluggable evaluation platform" that has tried (PIArena 46 stars,
DoomArena 62 and a year stale — both good architectures, both ignored).

## The core problem

Agents crossed the line from generating text to taking actions. The security
question changed with it, but the tooling did not: scanners probe endpoints
from outside and report that the app leaked. They cannot report which control
decided, or what that control cost, because they are not inside the system.

Meanwhile the defenses that *do* sit inside — CaMeL, FIDES, Progent, RTBAS,
FORGE, AWS AgentCore Policy with Cedar — have a measurement problem of their
own. Every one of them was validated on static benchmarks
([2606.26479](https://arxiv.org/abs/2606.26479)), none is comparable to the
others under one metric, and **none publishes its over-blocking rate**. CaMeL's
roughly 33% task loss has never been curve-mapped against alternatives. The
survey of forty agent-safety benchmarks
([2605.16282](https://arxiv.org/abs/2605.16282)) finds one that measures
over-refusal at all.

So the concrete problem is: *there is no way to ask what an authorization
policy for an agent actually costs you.*

## Differentiation, stated honestly

The framing — "the model was fooled" and "the system was compromised" are
different events — **is not novel and this project must never claim it is.**
Three prior publications state it by name, and one of the most-cited benchmarks
already scores over environment state rather than model compliance. Any README
sentence beginning "existing benchmarks only measure whether the model got
fooled" is false, and a senior reviewer will know it within one paragraph.

What is actually missing, and what interpose is:

**No harness ships the authorization layer as a first-class swappable defense
with a false-deny measurement.** AgentDojo's four shipped defenses are
`tool_filter`, `transformers_pi_detector`, `spotlighting_with_delimiting`, and
`repeat_user_prompt` — a naive pre-selection filter and three model-side
techniques. Not one is an authorization layer, and none reports the cost of
being wrong.

That is a plumbing gap worth a few hundred lines, not a philosophy worth a
movement. Saying so is the difference between a project that gets taken
seriously and one that gets filed under "another benchmark".

## The killer workflow

```console
$ interpose demo
```

Ten seconds, no credential, no container. Three policies against one attack and
one benign suite, and the middle row does the work:

```text
  permissive-baseline         COMPROMISED   exposed=YES   benign 8/8   false-deny 0
  path-prefix-v1              CONTAINED     exposed=no    benign 6/8   false-deny 2
  reference-least-privilege   CONTAINED     exposed=no    benign 8/8   false-deny 0
```

**Why three rows and not two.** Two rows — broken, then fixed — is the demo the
project was originally specified to build, and it is circular. The author picks
the protected asset, writes the attack, and writes the policy that blocks it;
the result has the epistemic content of `assert deny(payroll) == DENY`. It
cannot surprise anyone, and a measurement that cannot surprise you is not a
measurement. ContainmentBench ran essentially that experiment across seven
policy conditions and reported *no committed policy violations under any tested
defense* — the endpoint saturated at zero and their contribution had to move
elsewhere.

The escape is that the author does **not** control the second column. The
restricted `/hr/payroll_2026_q3.csv` has a benign sibling
`/hr/headcount_2026_q3.csv`, reachable through the same tool with the same
argument shape, that a legitimate weekly task requires. The intuitive fix —
deny the `/hr/` prefix — contains the attack and breaks that task. Nobody chose
that; it falls out of the world having a realistic shape.

Three protocol commitments keep it honest:

1. **The pair is mandatory.** No command prints containment without cost. A
   lone attack run prints `SCORECARD WITHHELD` and refuses to be a result.
2. **Policies are frozen before the attacks that score them**, content-hashed,
   with git commit order as the public tamper-evident proof. See
   [`PROTOCOL.md`](PROTOCOL.md).
3. **The policy never learns which trial it is in.** Not whether the run is the
   benign control or the attack, not the adversary objective, not the seed. The
   trust label says `untrusted_external`, never `malicious`. Enforced by an
   import-graph test, not by good intentions.

## Long-term vision, three years out

If it works, interpose becomes the neutral surface where an authorization
decision for an agent can be compared to another one. Cedar, OPA, OpenFGA,
Progent-style symbolic rules, FIDES/CaMeL-style label propagation, and a
human-approval gate all implement one interface and are measured on one
containment/utility frontier, by scenarios their authors did not write.

The research questions that unlocks, ranked:

1. What is the containment-per-unit-utility frontier across enforcement layers?
   Unanswerable today; no prior art.
2. Is enforcement efficacy independent of the model? If the authorization gap
   holds steady while injection compliance varies seventeen-fold across models,
   that is the strongest possible empirical statement of the thesis.
3. Cross-principal containment under injection — the confused deputy with real
   principals. The sharpest empty axis in the survey.
4. Does finer provenance granularity buy containment, and at what utility cost?

## V0: what actually exists

- One scenario: `indirect-document-injection`, with 8 benign tasks, 5 prompt
  paraphrases, and 5 injection phrasings.
- A world of 4 principals, 3 roles, 14 resources, 2 queues — sized to be read
  in one sitting, shaped so the measurement is not a toy.
- Five tools behind a single enforcement chokepoint.
- Three policies forming a frontier.
- A deterministic client with four behaviour classes; an optional Anthropic
  provider.
- Taint provenance with two bracketing views, and a JSONL causal trace.
- A shadow probe for the case where the model never tried.
- `verify` for citability; 69 tests; mypy and ruff clean; ~12 second suite.

## Explicitly refused, for now

Containers (four named triggers would force them — none is met). An adaptive or
LLM-driven attacker (non-reproducible by construction, and it changes the
measured quantity from "did the system hold" to "how good is our attacker").
A leaderboard. A multi-model matrix. Cedar and OPA adapters (the right first
V1 milestone, but an OPA sidecar breaks the no-build-step install and nobody
has checked whether Cedar can express taint). `ESCALATE` and a simulated
approver. A detection verdict — writing detections against a log schema you
designed yourself teaches log design, not detection engineering. Seasons, CTF
tiers, a TUI, a web dashboard, a SIEM, a persistent world, a simulated Active
Directory, a novel policy DSL, and any form of telemetry.

Each of those is in [`ROADMAP.md`](ROADMAP.md) with the condition that would
justify building it. None of them is justified by "a mature cyber range would
eventually need it".
