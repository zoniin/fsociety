# Practicality

The questions that had to be answered before writing code, answered again after
writing it. Where the honest answer is weak, it says so.

## Adoption — why would a security engineer install this?

**Because it runs in ten seconds with no credential and shows them a number
nobody publishes.** The install is `pip install interpose`, two runtime
dependencies, no Docker, no account, no build step. The comparable projects
cannot clear that bar: `pip install agentdojo` pulls `anthropic`, `cohere`,
`google-genai`, `langchain` and `openai` as *required* runtime dependencies and
its first documented run needs a paid key; `inspect_evals` starts with putting
a key in `.env`.

**Honest weakness.** The thing they install proves a fact about a simulated
company, not about their agent. The path from "your demo" to "my system" is a
documented interface (`SecurityPolicy`, one method) with three implementations
— real, but it is an interface, not a product. That is the single most likely
reason this gets starred and never cloned.

## Research — what experiment becomes easier?

Comparing two authorization policies on the same attack **with their costs
side by side.** Today that requires building a harness first; here it is one
command and a `result.json` with content digests.

The specific unanswered question it makes cheap: *what does a policy cost?*
CaMeL's roughly 33% task loss has never been curve-mapped against alternatives,
and one of forty surveyed benchmarks measures over-refusal at all.

**Honest weakness.** One scenario, eight benign tasks, five paraphrases. That
is a demonstration of a method, not a corpus. A researcher would need scenario
#5 before publishing anything.

## CI — could this be a regression gate?

Yes, and it already is one for itself.

```yaml
- run: interpose run indirect-document-injection --policy my_policies:Ours
```

Exit `0` contained and useful, `1` an expectation violated, `2` the harness
broke, `3` bad usage. **A policy that contains the attack but breaks a
legitimate task exits 1** — the pairing rule as an exit code. The `1`/`2` split
is what makes it a gate rather than noise.

Suite runs in 12 seconds with no network and no keys, enforced by a
socket-patching fixture.

**Honest weakness.** Gating on a synthetic scenario tells you your policy still
denies *this* attack. It is a canary, not coverage.

## Education — what does someone learn from V0?

Concretely, and modestly:

- **The reference monitor as an object.** Anderson's three properties become
  real when you have to decide whether the check sits on every path — and
  discover your own implementation has one of the three (SIMPL-0001).
- **Authorization over arguments, not names.** The gap between a tool allowlist
  and a rule over `(tool, arguments, context)` is the most transferable idea
  here, and the path-prefix policy demonstrates it by failing.
- **The confused deputy, by name.** Indirect prompt injection *is* Hardy's 1988
  confused deputy: a privileged component acting on an unprivileged party's
  intent.
- **Evaluation methodology** — seeds, fixtures, deterministic providers,
  separating "the client complied" from "the environment changed". Honestly the
  largest skill it imparts, and it is a science skill more than a security one.

What it does **not** teach: anything about Linux, processes, namespaces, TCP/IP,
DNS, HTTP, databases, cryptography, OS internals, or reverse engineering. The
sandbox is a Python dictionary. Claiming otherwise would be the fastest way to
lose a practitioner's trust. See [`LEARNING_PATH.md`](LEARNING_PATH.md).

## Extensibility — can someone contribute another scenario?

Yes, and the journey is tested: `interpose new scenario x` produces a copy that
already passes, and `tests/test_fairness_and_cli.py` asserts that the scaffold
runs clean before it is edited.

**Honest weakness, and the biggest open question in the project.** Scenario #2
has not been written. The data-only format is proven by exactly one user — its
author. Three design decisions (data-only scenarios, a fixed primitive library,
a generic scripted client) all rest on an expressiveness claim that a second
scenario would test and nothing else will. `ARCHITECTURE.md` names where it is
expected to strain.

## Vendor neutrality — could multiple vendors benchmark themselves?

**They could run it. They should not be ranked by it, and this project will not
rank them.**

The interface mirrors AWS AgentCore Policy's framing deliberately so that
Cedar, OPA, OpenFGA, and label-propagation defenses are all implementable
against it. Reporting is dominance-only, with non-dominated pairs left
unordered.

**Honest weakness, and it is structural.** The author has a commercial position
in this category. MITRE — two decades of institutional standing — watched
ATT&CK Evaluations go from ~30 vendors to 11. A solo maintainer has *less*
standing to run a vendor comparison, not more. That is why there is no
leaderboard and why there never should be one here. Neutrality is preserved by
refusing to be the judge, not by claiming to be impartial.

## Framework neutrality — could multiple agent frameworks run against it?

The provider interface is one method: `respond(transcript, tools) -> AgentTurn`.
Two implementations exist.

**Honest weakness.** No adapter has been written for LangChain, LangGraph, the
OpenAI SDK, or any real framework, so "framework agnostic" is currently a
property of the *shape* of the interface rather than a demonstrated fact.

## Reproducibility — can someone reproduce a reported result?

On the deterministic path, exactly: same inputs give the same run id, trace
digest and world digest, on any platform. `interpose verify result.json`
recomputes content digests and prints `AGREES`, `SCENARIO_DRIFT`, or
`UNVERIFIABLE`.

On the real-model path, no — and the tool says so. Artifacts are stamped
`deterministic: false`, and note that the usual determinism knobs are gone:
current frontier models reject `temperature`, `top_p` and `top_k` outright. A
number from a hosted endpoint measures an endpoint on a date.

## Safety — can it run without external targets?

Yes, and that is enforced by absence rather than by configuration. There is no
target parameter anywhere; a test asserts it. Networking imports appear in one
module. A full run under an audit hook attempts no egress. What that does *not*
prove is documented rather than glossed (SIMPL-0006).

## Simplicity — can someone understand it in an afternoon?

The seven concepts fit on one page of `ARCHITECTURE.md`. The whole package is
about 3,000 lines across 24 modules, none large. Two runtime dependencies.

**Honest weakness.** `providers/scripted.py` is the least clean module in the
project — a small state machine with special cases per behaviour class. It is
the part most likely to need rewriting when scenario #2 arrives.
