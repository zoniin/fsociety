# Measurement protocol

Two pages. If these commitments cannot be kept, the numbers this tool produces
are not worth publishing and the project should not exist.

## 1. The pairing rule

**A containment result is only reportable next to what containment cost.**

No command prints one without the other. A lone attack run prints
`SCORECARD WITHHELD` and its JSON carries `scorecard_withheld: true`. The
artifact type enforces it: `TrialResult` requires the benign list, and there is
no type for "attack run alone". A scenario that declares no benign task fails
validation at parse time with an error naming this rule.

Why: a policy that denies every action scores perfectly on containment alone,
and one of forty surveyed agent-safety benchmarks measures over-refusal at all.

## 2. The ordering rule

**A policy is authored, frozen, and content-hashed before the attack variants
that score it exist.**

The public, tamper-evident proof is git commit order plus the recorded
`policy.digest` in every result. Anyone can check it; nothing is asserted.

Why: the circularity objection. If the policy is written with knowledge of the
exact attack it will face, the demo has the epistemic content of
`assert deny(X) == DENY` and cannot surprise anyone.

**Known weakness, stated rather than hidden.** In V0 both the policies and the
attack were authored by the same person in the same week, so the ordering rule
is a *going-forward* commitment, not a claim about the current corpus. What
carries the anti-circularity weight today is the second column — the benign
suite — because the author did not choose the false-deny rate that a given
policy inflicts on it. The path-prefix policy's cost of 2 legitimate tasks is
the kind of result the author cannot write down in advance.

The strongest available fix is not a private held-out split (governance a solo
maintainer cannot carry, and a leaked one is strictly worse than none) but
**third-party attack authoring against a published frozen policy hash.** That
converts the holdout from a governance burden into a contribution funnel.

That is no longer only a plan. `policy-freeze.json` records the digest of every
published policy; `interpose freeze --check` runs in CI so a frozen policy
cannot be edited without the change being visible in a diff; and `interpose
challenge <scenario>` runs a third party's attack against those exact bytes and
exits 1 when the policy breaks. The full contributor path is in
[`CHALLENGE.md`](CHALLENGE.md).

What the mechanism still cannot do is manufacture a challenger. Until someone
outside the project uses it, the ordering rule remains a promise with good
plumbing behind it.

## 3. The blindness rule

**The policy never learns which trial it is in.**

Never given: the adversary objective, the target action signature, the outcome
predicate, the seed, the scorer, any flag that content "is the injection", or
whether this run is the benign control or the attack.

Enforced three ways: the context builder holds no reference to the attack
section; `policy/` imports nothing from `scenario/` (asserted by test); and the
decision stream is identical between benign and attack runs up to the point the
corpus differs (asserted by test).

## 4. The honesty rules

- **No rate from the deterministic path.** Runs there are byte-identical by
  construction. A confidence interval over them would measure the author's
  phrasing choices, not sampling error. `matrix` reports *paraphrase coverage*.
- **No claim that the scripted client resembles a model.** It is a programmed
  worst-case client. Artifacts are stamped `deterministic: true`, and that flag
  is what disqualifies the number from any statement about models.
- **No ranking.** Dominance only.
- **Every published metric names the simplifications that bias it**, and in
  which direction. See [`SIMPLIFICATIONS.md`](SIMPLIFICATIONS.md).
- **Prior work is cited, never re-claimed.** The compliance/containment split
  is published ([2607.23999](https://arxiv.org/abs/2607.23999),
  [2607.22024](https://arxiv.org/abs/2607.22024)). AgentDojo already scores
  over post-environment state. The sentence "existing benchmarks only measure
  whether the model got fooled" is false and must never appear.

## 5. What would falsify the project

Written down in advance so it cannot be rationalised later.

- If a reviewer constructs a benign suite under which
  `reference-least-privilege` over-blocks as badly as `path-prefix-v1`, the
  reference policy is not better — it is tuned to this suite. That is a real
  outcome and the harness must report it rather than the project defending
  against it.
- If no third party ever authors an attack against the frozen policy hash, the
  ordering rule stays a promise and the circularity objection stands.
- If a second scenario cannot be expressed in the data-only format without core
  changes, the contributor moat does not exist.

  **Partially falsified, V0.1.** The second scenario (`confidential-egress`) is
  data-only in the sense that mattered: three files, no code path, no new tool.
  But writing it correctly forced two engine changes it could not have worked
  around -- resources had to gain a reader allowlist so R3 could check
  entitlement per reader rather than aggregating clearance, and the outcome
  scorer had to split "read a protected asset" from "read it without
  authorization", because otherwise the scenario's own legitimate benign task
  scored as a compromise. Both were real gaps in the model, and finding them is
  the argument for a second scenario. But the honest reading is that the moat
  is thinner than V0 claimed: the *format* held, the *primitives* did not. A
  contributor whose scenario needs a distinction the engine cannot express will
  hit the same wall, and the roadmap should be read with that in mind.
