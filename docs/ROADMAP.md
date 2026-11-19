# Roadmap

Milestones are named by **the claim they unlock**, not numbered. Each release
headline is what can now be honestly said; the notes state what still cannot.

That framing is deliberate. A numbered "seasons" arc imports a consumer-content
metaphor into a measurement instrument whose value is stability over time, and
it reads as churn to exactly the practitioners this needs.

## Shipped — *in-process mediation*

**Claim unlocked:** for one scenario, swapping the authorization layer changes
whether an identical attack succeeds, and the cost of each policy is measured
rather than assumed.

**Still cannot claim:** that the enforcement point is tamper-proof (SIMPL-0001),
that exposure detection catches paraphrase (SIMPL-0003), that the corpus is
adaptive (SIMPL-0012), or anything at all about how a real model behaves
(SIMPL-0011).

## Shipped — *a policy can be wrong across scenarios*

**Claim unlocked:** a policy's score on one scenario does not predict its score
on another, and the corpus can now show that rather than assert it.
`path-prefix-v1` contains `indirect-document-injection` at a cost of two benign
tasks, and is *compromised* by `confidential-egress` while still costing one.
Against a single scenario it looked like a defensible trade-off. Against two it
is a policy that happened to match one attack.

**Also shipped:** the third-party challenge workflow — `policy-freeze.json`,
`interpose freeze --check` in CI, and `interpose challenge`, which runs an
outsider's scenario against the frozen digest and exits 1 when the policy
breaks. See [`CHALLENGE.md`](CHALLENGE.md).

**Still cannot claim:** anything the mechanism was built for. No third party has
used it yet, so the circularity objection in
[`PROTOCOL.md`](PROTOCOL.md) stands unchanged; what shipped is the plumbing, not
the evidence. The second scenario also partially falsified the data-only
expressiveness claim — the format held, but two engine primitives had to be
added. That is recorded in `PROTOCOL.md` §5 rather than quietly absorbed.

## Shipped — *a policy that holds when the agent paraphrases*

**Claim unlocked:** on the bundled corpus, containment under a restating client
is achievable, and its price can be named. `context-taint` checks egress against
every source in the agent's context rather than the text of the write. It holds
all three scenarios under all five scripted clients, at a cost of exactly one
benign task (`confidential-egress/b2-vendor-invoice-query`, label creep). The
reference policy, frozen and unchanged, still falls to paraphrase on both flow
scenarios. That is kept as a standing regression test, not fixed away.

**Also shipped:** `interpose frontier`, the sweep the claim rests on (scenario
x policy x client, with dominance marked and no combined score), and
`--html`, which writes it as one self-contained page.

**Still cannot claim:** that `context-taint` holds against an attack written
after it. It was written with every bundled attack in view, so under
[`PROTOCOL.md`](PROTOCOL.md) it is not evidence until a later scenario scores
it. Its digest is frozen from the commit that adds it, for exactly that
purpose.

## Shipped — *what label creep costs, and where it can be moved*

**Claim unlocked:** the cost of paraphrase-robust containment depends on
session length, and a per-call policy can move it but not remove it.

- `--session long` runs each benign suite as one session. `context-taint`
  drops from 24/25 to 22/25 once labels accumulate (SIMPL-0015 records what
  this models and what it does not).
- `sink-scoped-taint` declassifies by construction. When the trusted user's
  request names the output sink, reads that sink could not hold are refused,
  so the context never gets tainted. Fresh sessions: 25/25 tasks under
  paraphrase, 4 reads refused. Long sessions: dominated by `context-taint`,
  because refusing reads cannot undo carried taint.
- Refused calls are now a third frontier axis. Without it, a policy that
  finishes every task while refusing calls inside them scored as free.

**Still cannot claim:** a cross-task fix. Forgetting labels at a task boundary
is how a two-task exfiltration is laundered, so session scoping has to be an
architectural decision (and a scenario that attacks it) rather than a policy
rule. Also open: structural sink declaration instead of matching ids in the
request, and tasks whose outputs go to sinks of different sensitivity.

## Next — *scenario three: metadata that lies*

Both bundled scenarios hand the reference policy perfect metadata, which
SIMPL-0008 flags as the assumption most likely to make the reference policy look
better than it is.

- **Misclassified and unclassified objects.** In production, the single most
  common reason object-level authorization fails is that objects are
  unclassified, misclassified, or stale. A policy that only works given perfect
  metadata does not work. This is now the highest-value scenario, because it
  attacks the reference policy's foundation rather than its rules.
- **Cross-principal confused deputy** using the two human principals already in
  the world. Named in the founding survey as the sharpest empty axis, and the
  world already supports it.
- Either is a good first challenge for an outside contributor — see
  [`CHALLENGE.md`](CHALLENGE.md).

## Then — *policy adapters*

**Claim it would unlock:** that a real, externally-maintained authorization
engine can be measured on this frontier.

- Cedar first: embeddable, and AWS AgentCore Policy already uses it for exactly
  this shape of decision. **The open question is answered** -- see
  [`CEDAR-AND-ISOLATION.md`](CEDAR-AND-ISOLATION.md). Cedar can express R3, but
  only decomposed to one tainted source per request; the nested quantification
  R3 is written as is rejected at parse, because Cedar has no lambda. The gap is
  arity, not expressiveness, and the consequence is the publishable part: a
  Cedar-based gateway authorizes *actions*, and something upstream of it has to
  authorize *flows*. `cedarpy` installs as a prebuilt wheel, so the no-build-step
  property survives, and the `SecurityPolicy` interface needed no change.
  **Constraint for this and every adapter:** a PEP may decompose a question, it
  may not answer one. An adapter that has the harness precompute the verdict is
  measuring the harness.
- OPA second, and only behind an extra: an OPA sidecar breaks the no-build-step
  install that is currently the strongest adoption property.
- A human-approval adapter against a simulated approver with a configurable
  rubber-stamp rate. Regulation-adjacent and, as far as I can find, unoccupied.
  Requires `ESCALATE`, which requires a scorer that can grade it.

## Shipped — *the policy cannot touch its own scorecard (opt-in)*

**Claim unlocked:** with `--isolate-policy`, a policy adapter can no longer
rewrite the measurement of itself. It runs in a worker process behind `ipwp/1`.
The two Phase III attacks, rebinding the scorer and erasing tickets through the
heap, now score an honest `COMPROMISED` rather than a detected forgery. A
crashed, hung or malformed worker yields `POLICY_ERROR`, never a verdict. For an
honest policy, every event is identical to in-process apart from identity. See
[`POLICY_WORKER.md`](POLICY_WORKER.md).

Built ahead of the Phase III trigger (the first third-party adapter) because
making it opt-in removes the cost objection. The default path, and every
published number, is unchanged.

**Still cannot claim:** confinement (same user, same filesystem and network),
or containment in the reference-monitor sense. The *enforcement* point is still
in the agent's process, so SIMPL-0001 stays open.

## Then — *out-of-process enforcement*

**Claim it would unlock:** containment rather than convention.

Move `Runner._dispatch` itself, the enforcement point, into a separate process
with no import path from the agent, so tool execution is only reachable through
it. Combined with the policy worker, that is the reference-monitor shape
SIMPL-0001 asks for. Also the trigger for the first genuinely useful container
work: a `--network=none` job that turns the no-egress assertion into an
OS-enforced fact, and a worker that is confined rather than merely separate.

## Then — *paraphrase and adaptive attacks*

**Claim it would unlock:** that a policy holds against attacks its author did
not write.

- Seeded attack generators published alongside results, so instances rotate
  while results stay reproducible.
- Path diversity per objective: N distinct routes to the same predicate, with a
  declared diversity score, so a policy blocking 1 of 4 scores 0.75 and the
  weakness shows up in the number rather than hiding behind it.
- An adaptive attacker only after that, and only inside the containment
  guarantee. It is non-reproducible by construction and it silently changes the
  measured quantity from "did the system hold" to "how good is our attacker".

## Then — *real-model comparison*

**Claim it would unlock:** whether enforcement efficacy is independent of the
model — which would be the strongest empirical form of the thesis.

Needs: multiple seeds, intervals rather than points, and a cost figure nobody
has computed yet. Note that the usual determinism knobs no longer exist
(frontier models reject `temperature`), so this path can never be more than
distributionally reproducible.

## 1.0

Not defined yet, on purpose. A version number should mean something, and right
now nothing has been used by anyone but its author. The condition for
*defining* 1.0 is: three scenarios, two externally-contributed, and at least
one policy adapter for an engine this project did not write. Until then, 1.0
would be a claim about adoption that has not happened.

## Wild future

Explicitly not commitments. Recorded so today's design does not foreclose them,
and so that nothing here contaminates the next milestone.

Persistent enterprise state across scenarios. A full identity graph with
delegation, scoping and expiry. Network topology with a real egress boundary
and DNS exfiltration as a scored channel. Deliberately vulnerable internal
services. Attack graphs from foothold to objective. An incident-response mode
that gives defenders telemetry but not ground truth. Autonomous red and blue
agents. Tournament mode. Research trace datasets. An interactive replay UI.
A CTF surface.

Each is a different product with a funded incumbent. The rule that keeps this
honest: **complexity must be earned.** A subsystem gets built when a claim
requires it, never because a mature cyber range would eventually need it.

## Things that will not be built

- A vendor leaderboard or any ranking.
- A target parameter, in any form.
- Executable code in scenarios.
- Telemetry, crash reporting, or update checks.
- A simulated Active Directory.
- A novel policy DSL.
