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
  this shape of decision. **Open question that must be answered before
  starting:** Cedar has no taint or information-flow primitive, so it may not
  be able to express the R3 egress rule at all. If it cannot, that is itself a
  publishable finding about the gap between deployed authorization engines and
  what agent security needs.
- OPA second, and only behind an extra: an OPA sidecar breaks the no-build-step
  install that is currently the strongest adoption property.
- A human-approval adapter against a simulated approver with a configurable
  rubber-stamp rate. Regulation-adjacent and, as far as I can find, unoccupied.
  Requires `ESCALATE`, which requires a scorer that can grade it.

## Then — *out-of-process mediation*

**Claim it would unlock:** containment rather than convention. Today the policy
decision point is a function call in the agent's own process.

Enforcement point in a separate process, no import path from the agent,
serialization as the trust boundary. This closes SIMPL-0001 — the first entry
in the register and the one that biases every containment number.

Also the trigger for the first genuinely useful container work: a
`--network=none` job that turns the no-egress assertion into an OS-enforced
fact.

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
