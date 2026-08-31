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

## Next — *scenario two*

The highest-priority milestone, because three design decisions rest on an
expressiveness claim nothing has tested.

- Author a second scenario against the same primitive library and the same YAML
  contract. If it needs a primitive that does not exist, that is a core pull
  request — and it is the answer to whether the data-only format has a second
  user.
- Best candidate: **misclassified and unclassified objects.** SIMPL-0008 says
  the reference policy is handed perfect metadata, and in production the single
  most common reason object-level authorization fails is that objects are
  unclassified, misclassified, or stale. A policy that only works given perfect
  metadata does not work.
- Second candidate: **cross-principal confused deputy** using the two human
  principals already in the world. Named in the survey as the sharpest empty
  axis, and the world already supports it.

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
