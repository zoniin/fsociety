# The policy worker (`--isolate-policy`)

```console
interpose run confidential-egress --policy reference --isolate-policy
interpose frontier --isolate-policy
```

Hosts the policy under test in its own process, speaking `ipwp/1` over a pipe.
It is **opt-in**. The default stays in-process, so every published number and
the demo's wall clock are unchanged.

## What it stops

Phase III showed that a policy adapter is arbitrary Python in the harness
process, and reproduced what that allows. A policy that permits an exfiltration
can rebind `runner.evaluate_outcome` and score itself `CONTAINED`, and it can
walk the heap to the `World` and erase the evidence. In-process, integrity
detection catches the careless version of this and marks the run
`APPARATUS_TAMPERED`, but a policy that targets the detector defeats it.

In a worker, neither attack has anything to reach. The policy receives a
decision context as JSON and returns a decision as JSON. The scorer, the event
log and the world are in another address space. Both attacks are kept as tests
(`tests/test_policy_worker.py`). They now produce an honest `COMPROMISED`, not a
detected forgery.

## What it does not stop

- **It is not a sandbox.** The worker runs as the same user, with the same
  filesystem, network and ability to spawn processes. A policy can still read
  your home directory. Phase III measured this, and nothing here changes it.
  Confinement needs a container.
- **It does not close SIMPL-0001.** That entry is about the *enforcement* point,
  `Runner._dispatch`, living in the agent's process. The worker moves the
  *decision* out, not the enforcement.
- **A determined policy can still lie in its decisions.** Isolation protects
  the measurement, not the protected system. A policy that permits a leak is
  scored as permitting a leak, which is the point.

## How the Phase III objections are met

Phase III specified this worker and deliberately left it unbuilt
([`PHASE3_THESIS.md`](research/PHASE3_THESIS.md) §5). Its trigger was the first
third-party adapter, and it named four costs. Shipping it opt-in answers the
first. The other three are design rules here, each with a test.

| Objection | Answer |
|---|---|
| ~18.5% demo cost | Opt-in. The default path does not change. A full isolated `frontier` takes ~6s against ~3.5s in-process. |
| A dead worker scores `CONTAINED` | Every fault raises `PolicyFault`, which takes the existing policy-fault path: the call is denied and the run becomes `POLICY_ERROR`, exit 7, never scored. Faults are terminal for the connection, so every later run on it is `POLICY_ERROR` too. |
| The digest becomes self-attested | The worker's `READY` supplies labels only. The digest is computed by the harness: for a built-in, its in-process import-closure digest bound to the protocol version; for a third-party module, the bytes of every file on its module path, **located without importing it**. An object imitating the proxy cannot choose its digest, because the check is on the exact class. |
| Per-trial workers leak state across runs | One worker per policy, and a fresh policy *instance* inside it for every run (`NEW`). Per-run isolation of policy state (INV-LIFECYCLE-1) holds as it does in-process, without a spawn per run. |

For an honest policy, isolation changes nothing but identity. Every event of
every run is identical to the in-process run, apart from `run_id` and
`policy_digest`, which *should* differ. That is a parametrised test over three
scenarios and three policies.

## Protocol

As specified in [`agents/ipc-protocol.md`](research/phase3/agents/ipc-protocol.md):
`'IPO1'` magic, a big-endian `uint32` length, then canonical JSON. Exchanges:
`HELLO → READY`, `NEW → OK`, `DECIDE → DECISION`, `SHUTDOWN`, and `ERROR` from
the worker. Limits are 1 MiB per request, 64 KiB per response and nesting depth
8, checked on both sides. Unknown fields are rejected. A decision returns
`effect` (`allow`/`deny` only), `rule_id` (a strict pattern), `reason` (at most
512 chars) and `metadata` (`str → str`, at most 16 keys), and anything else is a
fault. The decision timeout is 5s, about 14,000× the measured p99, so reaching
it is always a fault. It never enters a digest.

The worker points fd 1 at stderr before importing the policy, and speaks the
protocol on a private duplicate. A policy that prints corrupts nothing (tested).

## Deviations from the spec

Recorded, not glossed:

1. **Rule-id vocabulary is not enforced.** The spec has the worker declare its
   rule ids in `READY`. Doing that for the built-in policies would change their
   source and so their frozen digests. Rule ids are still checked against the
   pattern.
2. **Argument text is sent unconditionally.** The spec gates model-authored
   arguments behind a negotiated capability. Every built-in policy reads them,
   and an in-process policy already sees them, so gating would change no
   threat in scope.
3. **Shadow-probe faults are not run faults.** The probe already fails closed
   on its *claim* when a policy raises: it reports no permitted route. If a
   worker dies only during the post-run probe, the run's verdict stands, and
   the latent-gap claim is the part lost.
4. **`challenge` does not take `--isolate-policy`.** It refuses non-built-in
   policies anyway, and built-ins are trusted code.
