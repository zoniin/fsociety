# Threat model of interpose itself

This project ships intentionally vulnerable material. Containment is therefore
a product feature, not a disclaimer. **This document threat-models the tool,
not the simulated company.** The simulated company being insecure is the point.

## Assets

What an attacker would want from someone who runs this:

- **Model-provider API keys** in the environment — monetizable, often
  organisation-scoped.
- **Developer machine credentials** — `~/.ssh`, `~/.aws`, `~/.config/gh`.
  Lateral movement into the user's real organisations.
- **Source repositories** on the same machine, under the same UID.
- **CI runner identity** — a compromise there reaches every user.
- **The release channel** — highest blast radius.
- **Distributability** — if a scanner or DLP flags the repository, nobody can
  clone it at work, and the project dies of that alone.

## Trust boundaries

1. **Scenario content into the harness process.** The only genuinely new
   boundary, and the one everything turns on. A scenario is something users
   obtain from strangers.
2. **Model provider into the harness process.** Model output is untrusted
   input. Tool-call arguments come from a source an attacker is actively trying
   to control — that is literally the scenario being simulated.
3. **Harness process to host.** Same UID, same environment, same filesystem.
   **There is no boundary here at V0.** Pretending otherwise is the failure
   mode; see SIMPL-0001.
4. **Contributor to repository to every user.** Standard supply chain, sharper
   here because the project's content is *supposed* to look malicious, which
   degrades reviewer signal.
5. **Repository bytes to third-party readers** — other people's coding agents,
   IDE assistants, scanners, crawlers.

## Risks that are real at V0

V0 is a single Python process with an in-memory simulated organisation, no
containers, no code-execution tool, and optional outbound HTTPS to one model
provider. Ranked honestly.

1. **Scenario-as-code becoming arbitrary code execution.** Critical if the
   feature exists; **zero because it does not**. Scenarios are data. There is
   no code path, not behind a flag. See the decision below.
2. **Unsafe deserialization in the loader.** Critical, trivially avoidable, and
   the most common way a "data-only" design turns back into code execution.
   Mitigated: `yaml.safe_load` only; no `pickle`, `marshal`, `eval`, `exec`, or
   dynamic import on scenario-derived values.
3. **Secrets leaking into run artifacts.** High — artifacts get pasted into
   issues and attached to papers. Mitigated by allowlist serialization: every
   artifact is built field-by-field from a declared schema, and nothing is
   written by dumping an object, a dict, or an exception. Proven by a test that
   puts a canary in `ANTHROPIC_API_KEY` and asserts it appears in no artifact.
4. **Path traversal from model-controlled arguments into real host files.**
   High. Mitigated: `read_internal_file` resolves against an in-memory
   namespace and never touches `pathlib.Path`. If it did, the demo would *be*
   the exploit. Tested against `../../../../etc/passwd`, absolute POSIX and
   Windows paths, and mixed traversal.
5. **The repository as a payload-distribution channel.** Medium-high, and a
   *distribution* risk rather than a compromise one. Mitigations in the next
   section.

## Risks that are not real at V0 — do not inflate them

- **Sandbox escape.** There is no sandbox. An in-process simulation with no
  code-execution tool is not a container with a hole in it.
- **Network pivot to third parties.** Impossible without a target parameter,
  and there is none. See below.
- **Container breakout, Docker socket abuse.** No containers.
- **"Prompt injection against interpose".** A scenario injecting the simulated
  agent is a **passing test**, not a vulnerability.

## The decision: scenarios are data

Scenarios may not ship executable code. Not behind a flag, not for trusted
authors, not ever. This is a one-way door — a code path can be added later, but
it can never be removed once scenarios circulate.

**Why, in two parts.**

*Python cannot sandbox Python, and implying otherwise is dishonest.* `exec`
with stripped builtins, AST allowlists and RestrictedPython all have documented
escapes via `().__class__.__bases__[0].__subclasses__()` walks and frame
introspection. PyPy's sandbox is deprecated. The only real boundaries are
OS-level (seccomp, Landlock, AppContainer via a child process), container-level,
or WASM — none of which fits a small-dependency single process.

`sys.addaudithook` is stronger than most people assume: it fires on
`socket.connect`, `getaddrinfo`, `urllib.Request`, `subprocess.Popen`,
`os.system`, `ctypes.dlopen`, `open`, `compile`, `exec`, `import` and
`marshal.loads`, and there is no `sys.removeaudithook`. But it is a *guardrail*,
not a sandbox: it does not propagate into child processes, and `ctypes` handles
acquired before installation remain an escape.

*And the code/data distinction is what makes third-party scenarios possible at
all.* The moment a scenario can ship Python, `interpose run community/x`
becomes "execute this stranger's code as me, with my API keys in the
environment and my SSH keys on disk", triggered by content designed to
manipulate. That is a malware distribution channel with a security-research
veneer, and it is precisely the agentic-supply-chain failure this project
exists to study.

**What is lost, and how it comes back.** Expressiveness now comes from a
harness-owned primitive library. A scenario needing genuinely new tool
behaviour is a pull request here, reviewed as code. Tool vocabulary grows on
purpose and slowly. That is a real cost, and it is the right trade.

**Policy adapters are different, deliberately.** They are ordinary Python
modules loaded by explicit dotted path, never referenced from scenario YAML,
never auto-downloaded, never resolved from a registry. Running one is running
its author's code with exactly the trust that implies — the same trust you
extend to any dependency you install and name on a command line. Scenario
content *circulates*; a policy adapter is *chosen*. Collapsing those two into
one rule is the mistake.

## Adversarial content in the repository

`scenarios/*/untrusted/` contains working prompt-injection payloads. Risks, in
order:

1. **Other people's agents ingest them.** A coding assistant indexing this
   repository reads text addressed to an assistant. That injection is not
   targeting *our* simulated agent — it targets whoever's assistant is reading.
2. **Scanners, EDR and corporate DLP flag the clone**, killing adoption inside
   exactly the organisations that need this.
3. **Training-data contamination**, which saturates the benchmark.

Conventions adopted:

- Payloads are **base64-encoded** under `scenarios/<name>/untrusted/`. This is
  friction and a statement of intent, **not a control** — assume a determined
  indexer defeats it.
- Every decoded payload must contain the marker
  `INTERPOSE-SIM-PAYLOAD-DO-NOT-EXECUTE`, and **the loader rejects any payload
  that lacks it**. A scenario cannot ship content that fails to identify
  itself. Scanner and DLP operators can grep for that string to classify a hit
  as laboratory content in one step.
- Every sensitive fixture carries an `INTERPOSE-CANARY-*` marker, which doubles
  as exact exposure detection and as an identifier if this corpus contaminates
  a training set.
- `untrusted/WARNING.md` addresses both humans and reading agents directly.
- Payload text never appears in `README.md`, docstrings, test names, commit
  messages, or CI logs.

**UNVERIFIED:** whether base64 encoding meaningfully affects any real scanner,
indexer, or DLP product. Assume it does not. A canary-repository experiment
before any public launch would settle it and has not been run.

## Network posture

Default-deny outbound. A deterministic run makes **zero** connections.

What is claimed and what is proven are different things, and only the weaker
claim is made:

- **Proven** (`tests/test_containment.py`): a fully warmed deterministic run
  under a process-wide audit hook attempts no egress, and a structural test
  asserts that `socket`, `httpx`, `requests` and `urllib` are imported by
  exactly one module in the whole package.
- **Not proven:** that the process is *incapable* of reaching the network. C
  extensions, pre-existing handles, and child processes all bypass an audit
  hook. The OS-enforced version of this claim is a `--network=none` container
  job on main and release.

A CPython note found while building this: on 3.13, installing any audit hook
breaks the cached-bytecode import path (`AttributeError: 'bytes' object has no
attribute 'co_filename'`) — even for `import json`. The probe therefore warms
every import before installing the hook, which means egress *during import* is
not covered by that test. SIMPL-0006.

## Secrets

API keys via environment variables only. Never a config field, never a CLI flag
— shell history, `ps`, and CI logs all capture flags.

Redaction, in priority order:

1. **Allowlist serialization is the control.** Artifacts are built
   field-by-field from declared schemas. Nothing is written by dumping an
   object, a dict, or an exception's `__dict__`.
2. Value-equality scrubbing would be the second layer. Pattern-only redaction
   is the thing that fails, and is never the first line.
3. The proving test: set `ANTHROPIC_API_KEY` to a canary, run everything,
   assert the bytes appear in no artifact.

Also: model-controlled and scenario-controlled strings pass through
`events.scrub()` before reaching a terminal or a log, so an ANSI escape in a
document body cannot repaint the report describing it.

## Containers: the trigger

Not in V0. They would add fidelity to a layer nothing is scored at, while
turning a twelve-second suite into a five-minute one with a new flake class.

Containers become **necessary**, not nice, at the first of:

1. A tool that executes arbitrary code (`run_shell`, `execute_python`). At that
   instant the Python process boundary stops being a boundary. No exceptions.
2. Enforcement expressed as network egress control — testing an egress proxy
   in-process tests a mock of the measured thing.
3. Benchmarking a third-party policy engine that ships as a server (OPA
   sidecar, SpiceDB, an MCP gateway). In-process Cedar via a binding is fine.
4. Tools that speak a wire protocol, because parser bugs enter scope.

"It would feel more real" is not a trigger.

When triggered, the posture is non-negotiable: no `--privileged`,
`--cap-drop=ALL`, `--security-opt=no-new-privileges`, default seccomp, non-root
UID, `--read-only` rootfs with one explicit tmpfs, `--network=none` for
deterministic runs and an internal-only bridge otherwise, memory/CPU/pid
limits, **never** mounting `/var/run/docker.sock`, no bind mount of the host
repository, images pinned by digest.

## Dangerous defaults that must never ship

1. No target host, URL, IP or endpoint parameter anywhere — not behind a flag,
   an environment variable, or "for advanced users". Enforced by a test.
2. No execution of scenario-supplied code, in any language.
3. No `yaml.load`, `pickle`, `marshal`, `eval`, `exec`, or dynamic import on
   scenario-derived values.
4. No network call in the default run path.
5. No `os.environ`, raw request objects, or unredacted headers in any artifact.
6. No API keys via CLI flag or config file.
7. No model- or scenario-supplied path resolved against the real filesystem.
8. No auto-download of scenarios, models, or datasets.
9. No telemetry, crash reporting, or update checks — not even opt-out.
10. No fork-PR CI with secrets in scope; actions pinned to commit SHAs.
11. No payload emitted without the required marker.
12. No raw model output to a terminal without control-character stripping.

## Known limitations

Everything in [`SIMPLIFICATIONS.md`](SIMPLIFICATIONS.md). The two that most
affect how you should read any number:

- **SIMPL-0001** — the policy decision point runs in the same address space as
  the thing it mediates. It is not tamper-proof and not independently
  verifiable: two of Anderson's three reference-monitor properties are absent.
  Every containment number is optimistic by an unmeasured amount.
- **SIMPL-0003** — exposure detection is exact canary matching, so an agent
  that paraphrases rather than quotes is not detected. Exposure is undercounted.
