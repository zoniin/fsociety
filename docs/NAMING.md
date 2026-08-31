# Naming

The project was specified under the codename **fsociety**, with an explicit
instruction that public naming was an open decision and that a note should be
written about whether a distinct identity would eventually be preferable.

It turned out not to be an "eventually" question. The codename is an install
blocker, and the fix is free now and expensive after the first public commit.

## What was verified, not assumed

- `https://pypi.org/pypi/fsociety/json` returns **HTTP 200**. The name is taken
  by "A Modular Penetration Testing Framework", 28 releases, actively
  published. Checked 2026-08-31.
- `Manisso/fsociety` holds roughly 12,000 stars on GitHub, using the same
  cultural reference, in the same vertical.

Three consequences, in order of severity:

1. **The install one-liner cannot be written.** `pip install fsociety` installs
   somebody else's penetration testing tool. For a project whose entire
   adoption argument is "runs in ten seconds with no setup", that is fatal, not
   cosmetic.
2. **GitHub and search ranking are unwinnable** against a 12k-star incumbent in
   the same category.
3. **The name signals offensive tooling**, which contradicts the containment
   promise and fails the clone policies of exactly the enterprises this needs
   to reach.

Five of the seven independent design reviewers raised the name unprompted. Two
verified the PyPI collision directly. It was the most agreed-upon item in the
entire review.

## The decision

The package, the CLI, and the project are **`interpose`**.
`https://pypi.org/pypi/interpose/json` returns 404 — the name is free.

It is not a mood, it is a description. The tool interposes a policy decision
point between an agent and its tools and measures what happens there.
*Interposition* is also an established term in systems security, so the name
tells a security engineer what the thing does before they read a word of prose.

The repository directory is still `fsociety` so the work is where you left it;
renaming it is one `git mv` plus one string in `pyproject.toml`. **This is a
directional product call and it is reversible cheaply right now** — if you want
a different name, the moment to say so is before the first public commit.

## What was rejected, and why it matters

The original brief suggested calling the simulated company **E Corp**. It is
not used.

The reasoning is the same as the naming reasoning, applied consistently: the
aesthetic is worth having, and borrowed trademarks are not worth the ambiguity.
The simulated organisation is **Aldergate Freight**, invented for this, and it
lives entirely in `scenarios/*/world.yaml` — never in core code — so any
scenario author can name their own company without touching the harness.

## Aesthetic direction, kept

The register that made the codename appealing is preserved where it costs
nothing and is load-bearing where it helps:

- Terminal-first, monochrome, fixed-width, information-dense.
- ASCII by default — not austerity, a bug fix. One non-ASCII glyph on a
  `cp1252` stdout raises `UnicodeEncodeError` *and* reports exit 0, so the
  report silently becomes empty the first time someone pipes it to `grep`.
- Anti-corporate in the sense that matters: no badge wall, no marketing voice,
  no dashboard, no telemetry. Claims carry their limitations inline.
- Slightly unsettling by *content* rather than by decoration. The most
  unsettling thing in the output is a real line — `NOT_ATTEMPTED_GAP_OPEN`,
  meaning nothing bad happened and the system would not have stopped it.

What was cut: any TUI, box-drawing theatrics, glitch effects, in-universe
character names in the codebase, and lore. Those repel the two audiences that
matter — platform engineers and authorization maintainers — and they are a
permanent maintenance and accessibility tax.

## No copyrighted material

No dialogue, images, characters, logos, music, episode names, or other
protected material from any work of fiction appears in this repository, and
none should be added. The influence is a register, not a reference.
