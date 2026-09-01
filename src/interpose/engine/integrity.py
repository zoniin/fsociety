"""Apparatus integrity: detect mutation of the measurement machinery.

Phase III established that a policy adapter is arbitrary Python in the harness
process, and demonstrated the consequence: a policy that permits the whole
`confidential-egress` exfiltration and rebinds `runner.evaluate_outcome` scores
itself ``CONTAINED``, defeats both observers, and **poisons every later policy
in the same process**. An impersonating adapter got ``interpose verify`` to
print ``AGREES`` over a forged result.

The response is deliberately not a process boundary. See
``docs/research/phase3/PHASE3_THESIS.md`` for why, and the escalation ladder
this module sits on:

    PREVENT             when the boundary is cheap and justified
    DETECT + INVALIDATE when prevention needs unjustified architecture
    DOCUMENT            when neither is credible

For a chosen first-party dependency, **detect and invalidate** is the honest
rung. A tampered run does not need to be *stopped*; it needs to not be
*published*. Once the grader may itself have changed, the security outcome is no
longer trustworthy, and reporting it as ``CONTAINED``, ``COMPROMISED`` or even
``ERROR`` would each be a different way of pretending otherwise.

What this does **not** do, stated plainly so nobody reads it as containment:

* It does not prevent anything. A policy that mutates the apparatus succeeds in
  mutating it; the run is then discarded.
* It does not survive an adapter that targets the detector itself. References
  are captured before any policy is loaded, which raises the bar, but this is
  detection of careless and casual tampering, not defence against a determined
  adversary. That adversary needs `INV-*` enforcement the process boundary
  would give, and the trigger for building it is in the thesis.
* It is not a security control for the *simulated* system. It is a validity
  control for the *experiment*.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "ApparatusSnapshot",
    "TamperReport",
    "pristine_functions",
    "snapshot_apparatus",
]


@dataclass(frozen=True)
class TamperReport:
    """What changed, if anything. Empty ``changes`` means the run is scorable."""

    changes: tuple[str, ...] = ()

    @property
    def tampered(self) -> bool:
        return bool(self.changes)

    def describe(self) -> str:
        return "; ".join(self.changes)


@dataclass(frozen=True)
class ApparatusSnapshot:
    """Identities of the machinery a run is scored by.

    Function *identity* rather than source: the demonstrated attack rebinds a
    module global, so the source on disk is unchanged and only the object the
    name resolves to differs. Comparing source would have missed it entirely.
    """

    functions: tuple[tuple[str, int], ...]
    world_digest: str

    def compare(self, other: ApparatusSnapshot) -> TamperReport:
        changes: list[str] = []

        before = dict(self.functions)
        after = dict(other.functions)
        for name in sorted(set(before) | set(after)):
            if name not in after:
                changes.append(f"{name} was removed")
            elif name not in before:
                changes.append(f"{name} appeared")
            elif before[name] != after[name]:
                changes.append(f"{name} was rebound")

        if self.world_digest != other.world_digest:
            changes.append(
                f"world state changed outside the mediated path "
                f"({self.world_digest[:19]} -> {other.world_digest[:19]})"
            )
        return TamperReport(tuple(changes))


#: The names whose rebinding would let a policy rewrite its own scorecard. Each
#: was reachable in the demonstrated attacks.
_WATCHED: tuple[tuple[str, str], ...] = (
    ("engine.runner", "evaluate_outcome"),
    ("engine.runner", "shadow_probe"),
    ("engine.outcome", "evaluate_outcome"),
    ("engine.outcome", "_verdict"),
    ("engine.probe", "shadow_probe"),
    ("world.models", "Resource"),
    ("policy.base", "evaluate"),
    ("policy.base", "policy_digest"),
)


def snapshot_apparatus(world_digest: str) -> ApparatusSnapshot:
    """Capture the identity of every watched name, plus the world digest.

    ``world_digest`` is supplied rather than computed here so the caller decides
    *when* the world is meant to be stable — the mediated path legitimately
    mutates it, so a snapshot taken at the wrong moment would report tampering
    on every successful write.
    """
    import importlib

    identities: list[tuple[str, int]] = []
    for module_suffix, attribute in _WATCHED:
        try:
            module: Any = importlib.import_module(f"interpose.{module_suffix}")
            target = getattr(module, attribute, None)
        except ImportError:  # pragma: no cover - a watched module must import
            target = None
        identities.append((f"{module_suffix}.{attribute}", id(target) if target else 0))

    return ApparatusSnapshot(functions=tuple(identities), world_digest=world_digest)


#: Captured when this module is first imported -- which happens as part of
#: importing the engine, and therefore **before any policy adapter is loaded**,
#: because `load_policy` runs at command time.
#:
#: The baseline must be process-level, not per-run. A policy that rebinds a
#: watched name in run N leaves it rebound for run N+1, so a per-run "before"
#: snapshot would capture the *patched* state as normal and report no tampering
#: for every subsequent policy. That is precisely the cross-run poisoning the
#: demonstrated attack achieved: one hostile adapter loaded once, and every
#: later honest policy in the batch scored wrong.
_PRISTINE: tuple[tuple[str, int], ...] = ()


def pristine_functions() -> tuple[tuple[str, int], ...]:
    """The watched identities as they were before any policy was loaded."""
    global _PRISTINE
    if not _PRISTINE:
        _PRISTINE = snapshot_apparatus("").functions
    return _PRISTINE

