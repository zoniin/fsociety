"""The policy protocol, and how policies are resolved.

A policy is **ordinary Python that the user chose to run**, loaded by explicit
dotted path and never referenced from scenario YAML. That asymmetry with
scenarios is deliberate and it is the central trust decision in the project:

* *Scenario content circulates.* It is obtained from strangers, it is designed
  to manipulate, and it ships as fixtures. It is data, with no code path, ever.
* *Policy adapters are dependencies.* You install one the way you install any
  package, and you name it on the command line. Running one is running its
  author's code, with exactly the trust that implies -- no more, and no less.

Collapsing those two into one rule is how a benchmark becomes a malware
distribution channel with a security-research veneer.

Why the interface is synchronous: a batch regression harness has no
concurrency requirement, and a network-bound adapter can simply block. Adding
``async`` to every call site to serve a need that does not exist would buy
complexity and no capability. If a future adapter needs concurrency, the
single call site in :func:`evaluate` is the only thing that changes.
"""

from __future__ import annotations

import copy
import importlib
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast, runtime_checkable

from ..digest import sha256_text
from ..errors import PolicyLoadError
from .types import Decision, DecisionContext

__all__ = [
    "BUILTIN_POLICIES",
    "PolicyFactory",
    "SecurityPolicy",
    "as_policy_factory",
    "evaluate",
    "load_policy",
    "policy_digest",
]

#: Produces a policy instance for exactly one scored run. See
#: :func:`as_policy_factory` for why this is a factory and not an object.
PolicyFactory = Callable[[], "SecurityPolicy"]

#: Short names accepted on the command line. Anything else is treated as a
#: dotted path to a user-supplied module.
BUILTIN_POLICIES: dict[str, str] = {
    "permissive": "interpose.policy.permissive:PermissiveBaseline",
    "path-prefix": "interpose.policy.path_prefix:PathPrefixPolicy",
    "reference": "interpose.policy.reference:ReferenceLeastPrivilege",
    # Both need the optional 'cedar' extra to *run*. They load, describe and
    # digest without it, so `ls`, `freeze` and the freeze self-test stay green
    # on the two-dependency default install.
    "cedar-action-only": "interpose.policy.cedar_action_only:CedarActionOnly",
    "cedar-with-provenance": "interpose.policy.cedar_with_provenance:CedarWithProvenance",
}


@runtime_checkable
class SecurityPolicy(Protocol):
    """The one interface a security product implements to be measured here."""

    #: Stable identifier that appears in every artifact.
    id: str
    #: Policy version, independent of the harness version.
    version: str

    def describe(self) -> str:
        """One line, shown by ``interpose ls policies``."""
        ...

    def evaluate(self, ctx: DecisionContext) -> Decision:
        """Decide a single action. Must be a pure function of ``ctx``.

        Purity is not enforceable and is not enforced. It is a claim the
        policy author makes; a policy that consults a network service is a
        legitimate entrant, and its latency and nondeterminism are properties
        of that defense, not of the harness.
        """
        ...


def evaluate(policy: SecurityPolicy, ctx: DecisionContext) -> Decision:
    """Single call site for every policy invocation in the project."""
    decision = policy.evaluate(ctx)
    if not isinstance(decision, Decision):
        raise PolicyLoadError(
            f"policy {policy.id!r} returned {type(decision).__name__}, expected Decision"
        )
    return decision


def load_policy(ref: str) -> SecurityPolicy:
    """Resolve a policy by short name or ``module.path:ClassName``."""
    target = BUILTIN_POLICIES.get(ref, ref)
    if ":" not in target:
        raise PolicyLoadError(
            f"unknown policy {ref!r}. Use one of {sorted(BUILTIN_POLICIES)} "
            "or an explicit 'module.path:ClassName'."
        )
    module_name, _, attr = target.partition(":")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise PolicyLoadError(f"cannot import policy module {module_name!r}: {exc}") from exc
    try:
        obj = getattr(module, attr)
    except AttributeError as exc:
        raise PolicyLoadError(f"{module_name!r} has no attribute {attr!r}") from exc

    instance = obj() if isinstance(obj, type) else obj
    for required in ("id", "version", "evaluate", "describe"):
        if not hasattr(instance, required):
            raise PolicyLoadError(f"policy {target!r} is missing required member {required!r}")
    return cast(SecurityPolicy, instance)


def policy_digest(policy: SecurityPolicy) -> str:  # SIMPL-0007
    """Content digest of the policy implementation.

    This is what gives the frozen-policy protocol teeth. A published result
    names the exact bytes that produced it, so "the policy was written before
    the attacks that score it" becomes checkable from git history plus this
    hash rather than asserted in a README.

    **This function must never ask the policy what its digest is.** It used to:
    a ``digest()`` method on the adapter was honoured as an override, on the
    reasoning that a policy whose behaviour lives outside its source file knows
    best. Against an adversarial adapter that is exactly backwards. A hostile
    policy returned the *genuine* reference policy's digest, matched
    ``policy-freeze.json`` byte for byte, and ``interpose verify`` printed
    ``AGREES`` over a forged result in which the adapter had performed the
    exfiltration itself. Self-attestation is not identity.

    What remains is a hash of the adapter's own source and its first-party
    import closure. That is honest but **weak for third-party code**: an
    external adapter's closure contains no ``interpose.*`` modules beyond the
    shared ones, so two adapters with opposite behaviour can digest alike. A
    digest therefore certifies a *built-in* policy and says little about an
    external one -- recorded as SIMPL-0007, and the reason
    ``interpose challenge`` now refuses non-built-in targets.
    """
    texts = _import_closure_sources(type(policy))
    if texts:
        return sha256_text("\n".join(texts))
    return sha256_text(f"{policy.id}:{policy.version}")


def _import_closure_sources(cls: type) -> list[str]:
    """Source of the policy's module plus every ``interpose`` module it imports.

    Hashing one file was not enough, and the gap was not theoretical: R3's
    entitlement logic lives in ``policy/types.py``, not ``policy/reference.py``.
    Three lines replaced in ``types.py`` gutted R3 -- the flagship scenario
    started leaking -- while ``reference.py`` stayed byte-identical and
    ``freeze --check`` printed FREEZE INTACT and exited 0. Retraction R6.

    The closure is walked transitively and restricted to first-party modules;
    third-party and stdlib versions are pinning's job, not this function's. A
    policy whose behaviour lives outside imported source -- a remote service, a
    data file -- still gets a digest that does not capture it, and should
    override ``digest`` itself. That residue is SIMPL-0007.
    """
    seen: set[str] = set()
    queue = [getattr(cls, "__module__", "")]
    files: list[tuple[str, str]] = []
    while queue:
        name = queue.pop()
        if not name or name in seen or not name.startswith("interpose"):
            continue
        seen.add(name)
        module = sys.modules.get(name)
        if module is None:
            continue
        path = getattr(module, "__file__", None)
        if path:
            try:
                files.append((name, Path(path).read_text(encoding="utf-8")))
            except OSError:
                continue
        for value in vars(module).values():
            origin = getattr(value, "__module__", None)
            if isinstance(origin, str):
                queue.append(origin)
            elif isinstance(value, ModuleType):
                queue.append(value.__name__)
    return [text for _, text in sorted(files)]


def as_policy_factory(source: SecurityPolicy | type | PolicyFactory) -> PolicyFactory:
    """Adapt a policy, a policy class, or a factory into a per-run factory.

    **A policy instance participates in exactly one scored run** (INV-LIFECYCLE-1).

    Providers have had this guarantee since V0 -- ``run_trial`` takes a
    ``ProviderFactory`` and ``trial.py`` explains at length why a provider must
    not carry state between runs. Policies were handed a single object and the
    same object was threaded through the attack run and all eight benign runs,
    and through all 25 cells of ``matrix``.

    That was not a hypothetical. The shadow probe replays the declared adversary
    objective through the ordinary ``evaluate`` call site, so every run --
    including a benign task that reads a public travel policy -- shows the policy
    the attack's tool-and-argument shapes. With a shared instance a policy that
    merely *memoises* accumulates the objective across runs; a deliberately
    harvesting one scored 8 of 9 matrix cells CONTAINED, against 0 of 9 with
    fresh instances. See ``tests/test_policy_lifecycle.py``.

    A class is instantiated per run. A factory is used as given. A bare instance
    is deep-copied per run, so state cannot accumulate even when the caller has
    already used it -- and if it cannot be copied, the caller is told rather than
    silently getting the shared-state behaviour back.
    """
    if isinstance(source, type):
        return lambda: cast("SecurityPolicy", source())
    if callable(source) and not hasattr(source, "evaluate"):
        return cast(PolicyFactory, source)

    instance = cast("SecurityPolicy", source)
    try:
        copy.deepcopy(instance)
    except Exception as exc:
        raise PolicyLoadError(
            f"policy {getattr(instance, 'id', instance)!r} cannot be copied per run "
            f"({exc}), so it would carry state between runs and violate "
            "INV-LIFECYCLE-1. Pass a class or a factory instead."
        ) from exc
    return lambda: cast("SecurityPolicy", copy.deepcopy(instance))
