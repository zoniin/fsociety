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

import importlib
import inspect
from pathlib import Path
from typing import Protocol, cast, runtime_checkable

from ..digest import sha256_text
from ..errors import PolicyLoadError
from .types import Decision, DecisionContext

__all__ = ["BUILTIN_POLICIES", "SecurityPolicy", "evaluate", "load_policy", "policy_digest"]

#: Short names accepted on the command line. Anything else is treated as a
#: dotted path to a user-supplied module.
BUILTIN_POLICIES: dict[str, str] = {
    "permissive": "interpose.policy.permissive:PermissiveBaseline",
    "path-prefix": "interpose.policy.path_prefix:PathPrefixPolicy",
    "reference": "interpose.policy.reference:ReferenceLeastPrivilege",
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

    A policy whose behaviour lives outside its own source file -- a remote
    service, a data file -- gets a digest that does not capture that
    behaviour. Such adapters should override ``digest`` themselves; the
    limitation is recorded as SIMPL-0007.
    """
    override = getattr(policy, "digest", None)
    if callable(override):
        return str(override())
    try:
        source_file = inspect.getsourcefile(type(policy))
        if source_file:
            text = Path(source_file).read_text(encoding="utf-8")
            return sha256_text(text)
    except (OSError, TypeError):
        pass
    return sha256_text(f"{policy.id}:{policy.version}")
