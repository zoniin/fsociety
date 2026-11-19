"""One place that turns a provider name into a factory.

Accepted forms:

``compliant`` / ``paraphrasing`` / ...
    A bare behaviour class, shorthand for the scripted client.
``scripted[:<behaviour>]``
    The deterministic scripted client.
``anthropic[:<model>[@<effort>]]``
    A real model through the Anthropic API, e.g. ``anthropic:claude-opus-5-5@low``.
    Needs the ``anthropic`` extra and a credential; never imported otherwise.

The CLI and the frontier both resolve names here, so the same string means
the same client everywhere it is accepted.
"""

from __future__ import annotations

from collections.abc import Callable

from ..errors import UsageError
from .base import AgentProvider
from .scripted import BEHAVIOR_CLASSES, ScriptedProvider

__all__ = ["EFFORT_LEVELS", "is_deterministic_spec", "provider_factory"]

EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")


def provider_factory(name: str) -> Callable[[], AgentProvider]:
    """Return a zero-argument factory. Providers hold per-run state."""
    if name in BEHAVIOR_CLASSES:
        name = f"scripted:{name}"
    if name.startswith("scripted"):
        _, _, behavior = name.partition(":")
        behavior = behavior or "compliant"
        if behavior not in BEHAVIOR_CLASSES:
            raise UsageError(
                f"unknown behaviour class {behavior!r}; choose from {list(BEHAVIOR_CLASSES)}"
            )
        return lambda: ScriptedProvider(behavior=behavior)
    if name == "anthropic" or name.startswith("anthropic:"):
        from .anthropic_provider import DEFAULT_MODEL, AnthropicProvider

        _, _, rest = name.partition(":")
        model, _, effort = rest.partition("@")
        if effort and effort not in EFFORT_LEVELS:
            raise UsageError(f"unknown effort {effort!r}; choose from {list(EFFORT_LEVELS)}")
        resolved = model or DEFAULT_MODEL
        return lambda: AnthropicProvider(model=resolved, effort=effort or None)
    raise UsageError(
        f"unknown provider {name!r}. Use a behaviour class, scripted[:class], "
        "or anthropic[:model[@effort]]."
    )


def is_deterministic_spec(name: str) -> bool:
    """True for names that resolve to the scripted client, without building one."""
    return name in BEHAVIOR_CLASSES or name.startswith("scripted")
