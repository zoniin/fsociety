"""Session-scoped near-duplicate detection between reads and privileged calls.

.. warning::

   **This module previously described itself as data provenance answering
   "which untrusted bytes reached which privileged call".** That claim was
   retracted on 2026-08-31 (R3, R4 in ``docs/research/RETRACTIONS.md``). What is
   implemented is literal eight-word-span matching between the content of a
   single-resource read and the text the model later wrote into a tool call.
   Any restatement of the content defeats it, and two of the five bundled tools
   attach no source to their output at all -- so for content arriving through
   ``search_documents`` or ``get_employee_profile`` the question is answered
   wrongly and silently rather than incompletely.

   Do not describe this as information-flow control. It is a DLP fingerprint
   matcher with a session scope.

**Labels on values that cross the tool boundary.** Every tool result is a
:class:`Tagged` value carrying the set of sources it was derived from --
in practice always zero or one, because no bundled tool derives a value from
more than one resource. The lattice join this was built for is never
exercised.

**Attribution of model-authored text.** The agent's tool-call *arguments* are
free text the model wrote. Nothing labels them, so provenance must be
recovered by matching argument content against ingested content. The matcher
here uses word shingles plus exact canary tokens.

That second mechanism is an *under-approximation*, and the honesty of every
containment number depends on saying so: an agent that paraphrases a payroll
row rather than quoting it defeats shingle matching entirely. Recorded as
SIMPL-0002; bias: optimistic.

Two provenance views are therefore recorded for every proposal, and they
bracket the truth:

``context_provenance``
    Every source that entered the agent context before the proposal. An
    *over*-approximation -- reading a document taints every later call.
``value_provenance``
    Sources whose content is detectably present in the arguments. An
    *under*-approximation.

A policy may use either. The reference policy uses ``value_provenance`` for
its egress rule; ``context_provenance`` is recorded alongside for comparison.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Generic, TypeVar

__all__ = [
    "CLASSIFICATION_ORDER",
    "SHINGLE_SIZE",
    "Classification",
    "ProvenanceIndex",
    "Source",
    "Tagged",
    "TrustClass",
    "join_sources",
]

T = TypeVar("T")

#: Word count per shingle used for content attribution. Larger is stricter
#: (fewer false attributions, more misses); 8 is a common near-duplicate
#: detection default and is fixed here so results stay comparable.
SHINGLE_SIZE = 8


class TrustClass(StrEnum):
    """Where content came from, from the harness point of view.

    Note what is *absent*: there is no ``malicious`` class. A policy is told
    that content is externally supplied, never that it is the attack. Handing
    a policy the answer key is the fastest way to build a benchmark that
    measures nothing.
    """

    TRUSTED_USER = "trusted_user"
    TRUSTED_SYSTEM = "trusted_system"
    UNTRUSTED_EXTERNAL = "untrusted_external"
    TOOL_OUTPUT = "tool_output"


class Classification(StrEnum):
    """Sensitivity of a resource. Ordered; see :data:`CLASSIFICATION_ORDER`."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


CLASSIFICATION_ORDER: dict[Classification, int] = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
}


@dataclass(frozen=True, order=True)
class Source:
    """One labelled unit of content that entered the run."""

    unit_id: str
    resource_uri: str
    trust: TrustClass
    classification: Classification

    def as_dict(self) -> dict[str, str]:
        return {
            "unit_id": self.unit_id,
            "resource_uri": self.resource_uri,
            "trust": self.trust.value,
            "classification": self.classification.value,
        }


@dataclass(frozen=True)
class Tagged(Generic[T]):
    """A value plus the set of sources it derives from."""

    value: T
    sources: frozenset[Source] = field(default_factory=frozenset)

    def with_sources(self, *extra: Source) -> Tagged[T]:
        return Tagged(self.value, self.sources | frozenset(extra))

    @property
    def max_classification(self) -> Classification:
        """Highest classification among the sources; PUBLIC when unsourced."""
        if not self.sources:
            return Classification.PUBLIC
        return max(
            (s.classification for s in self.sources),
            key=lambda c: CLASSIFICATION_ORDER[c],
        )

    @property
    def is_untrusted(self) -> bool:
        return any(s.trust is TrustClass.UNTRUSTED_EXTERNAL for s in self.sources)

    def sorted_sources(self) -> list[Source]:
        return sorted(self.sources, key=lambda s: s.unit_id)


def join_sources(*tagged: Tagged[object]) -> frozenset[Source]:
    """Lattice join: the union of every input source set."""
    out: frozenset[Source] = frozenset()
    for t in tagged:
        out |= t.sources
    return out


_WORD_RE = re.compile(r"[A-Za-z0-9_]+")


def _shingles(text: str, size: int = SHINGLE_SIZE) -> frozenset[str]:
    """Lowercased word n-grams. Deterministic and whitespace-insensitive."""
    words = [w.lower() for w in _WORD_RE.findall(text)]
    if not words:
        return frozenset()
    if len(words) < size:
        return frozenset([" ".join(words)])
    return frozenset(" ".join(words[i : i + size]) for i in range(len(words) - size + 1))


class ProvenanceIndex:
    """Attributes model-authored text back to the content it derives from.

    Registration order does not affect results: attribution returns a set and
    every consumer sorts by ``unit_id``.
    """

    def __init__(self, shingle_size: int = SHINGLE_SIZE) -> None:
        self._shingle_size = shingle_size
        self._by_unit: dict[str, tuple[Source, frozenset[str], frozenset[str]]] = {}

    def register(
        self,
        source: Source,
        text: str,
        canaries: frozenset[str] = frozenset(),
    ) -> None:
        """Index one content unit for later attribution.

        ``canaries`` are exact strings whose presence is unambiguous evidence.
        They are matched literally; shingles are the fuzzy fallback.
        """
        self._by_unit[source.unit_id] = (
            source,
            _shingles(text, self._shingle_size),
            canaries,
        )

    def attribute(self, text: str) -> frozenset[Source]:  # SIMPL-0002
        """Return sources whose content is detectably present in ``text``."""
        if not text:
            return frozenset()
        probe = _shingles(text, self._shingle_size)
        hits: set[Source] = set()
        for source, shingles, canaries in self._by_unit.values():
            if any(c in text for c in canaries) or shingles & probe:
                hits.add(source)
        return frozenset(hits)

    def attribute_args(self, arguments: dict[str, object]) -> frozenset[Source]:
        """Attribute the concatenation of every string-valued argument."""
        blob = "\n".join(str(v) for v in arguments.values() if isinstance(v, str))
        return self.attribute(blob)
