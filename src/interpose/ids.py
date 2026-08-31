"""Deterministic identifier generation.

``uuid4`` and wall-clock timestamps are the two most common ways a harness
that claims byte-stable output stops being byte-stable. Neither appears
anywhere in this package: identifiers come from seeded counters, and time
comes from :class:`Clock`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

__all__ = ["Clock", "Counter", "run_id_for"]


@dataclass
class Counter:
    """A monotonic, seeded id source.

    ``Counter("evt").next()`` yields ``evt_000001``, ``evt_000002``, ...
    """

    prefix: str
    _n: int = 0

    def next(self) -> str:
        self._n += 1
        return f"{self.prefix}_{self._n:06d}"

    def reset(self) -> None:
        self._n = 0


@dataclass
class Clock:
    """A fake clock that advances only when the harness says so.

    Real time is nondeterministic and it leaks into artifacts. Every timestamp
    in a run is milliseconds since an arbitrary fixed epoch, advanced one tick
    per recorded event. Wall-clock time appears exactly once per run, in
    ``result.json``'s ``created_at``, and is excluded from every digest.
    """

    tick_ms: int = 1
    _now_ms: int = 0
    _history: list[int] = field(default_factory=list)

    def now_ms(self) -> int:
        return self._now_ms

    def advance(self) -> int:
        self._now_ms += self.tick_ms
        self._history.append(self._now_ms)
        return self._now_ms

    def reset(self) -> None:
        self._now_ms = 0
        self._history.clear()


def run_id_for(*parts: str) -> str:
    """A stable run id derived from the run's inputs.

    Two runs with identical inputs share a run id -- which is the point. A
    changing run id would make golden-file comparison impossible and would
    imply nondeterminism the harness does not have.
    """
    h = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return "run_" + h[:12]
