"""A policy hosted in a separate process, behind ``ipwp/1``.

Opt-in (``--isolate-policy``). The default stays in-process, so every
published number and the demo's wall clock are unchanged.

What this buys, against the threat Phase III demonstrated: a policy can no
longer reach the harness's address space. It cannot rebind
``runner.evaluate_outcome``, walk frames to the ``World``, or mutate the event
log, because none of them exist in its process. It receives a decision
context as data and returns a decision as data.

How each Phase III objection is met (``docs/research/phase3/PHASE3_THESIS.md``
§3-4, ``agents/ipc-protocol.md``):

* **A dead worker must not score CONTAINED.** Every fault raises
  :class:`PolicyFault`. The runner's existing policy-fault path turns that into
  ``POLICY_ERROR``: the call is denied, and the run is invalidated rather
  than scored. A fault is terminal for the connection; every later call on it
  faults too, so one crash cannot be followed by a "recovered" run.
* **The digest must not be self-attested.** The worker's ``READY`` names a
  policy id and version, which label the artifact. The digest is computed by
  the harness from source it can read without executing it. For a built-in
  policy it is the in-process closure digest bound to the protocol version.
  For a third-party module it is the bytes of every file on the module path,
  located without importing anything, and it is labelled as such (SIMPL-0007).
* **Lifetime.** One worker per policy, and a fresh policy *instance* inside it
  for every run (``NEW``), so INV-LIFECYCLE-1 holds as it does in-process,
  without paying a process spawn per run.

What it does not buy, and the documentation must not claim: confinement. The
worker is the same user with the same filesystem and network. A policy can
still read files, open sockets, or spawn processes. It just cannot touch the
harness's memory.
"""

from __future__ import annotations

import contextlib
import importlib.machinery
import itertools
import queue
import subprocess
import sys
import tempfile
import threading
import weakref
from pathlib import Path
from typing import IO, Any

from ..digest import sha256_text
from .types import Decision, DecisionContext
from .wire import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL,
    WireError,
    ctx_to_wire,
    decision_from_wire,
    expect_keys,
    read_frame,
    write_frame,
)

__all__ = ["DECISION_TIMEOUT_S", "HANDSHAKE_TIMEOUT_S", "IsolatedPolicy", "PolicyFault"]

#: ~14 000x the measured p99 round trip. A healthy policy cannot reach it, so a
#: timeout is always a fault, never a slow answer. Never enters a digest.
DECISION_TIMEOUT_S = 5.0
#: Interpreter boot plus imports, including a Rust binding for Cedar.
HANDSHAKE_TIMEOUT_S = 20.0


class PolicyFault(RuntimeError):
    """The worker failed. Terminal for the run and for the connection."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"policy worker fault {code}" + (f": {detail}" if detail else ""))
        self.code = code


class _Connection:
    """One worker process. Synchronous, one request outstanding, ids strictly increasing."""

    def __init__(self, ref: str, *, decision_timeout: float, handshake_timeout: float) -> None:
        self.ref = ref
        self.decision_timeout = decision_timeout
        self._ids = itertools.count(1)
        self._instances = itertools.count(1)
        self._fault: PolicyFault | None = None
        # Lives as long as the worker; closed by the finalizer, not a with-block.
        self._stderr = tempfile.TemporaryFile()  # noqa: SIM115
        self._frames: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "interpose.policy.worker", ref],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
        )
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self._in: IO[bytes] = self.proc.stdin
        # A reader thread rather than select(): select does not work on pipes
        # on Windows, and CI runs there.
        threading.Thread(target=self._reader, args=(self.proc.stdout,), daemon=True).start()
        self._finalizer = weakref.finalize(self, _cleanup, self.proc, self._stderr)

        hello = {"kind": "HELLO", "protocol": PROTOCOL,
                 "limits": {"request": MAX_REQUEST_BYTES, "response": MAX_RESPONSE_BYTES}}
        ready = self._exchange(hello, timeout=handshake_timeout, expect="READY", correlate=False)
        try:
            expect_keys(ready, {"kind", "protocol", "policy_id", "version", "describe"})
        except WireError as exc:
            raise self._die(exc.code, exc.detail) from exc
        if ready["protocol"] != PROTOCOL:
            raise self._die("PROTOCOL_MISMATCH", str(ready["protocol"])[:64])
        self.ready = ready

    def _reader(self, stream: IO[bytes]) -> None:
        try:
            while True:
                frame = read_frame(stream, limit=MAX_RESPONSE_BYTES)
                if frame is None:
                    self._frames.put(("eof", None))
                    return
                self._frames.put(("frame", frame))
        except WireError as exc:
            self._frames.put(("error", exc))
        except Exception as exc:  # pipe torn down mid-read
            self._frames.put(("error", WireError("WORKER_CRASH", str(exc))))

    def _die(self, code: str, detail: str = "") -> PolicyFault:
        if self._fault is None:
            _terminate(self.proc)
            if code in ("WORKER_CRASH", "TIMEOUT") or self.proc.poll() not in (None, 0):
                detail = (detail + " " + self._stderr_tail()).strip()
            self._fault = PolicyFault(code, detail[:500])
        return self._fault

    def _stderr_tail(self) -> str:
        try:
            self._stderr.seek(0)
            data = self._stderr.read()[-400:]
            return data.decode("utf-8", "replace").strip().replace("\n", " | ")
        except OSError:
            return ""

    def _exchange(self, msg: dict[str, Any], *, timeout: float, expect: str,
                  correlate: bool = True) -> dict[str, Any]:
        if self._fault is not None:
            raise self._fault
        fid = next(self._ids)
        msg = {**msg, "id": fid} if correlate else msg
        try:
            write_frame(self._in, msg, limit=MAX_REQUEST_BYTES)
        except WireError as exc:
            raise self._die(exc.code, exc.detail) from exc
        except OSError as exc:
            raise self._die("WORKER_CRASH", f"write failed: {exc}") from exc
        try:
            kind, payload = self._frames.get(timeout=timeout)
        except queue.Empty:
            raise self._die("TIMEOUT", f"no answer in {timeout}s") from None
        if kind == "eof":
            raise self._die("WORKER_CRASH", f"exit status {self.proc.wait()}")
        if kind == "error":
            raise self._die(payload.code, payload.detail)
        frame: dict[str, Any] = payload
        if correlate and frame.get("id") != fid:
            raise self._die("CORRELATION", f"sent {fid}, got {frame.get('id')!r}")
        if frame.get("kind") == "ERROR":
            raise self._die(str(frame.get("code", "ERROR"))[:32], str(frame.get("detail", ""))[:400])
        if frame.get("kind") != expect:
            raise self._die("MALFORMED_FRAME", f"expected {expect}, got {frame.get('kind')!r}")
        return frame

    @property
    def fault(self) -> PolicyFault | None:
        return self._fault

    def new_instance(self) -> int:
        instance = next(self._instances)
        frame = self._exchange({"kind": "NEW", "instance": instance},
                               timeout=self.decision_timeout, expect="OK")
        try:
            expect_keys(frame, {"kind", "id"})
        except WireError as exc:
            raise self._die(exc.code, exc.detail) from exc
        return instance

    def decide(self, instance: int, ctx: DecisionContext) -> Decision:
        frame = self._exchange({"kind": "DECIDE", "instance": instance, "ctx": ctx_to_wire(ctx)},
                               timeout=self.decision_timeout, expect="DECISION")
        body = {k: v for k, v in frame.items() if k not in ("kind", "id")}
        try:
            return decision_from_wire(body)
        except WireError as exc:
            raise self._die(exc.code, exc.detail) from exc

    def close(self) -> None:
        if self._fault is None and self.proc.poll() is None:
            try:
                write_frame(self._in, {"kind": "SHUTDOWN"}, limit=MAX_REQUEST_BYTES)
                self.proc.wait(timeout=2)
            except Exception:
                pass
        self._finalizer()


def _cleanup(proc: subprocess.Popen[bytes], stderr: IO[bytes]) -> None:
    _terminate(proc)
    for stream in (proc.stdin, proc.stdout, stderr):
        if stream is not None:
            with contextlib.suppress(OSError):
                stream.close()


def _terminate(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=2)


class IsolatedPolicy:
    """Implements ``SecurityPolicy`` by forwarding to a worker process.

    ``copy.deepcopy`` -- which is how ``as_policy_factory`` gives every run its
    own policy -- returns a handle to a *fresh instance in the same worker*,
    so per-run isolation of policy state is preserved without a spawn per run.
    """

    def __init__(
        self,
        ref: str,
        *,
        decision_timeout: float = DECISION_TIMEOUT_S,
        handshake_timeout: float = HANDSHAKE_TIMEOUT_S,
        _conn: _Connection | None = None,
        _digest: str | None = None,
    ) -> None:
        self.ref = ref
        self._conn = _conn or _Connection(
            ref, decision_timeout=decision_timeout, handshake_timeout=handshake_timeout
        )
        ready = self._conn.ready
        # Labels, as the worker declares them. Never used as identity.
        self.id = str(ready["policy_id"])
        self.version = str(ready["version"])
        self._describe = str(ready["describe"])
        self.harness_digest = _digest or harness_digest(ref)
        # A dead connection still yields a handle: one whose every call raises
        # the original fault. Raising here instead would surface as a load
        # error and abort the whole trial, rather than marking each later run
        # POLICY_ERROR, which is what a fault is.
        self._instance: int | None
        try:
            self._instance = self._conn.new_instance()
        except PolicyFault:
            if _conn is None:
                raise
            self._instance = None

    def describe(self) -> str:
        return f"[isolated] {self._describe}"

    def evaluate(self, ctx: DecisionContext) -> Decision:
        if self._instance is None:
            raise self._conn.fault or PolicyFault("WORKER_CRASH", "no instance")
        return self._conn.decide(self._instance, ctx)

    def __deepcopy__(self, memo: dict[int, Any]) -> IsolatedPolicy:
        return IsolatedPolicy(self.ref, _conn=self._conn, _digest=self.harness_digest)

    def close(self) -> None:
        self._conn.close()


# -- the digest, computed by the harness ------------------------------------


def harness_digest(ref: str) -> str:
    """What the harness can attest about the code the worker will run.

    Never asks the worker. A built-in is digested exactly as in-process (its
    first-party import closure, which the harness already has loaded), bound to
    the protocol so isolated and in-process results never share a digest. A
    third-party module is located on the path *without executing it* and its
    files are hashed; that covers the entry module and its package
    ``__init__`` files, not what they import (SIMPL-0007, widened).
    """
    module_name = ref.partition(":")[0]
    if module_name.startswith("interpose."):
        from .base import load_policy, policy_digest

        inner = policy_digest(load_policy(ref))
        return sha256_text(f"{PROTOCOL}\nbuiltin\n{ref}\n{inner}")
    files = _locate_without_import(module_name)
    parts = [f"{PROTOCOL}", "external", ref]
    for path in files:
        try:
            parts.append(f"{path.name}\n{path.read_text(encoding='utf-8')}")
        except OSError:
            parts.append(f"{path.name}\n<unreadable>")
    return sha256_text("\n".join(parts))


def _locate_without_import(module_name: str) -> list[Path]:
    """Every source file on the way to ``module_name``, found by path search only."""
    out: list[Path] = []
    search: list[str] | None = None
    parts = module_name.split(".")
    for i in range(len(parts)):
        name = ".".join(parts[: i + 1])
        spec = importlib.machinery.PathFinder.find_spec(name, search)
        if spec is None:
            break
        if spec.origin and spec.origin not in ("built-in", "frozen", "namespace"):
            out.append(Path(spec.origin))
        search = list(spec.submodule_search_locations or [])
    return out
