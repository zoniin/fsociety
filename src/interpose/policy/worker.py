"""The policy worker: hosts one policy in its own process.

Run by the harness as ``python -m interpose.policy.worker <module:Class>``.
Speaks ``ipwp/1`` (see :mod:`interpose.policy.wire`) on a private copy of the
original stdout; fd 1 is pointed at stderr *before* the policy is imported, so
a policy that prints corrupts nothing.

The worker holds no world, no event log and no scorer. It receives a
:class:`DecisionContext` as data and returns a :class:`Decision` as data, which
is the whole point: whatever the policy does to this interpreter, the
harness's interpreter is not in reach.

**This is a process boundary, not a sandbox.** The worker runs as the same
user with the same filesystem and network. See ``docs/POLICY_WORKER.md``.
"""

from __future__ import annotations

import os
import sys
import traceback
from typing import Any

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m interpose.policy.worker <module:Class>", file=sys.stderr)
        return 2
    ref = args[0]

    # Take the protocol channel before anything else can write to it.
    wire_out = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    wire_in = sys.stdin.buffer

    from .base import as_policy_factory, load_policy
    from .wire import (
        MAX_REQUEST_BYTES,
        MAX_RESPONSE_BYTES,
        PROTOCOL,
        WireError,
        ctx_from_wire,
        decision_to_wire,
        expect_keys,
        read_frame,
        write_frame,
    )

    def send(obj: dict[str, Any]) -> None:
        write_frame(wire_out, obj, limit=MAX_RESPONSE_BYTES)

    try:
        hello = read_frame(wire_in, limit=MAX_REQUEST_BYTES)
        if hello is None or hello.get("kind") != "HELLO":
            return 3
        if hello.get("protocol") != PROTOCOL:
            send({"kind": "ERROR", "id": 0, "code": "PROTOCOL_MISMATCH",
                  "detail": f"worker speaks {PROTOCOL}"})
            return 3

        policy = load_policy(ref)
        factory = as_policy_factory(policy)
        send({
            "kind": "READY",
            "protocol": PROTOCOL,
            "policy_id": str(policy.id),
            "version": str(policy.version),
            "describe": str(policy.describe())[:512],
        })

        instances: dict[int, Any] = {}
        while True:
            frame = read_frame(wire_in, limit=MAX_REQUEST_BYTES)
            if frame is None:
                return 0
            kind = frame.get("kind")
            if kind == "SHUTDOWN":
                return 0
            fid = frame.get("id")
            if kind == "NEW":
                expect_keys(frame, {"kind", "id", "instance"})
                instances[int(frame["instance"])] = factory()
                send({"kind": "OK", "id": fid})
            elif kind == "DECIDE":
                expect_keys(frame, {"kind", "id", "instance", "ctx"})
                instance = instances.get(int(frame["instance"]))
                if instance is None:
                    send({"kind": "ERROR", "id": fid, "code": "NO_INSTANCE", "detail": ""})
                    continue
                try:
                    decision = instance.evaluate(ctx_from_wire(frame["ctx"]))
                    payload = decision_to_wire(decision)
                except WireError:
                    raise
                except Exception as exc:
                    detail = "".join(traceback.format_exception_only(exc)).strip()
                    send({"kind": "ERROR", "id": fid, "code": "POLICY_RAISED",
                          "detail": detail[:512]})
                    continue
                send({"kind": "DECISION", "id": fid, **payload})
            else:
                send({"kind": "ERROR", "id": fid, "code": "UNKNOWN_KIND",
                      "detail": str(kind)[:64]})
    except WireError as exc:
        print(f"interpose policy worker: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
