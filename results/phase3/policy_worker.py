"""A prototype out-of-process policy worker. Newline-delimited JSON on stdio.

Not a proposal for how the worker should be written. It exists so the
equivalence protocol can be exercised against a *real* process boundary before
one is committed to, and so the cost of that boundary is measured rather than
guessed.

Protocol, one JSON object per line:

    -> {"op": "hello",    "policy": "<ref>"}
    <- {"ok": true, "id": ..., "version": ..., "digest": ..., "describe": ...}
    -> {"op": "evaluate", "ctx": <wire context>}
    <- {"ok": true, "decision": <wire decision>}
    -> {"op": "bye"}

``digest`` is answered *by the worker*, from the worker's own interpreter
state. That is deliberate: ``policy_digest`` walks ``sys.modules`` for
first-party sources, so it is a property of the process that computes it, and
the protocol must be able to show whether the two processes agree.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "src"))
sys.path.insert(0, str(HERE))

from arch_wire import context_from_wire, decision_to_wire  # noqa: E402
from interpose.policy.base import load_policy, policy_digest  # noqa: E402


def main() -> int:
    policy = None
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            op = msg.get("op")
            if op == "hello":
                policy = load_policy(msg["policy"])
                reply = {
                    "ok": True,
                    "id": policy.id,
                    "version": getattr(policy, "version", ""),
                    "digest": policy_digest(policy),
                    "describe": policy.describe(),
                    "loaded_interpose_modules": sorted(
                        m for m in sys.modules if m.startswith("interpose")
                    ),
                }
            elif op == "evaluate":
                assert policy is not None, "evaluate before hello"
                decision = policy.evaluate(context_from_wire(msg["ctx"]))
                reply = {"ok": True, "decision": decision_to_wire(decision)}
            elif op == "bye":
                out.write(json.dumps({"ok": True}) + "\n")
                out.flush()
                return 0
            else:
                reply = {"ok": False, "error": f"unknown op {op!r}"}
        except Exception as exc:  # noqa: BLE001 - the boundary must report, not die
            reply = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        out.write(json.dumps(reply, ensure_ascii=False) + "\n")
        out.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
