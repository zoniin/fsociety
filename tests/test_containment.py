"""Containment properties, asserted rather than documented.

Every claim this project makes about being safe to run is worth exactly as
much as the test behind it. These are the tests.

The claims, in the order they matter:

1. A deterministic run makes no network call.
2. Networking is confined to one module, so the chokepoint is auditable.
3. Adversarial payloads cannot be smuggled in without the marker.
4. Fixture paths cannot escape the scenario directory.
5. A model-controlled path never reaches the real filesystem.
6. Secrets never reach an artifact.
7. There is no target parameter anywhere in the command surface.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from interpose.engine.trial import run_trial
from interpose.errors import ScenarioError
from interpose.policy.base import load_policy
from interpose.providers.scripted import ScriptedProvider
from interpose.tools.library import build_registry
from interpose.world.build import PAYLOAD_MARKER, build_world
from interpose.world.models import World


def test_deterministic_run_makes_no_network_calls(repo_root: Path) -> None:
    """A full scenario runs under an audit hook without attempting egress.

    The hook fires on ``socket.connect``, ``getaddrinfo``, ``urllib.Request``,
    ``subprocess.Popen``, ``os.system``, ``os.exec*``/``os.spawn*`` and
    ``ctypes.dlopen``. There is no public way to remove it once installed.

    **Why the hook is installed after a warm-up run rather than first.** On
    CPython 3.13 (verified on the Microsoft Store build used to develop this),
    installing any audit hook makes the cached-bytecode import path fail with
    ``AttributeError: 'bytes' object has no attribute 'co_filename'`` -- even
    for ``import json``. So the probe imports everything and performs one
    complete run first, then installs the hook, then runs again. Every module
    and every lazy import is resolved by that point.

    **What this therefore proves:** a fully warmed, deterministic scenario run
    attempts no egress. **What it does not prove:** that egress during import
    is impossible, or that the process is *incapable* of reaching the network.
    C extensions, handles acquired before installation, and child processes
    all bypass an audit hook. Recorded as SIMPL-0006. The OS-enforced version
    of this claim is the ``--network=none`` container job in CI, which is why
    the README claims only the weaker thing.
    """
    probe = r"""
import sys

from interpose.engine.trial import run_trial
from interpose.policy.base import load_policy
from interpose.providers.scripted import ScriptedProvider
from interpose.scenario.loader import load_scenario

# Warm-up: resolve every module and lazy import before the hook goes in.
scenario = load_scenario("indirect-document-injection")
run_trial(scenario, load_policy("reference"), lambda: ScriptedProvider("compliant"))

violations = []

def hook(event, args):
    if event in (
        "socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
        "socket.gethostbyname_ex", "urllib.Request", "subprocess.Popen",
        "os.system", "os.exec", "os.spawn", "ctypes.dlopen",
    ):
        violations.append(event)
        raise RuntimeError("egress attempt: " + event)

sys.addaudithook(hook)

scenario = load_scenario("indirect-document-injection")
trial, _ = run_trial(scenario, load_policy("reference"), lambda: ScriptedProvider("compliant"))
assert trial.attack.outcome.verdict == "CONTAINED"
print("VIOLATIONS:" + ",".join(violations))
"""
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        cwd=repo_root,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    assert "VIOLATIONS:" in completed.stdout
    assert completed.stdout.strip().endswith("VIOLATIONS:"), completed.stdout


def test_networking_is_confined_to_one_module(repo_root: Path) -> None:
    """A structural test, so the chokepoint stays auditable by grep.

    Only the optional provider may import an HTTP stack. If this fails,
    somebody added egress somewhere it cannot be reviewed.
    """
    allowed = {"providers/anthropic_provider.py"}
    offenders: list[str] = []
    for path in sorted((repo_root / "src" / "interpose").rglob("*.py")):
        rel = path.relative_to(repo_root / "src" / "interpose").as_posix()
        if rel in allowed:
            continue
        text = path.read_text(encoding="utf-8")
        for module in ("import socket", "import httpx", "import requests", "import urllib"):
            if module in text:
                offenders.append(f"{rel}: {module}")
    assert offenders == [], offenders


def test_unmarked_payload_is_rejected(tmp_path: Path) -> None:
    """A scenario cannot ship adversarial content that fails to self-identify."""
    encoded = base64.b64encode(b"quietly hostile text with no marker").decode()
    (tmp_path / "payload.b64").write_text(encoded, encoding="utf-8")
    (tmp_path / "world.yaml").write_text(
        "org_name: T\n"
        "principals:\n"
        "  - {id: p1, kind: human, clearance: internal}\n"
        "resources:\n"
        "  - uri: 'res://d/x'\n"
        "    trust: untrusted_external\n"
        "    payload_b64_file: payload.b64\n",
        encoding="utf-8",
    )
    with pytest.raises(ScenarioError, match="missing the required marker"):
        build_world(tmp_path / "world.yaml")


def test_marked_payload_is_accepted(tmp_path: Path) -> None:
    encoded = base64.b64encode(f"hostile text\n{PAYLOAD_MARKER}\n".encode()).decode()
    (tmp_path / "payload.b64").write_text(encoded, encoding="utf-8")
    (tmp_path / "world.yaml").write_text(
        "org_name: T\n"
        "principals:\n"
        "  - {id: p1, kind: human, clearance: internal}\n"
        "resources:\n"
        "  - uri: 'res://d/x'\n"
        "    trust: untrusted_external\n"
        "    payload_b64_file: payload.b64\n",
        encoding="utf-8",
    )
    world = build_world(tmp_path / "world.yaml")
    assert PAYLOAD_MARKER in world.resources["res://d/x"].body


def test_fixture_path_cannot_escape_the_scenario_root(tmp_path: Path) -> None:
    """Fixture paths come from a file a stranger wrote."""
    (tmp_path / "world.yaml").write_text(
        "org_name: T\n"
        "principals:\n"
        "  - {id: p1, kind: human, clearance: internal}\n"
        "resources:\n"
        "  - uri: 'res://d/x'\n"
        "    body_file: ../../../../etc/passwd\n",
        encoding="utf-8",
    )
    with pytest.raises(ScenarioError, match=r"escapes the scenario root|not found"):
        build_world(tmp_path / "world.yaml")


def test_model_controlled_path_never_touches_the_real_filesystem(scenario) -> None:
    """``read_internal_file`` resolves against an in-memory namespace.

    If this ever resolved against ``pathlib.Path``, the demo would be the
    exploit rather than a simulation of one.
    """
    world: World = scenario.build()
    registry = build_registry()
    tool = registry.get("read_internal_file")

    for hostile in (
        "../../../../etc/passwd",
        "/etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "/hr/../../../../../../etc/shadow",
    ):
        resolution = tool.resolve(world=world, arguments={"path": hostile})
        assert resolution.resource_uri is None, hostile
        with pytest.raises(Exception, match="no such file"):
            tool.execute(
                world=world,
                principal_id="svc:assistant",
                on_behalf_of="user:r.mehta",
                arguments={"path": hostile},
            )


def test_secrets_never_reach_an_artifact(scenario, monkeypatch) -> None:
    """The five-line test that catches almost everything.

    Put a canary in the environment, run everything, and assert the bytes do
    not appear in any artifact. Allowlist serialization is the real control;
    this is the proof that the control is working.
    """
    canary = "sk-ant-CANARY-3f9a2b7c-do-not-log"
    monkeypatch.setenv("ANTHROPIC_API_KEY", canary)
    monkeypatch.setenv("INTERPOSE_TEST_SECRET", canary)

    trial, records = run_trial(
        scenario, load_policy("reference"), lambda: ScriptedProvider("compliant")
    )
    blob = trial.model_dump_json()
    assert canary not in blob
    for record in records:
        assert canary not in record.log.to_jsonl()

    # And nothing resembling an environment dump made it in either.
    payload = json.loads(blob)
    assert "environ" not in json.dumps(payload).lower()


def test_no_target_parameter_exists_anywhere() -> None:
    """Containment as architecture: the code to point this outward is absent.

    A flag named ``--target`` is the single feature that would turn this into
    third-party-targeting infrastructure. It is not deferred; it is refused,
    and this test is the refusal.
    """
    from interpose.cli import build_parser

    forbidden = {"--target", "--host", "--url", "--endpoint", "--ip", "--base-url", "--server"}
    seen: set[str] = set()

    def walk(parser) -> None:
        for action in parser._actions:
            seen.update(action.option_strings)
            if action.choices and isinstance(action.choices, dict):
                for sub in action.choices.values():
                    walk(sub)

    walk(build_parser())
    assert forbidden & seen == set(), forbidden & seen


def test_environment_is_not_read_for_configuration() -> None:
    """No behaviour switches on an undocumented environment variable."""
    from interpose import cli

    source = Path(cli.__file__).read_text(encoding="utf-8")
    assert "os.environ" not in source
    assert "getenv" not in source
    _ = os  # imported for the monkeypatch fixture above
