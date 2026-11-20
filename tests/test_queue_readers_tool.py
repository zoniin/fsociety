"""``get_queue_readers``: the agent can see who will read what it writes.

Added after the real-model pilot, where Opus 5.5 refused a legitimate ticket
because it assumed a queue was widely read. The authorization layer knew the
readership; the agent had no way to ask.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from interpose.engine.trial import run_single
from interpose.policy.base import BUILTIN_POLICIES, load_policy
from interpose.providers.base import AgentTurn, Message, ProposedCall
from interpose.scenario.loader import discover_scenarios, load_scenario
from interpose.tools.library import TOOL_NAMES, build_registry
from interpose.tools.spec import ToolError, ToolSpec


def _exec(scenario: str, args: dict) -> str:
    world = load_scenario(scenario).build()
    tool = build_registry().get("get_queue_readers")
    return tool.execute(world=world, principal_id="svc:assistant",
                        on_behalf_of="user:r.mehta", arguments=args).result.value


def test_lists_exactly_the_queue_readers() -> None:
    out = _exec("compartment-egress", {"queue": "internal-ops"})
    assert "user:r.mehta" in out and "user:d.okafor" in out
    assert "t.alvarez" not in out and "vendor" not in out


def test_external_readers_are_labelled() -> None:
    out = _exec("confidential-egress", {"queue": "vendor-support"})
    assert "ext:vendor-portal" in out and "external" in out


def test_no_queue_lists_every_queue_and_unknown_is_an_error() -> None:
    out = _exec("compartment-egress", {})
    assert out.count("queue: ") == len(load_scenario("compartment-egress").build().queues)
    with pytest.raises(ToolError, match="Known queues"):
        _exec("compartment-egress", {"queue": "nope"})


def test_carries_no_content_label_and_is_not_a_sink() -> None:
    world = load_scenario("compartment-egress").build()
    tool = build_registry().get("get_queue_readers")
    assert tool.effect_class == "read"
    assert tool.resolve(world=world, arguments={"queue": "internal-ops"}).sink_id is None
    outcome = tool.execute(world=world, principal_id="svc:assistant",
                           on_behalf_of="user:r.mehta", arguments={"queue": "internal-ops"})
    assert not outcome.result.sources


@pytest.mark.parametrize("scenario", sorted(discover_scenarios()))
def test_every_scenario_grants_it(scenario: str) -> None:
    sc = load_scenario(scenario)
    assert "get_queue_readers" in sc.spec.agent.tools
    world = sc.build()
    assert "get_queue_readers" in world.tools_granted(world.principal(sc.spec.agent.actor))
    assert set(TOOL_NAMES) == {t.name for t in build_registry().subset(TOOL_NAMES)}


@dataclass
class CarefulModel:
    """Reads the note, checks the queue, then files: what the pilot model lacked."""

    id: str = "stub:careful"
    deterministic: bool = True
    _script: list[list[ProposedCall]] = field(default_factory=lambda: [
        [ProposedCall("read_internal_file", {"path": "/legal/dd_workstream_2026.md"})],
        [ProposedCall("get_queue_readers", {"queue": "internal-ops"})],
        [ProposedCall("create_support_ticket", {
            "queue": "internal-ops", "subject": "Halyard follow-ups",
            "body": "Four open items; owners as listed in the note."})],
        [],
    ])

    def describe(self) -> str:
        return self.id

    def respond(self, transcript: list[Message], tools: list[ToolSpec]) -> AgentTurn:
        return AgentTurn(text="", calls=self._script.pop(0))


def _cedar_available() -> bool:
    try:
        import cedarpy  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.parametrize("policy", sorted(BUILTIN_POLICIES))
def test_no_policy_treats_the_lookup_as_egress(policy: str) -> None:
    if policy.startswith("cedar") and not _cedar_available():
        pytest.skip("cedar extra not installed")
    sc = load_scenario("compartment-egress")
    task = next(t for t in sc.spec.benign if t.id == "b1-halyard-followup")
    record = run_single(sc, load_policy(policy), CarefulModel, benign_task=task)
    lookups = [e for e in record.log.of_type("policy.evaluated") if e.tool == "get_queue_readers"]
    assert lookups and all(e.effect == "allow" for e in lookups), [e.rule_id for e in lookups]
    assert record.outcome.benign_task_completed, record.outcome.verdict


def test_the_fixture_names_its_reviewers_as_the_world_does() -> None:
    sc = load_scenario("compartment-egress")
    world = sc.build()
    note = world.resource_by_path("/legal/dd_workstream_2026.md")
    assert note is not None
    for pid in note.readers:
        assert world.principal(pid).display_name in note.body
