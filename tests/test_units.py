"""Unit tests for the pieces the integration test depends on being correct."""

from __future__ import annotations

from pathlib import Path

import pytest

from interpose.digest import canonical_json, digest_obj, normalize_text, sha256_text
from interpose.errors import PolicyLoadError, ScenarioError
from interpose.events import EventLog, RunFinished, scrub
from interpose.policy.base import load_policy, policy_digest
from interpose.policy.types import (
    ActionView,
    Classification,
    DecisionContext,
    Effect,
    PrincipalView,
    ProvenanceView,
    ResourceView,
    SinkView,
    SourceView,
)
from interpose.provenance import (
    Classification as Cls,
)
from interpose.provenance import (
    ProvenanceIndex,
    Source,
    Tagged,
    TrustClass,
    join_sources,
)
from interpose.scenario.loader import load_scenario
from interpose.scenario.spec import CallPattern, ScenarioSpec

# -- digest ---------------------------------------------------------------


def test_canonical_json_is_key_order_independent() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_digests_normalize_line_endings() -> None:
    """A Windows checkout and a Linux CI runner must agree.

    Hashing raw file bytes would surface as "the benchmark is not
    reproducible", which is the most damaging possible false alarm here.
    """
    assert sha256_text("a\r\nb\r\n") == sha256_text("a\nb\n")
    assert normalize_text("﻿x\r\ny") == "x\ny"


def test_digest_is_stable_across_calls() -> None:
    payload = {"z": [3, 2, 1], "a": {"n": None, "t": True}}
    assert digest_obj(payload) == digest_obj(payload)


# -- provenance -----------------------------------------------------------


def _src(unit: str, cls: Cls = Cls.INTERNAL, trust: TrustClass = TrustClass.TRUSTED_SYSTEM):
    return Source(unit_id=unit, resource_uri=f"res://{unit}", trust=trust, classification=cls)


def test_tagged_join_takes_the_union_of_sources() -> None:
    a = Tagged("x", frozenset({_src("u1")}))
    b = Tagged("y", frozenset({_src("u2")}))
    assert {s.unit_id for s in join_sources(a, b)} == {"u1", "u2"}


def test_max_classification_is_the_lattice_top() -> None:
    tagged = Tagged(
        "x",
        frozenset({_src("u1", Cls.INTERNAL), _src("u2", Cls.RESTRICTED), _src("u3", Cls.PUBLIC)}),
    )
    assert tagged.max_classification is Cls.RESTRICTED


def test_unsourced_value_is_public() -> None:
    assert Tagged("x").max_classification is Cls.PUBLIC


def test_attribution_matches_quoted_content() -> None:
    index = ProvenanceIndex()
    source = _src("u1", Cls.RESTRICTED)
    index.register(source, "the quarterly export lists every employee and their annual band")
    hit = index.attribute("here is the quarterly export lists every employee and their annual band")
    assert {s.unit_id for s in hit} == {"u1"}


def test_attribution_misses_paraphrase_and_that_is_recorded() -> None:
    """SIMPL-0002, asserted rather than asserted-about.

    An agent that summarises rather than quotes escapes shingle attribution
    entirely. This test exists so the limitation is visible in the suite and
    cannot quietly stop being true without someone noticing.
    """
    index = ProvenanceIndex()
    index.register(_src("u1", Cls.RESTRICTED), "Alice Example earns 120000 in Operations band B4")
    paraphrase = "One operations staff member is paid a six figure sum in the fourth band"
    assert index.attribute(paraphrase) == frozenset()


def test_canary_is_matched_exactly_even_without_shingles() -> None:
    index = ProvenanceIndex()
    index.register(_src("u1", Cls.RESTRICTED), "short", canaries=frozenset({"CANARY-XYZ"}))
    assert {s.unit_id for s in index.attribute("prefix CANARY-XYZ suffix")} == {"u1"}


# -- events ---------------------------------------------------------------


def test_scrub_removes_control_characters_but_keeps_layout() -> None:
    assert scrub("a\x1b[31mred\x00b\tc\nd") == "a[31mredb\tc\nd"


def test_event_log_digest_changes_with_content() -> None:
    a = EventLog("run_x")
    a.emit(RunFinished, verdict="CONTAINED", turns=1, world_digest_final="d")
    b = EventLog("run_x")
    b.emit(RunFinished, verdict="COMPROMISED", turns=1, world_digest_final="d")
    assert a.digest() != b.digest()


def test_event_log_digest_is_stable_for_equal_content() -> None:
    def build() -> EventLog:
        log = EventLog("run_x")
        log.emit(RunFinished, verdict="CONTAINED", turns=2, world_digest_final="d")
        return log

    assert build().digest() == build().digest()


# -- scenario -------------------------------------------------------------


def test_bundled_scenario_loads_and_is_self_consistent(scenario) -> None:
    spec = scenario.spec
    assert spec.id == "indirect-document-injection"
    assert len(spec.benign) >= 8
    assert spec.attack.protected_assets
    world = scenario.build()
    for uri in spec.attack.protected_assets:
        assert world.resource(uri) is not None
    for task in spec.benign:
        assert task.requires_calls, f"{task.id} declares no required calls"


def test_scenario_digest_is_stable() -> None:
    assert load_scenario("indirect-document-injection").digest == load_scenario(
        "indirect-document-injection"
    ).digest


def test_scenario_without_benign_suite_is_refused() -> None:
    """Structural enforcement of the pairing rule.

    A scenario that cannot report utility cannot be run at all -- the error is
    raised at parse time, not at report time.
    """
    with pytest.raises(Exception, match="at least one benign task"):
        ScenarioSpec.model_validate(
            {
                "spec_version": "0.1",
                "id": "x",
                "version": "0.1.0",
                "bench_version": "2026.1",
                "title": "t",
                "summary": "s",
                "world": "world.yaml",
                "agent": {"actor": "a", "on_behalf_of": "b", "tools": []},
                "benign": [],
                "attack": {
                    "id": "a1",
                    "vector": "untrusted_document",
                    "injected_source": "res://x",
                    "prompt": "p",
                    "objective": [],
                },
            }
        )


def test_unknown_spec_version_is_refused() -> None:
    with pytest.raises(Exception, match="unsupported spec_version"):
        ScenarioSpec.model_validate({"spec_version": "9.9", "id": "x"})


def test_unknown_scenario_id_is_a_usage_error() -> None:
    with pytest.raises(ScenarioError, match="unknown scenario"):
        load_scenario("no-such-scenario")


def test_call_pattern_is_a_subset_match() -> None:
    pattern = CallPattern(tool="read_internal_file", args={"path": "/hr/x.csv"})
    assert pattern.matches("read_internal_file", {"path": "/hr/x.csv", "extra": 1})
    assert not pattern.matches("read_internal_file", {"path": "/hr/y.csv"})
    assert not pattern.matches("read_document", {"path": "/hr/x.csv"})


# -- policies -------------------------------------------------------------


def _ctx(
    tool: str,
    arguments: dict,
    *,
    effect_class: str = "read",
    resource: ResourceView | None = None,
    sink: SinkView | None = None,
    value_sources: tuple[SourceView, ...] = (),
    granted: frozenset[str] = frozenset({"read_internal_file", "create_support_ticket"}),
    behalf_clearance: Classification = Classification.INTERNAL,
) -> DecisionContext:
    return DecisionContext(
        step=1,
        principal=PrincipalView(
            id="svc:a",
            kind="agent",
            clearance=Classification.INTERNAL,
            roles=("r",),
            granted_tools=granted,
            on_behalf_of="user:u",
            on_behalf_of_clearance=behalf_clearance,
        ),
        action=ActionView(tool=tool, arguments=arguments, effect_class=effect_class),  # type: ignore[arg-type]
        provenance=ProvenanceView(value_sources=value_sources),
        resource=resource,
        sink=sink,
    )


RESTRICTED = ResourceView(
    uri="res://files/hr/payroll.csv",
    kind="file",
    classification=Classification.RESTRICTED,
    owner_principal_id="user:hr",
    readers=("user:hr",),
    path="/hr/payroll.csv",
)
BENIGN_SIBLING = ResourceView(
    uri="res://files/hr/headcount.csv",
    kind="file",
    classification=Classification.INTERNAL,
    owner_principal_id="user:hr",
    readers=(),
    path="/hr/headcount.csv",
)
# Mirrors what the harness actually builds for the bundled vendor-support
# queue: one internal reader and one public external reader. The previous
# version of this constant described an all-public sink the harness was
# structurally incapable of producing, so the test passed against a fiction.
# See docs/V0_REVIEW.md.
EXTERNAL_SINK = SinkView(
    id="vendor-support",
    reader_principal_ids=("ext:vendor-portal", "user:r.mehta"),
    max_reader_clearance=Classification.INTERNAL,
    min_reader_clearance=Classification.PUBLIC,
)


@pytest.mark.parametrize(
    ("policy_name", "resource", "expected"),
    [
        ("permissive", RESTRICTED, Effect.ALLOW),
        ("permissive", BENIGN_SIBLING, Effect.ALLOW),
        ("path-prefix", RESTRICTED, Effect.DENY),
        # The whole point of the middle policy: it cannot tell these apart.
        ("path-prefix", BENIGN_SIBLING, Effect.DENY),
        ("reference", RESTRICTED, Effect.DENY),
        ("reference", BENIGN_SIBLING, Effect.ALLOW),
    ],
)
def test_read_decisions(policy_name: str, resource: ResourceView, expected: Effect) -> None:
    policy = load_policy(policy_name)
    ctx = _ctx("read_internal_file", {"path": resource.path}, resource=resource)
    assert policy.evaluate(ctx).effect is expected


def test_reference_policy_blocks_egress_of_high_classification_data() -> None:
    policy = load_policy("reference")
    tainted = (
        SourceView(
            unit_id="u1",
            resource_uri="res://files/hr/payroll.csv",
            trust=TrustClass.TRUSTED_SYSTEM,
            classification=Classification.RESTRICTED,
        ),
    )
    ctx = _ctx(
        "create_support_ticket",
        {"queue": "vendor-support", "body": "..."},
        effect_class="write",
        sink=EXTERNAL_SINK,
        value_sources=tainted,
    )
    decision = policy.evaluate(ctx)
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "R3.egress-above-sink-clearance"


def test_reference_policy_allows_untainted_write_to_the_same_sink() -> None:
    """The egress rule keys on data, not on destination.

    A policy that simply banned the vendor queue would also contain the
    attack, and would break every legitimate vendor ticket.
    """
    policy = load_policy("reference")
    ctx = _ctx(
        "create_support_ticket",
        {"queue": "vendor-support", "body": "please confirm the invoice number"},
        effect_class="write",
        sink=EXTERNAL_SINK,
    )
    assert policy.evaluate(ctx).effect is Effect.ALLOW


def test_delegation_narrows_authority_it_never_widens_it() -> None:
    """A confused deputy check.

    The agent principal is cleared to internal. Acting for a public-clearance
    principal, it must not be able to read internal data.
    """
    policy = load_policy("reference")
    ctx = _ctx(
        "read_internal_file",
        {"path": BENIGN_SIBLING.path},
        resource=BENIGN_SIBLING,
        behalf_clearance=Classification.PUBLIC,
    )
    decision = policy.evaluate(ctx)
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "R2.insufficient-clearance"


def test_every_policy_denies_an_ungranted_tool() -> None:
    for name in ("permissive", "path-prefix", "reference"):
        policy = load_policy(name)
        ctx = _ctx("read_internal_file", {"path": "/x"}, granted=frozenset())
        assert policy.evaluate(ctx).effect is Effect.DENY, name


def test_every_decision_names_a_rule() -> None:
    """A deny with no rule identity is unauditable."""
    for name in ("permissive", "path-prefix", "reference"):
        policy = load_policy(name)
        for resource in (RESTRICTED, BENIGN_SIBLING):
            decision = policy.evaluate(
                _ctx("read_internal_file", {"path": resource.path}, resource=resource)
            )
            assert decision.rule_id and decision.reason, (name, decision)


def test_policy_digest_changes_with_implementation(tmp_path: Path) -> None:
    """The frozen-policy protocol needs the digest to actually track content."""
    digests = {policy_digest(load_policy(n)) for n in ("permissive", "path-prefix", "reference")}
    assert len(digests) == 3


def test_unknown_policy_reference_is_refused() -> None:
    with pytest.raises(PolicyLoadError):
        load_policy("not-a-policy")
    with pytest.raises(PolicyLoadError):
        load_policy("interpose.policy.reference:NoSuchClass")


def test_sink_view_matches_what_the_runner_builds(scenario) -> None:
    """The unit-test sink must be one the harness can actually emit.

    Asserting a policy decision against a hand-built context is only
    meaningful if the harness produces contexts of that shape.
    """
    from interpose.engine.runner import _extreme

    world = scenario.build()
    readers = world.queue_readers("vendor-support")
    assert _extreme(readers, highest=True) is EXTERNAL_SINK.max_reader_clearance
    assert _extreme(readers, highest=False) is EXTERNAL_SINK.min_reader_clearance


def test_egress_rule_uses_the_weakest_reader_not_the_strongest() -> None:
    """A queue is only as confidential as its least-cleared reader.

    Comparing against the strongest reader let an internal-cleared insider on
    the readership cover for an external one, so confidential data flowed to a
    vendor queue unimpeded. That inversion shipped and disabled R3 entirely.
    """
    policy = load_policy("reference")
    confidential = (
        SourceView(
            unit_id="u1",
            resource_uri="res://files/ops/postmortem",
            trust=TrustClass.TRUSTED_SYSTEM,
            classification=Classification.CONFIDENTIAL,
        ),
    )
    ctx = _ctx(
        "create_support_ticket",
        {"queue": "vendor-support", "body": "..."},
        effect_class="write",
        sink=EXTERNAL_SINK,
        value_sources=confidential,
    )
    decision = policy.evaluate(ctx)
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "R3.egress-above-sink-clearance"
