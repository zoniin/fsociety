"""The Cedar adapters, and the property the whole ablation rests on.

The load-bearing tests here are not the allow and the deny. They are the three
fail-closed tests, because the defect they cover is silent: Cedar skips a
policy whose condition errors, so a ``forbid`` with a misspelled context key is
not applied, and the request falls through to whatever ``permit`` matched. An
egress rule disabled that way still returns ``Allow`` and still logs nothing a
caller reads. ``test_cedar_itself_fails_open_on_a_wrong_typed_context``
demonstrates the defect against the real binding; the parametrized test beside
it shows the shipped adapter does not have it.

The whole file skips when the ``cedar`` extra is absent, which is the default
install. CI without the extra must stay green -- that is the point of shipping
Cedar as an extra at all.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cedarpy")

from interpose.engine.trial import run_trial
from interpose.policy import cedar_common
from interpose.policy.base import (
    BUILTIN_POLICIES,
    SecurityPolicy,
    _import_closure_sources,
    load_policy,
    policy_digest,
)
from interpose.policy.cedar_action_only import CedarActionOnly, CedarActionOnlyStrict
from interpose.policy.cedar_with_provenance import CedarWithProvenance
from interpose.policy.types import (
    ALLOW,
    DENY,
    ActionView,
    Decision,
    DecisionContext,
    PrincipalView,
    ProvenanceView,
    ReaderView,
    ResourceView,
    SinkView,
    SourceView,
)
from interpose.provenance import Classification, TrustClass
from interpose.providers.scripted import ScriptedProvider
from interpose.scenario.loader import load_scenario

READ_TOOL = "read_document"
WRITE_TOOL = "create_ticket"
GRANTED = frozenset({READ_TOOL, WRITE_TOOL})


def principal(
    clearance: Classification = Classification.CONFIDENTIAL,
    on_behalf_of: str = "user:r.mehta",
    on_behalf_of_clearance: Classification = Classification.CONFIDENTIAL,
) -> PrincipalView:
    return PrincipalView(
        id="svc:assistant",
        kind="service",
        clearance=clearance,
        roles=("assistant",),
        granted_tools=GRANTED,
        on_behalf_of=on_behalf_of,
        on_behalf_of_clearance=on_behalf_of_clearance,
    )


def read_ctx(
    resource: ResourceView | None,
    *,
    tool: str = READ_TOOL,
    who: PrincipalView | None = None,
) -> DecisionContext:
    return DecisionContext(
        step=0,
        principal=who or principal(),
        action=ActionView(tool=tool, arguments={"uri": "x"}, effect_class="read"),
        provenance=ProvenanceView(),
        resource=resource,
    )


def write_ctx(
    sources: tuple[SourceView, ...], readers: tuple[ReaderView, ...]
) -> DecisionContext:
    return DecisionContext(
        step=1,
        principal=principal(),
        action=ActionView(
            tool=WRITE_TOOL, arguments={"body": "text"}, effect_class="write"
        ),
        provenance=ProvenanceView(value_sources=sources),
        sink=SinkView(id="queue:vendor-support", readers=readers),
    )


def resource(
    uri: str = "doc:travel-policy",
    classification: Classification = Classification.PUBLIC,
    readers: tuple[str, ...] = (),
) -> ResourceView:
    return ResourceView(
        uri=uri,
        kind="document",
        classification=classification,
        owner_principal_id="user:r.mehta",
        readers=readers,
        path=f"/docs/{uri}",
    )


def source(
    classification: Classification = Classification.CONFIDENTIAL,
    readers: tuple[str, ...] = ("user:r.mehta",),
) -> SourceView:
    return SourceView(
        unit_id="unit:1",
        resource_uri="doc:postmortem",
        trust=TrustClass.TRUSTED_SYSTEM,
        classification=classification,
        readers=readers,
    )


# --------------------------------------------------------------------------
# registration, protocol, serialization
# --------------------------------------------------------------------------


def test_both_arms_are_registered_and_satisfy_the_policy_protocol() -> None:
    for short in ("cedar-action-only", "cedar-with-provenance"):
        assert short in BUILTIN_POLICIES
        policy = load_policy(short)
        assert isinstance(policy, SecurityPolicy)
        assert policy.describe()


def test_a_decision_serializes_to_json_with_its_rule_named() -> None:
    decision = CedarActionOnly().evaluate(read_ctx(resource()))
    assert isinstance(decision, Decision)
    payload = decision.as_dict()
    assert json.loads(json.dumps(payload))["rule_id"] == "R0.permitted"
    assert payload["reason"]


def test_the_two_arms_load_identical_cedar_policy_text() -> None:
    """The ablation's single-variable claim, asserted rather than asserted-in-prose.

    If these ever diverge, "the other policy was just worse" becomes an
    available explanation for every row of the ablation.
    """
    assert CedarActionOnly._policy_text is CedarWithProvenance._policy_text
    assert CedarActionOnly._policy_text == cedar_common.CEDAR_POLICIES


def test_the_frozen_digest_covers_the_cedar_policy_text() -> None:
    """SIMPL-0007, and the reason no ``digest`` override is needed here.

    These adapters' behaviour lives in a Cedar policy string, not only in the
    Python that calls Cedar. That would defeat a one-file digest. It does not
    defeat the import-closure digest, because the string is a literal in a
    first-party module the adapters import.
    """
    texts = _import_closure_sources(CedarActionOnly)
    assert any("R3.probe-integrity" in text for text in texts)
    assert any("R2.not-in-reader-set" in text for text in texts)
    assert policy_digest(CedarActionOnly()) != policy_digest(CedarWithProvenance())


def test_the_digest_does_not_depend_on_whether_cedarpy_is_importable() -> None:
    """The freeze self-test runs on the default install, which has no extra."""
    fresh = CedarWithProvenance()
    assert fresh._policy_set is None
    assert policy_digest(fresh) == policy_digest(load_policy("cedar-with-provenance"))


def test_the_missing_extra_names_the_install_command(monkeypatch: Any) -> None:
    from interpose.errors import PolicyLoadError

    monkeypatch.setattr(cedar_common, "_CEDARPY", None)
    monkeypatch.setitem(__import__("sys").modules, "cedarpy", None)
    with pytest.raises(PolicyLoadError, match=r"pip install interpose\[cedar\]"):
        CedarActionOnly().evaluate(read_ctx(resource()))


# --------------------------------------------------------------------------
# Cedar deciding
# --------------------------------------------------------------------------


def test_cedar_allows_a_granted_tool_against_an_authorized_object() -> None:
    decision = CedarActionOnly().evaluate(read_ctx(resource()))
    assert decision.effect is ALLOW
    assert decision.rule_id == "R0.permitted"


def test_cedar_denies_a_tool_the_principal_was_never_granted() -> None:
    decision = CedarActionOnly().evaluate(read_ctx(resource(), tool="delete_everything"))
    assert decision.effect is DENY
    assert decision.rule_id == "R1.tool-not-granted"


def test_cedar_denies_a_read_outside_the_resource_reader_allowlist() -> None:
    target = resource("doc:payroll", Classification.RESTRICTED, ("user:v.okafor",))
    decision = CedarActionOnly().evaluate(read_ctx(target))
    assert decision.effect is DENY
    assert decision.rule_id == "R2.not-in-reader-set"


def test_cedar_walks_its_own_lattice_for_the_clearance_branch() -> None:
    target = resource("doc:board-minutes", Classification.RESTRICTED)
    who = principal(
        clearance=Classification.INTERNAL,
        on_behalf_of_clearance=Classification.RESTRICTED,
    )
    decision = CedarActionOnly().evaluate(read_ctx(target, who=who))
    assert decision.effect is DENY
    assert decision.rule_id == "R2.insufficient-clearance"
    assert decision.metadata["cedar_rule"] == "R2.insufficient-clearance.agent"


def test_delegation_narrows_authority_and_never_widens_it() -> None:
    """Two ``forbid`` rules give the minimum of the two clearances for free."""
    who = principal(
        clearance=Classification.RESTRICTED,
        on_behalf_of="user:intern",
        on_behalf_of_clearance=Classification.INTERNAL,
    )
    decision = CedarActionOnly().evaluate(
        read_ctx(resource("doc:board-minutes", Classification.CONFIDENTIAL), who=who)
    )
    assert decision.effect is DENY
    assert decision.metadata["cedar_rule"] == "R2.insufficient-clearance.delegated"


def test_provenance_arm_denies_egress_to_an_unentitled_reader() -> None:
    ctx = write_ctx(
        (source(),),
        (ReaderView(id="user:vendor", clearance=Classification.PUBLIC),),
    )
    decision = CedarWithProvenance().evaluate(ctx)
    assert decision.effect is DENY
    assert decision.rule_id == "R3.egress-to-unentitled-reader"
    assert decision.metadata["unentitled_readers"] == ["user:vendor"]


def test_provenance_arm_permits_egress_when_every_reader_is_entitled() -> None:
    ctx = write_ctx(
        (source(),),
        (ReaderView(id="user:r.mehta", clearance=Classification.CONFIDENTIAL),),
    )
    decision = CedarWithProvenance().evaluate(ctx)
    assert decision.effect is ALLOW
    assert decision.metadata["probe_pairs"] == 1


def test_the_action_only_arm_permits_the_write_the_provenance_arm_refuses() -> None:
    """The ablation, on one context, with the policy text held identical."""
    ctx = write_ctx(
        (source(),),
        (ReaderView(id="user:vendor", clearance=Classification.PUBLIC),),
    )
    assert CedarActionOnly().evaluate(ctx).effect is ALLOW
    assert CedarWithProvenance().evaluate(ctx).effect is DENY


def test_the_enforcement_point_issues_one_request_per_source_reader_pair() -> None:
    policy = CedarWithProvenance()
    readers = (
        ReaderView(id="user:r.mehta", clearance=Classification.CONFIDENTIAL),
        ReaderView(id="user:a.chen", clearance=Classification.CONFIDENTIAL),
    )
    sources = (source(readers=("user:r.mehta", "user:a.chen")),)
    policy.evaluate(write_ctx(sources, readers))
    # one invocation request, plus |sources| x |readers| entitlement probes
    assert policy.cedar_calls == 1 + len(sources) * len(readers)


# --------------------------------------------------------------------------
# failing closed
# --------------------------------------------------------------------------


class _DropsTheTaintKey(CedarWithProvenance):
    """A plausible enforcement-point bug: the provenance key is never sent."""

    def _probe_request(
        self, reader_id: str, source_uri: str, declared: dict[str, Any]
    ) -> dict[str, Any]:
        request = super()._probe_request(reader_id, source_uri, declared)
        del request["context"]["taintedSources"]
        return request


class _MisspellsTheTaintKey(CedarWithProvenance):
    def _probe_request(
        self, reader_id: str, source_uri: str, declared: dict[str, Any]
    ) -> dict[str, Any]:
        request = super()._probe_request(reader_id, source_uri, declared)
        request["context"]["tainted_sources"] = request["context"].pop("taintedSources")
        return request


class _SendsTheWrongType(CedarWithProvenance):
    def _probe_request(
        self, reader_id: str, source_uri: str, declared: dict[str, Any]
    ) -> dict[str, Any]:
        request = super()._probe_request(reader_id, source_uri, declared)
        request["context"]["taintedSources"] = "doc:postmortem"
        return request


ENTITLED = (ReaderView(id="user:r.mehta", clearance=Classification.CONFIDENTIAL),)


@pytest.mark.parametrize(
    "broken", [_DropsTheTaintKey, _MisspellsTheTaintKey, _SendsTheWrongType]
)
def test_a_malformed_provenance_context_denies_instead_of_permitting(
    broken: type[CedarWithProvenance],
) -> None:
    """Every way of getting the context wrong ends in a deny, not an allow.

    The context here is one Cedar would otherwise *permit* -- the reader is
    entitled -- so a fail-open would show up as ALLOW and be invisible.
    """
    decision = broken().evaluate(write_ctx((source(),), ENTITLED))
    assert decision.effect is DENY
    assert decision.rule_id == "cedar.fail-closed"
    assert decision.metadata["cedar_errors"]


def test_cedar_itself_fails_open_on_a_wrong_typed_context() -> None:
    """The defect, demonstrated against the raw binding rather than described.

    Cedar skips a policy whose condition errors, so the wrongly typed
    ``taintedSources`` disables ``R3.probe-integrity`` and the request falls
    through to the ``permit``. Cedar returns **Allow**, and the only trace is a
    diagnostics entry. The ``has`` guards in the policy text do not help here:
    the key is present, it is merely the wrong type.

    This is what the adapter's two guards exist to close, and it is why one of
    them is not enough.
    """
    import cedarpy

    policy = CedarWithProvenance()
    ctx = write_ctx((source(),), ENTITLED)
    entities = policy._entities(ctx)
    entities.append(policy.source_entity(source()))
    declared: dict[str, Any] = {
        "taintedSources": "doc:postmortem",
        "sinkReaders": [cedar_common._ref("Principal", "user:r.mehta")],
    }
    request = policy._probe_request("user:r.mehta", "doc:postmortem", declared)

    raw = cedarpy.is_authorized(request, policy._policies(), entities)
    assert raw.decision == cedarpy.Decision.Allow
    assert raw.diagnostics.errors

    # Guard one: any diagnostics error is a deny, schema or no schema.
    assert policy._ask(request, entities, None).fail_closed is True

    # Guard two: the schema refuses the request outright, before evaluation.
    schema = policy._schema(ctx)
    assert cedarpy.is_authorized(request, policy._policies(), entities, schema).decision == (
        cedarpy.Decision.NoDecision
    )
    assert policy._ask(request, entities, schema).fail_closed is True


def test_a_probe_outside_the_declared_provenance_is_refused() -> None:
    """Cedar checks the enforcement point's unrolling against its declaration."""
    policy = CedarWithProvenance()
    ctx = write_ctx((source(),), ENTITLED)
    entities = policy._entities(ctx)
    entities.append(policy.source_entity(source()))
    declared = {
        "taintedSources": [cedar_common._ref("Resource", "doc:some-other-file")],
        "sinkReaders": [cedar_common._ref("Principal", "user:r.mehta")],
    }
    answer = policy._ask(
        policy._probe_request("user:r.mehta", "doc:postmortem", declared),
        entities,
        policy._schema(ctx),
    )
    assert answer.allowed is False
    assert answer.cedar_rule == "R3.probe-integrity"


# --------------------------------------------------------------------------
# agreement, determinism, latency
# --------------------------------------------------------------------------


def _reference_trace(scenario_id: str, behavior: str) -> list[DecisionContext]:
    captured: list[DecisionContext] = []
    inner = load_policy("reference")

    class _Recorder:
        id = inner.id
        version = inner.version

        def describe(self) -> str:
            return inner.describe()

        def evaluate(self, ctx: DecisionContext) -> Decision:
            captured.append(ctx)
            return inner.evaluate(ctx)

    run_trial(
        load_scenario(scenario_id), _Recorder(), lambda: ScriptedProvider(behavior=behavior)
    )
    return captured


@pytest.mark.parametrize(
    "scenario_id", ["indirect-document-injection", "confidential-egress"]
)
def test_the_provenance_arm_reproduces_the_reference_policy_exactly(
    scenario_id: str,
) -> None:
    reference = load_policy("reference")
    policy = CedarWithProvenance()
    contexts = _reference_trace(scenario_id, "compliant")
    assert contexts
    for ctx in contexts:
        expected = reference.evaluate(ctx)
        got = policy.evaluate(ctx)
        assert got.effect is expected.effect
        assert got.rule_id == expected.rule_id


def test_the_action_only_arm_differs_only_on_the_egress_rule() -> None:
    """Where the two arms disagree is exactly where provenance was the input."""
    reference = load_policy("reference")
    policy = CedarActionOnly()
    disagreements = set()
    for ctx in _reference_trace("confidential-egress", "compliant"):
        expected = reference.evaluate(ctx)
        got = policy.evaluate(ctx)
        if got.effect is not expected.effect:
            disagreements.add(expected.rule_id)
    assert disagreements == {"R3.egress-to-unentitled-reader"}


def test_repeated_calls_return_identical_decisions() -> None:
    policy = CedarWithProvenance()
    contexts = [
        read_ctx(resource()),
        read_ctx(resource("doc:payroll", Classification.RESTRICTED, ("user:v.okafor",))),
        write_ctx((source(),), (ReaderView(id="user:vendor", clearance=Classification.PUBLIC),)),
    ]
    first = [policy.evaluate(ctx).as_dict() for ctx in contexts]
    for _ in range(3):
        assert [policy.evaluate(ctx).as_dict() for ctx in contexts] == first


def test_the_ablation_artifact_records_a_latency_for_every_cell() -> None:
    path = Path(__file__).resolve().parents[1] / "results" / "phase2" / "cedar-ablation.json"
    artifact = json.loads(path.read_text(encoding="utf-8"))
    cells = artifact["cells"] + artifact["supplementary_cells"]
    n_scen = len({c["scenario"] for c in artifact["cells"]})
    n_pol = len({c["policy"] for c in artifact["cells"]})
    n_client = len({c["provider"] for c in artifact["cells"]})
    assert len(artifact["cells"]) == n_pol * n_scen * n_client
    assert n_scen == 3, "the ablation must cover the whole shipped corpus"
    for cell in cells:
        latency = cell["latency"]
        assert latency["decisions"] > 0
        assert isinstance(latency["mean_ms"], float)
        assert latency["mean_ms"] > 0


def test_the_strict_variant_is_loadable_but_not_registered() -> None:
    """Shipped as the measured answer to 'was the control arm a strawman?'."""
    assert CedarActionOnlyStrict.id not in BUILTIN_POLICIES.values()
    policy = load_policy("interpose.policy.cedar_action_only:CedarActionOnlyStrict")
    assert policy.id == "cedar-action-only-strict"
    ctx = write_ctx((), (ReaderView(id="user:vendor", clearance=Classification.PUBLIC),))
    assert policy.evaluate(ctx).effect is DENY
