"""Discovery and loading of scenarios.

Scenarios are found in two places: the directory bundled with the package, and
any directory named on the command line. There is no registry, no
``--from-url``, and no auto-download. Remote scenario distribution is the
trigger that would force a real sandbox, and V0 does not have one.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from ..digest import digest_obj, sha256_text
from ..errors import ScenarioError
from ..world.build import build_world, load_yaml, resolve_within
from ..world.models import World
from .spec import CallPattern, ScenarioSpec

__all__ = ["LoadedScenario", "bundled_root", "discover_scenarios", "load_scenario"]


@dataclass(frozen=True)
class LoadedScenario:
    spec: ScenarioSpec
    root: Path
    #: Digest over the manifest plus every fixture it references. Two runs
    #: that report the same scenario id but different digests are not
    #: comparable, and ``interpose verify`` says so.
    digest: str

    def build(self) -> World:
        # The world path comes from a file a stranger wrote. Before review it
        # was joined without a containment check, so `world: ../../elsewhere`
        # both loaded out of tree and contributed nothing to the digest --
        # `verify` printed AGREES for a scenario whose entire world had been
        # swapped.
        return build_world(resolve_within(self.root, self.spec.world, "world"))

    def payload_path(self, name: str) -> Path:
        return self.root / name


def bundled_root() -> Path:
    """Directory of scenarios shipped with the package."""
    packaged = Path(__file__).resolve().parent.parent / "_bundled" / "scenarios"
    if packaged.is_dir():
        return packaged
    # Running from a source checkout.
    return Path(__file__).resolve().parents[3] / "scenarios"


def discover_scenarios(extra: Path | None = None) -> dict[str, Path]:
    """Map scenario id to its directory. Sorted, so listings are stable."""
    found: dict[str, Path] = {}
    for root in [bundled_root()] + ([extra] if extra else []):
        if root is None or not root.is_dir():
            continue
        for manifest in sorted(root.glob("*/scenario.yaml")):
            try:
                data = load_yaml(manifest)
            except ScenarioError:
                continue
            sid = str(data.get("id", manifest.parent.name))
            found[sid] = manifest.parent
    return dict(sorted(found.items()))


def _fixture_digest(root: Path) -> str:
    """Digest over every fixture file, by normalized content.

    Hashes normalized bytes rather than raw bytes so that a Windows checkout
    and a Linux CI runner agree. Hashing raw bytes here would surface as
    "the benchmark is not reproducible", which is the most damaging possible
    false alarm for a project like this.
    """
    parts: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "scenario.yaml":
            continue
        if path.name.endswith(".pyc"):
            continue
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ScenarioError(f"fixture {rel} is not valid UTF-8: {exc}") from exc
        parts.append({"path": rel, "digest": sha256_text(text)})
    return digest_obj(parts)


def load_scenario(ref: str, extra_root: Path | None = None) -> LoadedScenario:
    """Load a scenario by id or by path to its directory."""
    candidate = Path(ref)
    if candidate.is_dir():
        root = candidate
    else:
        known = discover_scenarios(extra_root)
        if ref not in known:
            raise ScenarioError(
                f"unknown scenario {ref!r}. Known scenarios: {', '.join(known) or '(none)'}"
            )
        root = known[ref]

    manifest = root / "scenario.yaml"
    if not manifest.is_file():
        raise ScenarioError(f"{root} has no scenario.yaml")

    raw = load_yaml(manifest)
    try:
        spec = ScenarioSpec.model_validate(raw)
    except ValidationError as exc:
        raise ScenarioError(f"{manifest} failed validation:\n{exc}") from exc

    digest = digest_obj(
        {
            "manifest": sha256_text(manifest.read_text(encoding="utf-8")),
            "fixtures": _fixture_digest(root),
        }
    )
    loaded = LoadedScenario(spec=spec, root=root, digest=digest)
    _validate_references(loaded)
    return loaded


def _validate_references(loaded: LoadedScenario) -> None:
    """Check every declared call against the world, at load time.

    Without this a contributor typo is absorbed rather than reported. A
    ``requires_calls`` entry naming a tool that does not exist, or a URI absent
    from the world, produces a task the agent can never complete -- which the
    harness then scores as "the agent did not attempt it, not a policy cost",
    silently moving the utility number that the whole result rests on. A
    scenario that cannot be satisfied is a broken scenario, and it should fail
    at load with the task id in the message.
    """
    from ..tools.library import build_registry

    spec = loaded.spec
    world = loaded.build()
    registry = build_registry()
    granted = set(spec.agent.tools)
    problems: list[str] = []

    for principal_field in ("actor", "on_behalf_of"):
        pid = getattr(spec.agent, principal_field)
        if pid not in world.principals:
            problems.append(f"agent.{principal_field}: unknown principal {pid!r}")

    def check(where: str, pattern: CallPattern) -> None:
        if pattern.tool not in registry:
            problems.append(
                f"{where}: no such tool {pattern.tool!r}; "
                f"available: {', '.join(registry.names())}"
            )
            return
        if pattern.tool not in granted:
            problems.append(
                f"{where}: tool {pattern.tool!r} is not in agent.tools, so the "
                "agent can never make this call"
            )
        for key, value in pattern.args.items():
            text = str(value).strip()
            if key == "uri" and world.resource(text) is None:
                problems.append(f"{where}: no resource {text!r} in the world")
            elif key == "path" and world.resource_by_path(text) is None:
                problems.append(f"{where}: no file resource at path {text!r}")
            elif key == "queue" and text not in world.queues:
                problems.append(
                    f"{where}: no queue {text!r}; known queues: "
                    f"{', '.join(sorted(world.queues))}"
                )

    for task in spec.benign:
        for index, pattern in enumerate(task.requires_calls):
            check(f"benign[{task.id}].requires_calls[{index}]", pattern)

    for index, step in enumerate(spec.attack.objective):
        check(f"attack[{spec.attack.id}].objective[{index}]", step)

    if world.resource(spec.attack.injected_source) is None:
        problems.append(
            f"attack.injected_source: no resource {spec.attack.injected_source!r}"
        )
    for uri in spec.attack.protected_assets:
        if world.resource(uri) is None:
            problems.append(f"attack.protected_assets: no resource {uri!r}")

    for name in spec.agent.tools:
        if name not in registry:
            problems.append(f"agent.tools: no such tool {name!r}")

    if problems:
        joined = "\n  - ".join(problems)
        raise ScenarioError(
            f"{loaded.root / 'scenario.yaml'} declares calls that cannot resolve:\n"
            f"  - {joined}"
        )
