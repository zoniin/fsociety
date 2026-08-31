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
from .spec import ScenarioSpec

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
    return LoadedScenario(spec=spec, root=root, digest=digest)
