"""Build a :class:`World` from declarative fixtures.

Reset is rebuild, not rollback. ``build_world`` is pure with respect to the
fixture directory: it reads files, constructs about sixty objects, and returns
them. At this size, copy-on-write and snapshot layers would be unjustified
machinery.

Two safety properties are enforced here rather than documented and hoped for:

* **No code path.** Fixtures are parsed with ``yaml.safe_load``. There is no
  loader, tag, or flag that constructs arbitrary Python. A scenario is content
  obtained from a stranger; the most common way a "data-only" design turns
  back into code execution is a bare ``yaml.load``.
* **Every untrusted payload is self-identifying.** Adversarial fixtures are
  stored base64-encoded and the loader *rejects* any payload whose decoded
  text lacks :data:`PAYLOAD_MARKER`. A scenario therefore cannot smuggle in
  content that does not announce itself, and a DLP or EDR operator who sees
  the marker in an alert can triage it in one grep.

The base64 encoding is friction and a statement of intent, not a control. It
is there so that a coding assistant indexing this repository does not ingest a
live instruction to read the reader's SSH keys. Assume a determined indexer
defeats it.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import yaml

from ..digest import normalize_text
from ..errors import ScenarioError
from ..provenance import Classification, TrustClass
from .models import Principal, Queue, Resource, Role, World

__all__ = ["PAYLOAD_MARKER", "build_world", "load_yaml", "resolve_within"]

#: Required in every decoded adversarial payload. Quoted verbatim in
#: ``SECURITY.md`` so third parties can triage on it.
PAYLOAD_MARKER = "INTERPOSE-SIM-PAYLOAD-DO-NOT-EXECUTE"


def load_yaml(path: Path) -> dict[str, Any]:
    """Parse YAML with the safe loader, or fail loudly."""
    try:
        raw = normalize_text(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ScenarioError(f"cannot read {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ScenarioError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ScenarioError(f"{path}: expected a mapping at the top level")
    return data


def _body(spec: dict[str, Any], root: Path, uri: str, trust: TrustClass) -> str:
    """Resolve a resource body from inline text, a file, or a base64 payload.

    The marker requirement binds to the declared *trust class*, not to which
    key supplied the bytes. Enforcing it only on ``payload_b64_file`` left the
    bypass one YAML key wide: an inline ``body:`` on a resource declared
    ``trust: untrusted_external`` shipped unmarked adversarial content, and the
    bundled world already did exactly that. See docs/V0_REVIEW.md.
    """
    given = [k for k in ("body", "body_file", "payload_b64_file") if k in spec]
    if len(given) != 1:
        raise ScenarioError(
            f"{uri}: exactly one of body / body_file / payload_b64_file is required, got {given}"
        )

    if "body" in spec:
        return _require_marker(normalize_text(str(spec["body"])), uri, trust)

    if "body_file" in spec:
        target = resolve_within(root, str(spec["body_file"]), uri)
        return _require_marker(normalize_text(target.read_text(encoding="utf-8")), uri, trust)

    target = resolve_within(root, str(spec["payload_b64_file"]), uri)
    encoded = "".join(target.read_text(encoding="utf-8").split())
    try:
        text = normalize_text(base64.b64decode(encoded, validate=True).decode("utf-8"))
    except Exception as exc:
        raise ScenarioError(f"{uri}: payload is not valid base64 UTF-8: {exc}") from exc
    return _require_marker(text, uri, trust)


def _require_marker(text: str, uri: str, trust: TrustClass) -> str:
    """Untrusted content must announce itself, whatever key supplied it."""
    if trust is not TrustClass.UNTRUSTED_EXTERNAL:
        return text
    if PAYLOAD_MARKER not in text:
        raise ScenarioError(
            f"{uri}: content declared trust=untrusted_external is missing the required "
            f"marker {PAYLOAD_MARKER!r}. Untrusted fixtures must be self-identifying, "
            "whichever of body / body_file / payload_b64_file supplied them; "
            "see SECURITY.md."
        )
    return text


def resolve_within(root: Path, relative: str, uri: str) -> Path:
    """Resolve ``relative`` under ``root``, refusing to escape it.

    Fixture paths come from a file a stranger wrote. ``../../.ssh/id_rsa`` is
    the obvious first thing to try.
    """
    root = root.resolve()
    target = (root / relative).resolve()
    if root != target and root not in target.parents:
        raise ScenarioError(f"{uri}: fixture path escapes the scenario root: {relative}")
    if not target.is_file():
        raise ScenarioError(f"{uri}: fixture not found: {relative}")
    return target


def build_world(world_file: Path) -> World:
    """Construct the world described by ``world_file``."""
    root = world_file.parent
    spec = load_yaml(world_file)

    world = World(org_name=str(spec.get("org_name", "Unnamed Org")))

    for role_spec in spec.get("roles", []):
        role = Role(
            id=str(role_spec["id"]),
            name=str(role_spec.get("name", role_spec["id"])),
            tools=frozenset(str(t) for t in role_spec.get("tools", [])),
        )
        world.roles[role.id] = role

    for p_spec in spec.get("principals", []):
        principal = Principal(
            id=str(p_spec["id"]),
            kind=p_spec.get("kind", "human"),
            display_name=str(p_spec.get("display_name", p_spec["id"])),
            department=str(p_spec.get("department", "")),
            role_ids=tuple(str(r) for r in p_spec.get("roles", [])),
            clearance=Classification(p_spec.get("clearance", "public")),
        )
        for role_id in principal.role_ids:
            if role_id not in world.roles:
                raise ScenarioError(f"{principal.id}: unknown role {role_id}")
        world.principals[principal.id] = principal

    for q_spec in spec.get("queues", []):
        queue = Queue(
            id=str(q_spec["id"]),
            name=str(q_spec.get("name", q_spec["id"])),
            reader_principal_ids=tuple(str(p) for p in q_spec.get("readers", [])),
        )
        for reader in queue.reader_principal_ids:
            if reader not in world.principals:
                raise ScenarioError(f"queue {queue.id}: unknown reader {reader}")
        world.queues[queue.id] = queue

    for r_spec in spec.get("resources", []):
        uri = str(r_spec["uri"])
        trust = TrustClass(r_spec.get("trust", "trusted_system"))
        resource = Resource(
            uri=uri,
            kind=r_spec.get("kind", "document"),
            title=str(r_spec.get("title", uri)),
            body=_body(r_spec, root, uri, trust),
            classification=Classification(r_spec.get("classification", "internal")),
            trust=trust,
            owner_principal_id=str(r_spec.get("owner", "")),
            readers=tuple(str(p) for p in r_spec.get("readers", [])),
            path=r_spec.get("path"),
            index_terms=tuple(str(t) for t in r_spec.get("index_terms", [])),
        )
        if resource.owner_principal_id and resource.owner_principal_id not in world.principals:
            raise ScenarioError(f"{uri}: unknown owner {resource.owner_principal_id}")
        for reader in resource.readers:
            if reader not in world.principals:
                raise ScenarioError(f"{uri}: unknown reader {reader}")
        world.resources[uri] = resource

    if not world.principals:
        raise ScenarioError(f"{world_file}: no principals defined")
    return world
