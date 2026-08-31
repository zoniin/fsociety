"""Shared fixtures.

The autouse network ban is the load-bearing one. "CI runs without paid
credentials" is easy to say and easy to quietly break a year later, when
someone adds an import that phones home during collection. Patching the socket
constructor for the whole session turns that promise into a test failure
instead of a surprise invoice.

Note honestly what this does and does not prove. It is a *guardrail*: it
catches in-process socket use, which is how a regression would actually
arrive. It is not a boundary -- a C extension, a pre-existing handle, or a
subprocess would walk past it. The OS-enforced version of this claim lives in
the ``--network=none`` container job, which is why the README claims only the
weaker thing.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from interpose.policy.base import load_policy
from interpose.scenario.loader import load_scenario


@pytest.fixture(autouse=True, scope="session")
def _ban_network() -> None:
    def _refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError(
            "a test attempted to create a socket. The default path must make no "
            "network calls; see docs/THREAT-MODEL.md."
        )

    socket.socket = _refuse  # type: ignore[assignment]
    socket.create_connection = _refuse  # type: ignore[assignment]


@pytest.fixture()
def scenario():
    return load_scenario("indirect-document-injection")


@pytest.fixture()
def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture()
def policies():
    return {name: load_policy(name) for name in ("permissive", "path-prefix", "reference")}
