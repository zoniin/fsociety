"""Canonical serialization and content digests.

Every comparability claim in this project rests on two functions here.
``canonical_json`` must produce byte-identical output for equal values on
every platform; ``sha256_bytes`` hashes *normalized* bytes so that a Windows
checkout and a Linux CI runner agree.

The newline normalization is not incidental. Hashing raw file bytes means a
CRLF checkout produces different digests than an LF one, and the bug presents
as "the benchmark is not reproducible" -- the single most reputation-damaging
failure available to a project like this.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

__all__ = ["canonical_json", "digest_obj", "normalize_text", "sha256_bytes", "sha256_text"]


def normalize_text(text: str) -> str:
    """Normalize line endings and strip a UTF-8 BOM.

    Applied to every fixture before hashing or ingestion.
    """
    if text.startswith("﻿"):
        text = text[1:]
    return text.replace("\r\n", "\n").replace("\r", "\n")


def canonical_json(value: Any) -> bytes:
    """Serialize ``value`` to deterministic UTF-8 JSON bytes.

    Sorted keys, no insignificant whitespace, non-ASCII preserved. Any object
    that is not JSON-native must be converted by the caller -- silently
    stringifying unknown types is how two "equal" runs acquire different
    digests.
    """
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """Digest of text after newline/BOM normalization."""
    return sha256_bytes(normalize_text(text).encode("utf-8"))


def digest_obj(value: Any) -> str:
    """Digest of any JSON-serializable value under canonical encoding."""
    return sha256_bytes(canonical_json(value))
