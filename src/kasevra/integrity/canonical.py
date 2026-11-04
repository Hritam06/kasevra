"""Deterministic JSON serialization for KASEVRA integrity records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def _validate_value(value: Any, path: str = "$") -> None:
    """Reject values that are unsuitable for canonical JSON."""
    if value is None or isinstance(value, (str, bool, int)):
        return

    if isinstance(value, float):
        raise TypeError(f"Floating-point values are not permitted at {path}")

    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_value(item, f"{path}[{index}]")
        return

    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"JSON object keys must be strings at {path}")
            _validate_value(item, f"{path}.{key}")
        return

    raise TypeError(f"Unsupported value type at {path}: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize supported data into deterministic UTF-8 JSON bytes."""
    _validate_value(value)

    serialized = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return serialized.encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Return the SHA-256 digest of canonical JSON bytes."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def manifest_sha256(manifest: Mapping[str, Any]) -> str:
    """Hash a manifest while excluding its top-level digest field."""
    if not isinstance(manifest, Mapping):
        raise TypeError("manifest must be a mapping")

    digest_input = dict(manifest)
    digest_input.pop("manifest_digest", None)

    return canonical_sha256(digest_input)
