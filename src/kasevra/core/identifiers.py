"""Unique identifier generation for KASEVRA records."""

from __future__ import annotations

from uuid import uuid4


def new_id(prefix: str) -> str:
    """Generate a prefixed UUIDv4 identifier."""
    if not isinstance(prefix, str):
        raise TypeError("prefix must be a string")

    normalized = prefix.strip().lower()

    if not normalized or not normalized.replace("_", "").isalnum():
        raise ValueError("prefix must contain only letters, digits or underscores")

    return f"{normalized}_{uuid4()}"
