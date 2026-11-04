"""Validated chain-of-custody event records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kasevra.core.identifiers import new_id
from kasevra.core.timestamps import format_utc
from kasevra.integrity.canonical import canonical_sha256

GENESIS_HASH = "0" * 64
EVENT_FORMAT = "kasevra-custody-event-v1"


@dataclass(frozen=True)
class CustodyEvent:
    event_id: str
    case_id: str
    evidence_id: str | None
    timestamp_utc: str
    operator: str
    action: str
    details: dict[str, Any]
    previous_event_hash: str
    event_hash: str

    def payload(self) -> dict[str, Any]:
        return {
            "format": EVENT_FORMAT,
            "event_id": self.event_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "timestamp_utc": self.timestamp_utc,
            "operator": self.operator,
            "action": self.action,
            "details": self.details,
            "previous_event_hash": self.previous_event_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload(), "event_hash": self.event_hash}


def create_event(
    *,
    case_id: str,
    operator: str,
    action: str,
    details: dict[str, Any] | None = None,
    evidence_id: str | None = None,
    previous_event_hash: str = GENESIS_HASH,
) -> CustodyEvent:
    """Create a custody event linked to the preceding event."""
    for name, value in (
        ("case_id", case_id),
        ("operator", operator),
        ("action", action),
        ("previous_event_hash", previous_event_hash),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} cannot be empty")

    if len(previous_event_hash) != 64 or any(
        char not in "0123456789abcdef" for char in previous_event_hash
    ):
        raise ValueError("previous_event_hash must be a SHA-256 hexadecimal digest")

    if evidence_id is not None and (
        not isinstance(evidence_id, str) or not evidence_id.strip()
    ):
        raise ValueError("evidence_id must be a non-empty string or None")

    event_details = {} if details is None else details
    if not isinstance(event_details, dict):
        raise TypeError("details must be a dictionary")
    from kasevra.integrity.canonical import canonical_json_bytes

    try:
        canonical_json_bytes(event_details)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "details must contain canonical JSON-compatible values"
        ) from exc

    payload = {
        "format": EVENT_FORMAT,
        "event_id": new_id("event"),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "timestamp_utc": format_utc(),
        "operator": operator,
        "action": action,
        "details": event_details,
        "previous_event_hash": previous_event_hash,
    }
    digest = canonical_sha256(payload)

    return CustodyEvent(
        event_id=payload["event_id"],
        case_id=case_id,
        evidence_id=evidence_id,
        timestamp_utc=payload["timestamp_utc"],
        operator=operator,
        action=action,
        details=event_details,
        previous_event_hash=previous_event_hash,
        event_hash=digest,
    )
