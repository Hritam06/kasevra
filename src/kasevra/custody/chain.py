"""Append-only custody log storage and hash-chain validation."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from kasevra.custody.events import (
    EVENT_FORMAT,
    GENESIS_HASH,
    CustodyEvent,
    create_event,
)
from kasevra.integrity.canonical import canonical_json_bytes, canonical_sha256


class CustodyLogError(Exception):
    """Raised when a custody log cannot safely be read or appended."""


def _read_events(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink():
        raise CustodyLogError("Custody log must not be a symlink")
    if not path.exists():
        return []
    if not stat.S_ISREG(path.lstat().st_mode):
        raise CustodyLogError("Custody log must be a regular file")

    events = []
    try:
        with path.open("rb") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.endswith(b"\n"):
                    raise CustodyLogError(f"Incomplete custody log line {line_number}")
                try:
                    event = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise CustodyLogError(
                        f"Invalid JSON at custody log line {line_number}"
                    ) from exc
                if not isinstance(event, dict):
                    raise CustodyLogError(
                        f"Invalid event at custody log line {line_number}"
                    )
                events.append(event)
    except OSError as exc:
        raise CustodyLogError("Unable to read custody log") from exc
    return events


def validate_chain(path: Path) -> dict[str, Any]:
    """Validate event structure, hashes, ordering, and chain continuity."""
    path = Path(path)
    try:
        events = _read_events(path)
        previous_hash = GENESIS_HASH
        seen_ids = set()

        for index, event in enumerate(events, 1):
            required = {
                "format",
                "event_id",
                "case_id",
                "evidence_id",
                "timestamp_utc",
                "operator",
                "action",
                "details",
                "previous_event_hash",
                "event_hash",
            }
            if set(event) != required:
                raise CustodyLogError(f"Invalid event structure at line {index}")
            if event["format"] != EVENT_FORMAT:
                raise CustodyLogError(f"Unsupported event format at line {index}")
            if not isinstance(event["event_id"], str) or not event["event_id"]:
                raise CustodyLogError(f"Invalid event ID at line {index}")
            if event["event_id"] in seen_ids:
                raise CustodyLogError(f"Duplicate event ID at line {index}")
            seen_ids.add(event["event_id"])

            if event["previous_event_hash"] != previous_hash:
                raise CustodyLogError(f"Broken hash chain at line {index}")

            payload = {
                key: value for key, value in event.items() if key != "event_hash"
            }
            calculated = canonical_sha256(payload)
            if event["event_hash"] != calculated:
                raise CustodyLogError(f"Event hash mismatch at line {index}")

            previous_hash = calculated

        return {
            "status": "PASS",
            "event_count": len(events),
            "chain_head": previous_hash,
            "errors": [],
        }
    except (CustodyLogError, TypeError, ValueError) as exc:
        return {
            "status": "ERROR",
            "event_count": 0,
            "chain_head": None,
            "errors": [str(exc)],
        }


def append_event(
    path: Path,
    *,
    case_id: str,
    operator: str,
    action: str,
    details: dict[str, Any] | None = None,
    evidence_id: str | None = None,
) -> CustodyEvent:
    """Append one event under an exclusive lock after validating the chain."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.is_symlink():
        raise CustodyLogError("Custody log must not be a symlink")

    lock_path = path.with_name(path.name + ".lock")
    try:
        lock_fd = os.open(
            lock_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as exc:
        raise CustodyLogError(
            "Custody writer lock already exists; another writer may be active "
            "or a stale lock requires manual review"
        ) from exc
    except OSError as exc:
        raise CustodyLogError("Unable to create custody writer lock") from exc

    try:
        with os.fdopen(lock_fd, "w", encoding="ascii") as lock_stream:
            lock_stream.write(f"{os.getpid()}\n")
            lock_stream.flush()
            os.fsync(lock_stream.fileno())

        if path.is_symlink():
            raise CustodyLogError("Custody log must not be a symlink")

        if path.exists():
            validation = validate_chain(path)
            if validation["status"] != "PASS":
                raise CustodyLogError(
                    "Refusing to append to invalid custody log: "
                    + "; ".join(validation["errors"])
                )
            previous_hash = validation["chain_head"]
        else:
            previous_hash = GENESIS_HASH

        event = create_event(
            case_id=case_id,
            evidence_id=evidence_id,
            operator=operator,
            action=action,
            details=details,
            previous_event_hash=previous_hash,
        )

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise CustodyLogError("Custody log must be a regular file")
            with os.fdopen(fd, "ab", closefd=False) as stream:
                stream.write(canonical_json_bytes(event.to_dict()) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)

        return event
    except OSError as exc:
        raise CustodyLogError("Unable to append custody event safely") from exc
    finally:
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            pass
