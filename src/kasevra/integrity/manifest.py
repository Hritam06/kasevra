"""Deterministic V2 manifest serialization, persistence and validation."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from kasevra.integrity.canonical import canonical_json_bytes, manifest_sha256
from kasevra.schemas.manifest_v2 import FORMAT, SCHEMA_VERSION, ManifestV2


class ManifestError(ValueError):
    """Raised when a manifest is invalid or cannot be safely persisted."""


def serialize_manifest(manifest: ManifestV2) -> bytes:
    """Serialize a V2 manifest into deterministic canonical JSON bytes."""
    if not isinstance(manifest, ManifestV2):
        raise TypeError("manifest must be a ManifestV2 instance")

    calculated = manifest.calculate_digest()
    if manifest.manifest_digest != calculated:
        raise ManifestError("Manifest digest is missing or inconsistent")

    return canonical_json_bytes(manifest.to_dict()) + b"\n"


def write_manifest(path: str | Path, manifest: ManifestV2) -> Path:
    """Create a manifest without overwriting an existing file."""
    destination = Path(path)
    payload = serialize_manifest(manifest)

    destination.parent.mkdir(parents=True, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(destination, flags, 0o600)

    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return destination


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON object keys."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_manifest(path: str | Path) -> dict[str, Any]:
    """Load and validate a V2 manifest and its canonical digest."""
    source = Path(path)

    try:
        with source.open("r", encoding="utf-8") as stream:
            data = json.load(stream, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError("Manifest could not be read as valid JSON") from exc

    if not isinstance(data, dict):
        raise ManifestError("Manifest root must be a JSON object")

    if data.get("format") != FORMAT:
        raise ManifestError("Unsupported manifest format")

    if data.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError("Unsupported manifest schema version")

    required = {
        "format",
        "schema_version",
        "case",
        "integrity",
        "evidence",
        "collection",
        "manifest_digest",
    }
    if set(data) != required:
        raise ManifestError("Manifest contains missing or unexpected top-level fields")

    from kasevra.schemas.manifest_v2 import (
        CaseRecord,
        CollectionRecord,
        EvidenceRecord,
        ManifestV2,
    )

    try:
        case_data = data["case"]
        if not isinstance(case_data, dict) or set(case_data) != {
            "case_id",
            "case_name",
            "created_utc",
            "operator_id",
            "description",
        }:
            raise ValueError("Invalid case record fields")
        case = CaseRecord(**case_data)

        if not isinstance(data["evidence"], list):
            raise ValueError("Evidence must be an array")
        evidence_fields = {
            "evidence_id",
            "file_name",
            "relative_path",
            "size_bytes",
            "sha256",
            "acquired_utc",
            "operator",
            "source_description",
            "tool_name",
            "tool_version",
            "status",
            "errors",
            "warnings",
            "metadata",
        }
        evidence = []
        for item in data["evidence"]:
            if not isinstance(item, dict) or set(item) != evidence_fields:
                raise ValueError("Invalid evidence record fields")
            for sequence_field in ("errors", "warnings"):
                if not isinstance(item[sequence_field], list) or not all(
                    isinstance(value, str) for value in item[sequence_field]
                ):
                    raise ValueError(f"Invalid evidence {sequence_field}")
            if not isinstance(item["metadata"], dict):
                raise ValueError("Evidence metadata must be an object")
            evidence.append(
                EvidenceRecord(
                    **{
                        **item,
                        "errors": tuple(item["errors"]),
                        "warnings": tuple(item["warnings"]),
                    }
                )
            )

        collection_data = data["collection"]
        if not isinstance(collection_data, dict) or set(collection_data) != {
            "status",
            "collected_file_count",
            "warning_count",
            "error_count",
        }:
            raise ValueError("Invalid collection record fields")
        collection = CollectionRecord(**collection_data)
        ManifestV2(
            case=case,
            evidence=tuple(evidence),
            collection=collection,
            manifest_digest=data["manifest_digest"],
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise ManifestError(f"Manifest contains invalid nested data: {exc}") from exc

    integrity = data["integrity"]
    if integrity != {
        "hash_algorithm": "SHA-256",
        "canonicalization": "KASEVRA-C14N-1",
    }:
        raise ManifestError("Unsupported manifest integrity configuration")

    digest = data["manifest_digest"]
    if not isinstance(digest, str) or len(digest) != 64:
        raise ManifestError("Manifest digest is missing or malformed")

    try:
        calculated = manifest_sha256(data)
    except (TypeError, ValueError) as exc:
        raise ManifestError("Manifest contains unsupported canonical data") from exc

    if calculated != digest:
        raise ManifestError("Manifest digest verification failed")

    return data
