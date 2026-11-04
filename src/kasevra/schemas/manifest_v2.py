"""Typed and validated KASEVRA V2 evidence manifest records."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Any

from kasevra.integrity.canonical import manifest_sha256

FORMAT = "kasevra-evidence-manifest-v2"
SCHEMA_VERSION = "2.0.0"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

ACQUISITION_STATUSES = {"collected", "skipped", "failed"}
COLLECTION_STATUSES = {"complete", "partial", "failed"}


def _validate_utc(value: str, field_name: str) -> None:
    """Require an ISO 8601 UTC timestamp ending in Z."""
    from datetime import datetime

    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field_name} must be an ISO 8601 UTC timestamp ending in Z")

    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field_name} is not a valid UTC timestamp") from exc

    if parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


@dataclass(frozen=True)
class CaseRecord:
    """Identity and descriptive metadata for an evidence case."""

    case_id: str
    case_name: str
    created_utc: str
    operator_id: str
    description: str = ""

    def __post_init__(self) -> None:
        for name in ("case_id", "case_name", "operator_id"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} cannot be empty")
        _validate_utc(self.created_utc, "created_utc")


@dataclass(frozen=True)
class EvidenceRecord:
    """Metadata and integrity information for one acquired file."""

    evidence_id: str
    file_name: str
    relative_path: str
    size_bytes: int
    sha256: str | None
    acquired_utc: str
    operator: str
    source_description: str
    tool_name: str
    tool_version: str
    status: str = "collected"
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in (
            "evidence_id",
            "file_name",
            "relative_path",
            "operator",
            "tool_name",
            "tool_version",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} cannot be empty")

        path = PurePosixPath(self.relative_path)
        if (
            path.is_absolute()
            or ".." in path.parts
            or "\\" in self.relative_path
            or "\x00" in self.relative_path
            or re.match(r"^[A-Za-z]:", self.relative_path)
        ):
            raise ValueError("relative_path must be a safe relative POSIX path")

        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or self.size_bytes < 0
        ):
            raise ValueError("size_bytes must be a non-negative integer")

        if self.sha256 is not None and not SHA256_PATTERN.fullmatch(self.sha256):
            raise ValueError(
                "sha256 must be a 64-character lowercase hexadecimal digest"
            )

        if self.status not in ACQUISITION_STATUSES:
            raise ValueError(f"Unsupported acquisition status: {self.status}")

        if self.status == "collected" and self.sha256 is None:
            raise ValueError("Collected evidence must have a SHA-256 digest")

        _validate_utc(self.acquired_utc, "acquired_utc")


@dataclass(frozen=True)
class CollectionRecord:
    """Collection-level completion and warning summary."""

    status: str
    collected_file_count: int
    warning_count: int
    error_count: int = 0

    def __post_init__(self) -> None:
        if self.status not in COLLECTION_STATUSES:
            raise ValueError(f"Unsupported collection status: {self.status}")

        for name in ("collected_file_count", "warning_count", "error_count"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


@dataclass(frozen=True)
class ManifestV2:
    """Complete versioned KASEVRA evidence manifest."""

    case: CaseRecord
    evidence: tuple[EvidenceRecord, ...]
    collection: CollectionRecord
    manifest_digest: str | None = None

    def __post_init__(self) -> None:
        identifiers = [item.evidence_id for item in self.evidence]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Duplicate evidence_id values are not permitted")

        paths = [item.relative_path.casefold() for item in self.evidence]
        if len(paths) != len(set(paths)):
            raise ValueError("Duplicate evidence paths are not permitted")

        collected = sum(item.status == "collected" for item in self.evidence)
        warnings = sum(len(item.warnings) for item in self.evidence)
        errors = sum(len(item.errors) for item in self.evidence)

        if self.collection.collected_file_count != collected:
            raise ValueError("Collection file count does not match evidence records")
        if self.collection.warning_count != warnings:
            raise ValueError("Collection warning count does not match evidence records")
        if self.collection.error_count != errors:
            raise ValueError("Collection error count does not match evidence records")

        if self.manifest_digest is not None and not SHA256_PATTERN.fullmatch(
            self.manifest_digest
        ):
            raise ValueError("manifest_digest must be a SHA-256 hexadecimal digest")

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        """Return the manifest as a JSON-compatible dictionary."""
        result = {
            "format": FORMAT,
            "schema_version": SCHEMA_VERSION,
            "case": asdict(self.case),
            "integrity": {
                "hash_algorithm": "SHA-256",
                "canonicalization": "KASEVRA-C14N-1",
            },
            "evidence": [
                asdict(item)
                for item in sorted(self.evidence, key=lambda record: record.evidence_id)
            ],
            "collection": asdict(self.collection),
        }

        if include_digest and self.manifest_digest is not None:
            result["manifest_digest"] = self.manifest_digest

        return result

    def calculate_digest(self) -> str:
        """Calculate the canonical manifest digest."""
        return manifest_sha256(self.to_dict(include_digest=False))

    def with_digest(self) -> ManifestV2:
        """Return an equivalent immutable manifest with its digest populated."""
        from dataclasses import replace

        return replace(self, manifest_digest=self.calculate_digest())


def create_manifest(
    *,
    case: CaseRecord,
    evidence: tuple[EvidenceRecord, ...] | list[EvidenceRecord],
    status: str,
) -> ManifestV2:
    """Build a validated manifest and calculate its canonical digest."""
    records = tuple(evidence)

    collection = CollectionRecord(
        status=status,
        collected_file_count=sum(item.status == "collected" for item in records),
        warning_count=sum(len(item.warnings) for item in records),
        error_count=sum(len(item.errors) for item in records),
    )

    return ManifestV2(
        case=case,
        evidence=records,
        collection=collection,
    ).with_digest()
