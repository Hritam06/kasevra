"""Independent verification of KASEVRA V2 evidence collections."""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from kasevra.integrity.manifest import ManifestError, load_manifest

FILE_STATUSES = {"PASS", "MODIFIED", "MISSING", "UNEXPECTED", "ERROR"}


def _hash_open_file(path: Path) -> tuple[str, int]:
    """Hash a regular file without following its final symbolic link."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)

    try:
        metadata_before = os.fstat(descriptor)
        if not stat.S_ISREG(metadata_before.st_mode):
            raise OSError("Evidence is not a regular file")

        digest = hashlib.sha256()
        size = 0

        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)

        metadata_after = os.fstat(descriptor)
        if (
            metadata_before.st_dev != metadata_after.st_dev
            or metadata_before.st_ino != metadata_after.st_ino
            or metadata_before.st_size != metadata_after.st_size
            or metadata_before.st_mtime_ns != metadata_after.st_mtime_ns
        ):
            raise OSError("Evidence changed during verification")

        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def _safe_relative_path(value: Any) -> PurePosixPath:
    """Validate a portable, relative evidence path."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("Invalid evidence path")

    if "\\" in value or value.startswith("/") or ":" in value.split("/")[0]:
        raise ValueError("Unsafe evidence path")

    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("Unsafe evidence path")

    return path


def _scan_unexpected(root: Path, expected: set[str]) -> list[str]:
    """Find regular files not represented in the manifest."""
    unexpected: list[str] = []
    stack = [root]

    while stack:
        directory = stack.pop()

        with os.scandir(directory) as entries:
            children = sorted(entries, key=lambda entry: entry.name)

        for child in children:
            if directory == root and child.name == "manifest-v2.json":
                continue

            relative = Path(child.path).relative_to(root).as_posix()
            metadata = child.stat(follow_symlinks=False)

            if stat.S_ISLNK(metadata.st_mode):
                unexpected.append(relative)
                continue
            if stat.S_ISDIR(metadata.st_mode):
                stack.append(Path(child.path))
            elif stat.S_ISREG(metadata.st_mode) and relative not in expected:
                unexpected.append(relative)

    return sorted(unexpected)


def verify_v2_collection(collection: str | Path) -> dict[str, Any]:
    """Verify manifest integrity and every evidence file independently.

    Results distinguish file consistency from manifest integrity. A passing
    SHA-256 comparison does not establish authenticity or provenance.
    """
    root = Path(collection).expanduser().absolute()

    if root.is_symlink() or not root.is_dir():
        raise ValueError("Collection must be an existing, non-symlink directory")

    manifest_path = root / "manifest-v2.json"

    try:
        manifest = load_manifest(manifest_path)
        manifest_integrity = "PASS"
        manifest_error = None
    except ManifestError as exc:
        return {
            "manifest_integrity": "ERROR",
            "manifest_error": str(exc),
            "file_results": [],
            "summary": {"overall_status": "ERROR"},
            "verified_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }

    results: list[dict[str, Any]] = []
    expected: set[str] = set()
    seen_casefold: set[str] = set()

    for record in manifest["evidence"]:
        evidence_id = record.get("evidence_id")
        relative_value = record.get("relative_path")

        try:
            relative = _safe_relative_path(relative_value)
            normalized = relative.as_posix()
            folded = normalized.casefold()

            if folded in seen_casefold:
                raise ValueError("Duplicate evidence path")
            seen_casefold.add(folded)
            expected.add(normalized)

            if record.get("status") != "collected":
                results.append(
                    {
                        "evidence_id": evidence_id,
                        "path": normalized,
                        "status": "ERROR",
                        "reason": f"Acquisition status: {record.get('status')}",
                    }
                )
                continue

            target = root.joinpath(*relative.parts)

            current = root
            for part in relative.parts:
                current = current / part
                if current.is_symlink():
                    raise OSError("Symbolic link in evidence path")

            if not target.exists():
                results.append(
                    {
                        "evidence_id": evidence_id,
                        "path": normalized,
                        "status": "MISSING",
                    }
                )
                continue

            actual_hash, actual_size = _hash_open_file(target)
            expected_hash = record.get("sha256")
            expected_size = record.get("size_bytes")

            passed = actual_hash == expected_hash and actual_size == expected_size

            results.append(
                {
                    "evidence_id": evidence_id,
                    "path": normalized,
                    "status": "PASS" if passed else "MODIFIED",
                    "expected_sha256": expected_hash,
                    "actual_sha256": actual_hash,
                    "expected_size_bytes": expected_size,
                    "actual_size_bytes": actual_size,
                }
            )

        except FileNotFoundError:
            results.append(
                {
                    "evidence_id": evidence_id,
                    "path": str(relative_value),
                    "status": "MISSING",
                }
            )
        except (OSError, ValueError, TypeError) as exc:
            results.append(
                {
                    "evidence_id": evidence_id,
                    "path": str(relative_value),
                    "status": "ERROR",
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            )

    try:
        unexpected = _scan_unexpected(root, expected)
    except OSError as exc:
        unexpected = []
        scan_error = f"{type(exc).__name__}: {exc}"
    else:
        scan_error = None

    for path in unexpected:
        results.append(
            {
                "evidence_id": None,
                "path": path,
                "status": "UNEXPECTED",
            }
        )

    counts = {
        status: sum(item["status"] == status for item in results)
        for status in FILE_STATUSES
    }

    problems = (
        counts["MODIFIED"] + counts["MISSING"] + counts["UNEXPECTED"] + counts["ERROR"]
    )

    overall = "PASS" if problems == 0 and scan_error is None else "FAIL"

    return {
        "format": "kasevra-verification-report-v2",
        "case_id": manifest["case"]["case_id"],
        "manifest_integrity": manifest_integrity,
        "manifest_digest": manifest["manifest_digest"],
        "manifest_error": manifest_error,
        "file_results": results,
        "summary": {
            **counts,
            "overall_status": overall,
            "expected_evidence_count": len(expected),
        },
        "scan_error": scan_error,
        "verified_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "limitations": [
            "Matching hashes establish consistency with the supplied manifest only.",
            "A matching hash does not prove evidence authenticity.",
            "Verification does not establish chain of custody.",
            "Filesystem changes during verification cannot be eliminated on "
            "every platform.",
        ],
    }
