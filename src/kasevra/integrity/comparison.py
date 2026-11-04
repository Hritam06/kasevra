"""Independent V2 baseline comparison against manifests and disk evidence."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from kasevra.integrity.manifest import ManifestError, load_manifest

BASELINE_V2_FORMAT = "kasevra-baseline-v2"


class ComparisonError(ValueError):
    """Raised when a V2 baseline or comparison input is invalid."""


def _validate_baseline(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ComparisonError("Baseline must be an existing regular, non-symlink file")

    import json

    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ComparisonError(f"Duplicate baseline JSON key: {key}")
            result[key] = value
        return result

    try:
        if source.stat().st_size > 64 * 1024 * 1024:
            raise ComparisonError("Baseline exceeds the 64 MiB size limit")
        data = json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise ComparisonError("Baseline is not valid JSON") from exc

    required_fields = {
        "format",
        "schema_version",
        "created_utc",
        "case_id",
        "source_manifest_digest",
        "hash_algorithm",
        "entry_count",
        "entries",
        "limitations",
        "baseline_digest",
    }
    if not isinstance(data, dict) or set(data) != required_fields:
        raise ComparisonError("Invalid V2 baseline structure")
    if data.get("format") != BASELINE_V2_FORMAT:
        raise ComparisonError("Unsupported V2 baseline format")
    if data.get("schema_version") != "2.0.0":
        raise ComparisonError("Unsupported baseline schema version")
    if data.get("hash_algorithm") != "SHA-256":
        raise ComparisonError("Unsupported baseline hash algorithm")
    for field in ("case_id", "created_utc"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise ComparisonError(f"Invalid baseline {field}")
    for field in ("source_manifest_digest", "baseline_digest"):
        value = data.get(field)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise ComparisonError(f"Invalid baseline {field}")
    if not isinstance(data.get("limitations"), list) or not all(
        isinstance(item, str) for item in data["limitations"]
    ):
        raise ComparisonError("Invalid baseline limitations")

    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ComparisonError("Baseline entries must be an array")

    if data.get("entry_count") != len(entries):
        raise ComparisonError("Baseline entry count does not match entries")

    validated = {}
    seen_folded = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ComparisonError("Invalid baseline entry")

        relative = entry.get("relative_path")
        digest = entry.get("sha256")
        size = entry.get("size_bytes")

        if not isinstance(relative, str) or not relative or "\\" in relative:
            raise ComparisonError("Invalid baseline relative path")

        path_value = PurePosixPath(relative)
        if (
            path_value.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or ":" in relative.split("/")[0]
            or relative == "manifest-v2.json"
        ):
            raise ComparisonError("Unsafe baseline relative path")

        folded = relative.casefold()
        if folded in seen_folded:
            raise ComparisonError("Duplicate baseline path")
        seen_folded.add(folded)

        if set(entry) != {"evidence_id", "relative_path", "size_bytes", "sha256"}:
            raise ComparisonError("Invalid baseline entry fields")
        if not isinstance(entry.get("evidence_id"), str) or not entry["evidence_id"]:
            raise ComparisonError("Invalid baseline evidence ID")

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise ComparisonError("Invalid baseline SHA-256 digest")

        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ComparisonError("Invalid baseline file size")

        validated[relative] = {
            "sha256": digest,
            "size_bytes": size,
        }

    return {**data, "_entries": validated}


def create_v2_baseline(
    manifest_path: str | Path,
    output_path: str | Path,
) -> dict[str, Any]:
    """Create a V2 baseline from a validated V2 manifest."""
    import json
    from datetime import UTC, datetime

    from kasevra.integrity.canonical import canonical_sha256

    manifest_file = Path(manifest_path)
    destination = Path(output_path)

    if manifest_file.resolve() == destination.resolve():
        raise ComparisonError("Baseline and manifest paths must differ")

    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Refusing to overwrite an existing baseline")

    if manifest_file.is_symlink():
        raise ComparisonError("Manifest must not be a symbolic link")

    try:
        manifest = load_manifest(manifest_file)
    except ManifestError as exc:
        raise ComparisonError(f"Invalid V2 manifest: {exc}") from exc

    entries = []
    for record in manifest["evidence"]:
        if record.get("status") != "collected":
            continue
        entries.append(
            {
                "evidence_id": record["evidence_id"],
                "relative_path": record["relative_path"],
                "size_bytes": record["size_bytes"],
                "sha256": record["sha256"],
            }
        )

    entries.sort(key=lambda item: item["relative_path"])

    baseline = {
        "format": BASELINE_V2_FORMAT,
        "schema_version": "2.0.0",
        "created_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "case_id": manifest["case"]["case_id"],
        "source_manifest_digest": manifest["manifest_digest"],
        "hash_algorithm": "SHA-256",
        "entry_count": len(entries),
        "entries": entries,
        "limitations": [
            "A baseline records reference values and does not prove trustworthiness.",
            "Protect the baseline independently from the evidence collection.",
            "Baseline creation copies manifest hashes and does not independently "
            "rehash files.",
        ],
    }
    baseline["baseline_digest"] = canonical_sha256(baseline)

    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(baseline, ensure_ascii=False, sort_keys=True, indent=2).encode(
        "utf-8"
    ) + bytes([10])

    fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        destination.unlink(missing_ok=True)
        raise

    return {
        "status": "PASS",
        "baseline_path": str(destination),
        "baseline_digest": baseline["baseline_digest"],
        "entry_count": len(entries),
    }


def _hash_evidence(path: Path) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise OSError("Evidence is not a regular file")

        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)

        after = os.fstat(fd)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise OSError("Evidence changed during comparison")

        return digest.hexdigest(), size
    finally:
        os.close(fd)


def compare_v2_baseline(
    baseline_path: str | Path,
    collection_path: str | Path,
) -> dict[str, Any]:
    """Compare baseline, V2 manifest and actual evidence files."""

    baseline = _validate_baseline(baseline_path)
    baseline_digest = baseline.get("baseline_digest")
    digest_input = {
        key: value
        for key, value in baseline.items()
        if key not in {"baseline_digest", "_entries"}
    }

    from kasevra.integrity.canonical import canonical_sha256

    if (
        not isinstance(baseline_digest, str)
        or canonical_sha256(digest_input) != baseline_digest
    ):
        raise ComparisonError("Baseline digest verification failed")

    root = Path(collection_path).expanduser().absolute()
    if root.is_symlink() or not root.is_dir():
        raise ComparisonError("Collection must be a non-symlink directory")

    try:
        manifest = load_manifest(root / "manifest-v2.json")
    except ManifestError as exc:
        raise ComparisonError(f"Invalid collection manifest: {exc}") from exc

    baseline_entries = baseline["_entries"]
    current_records = {}

    for record in manifest["evidence"]:
        relative = record.get("relative_path")
        if not isinstance(relative, str) or not relative or "\\" in relative:
            raise ComparisonError("Invalid current manifest evidence path")
        safe = PurePosixPath(relative)
        if (
            safe.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or ":" in relative.split("/")[0]
            or relative == "manifest-v2.json"
        ):
            raise ComparisonError("Unsafe current manifest evidence path")
        folded = relative.casefold()
        if any(existing.casefold() == folded for existing in current_records):
            raise ComparisonError("Duplicate current manifest evidence path")
        current_records[relative] = record

    baseline_paths = set(baseline_entries)
    current_paths = {
        path
        for path, record in current_records.items()
        if record.get("status") == "collected"
    }

    added = sorted(current_paths - baseline_paths)
    removed = sorted(baseline_paths - current_paths)
    common = sorted(baseline_paths & current_paths)

    results = []
    counts = {
        "PASS": 0,
        "MODIFIED": 0,
        "MISSING": 0,
        "ADDED": len(added),
        "REMOVED": len(removed),
        "ERROR": 0,
    }

    for relative in common:
        record = current_records[relative]
        reference = baseline_entries[relative]

        try:
            actual_hash, actual_size = _hash_evidence(
                root.joinpath(*PurePosixPath(relative).parts)
            )
            hash_matches = actual_hash == reference["sha256"]
            size_matches = actual_size == reference["size_bytes"]
            status = "PASS" if hash_matches and size_matches else "MODIFIED"
            results.append(
                {
                    "path": relative,
                    "status": status,
                    "expected_sha256": reference["sha256"],
                    "actual_sha256": actual_hash,
                    "expected_size_bytes": reference["size_bytes"],
                    "actual_size_bytes": actual_size,
                    "manifest_sha256": record.get("sha256"),
                    "manifest_size_bytes": record.get("size_bytes"),
                }
            )
        except FileNotFoundError:
            status = "MISSING"
            results.append({"path": relative, "status": status})
        except OSError as exc:
            status = "ERROR"
            results.append(
                {
                    "path": relative,
                    "status": status,
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            )
        counts[status] += 1

    for relative in added:
        results.append({"path": relative, "status": "ADDED"})

    for relative in removed:
        results.append({"path": relative, "status": "REMOVED"})

    for relative, record in current_records.items():
        if record.get("status") != "collected":
            results.append(
                {
                    "path": relative,
                    "status": "ERROR",
                    "reason": f"Acquisition status: {record.get('status')}",
                }
            )
            counts["ERROR"] += 1

    try:
        from kasevra.integrity.verification import _scan_unexpected

        unexpected = _scan_unexpected(root, set(current_records))
    except OSError as exc:
        unexpected = []
        scan_error = f"{type(exc).__name__}: {exc}"
    else:
        scan_error = None

    for relative in unexpected:
        results.append({"path": relative, "status": "UNEXPECTED"})
    counts["UNEXPECTED"] = len(unexpected)

    failed = (
        counts["MODIFIED"]
        + counts["MISSING"]
        + counts["ADDED"]
        + counts["REMOVED"]
        + counts["ERROR"]
        + counts["UNEXPECTED"]
    )
    overall = "PASS" if failed == 0 and scan_error is None else "FAIL"

    return {
        "format": "kasevra-baseline-comparison-v2",
        "case_id": manifest["case"]["case_id"],
        "baseline_digest": baseline_digest,
        "current_manifest_digest": manifest["manifest_digest"],
        "summary": {
            **counts,
            "overall_status": overall,
            "baseline_entries": len(baseline_entries),
            "current_entries": len(current_paths),
        },
        "results": results,
        "scan_error": scan_error,
        "limitations": [
            "PASS means current file bytes match the supplied baseline hashes "
            "and sizes.",
            "A matching hash does not prove evidence authenticity or provenance.",
            "The baseline must be protected independently to provide a "
            "meaningful reference.",
            "Filesystem changes during comparison cannot be eliminated on "
            "every platform.",
        ],
    }
