"""Compare a collection manifest with a KASEVRA reference baseline."""

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from kasevra.commands.baseline import BASELINE_FORMAT, MANIFEST_FORMAT
from kasevra.core.results import OperationResult, ResultStatus
from kasevra.exceptions import IntegrityError, OperationError, SafetyError

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _read_json(path: Path, label: str) -> dict[str, Any]:
    path = Path(path).expanduser().absolute()

    if path.is_symlink():
        raise SafetyError(f"The {label} path must not be a symbolic link.")
    if not path.is_file():
        raise OperationError(
            f"The {label} path must point to an existing regular file."
        )

    try:
        with path.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"Could not read a valid {label} JSON file.") from exc

    if not isinstance(data, dict):
        raise IntegrityError(f"The {label} must contain a JSON object.")

    return data


def _validate_entries(
    data: dict[str, Any],
    *,
    expected_format: str,
    count_key: str,
    path_key: str,
    label: str,
) -> dict[str, dict[str, Any]]:
    if data.get("format") != expected_format:
        raise IntegrityError(f"Unsupported or invalid {label} format.")

    entries = data.get("entries")
    count = data.get(count_key)

    if (
        not isinstance(entries, list)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count != len(entries)
    ):
        raise IntegrityError(f"{label} entry count does not match its entries.")

    validated: dict[str, dict[str, Any]] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            raise IntegrityError(f"{label} contains an invalid entry.")

        path_value = entry.get(path_key)
        size = entry.get("size_bytes")
        digest = entry.get("sha256")

        if not isinstance(path_value, str) or not path_value:
            raise IntegrityError(f"{label} contains an invalid file path.")

        normalized = path_value.replace("\\", "/")
        relative = PurePosixPath(normalized)

        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in normalized.split("/"))
            or ":" in relative.parts[0]
            or normalized == "manifest.json"
        ):
            raise IntegrityError(f"{label} contains an unsafe relative path.")

        if normalized in validated:
            raise IntegrityError(f"{label} contains duplicate file paths.")

        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise IntegrityError(f"{label} contains an invalid file size.")

        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise IntegrityError(f"{label} contains an invalid SHA-256 digest.")

        validated[normalized] = {
            "size_bytes": size,
            "sha256": digest.lower(),
        }

    return validated


def analyze_collection(baseline_path: Path, manifest_path: Path) -> OperationResult:
    """Compare a collection manifest against a reference baseline."""

    baseline_path = Path(baseline_path).expanduser().absolute()
    manifest_path = Path(manifest_path).expanduser().absolute()

    if baseline_path == manifest_path:
        raise SafetyError("Baseline and collection manifest must be different files.")

    baseline_data = _read_json(baseline_path, "baseline")
    manifest_data = _read_json(manifest_path, "collection manifest")

    baseline_entries = _validate_entries(
        baseline_data,
        expected_format=BASELINE_FORMAT,
        count_key="entry_count",
        path_key="path",
        label="Baseline",
    )

    manifest_entries = _validate_entries(
        manifest_data,
        expected_format=MANIFEST_FORMAT,
        count_key="collected_file_count",
        path_key="collected_path",
        label="Collection manifest",
    )

    baseline_paths = set(baseline_entries)
    manifest_paths = set(manifest_entries)

    missing = sorted(baseline_paths - manifest_paths)
    unexpected = sorted(manifest_paths - baseline_paths)

    modified = sorted(
        path
        for path in baseline_paths & manifest_paths
        if (
            baseline_entries[path]["sha256"] != manifest_entries[path]["sha256"]
            or baseline_entries[path]["size_bytes"]
            != manifest_entries[path]["size_bytes"]
        )
    )

    unchanged_count = len(baseline_paths & manifest_paths) - len(modified)
    has_differences = bool(missing or unexpected or modified)

    status = ResultStatus.PARTIAL if has_differences else ResultStatus.SUCCESS

    if has_differences:
        message = (
            f"Comparison found {len(modified)} modified, {len(missing)} missing, "
            f"and {len(unexpected)} unexpected file(s)."
        )
    else:
        message = (
            f"All {unchanged_count} baseline entries match the collection manifest."
        )

    return OperationResult(
        name="Analysis",
        status=status,
        message=message,
        details={
            "baseline_entries": len(baseline_entries),
            "collection_entries": len(manifest_entries),
            "unchanged": unchanged_count,
            "modified": modified,
            "missing": missing,
            "unexpected": unexpected,
            "limitations": [
                "This compares manifest records; it does not re-hash files on disk.",
                "Differences indicate changes, not proof of malicious tampering.",
                "The baseline is only trustworthy if it was protected independently.",
            ],
        },
    )
