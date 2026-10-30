"""Create a validated reference baseline from a KASEVRA collection manifest."""

import json
import re
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from kasevra.core.results import OperationResult, ResultStatus
from kasevra.exceptions import IntegrityError, OperationError, SafetyError

MANIFEST_FORMAT = "kasevra-evidence-manifest-v1"
BASELINE_FORMAT = "kasevra-baseline-v1"
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def create_baseline(manifest_path: Path, output_path: Path) -> OperationResult:
    """Validate a collection manifest and write a new baseline JSON file."""
    manifest_path = Path(manifest_path).expanduser().absolute()
    output_path = Path(output_path).expanduser().absolute()

    if manifest_path.is_symlink():
        raise SafetyError("The manifest path must not be a symbolic link.")
    if not manifest_path.is_file():
        raise OperationError("Manifest path must point to an existing regular file.")
    if output_path.exists() or output_path.is_symlink():
        raise SafetyError("Baseline output already exists; refusing to overwrite it.")
    if output_path == manifest_path:
        raise SafetyError("Baseline output must differ from the manifest path.")

    try:
        with manifest_path.open("r", encoding="utf-8") as stream:
            manifest = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError("Could not read a valid JSON manifest.") from exc

    if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT:
        raise IntegrityError("Unsupported or invalid KASEVRA manifest format.")

    entries = manifest.get("entries")
    count = manifest.get("collected_file_count")
    if (
        not isinstance(entries, list)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count != len(entries)
    ):
        raise IntegrityError("Manifest entry count does not match its entries.")

    validated_entries: list[dict[str, object]] = []
    seen_paths: set[str] = set()

    for entry in entries:
        if not isinstance(entry, dict):
            raise IntegrityError("Manifest contains an invalid entry.")

        path_value = entry.get("collected_path")
        size = entry.get("size_bytes")
        digest = entry.get("sha256")

        if not isinstance(path_value, str) or not path_value:
            raise IntegrityError("Manifest entry has an invalid collected path.")
        normalized = path_value.replace("\\", "/")
        relative = PurePosixPath(normalized)
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in normalized.split("/"))
            or ":" in relative.parts[0]
        ):
            raise IntegrityError("Manifest contains an unsafe relative path.")
        if normalized == "manifest.json":
            raise IntegrityError("Manifest entry uses the reserved manifest path.")
        if normalized in seen_paths:
            raise IntegrityError("Manifest contains duplicate collected paths.")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise IntegrityError("Manifest entry has an invalid file size.")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise IntegrityError("Manifest entry has an invalid SHA-256 digest.")

        seen_paths.add(normalized)
        validated_entries.append(
            {
                "path": normalized,
                "size_bytes": size,
                "sha256": digest.lower(),
            }
        )

    baseline = {
        "format": BASELINE_FORMAT,
        "created_utc": datetime.now(UTC).isoformat(),
        "hash_algorithm": "SHA-256",
        "source_manifest_format": MANIFEST_FORMAT,
        "entry_count": len(validated_entries),
        "entries": validated_entries,
        "limitations": [
            "A baseline records a reference; it does not prove trustworthiness.",
            "Protect the baseline separately to help detect later changes.",
            "Baseline creation does not independently re-hash collected files.",
        ],
    }

    try:
        with output_path.open("x", encoding="utf-8") as stream:
            json.dump(baseline, stream, indent=2)
            stream.write("\n")
    except (OSError, ValueError) as exc:
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise OperationError("Could not write the baseline file.") from exc

    return OperationResult(
        name="Baseline",
        status=ResultStatus.SUCCESS,
        message=(f"Created baseline with {len(validated_entries)} reference entries."),
        details={
            "entries": len(validated_entries),
            "output": str(output_path),
        },
    )
