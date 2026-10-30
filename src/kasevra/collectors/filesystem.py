"""Safe, offline collection of explicitly selected filesystem files."""

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from kasevra.core.results import OperationResult, ResultStatus
from kasevra.exceptions import OperationError, SafetyError

DEFAULT_MAX_FILE_BYTES = 100 * 1024 * 1024
MANIFEST_NAME = "manifest.json"


def _sha256_file(path: Path) -> tuple[str, int]:
    """Hash a regular file while counting the bytes actually read."""
    digest = hashlib.sha256()
    size = 0

    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)

    return digest.hexdigest(), size


def collect_files(
    source: Path,
    destination: Path,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> OperationResult:
    """Copy selected files into a new evidence directory and write a manifest.

    Source files are never intentionally modified. Symlinks are not followed.
    The destination must not already exist. This is a basic collector, not a
    forensic disk imager or a guarantee of a bit-for-bit forensic acquisition.
    """
    source = Path(os.path.abspath(source.expanduser()))
    destination = Path(os.path.abspath(destination.expanduser()))

    if max_file_bytes < 1:
        raise SafetyError("Maximum file size must be greater than zero.")

    if source.is_symlink():
        raise SafetyError("The source path must not be a symbolic link.")

    if not source.exists():
        raise OperationError(f"Source path does not exist: {source}")

    if not source.is_dir() and not source.is_file():
        raise SafetyError("Source must be a regular file or directory.")

    if destination.exists() or destination.is_symlink():
        raise SafetyError("Destination already exists; refusing to overwrite it.")

    if destination == source or source in destination.parents:
        raise SafetyError("Destination must not be inside the source path.")

    if source.is_dir() and destination in source.parents:
        raise SafetyError("Destination must not contain the source directory.")

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.mkdir()
    except OSError as exc:
        raise OperationError("Could not create the destination directory.") from exc

    entries: list[dict[str, object]] = []
    errors: list[str] = []

    candidates = [source] if source.is_file() else sorted(source.rglob("*"))

    for item in candidates:
        try:
            if item.is_symlink():
                errors.append(f"Skipped symbolic link: {item.name}")
                continue

            if not item.is_file():
                continue

            relative_path = (
                Path(item.name) if source.is_file() else item.relative_to(source)
            )

            if relative_path.name == MANIFEST_NAME:
                errors.append(f"Skipped reserved manifest filename: {relative_path}")
                continue

            stat_before = item.stat(follow_symlinks=False)
            if stat_before.st_size > max_file_bytes:
                errors.append(f"Skipped oversized file: {relative_path}")
                continue

            target = destination / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)

            before_hash, before_size = _sha256_file(item)
            if before_size > max_file_bytes:
                errors.append(f"Skipped file exceeding size limit: {relative_path}")
                continue

            copied_hash = hashlib.sha256()
            copied_size = 0

            with item.open("rb") as src, target.open("xb") as dst:
                while chunk := src.read(1024 * 1024):
                    copied_size += len(chunk)
                    if copied_size > max_file_bytes:
                        break
                    copied_hash.update(chunk)
                    dst.write(chunk)

            if copied_size > max_file_bytes:
                target.unlink(missing_ok=True)
                errors.append(f"File exceeded size limit during copy: {relative_path}")
                continue

            after_hash = copied_hash.hexdigest()
            after_size = copied_size

            if before_hash != after_hash or before_size != after_size:
                target.unlink(missing_ok=True)
                errors.append(
                    f"Source changed or hash mismatch during copy: {relative_path}"
                )
                continue

            entries.append(
                {
                    "source_relative_path": str(relative_path),
                    "collected_path": str(relative_path),
                    "size_bytes": after_size,
                    "sha256": after_hash,
                }
            )
        except (OSError, ValueError) as exc:
            # Remove an incomplete output file created by this attempt.
            try:
                if "target" in locals() and target.exists():
                    target.unlink()
            except OSError:
                errors.append(f"Could not remove incomplete output for {item.name}")
            errors.append(f"Could not collect {item.name}: {type(exc).__name__}")

    manifest = {
        "format": "kasevra-evidence-manifest-v1",
        "created_utc": datetime.now(UTC).isoformat(),
        "hash_algorithm": "SHA-256",
        "source": str(source),
        "collected_file_count": len(entries),
        "entries": entries,
        "errors": errors,
        "limitations": [
            "Hashes record the bytes read and copied; they do not prove authenticity.",
            "This is not a bit-for-bit forensic image.",
        ],
    }

    try:
        manifest_path = destination / MANIFEST_NAME
        with manifest_path.open("x", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2)
            stream.write("\n")
    except (OSError, ValueError) as exc:
        cleanup_note = ""
        try:
            import shutil

            shutil.rmtree(destination)
        except OSError:
            cleanup_note = (
                " Cleanup failed; the destination may contain incomplete evidence."
            )
        raise OperationError(
            "Collection manifest could not be written." + cleanup_note
        ) from exc

    if errors:
        status = ResultStatus.PARTIAL
        message = (
            f"Collected {len(entries)} file(s) with "
            f"{len(errors)} warning(s). Review manifest.json."
        )
    else:
        status = ResultStatus.SUCCESS
        message = f"Collected {len(entries)} file(s) and wrote manifest.json."

    return OperationResult(
        name="Collect",
        status=status,
        message=message,
        details={
            "collected_files": len(entries),
            "warnings": len(errors),
            "destination": str(destination),
            "manifest": str(destination / MANIFEST_NAME),
        },
    )
