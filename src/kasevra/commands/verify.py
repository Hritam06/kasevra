"""Read-only verification of collected evidence against its manifest."""

import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from kasevra.commands.baseline import MANIFEST_FORMAT
from kasevra.core.results import OperationResult, ResultStatus
from kasevra.exceptions import IntegrityError, OperationError, SafetyError

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
CHUNK_SIZE = 1024 * 1024


def _load_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise SafetyError("The manifest must not be a symbolic link.")
    if not path.is_file():
        raise OperationError("The collection manifest does not exist.")

    try:
        with path.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError("Could not read a valid collection manifest.") from exc

    if not isinstance(data, dict) or data.get("format") != MANIFEST_FORMAT:
        raise IntegrityError("Unsupported or invalid collection manifest format.")

    return data


def _validate_entries(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = data.get("entries")
    count = data.get("collected_file_count")

    if (
        not isinstance(entries, list)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count != len(entries)
    ):
        raise IntegrityError("Manifest entry count does not match its entries.")

    validated: dict[str, dict[str, Any]] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            raise IntegrityError("Manifest contains an invalid entry.")

        path_value = entry.get("collected_path")
        size = entry.get("size_bytes")
        digest = entry.get("sha256")

        if not isinstance(path_value, str) or not path_value:
            raise IntegrityError("Manifest contains an invalid file path.")

        normalized = path_value.replace("\\", "/")
        relative = PurePosixPath(normalized)

        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in normalized.split("/"))
            or ":" in relative.parts[0]
            or normalized == "manifest.json"
        ):
            raise IntegrityError("Manifest contains an unsafe relative path.")

        if normalized in validated:
            raise IntegrityError("Manifest contains duplicate file paths.")

        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise IntegrityError("Manifest contains an invalid file size.")

        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise IntegrityError("Manifest contains an invalid SHA-256 digest.")

        validated[normalized] = {
            "size_bytes": size,
            "sha256": digest.lower(),
        }

    return validated


def _hash_file(path: Path) -> tuple[str, int]:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)

    descriptor = os.open(path, flags)

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("Evidence path is not a regular file.")

        digest = hashlib.sha256()
        size = 0

        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while chunk := stream.read(CHUNK_SIZE):
                digest.update(chunk)
                size += len(chunk)

        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def _scan_unexpected_files(
    root: Path,
    expected: set[str],
) -> tuple[list[str], list[str]]:
    unexpected: list[str] = []
    unsafe: list[str] = []

    def walk(directory: Path) -> None:
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError:
            unsafe.append(str(directory.relative_to(root)))
            return

        for child in children:
            relative = child.relative_to(root).as_posix()

            if relative == "manifest.json":
                continue

            try:
                metadata = child.lstat()
            except OSError:
                unsafe.append(relative)
                continue

            if stat.S_ISLNK(metadata.st_mode):
                unsafe.append(relative)
            elif stat.S_ISDIR(metadata.st_mode):
                walk(child)
            elif stat.S_ISREG(metadata.st_mode):
                if relative not in expected:
                    unexpected.append(relative)
            else:
                unsafe.append(relative)

    walk(root)
    return sorted(unexpected), sorted(unsafe)


def verify_collection(collection: Path) -> OperationResult:
    """Verify collected files without modifying the collection."""

    collection = Path(collection).expanduser().absolute()

    if collection.is_symlink():
        raise SafetyError("The collection directory must not be a symbolic link.")
    if not collection.is_dir():
        raise OperationError("Collection path must point to an existing directory.")

    manifest = _load_manifest(collection / "manifest.json")
    entries = _validate_entries(manifest)

    modified: list[str] = []
    missing: list[str] = []
    unreadable: list[str] = []
    unsafe: list[str] = []

    for relative, expected in entries.items():
        target = collection.joinpath(*PurePosixPath(relative).parts)

        try:
            current = collection
            for part in PurePosixPath(relative).parts:
                current = current / part
                if current.is_symlink():
                    raise SafetyError("Symbolic link encountered in evidence path.")

            actual_hash, actual_size = _hash_file(target)

            if (
                actual_hash != expected["sha256"]
                or actual_size != expected["size_bytes"]
            ):
                modified.append(relative)

        except FileNotFoundError:
            missing.append(relative)
        except SafetyError:
            unsafe.append(relative)
            unreadable.append(relative)
        except (OSError, ValueError):
            unreadable.append(relative)

    unexpected, scanned_unsafe = _scan_unexpected_files(collection, set(entries))
    unsafe = sorted(set(unsafe + scanned_unsafe))

    warnings = manifest.get("errors", [])
    if not isinstance(warnings, list) or not all(
        isinstance(item, str) for item in warnings
    ):
        raise IntegrityError("Manifest collection warnings must be a list of strings.")

    problems = bool(
        modified or missing or unreadable or unexpected or unsafe or warnings
    )
    status = ResultStatus.PARTIAL if problems else ResultStatus.SUCCESS

    if problems:
        message = (
            f"Verification found {len(modified)} modified, {len(missing)} missing, "
            f"{len(unexpected)} unexpected, {len(unreadable)} unreadable, "
            f"and {len(unsafe)} unsafe item(s)."
        )
    else:
        message = f"Verified all {len(entries)} collected file(s) successfully."

    return OperationResult(
        name="Verify",
        status=status,
        message=message,
        details={
            "verified_entries": len(entries),
            "modified": sorted(modified),
            "missing": sorted(missing),
            "unexpected": unexpected,
            "unreadable": sorted(unreadable),
            "unsafe": unsafe,
            "collection_warnings": warnings,
            "limitations": [
                "Verification checks consistency with the supplied manifest.",
                "Matching hashes do not prove authenticity or chain of custody.",
                "Verification does not modify evidence files.",
                "Filesystem changes during verification cannot be eliminated on "
                "all supported platforms.",
            ],
        },
    )
