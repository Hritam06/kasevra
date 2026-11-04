"""Safe, streaming V2 evidence acquisition."""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from kasevra.core.identifiers import new_id
from kasevra.core.timestamps import format_utc
from kasevra.integrity.hashing import DEFAULT_CHUNK_SIZE
from kasevra.schemas.manifest_v2 import (
    CaseRecord,
    EvidenceRecord,
    create_manifest,
)


class AcquisitionError(Exception):
    """Raised when acquisition cannot safely initialize or finalize."""


def _safe_source_file(path: Path) -> os.stat_result:
    """Open metadata for a regular, non-symlink source file."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise AcquisitionError("Symbolic links are not followed")
    if not stat.S_ISREG(info.st_mode):
        raise AcquisitionError("Source is not a regular file")
    return info


def _same_source(before: os.stat_result, after: os.stat_result) -> bool:
    """Detect common source changes during acquisition."""
    same_identity = (
        not before.st_ino or not after.st_ino or before.st_ino == after.st_ino
    )
    same_change_time = os.name != "posix" or before.st_ctime_ns == after.st_ctime_ns
    return (
        before.st_dev == after.st_dev
        and same_identity
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and same_change_time
    )


def acquire_files(
    source: str | Path,
    destination: str | Path,
    *,
    case_name: str = "Evidence Collection",
    operator: str = "unspecified",
    source_description: str = "",
    max_file_bytes: int | None = None,
    tool_version: str = "2.0.0-dev",
) -> dict[str, Any]:
    """Acquire selected files into a new destination and write a V2 manifest.

    The source is opened read-only. Symlinks are skipped and output files
    are created exclusively. A source change detected during copying causes
    the incomplete copy to be removed and recorded as a failed acquisition.

    This function does not claim bit-for-bit disk imaging or authenticity.
    """
    source_path = Path(os.path.abspath(Path(source).expanduser()))
    destination_path = Path(os.path.abspath(Path(destination).expanduser()))

    if max_file_bytes is not None and (
        not isinstance(max_file_bytes, int)
        or isinstance(max_file_bytes, bool)
        or max_file_bytes < 1
    ):
        raise ValueError("max_file_bytes must be a positive integer or None")

    if source_path.is_symlink():
        raise AcquisitionError("Source path must not be a symbolic link")
    if not source_path.exists():
        raise AcquisitionError("Source path does not exist")
    if not (source_path.is_file() or source_path.is_dir()):
        raise AcquisitionError("Source must be a regular file or directory")
    if destination_path.exists() or destination_path.is_symlink():
        raise AcquisitionError("Destination already exists")
    if destination_path == source_path or source_path in destination_path.parents:
        raise AcquisitionError("Destination must not be inside the source")
    if source_path.is_dir() and destination_path in source_path.parents:
        raise AcquisitionError("Destination must not contain the source")

    candidates = (
        [source_path]
        if source_path.is_file()
        else sorted(source_path.rglob("*"), key=lambda item: item.as_posix())
    )

    try:
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.mkdir()
    except OSError as exc:
        raise AcquisitionError("Could not create destination") from exc

    case = CaseRecord(
        case_id=new_id("case"),
        case_name=case_name,
        created_utc=format_utc(),
        operator_id=operator,
        description=source_description,
    )

    records: list[EvidenceRecord] = []
    acquired_count = 0
    error_count = 0
    warning_count = 0

    try:
        for candidate in candidates:
            target: Path | None = None
            relative = (
                PurePosixPath(candidate.name)
                if source_path.is_file()
                else PurePosixPath(candidate.relative_to(source_path).as_posix())
            )

            if relative.name == "manifest.json":
                warning_count += 1
                records.append(
                    EvidenceRecord(
                        evidence_id=new_id("ev"),
                        file_name=relative.name,
                        relative_path=relative.as_posix(),
                        size_bytes=0,
                        sha256=None,
                        acquired_utc=format_utc(),
                        operator=operator,
                        source_description=source_description,
                        tool_name="KASEVRA",
                        tool_version=tool_version,
                        status="skipped",
                        warnings=("Reserved manifest filename",),
                    )
                )
                continue

            try:
                if candidate.is_dir() and not candidate.is_symlink():
                    continue

                before = _safe_source_file(candidate)
                if max_file_bytes is not None and before.st_size > max_file_bytes:
                    raise AcquisitionError("File exceeds configured size limit")

                target = destination_path.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)

                import hashlib

                digest = hashlib.sha256()
                copied_size = 0
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                source_fd = os.open(candidate, flags)

                try:
                    opened = os.fstat(source_fd)
                    if not stat.S_ISREG(opened.st_mode) or not _same_source(
                        before, opened
                    ):
                        raise AcquisitionError(
                            "Source changed before it could be opened"
                        )

                    output_fd = os.open(
                        target,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                    )
                    try:
                        with os.fdopen(source_fd, "rb", closefd=False) as src:
                            with os.fdopen(output_fd, "wb", closefd=False) as dst:
                                while chunk := src.read(DEFAULT_CHUNK_SIZE):
                                    copied_size += len(chunk)
                                    if (
                                        max_file_bytes is not None
                                        and copied_size > max_file_bytes
                                    ):
                                        raise AcquisitionError(
                                            "File exceeded size limit during copying"
                                        )
                                    digest.update(chunk)
                                    dst.write(chunk)
                                dst.flush()
                                os.fsync(dst.fileno())
                    finally:
                        os.close(output_fd)
                finally:
                    os.close(source_fd)

                after = _safe_source_file(candidate)
                if not _same_source(before, after) or copied_size != before.st_size:
                    raise AcquisitionError("Source changed during acquisition")

                records.append(
                    EvidenceRecord(
                        evidence_id=new_id("ev"),
                        file_name=relative.name,
                        relative_path=relative.as_posix(),
                        size_bytes=copied_size,
                        sha256=digest.hexdigest(),
                        acquired_utc=format_utc(),
                        operator=operator,
                        source_description=source_description,
                        tool_name="KASEVRA",
                        tool_version=tool_version,
                    )
                )
                acquired_count += 1

            except (OSError, ValueError, AcquisitionError) as exc:
                error_count += 1
                if target is not None:
                    try:
                        target.unlink(missing_ok=True)
                    except OSError:
                        pass

                records.append(
                    EvidenceRecord(
                        evidence_id=new_id("ev"),
                        file_name=relative.name,
                        relative_path=relative.as_posix(),
                        size_bytes=0,
                        sha256=None,
                        acquired_utc=format_utc(),
                        operator=operator,
                        source_description=source_description,
                        tool_name="KASEVRA",
                        tool_version=tool_version,
                        status="failed",
                        errors=(f"{type(exc).__name__}: {exc}",),
                    )
                )

        collection_status = (
            "failed"
            if acquired_count == 0 and error_count
            else "partial"
            if error_count or warning_count
            else "complete"
        )

        manifest = create_manifest(
            case=case,
            evidence=records,
            status=collection_status,
        )

        manifest_path = destination_path / "manifest-v2.json"
        with manifest_path.open("x", encoding="utf-8") as stream:
            import json

            json.dump(manifest.to_dict(), stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

        return {
            "case_id": case.case_id,
            "destination": str(destination_path),
            "manifest_path": str(manifest_path),
            "manifest_digest": manifest.manifest_digest,
            "collection_status": collection_status,
            "collected_count": acquired_count,
            "error_count": error_count,
            "warning_count": warning_count,
            "evidence": [record.evidence_id for record in records],
        }

    except Exception:
        # Do not silently leave an unfinalized collection looking complete.
        # Preserve the destination for inspection if finalization fails.
        raise
