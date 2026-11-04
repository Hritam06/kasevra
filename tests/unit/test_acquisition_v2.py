"""Security regression tests for V2 evidence acquisition."""

import json
from pathlib import Path

import pytest

from kasevra.collectors.acquisition import AcquisitionError, acquire_files


def test_nested_and_empty_files_are_acquired(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "nested" / "data.bin").write_bytes(b"")
    (source / "sample.txt").write_bytes(b"KASEVRA")

    output = tmp_path / "collection"
    result = acquire_files(source, output, operator="tester")

    assert result["collection_status"] == "complete"
    assert result["collected_count"] == 2

    manifest = json.loads((output / "manifest-v2.json").read_text())
    assert manifest["manifest_digest"] == result["manifest_digest"]
    assert len(manifest["evidence"]) == 2


def test_symlink_is_not_acquired(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside evidence")
    (source / "linked.txt").symlink_to(outside)

    output = tmp_path / "collection"
    result = acquire_files(source, output)

    assert result["collection_status"] == "failed"
    assert result["collected_count"] == 0
    assert not (output / "linked.txt").exists()

    manifest = json.loads((output / "manifest-v2.json").read_text())
    assert manifest["evidence"][0]["status"] == "failed"


def test_oversized_file_is_recorded_as_failed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "large.bin").write_bytes(b"0123456789")

    result = acquire_files(source, tmp_path / "collection", max_file_bytes=5)

    assert result["collection_status"] == "failed"
    assert result["error_count"] == 1


def test_partial_acquisition_is_explicit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "good.txt").write_text("good")
    (source / "large.txt").write_text("too large")

    result = acquire_files(
        source,
        tmp_path / "collection",
        max_file_bytes=5,
    )

    assert result["collection_status"] == "partial"
    assert result["collected_count"] == 1
    assert result["error_count"] == 1


def test_existing_destination_is_never_overwritten(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("evidence")

    output = tmp_path / "collection"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("preserve")

    with pytest.raises(AcquisitionError):
        acquire_files(source, output)

    assert marker.read_text() == "preserve"


def test_source_file_is_not_modified(tmp_path: Path) -> None:
    source = tmp_path / "evidence.txt"
    source.write_bytes(b"original evidence")
    original = source.read_bytes()

    acquire_files(source, tmp_path / "collection")

    assert source.read_bytes() == original
