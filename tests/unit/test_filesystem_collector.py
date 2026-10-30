"""Safety tests for filesystem evidence collection."""

import hashlib
import json
from pathlib import Path

import pytest

from kasevra.collectors.filesystem import collect_files
from kasevra.core.results import ResultStatus
from kasevra.exceptions import SafetyError


def test_collect_file_copies_bytes_and_records_sha256(tmp_path) -> None:
    source = tmp_path / "evidence.txt"
    source.write_bytes(b"sample evidence\n")
    destination = tmp_path / "case-output"

    result = collect_files(source, destination)

    copied = destination / source.name
    manifest = json.loads((destination / "manifest.json").read_text())

    assert result.status is ResultStatus.SUCCESS
    assert copied.read_bytes() == source.read_bytes()
    assert (
        hashlib.sha256(copied.read_bytes()).hexdigest()
        == manifest["entries"][0]["sha256"]
    )
    assert manifest["collected_file_count"] == 1


def test_collect_directory_preserves_relative_paths(tmp_path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    nested = source / "logs"
    nested.mkdir()
    (nested / "event.log").write_text("test event\n")
    destination = tmp_path / "case-output"

    result = collect_files(source, destination)

    assert result.status is ResultStatus.SUCCESS
    assert (destination / "logs" / "event.log").read_text() == "test event\n"


def test_existing_destination_is_never_overwritten(tmp_path) -> None:
    source = tmp_path / "evidence.txt"
    source.write_text("original")
    destination = tmp_path / "existing"
    destination.mkdir()
    marker = destination / "keep.txt"
    marker.write_text("keep me")

    with pytest.raises(SafetyError, match="already exists"):
        collect_files(source, destination)

    assert marker.read_text() == "keep me"


def test_destination_inside_source_is_rejected(tmp_path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    (source / "evidence.txt").write_text("original")
    destination = source / "output"

    with pytest.raises(SafetyError, match="inside the source"):
        collect_files(source, destination)


def test_oversized_file_is_reported_as_partial(tmp_path) -> None:
    source = tmp_path / "large.bin"
    source.write_bytes(b"12345678")
    destination = tmp_path / "case-output"

    result = collect_files(source, destination, max_file_bytes=4)
    manifest = json.loads((destination / "manifest.json").read_text())

    assert result.status is ResultStatus.PARTIAL
    assert result.details["collected_files"] == 0
    assert manifest["collected_file_count"] == 0
    assert manifest["errors"]


def test_collect_directory_skips_symbolic_links(tmp_path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    (source / "real.txt").write_text("real evidence")
    (source / "linked.txt").symlink_to(source / "real.txt")
    destination = tmp_path / "case-output"

    result = collect_files(source, destination)
    manifest = json.loads((destination / "manifest.json").read_text())

    assert result.status is ResultStatus.PARTIAL
    assert (destination / "real.txt").read_text() == "real evidence"
    assert not (destination / "linked.txt").exists()
    assert any("symbolic link" in error for error in manifest["errors"])


def test_collection_detects_source_change_during_copy(tmp_path, monkeypatch) -> None:
    import builtins

    source = tmp_path / "evidence.txt"
    source.write_bytes(b"original")
    destination = tmp_path / "case-output"
    original_open = builtins.open

    class ChangingReader:
        def __init__(self, path):
            self.path = path
            self.stream = original_open(path, "rb")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size=-1):
            data = self.stream.read(size)
            if data:
                source.write_bytes(b"changed!")
            return data

    import kasevra.collectors.filesystem as collector

    original_path_open = Path.open

    def patched_open(path, *args, **kwargs):
        if path == source and args and args[0] == "rb":
            return ChangingReader(path)
        return original_path_open(path, *args, **kwargs)

    monkeypatch.setattr(collector.Path, "open", patched_open)

    result = collector.collect_files(source, destination)

    assert result.status is ResultStatus.PARTIAL
    assert result.details["collected_files"] == 0


def test_collection_does_not_modify_source_file(tmp_path) -> None:
    source = tmp_path / "evidence.txt"
    source.write_bytes(b"original evidence")
    original_bytes = source.read_bytes()
    original_mtime = source.stat().st_mtime_ns
    destination = tmp_path / "case-output"

    result = collect_files(source, destination)

    assert result.status is ResultStatus.SUCCESS
    assert source.read_bytes() == original_bytes
    assert source.stat().st_mtime_ns == original_mtime


def test_manifest_write_failure_is_reported(tmp_path, monkeypatch) -> None:
    import kasevra.collectors.filesystem as collector
    from kasevra.exceptions import OperationError

    source = tmp_path / "evidence.txt"
    source.write_text("test evidence")
    destination = tmp_path / "case-output"
    original_open = Path.open

    def failing_manifest_open(path, *args, **kwargs):
        if path.name == "manifest.json" and args and args[0] == "x":
            raise OSError("simulated manifest write failure")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(collector.Path, "open", failing_manifest_open)

    with pytest.raises(OperationError, match="manifest"):
        collector.collect_files(source, destination)

    assert not destination.exists()


def test_destination_symlink_is_rejected(tmp_path) -> None:
    source = tmp_path / "evidence.txt"
    source.write_text("evidence")

    real_destination = tmp_path / "real-destination"
    real_destination.mkdir()

    destination_link = tmp_path / "destination-link"
    destination_link.symlink_to(real_destination, target_is_directory=True)

    with pytest.raises(SafetyError, match="Destination already exists"):
        collect_files(source, destination_link)

    assert list(real_destination.iterdir()) == []


def test_failed_copy_does_not_leave_partial_file(tmp_path, monkeypatch) -> None:
    import kasevra.collectors.filesystem as collector

    source = tmp_path / "evidence.txt"
    source.write_bytes(b"evidence content")
    destination = tmp_path / "case-output"
    original_open = Path.open

    class FailingReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size=-1):
            raise OSError("simulated read failure")

    def patched_open(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        if path == source and args and args[0] == "rb":
            return FailingReader(stream)
        return stream

    monkeypatch.setattr(collector.Path, "open", patched_open)

    result = collector.collect_files(source, destination)

    assert result.status is ResultStatus.PARTIAL
    assert result.details["collected_files"] == 0
    assert not (destination / "evidence.txt").exists()
    assert (destination / "manifest.json").exists()


def test_directory_collection_excludes_sibling_files(tmp_path) -> None:
    source = tmp_path / "selected"
    source.mkdir()
    (source / "inside.txt").write_text("selected evidence")

    (tmp_path / "outside.txt").write_text("not selected")

    destination = tmp_path / "case-output"
    result = collect_files(source, destination)

    assert result.status is ResultStatus.SUCCESS
    assert (destination / "inside.txt").read_text() == "selected evidence"
    assert not (destination / "outside.txt").exists()
    assert result.details["collected_files"] == 1


def test_source_symlink_is_rejected(tmp_path) -> None:
    source_file = tmp_path / "real-evidence.txt"
    source_file.write_text("evidence")

    source_link = tmp_path / "evidence-link.txt"
    source_link.symlink_to(source_file)

    destination = tmp_path / "case-output"

    with pytest.raises(SafetyError, match="source path"):
        collect_files(source_link, destination)

    assert not destination.exists()
