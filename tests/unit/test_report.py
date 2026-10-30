"""Tests for KASEVRA JSON and HTML reporting."""

import hashlib
import json

import pytest

from kasevra.commands.report import generate_report
from kasevra.core.results import ResultStatus
from kasevra.exceptions import IntegrityError, SafetyError


def make_collection(tmp_path, *, warning=None):
    collection = tmp_path / "collection"
    collection.mkdir()

    content = b"sample evidence"
    entry = {
        "source_relative_path": "sample.txt",
        "collected_path": "sample.txt",
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }

    manifest = {
        "format": "kasevra-evidence-manifest-v1",
        "created_utc": "2026-01-01T00:00:00+00:00",
        "hash_algorithm": "SHA-256",
        "source": "/sample/source",
        "collected_file_count": 1,
        "entries": [entry],
        "errors": [warning] if warning else [],
        "limitations": ["Hashes do not prove authenticity."],
    }

    (collection / "sample.txt").write_bytes(content)
    (collection / "manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    return collection


def test_json_report_contains_collection_inventory(tmp_path):
    collection = make_collection(tmp_path)
    output = tmp_path / "report.json"

    result = generate_report(collection, output, "json")
    report = json.loads(output.read_text(encoding="utf-8"))

    assert result.status is ResultStatus.SUCCESS
    assert report["report_format"] == "kasevra-report-v1"
    assert report["collection"]["file_count"] == 1
    assert report["files"][0]["path"] == "sample.txt"
    assert report["files"][0]["size_bytes"] == len(b"sample evidence")
    assert (
        report["files"][0]["sha256"] == hashlib.sha256(b"sample evidence").hexdigest()
    )
    assert report["analysis"]["status"] == "not_included"
    assert report["verification"]["status"] == "not_included"


def test_html_report_contains_required_sections(tmp_path):
    collection = make_collection(tmp_path)
    output = tmp_path / "report.html"

    result = generate_report(collection, output, "html")
    content = output.read_text(encoding="utf-8")

    assert result.status is ResultStatus.SUCCESS
    assert "<!DOCTYPE html>" in content
    assert "KASEVRA" in content
    assert "Evidence inventory" in content
    assert "Analysis: NOT INCLUDED" in content
    assert "Verification: NOT INCLUDED" in content
    assert "does not independently verify evidence files" in content


def test_html_report_escapes_untrusted_content(tmp_path):
    collection = make_collection(
        tmp_path,
        warning="<script>alert('unsafe')</script>",
    )
    output = tmp_path / "report.html"

    generate_report(collection, output, "html")
    content = output.read_text(encoding="utf-8")

    assert "<script>" not in content
    assert "&lt;script&gt;" in content


def test_existing_report_is_not_overwritten(tmp_path):
    collection = make_collection(tmp_path)
    output = tmp_path / "report.json"
    output.write_text("preserve this", encoding="utf-8")

    with pytest.raises(SafetyError):
        generate_report(collection, output, "json")

    assert output.read_text(encoding="utf-8") == "preserve this"


def test_invalid_manifest_format_is_rejected(tmp_path):
    collection = make_collection(tmp_path)
    manifest_path = collection / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["format"] = "unknown-format"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(IntegrityError):
        generate_report(collection, tmp_path / "report.json")


def test_manifest_count_mismatch_is_rejected(tmp_path):
    collection = make_collection(tmp_path)
    manifest_path = collection / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["collected_file_count"] = 2
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(IntegrityError):
        generate_report(collection, tmp_path / "report.json")


def test_invalid_report_format_is_rejected(tmp_path):
    collection = make_collection(tmp_path)

    with pytest.raises(SafetyError):
        generate_report(collection, tmp_path / "report.txt", "text")


def test_report_cannot_be_written_inside_collection(tmp_path):
    collection = make_collection(tmp_path)

    with pytest.raises(SafetyError):
        generate_report(collection, collection / "report.json")


def test_report_cannot_overwrite_manifest(tmp_path):
    collection = make_collection(tmp_path)

    with pytest.raises(SafetyError):
        generate_report(collection, collection / "manifest.json")


def test_collection_warning_is_preserved(tmp_path):
    collection = make_collection(tmp_path, warning="Skipped a symbolic link")
    output = tmp_path / "report.json"

    generate_report(collection, output)
    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["collection_warnings"] == ["Skipped a symbolic link"]


def test_collection_symlink_is_rejected(tmp_path):
    collection = make_collection(tmp_path)
    linked = tmp_path / "linked"
    linked.symlink_to(collection, target_is_directory=True)

    with pytest.raises(SafetyError):
        generate_report(linked, tmp_path / "report.json")


def test_output_symlink_is_rejected(tmp_path):
    collection = make_collection(tmp_path)
    target = tmp_path / "target.json"
    target.write_text("preserve this", encoding="utf-8")
    output = tmp_path / "report.json"
    output.symlink_to(target)

    with pytest.raises(SafetyError):
        generate_report(collection, output)

    assert target.read_text(encoding="utf-8") == "preserve this"
