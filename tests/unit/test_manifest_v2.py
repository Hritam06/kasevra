"""Tests for deterministic V2 manifest persistence and validation."""

import json

import pytest

from kasevra.core.identifiers import new_id
from kasevra.core.timestamps import format_utc
from kasevra.integrity.manifest import (
    ManifestError,
    load_manifest,
    serialize_manifest,
    write_manifest,
)
from kasevra.schemas.manifest_v2 import CaseRecord, EvidenceRecord, create_manifest


def make_manifest():
    case = CaseRecord(new_id("case"), "Test case", format_utc(), "tester")
    records = [
        EvidenceRecord(
            new_id("ev"),
            "b.txt",
            "b.txt",
            1,
            "b" * 64,
            format_utc(),
            "tester",
            "test",
            "KASEVRA",
            "2.0.0",
        ),
        EvidenceRecord(
            new_id("ev"),
            "a.txt",
            "a.txt",
            1,
            "a" * 64,
            format_utc(),
            "tester",
            "test",
            "KASEVRA",
            "2.0.0",
        ),
    ]
    return create_manifest(case=case, evidence=records, status="complete")


def test_manifest_serialization_is_deterministic():
    manifest = make_manifest()
    assert serialize_manifest(manifest) == serialize_manifest(manifest)


def test_manifest_round_trip_and_digest(tmp_path):
    manifest = make_manifest()
    path = write_manifest(tmp_path / "manifest-v2.json", manifest)

    loaded = load_manifest(path)
    assert loaded["manifest_digest"] == manifest.manifest_digest
    assert [item["evidence_id"] for item in loaded["evidence"]] == sorted(
        item.evidence_id for item in manifest.evidence
    )


def test_manifest_refuses_overwrite(tmp_path):
    manifest = make_manifest()
    path = write_manifest(tmp_path / "manifest.json", manifest)

    with pytest.raises(FileExistsError):
        write_manifest(path, manifest)


def test_manifest_detects_tampering(tmp_path):
    manifest = make_manifest()
    path = write_manifest(tmp_path / "manifest.json", manifest)

    data = json.loads(path.read_text())
    data["case"]["case_name"] = "Tampered"
    path.write_text(json.dumps(data))

    with pytest.raises(ManifestError, match="digest verification failed"):
        load_manifest(path)


def test_manifest_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"format":"first","format":"second"}')

    with pytest.raises(ManifestError, match="Duplicate JSON object key"):
        load_manifest(path)


def test_manifest_rejects_unsupported_schema(tmp_path):
    manifest = make_manifest()
    path = write_manifest(tmp_path / "manifest.json", manifest)

    data = json.loads(path.read_text())
    data["schema_version"] = "99.0.0"
    path.write_text(json.dumps(data))

    with pytest.raises(ManifestError, match="schema version"):
        load_manifest(path)


def test_manifest_loader_rejects_invalid_nested_evidence(tmp_path):
    import json

    from kasevra.collectors.acquisition import acquire_files
    from kasevra.integrity.manifest import ManifestError, load_manifest

    source = tmp_path / "source"
    source.mkdir()
    (source / "item.txt").write_text("evidence")
    output = tmp_path / "collection"
    acquire_files(source, output)
    path = output / "manifest-v2.json"
    data = json.loads(path.read_text())
    data["evidence"][0]["size_bytes"] = True
    from kasevra.integrity.canonical import manifest_sha256

    data["manifest_digest"] = manifest_sha256(data)
    path.write_text(json.dumps(data))
    with pytest.raises(ManifestError):
        load_manifest(path)
