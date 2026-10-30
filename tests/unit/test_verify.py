"""Tests for KASEVRA evidence verification."""

import hashlib
import json

import pytest

from kasevra.commands.verify import verify_collection
from kasevra.core.results import ResultStatus
from kasevra.exceptions import IntegrityError, SafetyError


def make_manifest(collection, entries, errors=None):
    manifest = {
        "format": "kasevra-evidence-manifest-v1",
        "hash_algorithm": "SHA-256",
        "collected_file_count": len(entries),
        "entries": entries,
        "errors": errors or [],
    }
    (collection / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def add_entry(collection, relative, content):
    path = collection / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {
        "collected_path": relative,
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def test_valid_collection_verifies(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir()
    entry = add_entry(collection, "sample.txt", b"evidence")
    make_manifest(collection, [entry])

    result = verify_collection(collection)

    assert result.status is ResultStatus.SUCCESS
    assert result.details["verified_entries"] == 1
    assert result.details["modified"] == []


def test_modified_file_is_reported(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir()
    entry = add_entry(collection, "sample.txt", b"original")
    make_manifest(collection, [entry])
    (collection / "sample.txt").write_bytes(b"changed")

    result = verify_collection(collection)

    assert result.status is ResultStatus.PARTIAL
    assert result.details["modified"] == ["sample.txt"]


def test_missing_file_is_reported(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir()
    entry = {
        "collected_path": "missing.txt",
        "size_bytes": 4,
        "sha256": hashlib.sha256(b"data").hexdigest(),
    }
    make_manifest(collection, [entry])

    result = verify_collection(collection)

    assert result.status is ResultStatus.PARTIAL
    assert result.details["missing"] == ["missing.txt"]


def test_unexpected_file_is_reported(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir()
    entry = add_entry(collection, "sample.txt", b"evidence")
    (collection / "extra.txt").write_text("unexpected")
    make_manifest(collection, [entry])

    result = verify_collection(collection)

    assert result.status is ResultStatus.PARTIAL
    assert result.details["unexpected"] == ["extra.txt"]


def test_collection_warning_is_preserved(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir()
    make_manifest(collection, [], errors=["Skipped a symbolic link"])

    result = verify_collection(collection)

    assert result.status is ResultStatus.PARTIAL
    assert result.details["collection_warnings"] == ["Skipped a symbolic link"]


def test_unsafe_manifest_path_is_rejected(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir()
    make_manifest(
        collection,
        [
            {
                "collected_path": "../outside.txt",
                "size_bytes": 4,
                "sha256": hashlib.sha256(b"data").hexdigest(),
            }
        ],
    )

    with pytest.raises(IntegrityError):
        verify_collection(collection)


def test_manifest_count_mismatch_is_rejected(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir()
    make_manifest(collection, [])
    manifest_path = collection / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["collected_file_count"] = 1
    manifest_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(IntegrityError):
        verify_collection(collection)


def test_collection_symlink_is_rejected(tmp_path):
    collection = tmp_path / "real"
    collection.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(collection, target_is_directory=True)

    with pytest.raises(SafetyError):
        verify_collection(link)


def test_evidence_symlink_is_not_followed(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside evidence")
    (collection / "linked.txt").symlink_to(outside)

    entry = {
        "collected_path": "linked.txt",
        "size_bytes": 15,
        "sha256": hashlib.sha256(b"outside evidence").hexdigest(),
    }
    make_manifest(collection, [entry])

    result = verify_collection(collection)

    assert result.status is ResultStatus.PARTIAL
    assert result.details["unreadable"] == ["linked.txt"]
    assert result.details["unsafe"] == ["linked.txt"]


def test_nested_file_verifies_successfully(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir()
    entry = add_entry(collection, "nested/folder/sample.txt", b"nested evidence")
    make_manifest(collection, [entry])

    result = verify_collection(collection)

    assert result.status is ResultStatus.SUCCESS
    assert result.details["verified_entries"] == 1


def test_invalid_sha256_is_rejected(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir()
    make_manifest(
        collection,
        [
            {
                "collected_path": "sample.txt",
                "size_bytes": 4,
                "sha256": "invalid-hash",
            }
        ],
    )

    with pytest.raises(IntegrityError):
        verify_collection(collection)


def test_verification_does_not_modify_evidence(tmp_path):
    collection = tmp_path / "collection"
    collection.mkdir()
    content = b"preserve this evidence"
    entry = add_entry(collection, "sample.txt", content)
    make_manifest(collection, [entry])

    evidence_path = collection / "sample.txt"
    before = evidence_path.read_bytes()
    verify_collection(collection)
    after = evidence_path.read_bytes()

    assert before == after == content
