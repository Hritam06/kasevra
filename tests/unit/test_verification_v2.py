"""Independent V2 evidence verification tests."""

import json

from kasevra.collectors.acquisition import acquire_files
from kasevra.integrity.verification import verify_v2_collection


def make_collection(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "sample.txt").write_text("original evidence")
    result = acquire_files(source, tmp_path / "collection", operator="tester")
    return tmp_path / "collection", result


def test_verification_passes_unchanged_evidence(tmp_path):
    collection, _ = make_collection(tmp_path)
    result = verify_v2_collection(collection)

    assert result["manifest_integrity"] == "PASS"
    assert result["summary"]["overall_status"] == "PASS"
    assert result["summary"]["PASS"] == 1


def test_verification_detects_modified_evidence(tmp_path):
    collection, _ = make_collection(tmp_path)
    (collection / "sample.txt").write_text("changed evidence")

    result = verify_v2_collection(collection)
    assert result["summary"]["MODIFIED"] == 1
    assert result["summary"]["overall_status"] == "FAIL"


def test_verification_detects_missing_evidence(tmp_path):
    collection, _ = make_collection(tmp_path)
    (collection / "sample.txt").unlink()

    result = verify_v2_collection(collection)
    assert result["summary"]["MISSING"] == 1


def test_verification_detects_unexpected_evidence(tmp_path):
    collection, _ = make_collection(tmp_path)
    (collection / "extra.txt").write_text("unexpected")

    result = verify_v2_collection(collection)
    assert result["summary"]["UNEXPECTED"] == 1


def test_verification_detects_manifest_tampering(tmp_path):
    collection, _ = make_collection(tmp_path)
    path = collection / "manifest-v2.json"
    manifest = json.loads(path.read_text())
    manifest["case"]["case_name"] = "Tampered"
    path.write_text(json.dumps(manifest))

    result = verify_v2_collection(collection)
    assert result["manifest_integrity"] == "ERROR"
    assert result["summary"]["overall_status"] == "ERROR"


def test_verification_rejects_symlinked_evidence(tmp_path):
    collection, _ = make_collection(tmp_path)
    evidence = collection / "sample.txt"
    evidence.unlink()

    outside = tmp_path / "outside.txt"
    outside.write_text("external")
    evidence.symlink_to(outside)

    result = verify_v2_collection(collection)
    assert result["summary"]["ERROR"] == 1


def test_verification_reports_unexpected_symlink(tmp_path):
    collection, _ = make_collection(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    (collection / "unexpected-link").symlink_to(outside)
    result = verify_v2_collection(collection)
    assert result["summary"]["UNEXPECTED"] == 1
