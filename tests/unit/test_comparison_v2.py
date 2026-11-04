import json

import pytest

from kasevra.collectors.acquisition import acquire_files
from kasevra.integrity.comparison import (
    ComparisonError,
    compare_v2_baseline,
    create_v2_baseline,
)


def make_collection(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "sample.txt").write_text("original evidence")
    collection = tmp_path / "collection"
    acquire_files(
        source=source,
        destination=collection,
        case_name="Comparison case",
        operator="examiner",
    )
    baseline = tmp_path / "baseline-v2.json"
    create_v2_baseline(collection / "manifest-v2.json", baseline)
    return source, collection, baseline


def test_v2_baseline_round_trip_and_unchanged_comparison(tmp_path):
    _, collection, baseline = make_collection(tmp_path)
    result = compare_v2_baseline(baseline, collection)
    assert result["summary"]["overall_status"] == "PASS"
    assert result["summary"]["PASS"] == 1


def test_detects_modified_file_on_disk(tmp_path):
    _, collection, baseline = make_collection(tmp_path)
    (collection / "sample.txt").write_text("modified evidence")
    result = compare_v2_baseline(baseline, collection)
    assert result["summary"]["MODIFIED"] == 1
    assert result["summary"]["overall_status"] == "FAIL"


def test_detects_missing_file(tmp_path):
    _, collection, baseline = make_collection(tmp_path)
    (collection / "sample.txt").unlink()
    result = compare_v2_baseline(baseline, collection)
    assert result["summary"]["MISSING"] == 1


def test_detects_added_file_and_manifest_record(tmp_path):
    source, collection, baseline = make_collection(tmp_path)
    (source / "new.txt").write_text("new evidence")
    # The current manifest is deliberately unchanged. An unlisted file is unexpected.
    (collection / "new.txt").write_text("new evidence")
    result = compare_v2_baseline(baseline, collection)
    assert result["summary"]["UNEXPECTED"] == 1


def test_detects_manifest_added_evidence(tmp_path):
    source, collection, baseline = make_collection(tmp_path)
    (source / "new.txt").write_text("new evidence")
    new_collection = tmp_path / "new-collection"
    acquire_files(
        source=source,
        destination=new_collection,
        case_name="Comparison case",
        operator="examiner",
    )
    result = compare_v2_baseline(baseline, new_collection)
    assert result["summary"]["ADDED"] == 1


def test_refuses_baseline_overwrite(tmp_path):
    _, collection, baseline = make_collection(tmp_path)
    with pytest.raises(FileExistsError):
        create_v2_baseline(collection / "manifest-v2.json", baseline)


def test_detects_baseline_tampering(tmp_path):
    _, collection, baseline = make_collection(tmp_path)
    data = json.loads(baseline.read_text())
    data["entries"][0]["size_bytes"] += 1
    baseline.write_text(json.dumps(data))
    with pytest.raises(ComparisonError):
        compare_v2_baseline(baseline, collection)


def test_baseline_rejects_case_insensitive_duplicate_paths(tmp_path):
    _, collection, baseline = make_collection(tmp_path)
    data = json.loads(baseline.read_text())
    duplicate = dict(data["entries"][0])
    duplicate["relative_path"] = duplicate["relative_path"].upper()
    data["entries"].append(duplicate)
    data["entry_count"] += 1
    from kasevra.integrity.canonical import canonical_sha256

    digest_input = {k: v for k, v in data.items() if k != "baseline_digest"}
    data["baseline_digest"] = canonical_sha256(digest_input)
    baseline.write_text(json.dumps(data))
    with pytest.raises(ComparisonError):
        compare_v2_baseline(baseline, collection)
