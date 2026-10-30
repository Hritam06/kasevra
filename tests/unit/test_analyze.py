"""Tests for KASEVRA collection analysis."""

import json

import pytest

from kasevra.commands.analyze import analyze_collection
from kasevra.core.results import ResultStatus
from kasevra.exceptions import IntegrityError, SafetyError

HASH_A = "a" * 64
HASH_B = "b" * 64


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def write_inputs(tmp_path, baseline_entries=None, manifest_entries=None):
    baseline_entries = (
        baseline_entries
        if baseline_entries is not None
        else [
            {"path": "one.txt", "size_bytes": 4, "sha256": HASH_A},
            {"path": "two.txt", "size_bytes": 4, "sha256": HASH_A},
        ]
    )
    manifest_entries = (
        manifest_entries
        if manifest_entries is not None
        else [
            {"collected_path": "one.txt", "size_bytes": 4, "sha256": HASH_A},
            {"collected_path": "two.txt", "size_bytes": 4, "sha256": HASH_A},
        ]
    )

    baseline = write_json(
        tmp_path / "baseline.json",
        {
            "format": "kasevra-baseline-v1",
            "entry_count": len(baseline_entries),
            "entries": baseline_entries,
        },
    )
    manifest = write_json(
        tmp_path / "manifest.json",
        {
            "format": "kasevra-evidence-manifest-v1",
            "collected_file_count": len(manifest_entries),
            "entries": manifest_entries,
        },
    )
    return baseline, manifest


def test_identical_entries_succeed(tmp_path):
    baseline, manifest = write_inputs(tmp_path)

    result = analyze_collection(baseline, manifest)

    assert result.status is ResultStatus.SUCCESS
    assert result.details["unchanged"] == 2
    assert result.details["modified"] == []
    assert result.details["missing"] == []
    assert result.details["unexpected"] == []


def test_modified_file_is_reported(tmp_path):
    baseline, manifest = write_inputs(
        tmp_path,
        manifest_entries=[
            {"collected_path": "one.txt", "size_bytes": 4, "sha256": HASH_B},
            {"collected_path": "two.txt", "size_bytes": 4, "sha256": HASH_A},
        ],
    )

    result = analyze_collection(baseline, manifest)

    assert result.status is ResultStatus.PARTIAL
    assert result.details["modified"] == ["one.txt"]


def test_missing_and_unexpected_files_are_reported(tmp_path):
    baseline, manifest = write_inputs(
        tmp_path,
        manifest_entries=[
            {"collected_path": "one.txt", "size_bytes": 4, "sha256": HASH_A},
            {"collected_path": "extra.txt", "size_bytes": 4, "sha256": HASH_A},
        ],
    )

    result = analyze_collection(baseline, manifest)

    assert result.details["missing"] == ["two.txt"]
    assert result.details["unexpected"] == ["extra.txt"]


def test_invalid_entry_count_is_rejected(tmp_path):
    baseline, manifest = write_inputs(tmp_path)
    data = json.loads(baseline.read_text(encoding="utf-8"))
    data["entry_count"] = 99
    baseline.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(IntegrityError):
        analyze_collection(baseline, manifest)


def test_unsafe_path_is_rejected(tmp_path):
    baseline, manifest = write_inputs(
        tmp_path,
        baseline_entries=[
            {"path": "../outside.txt", "size_bytes": 4, "sha256": HASH_A},
        ],
    )

    with pytest.raises(IntegrityError):
        analyze_collection(baseline, manifest)


def test_duplicate_path_is_rejected(tmp_path):
    baseline, manifest = write_inputs(
        tmp_path,
        baseline_entries=[
            {"path": "one.txt", "size_bytes": 4, "sha256": HASH_A},
            {"path": "one.txt", "size_bytes": 4, "sha256": HASH_A},
        ],
    )

    with pytest.raises(IntegrityError):
        analyze_collection(baseline, manifest)


def test_symlink_input_is_rejected(tmp_path):
    baseline, manifest = write_inputs(tmp_path)
    link = tmp_path / "baseline-link.json"
    link.symlink_to(baseline)

    with pytest.raises(SafetyError):
        analyze_collection(link, manifest)
