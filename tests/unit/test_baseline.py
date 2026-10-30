"""Tests for validated baseline creation."""

import json

import pytest

from kasevra.commands.baseline import create_baseline
from kasevra.core.results import ResultStatus
from kasevra.exceptions import IntegrityError, SafetyError

VALID_HASH = "a" * 64


def write_manifest(path, entries=None):
    entries = (
        entries
        if entries is not None
        else [
            {
                "collected_path": "docs/evidence.txt",
                "size_bytes": 12,
                "sha256": VALID_HASH,
            }
        ]
    )
    path.write_text(
        json.dumps(
            {
                "format": "kasevra-evidence-manifest-v1",
                "collected_file_count": len(entries),
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )


def test_create_baseline_from_valid_manifest(tmp_path):
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "baseline.json"
    write_manifest(manifest)

    result = create_baseline(manifest, output)
    baseline = json.loads(output.read_text(encoding="utf-8"))

    assert result.status is ResultStatus.SUCCESS
    assert baseline["format"] == "kasevra-baseline-v1"
    assert baseline["entry_count"] == 1
    assert baseline["entries"][0]["path"] == "docs/evidence.txt"
    assert baseline["entries"][0]["sha256"] == VALID_HASH


@pytest.mark.parametrize(
    "entry",
    [
        {"collected_path": "../outside.txt", "size_bytes": 1, "sha256": VALID_HASH},
        {"collected_path": "/absolute.txt", "size_bytes": 1, "sha256": VALID_HASH},
        {"collected_path": "bad.txt", "size_bytes": 1, "sha256": "not-a-hash"},
        {"collected_path": "bad.txt", "size_bytes": -1, "sha256": VALID_HASH},
    ],
)
def test_rejects_unsafe_or_invalid_manifest_entries(tmp_path, entry):
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "baseline.json"
    write_manifest(manifest, [entry])

    with pytest.raises(IntegrityError):
        create_baseline(manifest, output)

    assert not output.exists()


def test_refuses_existing_baseline_output(tmp_path):
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "baseline.json"
    write_manifest(manifest)
    output.write_text("preserve", encoding="utf-8")

    with pytest.raises(SafetyError, match="already exists"):
        create_baseline(manifest, output)

    assert output.read_text(encoding="utf-8") == "preserve"


def test_rejects_mismatched_manifest_count(tmp_path):
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "baseline.json"
    write_manifest(manifest)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["collected_file_count"] = 99
    manifest.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(IntegrityError, match="count"):
        create_baseline(manifest, output)


def test_collect_manifest_can_create_baseline(tmp_path):
    from kasevra.collectors.filesystem import collect_files

    source = tmp_path / "evidence.txt"
    source.write_text("integration evidence", encoding="utf-8")
    collection = tmp_path / "collection"
    baseline = tmp_path / "baseline.json"

    result = collect_files(source, collection)
    assert result.status is ResultStatus.SUCCESS

    baseline_result = create_baseline(
        collection / "manifest.json",
        baseline,
    )

    assert baseline_result.status is ResultStatus.SUCCESS
    data = json.loads(baseline.read_text(encoding="utf-8"))
    assert data["entry_count"] == 1
    assert data["entries"][0]["path"] == "evidence.txt"
