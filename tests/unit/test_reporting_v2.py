"""Tests for enhanced V2 JSON and HTML reporting."""

import json

import pytest

from kasevra.exceptions import SafetyError
from kasevra.reporting.html_report import render_v2_html_report, write_v2_html_report
from kasevra.reporting.json_report import (
    build_v2_report,
    serialize_v2_report,
    write_v2_json_report,
)


def sample_report(**kwargs):
    return build_v2_report(
        {
            "case_id": "case-01",
            "evidence": [{"path": "sample.txt", "sha256": "a" * 64}],
        },
        generated_utc="2026-01-01T00:00:00Z",
        **kwargs,
    )


def test_report_records_supplied_sections_without_inference():
    report = sample_report(verification={"status": "PASS"})
    assert report["verification"]["status"] == "PASS"
    assert report["summary"]["included_sections"] == ["verification"]
    assert report["summary"]["not_included_sections"] == [
        "comparison",
        "signature",
        "custody",
    ]


def test_json_serialization_is_deterministic():
    report = sample_report(verification={"status": "PASS"})
    assert serialize_v2_report(report) == serialize_v2_report(report)
    assert (
        json.loads(serialize_v2_report(report))["report_format"] == "kasevra-report-v2"
    )


def test_json_output_refuses_overwrite(tmp_path):
    output = tmp_path / "report.json"
    output.write_text("keep", encoding="utf-8")
    with pytest.raises(SafetyError):
        write_v2_json_report(sample_report(), output)
    assert output.read_text(encoding="utf-8") == "keep"


def test_html_escapes_untrusted_values():
    report = sample_report(verification={"message": "<script>alert(1)</script>"})
    rendered = render_v2_html_report(report)
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_html_output_refuses_overwrite(tmp_path):
    output = tmp_path / "report.html"
    output.write_text("keep", encoding="utf-8")
    with pytest.raises(SafetyError):
        write_v2_html_report(sample_report(), output)
    assert output.read_text(encoding="utf-8") == "keep"


def test_report_rejects_non_json_floats():
    with pytest.raises(ValueError):
        sample_report(verification={"score": 1.5})


def test_report_includes_signature_and_custody_when_supplied():
    report = sample_report(
        signature={"status": "PASS", "algorithm": "Ed25519"},
        custody={"status": "PASS", "event_count": 3},
    )
    rendered = render_v2_html_report(report)
    assert "Ed25519" in rendered
    assert "event_count" in rendered
    assert report["summary"]["included_sections"] == ["signature", "custody"]
