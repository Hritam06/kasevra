import io
import os

import pytest

from kasevra.crypto.keys import KeyError as KasevraKeyError
from kasevra.crypto.keys import generate_keypair, load_private_key, load_public_key
from kasevra.exceptions import OperationError, SafetyError
from kasevra.integrity.hashing import sha256_bytes, sha256_file, sha256_stream
from kasevra.reporting.html_report import render_v2_html_report, write_v2_html_report
from kasevra.reporting.json_report import (
    build_v2_report,
    serialize_v2_report,
    write_v2_json_report,
)


def test_hashing_bytes_and_stream_boundaries(tmp_path):
    payload = b"KASEVRA evidence" * 100
    expected = sha256_bytes(payload)
    assert sha256_stream(io.BytesIO(payload), chunk_size=7) == expected
    file_path = tmp_path / "evidence.bin"
    file_path.write_bytes(payload)
    assert sha256_file(file_path, chunk_size=11) == expected


def test_hashing_rejects_invalid_inputs(tmp_path):
    with pytest.raises(TypeError):
        sha256_bytes("not bytes")
    with pytest.raises(TypeError):
        sha256_stream(io.BytesIO(b"x"), chunk_size=True)
    with pytest.raises(ValueError):
        sha256_stream(io.BytesIO(b"x"), chunk_size=0)

    class TextStream:
        def read(self, size):
            return "not bytes"

    with pytest.raises(TypeError):
        sha256_stream(TextStream())


def test_hashing_propagates_stream_read_errors():
    class BrokenStream:
        def read(self, size):
            raise OSError("read failed")

    with pytest.raises(OSError, match="read failed"):
        sha256_stream(BrokenStream())


def test_json_report_rejects_unsupported_and_float_values():
    with pytest.raises(ValueError):
        build_v2_report({"evidence": {"score": 1.5}})
    with pytest.raises(ValueError):
        build_v2_report({"evidence": {1: "invalid key"}})
    with pytest.raises(ValueError):
        build_v2_report({"evidence": {"value": object()}})
    with pytest.raises(ValueError):
        build_v2_report([])


def test_json_report_serialization_requires_v2_format():
    with pytest.raises(ValueError):
        serialize_v2_report({"report_format": "unknown"})


def test_json_report_writes_without_overwriting(tmp_path):
    report = build_v2_report(
        {"case_id": "case-1"}, generated_utc="2026-01-01T00:00:00Z"
    )
    output = tmp_path / "report.json"
    assert write_v2_json_report(report, output) == output
    assert output.exists()
    assert output.read_text().endswith("\n")
    with pytest.raises(SafetyError):
        write_v2_json_report(report, output)


def test_json_report_rejects_symlink_and_missing_parent(tmp_path):
    report = build_v2_report({})
    actual = tmp_path / "actual.json"
    actual.write_text("keep")
    link = tmp_path / "linked.json"
    link.symlink_to(actual)
    with pytest.raises(SafetyError):
        write_v2_json_report(report, link)
    with pytest.raises(OperationError):
        write_v2_json_report(report, tmp_path / "missing" / "report.json")


def test_html_report_renders_nested_values_and_escapes_content():
    report = build_v2_report(
        {"case": "<script>alert(1)</script>", "items": ["<img src=x>", None, True]},
        verification={"status": "PASS", "details": {"note": "'quoted' & <unsafe>"}},
        generated_utc="2026-01-01T00:00:00Z",
    )
    rendered = render_v2_html_report(report)
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "&lt;img src=x&gt;" in rendered
    assert "Not supplied" in rendered
    assert "true" in rendered


def test_html_report_rejects_invalid_report():
    with pytest.raises(ValueError):
        render_v2_html_report({"report_format": "wrong"})


def test_html_report_writes_without_overwriting(tmp_path):
    report = build_v2_report({"case_id": "case-2"})
    output = tmp_path / "report.html"
    assert write_v2_html_report(report, output) == output
    assert "KASEVRA V2 Evidence Report" in output.read_text()
    with pytest.raises(SafetyError):
        write_v2_html_report(report, output)


def test_html_report_rejects_symlink_and_missing_parent(tmp_path):
    report = build_v2_report({})
    actual = tmp_path / "actual.html"
    actual.write_text("keep")
    link = tmp_path / "linked.html"
    link.symlink_to(actual)
    with pytest.raises(SafetyError):
        write_v2_html_report(report, link)
    with pytest.raises(OperationError):
        write_v2_html_report(report, tmp_path / "missing" / "report.html")


def test_key_loaders_reject_malformed_and_wrong_key_types(tmp_path):
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    generate_keypair(private_path, public_path)

    malformed = tmp_path / "malformed.pem"
    malformed.write_text("not a PEM key")
    malformed.chmod(0o600)
    with pytest.raises(KasevraKeyError):
        load_private_key(malformed)
    with pytest.raises(KasevraKeyError):
        load_public_key(malformed)

    with pytest.raises(KasevraKeyError):
        load_private_key(public_path)


def test_key_loaders_reject_symlinked_key_files(tmp_path):
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    generate_keypair(private_path, public_path)
    private_link = tmp_path / "private-link.pem"
    public_link = tmp_path / "public-link.pem"
    private_link.symlink_to(private_path)
    public_link.symlink_to(public_path)

    with pytest.raises(KasevraKeyError):
        load_private_key(private_link)
    with pytest.raises(KasevraKeyError):
        load_public_key(public_link)


def test_key_generation_refuses_same_path_and_existing_files(tmp_path):
    same = tmp_path / "same.pem"
    with pytest.raises(KasevraKeyError):
        generate_keypair(same, same)

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    generate_keypair(private_path, public_path)
    with pytest.raises(FileExistsError):
        generate_keypair(private_path, public_path)


def test_generated_keypair_loads_as_ed25519(tmp_path):
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    generate_keypair(private_path, public_path)
    assert load_private_key(private_path).__class__.__name__ == "Ed25519PrivateKey"
    assert load_public_key(public_path).__class__.__name__ == "Ed25519PublicKey"
    if os.name == "posix":
        assert private_path.stat().st_mode & 0o077 == 0
