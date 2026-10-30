"""CLI tests for filesystem collection."""

from typer.testing import CliRunner

from kasevra.cli import app


def test_collect_command_copies_file_and_writes_manifest(tmp_path) -> None:
    source = tmp_path / "evidence.txt"
    source.write_text("test evidence")
    destination = tmp_path / "case-output"

    result = CliRunner().invoke(app, ["collect", str(source), str(destination)])

    assert result.exit_code == 0, result.output
    assert (destination / "evidence.txt").read_text() == "test evidence"
    assert (destination / "manifest.json").is_file()
    assert "Collected 1 file(s)" in result.output


def test_collect_command_refuses_existing_destination(tmp_path) -> None:
    source = tmp_path / "evidence.txt"
    source.write_text("test evidence")
    destination = tmp_path / "case-output"
    destination.mkdir()
    marker = destination / "keep.txt"
    marker.write_text("preserve")

    result = CliRunner().invoke(app, ["collect", str(source), str(destination)])

    assert result.exit_code != 0
    assert marker.read_text() == "preserve"
