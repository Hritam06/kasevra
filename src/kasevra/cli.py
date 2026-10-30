"""KASEVRA command-line application."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer

from kasevra.collectors.filesystem import collect_files
from kasevra.commands.analyze import analyze_collection
from kasevra.commands.baseline import create_baseline
from kasevra.commands.doctor import run_doctor
from kasevra.commands.report import generate_report
from kasevra.commands.verify import verify_collection
from kasevra.ui.branding import PRODUCT_DESCRIPTION, TAGLINE
from kasevra.ui.dashboard import dashboard_demo


def version_callback(value: bool) -> None:
    """Display the installed KASEVRA version."""
    if not value:
        return

    try:
        installed_version = version("kasevra")
    except PackageNotFoundError:
        installed_version = "unknown"

    typer.echo(f"KASEVRA {installed_version}")
    raise typer.Exit()


app = typer.Typer(
    name="kasevra",
    help=f"{PRODUCT_DESCRIPTION}\n\n{TAGLINE}",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
    pretty_exceptions_enable=False,
)


@app.command()
def doctor() -> None:
    """Check the local environment and KASEVRA runtime."""
    from kasevra.core.execution import execute

    raise typer.Exit(code=execute(run_doctor))


@app.command()
def collect(source: Path, destination: Path) -> None:
    """Copy selected files and write a SHA-256 manifest."""
    from kasevra.core.execution import execute

    raise typer.Exit(code=execute(lambda: collect_files(source, destination)))


@app.command()
def baseline(manifest: Path, output: Path) -> None:
    """Create a reference baseline from a collection manifest."""
    from kasevra.core.execution import execute

    raise typer.Exit(code=execute(lambda: create_baseline(manifest, output)))


@app.command()
def analyze(baseline: Path, manifest: Path) -> None:
    """Compare a collection manifest against a reference baseline."""
    from kasevra.core.execution import execute

    raise typer.Exit(code=execute(lambda: analyze_collection(baseline, manifest)))


@app.command()
def verify(collection: Path) -> None:
    """Verify collected evidence against its SHA-256 manifest."""
    from kasevra.core.execution import execute

    raise typer.Exit(code=execute(lambda: verify_collection(collection)))


@app.command()
def report(
    collection: Path,
    output: Path = typer.Option(..., "--output", "-o", help="Report output path."),
    report_format: str = typer.Option(
        "json",
        "--format",
        help="Report format: json or html.",
    ),
) -> None:
    """Generate a JSON or HTML report from a collection."""
    from kasevra.core.execution import execute

    raise typer.Exit(
        code=execute(lambda: generate_report(collection, output, report_format))
    )


@app.command(short_help="Preview terminal UI (sample data only).")
def dashboard() -> None:
    """Preview the terminal UI using sample data only."""
    dashboard_demo()


@app.callback()
def main(
    show_version: bool = typer.Option(
        False,
        "--version",
        help="Show the installed version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """KASEVRA: collect with care and verify with confidence."""


if __name__ == "__main__":
    app()
