"""Shared KASEVRA terminal interface."""

import os
import sys
from datetime import datetime

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .branding import (
    AMBER,
    APP_NAME,
    GREEN,
    PRODUCT_DESCRIPTION,
    RED,
    SHIELD,
    SHIELD_ASCII,
    TAGLINE,
    TEAL,
)

COLOR_ENABLED = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM", "") != "dumb"
)

console = Console(
    highlight=False,
    soft_wrap=True,
    color_system="auto" if COLOR_ENABLED else None,
)


def header(command: str = "dashboard", subtitle: str = "") -> None:
    """Render the KASEVRA identity and command context."""
    console.print()
    width = min(console.width, 88)
    logo_text = (
        SHIELD.strip("\n")
        if COLOR_ENABLED and width >= 65
        else SHIELD_ASCII.strip("\n")
    )
    accent = f"bold {TEAL}" if COLOR_ENABLED else "bold"
    brand = Text(justify="center")
    brand.append(logo_text + "\n", style=accent)
    brand.append("\n" + APP_NAME + "\n", style=accent)
    brand.append(
        PRODUCT_DESCRIPTION + "\n",
        style="dim" if COLOR_ENABLED else None,
    )
    brand.append(
        TAGLINE,
        style=f"italic {TEAL}" if COLOR_ENABLED else "italic",
    )
    console.print(
        Panel(
            Align.center(brand),
            width=width,
            border_style=TEAL if COLOR_ENABLED else "white",
            box=box.HEAVY,
            padding=(1, 2),
        )
    )
    details = Text()
    details.append("COMMAND  ", style=accent)
    details.append(f"kasevra {command}    ")
    details.append("TIME  ", style=accent)
    details.append(datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"))
    if subtitle:
        details.append("\n" + subtitle)
    console.print(Align.center(details, width=width))
    console.print()


def section(title: str) -> None:
    """Print a consistent section heading."""
    console.rule(
        f"[bold {TEAL}]{title}[/]" if COLOR_ENABLED else title,
        style=TEAL if COLOR_ENABLED else None,
    )


def status(label: str, message: str, state: str = "INFO") -> None:
    """Render a truthful status line."""
    styles = {
        "OK": (GREEN, "[OK]"),
        "WARN": (AMBER, "[WARN]"),
        "FAIL": (RED, "[FAIL]"),
        "INFO": (TEAL, "[INFO]"),
    }

    color, marker = styles.get(state, styles["INFO"])
    style = f"bold {color}" if COLOR_ENABLED else "bold"
    console.print(f"[{style}]{marker}[/] {label}: {message}")


def summary(title: str, rows: list[tuple[str, str]]) -> None:
    """Render a consistent command summary."""
    section(title)

    table = Table(box=box.SIMPLE, expand=True, width=min(console.width, 88))
    table.add_column("ITEM", style="bold" if COLOR_ENABLED else None)
    table.add_column("RESULT")

    for key, value in rows:
        table.add_row(key, value)

    console.print(table)


def dashboard_demo() -> None:
    """Preview the visual system with explicitly labelled demo data."""
    header("dashboard", "VISUAL PREVIEW · SAMPLE DATA ONLY")

    section("SYSTEM STATUS")
    status("Terminal", f"{console.width} columns")
    status("Color output", "enabled" if COLOR_ENABLED else "plain-text fallback")
    status("Network", "not contacted")
    status("Mode", "visual preview; no evidence collected")

    section("AVAILABLE COMMANDS")
    commands = Table(box=box.SIMPLE, expand=True, width=min(console.width, 88))
    commands.add_column("COMMAND", style=f"bold {TEAL}" if COLOR_ENABLED else "bold")
    commands.add_column("PURPOSE")

    for command, purpose in [
        ("doctor", "Check environment and supported capabilities"),
        ("collect", "Collect selected local security artifacts"),
        ("baseline", "Create or compare file baselines"),
        ("analyze", "Analyze supported logs"),
        ("verify", "Check case integrity"),
        ("report", "Generate HTML and JSON reports"),
    ]:
        commands.add_row(f"kasevra {command}", purpose)

    console.print(commands)

    summary(
        "PREVIEW SUMMARY",
        [
            ("Interface", "Loaded"),
            ("Evidence collection", "Not run"),
            ("Integrity verification", "Not run"),
            ("Report generation", "Not run"),
        ],
    )


if __name__ == "__main__":
    dashboard_demo()
