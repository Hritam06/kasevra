"""Responsive KASEVRA terminal dashboard."""

import os
import platform
import sys
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version

from rich import box
from rich.align import Align
from rich.columns import Columns
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


def _style(color: str) -> str | None:
    return color if COLOR_ENABLED else None


def _version() -> str:
    try:
        return version("kasevra")
    except PackageNotFoundError:
        return "unknown"


def header(command: str = "dashboard", subtitle: str = "") -> None:
    """Render the centered KASEVRA wordmark and command context."""
    width = min(console.width, 150)

    font = {
        "K": ("█   █", "█  █ ", "███  ", "█  █ ", "█   █"),
        "A": (" ███ ", "█   █", "█████", "█   █", "█   █"),
        "S": (" ████", "█    ", " ███ ", "    █", "████ "),
        "E": ("█████", "█    ", "████ ", "█    ", "█████"),
        "V": ("█   █", "█   █", "█   █", " █ █ ", "  █  "),
        "R": ("████ ", "█   █", "████ ", "█  █ ", "█   █"),
    }
    wordmark = "\n".join(
        "  ".join(font[letter][row] for letter in APP_NAME) for row in range(5)
    )

    brand = Text(justify="center")
    brand.append(
        wordmark + "\n\n", style=f"bold {_style(TEAL)}" if COLOR_ENABLED else "bold"
    )
    brand.append(
        "────  " + PRODUCT_DESCRIPTION.upper() + "  ────\n\n",
        style=f"bold {_style(TEAL)}" if COLOR_ENABLED else "bold",
    )
    brand.append(
        "///   " + TAGLINE + "   ///",
        style=f"italic {_style(TEAL)}" if COLOR_ENABLED else "italic",
    )

    console.print()
    console.print(
        Align.center(
            Panel(
                Align.center(brand),
                width=width,
                border_style=_style(TEAL) or "white",
                box=box.HEAVY,
                padding=(1, 2),
            ),
            width=console.width,
        )
    )

    details = Text()
    details.append(
        "COMMAND  ", style=f"bold {_style(TEAL)}" if COLOR_ENABLED else "bold"
    )
    details.append(f"kasevra {command}    ")
    details.append("TIME  ", style=f"bold {_style(TEAL)}" if COLOR_ENABLED else "bold")
    details.append(datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"))
    console.print(Align.center(details, width=width))
    if subtitle:
        console.print(
            Align.center(Text(subtitle, style=_style(AMBER) or ""), width=width)
        )
    console.print()


def section(title: str) -> None:
    """Print a consistent section heading."""
    console.rule(
        f"[bold {TEAL}]{title}[/]" if COLOR_ENABLED else title,
        style=_style(TEAL),
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
    table = Table(box=box.SIMPLE, expand=True, width=min(console.width, 100))
    table.add_column("ITEM", style="bold" if COLOR_ENABLED else None)
    table.add_column("RESULT")
    for key, value in rows:
        table.add_row(key, value)
    console.print(table)


def _card(title: str, lines: list[tuple[str, str]], note: str = "") -> Panel:
    """Build a compact dashboard panel."""
    body = Table.grid(padding=(0, 1))
    body.add_column(style=f"bold {_style(TEAL)}" if COLOR_ENABLED else "bold")
    body.add_column(ratio=1)

    for label, value in lines:
        body.add_row(label, value)

    if note:
        body.add_row("", Text(note, style=_style(AMBER) or ""))

    return Panel(
        body,
        title=f"[bold {TEAL}]{title}[/]" if COLOR_ENABLED else title,
        title_align="left",
        border_style=_style(TEAL) or "white",
        box=box.ROUNDED,
        padding=(0, 1),
    )


def _render_cards(cards: list[Panel]) -> None:
    """Adapt panel columns to the available terminal width."""
    width = console.width
    columns = 3 if width >= 145 else 2 if width >= 88 else 1
    for start in range(0, len(cards), columns):
        console.print(
            Columns(
                cards[start : start + columns],
                equal=True,
                expand=True,
                padding=(0, 1),
            )
        )


def dashboard_demo() -> None:
    """Preview the complete visual system using clearly labelled sample data."""
    header("dashboard", "VISUAL PREVIEW · SAMPLE DATA ONLY · NO EVIDENCE COLLECTED")

    section("COMMAND CENTER")

    overview = [
        _card(
            "AVAILABLE COMMANDS",
            [
                ("doctor", "Check environment readiness"),
                ("collect", "Copy files and create SHA-256 manifest"),
                ("baseline", "Create a reference baseline"),
                ("analyze", "Compare manifest against baseline"),
                ("verify", "Verify collected evidence"),
                ("report", "Generate JSON or HTML report"),
            ],
        ),
        _card(
            "SYSTEM STATUS",
            [
                ("KASEVRA", f"v{_version()}"),
                ("Python", platform.python_version()),
                ("Platform", f"{platform.system()} ({platform.machine()})"),
                ("Terminal", f"{console.width} columns"),
                ("Color", "Enabled" if COLOR_ENABLED else "Plain-text fallback"),
                ("Network", "Not contacted"),
            ],
        ),
        _card(
            "QUICK START",
            [
                ("01", "kasevra doctor"),
                ("02", "kasevra collect SOURCE DESTINATION"),
                ("03", "kasevra baseline MANIFEST OUTPUT"),
                ("04", "kasevra analyze BASELINE MANIFEST"),
                ("05", "kasevra verify COLLECTION"),
                ("06", "kasevra report COLLECTION --output REPORT.html --format html"),
            ],
            "Replace placeholders with your actual paths.",
        ),
    ]
    _render_cards(overview)

    section("EVIDENCE WORKFLOW")

    workflow = [
        _card(
            "01 · SYSTEM DIAGNOSTIC",
            [
                ("Command", "kasevra doctor"),
                ("Purpose", "Check Python, platform and runtime"),
                ("Preview", "Not run"),
            ],
        ),
        _card(
            "02 · EVIDENCE COLLECTION",
            [
                ("Command", "kasevra collect SOURCE DESTINATION"),
                ("Purpose", "Copy selected files and hash contents"),
                ("Evidence collection", "Not run"),
            ],
        ),
        _card(
            "03 · EVIDENCE ANALYSIS",
            [
                ("Command", "kasevra analyze BASELINE MANIFEST"),
                ("Purpose", "Compare collection with reference"),
                ("Analysis", "Not run"),
            ],
        ),
        _card(
            "04 · INTEGRITY VERIFICATION",
            [
                ("Command", "kasevra verify COLLECTION"),
                ("Purpose", "Recalculate and compare SHA-256 hashes"),
                ("Verification", "Not run"),
            ],
        ),
        _card(
            "05 · REPORT GENERATION",
            [
                (
                    "Command",
                    "kasevra report COLLECTION --output REPORT.html --format html",
                ),
                ("Purpose", "Generate an investigation report"),
                ("Report", "Not generated"),
            ],
        ),
        _card(
            "06 · HELP & EXAMPLES",
            [
                ("Help", "kasevra --help"),
                ("Command help", "kasevra COMMAND --help"),
                ("Dashboard", "kasevra dashboard"),
                ("Preview", "Sample data only"),
            ],
        ),
    ]
    _render_cards(workflow)

    console.print()
    console.print(
        Align.center(
            Text(
                "KASEVRA  ·  DIGITAL EVIDENCE & INTEGRITY TOOLKIT",
                style=f"bold {_style(TEAL)}" if COLOR_ENABLED else "bold",
            )
        )
    )
    console.print(
        Align.center(
            Text(
                "Collect with care. Verify with confidence.",
                style=f"italic {_style(TEAL)}" if COLOR_ENABLED else "italic",
            )
        )
    )
    console.print(
        Align.center(
            Text(
                "VISUAL PREVIEW · SAMPLE DATA ONLY · NETWORK NOT CONTACTED",
                style=_style(AMBER) or "",
            )
        )
    )


if __name__ == "__main__":
    dashboard_demo()
