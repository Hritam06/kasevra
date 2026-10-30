"""Local environment diagnostics for KASEVRA."""

import platform
import sys
from importlib.metadata import PackageNotFoundError, version

from kasevra.core.output import console
from kasevra.core.results import OperationResult, ResultStatus
from kasevra.ui.branding import APP_NAME, TEAL


def run_doctor() -> OperationResult:
    """Inspect basic local runtime information without modifying the system."""
    python_supported = sys.version_info >= (3, 11)
    os_name = platform.system() or "Unknown"
    architecture = platform.machine() or "Unknown"

    checks: list[tuple[str, bool, str]] = [
        (
            "Python",
            python_supported,
            f"{platform.python_version()} "
            f"({'supported' if python_supported else 'requires 3.11+'})",
        ),
        ("Operating system", os_name != "Unknown", os_name),
        ("Architecture", architecture != "Unknown", architecture),
    ]

    try:
        installed_version = version("kasevra")
        checks.append(("Package metadata", True, f"{APP_NAME} {installed_version}"))
    except PackageNotFoundError:
        checks.append(("Package metadata", False, "KASEVRA package metadata not found"))

    console.print(f"\n[bold {TEAL}]KASEVRA DOCTOR[/bold {TEAL}]")
    console.print(
        "Local environment checks only. No evidence collected; no network used.\n"
    )

    warnings = 0
    for label, passed, detail in checks:
        if passed:
            console.print(f"[green][OK][/green]   {label}: {detail}")
        else:
            warnings += 1
            console.print(f"[yellow][WARN][/yellow] {label}: {detail}")

    status = ResultStatus.PARTIAL if warnings else ResultStatus.SUCCESS
    message = (
        f"Completed {len(checks)} checks with {warnings} warning(s)."
        if warnings
        else f"All {len(checks)} environment checks passed."
    )

    return OperationResult(
        name="Doctor",
        status=status,
        message=message,
        details={"checks": len(checks), "warnings": warnings},
    )
