"""Shared output helpers for KASEVRA commands."""

from rich.console import Console

from kasevra.core.results import OperationResult, ResultStatus
from kasevra.ui.dashboard import COLOR_ENABLED, status

console = Console(
    highlight=False,
    soft_wrap=True,
    color_system="auto" if COLOR_ENABLED else None,
)


def print_info(label: str, message: str) -> None:
    """Print an informational status."""
    status(label, message, "INFO")


def print_success(label: str, message: str) -> None:
    """Print a successful status."""
    status(label, message, "OK")


def print_warning(label: str, message: str) -> None:
    """Print a warning status."""
    status(label, message, "WARN")


def print_failure(label: str, message: str) -> None:
    """Print a failure status."""
    status(label, message, "FAIL")


def render_result(result: OperationResult) -> int:
    """Render an operation result and return its process exit code."""
    if result.status is ResultStatus.SUCCESS:
        print_success(result.name, result.message)
    elif result.status is ResultStatus.PARTIAL:
        print_warning(result.name, result.message)
    else:
        print_failure(result.name, result.message)

    return result.exit_code
