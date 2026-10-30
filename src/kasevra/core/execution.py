"""Shared execution wrapper for KASEVRA operations."""

from collections.abc import Callable
from typing import TypeVar

from kasevra.core.output import print_failure, render_result
from kasevra.core.results import OperationResult
from kasevra.exceptions import KasevraError

T = TypeVar("T")


def execute(
    operation: Callable[[], OperationResult],
) -> int:
    """Run an operation and return its documented process exit code.

    Expected KASEVRA errors are reported without exposing a traceback.
    Unexpected programming errors are reported generically, without
    displaying potentially sensitive exception details.
    """
    try:
        result = operation()
    except KasevraError as exc:
        print_failure("Operation", str(exc))
        return 1
    except Exception:
        print_failure(
            "Operation",
            "Unexpected internal error. No successful result was recorded.",
        )
        return 1

    return render_result(result)
