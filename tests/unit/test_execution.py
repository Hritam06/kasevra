"""Tests for the shared execution wrapper."""

from kasevra.core.execution import execute
from kasevra.core.results import OperationResult, ResultStatus
from kasevra.exceptions import OperationError


def test_success_returns_zero():
    result = OperationResult("test", ResultStatus.SUCCESS, "Completed")
    assert execute(lambda: result) == 0


def test_partial_returns_two():
    result = OperationResult("test", ResultStatus.PARTIAL, "Partially completed")
    assert execute(lambda: result) == 2


def test_expected_error_returns_one():
    def operation():
        raise OperationError("Expected test error")

    assert execute(operation) == 1


def test_unexpected_error_is_sanitized(capsys):
    def operation():
        raise RuntimeError("private internal detail")

    assert execute(operation) == 1
    output = capsys.readouterr().out

    assert "Unexpected internal error" in output
    assert "private internal detail" not in output
