"""Tests for structured operation results."""

import pytest

from kasevra.core.results import OperationResult, ResultStatus


@pytest.mark.parametrize(
    ("status", "expected_exit", "expected_success"),
    [
        (ResultStatus.SUCCESS, 0, True),
        (ResultStatus.PARTIAL, 2, False),
        (ResultStatus.FAILURE, 1, False),
    ],
)
def test_result_status_contract(status, expected_exit, expected_success):
    result = OperationResult("test", status, "Test outcome")

    assert result.exit_code == expected_exit
    assert result.succeeded is expected_success


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("", "Valid message"),
        ("test", ""),
    ],
)
def test_result_rejects_empty_required_fields(name, message):
    with pytest.raises(ValueError):
        OperationResult(name, ResultStatus.SUCCESS, message)
