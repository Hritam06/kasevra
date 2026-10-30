"""Structured results shared by KASEVRA commands."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ResultStatus(StrEnum):
    """Outcome of a command or individual operation."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"


@dataclass(frozen=True, slots=True)
class OperationResult:
    """Describe an operation outcome without implying unperformed work succeeded."""

    name: str
    status: ResultStatus
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Result name must not be empty.")
        if not self.message.strip():
            raise ValueError("Result message must not be empty.")

    @property
    def succeeded(self) -> bool:
        """Return true only for a fully successful operation."""
        return self.status is ResultStatus.SUCCESS

    @property
    def exit_code(self) -> int:
        """Map the result to a conventional process exit code."""
        if self.status is ResultStatus.SUCCESS:
            return 0
        if self.status is ResultStatus.PARTIAL:
            return 2
        return 1
