"""Typed exceptions used by KASEVRA."""


class KasevraError(Exception):
    """Base exception for expected, user-facing KASEVRA errors."""


class ConfigurationError(KasevraError):
    """Raised when configuration is invalid or unusable."""


class OperationError(KasevraError):
    """Raised when an operation cannot be completed safely."""


class IntegrityError(KasevraError):
    """Raised when an integrity check detects a problem."""


class SafetyError(KasevraError):
    """Raised when a requested action violates a safety constraint."""
