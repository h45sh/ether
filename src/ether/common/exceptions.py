"""Root domain exceptions and taxonomy enums for Ether."""

from enum import Enum


class ExecutionErrorCategory(str, Enum):
    """Standardized taxonomy of execution error categories for supervisor diagnostics."""

    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
    BINARY_MISSING = "BINARY_MISSING"
    NON_ZERO_EXIT = "NON_ZERO_EXIT"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"


class EtherError(Exception):
    """Base exception for all domain errors raised by the Ether engine."""

    pass


class PolicyViolationError(EtherError):
    """Raised when an operation violates security policy boundaries (e.g. SSRF, metadata access)."""

    pass
