"""Root domain exceptions for Ether."""


class EtherError(Exception):
    """Base exception for all domain errors raised by the Ether engine."""

    pass


class PolicyViolationError(EtherError):
    """Raised when an operation violates security policy boundaries (e.g. SSRF, metadata access)."""

    pass

