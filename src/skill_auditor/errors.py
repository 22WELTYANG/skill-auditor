"""Controlled user-facing errors shared across command layers."""


class ScanError(ValueError):
    """A scan or command error that maps to the stable exit code 3."""
