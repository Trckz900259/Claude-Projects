"""
Typed exceptions for the platform.

Using specific exception classes (instead of bare `Exception`) lets the rest of
the code react precisely — e.g. the orchestrator can catch an OutOfScopeError on
a single candidate, log it, and keep going, without aborting the whole run.
"""

from __future__ import annotations


class BBPlatformError(Exception):
    """Base class for every error this platform raises on purpose."""


class ConfigError(BBPlatformError):
    """A program config file is missing, malformed, or fails validation."""


class OutOfScopeError(BBPlatformError):
    """
    Raised the instant something tries to touch a target that is NOT on the
    program's allow-list. This is the hard refusal required by the safety rules.
    It should never be 'handled away' silently — at most, logged and skipped.
    """

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"OUT OF SCOPE — refusing to touch {target!r}: {reason}")


class ScanningNotPermittedError(BBPlatformError):
    """
    Raised when a module would run an automated scan but the active program's
    config has `automated_scanning_allowed: false`. Respecting program rules.
    """

    def __init__(self, program: str, action: str) -> None:
        self.program = program
        self.action = action
        super().__init__(
            f"Automated scanning is DISABLED for program {program!r}; "
            f"refusing to perform: {action}"
        )


class ToolNotAvailableError(BBPlatformError):
    """An external CLI tool (e.g. subfinder, dalfox) was requested but not found."""

    def __init__(self, tool: str, install_hint: str = "") -> None:
        self.tool = tool
        self.install_hint = install_hint
        msg = f"Required external tool {tool!r} was not found on PATH."
        if install_hint:
            msg += f" Install hint: {install_hint}"
        super().__init__(msg)
