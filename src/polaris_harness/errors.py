"""Shared harness exceptions."""

from __future__ import annotations


class MellynUnavailableError(RuntimeError):
    """Raised fail-closed when `mellyn.airlock` or `mellyn.ir_lab` cannot be imported."""


__all__ = ["MellynUnavailableError"]
