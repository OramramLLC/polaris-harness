"""Domain models and exceptions for vault_service."""

from __future__ import annotations

from dataclasses import dataclass


class VaultError(Exception):
    """Base error for vault operations."""


class AccessDeniedError(VaultError):
    """Raised when a requested path violates vault confinement."""


@dataclass(frozen=True)
class FileEntry:
    """Metadata for a file stored in the vault."""

    rel_path: str
    size_bytes: int


@dataclass(frozen=True)
class ReadResult:
    """Contents and normalized path for a vault read."""

    rel_path: str
    content: str
    size_bytes: int
