"""Vault service package."""

from vault_service.models import AccessDeniedError, FileEntry, ReadResult, VaultError
from vault_service.paths import resolve_vault_path
from vault_service.service import DocumentService
from vault_service.storage import VaultStorage

__all__ = [
    "AccessDeniedError",
    "DocumentService",
    "FileEntry",
    "ReadResult",
    "VaultError",
    "VaultStorage",
    "resolve_vault_path",
]
