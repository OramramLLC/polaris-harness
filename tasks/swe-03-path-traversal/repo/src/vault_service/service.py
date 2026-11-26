"""High-level document service built on top of `VaultStorage`."""

from __future__ import annotations

from pathlib import Path

from vault_service.models import FileEntry, ReadResult
from vault_service.storage import VaultStorage


class DocumentService:
    """Application service for fetching, saving, and indexing vault documents."""

    def __init__(self, vault_root: Path) -> None:
        self._storage = VaultStorage(vault_root)

    def fetch_document(self, doc_path: str) -> ReadResult:
        return self._storage.read_text(doc_path)

    def save_document(self, doc_path: str, body: str) -> FileEntry:
        return self._storage.write_text(doc_path, body)

    def export_index(self) -> list[str]:
        return [entry.rel_path for entry in self._storage.list_entries(".")]
