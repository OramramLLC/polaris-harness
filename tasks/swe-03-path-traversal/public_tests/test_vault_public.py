"""Public tests for vault_service."""

from __future__ import annotations

from pathlib import Path

import pytest
from vault_service import AccessDeniedError, DocumentService


def test_read_and_write_valid_documents_including_double_dots(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    svc = DocumentService(vault)
    entry = svc.save_document("notes..v2.txt", "release notes")
    assert entry.rel_path == "notes..v2.txt"

    loaded = svc.fetch_document("notes..v2.txt")
    assert loaded.content == "release notes"
    assert svc.export_index() == ["notes..v2.txt"]


def test_blocks_parent_traversal_escape(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    outside = tmp_path / "outside.txt"
    outside.write_text("top-secret", encoding="utf-8")

    svc = DocumentService(vault)
    with pytest.raises(AccessDeniedError):
        svc.fetch_document("../outside.txt")
