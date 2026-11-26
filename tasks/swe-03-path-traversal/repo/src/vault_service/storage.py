"""Low-level filesystem storage operations confined by `resolve_vault_path`."""

from __future__ import annotations

from pathlib import Path

from vault_service.models import FileEntry, ReadResult, VaultError
from vault_service.paths import resolve_vault_path


class VaultStorage:
    """Confinement-enforcing file store rooted at `root`."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        return self._root

    def stat_entry(self, rel_path: str) -> FileEntry:
        target = resolve_vault_path(self._root, rel_path)
        if not target.is_file():
            raise VaultError(f"File not found: {rel_path!r}")
        rel = target.relative_to(self._root).as_posix()
        return FileEntry(rel_path=rel, size_bytes=target.stat().st_size)

    def read_text(self, rel_path: str) -> ReadResult:
        target = resolve_vault_path(self._root, rel_path)
        if not target.is_file():
            raise VaultError(f"File not found: {rel_path!r}")
        content = target.read_text(encoding="utf-8")
        rel = target.relative_to(self._root).as_posix()
        return ReadResult(rel_path=rel, content=content, size_bytes=len(content.encode("utf-8")))

    def write_text(self, rel_path: str, content: str) -> FileEntry:
        target = resolve_vault_path(self._root, rel_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
        rel = target.relative_to(self._root).as_posix()
        return FileEntry(rel_path=rel, size_bytes=target.stat().st_size)

    def list_entries(self, subdir: str = ".") -> list[FileEntry]:
        base = resolve_vault_path(self._root, subdir) if subdir != "." else self._root
        if not base.is_dir():
            raise VaultError(f"Directory not found: {subdir!r}")
        entries: list[FileEntry] = []
        for item in sorted(base.rglob("*")):
            if not item.is_file():
                continue
            resolved = item.resolve()
            if not resolved.is_relative_to(self._root):
                continue
            rel = resolved.relative_to(self._root).as_posix()
            entries.append(FileEntry(rel_path=rel, size_bytes=resolved.stat().st_size))
        return entries
