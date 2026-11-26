"""Path confinement helpers for vault_service."""

from __future__ import annotations

import os
from pathlib import Path

from vault_service.models import AccessDeniedError


def resolve_vault_path(root: Path, rel_path: str) -> Path:
    """
    Resolve `rel_path` inside `root` safely.

    Valid filenames containing `..` (e.g., `notes..v2.txt`, `reports/q4..final.md`)
    MUST be allowed. Empty paths, NUL bytes, absolute paths, `../` escapes,
    sibling-prefix escapes (`<root>_secret`), and symlinks/junctions pointing
    outside `root` MUST raise `AccessDeniedError`.
    """
    if not isinstance(rel_path, str) or not rel_path.strip():
        raise AccessDeniedError("Path cannot be empty.")

    # BUG: Naive string prefix check after os.path.normpath does not follow symlinks,
    # fails to reject sibling-prefix directories (<root>_secret), and misses some escapes.
    cleaned = rel_path.replace("\\", "/")
    if os.path.isabs(cleaned):
        raise AccessDeniedError(f"Absolute path denied: {rel_path!r}")

    normed = os.path.normpath(os.path.join(str(root), cleaned))
    if not normed.startswith(str(root)):
        raise AccessDeniedError(f"Path escapes vault root: {rel_path!r}")
    return Path(normed)
