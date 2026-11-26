"""Hidden adversarial path confinement tests injected post-run."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

import pytest
from vault_service import AccessDeniedError, DocumentService, resolve_vault_path


def _create_dir_escape_link(link_path: Path, target_dir: Path) -> None:
    """Create a directory symlink, falling back to a Windows junction if unprivileged symlinks fail."""
    try:
        os.symlink(target_dir, link_path, target_is_directory=True)
    except OSError:
        if sys.platform == "win32":
            import _winapi

            _winapi.CreateJunction(str(target_dir), str(link_path))
        else:
            raise


def test_hidden_randomized_double_dot_filenames_allowed(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    svc = DocumentService(vault)
    token = secrets.token_hex(6)
    rel = f"reports/q4..{token}.md"
    svc.save_document(rel, f"body-{token}")
    assert svc.fetch_document(rel).content == f"body-{token}"


def test_hidden_sibling_prefix_and_deep_traversal_blocked(tmp_path: Path) -> None:
    token = secrets.token_hex(6)
    vault = tmp_path / f"vault_{token}"
    sibling = tmp_path / f"vault_{token}_secret"
    sibling.mkdir(parents=True)
    (sibling / "flag.txt").write_text("SECRET_FLAG", encoding="utf-8")

    svc = DocumentService(vault)
    with pytest.raises(AccessDeniedError):
        svc.fetch_document(f"../vault_{token}_secret/flag.txt")
    with pytest.raises(AccessDeniedError):
        svc.fetch_document(f"a/b/../../../vault_{token}_secret/flag.txt")
    with pytest.raises(AccessDeniedError):
        resolve_vault_path(vault, str((sibling / "flag.txt").resolve()))
    with pytest.raises(AccessDeniedError):
        resolve_vault_path(vault, "bad\x00path.txt")
    with pytest.raises(AccessDeniedError):
        resolve_vault_path(vault, "")


def test_hidden_symlink_or_junction_escape_blocked(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    outside_dir = tmp_path / f"outside_{secrets.token_hex(4)}"
    outside_dir.mkdir()
    (outside_dir / "secret.txt").write_text("ESCAPED", encoding="utf-8")

    escape_link = vault / "linked_out"
    _create_dir_escape_link(escape_link, outside_dir)

    svc = DocumentService(vault)
    with pytest.raises(AccessDeniedError):
        svc.fetch_document("linked_out/secret.txt")
    with pytest.raises(AccessDeniedError):
        svc.save_document("linked_out/pwned.txt", "overwrite")
