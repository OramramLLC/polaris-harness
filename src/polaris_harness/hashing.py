"""Deterministic workspace file snapshots shared by the sandbox and the anti-reward-hack grader.

Locked-path patterns are matched by this module rather than `Path.glob`, whose handling of a trailing `**`
differs across Python versions (3.12 returns only directories; 3.13+ also returns files).
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

_SKIP_DIR_NAMES = frozenset({"__pycache__", ".pytest_cache", ".ruff_cache"})
_GLOB_CHARS = frozenset("*?")
LINK_DIGEST_PREFIX = "link:"


def _is_link(path: Path) -> bool:
    return path.is_symlink() or os.path.isjunction(path)


def iter_workspace_files(workspace_path: Path) -> dict[str, Path]:
    """Map workspace-relative POSIX paths to files, without following symlinks or junctions.

    Skips the root `.git` worktree pointer and cache directories. A symlink or junction (to a file or a directory)
    is listed as a single entry and never descended into.
    """
    ws = workspace_path.resolve()
    found: dict[str, Path] = {}
    for dirpath, dirnames, filenames in os.walk(ws, followlinks=False):
        current = Path(dirpath)
        at_root = current == ws
        keep: list[str] = []
        for name in dirnames:
            entry = current / name
            if (at_root and name == ".git") or name in _SKIP_DIR_NAMES:
                continue
            if _is_link(entry):
                found[entry.relative_to(ws).as_posix()] = entry
                continue
            keep.append(name)
        dirnames[:] = sorted(keep)
        for name in filenames:
            if at_root and name == ".git":
                continue
            entry = current / name
            found[entry.relative_to(ws).as_posix()] = entry
    return dict(sorted(found.items()))


def file_digest(path: Path) -> str:
    """SHA-256 of a file's bytes; a symlink/junction hashes its target string so swapping a file for a link shows."""
    try:
        if _is_link(path):
            target = os.readlink(path)
            return LINK_DIGEST_PREFIX + hashlib.sha256(os.fsencode(target)).hexdigest()
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        return f"unreadable:{type(exc).__name__}"


def snapshot_tree(workspace_path: Path) -> dict[str, str]:
    """Digest every workspace file (see `iter_workspace_files`)."""
    return {rel: file_digest(path) for rel, path in iter_workspace_files(workspace_path).items()}


def _normalize_pattern(pattern: str) -> str:
    norm = pattern.replace("\\", "/").strip()
    while norm.startswith("./"):
        norm = norm[2:]
    return norm.strip("/")


def compile_locked_pattern(pattern: str) -> re.Pattern[str] | None:
    """Compile one `locked_paths` entry into a full-match regex over workspace-relative POSIX paths.

    - No `*`/`?`: matches that exact file, or everything below it when it names a directory.
    - `*` and `?` match within one path segment; a `**` segment matches zero or more whole segments.
    Returns None for an empty pattern.
    """
    norm = _normalize_pattern(pattern)
    if not norm:
        return None
    if not _GLOB_CHARS.intersection(norm):
        escaped = re.escape(norm)
        return re.compile(f"{escaped}(?:/.*)?")

    segments = norm.split("/")
    parts: list[str] = []
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "**":
            parts.append(".+" if last else "(?:[^/]+/)*")
            continue
        parts.append("".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in segment))
        if not last:
            parts.append("/")
    return re.compile("".join(parts))


def select_locked(tree: Mapping[str, str], locked_paths: Sequence[str]) -> dict[str, str]:
    """Return the subset of a `snapshot_tree` result matched by any `locked_paths` pattern."""
    compiled = [p for p in (compile_locked_pattern(raw) for raw in locked_paths) if p is not None]
    return {rel: digest for rel, digest in sorted(tree.items()) if any(p.fullmatch(rel) for p in compiled)}


def snapshot_locked(workspace_path: Path, locked_paths: Sequence[str]) -> dict[str, str]:
    """Digest every workspace file matched by `locked_paths`."""
    return select_locked(snapshot_tree(workspace_path), locked_paths)


__all__ = [
    "LINK_DIGEST_PREFIX",
    "compile_locked_pattern",
    "file_digest",
    "iter_workspace_files",
    "select_locked",
    "snapshot_locked",
    "snapshot_tree",
]
