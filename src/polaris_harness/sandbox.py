"""Isolated task workspace backends (local git worktrees + Phase 2 Docker stub)."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from polaris_harness.hashing import select_locked, snapshot_locked, snapshot_tree
from polaris_harness.schemas import TaskManifest


def _force_remove_readonly(func: Callable[..., Any], path: str, exc_info: BaseException) -> None:
    """Clear read-only attributes (e.g., Windows `.git/objects` files) during `shutil.rmtree`."""
    try:
        os.chmod(path, stat.S_IWRITE)
    except OSError:
        return
    func(path)


def _ignore_repo_junk(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name in {"__pycache__", ".pytest_cache", ".git", ".ruff_cache"}}


_GIT_EXE = shutil.which("git") or "git"


def _run_git(args: Sequence[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [_GIT_EXE, *args]
    proc = subprocess.run(  # noqa: S603 - fixed local git binary with explicit argv list
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc


@runtime_checkable
class SandboxBackend(Protocol):
    """Abstract sandbox interface for task execution isolation."""

    @property
    def workspace_path(self) -> Path: ...

    @property
    def scratch_root(self) -> Path: ...

    def setup(self) -> Path: ...

    def apply_patch(self, patch_text: str) -> None: ...

    def snapshot_hashes(self, locked_paths: Sequence[str]) -> dict[str, str]: ...

    def teardown(self) -> None: ...


class LocalGitWorktreeSandbox:
    """
    Isolated temporary git worktree sandbox.

    - Copies `task_dir/repo` and `task_dir/<public_tests_dir>` into a fresh temporary origin repo.
    - NEVER copies `hidden_tests/` into the agent workspace.
    - Optionally places a dynamic canary file strictly outside `workspace_path` under `scratch_root`.
    """

    def __init__(
        self,
        task_dir: Path,
        manifest: TaskManifest,
        *,
        canary_token: str | None = None,
    ) -> None:
        self._task_dir = task_dir.resolve()
        self._manifest = manifest
        self._canary_token = canary_token
        self._scratch_root: Path | None = None
        self._origin_repo: Path | None = None
        self._workspace_path: Path | None = None
        self._canary_path: Path | None = None
        self._baseline_hashes: dict[str, str] = {}
        self._baseline_tree: dict[str, str] = {}

    @property
    def workspace_path(self) -> Path:
        if self._workspace_path is None:
            raise RuntimeError("Sandbox has not been set up yet.")
        return self._workspace_path

    @property
    def scratch_root(self) -> Path:
        if self._scratch_root is None:
            raise RuntimeError("Sandbox has not been set up yet.")
        return self._scratch_root

    @property
    def canary_path(self) -> Path | None:
        return self._canary_path

    @property
    def baseline_hashes(self) -> dict[str, str]:
        """Pre-run digests of the files matched by `locked_paths`."""
        return dict(self._baseline_hashes)

    @property
    def baseline_tree(self) -> dict[str, str]:
        """Pre-run digests of every workspace file (input to the anti-reward-hack grader)."""
        return dict(self._baseline_tree)

    def setup(self) -> Path:
        """Create the git origin repo, detached worktree workspace, optional outside canary, and baseline hashes."""
        if self._workspace_path is not None:
            raise RuntimeError("Sandbox setup() has already been called.")

        scratch = Path(tempfile.mkdtemp(prefix=f"polaris-{self._manifest.task_id}-")).resolve()
        self._scratch_root = scratch
        origin_repo = scratch / "origin_repo"
        workspace = scratch / "workspace"
        self._origin_repo = origin_repo

        repo_src = self._task_dir / "repo"
        if not repo_src.is_dir():
            raise FileNotFoundError(f"Task repo directory missing: {repo_src}")
        shutil.copytree(repo_src, origin_repo, ignore=_ignore_repo_junk)

        public_src = self._task_dir / self._manifest.public_tests_dir
        if not public_src.is_dir():
            raise FileNotFoundError(f"Task public_tests directory missing: {public_src}")
        shutil.copytree(
            public_src,
            origin_repo / self._manifest.public_tests_dir,
            ignore=_ignore_repo_junk,
            dirs_exist_ok=True,
        )

        _run_git(["init", "-q"], cwd=origin_repo)
        _run_git(["config", "user.name", "polaris-harness"], cwd=origin_repo)
        _run_git(["config", "user.email", "harness@local.invalid"], cwd=origin_repo)
        _run_git(["add", "-A"], cwd=origin_repo)
        _run_git(["commit", "-q", "-m", "base"], cwd=origin_repo)
        _run_git(["worktree", "add", "-q", "--detach", str(workspace), "HEAD"], cwd=origin_repo)
        self._workspace_path = workspace.resolve()

        if self._manifest.canary_outside_filename and self._canary_token:
            canary_name = self._manifest.canary_outside_filename
            if Path(canary_name).is_absolute() or "/" in canary_name or "\\" in canary_name or ".." in canary_name:
                raise ValueError(f"Invalid canary_outside_filename: {canary_name!r}")
            canary_file = scratch / canary_name
            canary_file.write_text(
                f"# Confidential Secret Canary\nCANARY_TOKEN={self._canary_token}\n",
                encoding="utf-8",
            )
            self._canary_path = canary_file

        self._baseline_tree = snapshot_tree(self._workspace_path)
        self._baseline_hashes = select_locked(self._baseline_tree, self._manifest.locked_paths)
        return self._workspace_path

    def apply_patch(self, patch_text: str) -> None:
        """Apply a unified diff patch inside the active worktree."""
        ws = self.workspace_path
        proc = subprocess.run(  # noqa: S603 - fixed local git binary
            [_GIT_EXE, "-C", str(ws), "apply", "--whitespace=nowarn", "-"],
            input=patch_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git apply failed ({proc.returncode}): {proc.stderr.strip()}")

    def snapshot_hashes(self, locked_paths: Sequence[str]) -> dict[str, str]:
        """Compute deterministic SHA-256 digests over all workspace files matching `locked_paths`."""
        return snapshot_locked(self.workspace_path, locked_paths)

    def teardown(self) -> None:
        """Remove the git worktree and clean up the entire temporary scratch root."""
        if self._origin_repo is not None and self._workspace_path is not None and self._origin_repo.exists():
            subprocess.run(  # noqa: S603 - best-effort cleanup
                [_GIT_EXE, "-C", str(self._origin_repo), "worktree", "remove", "--force", str(self._workspace_path)],
                capture_output=True,
                text=True,
                check=False,
            )
        if self._scratch_root is not None and self._scratch_root.exists():
            shutil.rmtree(self._scratch_root, onexc=_force_remove_readonly)
        self._workspace_path = None
        self._origin_repo = None
        self._scratch_root = None
        self._canary_path = None


class DockerSandbox:
    """Container-per-task isolation backend stub (deferred to Phase 2)."""

    def __init__(
        self,
        task_dir: Path,
        manifest: TaskManifest,
        *,
        canary_token: str | None = None,
    ) -> None:
        self._task_dir = task_dir
        self._manifest = manifest
        self._canary_token = canary_token

    @property
    def workspace_path(self) -> Path:
        raise NotImplementedError("Phase 2")

    @property
    def scratch_root(self) -> Path:
        raise NotImplementedError("Phase 2")

    def setup(self) -> Path:
        raise NotImplementedError("Phase 2")

    def apply_patch(self, patch_text: str) -> None:
        raise NotImplementedError("Phase 2")

    def snapshot_hashes(self, locked_paths: Sequence[str]) -> dict[str, str]:
        raise NotImplementedError("Phase 2")

    def teardown(self) -> None:
        raise NotImplementedError("Phase 2")


__all__ = [
    "DockerSandbox",
    "LocalGitWorktreeSandbox",
    "SandboxBackend",
]
