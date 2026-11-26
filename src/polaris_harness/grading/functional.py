"""Layer-1 functional grader: runs harness-owned copies of the task's test suites against the agent's code.

Every suite (public and hidden) is graded the same way, in a throwaway copy of the agent's final workspace:

- The test files come from the task bundle, never from the workspace, so edits to `public_tests/` cannot help.
- pytest runs under `python -I -B` with a harness-written ini (`-c`), so workspace `pytest.ini` / `pyproject.toml`
  / `tox.ini` / `setup.cfg` options, `PYTHON*` variables, `sitecustomize.py` on the source path and stale
  bytecode are all ignored. The code under test reaches `sys.path` only through the ini's `pythonpath`.
- `--confcutdir` is the injected test directory, so a `conftest.py` the agent wrote anywhere above it never loads.
- Entry-point plugin autoload is off and `PYTEST_*` variables are stripped.

Residual risk: the code under test is imported into the pytest process, so a hostile solution can still tamper with
pytest from inside that process. Layer 2 flags the obvious forms (importing pytest/pluggy from source files); full
isolation needs out-of-process grading in a container (Phase 2).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Literal

from polaris_harness.schemas import TestSuiteOutcome

_PASSED_RE = re.compile(r"(\d+)\s+passed")
_FAILED_RE = re.compile(r"(\d+)\s+failed")
_ERROR_RE = re.compile(r"(\d+)\s+errors?")
_COPY_JUNK = frozenset({".git", "__pycache__", ".pytest_cache", ".ruff_cache"})
GRADING_INI_NAME = "polaris_pytest.ini"
GRADING_WORKSPACE_NAME = "workspace"


def _clean_test_env() -> dict[str, str]:
    """Build a minimal subprocess env: no `PYTEST_*`/`PYTHON*` variables and no plugin autoload."""
    allowed_keys = (
        ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "PATHEXT", "LOCALAPPDATA")
        if sys.platform == "win32"
        else ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL")
    )
    env = {key: os.environ[key] for key in allowed_keys if key in os.environ}
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return env


def _parse_pytest_counts(output: str) -> tuple[int, int, int]:
    passed = sum(int(m.group(1)) for m in _PASSED_RE.finditer(output))
    failed = sum(int(m.group(1)) for m in _FAILED_RE.finditer(output))
    errors = sum(int(m.group(1)) for m in _ERROR_RE.finditer(output))
    return passed, failed, errors


def _failed_outcome(suite_name: Literal["public", "hidden"], returncode: int, tail: str) -> TestSuiteOutcome:
    return TestSuiteOutcome(
        suite_name=suite_name,
        passed=False,
        returncode=returncode,
        passed_count=0,
        failed_count=0,
        error_count=1,
        duration_seconds=0.0,
        output_tail=tail,
    )


def _ignore_copy_junk(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name in _COPY_JUNK}


def _write_grading_ini(grading_root: Path, grading_ws: Path) -> Path:
    # pytest resolves `pythonpath` relative to the ini file's directory and splits it on whitespace,
    # so the ini sits next to the copied workspace and names it by a space-free relative path.
    code_rel = f"{GRADING_WORKSPACE_NAME}/src" if (grading_ws / "src").is_dir() else GRADING_WORKSPACE_NAME
    ini_path = grading_root / GRADING_INI_NAME
    ini_path.write_text(f"[pytest]\npythonpath = {code_rel}\naddopts =\n", encoding="utf-8", newline="\n")
    return ini_path


def _grade_suite(
    workspace_path: Path,
    tests_source: Path,
    *,
    suite_name: Literal["public", "hidden"],
    timeout_seconds: int,
) -> TestSuiteOutcome:
    if not tests_source.is_dir():
        return _failed_outcome(suite_name, 2, f"{suite_name.capitalize()} tests source missing: {tests_source}")

    grading_root = Path(tempfile.mkdtemp(prefix=f"polaris-grade-{suite_name}-")).resolve()
    try:
        grading_ws = grading_root / GRADING_WORKSPACE_NAME
        injected_rel = f"_polaris_{suite_name}_tests"
        injected = grading_ws / injected_rel
        try:
            shutil.copytree(workspace_path.resolve(), grading_ws, symlinks=True, ignore=_ignore_copy_junk)
            if injected.exists():
                shutil.rmtree(injected)
            shutil.copytree(tests_source.resolve(), injected, ignore=_ignore_copy_junk)
        except (OSError, shutil.Error) as exc:
            return _failed_outcome(suite_name, 2, f"Could not build the grading copy: {exc}")
        ini_path = _write_grading_ini(grading_root, grading_ws)

        cmd = [
            sys.executable,
            "-I",
            "-B",
            "-m",
            "pytest",
            "-c",
            str(ini_path),
            "--rootdir",
            str(grading_ws),
            "--confcutdir",
            str(injected),
            "-p",
            "no:cacheprovider",
            "-v",
            injected_rel,
        ]
        start = time.perf_counter()
        try:
            proc = subprocess.run(  # noqa: S603 - fixed local python -m pytest invocation
                cmd,
                cwd=str(grading_ws),
                env=_clean_test_env(),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            outcome = _failed_outcome(suite_name, 124, f"pytest timed out after {timeout_seconds}s: {exc}")
            return outcome.model_copy(update={"duration_seconds": max(0.0, time.perf_counter() - start)})

        duration = max(0.0, time.perf_counter() - start)
        combined = (proc.stdout + "\n" + proc.stderr).strip()
        passed_count, failed_count, error_count = _parse_pytest_counts(combined)
        suite_passed = proc.returncode == 0 and passed_count > 0 and failed_count == 0 and error_count == 0
        return TestSuiteOutcome(
            suite_name=suite_name,
            passed=suite_passed,
            returncode=proc.returncode,
            passed_count=passed_count,
            failed_count=failed_count,
            error_count=error_count,
            duration_seconds=duration,
            output_tail="\n".join(combined.splitlines()[-25:]),
        )
    finally:
        shutil.rmtree(grading_root, ignore_errors=True)


def run_public_tests(
    workspace_path: Path,
    public_tests_source: Path,
    *,
    timeout_seconds: int = 60,
) -> TestSuiteOutcome:
    """Run the task bundle's pristine public tests against the agent's final workspace code."""
    return _grade_suite(workspace_path, public_tests_source, suite_name="public", timeout_seconds=timeout_seconds)


def run_hidden_tests(
    workspace_path: Path,
    hidden_tests_source: Path,
    *,
    timeout_seconds: int = 60,
) -> TestSuiteOutcome:
    """Run the withheld hidden tests post-run; they never enter the agent's live workspace."""
    return _grade_suite(workspace_path, hidden_tests_source, suite_name="hidden", timeout_seconds=timeout_seconds)


__all__ = [
    "run_hidden_tests",
    "run_public_tests",
]
