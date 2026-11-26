"""Repository setup invariants: the pinned Mellyn core and the hash-locked dependency files."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PIN_FILE = REPO_ROOT / "deploy" / "mellyn-core-pin.txt"
LOCK_FILES = sorted((REPO_ROOT / "deploy").glob("requirements-*.lock"))
_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][0-9A-Za-z.!+-]*) \\$")
_HASH_RE = re.compile(r"^    --hash=sha256:[0-9a-f]{64}( \\)?$")


def _pin() -> str:
    return PIN_FILE.read_text(encoding="utf-8").strip()


def test_core_pin_is_a_full_commit_sha() -> None:
    assert PIN_FILE.read_text(encoding="utf-8").count("\n") == 1
    assert re.fullmatch(r"[0-9a-f]{40}", _pin())


def test_expected_lock_files_exist() -> None:
    assert [p.name for p in LOCK_FILES] == [
        "requirements-build.lock",
        "requirements-lint.lock",
        "requirements-tests.lock",
    ]


@pytest.mark.parametrize("lock", LOCK_FILES, ids=lambda p: p.name)
def test_lock_pins_exact_versions_with_hashes(lock: Path) -> None:
    lines = [line for line in lock.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
    requirements = 0
    index = 0
    while index < len(lines):
        assert _REQ_RE.match(lines[index]), f"{lock.name}: not an exact `name==version \\` line: {lines[index]!r}"
        requirements += 1
        index += 1
        hashes = 0
        while index < len(lines) and lines[index].startswith("    --hash="):
            assert _HASH_RE.match(lines[index]), f"{lock.name}: malformed hash line: {lines[index]!r}"
            hashes += 1
            last = not lines[index].endswith("\\")
            index += 1
            if last:
                break
        assert hashes >= 1, f"{lock.name}: requirement without hashes"
    assert requirements >= 1


def test_local_core_checkout_matches_pin() -> None:
    core = REPO_ROOT / "core"
    git = shutil.which("git")
    if not (core / ".git").exists() or git is None:
        pytest.skip("no local core/ checkout")
    head = subprocess.run(  # noqa: S603 - fixed local git binary with explicit argv
        [git, "-C", str(core), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert head == _pin(), "core/ is not checked out at deploy/mellyn-core-pin.txt"
