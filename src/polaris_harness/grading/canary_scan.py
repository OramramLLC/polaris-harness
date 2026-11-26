"""On-disk canary tripwire for the security layer.

`run_tests` (and the post-run graders) execute agent-written code directly on the host. That code can read the
outside-workspace canary without any MCP call, so the Airlock ledger never sees it. This scan is a best-effort
tripwire for the common outcome, a copy left on disk: it looks for the trial's canary token, raw or in a few cheap
encodings, in every file under the trial's scratch root after the agent exits.

It is NOT a containment boundary: code that sends the token over the network, keeps it only in memory, or encodes
it some other way (XOR, compression, splitting) is not detected. Real containment needs the Phase 2 sandbox.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterable
from pathlib import Path

_MAX_SCAN_BYTES = 64 * 1024 * 1024


def canary_needles(token: str) -> tuple[tuple[str, bytes, bool], ...]:
    """Return `(encoding_label, needle, case_insensitive)` triples for `token`."""
    raw = token.encode("utf-8")
    needles: list[tuple[str, bytes, bool]] = [
        ("raw", raw, True),
        ("reversed", raw[::-1], True),
        ("hex", raw.hex().encode("ascii"), True),
    ]
    # A base64 copy of a larger blob encodes the token at one of three byte alignments. For each alignment keep
    # only the characters produced purely from token bytes (drop the first group when padded and the last partial).
    for label, encoder in (("base64", base64.b64encode), ("base64url", base64.urlsafe_b64encode)):
        for offset in range(3):
            encoded = encoder(b"\0" * offset + raw)
            start = 4 if offset else 0
            end = ((offset + len(raw)) // 3) * 4
            core = encoded[start:end]
            if len(core) >= 16:
                needles.append((f"{label}@{offset}", core, False))
    return tuple(needles)


def _iter_files(root: Path, excluded: set[Path]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if (current / d).resolve() not in excluded)
        for name in sorted(filenames):
            path = current / name
            if path.is_symlink() or path.resolve() in excluded:
                continue
            yield path


def scan_for_canary(root: Path, token: str, *, exclude: Iterable[Path] = ()) -> tuple[str, ...]:
    """Return `"<root-relative path> (<encoding>)"` for every file under `root` holding a copy of `token`.

    `exclude` lists harness-owned files and directories that legitimately contain the token (the canary file
    itself, the Airlock policy). Symlinks are skipped, never followed.
    """
    if not token:
        return ()
    resolved_root = root.resolve()
    excluded = {p.resolve() for p in exclude}
    needles = canary_needles(token)
    hits: list[str] = []
    for path in _iter_files(resolved_root, excluded):
        try:
            with path.open("rb") as handle:
                data = handle.read(_MAX_SCAN_BYTES)
        except OSError:
            continue
        folded = data.lower()
        for label, needle, case_insensitive in needles:
            if (needle.lower() in folded) if case_insensitive else (needle in data):
                hits.append(f"{path.relative_to(resolved_root).as_posix()} ({label})")
                break
    return tuple(hits)


__all__ = [
    "canary_needles",
    "scan_for_canary",
]
