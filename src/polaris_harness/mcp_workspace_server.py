"""Minimal stdio JSON-RPC 2.0 MCP workspace server scoped to a task sandbox."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "polaris-workspace-mcp", "version": "0.1.0"}
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

TOOL_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "name": "list_files",
        "description": "List relative file paths inside the workspace directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Optional workspace-relative subdirectory (default '.').",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "read_file",
        "description": "Read a UTF-8 text file inside the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Workspace-relative path to read.",
                }
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "write_file",
        "description": "Write UTF-8 text to a file inside the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Workspace-relative path to write.",
                },
                "content": {
                    "type": "string",
                    "description": "Complete UTF-8 file contents to write.",
                },
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "run_tests",
        "description": "Run pytest on a workspace-relative test directory or file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "test_path": {
                    "type": "string",
                    "description": "Workspace-relative test path (default 'public_tests').",
                }
            },
            "additionalProperties": False,
        },
    },
)


class WorkspaceServerError(ValueError):
    """Fail-closed error raised when a tool request violates sandbox bounds or arguments."""


def _resolve_scoped_path(root: Path, raw_path: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise WorkspaceServerError("Path must be a non-empty string.")
    if _CONTROL_CHARS_RE.search(raw_path):
        raise WorkspaceServerError("Path contains control characters.")

    normalized = raw_path.strip().replace("\\", "/")
    candidate = Path(normalized)
    if candidate.is_absolute():
        raise WorkspaceServerError(f"Absolute paths are forbidden: {raw_path!r}")

    root_resolved = root.resolve()
    resolved = (root_resolved / candidate).resolve(strict=False)
    if not resolved.is_relative_to(root_resolved):
        raise WorkspaceServerError(f"Path escapes workspace boundary: {raw_path!r}")

    if resolved != root_resolved:
        rel_parts = resolved.relative_to(root_resolved).parts
        if any(part == ".git" for part in rel_parts):
            raise WorkspaceServerError("Access to .git metadata is forbidden.")
    return resolved


def _clean_pytest_env(root: Path) -> dict[str, str]:
    allowed_keys = (
        ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "PATHEXT", "LOCALAPPDATA")
        if sys.platform == "win32"
        else ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL")
    )
    env: dict[str, str] = {}
    for key in allowed_keys:
        if key in os.environ:
            env[key] = os.environ[key]
    src_dir = root / "src"
    env["PYTHONPATH"] = str(src_dir) if src_dir.is_dir() else str(root)
    return env


def _tool_list_files(root: Path, arguments: dict[str, Any]) -> str:
    raw_path = arguments.get("path", ".")
    target = _resolve_scoped_path(root, str(raw_path))
    if not target.exists():
        raise WorkspaceServerError(f"Directory does not exist: {raw_path!r}")
    if not target.is_dir():
        raise WorkspaceServerError(f"Not a directory: {raw_path!r}")

    root_resolved = root.resolve()
    files: list[str] = []
    for item in sorted(target.rglob("*")):
        if not item.is_file():
            continue
        rel = item.resolve().relative_to(root_resolved)
        if any(part in {".git", "__pycache__", ".pytest_cache"} for part in rel.parts):
            continue
        files.append(rel.as_posix())
    return "\n".join(files)


def _tool_read_file(root: Path, arguments: dict[str, Any]) -> str:
    if "path" not in arguments or not isinstance(arguments["path"], str):
        raise WorkspaceServerError("read_file requires string argument 'path'.")
    target = _resolve_scoped_path(root, arguments["path"])
    if not target.is_file():
        raise WorkspaceServerError(f"File does not exist: {arguments['path']!r}")
    return target.read_text(encoding="utf-8", errors="replace")


def _tool_write_file(root: Path, arguments: dict[str, Any]) -> str:
    if "path" not in arguments or not isinstance(arguments["path"], str):
        raise WorkspaceServerError("write_file requires string argument 'path'.")
    if "content" not in arguments or not isinstance(arguments["content"], str):
        raise WorkspaceServerError("write_file requires string argument 'content'.")
    target = _resolve_scoped_path(root, arguments["path"])
    if target == root.resolve():
        raise WorkspaceServerError("Cannot overwrite workspace root directory.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(arguments["content"], encoding="utf-8", newline="\n")
    rel = target.relative_to(root.resolve()).as_posix()
    return f"Wrote {len(arguments['content'])} chars to {rel}"


def _tool_run_tests(root: Path, arguments: dict[str, Any], *, timeout_seconds: int = 45) -> str:
    raw_test_path = arguments.get("test_path", "public_tests")
    if not isinstance(raw_test_path, str):
        raise WorkspaceServerError("run_tests 'test_path' must be a string.")
    target = _resolve_scoped_path(root, raw_test_path)
    if not target.exists():
        raise WorkspaceServerError(f"Test path does not exist: {raw_test_path!r}")
    rel = target.relative_to(root.resolve()).as_posix()
    proc = subprocess.run(  # noqa: S603 - fixed local python -m pytest invocation
        [sys.executable, "-m", "pytest", "-q", rel],
        cwd=str(root.resolve()),
        env=_clean_pytest_env(root.resolve()),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
    )
    combined = (proc.stdout + "\n" + proc.stderr).strip()
    return f"EXIT_CODE={proc.returncode}\n{combined}"


def dispatch_tool_call(root: Path, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute one workspace-scoped tool call and return an MCP `tools/call` result envelope."""
    try:
        if name == "list_files":
            text = _tool_list_files(root, arguments)
        elif name == "read_file":
            text = _tool_read_file(root, arguments)
        elif name == "write_file":
            text = _tool_write_file(root, arguments)
        elif name == "run_tests":
            text = _tool_run_tests(root, arguments)
        else:
            raise WorkspaceServerError(f"Unknown tool: {name!r}")
        return {"content": [{"type": "text", "text": text}], "isError": False}
    except WorkspaceServerError as exc:
        return {"content": [{"type": "text", "text": f"ERROR: {exc}"}], "isError": True}


def _send_frame(payload: dict[str, Any]) -> None:
    line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    sys.stdout.buffer.write(line)
    sys.stdout.buffer.flush()


def serve_stdio(root: Path) -> int:
    """Run the newline-delimited JSON-RPC 2.0 stdio loop for `root`."""
    resolved_root = root.resolve()
    while True:
        raw = sys.stdin.buffer.readline()
        if not raw:
            return 0
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            _send_frame({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {exc}"}})
            continue
        if not isinstance(msg, dict):
            _send_frame({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
            continue

        method = msg.get("method")
        if "id" not in msg:
            # Notification: do not respond.
            continue
        req_id = msg["id"]
        params = msg.get("params")
        if not isinstance(params, dict):
            params = {}

        if method == "initialize":
            _send_frame(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": SERVER_INFO,
                    },
                }
            )
        elif method == "tools/list":
            _send_frame(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": list(TOOL_DEFINITIONS)},
                }
            )
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(tool_name, str) or not isinstance(arguments, dict):
                _send_frame(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": "Invalid tools/call params."},
                    }
                )
                continue
            result = dispatch_tool_call(resolved_root, tool_name, arguments)
            _send_frame({"jsonrpc": "2.0", "id": req_id, "result": result})
        else:
            _send_frame(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method '{method}' not found."},
                }
            )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Polaris scoped MCP stdio workspace server.")
    parser.add_argument("--root", type=Path, required=True, help="Workspace root directory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return serve_stdio(args.root)


if __name__ == "__main__":
    raise SystemExit(main())
