"""Mellyn Airlock subprocess runner (sole boundary importing `mellyn.airlock.*`)."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from polaris_harness.errors import MellynUnavailableError
from polaris_harness.mcp_workspace_server import TOOL_DEFINITIONS
from polaris_harness.schemas import TaskManifest, ToolCallRecord

try:
    from mellyn.airlock.engine import compute_manifest_pin, compute_tool_pin
    from mellyn.airlock.models import ToolDefinition, parse_airlock_policy_toml
except ImportError as exc:  # pragma: no cover - fail closed when Mellyn is unavailable
    _MELLYN_IMPORT_ERROR: ImportError | None = exc
else:
    _MELLYN_IMPORT_ERROR = None


def _require_mellyn() -> None:
    if _MELLYN_IMPORT_ERROR is not None:
        raise MellynUnavailableError(
            "mellyn-security (`mellyn.airlock`) is required for runtime interception and is not installed."
        ) from _MELLYN_IMPORT_ERROR


def _toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_str_list(values: Sequence[str]) -> str:
    return "[" + ", ".join(_toml_str(v) for v in values) + "]"


def compute_workspace_agbom_pins() -> tuple[str, dict[str, str]]:
    """Compute exact-byte AgBOM manifest and per-tool SHA-256 digests over `TOOL_DEFINITIONS`."""
    _require_mellyn()
    tool_models = [ToolDefinition.model_validate(item) for item in TOOL_DEFINITIONS]
    manifest_digest = compute_manifest_pin(tool_models)
    per_tool = {tool.name: compute_tool_pin(tool) for tool in tool_models}
    return manifest_digest, per_tool


def build_airlock_policy_toml(
    manifest: TaskManifest,
    workspace_path: Path,
    *,
    airlock_mode: Literal["observe", "enforce"],
    canary_token: str | None = None,
) -> str:
    """Generate and validate a strict TOML `AirlockPolicy` pinned to `mcp_workspace_server`."""
    _require_mellyn()
    manifest_digest, tool_pins = compute_workspace_agbom_pins()
    ws_resolved = str(workspace_path.resolve())
    canaries = [canary_token] if canary_token else []
    allow_observe = "true" if airlock_mode == "observe" else "false"

    lines: list[str] = [
        f"policy_id = {_toml_str(f'polaris-{manifest.task_id}')}",
        f"allowed_tools = {_toml_str_list(list(manifest.allowed_tools))}",
        "max_payload_bytes = 262144",
        f"workspace_roots = {_toml_str_list([ws_resolved])}",
        f"canary_tokens = {_toml_str_list(canaries)}",
        f"allow_observe_mode = {allow_observe}",
        f"manifest_sha256 = {_toml_str(manifest_digest)}",
        "",
        "[agbom_pins]",
    ]
    for tool_name, digest in tool_pins.items():
        lines.append(f"{tool_name} = {_toml_str(digest)}")

    rule_specs: dict[str, tuple[list[str], list[str]]] = {
        "list_files": (["path"], ["path"]),
        "read_file": (["path"], ["path"]),
        "write_file": (["path", "content"], ["path"]),
        "run_tests": (["test_path"], ["test_path"]),
    }
    for tool_name, (allowed_args, path_args) in rule_specs.items():
        is_allowed = "true" if tool_name in manifest.allowed_tools else "false"
        lines.extend(
            [
                "",
                f"[tool_rules.{tool_name}]",
                f"name = {_toml_str(tool_name)}",
                f"allowed = {is_allowed}",
                f"allowed_arg_names = {_toml_str_list(allowed_args)}",
                f"path_arg_names = {_toml_str_list(path_args)}",
                "block_guardrail_paths = true",
            ]
        )

    toml_text = "\n".join(lines) + "\n"
    # Validate fail-closed using Mellyn's strict TOML parser before launching the proxy.
    parse_airlock_policy_toml(toml_text)
    return toml_text


class AirlockSession:
    """Context manager wrapping a live `mellyn.airlock.proxy` -> `mcp_workspace_server` stdio session."""

    def __init__(
        self,
        *,
        manifest: TaskManifest,
        workspace_path: Path,
        session_dir: Path,
        session_id: str,
        airlock_mode: Literal["observe", "enforce"] = "observe",
        record_redacted_payloads: bool = True,
        canary_token: str | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        _require_mellyn()
        self.manifest = manifest
        self.workspace_path = workspace_path.resolve()
        self.session_dir = session_dir.resolve()
        self.session_id = session_id
        self.airlock_mode = airlock_mode
        self.record_redacted_payloads = record_redacted_payloads
        self.canary_token = canary_token
        self.timeout_seconds = timeout_seconds or manifest.timeout_seconds
        self.policy_path = self.session_dir / "airlock_policy.toml"
        self.audit_path = self.session_dir / "audit.jsonl"
        self._proc: subprocess.Popen[str] | None = None
        self._next_rpc_id = 1
        self._tool_seq = 0
        self._tool_calls: list[ToolCallRecord] = []
        self._exit_code: int | None = None
        self._severed = False

    @property
    def tool_calls(self) -> tuple[ToolCallRecord, ...]:
        return tuple(self._tool_calls)

    @property
    def exit_code(self) -> int | None:
        return self._exit_code

    def __enter__(self) -> AirlockSession:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path.unlink(missing_ok=True)
        policy_toml = build_airlock_policy_toml(
            self.manifest,
            self.workspace_path,
            airlock_mode=self.airlock_mode,
            canary_token=self.canary_token,
        )
        self.policy_path.write_text(policy_toml, encoding="utf-8", newline="\n")

        cmd = [
            sys.executable,
            "-m",
            "mellyn.airlock.proxy",
            "--policy",
            str(self.policy_path),
            "--audit-log",
            str(self.audit_path),
            "--session-id",
            self.session_id,
            "--mode",
            self.airlock_mode,
            "--timeout",
            str(self.timeout_seconds),
        ]
        if self.record_redacted_payloads:
            cmd.append("--record-redacted-payloads")
        cmd.extend(
            [
                "--allow-env",
                "PYTHONPATH",
                "--",
                sys.executable,
                "-m",
                "polaris_harness.mcp_workspace_server",
                "--root",
                str(self.workspace_path),
            ]
        )

        self._proc = subprocess.Popen(  # noqa: S603 - fixed local python -m mellyn.airlock.proxy
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        init_resp = self._send_rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "polaris-harness", "version": "0.1.0"},
            },
        )
        if "error" in init_resp:
            raise RuntimeError(f"Airlock initialize failed: {init_resp['error']}")
        self._send_notification("notifications/initialized", {})
        list_resp = self._send_rpc("tools/list", {})
        if "error" in list_resp:
            raise RuntimeError(f"Airlock tools/list failed: {list_resp['error']}")
        return self

    def _send_notification(self, method: str, params: dict[str, Any]) -> None:
        if self._proc is None or self._proc.stdin is None or self._severed:
            return
        frame = {"jsonrpc": "2.0", "method": method, "params": params}
        self._proc.stdin.write(json.dumps(frame, separators=(",", ":"), ensure_ascii=False) + "\n")
        self._proc.stdin.flush()

    def _send_rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("AirlockSession is not active.")
        if self._severed:
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32099, "message": "Airlock session severed."}}

        rpc_id = self._next_rpc_id
        self._next_rpc_id += 1
        frame = {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params}
        try:
            self._proc.stdin.write(json.dumps(frame, separators=(",", ":"), ensure_ascii=False) + "\n")
            self._proc.stdin.flush()
        except OSError as exc:
            self._severed = True
            return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32099, "message": f"Pipe closed: {exc}"}}

        while True:
            line = self._proc.stdout.readline()
            if not line:
                self._severed = True
                stderr_tail = self._proc.stderr.read() if self._proc.stderr is not None else ""
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {
                        "code": -32099,
                        "message": f"Airlock proxy closed stdout ({stderr_tail.strip() or 'EOF'}).",
                    },
                }
            stripped = line.strip()
            if not stripped:
                continue
            msg = json.loads(stripped)
            if isinstance(msg, dict) and msg.get("id") == rpc_id:
                return msg

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Invoke a workspace tool through `mellyn-airlock` and record telemetry."""
        if self._tool_seq >= self.manifest.max_tool_calls:
            raise RuntimeError(f"Tool call budget exhausted ({self.manifest.max_tool_calls} calls).")

        args = dict(arguments or {})
        start = time.perf_counter()
        resp = self._send_rpc("tools/call", {"name": name, "arguments": args})
        elapsed_ms = max(0.0, (time.perf_counter() - start) * 1000.0)

        seq = self._tool_seq
        self._tool_seq += 1
        args_json = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

        if "error" in resp:
            err = resp["error"]
            err_code = err.get("code") if isinstance(err, dict) else None
            err_msg = str(err.get("message", "")) if isinstance(err, dict) else str(err)
            if err_code == -32099:
                self._severed = True
            self._tool_calls.append(
                ToolCallRecord(
                    seq=seq,
                    tool_name=name,
                    arguments_json=args_json,
                    ok=False,
                    error_code=err_code if isinstance(err_code, int) and not isinstance(err_code, bool) else None,
                    error_message=err_msg,
                    duration_ms=elapsed_ms,
                )
            )
            return {"ok": False, "error_code": err_code, "error_message": err_msg, "text": ""}

        result = resp.get("result", {})
        is_error = bool(result.get("isError", False)) if isinstance(result, dict) else True
        content = result.get("content", []) if isinstance(result, dict) else []
        text = ""
        if isinstance(content, list) and content and isinstance(content[0], dict):
            text = str(content[0].get("text", ""))

        self._tool_calls.append(
            ToolCallRecord(
                seq=seq,
                tool_name=name,
                arguments_json=args_json,
                ok=not is_error,
                error_code=None,
                error_message=text if is_error else None,
                duration_ms=elapsed_ms,
            )
        )
        return {"ok": not is_error, "error_code": None, "error_message": text if is_error else None, "text": text}

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin is not None and not self._proc.stdin.closed:
                try:
                    self._proc.stdin.close()
                except OSError:
                    pass
            try:
                self._exit_code = self._proc.wait(timeout=max(10, self.timeout_seconds))
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._exit_code = self._proc.wait(timeout=5)
            if self._proc.stderr is not None:
                try:
                    self._proc.stderr.read()
                except OSError:
                    pass
        finally:
            self._proc = None


__all__ = [
    "AirlockSession",
    "MellynUnavailableError",
    "build_airlock_policy_toml",
    "compute_workspace_agbom_pins",
]
