"""Pipelock plugin implementation.

Each registered hook builds a payload matching Hermes' shell-hook wire schema
and dispatches it to `pipelock hermes hook`. The command performs
the scan and returns a decision JSON object the plugin translates into the
Hermes hook return value.

Fail-closed semantics: any subprocess error, timeout, missing binary, or
malformed response yields a block decision. Pipelock's hard rule is to deny
on uncertainty rather than fail open.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Optional

# The hook is a subcommand of the main pipelock binary: `pipelock hermes hook`.
# Overridable via PIPELOCK_BIN for operators who installed pipelock outside
# PATH or under a different name.
DEFAULT_PIPELOCK_BIN = "pipelock"

# Sidecar file written by `pipelock hermes install` recording the pipelock
# config path the hook should use. Lives next to this module so config flows
# without depending on Hermes' runtime environment.
CONFIG_SIDECAR = "pipelock.conf"

# Timeout for each subprocess invocation. Hermes' default hook timeout is 60s;
# we stay well under that so the plugin returns before Hermes' own watchdog
# fires.
DEFAULT_TIMEOUT_SECONDS = 30


def _resolve_pipelock() -> Optional[str]:
    override = os.environ.get("PIPELOCK_BIN")
    if override:
        return override if os.path.isfile(override) else None
    return shutil.which(DEFAULT_PIPELOCK_BIN)


def _resolve_config() -> Optional[str]:
    """Resolve the pipelock config path: install sidecar, then env, then none."""
    sidecar = os.path.join(os.path.dirname(os.path.abspath(__file__)), CONFIG_SIDECAR)
    try:
        with open(sidecar, "r", encoding="utf-8") as fh:
            path = fh.read().strip()
        if path:
            return path
    except OSError:
        pass
    env_path = os.environ.get("PIPELOCK_HERMES_HOOK_CONFIG")
    if env_path:
        return env_path
    return None


def _invoke(payload: dict) -> dict:
    """Run `pipelock hermes hook` with payload JSON on stdin; return decision."""
    pipelock = _resolve_pipelock()
    if not pipelock:
        return {
            "decision": "block",
            "reason": "pipelock binary not found; install pipelock or set PIPELOCK_BIN",
        }

    argv = [pipelock, "hermes", "hook"]
    config_path = _resolve_config()
    if config_path:
        argv.extend(["--config", config_path])

    # Serialize before the subprocess call so a non-JSON-serializable tool
    # argument or result (a custom object in tool_input/result) fails closed
    # here instead of raising an uncaught TypeError. Hermes logs-and-continues
    # on hook exceptions, so an escaped TypeError would silently skip the scan.
    try:
        payload_bytes = json.dumps(payload).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        # TypeError: non-serializable type. ValueError: circular reference.
        # RecursionError: payload nested deeper than the interpreter limit.
        # All three must block rather than escape into Hermes' log-and-continue.
        return {
            "decision": "block",
            "reason": f"pipelock hermes hook: payload not serializable: {exc}",
        }

    try:
        proc = subprocess.run(
            argv,
            input=payload_bytes,
            capture_output=True,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"decision": "block", "reason": "pipelock hermes hook timed out"}
    except (OSError, ValueError) as exc:
        return {
            "decision": "block",
            "reason": f"pipelock hermes hook invocation failed: {exc}",
        }

    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        return {
            "decision": "block",
            "reason": f"pipelock hermes hook exit {proc.returncode}: {stderr}",
        }

    raw = proc.stdout.decode("utf-8", errors="replace").strip()
    if not raw:
        return {"decision": "block", "reason": "pipelock hermes hook emitted empty JSON"}
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return {"decision": "block", "reason": "pipelock hermes hook emitted invalid JSON"}
    if not isinstance(decoded, dict):
        return {"decision": "block", "reason": "pipelock hermes hook emitted non-object JSON"}
    return decoded


def _pre_tool_call(tool_name: str, args: Any, task_id: str) -> Optional[dict]:
    result = _invoke({
        "hook_event_name": "pre_tool_call",
        "tool_name": tool_name,
        "tool_input": args if isinstance(args, (dict, list, str, int, float, bool)) else str(args),
        "extra": {"task_id": task_id},
    })
    if result.get("decision") == "block":
        return {
            "action": "block",
            "message": result.get("reason") or "pipelock blocked this tool call",
        }
    return None


def _transform_tool_result(
    tool_name: str,
    arguments: Any,
    result: Any,
    task_id: str,
) -> Optional[str]:
    scan = _invoke({
        "hook_event_name": "transform_tool_result",
        "tool_name": tool_name,
        "tool_input": {"arguments": arguments, "result": result},
        "extra": {"task_id": task_id},
    })
    if scan.get("decision") == "block":
        reason = scan.get("reason") or "pipelock redacted this tool result"
        return f"[pipelock] tool result blocked: {reason}"
    return None


def _pre_gateway_dispatch(event: Any, gateway: Any, session_store: Any) -> Optional[dict]:
    text = getattr(event, "text", "") or ""
    sender = getattr(event, "sender", "") or ""
    scan = _invoke({
        "hook_event_name": "pre_gateway_dispatch",
        "tool_name": "gateway",
        "tool_input": {"text": text, "sender": sender},
    })
    if scan.get("decision") == "block":
        return {"action": "skip"}
    return None


def _on_session_start(session_id: str) -> None:
    _invoke({
        "hook_event_name": "on_session_start",
        "session_id": session_id,
    })


def _on_session_end(session_id: str, completed: bool = False, interrupted: bool = False) -> None:
    _invoke({
        "hook_event_name": "on_session_end",
        "session_id": session_id,
        "extra": {"completed": completed, "interrupted": interrupted},
    })


def register(ctx: Any) -> None:
    """Hermes plugin entry point. Called once at plugin load time."""
    ctx.register_hook("pre_tool_call", _pre_tool_call)
    ctx.register_hook("transform_tool_result", _transform_tool_result)
    ctx.register_hook("pre_gateway_dispatch", _pre_gateway_dispatch)
    ctx.register_hook("on_session_start", _on_session_start)
    ctx.register_hook("on_session_end", _on_session_end)
