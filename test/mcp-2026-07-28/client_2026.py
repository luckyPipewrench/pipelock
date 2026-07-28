#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""MCP 2026-07-28 client driver, official SDK (mcp==2.0.0), Streamable HTTP.

Drives a single tool call at a target URL and reports a machine-readable
verdict on stdout. Used to prove, live, whether a compliant 2026-07-28 client
can transit Pipelock at all.

Usage: client_2026.py <url> [tool] [json-args]
Exit 0 = call succeeded, 1 = call failed. The JSON verdict is on stdout either
way, so a caller can distinguish "blocked by Pipelock" from "transport died".
"""

from __future__ import annotations

import asyncio
import json
import sys

from mcp import Client


async def drive(url: str, tool: str, args: dict) -> dict:
    verdict: dict = {"url": url, "tool": tool, "ok": False}
    try:
        async with Client(url, raise_exceptions=True) as client:
            tools = await client.list_tools()
            verdict["tools_listed"] = sorted(t.name for t in tools.tools)
            result = await client.call_tool(tool, args)
            verdict["ok"] = True
            verdict["result_type"] = getattr(result, "resultType", None) or getattr(
                result, "result_type", None
            )
            verdict["is_error"] = bool(getattr(result, "isError", False))
            blocks = []
            for block in getattr(result, "content", []) or []:
                blocks.append(getattr(block, "text", None) or repr(block))
            verdict["content"] = blocks
    except Exception as exc:  # noqa: BLE001 - the failure shape IS the result
        verdict["error_type"] = type(exc).__name__
        verdict["error"] = str(exc)[:500]
    return verdict


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: client_2026.py <url> [tool] [json-args]", file=sys.stderr)
        return 2
    url = sys.argv[1]
    tool = sys.argv[2] if len(sys.argv) > 2 else "echo"
    try:
        args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {"text": "hello"}
        if not isinstance(args, dict):
            raise TypeError("tool arguments must be a JSON object")
    except (ValueError, TypeError) as exc:
        # The contract is a JSON verdict either way, so a bad argument string
        # must not exit through a traceback.
        print(json.dumps({"url": url, "tool": tool, "ok": False,
                          "error_type": type(exc).__name__, "error": str(exc)}, indent=2))
        return 1
    verdict = asyncio.run(drive(url, tool, args))
    print(json.dumps(verdict, indent=2, default=str))
    return 0 if verdict["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
