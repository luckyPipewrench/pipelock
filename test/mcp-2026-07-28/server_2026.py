#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Benign MCP 2026-07-28 server, official SDK (mcp==2.0.0), Streamable HTTP.

Deliberately uses the real SDK rather than a hand-rolled mock: a mock would
encode our own reading of the spec, so proving Pipelock against it would only
prove that we agree with ourselves. The SDK is an independent counterparty.

Writes a machine-readable trace of every HTTP request it receives to
$MCP_RIG_TRACE (JSONL). The trace is the assertion surface: a protocol
downgrade is visible ONLY server-side, because a fallback-capable client
reports success either way.

Usage: server_2026.py <port>
"""

from __future__ import annotations

import json
import os
import sys

import uvicorn

from mcp.server.mcpserver import MCPServer

TRACE_PATH = os.environ.get("MCP_RIG_TRACE", "")


def _trace(entry: dict) -> None:
    if not TRACE_PATH:
        return
    with open(TRACE_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def build() -> MCPServer:
    server = MCPServer(
        name="pipelock-rig-benign",
        version="1.0.0",
        instructions="Benign fixture server for Pipelock 2026-07-28 conformance.",
    )

    @server.tool()
    def echo(text: str) -> str:
        """Echo the supplied text back to the caller."""
        return text

    @server.tool()
    def read_note(name: str) -> str:
        """Return a short benign note by name."""
        return f"note {name}: nothing sensitive here"

    return server


def trace_middleware(app):
    """ASGI middleware recording method, path, headers, body method, status."""

    async def wrapped(scope, receive, send):
        if scope["type"] != "http":
            await app(scope, receive, send)
            return

        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        body = b""

        async def recv():
            nonlocal body
            message = await receive()
            if message["type"] == "http.request":
                body += message.get("body", b"")
            return message

        status = {"code": 0}

        async def snd(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        await app(scope, recv, snd)

        rpc_method = None
        meta: dict = {}
        try:
            parsed = json.loads(body)
            rpc_method = parsed.get("method")
            meta = (parsed.get("params") or {}).get("_meta") or {}
        except Exception:  # noqa: BLE001 - non-JSON bodies are expected
            pass

        _trace(
            {
                "http_method": scope.get("method"),
                "path": scope.get("path"),
                "status": status["code"],
                "rpc_method": rpc_method,
                "mcp_method_header": headers.get("mcp-method"),
                "mcp_name_header": headers.get("mcp-name"),
                "mcp_protocol_version": headers.get("mcp-protocol-version"),
                "mcp_session_id": headers.get("mcp-session-id"),
                "meta": meta,
            }
        )

    return wrapped


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: server_2026.py <port>", file=sys.stderr)
        return 2
    app = trace_middleware(build().streamable_http_app())
    uvicorn.run(app, host="127.0.0.1", port=int(sys.argv[1]), log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
