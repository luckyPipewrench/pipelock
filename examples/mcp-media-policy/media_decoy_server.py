#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Stdio MCP decoy for examples/mcp-media-policy/.

Returns text, JPEG-with-EXIF, audio, and video tool results so media_policy
strip/block behavior can be asserted offline.
"""

from __future__ import annotations

import base64
import json
import struct
import sys
from typing import Any

MARKER = b"mcp-secret-metadata"


def _segment(marker: int, payload: bytes) -> bytes:
    out = bytearray([0xFF, marker])
    out.extend(struct.pack(">H", len(payload) + 2))
    out.extend(payload)
    return bytes(out)


def build_jpeg_with_exif(marker: bytes = MARKER) -> bytes:
    buf = bytearray(b"\xFF\xD8")
    buf.extend(_segment(0xE0, b"JFIF header"))
    buf.extend(_segment(0xE1, b"Exif\x00\x00" + marker))
    buf.extend(b"\xFF\xDA\x00\x08\x01\x00\x00\x00\x3F\x00")
    buf.extend(b"\x11\x22\x33")
    buf.extend(b"\xFF\xD9")
    return bytes(buf)


JPEG_B64 = base64.standard_b64encode(build_jpeg_with_exif()).decode("ascii")
AUDIO_B64 = base64.standard_b64encode(b"fake audio bytes").decode("ascii")
VIDEO_B64 = base64.standard_b64encode(b"fake video bytes").decode("ascii")

TOOLS = [
    {
        "name": "get_text",
        "description": "Return a plain text result.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_jpeg_exif",
        "description": "Return a JPEG with synthetic EXIF metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_audio",
        "description": "Return an audio payload (blocked by default media_policy).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_video",
        "description": "Return a video payload (blocked by default media_policy).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def handle(request: dict[str, Any]) -> dict[str, Any] | None:
    method = request.get("method", "")
    req_id = request.get("id")
    if req_id is None:
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "media-decoy-demo", "version": "0.0.1-demo"},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = request.get("params")
        if not isinstance(params, dict):
            params = {}
        name = params.get("name", "")
        if name == "get_text":
            content: list[dict[str, Any]] = [
                {"type": "text", "text": "media-decoy ok: get_text"},
            ]
        elif name == "get_jpeg_exif":
            content = [
                {"type": "image", "mimeType": "image/jpeg", "data": JPEG_B64},
                {"type": "text", "text": "media-decoy ok: get_jpeg_exif"},
            ]
        elif name == "get_audio":
            content = [
                {"type": "audio", "mimeType": "audio/mpeg", "data": AUDIO_B64},
            ]
        elif name == "get_video":
            content = [
                {"type": "video", "mimeType": "video/mp4", "data": VIDEO_B64},
            ]
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: {name}"},
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": content, "isError": False},
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def run_stdio() -> None:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            if not isinstance(req, dict):
                continue
        except json.JSONDecodeError:
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    run_stdio()
