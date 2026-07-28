#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Named assertions over a server-side request trace (JSONL).

Named queries rather than an evaluated expression: this rig ships in a security
product and the pattern gets copied, so it must not normalise passing code
through a string evaluator.

Usage: trace_check.py <trace.jsonl> <query>
Prints the result and exits 0 on true / 1 on false (count queries always exit 0).
"""

from __future__ import annotations

import json
import sys


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def q_used_legacy_handshake(rows: list[dict]) -> bool:
    return any(r.get("rpc_method") == "initialize" for r in rows)


def q_used_session_transport(rows: list[dict]) -> bool:
    return any(r.get("http_method") in ("GET", "DELETE") for r in rows)


def q_count_400(rows: list[dict]) -> int:
    return sum(1 for r in rows if r.get("status") == 400)


def q_all_posts_have_mcp_method(rows: list[dict]) -> bool:
    posts = [r for r in rows if r.get("http_method") == "POST"]
    return bool(posts) and all(r.get("mcp_method_header") for r in posts)


def q_tools_call_has_mcp_name(rows: list[dict]) -> bool:
    """Mcp-Name names the invoked entity, so it appears on tools/call but not
    on unnamed methods such as server/discover or tools/list. Asserting it on
    every POST would pin a state the protocol cannot produce."""
    calls = [r for r in rows if r.get("rpc_method") == "tools/call"]
    return bool(calls) and all(r.get("mcp_name_header") for r in calls)


def q_protocol_versions(rows: list[dict]) -> str:
    seen = {r.get("mcp_protocol_version") for r in rows}
    return ",".join(sorted(v for v in seen if v))


QUERIES = {
    "used_legacy_handshake": q_used_legacy_handshake,
    "used_session_transport": q_used_session_transport,
    "count_400": q_count_400,
    "all_posts_have_mcp_method": q_all_posts_have_mcp_method,
    "tools_call_has_mcp_name": q_tools_call_has_mcp_name,
    "protocol_versions": q_protocol_versions,
}


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2] not in QUERIES:
        print(f"usage: trace_check.py <trace.jsonl> <{'|'.join(QUERIES)}>", file=sys.stderr)
        return 2
    result = QUERIES[sys.argv[2]](load(sys.argv[1]))
    print(result)
    return 0 if not isinstance(result, bool) or result else 1


if __name__ == "__main__":
    raise SystemExit(main())
