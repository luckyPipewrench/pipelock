#!/usr/bin/env python3
"""Check what happens when the agent can touch the harness files directly."""

from __future__ import annotations

import shutil
import time
from typing import Any, Callable

from demo_support import (
    CONFIG,
    EVIDENCE_DIR,
    generate_signing_key,
    load_receipts_from_evidence,
    read_response,
    reset_evidence_dir,
    send_request,
    start_pipelock_mcp_stdio,
    stop_process,
    strip_flight_recorder_block,
)


def initialize_session(proc: Any) -> None:
    send_request(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "capability-separation-demo", "version": "0"},
            },
        },
    )
    _ = read_response(proc)
    send_request(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    _ = read_response(proc)


def call_tool(proc: Any, request_id: int) -> dict[str, Any]:
    send_request(
        proc,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": "play_game", "arguments": {"player": f"case-{request_id}"}},
        },
    )
    return read_response(proc, timeout_s=10.0)


def describe_response(response: dict[str, Any]) -> str:
    error = response.get("error")
    if error is not None:
        return f"jsonrpc error: {error}"
    return str(response.get("result", {}))[:200]


def wait_for_visible_receipts(pub_hex: str, timeout_s: float = 2.0) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    deadline = time.monotonic() + timeout_s
    receipts: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        receipts, verified = load_receipts_from_evidence(pub_hex)
        if receipts or any(EVIDENCE_DIR.glob("*.jsonl")):
            return receipts, verified
        time.sleep(0.05)
    return receipts, verified


def remove_evidence_dir() -> str:
    shutil.rmtree(EVIDENCE_DIR)
    return "deleted evidence directory"


def truncate_evidence_files() -> str:
    files = sorted(EVIDENCE_DIR.glob("*.jsonl"))
    for path in files:
        path.write_text("", encoding="utf-8")
    return f"truncated {len(files)} JSONL file(s)"


def remove_flight_recorder_from_config() -> str:
    original = CONFIG.read_text(encoding="utf-8")
    CONFIG.write_text(strip_flight_recorder_block(original), encoding="utf-8")
    return "removed flight_recorder block from config file"


def run_case(name: str, mutator: Callable[[], str]) -> dict[str, Any]:
    original_config = CONFIG.read_text(encoding="utf-8")
    reset_evidence_dir()
    _, pub = generate_signing_key()
    pub_hex = pub.hex()
    proc = start_pipelock_mcp_stdio()
    try:
        initialize_session(proc)
        first = call_tool(proc, 3)
        before_receipts, before_verified = wait_for_visible_receipts(pub_hex)
        before_files = len(list(EVIDENCE_DIR.glob("*.jsonl")))
        mutation_result = mutator()
        second = call_tool(proc, 4)
    finally:
        stderr = stop_process(proc)
        CONFIG.write_text(original_config, encoding="utf-8")
    after_receipts, after_verified = load_receipts_from_evidence(pub_hex)
    return {
        "name": name,
        "first": describe_response(first),
        "second": describe_response(second),
        "mutation": mutation_result,
        "before_receipts": len(before_receipts),
        "before_verified": len(before_verified),
        "before_files": before_files,
        "after_receipts": len(after_receipts),
        "after_verified": len(after_verified),
        "after_files": len(list(EVIDENCE_DIR.glob("*.jsonl"))),
        "evidence_dir_exists": EVIDENCE_DIR.exists(),
        "stderr_tail": stderr.strip().splitlines()[-1] if stderr.strip() else "",
    }


def print_case(summary: dict[str, Any]) -> None:
    print()
    print(summary["name"])
    print(f"  first call:           {summary['first']}")
    print(f"  mutation:             {summary['mutation']}")
    print(f"  second call:          {summary['second']}")
    print(f"  files before:         {summary['before_files']}")
    print(f"  receipts before:      {summary['before_receipts']}")
    print(f"  verified before:      {summary['before_verified']}")
    print(f"  files after:          {summary['after_files']}")
    print(f"  receipts after:       {summary['after_receipts']}")
    print(f"  verified after:       {summary['after_verified']}")
    print(f"  evidence dir exists:  {summary['evidence_dir_exists']}")
    if summary["stderr_tail"]:
        print(f"  stderr tail:          {summary['stderr_tail']}")


def main() -> int:
    print("CAPABILITY SEPARATION DEMO")
    print("This runs the attack as the same user that owns the harness files.")

    summaries = [
        run_case("CASE 1: rm -rf ./evidence", remove_evidence_dir),
        run_case("CASE 2: truncate ./evidence/*.jsonl", truncate_evidence_files),
        run_case("CASE 3: delete flight_recorder block from config", remove_flight_recorder_from_config),
    ]

    for summary in summaries:
        print_case(summary)

    print()
    print("OBSERVATION")
    print("  This demo reports what happened on disk in this environment.")
    print("  Case 1 shows whether the agent can delete the evidence directory outright.")
    print("  Cases 2 and 3 show whether truncation or config edits change what survives on disk in the same-user deployment model.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
