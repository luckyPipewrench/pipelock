#!/usr/bin/env python3
"""Real-upstream MCP runtime E2E for `pipelock cline install`.

Builds the pipelock binary from the worktree (or reuses one passed via
PIPELOCK_BIN), seeds a temp cline_mcp_settings.json with an entry for
@modelcontextprotocol/server-everything (the official MCP test server),
runs `pipelock cline install`, spawns the wrapped subprocess, drives the
full MCP handshake (initialize, initialized notification, tools/list),
asserts the everything server's known tools came back through pipelock's
MCP proxy, then runs `pipelock cline remove` and verifies the config is
semantically equivalent to the seed JSON.

Usage:
    python3 scripts/e2e/cline-mcp-runtime.py
    PIPELOCK_BIN=~/.local/bin/pipelock python3 scripts/e2e/cline-mcp-runtime.py
    KEEP_WORKDIR=1 python3 scripts/e2e/cline-mcp-runtime.py

Exit 0 on full pass, non-zero on first failure.
"""
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Pinned upstream package. Updating this is a deliberate supply-chain choice;
# do not loosen to `@latest` or unpinned without auditing the new version.
EVERYTHING_PACKAGE = "@modelcontextprotocol/server-everything@2026.1.26"

# Subset of tools the everything server is known to ship as of mid-2026.
# Asserting these come back through pipelock proves the full handshake and
# tools/list pipe both round-tripped (init -> notification -> request ->
# response). The server's tool roster has shifted across versions: keep
# this list to a few stable names that appear in every recent release.
EXPECTED_TOOLS = {"echo", "get-sum"}


def build_pipelock(workdir: Path) -> Path:
    """Compile pipelock from the surrounding worktree or honor PIPELOCK_BIN."""
    bin_override = os.environ.get("PIPELOCK_BIN")
    if bin_override:
        print(f"Using pre-built pipelock at {bin_override}")
        return Path(bin_override)
    out = workdir / "pipelock"
    print(f"Building pipelock from {REPO_ROOT} -> {out}")
    subprocess.run(
        ["go", "build", "-o", str(out), "./cmd/pipelock"],
        cwd=REPO_ROOT,
        check=True,
    )
    return out


def seed_config(workdir: Path) -> Path:
    """Write a Cline-shape config with one entry pointing at the everything server."""
    cfg = {
        "mcpServers": {
            "everything": {
                "command": "npx",
                "args": ["-y", EVERYTHING_PACKAGE],
            }
        }
    }
    cfg_path = workdir / "cline_mcp_settings.json"
    seed_path = workdir / "cline_mcp_settings.seed.json"
    body = json.dumps(cfg, indent=2) + "\n"
    cfg_path.write_text(body)
    seed_path.write_text(body)
    return cfg_path


def seed_pipelock_config(workdir: Path) -> Path:
    """Write a minimal pipelock config with sandbox off so the wrapped
    subprocess can reach the npm registry to fetch the upstream package.

    Auto-discovery would otherwise pick up the operator's config, which
    typically has sandbox enabled. This test is hermetic by design.
    """
    body = """mode: balanced
sandbox:
  enabled: false
file_sentry:
  enabled: false
flight_recorder:
  enabled: false
"""
    p = workdir / "pipelock.yaml"
    p.write_text(body)
    return p


def run_install(pipelock: Path, cfg_path: Path, pipelock_cfg: Path) -> None:
    result = subprocess.run(
        [str(pipelock), "cline", "install", "--path", str(cfg_path), "-c", str(pipelock_cfg)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.exit(f"install failed: {result.stderr}")
    if "Wrapped 1 server" not in result.stdout:
        sys.exit(f"install did not wrap the expected count: {result.stdout!r}")


def extract_wrapped_argv(cfg_path: Path):
    data = json.loads(cfg_path.read_text())
    entry = data["mcpServers"]["everything"]
    if "_pipelock" not in entry:
        sys.exit("wrapped entry missing _pipelock metadata")
    return entry["command"], entry["args"]


def send_message(proc, payload: dict) -> None:
    line = json.dumps(payload) + "\n"
    proc.stdin.write(line.encode("utf-8"))
    proc.stdin.flush()


class StreamTail:
    """Thread-safe bounded text tail for subprocess diagnostics."""

    def __init__(self, limit: int = 8192):
        self._limit = limit
        self._text = ""
        self._lock = threading.Lock()

    def append(self, raw: bytes) -> None:
        text = raw.decode("utf-8", errors="replace")
        with self._lock:
            self._text = (self._text + text)[-self._limit:]

    def tail(self, limit: int = 2000) -> str:
        with self._lock:
            return self._text[-limit:]


def start_stdout_reader(stream) -> tuple[queue.Queue, threading.Thread]:
    lines = queue.Queue()

    def read_lines() -> None:
        try:
            for raw in iter(stream.readline, b""):
                lines.put(raw)
        finally:
            lines.put(None)

    thread = threading.Thread(target=read_lines, name="pipelock-e2e-stdout", daemon=True)
    thread.start()
    return lines, thread


def start_stderr_tailer(stream, tail: StreamTail) -> threading.Thread:
    def read_stderr() -> None:
        for chunk in iter(lambda: stream.read(4096), b""):
            tail.append(chunk)

    thread = threading.Thread(target=read_stderr, name="pipelock-e2e-stderr", daemon=True)
    thread.start()
    return thread


def read_response(proc, stdout_lines, stderr_tail: StreamTail, expected_id, timeout: float = 30.0) -> dict:
    """Read JSON-RPC frames from stdout until one matches expected_id.

    The proxy may interleave log lines; non-JSON output is skipped. A
    background reader owns the blocking pipe read so this function's timeout
    cannot hang behind readline().
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            line = stdout_lines.get(timeout=min(0.1, remaining))
        except queue.Empty:
            if proc.poll() is not None:
                sys.exit(
                    f"subprocess exited before response id={expected_id}; "
                    f"stderr tail:\n{stderr_tail.tail()}"
                )
            continue
        if not line:
            if proc.poll() is not None:
                sys.exit(
                    f"subprocess exited before response id={expected_id}; "
                    f"stderr tail:\n{stderr_tail.tail()}"
                )
            continue
        text = line.decode("utf-8", errors="replace").strip()
        if not text or not text.startswith("{"):
            continue
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            continue
        if obj.get("id") == expected_id:
            return obj
    sys.exit(
        f"timeout waiting for response id={expected_id}; "
        f"stderr tail:\n{stderr_tail.tail()}"
    )


def main():
    # Opt-in gate. This E2E fetches an upstream npm package at runtime, which
    # is a supply-chain surface even with a pinned version. The default is to
    # skip; operators who want the live-upstream test set PIPELOCK_E2E_LIVE_UPSTREAM=1.
    if not os.environ.get("PIPELOCK_E2E_LIVE_UPSTREAM"):
        print(
            "Skipping runtime MCP E2E. Set PIPELOCK_E2E_LIVE_UPSTREAM=1 to run "
            "the test, which fetches @modelcontextprotocol/server-everything "
            f"({EVERYTHING_PACKAGE}) from npm."
        )
        return

    workdir = Path(tempfile.mkdtemp(prefix="pipelock-cline-runtime-"))
    print(f"Workdir: {workdir}")
    keep_workdir = bool(os.environ.get("KEEP_WORKDIR"))

    try:
        pipelock = build_pipelock(workdir)
        cfg_path = seed_config(workdir)
        pipelock_cfg = seed_pipelock_config(workdir)

        print("\n[1] install")
        run_install(pipelock, cfg_path, pipelock_cfg)
        cmd, args = extract_wrapped_argv(cfg_path)
        print(f"  wrapped command: {cmd}")
        print(f"  wrapped args head: {' '.join(args[:6])} ...")

        print("\n[2] spawn wrapped subprocess and drive MCP handshake")
        proc = subprocess.Popen(
            [cmd, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout_lines, stdout_thread = start_stdout_reader(proc.stdout)
        stderr_tail = StreamTail()
        stderr_thread = start_stderr_tailer(proc.stderr, stderr_tail)
        try:
            send_message(proc, {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "pipelock-e2e", "version": "0"},
                },
            })
            resp = read_response(proc, stdout_lines, stderr_tail, expected_id=1, timeout=60.0)
            if "result" not in resp or "serverInfo" not in resp["result"]:
                sys.exit(f"initialize returned unexpected shape: {resp}")
            server_name = resp["result"]["serverInfo"].get("name", "?")
            print(f"  initialize OK; serverInfo.name={server_name!r}")

            send_message(proc, {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            })

            send_message(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            resp = read_response(proc, stdout_lines, stderr_tail, expected_id=2, timeout=30.0)
            tools = resp.get("result", {}).get("tools", [])
            tool_names = {t.get("name") for t in tools}
            print(f"  tools/list returned {len(tools)} tools")
            missing = EXPECTED_TOOLS - tool_names
            if missing:
                sys.exit(
                    f"expected tools missing from response: {missing}; "
                    f"got {sorted(tool_names)}"
                )
            print(f"  all expected tools present: {sorted(EXPECTED_TOOLS)}")
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=5)
            for stream in (proc.stdout, proc.stderr):
                try:
                    stream.close()
                except Exception:
                    pass
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)

        print("\n[3] remove and verify canonical-JSON restoration")
        remove = subprocess.run(
            [str(pipelock), "cline", "remove", "--path", str(cfg_path)],
            capture_output=True, text=True,
        )
        if remove.returncode != 0:
            sys.exit(f"remove failed: {remove.stderr}")

        # Semantic compare, not byte-for-byte: pipelock's Go json.MarshalIndent
        # sorts map keys alphabetically, so the post-remove file may carry
        # `{args, command}` where the seed had `{command, args}`. The contents
        # are equivalent. The shell fixture E2E uses the same canonical compare
        # via `jq -S`.
        seed_obj = json.loads((workdir / "cline_mcp_settings.seed.json").read_text())
        post_obj = json.loads(cfg_path.read_text())
        if json.dumps(seed_obj, sort_keys=True) != json.dumps(post_obj, sort_keys=True):
            sys.exit(
                "post-remove config not semantically equal to seed:\n"
                f"seed: {json.dumps(seed_obj, indent=2)}\n"
                f"post: {json.dumps(post_obj, indent=2)}"
            )
        print("  config restored to canonical-JSON equivalent of seed")

        print("\nALL PASS")
    finally:
        if keep_workdir:
            print(f"\nKEEP_WORKDIR set; preserved {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
