#!/usr/bin/env python3
"""Shared helpers for the tool-response-injection demos."""

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
import os
import re
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from malicious_mcp_server import DEFAULT_INJECTION_PAYLOAD

HERE = Path(__file__).resolve().parent
MCP_SERVER = HERE / "malicious_mcp_server.py"
CONFIG = HERE / "pipelock.yaml"
KEY_PATH = HERE / "signing.key"
EVIDENCE_DIR = HERE / "evidence"
PIPELOCK_BIN = os.environ.get("PIPELOCK_BIN", "pipelock")

_ACTION_RECORD_FIELDS = [
    ("version", False),
    ("action_id", False),
    ("action_type", False),
    ("timestamp", False),
    ("principal", False),
    ("actor", False),
    ("delegation_chain", False),
    ("target", False),
    ("intent", True),
    ("data_classes_in", True),
    ("data_classes_out", True),
    ("side_effect_class", False),
    ("reversibility", False),
    ("policy_hash", False),
    ("verdict", False),
    ("transport", False),
    ("method", True),
    ("layer", True),
    ("pattern", True),
    ("request_id", True),
    ("chain_prev_hash", False),
    ("chain_seq", False),
    ("venue", True),
    ("jurisdiction", True),
    ("rulebook_id", True),
    ("remedy_class", True),
    ("contestation_window", True),
    ("precedent_refs", True),
]


class PayloadHTTPHandler(BaseHTTPRequestHandler):
    payload = DEFAULT_INJECTION_PAYLOAD

    def do_GET(self) -> None:  # noqa: N802
        body = (
            "<html><body><main><h1>Game Results</h1>"
            f"<p>{self.payload}</p>"
            "</main></body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def _is_go_zero(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, str):
        return value == ""
    if isinstance(value, (list, tuple, dict)):
        return len(value) == 0
    return False


def _canonical_action_record(ar: dict[str, Any]) -> bytes:
    ordered: dict[str, Any] = {}
    for name, omitempty in _ACTION_RECORD_FIELDS:
        if name not in ar:
            continue
        value = ar[name]
        if omitempty and _is_go_zero(value):
            continue
        ordered[name] = value
    raw = json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)
    raw = (
        raw.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    return raw.encode("utf-8")


def ensure_pipelock_binary() -> str:
    if shutil.which(PIPELOCK_BIN) is None and not Path(PIPELOCK_BIN).exists():
        sys.stderr.write(
            f"pipelock binary not found (tried: {PIPELOCK_BIN}).\n"
            "Set PIPELOCK_BIN=/path/to/pipelock or add pipelock to PATH.\n"
        )
        raise SystemExit(2)
    return PIPELOCK_BIN


def generate_signing_key() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    encoded = base64.b64encode(seed + pub).decode("ascii")
    KEY_PATH.write_text(f"pipelock-ed25519-private-v1\n{encoded}\n", encoding="utf-8")
    KEY_PATH.chmod(0o600)
    return priv, pub


def reset_evidence_dir() -> None:
    if EVIDENCE_DIR.exists():
        shutil.rmtree(EVIDENCE_DIR)
    EVIDENCE_DIR.mkdir(parents=True, mode=0o750)


def receipt_identity(receipt: dict[str, Any]) -> tuple[str, str]:
    ar = receipt.get("action_record", {})
    return str(ar.get("action_id", "")), str(receipt.get("signature", ""))


def snapshot_receipts(pub_hex: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[Path]]:
    receipts, verified = load_receipts_from_evidence(pub_hex)
    return receipts, verified, set(EVIDENCE_DIR.glob("*.jsonl"))


def reserve_port() -> int:
    """Reserve a loopback port number for a subprocess to re-bind later.

    TOCTOU caveat: subprocess listeners that accept a ``--listen ADDR``
    flag have to close this socket and ask the child to bind it again,
    which leaves a small race window. We minimize it by setting
    SO_REUSEADDR (and SO_REUSEPORT on Linux) before bind so the kernel
    will honor the rebind immediately, and by calling wait_for_tcp
    against the final child port before using it. For in-process
    Python HTTP servers use ``start_payload_web_server`` instead — it
    binds port 0 directly with no race at all.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                # Not all kernels expose SO_REUSEPORT at runtime; it's a
                # best-effort narrowing of the TOCTOU window, not a
                # correctness requirement.
                pass
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_tcp(host: str, port: int, timeout_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {host}:{port}")


def wait_for_http(url: str, timeout_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.5) as response:  # noqa: S310
                if response.status < 500:
                    return
        except urllib.error.URLError:
            time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {url}")


def build_env(payload: str | None = None) -> dict[str, str]:
    env = os.environ.copy()
    if payload is not None:
        env["MALICIOUS_PAYLOAD"] = payload
    else:
        env.pop("MALICIOUS_PAYLOAD", None)
    return env


def start_pipelock_mcp_stdio(payload: str | None = None) -> subprocess.Popen[bytes]:
    cmd = [
        ensure_pipelock_binary(),
        "mcp",
        "proxy",
        "--config",
        str(CONFIG),
        "--",
        sys.executable,
        str(MCP_SERVER),
    ]
    return subprocess.Popen(  # noqa: S603
        cmd,
        cwd=HERE,
        env=build_env(payload),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def start_mcp_http_server(payload: str | None = None) -> tuple[subprocess.Popen[bytes], str]:
    port = reserve_port()
    listen = f"127.0.0.1:{port}"
    cmd = [sys.executable, str(MCP_SERVER), "--transport", "http", "--listen", listen]
    proc = subprocess.Popen(  # noqa: S603
        cmd,
        cwd=HERE,
        env=build_env(payload),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_for_tcp("127.0.0.1", port)
    return proc, f"http://{listen}"


def start_pipelock_mcp_http(upstream_url: str) -> subprocess.Popen[bytes]:
    cmd = [
        ensure_pipelock_binary(),
        "mcp",
        "proxy",
        "--config",
        str(CONFIG),
        "--upstream",
        upstream_url,
    ]
    return subprocess.Popen(  # noqa: S603
        cmd,
        cwd=HERE,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def start_pipelock_fetch_proxy(listen: str) -> subprocess.Popen[bytes]:
    cmd = [ensure_pipelock_binary(), "run", "--config", str(CONFIG), "--listen", listen]
    proc = subprocess.Popen(  # noqa: S603
        cmd,
        cwd=HERE,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_for_http(f"http://{listen}/health")
    return proc


def reserve_listen_addr() -> str:
    return f"127.0.0.1:{reserve_port()}"


def start_payload_web_server(payload: str) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    class Handler(PayloadHTTPHandler):
        pass

    Handler.payload = payload
    # Bind port 0 directly on the server socket and read back the bound
    # port. No reserve/rebind race — the listener exists before we
    # publish the address to any caller.
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{port}/"


def stop_payload_web_server(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    thread.join(timeout=2)
    server.server_close()


def stop_process(proc: subprocess.Popen[bytes], timeout_s: float = 5.0) -> str:
    try:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
    except BrokenPipeError:
        pass
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    stderr = b""
    if proc.stderr is not None:
        stderr = proc.stderr.read()
    return stderr.decode("utf-8", errors="replace")


def send_request(proc: subprocess.Popen[bytes], message: dict[str, Any]) -> None:
    assert proc.stdin is not None
    proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
    proc.stdin.flush()


def read_response(proc: subprocess.Popen[bytes], timeout_s: float = 8.0) -> dict[str, Any]:
    """Read one JSON-RPC response from ``proc.stdout`` within the timeout.

    The original implementation called ``readline()`` in a loop with a
    time check, but ``readline()`` is blocking — once we enter it, the
    whole timeout budget can be consumed by a single stalled line. We
    now use ``selectors`` to gate each read on readiness, and we also
    fail fast if the child process exited before we got a response.
    """
    assert proc.stdout is not None
    buffer = bytearray()
    deadline = time.monotonic() + timeout_s

    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("no JSON-RPC response from pipelock within timeout")
            # Child exited without emitting a response — no point waiting.
            if proc.poll() is not None:
                raise TimeoutError(
                    f"pipelock process exited (code={proc.returncode}) before sending a JSON-RPC response"
                )
            events = sel.select(timeout=min(remaining, 0.2))
            if not events:
                continue
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                # Clean EOF: the child closed stdout without more data.
                raise TimeoutError("pipelock closed stdout before sending a JSON-RPC response")
            buffer.extend(chunk)
            while b"\n" in buffer:
                line, _, rest = bytes(buffer).partition(b"\n")
                buffer = bytearray(rest)
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                try:
                    obj = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0":
                    return obj
    finally:
        sel.unregister(proc.stdout)
        sel.close()


def run_mcp_exchange(proc: subprocess.Popen[bytes], call_count: int = 1) -> list[dict[str, Any]]:
    send_request(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "tool-response-injection-demo", "version": "0"},
            },
        },
    )
    _ = read_response(proc)

    send_request(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    _ = read_response(proc)

    responses: list[dict[str, Any]] = []
    for index in range(call_count):
        send_request(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3 + index,
                "method": "tools/call",
                "params": {"name": "play_game", "arguments": {"player": f"demo-{index}"}},
            },
        )
        responses.append(read_response(proc, timeout_s=10.0))
    return responses


def fetch_via_proxy(listen: str, target_url: str) -> tuple[int, dict[str, Any]]:
    url = f"http://{listen}/fetch?url={urllib.parse.quote(target_url, safe='')}"
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            status = response.status
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        status = err.code
        body = err.read().decode("utf-8")
    return status, json.loads(body)


def verify_receipt_inline(receipt: dict[str, Any], pub_hex: str) -> None:
    sig_str = receipt.get("signature", "")
    if not sig_str.startswith("ed25519:"):
        raise ValueError("receipt signature is not ed25519")
    canonical = _canonical_action_record(receipt["action_record"])
    digest = hashlib.sha256(canonical).digest()
    sig_bytes = bytes.fromhex(sig_str[len("ed25519:") :])
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    pub.verify(sig_bytes, digest)


def load_receipts_from_evidence(pub_hex: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load and verify receipts from the evidence directory.

    Parse and verification failures are reported on stderr rather than
    silently dropped. For a demo centered on signed evidence and tamper
    detection, an audit gap is worse than noisy output — if corruption,
    truncation, or unexpected format changes occur, the operator sees
    exactly which file and line were affected instead of "why are my
    receipt counts different."
    """
    receipts: list[dict[str, Any]] = []
    for jsonl in sorted(EVIDENCE_DIR.glob("*.jsonl")):
        for lineno, raw in enumerate(jsonl.read_text(encoding="utf-8").splitlines(), start=1):
            stripped_line = raw.strip()
            if not stripped_line:
                continue
            try:
                entry = json.loads(stripped_line)
            except json.JSONDecodeError as exc:
                sys.stderr.write(
                    f"[load_receipts] {jsonl.name}:{lineno}: skipped malformed JSON line ({exc})\n"
                )
                continue
            if entry.get("type") != "action_receipt":
                continue
            detail = entry.get("detail")
            if isinstance(detail, dict):
                receipts.append(detail)
            elif isinstance(detail, str):
                try:
                    receipts.append(json.loads(detail))
                except json.JSONDecodeError as exc:
                    sys.stderr.write(
                        f"[load_receipts] {jsonl.name}:{lineno}: skipped malformed detail JSON ({exc})\n"
                    )
                    continue
            else:
                sys.stderr.write(
                    f"[load_receipts] {jsonl.name}:{lineno}: skipped entry with non-object detail\n"
                )

    verified: list[dict[str, Any]] = []
    for index, receipt in enumerate(receipts):
        try:
            verify_receipt_inline(receipt, pub_hex)
        except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
            action_id = receipt.get("action_record", {}).get("action_id", "?")
            sys.stderr.write(
                f"[load_receipts] receipt #{index} (action_id={action_id}): verification failed ({exc})\n"
            )
            continue
        verified.append(receipt)
    return receipts, verified


def select_new_receipts(before_ids: set[tuple[str, str]], receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [receipt for receipt in receipts if receipt_identity(receipt) not in before_ids]


def tamper_signature(receipt: dict[str, Any]) -> dict[str, Any]:
    tampered = copy.deepcopy(receipt)
    signature = tampered["signature"]
    prefix, value = signature.split(":", 1)
    first = value[:2]
    flipped = "00" if first.lower() != "00" else "ff"
    tampered["signature"] = f"{prefix}:{flipped}{value[2:]}"
    return tampered


def write_chain_break_file(source: Path) -> tuple[Path, int]:
    lines = source.read_text(encoding="utf-8").splitlines()
    receipt_indexes: list[tuple[int, dict[str, Any]]] = []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("type") != "action_receipt":
            continue
        detail = entry.get("detail")
        if isinstance(detail, str):
            detail = json.loads(detail)
        receipt_indexes.append((index, detail))
    if len(receipt_indexes) < 3:
        raise ValueError("need at least 3 receipts for a chain-break demo")

    middle_index = len(receipt_indexes) // 2
    line_index, _ = receipt_indexes[middle_index]
    _, next_receipt = receipt_indexes[middle_index + 1]
    kept = [line for idx, line in enumerate(lines) if idx != line_index]

    out_path = Path(tempfile.mkdtemp(prefix="pipelock-chain-break-")) / source.name
    out_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return out_path, int(next_receipt["action_record"]["chain_seq"])


def run_verify_receipt(path: Path, pub_hex: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [ensure_pipelock_binary(), "verify-receipt", str(path), "--key", pub_hex],
        check=False,
        capture_output=True,
        text=True,
        cwd=HERE,
    )


def variant_payloads() -> list[tuple[str, str]]:
    base = DEFAULT_INJECTION_PAYLOAD
    gzip_b64 = base64.b64encode(gzip.compress(base.encode("utf-8"))).decode("ascii")
    unicode_escaped = base.encode("unicode_escape").decode("ascii")
    cyrillic = base.replace("Ignore", "Іgnore").replace("previous", "prevіous")
    return [
        ("base64", f"base64:{base64.b64encode(base.encode('utf-8')).decode('ascii')}"),
        ("gzip_base64", f"gzip+base64:{gzip_b64}"),
        ("url_encoded", urllib.parse.quote(base, safe="")),
        ("unicode_escaped", unicode_escaped),
        ("cyrillic_homoglyph", cyrillic),
    ]


_FLIGHT_RECORDER_RE = re.compile(
    # Match a top-level ``flight_recorder:`` key (not indented) plus any
    # number of blank or indented continuation lines that belong to the
    # same YAML block. Stop at the next top-level key or EOF. Captured
    # as multiline (^ anchors to line starts).
    r"^flight_recorder:[ \t]*(?:\r?\n|$)(?:[ \t]+[^\n]*(?:\r?\n|$)|[ \t]*(?:\r?\n|$))*",
    re.MULTILINE,
)


def strip_flight_recorder_block(text: str) -> str:
    """Remove the ``flight_recorder`` YAML block from a pipelock config.

    Handles: block at start of file, block at end of file, block with
    comments in the middle, and indented continuation lines. Raises
    ValueError if the mutation does not actually eliminate the block —
    this catches regressions where the demo reports "flight recorder
    removed" but the file still contains it (GPT review, demo audit
    integrity).
    """
    stripped = _FLIGHT_RECORDER_RE.sub("", text)
    if re.search(r"^flight_recorder:", stripped, re.MULTILINE):
        raise ValueError(
            "strip_flight_recorder_block: flight_recorder section still present after mutation"
        )
    return stripped
