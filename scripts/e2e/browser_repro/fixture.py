# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Generated, credential-free browser fixture. Binds only IPv4 loopback."""

from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import CookieError, SimpleCookie
import argparse
import hashlib
import json
from pathlib import Path
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

HOST = "browser.fixture.example"
FORBIDDEN_HOST = "forbidden.fixture.example"
CANARY = "PIPELOCK_BROWSER_REPRO_SYNTHETIC_CANARY"
REQUEST_TIMEOUT_SECONDS = 2
MAX_HANDLERS = 32
MAX_SESSION_BYTES = 1024

APP = """<!doctype html><meta charset="utf-8"><title>Browser reproduction fixture</title>
<style>body{font:20px sans-serif;margin:24px}#motion{height:20px;width:20px;background:green}</style>
<h1>Synthetic browser fixture</h1><p id="state">loading</p><p id="data"></p>
<label>Input <input id="input" autocomplete="off"></label><button id="count">Count</button>
<output id="counted">0</output><output id="keyed">0</output><div id="motion"></div><script src="/bundle.js"></script>
"""
LOGIN = """<!doctype html><meta charset="utf-8"><title>Synthetic login</title>
<h1>Synthetic login</h1><form id="fixture-login" method="post" action="/session">
<label>User <input id="user" name="user" autocomplete="off"></label>
<label>Fixture code <input id="code" name="code" autocomplete="off"></label>
<button id="login">Sign in</button></form>"""
SCRIPT = """
window.fixture = {state:'loading',count:0,keys:0,keyUps:0,frames:[],started:performance.now()};
const f=window.fixture; let previous=performance.now();
function animate(now){f.frames.push(now-previous);if(f.frames.length>240)f.frames.shift();previous=now;
document.getElementById('motion').style.transform='translateX('+Math.round(now%200)+'px)';requestAnimationFrame(animate)}
requestAnimationFrame(animate);
document.getElementById('count').onclick=()=>{f.count++;document.getElementById('counted').textContent=f.count};
document.getElementById('input').onkeydown=event=>{if(event.key==='Enter'){f.keys++;document.getElementById('keyed').textContent=f.keys}};
document.getElementById('input').onkeyup=event=>{if(event.key==='Enter')f.keyUps++};
const scenario=new URL(location.href).searchParams.get('scenario')||'normal';
const delayed=new Promise((resolve,reject)=>{const s=document.createElement('script');
s.src='/delayed.js';s.onload=resolve;s.onerror=()=>reject(Error('script failed'));document.head.append(s)});
const data=fetch('/api/data?scenario='+encodeURIComponent(scenario)).then(async r=>{
if(!r.ok)throw Error('HTTP '+r.status);return r.json()});
Promise.all([delayed,data]).then(([,value])=>{if(window.fixtureScriptLoaded!==true)throw Error('script execution marker missing');
document.getElementById('data').textContent=value.message;
localStorage.setItem('fixture-visited','yes');f.state='ready';f.ready=performance.now();
document.getElementById('state').textContent='ready'}).catch(error=>{f.state='error';
f.error=error.message;document.getElementById('state').textContent='error: '+error.message});
"""


def generated_bundle(size=2_000_000, marker=False):
    """Readable deterministic code, not a captured or obfuscated third-party bundle."""
    if not 4096 <= size <= 8_000_000:
        raise ValueError("bundle size must be between 4096 and 8000000")
    parts = ["'use strict';\n"]
    length = len(parts[0]) + len(SCRIPT)
    index = 0
    while length < size:
        item = f"function fixtureRow{index}(value){{return value+{index};}}\n"
        parts.append(item)
        length += len(item)
        index += 1
    parts.append(SCRIPT)
    if marker:
        parts.append("\n/* BROWSER_REPRO_RESPONSE_MARKER */\n")
    return "".join(parts).encode()


def write_fixtures(output, size=2_000_000):
    """Freeze exact scanner inputs once, with hashes; never overwrite a run."""
    clean = generated_bundle(size)
    marked = generated_bundle(size, marker=True)
    output.mkdir(mode=0o700)
    manifest = {}
    for name, body in (("generated-js.js", clean), ("generated-js-marker.js", marked)):
        path = output / name
        path.write_bytes(body)
        path.chmod(0o600)
        manifest[name] = {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    path = output / "generated-fixtures.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return manifest


class BoundedHTTPServer(ThreadingHTTPServer):
    """Limit live connections and retire every admitted handler on shutdown."""
    daemon_threads = False

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(MAX_HANDLERS)
        self.connections = set()
        self.connection_lock = threading.Lock()
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(REQUEST_TIMEOUT_SECONDS)
        return connection, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self.connection_lock:
            self.connections.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.connection_lock:
                self.connections.discard(request)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.connection_lock:
                self.connections.discard(request)
            self.slots.release()

    def server_close(self):
        with self.connection_lock:
            connections = tuple(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # A handler may already have closed its own connection.
        super().server_close()


class Fixture:
    def __init__(self, size=2_000_000, delay=0.2):
        self.bundle = generated_bundle(size)
        self.delay = delay
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.events = defaultdict(lambda: deque(maxlen=32))
        self.counts = defaultdict(int)
        self.scenario_counts = defaultdict(int)
        self.auth_counts = defaultdict(int)
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def handle(self):
                try:
                    super().handle()
                except (TimeoutError, ConnectionError):
                    pass  # Client disconnects must not produce raw request logs.

            def log_message(self, *_args):
                pass  # Never log cookies, submitted values or raw URLs.

            def reply(self, code, body=b"", mime="text/plain", headers=None):
                self.send_response(code)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(body)))
                if "Cache-Control" not in (headers or {}):
                    self.send_header("Cache-Control", "no-store")
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_POST(self):
                def reject(code):
                    # Unread or ambiguous request bytes cannot be another request.
                    self.close_connection = True
                    self.reply(code, headers={"Connection": "close"})

                if self.path != "/session":
                    reject(404)
                    return
                with fixture.lock:
                    fixture.auth_counts["session_submissions"] += 1
                lengths = self.headers.get_all("Content-Length", [])
                if "Transfer-Encoding" in self.headers or len(lengths) > 1:
                    reject(400)
                    return
                if not lengths:
                    reject(411)
                    return
                length = lengths[0].strip(" \t")
                if not length.isascii() or not length.isdecimal():
                    reject(400)
                    return
                # Bound before int() as headers can exceed Python's digit limit.
                length = length.lstrip("0") or "0"
                if len(length) > len(str(MAX_SESSION_BYTES)) or int(length) > MAX_SESSION_BYTES:
                    reject(413)
                    return
                size = int(length)
                try:
                    body = self.rfile.read(size)
                except TimeoutError:
                    reject(408)
                    return
                if len(body) != size:
                    reject(400)
                    return
                try:
                    fields = parse_qs(body.decode("utf-8"), errors="strict")
                except UnicodeError:
                    reject(400)
                    return
                if fields != {"user": ["fixture"], "code": ["fixture-only"]}:
                    with fixture.lock:
                        fixture.auth_counts["session_rejections"] += 1
                    self.reply(401, b"synthetic login rejected")
                    return
                with fixture.lock:
                    fixture.auth_counts["session_acceptances"] += 1
                self.reply(303, headers={"Location": "/account", "Set-Cookie":
                           "fixture_session=synthetic; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax"})

            def do_GET(self):
                parsed = urlsplit(self.path)
                route = parsed.path
                start = time.monotonic()
                with fixture.lock:
                    fixture.counts[route if route in {"/", "/app", "/account", "/login", "/bundle.js", "/delayed.js", "/api/data", "/health", "/response-marker"} else "other"] += 1
                try:
                    if route in ("/", "/app", "/account"):
                        cookies = SimpleCookie()
                        try:
                            cookies.load(self.headers.get("Cookie", ""))
                        except CookieError:
                            cookies.clear()
                        session = cookies.get("fixture_session")
                        authenticated = session is not None and session.value == "synthetic"
                        if route == "/account":
                            with fixture.lock:
                                fixture.auth_counts["account_authenticated" if authenticated else "account_login_required"] += 1
                        if route == "/account" and not authenticated:
                            self.reply(303, headers={"Location": "/login"})
                        else:
                            self.reply(200, APP.encode(), "text/html")
                    elif route == "/login":
                        self.reply(200, LOGIN.encode(), "text/html")
                    elif route == "/bundle.js":
                        self.reply(200, fixture.bundle, "application/javascript", {"Cache-Control": "public, max-age=3600"})
                    elif route == "/delayed.js":
                        fixture.stop.wait(fixture.delay)
                        self.reply(200, b"window.fixtureScriptLoaded=true;", "application/javascript")
                    elif route == "/api/data":
                        scenario = parse_qs(parsed.query).get("scenario", ["normal"])[0]
                        with fixture.lock:
                            fixture.scenario_counts[scenario if scenario in {"normal", "delayed", "error", "incomplete", "pending"} else "other"] += 1
                        if scenario == "pending":
                            fixture.stop.wait(60)
                        elif scenario == "delayed":
                            fixture.stop.wait(fixture.delay * 4)
                        if scenario == "error":
                            self.reply(503, b'{"error":"synthetic unavailable"}', "application/json")
                        elif scenario == "incomplete":
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", "1024")
                            self.send_header("Connection", "close")
                            self.end_headers()
                            self.wfile.write(b'{"message":')
                            self.close_connection = True
                        else:
                            self.reply(200, b'{"message":"generated data complete"}', "application/json")
                    elif route == "/response-marker":
                        self.reply(200, b"system: synthetic fixture marker only")
                    elif route == "/health":
                        self.reply(200, b"fixture-ready")
                    else:
                        self.reply(404, b"missing synthetic route")
                except (TimeoutError, ConnectionError):
                    pass
                finally:
                    # Finite route vocabulary and ring lengths bound evidence memory.
                    key = route if route in {"/", "/app", "/account", "/login", "/bundle.js", "/delayed.js", "/api/data", "/health", "/response-marker"} else "other"
                    with fixture.lock:
                        fixture.events[key].append({"elapsed_ms": round((time.monotonic()-start)*1000, 3)})

        self.server = BoundedHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self):
        return self.server.server_port

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def evidence(self):
        with self.lock:
            return {"counts": dict(self.counts), "scenario_counts": dict(self.scenario_counts),
                    "auth_counts": dict(self.auth_counts),
                    "routes": {key: list(value) for key, value in self.events.items()}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Freeze generated browser JavaScript for scanner-only comparisons")
    parser.add_argument("--output", required=True, type=Path, help="new directory; must not exist")
    parser.add_argument("--bundle-bytes", type=int, default=2_000_000)
    args = parser.parse_args()
    try:
        print(json.dumps(write_fixtures(args.output, args.bundle_bytes), indent=2))
    except (OSError, ValueError) as error:
        parser.error(str(error))
