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
import threading
import time
from urllib.parse import parse_qs, urlsplit

HOST = "browser.fixture.example"
FORBIDDEN_HOST = "forbidden.fixture.example"
CANARY = "PIPELOCK_BROWSER_REPRO_SYNTHETIC_CANARY"

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
                if self.path != "/session":
                    self.reply(404)
                    return
                with fixture.lock:
                    fixture.auth_counts["session_submissions"] += 1
                size = int(self.headers.get("Content-Length", "0"))
                if size > 1024:
                    self.reply(413)
                    return
                fields = parse_qs(self.rfile.read(size).decode())
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
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    # Finite route vocabulary and ring lengths bound evidence memory.
                    key = route if route in {"/", "/app", "/account", "/login", "/bundle.js", "/delayed.js", "/api/data", "/health", "/response-marker"} else "other"
                    with fixture.lock:
                        fixture.events[key].append({"elapsed_ms": round((time.monotonic()-start)*1000, 3)})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
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
