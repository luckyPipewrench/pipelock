#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Run generated browser diagnostics through the shipped Pipelock CLI.

Default mode requires the shipped strict sandbox. --mode proxy-only is an
explicit diagnostic with no Pipelock kernel-containment claim. No installations,
managed-host changes, credentials, external target URLs or third-party assets.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

from fixture import CANARY, FORBIDDEN_HOST, HOST, Fixture

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUPERVISOR = ROOT / "scripts/ci_process_supervisor.py"
NODE_IDENTITY = "JSON.stringify({execPath:process.execPath,version:process.versions.node,release:process.release.name})"


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def node_identity(output):
    """Resolve the runtime reported by Node, never copy a PATH launcher/shim."""
    if len(output) > 4096:
        raise RuntimeError("Node identity output exceeds its bound")
    try:
        identity = json.loads(output)
        version = identity["version"]
        executable = Path(identity["execPath"])
        if identity["release"] != "node" or not isinstance(version, str):
            raise ValueError("not a Node runtime")
        match = re.fullmatch(r"(\d+)\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?", version)
        if not match or int(match[1]) < 22:
            raise ValueError("Node 22+ is required")
        if not executable.is_absolute():
            raise ValueError("Node execPath is not absolute")
        executable = executable.resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("Node execPath is not executable")
        with executable.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise ValueError("Node execPath is not a native Linux executable")
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise RuntimeError(f"invalid Node runtime identity: {error}; use --node with the native executable") from error
    return {"exec_path": str(executable), "version": version}


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def copy_node_runtime(identity, destination):
    source = Path(identity["exec_path"])
    source_hash = file_sha256(source)
    shutil.copyfile(source, destination)
    destination.chmod(0o750)
    copied_hash = file_sha256(destination)
    if copied_hash != source_hash:
        raise RuntimeError("Node runtime changed while being copied")
    return {"source_sha256": source_hash, "copied_sha256": copied_hash}


def isolated_environment(root):
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
    for name, part in [("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                       ("XDG_DATA_HOME", "data"), ("XDG_STATE_HOME", "state"),
                       ("XDG_CACHE_HOME", "cache"), ("TMPDIR", "tmp")]:
        directory = root / part
        directory.mkdir(mode=0o700)
        env[name] = str(directory)
    env["PIPELOCK_POSTURE_PROOF"] = str(root / "absent-proof.json")
    return env


class Cancellation:
    """Defer signals to safe checkpoints so process creation/cleanup is atomic."""
    def __init__(self):
        self.signum = None
        self.previous = {}

    def interrupted(self, signum, _frame):
        if self.signum is None:
            self.signum = signum

    def install(self):
        for signum in (signal.SIGTERM, signal.SIGINT):
            self.previous[signum] = signal.signal(signum, self.interrupted)

    def restore(self):
        for signum, handler in self.previous.items():
            signal.signal(signum, handler)

    def check(self):
        if self.signum is not None:
            raise RuntimeError(f"runner interrupted by signal {self.signum}")


class Process:
    """Continuously drain both pipes; cap retained bytes, never stop reading."""
    def __init__(self, command, output, env, cwd, cancellation=None, signal_grace_seconds=2):
        if type(signal_grace_seconds) is not int or not 2 <= signal_grace_seconds <= 20:
            raise ValueError("signal grace must be an integer from 2 to 20 seconds")
        self.signal_grace_seconds = signal_grace_seconds
        self.cancellation = cancellation
        if cancellation:
            cancellation.check()
        children_file = Path(f"/proc/self/task/{os.getpid()}/children")
        if not children_file.is_file():
            raise RuntimeError("verified process cleanup unavailable: procfs children file is absent")
        self.command = command
        self.output = output
        self.buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self.counts = {"stdout": 0, "stderr": 0}
        self.eof = {"stdout": False, "stderr": False}
        self.read_errors = {}
        self.output_lock = threading.Lock()
        self.process = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "--status-file", str(output.with_suffix(".cleanup.json")),
             "--signal-grace-seconds", str(signal_grace_seconds), "--", *command],
            cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.threads = []
        for name in self.buffers:
            thread = threading.Thread(target=self.drain, args=(name,), daemon=True)
            thread.start()
            self.threads.append(thread)

    def drain(self, name):
        stream = getattr(self.process, name)
        try:
            # read() may wait for a full buffer while a long-lived child has
            # already emitted its short startup witness. Drain available bytes.
            while chunk := stream.read1(8192):
                with self.output_lock:
                    self.counts[name] += len(chunk)
                    self.buffers[name].extend(chunk)
                    del self.buffers[name][:-65536]
            self.eof[name] = True
        except Exception as error:
            self.read_errors[name] = str(error)[:512]
        finally:
            try:
                stream.close()
            except Exception as error:
                self.read_errors[name] = str(error)[:512]

    def output_snapshot(self, name):
        with self.output_lock:
            return bytes(self.buffers[name]), self.counts[name]

    def wait(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if self.cancellation:
                self.cancellation.check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(self.command, timeout)
            try:
                return self.process.wait(timeout=min(0.1, remaining))
            except subprocess.TimeoutExpired:
                pass

    def stop(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=self.signal_grace_seconds + 6)
            except subprocess.TimeoutExpired:
                # Do not invent cleanup success if the shipped supervisor stalls.
                raise RuntimeError("process supervisor did not complete descendant cleanup")
        for thread in self.threads:
            thread.join(timeout=2)
        drained = all(self.eof.values()) and not self.read_errors and not any(thread.is_alive() for thread in self.threads)
        result = {"exit_code": self.process.returncode, "streams_drained": drained, "read_errors": self.read_errors, "streams": {}}
        for name, data in self.buffers.items():
            self.output.with_suffix("."+name).write_bytes(bytes(data))
            self.output.with_suffix("."+name).chmod(0o600)
            result["streams"][name] = {"total_bytes": self.counts[name], "retained_bytes": len(data), "truncated": self.counts[name] > len(data)}
        cleanup_path = self.output.with_suffix(".cleanup.json")
        try:
            cleanup = json.loads(cleanup_path.read_text())
        except (OSError, ValueError) as error:
            raise RuntimeError(f"missing or invalid cleanup witness: {self.output.name}") from error
        result["cleanup"] = cleanup
        write_json(self.output.with_suffix(".process.json"), result)
        if not drained:
            raise RuntimeError(f"output drain did not reach EOF: {self.output.name}")
        if not cleanup.get("cleanup_complete") or cleanup.get("unexpected_live_descendants"):
            raise RuntimeError(f"descendant cleanup was incomplete or unexpected: {self.output.name}")
        return result


def probe(command, name, output, env, work, cancellation, report):
    process = Process(command, output / name, env, work, cancellation)
    try:
        code = process.wait(timeout=5)
    finally:
        report["processes"][name] = process.stop()
    if code != 0:
        raise RuntimeError(f"{name} probe failed; use an explicit installed native executable")
    if process.counts["stdout"] > 4096:
        raise RuntimeError(f"{name} probe output exceeds its bound")
    return bytes(process.buffers["stdout"]).decode("utf-8").strip()


def owned_proxy_address(output, total_bytes):
    """Read one complete startup witness from this invocation's stdout pipe."""
    if total_bytes > len(output) or len(output) > 65536:
        raise RuntimeError("proxy startup evidence was truncated")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    addresses = []
    for line in output.split(b"\n")[:-1]:
        if not line.strip():
            continue
        try:
            record = json.loads(line, object_pairs_hook=unique_object)
        except (ValueError, UnicodeError) as error:
            raise RuntimeError("proxy startup evidence is not valid JSON") from error
        if not isinstance(record, dict):
            raise RuntimeError("proxy startup evidence is not an object")
        if record.get("event") != "startup":
            continue
        address = record.get("listen")
        match = re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]{0,4})", address or "") if isinstance(address, str) else None
        if not match or int(match[1]) > 65535:
            raise RuntimeError("proxy startup address is not a bound loopback endpoint")
        addresses.append("http://" + address)
    if len(addresses) > 1:
        raise RuntimeError("proxy startup evidence is ambiguous")
    return addresses[0] if addresses else None


def wait_owned_proxy(process, opener, cancellation, timeout=15):
    """A healthy unrelated listener is never a substitute for owned startup."""
    deadline = time.monotonic() + timeout
    while True:
        cancellation.check()
        if process.process.poll() is not None:
            raise RuntimeError("proxy exited before readiness")
        output, count = process.output_snapshot("stdout")
        address = owned_proxy_address(output, count)
        if address:
            try:
                with opener.open(address + "/health", timeout=0.5) as response:
                    if response.status == 200:
                        cancellation.check()
                        if process.process.poll() is not None:
                            raise RuntimeError("proxy exited during readiness")
                        return address
            except (OSError, urllib.error.URLError):
                pass
        if time.monotonic() >= deadline:
            raise RuntimeError("owned proxy readiness deadline expired")
        time.sleep(0.05)


def config_for():
    # Exact synthetic hostname trust is necessary for host-loopback fixtures.
    # No broad IP exemptions, response exemptions, disabled scanners or relaxed
    # actions are used. Defaults supply built-in patterns; this adds a canary.
    return {
        "mode": "strict", "api_allowlist": [HOST], "trusted_domains": [HOST],
        "dns": {"host_overrides": {HOST: ["127.0.0.1"], FORBIDDEN_HOST: ["127.0.0.1"]}},
        "forward_proxy": {"enabled": True},
        "response_scanning": {"enabled": True, "action": "block"},
        "canary_tokens": {"enabled": True, "tokens": [{"name": "browser-repro", "value": CANARY}]},
        "logging": {"format": "json", "output": "stdout", "include_allowed": True, "include_blocked": True},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pipelock", required=True, type=Path, help="explicit candidate binary; never builds/installs automatically")
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory (must not exist)")
    parser.add_argument("--mode", choices=["sandbox", "proxy-only"], default="sandbox")
    parser.add_argument("--node", default=shutil.which("node"))
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    parser.add_argument("--bundle-bytes", type=int, default=2_000_000)
    args = parser.parse_args()
    if not args.node or not args.chromium:
        parser.error("Node 22+ and Chromium are required; pass explicit executable paths")
    args.pipelock = args.pipelock.resolve(strict=True)
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700, parents=False)
    os.umask(0o077)
    report = {"schema": 1, "mode": args.mode, "status": "incomplete", "containment": "not_established",
              "scope": "generated HTTP fixtures only; no production acceptance", "processes": {}, "versions": {}}
    cancellation = Cancellation()
    cancellation.install()
    try:
        report.update({
            "binary_sha256": hashlib.sha256(args.pipelock.read_bytes()).hexdigest(),
            "source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10).strip(),
            "tracked_diff_sha256": hashlib.sha256(subprocess.check_output(["git", "diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--"], cwd=ROOT, timeout=10)).hexdigest(),
            "source_status": subprocess.check_output(["git", "-c", "core.fsmonitor=false", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT, text=True, timeout=10).splitlines(),
            "supervisor_sha256": hashlib.sha256(SUPERVISOR.read_bytes()).hexdigest(),
            "harness_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in HERE.iterdir() if path.suffix in (".py", ".mjs")},
        })
        with tempfile.TemporaryDirectory(prefix="browser-repro-") as temporary, Fixture(args.bundle_bytes) as fixture:
            work = Path(temporary)
            env = isolated_environment(work)
            identity = node_identity(probe([args.node, "-p", NODE_IDENTITY], "identity-node",
                                          args.output, env, work, cancellation, report))
            report["versions"]["node"] = {"exit_code": 0, "version": identity["version"]}
            chromium_version = probe([args.chromium, "--version"], "version-chromium",
                                     args.output, env, work, cancellation, report)
            report["versions"]["chromium"] = {"exit_code": 0, "version": chromium_version[:1024]}
            # The workspace is already the explicit writable/execute grant. Copy
            # this selected executable rather than widening host directory access.
            node_runtime = work / "node-runtime"
            report["node_runtime"] = {**identity, **copy_node_runtime(identity, node_runtime)}
            copied = node_identity(probe([str(node_runtime), "-p", NODE_IDENTITY], "identity-node-copy",
                                        args.output, env, work, cancellation, report))
            if copied != {"exec_path": str(node_runtime.resolve()), "version": identity["version"]}:
                raise RuntimeError("copied Node runtime identity does not match the selected runtime")
            report["node_runtime"]["copied_identity_verified"] = True
            env["PIPELOCK_CONFIG"] = str(work / "pipelock.json")
            write_json(work / "pipelock.json", config_for())
            write_json(args.output / "config.json", config_for())
            report["config_sha256"] = hashlib.sha256((work / "pipelock.json").read_bytes()).hexdigest()
            report["bundle_sha256"] = hashlib.sha256(fixture.bundle).hexdigest()
            report["bundle_bytes"] = len(fixture.bundle)
            report["parent_net_namespace"] = os.readlink("/proc/self/ns/net")
            # Parent witness is independent of the contained client, and the
            # dynamically selected fixture listener is known to be alive.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"http://127.0.0.1:{fixture.port}/health", timeout=2) as response:
                report["parent_fixture_witness"] = response.status
            for name in ("driver.mjs", "contracts.mjs"):
                shutil.copyfile(HERE / name, work / name)
            settings = {"mode": args.mode, "port": fixture.port, "canary": CANARY,
                        "chromium": str(Path(args.chromium).resolve()), "profile": str(work / "profile"),
                        "output": str(work), "parent_net_namespace": report["parent_net_namespace"]}
            proxy_process = None
            driver_process = None
            try:
                if args.mode == "proxy-only":
                    report["containment"] = "not_tested_proxy_only"
                    proxy_process = Process([str(args.pipelock), "run", "--config", env["PIPELOCK_CONFIG"], "--listen", "127.0.0.1:0"],
                                            args.output / "proxy", env, work, cancellation)
                    settings["proxy"] = wait_owned_proxy(proxy_process, opener, cancellation)
                    report["proxy_startup_address"] = settings["proxy"]
                write_json(work / "settings.json", settings)
                command = [str(node_runtime), str(work / "driver.mjs"), str(work / "settings.json")]
                if args.mode == "sandbox":
                    preflight = Process([str(args.pipelock), "sandbox", "--strict", "--dry-run", "--json", "--config", env["PIPELOCK_CONFIG"], "--workspace", str(work), "--", "/usr/bin/true"], args.output / "preflight", env, work, cancellation)
                    try:
                        report["preflight_exit"] = preflight.wait(timeout=20)
                    finally:
                        report["processes"]["preflight"] = preflight.stop()
                    command = [str(args.pipelock), "sandbox", "--strict", "--config", env["PIPELOCK_CONFIG"], "--workspace", str(work), "--", *command]
                driver_process = Process(command, args.output / "driver", env, work, cancellation)
                code = driver_process.wait(timeout=180)
                report["driver_exit"] = code
                if (work / "browser.json").exists():
                    browser = json.loads((work / "browser.json").read_text())
                    write_json(args.output / "browser.json", browser)
                    report["status"] = browser["status"] if code == 0 else "fail"
                    if args.mode == "sandbox" and report.get("preflight_exit") != 0:
                        report["status"] = "fail"
                        report["failure"] = "strict preflight was not ready; actual launch retained for diagnosis only"
                    if args.mode == "sandbox" and report["status"] == "complete":
                        report["containment"] = "strict_launch_and_own_endpoint_boundary_observed"
                    for image in work.glob("*.png"):
                        shutil.copyfile(image, args.output / image.name)
                        (args.output / image.name).chmod(0o600)
                else:
                    report["status"] = "fail"
                    report["failure"] = "browser result absent; inspect driver.stderr for the exact launch refusal"
            finally:
                cleanup_errors = []
                for name, process in (("driver", driver_process), ("proxy", proxy_process)):
                    if process:
                        try:
                            if name == "proxy" and process.process.poll() is not None:
                                cleanup_errors.append("proxy exited during diagnostics")
                            report["processes"][name] = process.stop()
                            if name == "proxy" and report["processes"][name]["exit_code"] != 128 + signal.SIGTERM:
                                cleanup_errors.append("proxy did not remain live until owned shutdown")
                        except Exception as error:
                            cleanup_errors.append(f"{name}: {error}")
                write_json(args.output / "fixture.json", fixture.evidence())
                if cleanup_errors:
                    raise RuntimeError("; ".join(cleanup_errors))
                if args.mode == "sandbox" and driver_process and not (work / "browser.json").exists():
                    stderr = (args.output / "driver.stderr").read_text(errors="replace")
                    if "unix proxy listen:" in stderr and "operation not permitted" in stderr:
                        report["status"] = "refused"
                        report["failure"] = "strict sandbox Unix proxy listener refused: operation not permitted"
                    elif "sandbox layer unavailable" in stderr or "FATAL: Landlock" in stderr:
                        report["status"] = "refused"
                        report["failure"] = "required sandbox layer unavailable; see driver.stderr"
            # Two allowed /health arrivals are expected: parent witness and
            # mediated positive control. Every blocked control must stay away.
            report["health_arrivals"] = fixture.evidence()["counts"].get("/health", 0)
            if report["status"] == "complete" and report["health_arrivals"] != 2:
                report["status"] = "fail"
                report["failure"] = "unexpected fixture health arrival; negative-control attribution failed"
            if report["status"] == "complete":
                evidence = fixture.evidence()
                for scenario in ("error", "incomplete", "pending"):
                    if evidence["scenario_counts"].get(scenario) != 1:
                        report["status"] = "fail"
                        report["failure"] = f"intended {scenario} fixture was not observed exactly once"
                if evidence["counts"].get("/response-marker") != 1:
                    report["status"] = "fail"
                    report["failure"] = "response marker did not reach fixture exactly once before response scanning"
                auth = evidence["auth_counts"]
                report["auth_observations"] = auth
                if (auth.get("session_submissions") != 1 or auth.get("session_acceptances") != 1
                        or auth.get("session_rejections", 0) != 0
                        or auth.get("account_authenticated", 0) < 2
                        or auth.get("account_login_required", 0) < 2):
                    report["status"] = "fail"
                    report["failure"] = "fixture did not corroborate login, restart and cookie-clearing recovery"
        cancellation.check()
    except Exception as error:
        report["status"] = "fail"
        report["failure"] = str(error)
    finally:
        try:
            if cancellation.signum is not None:
                report["status"] = "fail"
                report["interrupted_signal"] = cancellation.signum
                report.setdefault("failure", f"runner interrupted by signal {cancellation.signum}")
            write_json(args.output / "summary.json", report)
        finally:
            cancellation.restore()
    print(json.dumps({"status": report["status"], "mode": args.mode, "containment": report["containment"], "output": str(args.output)}))
    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
