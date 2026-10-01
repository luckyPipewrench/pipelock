#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Adapt generated browser diagnostics to an explicitly prepared disposable contain VM.

Preparation writes ordinary synthetic artifacts only. Running requires a separately
installed, authorized managed containment boundary. Neither command installs tools,
changes host policy, generates signing keys, or discovers production installations.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import sys
import time
import uuid
import urllib.request

from fixture import CANARY, Fixture
from run import (HERE, ROOT, SUPERVISOR, Cancellation, Process, config_for, file_sha256,
                 isolated_environment, node_identity, NODE_IDENTITY, probe, write_final_report, write_json,
                 copy_browser_screenshots, decode_json, finalize_workspace, preserve_browser_report, read_regular)

SCHEMA = 1
PURPOSE = "pipelock-disposable-synthetic-browser-v1"
INSTALLED_BINARY = Path("/usr/local/bin/pipelock")
INSTALLED_CONFIG = Path("/etc/pipelock/pipelock.yaml")
INTEGRITY_PIN = Path("/etc/pipelock/integrity/binary-pin.sha256")
TOOLS = Path("/etc/pipelock/contain/tools.list")
WORKSPACES = Path("/etc/pipelock/contain/workspaces.json")
WORKSPACE_ROOT = Path("/srv/pipelock-browser-repro")
NODE_TOOL = "browser-repro-node"
MANAGED_SERVICE = "pipelock.service"
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
ID128 = re.compile(r"[0-9a-f]{32}\Z")
PROXY_SERVICE_FIELDS = "Id,LoadState,MainPID,ExecMainPID,ActiveState,SubState,InvocationID"
JOURNAL_FIELDS = "__CURSOR,_BOOT_ID,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_PID,_TRANSPORT,_LINE_BREAK,MESSAGE"


def same_json(left, right):
    # Python equality treats True and 1 as equal; policy identity must not.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def require_private_parent(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("root evidence output must be an absolute clean path")
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("root evidence output has an untrusted parent")


def managed_config(proxy_port):
    if type(proxy_port) is not int or not 1024 <= proxy_port <= 65535 or proxy_port == 9091:
        raise ValueError("proxy port must be 1024..65535 and distinct from metrics port 9091")
    cfg = config_for()
    cfg.update({"fetch_proxy": {"listen": f"127.0.0.1:{proxy_port}"},
                "metrics_listen": "127.0.0.1:9091",
                "flight_recorder": {"signing_key_path": "/etc/pipelock/keys/flight-recorder-signing.key"}})
    return cfg


def validate_manifest(value):
    keys = {"schema", "purpose", "installation_id", "workspace", "proxy_port", "pipelock_sha256",
            "node", "chromium", "source_sha256", "configuration"}
    if not isinstance(value, dict) or set(value) != keys or type(value["schema"]) is not int or value["schema"] != SCHEMA or value["purpose"] != PURPOSE:
        raise ValueError("not an exact synthetic installation manifest")
    if not isinstance(value["installation_id"], str) or not ID128.fullmatch(value["installation_id"]):
        raise ValueError("invalid installation identity")
    expected_workspace = str(WORKSPACE_ROOT / value["installation_id"])
    if value["workspace"] != expected_workspace:
        raise ValueError("workspace must be the dedicated installation directory")
    if not same_json(value["configuration"], managed_config(value["proxy_port"])):
        raise ValueError("manifest policy differs from the generated synthetic policy")
    if not isinstance(value["pipelock_sha256"], str) or not HEX256.fullmatch(value["pipelock_sha256"]):
        raise ValueError("invalid candidate digest")
    for name in ("node", "chromium"):
        entry = value[name]
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise ValueError("invalid executable identity")
        if not isinstance(entry["path"], str) or not entry["path"].startswith("/") or str(Path(entry["path"])) != entry["path"] or ".." in Path(entry["path"]).parts:
            raise ValueError("executable path must be absolute and clean")
        if not isinstance(entry["sha256"], str) or not HEX256.fullmatch(entry["sha256"]):
            raise ValueError("invalid executable digest")
    source = value["source_sha256"]
    if not isinstance(source, dict) or set(source) != {"driver.mjs", "contracts.mjs", "managed.py", "run.py", "fixture.py", "ci_process_supervisor.py"} or any(not isinstance(v, str) or not HEX256.fullmatch(v) for v in source.values()):
        raise ValueError("invalid harness identity")
    return value


def validate_config(actual, manifest):
    if not same_json(actual, managed_config(manifest["proxy_port"])):
        raise ValueError("installed config is not the exact generated synthetic policy")


def validate_workspace_inventory(value, manifest):
    if not isinstance(value, dict) or set(value) != {"workspaces"} or not isinstance(value["workspaces"], list) or len(value["workspaces"]) != 1:
        raise ValueError("exactly one synthetic workspace grant is required")
    grant = value["workspaces"][0]
    if not isinstance(grant, dict) or grant.get("path") != manifest["workspace"] or grant.get("mode") != "read-write" or grant.get("agent_user") != "pipelock-agent":
        raise ValueError("workspace grant is missing, ambiguous or unrelated")
    if not grant.get("owner") or not grant.get("created"):
        raise ValueError("legacy workspace grants are not accepted")
    if set(grant) - {"path", "mode", "agent_user", "owner", "reason", "created", "expires"} or any(not isinstance(v, str) for v in grant.values()):
        raise ValueError("workspace grant metadata is malformed")


def validate_registry(raw, manifest):
    entries = {}
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 2 or fields[0] in entries:
            raise ValueError("ambiguous tool registry")
        entries[fields[0]] = fields[1]
    if entries.get(NODE_TOOL) != manifest["node"]["path"]:
        raise ValueError("registered tool is not the selected native Node runtime")
    # Existing installer defaults may be present on the dedicated VM; no tool
    # other than this pinned Node target is launched by the adapter.
    if set(entries) - {NODE_TOOL, "claude", "codex", "gemini", "playwright"}:
        raise ValueError("unexpected tool registrations on synthetic host")


def source_hashes():
    return {name: file_sha256(SUPERVISOR if name == SUPERVISOR.name else HERE / name)
            for name in ("driver.mjs", "contracts.mjs", "managed.py", "run.py", "fixture.py", SUPERVISOR.name)}


def executable_identity(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("selected executable is unavailable")
    # Version-manager launchers and shell browser wrappers are not runtime
    # identities. Use the native runtime beneath an explicitly selected wrapper.
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise ValueError("select the native Linux executable, not a launcher")
    return {"path": str(path), "sha256": file_sha256(path)}


def require_root_runtime(path):
    # Managed orchestration invokes the Node identity probe as root. Never
    # execute an agent/operator-writable runtime merely because its bytes were
    # previously listed in a manifest; hashes do not grant ownership.
    path = Path(path)
    require_private_parent(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & 0o6022 or not info.st_mode & 0o111):
        raise ValueError("managed native runtimes must be root-owned and not writable by the contained user")
    try:
        os.getxattr(path, "security.capability", follow_symlinks=False)
    except OSError as error:
        if error.errno != errno.ENODATA:
            raise ValueError("managed runtime file capabilities could not be verified") from error
    else:
        raise ValueError("managed native runtimes must not carry file capabilities")


def prepare(args):
    candidate = executable_identity(args.pipelock)
    instance = uuid.uuid4().hex
    manifest = {"schema": SCHEMA, "purpose": PURPOSE, "installation_id": instance,
                "workspace": str(WORKSPACE_ROOT / instance), "proxy_port": args.proxy_port,
                "pipelock_sha256": candidate["sha256"], "node": executable_identity(args.node),
                "chromium": executable_identity(args.chromium), "source_sha256": source_hashes(),
                "configuration": managed_config(args.proxy_port)}
    validate_manifest(manifest)
    args.output.mkdir(mode=0o700)
    write_json(args.output / "manifest.json", manifest)
    write_json(args.output / "pipelock.json", manifest["configuration"])
    print(json.dumps({"status": "prepared_only", "output": str(args.output), "workspace": manifest["workspace"],
                      "host_setup": "separate explicit operator authorization required; no installation performed"}))
    return 0


def validate_running_proxy(snapshot, manifest, config_hash):
    digest = manifest["pipelock_sha256"]
    if (snapshot.get("active_state") != "active" or snapshot.get("sub_state") != "running"
            or type(snapshot.get("pid")) is not int or snapshot["pid"] <= 1
            or type(snapshot.get("start_ticks")) is not int or snapshot["start_ticks"] <= 0
            or snapshot.get("unit") != MANAGED_SERVICE
            or type(snapshot.get("exec_main_pid")) is not int or snapshot["exec_main_pid"] != snapshot["pid"]
            or snapshot.get("exe_path") != str(INSTALLED_BINARY)
            or snapshot.get("installed_sha256") != digest or snapshot.get("running_sha256") != digest
            or snapshot.get("config_sha256") != config_hash):
        raise ValueError("candidate is not bound to the installed and running managed proxy")
    argv = snapshot.get("argv")
    prefix = [str(INSTALLED_BINARY), "run", "--config", str(INSTALLED_CONFIG)]
    if argv != prefix + ["--capture-output", "/var/lib/pipelock/captures"]:
        raise ValueError("running managed proxy command differs from expected config")
    for name in ("invocation_id", "boot_id"):
        value = snapshot.get(name)
        if not isinstance(value, str) or not ID128.fullmatch(value) or value == "0" * 32:
            raise ValueError("managed proxy invocation identity is missing")
    identity = snapshot.get("config_identity")
    names = {"dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"}
    if (not isinstance(identity, dict) or set(identity) != names
            or any(type(value) is not int or value < 0 for value in identity.values())
            or not stat.S_ISREG(identity["mode"]) or identity["mode"] & 0o022
            or identity["uid"] != 0 or identity["nlink"] != 1 or identity["ino"] == 0
            or identity["size"] > 32768):
        raise ValueError("managed config file identity is missing or untrusted")
    validate_proxy_startup(snapshot.get("startup"), snapshot, manifest, config_hash)


def validate_proxy_startup(record, snapshot, manifest, config_hash):
    # These underscore fields come from journald, not the JSON written by the
    # application. PID plus unit invocation and boot excludes another launch.
    trusted = {"_PID": str(snapshot["pid"]), "_SYSTEMD_UNIT": MANAGED_SERVICE,
               "_SYSTEMD_INVOCATION_ID": snapshot["invocation_id"], "_BOOT_ID": snapshot["boot_id"],
               "_TRANSPORT": "stdout"}
    if (not isinstance(record, dict) or any(record.get(key) != value for key, value in trusted.items())
            or "_LINE_BREAK" in record or not isinstance(record.get("__CURSOR"), str)
            or not re.fullmatch(r"\S{1,256}", record["__CURSOR"])
            or not isinstance(record.get("MESSAGE"), str) or len(record["MESSAGE"].encode("utf-8")) > 2048):
        raise ValueError("managed proxy startup journal identity is missing or ambiguous")
    message = decode_json(record["MESSAGE"])
    if (not isinstance(message, dict) or message.get("event") != "startup"
            or message.get("config_hash") != config_hash or message.get("mode") != "strict"
            or message.get("listen") != f"127.0.0.1:{manifest['proxy_port']}"):
        raise ValueError("managed proxy startup does not witness the loaded synthetic config")


def proxy_startup(command_probe, snapshot, manifest, config_hash):
    # Config.Hash in the startup event hashes the bytes actually loaded by the
    # proxy. Never infer that digest from a later read of its configuration file.
    # Also refuse observed reload records. Their absence is NOT proof that no
    # reload occurred: this diagnostic requires a quiescent, trusted-operator VM.
    raw = command_probe(["/usr/bin/journalctl", "--system", "--no-pager", "--all", "--output=json",
                         "--output-fields=" + JOURNAL_FIELDS, "--lines=3",
                         "_SYSTEMD_UNIT=" + MANAGED_SERVICE, "_PID=" + str(snapshot["pid"]),
                         "_SYSTEMD_INVOCATION_ID=" + snapshot["invocation_id"],
                         "_BOOT_ID=" + snapshot["boot_id"],
                         '--grep="event"[[:space:]]*:[[:space:]]*"(startup|config_reload)"'], "proxy-startup")
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 4096:
        raise ValueError("managed proxy startup journal exceeds its bound")
    lines = raw.splitlines()
    if len(lines) != 1:
        raise ValueError("managed proxy startup journal is missing, ambiguous or contains a reload")
    record = decode_json(lines[0])
    validate_proxy_startup(record, snapshot, manifest, config_hash)
    return record


def proxy_config_identity(config_raw):
    def identity(info):
        return {name: getattr(info, "st_" + name) for name in
                ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")}
    before = identity(INSTALLED_CONFIG.lstat())
    fresh = read_regular(INSTALLED_CONFIG, 32768, root_controlled=True)
    after = identity(INSTALLED_CONFIG.lstat())
    if before != after or fresh != config_raw or len(fresh) != after["size"]:
        raise ValueError("managed config changed during identity check")
    return after


def process_start(pid):
    # The comm field can contain spaces and parentheses; fields after its final
    # closing parenthesis are fixed kernel stat fields, not command arguments.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[19])


def proxy_service(command_probe):
    raw = command_probe(["/usr/bin/systemctl", "show", MANAGED_SERVICE,
                         "--property=" + PROXY_SERVICE_FIELDS], "proxy-service")
    fields = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise ValueError("ambiguous managed service observation")
        fields[key] = value
    if (set(fields) != set(PROXY_SERVICE_FIELDS.split(",")) or fields["Id"] != MANAGED_SERVICE
            or fields["LoadState"] != "loaded" or fields["ActiveState"] != "active"
            or fields["SubState"] != "running" or not re.fullmatch(r"[1-9][0-9]*", fields["MainPID"])
            or int(fields["MainPID"]) <= 1 or fields["ExecMainPID"] != fields["MainPID"]
            or not ID128.fullmatch(fields["InvocationID"]) or fields["InvocationID"] == "0" * 32):
        raise ValueError("managed proxy service identity is missing or not running")
    return fields


def proxy_snapshot(command_probe, manifest, config_raw):
    require_root_runtime(INSTALLED_BINARY)
    fields = proxy_service(command_probe)
    pid = int(fields["MainPID"])
    start = process_start(pid)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if str(uuid.UUID(boot)) != boot or uuid.UUID(boot).int == 0:
        raise ValueError("managed proxy boot identity is missing")
    exe_path = os.readlink(f"/proc/{pid}/exe")
    running_hash = file_sha256(Path(f"/proc/{pid}/exe"))
    if exe_path != str(INSTALLED_BINARY) or running_hash != manifest["pipelock_sha256"]:
        raise ValueError("managed service is not the prepared candidate")
    argv_raw = read_regular(Path(f"/proc/{pid}/cmdline"), 4096)
    argv = argv_raw.rstrip(b"\0").decode("utf-8").split("\0")
    config_hash = hashlib.sha256(config_raw).hexdigest()
    value = {"active_state": fields.get("ActiveState"), "sub_state": fields.get("SubState"), "pid": pid,
             "unit": fields["Id"], "exec_main_pid": int(fields["ExecMainPID"]),
             "invocation_id": fields["InvocationID"], "boot_id": uuid.UUID(boot).hex, "start_ticks": start,
             "exe_path": exe_path, "argv": argv, "installed_sha256": file_sha256(INSTALLED_BINARY),
             "running_sha256": running_hash, "config_sha256": config_hash,
             "config_identity": proxy_config_identity(config_raw)}
    value["startup"] = proxy_startup(command_probe, value, manifest, config_hash)
    if proxy_service(command_probe) != fields or proxy_config_identity(config_raw) != value["config_identity"]:
        raise ValueError("managed proxy service or config changed during identity check")
    if process_start(pid) != start:
        raise ValueError("managed proxy process changed during identity check")
    validate_running_proxy(value, manifest, config_hash)
    return value


def require_quiet_agent(uid):
    entries = list(Path("/proc").iterdir())
    if len(entries) > 16384:
        raise ValueError("process inventory exceeds synthetic-host budget")
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text()
            row = next(line for line in status.splitlines() if line.startswith("Uid:"))
            if uid in [int(value) for value in row.split()[1:]]:
                raise ValueError("contained user already has a process; synthetic VM must be idle")
        except FileNotFoundError:
            continue


def validate_installation(manifest):
    config_raw = read_regular(INSTALLED_CONFIG, 32768, root_controlled=True)
    validate_config(decode_json(config_raw), manifest)
    validate_registry(read_regular(TOOLS, 16384, root_controlled=True).decode("utf-8"), manifest)
    validate_workspace_inventory(decode_json(read_regular(WORKSPACES, 16384, root_controlled=True)), manifest)
    pin = read_regular(INTEGRITY_PIN, 512, root_controlled=True).decode("ascii").split()
    require_root_runtime(INSTALLED_BINARY)
    if not pin or pin[0] != manifest["pipelock_sha256"] or file_sha256(INSTALLED_BINARY) != manifest["pipelock_sha256"]:
        raise ValueError("installed candidate integrity pin differs")
    if source_hashes() != manifest["source_sha256"]:
        raise ValueError("harness changed since synthetic preparation")
    for name in ("node", "chromium"):
        require_root_runtime(manifest[name]["path"])
        if executable_identity(manifest[name]["path"]) != manifest[name]:
            raise ValueError("selected native executable changed")
    workspace = Path(manifest["workspace"])
    if workspace.resolve(strict=True) != workspace or not workspace.is_dir():
        raise ValueError("approved synthetic workspace is unavailable or aliased")
    if any(workspace.iterdir()):
        raise ValueError("synthetic workspace must be empty before launch")
    agent = pwd.getpwnam("pipelock-agent")
    if agent.pw_uid == 0 or agent.pw_gid == 0:
        raise ValueError("contained runtime identity must be nonroot")
    require_quiet_agent(agent.pw_uid)
    return config_raw, agent


def create_agent_directory(path, uid, gid):
    path.mkdir(mode=0o700)
    os.chown(path, uid, gid)


def stage_driver(work, settings, agent):
    # Only newly created generated data is shared. The report/lifecycle evidence
    # stays in a different root-private tree, outside the agent's workspace.
    work.mkdir(mode=0o750)
    os.chown(work, 0, agent.pw_gid)
    work.chmod(0o750)
    for name in ("driver.mjs", "contracts.mjs"):
        target = work / name
        target.write_bytes((HERE / name).read_bytes())
        os.chown(target, 0, agent.pw_gid)
        target.chmod(0o640)
    target = work / "settings.json"
    target.write_text(json.dumps(settings) + "\n", encoding="utf-8")
    os.chown(target, 0, agent.pw_gid)
    target.chmod(0o640)
    create_agent_directory(work / "profile", agent.pw_uid, agent.pw_gid)
    create_agent_directory(work / "results", agent.pw_uid, agent.pw_gid)


def fixture_acceptance(evidence):
    if evidence["counts"].get("/health", 0) != 2:
        raise ValueError("negative-control fixture arrival attribution failed")
    if any(evidence["scenario_counts"].get(name) != 1 for name in ("error", "incomplete", "pending")):
        raise ValueError("expected application scenario did not arrive exactly once")
    if evidence["counts"].get("/response-marker") != 1:
        raise ValueError("response marker origin witness is missing")
    auth = evidence["auth_counts"]
    if (auth.get("session_submissions") != 1 or auth.get("session_acceptances") != 1
            or auth.get("session_rejections", 0) != 0 or auth.get("account_authenticated", 0) < 2
            or auth.get("account_login_required", 0) < 2):
        raise ValueError("fixture did not witness authentication, restart and cookie clearing")


def argv_sha256(argv):
    # Match Go encoding/json for the existing contain argument digest.
    raw = json.dumps(argv, ensure_ascii=False, separators=(",", ":"))
    for value, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                           ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        raw = raw.replace(value, escaped)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def validate_lifecycle_cleanup(value, expected):
    """Verify owned service cleanup independently of the command's outcome."""
    if not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1:
        raise ValueError("lifecycle report is missing or unsupported")
    if (value.get("phase") not in ("complete", "incomplete") or any(value.get(name) is not True for name in
            ("final", "admission_observed", "argv_observed", "cleanup_complete", "cgroup_empty"))
            or type(value.get("cancelled")) is not bool):
        raise ValueError("managed service cleanup is incomplete")
    run_id, invocation_id = value.get("run_id"), value.get("invocation_id")
    if (not isinstance(run_id, str) or not ID128.fullmatch(run_id) or run_id == "0" * 32
            or not isinstance(invocation_id, str) or not ID128.fullmatch(invocation_id) or invocation_id == "0" * 32):
        raise ValueError("managed service identity is missing")
    unit = f"pipelock-contain-{run_id}.service"
    if value.get("unit") != unit or value.get("control_group") != f"/system.slice/{unit}":
        raise ValueError("managed service identity is inconsistent")
    for name in ("argv_sha256", "binary_sha256", "config_sha256", "posture_capsule_sha256"):
        if not isinstance(value.get(name), str) or not HEX256.fullmatch(value[name]) or value[name] != expected[name]:
            raise ValueError("lifecycle identity does not match this browser invocation")
    if not isinstance(value.get("policy_sha256"), str) or not HEX256.fullmatch(value["policy_sha256"]):
        raise ValueError("lifecycle policy identity is missing")
    for name, maximum in (("admission_timeout_seconds", 3), ("cleanup_timeout_seconds", 12), ("client_wait_timeout_seconds", 2)):
        if type(value.get(name)) is not int or not 0 < value[name] <= maximum:
            raise ValueError("lifecycle deadline contract exceeds runner cancellation budget")
    for name in ("stop_requested", "kill_requested"):
        if type(value.get(name)) is not bool:
            raise ValueError("lifecycle action status is ambiguous")
    terminal = value.get("terminal")
    if (not isinstance(terminal, dict) or terminal.get("Id") != unit or
            (terminal.get("LoadState") != "not-found" and
             (terminal.get("ActiveState") not in ("inactive", "failed") or terminal.get("MainPID") != "0"))):
        raise ValueError("terminal service state is missing")
    if terminal.get("InvocationID") not in (None, "", invocation_id):
        raise ValueError("terminal service belongs to another invocation")
    return value


def validate_lifecycle(value, expected):
    validate_lifecycle_cleanup(value, expected)
    if value.get("phase") != "complete" or value.get("cancelled") is not False or value.get("failure"):
        raise ValueError("managed service lifecycle is incomplete")
    return value


def run_managed(args):
    # No host state is inspected until the explicit operator declaration and
    # root-private generated manifest have passed. A declaration is not proof
    # the host has never held secrets; exact config/workspace/runtime checks
    # reject mismatches, and the report preserves that trust boundary.
    if not args.acknowledge_disposable_synthetic_host:
        raise ValueError("explicit disposable synthetic-only VM acknowledgment is required")
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("managed diagnostic requires the separately authorized Linux VM operator (root)")
    manifest = validate_manifest(decode_json(read_regular(args.manifest, 32768, owner=0, private=True)))
    candidate = executable_identity(args.pipelock)
    if candidate["sha256"] != manifest["pipelock_sha256"]:
        raise ValueError("explicit candidate differs from prepared manifest")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise ValueError("safe generated-workspace cleanup is unavailable")
    require_private_parent(args.output)
    args.output.mkdir(mode=0o700)
    args.output.chmod(0o700)
    output = args.output.resolve(strict=True)
    if output.is_relative_to(WORKSPACE_ROOT):
        raise ValueError("root evidence must be outside the agent workspace")
    report = {"schema": 1, "mode": "managed-contain", "status": "fail", "containment": "not_established",
              "scope": "generated HTTP fixtures on an operator-declared disposable synthetic-only VM",
              "host_freshness": "operator_declared_not_independently_proven", "processes": {},
              "installation_id": manifest["installation_id"], "binary_sha256": candidate["sha256"],
              "harness_sha256": source_hashes(), "unsupported": ["production authentication", "TLS interception",
              "agent-browser daemon", "managed viewer input and reconnect"]}
    cancellation = Cancellation()
    cancellation.install()
    work = None
    driver_process = None
    try:
        # Preserve the same fail-closed local descendant gate. Managed service
        # cleanup requires its own invocation-bound lifecycle witness as well.
        if not Path(f"/proc/self/task/{os.getpid()}/children").is_file():
            raise ValueError("verified process cleanup unavailable: procfs children file is absent")
        envroot = output / "environment"
        envroot.mkdir(mode=0o700)
        env = isolated_environment(envroot)
        # contain run emits/binds its own capsule. Do not substitute the
        # standalone runner's deliberately absent posture sentinel.
        env.pop("PIPELOCK_POSTURE_PROOF", None)
        config_raw, agent = validate_installation(manifest)
        report["config_sha256"] = hashlib.sha256(config_raw).hexdigest()
        counter = 0
        def command_probe(command, name):
            nonlocal counter
            counter += 1
            return probe(command, f"{counter}-{name}", output, env, output, cancellation, report)
        identity = node_identity(command_probe([manifest["node"]["path"], "-p", NODE_IDENTITY], "node-identity"))
        if identity["exec_path"] != manifest["node"]["path"]:
            raise ValueError("registered Node target is a launcher")
        report["node_runtime"] = identity
        before = proxy_snapshot(command_probe, manifest, config_raw)
        report["proxy_identity"] = before
        with Fixture(args.bundle_bytes) as fixture:
            report["bundle_sha256"] = hashlib.sha256(fixture.bundle).hexdigest()
            report["bundle_bytes"] = len(fixture.bundle)
            parent_namespace = os.readlink("/proc/self/ns/net")
            report["parent_net_namespace"] = parent_namespace
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"http://127.0.0.1:{fixture.port}/health", timeout=2) as response:
                if response.status != 200:
                    raise ValueError("owned fixture is not alive")
            work = Path(manifest["workspace"]) / ("run-" + uuid.uuid4().hex)
            settings = {"mode": "managed-contain", "port": fixture.port, "canary": CANARY,
                        "chromium": manifest["chromium"]["path"], "profile": str(work / "profile"),
                        "output": str(work / "results"), "parent_net_namespace": parent_namespace,
                        "expected_uid": agent.pw_uid, "expected_gid": agent.pw_gid,
                        "expected_node": identity, "expected_proxy": f"http://127.0.0.1:{manifest['proxy_port']}"}
            stage_driver(work, settings, agent)
            command_probe(["/usr/bin/sudo", "-n", "-u", "pipelock-agent", "--", "/usr/bin/test",
                           "-r", str(work / "driver.mjs"), "-a", "-r", str(work / "settings.json"),
                           "-a", "-x", str(work), "-a", "-w", str(work / "profile"),
                           "-a", "-w", str(work / "results"), "-a", "-x", manifest["node"]["path"],
                           "-a", "-x", manifest["chromium"]["path"]], "agent-workspace-access")
            tool_args = [NODE_TOOL, str(work / "driver.mjs"), str(work / "settings.json")]
            # Existing default posture location is part of the verified managed
            # contract. Do not redirect a separately running proxy to another
            # capsule or supply a different signing config.
            command = [str(INSTALLED_BINARY), "contain", "run", "--config", str(INSTALLED_CONFIG),
                       "--port", str(manifest["proxy_port"]), "--lifecycle-output", str(output / "lifecycle"),
                       "--", *tool_args]
            try:
                driver_process = Process(command, output / "driver", env, output, cancellation, signal_grace_seconds=20)
                try:
                    report["driver_exit"] = driver_process.wait(timeout=240)
                except Exception as error:
                    report["driver_wait_error"] = str(error)[:1024]
                    raise
            finally:
                try:
                    if driver_process:
                        report["processes"]["driver"] = driver_process.stop()
                finally:
                    pending_error = sys.exc_info()[1]
                    try:
                        evidence = fixture.evidence()
                        write_json(output / "fixture.json", evidence)
                    except Exception as error:
                        # Keep the cleanup/wait failure primary while exposing
                        # any secondary loss of the in-memory origin witness.
                        report["fixture_artifact_error"] = str(error)[:1024]
                        if pending_error is None:
                            raise
            # An exit-zero client or a surviving report from another launch is
            # never sufficient: require root-owned service and proof bindings.
            lifecycle_raw = read_regular(output / "lifecycle" / "lifecycle.json", 16384, owner=0, private=True)
            lifecycle = decode_json(lifecycle_raw)
            report["lifecycle_diagnostic"] = lifecycle
            proof_raw = read_regular(Path("/var/lib/pipelock/contain/posture/proof.json"), 2 * 1024 * 1024)
            expected = {"argv_sha256": argv_sha256(tool_args), "binary_sha256": candidate["sha256"],
                        "config_sha256": report["config_sha256"], "posture_capsule_sha256": hashlib.sha256(proof_raw).hexdigest()}
            validate_lifecycle_cleanup(lifecycle, expected)
            report["lifecycle_cleanup"] = lifecycle
            (output / "proof.json").write_bytes(proof_raw)
            (output / "proof.json").chmod(0o600)
            # Preserve valid failure diagnostics before verified cleanup can
            # remove the workspace. A report never overrides command failure.
            result_dir = work / "results"
            browser = preserve_browser_report(result_dir, output, "managed-contain", agent.pw_uid, report)
            try:
                copy_browser_screenshots(result_dir, output, agent.pw_uid, report)
            except (OSError, ValueError) as error:
                report["screenshot_artifact_error"] = str(error)[:1024]
            if report["driver_exit"] != 0:
                raise ValueError(f"contained browser command failed (exit {report['driver_exit']})")
            validate_lifecycle(lifecycle, expected)
            report["lifecycle"] = lifecycle
            if browser is None:
                raise ValueError(report["browser_artifact_error"])
            if browser.get("status") != "complete":
                raise ValueError("browser diagnostics are incomplete")
            if "screenshot_artifact_error" in report:
                raise ValueError(report["screenshot_artifact_error"])
            fixture_acceptance(evidence)
            config_after = read_regular(INSTALLED_CONFIG, 32768)
            if config_after != config_raw or proxy_snapshot(command_probe, manifest, config_after) != before:
                raise ValueError("managed proxy changed during diagnostic")
            if source_hashes() != manifest["source_sha256"]:
                raise ValueError("harness changed during diagnostic")
            for name in ("node", "chromium"):
                require_root_runtime(manifest[name]["path"])
                if executable_identity(manifest[name]["path"]) != manifest[name]:
                    raise ValueError("native runtime changed during diagnostic")
            require_quiet_agent(agent.pw_uid)
            report["status"] = "complete"
            report["containment"] = "managed_launch_and_own_endpoint_boundary_observed"
            report["auth_observations"] = evidence["auth_counts"]
        cancellation.check()
    except Exception as error:
        report["status"] = "fail"
        report["failure"] = str(error)[:1024]
    finally:
        try:
            if cancellation.signum is not None:
                report["status"] = "fail"
                report["interrupted_signal"] = cancellation.signum
            if work is not None:
                # Only the invocation-bound, validated service lifecycle can
                # authorize removal; local client cleanup alone is insufficient.
                finalize_workspace(work, output / "summary.json", report,
                                   report.get("lifecycle_cleanup", {}).get("cleanup_complete") is True)
            if cancellation.signum is not None:
                report["status"] = "fail"
                report["interrupted_signal"] = cancellation.signum
            try:
                write_final_report(output / "summary.json", report, cancellation)
            except OSError as error:
                report["status"] = "fail"
                report["containment"] = "not_established"
                report["summary_write_error"] = str(error)[:1024]
        finally:
            cancellation.restore()
    console = {"status": report["status"], "mode": report["mode"],
               "containment": report["containment"], "output": str(output)}
    for name in ("driver_exit", "workspace_removed", "retained_synthetic_workspace", "summary_write_error"):
        if name in report:
            console[name] = report[name]
    print(json.dumps(console))
    return 0 if report["status"] == "complete" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare", help="write synthetic manifest/config only; never install or create keys")
    prep.add_argument("--pipelock", type=Path, required=True)
    prep.add_argument("--node", type=Path, required=True, help="explicit native Node executable")
    prep.add_argument("--chromium", type=Path, required=True, help="explicit native Chromium executable")
    prep.add_argument("--proxy-port", type=int, default=8888)
    prep.add_argument("--output", type=Path, required=True)
    launch = sub.add_parser("run", help="use an explicitly prepared disposable synthetic-only contain VM")
    launch.add_argument("--pipelock", type=Path, required=True)
    launch.add_argument("--manifest", type=Path, required=True)
    launch.add_argument("--output", type=Path, required=True)
    launch.add_argument("--bundle-bytes", type=int, default=2_000_000)
    launch.add_argument("--acknowledge-disposable-synthetic-host", action="store_true")
    args = parser.parse_args()
    try:
        return prepare(args) if args.command == "prepare" else run_managed(args)
    except (ValueError, OSError, KeyError) as error:
        print(json.dumps({"status": "refused", "failure": str(error)[:1024]}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
