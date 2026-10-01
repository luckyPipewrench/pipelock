# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Source-only managed-adapter contracts, not managed-host acceptance tests.

Filesystem and native Node checks use real temporary files and the installed
runtime. Directory-ownership fixtures are explicitly mocked because these tests
must not create a root-owned installation, invoke contain, or change host policy.
"""

import argparse
import contextlib
import copy
import errno
import io
import importlib.util
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import managed
from run import NODE_IDENTITY, Process, SUPERVISOR, node_identity


# Keep this independent of managed_config: a changed production policy must not
# silently change the expected test policy at the same time.
def expected_config(port=8888):
    return {
        "mode": "strict",
        "api_allowlist": ["browser.fixture.example"],
        "trusted_domains": ["browser.fixture.example"],
        "dns": {"host_overrides": {"browser.fixture.example": ["127.0.0.1"],
                                   "forbidden.fixture.example": ["127.0.0.1"]}},
        "forward_proxy": {"enabled": True},
        "response_scanning": {"enabled": True, "action": "block"},
        "canary_tokens": {"enabled": True, "tokens": [{"name": "browser-repro", "value": ""}]},
        "logging": {"format": "json", "output": "stdout", "include_allowed": True, "include_blocked": True},
        "fetch_proxy": {"listen": f"127.0.0.1:{port}"},
        "metrics_listen": "127.0.0.1:9091",
        "flight_recorder": {"signing_key_path": "/etc/pipelock/keys/flight-recorder-signing.key"},
    }


def manifest_fixture():
    config = expected_config()
    # A generated marker is public synthetic data, not an environment credential.
    from fixture import CANARY
    config["canary_tokens"]["tokens"][0]["value"] = CANARY
    return {
        "schema": 1,
        "purpose": "pipelock-disposable-synthetic-browser-v1",
        "installation_id": "01" * 16,
        "workspace": "/srv/pipelock-browser-repro/" + "01" * 16,
        "proxy_port": 8888,
        "pipelock_sha256": "ab" * 32,
        "node": {"path": "/usr/local/bin/node", "sha256": "cd" * 32},
        "chromium": {"path": "/usr/lib/chromium/chromium", "sha256": "ef" * 32},
        "source_sha256": {name: "12" * 32 for name in (
            "driver.mjs", "contracts.mjs", "managed.py", "run.py", "fixture.py", "ci_process_supervisor.py")},
        "configuration": config,
    }


def workspace_fixture(manifest):
    return {"workspaces": [{"path": manifest["workspace"], "mode": "read-write",
                            "agent_user": "pipelock-agent", "owner": "synthetic-operator",
                            "created": "2026-10-01T00:00:00Z", "reason": "generated browser fixture"}]}


class ManagedJSONTests(unittest.TestCase):
    def test_decode_accepts_only_json_with_unique_keys_and_finite_numbers(self):
        self.assertEqual(managed.decode_json(b'{"outer":{"enabled":true},"items":[1,2]}'),
                         {"outer": {"enabled": True}, "items": [1, 2]})
        for raw in ('mode: strict\n', '{"x":1,"x":2}', '{"outer":{"x":1,"x":2}}',
                    '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}', '{} trailing',
                    '{}\n{}', '', '{"mode":"strict",}'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, TypeError)):
                managed.decode_json(raw)

    def test_generated_policy_matches_independent_exact_fixture(self):
        expected = manifest_fixture()["configuration"]
        self.assertEqual(managed.managed_config(8888), expected)
        first = managed.managed_config(8888)
        first["api_allowlist"].append("unrelated.example")
        self.assertEqual(managed.managed_config(8888), expected)
        for port in (1024, 65535):
            self.assertEqual(managed.managed_config(port)["fetch_proxy"]["listen"], f"127.0.0.1:{port}")
        for port in (None, True, False, "8888", 8888.0, 0, 1023, 65536, 9091):
            with self.subTest(port=port), self.assertRaises(ValueError):
                managed.managed_config(port)

    def test_manifest_accepts_exact_synthetic_identity(self):
        manifest = manifest_fixture()
        self.assertEqual(managed.validate_manifest(manifest), manifest)
        managed.validate_config(copy.deepcopy(manifest["configuration"]), manifest)

    def test_manifest_rejects_wrong_schema_missing_extra_or_nonsynthetic_identity(self):
        manifest = manifest_fixture()
        invalid = [None, [], "synthetic"]
        for key in manifest:
            altered = copy.deepcopy(manifest)
            del altered[key]
            invalid.append(altered)
        for key, value in (("schema", True), ("schema", 1.0), ("schema", 2),
                           ("purpose", "production"), ("installation_id", "../outside"),
                           ("installation_id", "AB" * 16), ("workspace", "/srv/pipelock-browser-repro"),
                           ("workspace", manifest["workspace"] + "/../other"),
                           ("pipelock_sha256", "AB" * 32), ("pipelock_sha256", "ab" * 31),
                           ("pipelock_sha256", None), ("proxy_port", True),
                           ("source_sha256", {}), ("unrequested", True)):
            invalid.append({**copy.deepcopy(manifest), key: value})
        for index, value in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(ValueError):
                managed.validate_manifest(value)

    def test_manifest_rejects_ambiguous_executable_and_source_fields(self):
        for executable in ("node", "chromium"):
            for entry in (None, [], {}, {"path": "/native", "sha256": "ab" * 32, "extra": 1},
                          {"path": "relative/native", "sha256": "ab" * 32},
                          {"path": "/native/../other", "sha256": "ab" * 32},
                          {"path": "/native//other", "sha256": "ab" * 32},
                          {"path": "/native/./other", "sha256": "ab" * 32},
                          {"path": "/native/", "sha256": "ab" * 32},
                          {"path": 1, "sha256": "ab" * 32},
                          {"path": "/native", "sha256": "invalid"}):
                manifest = manifest_fixture()
                manifest[executable] = entry
                with self.subTest(executable=executable, entry=entry), self.assertRaises(ValueError):
                    managed.validate_manifest(manifest)
        for mutate in (lambda source: source.update({"extra.py": "ab" * 32}),
                       lambda source: source.update({"run.py": True}),
                       lambda source: source.pop("fixture.py")):
            manifest = manifest_fixture()
            mutate(manifest["source_sha256"])
            with self.assertRaises(ValueError):
                managed.validate_manifest(manifest)

    def test_policy_rejects_changed_values_extra_keys_and_boolean_integer_aliases(self):
        mutations = (
            lambda cfg: cfg.update({"mode": "audit"}),
            lambda cfg: cfg.update({"sandbox": {"enabled": False}}),
            lambda cfg: cfg["api_allowlist"].append("unrelated.example"),
            lambda cfg: cfg["trusted_domains"].append("*.example"),
            lambda cfg: cfg["response_scanning"].update({"action": "warn"}),
            lambda cfg: cfg["response_scanning"].update({"patterns": []}),
            lambda cfg: cfg["response_scanning"].update({"enabled": 1}),
            lambda cfg: cfg["forward_proxy"].update({"enabled": 1}),
            lambda cfg: cfg["canary_tokens"].update({"enabled": 1}),
            lambda cfg: cfg["logging"].update({"include_allowed": 1}),
            lambda cfg: cfg["logging"].update({"include_blocked": None}),
            lambda cfg: cfg["fetch_proxy"].update({"listen": "0.0.0.0:8888"}),
            lambda cfg: cfg["dns"]["host_overrides"].update({"browser.fixture.example": ["192.0.2.1"]}),
        )
        for index, mutate in enumerate(mutations):
            manifest = manifest_fixture()
            changed = copy.deepcopy(manifest["configuration"])
            mutate(changed)
            with self.subTest(index=index, location="installed"), self.assertRaises(ValueError):
                managed.validate_config(changed, manifest)
            manifest["configuration"] = changed
            with self.subTest(index=index, location="manifest"), self.assertRaises(ValueError):
                managed.validate_manifest(manifest)

    def test_workspace_requires_one_exact_explicit_agent_grant(self):
        manifest = manifest_fixture()
        valid = workspace_fixture(manifest)
        managed.validate_workspace_inventory(valid, manifest)
        invalid = [None, [], {}, {"workspaces": None}, {"workspaces": []},
                   {**valid, "other": []}, {"workspaces": valid["workspaces"] * 2},
                   {"workspaces": [None]}]
        for key, value in (("path", "/srv/unrelated"), ("path", manifest["workspace"] + "/child"),
                           ("mode", "read-only"), ("agent_user", ""), ("agent_user", "other-agent"),
                           ("owner", ""), ("created", "")):
            changed = copy.deepcopy(valid)
            changed["workspaces"][0][key] = value
            invalid.append(changed)
        for key in ("agent_user", "owner", "created"):
            changed = copy.deepcopy(valid)
            del changed["workspaces"][0][key]
            invalid.append(changed)
        for key, value in (("owner", True), ("created", 2026), ("reason", []),
                           ("expires", None), ("unapproved_metadata", "synthetic")):
            changed = copy.deepcopy(valid)
            changed["workspaces"][0][key] = value
            invalid.append(changed)
        for index, value in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(ValueError):
                managed.validate_workspace_inventory(value, manifest)

    def test_registry_pins_one_native_node_target_and_refuses_ambiguity(self):
        manifest = manifest_fixture()
        valid = "# Generated synthetic fixture\n\nbrowser-repro-node /usr/local/bin/node\n"
        managed.validate_registry(valid, manifest)
        managed.validate_registry(valid + "claude /usr/local/bin/claude\ncodex /usr/local/bin/codex\n", manifest)
        for raw in ("", "node /usr/local/bin/node\n", "browser-repro-node\n",
                    "browser-repro-node /usr/local/bin/node extra\n", valid + valid,
                    valid + "unapproved /usr/local/bin/unapproved\n",
                    "browser-repro-node /usr/local/bin/version-manager\n",
                    "browser-repro-node /usr/local/bin/../bin/node\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                managed.validate_registry(raw, manifest)


def proxy_fixture(manifest, config_hash):
    return {
        "active_state": "active", "sub_state": "running", "pid": 321,
        "start_ticks": 2468, "start_unix_ns": 1_000_000_000_000,
        "config_mtime_ns": 999_000_000_000, "exe_path": "/usr/local/bin/pipelock",
        "argv": ["/usr/local/bin/pipelock", "run", "--config", "/etc/pipelock/pipelock.yaml",
                 "--capture-output", "/var/lib/pipelock/captures"],
        "installed_sha256": manifest["pipelock_sha256"], "running_sha256": manifest["pipelock_sha256"],
        "config_sha256": config_hash,
    }


def lifecycle_fixture(outcome="complete"):
    expected = {"argv_sha256": "aa" * 32, "binary_sha256": "bb" * 32,
                "config_sha256": "cc" * 32, "posture_capsule_sha256": "dd" * 32}
    run_id = "01" * 16
    invocation_id = "23" * 16
    unit = f"pipelock-contain-{run_id}.service"
    record = {
        "schema": 1, "phase": "complete", "final": True, "admission_observed": True, "argv_observed": True,
        "cleanup_complete": True, "cgroup_empty": True, "cancelled": False,
        "run_id": run_id, "invocation_id": invocation_id, "unit": unit,
        "control_group": f"/system.slice/{unit}", **expected, "policy_sha256": "ee" * 32,
        "admission_timeout_seconds": 3, "cleanup_timeout_seconds": 12,
        "client_wait_timeout_seconds": 2, "stop_requested": False, "kill_requested": False,
        "terminal": {"Id": unit, "LoadState": "loaded", "ActiveState": "inactive",
                     "SubState": "dead", "MainPID": "0", "InvocationID": invocation_id},
    }
    # superviseLifecycleService publishes incomplete for a failed or cancelled
    # command even when stopLifecycleService verified the owned cgroup empty.
    if outcome != "complete":
        record["phase"] = "incomplete"
        record["failure"] = "context canceled" if outcome == "cancelled" else "exit status 7"
        record["cancelled"] = outcome == "cancelled"
        record["terminal"]["ActiveState"] = "failed"
        record["terminal"]["SubState"] = "failed"
    return record, expected


def fixture_evidence():
    return {
        "counts": {"/health": 2, "/response-marker": 1},
        "scenario_counts": {"error": 1, "incomplete": 1, "pending": 1},
        "auth_counts": {"session_submissions": 1, "session_acceptances": 1,
                        "session_rejections": 0, "account_authenticated": 2, "account_login_required": 2},
    }


class ManagedBindingTests(unittest.TestCase):
    def test_failed_and_cancelled_lifecycle_cleanup_is_not_success_acceptance(self):
        for outcome in ("failed", "cancelled"):
            record, expected = lifecycle_fixture(outcome)
            with self.subTest(outcome=outcome):
                self.assertEqual(managed.validate_lifecycle_cleanup(record, expected), record)
                with self.assertRaisesRegex(ValueError, "lifecycle is incomplete"):
                    managed.validate_lifecycle(record, expected)
                for field in ("final", "admission_observed", "argv_observed", "cleanup_complete", "cgroup_empty"):
                    with self.subTest(missing=field), self.assertRaises(ValueError):
                        managed.validate_lifecycle_cleanup({**record, field: False}, expected)
                for field in expected:
                    with self.subTest(mismatch=field), self.assertRaises(ValueError):
                        managed.validate_lifecycle_cleanup({**record, field: "ff" * 32}, expected)
                for field, value in (("phase", "admitted"), ("cancelled", 1),
                                     ("terminal", {"Id": record["unit"], "LoadState": "loaded",
                                                   "ActiveState": "active", "MainPID": "321"})):
                    with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                        managed.validate_lifecycle_cleanup({**record, field: value}, expected)

    def test_argv_digest_matches_go_encoding_json_golden_bytes(self):
        argv = ["browser-repro-node", "<>&", "\u2028\u2029", "café", '"\\\n']
        # Independent encoding/json.Marshal golden bytes: Go escapes HTML and
        # Unicode separators but leaves non-ASCII letters as UTF-8.
        go_json = r'["browser-repro-node","\u003c\u003e\u0026","\u2028\u2029","café","\"\\\n"]'.encode("utf-8")
        self.assertEqual(json.loads(go_json), argv)
        self.assertEqual(managed.argv_sha256(argv), hashlib.sha256(go_json).hexdigest())
        self.assertNotEqual(managed.argv_sha256(["node", "a b"]), managed.argv_sha256(["node", "a", "b"]))

    def test_running_proxy_requires_candidate_config_process_and_exact_command(self):
        manifest = manifest_fixture()
        config_hash = "34" * 32
        original = proxy_fixture(manifest, config_hash)
        managed.validate_running_proxy(original, manifest, config_hash)
        changes = (
            ("active_state", "inactive"), ("sub_state", "exited"), ("pid", True), ("pid", 1),
            ("pid", "321"), ("start_ticks", 0), ("start_ticks", True),
            ("exe_path", "/usr/local/bin/pipelock (deleted)"), ("installed_sha256", "ef" * 32),
            ("running_sha256", "ef" * 32), ("running_sha256", None), ("config_sha256", "ef" * 32),
            ("argv", original["argv"][:4]), ("argv", original["argv"] + ["--listen", "0.0.0.0:8888"]),
            ("argv", ["/usr/bin/pipelock", *original["argv"][1:]]),
            ("argv", [*original["argv"][:-1], "/var/lib/pipelock/other"]),
            ("start_unix_ns", True), ("config_mtime_ns", True),
            ("config_mtime_ns", original["start_unix_ns"] + 1),
        )
        for key, value in changes:
            changed = copy.deepcopy(original)
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                managed.validate_running_proxy(changed, manifest, config_hash)
        for key in original:
            changed = copy.deepcopy(original)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                managed.validate_running_proxy(changed, manifest, config_hash)

    def test_lifecycle_requires_complete_independently_bound_service_evidence(self):
        record, expected = lifecycle_fixture()
        self.assertEqual(managed.validate_lifecycle(record, expected), record)
        for state in ("inactive", "failed"):
            changed = copy.deepcopy(record)
            changed["terminal"]["ActiveState"] = state
            managed.validate_lifecycle(changed, expected)
        unloaded = copy.deepcopy(record)
        unloaded["terminal"] = {"Id": record["unit"], "LoadState": "not-found"}
        managed.validate_lifecycle(unloaded, expected)
        for value in (None, [], {}, {"exit_code": 0}, {"schema": 1, "exit_code": 0},
                      {**record, "phase": "admitted", "exit_code": 0},
                      {**record, "cleanup_complete": False, "exit_code": 0},
                      {**record, "cgroup_empty": False, "exit_code": 0}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                managed.validate_lifecycle(value, expected)

    def test_lifecycle_rejects_missing_fields_bool_aliases_and_cancellation(self):
        record, expected = lifecycle_fixture()
        for key in record:
            changed = copy.deepcopy(record)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                managed.validate_lifecycle(changed, expected)
        for key, value in (("schema", True), ("schema", 1.0), ("schema", 2),
                           ("phase", "refused"), ("phase", "cleanup"), ("cancelled", True),
                           ("cancelled", 0), ("failure", "synthetic failure")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                managed.validate_lifecycle({**record, key: value}, expected)
        for key in ("final", "admission_observed", "argv_observed", "cleanup_complete", "cgroup_empty"):
            for value in (False, 1, "true", None):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    managed.validate_lifecycle({**record, key: value}, expected)
        for key in ("stop_requested", "kill_requested"):
            for value in (1, 0, "false", None):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    managed.validate_lifecycle({**record, key: value}, expected)

    def test_lifecycle_rejects_stale_bindings_inconsistent_units_and_live_terminal(self):
        record, expected = lifecycle_fixture()
        for key in expected:
            for value in ("00" * 32, "AA" * 32, None, "not-a-digest"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    managed.validate_lifecycle({**record, key: value}, expected)
        for key, value in (("run_id", "stale"), ("run_id", "45" * 16),
                           ("invocation_id", "AB" * 16), ("invocation_id", "45" * 16),
                           ("invocation_id", "0" * 32), ("run_id", "0" * 32),
                           ("unit", "pipelock.service"), ("control_group", "/system.slice/other.service"),
                           ("policy_sha256", "missing"), ("policy_sha256", None),
                           ("terminal", None), ("terminal", {}),
                           ("terminal", {"ActiveState": "active", "SubState": "running"}),
                           ("terminal", {"ActiveState": "inactive", "InvocationID": "45" * 16})):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                managed.validate_lifecycle({**record, key: value}, expected)

    def test_terminal_unit_and_dead_pid_are_independent_of_client_exit(self):
        record, expected = lifecycle_fixture()
        original = record["terminal"]
        for key, value in (("Id", "pipelock.service"), ("Id", None),
                           ("ActiveState", "active"), ("ActiveState", "activating"),
                           ("MainPID", "321"), ("MainPID", 0), ("MainPID", False),
                           ("MainPID", None), ("InvocationID", "45" * 16)):
            changed = {**record, "exit_code": 0, "terminal": {**original, key: value}}
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                managed.validate_lifecycle(changed, expected)
        for invocation in (None, "", record["invocation_id"]):
            changed = {**record, "terminal": {**original, "InvocationID": invocation}}
            managed.validate_lifecycle(changed, expected)
        vanished = {**record, "terminal": {"Id": record["unit"], "LoadState": "not-found"}}
        managed.validate_lifecycle(vanished, expected)

    def test_lifecycle_deadlines_are_bounded_strict_integers(self):
        record, expected = lifecycle_fixture()
        for key, maximum in (("admission_timeout_seconds", 3), ("cleanup_timeout_seconds", 12),
                             ("client_wait_timeout_seconds", 2)):
            for value in (1, maximum):
                managed.validate_lifecycle({**record, key: value}, expected)
            for value in (None, True, False, 0, -1, maximum + 1, float(maximum), str(maximum)):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    managed.validate_lifecycle({**record, key: value}, expected)

    def test_fixture_acceptance_requires_independent_origin_and_auth_arrivals(self):
        original = fixture_evidence()
        managed.fixture_acceptance(original)
        changes = [
            ("counts", "/health", 1), ("counts", "/health", 3),
            ("counts", "/response-marker", 0), ("counts", "/response-marker", 2),
            ("auth_counts", "session_submissions", 0), ("auth_counts", "session_acceptances", 0),
            ("auth_counts", "session_rejections", 1), ("auth_counts", "account_authenticated", 1),
            ("auth_counts", "account_login_required", 1),
        ]
        changes += [("scenario_counts", name, value) for name in ("error", "incomplete", "pending")
                    for value in (0, 2)]
        for group, key, value in changes:
            changed = copy.deepcopy(original)
            changed[group][key] = value
            with self.subTest(group=group, key=key, value=value), self.assertRaises(ValueError):
                managed.fixture_acceptance(changed)

    def test_disposable_acknowledgment_and_root_gate_precede_all_host_reads(self):
        args = argparse.Namespace(acknowledge_disposable_synthetic_host=False)
        with patch("managed.read_regular", side_effect=AssertionError("host file read")), \
                patch("managed.executable_identity", side_effect=AssertionError("runtime read")), \
                patch("managed.validate_installation", side_effect=AssertionError("host inspection")):
            with self.assertRaisesRegex(ValueError, "acknowledgment"):
                managed.run_managed(args)
            args.acknowledge_disposable_synthetic_host = True
            with patch("managed.os.geteuid", return_value=1000), patch("managed.sys.platform", "linux"):
                with self.assertRaisesRegex(ValueError, "root"):
                    managed.run_managed(args)
            with patch("managed.os.geteuid", return_value=0), patch("managed.sys.platform", "darwin"):
                with self.assertRaisesRegex(ValueError, "Linux"):
                    managed.run_managed(args)


class ManagedFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "evidence.json"
        self.path.write_bytes(b'{"synthetic":true}\n')
        self.path.chmod(0o600)

    def test_reads_real_bounded_file_and_checks_owner(self):
        raw = self.path.read_bytes()
        self.assertEqual(managed.read_regular(self.path, limit=len(raw), owner=os.getuid()), raw)
        with self.assertRaises(ValueError):
            managed.read_regular(self.path, limit=len(raw) - 1)
        with self.assertRaises(ValueError):
            managed.read_regular(self.path, owner=os.getuid() + 1)

    def root_controlled_policy_facts(self, file_owner=0, file_mode=0o644,
                                     ancestor=None, ancestor_owner=0, ancestor_mode=0o755):
        real_fstat = os.fstat
        component = 0
        def observe(fd):
            nonlocal component
            fields = list(real_fstat(fd))
            directory = stat.S_ISDIR(fields[0])
            fields[4] = 0 if directory else file_owner
            fields[0] = stat.S_IFMT(fields[0]) | (0o755 if directory else file_mode)
            if directory:
                if component == ancestor:
                    fields[4] = ancestor_owner
                    fields[0] = stat.S_IFDIR | ancestor_mode
                component += 1
            return os.stat_result(fields)
        # Substitute only owner/mode facts. File reads, type, size, aliases and
        # descriptor-relative traversal remain real and confined to temp files.
        return patch("managed.os.fstat", side_effect=observe)

    def test_installed_policy_accepts_root_owned_readable_modes_without_requiring_private(self):
        for mode in (0o400, 0o444, 0o600, 0o640, 0o644):
            with self.subTest(mode=oct(mode)), self.root_controlled_policy_facts(file_mode=mode):
                self.assertEqual(managed.read_regular(self.path, root_controlled=True), self.path.read_bytes())
        with self.root_controlled_policy_facts(file_mode=0o644), \
                self.assertRaisesRegex(ValueError, "owner-only"):
            managed.read_regular(self.path, owner=0, private=True, root_controlled=True)

    def test_installed_policy_rejects_untrusted_file_even_when_contents_match(self):
        expected = self.path.read_bytes()
        for owner, mode in ((1234, 0o600), (1234, 0o644), (0, 0o620), (0, 0o602), (0, 0o666)):
            with self.subTest(owner=owner, mode=oct(mode)), \
                    self.root_controlled_policy_facts(file_owner=owner, file_mode=mode), \
                    self.assertRaisesRegex(ValueError, "not root-controlled"):
                managed.read_regular(self.path, root_controlled=True)
            self.assertEqual(self.path.read_bytes(), expected)

    def test_installed_policy_checks_every_ancestor_including_filesystem_root(self):
        for ancestor in range(len(self.path.parts) - 1):
            for owner, mode in ((1234, 0o755), (0, 0o775), (0, 0o757), (0, 0o1777)):
                with self.subTest(ancestor=ancestor, owner=owner, mode=oct(mode)), \
                        self.root_controlled_policy_facts(ancestor=ancestor,
                            ancestor_owner=owner, ancestor_mode=mode), \
                        self.assertRaisesRegex(ValueError, "untrusted parent"):
                    managed.read_regular(self.path, root_controlled=True)

    def test_installed_policy_still_refuses_leaf_and_parent_symlinks_and_hardlinks(self):
        leaf = self.root / "policy-link"
        leaf.symlink_to(self.path)
        parent = self.root / "policy-directory-link"
        parent.symlink_to(self.root, target_is_directory=True)
        for path in (leaf, parent / self.path.name):
            with self.subTest(path=path), self.root_controlled_policy_facts(), \
                    self.assertRaises((OSError, ValueError)):
                managed.read_regular(path, root_controlled=True)
        alias = self.root / "policy-hardlink"
        alias.hardlink_to(self.path)
        for path in (self.path, alias):
            with self.subTest(path=path), self.root_controlled_policy_facts(), \
                    self.assertRaisesRegex(ValueError, "one bounded regular file"):
                managed.read_regular(path, root_controlled=True)

    def test_read_limit_is_enforced_again_after_metadata_check(self):
        real_fstat = os.fstat
        def stale_size(fd):
            info = real_fstat(fd)
            if stat.S_ISREG(info.st_mode):
                fields = list(info)
                fields[6] = 0
                return os.stat_result(fields)
            return info
        # Simulate a growing file's stale size; the bytes are genuinely longer.
        with patch("managed.os.fstat", side_effect=stale_size):
            with self.assertRaisesRegex(ValueError, "size bound"):
                managed.read_regular(self.path, limit=2)

    def test_refuses_symlinks_at_leaf_or_parent_and_hardlink_aliases(self):
        leaf = self.root / "leaf-link"
        leaf.symlink_to(self.path)
        directory = self.root / "directory"
        directory.mkdir()
        parent = self.root / "parent-link"
        parent.symlink_to(directory, target_is_directory=True)
        (directory / "file").write_text("synthetic")
        for path in (leaf, parent / "file"):
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                managed.read_regular(path)
        alias = self.root / "hardlink"
        alias.hardlink_to(self.path)
        for path in (self.path, alias):
            with self.subTest(path=path), self.assertRaises(ValueError):
                managed.read_regular(path)

    def test_refuses_nonregular_files_without_blocking_and_unclean_paths(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        for path in (fifo, self.root, self.root / "missing", Path("relative"), self.root / ".." / self.root.name / self.path.name):
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                managed.read_regular(path)

    def trusted_directory_fstat(self):
        # Only ancestor trust is unavailable in this unprivileged test runner.
        # Preserve real leaf ownership, type, link count, size and permissions.
        real_fstat = os.fstat
        def synthetic_ancestors(fd):
            info = real_fstat(fd)
            if stat.S_ISDIR(info.st_mode):
                fields = list(info)
                fields[0] &= ~0o022
                fields[4] = os.getuid()
                return os.stat_result(fields)
            return info
        return patch("managed.os.fstat", side_effect=synthetic_ancestors)

    def test_private_output_parent_rejects_writable_aliased_and_nonroot_ancestors(self):
        real_lstat = Path.lstat
        def root_owned(path):
            info = real_lstat(path)
            fields = list(info)
            fields[4] = 0
            if not path.is_relative_to(self.root):
                fields[0] &= ~0o022
            return os.stat_result(fields)
        # Mock host ancestor ownership/modes; preserve the actual controlled
        # subtree's mode and symlink type, including on ordinary sticky /tmp.
        with patch("managed.Path.lstat", root_owned):
            managed.require_private_parent(self.root / "new-output")
            for mode in (0o770, 0o707):
                self.root.chmod(mode)
                with self.subTest(mode=oct(mode)), self.assertRaises(ValueError):
                    managed.require_private_parent(self.root / "new-output")
            self.root.chmod(0o700)
            alias = self.root / "alias"
            alias.symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(ValueError):
                managed.require_private_parent(alias / "new-output")
            for path in (Path("relative/output"), self.root / ".." / "new-output"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    managed.require_private_parent(path)
        def untrusted_owner(path):
            fields = list(real_lstat(path))
            fields[4] = 1234
            return os.stat_result(fields)
        with patch("managed.Path.lstat", untrusted_owner), self.assertRaises(ValueError):
            managed.require_private_parent(self.root / "new-output")

    def root_owned_runtime_facts(self, untrusted=None, special=0):
        real_lstat = Path.lstat
        def observe(path):
            fields = list(real_lstat(path))
            fields[4] = 1234 if path == untrusted else 0
            if path == self.path:
                fields[0] |= special
            # Only unmanaged ancestors are substituted. The controlled temp
            # tree preserves actual type, mode, and link count.
            if not path.is_relative_to(self.root):
                fields[0] &= ~0o022
            return os.stat_result(fields)
        return patch("managed.Path.lstat", observe)

    def test_privileged_runtime_requires_root_control_even_when_bytes_match(self):
        self.path.write_bytes(b"\x7fELFgenerated-never-executed-runtime-fixture")
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        for mode in (0o500, 0o700, 0o750, 0o755):
            self.path.chmod(mode)
            with self.subTest(accepted=oct(mode)), self.root_owned_runtime_facts():
                managed.require_root_runtime(self.path)
        for mode in (0o600, 0o775, 0o702, 0o722, 0o777):
            self.path.chmod(mode)
            with self.subTest(refused=oct(mode)), self.root_owned_runtime_facts(), self.assertRaises(ValueError):
                managed.require_root_runtime(self.path)
            self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), digest)
        self.path.chmod(0o755)
        for untrusted in (self.path, self.root):
            with self.subTest(nonroot=untrusted), self.root_owned_runtime_facts(untrusted), self.assertRaises(ValueError):
                managed.require_root_runtime(self.path)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), digest)

    def test_privileged_runtime_rejects_special_mode_bits_without_changing_host_modes(self):
        self.path.chmod(0o755)
        for special in (stat.S_ISUID, stat.S_ISGID, stat.S_ISUID | stat.S_ISGID):
            # Only observed metadata is substituted; no setuid/setgid bit is set.
            with self.subTest(special=special), self.root_owned_runtime_facts(special=special), \
                    patch("managed.os.getxattr") as capabilities, self.assertRaises(ValueError):
                managed.require_root_runtime(self.path)
            capabilities.assert_not_called()
        self.assertEqual(self.path.stat().st_mode & 0o7777, 0o755)

    def test_privileged_runtime_capability_check_requires_conclusive_absence(self):
        self.path.chmod(0o755)
        for value in (b"synthetic-present-capability", b""):
            with self.subTest(present=value), self.root_owned_runtime_facts(), \
                    patch("managed.os.getxattr", return_value=value) as capabilities, \
                    self.assertRaisesRegex(ValueError, "must not carry"):
                managed.require_root_runtime(self.path)
            capabilities.assert_called_once_with(self.path, "security.capability", follow_symlinks=False)
        for code in (errno.EACCES, errno.EOPNOTSUPP, errno.EIO, errno.EINTR):
            with self.subTest(inconclusive=code), self.root_owned_runtime_facts(), \
                    patch("managed.os.getxattr", side_effect=OSError(code, "synthetic unavailable")), \
                    self.assertRaisesRegex(ValueError, "could not be verified"):
                managed.require_root_runtime(self.path)
        with self.root_owned_runtime_facts(), \
                patch("managed.os.getxattr", side_effect=OSError(errno.ENODATA, "synthetic absent")):
            managed.require_root_runtime(self.path)

    def test_privileged_runtime_refuses_real_aliases_nonregular_files_and_writable_parents(self):
        self.path.chmod(0o755)
        leaf = self.root / "runtime-link"
        leaf.symlink_to(self.path)
        directory_alias = self.root / "directory-alias"
        directory_alias.symlink_to(self.root, target_is_directory=True)
        fifo = self.root / "runtime-fifo"
        os.mkfifo(fifo, 0o700)
        with self.root_owned_runtime_facts():
            for path in (leaf, directory_alias / self.path.name, self.root, fifo, self.root / "missing"):
                with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                    managed.require_root_runtime(path)
            self.root.chmod(0o770)
            with self.assertRaisesRegex(ValueError, "untrusted parent"):
                managed.require_root_runtime(self.path)
            self.root.chmod(0o700)
            alias = self.root / "runtime-hardlink"
            alias.hardlink_to(self.path)
            for path in (self.path, alias):
                with self.subTest(hardlink=path), self.assertRaises(ValueError):
                    managed.require_root_runtime(path)

    def test_staging_separates_operator_owned_sources_from_agent_writable_data(self):
        work = self.root / "run-synthetic"
        agent = SimpleNamespace(pw_uid=1234, pw_gid=1235)
        settings = {"mode": "managed-contain", "profile": str(work / "profile"),
                    "output": str(work / "results")}
        # chown is the only unavailable host operation. No real account or
        # permission grant is created; actual temp files/modes are inspected.
        with patch("managed.os.chown") as chown:
            managed.stage_driver(work, settings, agent)
        expected = [(work, 0, agent.pw_gid)]
        for name in ("driver.mjs", "contracts.mjs", "settings.json"):
            expected.append((work / name, 0, agent.pw_gid))
            self.assertEqual((work / name).stat().st_mode & 0o777, 0o640)
        for name in ("profile", "results"):
            expected.append((work / name, agent.pw_uid, agent.pw_gid))
            self.assertEqual((work / name).stat().st_mode & 0o777, 0o700)
            self.assertEqual(list((work / name).iterdir()), [])
        self.assertEqual([call.args for call in chown.call_args_list], expected)
        self.assertEqual(work.stat().st_mode & 0o777, 0o750)
        self.assertEqual(json.loads((work / "settings.json").read_text()), settings)
        for name in ("driver.mjs", "contracts.mjs"):
            self.assertEqual((work / name).read_bytes(), (managed.HERE / name).read_bytes())
        (work / "profile" / "synthetic-cookie").write_text("generated-only")
        with patch("managed.os.chown") as chown, self.assertRaises(FileExistsError):
            managed.stage_driver(work, settings, agent)
        chown.assert_not_called()
        self.assertEqual((work / "profile" / "synthetic-cookie").read_text(), "generated-only")

    def test_private_evidence_uses_real_leaf_mode_with_mocked_trusted_ancestors(self):
        with self.trusted_directory_fstat():
            self.assertEqual(managed.read_regular(self.path, owner=os.getuid(), private=True), self.path.read_bytes())
            for mode in (0o640, 0o604, 0o602, 0o601, 0o660, 0o777):
                self.path.chmod(mode)
                with self.subTest(mode=oct(mode)), self.assertRaises(ValueError):
                    managed.read_regular(self.path, owner=os.getuid(), private=True)

    def test_private_evidence_refuses_actual_group_writable_parent(self):
        self.root.chmod(0o770)
        with self.assertRaisesRegex(ValueError, "untrusted parent"):
            managed.read_regular(self.path, owner=os.getuid(), private=True)

    def test_executable_identity_rejects_shell_launchers_and_nonexecutable_bytes(self):
        launcher = self.root / "launcher"
        launcher.write_text("#!/bin/sh\nexit 0\n")
        launcher.chmod(0o750)
        with self.assertRaisesRegex(ValueError, "native Linux"):
            managed.executable_identity(launcher)
        self.path.write_bytes(b"\x7fELFsynthetic-not-an-executable")
        with self.assertRaisesRegex(ValueError, "unavailable"):
            managed.executable_identity(self.path)
        for path in (self.root, self.root / "missing"):
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                managed.executable_identity(path)

    def test_prepare_writes_only_new_private_synthetic_artifacts_without_launching(self):
        selected = shutil.which("node")
        if not selected:
            self.skipTest("installed native executable required for source-only preparation")
        observed = subprocess.run([selected, "-p", NODE_IDENTITY], check=True,
                                  capture_output=True, text=True, timeout=5,
                                  cwd=self.root, env={"PATH": "/usr/bin:/bin", "HOME": str(self.root)})
        native = Path(node_identity(observed.stdout.strip())["exec_path"])
        # Use one known native executable for all identity slots. This only
        # checks preparation, whose result explicitly does not claim acceptance.
        args = argparse.Namespace(pipelock=native, node=native, chromium=native,
                                  proxy_port=8888, output=self.root / "prepared")
        output = io.StringIO()
        with patch("run.subprocess.Popen", side_effect=AssertionError("preparation launched a process")), \
                patch("managed.require_root_runtime", side_effect=AssertionError("preparation required root ownership")):
            with contextlib.redirect_stdout(output):
                self.assertEqual(managed.prepare(args), 0)
        status = json.loads(output.getvalue())
        self.assertEqual(status["status"], "prepared_only")
        self.assertEqual({path.name for path in args.output.iterdir()}, {"manifest.json", "pipelock.json"})
        self.assertEqual(args.output.stat().st_mode & 0o777, 0o700)
        manifest = json.loads((args.output / "manifest.json").read_text())
        managed.validate_manifest(manifest)
        config = json.loads((args.output / "pipelock.json").read_text())
        self.assertEqual(config, manifest_fixture()["configuration"])
        self.assertEqual(config, manifest["configuration"])
        before = {path.name: path.read_bytes() for path in args.output.iterdir()}
        for path in args.output.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            managed.prepare(args)
        self.assertEqual(before, {path.name: path.read_bytes() for path in args.output.iterdir()})

    def test_real_native_node_identity_hash_and_registered_path_are_bound(self):
        selected = shutil.which("node")
        if not selected:
            self.skipTest("installed Node required for the native runtime identity oracle")
        # The only launched program is a generated one-shot Node identity query.
        observed = subprocess.run([selected, "-p", NODE_IDENTITY], check=True,
                                  capture_output=True, text=True, timeout=5,
                                  cwd=self.root, env={"PATH": "/usr/bin:/bin", "HOME": str(self.root)})
        runtime = node_identity(observed.stdout.strip())
        native = Path(runtime["exec_path"])
        actual = managed.executable_identity(native)
        self.assertEqual(actual, {"path": str(native), "sha256": hashlib.sha256(native.read_bytes()).hexdigest()})
        link = self.root / "selected-node"
        link.symlink_to(native)
        self.assertEqual(managed.executable_identity(link), actual)
        manifest = manifest_fixture()
        manifest["node"] = actual
        managed.validate_registry(f"browser-repro-node {native}\n", manifest)
        with self.assertRaises(ValueError):
            managed.validate_registry(f"browser-repro-node {link}\n", manifest)


class ManagedFailureFlowTests(unittest.TestCase):
    def test_every_installed_policy_read_requires_root_control_before_runtime_checks(self):
        manifest = manifest_fixture()
        responses = {
            managed.INSTALLED_CONFIG: json.dumps(manifest["configuration"]).encode(),
            managed.TOOLS: b"browser-repro-node /usr/local/bin/node\n",
            managed.WORKSPACES: json.dumps(workspace_fixture(manifest)).encode(),
            managed.INTEGRITY_PIN: (manifest["pipelock_sha256"] + "\n").encode(),
        }
        paths = list(responses)
        for refused in paths:
            visited = []
            def read_policy(path, limit, **options):
                self.assertEqual(options, {"root_controlled": True})
                self.assertIn(path, responses)
                visited.append(path)
                if path == refused:
                    raise ValueError("synthetic installed policy is not root-controlled")
                return responses[path]
            with self.subTest(refused=refused), patch("managed.read_regular", side_effect=read_policy), \
                    patch("managed.require_root_runtime") as runtime, \
                    patch("managed.executable_identity") as identity, \
                    patch("managed.require_quiet_agent") as inventory, \
                    self.assertRaisesRegex(ValueError, "not root-controlled"):
                managed.validate_installation(manifest)
            self.assertEqual(visited, paths[:paths.index(refused) + 1])
            runtime.assert_not_called()
            identity.assert_not_called()
            inventory.assert_not_called()

    def test_untrusted_runtime_is_refused_before_privileged_node_probe(self):
        # Use actual installation validation, with generated read-only host
        # responses and ownership observations standing in for a managed VM.
        # No Node query, child process, private host read or chown is performed.
        for refused_name in ("pipelock", "node", "chromium"):
            with self.subTest(refused=refused_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = manifest_fixture()
                args = argparse.Namespace(acknowledge_disposable_synthetic_host=True,
                    pipelock=Path("/synthetic/candidate"), manifest=root / "manifest.json",
                    output=root / "evidence", bundle_bytes=4096)
                responses = {
                    args.manifest: json.dumps(manifest).encode(),
                    managed.INSTALLED_CONFIG: json.dumps(manifest["configuration"]).encode(),
                    managed.TOOLS: b"browser-repro-node /usr/local/bin/node\n",
                    managed.WORKSPACES: json.dumps(workspace_fixture(manifest)).encode(),
                    managed.INTEGRITY_PIN: (manifest["pipelock_sha256"] + "\n").encode(),
                }
                runtime_paths = {"pipelock": managed.INSTALLED_BINARY,
                                 "node": Path(manifest["node"]["path"]),
                                 "chromium": Path(manifest["chromium"]["path"])}
                examined = []
                def ownership_gate(path):
                    path = Path(path)
                    examined.append(path)
                    if path == runtime_paths[refused_name]:
                        raise ValueError("synthetic runtime owner is not root")
                def read_host(path, *args, **kwargs):
                    return responses[Path(path)]
                def identity(path):
                    if Path(path) == args.pipelock:
                        return {"path": str(path), "sha256": manifest["pipelock_sha256"]}
                    for name in ("node", "chromium"):
                        if Path(path) == runtime_paths[name]:
                            return manifest[name]
                    raise AssertionError("unexpected runtime identity request")
                original_is_file = Path.is_file
                def is_file(path):
                    if str(path) == f"/proc/self/task/{os.getpid()}/children":
                        return True
                    return original_is_file(path)
                with contextlib.ExitStack() as stack:
                    launch = Mock(side_effect=AssertionError("managed process launched before ownership gate"))
                    probe = Mock(side_effect=AssertionError("Node was executed before ownership gate"))
                    overrides = {"sys.platform": "linux", "os.geteuid": Mock(return_value=0),
                        "require_private_parent": Mock(), "read_regular": read_host,
                        "executable_identity": identity, "source_hashes": Mock(return_value=manifest["source_sha256"]),
                        "file_sha256": Mock(return_value=manifest["pipelock_sha256"]),
                        "require_root_runtime": ownership_gate, "Path.is_file": is_file,
                        "probe": probe, "Process": launch}
                    for target, replacement in overrides.items():
                        stack.enter_context(patch("managed." + target, replacement))
                    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                    self.assertEqual(managed.run_managed(args), 2)
                    probe.assert_not_called()
                    launch.assert_not_called()
                wanted = [runtime_paths[name] for name in ("pipelock", "node", "chromium")]
                self.assertEqual(examined, wanted[:wanted.index(runtime_paths[refused_name]) + 1])
                report = json.loads((args.output / "summary.json").read_text())
                self.assertEqual(report["status"], "fail")
                self.assertIn("owner is not root", report["failure"])
                self.assertNotIn("node_runtime", report)
                self.assertNotIn("driver_exit", report)

    def test_failed_runs_retain_scratch_until_service_lifecycle_is_verified(self):
        # This is adapter orchestration, not host acceptance: installed identity,
        # root ownership, procfs capability and systemd execution are unavailable
        # boundaries mocked below. The HTTP fixture, generated files, report
        # writes, and safe removal are real and limited to this temporary tree.
        verified_scenarios = ("bound-complete", "nonzero-failed-report", "nonzero-complete-report",
                              "nonzero-missing-report", "nonzero-malformed-report", "nonzero-symlink-report",
                              "nonzero-save-failed-report", "nonzero-screenshot-invalid", "nonzero-screenshot-save-failed",
                              "nonzero-summary-save-failed", "nonzero-final-summary-save-failed",
                              "nonzero-cancelled-report", "zero-cancelled-report", "cleanup-signal",
                              "zero-failed-report", "zero-malformed-report", "zero-screenshot-invalid")
        for scenario in ("missing", "partial", "local-cleanup-failed", "accessibility-failed", *verified_scenarios):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace_root = root / "workspace-root"
                manifest = manifest_fixture()
                manifest["workspace"] = str(workspace_root / manifest["installation_id"])
                Path(manifest["workspace"]).mkdir(parents=True)
                manifest_path = root / "manifest.json"
                manifest_path.write_text(json.dumps(manifest))
                manifest_path.chmod(0o600)
                args = argparse.Namespace(acknowledge_disposable_synthetic_host=True,
                    pipelock=Path("/synthetic/candidate"), manifest=manifest_path,
                    output=root / "evidence", bundle_bytes=4096)
                config_raw = json.dumps(manifest["configuration"]).encode()
                config_hash = hashlib.sha256(config_raw).hexdigest()
                proof_raw = b"generated synthetic posture binding fixture\n"
                # Generated artifacts use this test process's real ownership;
                # managed host admission remains an explicitly mocked boundary.
                agent = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
                browser_record = {"schema": 1, "mode": "managed-contain", "status": "fail",
                                  "failure": "generated browser failure detail", "cases": []}
                if scenario in ("nonzero-complete-report", "zero-screenshot-invalid", "zero-cancelled-report", "cleanup-signal"):
                    browser_record["status"] = "complete"
                valid_report_scenarios = ("nonzero-failed-report", "nonzero-complete-report", "zero-failed-report",
                    "nonzero-save-failed-report", "nonzero-screenshot-invalid", "nonzero-screenshot-save-failed",
                    "nonzero-summary-save-failed", "nonzero-final-summary-save-failed",
                    "nonzero-cancelled-report", "zero-cancelled-report", "cleanup-signal",
                    "zero-screenshot-invalid")
                png = b"\x89PNG\r\n\x1a\ngenerated screenshot fixture; not rendered pixels"
                driver_exit = 7 if scenario.startswith("nonzero-") else 0
                launched = []
                original_read = managed.read_regular
                original_is_file = Path.is_file
                probes = []
                cancellation = managed.Cancellation()

                def command_probe(command, name, *unused):
                    probes.append(command)
                    if command[0] == "/usr/bin/sudo":
                        self.assertEqual(command[:6], ["/usr/bin/sudo", "-n", "-u", "pipelock-agent", "--", "/usr/bin/test"])
                        if scenario == "accessibility-failed":
                            raise RuntimeError("synthetic agent scratch access refused")
                        return ""
                    return json.dumps({"execPath": manifest["node"]["path"],
                                       "version": "24.0.0", "release": "node"})

                def local_read(path, limit=65536, owner=None, private=False):
                    path = Path(path)
                    if path == Path("/var/lib/pipelock/contain/posture/proof.json"):
                        return proof_raw
                    if scenario == "cleanup-signal" and path == managed.INSTALLED_CONFIG:
                        return config_raw
                    if not path.is_relative_to(root):
                        raise AssertionError(f"unexpected host file read: {path}")
                    return original_read(path, limit=limit)

                def local_or_proc_file(path):
                    if str(path) == f"/proc/self/task/{os.getpid()}/children":
                        return True
                    return original_is_file(path)

                class SyntheticManagedProcess:
                    def __init__(self, command, output, env, cwd, cancellation, signal_grace_seconds):
                        launched.append(command)
                        if signal_grace_seconds != 20:
                            raise AssertionError("managed cleanup grace changed")
                        if scenario == "missing":
                            return
                        outcome = "cancelled" if "cancelled-report" in scenario else "failed" if driver_exit else "complete"
                        record, _ = lifecycle_fixture(outcome)
                        tool_args = command[command.index("--") + 1:]
                        record.update({"argv_sha256": managed.argv_sha256(tool_args),
                            "binary_sha256": manifest["pipelock_sha256"], "config_sha256": config_hash,
                            "posture_capsule_sha256": hashlib.sha256(proof_raw).hexdigest()})
                        if scenario == "partial":
                            record["phase"] = "admitted"
                        lifecycle = args.output / "lifecycle"
                        lifecycle.mkdir(mode=0o700)
                        (lifecycle / "lifecycle.json").write_text(json.dumps(record))
                        (lifecycle / "lifecycle.json").chmod(0o600)
                        artifact = Path(tool_args[1]).parent / "results" / "browser.json"
                        if scenario in valid_report_scenarios:
                            artifact.write_text(json.dumps(browser_record))
                            if scenario == "nonzero-save-failed-report":
                                (args.output / "browser.json").mkdir()
                        elif scenario in ("nonzero-malformed-report", "zero-malformed-report"):
                            artifact.write_text('{"generated":"truncated"')
                        elif scenario == "nonzero-symlink-report":
                            reference = root / "owned-reference.json"
                            reference.write_text(json.dumps(browser_record))
                            artifact.symlink_to(reference)
                        if scenario in verified_scenarios:
                            for name in ("cold.png", "delayed.png"):
                                (artifact.parent / name).write_bytes(png)
                            if scenario in ("nonzero-screenshot-invalid", "zero-screenshot-invalid"):
                                (artifact.parent / "cold.png").write_bytes(b"generated invalid PNG")
                            elif scenario == "nonzero-screenshot-save-failed":
                                (args.output / "cold.png").mkdir()
                            if scenario == "nonzero-summary-save-failed":
                                (args.output / "summary.json").mkdir()
                    def wait(self, timeout):
                        return driver_exit
                    def stop(self):
                        if scenario == "local-cleanup-failed":
                            raise RuntimeError("synthetic local descendant cleanup failed")
                        return {"streams_drained": True, "cleanup": {"cleanup_complete": True,
                                "unexpected_live_descendants": False}, "exit_code": driver_exit}

                original_write_json = managed.write_json
                original_rmtree = shutil.rmtree
                def remove_with_cancellation(path, *args, **kwargs):
                    result = original_rmtree(path, *args, **kwargs)
                    if scenario == "cleanup-signal" and Path(path).parent == Path(manifest["workspace"]):
                        cancellation.interrupted(signal.SIGTERM, None)
                    return result
                remove_with_cancellation.avoids_symlink_attacks = original_rmtree.avoids_symlink_attacks

                summary_writes = 0
                def write_with_late_destination_failure(path, data, **kwargs):
                    nonlocal summary_writes
                    if path == args.output / "summary.json":
                        summary_writes += 1
                        if scenario == "nonzero-final-summary-save-failed" and summary_writes == 2:
                            # Keep the real incomplete snapshot, then cause the
                            # terminal write to fail through actual filesystem I/O.
                            path.rename(args.output / "summary-before-cleanup.json")
                            path.mkdir()
                    return original_write_json(path, data, **kwargs)

                with contextlib.ExitStack() as stack:
                    overrides = {
                        "sys.platform": "linux", "os.geteuid": Mock(return_value=0),
                        "WORKSPACE_ROOT": workspace_root, "read_regular": local_read,
                        "Path.is_file": local_or_proc_file, "require_private_parent": Mock(),
                        "executable_identity": Mock(return_value={"path": str(args.pipelock),
                                                                  "sha256": manifest["pipelock_sha256"]}),
                        "source_hashes": Mock(return_value=manifest["source_sha256"]),
                        "validate_installation": Mock(return_value=(config_raw, agent)),
                        "probe": command_probe,
                        "node_identity": Mock(return_value={"exec_path": manifest["node"]["path"], "version": "24.0.0"}),
                        "proxy_snapshot": Mock(return_value=proxy_fixture(manifest, config_hash)),
                        "os.chown": Mock(), "Process": SyntheticManagedProcess,
                        "Cancellation": Mock(return_value=cancellation),
                    }
                    if scenario == "cleanup-signal":
                        # Supply independently defined successful observations
                        # so the cancellation, not an earlier fixture failure,
                        # determines the terminal state. No browser is launched.
                        overrides.update({"Fixture.evidence": Mock(return_value=fixture_evidence()),
                            "require_root_runtime": Mock(), "require_quiet_agent": Mock(),
                            "executable_identity": lambda path: manifest["node"] if str(path) == manifest["node"]["path"]
                                else manifest["chromium"] if str(path) == manifest["chromium"]["path"]
                                else {"path": str(args.pipelock), "sha256": manifest["pipelock_sha256"]}})
                    for target, replacement in overrides.items():
                        stack.enter_context(patch("managed." + target, replacement))
                    stack.enter_context(patch("run.write_json", write_with_late_destination_failure))
                    stack.enter_context(patch("run.shutil.rmtree", remove_with_cancellation))
                    stdout = io.StringIO()
                    stack.enter_context(contextlib.redirect_stdout(stdout))
                    self.assertEqual(managed.run_managed(args), 2)
                self.assertEqual(len(probes), 2)
                if scenario == "accessibility-failed":
                    self.assertEqual(launched, [])
                else:
                    self.assertEqual(len(launched), 1)
                    self.assertEqual(launched[0][:3], ["/usr/local/bin/pipelock", "contain", "run"])
                    self.assertIn("--lifecycle-output", launched[0])
                if scenario in ("nonzero-summary-save-failed", "nonzero-final-summary-save-failed"):
                    console = json.loads(stdout.getvalue())
                    self.assertEqual(console["status"], "fail")
                    self.assertEqual(console["containment"], "not_established")
                    self.assertEqual(console["driver_exit"], 7)
                    self.assertIn("summary_write_error", console)
                    self.assertEqual(json.loads((args.output / "browser.json").read_text()), browser_record)
                    self.assertEqual((args.output / "delayed.png").read_bytes(), png)
                    if scenario == "nonzero-summary-save-failed":
                        self.assertFalse(console["workspace_removed"])
                        retained = Path(console["retained_synthetic_workspace"])
                        self.assertTrue(retained.is_relative_to(Path(manifest["workspace"])))
                        self.assertEqual(json.loads((retained / "results" / "browser.json").read_text()), browser_record)
                    else:
                        self.assertTrue(console["workspace_removed"])
                        self.assertNotIn("retained_synthetic_workspace", console)
                        self.assertEqual(list(Path(manifest["workspace"]).iterdir()), [])
                        pending = json.loads((args.output / "summary-before-cleanup.json").read_text())
                        self.assertEqual(pending["status"], "incomplete")
                        self.assertEqual(pending["containment"], "not_established")
                        self.assertEqual(pending["driver_exit"], 7)
                        self.assertEqual(pending["failure"], "contained browser command failed (exit 7)")
                    continue
                report = json.loads((args.output / "summary.json").read_text())
                self.assertEqual(report["status"], "fail")
                self.assertEqual(report["containment"], "not_established")
                if scenario == "accessibility-failed":
                    self.assertNotIn("driver_exit", report)
                    self.assertIn("scratch access refused", report["failure"])
                else:
                    self.assertEqual(report["driver_exit"], driver_exit)
                self.assertEqual((args.output / "summary.json").stat().st_mode & 0o777, 0o600)
                if driver_exit:
                    self.assertEqual(report["failure"], "contained browser command failed (exit 7)")
                if scenario == "cleanup-signal":
                    self.assertEqual(report["interrupted_signal"], signal.SIGTERM)
                if scenario == "zero-cancelled-report":
                    self.assertEqual(report["failure"], "managed service lifecycle is incomplete")
                if scenario in verified_scenarios:
                    if scenario in ("nonzero-save-failed-report", "nonzero-screenshot-save-failed"):
                        self.assertFalse(report["workspace_removed"])
                        retained = Path(report["retained_synthetic_workspace"])
                        self.assertEqual(json.loads((retained / "results" / "browser.json").read_text()), browser_record)
                    else:
                        self.assertTrue(report["workspace_removed"])
                        self.assertEqual(list(Path(manifest["workspace"]).iterdir()), [])
                    self.assertTrue(report["lifecycle_cleanup"]["cleanup_complete"])
                    if driver_exit or scenario == "zero-cancelled-report":
                        self.assertNotIn("lifecycle", report)
                        self.assertEqual(report["lifecycle_cleanup"]["phase"], "incomplete")
                        self.assertTrue(report["lifecycle_cleanup"]["failure"])
                    else:
                        self.assertTrue(report["lifecycle"]["cleanup_complete"])
                    self.assertTrue((args.output / "proof.json").is_file())
                    saved_browser = args.output / "browser.json"
                    self.assertEqual((args.output / "delayed.png").read_bytes(), png)
                    if scenario in ("nonzero-screenshot-invalid", "zero-screenshot-invalid", "nonzero-screenshot-save-failed"):
                        self.assertFalse((args.output / "cold.png").is_file())
                        self.assertIn("screenshot_artifact_error", report)
                        if scenario == "nonzero-screenshot-save-failed":
                            self.assertTrue(report["screenshot_artifact_save_failed"])
                        if scenario == "zero-screenshot-invalid":
                            self.assertEqual(report["failure"], report["screenshot_artifact_error"])
                    else:
                        self.assertEqual((args.output / "cold.png").read_bytes(), png)
                    if scenario in valid_report_scenarios and scenario != "nonzero-save-failed-report":
                        self.assertEqual(report["browser_artifact_status"], "preserved")
                        self.assertEqual(json.loads(saved_browser.read_text()), browser_record)
                        self.assertEqual(saved_browser.stat().st_mode & 0o777, 0o600)
                        self.assertNotIn("browser_artifact_error", report)
                        if scenario == "zero-failed-report":
                            self.assertEqual(report["failure"], "browser diagnostics are incomplete")
                    elif scenario == "nonzero-save-failed-report":
                        self.assertFalse(saved_browser.is_file())
                        self.assertEqual(report["browser_artifact_status"], "save_failed")
                        self.assertIn("could not be saved", report["browser_artifact_error"])
                    else:
                        self.assertFalse(saved_browser.exists())
                        self.assertEqual(report["browser_artifact_status"],
                            "missing" if scenario in ("bound-complete", "nonzero-missing-report") else "rejected")
                        self.assertIn("browser result", report["browser_artifact_error"])
                else:
                    self.assertFalse(report["workspace_removed"])
                    retained = Path(report["retained_synthetic_workspace"])
                    self.assertTrue(retained.is_relative_to(Path(manifest["workspace"])))
                    self.assertTrue((retained / "profile").is_dir())
                    self.assertTrue((retained / "driver.mjs").is_file())
                    self.assertNotIn("lifecycle", report)


class ManagedSupervisorGraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("browser_repro_supervisor_test", SUPERVISOR)
        cls.supervisor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.supervisor)

    def test_process_rejects_invalid_grace_before_capability_checks_or_launch(self):
        for value in (None, True, False, "2", 2.0, 0, 1, 21, -1):
            with self.subTest(value=value), patch("run.subprocess.Popen") as launch,                     patch("run.Path.is_file") as capability:
                with self.assertRaises(ValueError):
                    Process(["unused"], Path("unused"), {}, Path("."), signal_grace_seconds=value)
                launch.assert_not_called()
                capability.assert_not_called()

    def test_process_propagates_default_and_managed_grace_to_supervisor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for kwargs, expected in (({}, 2), ({"signal_grace_seconds": 20}, 20)):
                with self.subTest(grace=expected):
                    # Mock only the unavailable process/procfs boundary. Real
                    # drain threads reach EOF on bounded in-memory byte streams.
                    child = Mock(stdout=io.BytesIO(b"synthetic"), stderr=io.BytesIO())
                    with patch("run.Path.is_file", return_value=True),                             patch("run.subprocess.Popen", return_value=child) as launch:
                        process = Process(["synthetic-command"], root / "child", {}, root, **kwargs)
                    for thread in process.threads:
                        thread.join(timeout=2)
                        self.assertFalse(thread.is_alive())
                    argv = launch.call_args.args[0]
                    self.assertEqual(argv[argv.index("--signal-grace-seconds") + 1], str(expected))
                    self.assertEqual(argv[argv.index("--") + 1:], ["synthetic-command"])
                    self.assertEqual(process.signal_grace_seconds, expected)
                    self.assertTrue(all(process.eof.values()))

    def test_stop_wait_budget_includes_promised_grace_and_existing_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            for grace in (2, 20):
                process = Process.__new__(Process)
                process.signal_grace_seconds = grace
                process.output_lock = threading.Lock()
                process.output = Path(temporary) / f"child-{grace}"
                process.process = Mock(returncode=0)
                process.process.poll.return_value = None
                process.threads = []
                process.buffers = {"stdout": bytearray(), "stderr": bytearray()}
                process.counts = {"stdout": 0, "stderr": 0}
                process.eof = {"stdout": True, "stderr": True}
                process.read_errors = {}
                process.output.with_suffix(".cleanup.json").write_text(json.dumps(
                    {"cleanup_complete": True, "unexpected_live_descendants": False}))
                self.assertTrue(process.stop()["streams_drained"])
                process.process.send_signal.assert_called_once_with(signal.SIGTERM)
                process.process.wait.assert_called_once_with(timeout=grace + 6)

    def test_real_supervisor_cli_rejects_out_of_bounds_before_child_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "must-not-exist"
            program = "from pathlib import Path; Path(" + repr(str(marker)) + ").write_text('unexpected')"
            for value in ("1", "21", "2.0", "true"):
                with self.subTest(value=value):
                    result = subprocess.run([sys.executable, str(SUPERVISOR), "--status-file",
                        str(root / "status.json"), "--signal-grace-seconds", value, "--",
                        sys.executable, "-c", program], check=False, capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("--signal-grace-seconds", result.stderr)
                    self.assertFalse(marker.exists())
                    self.assertFalse((root / "status.json").exists())

    def test_supervisor_cli_default_and_override_reach_existing_supervise_api(self):
        for extra, expected in (([], 2), (["--signal-grace-seconds", "20"], 20)):
            with self.subTest(grace=expected), patch.object(self.supervisor, "supervise", return_value=0) as supervise,                     patch.object(sys, "argv", ["supervisor", "--status-file", "/synthetic/status.json",
                                               *extra, "--", "synthetic-command"]):
                self.assertEqual(self.supervisor.main(), 0)
                supervise.assert_called_once_with(["synthetic-command"], Path("/synthetic/status.json"), expected)

    def test_interrupt_grace_waits_until_deadline_without_killing_unrelated_processes(self):
        process = Mock(pid=4321, returncode=None)
        with patch.object(self.supervisor.os, "killpg") as killpg,                 patch.object(self.supervisor, "reap_exited_children", return_value=True) as reap,                 patch.object(self.supervisor.time, "monotonic", side_effect=[10, 11, 29.9, 30]),                 patch.object(self.supervisor.time, "sleep") as sleep:
            self.supervisor.interrupt_command(process, signal.SIGTERM, 20)
        killpg.assert_called_once_with(4321, signal.SIGTERM)
        self.assertEqual(reap.call_count, 3)
        self.assertEqual(sleep.call_args_list, [unittest.mock.call(0.01), unittest.mock.call(0.01)])
        process.returncode = 0
        with patch.object(self.supervisor.os, "killpg") as killpg:
            self.supervisor.interrupt_command(process, signal.SIGTERM, 20)
        killpg.assert_not_called()

    def test_supervision_still_cleans_owned_children_after_the_full_grace(self):
        supervisor = self.supervisor
        handlers = {}
        observations = []
        process = Mock(pid=4321, returncode=None)
        def install_handler(signum, handler):
            handlers[signum] = handler
        def start_process(*args, **kwargs):
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            return process
        def reap(child):
            self.assertIs(child, process)
            observations.append("reap")
            return True
        def cleanup(child, records):
            self.assertIs(child, process)
            self.assertEqual(records, {})
            observations.append("cleanup")
            return True, False
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            status = Path(temporary) / "status.json"
            for target, replacement in (("signal.signal", install_handler),
                ("enable_child_adoption", Mock()), ("os.getsid", Mock(return_value=1000)),
                ("os.getpid", Mock(return_value=1000)), ("os.killpg", Mock()),
                ("subprocess.Popen", start_process), ("reap_exited_children", reap),
                ("cleanup_children", cleanup),
                ("time.monotonic", Mock(side_effect=[10, 11, 29.9, 30])), ("time.sleep", Mock())):
                parts = target.split(".")
                owner = getattr(supervisor, parts[0]) if len(parts) == 2 else supervisor
                stack.enter_context(patch.object(owner, parts[-1], replacement))
            self.assertEqual(supervisor.supervise(["synthetic-command"], status, 20), 128 + signal.SIGTERM)
            witness = json.loads(status.read_text())
        self.assertEqual(observations, ["reap", "reap", "reap", "cleanup"])
        self.assertTrue(witness["cleanup_complete"])
        self.assertFalse(witness["unexpected_live_descendants"])
        self.assertEqual(witness["exit_code"], 128 + signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
