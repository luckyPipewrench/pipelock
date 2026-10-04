# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Terminal report contracts using inert observations and real private files."""
import ast
import copy
import errno
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

import managed
import run


class AtomicJSONTests(unittest.TestCase):
    def test_private_complete_file_precedes_the_single_publication_step(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "summary.json"
            before = b'{"status":"incomplete","containment":"not_established"}\n'
            target.write_bytes(before)
            after = {"status": "complete", "containment": "synthetic-observation"}
            original_replace = os.replace
            commits = []
            def observe_commit(source, destination):
                source = Path(source)
                self.assertEqual(source.parent, root)
                self.assertNotEqual(source, target)
                self.assertEqual(target.read_bytes(), before)
                self.assertEqual(source.stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(source.read_bytes()), after)
                commits.append(source)
                original_replace(source, destination)
            with patch("run.os.replace", observe_commit):
                run.write_json(target, after)
            self.assertEqual(len(commits), 1)
            self.assertEqual(json.loads(target.read_bytes()), after)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(root.iterdir()), [target])

    def test_precommit_faults_preserve_the_actual_incomplete_snapshot(self):
        for fault in ("partial-write", "permission", "flush", "close", "replace"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = root / "summary.json"
                before = b'{"status":"incomplete","containment":"not_established"}\n'
                target.write_bytes(before)
                unrelated = root / ".unrelated.tmp"
                unrelated.write_bytes(b"generated unrelated file")
                original_write, original_chmod, original_close = os.write, os.fchmod, os.close
                calls = 0
                def fail_write(fd, raw):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        return original_write(fd, raw[:13])
                    raise OSError(errno.EIO, "generated partial-write failure")
                def fail_permission(fd, mode):
                    original_chmod(fd, mode)
                    raise OSError(errno.EPERM, "generated permission failure")
                def fail_close(fd):
                    original_close(fd)
                    raise OSError(errno.EIO, "generated close failure")
                hooks = {
                    "partial-write": ("write", fail_write), "permission": ("fchmod", fail_permission),
                    "flush": ("fsync", lambda fd: (_ for _ in ()).throw(OSError(errno.EIO, "generated flush failure"))),
                    "close": ("close", fail_close),
                    "replace": ("replace", lambda source, destination: (_ for _ in ()).throw(OSError(errno.EACCES, "generated replacement failure"))),
                }
                name, hook = hooks[fault]
                with patch("run.os." + name, hook), self.assertRaises(OSError):
                    run.write_final_report(target, {"status": "complete", "containment": "synthetic-observation"})
                if fault == "partial-write":
                    self.assertEqual(calls, 2)
                self.assertEqual(target.read_bytes(), before)
                self.assertEqual(unrelated.read_bytes(), b"generated unrelated file")
                self.assertEqual(set(root.iterdir()), {target, unrelated})

    def test_serialization_failure_cannot_create_or_replace_a_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "summary.json"
            target.write_bytes(b'{"status":"incomplete"}\n')
            before = target.read_bytes()
            with self.assertRaises(TypeError):
                run.write_json(target, {"unsupported": object()})
            self.assertEqual(target.read_bytes(), before)
            self.assertEqual(list(root.iterdir()), [target])


class TerminalReportTests(unittest.TestCase):
    def test_cancellation_at_publication_reconciles_saved_and_in_memory_reports(self):
        for timing in ("before-replace", "after-replace", "after-writer-return"):
            for status in ("complete", "fail"):
                with self.subTest(timing=timing, status=status), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    target = root / "summary.json"
                    run.write_json(target, {"status": "incomplete", "containment": "not_established"})
                    cancellation = run.Cancellation()
                    report = {"status": status, "containment": "synthetic-observation",
                              "workspace_removed": False, "retained_synthetic_workspace": "generated-workspace",
                              "observations": {"cleanup_complete": True}}
                    if status == "fail":
                        report.update(failure="generated original failure", fixture_artifact_error="generated save failure")
                    original_replace, original_writer = os.replace, run.write_json
                    commits = []
                    writes = []

                    def interrupt_at_replace(source, destination):
                        commits.append(json.loads(Path(source).read_bytes()))
                        if len(commits) == 1 and timing == "before-replace":
                            cancellation.interrupted(signal.SIGTERM, None)
                        result = original_replace(source, destination)
                        if len(commits) == 1 and timing == "after-replace":
                            cancellation.interrupted(signal.SIGTERM, None)
                        return result

                    def interrupt_after_writer(*args, **kwargs):
                        writes.append(copy.deepcopy(args[1]))
                        result = original_writer(*args, **kwargs)
                        if len(writes) == 1 and timing == "after-writer-return":
                            cancellation.interrupted(signal.SIGTERM, None)
                        return result

                    with patch("run.os.replace", interrupt_at_replace), patch("run.write_json", interrupt_after_writer):
                        run.write_final_report(target, report, cancellation)
                    self.assertEqual(report["status"], "fail")
                    self.assertEqual(report["containment"], "not_established")
                    self.assertEqual(report["interrupted_signal"], signal.SIGTERM)
                    self.assertEqual(report["observations"], {"cleanup_complete": True})
                    self.assertFalse(report["workspace_removed"])
                    self.assertEqual(report["retained_synthetic_workspace"], "generated-workspace")
                    if status == "fail":
                        self.assertEqual(report["failure"], "generated original failure")
                        self.assertEqual(report["fixture_artifact_error"], "generated save failure")
                    self.assertEqual(len(writes), 2)
                    self.assertEqual(len(commits), 2)
                    self.assertEqual(json.loads(target.read_bytes()), report)
                    self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(list(root.iterdir()), [target])

    def test_corrective_write_failure_cannot_leave_a_published_positive(self):
        for status in ("complete", "fail"):
            for fault in ("create", "permission", "partial-write", "flush", "close", "replace"):
                with self.subTest(status=status, fault=fault), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    target = root / "summary.json"
                    run.write_json(target, {"status": "incomplete", "containment": "not_established"})
                    unrelated = root / "browser.json"
                    unrelated.write_bytes(b"generated retained raw observation")
                    cancellation = run.Cancellation()
                    report = {"status": status, "containment": "synthetic-observation"}
                    if status == "fail":
                        report["failure"] = "generated original failure"
                    original_writer, original_replace = run.write_json, os.replace
                    original_close, original_write = os.close, os.write
                    writes = 0

                    def interrupt_at_replace(source, destination):
                        result = original_replace(source, destination)
                        if writes == 1:
                            cancellation.interrupted(signal.SIGTERM, None)
                        return result

                    def fail(*args, **kwargs):
                        raise OSError(errno.EIO, "generated corrective write failure")

                    def fail_close(fd):
                        original_close(fd)
                        fail()

                    def fail_write(fd, raw):
                        original_write(fd, raw[:13])
                        fail()

                    def fail_correction(*args, **kwargs):
                        nonlocal writes
                        writes += 1
                        if writes == 1:
                            return original_writer(*args, **kwargs)
                        self.assertEqual(args[1]["status"], "fail")
                        self.assertEqual(args[1]["containment"], "not_established")
                        if status == "complete":
                            self.assertFalse(target.exists())
                        else:
                            self.assertEqual(json.loads(target.read_bytes())["status"], "fail")
                        name, hook = {
                            "create": ("tempfile.mkstemp", fail), "permission": ("os.fchmod", fail),
                            "partial-write": ("os.write", fail_write), "flush": ("os.fsync", fail),
                            "close": ("os.close", fail_close), "replace": ("os.replace", fail),
                        }[fault]
                        with patch("run." + name, hook):
                            return original_writer(*args, **kwargs)

                    with patch("run.os.replace", interrupt_at_replace), patch("run.write_json", fail_correction):
                        with self.assertRaisesRegex(OSError, "generated corrective write failure"):
                            run.write_final_report(target, report, cancellation)
                    self.assertEqual(writes, 2)
                    self.assertEqual(report["status"], "fail")
                    self.assertEqual(report["containment"], "not_established")
                    self.assertEqual(report["interrupted_signal"], signal.SIGTERM)
                    if status == "complete":
                        self.assertEqual(list(root.iterdir()), [unrelated])
                    else:
                        self.assertEqual(report["failure"], "generated original failure")
                        self.assertEqual(json.loads(target.read_bytes())["failure"], "generated original failure")
                        self.assertEqual(set(root.iterdir()), {unrelated, target})
                    self.assertEqual(unrelated.read_bytes(), b"generated retained raw observation")

    def test_invalidation_failure_is_explicit_and_does_not_claim_correction(self):
        # An invalidation refusal is distinct from corrective-write failure:
        # callers must report that the on-disk summary may still be stale.
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "summary.json"
            cancellation = run.Cancellation()
            report = {"status": "complete", "containment": "synthetic-observation"}
            original_replace, original_unlink = os.replace, Path.unlink

            def interrupt_at_replace(source, destination):
                result = original_replace(source, destination)
                cancellation.interrupted(signal.SIGTERM, None)
                return result

            def fail_invalidation(path, *args, **kwargs):
                if path == target:
                    raise OSError(errno.EACCES, "generated invalidation denial")
                return original_unlink(path, *args, **kwargs)

            with patch("run.os.replace", interrupt_at_replace), patch.object(Path, "unlink", fail_invalidation):
                with self.assertRaisesRegex(OSError, "summary.json may retain stale completion") as raised:
                    run.write_final_report(target, report, cancellation)
            self.assertIn("generated invalidation denial", str(raised.exception))
            self.assertEqual(raised.exception.__cause__.errno, errno.EACCES)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["containment"], "not_established")
            self.assertEqual(report["interrupted_signal"], signal.SIGTERM)
            self.assertEqual(json.loads(target.read_bytes())["status"], "complete")

    def test_precommit_cancellation_keeps_incomplete_snapshot_if_correction_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "summary.json"
            run.write_json(target, {"status": "incomplete", "containment": "not_established"})
            before = target.read_bytes()
            cancellation = run.Cancellation()
            report = {"status": "complete", "containment": "synthetic-observation"}
            original_fsync, original_writer = os.fsync, run.write_json
            writes = 0

            def interrupt_after_flush(fd):
                original_fsync(fd)
                cancellation.interrupted(signal.SIGTERM, None)

            def fail_correction(*args, **kwargs):
                nonlocal writes
                writes += 1
                if writes == 2:
                    raise OSError("generated correction failure before commit")
                return original_writer(*args, **kwargs)

            with patch("run.os.fsync", interrupt_after_flush), patch("run.write_json", fail_correction):
                with self.assertRaisesRegex(OSError, "generated correction failure before commit"):
                    run.write_final_report(target, report, cancellation)
            self.assertEqual(writes, 2)
            self.assertEqual(target.read_bytes(), before)
            self.assertEqual(list(root.iterdir()), [target])
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["containment"], "not_established")
            self.assertEqual(report["interrupted_signal"], signal.SIGTERM)

    def test_cancellation_during_private_write_prevents_a_complete_commit(self):
        for mode, claim in (("sandbox", "strict_launch_and_own_endpoint_boundary_observed"),
                            ("managed-contain", "managed_launch_and_own_endpoint_boundary_observed"),
                            ("proxy-only", "not_tested_proxy_only")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = root / "summary.json"
                target.write_text('{"status":"incomplete","containment":"not_established"}\n')
                cancellation = run.Cancellation()
                report = {"status": "complete", "mode": mode, "containment": claim}
                original_fsync, original_replace = os.fsync, os.replace
                commits = []
                def interrupt_after_flush(fd):
                    original_fsync(fd)
                    cancellation.interrupted(signal.SIGTERM, None)
                def observe_commit(source, destination):
                    candidate = json.loads(Path(source).read_bytes())
                    self.assertEqual(candidate["status"], "fail")
                    self.assertEqual(candidate["interrupted_signal"], signal.SIGTERM)
                    commits.append(candidate)
                    original_replace(source, destination)
                with patch("run.os.fsync", interrupt_after_flush), patch("run.os.replace", observe_commit):
                    run.write_final_report(target, report, cancellation)
                self.assertEqual(len(commits), 1)
                self.assertEqual(json.loads(target.read_bytes()), report)
                self.assertEqual(report["containment"], "not_tested_proxy_only" if mode == "proxy-only" else "not_established")
                self.assertEqual(list(root.iterdir()), [target])

    def test_late_failures_remove_aggregate_claim_and_preserve_raw_observations(self):
        for mode, claim in (
            ("sandbox", "strict_launch_and_own_endpoint_boundary_observed"),
            ("managed-contain", "managed_launch_and_own_endpoint_boundary_observed"),
        ):
            for failure in ("fixture accounting failed", "workspace cleanup failed", "late interruption"):
                with self.subTest(mode=mode, failure=failure), tempfile.TemporaryDirectory() as temporary:
                    report = {"mode": mode, "status": "fail", "containment": claim,
                              "failure": failure, "lifecycle": {"cleanup_complete": True},
                              "observations": {"namespace_distinct": True, "health_arrivals": 3}}
                    if failure == "late interruption":
                        report["interrupted_signal"] = 15
                    original = copy.deepcopy(report)
                    path = Path(temporary) / "summary.json"
                    run.write_final_report(path, report)
                    expected = {**original, "containment": "not_established"}
                    # The same normalized object drives the console summary.
                    self.assertEqual(report, expected)
                    self.assertEqual(json.loads(path.read_text()), expected)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_success_incomplete_refusal_and_proxy_only_states_are_unambiguous(self):
        cases = [
            ("complete", "strict_launch_and_own_endpoint_boundary_observed", "strict_launch_and_own_endpoint_boundary_observed"),
            ("complete", "managed_launch_and_own_endpoint_boundary_observed", "managed_launch_and_own_endpoint_boundary_observed"),
            ("incomplete", "managed_launch_and_own_endpoint_boundary_observed", "not_established"),
            ("refused", "strict_launch_and_own_endpoint_boundary_observed", "not_established"),
            ("fail", "not_established", "not_established"),
            ("fail", "not_tested_proxy_only", "not_tested_proxy_only"),
            ("complete", "not_tested_proxy_only", "not_tested_proxy_only"),
        ]
        for status, before, after in cases:
            with self.subTest(status=status, before=before), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "summary.json"
                report = {"status": status, "containment": before}
                run.write_final_report(path, report)
                self.assertEqual(json.loads(path.read_text()), {"status": status, "containment": after})
                self.assertEqual(report["containment"], after)

    def test_both_entrypoints_finalize_their_summary_through_the_shared_writer(self):
        # Structural wiring witness only; this does not claim a managed host or
        # Chromium ran. Behavioral assertions above inspect actual saved JSON.
        self.assertIs(managed.write_final_report, run.write_final_report)
        for module in (run, managed):
            tree = ast.parse(Path(module.__file__).read_text())
            summary_calls = []
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not node.args:
                    continue
                if any(isinstance(part, ast.Constant) and part.value == "summary.json"
                       for part in ast.walk(node.args[0])):
                    summary_calls.append(node)
            self.assertEqual(len(summary_calls), 1, module.__name__)
            self.assertIsInstance(summary_calls[0].func, ast.Name)
            self.assertEqual(summary_calls[0].func.id, "write_final_report")


if __name__ == "__main__":
    unittest.main()
