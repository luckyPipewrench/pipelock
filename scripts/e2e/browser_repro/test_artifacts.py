# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Artifact rejection with inert owned files, not a browser/containment run."""
import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import Mock, patch

import managed
import run


PNG = b"\x89PNG\r\n\x1a\ngenerated artifact fixture; not rendered pixels"


def browser_report(mode="sandbox", status="fail"):
    return {"schema": 1, "mode": mode, "status": status,
            "failure": "generated failure detail", "cases": []}


class ArtifactFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / "workspace"
        self.work.mkdir(mode=0o700)
        self.output = self.root / "evidence"
        self.output.mkdir(mode=0o700)

    def preserve(self, result_dir=None, owner=None):
        report = {"status": "fail", "containment": "not_established"}
        browser = run.preserve_browser_report(result_dir or self.work, self.output,
            "sandbox", os.geteuid() if owner is None else owner, report)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["containment"], "not_established")
        return browser, report

    def test_both_runners_share_the_reader_decoder_and_artifact_helpers(self):
        for name in ("read_regular", "decode_json", "preserve_browser_report", "copy_browser_screenshots"):
            self.assertIs(getattr(run, name), getattr(managed, name))

    def test_valid_report_preserves_exact_bounded_bytes_without_an_acceptance_claim(self):
        raw = (json.dumps(browser_report(), separators=(",", ":")) + "\n").encode()
        (self.work / "browser.json").write_bytes(raw)
        browser, report = self.preserve()
        self.assertEqual(browser, browser_report())
        self.assertEqual(report["browser_artifact_status"], "preserved")
        self.assertNotIn("browser_artifact_error", report)
        self.assertEqual((self.output / "browser.json").read_bytes(), raw)
        self.assertEqual((self.output / "browser.json").stat().st_mode & 0o777, 0o600)

    def test_missing_report_is_identified_without_creating_evidence(self):
        browser, report = self.preserve()
        self.assertIsNone(browser)
        self.assertEqual(report["browser_artifact_status"], "missing")
        self.assertIn("browser result absent", report["browser_artifact_error"])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_report_save_failure_is_distinct_from_rejected_child_evidence(self):
        (self.work / "browser.json").write_text(json.dumps(browser_report()))
        (self.output / "browser.json").mkdir()
        browser, report = self.preserve()
        self.assertIsNone(browser)
        self.assertEqual(report["browser_artifact_status"], "save_failed")
        self.assertIn("could not be saved", report["browser_artifact_error"])
        self.assertEqual(json.loads((self.work / "browser.json").read_text()), browser_report())

    def test_invalid_json_and_report_identity_are_rejected(self):
        invalid = [b"{", b"\xff", b"[]", b"null", b'{"value":NaN}',
            b'{"status":"fail","status":"complete"}', b"[" * 1500 + b"]" * 1500]
        for field, value in (("schema", True), ("schema", 2), ("mode", "managed-contain"),
                             ("status", "unknown"), ("status", None)):
            invalid.append(json.dumps({**browser_report(), field: value}).encode())
        invalid.append(json.dumps({"mode": "sandbox", "status": "complete"}).encode())
        for raw in invalid:
            with self.subTest(raw=raw[:80]):
                (self.work / "browser.json").write_bytes(raw)
                browser, report = self.preserve()
                self.assertIsNone(browser)
                self.assertEqual(report["browser_artifact_status"], "rejected")
                self.assertEqual(list(self.output.iterdir()), [])

    def test_report_rejects_real_leaf_aliases_and_nonregular_files(self):
        reference = self.root / "owned-reference.json"
        reference.write_text(json.dumps(browser_report()))
        artifact = self.work / "browser.json"
        for kind in ("symlink", "hardlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    artifact.symlink_to(reference)
                elif kind == "hardlink":
                    artifact.hardlink_to(reference)
                elif kind == "fifo":
                    os.mkfifo(artifact, 0o600)
                else:
                    artifact.mkdir()
                browser, report = self.preserve()
                self.assertIsNone(browser)
                self.assertEqual(report["browser_artifact_status"], "rejected")
                self.assertEqual(list(self.output.iterdir()), [])
                artifact.rmdir() if kind == "directory" else artifact.unlink()

    def test_report_rejects_real_parent_alias_owner_mismatch_and_oversize(self):
        artifact = self.work / "browser.json"
        artifact.write_text(json.dumps(browser_report()))
        alias = self.root / "workspace-alias"
        alias.symlink_to(self.work, target_is_directory=True)
        browser, report = self.preserve(result_dir=alias)
        self.assertIsNone(browser)
        self.assertEqual(report["browser_artifact_status"], "rejected")
        browser, report = self.preserve(owner=os.geteuid() + 1)
        self.assertIsNone(browser)
        self.assertIn("unexpected file owner", report["browser_artifact_error"])
        with artifact.open("wb") as stream:
            stream.truncate(2 * 1024 * 1024 + 1)
        browser, report = self.preserve()
        self.assertIsNone(browser)
        self.assertEqual(report["browser_artifact_status"], "rejected")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_screenshots_use_only_four_supported_names_and_private_outputs(self):
        names = ("cold.png", "warm.png", "reload.png", "delayed.png")
        for name in (*names, "extra.png", "unexpected-name.png"):
            (self.work / name).write_bytes(PNG)
        # Even a nonregular extra entry must never be opened or enumerated.
        os.mkfifo(self.work / "unused.png", 0o600)
        with patch("run.Path.glob", side_effect=AssertionError("artifact glob is unbounded")):
            run.copy_browser_screenshots(self.work, self.output, os.geteuid())
        self.assertEqual({path.name for path in self.output.iterdir()}, set(names))
        for path in self.output.iterdir():
            self.assertEqual(path.read_bytes(), PNG)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_screenshots_reject_real_aliases_nonregular_files_and_invalid_bytes(self):
        reference = self.root / "owned-reference.png"
        reference.write_bytes(PNG)
        artifact = self.work / "cold.png"
        for kind in ("symlink", "hardlink", "fifo", "directory", "invalid", "oversize"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    artifact.symlink_to(reference)
                elif kind == "hardlink":
                    artifact.hardlink_to(reference)
                elif kind == "fifo":
                    os.mkfifo(artifact, 0o600)
                elif kind == "directory":
                    artifact.mkdir()
                elif kind == "invalid":
                    artifact.write_bytes(b"generated non-PNG fixture")
                else:
                    with artifact.open("wb") as stream:
                        stream.truncate(8 * 1024 * 1024 + 1)
                with self.assertRaises((OSError, ValueError)):
                    run.copy_browser_screenshots(self.work, self.output, os.geteuid())
                self.assertEqual(list(self.output.iterdir()), [])
                artifact.rmdir() if kind == "directory" else artifact.unlink()

    def test_screenshots_reject_real_parent_alias_and_owner_mismatch(self):
        (self.work / "cold.png").write_bytes(PNG)
        alias = self.root / "workspace-alias"
        alias.symlink_to(self.work, target_is_directory=True)
        for directory, owner in ((alias, os.geteuid()), (self.work, os.geteuid() + 1)):
            with self.subTest(directory=directory, owner=owner), self.assertRaises((OSError, ValueError)):
                run.copy_browser_screenshots(directory, self.output, owner)
            self.assertEqual(list(self.output.iterdir()), [])

    def test_valid_screenshots_survive_independent_artifact_rejections(self):
        (self.work / "cold.png").write_bytes(b"generated non-PNG fixture")
        reference = self.root / "owned-reference.png"
        reference.write_bytes(PNG)
        (self.work / "reload.png").symlink_to(reference)
        for name in ("warm.png", "delayed.png"):
            (self.work / name).write_bytes(PNG)
        with self.assertRaises(ValueError):
            run.copy_browser_screenshots(self.work, self.output, os.geteuid())
        self.assertEqual({path.name for path in self.output.iterdir()}, {"warm.png", "delayed.png"})
        for path in self.output.iterdir():
            self.assertEqual(path.read_bytes(), PNG)

    def test_screenshot_save_failure_is_reported_while_later_images_are_preserved(self):
        for name in ("cold.png", "delayed.png"):
            (self.work / name).write_bytes(PNG)
        (self.output / "cold.png").mkdir()
        report = {}
        with self.assertRaisesRegex(ValueError, "could not be saved"):
            run.copy_browser_screenshots(self.work, self.output, os.geteuid(), report)
        self.assertTrue(report["screenshot_artifact_save_failed"])
        self.assertEqual((self.output / "delayed.png").read_bytes(), PNG)


class StandaloneArtifactFlowTests(unittest.TestCase):
    def test_main_collects_only_safe_artifacts_and_keeps_failed_runs_failed(self):
        # Mock unavailable process execution and native runtime identity only.
        # The fixture, artifact links, reads, writes and summary are real; no
        # browser, sandbox, existing user files or host policies are involved.
        retained_scenarios = ("report-save-failed", "screenshot-save-failed", "summary-save-failed",
                              "stop-failed", "wait-failed", "missing-cleanup-witness", "fixture-save-failed",
                              "stop-fixture-save-failed", "wait-fixture-save-failed", "wait-stop-fixture-save-failed")
        for scenario in ("report-alias", "screenshot-alias", "failed-report", "failed-screenshot-alias",
                         "missing-report", "final-summary-save-failed", "cleanup-signal", *retained_scenarios):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                work = root / "workspace"
                work.mkdir()
                candidate = root / "unused-candidate"
                candidate.write_bytes(b"generated bytes, never executed")
                output = root / "evidence"
                record = browser_report(status="complete" if scenario in ("screenshot-alias", "cleanup-signal") else "fail")
                reference = root / "owned-reference"
                reference.write_bytes(PNG if "screenshot-alias" in scenario else json.dumps(record).encode())
                exit_code = 7 if scenario in ("failed-report", "failed-screenshot-alias", "missing-report",
                                              "report-save-failed", "screenshot-save-failed") else 0
                cancellation = run.Cancellation()

                class SyntheticProcess:
                    def __init__(self, command, log, env, cwd, cancellation):
                        self.log = log
                        if log.name != "driver":
                            return
                        settings = json.loads((work / "settings.json").read_text())
                        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", settings["port"], timeout=2)) as connection:
                            connection.request("POST", "/session", "user=fixture&code=fixture-only")
                            response = connection.getresponse()
                            if response.status != 303:
                                raise AssertionError("owned synthetic session failed")
                            response.read()
                            connection.request("GET", "/account", headers={"Cookie": "fixture_session=synthetic"})
                            response = connection.getresponse()
                            if response.status != 200:
                                raise AssertionError("owned synthetic account failed")
                            response.read()
                        if "fixture-save-failed" in scenario:
                            (output / "fixture.json").mkdir()
                        if scenario == "missing-report":
                            return
                        if scenario == "report-alias":
                            (work / "browser.json").symlink_to(reference)
                        else:
                            (work / "browser.json").write_text(json.dumps(record))
                        if "screenshot-alias" in scenario:
                            (work / "cold.png").symlink_to(reference)
                        if scenario == "report-save-failed":
                            (output / "browser.json").mkdir()
                        elif scenario == "screenshot-save-failed":
                            (work / "cold.png").write_bytes(PNG)
                            (output / "cold.png").mkdir()
                        elif scenario == "summary-save-failed":
                            (output / "summary.json").mkdir()

                    def wait(self, timeout):
                        if self.log.name == "driver" and scenario.startswith("wait-"):
                            raise RuntimeError("generated interrupted wait")
                        return exit_code if self.log.name == "driver" else 0

                    def stop(self):
                        if self.log.name == "driver" and scenario in ("stop-failed", "stop-fixture-save-failed", "wait-stop-fixture-save-failed"):
                            raise RuntimeError("generated incomplete process cleanup")
                        self.log.with_suffix(".stderr").write_text("generated diagnostic\n")
                        cleanup = {"cleanup_complete": True, "unexpected_live_descendants": False}
                        if self.log.name == "driver" and scenario == "missing-cleanup-witness":
                            cleanup.pop("unexpected_live_descendants")
                        return {"exit_code": exit_code if self.log.name == "driver" else 0,
                                "streams_drained": True, "cleanup": cleanup}

                def source_command(command, **kwargs):
                    return "0" * 40 if "rev-parse" in command else ("" if kwargs.get("text") else b"")

                original_write_json = run.write_json
                original_rmtree = run.shutil.rmtree
                def remove_with_cancellation(path, *args, **kwargs):
                    result = original_rmtree(path, *args, **kwargs)
                    if scenario == "cleanup-signal" and Path(path) == work:
                        cancellation.interrupted(signal.SIGTERM, None)
                    return result
                remove_with_cancellation.avoids_symlink_attacks = original_rmtree.avoids_symlink_attacks

                summary_writes = 0
                def write_with_late_destination_failure(path, data, **kwargs):
                    nonlocal summary_writes
                    if path == output / "summary.json":
                        summary_writes += 1
                        if scenario == "final-summary-save-failed" and summary_writes == 2:
                            # Preserve the actual incomplete snapshot and then
                            # make the final destination fail via real file I/O.
                            path.rename(output / "summary-before-cleanup.json")
                            path.mkdir()
                    return original_write_json(path, data, **kwargs)

                with contextlib.ExitStack() as stack:
                    overrides = {
                        "sys.argv": ["run.py", "--pipelock", str(candidate), "--output", str(output),
                                     "--node", "unused-node", "--chromium", "unused-chromium", "--bundle-bytes", "4096"],
                        "tempfile.mkdtemp": Mock(return_value=str(work)),
                        "subprocess.check_output": source_command, "Process": SyntheticProcess,
                        "probe": Mock(return_value="generated identity"), "copy_node_runtime": Mock(return_value={}),
                        "write_json": write_with_late_destination_failure,
                        "Cancellation": Mock(return_value=cancellation), "shutil.rmtree": remove_with_cancellation,
                        "node_identity": Mock(side_effect=[{"exec_path": str(candidate), "version": "24.0.0"},
                            {"exec_path": str(work / "node-runtime"), "version": "24.0.0"}]),
                    }
                    if scenario == "cleanup-signal":
                        # These otherwise successful observations isolate the
                        # cleanup-time cancellation from earlier failure paths.
                        overrides["Fixture.evidence"] = Mock(return_value={
                            "counts": {"/health": 2, "/response-marker": 1},
                            "scenario_counts": {"error": 1, "incomplete": 1, "pending": 1},
                            "auth_counts": {"session_submissions": 1, "session_acceptances": 1,
                                "session_rejections": 0, "account_authenticated": 2, "account_login_required": 2}})
                    for target, value in overrides.items():
                        stack.enter_context(patch("run." + target, value))
                    stdout = io.StringIO()
                    stack.enter_context(contextlib.redirect_stdout(stdout))
                    self.assertEqual(run.main(), 2)
                console = json.loads(stdout.getvalue())
                if scenario in ("summary-save-failed", "final-summary-save-failed"):
                    self.assertEqual(console["status"], "fail")
                    self.assertEqual(console["containment"], "not_established")
                    self.assertIn("summary_write_error", console)
                    if scenario == "summary-save-failed":
                        self.assertFalse(console["workspace_removed"])
                        self.assertEqual(console["retained_synthetic_workspace"], str(work))
                        self.assertTrue(work.is_dir())
                    else:
                        self.assertTrue(console["workspace_removed"])
                        self.assertNotIn("retained_synthetic_workspace", console)
                        self.assertFalse(work.exists())
                        pending = json.loads((output / "summary-before-cleanup.json").read_text())
                        self.assertEqual(pending["status"], "incomplete")
                        self.assertEqual(pending["containment"], "not_established")
                        self.assertEqual(json.loads((output / "browser.json").read_text()), record)
                    continue
                report = json.loads((output / "summary.json").read_text())
                self.assertEqual(report["status"], "fail")
                self.assertEqual(report["containment"], "not_established")
                if scenario.startswith("wait-"):
                    self.assertNotIn("driver_exit", report)
                    self.assertEqual(report["driver_wait_error"], "generated interrupted wait")
                    if scenario != "wait-stop-fixture-save-failed":
                        self.assertEqual(report["failure"], report["driver_wait_error"])
                else:
                    self.assertEqual(report["driver_exit"], exit_code)
                if scenario in ("stop-failed", "stop-fixture-save-failed", "wait-stop-fixture-save-failed"):
                    self.assertEqual(report["failure"], "driver: generated incomplete process cleanup")
                if "fixture-save-failed" in scenario:
                    self.assertIn("fixture.json", report["fixture_artifact_error"])
                    self.assertTrue((output / "fixture.json").is_dir())
                    if scenario == "fixture-save-failed":
                        self.assertEqual(report["failure"], report["fixture_artifact_error"])
                elif scenario != "cleanup-signal":
                    evidence_path = output / "fixture.json"
                    evidence = json.loads(evidence_path.read_text())
                    self.assertEqual(evidence["counts"], {"/health": 1, "/account": 1})
                    self.assertEqual(evidence["auth_counts"], {"session_submissions": 1,
                        "session_acceptances": 1, "account_authenticated": 1})
                    self.assertEqual(evidence_path.stat().st_mode & 0o777, 0o600)
                    self.assertNotIn("fixture_artifact_error", report)
                self.assertFalse((output / "cold.png").is_file())
                if scenario in ("failed-report", "screenshot-alias", "failed-screenshot-alias",
                                "screenshot-save-failed", "stop-failed", "missing-cleanup-witness", "cleanup-signal",
                                "fixture-save-failed", "stop-fixture-save-failed"):
                    self.assertEqual(json.loads((output / "browser.json").read_text()), record)
                    self.assertEqual(report["browser_artifact_status"], "preserved")
                elif scenario.startswith("wait-"):
                    self.assertNotIn("browser_artifact_status", report)
                    self.assertFalse((output / "browser.json").exists())
                else:
                    self.assertFalse((output / "browser.json").is_file())
                    self.assertEqual(report["browser_artifact_status"],
                        "missing" if scenario == "missing-report" else
                        "save_failed" if scenario == "report-save-failed" else "rejected")
                if exit_code:
                    self.assertIn("browser command failed (exit 7)", report["failure"])
                if "screenshot-alias" in scenario:
                    self.assertIn("screenshot_artifact_error", report)
                if scenario == "cleanup-signal":
                    self.assertEqual(report["interrupted_signal"], signal.SIGTERM)
                if scenario in retained_scenarios:
                    self.assertFalse(report["workspace_removed"])
                    self.assertEqual(report["retained_synthetic_workspace"], str(work))
                    self.assertEqual(console["retained_synthetic_workspace"], str(work))
                    self.assertTrue(work.is_dir())
                    self.assertEqual(json.loads((work / "browser.json").read_text()), record)
                else:
                    self.assertTrue(report["workspace_removed"])
                    self.assertNotIn("retained_synthetic_workspace", report)
                    self.assertFalse(work.exists())


class WorkspaceRetentionTests(unittest.TestCase):
    def test_fixture_save_failure_retains_scratch_despite_other_complete_witnesses(self):
        for failure in ("generated fixture save failure", ""):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                work = root / "workspace"
                work.mkdir()
                state = work / "generated-state"
                state.write_text("generated inert state")
                report = {"status": "complete", "browser_artifact_status": "preserved",
                          "fixture_artifact_error": failure}
                run.finalize_workspace(work, root / "summary.json", report, cleanup_verified=True)
                self.assertEqual(report["status"], "fail")
                self.assertFalse(report["workspace_removed"])
                self.assertEqual(report["retained_synthetic_workspace"], str(work))
                self.assertEqual(state.read_text(), "generated inert state")
                self.assertFalse((root / "summary.json").exists())

    def test_successful_removal_requires_a_saved_incomplete_summary_first(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "workspace"
            work.mkdir()
            (work / "generated-state").write_text("generated inert state")
            summary = root / "summary.json"
            report = {"status": "complete", "containment": "strict_launch_and_own_endpoint_boundary_observed",
                      "browser_artifact_status": "preserved"}
            run.finalize_workspace(work, summary, report, cleanup_verified=True)
            self.assertFalse(work.exists())
            self.assertTrue(report["workspace_removed"])
            self.assertNotIn("retained_synthetic_workspace", report)
            pending = json.loads(summary.read_text())
            self.assertEqual(pending["status"], "incomplete")
            self.assertEqual(pending["containment"], "not_established")
            run.write_final_report(summary, report)
            self.assertEqual(json.loads(summary.read_text()), report)


if __name__ == "__main__":
    unittest.main()
