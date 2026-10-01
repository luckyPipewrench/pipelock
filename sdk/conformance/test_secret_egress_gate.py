# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Benign gate-mechanics tests, independent of real receipt verification.

Run with ``python3 -m unittest discover -s sdk/conformance -p 'test_*.py'``.
Fake CLIs inspect inert filenames only; these tests do not establish that any
product verifier validates signed evidence correctly.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("secret-egress-gate.py")
SPEC = importlib.util.spec_from_file_location("secret_egress_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


class GateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="benign gate mechanics ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        self.manifest = {
            "version": 1,
            "public_key_hex": "ab" * 32,
            "registry_hash": "sha256:" + "cd" * 32,
            "cases": [
                {
                    "name": "valid",
                    "file": "valid.json",
                    "valid": True,
                    "reason": "benign smoke",
                },
                {
                    "name": "invalid",
                    "file": "invalid.json",
                    "valid": False,
                    "reason": "benign reject",
                },
            ],
        }
        for entry in self.manifest["cases"]:
            (self.corpus / entry["file"]).write_text("{}", encoding="utf-8")
        # Inert lane identifiers only: fake CLIs still do no cryptography.
        self.valid_fixture = {
            "record_type": "evidence_receipt_v2",
            "payload_kind": "secret_egress_decision_v1",
        }
        (self.corpus / "valid.json").write_text(json.dumps(self.valid_fixture))
        self.save_manifest()
        self.fake = self.root / "fake verifier.py"
        self.fake.write_text(
            "import pathlib, sys\n"
            "assert sys.argv[1:3] == ['--fixed', 'a b ; $(inert)']\n"
            "assert sys.argv[4:] == ['--key', 'ab' * 32]\n"
            "sys.exit(0 if pathlib.Path(sys.argv[3]).name == 'valid.json' else 1)\n",
            encoding="utf-8",
        )
        command = shlex.join(
            [sys.executable, str(self.fake), "--fixed", "a b ; $(inert)"]
        )
        self.env = dict.fromkeys(GATE.COMMANDS, command)

    def save_manifest(self) -> None:
        (self.corpus / "manifest.json").write_text(
            json.dumps(self.manifest), encoding="utf-8"
        )

    def invoke(self, *, timeout: str = "5") -> tuple[int, str]:
        output = io.StringIO()
        with (
            patch.dict(os.environ, self.env, clear=True),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            result = GATE.main(["--corpus", str(self.corpus), "--timeout", timeout])
        return result, output.getvalue()

    def fake_body(self, body: str) -> None:
        self.fake.write_text("import pathlib, sys\n" + body, encoding="utf-8")

    def test_four_commands_match_expectations_and_preserve_quoted_arguments(
        self,
    ) -> None:
        code, output = self.invoke()
        self.assertEqual(code, 0, output)
        self.assertIn("checked 2 signed secret-egress fixtures; 0 failure(s)", output)
        self.assertIn("PASS:", output)

    def test_all_accept_fails_expected_rejection(self) -> None:
        self.fake_body("sys.exit(0)\n")
        code, output = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn(
            "invalid reject accept accept accept accept EXPECT-MISMATCH", output
        )

    def test_expected_valid_fixture_must_select_secret_egress_kind(self) -> None:
        for value in (
            {},
            [],
            self.valid_fixture | {"payload_kind": "proxy_decision"},
            self.valid_fixture | {"record_type": "action_receipt_v1"},
        ):
            with self.subTest(value=value):
                (self.corpus / "valid.json").write_text(json.dumps(value))
                with patch.object(GATE.subprocess, "run") as run:
                    code, output = self.invoke()
                    run.assert_not_called()
                self.assertEqual(code, 2, output)
                self.assertIn("expected-valid fixture must be", output)

    def test_every_expected_valid_fixture_is_bound_not_only_smoke(self) -> None:
        self.manifest["cases"].append(
            {
                "name": "second",
                "file": "second.json",
                "valid": True,
                "reason": "wrong lane",
            }
        )
        (self.corpus / "second.json").write_text(
            json.dumps(self.valid_fixture | {"payload_kind": "proxy_decision"})
        )
        self.save_manifest()
        code, output = self.invoke()
        self.assertEqual(code, 2, output)
        self.assertIn("second: expected-valid fixture must be", output)

    def test_negative_fixture_can_deliberately_have_another_kind(self) -> None:
        (self.corpus / "invalid.json").write_text(
            json.dumps(self.valid_fixture | {"payload_kind": "proxy_decision"})
        )
        code, output = self.invoke()
        self.assertEqual(code, 0, output)

    def test_expected_valid_fixture_json_failure_is_configuration_error(self) -> None:
        for raw in (
            "{",
            '{"payload_kind":"secret_egress_decision_v1","payload_kind":"proxy_decision"}',
        ):
            with self.subTest(raw=raw):
                (self.corpus / "valid.json").write_text(raw)
                code, output = self.invoke()
                self.assertEqual(code, 2, output)
                self.assertIn("cannot read expected-valid fixture", output)

    def test_all_reject_fails_known_valid_smoke(self) -> None:
        self.fake_body("sys.exit(1)\n")
        self.manifest["cases"].reverse()
        self.save_manifest()
        code, output = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("known-valid smoke failed", output)
        self.assertNotIn("invalid reject", output)

    def test_differential_also_checks_authoritative_expectation(self) -> None:
        accept = self.root / "accept.py"
        accept.write_text("raise SystemExit(0)\n", encoding="utf-8")
        self.env["TS_VERIFY"] = shlex.join([sys.executable, str(accept)])
        code, output = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("DIFFERENTIAL+EXPECT-MISMATCH", output)

    def test_candidate_overrides_are_local_to_new_gate(self) -> None:
        baseline = self.env.copy()
        for variable in ("GO_VERIFY", "PY_VERIFY"):
            with self.subTest(variable=variable):
                self.env = baseline.copy()
                self.env[f"SECRET_EGRESS_{variable}"] = self.env[variable]
                self.env[variable] = str(self.root / "unused legacy verifier")
                self.assertEqual(self.invoke()[0], 0)
                self.env.pop(variable)
                self.assertEqual(self.invoke()[0], 0)

    def test_explicit_empty_override_does_not_silently_fall_back(self) -> None:
        for variable in ("GO_VERIFY", "PY_VERIFY"):
            with (
                self.subTest(variable=variable),
                patch.dict(self.env, {f"SECRET_EGRESS_{variable}": ""}),
            ):
                self.assertEqual(self.invoke()[0], 2)

    def test_command_failure_is_not_expected_rejection(self) -> None:
        for status in (2, 9, 126, 127):
            with self.subTest(status=status):
                self.fake_body(
                    "valid = pathlib.Path(sys.argv[3]).name == 'valid.json'\n"
                    f"sys.exit(0 if valid else {status})\n"
                )
                code, output = self.invoke()
                self.assertEqual(code, 2)
                self.assertIn(f"command failed with exit {status} on invalid", output)
                self.assertNotIn("PASS:", output)

    def go_parse_report(self, **updates: object) -> dict[str, object]:
        return {
            "path": str(self.corpus / "invalid.json"),
            "record_type": "evidence_receipt_v2",
            "valid": False,
            "signatures_verified": False,
            "error": "benign parse rejection",
        } | updates

    def use_go_report(
        self, report: str, *, status: int = 2, label: str = "GO_VERIFY"
    ) -> None:
        fake = self.root / "parse report.py"
        fake.write_text(
            "import pathlib, sys\n"
            "if pathlib.Path(sys.argv[1]).name == 'valid.json': sys.exit(0)\n"
            f"print({report!r})\n"
            "print('separate diagnostic', file=sys.stderr)\n"
            f"sys.exit({status})\n",
            encoding="utf-8",
        )
        self.env[label] = shlex.join([sys.executable, str(fake)])

    def test_go_typed_parse_rejection_is_expected_rejection(self) -> None:
        self.use_go_report(json.dumps(self.go_parse_report()))
        code, output = self.invoke()
        self.assertEqual(code, 0, output)
        self.assertIn("invalid reject reject reject reject reject ok", output)

    def test_go_parse_rejection_of_expected_valid_fixture_is_mismatch(self) -> None:
        report = self.go_parse_report(path=str(self.corpus / "valid.json"))
        fake = self.root / "reject valid.py"
        self.env["GO_VERIFY"] = shlex.join([sys.executable, str(fake)])
        for path, expected_status in (
            (str(self.corpus / "valid.json"), 1),
            (str(self.corpus / "another.json"), 2),
        ):
            with self.subTest(report_path=path):
                report["path"] = path
                fake.write_text(
                    "import json\n"
                    f"print(json.dumps({report!r}))\n"
                    "raise SystemExit(2)\n",
                    encoding="utf-8",
                )
                code, output = self.invoke()
                self.assertEqual(code, expected_status, output)
                if expected_status == 1:
                    self.assertIn("DIFFERENTIAL+EXPECT-MISMATCH", output)
                    self.assertIn("known-valid smoke failed", output)
                    self.assertNotIn("command failed with exit", output)
                else:
                    self.assertIn("command failed with exit 2", output)

    def test_go_parse_rejection_without_detected_type_is_expected(self) -> None:
        report = self.go_parse_report()
        report.pop("record_type")
        self.use_go_report(json.dumps(report))
        code, output = self.invoke()
        self.assertEqual(code, 0, output)
        self.assertIn("invalid reject reject reject reject reject ok", output)
        case = GATE.Case("invalid", self.corpus / "invalid.json", False)
        for key in ("path", "valid", "signatures_verified", "error"):
            missing = report.copy()
            missing.pop(key)
            with self.subTest(missing=key):
                self.assertFalse(
                    GATE.go_parse_rejection(json.dumps(missing).encode(), case)
                )
        for changes in (
            {"valid": True},
            {"path": "/wrong/fixture.json"},
            {"extra": True},
        ):
            with self.subTest(changes=changes):
                self.assertFalse(
                    GATE.go_parse_rejection(json.dumps(report | changes).encode(), case)
                )

    def test_go_exit_two_without_exact_bound_rejection_report_is_fatal(self) -> None:
        changes = [
            {"path": "/wrong/fixture.json"},
            {"record_type": "action_receipt_v1"},
            {"record_type": None},
            {"record_type": ""},
            {"record_type": False},
            {"valid": True},
            {"valid": 0},
            {"valid": "false"},
            {"signatures_verified": True},
            {"signatures_verified": 0},
            {"error": ""},
            {"error": "   "},
            {"error": False},
            {"unpinned": True},
            {"valid_extra": True},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.use_go_report(json.dumps(self.go_parse_report(**change)))
                self.assertEqual(self.invoke()[0], 2)
        missing = self.go_parse_report()
        missing.pop("error")
        for report in (
            "",
            "file read failed",
            "{}",
            "[]",
            "null",
            json.dumps(missing),
            json.dumps(self.go_parse_report()) + " {}",
            json.dumps(self.go_parse_report())[:-1] + ',"valid":false}',
            " " * 65537 + json.dumps(self.go_parse_report()),
        ):
            with self.subTest(report=report[:80]):
                self.use_go_report(report)
                self.assertEqual(self.invoke()[0], 2)

    def test_report_exception_is_only_go_exit_two(self) -> None:
        baseline = self.env.copy()
        for label, status in (
            ("TS_VERIFY", 2),
            ("RUST_VERIFY", 2),
            ("PY_VERIFY", 2),
            ("GO_VERIFY", 3),
            ("GO_VERIFY", 127),
        ):
            with self.subTest(label=label, status=status):
                self.env = baseline.copy()
                self.use_go_report(
                    json.dumps(self.go_parse_report()), status=status, label=label
                )
                self.assertEqual(self.invoke()[0], 2)

    def test_go_parse_report_requires_utf8(self) -> None:
        case = GATE.Case("invalid", self.corpus / "invalid.json", False)
        self.assertFalse(GATE.go_parse_rejection(b"\xff", case))

    def test_signal_is_infrastructure_failure(self) -> None:
        with patch.object(
            GATE.subprocess, "run", return_value=subprocess.CompletedProcess([], -15)
        ):
            code, output = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn("command failed with exit -15", output)

    def test_actual_timeout_is_infrastructure_failure(self) -> None:
        # An inert event wait performs no service I/O. A timeout on the negative
        # fixture must never masquerade as its expected rejection.
        self.fake_body(
            "if pathlib.Path(sys.argv[3]).name == 'valid.json': sys.exit(0)\n"
            "import threading\nthreading.Event().wait()\n"
        )
        code, output = self.invoke(timeout="0.5")
        self.assertEqual(code, 2)
        self.assertIn("timed out after 0.5s on invalid", output)

    def test_missing_executable_is_infrastructure_failure(self) -> None:
        self.env["GO_VERIFY"] = str(self.root / "missing")
        code, output = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn("could not run verifier", output)

    def test_unexecutable_command_is_infrastructure_failure(self) -> None:
        self.env["GO_VERIFY"] = shlex.quote(str(self.fake))
        self.assertEqual(self.invoke()[0], 2)

    def test_all_four_commands_are_required(self) -> None:
        for variable in GATE.COMMANDS:
            with self.subTest(variable=variable):
                with patch.dict(self.env, {variable: ""}):
                    code, output = self.invoke()
                self.assertEqual(code, 2)
                self.assertIn(variable, output)

    def test_bad_command_quoting_and_nul_are_configuration_errors(self) -> None:
        for value in ("'unterminated", '""', "python\0"):
            with self.subTest(value=value):
                commands = self.env | {"GO_VERIFY": value}
                with self.assertRaises(GATE.GateError):
                    GATE.load_commands(commands)

    def test_manifest_metadata_supported(self) -> None:
        self.manifest.update(
            status="fixture_only",
            test_key_derivation="TEST ONLY",
            registry_manifest="registry-manifest.json",
        )
        self.save_manifest()
        self.assertEqual(self.invoke()[0], 0)

    def test_missing_corpus_or_manifest_is_fatal(self) -> None:
        for directory in (self.root / "missing", self.root):
            with self.subTest(directory=directory), self.assertRaises(GATE.GateError):
                GATE.load_corpus(directory)

    def test_invalid_manifest_json(self) -> None:
        for text in ("not JSON", '{"version":1,"version":1}', "[]", "null"):
            with self.subTest(text=text):
                (self.corpus / "manifest.json").write_text(text, encoding="utf-8")
                self.assertEqual(self.invoke()[0], 2)

    def test_invalid_utf8_manifest(self) -> None:
        (self.corpus / "manifest.json").write_bytes(b"\xff")
        self.assertEqual(self.invoke()[0], 2)

    def test_manifest_root_and_fields_validated(self) -> None:
        changes = [
            {"version": True},
            {"version": 2},
            {"version": "1"},
            {"public_key_hex": "AB" * 32},
            {"public_key_hex": "ab"},
            {"public_key_hex": None},
            {"registry_hash": "cd" * 32},
            {"registry_hash": "sha256:" + "CD" * 32},
            {"cases": []},
            {"cases": {}},
            {"cases": [None]},
            {"cases": [{"name": "incomplete"}]},
            {"extra": 1},
            {"status": "published"},
            {"test_key_derivation": ""},
            {"registry_manifest": False},
        ]
        baseline = self.manifest.copy()
        for change in changes:
            with self.subTest(change=change):
                self.manifest = baseline | change
                self.save_manifest()
                self.assertEqual(self.invoke()[0], 2)
        self.manifest = baseline.copy()
        del self.manifest["registry_hash"]
        self.save_manifest()
        self.assertEqual(self.invoke()[0], 2)

    def test_case_fields_validated(self) -> None:
        baseline = self.manifest["cases"][1].copy()
        changes = [
            {"name": "valid"},
            {"name": ""},
            {"name": "spaces "},
            {"name": "line\nbreak"},
            {"name": 1},
            {"valid": 0},
            {"valid": "false"},
            {"reason": ""},
            {"reason": None},
            {"file": False},
            {"file": ""},
            {"extra": 1},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.manifest["cases"][1] = baseline | change
                self.save_manifest()
                self.assertEqual(self.invoke()[0], 2)

    def test_requires_both_valid_and_invalid_cases(self) -> None:
        for valid in (True, False):
            with self.subTest(valid=valid):
                for entry in self.manifest["cases"]:
                    entry["valid"] = valid
                self.save_manifest()
                self.assertEqual(self.invoke()[0], 2)

    def test_unsafe_missing_and_duplicate_fixture_paths(self) -> None:
        paths = [
            "../outside.json",
            "/absolute.json",
            "./invalid.json",
            "nested//invalid.json",
            "nested/../invalid.json",
            "nested\\invalid.json",
            "invalid.txt",
            "absent.json",
            "valid.json",
            "manifest.json",
        ]
        for filename in paths:
            with self.subTest(filename=filename):
                self.manifest["cases"][1]["file"] = filename
                self.save_manifest()
                self.assertEqual(self.invoke()[0], 2)

    def test_directory_fixture_rejected(self) -> None:
        (self.corpus / "directory.json").mkdir()
        self.manifest["cases"][1]["file"] = "directory.json"
        self.save_manifest()
        self.assertEqual(self.invoke()[0], 2)

    def test_outside_and_aliased_fixture_symlinks_rejected(self) -> None:
        outside = self.root / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        alias = self.corpus / "alias.json"
        for target in (outside, self.corpus / "valid.json"):
            with self.subTest(target=target):
                alias.symlink_to(target)
                self.manifest["cases"][1]["file"] = "alias.json"
                self.save_manifest()
                self.assertEqual(self.invoke()[0], 2)
                alias.unlink()

    def test_manifest_symlink_outside_corpus_rejected(self) -> None:
        manifest_path = self.corpus / "manifest.json"
        outside = self.root / "outside.json"
        manifest_path.rename(outside)
        manifest_path.symlink_to(outside)
        self.assertEqual(self.invoke()[0], 2)

    def test_looping_fixture_symlink_is_configuration_error(self) -> None:
        alias = self.corpus / "alias.json"
        alias.symlink_to(alias)
        self.manifest["cases"][1]["file"] = "alias.json"
        self.save_manifest()
        self.assertEqual(self.invoke()[0], 2)

    def test_bad_timeouts_rejected(self) -> None:
        for timeout in ("nan", "inf", "0", "-1", "nonsense"):
            with (
                self.subTest(timeout=timeout),
                self.assertRaises(SystemExit) as failure,
            ):
                self.invoke(timeout=timeout)
            self.assertEqual(failure.exception.code, 2)

    def test_main_environment_corpus_and_default_timeout(self) -> None:
        self.env["SECRET_EGRESS_CORPUS"] = str(self.corpus)
        with (
            patch.dict(os.environ, self.env, clear=True),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(GATE.main([]), 0)

    def test_command_diagnostics_are_bounded(self) -> None:
        self.fake_body("print('diagnostic' * 1000)\nsys.exit(2)\n")
        code, output = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn("diagnostic", output)
        self.assertLess(len(output), 4400)

    def test_script_entry_point(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--corpus", str(self.corpus)],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def shell_gate(self, *, provenance_only: bool) -> subprocess.CompletedProcess[str]:
        # Exercise only plumbing with inert local fake CLIs and tiny fake corpora.
        # Existing legacy shell commands deliberately retain their old splitting
        # behavior, so use a separate no-space directory for this integration.
        with tempfile.TemporaryDirectory(prefix="gate-integration-") as directory:
            root = Path(directory)
            shell = root / "corpus-gate.sh"
            shell.write_text(SCRIPT.with_name("corpus-gate.sh").read_text())
            (root / SCRIPT.name).write_text(SCRIPT.read_text())
            fake = root / "fake.py"
            fake.write_text(
                "import sys\n"
                "if '--key' in sys.argv: sys.exit(0)\n"
                'print(\'{"overall":"valid"}\')\n'
            )
            command = shlex.join([sys.executable, str(fake)])
            legacy = root / "legacy"
            golden = legacy / "golden"
            golden.mkdir(parents=True)
            (golden / "01-allow-clean-get.json").write_text("{}")
            (golden / "01-allow-clean-get.expect.json").write_text(
                '{"verdict":"accept"}'
            )
            provenance = root / "provenance"
            provenance.mkdir()
            (provenance / "benign.json").write_text("{}")
            (provenance / "benign.expect.json").write_text('{"overall":"valid"}')
            env = os.environ | dict.fromkeys(GATE.COMMANDS, command)
            env.update(
                dict.fromkeys(
                    (
                        "GO_PROVENANCE",
                        "TS_PROVENANCE",
                        "RUST_PROVENANCE",
                        "PY_PROVENANCE",
                    ),
                    command,
                )
            )
            env.update(
                KEY="ab" * 32,
                CORPUS=str(legacy),
                PROVENANCE_CORPUS=str(provenance),
                SECRET_EGRESS_CORPUS=str(root / "missing-candidate-corpus"),
                PROVENANCE_ONLY="1" if provenance_only else "0",
            )
            if provenance_only:
                for variable in GATE.COMMANDS:
                    env.pop(variable)
            return subprocess.run(
                ["bash", str(shell)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

    def test_shell_integration_requires_new_corpus_in_ordinary_lane(self) -> None:
        result = self.shell_gate(provenance_only=False)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("cannot read corpus manifest", result.stderr)
        self.assertIn("all four verifiers agree across the corpus", result.stdout)

    def test_shell_provenance_only_does_not_require_new_corpus_or_receipt_commands(
        self,
    ) -> None:
        result = self.shell_gate(provenance_only=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("byte-identical staged provenance results", result.stdout)
        self.assertNotIn("SECRET-EGRESS", result.stdout)


if __name__ == "__main__":
    unittest.main()
