# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Check signed secret-egress fixtures with all four receipt CLI verifiers.

This is fixture-only offline conformance, not a runtime egress gate. Commands
come from GO_VERIFY, TS_VERIFY, RUST_VERIFY and PY_VERIFY. Candidate-only
SECRET_EGRESS_GO_VERIFY and SECRET_EGRESS_PY_VERIFY overrides can select the
v2-capable in-repo CLIs without changing legacy lanes. Commands use shell-style
quoting but never a shell, and receive ``<fixture> --key <manifest public key>``.
The gate exits 0 for conformance, 1 for a verdict mismatch, and 2 for unusable
configuration or a command failure. Verifier subprocesses return 0 for accept
and 1 for reject. The existing Go CLI also returns 2 for a parse rejection;
only its strictly validated, fixture-bound JSON rejection report is accepted
as that documented exception. The CLI omits record_type when detection fails.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

COMMANDS = ("GO_VERIFY", "TS_VERIFY", "RUST_VERIFY", "PY_VERIFY")
DEFAULT_CORPUS = Path(__file__).resolve().parent / "testdata" / "secret-egress-v1"
HEX_256 = re.compile(r"[0-9a-f]{64}\Z")


class GateError(Exception):
    """An infrastructure or manifest error, never an expected rejection."""


@dataclass(frozen=True)
class Case:
    name: str
    path: Path
    valid: bool


@dataclass(frozen=True)
class Corpus:
    public_key_hex: str
    cases: tuple[Case, ...]


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GateError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def nonempty_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and value == value.strip()
        and value.isprintable()
    )


def load_corpus(directory: Path) -> Corpus:
    try:
        root = directory.resolve(strict=True)
        manifest_path = (root / "manifest.json").resolve(strict=True)
        if not manifest_path.is_relative_to(root):
            raise GateError("manifest must stay inside the corpus directory")
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
        )
    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        raise GateError(f"cannot read corpus manifest: {exc}") from exc
    required = {"version", "public_key_hex", "registry_hash", "cases"}
    optional = {"status", "test_key_derivation", "registry_manifest"}
    if (
        not isinstance(manifest, dict)
        or not required <= set(manifest)
        or not set(manifest) <= required | optional
    ):
        raise GateError(
            "manifest must contain version, public_key_hex, registry_hash, cases"
        )
    if type(manifest["version"]) is not int or manifest["version"] != 1:
        raise GateError("manifest version must be integer 1")
    key = manifest["public_key_hex"]
    if not isinstance(key, str) or not HEX_256.fullmatch(key):
        raise GateError(
            "manifest public_key_hex must be 64 lowercase hexadecimal characters"
        )
    digest = manifest["registry_hash"]
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise GateError(
            "manifest registry_hash must be sha256: plus 64 lowercase hex characters"
        )
    if "status" in manifest and manifest["status"] != "fixture_only":
        raise GateError("manifest status must be fixture_only")
    for field in ("test_key_derivation", "registry_manifest"):
        if field in manifest and not nonempty_text(manifest[field]):
            raise GateError(f"manifest {field} must be nonempty printable text")
    entries = manifest["cases"]
    if not isinstance(entries, list) or not entries:
        raise GateError("manifest cases must be a nonempty array")

    names: set[str] = set()
    paths: set[Path] = set()
    cases: list[Case] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "name",
            "file",
            "valid",
            "reason",
        }:
            raise GateError("each case must contain name, file, valid, reason")
        name = entry["name"]
        if not nonempty_text(name) or name in names:
            raise GateError("case names must be nonempty, printable and unique")
        if not nonempty_text(entry["reason"]):
            raise GateError(f"{name}: reason must be nonempty printable text")
        if type(entry["valid"]) is not bool:
            raise GateError(f"{name}: valid must be a boolean")
        filename = entry["file"]
        if not isinstance(filename, str) or not nonempty_text(filename):
            raise GateError(f"{name}: file must be a relative JSON path")
        relative = PurePosixPath(filename)
        if (
            relative.is_absolute()
            or "\\" in filename
            or any(part in ("", ".", "..") for part in filename.split("/"))
            or relative.suffix != ".json"
        ):
            raise GateError(
                f"{name}: file must be a relative JSON path without traversal"
            )
        try:
            path = (root / filename).resolve(strict=True)
        except (OSError, ValueError, RuntimeError) as exc:
            raise GateError(f"{name}: cannot resolve fixture: {exc}") from exc
        if not path.is_relative_to(root) or not path.is_file() or path == manifest_path:
            raise GateError(f"{name}: fixture must be a regular file inside the corpus")
        if path in paths:
            raise GateError(f"{name}: fixture paths must be unique")
        names.add(name)
        paths.add(path)
        case = Case(name, path, entry["valid"])
        if case.valid:
            require_secret_egress_fixture(case)
        cases.append(case)
    if {case.valid for case in cases} != {False, True}:
        raise GateError("corpus must include both valid and invalid cases")
    return Corpus(manifest["public_key_hex"], tuple(cases))


def require_secret_egress_fixture(case: Case) -> None:
    """Bind expected-valid cases to this lane, without duplicating verification.

    Negative cases can deliberately use another kind or malformed JSON. The
    Go conformance test separately pins the committed corpus byte-for-byte;
    this guard also binds a caller-selected standalone corpus to the new kind.
    """
    try:
        receipt = json.loads(
            case.path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, UnicodeError, ValueError, GateError) as exc:
        raise GateError(
            f"{case.name}: cannot read expected-valid fixture: {exc}"
        ) from exc
    if (
        not isinstance(receipt, dict)
        or receipt.get("record_type") != "evidence_receipt_v2"
        or receipt.get("payload_kind") != "secret_egress_decision_v1"
    ):
        raise GateError(
            f"{case.name}: expected-valid fixture must be a secret-egress evidence receipt"
        )


def load_commands(environ: Mapping[str, str]) -> dict[str, list[str]]:
    commands: dict[str, list[str]] = {}
    for variable in COMMANDS:
        try:
            value = environ.get(variable, "")
            if variable in ("GO_VERIFY", "PY_VERIFY"):
                value = environ.get(f"SECRET_EGRESS_{variable}", value)
            command = shlex.split(value)
        except ValueError as exc:
            raise GateError(f"{variable}: invalid command quoting: {exc}") from exc
        if not command or not command[0] or any("\0" in arg for arg in command):
            raise GateError(
                f"{variable} must set a usable verifier command (need all four)"
            )
        commands[variable] = command
    return commands


def go_parse_rejection(output: bytes, case: Case) -> bool:
    """Recognize Go's typed parse-rejection report, not generic exit-2 errors.

    The existing standalone CLI's decode-failure branch emits this report
    with --json; record_type is omitted when receipt detection cannot name it. Key resolution and file-read/config failures do not emit it.
    Keeping this exception here avoids changing existing CLI exit semantics.
    """
    if len(output) > 65536:
        return False
    try:
        report = json.loads(output.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, GateError):
        return False
    return (
        isinstance(report, dict)
        and set(report)
        in (
            {"path", "valid", "signatures_verified", "error"},
            {"path", "record_type", "valid", "signatures_verified", "error"},
        )
        and report["path"] == str(case.path)
        and (
            "record_type" not in report
            or report["record_type"] == "evidence_receipt_v2"
        )
        and report["valid"] is False
        and report["signatures_verified"] is False
        and isinstance(report["error"], str)
        and bool(report["error"].strip())
    )


def verdict(
    label: str, command: list[str], case: Case, key: str, timeout: float
) -> bool:
    # Separate stdout's machine report from stderr diagnostics. Temporary files
    # avoid accumulating arbitrary output in memory; reads are bounded below.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as diagnostics:
        try:
            result = subprocess.run(
                [*command, str(case.path), "--key", key],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=diagnostics,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GateError(
                f"{label}: timed out after {timeout:g}s on {case.name}"
            ) from exc
        except (OSError, ValueError) as exc:
            raise GateError(
                f"{label}: could not run verifier on {case.name}: {exc}"
            ) from exc
        if result.returncode not in (0, 1):
            output.seek(0)
            if (
                label == "GO_VERIFY"
                and result.returncode == 2
                and go_parse_rejection(output.read(65537), case)
            ):
                return False
            output.seek(0)
            diagnostics.seek(0)
            detail = (
                (output.read(2048) + diagnostics.read(2048))
                .decode("utf-8", errors="replace")
                .strip()
            )
            raise GateError(
                f"{label}: command failed with exit {result.returncode} on {case.name}"
                + (f"\n{detail}" if detail else "")
            )
    return result.returncode == 0


def run_gate(corpus: Corpus, commands: dict[str, list[str]], timeout: float) -> int:
    # Run a known-valid fixture first. Four broken/all-reject commands cannot
    # make an invalid-only run appear to demonstrate successful verification.
    smoke = next(case for case in corpus.cases if case.valid)
    ordered = (smoke, *(case for case in corpus.cases if case is not smoke))
    failures = 0
    print("SECRET-EGRESS FIXTURE EXPECT GO TS RUST PY RESULT")
    for case in ordered:
        results = [
            verdict(label, command, case, corpus.public_key_hex, timeout)
            for label, command in commands.items()
        ]
        issues = []
        if len(set(results)) != 1:
            issues.append("DIFFERENTIAL")
        if any(result != case.valid for result in results):
            issues.append("EXPECT-MISMATCH")
        expected = "accept" if case.valid else "reject"
        observed = " ".join("accept" if result else "reject" for result in results)
        print(f"{case.name} {expected} {observed} {'+'.join(issues) or 'ok'}")
        if issues:
            failures += 1
            if case is smoke:
                print(
                    "FAIL: known-valid smoke failed; "
                    "check receipt validation and command wiring"
                )
                return 1
    print(
        f"checked {len(ordered)} signed secret-egress fixtures; {failures} failure(s)"
    )
    if failures:
        return 1
    print("PASS: all four receipt CLIs match every signed secret-egress expectation")
    return 0


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "timeout must be a positive finite number"
        ) from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be a positive finite number")
    return timeout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=os.environ.get("SECRET_EGRESS_CORPUS", str(DEFAULT_CORPUS)),
    )
    parser.add_argument("--timeout", type=positive_timeout, default=30.0)
    args = parser.parse_args(argv)
    try:
        commands = load_commands(os.environ)
        corpus = load_corpus(args.corpus)
        return run_gate(corpus, commands, args.timeout)
    except (GateError, OSError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
