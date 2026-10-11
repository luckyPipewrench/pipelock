# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Require four CLI consumers to agree on schema keys and free-form maps.

Uses the same GO_AARP/TS_AARP/RUST_AARP/PY_AARP prefixes as aarp-corpus-gate.sh.
Every artifact has an accepted control, so rejection cannot mask broken wiring.
"""

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "testdata"
CORPUS = DATA / "aarp-corpus"
KEY = json.loads((DATA / "test-key.json").read_text())["public_key_hex"]


def alias(text, key, vector):
    """Insert a noncanonical alias without changing the signed original value."""
    marker = json.dumps(key) + ":"
    if marker not in text:
        raise ValueError(f"fixture has no field {key}")
    spelling = vector.get("alias", key.upper())
    encoded = json.dumps(spelling)
    if vector.get("escaped_alias", False):
        encoded = '"' + "".join(f"\\u{ord(char):04x}" for char in spelling) + '"'
    return text.replace(marker, encoded + ":null," + marker, 1)


def prepare(vector, directory):
    artifact, variant = vector["artifact"], vector["variant"]
    target = directory / "input.json"
    if artifact in ("aarp-ext", "svid"):
        source = CORPUS / (
            "golden/g01-single-ed25519-mediated.aarp.json"
            if artifact == "aarp-ext"
            else "svid/s02-valid-ed25519-baseline.aarp.json"
        )
        text = source.read_text()
        if artifact == "aarp-ext":
            if variant == "case-distinct-map":
                obj = json.loads(text)
                obj["ext"] = {
                    "vendor.note": "one",
                    "Vendor.Note": "two",
                    "k": 1,
                    "K": 2,
                }
                text = json.dumps(obj)
            elif variant == "exact-map-duplicate":
                text = (
                    text.rstrip().removesuffix("}")
                    + ',"ext":{"vendor.note":1,"vendor.note":2}}'
                )
            elif variant == "schema-alias":
                text = alias(text, "profile", vector)
        target.write_text(text)
        args = ["aarp", str(target), "--trust", str(CORPUS / "trust.json"), "--json"]
        if artifact == "svid":
            sidecar = directory / "svid.json"
            text = source.with_name(
                source.name.replace(".aarp.json", ".svid.json")
            ).read_text()
            sidecar.write_text(
                alias(text, "verify", vector) if variant == "schema-alias" else text
            )
            args += ["--svid", str(sidecar)]
        return args
    if artifact == "rotation":
        source = DATA / "parity/rotated"
        target = directory / "rotated"
        shutil.copytree(source, target)
        endorsement = target / "rotation-endorsement.json"
        if variant == "schema-alias":
            endorsement.write_text(alias(endorsement.read_text(), "version", vector))
        return [
            "chain",
            str(target),
            "--dir",
            "--key",
            str(target / "signer-key.hex"),
            "--rotation-endorsement",
            str(endorsement),
            "--json",
        ]
    if artifact == "recorder-line":
        source = DATA / "g1-ext-chain.jsonl"
        text = source.read_text()
        if variant == "schema-alias":
            text = alias(text, "action_record", vector)
        target.write_text(text)
        args = ["chain", str(target), "--key", KEY, "--json"]
        return args
    if artifact == "group":
        archive = ROOT.parent / "verifiers/ts/tests/fixtures/receipt-groups.zip"
        with zipfile.ZipFile(archive) as z:
            for member in z.namelist():
                if member.startswith("group-valid/"):
                    relative = Path(member)
                    if relative.is_absolute() or ".." in relative.parts:
                        raise ValueError("unsafe fixture archive path")
                    z.extract(member, directory)
        group = directory / "group-valid"
        manifest = next(group.glob("receipt-group-*-open.json"))
        group_id = manifest.name.removeprefix("receipt-group-").removesuffix(
            "-open.json"
        )
        keys = json.loads((group / "trust.json").read_text())["trusted_keys"]
        if variant == "schema-alias":
            manifest.write_text(alias(manifest.read_text(), "version", vector))
        return [
            "chain",
            str(group),
            "--dir",
            "--group",
            group_id,
            "--key",
            ",".join(keys),
            "--json",
        ]
    if artifact == "provenance-proof":
        text = (DATA / "key-artifacts/provenance-control.json").read_text()
        target.write_text(
            alias(text, "format", vector) if variant == "schema-alias" else text
        )
        return ["provenance", str(target), "--allow-incomplete"]
    raise ValueError(f"unknown artifact {artifact}")


def main():
    commands = {}
    for name in ("GO", "TS", "RUST", "PY"):
        command = shlex.split(os.environ[name + "_AARP"])
        if not command or command[-1] != "aarp":
            raise ValueError(f"{name}_AARP must end in aarp")
        commands[name] = command[:-1]
    vectors_path = Path(
        os.environ.get(
            "PIPELOCK_KEY_ARTIFACT_VECTORS", DATA / "key-artifacts/vectors.json"
        )
    )
    vectors = json.loads(vectors_path.read_text())
    failures = 0
    with tempfile.TemporaryDirectory(prefix="pipelock-key-artifacts-") as temp:
        for index, vector in enumerate(vectors):
            directory = Path(temp) / str(index)
            directory.mkdir()
            args = prepare(vector, directory)
            verdicts = {}
            for name, command in commands.items():
                # Python does not implement rotation endorsements. Its real
                # receipt and group consumers use different command names.
                if vector["artifact"] == "rotation" and name == "PY":
                    continue
                cli_args = list(args)
                if name == "PY" and vector["artifact"] == "recorder-line":
                    cli_args[0] = "receipt"
                    cli_args += ["--chain"]
                if vector["artifact"] == "group" and name in ("RUST", "PY"):
                    group_index = cli_args.index("--group")
                    group_id = cli_args[group_index + 1]
                    key = cli_args[cli_args.index("--key") + 1]
                    cli_args = (
                        ["group", cli_args[1], "--group-id", group_id]
                        if name == "RUST"
                        else ["receipt", cli_args[1], "--group", group_id]
                    )
                    cli_args += ["--key", key, "--json"]
                result = subprocess.run(
                    command + cli_args,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                verdicts[name] = result.returncode == 0
                if verdicts[name] != vector["accept"]:
                    print(f"{name}: {result.stdout}\n{result.stderr}")
            passed = all(value == vector["accept"] for value in verdicts.values())
            failures += not passed
            print(
                vector["artifact"],
                vector["variant"],
                verdicts,
                "PASS" if passed else "FAIL",
                flush=True,
            )
    print(
        "Rotation parity covers Go/TypeScript/Rust; Python has no rotation-endorsement parser/CLI."
    )
    print(f"{len(vectors)} artifact vectors; {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
