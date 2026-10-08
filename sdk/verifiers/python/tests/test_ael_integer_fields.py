# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Native AEL integer fields follow Go's typed decode.

Go decodes ``v``, ``seq``, ``count``, ``hmax`` and ``htol`` into integer types,
so a JSON boolean or float is a decode error. Python treats ``True == 1``, so
each integer field needs an exact-type check. Malformed field types must raise
AELVerificationError, never TypeError.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pipelock_aarp_verify.ael import AELVerificationError, _go_json, verify_ael_run

RUN = "ab" * 16
TS = "2026-10-07T00:00:00Z"


def _b64(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


class _Run:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.signer = self.pub.hex()
        self.key_id = hashlib.sha256(self.pub).hexdigest()

    def base(self, seq: int, prev: str, kind: str) -> dict[str, Any]:
        return {
            "key": self.key_id,
            "prev": prev,
            "recorder": "pipelock",
            "run": RUN,
            "seq": seq,
            "ts": TS,
            "type": kind,
            "v": 1,
        }

    def write(self, records: list[dict[str, Any]]) -> None:
        run_dir = self.root / "ael" / RUN
        (run_dir / "keys").mkdir(parents=True)
        (run_dir / "recorders").mkdir(parents=True)
        manifest = {
            "ael_format": 1,
            "coverage": "mediated-only",
            "custody": "same-process",
            "recorders": [
                {
                    "file": "recorders/pipelock.jsonl",
                    "id": "pipelock",
                    "key": self.key_id,
                    "run": RUN,
                }
            ],
            "runs": [RUN],
        }
        (run_dir / "manifest.json").write_bytes(_go_json(manifest))
        (run_dir / "keys" / f"{self.key_id}.pub").write_bytes(
            base64.b64encode(self.pub)
        )
        lines = []
        for record in records:
            payload = _go_json(record)
            lines.append(_b64(payload) + b"." + _b64(self.key.sign(payload)))
        (run_dir / "recorders" / "pipelock.jsonl").write_bytes(
            b"\n".join(lines) + b"\n"
        )


def _records(run: _Run, mutate: Any = None) -> list[dict[str, Any]]:
    zero = "0" * 64
    opening = {**run.base(0, zero, "open"), "hmax": 30, "htol": 5}
    activity = {
        **run.base(1, hashlib.sha256(_go_json(opening)).hexdigest(), "activity"),
        "event": {"class": "http", "dir": "out", "id": "evt-1"},
    }
    closing = {
        **run.base(2, hashlib.sha256(_go_json(activity)).hexdigest(), "close"),
        "count": 3,
        "head": hashlib.sha256(_go_json(activity)).hexdigest(),
    }
    records = [opening, activity, closing]
    if mutate is not None:
        mutate(records)
    return records


def _rechain(records: list[dict[str, Any]]) -> None:
    """Recompute prev/head after a mutation so only the mutated field is wrong."""
    prev = "0" * 64
    for record in records:
        record["prev"] = prev
        if record["type"] == "close":
            record["head"] = prev
        prev = hashlib.sha256(_go_json(record)).hexdigest()


def _verify(tmp_path: Path, mutate: Any = None) -> dict[str, Any]:
    run = _Run(tmp_path)
    records = _records(run, mutate)
    if mutate is not None:
        _rechain(records)
    run.write(records)
    return verify_ael_run(tmp_path, RUN, run.signer)


def test_well_formed_signed_run_verifies(tmp_path: Path) -> None:
    head = _verify(tmp_path)
    assert head["record_count"] == 3
    assert head["final_seq"] == 2


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        ("v-true", lambda r: r[0].__setitem__("v", True)),
        ("v-float", lambda r: r[0].__setitem__("v", 1.0)),
        ("seq-true", lambda r: r[1].__setitem__("seq", True)),
        ("hmax-true", lambda r: r[0].__setitem__("hmax", True)),
        ("htol-false", lambda r: r[0].__setitem__("htol", False)),
        ("count-true", lambda r: r[2].__setitem__("count", True)),
        ("event-dir-list", lambda r: r[1]["event"].__setitem__("dir", ["out"])),
        ("event-class-number", lambda r: r[1]["event"].__setitem__("class", 7)),
        ("event-id-object", lambda r: r[1]["event"].__setitem__("id", {"a": 1})),
    ],
)
def test_malformed_integer_and_string_fields_raise_ael_error(
    tmp_path: Path, name: str, mutate: Any
) -> None:
    with pytest.raises(AELVerificationError):
        _verify(tmp_path, mutate)


def test_control_mutation_is_not_vacuous(tmp_path: Path) -> None:
    """A mutation that keeps the types valid still verifies (the rechain works)."""
    head = _verify(tmp_path, lambda r: copy.deepcopy(r))
    assert head["record_count"] == 3
    assert json.dumps(head)
