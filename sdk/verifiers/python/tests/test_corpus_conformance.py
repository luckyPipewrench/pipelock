# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Corpus-driven conformance test over EVERY fixture in the AARP corpus.

For each fixture:

  - ``appraise`` verdict: the CLI must exit 0 and its ``--json`` stdout must equal
    the committed ``.appraisal.json`` bytes (trailing whitespace trimmed).
  - ``fatal`` verdict: the CLI must exit non-zero.

This is the same equality surface the cross-language gate enforces, so a pass here
means the Python arm agrees with the Go reference on the whole corpus.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from pipelock_aarp_verify.cli import main


def _iter_expect_files(corpus_dir: Path) -> list[Path]:
    out: list[Path] = []
    for category in ("golden", "malicious", "edge", "chain", "svid"):
        out.extend(sorted((corpus_dir / category).glob("*.expect.json")))
    return out


def _fixture_params(corpus_dir: Path) -> list[tuple[str, Path, dict]]:
    params: list[tuple[str, Path, dict]] = []
    for expfile in _iter_expect_files(corpus_dir):
        meta = json.loads(expfile.read_text())
        base = expfile.name[: -len(".expect.json")]
        params.append((base, expfile, meta))
    return params


# Build the parametrization at import time so each fixture is a named test case.
_CORPUS = (
    Path(__file__).resolve().parents[3] / "conformance" / "testdata" / "aarp-corpus"
)
_PARAMS = _fixture_params(_CORPUS)


def _run_cli(args: list[str]) -> tuple[int, str]:
    """Invoke the CLI with stdout captured; returns (exit_code, stdout)."""
    old_out = sys.stdout
    buf = io.StringIO()
    sys.stdout = buf
    try:
        rc = main(args)
    finally:
        sys.stdout = old_out
    return rc, buf.getvalue()


@pytest.mark.parametrize("base,expfile,meta", _PARAMS, ids=[p[0] for p in _PARAMS])
def test_corpus_fixture(base: str, expfile: Path, meta: dict, trust_path: Path) -> None:
    category = meta["category"]
    verdict = meta["verdict"]
    informat = meta.get("input_format", "envelope")
    corpus_dir = expfile.parent

    if informat == "chain":
        fixture = corpus_dir / f"{base}.aarp.jsonl"
        args = ["aarp", str(fixture), "--trust", str(trust_path), "--chain", "--json"]
    elif category == "svid":
        fixture = corpus_dir / f"{base}.aarp.json"
        sidecar = corpus_dir / f"{base}.svid.json"
        assert sidecar.is_file(), f"missing svid sidecar {sidecar}"
        args = [
            "aarp",
            str(fixture),
            "--trust",
            str(trust_path),
            "--svid",
            str(sidecar),
            "--json",
        ]
    else:
        fixture = corpus_dir / f"{base}.aarp.json"
        args = ["aarp", str(fixture), "--trust", str(trust_path), "--json"]

    assert fixture.is_file(), f"missing fixture {fixture}"
    rc, out = _run_cli(args)

    if verdict == "fatal":
        assert rc != 0, f"{base}: expected non-zero exit, got {rc}; stdout={out!r}"
    else:
        assert rc == 0, f"{base}: expected exit 0, got {rc}; stdout={out!r}"
        want = (corpus_dir / f"{base}.appraisal.json").read_text()
        assert out.strip() == want.strip(), (
            f"{base}: comparable output does not match committed appraisal\n"
            f"  got:  {out.strip()!r}\n  want: {want.strip()!r}"
        )
    assert category in {"golden", "malicious", "edge", "chain", "svid"}


def test_corpus_is_nonempty() -> None:
    # Guard against a silently-empty corpus path producing a vacuous pass. The
    # corpus is 35 envelope fixtures (golden/malicious/edge/chain) plus 21 svid
    # (s01-s21), so 56 total.
    assert len(_PARAMS) >= 56, (
        f"expected the full corpus, found {len(_PARAMS)} fixtures"
    )
