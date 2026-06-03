# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Shared test fixtures: locate the committed AARP conformance corpus."""

from __future__ import annotations

from pathlib import Path

import pytest

# tests/ -> python/ -> verifiers/ -> sdk/ : the corpus lives under
# sdk/conformance/testdata/aarp-corpus relative to the repo root.
_THIS = Path(__file__).resolve()
_SDK_DIR = _THIS.parents[3]
CORPUS_DIR = _SDK_DIR / "conformance" / "testdata" / "aarp-corpus"


@pytest.fixture(scope="session")
def corpus_dir() -> Path:
    assert CORPUS_DIR.is_dir(), f"corpus not found at {CORPUS_DIR}"
    return CORPUS_DIR


@pytest.fixture(scope="session")
def trust_path(corpus_dir: Path) -> Path:
    return corpus_dir / "trust.json"
