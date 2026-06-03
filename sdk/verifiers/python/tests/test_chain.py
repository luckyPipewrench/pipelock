# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Rung-1 chain linkage tests."""

from __future__ import annotations

import json
from pathlib import Path

from pipelock_aarp_verify.chain import (
    comparable_chain,
    is_chain_linked,
    verify_chain,
)
from pipelock_aarp_verify.envelope import unmarshal

_CORPUS = (
    Path(__file__).resolve().parents[3] / "conformance" / "testdata" / "aarp-corpus"
)


def _load_stream(name: str):
    lines = (_CORPUS / "chain" / name).read_text().splitlines()
    return [unmarshal(line) for line in lines if line.strip()]


def test_valid_stream_links():
    envs = _load_stream("c01-valid-stream.aarp.jsonl")
    assert is_chain_linked(envs) is True
    verify_chain(envs)  # no raise
    out = comparable_chain(envs).decode("utf-8")
    assert out == '{"chain_linked":true,"length":3}'


def test_reordered_stream_breaks():
    envs = _load_stream("c02-reordered-stream.aarp.jsonl")
    assert is_chain_linked(envs) is False
    out = comparable_chain(envs).decode("utf-8")
    assert '"chain_linked":false' in out


def test_mixed_issuer_stream_breaks():
    envs = _load_stream("c03-mixed-issuer-stream.aarp.jsonl")
    assert is_chain_linked(envs) is False


def test_backdated_stream_breaks():
    envs = _load_stream("c04-backdated-stream.aarp.jsonl")
    assert is_chain_linked(envs) is False


def test_empty_chain_not_linked():
    assert is_chain_linked([]) is False
    out = comparable_chain([]).decode("utf-8")
    assert out == '{"chain_linked":false,"length":0}'


def test_envelope_without_chain_link_breaks():
    obj = json.loads(
        (_CORPUS / "golden" / "g01-single-ed25519-mediated.aarp.json").read_text()
    )
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    assert env.chain is None
    assert is_chain_linked([env]) is False


def _genesis_envelope() -> dict:
    return json.loads(
        (_CORPUS / "chain" / "c01-valid-stream.aarp.jsonl").read_text().splitlines()[0]
    )


def test_genesis_with_nonzero_prior_hash_breaks():
    obj = _genesis_envelope()
    obj["chain"]["prior_hash"] = "a" * 64  # seq 0 but non-genesis prior hash
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    assert is_chain_linked([env]) is False


def test_nongenesis_with_genesis_prior_hash_breaks():
    obj = _genesis_envelope()
    obj["chain"]["seq"] = "1"  # seq 1 but zero prior hash
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    assert is_chain_linked([env]) is False


def test_chain_bad_seq_grammar_breaks():
    obj = _genesis_envelope()
    obj["chain"]["seq"] = "01"  # leading zero
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    assert is_chain_linked([env]) is False


def test_chain_empty_issuer_breaks():
    obj = _genesis_envelope()
    obj["chain"]["issuer_id"] = ""
    env = unmarshal(json.dumps(obj).encode("utf-8"))
    assert is_chain_linked([env]) is False
