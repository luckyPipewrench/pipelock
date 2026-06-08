# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""CLI exit-code and output-shape tests, including trust-file loading errors."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from pipelock_aarp_verify.cli import (
    EXIT_CONFIG,
    EXIT_GENERAL,
    EXIT_OK,
    EXIT_USAGE,
    main,
)

_CORPUS = (
    Path(__file__).resolve().parents[3] / "conformance" / "testdata" / "aarp-corpus"
)
_TRUST = _CORPUS / "trust.json"
_G01 = _CORPUS / "golden" / "g01-single-ed25519-mediated.aarp.json"
_M09 = _CORPUS / "malicious" / "m09-profile-mismatch.aarp.json"
_C01 = _CORPUS / "chain" / "c01-valid-stream.aarp.jsonl"


def run(args, monkeypatch_out=True):
    out = io.StringIO()
    err = io.StringIO()
    old_o, old_e = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        rc = main(args)
    finally:
        sys.stdout, sys.stderr = old_o, old_e
    return rc, out.getvalue(), err.getvalue()


def test_appraise_exit_zero():
    rc, out, _ = run(["aarp", str(_G01), "--trust", str(_TRUST), "--json"])
    assert rc == EXIT_OK
    assert json.loads(out)["assertion_signed"] is True
    assert out.endswith("\n")


def test_appraise_human_mode():
    rc, out, _ = run(["aarp", str(_G01), "--trust", str(_TRUST)])
    assert rc == EXIT_OK
    assert "AARP appraisal" in out
    assert "assertion_signed" in out


def test_fatal_json_marker():
    rc, out, _ = run(["aarp", str(_M09), "--trust", str(_TRUST), "--json"])
    assert rc == EXIT_GENERAL
    body = json.loads(out)
    assert body["envelope_fatal"] is True


def test_fatal_human_mode_writes_stderr():
    rc, out, err = run(["aarp", str(_M09), "--trust", str(_TRUST)])
    assert rc == EXIT_GENERAL
    assert "ENVELOPE FATAL" in err


def test_chain_links_exit_zero():
    rc, out, _ = run(["aarp", str(_C01), "--trust", str(_TRUST), "--chain", "--json"])
    assert rc == EXIT_OK
    assert json.loads(out)["chain_linked"] is True


def test_chain_human_mode():
    rc, out, _ = run(["aarp", str(_C01), "--trust", str(_TRUST), "--chain"])
    assert rc == EXIT_OK
    assert "AARP chain" in out


def test_missing_envelope_is_config_error():
    rc, _, err = run(["aarp", "/no/such/file.json", "--trust", str(_TRUST), "--json"])
    assert rc == EXIT_CONFIG
    assert "read envelope" in err


def test_missing_trust_file_is_config_error():
    rc, _, err = run(["aarp", str(_G01), "--trust", "/no/such/trust.json"])
    assert rc == EXIT_CONFIG
    assert "load trust" in err


def test_no_trust_flag_means_unknown_key():
    rc, out, _ = run(["aarp", str(_G01), "--json"])
    assert rc == EXIT_OK
    assert json.loads(out)["assertion_signed"] is False


def test_no_command_is_usage_error():
    rc, _, _ = run([])
    assert rc == EXIT_USAGE


def test_unknown_flag_is_usage_error():
    rc, _, _ = run(["aarp", str(_G01), "--bogus"])
    assert rc == EXIT_USAGE


def test_bad_trust_unknown_field(tmp_path: Path):
    bad = tmp_path / "trust.json"
    bad.write_text('{"trusted_keys": {}, "surprise": 1}')
    rc, _, err = run(["aarp", str(_G01), "--trust", str(bad)])
    assert rc == EXIT_CONFIG
    assert "unknown field" in err


def test_bad_trust_not_hex(tmp_path: Path):
    bad = tmp_path / "trust.json"
    bad.write_text('{"trusted_keys": {"k": "nothex!!"}}')
    rc, _, err = run(["aarp", str(_G01), "--trust", str(bad)])
    assert rc == EXIT_CONFIG
    assert "not hex" in err


def test_bad_trust_wrong_key_size(tmp_path: Path):
    bad = tmp_path / "trust.json"
    bad.write_text('{"trusted_keys": {"k": "aabb"}}')
    rc, _, err = run(["aarp", str(_G01), "--trust", str(bad)])
    assert rc == EXIT_CONFIG
    assert "bytes" in err


def test_bad_trust_not_object(tmp_path: Path):
    bad = tmp_path / "trust.json"
    bad.write_text("[]")
    rc, _, err = run(["aarp", str(_G01), "--trust", str(bad)])
    assert rc == EXIT_CONFIG


def test_bad_trust_malformed_json(tmp_path: Path):
    bad = tmp_path / "trust.json"
    bad.write_text("{not json")
    rc, _, err = run(["aarp", str(_G01), "--trust", str(bad)])
    assert rc == EXIT_CONFIG
    assert "parse trust file" in err


def test_bad_trust_entry_unknown_field(tmp_path: Path):
    bad = tmp_path / "trust.json"
    bad.write_text('{"trusted_keys": {}, "trust_entries": {"k": {"surprise": "x"}}}')
    rc, _, err = run(["aarp", str(_G01), "--trust", str(bad)])
    assert rc == EXIT_CONFIG


def test_chain_bad_line_is_fatal(tmp_path: Path):
    bad = tmp_path / "stream.jsonl"
    bad.write_text("{not json\n")
    rc, out, _ = run(["aarp", str(bad), "--trust", str(_TRUST), "--chain", "--json"])
    assert rc == EXIT_GENERAL
    assert json.loads(out)["envelope_fatal"] is True


def test_chain_not_linked_exit_one():
    m02 = _CORPUS / "chain" / "c02-reordered-stream.aarp.jsonl"
    rc, out, _ = run(["aarp", str(m02), "--trust", str(_TRUST), "--chain", "--json"])
    assert rc == EXIT_GENERAL
    assert json.loads(out)["chain_linked"] is False


def test_chain_skips_blank_lines(tmp_path: Path):
    # A blank line between envelopes is ignored, not treated as a parse error.
    stream = _C01.read_text().splitlines()
    body = stream[0] + "\n\n" + stream[1] + "\n" + stream[2] + "\n"
    f = tmp_path / "stream.jsonl"
    f.write_text(body)
    rc, out, _ = run(["aarp", str(f), "--trust", str(_TRUST), "--chain", "--json"])
    assert rc == EXIT_OK
    assert json.loads(out)["chain_linked"] is True


def test_trusted_keys_not_object(tmp_path: Path):
    bad = tmp_path / "trust.json"
    bad.write_text('{"trusted_keys": []}')
    rc, _, err = run(["aarp", str(_G01), "--trust", str(bad)])
    assert rc == EXIT_CONFIG
    assert "trusted_keys must be an object" in err


def test_trust_entries_not_object(tmp_path: Path):
    bad = tmp_path / "trust.json"
    bad.write_text('{"trusted_keys": {}, "trust_entries": []}')
    rc, _, err = run(["aarp", str(_G01), "--trust", str(bad)])
    assert rc == EXIT_CONFIG
    assert "trust_entries must be an object" in err


def test_trust_entry_not_object(tmp_path: Path):
    bad = tmp_path / "trust.json"
    bad.write_text('{"trusted_keys": {}, "trust_entries": {"k": "x"}}')
    rc, _, err = run(["aarp", str(_G01), "--trust", str(bad)])
    assert rc == EXIT_CONFIG


def test_trusted_key_not_string(tmp_path: Path):
    bad = tmp_path / "trust.json"
    bad.write_text('{"trusted_keys": {"k": 5}}')
    rc, _, err = run(["aarp", str(_G01), "--trust", str(bad)])
    assert rc == EXIT_CONFIG
    assert "not a string" in err


def test_overclaim_risk_sentence_maps_known_codes_and_falls_back():
    """The human view renders an explanatory sentence per risk code (matching the
    Go CLI), and falls back to the bare code for an unknown one so a verifier
    ahead of this CLI never drops a warning silently.
    """
    from pipelock_aarp_verify.appraise import (
        RISK_CHAIN_LINK_NOT_CONTIGUOUS_CHAIN,
        RISK_SIGNATURE_VALID_NOT_TRANSPARENCY,
        RISK_SVID_IDENTITY_NOT_DEPLOYMENT_NON_BYPASS,
    )
    from pipelock_aarp_verify.cli import _overclaim_risk_sentence

    for code in (
        RISK_SIGNATURE_VALID_NOT_TRANSPARENCY,
        RISK_SVID_IDENTITY_NOT_DEPLOYMENT_NON_BYPASS,
        RISK_CHAIN_LINK_NOT_CONTIGUOUS_CHAIN,
    ):
        sentence = _overclaim_risk_sentence(code)
        assert sentence and sentence != code
    assert _overclaim_risk_sentence("some_future_risk_code") == "some_future_risk_code"
