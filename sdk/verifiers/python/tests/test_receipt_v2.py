# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path

from pipelock_aarp_verify.cli import main
from pipelock_aarp_verify.receipt import verify_receipt_file

ROOT = Path(__file__).resolve().parents[4]
VALID_SPANNED_V2 = (
    ROOT
    / "internal/contract/testdata/golden/"
    / "valid_evidence_receipt_proxy_decision_with_spans.json"
)
V2_GOLDEN_PUBLIC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def test_valid_spanned_v2_receipt_verifies() -> None:
    report = verify_receipt_file(VALID_SPANNED_V2, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is True, report.get("error")
    assert report["action_id"] == "01F8MECHZX3TBDSZ7XRADM79ZS"
    assert report["verdict"] == "block"
    assert report["transport"] == "forward"


def test_tampered_spanned_v2_receipt_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["payload"]["source_spans"][0]["rule_id"] = "aws_access_key_tampered"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "signature verification failed" in report["error"]


def test_unknown_spanned_v2_field_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["payload"]["source_spans"][0]["raw_match"] = "lowentropy"
    path = tmp_path / "unknown.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "unknown field raw_match" in report["error"]


def test_empty_dlp_normalized_suffix_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["payload"]["source_spans"][0]["normalized_view"] = "dlp_normalized:"
    path = tmp_path / "empty-view.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "normalized_view is invalid" in report["error"]


def test_spanned_v2_receipt_does_not_expose_oracle_key() -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    span = receipt["payload"]["source_spans"][0]
    assert span["match_hash_alg"] == "hmac-sha256"
    assert span["match_hash"].startswith("hmac-sha256:")
    assert "golden-span-mac-key" not in json.dumps(receipt)


def test_receipt_cli_json(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(["receipt", str(VALID_SPANNED_V2), "--key", V2_GOLDEN_PUBLIC_KEY, "--json"])
    captured = capsys.readouterr()
    assert code == 0
    body = json.loads(captured.out)
    assert body["valid"] is True
