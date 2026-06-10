# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pipelock_aarp_verify.cli import main
from pipelock_aarp_verify.receipt import (
    receipt_hash,
    verify_evidence_chain,
    verify_receipt_file,
)

ROOT = Path(__file__).resolve().parents[4]
VALID_SPANNED_V2 = (
    ROOT
    / "internal/contract/testdata/golden/"
    / "valid_evidence_receipt_proxy_decision_with_spans.json"
)
VALID_PLAIN_V2 = (
    ROOT
    / "internal/contract/testdata/golden/"
    / "valid_evidence_receipt_proxy_decision.json"
)
V2_GOLDEN_PUBLIC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
V2_GOLDEN_POLICY_HASH = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
V2_PRIVATE_SEED_HEX = (
    "9d61b19d"
    "effd5a60"
    "ba844af4"
    "92ec2cc4"
    "4449c569"
    "7b326919"
    "703bac03"
    "1cae7f60"
)


def test_valid_spanned_v2_receipt_verifies() -> None:
    report = verify_receipt_file(VALID_SPANNED_V2, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is True, report.get("error")
    assert report["action_id"] == "01F8MECHZX3TBDSZ7XRADM79ZS"
    assert report["verdict"] == "block"
    assert report["transport"] == "forward"
    assert report["signer_key"] == V2_GOLDEN_PUBLIC_KEY
    assert report["policy_hash"] == V2_GOLDEN_POLICY_HASH


def test_valid_plain_v2_receipt_verifies() -> None:
    report = verify_receipt_file(VALID_PLAIN_V2, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is True, report.get("error")
    assert report["policy_hash"] == V2_GOLDEN_POLICY_HASH


def test_missing_v2_policy_hash_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_PLAIN_V2.read_text())
    del receipt["policy_hash"]
    path = tmp_path / "missing-policy-hash.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "policy_hash" in report["error"]


def test_reserved_defer_v2_payload_kind_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_PLAIN_V2.read_text())
    receipt["payload_kind"] = "defer_opened"
    path = tmp_path / "reserved-defer.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "known but not implemented" in report["error"]


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


def test_optional_span_metadata_must_be_string(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["payload"]["source_spans"][0]["redacted_sample"] = 42
    path = tmp_path / "bad-optional-span-field.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "redacted_sample must be a string" in report["error"]


def test_unsupported_canonicalization_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["canonicalization"]["jcs_profile"] = "rfc8785"
    path = tmp_path / "bad-canonicalization.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "canonicalization.jcs_profile is invalid" in report["error"]


def test_missing_source_spans_crit_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["crit"] = ["canonicalization"]
    path = tmp_path / "missing-source-span-crit.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "crit must include source_spans" in report["error"]


def test_unknown_crit_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_SPANNED_V2.read_text())
    receipt["crit"] = ["canonicalization", "source_spans", "future_extension"]
    path = tmp_path / "unknown-crit.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "crit has unknown field future_extension" in report["error"]


def test_source_spans_crit_on_plain_payload_rejects(tmp_path: Path) -> None:
    receipt = json.loads(VALID_PLAIN_V2.read_text())
    receipt["crit"] = ["canonicalization", "source_spans"]
    path = tmp_path / "plain-source-span-crit.json"
    path.write_text(json.dumps(receipt))

    report = verify_receipt_file(path, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "crit source_spans is invalid for proxy_decision" in report["error"]


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


def test_receipt_cli_without_key_is_unpinned_nonzero(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(["receipt", str(VALID_SPANNED_V2), "--json"])
    captured = capsys.readouterr()
    assert code == 1
    body = json.loads(captured.out)
    assert body["valid"] is False
    assert body["unpinned"] is True


def test_receipt_cli_allow_unpinned_exits_zero(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(["receipt", str(VALID_SPANNED_V2), "--allow-unpinned", "--json"])
    captured = capsys.readouterr()
    assert code == 0
    body = json.loads(captured.out)
    assert body["valid"] is True
    assert body["unpinned"] is True


def test_v2_multi_receipt_chain_verifies() -> None:
    report = verify_evidence_chain(_build_v2_chain(2), V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is True, report.get("error")
    assert report["receipt_count"] == 2
    assert report["final_seq"] == 1


def test_v2_tampered_chain_fails_closed() -> None:
    receipts = _build_v2_chain(2)
    receipts[1]["chain_prev_hash"] = "sha256:0"
    report = verify_evidence_chain(receipts, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "signature" in report["error"] or "chain_prev_hash" in report["error"]


def test_v2_truncated_middle_receipt_fails_closed() -> None:
    receipts = _build_v2_chain(3)
    del receipts[1]
    report = verify_evidence_chain(receipts, V2_GOLDEN_PUBLIC_KEY)
    assert report["valid"] is False
    assert "signature" in report["error"] or "seq gap" in report["error"]


def _build_v2_chain(count: int) -> list[dict[str, object]]:
    base = json.loads(VALID_PLAIN_V2.read_text())
    receipts: list[dict[str, object]] = []
    prev_hash = "genesis"
    for i in range(count):
        receipt = json.loads(json.dumps(base))
        receipt["event_id"] = f"01F8MECHZX3TBDSZ7XRADM79V{i}"
        receipt["chain_seq"] = i
        receipt["chain_prev_hash"] = prev_hash
        _sign_v2_receipt(receipt)
        receipts.append(receipt)
        prev_hash = receipt_hash(receipt)
    return receipts


def _sign_v2_receipt(receipt: dict[str, object]) -> None:
    from pipelock_aarp_verify.canonical import canonicalize

    signature = receipt["signature"]
    assert isinstance(signature, dict)
    receipt["signature"] = {
        "signer_key_id": "",
        "key_purpose": "",
        "algorithm": "",
        "signature": "",
    }
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V2_PRIVATE_SEED_HEX))
    sig = key.sign(canonicalize(receipt))
    receipt["signature"] = {
        "signer_key_id": signature.get("signer_key_id", "receipt-signing-test"),
        "key_purpose": "receipt-signing",
        "algorithm": "ed25519",
        "signature": f"ed25519:{sig.hex()}",
    }
