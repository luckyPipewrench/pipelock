// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const (
	recordTypeEvidenceV2 = "evidence_receipt_v2"
	recordTypeActionV1   = "action_receipt_v1"
)

type evidenceBindingOptions struct {
	expectSignerKeyID  string
	expectContractHash string
	expectManifestHash string
	expectPayloadKind  string
}

func (opts evidenceBindingOptions) anySet() bool {
	return opts.expectSignerKeyID != "" ||
		opts.expectContractHash != "" ||
		opts.expectManifestHash != "" ||
		opts.expectPayloadKind != ""
}

func (opts evidenceBindingOptions) chainVerifyOptions(keyHex string) (contractreceipt.ChainVerifyOptions, error) {
	pub, err := decodePinnedEvidenceKey(keyHex)
	if err != nil {
		return contractreceipt.ChainVerifyOptions{}, err
	}
	return contractreceipt.ChainVerifyOptions{
		PinnedKey:          pub,
		ExpectSignerKeyID:  opts.expectSignerKeyID,
		ExpectContractHash: opts.expectContractHash,
		ExpectManifestHash: opts.expectManifestHash,
		ExpectPayloadKind:  contractreceipt.PayloadKind(opts.expectPayloadKind),
	}, nil
}

func decodePinnedEvidenceKey(keyHex string) (ed25519.PublicKey, error) {
	if keyHex == "" {
		return nil, nil
	}
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode pinned key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pinned key length=%d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func detectSingleReceiptRecordType(data []byte) (string, error) {
	var probe struct {
		RecordType string `json:"record_type"`
		Version    int    `json:"version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("parse receipt JSON: %w", err)
	}
	if probe.RecordType != "" {
		return probe.RecordType, nil
	}
	if probe.Version == 1 {
		return recordTypeActionV1, nil
	}
	return "", nil
}

func decodeEvidenceReceipt(data []byte) (contractreceipt.EvidenceReceipt, error) {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return contractreceipt.EvidenceReceipt{}, err
	}
	var r contractreceipt.EvidenceReceipt
	if err := contract.DecodeStrictJSON(data, &r); err != nil {
		return contractreceipt.EvidenceReceipt{}, err
	}
	return r, nil
}

func verifyEvidenceReceipt(r contractreceipt.EvidenceReceipt, keyHex string, opts evidenceBindingOptions) (bool, error) {
	chainOpts, err := opts.chainVerifyOptions(keyHex)
	if err != nil {
		return false, err
	}
	if opts.expectSignerKeyID != "" && r.Signature.SignerKeyID != opts.expectSignerKeyID {
		return false, fmt.Errorf("signer_key_id %q does not match expected %q", r.Signature.SignerKeyID, opts.expectSignerKeyID)
	}
	if opts.expectPayloadKind != "" && r.PayloadKind != contractreceipt.PayloadKind(opts.expectPayloadKind) {
		return false, fmt.Errorf("payload_kind %q does not match expected %q", r.PayloadKind, opts.expectPayloadKind)
	}
	if opts.expectContractHash != "" && r.ContractHash != opts.expectContractHash {
		return false, fmt.Errorf("contract_hash does not match expected")
	}
	if opts.expectManifestHash != "" && r.ActiveManifestHash != opts.expectManifestHash {
		return false, fmt.Errorf("active_manifest_hash does not match expected")
	}
	if chainOpts.PinnedKey == nil {
		if err := r.Validate(); err != nil {
			return false, err
		}
		if _, err := contractreceipt.ReceiptHash(r); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := contractreceipt.VerifyWithKey(r, chainOpts.PinnedKey, r.Signature.SignerKeyID); err != nil {
		return false, err
	}
	return true, nil
}
