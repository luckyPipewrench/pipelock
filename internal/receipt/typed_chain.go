// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// A current run writes two receipt chains into the same recorder files: the
// ActionReceipt v1 chain and the EvidenceReceipt v2 chain. Each is signed on
// its own, so a forged receipt in one leaves the other intact. Every verifier
// entry point must verify both chains present; the helpers below are the one
// place that decides how a v2 chain is keyed and checked, so the reference
// CLI, the standalone verifier and the base check cannot drift apart.

// FindingDuplicateRunNonce reports two chains of one base whose signed action
// records carry the same run nonce. Each process run mints its own nonce and
// binds it into every action record it signs, so two chains sharing one are
// the same run presented twice: a replayed run under a second session name.
const FindingDuplicateRunNonce = "duplicate_run_nonce"

// EvidenceChainPin selects the key an EvidenceReceipt v2 chain is verified
// against. A v2 chain has a single signer. With a trusted set, the chain's
// declared signer_key_id must be one of the trusted keys; the declared id only
// selects, and every receipt is then verified against that key. A declared
// signer outside the set is an error. With no trusted keys the result is nil,
// meaning structural verification only.
func EvidenceChainPin(receipts []contractreceipt.EvidenceReceipt, trusted []string) (ed25519.PublicKey, error) {
	if len(trusted) == 0 || len(receipts) == 0 {
		return nil, nil
	}
	declared := strings.ToLower(strings.TrimSpace(receipts[0].Signature.SignerKeyID))
	for _, k := range trusted {
		if strings.ToLower(strings.TrimSpace(k)) == declared {
			return decodeEd25519Hex(declared)
		}
	}
	return nil, fmt.Errorf("evidence receipt signer %q is not in the trusted key set", receipts[0].Signature.SignerKeyID)
}

func decodeEd25519Hex(keyHex string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(keyHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signer key %q is not a %d-byte hex Ed25519 public key", keyHex, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// VerifyEvidenceChainTrusted verifies an EvidenceReceipt v2 chain against a
// trusted key set, keyed as EvidenceChainPin describes. opts carries any
// caller expectations; its PinnedKey is replaced.
//
// With no trusted keys every signature is still checked, against the chain's
// own declared signer: the v2 counterpart of the self-consistency check an
// unpinned ActionReceipt v1 chain gets, so a receipt edited after signing
// fails in either chain. That proves nothing about who signed, so
// SignaturesVerified is false and the caller must report the chain as
// unpinned, never as provenance.
func VerifyEvidenceChainTrusted(receipts []contractreceipt.EvidenceReceipt, trusted []string, opts contractreceipt.ChainVerifyOptions) contractreceipt.ChainResult {
	var (
		pin ed25519.PublicKey
		err error
	)
	if len(trusted) == 0 {
		if len(receipts) > 0 {
			pin, err = decodeEd25519Hex(strings.ToLower(strings.TrimSpace(receipts[0].Signature.SignerKeyID)))
		}
	} else {
		pin, err = EvidenceChainPin(receipts, trusted)
	}
	if err != nil {
		return contractreceipt.ChainResult{Valid: false, Error: err.Error()}
	}
	opts.PinnedKey = pin
	res := contractreceipt.VerifyChain(receipts, opts)
	if len(trusted) == 0 {
		res.SignaturesVerified = false
	}
	return res
}

// ScopedChainTrust narrows the operator's trusted keys and endorsements to one
// chain of a verified base. A restart-time key change is authorized by an
// endorsement bound to the PREDECESSOR run's tail, which only the link check
// can place; handing it to the single-chain verifier of either run would be
// rejected as unused. So a chain gets only endorsements for its own in-chain
// rotations, plus the successor key when the base check verified an endorsed
// link into it.
func ScopedChainTrust(report BaseReport, session string, trustedKeys []string, endorsements []RotationEndorsement) ([]string, []RotationEndorsement) {
	var own []RotationEndorsement
	for _, e := range endorsements {
		if e.SessionID != session {
			continue
		}
		crossChain := false
		for _, c := range report.Chains {
			if c.Link != nil && VerifyCrossChainEndorsement(e, *c.Link) == nil {
				crossChain = true
				break
			}
		}
		if !crossChain {
			own = append(own, e)
		}
	}
	keys := trustedKeys
	for _, c := range report.Chains {
		if c.Session == session && c.Link != nil && c.LinkTrust == LinkTrustEndorsed {
			keys = append(slices.Clone(trustedKeys), c.Link.SuccessorSignerKey)
		}
	}
	return keys, own
}

// CheckRecorderFile applies the per-file rules a single evidence file must
// meet on its own: it holds one recorder session, which is the session its
// file name claims when the name claims one, and the recorder entry hash
// chain holds from genesis. The hash chain pins the session only for v3
// entries, so the session rule is checked here for every entry version.
func CheckRecorderFile(name string, entries []recorder.Entry) error {
	if session, _, ok := recorder.ParseEvidenceFilename(name); ok {
		if err := recorder.CheckEntrySessions(entries, session); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	} else if len(entries) > 0 {
		for _, e := range entries[1:] {
			if e.SessionID != entries[0].SessionID {
				return fmt.Errorf("%w: evidence file mixes recorder sessions %q and %q", recorder.ErrEvidenceRefused, entries[0].SessionID, e.SessionID)
			}
		}
	}
	if err := recorder.VerifyChain(entries); err != nil {
		return fmt.Errorf("recorder entry hash chain: %w", err)
	}
	return nil
}

// runNonces returns the distinct run nonces the action records carry, sorted.
func runNonces(receipts []Receipt) []string {
	seen := make(map[string]struct{})
	for _, r := range receipts {
		if n := r.ActionRecord.RunNonce; n != "" {
			seen[n] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// RecorderFileChains returns the two receipt chains one recorder file holds,
// after the per-file checks CheckRecorderFile applies. name is the file's base
// name. ok is false when the entries hold no receipt of either kind, so a
// caller can keep its compatibility path for input that is not recorder
// output.
func RecorderFileChains(name string, entries []recorder.Entry) ([]Receipt, []contractreceipt.EvidenceReceipt, bool, error) {
	actions, err := extractReceiptsFromEntries(entries)
	if err != nil {
		return nil, nil, true, err
	}
	evidence, err := contractreceipt.ExtractEvidenceReceiptsFromEntries(entries)
	if err != nil {
		return nil, nil, true, fmt.Errorf("extracting evidence receipts: %w", err)
	}
	if len(actions) == 0 && len(evidence) == 0 {
		return nil, nil, false, nil
	}
	if err := CheckRecorderFile(name, entries); err != nil {
		return nil, nil, true, err
	}
	return actions, evidence, true, nil
}
