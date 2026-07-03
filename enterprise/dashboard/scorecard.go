//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	StateVerify  = "verify"
	StateWarn    = "warn"
	StateFail    = "fail"
	StateLimited = "limited"

	chipAbsent           = "ABSENT"
	chipChainBroken      = "Chain broken"
	chipChainIntact      = "Chain intact"
	chipNotAnchored      = "Not anchored"
	chipPartial          = "Partial"
	chipSignaturesVerify = "Signatures verify"
	chipUnverified       = "Unverified"
)

// TrustedKey describes why a signer key is trusted by the operator.
type TrustedKey struct {
	Source string
}

// Line is one independently evaluated scorecard fact. There is intentionally
// no aggregate status: every line must be read on its own.
type Line struct {
	State  string
	Chip   string
	Detail string
	Sub    string
}

// Scorecard reports the four honest evidence facts shown to operators.
type Scorecard struct {
	Authentic    Line
	Untampered   Line
	Anchored     Line
	Completeness Line
}

type scorecardResult struct {
	Scorecard Scorecard
	Chain     receipt.ChainResult
}

func computeScorecard(receipts []receipt.Receipt, trustedKeys map[string]TrustedKey, sessionID string) scorecardResult {
	if len(receipts) == 0 {
		return scorecardResult{
			Scorecard: absentScorecard(),
			Chain:     receipt.ChainResult{Valid: false, Error: "no receipts"},
		}
	}

	signers := signerKeys(receipts)
	structural := receipt.VerifyChainTrusted(receipts, signers)
	trustedSessionKeys := trustedKeysForSession(signers, trustedKeys)

	chain := structural
	var authentic Line
	if len(trustedSessionKeys) > 0 {
		chain = receipt.VerifyChainTrusted(receipts, trustedSessionKeys)
		authentic = authenticLineFromTrustedResult(chain, trustedSessionKeys, trustedKeys, uint64(len(receipts)))
	} else {
		authentic = unverifiedAuthenticLine(signers, structural)
	}

	anchoredState, anchoredChip, anchoredDetail, anchoredSub := anchorState(sessionID)
	return scorecardResult{
		Scorecard: Scorecard{
			Authentic:    authentic,
			Untampered:   untamperedLine(chain, len(receipts)),
			Anchored:     Line{State: anchoredState, Chip: anchoredChip, Detail: anchoredDetail, Sub: anchoredSub},
			Completeness: completenessLine(chain, receipts),
		},
		Chain: chain,
	}
}

func absentScorecard() Scorecard {
	return Scorecard{
		Authentic: Line{
			State:  StateFail,
			Chip:   chipAbsent,
			Detail: "No receipts were recorded, so there are no signatures to authenticate.",
			Sub:    "Enable receipts before treating this agent's decisions as independently evidenced.",
		},
		Untampered: Line{
			State:  StateFail,
			Chip:   chipAbsent,
			Detail: "No hash chain exists for this session.",
			Sub:    "Absence is a red evidence state, not a successful verification.",
		},
		Anchored: Line{
			State:  StateWarn,
			Chip:   chipAbsent,
			Detail: "No inclusion proof - local or external - was recorded.",
			Sub:    "Ordering cannot be established without receipts.",
		},
		Completeness: Line{
			State:  StateLimited,
			Chip:   chipAbsent,
			Detail: "0 receipts, 0 chain gaps. Covers no mediated egress decisions.",
			Sub:    "Cannot prove that no unmediated action occurred outside the boundary.",
		},
	}
}

func unverifiedAuthenticLine(signers []string, chain receipt.ChainResult) Line {
	detail := fmt.Sprintf(
		"Signer key %s is not in the trusted-key set; signatures are well-formed but UNTRUSTED.",
		formatKeyList(signers),
	)
	if !chain.Valid {
		detail = fmt.Sprintf(
			"Signer key %s is not in the trusted-key set, and the chain could not be structurally verified: %s.",
			formatKeyList(signers),
			chain.Error,
		)
	}
	return Line{
		State:  StateWarn,
		Chip:   chipUnverified,
		Detail: detail,
		Sub:    "Import the signer key from an operator-controlled source to upgrade this line.",
	}
}

func authenticLineFromTrustedResult(chain receipt.ChainResult, trustedSessionKeys []string, trustedKeys map[string]TrustedKey, receiptCount uint64) Line {
	if chain.UntrustedSignerKey != "" {
		return Line{
			State: StateWarn,
			Chip:  chipUnverified,
			Detail: fmt.Sprintf(
				"Signer key %s is not in the trusted-key set; signatures may be well-formed but are UNTRUSTED.",
				fingerprint(chain.UntrustedSignerKey),
			),
			Sub: "Import the key only after confirming it came from an operator-controlled source.",
		}
	}
	if !chain.Valid {
		return Line{
			State:  StateFail,
			Chip:   "Signature check failed",
			Detail: fmt.Sprintf("Trusted-key verification failed: %s.", chain.Error),
			Sub:    "Treat this evidence as broken until the receipt chain is investigated.",
		}
	}

	keyText := formatKeyList(trustedSessionKeys)
	source := provenanceText(trustedSessionKeys, trustedKeys)
	if chain.ReceiptCount > 0 {
		receiptCount = chain.ReceiptCount
	}
	return Line{
		State: StateVerify,
		Chip:  chipSignaturesVerify,
		Detail: fmt.Sprintf(
			"%d/%d signatures verify against trusted key %s - source: %s.",
			receiptCount,
			receiptCount,
			keyText,
			source,
		),
		Sub: "Signer trust came from configured operator provenance, not trust-on-first-use.",
	}
}

func untamperedLine(chain receipt.ChainResult, receiptCount int) Line {
	if chain.Valid && chain.BrokenAtSeq == 0 {
		finalSeq := chain.FinalSeq
		if receiptCount == 0 {
			finalSeq = 0
		}
		return Line{
			State:  StateVerify,
			Chip:   chipChainIntact,
			Detail: fmt.Sprintf("hash chain intact; sequence contiguous 0-%d.", finalSeq),
			Sub:    "Every receipt links to the previous receipt hash.",
		}
	}

	return Line{
		State: StateFail,
		Chip:  chipChainBroken,
		Detail: fmt.Sprintf(
			"BROKEN at seq %d - this receipt and later receipts are unverifiable.",
			chain.BrokenAtSeq,
		),
		Sub: emptyToDefault(
			chain.Error,
			"Hash or signature continuity failed.",
		),
	}
}

func anchorState(_ string) (state, chip, detail, sub string) {
	// MVP always reports not-anchored. TODO: wire real external/local inclusion-proof detection and return
	// the external/local states here; keep the chip derived from the state so it cannot misreport.
	return StateWarn,
		chipNotAnchored,
		"no inclusion proof - local or external - was recorded; ordering rests on the hash chain alone.",
		"Add an external inclusion proof before treating ordering as independently anchored."
}

func completenessLine(chain receipt.ChainResult, receipts []receipt.Receipt) Line {
	receiptCount := len(receipts)
	gaps := 0
	detail := fmt.Sprintf(
		"%d receipts, %d chain gaps. Covers mediated egress inside the declared Pipelock boundary.",
		receiptCount,
		gaps,
	)
	if !chain.Valid || chain.BrokenAtSeq != 0 {
		gaps = 1
		lost := receiptsAtOrAfterBreak(receipts, chain.BrokenAtIndex)
		verifiable := receiptCount - lost
		detail = fmt.Sprintf(
			"%d of %d receipts verifiable; %d lost to the break. %d receipts, %d chain gaps. Covers mediated egress inside the declared Pipelock boundary.",
			verifiable,
			receiptCount,
			lost,
			receiptCount,
			gaps,
		)
	}
	return Line{
		State:  StateLimited,
		Chip:   "Boundary-limited",
		Detail: detail,
		Sub:    "Cannot prove that no unmediated action occurred outside the boundary.",
	}
}

func readLimitedScorecard(loadedReceipts, readLimit int) Scorecard {
	limitDetail := fmt.Sprintf(
		"Dashboard read ceiling reached after %d recorder entries; this page did not load the complete session.",
		readLimit,
	)
	return Scorecard{
		Authentic: Line{
			State:  StateLimited,
			Chip:   chipPartial,
			Detail: fmt.Sprintf("Loaded %d receipts, but the dashboard did not authenticate the complete session. %s", loadedReceipts, limitDetail),
			Sub:    "Run the offline verifier before relying on authenticity for this session.",
		},
		Untampered: Line{
			State:  StateLimited,
			Chip:   "Prefix only",
			Detail: fmt.Sprintf("Loaded %d receipts before the dashboard ceiling. Later receipts may exist and were not chain-verified here.", loadedReceipts),
			Sub:    "The online view is intentionally bounded to avoid unbounded memory and CPU use.",
		},
		Anchored: Line{
			State:  StateWarn,
			Chip:   chipNotAnchored,
			Detail: "No complete-session inclusion proof was verified in this bounded dashboard view.",
			Sub:    "Use a signed bundle and external proof for complete ordering evidence.",
		},
		Completeness: Line{
			State:  StateLimited,
			Chip:   "Boundary-limited",
			Detail: fmt.Sprintf("%d receipts loaded before the dashboard read ceiling. Covers only the loaded prefix of mediated egress.", loadedReceipts),
			Sub:    "Cannot prove that no unmediated action occurred outside the boundary, or that no later mediated receipt exists.",
		},
	}
}

func receiptsAtOrAfterBreak(receipts []receipt.Receipt, brokenAtIndex int) int {
	if len(receipts) == 0 {
		return 0
	}
	if brokenAtIndex < 0 || brokenAtIndex >= len(receipts) {
		return len(receipts)
	}
	return len(receipts) - brokenAtIndex
}

func signerKeys(receipts []receipt.Receipt) []string {
	keys := make([]string, 0, len(receipts))
	seen := make(map[string]struct{}, len(receipts))
	for _, r := range receipts {
		key := strings.TrimSpace(r.SignerKey)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func trustedKeysForSession(signers []string, trustedKeys map[string]TrustedKey) []string {
	if len(trustedKeys) == 0 {
		return nil
	}
	keys := make([]string, 0, len(signers))
	for _, signer := range signers {
		if _, ok := trustedKeys[signer]; ok {
			keys = append(keys, signer)
		}
	}
	return keys
}

func provenanceText(keys []string, trustedKeys map[string]TrustedKey) string {
	sources := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		source := trustedKeys[key].Source
		if source == "" {
			source = "configured trusted key"
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		sources = append(sources, source)
	}
	return strings.Join(sources, ", ")
}

func formatKeyList(keys []string) string {
	if len(keys) == 0 {
		return "none"
	}
	fps := make([]string, 0, len(keys))
	for _, key := range keys {
		fps = append(fps, fingerprint(key))
	}
	return strings.Join(fps, ", ")
}

func fingerprint(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 12 {
		return key
	}
	return key[:12]
}

func emptyToDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
