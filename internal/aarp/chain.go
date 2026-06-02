// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"errors"
	"fmt"
)

// GenesisPriorHash is the prior-hash sentinel for the first link in a stream:
// 64 hex zeros, meaning "no prior receipt". A genesis link carries seq "0".
const GenesisPriorHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Chain failure classes. Compare with errors.Is.
var (
	// ErrChainSchema means a chain link is structurally invalid (bad issuer,
	// seq, or prior-hash grammar).
	ErrChainSchema = errors.New("aarp: chain link schema violation")

	// ErrChainBroken means a sequence of links does not form a contiguous,
	// hash-linked stream: a non-incrementing sequence, a mismatched prior hash,
	// a mixed issuer, or a genesis link with a non-zero prior hash. This is the
	// signal an insertion, reorder, or backdating attempt produces.
	ErrChainBroken = errors.New("aarp: chain linkage broken")
)

// ChainLink places an envelope in an issuer's append-only, hash-chained stream
// (Rung-1 timestamp trust). It is issuer-agnostic: any issuer that maintains a
// monotonic sequence and links each receipt's payload digest to the prior one
// gets backdating detection without depending on a specific issuer deployment.
//
// The link is part of the signed payload, so seq and prior_hash cannot be
// altered after signing. Inserting, reordering, or backdating a receipt within
// the stream breaks the signed linkage and is detected by VerifyChain.
type ChainLink struct {
	// IssuerID identifies the stream this link belongs to. All links in a
	// verified stream must share one issuer.
	IssuerID string `json:"issuer_id"`
	// Seq is the monotonic position in the stream, a uint64 typed string
	// (number-safety: sequence numbers routinely exceed the I-JSON safe range).
	Seq string `json:"seq"`
	// PriorHash is the lowercase-hex SHA-256 of the previous link's payload
	// digest, or GenesisPriorHash for the first link.
	PriorHash string `json:"prior_hash"`
}

func (c ChainLink) validate() error {
	if c.IssuerID == "" {
		return fmt.Errorf("%w: chain.issuer_id is required", ErrChainSchema)
	}
	if err := ValidateUint64String(c.Seq); err != nil {
		return fmt.Errorf("%w: chain.seq: %w", ErrChainSchema, err)
	}
	if err := ValidateHex256(c.PriorHash); err != nil {
		return fmt.Errorf("%w: chain.prior_hash: %w", ErrChainSchema, err)
	}
	if c.Seq == "0" && c.PriorHash != GenesisPriorHash {
		return fmt.Errorf("%w: genesis link (seq 0) must carry the zero prior hash", ErrChainSchema)
	}
	if c.Seq != "0" && c.PriorHash == GenesisPriorHash {
		return fmt.Errorf("%w: non-genesis link (seq %s) must not carry the genesis prior hash", ErrChainSchema, c.Seq)
	}
	return nil
}

// VerifyChain checks that envs form a contiguous, hash-linked stream from a
// single issuer: every envelope carries a chain link, all links share one
// issuer, the sequence increments by exactly 1 across the slice, and each
// link's prior_hash equals the previous envelope's payload digest. The first
// element may be a genesis link (seq 0, zero prior hash) but need not be — a
// caller may verify a contiguous segment that starts mid-stream.
//
// VerifyChain does NOT check signatures; callers verify each envelope's
// signatures separately. It checks only the linkage that makes backdating,
// insertion, and reordering within the stream detectable. The slice must be in
// ascending stream order.
func VerifyChain(envs []Envelope) error {
	if len(envs) == 0 {
		return fmt.Errorf("%w: empty chain", ErrChainBroken)
	}
	var (
		issuer   string
		prevSeq  uint64
		prevHash string
	)
	for i, e := range envs {
		if e.Chain == nil {
			return fmt.Errorf("%w: envelope[%d] has no chain link", ErrChainBroken, i)
		}
		if err := e.Chain.validate(); err != nil {
			return err
		}
		seq, err := parseSeq(e.Chain.Seq)
		if err != nil {
			return fmt.Errorf("%w: envelope[%d]: %w", ErrChainBroken, i, err)
		}
		if i == 0 {
			issuer = e.Chain.IssuerID
		} else {
			if e.Chain.IssuerID != issuer {
				return fmt.Errorf("%w: envelope[%d] issuer %q != stream issuer %q", ErrChainBroken, i, e.Chain.IssuerID, issuer)
			}
			if seq != prevSeq+1 {
				return fmt.Errorf("%w: envelope[%d] seq %d, expected %d", ErrChainBroken, i, seq, prevSeq+1)
			}
			// Both sides are lowercase hex: PriorHash passed ValidateHex256
			// (rejects uppercase) and prevHash comes from hex.EncodeToString.
			// Compare exactly — do not tolerate case the grammar already forbids.
			if e.Chain.PriorHash != prevHash {
				return fmt.Errorf("%w: envelope[%d] prior_hash does not match previous payload digest", ErrChainBroken, i)
			}
		}
		digest, err := e.PayloadDigest()
		if err != nil {
			return fmt.Errorf("%w: envelope[%d]: %w", ErrChainBroken, i, err)
		}
		prevSeq = seq
		prevHash = digest
	}
	return nil
}

// parseSeq converts a validated uint64 typed-string to its numeric value.
func parseSeq(s string) (uint64, error) {
	if err := ValidateUint64String(s); err != nil {
		return 0, err
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		n = n*10 + uint64(s[i]-'0')
	}
	return n, nil
}
