// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

// Run-session suffix layout: runSuffixRandomBytes random bytes followed by
// runSuffixMACBytes of proof, hex encoded to 32 lowercase characters. The
// shape is unchanged from earlier releases, so readers and verifiers need no
// change; 96 random bits keep two process starts from colliding.
const (
	runSuffixRandomBytes = 12
	runSuffixMACBytes    = 4
	runSuffixHexLen      = 2 * (runSuffixRandomBytes + runSuffixMACBytes)
)

// NewRunSessionSuffix mints the random suffix of a run session for base. The
// suffix carries this process's origin proof bound to base, so the content
// boundary can exclude it from detector input while still scanning base,
// which the operator chose.
func NewRunSessionSuffix(base string) string {
	var b [runSuffixRandomBytes + runSuffixMACBytes]byte
	_, _ = rand.Read(b[:runSuffixRandomBytes]) // crypto/rand.Read does not return an error
	mac := runSuffixMAC(base, b[:runSuffixRandomBytes])
	copy(b[runSuffixRandomBytes:], mac[:runSuffixMACBytes])
	return hex.EncodeToString(b[:])
}

// SplitProvenRunSession returns the operator base of s when s is
// "<base>.run.<suffix>" and the suffix was minted by NewRunSessionSuffix in
// this process for exactly that base. A suffix a caller chose, including one
// with the right shape, or a proven suffix grafted onto another base, is not
// proven.
func SplitProvenRunSession(s string) (string, bool) {
	base, suffix, ok := strings.Cut(s, evidencename.RunInfix)
	if !ok || base == "" || len(suffix) != runSuffixHexLen || strings.ToLower(suffix) != suffix {
		return "", false
	}
	raw, err := hex.DecodeString(suffix)
	if err != nil {
		return "", false
	}
	mac := runSuffixMAC(base, raw[:runSuffixRandomBytes])
	if !hmac.Equal(raw[runSuffixRandomBytes:], mac[:runSuffixMACBytes]) {
		return "", false
	}
	return base, true
}

func runSuffixMAC(base string, random []byte) []byte {
	m := hmac.New(sha256.New, idKey)
	_, _ = m.Write([]byte("pipelock run session\x00"))
	_, _ = m.Write([]byte(base))
	_, _ = m.Write([]byte{0})
	_, _ = m.Write(random)
	return m.Sum(nil)
}
