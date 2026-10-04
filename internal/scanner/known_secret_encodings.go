// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// knownSecretEncodings holds every encoded form matchSecretEncodingSpan looks
// for. Each field is a pure function of the secret, so building them once per
// scanner is equivalent to building them on every scan.
type knownSecretEncodings struct {
	base64Std      string
	base64StdNoPad string
	base64URL      string
	base64URLNoPad string
	hex            string
	// hexDelimited holds the colon, space, hyphen, comma, \x and 0x forms, in
	// that order.
	hexDelimited [6]string
	// decimal holds the comma and space separated character-code forms.
	decimal       [2]string
	base32Std     string
	base32NoPad   string
	retainedBytes int
}

func newKnownSecretEncodings(secret string) *knownSecretEncodings {
	raw := []byte(secret)
	e := &knownSecretEncodings{
		base64Std: base64.StdEncoding.EncodeToString(raw),
		base64URL: base64.URLEncoding.EncodeToString(raw),
		hex:       hex.EncodeToString(raw),
		decimal: [2]string{
			decimalCharacterCodes(secret, ","),
			decimalCharacterCodes(secret, " "),
		},
		base32Std:   base32.StdEncoding.EncodeToString(raw),
		base32NoPad: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw),
	}
	e.base64StdNoPad = strings.TrimRight(e.base64Std, "=")
	e.base64URLNoPad = strings.TrimRight(e.base64URL, "=")
	e.hexDelimited = [6]string{
		hexByteSep(e.hex, ":"),
		hexByteSep(e.hex, " "),
		hexByteSep(e.hex, "-"),
		hexByteSep(e.hex, ","),
		hexBytePrefix(e.hex, `\x`),
		hexBytePrefix(e.hex, "0x"),
	}
	e.retainedBytes = len(e.base64Std) + len(e.base64URL) + len(e.hex) + len(e.base32Std) + len(e.base32NoPad)
	for _, form := range e.hexDelimited {
		e.retainedBytes += len(form)
	}
	for _, form := range e.decimal {
		e.retainedBytes += len(form)
	}
	return e
}

// knownSecretEncodingBudgetBytes bounds the memory spent on precomputed forms,
// which run to roughly thirty bytes per secret byte. Secrets past the budget
// are encoded per scan exactly as before; the budget only trades speed.
const knownSecretEncodingBudgetBytes = 32 << 20

// buildKnownSecretEncodings precomputes encodings for each secret, in list
// order, until the byte budget is spent.
func buildKnownSecretEncodings(budget int, lists ...[]string) map[string]*knownSecretEncodings {
	set := make(map[string]*knownSecretEncodings)
	for _, secrets := range lists {
		for _, secret := range secrets {
			if _, ok := set[secret]; ok || secret == "" {
				continue
			}
			encodings := newKnownSecretEncodings(secret)
			if encodings.retainedBytes > budget {
				continue
			}
			budget -= encodings.retainedBytes
			set[secret] = encodings
		}
	}
	return set
}
