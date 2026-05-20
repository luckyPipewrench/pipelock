// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// RedactionSecretValues exposes scanner-known secret literals and common
// encoded forms to the proxy redaction runtime. The values never leave the
// process; callers use them only to build in-memory literal dictionaries so
// redaction and DLP share the same knowledge of env/file secret leaks.
type RedactionSecretValues struct {
	Env  []string
	File []string
}

// RedactionSecretValues returns deduplicated raw and encoded forms of the
// scanner's env/file secret sets. Returned slices are caller-owned.
func (s *Scanner) RedactionSecretValues() RedactionSecretValues {
	if s == nil {
		return RedactionSecretValues{}
	}
	return RedactionSecretValues{
		Env:  redactionSecretEntries(s.envSecrets),
		File: redactionSecretEntries(s.fileSecrets),
	}
}

func redactionSecretEntries(secrets []string) []string {
	if len(secrets) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(secrets)*8)
	out := make([]string, 0, len(secrets)*8)
	add := func(v string) {
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, secret := range secrets {
		add(secret)

		b64Std := base64.StdEncoding.EncodeToString([]byte(secret))
		add(b64Std)
		add(strings.TrimRight(b64Std, "="))

		b64URL := base64.URLEncoding.EncodeToString([]byte(secret))
		add(b64URL)
		add(strings.TrimRight(b64URL, "="))

		hexEnc := hex.EncodeToString([]byte(secret))
		add(hexEnc)
		add(strings.ToUpper(hexEnc))
		add(hexByteSep(hexEnc, ":"))
		add(hexByteSep(hexEnc, " "))
		add(hexByteSep(hexEnc, "-"))
		add(hexByteSep(hexEnc, ","))
		add(hexBytePrefix(hexEnc, `\x`))
		add(hexBytePrefix(hexEnc, "0x"))

		b32Std := base32.StdEncoding.EncodeToString([]byte(secret))
		add(b32Std)
		add(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret)))
	}
	return out
}
