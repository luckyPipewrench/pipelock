// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// QueryUnescapePartial keeps malformed escapes verbatim and decodes every
// complete percent escape. It has form semantics: plus becomes a space.
func QueryUnescapePartial(value string) string {
	if !strings.ContainsAny(value, "%+") {
		return value
	}
	var out strings.Builder
	out.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) {
			a, aOK := hexNibble(value[i+1])
			b, bOK := hexNibble(value[i+2])
			if aOK && bOK {
				out.WriteByte(a<<4 | b)
				i += 2
				continue
			}
		}
		if value[i] == '+' {
			out.WriteByte(' ')
		} else {
			out.WriteByte(value[i])
		}
	}
	return out.String()
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// RecoveryToken retains the selected encoding alphabet without interpreting
// surrounding junk as a reason to discard the candidate. The existing token
// size bound also applies to recovery. Prefix removal precedes hex filtering.
func RecoveryToken(value, alphabet string) string {
	return recoveryToken(value, alphabet, true)
}

func recoveryToken(value, alphabet string, stripPrefixes bool) string {
	var out strings.Builder
	out.Grow(min(len(value), maxReassembledTokenLen))
	for i := 0; i < len(value); i++ {
		if stripPrefixes && alphabet == "hex" && i+3 < len(value) && (value[i] == '0' || value[i] == '\\') && (value[i+1] == 'x' || value[i+1] == 'X') {
			_, a := hexNibble(value[i+2])
			_, b := hexNibble(value[i+3])
			if a && b {
				i += 2
			}
		}
		c := value[i]
		_, keep := hexNibble(c)
		if alphabet != "hex" {
			keep = c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '='
			keep = keep || alphabet == "standard" && (c == '+' || c == '/') || alphabet == "url" && (c == '-' || c == '_')
		}
		if keep {
			if out.Len() == maxReassembledTokenLen {
				return ""
			}
			out.WriteByte(c)
		}
	}
	return out.String()
}

// DecodeRecovery selects the occurrence-th printable scanner recovery view.
// An absent occurrence returns empty output. Alignment and hex-prefix
// ambiguity are handled by the same candidate enumeration as production.
func DecodeRecovery(value, alphabet string, occurrence uint32) (string, error) {
	if alphabet != "hex" && alphabet != "standard" && alphabet != "url" {
		return "", fmt.Errorf("decode recovery: unknown alphabet %q", alphabet)
	}
	if occurrence > 3 {
		return "", fmt.Errorf("decode recovery: occurrence exceeds 3")
	}
	views := RecoveryViews(value, alphabet)
	if int(occurrence) >= len(views) {
		return "", nil
	}
	return views[occurrence], nil
}

// RecoveryViews filters once and reuses a decode buffer across alignments. Only
// candidates with an eight-byte printable run can carry a credential prefix.
//
//pipelock:provenance-transform decode_recovery
func RecoveryViews(value, alphabet string) []string {
	tokens := [2]string{RecoveryToken(value, alphabet)}
	if alphabet == "hex" && strings.ContainsAny(value, "xX") {
		// A zero before x can be notation or a real nibble followed by junk.
		// Preserve both interpretations rather than choosing destructively.
		preserved := recoveryToken(value, alphabet, false)
		if preserved != tokens[0] {
			tokens[1] = preserved
		}
	}
	minimum, limit := 11, uint32(4)
	if alphabet == "hex" {
		minimum, limit = 16, 2
	}
	var buffer [maxReassembledTokenLen]byte
	var views, binaryViews []string
	for _, token := range tokens {
		if len(token) < minimum {
			continue
		}
		for offset := range limit {
			decoded, err := decodeRecoveryToken(token, alphabet, offset, buffer[:])
			if err != nil {
				continue
			}
			run := 0
			for _, c := range decoded {
				if c >= 0x20 && c <= 0x7e {
					run++
				} else {
					run = 0
				}
				if run >= 8 {
					if utf8.Valid(decoded) {
						views = append(views, string(decoded))
					} else {
						binaryViews = append(binaryViews, string(decoded))
					}
					break
				}
			}
		}
	}
	// Keep binary views for security scanning, after replayable UTF-8 views.
	return append(views, binaryViews...)
}

func decodeRecoveryToken(token, alphabet string, occurrence uint32, buffer []byte) ([]byte, error) {
	if int(occurrence) >= len(token) {
		return nil, nil
	}
	token = token[occurrence:]
	if alphabet == "hex" {
		n, err := hex.Decode(buffer, []byte(token[:len(token)/2*2]))
		if err != nil {
			return nil, fmt.Errorf("decode recovery: %w", err)
		}
		return buffer[:n], nil
	}
	// Padding terminates an encoded value. Raw decoding of its preceding data
	// retains the same complete bytes even when the padding is malformed.
	if before, _, found := strings.Cut(token, "="); found {
		token = before
	}
	if len(token)%4 == 1 {
		token = token[:len(token)-1]
	}
	enc := base64.RawStdEncoding
	if alphabet == "url" {
		enc = base64.RawURLEncoding
	}
	n, err := enc.Decode(buffer, []byte(token))
	if err != nil {
		return nil, fmt.Errorf("decode recovery: %w", err)
	}
	return buffer[:n], nil
}
