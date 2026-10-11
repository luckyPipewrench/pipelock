// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
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
	var out strings.Builder
	out.Grow(min(len(value), maxReassembledTokenLen))
	for i := 0; i < len(value); i++ {
		if alphabet == "hex" && i+3 < len(value) && (value[i] == '0' || value[i] == '\\') && (value[i+1] == 'x' || value[i+1] == 'X') {
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

// DecodeRecovery reads a filtered token at one of its byte alignments. Only
// complete hex pairs or base64 quanta are returned; undecodable tails do not
// discard bytes that were decoded successfully. Occurrence is an ASCII offset.
func DecodeRecovery(value, alphabet string, occurrence uint32) (string, error) {
	limit := uint32(3)
	if alphabet == "hex" {
		limit = 1
	} else if alphabet != "standard" && alphabet != "url" {
		return "", fmt.Errorf("decode recovery: unknown alphabet %q", alphabet)
	}
	if occurrence > limit {
		return "", fmt.Errorf("decode recovery: offset exceeds %d", limit)
	}
	token := RecoveryToken(value, alphabet)
	decoded, err := decodeRecoveryToken(token, alphabet, occurrence, make([]byte, len(token)))
	return string(decoded), err
}

// RecoveryViews filters once and reuses a decode buffer across alignments. Only
// candidates with an eight-byte printable run can carry a credential prefix.
//
//pipelock:provenance-transform decode_recovery
func RecoveryViews(value, alphabet string) []string {
	token := RecoveryToken(value, alphabet)
	minimum, limit := 11, uint32(4)
	if alphabet == "hex" {
		minimum, limit = 16, 2
	}
	if len(token) < minimum {
		return nil
	}
	var buffer [maxReassembledTokenLen]byte
	var views []string
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
				views = append(views, string(decoded))
				break
			}
		}
	}
	return views
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
