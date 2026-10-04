// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

const testBridgeAddr = "127.0.0.1:43210"

// TestDeveloperEnvRejectsMalformedEntries checks that the final command's
// environment is refused, not repaired, when an entry is ambiguous.
func TestDeveloperEnvRejectsMalformedEntries(t *testing.T) {
	tests := []struct {
		name    string
		env     []string
		bridge  string
		wantErr string
	}{
		{name: "distinct entries accepted", env: []string{"PATH=/developer/bin", "VENDOR_HOME=/work"}, bridge: testBridgeAddr},
		{name: "missing bridge address", env: []string{"PATH=/developer/bin"}, wantErr: "bridge address is required"},
		{name: "entry without equals", env: []string{"PATH=/developer/bin", "NOEQUALS"}, bridge: testBridgeAddr, wantErr: "malformed developer environment entry"},
		{name: "entry with empty key", env: []string{"=value"}, bridge: testBridgeAddr, wantErr: "malformed developer environment entry"},
		{name: "entry containing NUL", env: []string{"VENDOR_FLAG=on\x00off"}, bridge: testBridgeAddr, wantErr: "contains NUL"},
		{name: "duplicate key", env: []string{"PATH=/developer/bin", "PATH=/other/bin"}, bridge: testBridgeAddr, wantErr: `duplicate developer environment key "PATH"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeveloperEnv(tt.env, tt.bridge)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("DeveloperEnv() = %v, want nil", err)
				}
				if envValue(got, "PATH") != "/developer/bin" || envValue(got, "HTTPS_PROXY") != "http://"+testBridgeAddr {
					t.Fatalf("DeveloperEnv() = %q, want developer PATH and bridge proxy", got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("DeveloperEnv() = %v, want error containing %q", err, tt.wantErr)
			}
			if got != nil {
				t.Fatalf("DeveloperEnv() returned %q alongside an error", got)
			}
		})
	}
}

// sizedEntry returns a KEY=value entry of exactly n bytes.
func sizedEntry(key string, n int) string {
	return key + "=" + strings.Repeat("x", n-len(key)-1)
}

// minimalEntries returns n distinct KEY= entries using the shortest keys
// available from [A-Za-z0-9_], in order of key length.
func minimalEntries(n int) []string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
	out := make([]string, 0, n)
	keys := []string{""}
	for len(out) < n {
		next := make([]string, 0, len(keys)*len(alphabet))
		for _, prefix := range keys {
			for _, c := range alphabet {
				key := prefix + string(c)
				next = append(next, key)
				if len(out) < n {
					out = append(out, key+"=")
				}
			}
		}
		keys = next
	}
	return out
}

// TestEncodeDeveloperEnvironmentBounds pins the encoder's limits at their
// exact edges: a payload of exactly developerEnvironmentMaxPayload bytes is
// accepted and round-trips, one byte more is refused.
func TestEncodeDeveloperEnvironmentBounds(t *testing.T) {
	const maxPayload = developerEnvironmentMaxPayload
	// Header is 12 bytes; each entry adds a 4-byte length prefix.
	single := maxPayload - 12 - 4
	pair := maxPayload - 12 - 8
	first := pair / 2

	tooMany := make([]string, maxPayload/4+1)
	// The count cap (maxPayload/4) cannot be reached by an accepted
	// environment: every entry costs at least six bytes. Pin instead that the
	// cap never refuses a count the size bound would accept.
	fitsCount := maxPayload/8 + 1
	fits := minimalEntries(fitsCount)
	many := make([]string, 0, 1000)
	for i := range 1000 {
		many = append(many, fmt.Sprintf("VENDOR_%d=v", i))
	}

	tests := []struct {
		name    string
		env     []string
		wantErr string
	}{
		{name: "single entry filling the payload", env: []string{sizedEntry("BIG", single)}},
		{name: "single entry one byte over", env: []string{sizedEntry("BIG", single+1)}, wantErr: "payload exceeds 1 MiB"},
		{name: "two entries filling the payload", env: []string{sizedEntry("ONE", first), sizedEntry("TWO", pair-first)}},
		{name: "two entries one byte over", env: []string{sizedEntry("ONE", first), sizedEntry("TWO", pair-first+1)}, wantErr: "payload exceeds 1 MiB"},
		{name: "many small entries", env: many},
		{name: "entry count over the bound", env: tooMany, wantErr: "too many entries"},
		{name: "large entry count that fits the payload", env: fits},
		{name: "entry without equals", env: []string{"PATH=/bin", "NOEQUALS"}, wantErr: "malformed developer environment entry"},
		{name: "entry containing NUL", env: []string{"VENDOR_FLAG=a\x00b"}, wantErr: "contains NUL"},
		{name: "duplicate key", env: []string{"PATH=/bin", "PATH=/usr/bin"}, wantErr: `duplicate developer environment key "PATH"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := encodeDeveloperEnvironment(tt.env)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("encodeDeveloperEnvironment() = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("encodeDeveloperEnvironment() = %v, want nil", err)
			}
			if len(payload) > maxPayload {
				t.Fatalf("payload is %d bytes, over the %d byte bound", len(payload), maxPayload)
			}
			got, err := decodeDeveloperEnvironment(payload)
			if err != nil {
				t.Fatalf("decodeDeveloperEnvironment() = %v, want nil", err)
			}
			if strings.Join(got, "\x00") != strings.Join(tt.env, "\x00") {
				t.Fatalf("round trip changed the environment (%d entries in, %d out)", len(tt.env), len(got))
			}
		})
	}
}

// TestDecodeDeveloperEnvironmentRejectsBadFraming covers header and framing
// failures the existing malformed-payload cases do not reach.
func TestDecodeDeveloperEnvironmentRejectsBadFraming(t *testing.T) {
	valid, err := encodeDeveloperEnvironment([]string{"PATH=/developer/bin"})
	if err != nil {
		t.Fatalf("encodeDeveloperEnvironment: %v", err)
	}

	otherVersion := append([]byte(nil), valid...)
	binary.BigEndian.PutUint32(otherVersion[4:8], developerEnvironmentVersion+1)

	badMagic := append([]byte(nil), valid...)
	badMagic[0] ^= 0xff

	// Two declared entries; the first is complete and the remaining three
	// bytes cannot hold the second entry's length prefix. The count passes the
	// up-front bound, so only the per-entry framing check can catch it.
	var truncatedPrefix []byte
	truncatedPrefix = append(truncatedPrefix, developerEnvironmentMagic[:]...)
	truncatedPrefix = binary.BigEndian.AppendUint32(truncatedPrefix, developerEnvironmentVersion)
	truncatedPrefix = binary.BigEndian.AppendUint32(truncatedPrefix, 2)
	truncatedPrefix = binary.BigEndian.AppendUint32(truncatedPrefix, 3)
	truncatedPrefix = append(truncatedPrefix, "K=v"...)
	truncatedPrefix = append(truncatedPrefix, 0, 0, 0)
	// Clip capacity to length so a missing bound shows up as an out-of-range
	// read instead of silently reading spare capacity past the payload.
	truncatedPrefix = truncatedPrefix[:len(truncatedPrefix):len(truncatedPrefix)]

	tests := []struct {
		name    string
		payload []byte
		wantErr string
	}{
		{name: "valid payload", payload: valid},
		{name: "unsupported version", payload: otherVersion, wantErr: "unsupported developer environment payload version"},
		{name: "wrong magic", payload: badMagic, wantErr: "malformed developer environment payload"},
		{name: "short header", payload: valid[:11], wantErr: "malformed developer environment payload"},
		{name: "length prefix cut short", payload: truncatedPrefix, wantErr: "truncated developer environment payload"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeDeveloperEnvironment(tt.payload)
			if tt.wantErr == "" {
				if err != nil || len(got) != 1 || got[0] != "PATH=/developer/bin" {
					t.Fatalf("decodeDeveloperEnvironment() = %q, %v; want the encoded entry", got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("decodeDeveloperEnvironment() = %q, %v; want error containing %q", got, err, tt.wantErr)
			}
		})
	}
}
