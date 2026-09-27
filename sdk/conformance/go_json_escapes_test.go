// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// The TypeScript and Rust verifiers rebuild bytes that Go signed with
// encoding/json, such as the rotation endorsement digest. These fixtures record
// what Go actually writes, so the ports are held to the encoder rather than to
// anyone's memory of it. Regenerate with PIPELOCK_GO_JSON_ESCAPE_FIXTURES=1.
const goJSONEscapeDir = "testdata/go-json-escapes"

type goJSONEscapeEntry struct {
	Codepoint string `json:"codepoint"`
	GoJSONHex string `json:"go_json_hex"`
}

type goJSONEscapeTable struct {
	Description string              `json:"description"`
	Entries     []goJSONEscapeEntry `json:"entries"`
}

// goJSONEscapeCodepoints is every ASCII code point plus the two line
// separators encoding/json escapes outside ASCII.
func goJSONEscapeCodepoints() []rune {
	cps := make([]rune, 0, 0x82)
	for c := rune(0); c < 0x80; c++ {
		cps = append(cps, c)
	}
	return append(cps, 0x2028, 0x2029)
}

func buildGoJSONEscapeTable(t *testing.T) []byte {
	t.Helper()
	table := goJSONEscapeTable{
		Description: "encoding/json.Marshal of a one-character string, as hex, for every code point listed",
	}
	for _, c := range goJSONEscapeCodepoints() {
		b, err := json.Marshal(string(c))
		if err != nil {
			t.Fatal(err)
		}
		table.Entries = append(table.Entries, goJSONEscapeEntry{
			Codepoint: fmt.Sprintf("%04x", c),
			GoJSONHex: hex.EncodeToString(b),
		})
	}
	out, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// testOnlyKey derives a throwaway Ed25519 key from a label, so the fixture is
// reproducible and no private key is committed.
func testOnlyKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// buildEscapeEndorsement signs a rotation endorsement whose session_id carries
// every character class encoding/json escapes differently: short escapes,
// \u00XX controls, HTML characters, the line separators, and DEL and non-ASCII
// that it leaves raw.
func buildEscapeEndorsement(t *testing.T) []byte {
	t.Helper()
	tail := sha256.Sum256([]byte("go-json-escapes prior tail"))
	signed, err := receipt.SignRotationEndorsement(receipt.RotationEndorsement{
		Version:       receipt.RotationEndorsementVersion,
		SessionID:     "run\b\f\t\n\r\x00\x01\x1f\"\\<>&\u2028\u2029\x7f/é",
		PriorFinalSeq: 7,
		PriorTailHash: hex.EncodeToString(tail[:]),
		NewSignerKey:  hex.EncodeToString(testOnlyKey("go-json-escapes successor").Public().(ed25519.PublicKey)),
		RotatedAt:     "2026-01-02T03:04:05.123456789Z",
	}, testOnlyKey("go-json-escapes prior"))
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyRotationEndorsement(signed); err != nil {
		t.Fatalf("Go rejects its own endorsement: %v", err)
	}
	out, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// buildEscapeLink signs a chain link whose session names carry the same
// character classes, so the link digest is checked the way the endorsement
// digest is.
func buildEscapeLink(t *testing.T) []byte {
	t.Helper()
	tail := sha256.Sum256([]byte("go-json-escapes link tail"))
	signed, err := receipt.SignChainLink(receipt.ChainLink{
		PredecessorSession:   "proxy.run.a\b\f\x01\x1f<>&\u2028\u2029\x7f/é",
		PredecessorTailSeq:   4,
		PredecessorTailHash:  hex.EncodeToString(tail[:]),
		PredecessorSignerKey: hex.EncodeToString(testOnlyKey("go-json-escapes prior").Public().(ed25519.PublicKey)),
		SuccessorSession:     "proxy.run.b\b\f\t\n\r\x00\"\\",
		LinkedAt:             "2026-01-02T03:04:05.123456789Z",
	}, testOnlyKey("go-json-escapes successor"))
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyChainLink(signed); err != nil {
		t.Fatalf("Go rejects its own link: %v", err)
	}
	out, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func TestGoJSONEscapeFixtures(t *testing.T) {
	t.Parallel()
	files := map[string][]byte{
		"table.json":       buildGoJSONEscapeTable(t),
		"endorsement.json": buildEscapeEndorsement(t),
		"chain-link.json":  buildEscapeLink(t),
	}
	for name, want := range files {
		path := filepath.Join(goJSONEscapeDir, name)
		if os.Getenv("PIPELOCK_GO_JSON_ESCAPE_FIXTURES") == "1" {
			if err := os.MkdirAll(goJSONEscapeDir, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, want, 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read %s: %v (regenerate with PIPELOCK_GO_JSON_ESCAPE_FIXTURES=1)", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s no longer matches what encoding/json writes; regenerate with PIPELOCK_GO_JSON_ESCAPE_FIXTURES=1 and check both ports", path)
		}
	}
}
