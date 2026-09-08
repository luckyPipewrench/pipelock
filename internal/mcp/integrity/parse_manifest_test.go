// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A manifest file is untrusted input: it pins the hashes an MCP server binary
// is checked against, so whoever can edit it decides what counts as
// unmodified. ParseManifest is the gate, and each of its rejections is
// reachable only from a file we did not write. It had no direct test; the
// rejections were exercised through the file-loading wrapper instead.
func TestParseManifestRejections(t *testing.T) {
	t.Parallel()

	// Control first: a well-formed manifest parses, so every rejection below
	// is attributable to the one thing that case changes.
	t.Run("control_well_formed_manifest_parses", func(t *testing.T) {
		t.Parallel()
		good := fmt.Sprintf(`{"version":%d,"entries":{"/opt/server":"abc"}}`, ManifestVersion)
		m, err := ParseManifest([]byte(good))
		if err != nil {
			t.Fatalf("ParseManifest(control) = %v, want a parsed manifest", err)
		}
		if got := m.Entries["/opt/server"]; got != "abc" {
			t.Fatalf("entries[/opt/server] = %q, want %q", got, "abc")
		}
	})

	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name:    "not json",
			data:    `{"version":`,
			wantErr: "parsing manifest",
		},
		{
			// An unsupported version must not be parsed on a best-effort
			// basis: field meanings can change between versions, so a hash
			// read under the wrong schema pins the wrong thing.
			name:    "future version",
			data:    fmt.Sprintf(`{"version":%d,"entries":{}}`, ManifestVersion+1),
			wantErr: "unsupported manifest version",
		},
		{
			name:    "zero version",
			data:    `{"entries":{}}`,
			wantErr: "unsupported manifest version",
		},
		{
			// Explicit null entries is the case with no other coverage. An
			// empty pin set means nothing is pinned, so accepting a null
			// entries field would let a truncated or blanked manifest read as
			// a valid one that happens to pin nothing.
			name:    "null entries",
			data:    fmt.Sprintf(`{"version":%d,"entries":null}`, ManifestVersion),
			wantErr: "missing or null 'entries' field",
		},
		{
			name:    "absent entries",
			data:    fmt.Sprintf(`{"version":%d}`, ManifestVersion),
			wantErr: "missing or null 'entries' field",
		},
		{
			// Duplicate keys are a parser-differential defense. Go's decoder
			// keeps the last occurrence while other JSON readers keep the
			// first, so a manifest with two entries maps could pin one set of
			// hashes for this verifier and show a different set to anyone
			// auditing the same file.
			name:    "duplicate entries key",
			data:    fmt.Sprintf(`{"version":%d,"entries":{"/opt/a":"1"},"entries":{"/opt/a":"2"}}`, ManifestVersion),
			wantErr: "parsing manifest",
		},
		{
			name:    "duplicate key nested inside entries",
			data:    fmt.Sprintf(`{"version":%d,"entries":{"/opt/a":"1","/opt/a":"2"}}`, ManifestVersion),
			wantErr: "parsing manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := ParseManifest([]byte(tt.data))
			if err == nil {
				t.Fatalf("ParseManifest accepted %s; got manifest %+v", tt.name, m)
			}
			if m != nil {
				t.Errorf("ParseManifest returned a non-nil manifest alongside an error, which a caller could use")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// The size cap bounds a manifest before it is decoded, so an oversized file
// cannot be used to make the verifier do unbounded work at startup.
func TestParseManifestRejectsOversizedInput(t *testing.T) {
	t.Parallel()

	// One byte over the cap, built as valid JSON so the rejection is
	// attributable to the size check rather than to a decode failure.
	filler := strings.Repeat("a", maxManifestFileSize)
	data := fmt.Sprintf(`{"version":%d,"entries":{"/opt/server":"%s"}}`, ManifestVersion, filler)
	if len(data) <= maxManifestFileSize {
		t.Fatalf("fixture is %d bytes, which does not exceed the %d cap, so this case tests nothing", len(data), maxManifestFileSize)
	}
	if !json.Valid([]byte(data)) {
		t.Fatal("fixture is not valid JSON, so a rejection would not prove the size check fired")
	}

	if _, err := ParseManifest([]byte(data)); err == nil {
		t.Fatal("ParseManifest accepted input over the size cap")
	} else if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want it to name the size cap", err)
	}
}
