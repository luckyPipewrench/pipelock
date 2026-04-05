// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testTarget    = "https://example.com/api"
	testTransport = "fetch"
	testVerdict   = "block"
)

func validActionRecord() ActionRecord {
	return ActionRecord{
		Version:    ActionRecordVersion,
		ActionID:   NewActionID(),
		ActionType: ActionRead,
		Timestamp:  time.Now().UTC(),
		Target:     testTarget,
		Verdict:    testVerdict,
		Transport:  testTransport,
	}
}

func TestValidActionType(t *testing.T) {
	t.Parallel()

	validTypes := []ActionType{
		ActionRead, ActionDerive, ActionWrite, ActionDelegate,
		ActionAuthorize, ActionSpend, ActionCommit, ActionActuate,
		ActionUnclassified,
	}

	for _, at := range validTypes {
		t.Run(string(at), func(t *testing.T) {
			t.Parallel()
			if !ValidActionType(at) {
				t.Errorf("ValidActionType(%q) = false, want true", at)
			}
		})
	}

	t.Run("unknown_returns_false", func(t *testing.T) {
		t.Parallel()
		if ValidActionType("nonexistent") {
			t.Error("ValidActionType(\"nonexistent\") = true, want false")
		}
	})

	t.Run("empty_returns_false", func(t *testing.T) {
		t.Parallel()
		if ValidActionType("") {
			t.Error("ValidActionType(\"\") = true, want false")
		}
	})
}

func TestNewActionID(t *testing.T) {
	t.Parallel()

	uuidV4Re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	t.Run("format", func(t *testing.T) {
		t.Parallel()
		id := NewActionID()
		if !uuidV4Re.MatchString(id) {
			t.Errorf("NewActionID() = %q, does not match UUID v4 format", id)
		}
	})

	t.Run("uniqueness", func(t *testing.T) {
		t.Parallel()
		const count = 100
		seen := make(map[string]struct{}, count)
		for range count {
			id := NewActionID()
			if _, ok := seen[id]; ok {
				t.Fatalf("duplicate action ID generated: %s", id)
			}
			seen[id] = struct{}{}
		}
	})
}

func TestActionRecord_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		modify  func(*ActionRecord)
		wantErr string
	}{
		{
			name:   "valid",
			modify: func(_ *ActionRecord) {},
		},
		{
			name:    "missing_action_id",
			modify:  func(ar *ActionRecord) { ar.ActionID = "" },
			wantErr: "action_id is required",
		},
		{
			name:    "invalid_action_type",
			modify:  func(ar *ActionRecord) { ar.ActionType = "bogus" },
			wantErr: "invalid action_type",
		},
		{
			name:    "empty_action_type",
			modify:  func(ar *ActionRecord) { ar.ActionType = "" },
			wantErr: "invalid action_type",
		},
		{
			name:    "missing_timestamp",
			modify:  func(ar *ActionRecord) { ar.Timestamp = time.Time{} },
			wantErr: "timestamp is required",
		},
		{
			name:    "missing_target",
			modify:  func(ar *ActionRecord) { ar.Target = "" },
			wantErr: "target is required",
		},
		{
			name:    "missing_verdict",
			modify:  func(ar *ActionRecord) { ar.Verdict = "" },
			wantErr: "verdict is required",
		},
		{
			name:    "missing_transport",
			modify:  func(ar *ActionRecord) { ar.Transport = "" },
			wantErr: "transport is required",
		},
		{
			name:    "wrong_version",
			modify:  func(ar *ActionRecord) { ar.Version = 99 },
			wantErr: "unsupported action record version",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ar := validActionRecord()
			tc.modify(&ar)
			err := ar.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() expected error, got nil")
			}
			if got := err.Error(); !contains(got, tc.wantErr) {
				t.Errorf("Validate() error = %q, want substring %q", got, tc.wantErr)
			}
		})
	}
}

func TestActionRecord_Canonical(t *testing.T) {
	t.Parallel()

	t.Run("returns_valid_json", func(t *testing.T) {
		t.Parallel()
		ar := validActionRecord()
		data, err := ar.Canonical()
		if err != nil {
			t.Fatalf("Canonical() error: %v", err)
		}
		if !json.Valid(data) {
			t.Fatalf("Canonical() returned invalid JSON: %s", data)
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()
		ar := validActionRecord()
		// Fix timestamp to remove any time drift between calls.
		ar.Timestamp = time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)

		data1, err := ar.Canonical()
		if err != nil {
			t.Fatalf("Canonical() first call error: %v", err)
		}
		data2, err := ar.Canonical()
		if err != nil {
			t.Fatalf("Canonical() second call error: %v", err)
		}
		if string(data1) != string(data2) {
			t.Errorf("Canonical() not deterministic:\n  first:  %s\n  second: %s", data1, data2)
		}
	})
}

func TestActionRecord_Hash(t *testing.T) {
	t.Parallel()

	hexRe := regexp.MustCompile(`^[0-9a-f]{64}$`)

	t.Run("format", func(t *testing.T) {
		t.Parallel()
		ar := validActionRecord()
		h, err := ar.Hash()
		if err != nil {
			t.Fatalf("Hash() error: %v", err)
		}
		if !hexRe.MatchString(h) {
			t.Errorf("Hash() = %q, does not match 64-char hex", h)
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()
		ar := validActionRecord()
		ar.Timestamp = time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)

		h1, err := ar.Hash()
		if err != nil {
			t.Fatalf("Hash() first call error: %v", err)
		}
		h2, err := ar.Hash()
		if err != nil {
			t.Fatalf("Hash() second call error: %v", err)
		}
		if h1 != h2 {
			t.Errorf("Hash() not deterministic: %s != %s", h1, h2)
		}
	})

	t.Run("different_records_different_hashes", func(t *testing.T) {
		t.Parallel()
		ar1 := validActionRecord()
		ar1.Timestamp = time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
		ar2 := ar1
		ar2.Target = "https://other.example.com"

		h1, err := ar1.Hash()
		if err != nil {
			t.Fatalf("Hash() ar1 error: %v", err)
		}
		h2, err := ar2.Hash()
		if err != nil {
			t.Fatalf("Hash() ar2 error: %v", err)
		}
		if h1 == h2 {
			t.Error("Hash() same for different records")
		}
	})
}

func TestNormalizeVerdict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "block", input: config.ActionBlock, want: "block"},
		{name: "allow", input: config.ActionAllow, want: "allow"},
		{name: "warn", input: config.ActionWarn, want: "warn"},
		{name: "ask", input: config.ActionAsk, want: "ask"},
		{name: "strip", input: config.ActionStrip, want: "strip"},
		{name: "forward", input: config.ActionForward, want: "forward"},
		{name: "unknown_passthrough", input: "custom_verdict", want: "custom_verdict"},
		{name: "empty_passthrough", input: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeVerdict(tc.input)
			if got != tc.want {
				t.Errorf("NormalizeVerdict(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// contains is a helper to check substring presence without importing strings.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
