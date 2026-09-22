// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

var runSessionPattern = regexp.MustCompile(`^proxy\.run\.[0-9a-f]{32}$`)

func TestNewRunSessionID_Format(t *testing.T) {
	id, err := NewRunSessionID("proxy")
	if err != nil {
		t.Fatalf("NewRunSessionID: %v", err)
	}
	if !runSessionPattern.MatchString(id) {
		t.Fatalf("run session id %q does not match expected shape <base>.run.<32 hex>", id)
	}
}

func TestNewRunSessionID_UniquePerCall(t *testing.T) {
	seen := make(map[string]bool)
	const n = 200
	for i := 0; i < n; i++ {
		id, err := NewRunSessionID("proxy")
		if err != nil {
			t.Fatalf("NewRunSessionID: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate run session id %q after %d calls", id, i)
		}
		seen[id] = true
	}
	if len(seen) != n {
		t.Fatalf("expected %d unique ids, got %d", n, len(seen))
	}
}

func TestNewRunSessionID_RejectsReservedBase(t *testing.T) {
	cases := []string{
		"proxy.run.deadbeef",
		"a/b",
		`a\b`,
		"",
	}
	for _, base := range cases {
		if _, err := NewRunSessionID(base); err == nil {
			t.Errorf("NewRunSessionID(%q): expected refusal, got nil error", base)
		} else if !errors.Is(err, evidencename.ErrReservedSessionID) {
			t.Errorf("NewRunSessionID(%q): expected ErrReservedSessionID, got %v", base, err)
		}
	}
}

func TestNewRunSessionID_DifferentBasesPreserved(t *testing.T) {
	id, err := NewRunSessionID("proxy-decision")
	if err != nil {
		t.Fatalf("NewRunSessionID: %v", err)
	}
	if !strings.HasPrefix(id, "proxy-decision.run.") {
		t.Fatalf("run session id %q does not preserve base %q", id, "proxy-decision")
	}
}

// TestValidateOperatorSessionID_RejectsReservedInfix is the refusal proof
// required by the design: an operator-supplied session id containing the
// reserved ".run." infix is refused, with a message naming what to change.
func TestValidateOperatorSessionID_RejectsReservedInfix(t *testing.T) {
	err := evidencename.ValidateOperatorSessionID("proxy.run.abc123")
	if err == nil {
		t.Fatal("expected refusal for operator session id containing reserved infix, got nil")
	}
	if !errors.Is(err, evidencename.ErrReservedSessionID) {
		t.Fatalf("expected ErrReservedSessionID, got %v", err)
	}
	if !strings.Contains(err.Error(), ".run.") {
		t.Fatalf("error message does not name the offending infix: %v", err)
	}
}

// TestValidateOperatorSessionID_RejectsPathSeparators covers the "/" and "\"
// refusal half of the same guard.
func TestValidateOperatorSessionID_RejectsPathSeparators(t *testing.T) {
	for _, id := range []string{"a/b", `a\b`, "/etc/passwd", `..\..\x`} {
		if err := evidencename.ValidateOperatorSessionID(id); err == nil {
			t.Errorf("ValidateOperatorSessionID(%q): expected refusal, got nil", id)
		} else if !errors.Is(err, evidencename.ErrReservedSessionID) {
			t.Errorf("ValidateOperatorSessionID(%q): expected ErrReservedSessionID, got %v", id, err)
		}
	}
}

// TestValidateOperatorSessionID_AcceptsPlainID is the positive control for
// the two refusal tests above: an ordinary operator-chosen session id must
// still pass, so the guard is proven to reject the bad shape specifically
// and not merely reject everything.
func TestValidateOperatorSessionID_AcceptsPlainID(t *testing.T) {
	for _, id := range []string{"proxy", "my-agent-session", "session_123", "a.b.c"} {
		if err := evidencename.ValidateOperatorSessionID(id); err != nil {
			t.Errorf("ValidateOperatorSessionID(%q): unexpected refusal: %v", id, err)
		}
	}
}

func TestValidateOperatorSessionID_RejectsEmpty(t *testing.T) {
	if err := evidencename.ValidateOperatorSessionID(""); err == nil {
		t.Fatal("expected refusal for empty session id, got nil")
	}
}
