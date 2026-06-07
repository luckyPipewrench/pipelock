// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/capture"
)

const (
	testActionRead  = "read"
	testActionWrite = "write"
)

func TestCaptureMCPFrameActionClass_UsesToolArguments(t *testing.T) {
	t.Parallel()

	if got := captureMCPFrameActionClass("doSomething", methodToolsCall, `{"path":"/tmp/file","content":"x"}`); got != testActionWrite {
		t.Fatalf("generic tool with write arguments action_class = %q, want write", got)
	}
	if got := captureMCPFrameActionClass("edit_file", methodToolsCall, `{"path":"/tmp/file","content":"x"}`); got != testActionWrite {
		t.Fatalf("edit_file action_class = %q, want write", got)
	}
}

func TestCaptureMCPFrameActionClass_SecretFallsBackToToolVerb(t *testing.T) {
	t.Parallel()

	if got := captureMCPFrameActionClass("write_file", methodToolsCall, `{"path":"/etc/shadow","content":"x"}`); got != testActionWrite {
		t.Fatalf("secret write action_class = %q, want write", got)
	}
	if got := captureMCPFrameActionClass("read_file", methodToolsCall, `{"path":"/etc/shadow"}`); got != testActionRead {
		t.Fatalf("secret read action_class = %q, want read", got)
	}
}

func TestCaptureRPCID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   json.RawMessage
		want json.RawMessage
	}{
		{"numeric id", json.RawMessage("1"), json.RawMessage("1")},
		{"string id", json.RawMessage(`"abc"`), json.RawMessage(`"abc"`)},
		{"notification (nil)", nil, nil},
		{"notification (empty)", json.RawMessage(""), nil},
		{"literal null", json.RawMessage("null"), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := captureRPCID(tc.in)
			if string(got) != string(tc.want) {
				t.Errorf("captureRPCID(%q) = %q, want %q", string(tc.in), string(got), string(tc.want))
			}
		})
	}
}

func TestCaptureRPCID_DropsOverlength(t *testing.T) {
	t.Parallel()

	// A client-controlled id over MaxRPCIDLen must be dropped so it can't smuggle
	// a large blob into the cleartext summary.
	big := json.RawMessage(`"` + strings.Repeat("a", capture.MaxRPCIDLen) + `"`)
	if got := captureRPCID(big); got != nil {
		t.Fatalf("overlength id was retained (len=%d, cap=%d)", len(big), capture.MaxRPCIDLen)
	}
	// Exactly at the cap is retained.
	atCap := json.RawMessage(`"` + strings.Repeat("a", capture.MaxRPCIDLen-2) + `"`)
	if got := captureRPCID(atCap); string(got) != string(atCap) {
		t.Fatalf("at-cap id should be retained")
	}
}
