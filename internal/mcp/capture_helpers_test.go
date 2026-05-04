// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import "testing"

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
