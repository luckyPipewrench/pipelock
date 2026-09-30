// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// A benign tools/list whose description fuses into a key-shaped run in the
// whitespace-joined DLP view must not block the server; a tool description or
// result carrying a real key split by spaces must still block.
func TestScanResponse_JoinedEnglishAWSFalsePositive(t *testing.T) {
	sc := testScanner(t)

	desc := "hide_canvas: Add random noise to canvas operations to prevent fingerprinting"
	tools := []map[string]any{{
		"name":        "stealthy_fetch",
		"description": "Fetch a page. " + desc + " CANVAS OPERATIONS TO PREVENT FINGERPRINTING",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"hide_canvas": map[string]any{"type": "boolean", "description": desc},
				"region":      map[string]any{"type": "string", "description": "Asia Pacific region deployment operations"},
			},
		},
	}}
	list, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"tools": tools}})
	if err != nil {
		t.Fatal(err)
	}
	if v := ScanResponse(list, sc); !v.Clean {
		t.Fatalf("benign tools/list blocked: %+v", v)
	}

	// Tool result text path.
	if v := ScanResponse([]byte(makeResponse(2, desc+" CANVAS OPERATIONS TO PREVENT FINGERPRINTING")), sc); !v.Clean {
		t.Fatalf("benign tool result blocked: %+v", v)
	}

	// Real key split by spaces still blocks on both paths.
	key := "AKIA" + "IOSFODNN" + "7EXAMPLE"
	spaced := strings.Join([]string{key[:4], key[4:9], key[9:14], key[14:]}, " ")
	tools[0]["description"] = "Fetch a page. Use " + spaced
	bad, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 3, "result": map[string]any{"tools": tools}})
	if err != nil {
		t.Fatal(err)
	}
	if v := ScanResponse(bad, sc); v.Clean {
		t.Fatal("tools/list with a space-split key must block")
	}
	if v := ScanResponse([]byte(makeResponse(4, "result: "+spaced)), sc); v.Clean {
		t.Fatal("tool result with a space-split key must block")
	}
}
