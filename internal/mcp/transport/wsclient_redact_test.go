// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"strings"
	"testing"
)

func TestRedactDialURL(t *testing.T) {
	secret := "dial-" + "pass-9Kt"
	for raw, want := range map[string]string{
		"wss://ops:" + secret + "@mcp.vendor.example/mcp?token=" + secret + "#" + secret: "wss://mcp.vendor.example/mcp",
		"ws://mcp.vendor.example/mcp": "ws://mcp.vendor.example/mcp",
		"ws://[::1":                   "<invalid>",
	} {
		if got := redactDialURL(raw); got != want {
			t.Errorf("redactDialURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

// A failed dial names the endpoint without the credential in its URL.
func TestWSDialErrorOmitsCredentials(t *testing.T) {
	secret := "dial-" + "pass-2Wq"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewWSClient(ctx, "ws://ops:"+secret+"@127.0.0.1:1/mcp?token="+secret)
	if err == nil {
		t.Fatal("dial with a cancelled context succeeded")
	}
	if strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "ws dial ws://127.0.0.1:1/mcp") {
		t.Fatalf("dial error = %v", err)
	}
}
