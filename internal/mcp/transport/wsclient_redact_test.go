// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestRedactDialURL(t *testing.T) {
	secret := "dial-" + "pass-9Kt"
	for raw, want := range map[string]string{
		"wss://ops:" + secret + "@mcp.vendor.example/mcp?token=" + secret + "#" + secret: "wss://mcp.vendor.example/mcp",
		"ws://mcp.vendor.example/mcp": "ws://mcp.vendor.example/mcp",
		"ws://[::1":                   "<invalid>",
		"ws:ops:" + secret + "@mcp.vendor.example/mcp": "ws:<redacted>",
		"mailto:" + secret: "mailto:<redacted>",
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

// A URL that fails to parse is reported without the parse error, whose text
// repeats the URL with its user info and query.
func TestWSDialParseErrorOmitsCredentials(t *testing.T) {
	secret := "dial-" + "pass-6Hn"
	token := "dial-" + "token-3Lp"
	for _, raw := range []string{
		"ws://ops:" + secret + "@[::1/mcp?token=" + token,
		"ws://ops:" + secret + "@mcp.vendor.example/m%zz?token=" + token,
	} {
		_, err := NewWSClient(context.Background(), raw)
		if err == nil {
			t.Fatalf("malformed URL %q dialed", raw)
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "invalid upstream URL") {
			t.Fatalf("dial error = %v", err)
		}
	}
}

// Failures other than a parse error keep their cause for errors.Is: a
// cancellation, and a dialer's own error, including one wrapped in a
// *url.Error whose URL carries credentials.
func TestWSDialErrorKeepsCause(t *testing.T) {
	secret := "dial-" + "pass-8Vb"
	raw := "ws://ops:" + secret + "@mcp.vendor.example/mcp?token=" + secret
	sentinel := errors.New("dialer refused")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewWSClientWithDialer(ctx, raw, func(ctx context.Context, _, _ string) (net.Conn, error) {
		return nil, ctx.Err()
	})
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), secret) {
		t.Fatalf("cancelled dial error = %v, want context.Canceled without credentials", err)
	}

	for name, dialErr := range map[string]error{
		"plain":       sentinel,
		"url wrapped": &url.Error{Op: "dial", URL: raw, Err: sentinel},
	} {
		_, err := NewWSClientWithDialer(context.Background(), raw, func(context.Context, string, string) (net.Conn, error) {
			return nil, dialErr
		})
		if !errors.Is(err, sentinel) {
			t.Errorf("%s: dial error %v lost its cause", name, err)
		}
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("%s: dial error exposes credentials: %v", name, err)
		}
	}
}

// An opaque URL is dialed (as a host-less address) and its failure names
// the scheme only; the opaque part carries the credentials.
func TestWSDialOpaqueURLOmitsCredentials(t *testing.T) {
	secret := "dial-" + "pass-5Qm"
	_, err := NewWSClient(context.Background(), "ws:ops:"+secret+"@127.0.0.1:1/mcp?token="+secret)
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "ws dial ws:<redacted>") {
		t.Fatalf("opaque dial error = %v", err)
	}
}

// The dial-error helper redacts every endpoint shape the same way the CLI's
// does, and a dial of each shape names the endpoint without the secret.
func TestRedactDialURLClasses(t *testing.T) {
	secret := "class-" + "pass-2Hv"
	esc := url.QueryEscape("@" + secret + ":")
	host := "127.0.0.1:1"
	for _, c := range []struct{ class, raw, want string }{
		{"opaque websocket", "ws:ops:" + secret + "@" + host + "/mcp", "ws:<redacted>"},
		{"opaque bare", "wss:" + secret, "wss:<redacted>"},
		{"host-less", "ws://ops:" + secret + "@/mcp?token=" + secret, "ws:///mcp"},
		{"scheme-relative", "//ops:" + secret + "@" + host + "/mcp", "//" + host + "/mcp"},
		{"malformed host", "ws://ops:" + secret + "@[::1/mcp", "<invalid>"},
		{"malformed escape", "ws://ops:" + secret + "@" + host + "/%zz", "<invalid>"},
		{"unsupported scheme", "ftp://ops:" + secret + "@" + host + "/mcp", "ftp://" + host + "/mcp"},
		{"mixed-case scheme", "Wss://ops:" + secret + "@" + host + "/mcp#" + secret, "wss://" + host + "/mcp"},
		{"escaped secret", "ws://ops:" + esc + "@" + host + "/mcp?k=" + esc, "ws://" + host + "/mcp"},
		{"valid endpoint", "ws://" + host + "/mcp", "ws://" + host + "/mcp"},
	} {
		if got := redactDialURL(c.raw); got != c.want {
			t.Errorf("%s: redactDialURL(%q) = %q, want %q", c.class, c.raw, got, c.want)
		}
		_, err := NewWSClient(context.Background(), c.raw)
		if err == nil {
			t.Errorf("%s: dial of %q succeeded", c.class, c.raw)
			continue
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), url.QueryEscape(secret)) {
			t.Errorf("%s: dial error exposes the secret: %v", c.class, err)
		}
	}
}
