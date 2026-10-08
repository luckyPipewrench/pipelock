// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"net/url"
	"strings"
	"testing"
)

// upstreamURLClasses are the shapes an operator-supplied endpoint can take.
// Every one carries the secret in a credential position, and none of them
// may show it once redacted, raw or percent-escaped. want, where set, is the
// exact redacted form: a valid endpoint keeps its scheme, host, port and
// path so diagnostics still name it.
func upstreamURLClasses(secret, host string) []struct{ class, raw, want string } {
	esc := url.QueryEscape("@" + secret + ":")
	return []struct{ class, raw, want string }{
		{"opaque with credentials", "http:ops:" + secret + "@" + host + "/mcp?token=" + secret, "http:<redacted>"},
		{"opaque websocket", "ws:ops:" + secret + "@" + host + "/mcp", "ws:<redacted>"},
		{"opaque bare", "mailto:" + secret, "mailto:<redacted>"},
		{"scheme-like user info", "ops:" + secret + "@" + host, "ops:<redacted>"},
		{"host-less with query", "http:///mcp?token=" + secret, "http:///mcp"},
		{"host-less with user info", "http://ops:" + secret + "@/mcp", "http:///mcp"},
		{"scheme-relative", "//ops:" + secret + "@" + host + "/mcp", "//" + host + "/mcp"},
		{"relative path", "/mcp?token=" + secret, "/mcp"},
		{"malformed host", "http://ops:" + secret + "@[::1/mcp?token=" + secret, "<invalid>"},
		{"malformed escape", "http://ops:" + secret + "@" + host + "/%zz?token=" + secret, "<invalid>"},
		{"control character", "http://ops:" + secret + "@" + host + "/\x7f", "<invalid>"},
		{"unsupported scheme", "ftp://ops:" + secret + "@" + host + "/mcp?token=" + secret, "ftp://" + host + "/mcp"},
		{"upper-case scheme", "HTTP://ops:" + secret + "@" + host + "/mcp?token=" + secret, "http://" + host + "/mcp"},
		{"mixed-case websocket", "Ws://ops:" + secret + "@" + host + "/mcp#" + secret, "ws://" + host + "/mcp"},
		{"escaped user info and query", "https://ops%3Aname:" + secret + "%40x@" + host + "/mcp?token=" + secret + "&x=%2F#" + secret, "https://" + host + "/mcp"},
		{"escaped secret", "https://ops:" + esc + "@" + host + "/mcp?k=" + esc, "https://" + host + "/mcp"},
		{"valid endpoint", "https://" + host + "/mcp", "https://" + host + "/mcp"},
	}
}

func TestRedactEndpointURLClasses(t *testing.T) {
	secret := "class-" + "pass-7Td"
	for _, c := range upstreamURLClasses(secret, "mcp.vendor.example:8443") {
		got := RedactEndpoint(c.raw)
		if strings.Contains(got, secret) || strings.Contains(got, url.QueryEscape(secret)) {
			t.Errorf("%s: RedactEndpoint exposes the secret: %q", c.class, got)
		}
		if got != c.want {
			t.Errorf("%s: RedactEndpoint(%q) = %q, want %q", c.class, c.raw, got, c.want)
		}
	}
}

// Every class reaches a real --upstream branch: the missing-host and
// unsupported-scheme refusals, a parse failure, or a dial to an endpoint
// nothing listens on. None of the output may carry the secret.
func TestMCPProxyUpstreamURLClassesOmitSecret(t *testing.T) {
	secret := "class-" + "pass-3Kw"
	for _, c := range upstreamURLClasses(secret, unavailableTCPAddr(t)) {
		stdout, stderr, err := runMCPProxyCommandWithInput(t, []string{"proxy", "--upstream", c.raw},
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n")
		out := stdout + stderr
		if err != nil {
			out += err.Error()
		}
		if strings.Contains(out, secret) || strings.Contains(out, url.QueryEscape(secret)) {
			t.Errorf("%s: proxy output exposes the secret:\n%s", c.class, out)
		}
	}
}
